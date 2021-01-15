#include <aws/http/request_response.h>
#include <aws/http/websocket.h>
#include <aws/io/channel_bootstrap.h>
#include <aws/io/event_loop.h>
#include <aws/io/tls_channel_handler.h>
#include <aws/iotdevice/iotdevice.h>
#include <aws/iotdevice/private/serializer.h>
#include <aws/iotdevice/secure_tunneling.h>
#include <math.h>

#define MAX_WEBSOCKET_PAYLOAD 131076
#define INVALID_STREAM_ID 0
#define PAYLOAD_BYTE_LENGTH_PREFIX 2

#define UNUSED(x) (void)(x)

// static struct aws_mutex send_data_mutex = AWS_MUTEX_INIT;
// static struct aws_condition_variable send_data_condition_variable = AWS_CONDITION_VARIABLE_INIT;

static void s_send_websocket_ping(struct aws_secure_tunnel *secure_tunnel) {
    if (!secure_tunnel->websocket) {
        return;
    }

    struct aws_websocket_send_frame_options frame_options;
    AWS_ZERO_STRUCT(frame_options);
    frame_options.opcode = AWS_WEBSOCKET_OPCODE_PING;
    frame_options.fin = true;
    aws_websocket_send_frame(secure_tunnel->websocket, &frame_options);
}

static void s_ping_task(struct aws_task *task, void *user_data, enum aws_task_status task_status) {
    AWS_LOGF_TRACE(AWS_LS_IOTDEVICE_SECURE_TUNNELING, "s_ping_task");

    if (task_status != AWS_TASK_STATUS_RUN_READY) {
        AWS_LOGF_ERROR(AWS_LS_IOTDEVICE_SECURE_TUNNELING, "task_status is not ready. Do nothing.");
        return;
    }

    struct aws_secure_tunnel *secure_tunnel = user_data;
    s_send_websocket_ping(secure_tunnel);

    // Schedule the next task
    struct aws_event_loop *event_loop =
        aws_event_loop_group_get_next_loop(secure_tunnel->config.bootstrap->event_loop_group);
    uint64_t now;
    aws_event_loop_current_clock_time(event_loop, &now);
    aws_event_loop_schedule_task_future(event_loop, task, now + (uint64_t)20 * 1000000000);
}

static void s_on_websocket_setup(
    struct aws_websocket *websocket,
    int error_code,
    int handshake_response_status,
    const struct aws_http_header *handshake_response_header_array,
    size_t num_handshake_response_headers,
    void *user_data) {

    UNUSED(websocket);
    UNUSED(error_code);
    UNUSED(handshake_response_status);
    UNUSED(handshake_response_header_array);
    UNUSED(num_handshake_response_headers);

    /* TODO: Handle error
     * https://github.com/aws-samples/aws-iot-securetunneling-localproxy/blob/master/WebsocketProtocolGuide.md#handshake-error-responses
     */

    struct aws_secure_tunnel *secure_tunnel = user_data;
    aws_http_message_release(secure_tunnel->handshake_request);
    secure_tunnel->handshake_request = NULL;

    secure_tunnel->websocket = websocket;
    secure_tunnel->config.on_connection_complete(secure_tunnel->config.user_data);

    struct aws_event_loop *event_loop =
        aws_event_loop_group_get_next_loop(secure_tunnel->config.bootstrap->event_loop_group);
    aws_event_loop_schedule_task_now(event_loop, &secure_tunnel->ping_task);
}

static void s_on_websocket_shutdown(struct aws_websocket *websocket, int error_code, void *user_data) {
    UNUSED(websocket);
    UNUSED(error_code);
    UNUSED(user_data);
}

static bool s_on_websocket_incoming_frame_begin(
    struct aws_websocket *websocket,
    const struct aws_websocket_incoming_frame *frame,
    void *user_data) {
    UNUSED(websocket);
    UNUSED(frame);
    UNUSED(user_data);
    return true;
}

static void s_handle_stream_start(struct aws_secure_tunnel *secure_tunnel, struct aws_iot_st_msg *st_msg) {
    if (secure_tunnel->config.local_proxy_mode == AWS_SECURE_TUNNELING_SOURCE_MODE) {
        /* Source mode tunnel clients SHOULD treat receiving StreamStart as an error and close the active data stream
         * and WebSocket connection. */
        AWS_LOGF_ERROR(AWS_LS_IOTDEVICE_SECURE_TUNNELING, "Received StreamStart in source mode. Closing the tunnel.");
        secure_tunnel->vtable.close(secure_tunnel);
    } else {
        AWS_LOGF_INFO(
            AWS_LS_IOTDEVICE_SECURE_TUNNELING,
            "Received StreamStart in destination mode. stream_id=%d",
            st_msg->stream_id);
        secure_tunnel->stream_id = st_msg->stream_id;
        secure_tunnel->config.on_stream_start(secure_tunnel->config.user_data);
    }
}

static void s_reset_secure_tunnel(struct aws_secure_tunnel *secure_tunnel) {
    secure_tunnel->stream_id = INVALID_STREAM_ID;
    secure_tunnel->received_data.len = 0; /* Drop any incomplete secure tunnel frame */
}

static void s_handle_stream_reset(struct aws_secure_tunnel *secure_tunnel, struct aws_iot_st_msg *st_msg) {
    if (secure_tunnel->stream_id == INVALID_STREAM_ID || secure_tunnel->stream_id != st_msg->stream_id) {
        AWS_LOGF_WARN(
            AWS_LS_IOTDEVICE_SECURE_TUNNELING,
            "Received StreamReset with stream_id different than the active stream_id. Ignoring. st_msg->stream_id=%d "
            "secure_tunnel->stream_id=%d",
            st_msg->stream_id,
            secure_tunnel->stream_id);
        return;
    }

    secure_tunnel->config.on_stream_reset(secure_tunnel->config.user_data);
    s_reset_secure_tunnel(secure_tunnel);
}

static void s_handle_session_reset(struct aws_secure_tunnel *secure_tunnel) {
    if (secure_tunnel->stream_id == INVALID_STREAM_ID) { /* Session reset does not need to check stream id */
        return;
    }

    secure_tunnel->config.on_session_reset(secure_tunnel->config.user_data);
    s_reset_secure_tunnel(secure_tunnel);
}

static void s_process_iot_st_msg(struct aws_secure_tunnel *secure_tunnel, struct aws_iot_st_msg *st_msg) {
    /* TODO: Check stream_id, send reset? */

    switch (st_msg->type) {
        case DATA:
            secure_tunnel->config.on_data_receive(&st_msg->payload, secure_tunnel->config.user_data);
            break;
        case STREAM_START:
            s_handle_stream_start(secure_tunnel, st_msg);
            break;
        case STREAM_RESET:
            s_handle_stream_reset(secure_tunnel, st_msg);
            break;
        case SESSION_RESET:
            s_handle_session_reset(secure_tunnel);
            break;
        case UNKNOWN:
        default:
            if (!st_msg->ignorable) {
                AWS_LOGF_WARN(
                    AWS_LS_IOTDEVICE_SECURE_TUNNELING,
                    "Encountered an unknown but un-ignorable message. type=%d",
                    st_msg->type);
            }
            break;
    }
}

static void s_process_received_data(struct aws_secure_tunnel *secure_tunnel) {
    struct aws_byte_buf *received_data = &secure_tunnel->received_data;
    struct aws_byte_cursor cursor = aws_byte_cursor_from_buf(received_data);

    uint16_t data_length = 0;
    struct aws_byte_cursor tmp_cursor =
        cursor; /* If there are at least two bytes for the data_length, but not enough      */
                /* data for a complete secure tunnel frame, we don't want to move `cursor`. */
    while (aws_byte_cursor_read_be16(&tmp_cursor, &data_length) && tmp_cursor.len >= data_length) {
        cursor = tmp_cursor;

        struct aws_byte_cursor st_frame = {.len = data_length, .ptr = cursor.ptr};
        aws_byte_cursor_advance(&cursor, data_length);
        tmp_cursor = cursor;

        struct aws_iot_st_msg st_msg;
        aws_iot_st_msg_deserialize_from_cursor(&st_msg, &st_frame, secure_tunnel->config.allocator);
        s_process_iot_st_msg(secure_tunnel, &st_msg);

        if (st_msg.type == DATA) {
            aws_byte_buf_clean_up(&st_msg.payload);
        }
    }

    if (cursor.ptr != received_data->buffer) {
        /* TODO: Consider better data structure that doesn't require moving bytes */

        /* Move unprocessed data to the beginning */
        received_data->len = 0;
        aws_byte_buf_append(received_data, &cursor);
    }
}

bool on_websocket_incoming_frame_payload(
    struct aws_websocket *websocket,
    const struct aws_websocket_incoming_frame *frame,
    struct aws_byte_cursor data,
    void *user_data) {

    UNUSED(websocket);
    UNUSED(frame);

    if (data.len > 0) {
        struct aws_secure_tunnel *secure_tunnel = user_data;
        aws_byte_buf_append(&secure_tunnel->received_data, &data);
        s_process_received_data(secure_tunnel);
    }

    return true;
}

static bool s_on_websocket_incoming_frame_complete(
    struct aws_websocket *websocket,
    const struct aws_websocket_incoming_frame *frame,
    int error_code,
    void *user_data) {
    UNUSED(websocket);
    UNUSED(frame);
    UNUSED(error_code);
    UNUSED(user_data);

    /* TODO: Check error_code */

    return true;
}

static const char *s_get_proxy_mode_string(enum aws_secure_tunneling_local_proxy_mode local_proxy_mode) {
    if (local_proxy_mode == AWS_SECURE_TUNNELING_SOURCE_MODE) {
        return "source";
    }

    return "destination";
}

static struct aws_http_message *s_new_handshake_request(const struct aws_secure_tunnel *secure_tunnel) {
    char path[50];
    snprintf(
        path,
        sizeof(path),
        "/tunnel?local-proxy-mode=%s",
        s_get_proxy_mode_string(secure_tunnel->config.local_proxy_mode));
    struct aws_http_message *handshake_request = aws_http_message_new_websocket_handshake_request(
        secure_tunnel->config.allocator, aws_byte_cursor_from_c_str(path), secure_tunnel->config.endpoint_host);

    struct aws_http_header extra_headers[] = {
        {
            .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("Sec-WebSocket-Protocol"),
            .value = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("aws.iot.securetunneling-1.0"),
        },
        {
            .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("access-token"),
            .value = secure_tunnel->config.access_token,
        },
    };
    for (size_t i = 0; i < AWS_ARRAY_SIZE(extra_headers); ++i) {
        aws_http_message_add_header(handshake_request, extra_headers[i]);
    }

    return handshake_request;
}

void init_websocket_client_connection_options(
    struct aws_secure_tunnel *secure_tunnel,
    struct aws_websocket_client_connection_options *websocket_options) {

    AWS_ZERO_STRUCT(*websocket_options);
    websocket_options->allocator = secure_tunnel->config.allocator;
    websocket_options->bootstrap = secure_tunnel->config.bootstrap;
    websocket_options->socket_options = secure_tunnel->config.socket_options;
    websocket_options->tls_options = &secure_tunnel->tls_con_opt;
    websocket_options->host = secure_tunnel->config.endpoint_host;
    websocket_options->port = 443;
    websocket_options->handshake_request = s_new_handshake_request(secure_tunnel);
    websocket_options->initial_window_size = MAX_WEBSOCKET_PAYLOAD; /* TODO: followup */
    websocket_options->user_data = secure_tunnel;
    websocket_options->on_connection_setup = s_on_websocket_setup;
    websocket_options->on_connection_shutdown = s_on_websocket_shutdown;
    websocket_options->on_incoming_frame_begin = s_on_websocket_incoming_frame_begin;
    websocket_options->on_incoming_frame_payload = on_websocket_incoming_frame_payload;
    websocket_options->on_incoming_frame_complete = s_on_websocket_incoming_frame_complete;
    websocket_options->manual_window_management = false;

    /* Save handshake_request to release it later */
    secure_tunnel->handshake_request = websocket_options->handshake_request;
}

static int s_secure_tunneling_connect(struct aws_secure_tunnel *secure_tunnel) {
    if (secure_tunnel == NULL || secure_tunnel->stream_id != INVALID_STREAM_ID) {
        return AWS_OP_ERR;
    }

    struct aws_websocket_client_connection_options websocket_options;
    init_websocket_client_connection_options(secure_tunnel, &websocket_options);
    if (aws_websocket_client_connect(&websocket_options)) {
        return AWS_OP_ERR;
    }

    return AWS_OP_SUCCESS;
}

static int s_secure_tunneling_close(struct aws_secure_tunnel *secure_tunnel) {
    if (secure_tunnel == NULL) {
        return AWS_OP_ERR;
    }

    s_reset_secure_tunnel(secure_tunnel);
    aws_websocket_close(secure_tunnel->websocket, false);
    aws_websocket_release(secure_tunnel->websocket);
    secure_tunnel->websocket = NULL;
    return AWS_OP_SUCCESS;
}

static void s_secure_tunneling_on_send_data_complete_callback(
    struct aws_websocket *websocket,
    int error_code,
    void *user_data) {
    UNUSED(websocket);
    struct data_tunnel_pair *pair = user_data;
    struct aws_secure_tunnel *secure_tunnel = (struct aws_secure_tunnel *)pair->secure_tunnel;
    secure_tunnel->config.on_send_data_complete(error_code, pair->secure_tunnel->config.user_data);
    aws_byte_buf_clean_up(&pair->buf);
    aws_mem_release(pair->secure_tunnel->config.allocator, pair);
    aws_condition_variable_notify_one(&secure_tunnel->send_data_condition_variable);
}

bool secure_tunneling_send_data_call(struct aws_websocket *websocket, struct aws_byte_buf *out_buf, void *user_data) {
    UNUSED(websocket);
    struct data_tunnel_pair *pair = user_data;
    size_t space_available = out_buf->capacity - out_buf->len;
    if ((pair->length_prefix_written == false) && (space_available >= PAYLOAD_BYTE_LENGTH_PREFIX)) {
        if (aws_byte_buf_write_be16(out_buf, (int16_t)pair->buf.len) == false) {
            AWS_LOGF_ERROR(AWS_LS_IOTDEVICE_SECURE_TUNNELING, "Failure writing buffer length prefix to out_buf");
            return false;
        }
        pair->length_prefix_written = true;
        space_available = out_buf->capacity - out_buf->len;
    }
    if (pair->length_prefix_written == true) {
        size_t bytes_max = pair->cur.len;
        size_t amount_to_send = bytes_max < space_available ? bytes_max : space_available;

        struct aws_byte_cursor send_cursor = aws_byte_cursor_advance(&pair->cur, amount_to_send);
        if (send_cursor.len) {
            if (aws_byte_buf_write_from_whole_cursor(out_buf, send_cursor) == false) {
                AWS_LOGF_ERROR(AWS_LS_IOTDEVICE_SECURE_TUNNELING, "Failure writing data to out_buf");
                return false;
            }
        }
    }
    return true;
}

static void s_init_websocket_send_frame_options(
    struct aws_websocket_send_frame_options *frame_options,
    struct data_tunnel_pair *pair) {
    frame_options->payload_length = pair->buf.len + PAYLOAD_BYTE_LENGTH_PREFIX;
    frame_options->user_data = pair;
    frame_options->stream_outgoing_payload = secure_tunneling_send_data_call;
    frame_options->on_complete = s_secure_tunneling_on_send_data_complete_callback;
    frame_options->opcode = AWS_WEBSOCKET_OPCODE_BINARY;
    frame_options->fin = true;
    frame_options->high_priority = false;
    AWS_ZERO_STRUCT(frame_options->rsv);
}

static int s_init_data_tunnel_pair(
    struct data_tunnel_pair *pair,
    struct aws_secure_tunnel *secure_tunnel,
    const struct aws_byte_cursor *data,
    enum aws_iot_st_message_type type) {
    struct aws_iot_st_msg message;
    message.stream_id = secure_tunnel->stream_id;
    message.ignorable = 0;
    message.type = type;
    if (data != NULL) {
        message.payload.buffer = data->ptr;
        message.payload.len = data->len;
    } else {
        message.payload.buffer = NULL;
        message.payload.len = 0;
    }
    pair->secure_tunnel = secure_tunnel;
    pair->length_prefix_written = false;
    if (aws_iot_st_msg_serialize_from_struct(&pair->buf, secure_tunnel->config.allocator, message) != AWS_OP_SUCCESS) {
        AWS_LOGF_ERROR(AWS_LS_IOTDEVICE_SECURE_TUNNELING, "Failure serializing message");
        goto cleanup;
    }
    if (pair->buf.len > AWS_IOT_ST_MAX_MESSAGE_SIZE) {
        AWS_LOGF_ERROR(AWS_LS_IOTDEVICE_SECURE_TUNNELING, "Message size greater than AWS_IOT_ST_MAX_MESSAGE_SIZE");
        goto cleanup;
    }
    pair->cur = aws_byte_cursor_from_buf(&pair->buf);
    return AWS_OP_SUCCESS;
cleanup:
    aws_byte_buf_clean_up(&pair->buf);
    aws_mem_release(pair->secure_tunnel->config.allocator, (void *)pair);
    return AWS_OP_ERR;
}

int secure_tunneling_init_send_frame(
    struct aws_websocket_send_frame_options *frame_options,
    struct aws_secure_tunnel *secure_tunnel,
    const struct aws_byte_cursor *data,
    enum aws_iot_st_message_type type) {
    struct data_tunnel_pair *pair =
        (struct data_tunnel_pair *)aws_mem_acquire(secure_tunnel->config.allocator, sizeof(struct data_tunnel_pair));
    if (s_init_data_tunnel_pair(pair, secure_tunnel, data, type) != AWS_OP_SUCCESS) {
        return AWS_OP_ERR;
    }
    s_init_websocket_send_frame_options(frame_options, pair);
    return AWS_OP_SUCCESS;
}

static int s_secure_tunneling_send(
    struct aws_secure_tunnel *secure_tunnel,
    const struct aws_byte_cursor *data,
    enum aws_iot_st_message_type type) {

    struct aws_websocket_send_frame_options frame_options;
    if (secure_tunneling_init_send_frame(&frame_options, secure_tunnel, data, type) != AWS_OP_SUCCESS) {
        return AWS_OP_ERR;
    }
    return aws_websocket_send_frame(secure_tunnel->websocket, &frame_options);
}

static int s_secure_tunneling_send_data(struct aws_secure_tunnel *secure_tunnel, const struct aws_byte_cursor *data) {
    if (secure_tunnel->stream_id == INVALID_STREAM_ID) {
        AWS_LOGF_ERROR(AWS_LS_IOTDEVICE_SECURE_TUNNELING, "Invalid Stream Id");
        return AWS_ERROR_IOTDEVICE_SECUTRE_TUNNELING_INVALID_STREAM;
    }
    struct aws_byte_cursor new_data;
    new_data.ptr = data->ptr;
    new_data.len = data->len;
    while (new_data.len) {
        size_t bytes_max = new_data.len;
        size_t amount_to_send = bytes_max < AWS_IOT_ST_SPLIT_MESSAGE_SIZE ? bytes_max : AWS_IOT_ST_SPLIT_MESSAGE_SIZE;

        struct aws_byte_cursor send_cursor = aws_byte_cursor_advance(&new_data, amount_to_send);
        if (send_cursor.len) {
            if (s_secure_tunneling_send(secure_tunnel, &send_cursor, DATA) != AWS_OP_SUCCESS) {
                AWS_LOGF_ERROR(AWS_LS_IOTDEVICE_SECURE_TUNNELING, "Failure writing data to out_buf");
                return AWS_OP_ERR;
            }
        }
        aws_mutex_lock(&secure_tunnel->send_data_mutex);
        aws_condition_variable_wait(&secure_tunnel->send_data_condition_variable, &secure_tunnel->send_data_mutex);
        aws_mutex_unlock(&secure_tunnel->send_data_mutex);
    }
    return AWS_OP_SUCCESS;
}

static int s_secure_tunneling_send_stream_start(struct aws_secure_tunnel *secure_tunnel) {
    if (secure_tunnel->config.local_proxy_mode == AWS_SECURE_TUNNELING_DESTINATION_MODE) {
        AWS_LOGF_ERROR(AWS_LS_IOTDEVICE_SECURE_TUNNELING, "Start can only be sent from src mode");
        return AWS_ERROR_IOTDEVICE_SECUTRE_TUNNELING_INCORRECT_MODE;
    }
    secure_tunnel->stream_id += 1;
    if (secure_tunnel->stream_id == 0) {
        secure_tunnel->stream_id += 1;
    }
    return s_secure_tunneling_send(secure_tunnel, NULL, STREAM_START);
}

static int s_secure_tunneling_send_stream_reset(struct aws_secure_tunnel *secure_tunnel) {
    if (secure_tunnel->stream_id == INVALID_STREAM_ID) {
        AWS_LOGF_ERROR(AWS_LS_IOTDEVICE_SECURE_TUNNELING, "Invalid Stream Id");
        return AWS_ERROR_IOTDEVICE_SECUTRE_TUNNELING_INVALID_STREAM;
    }

    int result = s_secure_tunneling_send(secure_tunnel, NULL, STREAM_RESET);
    s_reset_secure_tunnel(secure_tunnel);
    return result;
}

static void s_copy_secure_tunneling_connection_config(
    const struct aws_secure_tunneling_connection_config *src,
    struct aws_secure_tunneling_connection_config *dest) {
    *dest = *src;
}

struct aws_secure_tunnel *aws_secure_tunnel_new(
    const struct aws_secure_tunneling_connection_config *connection_config) {

    struct aws_secure_tunnel *secure_tunnel =
        aws_mem_acquire(connection_config->allocator, sizeof(struct aws_secure_tunnel));
    AWS_ZERO_STRUCT(*secure_tunnel);

    s_copy_secure_tunneling_connection_config(connection_config, &secure_tunnel->config);

    /* tls */
    struct aws_tls_ctx_options tls_ctx_opt;
    aws_tls_ctx_options_init_default_client(&tls_ctx_opt, connection_config->allocator);
    aws_tls_ctx_options_override_default_trust_store_from_path(&tls_ctx_opt, NULL, connection_config->root_ca);
    secure_tunnel->tls_ctx = aws_tls_client_ctx_new(connection_config->allocator, &tls_ctx_opt);
    aws_tls_ctx_options_clean_up(&tls_ctx_opt);
    aws_tls_connection_options_init_from_ctx(&secure_tunnel->tls_con_opt, secure_tunnel->tls_ctx);
    aws_tls_connection_options_set_server_name(
        &secure_tunnel->tls_con_opt,
        connection_config->allocator,
        (struct aws_byte_cursor *)&connection_config->endpoint_host);

    /* Setup vtable here */
    secure_tunnel->vtable.connect = s_secure_tunneling_connect;
    secure_tunnel->vtable.close = s_secure_tunneling_close;
    secure_tunnel->vtable.send_data = s_secure_tunneling_send_data;
    secure_tunnel->vtable.send_stream_start = s_secure_tunneling_send_stream_start;
    secure_tunnel->vtable.send_stream_reset = s_secure_tunneling_send_stream_reset;

    secure_tunnel->handshake_request = NULL;
    secure_tunnel->stream_id = INVALID_STREAM_ID;
    secure_tunnel->websocket = NULL;

    struct aws_mutex mutex = AWS_MUTEX_INIT;
    struct aws_condition_variable condition_variable = AWS_CONDITION_VARIABLE_INIT;
    secure_tunnel->send_data_mutex = mutex;
    secure_tunnel->send_data_condition_variable = condition_variable;

    /* TODO: Release this buffer when there is no data to hold */
    aws_byte_buf_init(&secure_tunnel->received_data, connection_config->allocator, MAX_WEBSOCKET_PAYLOAD);

    aws_task_init(&secure_tunnel->ping_task, s_ping_task, secure_tunnel, "SecureTunnelingPingTask");

    return secure_tunnel;
}

void aws_secure_tunnel_release(struct aws_secure_tunnel *secure_tunnel) {
    aws_byte_buf_clean_up(&secure_tunnel->received_data);
    aws_tls_connection_options_clean_up(&secure_tunnel->tls_con_opt);
    aws_tls_ctx_release(secure_tunnel->tls_ctx);
    aws_mem_release(secure_tunnel->config.allocator, secure_tunnel);
}

int aws_secure_tunnel_connect(struct aws_secure_tunnel *secure_tunnel) {
    return secure_tunnel->vtable.connect(secure_tunnel);
}

int aws_secure_tunnel_close(struct aws_secure_tunnel *secure_tunnel) {
    return secure_tunnel->vtable.close(secure_tunnel);
}

int aws_secure_tunnel_send_data(struct aws_secure_tunnel *secure_tunnel, const struct aws_byte_cursor *data) {
    return secure_tunnel->vtable.send_data(secure_tunnel, data);
}

int aws_secure_tunnel_stream_start(struct aws_secure_tunnel *secure_tunnel) {
    return secure_tunnel->vtable.send_stream_start(secure_tunnel);
}

int aws_secure_tunnel_stream_reset(struct aws_secure_tunnel *secure_tunnel) {
    return secure_tunnel->vtable.send_stream_reset(secure_tunnel);
}
