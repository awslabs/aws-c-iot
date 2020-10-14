#include <aws/http/request_response.h>
#include <aws/http/websocket.h>
#include <aws/io/tls_channel_handler.h>
#include <aws/iotdevice/iotdevice.h>
#include <aws/iotdevice/private/serializer.h>
#include <aws/iotdevice/secure_tunneling.h>

#define MAX_WEBSOCKET_PAYLOAD 131076
#define INVALID_STREAM_ID 0
#define MAX_ST_PAYLOAD 64512
#define PAYLOAD_BYTE_LENGTH_PREFIX 2

/* TODO: Remove me */
#define UNUSED(x) (void)(x)

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

    secure_tunnel->stream_id++;
    secure_tunnel->websocket = websocket;
    secure_tunnel->config.on_connection_complete(secure_tunnel);
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
            st_msg->streamId);
        secure_tunnel->stream_id = st_msg->streamId;
        secure_tunnel->config.on_stream_start(secure_tunnel);
    }
}

static void s_reset_secure_tunnel(struct aws_secure_tunnel *secure_tunnel) {
    secure_tunnel->stream_id = INVALID_STREAM_ID;
    secure_tunnel->received_data.len = 0; /* Drop any incomplete secure tunnel frame */
}

static void s_handle_stream_reset(struct aws_secure_tunnel *secure_tunnel, struct aws_iot_st_msg *st_msg) {
    if (secure_tunnel->stream_id == INVALID_STREAM_ID || secure_tunnel->stream_id != st_msg->streamId) {
        AWS_LOGF_WARN(
            AWS_LS_IOTDEVICE_SECURE_TUNNELING,
            "Received StreamReset with stream_id different than the active stream_id. Ignoring. st_msg->stream_id=%d "
            "secure_tunnel->stream_id=%d",
            st_msg->streamId,
            secure_tunnel->stream_id);
        return;
    }

    secure_tunnel->config.on_stream_reset(secure_tunnel);
    s_reset_secure_tunnel(secure_tunnel);
}

static void s_handle_session_reset(struct aws_secure_tunnel *secure_tunnel) {
    if (secure_tunnel->stream_id == INVALID_STREAM_ID) { /* Session reset does not need to check stream id */
        return;
    }

    secure_tunnel->config.on_session_reset(secure_tunnel);
    s_reset_secure_tunnel(secure_tunnel);
}

static void s_process_iot_st_msg(struct aws_secure_tunnel *secure_tunnel, struct aws_iot_st_msg *st_msg) {
    /* TODO: Check stream_id, send reset? */

    switch (st_msg->type) {
        case DATA:
            secure_tunnel->config.on_data_receive(secure_tunnel, &st_msg->payload);
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
        cursor; // If there are at least two bytes for the data_length, but not enough
                // data for a complete secure tunnel frame, we don't want to move `cursor`.
    while (aws_byte_cursor_read_be16(&tmp_cursor, &data_length) && tmp_cursor.len >= data_length) {
        cursor = tmp_cursor;

        struct aws_byte_cursor st_frame = {.len = data_length, .ptr = cursor.ptr};
        aws_byte_cursor_advance(&cursor, data_length);

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
    if (secure_tunnel == NULL || secure_tunnel->stream_id == INVALID_STREAM_ID) {
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
    pair->secure_tunnel->config.on_send_data_complete(error_code, user_data);
    aws_mem_release(pair->secure_tunnel->config.allocator, (void *)pair);
}

static bool s_secure_tunneling_send_data_call(
    struct aws_websocket *websocket,
    struct aws_byte_buf *out_buf,
    void *user_data) {
    UNUSED(websocket);
    struct data_tunnel_pair *pair = user_data;
    struct aws_byte_buf *buffer = &pair->buf;
    if (aws_byte_buf_write_be16(out_buf, (int16_t)pair->buf.len) == false) {
        AWS_LOGF_ERROR(AWS_LS_IOTDEVICE_SECURE_TUNNELING, "Failure writing buffer length prefix to out_buf");
        goto cleanup;
    }
    if (aws_byte_buf_write(out_buf, buffer->buffer, buffer->len) == false) {
        AWS_LOGF_ERROR(AWS_LS_IOTDEVICE_SECURE_TUNNELING, "Failure writing data to out_buf");
        goto cleanup;
    }
    aws_byte_buf_clean_up(buffer);
    aws_mem_release(pair->secure_tunnel->config.allocator, (void *)pair);
    return true;
cleanup:
    aws_byte_buf_clean_up(buffer);
    aws_mem_release(pair->secure_tunnel->config.allocator, (void *)pair);
    return false;
}

static void s_init_websocket_send_frame_options(
    struct aws_websocket_send_frame_options *frame_options,
    struct data_tunnel_pair *pair) {
    frame_options->payload_length = pair->buf.len + PAYLOAD_BYTE_LENGTH_PREFIX;
    frame_options->user_data = pair;
    frame_options->stream_outgoing_payload = s_secure_tunneling_send_data_call;
    frame_options->on_complete = s_secure_tunneling_on_send_data_complete_callback;
    frame_options->opcode = AWS_WEBSOCKET_OPCODE_BINARY;
    frame_options->fin = true;
    frame_options->high_priority = false;
    AWS_ZERO_STRUCT(frame_options->rsv);
}

static int s_secure_tunneling_send(
    struct aws_secure_tunnel *secure_tunnel,
    const struct aws_byte_cursor *data,
    enum aws_iot_st_message_type type) {
    struct aws_iot_st_msg message;
    message.streamId = secure_tunnel->stream_id;
    message.ignorable = 0;
    message.type = type;
    if (data != NULL) {
        message.payload.buffer = data->ptr;
        message.payload.len = data->len;
    } else {
        message.payload.buffer = NULL;
        message.payload.len = 0;
    }
    struct data_tunnel_pair *pair =
        (struct data_tunnel_pair *)aws_mem_acquire(secure_tunnel->config.allocator, sizeof(struct data_tunnel_pair));
    pair->secure_tunnel = secure_tunnel;
    if (aws_iot_st_msg_serialize_from_struct(&pair->buf, secure_tunnel->config.allocator, message) != AWS_OP_SUCCESS) {
        AWS_LOGF_ERROR(AWS_LS_IOTDEVICE_SECURE_TUNNELING, "Failure serializing message");
        goto cleanup;
    }
    if (pair->buf.len > MAX_ST_PAYLOAD) {
        AWS_LOGF_ERROR(AWS_LS_IOTDEVICE_SECURE_TUNNELING, "Message size greater than MAX_ST_PAYLOAD");
        goto cleanup;
    }
    struct aws_websocket_send_frame_options frame_options;
    s_init_websocket_send_frame_options(&frame_options, pair);
    aws_websocket_send_frame(secure_tunnel->websocket, &frame_options);
    return AWS_OP_SUCCESS;
cleanup:
    aws_byte_buf_clean_up(&pair->buf);
    aws_mem_release(pair->secure_tunnel->config.allocator, (void *)pair);
    return AWS_OP_ERR;
}

static int s_secure_tunneling_send_data(struct aws_secure_tunnel *secure_tunnel, const struct aws_byte_cursor *data) {
    if (secure_tunnel->stream_id == INVALID_STREAM_ID) {
        AWS_LOGF_ERROR(AWS_LS_IOTDEVICE_SECURE_TUNNELING, "Invalid Stream Id");
        return AWS_ERROR_IOTDEVICE_SECUTRE_TUNNELING_INVALID_STREAM;
    }
    return s_secure_tunneling_send(secure_tunnel, data, DATA);
}

static int s_secure_tunneling_send_stream_start(struct aws_secure_tunnel *secure_tunnel) {
    if (secure_tunnel->config.local_proxy_mode == AWS_SECURE_TUNNELING_DESTINATION_MODE) {
        AWS_LOGF_ERROR(AWS_LS_IOTDEVICE_SECURE_TUNNELING, "Start can only be sent from src mode");
        return AWS_ERROR_IOTDEVICE_SECUTRE_TUNNELING_INCORRECT_MODE;
    }
    secure_tunnel->stream_id += 1;
    if (secure_tunnel->stream_id == 0)
        secure_tunnel->stream_id += 1;
    return s_secure_tunneling_send(secure_tunnel, NULL, STREAM_START);
}

static int s_secure_tunneling_send_stream_reset(struct aws_secure_tunnel *secure_tunnel) {
    if (secure_tunnel->stream_id == INVALID_STREAM_ID) {
        AWS_LOGF_ERROR(AWS_LS_IOTDEVICE_SECURE_TUNNELING, "Invalid Stream Id");
        return AWS_ERROR_IOTDEVICE_SECUTRE_TUNNELING_INVALID_STREAM;
    }
    return s_secure_tunneling_send(secure_tunnel, NULL, STREAM_RESET);
}

static int s_secure_tunneling_send_data(struct aws_secure_tunnel *secure_tunnel, const struct aws_byte_buf *data) {
    if (secure_tunnel == NULL || secure_tunnel->stream_id == INVALID_STREAM_ID) {
        return AWS_OP_ERR;
    }
    return s_secure_tunneling_send(secure_tunnel, data, DATA);
}

static int s_secure_tunneling_send_stream_start(struct aws_secure_tunnel *secure_tunnel) {
    if (secure_tunnel == NULL || secure_tunnel->config.local_proxy_mode == AWS_SECURE_TUNNELING_DESTINATION_MODE) {
        return AWS_OP_ERR;
    }
    secure_tunnel->stream_id += 1;
    if (secure_tunnel->stream_id == 0)
        secure_tunnel->stream_id += 1;
    return s_secure_tunneling_send(secure_tunnel, NULL, STREAM_START);
}

static int s_secure_tunneling_send_stream_reset(struct aws_secure_tunnel *secure_tunnel) {
    if (secure_tunnel == NULL || secure_tunnel->stream_id == INVALID_STREAM_ID) {
        return AWS_OP_ERR;
    }
    return s_secure_tunneling_send(secure_tunnel, NULL, STREAM_RESET);
}

static void s_copy_secure_tunneling_connection_config(
    const struct aws_secure_tunneling_connection_config *src,
    struct aws_secure_tunneling_connection_config *dest) {
    dest->allocator = src->allocator;
    dest->bootstrap = src->bootstrap;
    dest->socket_options = src->socket_options;
    dest->access_token = src->access_token; /* TODO: followup */
    dest->local_proxy_mode = src->local_proxy_mode;
    dest->endpoint_host = src->endpoint_host; /* TODO: followup */

    dest->on_connection_complete = src->on_connection_complete;
    dest->on_send_data_complete = src->on_send_data_complete;
    dest->on_data_receive = src->on_data_receive;
    dest->on_stream_start = src->on_stream_start;
    dest->on_stream_reset = src->on_stream_reset;
    dest->on_session_reset = src->on_session_reset;
    dest->on_close = src->on_close;
}

struct aws_secure_tunnel *aws_secure_tunnel_new(
    const struct aws_secure_tunneling_connection_config *connection_config) {

    struct aws_secure_tunnel *secure_tunnel =
        aws_mem_acquire(connection_config->allocator, sizeof(struct aws_secure_tunnel));
    AWS_ZERO_STRUCT(*secure_tunnel);

    s_copy_secure_tunneling_connection_config(connection_config, &secure_tunnel->config);

    // tls
    struct aws_tls_ctx_options tls_ctx_opt;
    aws_tls_ctx_options_init_default_client(&tls_ctx_opt, connection_config->allocator);
    aws_tls_ctx_options_set_verify_peer(&tls_ctx_opt, false); /* TODO: remove me! */
    secure_tunnel->tls_ctx = aws_tls_client_ctx_new(connection_config->allocator, &tls_ctx_opt);
    aws_tls_ctx_options_clean_up(&tls_ctx_opt);
    aws_tls_connection_options_init_from_ctx(&secure_tunnel->tls_con_opt, secure_tunnel->tls_ctx);

    /* Setup vtable here */
    secure_tunnel->vtable.connect = s_secure_tunneling_connect;
    secure_tunnel->vtable.close = s_secure_tunneling_close;
    secure_tunnel->vtable.send_data = s_secure_tunneling_send_data;
    secure_tunnel->vtable.send_stream_start = s_secure_tunneling_send_stream_start;
    secure_tunnel->vtable.send_stream_reset = s_secure_tunneling_send_stream_reset;

    secure_tunnel->handshake_request = NULL;
    secure_tunnel->stream_id = INVALID_STREAM_ID;
    secure_tunnel->websocket = NULL;

    /* TODO: Release this buffer when there is no data to hold */
    aws_byte_buf_init(&secure_tunnel->received_data, connection_config->allocator, MAX_WEBSOCKET_PAYLOAD);

    return secure_tunnel;
}

void aws_secure_tunnel_release(struct aws_secure_tunnel *secure_tunnel) {
    aws_byte_buf_clean_up(&secure_tunnel->received_data);
    aws_tls_connection_options_clean_up(&secure_tunnel->tls_con_opt);
    aws_tls_ctx_release(secure_tunnel->tls_ctx);
    aws_mem_release(secure_tunnel->config.allocator, secure_tunnel);
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
