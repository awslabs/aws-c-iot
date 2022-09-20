/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/iotdevice/private/secure_tunneling_impl.h>

#include <aws/common/string.h>
#include <aws/http/proxy.h>
#include <aws/http/request_response.h>
#include <aws/http/websocket.h>
#include <aws/io/channel_bootstrap.h>
#include <aws/io/event_loop.h>
#include <aws/io/socket.h>
#include <aws/iotdevice/private/iotdevice_internals.h>
#include <aws/iotdevice/private/serializer.h>
#include <math.h>

#define MAX_WEBSOCKET_PAYLOAD 131076
#define INVALID_STREAM_ID 0
#define PAYLOAD_BYTE_LENGTH_PREFIX 2
#define PING_TASK_INTERVAL ((uint64_t)20 * 1000000000)

#define UNUSED(x) (void)(x)

struct aws_secure_tunnel_options_storage {
    struct aws_secure_tunnel_options options;

    /* backup */
    struct aws_socket_options socket_options;
    struct aws_http_proxy_options http_proxy_options;
    struct aws_http_proxy_config *http_proxy_config;
    struct aws_byte_buf cursor_storage;
    struct aws_string *root_ca;
};

int aws_secure_tunnel_options_validate(const struct aws_secure_tunnel_options *options) {
    AWS_ASSERT(options && options->allocator);
    if (options->bootstrap == NULL) {
        AWS_LOGF_ERROR(AWS_LS_IOTDEVICE_SECURE_TUNNELING, "bootstrap cannot be NULL");
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }
    if (options->socket_options == NULL) {
        AWS_LOGF_ERROR(AWS_LS_IOTDEVICE_SECURE_TUNNELING, "socket options cannot be NULL");
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }
    if (options->access_token.len == 0) {
        AWS_LOGF_ERROR(AWS_LS_IOTDEVICE_SECURE_TUNNELING, "access token is required");
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }
    if (options->endpoint_host.len == 0) {
        AWS_LOGF_ERROR(AWS_LS_IOTDEVICE_SECURE_TUNNELING, "endpoint host is required");
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }

    return AWS_OP_SUCCESS;
}

void aws_secure_tunnel_options_storage_destroy(struct aws_secure_tunnel_options_storage *storage) {
    if (storage == NULL) {
        return;
    }

    aws_client_bootstrap_release(storage->options.bootstrap);
    aws_http_proxy_config_destroy(storage->http_proxy_config);
    aws_byte_buf_clean_up(&storage->cursor_storage);
    aws_string_destroy(storage->root_ca);
    aws_mem_release(storage->options.allocator, storage);
}

struct aws_secure_tunnel_options_storage *aws_secure_tunnel_options_storage_new(
    const struct aws_secure_tunnel_options *src) {

    if (aws_secure_tunnel_options_validate(src)) {
        return NULL;
    }

    struct aws_allocator *alloc = src->allocator;

    struct aws_secure_tunnel_options_storage *storage =
        aws_mem_calloc(alloc, 1, sizeof(struct aws_secure_tunnel_options_storage));

    /* shallow-copy everything that's shallow-copy-able */
    storage->options = *src;

    /* acquire reference to everything that's ref-counted */
    aws_client_bootstrap_acquire(storage->options.bootstrap);

    /* deep-copy anything that needs deep-copying */
    storage->socket_options = *src->socket_options;
    storage->options.socket_options = &storage->socket_options;

    /* deep-copy the http-proxy-options to http_proxy_config */
    if (src->http_proxy_options != NULL) {
        storage->http_proxy_config =
            aws_http_proxy_config_new_tunneling_from_proxy_options(alloc, src->http_proxy_options);
        if (storage->http_proxy_config == NULL) {
            goto error;
        }

        /* Make a copy of http_proxy_options and point to it */
        aws_http_proxy_options_init_from_config(&storage->http_proxy_options, storage->http_proxy_config);
        storage->options.http_proxy_options = &storage->http_proxy_options;
    }

    /* Store contents of all cursors within single buffer (and update cursors to point into it) */
    aws_byte_buf_init_cache_and_update_cursors(
        &storage->cursor_storage, alloc, &storage->options.access_token, &storage->options.endpoint_host, NULL);

    if (src->root_ca != NULL) {
        storage->root_ca = aws_string_new_from_c_str(alloc, src->root_ca);
        storage->options.root_ca = aws_string_c_str(storage->root_ca);
    }

    return storage;

error:
    aws_secure_tunnel_options_storage_destroy(storage);
    return NULL;
}

typedef int(
    websocket_send_frame)(struct aws_websocket *websocket, const struct aws_websocket_send_frame_options *options);

static void s_send_websocket_ping(struct aws_websocket *websocket, websocket_send_frame *send_frame) {
    if (!websocket) {
        return;
    }

    struct aws_websocket_send_frame_options frame_options;
    AWS_ZERO_STRUCT(frame_options);
    frame_options.opcode = AWS_WEBSOCKET_OPCODE_PING;
    frame_options.fin = true;
    send_frame(websocket, &frame_options);
}

struct ping_task_context {
    struct aws_allocator *allocator;
    struct aws_event_loop *event_loop;

    struct aws_task ping_task;
    struct aws_atomic_var task_cancelled;
    struct aws_websocket *websocket;

    /* The ping_task shares the vtable function used by the secure tunnel to send frames over the websocket. */
    websocket_send_frame *send_frame;
};

static void s_ping_task(struct aws_task *task, void *user_data, enum aws_task_status task_status) {
    AWS_LOGF_TRACE(AWS_LS_IOTDEVICE_SECURE_TUNNELING, "s_ping_task");

    struct ping_task_context *ping_task_context = user_data;

    if (task_status == AWS_TASK_STATUS_CANCELED) {
        AWS_LOGF_INFO(
            AWS_LS_IOTDEVICE_SECURE_TUNNELING, "task_status is AWS_TASK_STATUS_CANCELED. Cleaning up ping task.");
        aws_mem_release(ping_task_context->allocator, ping_task_context);
        return;
    }

    const size_t task_cancelled = aws_atomic_load_int(&ping_task_context->task_cancelled);
    if (task_cancelled) {
        AWS_LOGF_INFO(AWS_LS_IOTDEVICE_SECURE_TUNNELING, "task_cancelled is true. Cleaning up ping task.");
        aws_mem_release(ping_task_context->allocator, ping_task_context);
        return;
    }

    s_send_websocket_ping(ping_task_context->websocket, ping_task_context->send_frame);

    /* Schedule the next task */
    uint64_t now;
    aws_event_loop_current_clock_time(ping_task_context->event_loop, &now);
    aws_event_loop_schedule_task_future(ping_task_context->event_loop, task, now + PING_TASK_INTERVAL);
}

static void s_on_websocket_setup(
    struct aws_websocket *websocket,
    int error_code,
    int handshake_response_status,
    const struct aws_http_header *handshake_response_header_array,
    size_t num_handshake_response_headers,
    void *user_data) {

    UNUSED(handshake_response_status);
    UNUSED(handshake_response_header_array);
    UNUSED(num_handshake_response_headers);

    /* Setup callback contract is: if error_code is non-zero then websocket is NULL. */
    AWS_FATAL_ASSERT((error_code != 0) == (websocket == NULL));

    struct aws_secure_tunnel *secure_tunnel = user_data;
    aws_http_message_release(secure_tunnel->handshake_request);
    secure_tunnel->handshake_request = NULL;

    secure_tunnel->connection_error_code = error_code;
    secure_tunnel->options->on_connection_complete(secure_tunnel->options->user_data);

    if (websocket) {
        secure_tunnel->websocket = websocket;
        struct ping_task_context *ping_task_context =
            aws_mem_acquire(secure_tunnel->alloc, sizeof(struct ping_task_context));
        secure_tunnel->ping_task_context = ping_task_context;
        AWS_ZERO_STRUCT(*ping_task_context);
        ping_task_context->allocator = secure_tunnel->alloc;
        ping_task_context->event_loop =
            aws_event_loop_group_get_next_loop(secure_tunnel->options->bootstrap->event_loop_group);
        aws_atomic_store_int(&ping_task_context->task_cancelled, 0);
        ping_task_context->websocket = websocket;
        ping_task_context->send_frame = secure_tunnel->websocket_vtable.send_frame;

        aws_task_init(&ping_task_context->ping_task, s_ping_task, ping_task_context, "SecureTunnelingPingTask");
        aws_event_loop_schedule_task_now(ping_task_context->event_loop, &ping_task_context->ping_task);
    }
}

static void s_on_websocket_shutdown(struct aws_websocket *websocket, int error_code, void *user_data) {
    UNUSED(websocket);
    UNUSED(error_code);

    struct aws_secure_tunnel *secure_tunnel = user_data;
    aws_atomic_store_int(&secure_tunnel->ping_task_context->task_cancelled, 1);
    secure_tunnel->ping_task_context->websocket = NULL;
    secure_tunnel->options->on_connection_shutdown(secure_tunnel->options->user_data);
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
    if (secure_tunnel->options->local_proxy_mode == AWS_SECURE_TUNNELING_SOURCE_MODE) {
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
        secure_tunnel->options->on_stream_start(secure_tunnel->options->user_data);
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

    secure_tunnel->options->on_stream_reset(secure_tunnel->options->user_data);
    s_reset_secure_tunnel(secure_tunnel);
}

static void s_handle_session_reset(struct aws_secure_tunnel *secure_tunnel) {
    if (secure_tunnel->stream_id == INVALID_STREAM_ID) { /* Session reset does not need to check stream id */
        return;
    }

    secure_tunnel->options->on_session_reset(secure_tunnel->options->user_data);
    s_reset_secure_tunnel(secure_tunnel);
}

static void s_process_iot_st_msg(struct aws_secure_tunnel *secure_tunnel, struct aws_iot_st_msg *st_msg) {
    /* TODO: Check stream_id, send reset? */

    switch (st_msg->type) {
        case DATA:
            secure_tunnel->options->on_data_receive(&st_msg->payload, secure_tunnel->options->user_data);
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
        aws_iot_st_msg_deserialize_from_cursor(&st_msg, &st_frame, secure_tunnel->alloc);
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
        s_get_proxy_mode_string(secure_tunnel->options->local_proxy_mode));
    struct aws_http_message *handshake_request = aws_http_message_new_websocket_handshake_request(
        secure_tunnel->alloc, aws_byte_cursor_from_c_str(path), secure_tunnel->options->endpoint_host);

    struct aws_http_header extra_headers[] = {
        {
            .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("Sec-WebSocket-Protocol"),
            .value = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("aws.iot.securetunneling-1.0"),
        },
        {
            .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("access-token"),
            .value = secure_tunnel->options->access_token,
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
    websocket_options->allocator = secure_tunnel->alloc;
    websocket_options->bootstrap = secure_tunnel->options->bootstrap;
    websocket_options->socket_options = secure_tunnel->options->socket_options;
    websocket_options->tls_options = &secure_tunnel->tls_con_opt;
    websocket_options->host = secure_tunnel->options->endpoint_host;
    websocket_options->port = 443;
    websocket_options->handshake_request = s_new_handshake_request(secure_tunnel);
    websocket_options->initial_window_size = MAX_WEBSOCKET_PAYLOAD; /* TODO: followup */
    websocket_options->user_data = secure_tunnel;
    websocket_options->proxy_options = secure_tunnel->options->http_proxy_options;
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
    if (secure_tunnel->websocket_vtable.client_connect(&websocket_options)) {
        return AWS_OP_ERR;
    }

    return AWS_OP_SUCCESS;
}

static int s_secure_tunneling_close(struct aws_secure_tunnel *secure_tunnel) {
    if (secure_tunnel == NULL) {
        return AWS_OP_ERR;
    }

    s_reset_secure_tunnel(secure_tunnel);
    if (secure_tunnel->websocket != NULL) {
        secure_tunnel->websocket_vtable.close(secure_tunnel->websocket, false);
        secure_tunnel->websocket_vtable.release(secure_tunnel->websocket);
        secure_tunnel->websocket = NULL;
    }
    return AWS_OP_SUCCESS;
}

static void s_secure_tunneling_on_send_data_complete_callback(
    struct aws_websocket *websocket,
    int error_code,
    void *user_data) {
    UNUSED(websocket);
    struct data_tunnel_pair *pair = user_data;
    struct aws_secure_tunnel *secure_tunnel = (struct aws_secure_tunnel *)pair->secure_tunnel;
    secure_tunnel->options->on_send_data_complete(error_code, pair->secure_tunnel->options->user_data);
    aws_byte_buf_clean_up(&pair->buf);
    aws_mem_release(secure_tunnel->alloc, pair);
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
    if (aws_iot_st_msg_serialize_from_struct(&pair->buf, secure_tunnel->alloc, message) != AWS_OP_SUCCESS) {
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
    aws_mem_release(pair->secure_tunnel->alloc, (void *)pair);
    return AWS_OP_ERR;
}

int secure_tunneling_init_send_frame(
    struct aws_websocket_send_frame_options *frame_options,
    struct aws_secure_tunnel *secure_tunnel,
    const struct aws_byte_cursor *data,
    enum aws_iot_st_message_type type) {
    struct data_tunnel_pair *pair =
        (struct data_tunnel_pair *)aws_mem_acquire(secure_tunnel->alloc, sizeof(struct data_tunnel_pair));
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
    return secure_tunnel->websocket_vtable.send_frame(secure_tunnel->websocket, &frame_options);
}

static int s_secure_tunneling_send_data(struct aws_secure_tunnel *secure_tunnel, const struct aws_byte_cursor *data) {
    if (secure_tunnel->stream_id == INVALID_STREAM_ID) {
        AWS_LOGF_ERROR(AWS_LS_IOTDEVICE_SECURE_TUNNELING, "Invalid Stream Id");
        return AWS_ERROR_IOTDEVICE_SECUTRE_TUNNELING_INVALID_STREAM;
    }
    struct aws_byte_cursor new_data = *data;
    while (new_data.len) {
        size_t bytes_max = new_data.len;
        size_t amount_to_send = bytes_max < AWS_IOT_ST_SPLIT_MESSAGE_SIZE ? bytes_max : AWS_IOT_ST_SPLIT_MESSAGE_SIZE;

        struct aws_byte_cursor send_cursor = aws_byte_cursor_advance(&new_data, amount_to_send);
        AWS_FATAL_ASSERT(send_cursor.len > 0);
        if (send_cursor.len) {
            if (s_secure_tunneling_send(secure_tunnel, &send_cursor, DATA) != AWS_OP_SUCCESS) {
                AWS_LOGF_ERROR(AWS_LS_IOTDEVICE_SECURE_TUNNELING, "Failure writing data to out_buf");
                return AWS_OP_ERR;
            }
        }
    }
    return AWS_OP_SUCCESS;
}

static int s_secure_tunneling_send_stream_start(struct aws_secure_tunnel *secure_tunnel) {
    if (secure_tunnel->options->local_proxy_mode == AWS_SECURE_TUNNELING_DESTINATION_MODE) {
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

static void s_secure_tunnel_destroy(void *user_data);

struct aws_secure_tunnel *aws_secure_tunnel_new(const struct aws_secure_tunnel_options *options) {

    struct aws_tls_ctx_options tls_ctx_opt;
    AWS_ZERO_STRUCT(tls_ctx_opt);

    struct aws_secure_tunnel *secure_tunnel = aws_mem_calloc(options->allocator, 1, sizeof(struct aws_secure_tunnel));
    secure_tunnel->alloc = options->allocator;
    aws_ref_count_init(&secure_tunnel->ref_count, secure_tunnel, s_secure_tunnel_destroy);

    /* store options */
    secure_tunnel->options_storage = aws_secure_tunnel_options_storage_new(options);
    if (secure_tunnel->options_storage == NULL) {
        goto error;
    }
    secure_tunnel->options = &secure_tunnel->options_storage->options;

    /* tls_ctx */
    aws_tls_ctx_options_init_default_client(&tls_ctx_opt, options->allocator);

    if (options->root_ca != NULL) {
        if (aws_tls_ctx_options_override_default_trust_store_from_path(&tls_ctx_opt, NULL, options->root_ca)) {
            goto error;
        }
    }

    secure_tunnel->tls_ctx = aws_tls_client_ctx_new(options->allocator, &tls_ctx_opt);
    if (secure_tunnel->tls_ctx == NULL) {
        goto error;
    }

    /* tls_connection_options */
    aws_tls_connection_options_init_from_ctx(&secure_tunnel->tls_con_opt, secure_tunnel->tls_ctx);
    if (aws_tls_connection_options_set_server_name(
            &secure_tunnel->tls_con_opt, options->allocator, (struct aws_byte_cursor *)&options->endpoint_host)) {
        goto error;
    }

    aws_tls_ctx_options_clean_up(&tls_ctx_opt);

    /* Setup vtables here. */
    secure_tunnel->vtable.connect = s_secure_tunneling_connect;
    secure_tunnel->vtable.close = s_secure_tunneling_close;
    secure_tunnel->vtable.send_data = s_secure_tunneling_send_data;
    secure_tunnel->vtable.send_stream_start = s_secure_tunneling_send_stream_start;
    secure_tunnel->vtable.send_stream_reset = s_secure_tunneling_send_stream_reset;

    secure_tunnel->websocket_vtable.client_connect = aws_websocket_client_connect;
    secure_tunnel->websocket_vtable.send_frame = aws_websocket_send_frame;
    secure_tunnel->websocket_vtable.close = aws_websocket_close;
    secure_tunnel->websocket_vtable.release = aws_websocket_release;

    secure_tunnel->handshake_request = NULL;
    secure_tunnel->stream_id = INVALID_STREAM_ID;
    secure_tunnel->websocket = NULL;

    /* TODO: Release this buffer when there is no data to hold */
    aws_byte_buf_init(&secure_tunnel->received_data, options->allocator, MAX_WEBSOCKET_PAYLOAD);

    return secure_tunnel;

error:
    aws_tls_ctx_options_clean_up(&tls_ctx_opt);
    aws_secure_tunnel_release(secure_tunnel);
    return NULL;
}

struct aws_secure_tunnel *aws_secure_tunnel_acquire(struct aws_secure_tunnel *secure_tunnel) {
    aws_ref_count_acquire(&secure_tunnel->ref_count);
    return secure_tunnel;
}

void aws_secure_tunnel_release(struct aws_secure_tunnel *secure_tunnel) {
    if (secure_tunnel == NULL) {
        return;
    }
    aws_ref_count_release(&secure_tunnel->ref_count);
}

static void s_secure_tunnel_destroy(void *user_data) {
    struct aws_secure_tunnel *secure_tunnel = user_data;

    aws_secure_tunneling_on_termination_complete_fn *on_termination_complete = NULL;
    void *termination_complete_user_data = NULL;
    if (secure_tunnel->options != NULL) {
        on_termination_complete = secure_tunnel->options->on_termination_complete;
        termination_complete_user_data = secure_tunnel->options->user_data;
    }

    aws_secure_tunnel_options_storage_destroy(secure_tunnel->options_storage);
    aws_byte_buf_clean_up(&secure_tunnel->received_data);
    aws_tls_connection_options_clean_up(&secure_tunnel->tls_con_opt);
    aws_tls_ctx_release(secure_tunnel->tls_ctx);
    aws_mem_release(secure_tunnel->alloc, secure_tunnel);

    if (on_termination_complete != NULL) {
        (*on_termination_complete)(termination_complete_user_data);
    }
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
