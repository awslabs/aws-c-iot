#include <aws/iotdevice/secure_tunneling.h>

#include <aws/http/request_response.h>
#include <aws/http/websocket.h>

/* TODO: Remove me */
#define UNUSED(x) (void)(x)

/* Only one active secure tunnel is supported */
static int32_t s_active_stream_id = -1;
static struct aws_websocket *s_active_websocket = NULL;

struct aws_secure_tunneling_connection_ctx {
    struct aws_allocator *allocator;
    struct aws_http_message *handshake_request;
    aws_secure_tunneling_on_connection_complete_fn *on_connection_complete;
};

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

    const struct aws_secure_tunneling_connection_ctx *connection_ctx = user_data;
    aws_http_message_release(connection_ctx->handshake_request);

    s_active_stream_id++;
    s_active_websocket = websocket;
    connection_ctx->on_connection_complete(s_active_stream_id);

    aws_mem_release(connection_ctx->allocator, (void *)connection_ctx);
}

static void s_on_websocket_shutdown(struct aws_websocket *websocket, int error_code, void *user_data) {
    UNUSED(websocket);
    UNUSED(error_code);
    UNUSED(user_data);
}

static const char *s_get_proxy_mode_string(enum aws_secure_tunneling_local_proxy_mode local_proxy_mode) {
    if (local_proxy_mode == AWS_SECURE_TUNNELING_SOURCE_MODE) {
        return "source";
    } else {
        return "destination";
    }
}

static struct aws_http_message *s_new_handshake_request(
    const struct aws_secure_tunneling_connection_config *connection_config) {
    struct aws_byte_buf path;
    aws_byte_buf_init(&path, connection_config->allocator, 50);
    snprintf(
        (char *)path.buffer,
        path.capacity,
        "/tunnel?local-proxy-mode=%s",
        s_get_proxy_mode_string(connection_config->local_proxy_mode));

    struct aws_http_message *handshake_request = aws_http_message_new_websocket_handshake_request(
        connection_config->allocator, aws_byte_cursor_from_buf(&path), connection_config->endpoint_host);

    aws_byte_buf_clean_up(&path);

    struct aws_http_header extra_headers[] = {
        {
            .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("Sec-WebSocket-Protocol"),
            .value = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("aws.iot.securetunneling-1.0"),
        },
        {
            .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("access-token"),
            .value = connection_config->access_token,
        },
    };
    for (size_t i = 0; i < AWS_ARRAY_SIZE(extra_headers); ++i) {
        aws_http_message_add_header(handshake_request, extra_headers[i]);
    }

    return handshake_request;
}

static void s_init_websocket_client_connection_options(
    const struct aws_secure_tunneling_connection_config *connection_config,
    struct aws_websocket_client_connection_options *websocket_options) {

    websocket_options->allocator = connection_config->allocator;
    websocket_options->bootstrap = connection_config->bootstrap;
    websocket_options->socket_options = connection_config->socket_options;
    websocket_options->host = connection_config->endpoint_host;
    websocket_options->handshake_request = s_new_handshake_request(connection_config);
    websocket_options->initial_window_size = AWS_WEBSOCKET_MAX_PAYLOAD_LENGTH; /* TODO: followup */

    struct aws_secure_tunneling_connection_ctx *connection_ctx =
        aws_mem_acquire(connection_config->allocator, sizeof(struct aws_secure_tunneling_connection_ctx));
    connection_ctx->allocator = connection_config->allocator;
    connection_ctx->handshake_request = websocket_options->handshake_request;
    connection_ctx->on_connection_complete = connection_config->on_connection_complete;
    websocket_options->user_data = connection_ctx;

    websocket_options->on_connection_setup = s_on_websocket_setup;
    websocket_options->on_connection_shutdown = s_on_websocket_shutdown;
    // websocket_options->on_incoming_frame_begin
    // websocket_options->on_incoming_frame_payload
    // websocket_options->on_incoming_frame_complete
    websocket_options->manual_window_management = false;
}

int aws_secure_tunneling_connect(const struct aws_secure_tunneling_connection_config *connection_config) {
    struct aws_websocket_client_connection_options websocket_options;
    s_init_websocket_client_connection_options(connection_config, &websocket_options);
    if (aws_websocket_client_connect(&websocket_options)) {
        return AWS_OP_ERR;
    }

    return AWS_OP_SUCCESS;
}

static bool s_is_active_stream(int32_t stream_id) {
    return stream_id == s_active_stream_id;
}

int aws_secure_tunneling_close(int32_t stream_id) {
    if (s_is_active_stream(stream_id)) {
        return AWS_OP_ERR;
    }

    s_active_stream_id = -1;
    aws_websocket_release(s_active_websocket);
    s_active_websocket = NULL;
    return AWS_OP_SUCCESS;
}
