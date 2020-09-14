#include <aws/iotdevice/secure_tunneling.h>
#include <aws/http/websocket.h>

/*
 * Connection
 */
static int s_active_stream_id = -1;

static void s_on_websocket_setup(
    struct aws_websocket *websocket,
    int error_code,
    int handshake_response_status,
    const struct aws_http_header *handshake_response_header_array,
    size_t num_handshake_response_headers,
    void *user_data) {

    const struct aws_secure_tunneling_connection_config *config = user_data;

    s_active_stream_id++;
    config->on_connection_complete(s_active_stream_id);
}

static void s_on_websocket_shutdown(struct aws_websocket *websocket, int error_code, void *user_data) {

}

static void s_init_websocket_client_connection_options(
    const struct aws_secure_tunneling_connection_config *config,
    struct aws_websocket_client_connection_options *websocket_options) {

    /* TODO: populate websocket_options */
    websocket_options->allocator = config->allocator;
    // websocket_options->bootstrap
    // websocket_options->socket_options
    websocket_options->host = config->endpoint_host;

    struct aws_byte_cursor path = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("/"); /* TODO: What is the path? */
    websocket_options->handshake_request = aws_http_message_new_websocket_handshake_request(
        config->allocator,
        path,
        config->endpoint_host);

    // websocket_options->initial_window_size
    websocket_options->user_data = (struct aws_secure_tunneling_connection_config*) config;
    websocket_options->on_connection_setup = s_on_websocket_setup;
    websocket_options->on_connection_shutdown = s_on_websocket_shutdown;
    // websocket_options->on_incoming_frame_begin
    // websocket_options->on_incoming_frame_payload
    // websocket_options->on_incoming_frame_complete
    websocket_options->manual_window_management = false;
}

/* TODO: tag with some API? */
int aws_secure_tunneling_connect(const struct aws_secure_tunneling_connection_config *config) {
    struct aws_websocket_client_connection_options websocket_options;
    s_init_websocket_client_connection_options(config, &websocket_options);

    if (aws_websocket_client_connect(&websocket_options)) {

    }

    return 0;
}

int aws_secure_tunneling_close(int32_t stream_id) {
    return 0;
}
