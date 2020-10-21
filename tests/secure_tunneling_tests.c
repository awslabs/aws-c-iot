#include <aws/common/zero.h>
#include <aws/http/http.h>
#include <aws/io/channel_bootstrap.h>
#include <aws/io/event_loop.h>
#include <aws/io/socket.h>
#include <aws/iotdevice/iotdevice.h>
#include <aws/iotdevice/private/serializer.h>
#include <aws/iotdevice/secure_tunneling.h>
#include <aws/testing/aws_test_harness.h>

#define UNUSED(x) (void)(x)

#define ACCESS_TOKEN "access_token"
#define ENDPOINT "data.tunneling.iot.us-west-2.amazonaws.com"

/* Callback when websocket gets data. The tests here are calling this function directly. */
struct aws_websocket_incoming_frame;
extern bool on_websocket_incoming_frame_payload(
    struct aws_websocket *websocket,
    const struct aws_websocket_incoming_frame *frame,
    struct aws_byte_cursor data,
    void *user_data);

struct secure_tunneling_test_context {
    enum aws_secure_tunneling_local_proxy_mode local_proxy_mode;
    struct aws_secure_tunnel *secure_tunnel;
};
static struct secure_tunneling_test_context s_test_context = {0};

static bool s_on_stream_start_called = false;
static void s_on_stream_start(const struct aws_secure_tunnel *secure_tunnel) {
    UNUSED(secure_tunnel);
    s_on_stream_start_called = true;
}

static void s_init_secure_tunneling_connection_config(
    struct aws_allocator *allocator,
    struct aws_client_bootstrap *bootstrap,
    struct aws_socket_options *socket_options,
    const char *access_token,
    enum aws_secure_tunneling_local_proxy_mode local_proxy_mode,
    const char *endpoint,
    struct aws_secure_tunneling_connection_config *config) {

    AWS_ZERO_STRUCT(*config);
    config->allocator = allocator;
    config->bootstrap = bootstrap;
    config->socket_options = socket_options;

    config->access_token = aws_byte_cursor_from_c_str(access_token);
    config->local_proxy_mode = local_proxy_mode;
    config->endpoint_host = aws_byte_cursor_from_c_str(endpoint);

    config->on_stream_start = s_on_stream_start;
    /* TODO: Initialize the rest of the callbacks */
}

static int before(struct aws_allocator *allocator, void *ctx) {
    struct secure_tunneling_test_context *test_context = ctx;

    aws_http_library_init(allocator);
    aws_iotdevice_library_init(allocator);

    struct aws_secure_tunneling_connection_config config;
    s_init_secure_tunneling_connection_config(
        allocator, NULL, NULL, ACCESS_TOKEN, test_context->local_proxy_mode, ENDPOINT, &config);

    test_context->secure_tunnel = aws_secure_tunnel_new(&config);

    return AWS_OP_SUCCESS;
}

static int after(struct aws_allocator *allocator, int setup_result, void *ctx) {
    UNUSED(allocator);
    UNUSED(setup_result);

    struct secure_tunneling_test_context *test_context = ctx;

    aws_secure_tunnel_release(test_context->secure_tunnel);
    aws_iotdevice_library_clean_up();
    aws_http_library_clean_up();

    return AWS_OP_SUCCESS;
}

static void s_send_secure_tunneling_frame_to_websocket(
    const struct aws_iot_st_msg *st_msg,
    struct aws_allocator *allocator,
    struct aws_secure_tunnel *secure_tunnel) {

    struct aws_byte_buf serialized_st_msg;
    aws_iot_st_msg_serialize_from_struct(&serialized_st_msg, allocator, *st_msg);

    /* Prepend 2 bytes length */
    struct aws_byte_buf websocket_frame;
    aws_byte_buf_init(&websocket_frame, allocator, serialized_st_msg.len + 2);
    aws_byte_buf_write_be16(&websocket_frame, (uint16_t)serialized_st_msg.len);
    struct aws_byte_cursor c = aws_byte_cursor_from_buf(&serialized_st_msg);
    aws_byte_buf_append(&websocket_frame, &c);
    c = aws_byte_cursor_from_buf(&websocket_frame);

    on_websocket_incoming_frame_payload(NULL, NULL, c, secure_tunnel);

    aws_byte_buf_clean_up(&serialized_st_msg);
    aws_byte_buf_clean_up(&websocket_frame);
}

AWS_TEST_CASE_FIXTURE(
    secure_tunneling_handle_stream_start_test,
    before,
    s_secure_tunneling_handle_stream_start_test,
    after,
    &s_test_context);
static int s_secure_tunneling_handle_stream_start_test(struct aws_allocator *allocator, void *ctx) {
    const int32_t expected_stream_id = 10;

    struct secure_tunneling_test_context *test_context = ctx;
    test_context->secure_tunnel->config.local_proxy_mode = AWS_SECURE_TUNNELING_DESTINATION_MODE;

    s_on_stream_start_called = false;

    struct aws_iot_st_msg st_msg;
    AWS_ZERO_STRUCT(st_msg);
    st_msg.type = STREAM_START;
    st_msg.streamId = expected_stream_id;
    s_send_secure_tunneling_frame_to_websocket(&st_msg, allocator, test_context->secure_tunnel);

    ASSERT_TRUE(s_on_stream_start_called);
    ASSERT_INT_EQUALS(expected_stream_id, test_context->secure_tunnel->stream_id);

    return AWS_OP_SUCCESS;
}
