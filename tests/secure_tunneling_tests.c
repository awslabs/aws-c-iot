#include <aws/common/zero.h>
#include <aws/http/http.h>
#include <aws/http/websocket.h>
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

extern int secure_tunneling_init_send_frame(
    struct aws_websocket_send_frame_options *frame_options,
    struct aws_secure_tunnel *secure_tunnel,
    const struct aws_byte_cursor *data,
    enum aws_iot_st_message_type type);

extern bool secure_tunneling_send_data_call(
    struct aws_websocket *websocket,
    struct aws_byte_buf *out_buf,
    void *user_data);

extern void secure_tunneling_on_send_data_complete_callback(
    struct aws_websocket *websocket,
    int error_code,
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

static int s_test_sent_data(
    struct secure_tunneling_test_context *test_context,
    const char *expected_payload,
    const int32_t expected_stream_id,
    const int prefix_bytes,
    const enum aws_iot_st_message_type type) {

    struct aws_iot_st_msg c_message;
    c_message.type = type;
    c_message.streamId = expected_stream_id;
    c_message.ignorable = 0;
    c_message.payload = aws_byte_buf_from_c_str(expected_payload);
    struct aws_byte_buf serialized_st_msg;
    aws_iot_st_msg_serialize_from_struct(&serialized_st_msg, test_context->secure_tunnel->config.allocator, c_message);

    struct aws_byte_cursor cur = aws_byte_cursor_from_c_str(expected_payload);
    struct aws_websocket_send_frame_options frame_options;
    ASSERT_INT_EQUALS(
        secure_tunneling_init_send_frame(&frame_options, test_context->secure_tunnel, &cur, c_message.type),
        AWS_OP_SUCCESS);

    ASSERT_INT_EQUALS(frame_options.payload_length, serialized_st_msg.len + prefix_bytes);

    struct aws_byte_buf out_buf;
    ASSERT_INT_EQUALS(
        aws_byte_buf_init(&out_buf, test_context->secure_tunnel->config.allocator, frame_options.payload_length),
        AWS_OP_SUCCESS);

    ASSERT_INT_EQUALS(secure_tunneling_send_data_call(NULL, &out_buf, frame_options.user_data), true);
    struct aws_byte_cursor out_buf_cur = aws_byte_cursor_from_buf(&out_buf);

    ASSERT_INT_EQUALS(out_buf_cur.len - prefix_bytes, serialized_st_msg.len);

    uint16_t payload_prefixed_length;
    aws_byte_cursor_read_be16(&out_buf_cur, &payload_prefixed_length);
    ASSERT_INT_EQUALS(payload_prefixed_length, (uint16_t)serialized_st_msg.len);
    for (size_t i = 0; i < out_buf_cur.len; i++) {
        ASSERT_INT_EQUALS(out_buf_cur.ptr[i], serialized_st_msg.buffer[i]);
    }

    struct data_tunnel_pair *pair = frame_options.user_data;
    aws_byte_buf_clean_up(&pair->buf);
    aws_mem_release(pair->secure_tunnel->config.allocator, (void *)pair);
    aws_byte_buf_clean_up(&serialized_st_msg);
    aws_byte_buf_clean_up(&out_buf);

    return AWS_OP_SUCCESS;
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

AWS_TEST_CASE_FIXTURE(
    secure_tunneling_handle_send_data,
    before,
    s_secure_tunneling_handle_send_data,
    after,
    &s_test_context);
static int s_secure_tunneling_handle_send_data(struct aws_allocator *allocator, void *ctx) {
    const char *expected_payload = "Hi! I'm Paul / Some random payload\n";
    const int32_t expected_stream_id = 1;
    const int prefix_bytes = 2;
    const enum aws_iot_st_message_type type = DATA;

    struct secure_tunneling_test_context *test_context = ctx;
    test_context->secure_tunnel->config.local_proxy_mode = AWS_SECURE_TUNNELING_SOURCE_MODE;
    test_context->secure_tunnel->stream_id = expected_stream_id;

    s_test_sent_data(test_context, expected_payload, expected_stream_id, prefix_bytes, type);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE_FIXTURE(
    secure_tunneling_handle_send_data_stream_start,
    before,
    s_secure_tunneling_handle_send_data_stream_start,
    after,
    &s_test_context);
static int s_secure_tunneling_handle_send_data_stream_start(struct aws_allocator *allocator, void *ctx) {
    const char *expected_payload = "";
    const int32_t expected_stream_id = 1;
    const int prefix_bytes = 2;
    const enum aws_iot_st_message_type type = STREAM_START;

    struct secure_tunneling_test_context *test_context = ctx;
    test_context->secure_tunnel->config.local_proxy_mode = AWS_SECURE_TUNNELING_SOURCE_MODE;
    test_context->secure_tunnel->stream_id = expected_stream_id;

    s_test_sent_data(test_context, expected_payload, expected_stream_id, prefix_bytes, type);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE_FIXTURE(
    secure_tunneling_handle_send_data_stream_reset,
    before,
    s_secure_tunneling_handle_send_data_stream_reset,
    after,
    &s_test_context);
static int s_secure_tunneling_handle_send_data_stream_reset(struct aws_allocator *allocator, void *ctx) {
    const char *expected_payload = "";
    const int32_t expected_stream_id = 1;
    const int prefix_bytes = 2;
    const enum aws_iot_st_message_type type = STREAM_RESET;

    struct secure_tunneling_test_context *test_context = ctx;
    test_context->secure_tunnel->config.local_proxy_mode = AWS_SECURE_TUNNELING_SOURCE_MODE;
    test_context->secure_tunnel->stream_id = expected_stream_id;

    s_test_sent_data(test_context, expected_payload, expected_stream_id, prefix_bytes, type);

    return AWS_OP_SUCCESS;
}
