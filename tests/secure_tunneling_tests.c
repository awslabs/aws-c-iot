#include <aws/common/string.h>
#include <aws/common/zero.h>
#include <aws/http/http.h>
#include <aws/http/request_response.h>
#include <aws/http/websocket.h>
#include <aws/io/channel_bootstrap.h>
#include <aws/io/event_loop.h>
#include <aws/io/socket.h>
#include <aws/iotdevice/iotdevice.h>
#include <aws/iotdevice/private/iotdevice_internals.h>
#include <aws/iotdevice/private/serializer.h>
#include <aws/iotdevice/secure_tunneling.h>
#include <aws/testing/aws_test_harness.h>

#define UNUSED(x) (void)(x)

#define INVALID_STREAM_ID 0
#define STREAM_ID 10
#define ACCESS_TOKEN "my_super_secret_access_token"
#define ENDPOINT "data.tunneling.iot.us-west-2.amazonaws.com"
#define PAYLOAD "secure tunneling data payload"

/*
 * The tests here call these functions directly.
 */

struct secure_tunneling_test_context {
    enum aws_secure_tunneling_local_proxy_mode local_proxy_mode;
    struct aws_secure_tunnel *secure_tunnel;
};
static struct secure_tunneling_test_context s_test_context = {0};

static bool s_on_stream_start_called = false;
static void s_on_stream_start(void *user_data) {
    UNUSED(user_data);
    s_on_stream_start_called = true;
}

static bool s_on_data_receive_correct_payload = false;
static void s_on_data_receive(const struct aws_byte_buf *data, void *user_data) {
    UNUSED(user_data);
    s_on_data_receive_correct_payload = aws_byte_buf_eq_c_str(data, PAYLOAD);
}

static bool s_on_stream_reset_called = false;
static void s_on_stream_reset(void *user_data) {
    UNUSED(user_data);
    s_on_stream_reset_called = true;
}

static bool s_on_session_reset_called = false;
static void s_on_session_reset(void *user_data) {
    UNUSED(user_data);
    s_on_session_reset_called = true;
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
    config->on_data_receive = s_on_data_receive;
    config->on_stream_reset = s_on_stream_reset;
    config->on_session_reset = s_on_session_reset;
    /* TODO: Initialize the rest of the callbacks */
}

static int before(struct aws_allocator *allocator, void *ctx) {
    struct secure_tunneling_test_context *test_context = ctx;

    aws_http_library_init(allocator);
    aws_iotdevice_library_init(allocator);

    struct aws_event_loop_group *elg = aws_event_loop_group_new_default(allocator, 1, NULL);
    struct aws_host_resolver_default_options host_resolver_default_options;
    AWS_ZERO_STRUCT(host_resolver_default_options);
    host_resolver_default_options.max_entries = 8;
    host_resolver_default_options.el_group = elg;
    host_resolver_default_options.shutdown_options = NULL;
    host_resolver_default_options.system_clock_override_fn = NULL;
    struct aws_host_resolver *resolver = aws_host_resolver_new_default(allocator, &host_resolver_default_options);
    struct aws_client_bootstrap_options bootstrap_options = {
        .event_loop_group = elg,
        .host_resolver = resolver,
    };
    struct aws_client_bootstrap *bootstrap = aws_client_bootstrap_new(allocator, &bootstrap_options);

    struct aws_secure_tunneling_connection_config config;
    s_init_secure_tunneling_connection_config(
        allocator, bootstrap, NULL, ACCESS_TOKEN, test_context->local_proxy_mode, ENDPOINT, &config);

    test_context->secure_tunnel = aws_secure_tunnel_new(&config);

    return AWS_OP_SUCCESS;
}

static int after(struct aws_allocator *allocator, int setup_result, void *ctx) {
    UNUSED(allocator);
    UNUSED(setup_result);

    struct secure_tunneling_test_context *test_context = ctx;

    aws_host_resolver_release(test_context->secure_tunnel->config.bootstrap->host_resolver);
    aws_event_loop_group_release(test_context->secure_tunnel->config.bootstrap->event_loop_group);
    aws_client_bootstrap_release(test_context->secure_tunnel->config.bootstrap);

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

    struct aws_iot_st_msg message;
    message.type = type;
    message.stream_id = expected_stream_id;
    message.ignorable = 0;
    message.payload = aws_byte_buf_from_c_str(expected_payload);
    struct aws_byte_buf serialized_st_msg;
    aws_iot_st_msg_serialize_from_struct(&serialized_st_msg, test_context->secure_tunnel->config.allocator, message);

    struct aws_byte_cursor cur = aws_byte_cursor_from_c_str(expected_payload);
    struct aws_websocket_send_frame_options frame_options;
    ASSERT_INT_EQUALS(
        AWS_OP_SUCCESS,
        secure_tunneling_init_send_frame(&frame_options, test_context->secure_tunnel, &cur, message.type));

    ASSERT_INT_EQUALS(serialized_st_msg.len + prefix_bytes, frame_options.payload_length);

    struct aws_byte_buf out_buf;
    ASSERT_INT_EQUALS(
        AWS_OP_SUCCESS,
        aws_byte_buf_init(
            &out_buf, test_context->secure_tunnel->config.allocator, (size_t)frame_options.payload_length));

    ASSERT_TRUE(secure_tunneling_send_data_call(NULL, &out_buf, frame_options.user_data));
    struct aws_byte_cursor out_buf_cur = aws_byte_cursor_from_buf(&out_buf);

    ASSERT_INT_EQUALS(out_buf_cur.len - prefix_bytes, serialized_st_msg.len);

    uint16_t payload_prefixed_length;
    aws_byte_cursor_read_be16(&out_buf_cur, &payload_prefixed_length);
    ASSERT_INT_EQUALS((uint16_t)serialized_st_msg.len, payload_prefixed_length);
    ASSERT_BIN_ARRAYS_EQUALS(serialized_st_msg.buffer, serialized_st_msg.len, out_buf_cur.ptr, out_buf_cur.len);

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
    struct secure_tunneling_test_context *test_context = ctx;
    test_context->secure_tunnel->config.local_proxy_mode = AWS_SECURE_TUNNELING_DESTINATION_MODE;

    struct aws_iot_st_msg st_msg;
    AWS_ZERO_STRUCT(st_msg);
    st_msg.type = STREAM_START;
    st_msg.stream_id = STREAM_ID;
    s_on_stream_start_called = false;
    s_send_secure_tunneling_frame_to_websocket(&st_msg, allocator, test_context->secure_tunnel);

    ASSERT_TRUE(s_on_stream_start_called);
    ASSERT_INT_EQUALS(STREAM_ID, test_context->secure_tunnel->stream_id);
    ASSERT_UINT_EQUALS(0, test_context->secure_tunnel->received_data.len);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE_FIXTURE(
    secure_tunneling_handle_data_receive_test,
    before,
    s_secure_tunneling_handle_data_receive_test,
    after,
    &s_test_context);
static int s_secure_tunneling_handle_data_receive_test(struct aws_allocator *allocator, void *ctx) {
    struct secure_tunneling_test_context *test_context = ctx;
    test_context->secure_tunnel->config.local_proxy_mode = AWS_SECURE_TUNNELING_DESTINATION_MODE;

    /* Send StreamStart first */
    struct aws_iot_st_msg st_msg;
    AWS_ZERO_STRUCT(st_msg);
    st_msg.type = STREAM_START;
    st_msg.stream_id = STREAM_ID;
    s_send_secure_tunneling_frame_to_websocket(&st_msg, allocator, test_context->secure_tunnel);

    /* Send data */
    AWS_ZERO_STRUCT(st_msg);
    st_msg.type = DATA;
    st_msg.stream_id = STREAM_ID;
    st_msg.payload = aws_byte_buf_from_c_str(PAYLOAD);
    s_on_data_receive_correct_payload = false;
    s_send_secure_tunneling_frame_to_websocket(&st_msg, allocator, test_context->secure_tunnel);

    ASSERT_TRUE(s_on_data_receive_correct_payload);
    ASSERT_INT_EQUALS(STREAM_ID, test_context->secure_tunnel->stream_id);
    ASSERT_UINT_EQUALS(0, test_context->secure_tunnel->received_data.len);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE_FIXTURE(
    secure_tunneling_handle_stream_reset_test,
    before,
    s_secure_tunneling_handle_stream_reset_test,
    after,
    &s_test_context);
static int s_secure_tunneling_handle_stream_reset_test(struct aws_allocator *allocator, void *ctx) {
    struct secure_tunneling_test_context *test_context = ctx;
    test_context->secure_tunnel->config.local_proxy_mode = AWS_SECURE_TUNNELING_DESTINATION_MODE;

    /* Send StreamStart first */
    struct aws_iot_st_msg st_msg;
    AWS_ZERO_STRUCT(st_msg);
    st_msg.type = STREAM_START;
    st_msg.stream_id = STREAM_ID;
    s_send_secure_tunneling_frame_to_websocket(&st_msg, allocator, test_context->secure_tunnel);

    /* Send StreamReset */
    AWS_ZERO_STRUCT(st_msg);
    st_msg.type = STREAM_RESET;
    st_msg.stream_id = STREAM_ID;
    s_on_stream_reset_called = false;
    s_send_secure_tunneling_frame_to_websocket(&st_msg, allocator, test_context->secure_tunnel);

    ASSERT_TRUE(s_on_stream_reset_called);
    ASSERT_INT_EQUALS(INVALID_STREAM_ID, test_context->secure_tunnel->stream_id);
    ASSERT_UINT_EQUALS(0, test_context->secure_tunnel->received_data.len);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE_FIXTURE(
    secure_tunneling_handle_session_reset_test,
    before,
    s_secure_tunneling_handle_session_reset_test,
    after,
    &s_test_context);
static int s_secure_tunneling_handle_session_reset_test(struct aws_allocator *allocator, void *ctx) {
    struct secure_tunneling_test_context *test_context = ctx;
    test_context->secure_tunnel->config.local_proxy_mode = AWS_SECURE_TUNNELING_DESTINATION_MODE;

    /* Send StreamStart first */
    struct aws_iot_st_msg st_msg;
    AWS_ZERO_STRUCT(st_msg);
    st_msg.type = STREAM_START;
    st_msg.stream_id = STREAM_ID;
    s_send_secure_tunneling_frame_to_websocket(&st_msg, allocator, test_context->secure_tunnel);

    /* Send StreamReset */
    AWS_ZERO_STRUCT(st_msg);
    st_msg.type = SESSION_RESET;
    st_msg.stream_id = STREAM_ID;
    s_on_session_reset_called = false;
    s_send_secure_tunneling_frame_to_websocket(&st_msg, allocator, test_context->secure_tunnel);

    ASSERT_TRUE(s_on_session_reset_called);
    ASSERT_INT_EQUALS(INVALID_STREAM_ID, test_context->secure_tunnel->stream_id);
    ASSERT_UINT_EQUALS(0, test_context->secure_tunnel->received_data.len);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE_FIXTURE(
    secure_tunneling_init_websocket_options_test,
    before,
    s_secure_tunneling_init_websocket_options_test,
    after,
    &s_test_context);
static int s_secure_tunneling_init_websocket_options_test(struct aws_allocator *allocator, void *ctx) {
    UNUSED(allocator);

    struct secure_tunneling_test_context *test_context = ctx;

    struct aws_websocket_client_connection_options websocket_options;
    init_websocket_client_connection_options(test_context->secure_tunnel, &websocket_options);

    ASSERT_TRUE(aws_byte_cursor_eq_c_str(&websocket_options.host, ENDPOINT));

    /*
     * Verify handshake request
     */

    ASSERT_TRUE(aws_http_message_is_request(websocket_options.handshake_request));

    struct aws_byte_cursor method;
    aws_http_message_get_request_method(websocket_options.handshake_request, &method);
    ASSERT_TRUE(aws_byte_cursor_eq_c_str(&method, "GET"));

    /* Verify path */
    struct aws_byte_cursor path;
    aws_http_message_get_request_path(websocket_options.handshake_request, &path);
    ASSERT_TRUE(aws_byte_cursor_eq_c_str(&path, "/tunnel?local-proxy-mode=source"));

    /* Verify headers */
    const char *expected_headers[][2] = {{"Sec-WebSocket-Protocol", "aws.iot.securetunneling-1.0"},
					 {"access-token", ACCESS_TOKEN}};

    const struct aws_http_headers *headers = aws_http_message_get_const_headers(websocket_options.handshake_request);
    for (size_t i = 0; i < sizeof(expected_headers) / sizeof(expected_headers[0]); i++) {
        struct aws_byte_cursor name = aws_byte_cursor_from_c_str(expected_headers[i][0]);
        struct aws_byte_cursor value;
        ASSERT_INT_EQUALS(AWS_OP_SUCCESS, aws_http_headers_get(headers, name, &value));
        ASSERT_TRUE(aws_byte_cursor_eq_c_str(&value, expected_headers[i][1]));
    }

    aws_http_message_release(websocket_options.handshake_request);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE_FIXTURE(
    secure_tunneling_handle_send_data,
    before,
    s_secure_tunneling_handle_send_data,
    after,
    &s_test_context);
static int s_secure_tunneling_handle_send_data(struct aws_allocator *allocator, void *ctx) {
    UNUSED(allocator);
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
    UNUSED(allocator);
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
    UNUSED(allocator);
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
