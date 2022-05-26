/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/common/allocator.h>
#include <aws/common/byte_buf.h>
#include <aws/common/device_random.h>
#include <aws/common/error.h>
#include <aws/common/string.h>
#include <aws/common/zero.h>
#include <aws/http/http.h>
#include <aws/http/request_response.h>
#include <aws/http/websocket.h>
#include <aws/io/channel_bootstrap.h>
#include <aws/io/event_loop.h>
#include <aws/io/host_resolver.h>
#include <aws/io/socket.h>
#include <aws/iotdevice/iotdevice.h>
#include <aws/iotdevice/private/iotdevice_internals.h>
#include <aws/iotdevice/private/secure_tunneling_impl.h>
#include <aws/iotdevice/private/serializer.h>
#include <aws/iotdevice/secure_tunneling.h>
#include <aws/testing/aws_test_harness.h>

#include <stdint.h>

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
    uint16_t max_threads;
    struct aws_event_loop_group *elg;
    struct aws_host_resolver *resolver;
    struct aws_client_bootstrap *bootstrap;
    struct aws_secure_tunnel *secure_tunnel;
};
static struct secure_tunneling_test_context s_test_context = {.max_threads = 1};

/* Dummy websocket for unit test only. */
struct aws_websocket {};
static struct aws_websocket s_aws_websocket;

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
    struct aws_secure_tunnel_options *options) {

    AWS_ZERO_STRUCT(*options);
    options->allocator = allocator;
    options->bootstrap = bootstrap;
    options->socket_options = socket_options;

    options->access_token = aws_byte_cursor_from_c_str(access_token);
    options->local_proxy_mode = local_proxy_mode;
    options->endpoint_host = aws_byte_cursor_from_c_str(endpoint);

    options->on_stream_start = s_on_stream_start;
    options->on_data_receive = s_on_data_receive;
    options->on_stream_reset = s_on_stream_reset;
    options->on_session_reset = s_on_session_reset;
    /* TODO: Initialize the rest of the callbacks */
}

/*
 * Mock aws websocket api used by the secure tunnel.
 */

int s_mock_aws_websocket_client_connect(const struct aws_websocket_client_connection_options *options) {
    UNUSED(options);
    return AWS_OP_SUCCESS;
}

static size_t s_mock_aws_websocket_send_frame_call_count = 0U;

static size_t s_mock_aws_websocket_send_frame_payload_len = 0U;

int s_mock_aws_websocket_send_frame(
    struct aws_websocket *websocket,
    const struct aws_websocket_send_frame_options *options) {
    UNUSED(websocket);
    ++s_mock_aws_websocket_send_frame_call_count;

    struct data_tunnel_pair *pair = (struct data_tunnel_pair *)options->user_data;
    struct aws_byte_buf *buf = &pair->buf;
    struct aws_byte_cursor cursor = aws_byte_cursor_from_buf(buf);

    /* Deserialize the wire format to obtain original payload. */
    struct aws_iot_st_msg message;
    int rc = aws_iot_st_msg_deserialize_from_cursor(&message, &cursor, s_test_context.secure_tunnel->alloc);
    ASSERT_INT_EQUALS(AWS_OP_SUCCESS, rc);
    s_mock_aws_websocket_send_frame_payload_len += message.payload.len;
    aws_byte_buf_clean_up(&message.payload);

    /* Deallocate memory for the buffer holding the wire protocol data and the tunnel context. */
    aws_byte_buf_clean_up(buf);
    aws_mem_release(s_test_context.secure_tunnel->alloc, pair);

    return AWS_OP_SUCCESS;
}

void s_mock_aws_websocket_close(struct aws_websocket *websocket, bool free_scarce_resources_immediately) {
    UNUSED(websocket);
    UNUSED(free_scarce_resources_immediately);
}

void s_mock_aws_websocket_release(struct aws_websocket *websocket) {
    UNUSED(websocket);
    /* Release the handshake_request. In a non-mocked context this would occur after handshake completes. */
    aws_http_message_release(s_test_context.secure_tunnel->handshake_request);
}

/* s_secure_tunnel_new_mock returns a secure_tunnel that mocks the aws websocket public api. */
static struct aws_secure_tunnel *s_secure_tunnel_new_mock(const struct aws_secure_tunnel_options *options) {
    struct aws_secure_tunnel *secure_tunnel = aws_secure_tunnel_new(options);
    if (!secure_tunnel) {
        return secure_tunnel;
    }
    secure_tunnel->websocket_vtable.client_connect = s_mock_aws_websocket_client_connect;
    secure_tunnel->websocket_vtable.send_frame = s_mock_aws_websocket_send_frame;
    secure_tunnel->websocket_vtable.close = s_mock_aws_websocket_close;
    secure_tunnel->websocket_vtable.release = s_mock_aws_websocket_release;

    /*
     * Initialize a dummy websocket when the tunnel is created.
     *
     * In the non-mock implementation this websocket would be initialized when
     * an http upgrade request is received sometime after the tunnel is created.
     *
     * Since no http request is exercised by these tests we initialize a dummy
     * websocket as soon as the tunnel is created.
     */
    secure_tunnel->websocket = &s_aws_websocket;

    return secure_tunnel;
}

static int before(struct aws_allocator *allocator, void *ctx) {
    struct secure_tunneling_test_context *test_context = ctx;

    /* Initialize aws-c-http and aws-c-iot libraries. */
    aws_http_library_init(allocator);
    aws_iotdevice_library_init(allocator);

    /* Initialize event loop. */
    test_context->elg = aws_event_loop_group_new_default(allocator, test_context->max_threads, NULL);

    /* Initialize dns resolver. */
    struct aws_host_resolver_default_options host_resolver_default_options;
    AWS_ZERO_STRUCT(host_resolver_default_options);
    host_resolver_default_options.max_entries = 8;
    host_resolver_default_options.el_group = test_context->elg;
    host_resolver_default_options.shutdown_options = NULL;
    host_resolver_default_options.system_clock_override_fn = NULL;
    test_context->resolver = aws_host_resolver_new_default(allocator, &host_resolver_default_options);

    /* Initialize client_bootstrap with event loop and dns resolver. */
    struct aws_client_bootstrap_options bootstrap_options = {
        .event_loop_group = test_context->elg,
        .host_resolver = test_context->resolver,
    };
    test_context->bootstrap = aws_client_bootstrap_new(allocator, &bootstrap_options);

    /* Initialize socket_options for secure tunnel. */
    struct aws_socket_options socket_options;
    AWS_ZERO_STRUCT(socket_options);

    /* Initialize secure_tunnel_options with client_bootstrap. */
    struct aws_secure_tunnel_options options;
    s_init_secure_tunneling_connection_config(
        allocator,
        test_context->bootstrap,
        &socket_options,
        ACCESS_TOKEN,
        test_context->local_proxy_mode,
        ENDPOINT,
        &options);

    /* Initialize secure_tunnel. */
    test_context->secure_tunnel = s_secure_tunnel_new_mock(&options);
    ASSERT_NOT_NULL(test_context->secure_tunnel);

    return AWS_OP_SUCCESS;
}

static int after(struct aws_allocator *allocator, int setup_result, void *ctx) {
    UNUSED(allocator);
    UNUSED(setup_result);

    struct secure_tunneling_test_context *test_context = ctx;

    aws_host_resolver_release(test_context->resolver);
    aws_event_loop_group_release(test_context->elg);
    aws_client_bootstrap_release(test_context->bootstrap);

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
    /*
     * The public api used to send data over a secure tunnel is aws_secure_tunnel_send_data.
     *
     * 1/ The public api accepts an aws_byte_cursor and logically splits this cursor into smaller
     *    nonoverlapping cursors aka frames using the private secure_tunneling_init_send_frame function.
     *
     * 2/ Each frame is written to the websocket connection using the public api aws_websocket_send_frame.
     *    The websocket api pushes the frame on a fifo queue of frames managed by the event loop.
     *    The event loop thread pops frames from the queue and writes the data to the websocket connection.
     *
     * The function implemented below differs from the public api in some important ways.
     *
     * 1/ This function frames a aws_byte_cursor by calling the private api secure_tunneling_init_send_frame.
     *    As a result, this function does not exercise the logic in the public api aws_secure_tunnel_send_data
     *    to split the input cursor into multiple frames.
     *
     * 2/ This function does not exercise any of the websocket api. Instead this function calls a private api
     *    secure_tunneling_send_data_call with the websocket set to NULL.  Instead of queueing frames, this
     *    api writes frames to a second buffer in the websocket wire protocol format. The test compares the
     *    second buffer to what is expected from the wire format.  In the public api, the functionality to
     *    write the frame in the websocket wire protocol format is invoked as a callback from the event loop.
     *
     * To summarize, the test below has value, but such value is limited by carefully avoiding the public
     * api to send data over a secure tunnel.  A separate group of tests are required to more directly
     * exercise the public api.
     *
     */

    struct aws_iot_st_msg message;
    message.type = type;
    message.stream_id = expected_stream_id;
    message.ignorable = 0;
    message.payload = aws_byte_buf_from_c_str(expected_payload);
    struct aws_byte_buf serialized_st_msg;
    aws_iot_st_msg_serialize_from_struct(&serialized_st_msg, test_context->secure_tunnel->options->allocator, message);

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
            &out_buf, test_context->secure_tunnel->options->allocator, (size_t)frame_options.payload_length));

    ASSERT_TRUE(secure_tunneling_send_data_call(NULL, &out_buf, frame_options.user_data));
    struct aws_byte_cursor out_buf_cur = aws_byte_cursor_from_buf(&out_buf);

    ASSERT_UINT_EQUALS(out_buf_cur.len - prefix_bytes, serialized_st_msg.len);

    uint16_t payload_prefixed_length;
    aws_byte_cursor_read_be16(&out_buf_cur, &payload_prefixed_length);
    ASSERT_UINT_EQUALS((uint16_t)serialized_st_msg.len, payload_prefixed_length);
    ASSERT_BIN_ARRAYS_EQUALS(serialized_st_msg.buffer, serialized_st_msg.len, out_buf_cur.ptr, out_buf_cur.len);

    struct data_tunnel_pair *pair = frame_options.user_data;
    aws_byte_buf_clean_up(&pair->buf);
    aws_mem_release(pair->secure_tunnel->options->allocator, (void *)pair);
    aws_byte_buf_clean_up(&serialized_st_msg);
    aws_byte_buf_clean_up(&out_buf);

    return AWS_OP_SUCCESS;
}

static int s_byte_buf_init_rand(struct aws_byte_buf *buf, struct aws_allocator *allocator, size_t capacity) {
    int rc = aws_byte_buf_init(buf, allocator, capacity);
    if (rc != AWS_OP_SUCCESS) {
        return rc;
    }
    return aws_device_random_buffer(buf);
}

AWS_TEST_CASE_FIXTURE(
    secure_tunneling_handle_stream_start_test,
    before,
    s_secure_tunneling_handle_stream_start_test,
    after,
    &s_test_context);
static int s_secure_tunneling_handle_stream_start_test(struct aws_allocator *allocator, void *ctx) {
    /*
     * When secure tunnel running in destination mode receives a StreamStart message,
     * verify the stream start callback is invoked and that the stream ID is parsed from the message.
     */

    struct secure_tunneling_test_context *test_context = ctx;
    test_context->secure_tunnel->options->local_proxy_mode = AWS_SECURE_TUNNELING_DESTINATION_MODE;

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
    /*
     * When secure tunnel running in destination mode receives a Data message,
     * verify the data callback is invoked with matching message payload.
     */

    struct secure_tunneling_test_context *test_context = ctx;
    test_context->secure_tunnel->options->local_proxy_mode = AWS_SECURE_TUNNELING_DESTINATION_MODE;

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
    /*
     * When secure tunnel running in destination mode receives a StreamReset message,
     * verify the stream reset callback is invoked and the stream ID is unset.
     */

    struct secure_tunneling_test_context *test_context = ctx;
    test_context->secure_tunnel->options->local_proxy_mode = AWS_SECURE_TUNNELING_DESTINATION_MODE;

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
    /*
     * When secure tunnel running in destination mode receives a SessionReset message with a valid stream ID,
     * verify the session reset callback is invoked and the stream ID is unset.
     */

    struct secure_tunneling_test_context *test_context = ctx;
    test_context->secure_tunnel->options->local_proxy_mode = AWS_SECURE_TUNNELING_DESTINATION_MODE;

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
    secure_tunneling_handle_session_reset_no_stream_test,
    before,
    s_secure_tunneling_handle_session_reset_no_stream_test,
    after,
    &s_test_context);
static int s_secure_tunneling_handle_session_reset_no_stream_test(struct aws_allocator *allocator, void *ctx) {
    /*
     * When secure tunnel running in destination mode receives a SessionReset message without valid stream ID,
     * verify the session reset callback is not invoked.
     */

    struct secure_tunneling_test_context *test_context = ctx;
    test_context->secure_tunnel->options->local_proxy_mode = AWS_SECURE_TUNNELING_DESTINATION_MODE;

    /* Send StreamReset without existing stream */
    struct aws_iot_st_msg st_msg;
    AWS_ZERO_STRUCT(st_msg);
    st_msg.type = SESSION_RESET;
    s_on_session_reset_called = false;
    s_send_secure_tunneling_frame_to_websocket(&st_msg, allocator, test_context->secure_tunnel);

    ASSERT_FALSE(s_on_session_reset_called);
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
    /*
     * When a client connects to a websocket server,
     * verify the client handshake includes the aws secure tunneling protocol string and access token
     * provided by the secure tunneling service when the tunnel is provisioned.
     */

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
    const char *expected_headers[][2] = {
        {"Sec-WebSocket-Protocol", "aws.iot.securetunneling-1.0"},
        {"access-token", ACCESS_TOKEN},
    };

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
    /*
     * When a secure tunnel running in source mode sends data to destination,
     * verify the data are written to the tunnel in the expected websocket wire protocol format.
     */

    UNUSED(allocator);
    const char *expected_payload = "Hi! I'm Paul / Some random payload\n";
    const int32_t expected_stream_id = 1;
    const int prefix_bytes = 2;
    const enum aws_iot_st_message_type type = DATA;

    struct secure_tunneling_test_context *test_context = ctx;
    test_context->secure_tunnel->options->local_proxy_mode = AWS_SECURE_TUNNELING_SOURCE_MODE;
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
    /*
     * When a secure tunnel running in source mode sends StreamStart to destination,
     * verify the data are written to the tunnel in the expected websocket wire protocol format.
     */

    UNUSED(allocator);
    const char *expected_payload = "";
    const int32_t expected_stream_id = 1;
    const int prefix_bytes = 2;
    const enum aws_iot_st_message_type type = STREAM_START;

    struct secure_tunneling_test_context *test_context = ctx;
    test_context->secure_tunnel->options->local_proxy_mode = AWS_SECURE_TUNNELING_SOURCE_MODE;
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
    /*
     * When a secure tunnel running in source mode sends StreamReset to destination,
     * verify the data are written to the tunnel in the expected websocket wire protocol format.
     */

    UNUSED(allocator);
    const char *expected_payload = "";
    const int32_t expected_stream_id = 1;
    const int prefix_bytes = 2;
    const enum aws_iot_st_message_type type = STREAM_RESET;

    struct secure_tunneling_test_context *test_context = ctx;
    test_context->secure_tunnel->options->local_proxy_mode = AWS_SECURE_TUNNELING_SOURCE_MODE;
    test_context->secure_tunnel->stream_id = expected_stream_id;

    s_test_sent_data(test_context, expected_payload, expected_stream_id, prefix_bytes, type);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE_FIXTURE(
    secure_tunneling_handle_send_data_public,
    before,
    s_secure_tunneling_handle_send_data_public,
    after,
    &s_test_context);
static int s_secure_tunneling_handle_send_data_public(struct aws_allocator *allocator, void *ctx) {
    /*
     * When a secure tunnel running in source mode sends data to destination using the public api,
     * verify that the payload length matches what the client sends and the number of frames sent
     * is equal to size of the payload divided by the maximum frame length.
     */

    struct secure_tunneling_test_context *test_context = ctx;
    test_context->secure_tunnel->options->local_proxy_mode = AWS_SECURE_TUNNELING_SOURCE_MODE;

    /* Open the tunnel. */
    int rc = aws_secure_tunnel_connect(test_context->secure_tunnel);
    ASSERT_INT_EQUALS(AWS_OP_SUCCESS, rc);

    size_t buf_sizes[] = {10, 100, 1000, AWS_IOT_ST_SPLIT_MESSAGE_SIZE + 1, 2 * AWS_IOT_ST_SPLIT_MESSAGE_SIZE + 1};
    size_t buf_sizes_len = sizeof(buf_sizes) / sizeof(buf_sizes[0]);

    for (size_t i = 0; i < buf_sizes_len; ++i) {
        /* Start a stream. */
        s_mock_aws_websocket_send_frame_call_count = 0U;
        s_mock_aws_websocket_send_frame_payload_len = 0U;
        rc = aws_secure_tunnel_stream_start(test_context->secure_tunnel);
        ASSERT_INT_EQUALS(AWS_OP_SUCCESS, rc);
        ASSERT_UINT_EQUALS(1U, s_mock_aws_websocket_send_frame_call_count);
        ASSERT_UINT_EQUALS(0U, s_mock_aws_websocket_send_frame_payload_len);

        /* Initialize buffer of random values to send. */
        struct aws_byte_buf buf;
        rc = s_byte_buf_init_rand(&buf, allocator, buf_sizes[i]);
        ASSERT_INT_EQUALS(AWS_OP_SUCCESS, rc);

        struct aws_byte_cursor cur = aws_byte_cursor_from_buf(&buf);

        /* Call public api to send data over secure tunnel. */
        s_mock_aws_websocket_send_frame_call_count = 0U;
        s_mock_aws_websocket_send_frame_payload_len = 0U;
        rc = aws_secure_tunnel_send_data(test_context->secure_tunnel, &cur);
        ASSERT_INT_EQUALS(AWS_OP_SUCCESS, rc);
        int expected_call_count = (int)buf_sizes[i] / AWS_IOT_ST_SPLIT_MESSAGE_SIZE + 1;
        ASSERT_UINT_EQUALS(expected_call_count, s_mock_aws_websocket_send_frame_call_count);
        ASSERT_UINT_EQUALS(buf_sizes[i], s_mock_aws_websocket_send_frame_payload_len);

        /* Free buffer. */
        aws_byte_buf_clean_up(&buf);
    }

    /* Close the tunnel. */
    aws_secure_tunnel_close(test_context->secure_tunnel);

    return AWS_OP_SUCCESS;
}
