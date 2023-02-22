/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/common/allocator.h>
#include <aws/common/byte_buf.h>
#include <aws/common/clock.h>
#include <aws/common/error.h>
#include <aws/common/string.h>
#include <aws/http/websocket.h>
#include <aws/io/channel_bootstrap.h>
#include <aws/io/event_loop.h>
#include <aws/io/host_resolver.h>
#include <aws/io/socket.h>
#include <aws/iotdevice/iotdevice.h>
#include <aws/iotdevice/private/secure_tunneling_impl.h>
#include <aws/iotdevice/private/secure_tunneling_operations.h>
#include <aws/iotdevice/private/serializer.h>
#include <aws/iotdevice/secure_tunneling.h>
#include <aws/testing/aws_test_harness.h>
#include <stdint.h>

#define PAYLOAD_BYTE_LENGTH_PREFIX 2
AWS_STATIC_STRING_FROM_LITERAL(s_access_token, "IAmAnAccessToken");
AWS_STATIC_STRING_FROM_LITERAL(s_client_token, "IAmAClientToken");
AWS_STATIC_STRING_FROM_LITERAL(s_endpoint_host, "IAmAnEndpointHost");
AWS_STATIC_STRING_FROM_LITERAL(s_service_id_1, "ServiceId1");
AWS_STATIC_STRING_FROM_LITERAL(s_service_id_2, "ServiceId2");
AWS_STATIC_STRING_FROM_LITERAL(s_service_id_3, "ServiceId3");
AWS_STATIC_STRING_FROM_LITERAL(s_service_id_wrong, "ServiceIdWrong");
AWS_STATIC_STRING_FROM_LITERAL(s_payload_text, "IAmABunchOfPayloadText");

#ifdef _WIN32
#    define LOCAL_SOCK_TEST_PATTERN "\\\\.\\pipe\\testsock%llu"
#else
#    define LOCAL_SOCK_TEST_PATTERN "testsock%llu.sock"
#endif

struct aws_secure_tunnel_mock_websocket_vtable {
    aws_websocket_on_connection_setup_fn *on_connection_setup_fn;
    aws_websocket_on_connection_shutdown_fn *on_connection_shutdown_fn;
    aws_websocket_on_incoming_frame_begin_fn *on_incoming_frame_begin_fn;
    aws_websocket_on_incoming_frame_payload_fn *on_incoming_frame_payload_fn;
    aws_websocket_on_incoming_frame_complete_fn *on_incoming_frame_complete_fn;
};

struct aws_secure_tunnel_mock_test_fixture_options {
    struct aws_secure_tunnel_options *secure_tunnel_options;
    struct aws_secure_tunnel_mock_websocket_vtable *websocket_function_table;

    void *mock_server_user_data;
};

struct secure_tunnel_test_options {
    struct aws_secure_tunnel_options secure_tunnel_options;
    struct aws_secure_tunnel_mock_websocket_vtable websocket_function_table;
};

static void s_secure_tunnel_test_init_default_options(struct secure_tunnel_test_options *test_options) {
    struct aws_secure_tunnel_options local_secure_tunnel_options = {
        .endpoint_host = aws_byte_cursor_from_string(s_endpoint_host),
        .access_token = aws_byte_cursor_from_string(s_access_token),
        .local_proxy_mode = AWS_SECURE_TUNNELING_DESTINATION_MODE,
    };
    test_options->secure_tunnel_options = local_secure_tunnel_options;
}

typedef int(aws_secure_tunnel_mock_test_fixture_header_check_fn)(
    const struct aws_http_headers *request_headers,
    void *user_data);

struct aws_secure_tunnel_mock_test_fixture {
    struct aws_allocator *allocator;

    struct aws_event_loop_group *secure_tunnel_elg;
    struct aws_host_resolver *host_resolver;
    struct aws_client_bootstrap *secure_tunnel_bootstrap;
    struct aws_socket_endpoint endpoint;
    struct aws_socket_options socket_options;

    struct aws_secure_tunnel_mock_websocket_vtable *websocket_function_table;
    void *mock_server_user_data;

    struct aws_secure_tunnel *secure_tunnel;
    struct aws_secure_tunnel_vtable secure_tunnel_vtable;

    aws_secure_tunnel_mock_test_fixture_header_check_fn *header_check;

    struct aws_mutex lock;
    struct aws_condition_variable signal;
    bool listener_destroyed;
    bool secure_tunnel_terminated;
    bool secure_tunnel_connected_succesfully;
    bool secure_tunnel_connection_shutdown;
    bool secure_tunnel_connection_failed;
    bool secure_tunnel_stream_started;
    bool secure_tunnel_bad_stream_request;
    bool secure_tunnel_stream_reset_received;
    bool secure_tunnel_session_reset_received;

    struct aws_byte_buf last_message_payload_buf;

    int secure_tunnel_message_received_count;
    int secure_tunnel_stream_started_count;
    int secure_tunnel_stream_started_count_target;
    int secure_tunnel_message_count_target;
};

/*****************************************************************************************************************
 *                                    SECURE TUNNEL CALLBACKS
 *****************************************************************************************************************/

static void s_on_test_secure_tunnel_connection_complete(
    const struct aws_secure_tunnel_connection_view *connection_view,
    int error_code,
    void *user_data) {
    struct aws_secure_tunnel_mock_test_fixture *test_fixture = user_data;

    aws_mutex_lock(&test_fixture->lock);
    if (error_code == 0) {
        test_fixture->secure_tunnel_connected_succesfully = true;
    } else {
        test_fixture->secure_tunnel_connection_failed = true;
    }
    aws_mutex_unlock(&test_fixture->lock);
    aws_condition_variable_notify_all(&test_fixture->signal);
}

static void s_on_test_secure_tunnel_connection_shutdown(int error_code, void *user_data) {
    struct aws_secure_tunnel_mock_test_fixture *test_fixture = user_data;

    aws_mutex_lock(&test_fixture->lock);
    test_fixture->secure_tunnel_connection_shutdown = true;
    aws_mutex_unlock(&test_fixture->lock);
    aws_condition_variable_notify_all(&test_fixture->signal);
}

static void s_on_test_secure_tunnel_message_received(
    const struct aws_secure_tunnel_message_view *message,
    void *user_data) {
    struct aws_secure_tunnel_mock_test_fixture *test_fixture = user_data;
    aws_mutex_lock(&test_fixture->lock);
    test_fixture->secure_tunnel_message_received_count++;
    aws_byte_buf_clean_up(&test_fixture->last_message_payload_buf);
    aws_byte_buf_init(&test_fixture->last_message_payload_buf, test_fixture->allocator, message->payload->len);
    struct aws_byte_cursor payload_cur = {
        .ptr = message->payload->ptr,
        .len = message->payload->len,
    };
    aws_byte_buf_write_from_whole_cursor(&test_fixture->last_message_payload_buf, payload_cur);
    aws_mutex_unlock(&test_fixture->lock);
    aws_condition_variable_notify_all(&test_fixture->signal);
}

static void s_on_test_secure_tunnel_send_data_complete(int error_code, void *user_data) {
    (void)error_code;
    (void)user_data;
}

static void s_on_test_secure_tunnel_on_session_reset(void *user_data) {
    struct aws_secure_tunnel_mock_test_fixture *test_fixture = user_data;

    aws_mutex_lock(&test_fixture->lock);
    test_fixture->secure_tunnel_session_reset_received = true;
    aws_mutex_unlock(&test_fixture->lock);
    aws_condition_variable_notify_all(&test_fixture->signal);
}

static void s_on_test_secure_tunnel_on_stopped(void *user_data) {
    (void)user_data;
}

static void s_on_test_secure_tunnel_termination(void *user_data) {
    struct aws_secure_tunnel_mock_test_fixture *test_fixture = user_data;

    aws_mutex_lock(&test_fixture->lock);
    test_fixture->secure_tunnel_terminated = true;
    aws_mutex_unlock(&test_fixture->lock);
    aws_condition_variable_notify_all(&test_fixture->signal);
}

static void s_on_test_secure_tunnel_on_stream_reset(
    const struct aws_secure_tunnel_message_view *message,
    int error_code,
    void *user_data) {
    (void)message;
    (void)error_code;

    struct aws_secure_tunnel_mock_test_fixture *test_fixture = user_data;

    aws_mutex_lock(&test_fixture->lock);
    test_fixture->secure_tunnel_stream_reset_received = true;
    aws_mutex_unlock(&test_fixture->lock);
    aws_condition_variable_notify_all(&test_fixture->signal);
}

static void s_on_test_secure_tunnel_on_stream_start(
    const struct aws_secure_tunnel_message_view *message,
    int error_code,
    void *user_data) {
    (void)message;

    struct aws_secure_tunnel_mock_test_fixture *test_fixture = user_data;

    aws_mutex_lock(&test_fixture->lock);
    if (error_code == AWS_OP_SUCCESS) {
        test_fixture->secure_tunnel_stream_started = true;
        test_fixture->secure_tunnel_stream_started_count++;
    } else {
        test_fixture->secure_tunnel_bad_stream_request = true;
    }
    aws_mutex_unlock(&test_fixture->lock);
    aws_condition_variable_notify_all(&test_fixture->signal);
}

/*****************************************************************************************************************
 *                                    SECURE TUNNEL STATUS CHECKS
 *****************************************************************************************************************/

static bool s_has_secure_tunnel_terminated(void *arg) {
    struct aws_secure_tunnel_mock_test_fixture *test_fixture = arg;
    return test_fixture->secure_tunnel_terminated;
}

static void s_wait_for_secure_tunnel_terminated(struct aws_secure_tunnel_mock_test_fixture *test_fixture) {
    aws_mutex_lock(&test_fixture->lock);
    aws_condition_variable_wait_pred(
        &test_fixture->signal, &test_fixture->lock, s_has_secure_tunnel_terminated, test_fixture);
    aws_mutex_unlock(&test_fixture->lock);
}

static bool s_has_secure_tunnel_connected_succesfully(void *arg) {
    struct aws_secure_tunnel_mock_test_fixture *test_fixture = arg;
    return test_fixture->secure_tunnel_connected_succesfully;
}

static void s_wait_for_connected_successfully(struct aws_secure_tunnel_mock_test_fixture *test_fixture) {
    aws_mutex_lock(&test_fixture->lock);
    aws_condition_variable_wait_pred(
        &test_fixture->signal, &test_fixture->lock, s_has_secure_tunnel_connected_succesfully, test_fixture);
    aws_mutex_unlock(&test_fixture->lock);
}

static bool s_has_secure_tunnel_connection_shutdown(void *arg) {
    struct aws_secure_tunnel_mock_test_fixture *test_fixture = arg;
    return test_fixture->secure_tunnel_connection_shutdown;
}

static void s_wait_for_connection_shutdown(struct aws_secure_tunnel_mock_test_fixture *test_fixture) {
    aws_mutex_lock(&test_fixture->lock);
    aws_condition_variable_wait_pred(
        &test_fixture->signal, &test_fixture->lock, s_has_secure_tunnel_connection_shutdown, test_fixture);
    aws_mutex_unlock(&test_fixture->lock);
}

static bool s_has_secure_tunnel_stream_started(void *arg) {
    struct aws_secure_tunnel_mock_test_fixture *test_fixture = arg;
    return test_fixture->secure_tunnel_stream_started;
}

static void s_wait_for_stream_started(struct aws_secure_tunnel_mock_test_fixture *test_fixture) {
    aws_mutex_lock(&test_fixture->lock);
    aws_condition_variable_wait_pred(
        &test_fixture->signal, &test_fixture->lock, s_has_secure_tunnel_stream_started, test_fixture);
    aws_mutex_unlock(&test_fixture->lock);
}

static bool s_has_secure_tunnel_bad_stream_request(void *arg) {
    struct aws_secure_tunnel_mock_test_fixture *test_fixture = arg;
    return test_fixture->secure_tunnel_bad_stream_request;
}

static void s_wait_for_bad_stream_request(struct aws_secure_tunnel_mock_test_fixture *test_fixture) {
    aws_mutex_lock(&test_fixture->lock);
    aws_condition_variable_wait_pred(
        &test_fixture->signal, &test_fixture->lock, s_has_secure_tunnel_bad_stream_request, test_fixture);
    aws_mutex_unlock(&test_fixture->lock);
}

static bool s_has_secure_tunnel_stream_reset_received(void *arg) {
    struct aws_secure_tunnel_mock_test_fixture *test_fixture = arg;
    return test_fixture->secure_tunnel_stream_reset_received;
}

static void s_wait_for_stream_reset_received(struct aws_secure_tunnel_mock_test_fixture *test_fixture) {
    aws_mutex_lock(&test_fixture->lock);
    aws_condition_variable_wait_pred(
        &test_fixture->signal, &test_fixture->lock, s_has_secure_tunnel_stream_reset_received, test_fixture);
    aws_mutex_unlock(&test_fixture->lock);
}

static bool s_has_secure_tunnel_n_stream_started(void *arg) {
    struct aws_secure_tunnel_mock_test_fixture *test_fixture = arg;
    return test_fixture->secure_tunnel_stream_started_count == test_fixture->secure_tunnel_stream_started_count_target;
}

static void s_wait_for_n_stream_started(struct aws_secure_tunnel_mock_test_fixture *test_fixture) {
    aws_mutex_lock(&test_fixture->lock);
    aws_condition_variable_wait_pred(
        &test_fixture->signal, &test_fixture->lock, s_has_secure_tunnel_n_stream_started, test_fixture);
    aws_mutex_unlock(&test_fixture->lock);
}

static bool s_has_secure_tunnel_session_reset_received(void *arg) {
    struct aws_secure_tunnel_mock_test_fixture *test_fixture = arg;
    return test_fixture->secure_tunnel_session_reset_received;
}

static void s_wait_for_session_reset_received(struct aws_secure_tunnel_mock_test_fixture *test_fixture) {
    aws_mutex_lock(&test_fixture->lock);
    aws_condition_variable_wait_pred(
        &test_fixture->signal, &test_fixture->lock, s_has_secure_tunnel_session_reset_received, test_fixture);
    aws_mutex_unlock(&test_fixture->lock);
}

static bool s_has_secure_tunnel_n_messages_received(void *arg) {
    struct aws_secure_tunnel_mock_test_fixture *test_fixture = arg;
    return test_fixture->secure_tunnel_stream_started_count == test_fixture->secure_tunnel_message_count_target;
}

static void s_wait_for_n_messages_received(struct aws_secure_tunnel_mock_test_fixture *test_fixture) {
    aws_mutex_lock(&test_fixture->lock);
    aws_condition_variable_wait_pred(
        &test_fixture->signal, &test_fixture->lock, s_has_secure_tunnel_n_messages_received, test_fixture);
    aws_mutex_unlock(&test_fixture->lock);
}

/*****************************************************************************************************************
 *                                    WEBSOCKET MOCK FUNCTIONS
 *****************************************************************************************************************/

/* Serializes message view and sends as Websocket */
void aws_secure_tunnel_send_mock_message(
    struct aws_secure_tunnel_mock_test_fixture *test_fixture,
    const struct aws_secure_tunnel_message_view *message_view) {

    struct aws_byte_buf data_buf;
    struct aws_byte_cursor data_cur;
    struct aws_byte_buf out_buf;
    aws_iot_st_msg_serialize_from_view(&data_buf, test_fixture->allocator, message_view);
    data_cur = aws_byte_cursor_from_buf(&data_buf);
    aws_byte_buf_init(&out_buf, test_fixture->allocator, data_cur.len + PAYLOAD_BYTE_LENGTH_PREFIX);
    aws_byte_buf_write_be16(&out_buf, (int16_t)data_buf.len);
    aws_byte_buf_write_to_capacity(&out_buf, &data_cur);
    data_cur = aws_byte_cursor_from_buf(&out_buf);
    test_fixture->websocket_function_table->on_incoming_frame_payload_fn(
        NULL, NULL, data_cur, test_fixture->secure_tunnel);

    aws_byte_buf_clean_up(&out_buf);
    aws_byte_buf_clean_up(&data_buf);
}

int aws_websocket_client_connect_mock_fn(const struct aws_websocket_client_connection_options *options) {
    struct aws_secure_tunnel *secure_tunnel = options->user_data;
    struct aws_secure_tunnel_mock_test_fixture *test_fixture = secure_tunnel->config->user_data;

    if (!options->handshake_request) {
        AWS_LOGF_ERROR(
            AWS_LS_HTTP_WEBSOCKET_SETUP,
            "id=static: Invalid connection options, missing required request for websocket client handshake.");
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }

    const struct aws_http_headers *request_headers = aws_http_message_get_headers(options->handshake_request);
    if (test_fixture->header_check) {
        ASSERT_SUCCESS(test_fixture->header_check(request_headers, test_fixture));
    }

    test_fixture->websocket_function_table->on_connection_setup_fn = options->on_connection_setup;
    test_fixture->websocket_function_table->on_connection_shutdown_fn = options->on_connection_shutdown;
    test_fixture->websocket_function_table->on_incoming_frame_begin_fn = options->on_incoming_frame_begin;
    test_fixture->websocket_function_table->on_incoming_frame_payload_fn = options->on_incoming_frame_payload;
    test_fixture->websocket_function_table->on_incoming_frame_complete_fn = options->on_incoming_frame_complete;

    void *pointer = test_fixture;
    struct aws_websocket_on_connection_setup_data websocket_setup = {.error_code = AWS_ERROR_SUCCESS,
                                                                     .websocket = pointer};

    (test_fixture->websocket_function_table->on_connection_setup_fn)(&websocket_setup, secure_tunnel);

    struct aws_byte_cursor service_1 = aws_byte_cursor_from_string(s_service_id_1);
    struct aws_byte_cursor service_2 = aws_byte_cursor_from_string(s_service_id_2);
    struct aws_byte_cursor service_3 = aws_byte_cursor_from_string(s_service_id_3);

    struct aws_secure_tunnel_message_view service_ids_message = {
        .type = AWS_SECURE_TUNNEL_MT_SERVICE_IDS,
        .service_id = &service_1,
        .service_id_2 = &service_2,
        .service_id_3 = &service_3,
    };

    aws_secure_tunnel_send_mock_message(test_fixture, &service_ids_message);

    return AWS_OP_SUCCESS;
}

int aws_websocket_send_frame_mock_fn(
    struct aws_websocket *websocket,
    const struct aws_websocket_send_frame_options *options) {
    (void)websocket;
    (void)options;
    return AWS_OP_SUCCESS;
}

void aws_websocket_release_mock_fn(struct aws_websocket *websocket) {
    (void)websocket;
}

void aws_websocket_close_mock_fn(struct aws_websocket *websocket, bool free_scarce_resources_immediately) {
    void *pointer = websocket;
    struct aws_secure_tunnel_mock_test_fixture *test_fixture = pointer;
    test_fixture->websocket_function_table->on_connection_shutdown_fn(websocket, 0, test_fixture->secure_tunnel);
}

/*****************************************************************************************************************
 *                                    TEST FIXTURE
 *****************************************************************************************************************/

int aws_secure_tunnel_mock_test_fixture_init(
    struct aws_secure_tunnel_mock_test_fixture *test_fixture,
    struct aws_allocator *allocator,
    struct aws_secure_tunnel_mock_test_fixture_options *options) {

    AWS_ZERO_STRUCT(*test_fixture);
    test_fixture->allocator = allocator;

    aws_mutex_init(&test_fixture->lock);
    aws_condition_variable_init(&test_fixture->signal);

    test_fixture->websocket_function_table = options->websocket_function_table;
    test_fixture->mock_server_user_data = options->mock_server_user_data;

    struct aws_socket_options socket_options = {
        .connect_timeout_ms = 1000,
        .domain = AWS_SOCKET_LOCAL,
    };

    test_fixture->socket_options = socket_options;

    test_fixture->secure_tunnel_elg = aws_event_loop_group_new_default(allocator, 4, NULL);
    struct aws_host_resolver_default_options resolver_options = {
        .el_group = test_fixture->secure_tunnel_elg,
        .max_entries = 1,
    };
    test_fixture->host_resolver = aws_host_resolver_new_default(allocator, &resolver_options);

    struct aws_client_bootstrap_options bootstrap_options = {
        .event_loop_group = test_fixture->secure_tunnel_elg,
        .user_data = test_fixture,
        .host_resolver = test_fixture->host_resolver,
    };

    test_fixture->secure_tunnel_bootstrap = aws_client_bootstrap_new(allocator, &bootstrap_options);

    uint64_t timestamp = 0;
    ASSERT_SUCCESS(aws_sys_clock_get_ticks(&timestamp));

    snprintf(
        test_fixture->endpoint.address,
        sizeof(test_fixture->endpoint.address),
        LOCAL_SOCK_TEST_PATTERN,
        (long long unsigned)timestamp);

    options->secure_tunnel_options->endpoint_host = aws_byte_cursor_from_c_str(test_fixture->endpoint.address);
    options->secure_tunnel_options->bootstrap = test_fixture->secure_tunnel_bootstrap;
    options->secure_tunnel_options->socket_options = &test_fixture->socket_options;
    options->secure_tunnel_options->access_token = aws_byte_cursor_from_string(s_access_token);
    options->secure_tunnel_options->user_data = test_fixture;

    /* Secure Tunnel Callbacks */
    options->secure_tunnel_options->on_connection_complete = s_on_test_secure_tunnel_connection_complete;
    options->secure_tunnel_options->on_connection_shutdown = s_on_test_secure_tunnel_connection_shutdown;
    options->secure_tunnel_options->on_message_received = s_on_test_secure_tunnel_message_received;
    options->secure_tunnel_options->on_send_data_complete = s_on_test_secure_tunnel_send_data_complete;
    options->secure_tunnel_options->on_session_reset = s_on_test_secure_tunnel_on_session_reset;
    options->secure_tunnel_options->on_stopped = s_on_test_secure_tunnel_on_stopped;
    options->secure_tunnel_options->on_stream_reset = s_on_test_secure_tunnel_on_stream_reset;
    options->secure_tunnel_options->on_stream_start = s_on_test_secure_tunnel_on_stream_start;
    options->secure_tunnel_options->on_termination_complete = s_on_test_secure_tunnel_termination;
    options->secure_tunnel_options->secure_tunnel_on_termination_user_data = test_fixture;

    test_fixture->secure_tunnel = aws_secure_tunnel_new(allocator, options->secure_tunnel_options);

    /* Replace Secure Tunnel's vtable functions */
    test_fixture->secure_tunnel_vtable = *aws_secure_tunnel_get_default_vtable();
    test_fixture->secure_tunnel_vtable.aws_websocket_client_connect_fn = aws_websocket_client_connect_mock_fn;
    test_fixture->secure_tunnel_vtable.aws_websocket_send_frame_fn = aws_websocket_send_frame_mock_fn;
    test_fixture->secure_tunnel_vtable.aws_websocket_release_fn = aws_websocket_release_mock_fn;
    test_fixture->secure_tunnel_vtable.aws_websocket_close_fn = aws_websocket_close_mock_fn;
    test_fixture->secure_tunnel_vtable.vtable_user_data = test_fixture;

    aws_secure_tunnel_set_vtable(test_fixture->secure_tunnel, &test_fixture->secure_tunnel_vtable);

    return AWS_OP_SUCCESS;
}

void aws_secure_tunnel_mock_test_fixture_clean_up(struct aws_secure_tunnel_mock_test_fixture *test_fixture) {
    s_wait_for_secure_tunnel_terminated(test_fixture);
    aws_client_bootstrap_release(test_fixture->secure_tunnel_bootstrap);
    aws_host_resolver_release(test_fixture->host_resolver);

    aws_event_loop_group_release(test_fixture->secure_tunnel_elg);

    aws_byte_buf_clean_up(&test_fixture->last_message_payload_buf);
    aws_mutex_clean_up(&test_fixture->lock);
    aws_condition_variable_clean_up(&test_fixture->signal);
}

/*********************************************************************************************************************
 * TESTS
 ********************************************************************************************************************/

/* [Func-UC1] */
int secure_tunneling_access_token_check(const struct aws_http_headers *request_headers, void *user_data) {
    struct aws_byte_cursor access_token_cur;
    if (aws_http_headers_get(request_headers, aws_byte_cursor_from_c_str("access-token"), &access_token_cur)) {
        AWS_LOGF_ERROR(
            AWS_LS_HTTP_WEBSOCKET_SETUP,
            "id=static: Websocket handshake request is missing required 'access-token' header");
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }
    ASSERT_CURSOR_VALUE_STRING_EQUALS(access_token_cur, s_access_token);
    return AWS_ERROR_SUCCESS;
}

static int s_secure_tunneling_functionality_connect_test_fn(struct aws_allocator *allocator, void *ctx) {
    aws_http_library_init(allocator);
    aws_iotdevice_library_init(allocator);

    struct secure_tunnel_test_options test_options;
    s_secure_tunnel_test_init_default_options(&test_options);

    struct aws_secure_tunnel_mock_test_fixture_options test_fixture_options = {
        .secure_tunnel_options = &test_options.secure_tunnel_options,
        .websocket_function_table = &test_options.websocket_function_table,
    };

    struct aws_secure_tunnel_mock_test_fixture test_fixture;
    ASSERT_SUCCESS(aws_secure_tunnel_mock_test_fixture_init(&test_fixture, allocator, &test_fixture_options));

    test_fixture.header_check = secure_tunneling_access_token_check;

    struct aws_secure_tunnel *secure_tunnel = test_fixture.secure_tunnel;

    ASSERT_SUCCESS(aws_secure_tunnel_start(secure_tunnel));
    s_wait_for_connected_successfully(&test_fixture);

    ASSERT_SUCCESS(aws_secure_tunnel_stop(secure_tunnel));
    s_wait_for_connection_shutdown(&test_fixture);

    aws_secure_tunnel_release(secure_tunnel);
    s_wait_for_secure_tunnel_terminated(&test_fixture);

    aws_secure_tunnel_mock_test_fixture_clean_up(&test_fixture);
    aws_iotdevice_library_clean_up();
    aws_http_library_clean_up();
    aws_iotdevice_library_clean_up();

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(secure_tunneling_functionality_connect_test, s_secure_tunneling_functionality_connect_test_fn)

/* [Func-UC2] */
int secure_tunneling_client_token_check(const struct aws_http_headers *request_headers, void *user_data) {
    struct aws_byte_cursor client_token_cur;
    if (aws_http_headers_get(request_headers, aws_byte_cursor_from_c_str("client-token"), &client_token_cur)) {
        AWS_LOGF_ERROR(
            AWS_LS_HTTP_WEBSOCKET_SETUP,
            "id=static: Websocket handshake request is missing required 'client-token' header");
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }
    ASSERT_CURSOR_VALUE_STRING_EQUALS(client_token_cur, s_client_token);
    return AWS_ERROR_SUCCESS;
}

static int s_secure_tunneling_functionality_client_token_test_fn(struct aws_allocator *allocator, void *ctx) {
    aws_http_library_init(allocator);
    aws_iotdevice_library_init(allocator);

    struct secure_tunnel_test_options test_options;
    s_secure_tunnel_test_init_default_options(&test_options);
    test_options.secure_tunnel_options.client_token = aws_byte_cursor_from_string(s_client_token);

    struct aws_secure_tunnel_mock_test_fixture_options test_fixture_options = {
        .secure_tunnel_options = &test_options.secure_tunnel_options,
        .websocket_function_table = &test_options.websocket_function_table,
    };

    struct aws_secure_tunnel_mock_test_fixture test_fixture;
    ASSERT_SUCCESS(aws_secure_tunnel_mock_test_fixture_init(&test_fixture, allocator, &test_fixture_options));

    test_fixture.header_check = secure_tunneling_client_token_check;

    struct aws_secure_tunnel *secure_tunnel = test_fixture.secure_tunnel;

    ASSERT_SUCCESS(aws_secure_tunnel_start(secure_tunnel));
    s_wait_for_connected_successfully(&test_fixture);

    ASSERT_SUCCESS(aws_secure_tunnel_stop(secure_tunnel));
    s_wait_for_connection_shutdown(&test_fixture);

    aws_secure_tunnel_release(secure_tunnel);
    s_wait_for_secure_tunnel_terminated(&test_fixture);

    aws_secure_tunnel_mock_test_fixture_clean_up(&test_fixture);
    aws_iotdevice_library_clean_up();
    aws_http_library_clean_up();
    aws_iotdevice_library_clean_up();

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(secure_tunneling_functionality_client_token_test, s_secure_tunneling_functionality_client_token_test_fn)

/* [Func-UC3] */

int aws_websocket_client_connect_fail_once_fn(const struct aws_websocket_client_connection_options *options) {
    struct aws_secure_tunnel *secure_tunnel = options->user_data;
    struct aws_secure_tunnel_mock_test_fixture *test_fixture = secure_tunnel->config->user_data;
    bool is_connection_failed_once = false;

    aws_mutex_lock(&test_fixture->lock);
    is_connection_failed_once = test_fixture->secure_tunnel_connection_failed;
    aws_mutex_unlock(&test_fixture->lock);

    if (is_connection_failed_once) {
        if (!options->handshake_request) {
            AWS_LOGF_ERROR(
                AWS_LS_HTTP_WEBSOCKET_SETUP,
                "id=static: Invalid connection options, missing required request for websocket client handshake.");
            return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
        }

        const struct aws_http_headers *request_headers = aws_http_message_get_headers(options->handshake_request);
        if (test_fixture->header_check) {
            ASSERT_SUCCESS(test_fixture->header_check(request_headers, test_fixture));
        }

        test_fixture->websocket_function_table->on_connection_setup_fn = options->on_connection_setup;
        test_fixture->websocket_function_table->on_connection_shutdown_fn = options->on_connection_shutdown;
        test_fixture->websocket_function_table->on_incoming_frame_begin_fn = options->on_incoming_frame_begin;
        test_fixture->websocket_function_table->on_incoming_frame_payload_fn = options->on_incoming_frame_payload;
        test_fixture->websocket_function_table->on_incoming_frame_complete_fn = options->on_incoming_frame_complete;

        void *pointer = test_fixture;
        struct aws_websocket_on_connection_setup_data websocket_setup = {.error_code = AWS_ERROR_SUCCESS,
                                                                         .websocket = pointer};

        (test_fixture->websocket_function_table->on_connection_setup_fn)(&websocket_setup, secure_tunnel);

        struct aws_byte_cursor service_1 = aws_byte_cursor_from_string(s_service_id_1);
        struct aws_byte_cursor service_2 = aws_byte_cursor_from_string(s_service_id_2);
        struct aws_byte_cursor service_3 = aws_byte_cursor_from_string(s_service_id_3);

        struct aws_secure_tunnel_message_view service_ids_message = {
            .type = AWS_SECURE_TUNNEL_MT_SERVICE_IDS,
            .service_id = &service_1,
            .service_id_2 = &service_2,
            .service_id_3 = &service_3,
        };

        aws_secure_tunnel_send_mock_message(test_fixture, &service_ids_message);

        return AWS_OP_SUCCESS;
    } else {
        return AWS_OP_ERR;
    }
}

static int s_secure_tunneling_fail_and_retry_connection_test_fn(struct aws_allocator *allocator, void *ctx) {
    aws_http_library_init(allocator);
    aws_iotdevice_library_init(allocator);

    struct secure_tunnel_test_options test_options;
    s_secure_tunnel_test_init_default_options(&test_options);

    struct aws_secure_tunnel_mock_test_fixture_options test_fixture_options = {
        .secure_tunnel_options = &test_options.secure_tunnel_options,
        .websocket_function_table = &test_options.websocket_function_table,
    };

    struct aws_secure_tunnel_mock_test_fixture test_fixture;
    ASSERT_SUCCESS(aws_secure_tunnel_mock_test_fixture_init(&test_fixture, allocator, &test_fixture_options));

    test_fixture.secure_tunnel_vtable = *aws_secure_tunnel_get_default_vtable();
    test_fixture.secure_tunnel_vtable.aws_websocket_client_connect_fn = aws_websocket_client_connect_fail_once_fn;
    test_fixture.secure_tunnel_vtable.aws_websocket_send_frame_fn = aws_websocket_send_frame_mock_fn;
    test_fixture.secure_tunnel_vtable.aws_websocket_release_fn = aws_websocket_release_mock_fn;
    test_fixture.secure_tunnel_vtable.aws_websocket_close_fn = aws_websocket_close_mock_fn;
    test_fixture.secure_tunnel_vtable.vtable_user_data = &test_fixture;

    struct aws_secure_tunnel *secure_tunnel = test_fixture.secure_tunnel;

    ASSERT_SUCCESS(aws_secure_tunnel_start(secure_tunnel));
    s_wait_for_connected_successfully(&test_fixture);

    ASSERT_SUCCESS(aws_secure_tunnel_stop(secure_tunnel));
    s_wait_for_connection_shutdown(&test_fixture);

    aws_secure_tunnel_release(secure_tunnel);
    s_wait_for_secure_tunnel_terminated(&test_fixture);

    aws_secure_tunnel_mock_test_fixture_clean_up(&test_fixture);
    aws_iotdevice_library_clean_up();
    aws_http_library_clean_up();
    aws_iotdevice_library_clean_up();

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(secure_tunneling_fail_and_retry_connection_test, s_secure_tunneling_fail_and_retry_connection_test_fn)

/* [Func-UC4] */

static int s_secure_tunneling_store_service_ids_test_fn(struct aws_allocator *allocator, void *ctx) {
    aws_http_library_init(allocator);
    aws_iotdevice_library_init(allocator);

    struct secure_tunnel_test_options test_options;
    s_secure_tunnel_test_init_default_options(&test_options);

    struct aws_secure_tunnel_mock_test_fixture_options test_fixture_options = {
        .secure_tunnel_options = &test_options.secure_tunnel_options,
        .websocket_function_table = &test_options.websocket_function_table,
    };

    struct aws_secure_tunnel_mock_test_fixture test_fixture;
    ASSERT_SUCCESS(aws_secure_tunnel_mock_test_fixture_init(&test_fixture, allocator, &test_fixture_options));

    struct aws_secure_tunnel *secure_tunnel = test_fixture.secure_tunnel;

    ASSERT_SUCCESS(aws_secure_tunnel_start(secure_tunnel));
    s_wait_for_connected_successfully(&test_fixture);

    /* check that service ids have been stored */
    struct aws_hash_element *elem = NULL;
    struct aws_byte_cursor service_id_1_cur = aws_byte_cursor_from_string(s_service_id_1);
    aws_hash_table_find(&secure_tunnel->config->service_ids, &service_id_1_cur, &elem);
    ASSERT_NOT_NULL(elem);
    elem = NULL;
    struct aws_byte_cursor service_id_2_cur = aws_byte_cursor_from_string(s_service_id_2);
    aws_hash_table_find(&secure_tunnel->config->service_ids, &service_id_2_cur, &elem);
    ASSERT_NOT_NULL(elem);
    elem = NULL;
    struct aws_byte_cursor service_id_3_cur = aws_byte_cursor_from_string(s_service_id_3);
    aws_hash_table_find(&secure_tunnel->config->service_ids, &service_id_3_cur, &elem);
    ASSERT_NOT_NULL(elem);

    ASSERT_SUCCESS(aws_secure_tunnel_stop(secure_tunnel));
    s_wait_for_connection_shutdown(&test_fixture);

    aws_secure_tunnel_release(secure_tunnel);
    s_wait_for_secure_tunnel_terminated(&test_fixture);

    aws_secure_tunnel_mock_test_fixture_clean_up(&test_fixture);
    aws_iotdevice_library_clean_up();
    aws_http_library_clean_up();
    aws_iotdevice_library_clean_up();

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(secure_tunneling_store_service_ids_test, s_secure_tunneling_store_service_ids_test_fn)

/* [Func-UC5] */

static int s_secure_tunneling_receive_stream_start_test_fn(struct aws_allocator *allocator, void *ctx) {
    aws_http_library_init(allocator);
    aws_iotdevice_library_init(allocator);

    struct secure_tunnel_test_options test_options;
    s_secure_tunnel_test_init_default_options(&test_options);

    struct aws_secure_tunnel_mock_test_fixture_options test_fixture_options = {
        .secure_tunnel_options = &test_options.secure_tunnel_options,
        .websocket_function_table = &test_options.websocket_function_table,
    };

    struct aws_secure_tunnel_mock_test_fixture test_fixture;
    ASSERT_SUCCESS(aws_secure_tunnel_mock_test_fixture_init(&test_fixture, allocator, &test_fixture_options));

    struct aws_secure_tunnel *secure_tunnel = test_fixture.secure_tunnel;

    ASSERT_SUCCESS(aws_secure_tunnel_start(secure_tunnel));
    s_wait_for_connected_successfully(&test_fixture);

    /* Create and send a stream start message from the server to the destination client */
    struct aws_byte_cursor service_1 = aws_byte_cursor_from_string(s_service_id_1);
    struct aws_secure_tunnel_message_view stream_start_message_view = {
        .type = AWS_SECURE_TUNNEL_MT_STREAM_START,
        .service_id = &service_1,
        .stream_id = 1,
    };
    aws_secure_tunnel_send_mock_message(&test_fixture, &stream_start_message_view);

    /* Wait and confirm that a stream has been started */
    s_wait_for_stream_started(&test_fixture);

    /* check that service id stream has been set properly */
    struct aws_hash_element *elem = NULL;
    aws_hash_table_find(&secure_tunnel->config->service_ids, stream_start_message_view.service_id, &elem);
    ASSERT_NOT_NULL(elem);
    struct aws_service_id_element *service_id_elem = elem->value;
    ASSERT_TRUE(service_id_elem->stream_id == stream_start_message_view.stream_id);

    ASSERT_SUCCESS(aws_secure_tunnel_stop(secure_tunnel));
    s_wait_for_connection_shutdown(&test_fixture);

    aws_secure_tunnel_release(secure_tunnel);
    s_wait_for_secure_tunnel_terminated(&test_fixture);

    aws_secure_tunnel_mock_test_fixture_clean_up(&test_fixture);
    aws_iotdevice_library_clean_up();
    aws_http_library_clean_up();
    aws_iotdevice_library_clean_up();

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(secure_tunneling_receive_stream_start_test, s_secure_tunneling_receive_stream_start_test_fn)

/* [Func-UC6] */

static int s_secure_tunneling_rejected_service_id_stream_start_test_fn(struct aws_allocator *allocator, void *ctx) {
    aws_http_library_init(allocator);
    aws_iotdevice_library_init(allocator);

    struct secure_tunnel_test_options test_options;
    s_secure_tunnel_test_init_default_options(&test_options);

    struct aws_secure_tunnel_mock_test_fixture_options test_fixture_options = {
        .secure_tunnel_options = &test_options.secure_tunnel_options,
        .websocket_function_table = &test_options.websocket_function_table,
    };

    struct aws_secure_tunnel_mock_test_fixture test_fixture;
    ASSERT_SUCCESS(aws_secure_tunnel_mock_test_fixture_init(&test_fixture, allocator, &test_fixture_options));

    struct aws_secure_tunnel *secure_tunnel = test_fixture.secure_tunnel;

    ASSERT_SUCCESS(aws_secure_tunnel_start(secure_tunnel));
    s_wait_for_connected_successfully(&test_fixture);

    /* Create and send a bad stream start message from the server to the destination client */
    struct aws_byte_cursor service_id = aws_byte_cursor_from_string(s_service_id_wrong);
    struct aws_secure_tunnel_message_view stream_start_message_view = {
        .type = AWS_SECURE_TUNNEL_MT_STREAM_START,
        .service_id = &service_id,
        .stream_id = 1,
    };
    aws_secure_tunnel_send_mock_message(&test_fixture, &stream_start_message_view);

    /* Wait and confirm that a bad stream request was received */
    s_wait_for_bad_stream_request(&test_fixture);

    ASSERT_SUCCESS(aws_secure_tunnel_stop(secure_tunnel));
    s_wait_for_connection_shutdown(&test_fixture);

    aws_secure_tunnel_release(secure_tunnel);
    s_wait_for_secure_tunnel_terminated(&test_fixture);

    aws_secure_tunnel_mock_test_fixture_clean_up(&test_fixture);
    aws_iotdevice_library_clean_up();
    aws_http_library_clean_up();
    aws_iotdevice_library_clean_up();

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(
    secure_tunneling_rejected_service_id_stream_start_test,
    s_secure_tunneling_rejected_service_id_stream_start_test_fn)

/* [Func-UC7] */

static int s_secure_tunneling_close_stream_on_stream_reset_test_fn(struct aws_allocator *allocator, void *ctx) {
    aws_http_library_init(allocator);
    aws_iotdevice_library_init(allocator);

    struct secure_tunnel_test_options test_options;
    s_secure_tunnel_test_init_default_options(&test_options);

    struct aws_secure_tunnel_mock_test_fixture_options test_fixture_options = {
        .secure_tunnel_options = &test_options.secure_tunnel_options,
        .websocket_function_table = &test_options.websocket_function_table,
    };

    struct aws_secure_tunnel_mock_test_fixture test_fixture;
    ASSERT_SUCCESS(aws_secure_tunnel_mock_test_fixture_init(&test_fixture, allocator, &test_fixture_options));

    struct aws_secure_tunnel *secure_tunnel = test_fixture.secure_tunnel;

    ASSERT_SUCCESS(aws_secure_tunnel_start(secure_tunnel));
    s_wait_for_connected_successfully(&test_fixture);

    /* Create and send a stream start message from the server to the destination client */
    struct aws_byte_cursor service_1 = aws_byte_cursor_from_string(s_service_id_1);
    struct aws_secure_tunnel_message_view stream_start_message_view = {
        .type = AWS_SECURE_TUNNEL_MT_STREAM_START,
        .service_id = &service_1,
        .stream_id = 1,
    };
    aws_secure_tunnel_send_mock_message(&test_fixture, &stream_start_message_view);

    /* Wait and confirm that a stream has been started */
    s_wait_for_stream_started(&test_fixture);

    /* Send a stream reset message from the server to the destination client */
    stream_start_message_view.type = AWS_SECURE_TUNNEL_MT_STREAM_RESET;

    aws_secure_tunnel_send_mock_message(&test_fixture, &stream_start_message_view);

    /* Wait for a stream reset to have been received */
    s_wait_for_stream_reset_received(&test_fixture);

    /* check that service id stream has been reset */
    struct aws_hash_element *elem = NULL;
    aws_hash_table_find(&secure_tunnel->config->service_ids, stream_start_message_view.service_id, &elem);
    ASSERT_NOT_NULL(elem);
    struct aws_service_id_element *service_id_elem = elem->value;
    ASSERT_TRUE(service_id_elem->stream_id == 0);

    ASSERT_SUCCESS(aws_secure_tunnel_stop(secure_tunnel));
    s_wait_for_connection_shutdown(&test_fixture);

    aws_secure_tunnel_release(secure_tunnel);
    s_wait_for_secure_tunnel_terminated(&test_fixture);

    aws_secure_tunnel_mock_test_fixture_clean_up(&test_fixture);
    aws_iotdevice_library_clean_up();
    aws_http_library_clean_up();
    aws_iotdevice_library_clean_up();

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(
    secure_tunneling_close_stream_on_stream_reset_test,
    s_secure_tunneling_close_stream_on_stream_reset_test_fn)

/* [Func-UC8] */
static int s_secure_tunneling_session_reset_test_fn(struct aws_allocator *allocator, void *ctx) {
    aws_http_library_init(allocator);
    aws_iotdevice_library_init(allocator);

    struct secure_tunnel_test_options test_options;
    s_secure_tunnel_test_init_default_options(&test_options);

    struct aws_secure_tunnel_mock_test_fixture_options test_fixture_options = {
        .secure_tunnel_options = &test_options.secure_tunnel_options,
        .websocket_function_table = &test_options.websocket_function_table,
    };

    struct aws_secure_tunnel_mock_test_fixture test_fixture;
    ASSERT_SUCCESS(aws_secure_tunnel_mock_test_fixture_init(&test_fixture, allocator, &test_fixture_options));

    struct aws_secure_tunnel *secure_tunnel = test_fixture.secure_tunnel;

    ASSERT_SUCCESS(aws_secure_tunnel_start(secure_tunnel));
    s_wait_for_connected_successfully(&test_fixture);

    /* Create and send a stream start message from the server to the destination client */
    struct aws_byte_cursor service_1 = aws_byte_cursor_from_string(s_service_id_1);
    struct aws_byte_cursor service_2 = aws_byte_cursor_from_string(s_service_id_2);
    struct aws_byte_cursor service_3 = aws_byte_cursor_from_string(s_service_id_3);
    struct aws_secure_tunnel_message_view stream_start_message_view = {
        .type = AWS_SECURE_TUNNEL_MT_STREAM_START,
        .service_id = &service_1,
        .stream_id = 1,
    };
    aws_secure_tunnel_send_mock_message(&test_fixture, &stream_start_message_view);
    stream_start_message_view.service_id = &service_2;
    aws_secure_tunnel_send_mock_message(&test_fixture, &stream_start_message_view);
    stream_start_message_view.service_id = &service_3;
    aws_secure_tunnel_send_mock_message(&test_fixture, &stream_start_message_view);

    test_fixture.secure_tunnel_stream_started_count_target = 3;
    s_wait_for_n_stream_started(&test_fixture);

    /* check that stream ids have been set */
    struct aws_hash_element *elem = NULL;
    struct aws_byte_cursor service_id_1_cur = aws_byte_cursor_from_string(s_service_id_1);
    aws_hash_table_find(&secure_tunnel->config->service_ids, &service_id_1_cur, &elem);
    ASSERT_NOT_NULL(elem);
    struct aws_service_id_element *service_id_elem = elem->value;
    ASSERT_TRUE(service_id_elem->stream_id == stream_start_message_view.stream_id);
    elem = NULL;
    struct aws_byte_cursor service_id_2_cur = aws_byte_cursor_from_string(s_service_id_2);
    aws_hash_table_find(&secure_tunnel->config->service_ids, &service_id_2_cur, &elem);
    ASSERT_NOT_NULL(elem);
    service_id_elem = elem->value;
    ASSERT_TRUE(service_id_elem->stream_id == stream_start_message_view.stream_id);
    elem = NULL;
    struct aws_byte_cursor service_id_3_cur = aws_byte_cursor_from_string(s_service_id_3);
    aws_hash_table_find(&secure_tunnel->config->service_ids, &service_id_3_cur, &elem);
    ASSERT_NOT_NULL(elem);
    service_id_elem = elem->value;
    ASSERT_TRUE(service_id_elem->stream_id == stream_start_message_view.stream_id);

    /* Create and send a session reset message from the server to the destination client */
    struct aws_secure_tunnel_message_view reset_message_view = {
        .type = AWS_SECURE_TUNNEL_MT_SESSION_RESET,
    };
    aws_secure_tunnel_send_mock_message(&test_fixture, &reset_message_view);

    s_wait_for_session_reset_received(&test_fixture);

    /* Check that stream ids have been reset */
    elem = NULL;
    aws_hash_table_find(&secure_tunnel->config->service_ids, &service_id_1_cur, &elem);
    ASSERT_NOT_NULL(elem);
    service_id_elem = elem->value;
    ASSERT_TRUE(service_id_elem->stream_id == 0);
    elem = NULL;
    aws_hash_table_find(&secure_tunnel->config->service_ids, &service_id_2_cur, &elem);
    ASSERT_NOT_NULL(elem);
    service_id_elem = elem->value;
    ASSERT_TRUE(service_id_elem->stream_id == 0);
    elem = NULL;
    aws_hash_table_find(&secure_tunnel->config->service_ids, &service_id_3_cur, &elem);
    ASSERT_NOT_NULL(elem);
    service_id_elem = elem->value;
    ASSERT_TRUE(service_id_elem->stream_id == 0);

    ASSERT_SUCCESS(aws_secure_tunnel_stop(secure_tunnel));
    s_wait_for_connection_shutdown(&test_fixture);

    aws_secure_tunnel_release(secure_tunnel);
    s_wait_for_secure_tunnel_terminated(&test_fixture);

    aws_secure_tunnel_mock_test_fixture_clean_up(&test_fixture);
    aws_iotdevice_library_clean_up();
    aws_http_library_clean_up();
    aws_iotdevice_library_clean_up();

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(secure_tunneling_session_reset_test, s_secure_tunneling_session_reset_test_fn)

/*
static int s_secure_tunneling_template_test_fn(struct aws_allocator *allocator, void *ctx) {
    aws_http_library_init(allocator);
    aws_iotdevice_library_init(allocator);

    struct secure_tunnel_test_options test_options;
    s_secure_tunnel_test_init_default_options(&test_options);

    struct aws_secure_tunnel_mock_test_fixture_options test_fixture_options = {
        .secure_tunnel_options = &test_options.secure_tunnel_options,
        .websocket_function_table = &test_options.websocket_function_table,
    };

    struct aws_secure_tunnel_mock_test_fixture test_fixture;
    ASSERT_SUCCESS(aws_secure_tunnel_mock_test_fixture_init(&test_fixture, allocator, &test_fixture_options));

    struct aws_secure_tunnel *secure_tunnel = test_fixture.secure_tunnel;

    ASSERT_SUCCESS(aws_secure_tunnel_start(secure_tunnel));
    s_wait_for_connected_successfully(&test_fixture);

    ASSERT_SUCCESS(aws_secure_tunnel_stop(secure_tunnel));
    s_wait_for_connection_shutdown(&test_fixture);

    aws_secure_tunnel_release(secure_tunnel);
    s_wait_for_secure_tunnel_terminated(&test_fixture);

    aws_secure_tunnel_mock_test_fixture_clean_up(&test_fixture);
    aws_iotdevice_library_clean_up();
    aws_http_library_clean_up();
    aws_iotdevice_library_clean_up();

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(secure_tunneling_template_test, s_secure_tunneling_template_test_fn)
*/

/* [Func-UC9] */

static int s_secure_tunneling_serializer_data_message_test_fn(struct aws_allocator *allocator, void *ctx) {
    aws_http_library_init(allocator);
    aws_iotdevice_library_init(allocator);

    struct secure_tunnel_test_options test_options;
    s_secure_tunnel_test_init_default_options(&test_options);

    struct aws_secure_tunnel_mock_test_fixture_options test_fixture_options = {
        .secure_tunnel_options = &test_options.secure_tunnel_options,
        .websocket_function_table = &test_options.websocket_function_table,
    };

    struct aws_secure_tunnel_mock_test_fixture test_fixture;
    ASSERT_SUCCESS(aws_secure_tunnel_mock_test_fixture_init(&test_fixture, allocator, &test_fixture_options));

    struct aws_secure_tunnel *secure_tunnel = test_fixture.secure_tunnel;

    ASSERT_SUCCESS(aws_secure_tunnel_start(secure_tunnel));
    s_wait_for_connected_successfully(&test_fixture);

    /* Create and send a stream start message from the server to the destination client */
    struct aws_byte_cursor service_1 = aws_byte_cursor_from_string(s_service_id_1);
    struct aws_secure_tunnel_message_view stream_start_message_view = {
        .type = AWS_SECURE_TUNNEL_MT_STREAM_START,
        .service_id = &service_1,
        .stream_id = 1,
    };
    aws_secure_tunnel_send_mock_message(&test_fixture, &stream_start_message_view);

    /* Create and send a data message from the server to the destination client */
    struct aws_byte_cursor payload_cur = aws_byte_cursor_from_string(s_payload_text);
    struct aws_secure_tunnel_message_view data_message_view = {
        .type = AWS_SECURE_TUNNEL_MT_DATA,
        .service_id = &service_1,
        .stream_id = 1,
        .payload = &payload_cur,
    };

    aws_secure_tunnel_send_mock_message(&test_fixture, &data_message_view);
    test_fixture.secure_tunnel_message_count_target = 1;
    s_wait_for_n_messages_received(&test_fixture);

    struct aws_byte_cursor payload_comp_cur = {
        .ptr = test_fixture.last_message_payload_buf.buffer,
        .len = test_fixture.last_message_payload_buf.len,
    };
    ASSERT_CURSOR_VALUE_STRING_EQUALS(payload_comp_cur, s_payload_text);

    /* Wait and confirm that a stream has been started */
    s_wait_for_stream_started(&test_fixture);

    ASSERT_SUCCESS(aws_secure_tunnel_stop(secure_tunnel));
    s_wait_for_connection_shutdown(&test_fixture);

    aws_secure_tunnel_release(secure_tunnel);
    s_wait_for_secure_tunnel_terminated(&test_fixture);

    aws_secure_tunnel_mock_test_fixture_clean_up(&test_fixture);
    aws_iotdevice_library_clean_up();
    aws_http_library_clean_up();
    aws_iotdevice_library_clean_up();

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(secure_tunneling_serializer_data_message_test, s_secure_tunneling_serializer_data_message_test_fn)
