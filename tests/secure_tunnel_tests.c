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
#include <aws/iotdevice/private/serializer.h>
#include <aws/iotdevice/secure_tunneling.h>
#include <aws/testing/aws_test_harness.h>
#include <stdint.h>

#define PAYLOAD_BYTE_LENGTH_PREFIX 2
AWS_STATIC_STRING_FROM_LITERAL(s_access_token, "IAmAnAccessToken");
AWS_STATIC_STRING_FROM_LITERAL(s_endpoint_host, "IAmAnEndpointHost");
AWS_STATIC_STRING_FROM_LITERAL(s_service_id_1, "ServiceId1");
AWS_STATIC_STRING_FROM_LITERAL(s_service_id_2, "ServiceId2");
AWS_STATIC_STRING_FROM_LITERAL(s_service_id_3, "ServiceId3");

#ifdef _WIN32
#    define LOCAL_SOCK_TEST_PATTERN "\\\\.\\pipe\\testsock%llu"
#else
#    define LOCAL_SOCK_TEST_PATTERN "testsock%llu.sock"
#endif

struct aws_secure_tunnel_server_mock_connection_context {
    struct aws_allocator *allocator;

    struct aws_channel *channel;
    struct aws_channel_handler handler;
    struct aws_channel_slot *slot;

    struct aws_secure_tunnel_mock_test_fixture *test_fixture;

    struct aws_task service_task;
};

typedef int(aws_secure_tunnel_on_mock_server_message_received_fn)(
    void *message_view,
    struct aws_secure_tunnel_server_mock_connection_context *connection,
    void *message_received_user_data);

typedef void(aws_secure_tunnel_mock_server_service_fn)(
    struct aws_secure_tunnel_server_mock_connection_context *mock_server,
    void *user_data);

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

    struct aws_mutex lock;
    struct aws_condition_variable signal;
    bool listener_destroyed;
    bool secure_tunnel_terminated;
    bool secure_tunnel_connected_succesfully;
    bool secure_tunnel_connection_failed;
};

static void s_on_test_secure_tunnel_termination(void *user_data) {
    struct aws_secure_tunnel_mock_test_fixture *test_fixture = user_data;

    aws_mutex_lock(&test_fixture->lock);
    test_fixture->secure_tunnel_terminated = true;
    aws_mutex_unlock(&test_fixture->lock);
    aws_condition_variable_notify_all(&test_fixture->signal);
}

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

static bool s_has_secure_tunnel_terminated(void *arg) {
    struct aws_secure_tunnel_mock_test_fixture *test_fixture = arg;
    return test_fixture->secure_tunnel_terminated;
}

static void s_wait_for_secure_tunnel_terminated(struct aws_secure_tunnel_mock_test_fixture *test_context) {
    aws_mutex_lock(&test_context->lock);
    aws_condition_variable_wait_pred(
        &test_context->signal, &test_context->lock, s_has_secure_tunnel_terminated, test_context);
    aws_mutex_unlock(&test_context->lock);
}

static bool s_has_secure_tunnel_connected_succesfully(void *arg) {
    struct aws_secure_tunnel_mock_test_fixture *test_fixture = arg;
    return test_fixture->secure_tunnel_connected_succesfully;
}

static void s_wait_for_connected_successfully(struct aws_secure_tunnel_mock_test_fixture *test_context) {
    aws_mutex_lock(&test_context->lock);
    aws_condition_variable_wait_pred(
        &test_context->signal, &test_context->lock, s_has_secure_tunnel_connected_succesfully, test_context);
    aws_mutex_unlock(&test_context->lock);
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
    struct aws_byte_cursor access_token_cur;
    if (aws_http_headers_get(request_headers, aws_byte_cursor_from_c_str("access-token"), &access_token_cur)) {
        AWS_LOGF_ERROR(
            AWS_LS_HTTP_WEBSOCKET_SETUP,
            "id=static: Websocket handshake request is missing required 'access-token' header");
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }

    test_fixture->websocket_function_table->on_connection_setup_fn = options->on_connection_setup;
    test_fixture->websocket_function_table->on_connection_shutdown_fn = options->on_connection_shutdown;
    test_fixture->websocket_function_table->on_incoming_frame_begin_fn = options->on_incoming_frame_begin;
    test_fixture->websocket_function_table->on_incoming_frame_payload_fn = options->on_incoming_frame_payload;
    test_fixture->websocket_function_table->on_incoming_frame_complete_fn = options->on_incoming_frame_complete;

    struct aws_websocket_on_connection_setup_data websocket_setup = {.error_code = AWS_ERROR_SUCCESS,
                                                                     .websocket = test_fixture};

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
    struct aws_secure_tunnel_mock_test_fixture *test_fixture = websocket;
}

void aws_websocket_close_mock_fn(struct aws_websocket *websocket, bool free_scarce_resources_immediately) {

    struct aws_secure_tunnel_mock_test_fixture *test_fixture = websocket;

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

    // Steve TODO set secure tunnel callbacks
    options->secure_tunnel_options->on_connection_complete = s_on_test_secure_tunnel_connection_complete;
    // options->secure_tunnel_options->on_connection_shutdown
    // options->secure_tunnel_options->on_message_received
    // options->secure_tunnel_options->on_send_data_complete
    // options->secure_tunnel_options->on_session_reset
    // options->secure_tunnel_options->on_stopped
    // options->secure_tunnel_options->on_stream_reset
    // options->secure_tunnel_options->on_stream_start
    options->secure_tunnel_options->on_termination_complete = s_on_test_secure_tunnel_termination;
    options->secure_tunnel_options->secure_tunnel_on_termination_user_data = test_fixture;

    test_fixture->secure_tunnel = aws_secure_tunnel_new(allocator, options->secure_tunnel_options);

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

    // aws_thread_join_all_managed();

    aws_mutex_clean_up(&test_fixture->lock);
    aws_condition_variable_clean_up(&test_fixture->signal);
}

/*********************************************************************************************************************
 * TESTS
 ********************************************************************************************************************/

static int s_secure_tunneling_serializer_data_message_test_fn(struct aws_allocator *allocator, void *ctx) {
    aws_http_library_init(allocator);
    aws_iotdevice_library_init(allocator);

    struct secure_tunnel_test_options test_options;
    s_secure_tunnel_test_init_default_options(&test_options);

    struct aws_secure_tunnel_mock_test_fixture_options test_fixture_options = {
        .secure_tunnel_options = &test_options.secure_tunnel_options,
        .websocket_function_table = &test_options.websocket_function_table,
    };

    struct aws_secure_tunnel_mock_test_fixture test_context;
    ASSERT_SUCCESS(aws_secure_tunnel_mock_test_fixture_init(&test_context, allocator, &test_fixture_options));

    struct aws_secure_tunnel *secure_tunnel = test_context.secure_tunnel;

    ASSERT_SUCCESS(aws_secure_tunnel_start(secure_tunnel));
    s_wait_for_connected_successfully(&test_context);

    ASSERT_SUCCESS(aws_secure_tunnel_stop(secure_tunnel));

    aws_secure_tunnel_release(secure_tunnel);

    aws_secure_tunnel_mock_test_fixture_clean_up(&test_context);
    aws_iotdevice_library_clean_up();
    aws_http_library_clean_up();
    aws_iotdevice_library_clean_up();

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(secure_tunneling_serializer_data_message_test, s_secure_tunneling_serializer_data_message_test_fn)
