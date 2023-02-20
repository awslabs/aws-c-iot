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

AWS_STATIC_STRING_FROM_LITERAL(s_access_token, "IAmAnAccessToken");
AWS_STATIC_STRING_FROM_LITERAL(s_endpoint_host, "IAmAnEndpointHost");

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

    // Add a function table for serializer.c decoding/encoding

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

struct aws_secure_tunnel_mock_server_vtable {
    // STEVE TODO Not needed?
    aws_secure_tunnel_on_mock_server_message_received_fn *packet_handler_fn;
    aws_secure_tunnel_mock_server_service_fn *service_task_fn;

    aws_websocket_on_connection_setup_fn *on_connection_setup_fn;
    aws_websocket_on_connection_shutdown_fn *on_connection_shutdown_fn;
    aws_websocket_on_incoming_frame_begin_fn *on_incoming_frame_begin_fn;
    aws_websocket_on_incoming_frame_payload_fn *on_incoming_frame_payload_fn;
    aws_websocket_on_incoming_frame_complete_fn *on_incoming_frame_complete_fn;
};

struct aws_secure_tunnel_mock_test_fixture_options {
    struct aws_secure_tunnel_options *secure_tunnel_options;
    struct aws_secure_tunnel_mock_server_vtable *server_function_table;

    void *mock_server_user_data;
};

struct aws_secure_tunnel_mock_test_fixture {
    struct aws_allocator *allocator;

    struct aws_event_loop_group *secure_tunnel_elg;
    struct aws_event_loop_group *server_elg;
    struct aws_host_resolver *host_resolver;
    struct aws_client_bootstrap *secure_tunnel_bootstrap;
    struct aws_server_bootstrap *server_bootstrap;
    struct aws_socket_endpoint endpoint;
    struct aws_socket_options socket_options;
    struct aws_socket *listener;
    struct aws_channel *server_channel;

    struct aws_secure_tunnel_mock_server_vtable *server_function_table;
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
    struct aws_secure_tunnel_mock_server_vtable server_function_table;
};

static void s_secure_tunnel_test_init_default_options(struct secure_tunnel_test_options *test_options) {
    struct aws_secure_tunnel_options local_secure_tunnel_options = {
        .endpoint_host = aws_byte_cursor_from_string(s_endpoint_host),
        .access_token = aws_byte_cursor_from_string(s_access_token),
        .local_proxy_mode = AWS_SECURE_TUNNELING_DESTINATION_MODE,
    };
    test_options->secure_tunnel_options = local_secure_tunnel_options;
}

static int s_process_read_message(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    struct aws_io_message *message) {

    struct aws_secure_tunnel_server_mock_connection_context *server_connection = handler->impl;

    if (message->message_type != AWS_IO_MESSAGE_APPLICATION_DATA) {
        return AWS_OP_ERR;
    }

    // STEVE TODO incomming data needs to be processed
    (void)server_connection;
    // struct aws_byte_cursor message_cursor = aws_byte_cursor_from_buf(&message->message_data);

    // int result = aws_mqtt5_decoder_on_data_received(&server_connection->decoder, message_cursor);
    // if (result != AWS_OP_SUCCESS) {
    //     aws_channel_shutdown(server_connection->channel, aws_last_error());
    //     goto done;
    // }

    aws_channel_slot_increment_read_window(slot, message->message_data.len);

    // done:

    aws_mem_release(message->allocator, message);

    return AWS_OP_SUCCESS;
}

static int s_shutdown(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    enum aws_channel_direction dir,
    int error_code,
    bool free_scarce_resources_immediately) {

    (void)handler;

    return aws_channel_slot_on_handler_shutdown_complete(slot, dir, error_code, free_scarce_resources_immediately);
}

static size_t s_initial_window_size(struct aws_channel_handler *handler) {
    (void)handler;

    return SIZE_MAX;
}

static void s_destroy(struct aws_channel_handler *handler) {
    struct aws_secure_tunnel_server_mock_connection_context *server_connection = handler->impl;

    aws_event_loop_cancel_task(
        aws_channel_get_event_loop(server_connection->channel), &server_connection->service_task);

    // aws_mqtt5_decoder_clean_up(&server_connection->decoder);
    // aws_mqtt5_encoder_clean_up(&server_connection->encoder);
    // aws_mqtt5_inbound_topic_alias_resolver_clean_up(&server_connection->inbound_alias_resolver);

    aws_mem_release(server_connection->allocator, server_connection);
}

static size_t s_message_overhead(struct aws_channel_handler *handler) {
    (void)handler;

    return 0;
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

static struct aws_channel_handler_vtable s_secure_tunnel_mock_server_channel_handler_vtable = {
    .process_read_message = &s_process_read_message,
    .process_write_message = NULL,
    .increment_read_window = NULL,
    .shutdown = &s_shutdown,
    .initial_window_size = &s_initial_window_size,
    .message_overhead = &s_message_overhead,
    .destroy = &s_destroy,
};

static void s_mock_server_service_task_fn(struct aws_task *task, void *arg, enum aws_task_status status) {
    if (status != AWS_TASK_STATUS_RUN_READY) {
        return;
    }

    struct aws_secure_tunnel_server_mock_connection_context *server_connection = arg;

    aws_secure_tunnel_mock_server_service_fn *service_fn =
        server_connection->test_fixture->server_function_table->service_task_fn;
    if (service_fn != NULL) {
        (*service_fn)(server_connection, server_connection->test_fixture->mock_server_user_data);
    }

    uint64_t now = 0;
    aws_high_res_clock_get_ticks(&now);
    uint64_t next_service_time = now + aws_timestamp_convert(1, AWS_TIMESTAMP_SECS, AWS_TIMESTAMP_NANOS, NULL);

    aws_event_loop_schedule_task_future(
        aws_channel_get_event_loop(server_connection->channel), task, next_service_time);
}

static void s_on_incoming_channel_setup_fn(
    struct aws_server_bootstrap *bootstrap,
    int error_code,
    struct aws_channel *channel,
    void *user_data) {
    (void)bootstrap;
    struct aws_secure_tunnel_mock_test_fixture *test_fixture = user_data;

    if (!error_code) {
        struct aws_channel_slot *test_handler_slot = aws_channel_slot_new(channel);
        aws_channel_slot_insert_end(channel, test_handler_slot);

        struct aws_secure_tunnel_server_mock_connection_context *server_connection =
            aws_mem_calloc(test_fixture->allocator, 1, sizeof(struct aws_secure_tunnel_server_mock_connection_context));
        server_connection->allocator = test_fixture->allocator;
        server_connection->channel = channel;
        server_connection->test_fixture = test_fixture;
        server_connection->slot = test_handler_slot;
        server_connection->handler.alloc = server_connection->allocator;
        server_connection->handler.vtable = &s_secure_tunnel_mock_server_channel_handler_vtable;
        server_connection->handler.impl = server_connection;

        aws_task_init(
            &server_connection->service_task,
            s_mock_server_service_task_fn,
            server_connection,
            "mock_server_service_task_fn");
        aws_event_loop_schedule_task_now(aws_channel_get_event_loop(channel), &server_connection->service_task);

        aws_channel_slot_set_handler(server_connection->slot, &server_connection->handler);

        // STEVE TODO add serializer.c function calls to encode/decode messages

        // aws_mqtt5_encode_init_testing_function_table(&server_connection->encoding_table);

        // struct aws_mqtt5_encoder_options encoder_options = {
        //     .client = NULL,
        //     .encoders = &server_connection->encoding_table,
        // };

        // aws_mqtt5_encoder_init(&server_connection->encoder, server_connection->allocator, &encoder_options);

        // aws_mqtt5_decode_init_testing_function_table(&server_connection->decoding_table);

        // struct aws_mqtt5_decoder_options decoder_options = {
        //     .callback_user_data = server_connection,
        //     .on_packet_received = s_aws_mqtt5_mock_test_fixture_on_packet_received_fn,
        //     .decoder_table = &server_connection->decoding_table,
        // };

        // aws_mqtt5_decoder_init(&server_connection->decoder, server_connection->allocator, &decoder_options);
        // aws_mqtt5_inbound_topic_alias_resolver_init(
        //     &server_connection->inbound_alias_resolver, server_connection->allocator);
        // aws_mqtt5_inbound_topic_alias_resolver_reset(
        //     &server_connection->inbound_alias_resolver, test_fixture->maximum_inbound_topic_aliases);
        // aws_mqtt5_decoder_set_inbound_topic_alias_resolver(
        //     &server_connection->decoder, &server_connection->inbound_alias_resolver);

        aws_mutex_lock(&test_fixture->lock);
        test_fixture->server_channel = channel;
        aws_mutex_unlock(&test_fixture->lock);

        /*
         * Just like the tls tests in aws-c-io, it's possible for the server channel setup to execute after the client
         * channel setup has already posted data to the socket.  In this case, the read notification gets lost because
         * the server hasn't subscribed to it yet and then we hang and time out.  So do the same thing we do for
         * tls server channel setup and force a read of the socket after we're fully initialized.
         */
        aws_channel_trigger_read(channel);
    }
}

static void s_on_incoming_channel_shutdown_fn(
    struct aws_server_bootstrap *bootstrap,
    int error_code,
    struct aws_channel *channel,
    void *user_data) {
    (void)bootstrap;
    (void)error_code;
    (void)channel;
    (void)user_data;
}

static void s_on_listener_destroy(struct aws_server_bootstrap *bootstrap, void *user_data) {
    (void)bootstrap;
    struct aws_secure_tunnel_mock_test_fixture *test_fixture = user_data;
    aws_mutex_lock(&test_fixture->lock);
    test_fixture->listener_destroyed = true;
    aws_mutex_unlock(&test_fixture->lock);
    aws_condition_variable_notify_one(&test_fixture->signal);
}

static bool s_is_listener_destroyed(void *arg) {
    struct aws_secure_tunnel_mock_test_fixture *test_fixture = arg;
    return test_fixture->listener_destroyed;
}

static void s_wait_on_listener_cleanup(struct aws_secure_tunnel_mock_test_fixture *test_fixture) {
    aws_mutex_lock(&test_fixture->lock);
    aws_condition_variable_wait_pred(&test_fixture->signal, &test_fixture->lock, s_is_listener_destroyed, test_fixture);
    aws_mutex_unlock(&test_fixture->lock);
}

/*****************************************************************************************************************
 *                                    WEBSOCKET MOCK FUNCTIONS
 *****************************************************************************************************************/

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

    test_fixture->server_function_table->on_connection_setup_fn = options->on_connection_setup;
    test_fixture->server_function_table->on_connection_shutdown_fn = options->on_connection_shutdown;
    test_fixture->server_function_table->on_incoming_frame_begin_fn = options->on_incoming_frame_begin;
    test_fixture->server_function_table->on_incoming_frame_payload_fn = options->on_incoming_frame_payload;
    test_fixture->server_function_table->on_incoming_frame_complete_fn = options->on_incoming_frame_complete;

    // struct aws_websocket_on_connection_setup_data websocket_setup = {.error_code = AWS_ERROR_SUCCESS,
    //                                                                  .websocket = test_fixture};

    // (test_fixture->server_function_table->on_connection_setup_fn)(&websocket_setup, secure_tunnel);

    return AWS_OP_SUCCESS;
}

int aws_websocket_send_frame_mock_fn(
    struct aws_websocket *websocket,
    const struct aws_websocket_send_frame_options *options) {
    (void)websocket;
    (void)options;
    return AWS_OP_SUCCESS;
}

void aws_websocket_release_mock_fn(struct aws_websocket *websocket) {}

void aws_websocket_close_mock_fn(struct aws_websocket *websocket, bool free_scarce_resources_immediately) {}

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

    test_fixture->server_function_table = options->server_function_table;
    test_fixture->mock_server_user_data = options->mock_server_user_data;

    struct aws_socket_options socket_options = {
        .connect_timeout_ms = 1000,
        .domain = AWS_SOCKET_LOCAL,
    };

    test_fixture->socket_options = socket_options;
    test_fixture->server_elg = aws_event_loop_group_new_default(allocator, 1, NULL);
    test_fixture->server_bootstrap = aws_server_bootstrap_new(allocator, test_fixture->server_elg);

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

    struct aws_server_socket_channel_bootstrap_options server_bootstrap_options = {
        .bootstrap = test_fixture->server_bootstrap,
        .host_name = test_fixture->endpoint.address,
        .port = test_fixture->endpoint.port,
        .socket_options = &test_fixture->socket_options,
        .incoming_callback = s_on_incoming_channel_setup_fn,
        .shutdown_callback = s_on_incoming_channel_shutdown_fn,
        .destroy_callback = s_on_listener_destroy,
        .user_data = test_fixture,
    };
    test_fixture->listener = aws_server_bootstrap_new_socket_listener(&server_bootstrap_options);

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
    aws_secure_tunnel_release(test_fixture->secure_tunnel);
    s_wait_for_secure_tunnel_terminated(test_fixture);
    aws_client_bootstrap_release(test_fixture->secure_tunnel_bootstrap);
    aws_host_resolver_release(test_fixture->host_resolver);
    aws_server_bootstrap_destroy_socket_listener(test_fixture->server_bootstrap, test_fixture->listener);

    s_wait_on_listener_cleanup(test_fixture);

    aws_server_bootstrap_release(test_fixture->server_bootstrap);
    aws_event_loop_group_release(test_fixture->server_elg);
    aws_event_loop_group_release(test_fixture->secure_tunnel_elg);

    // aws_thread_join_all_managed();

    aws_mutex_clean_up(&test_fixture->lock);
    aws_condition_variable_clean_up(&test_fixture->signal);
}

/*********************************************************************************************************************
 * TESTS
 ********************************************************************************************************************/

static int s_secure_tunneling_serializer_data_message_test_fn(struct aws_allocator *allocator, void *ctx) {
    // aws_iotdevice_library_init(allocator);
    aws_http_library_init(allocator);
    aws_iotdevice_library_init(allocator);

    struct secure_tunnel_test_options test_options;
    s_secure_tunnel_test_init_default_options(&test_options);

    struct aws_secure_tunnel_mock_test_fixture_options test_fixture_options = {
        .secure_tunnel_options = &test_options.secure_tunnel_options,
        .server_function_table = &test_options.server_function_table,
    };

    struct aws_secure_tunnel_mock_test_fixture test_context;
    ASSERT_SUCCESS(aws_secure_tunnel_mock_test_fixture_init(&test_context, allocator, &test_fixture_options));

    struct aws_secure_tunnel *secure_tunnel = test_context.secure_tunnel;

    ASSERT_SUCCESS(aws_secure_tunnel_start(secure_tunnel));
    s_wait_for_connected_successfully(&test_context);

    aws_secure_tunnel_mock_test_fixture_clean_up(&test_context);
    // aws_iotdevice_library_clean_up();
    aws_http_library_clean_up();
    aws_iotdevice_library_clean_up();

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(secure_tunneling_serializer_data_message_test, s_secure_tunneling_serializer_data_message_test_fn)
