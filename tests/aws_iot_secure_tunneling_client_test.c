/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/common/condition_variable.h>
#include <aws/common/mutex.h>
#include <aws/http/http.h>
#include <aws/io/channel_bootstrap.h>
#include <aws/io/event_loop.h>
#include <aws/io/socket.h>
#include <aws/iotdevice/iotdevice.h>
#include <aws/iotdevice/secure_tunneling.h>
#include <aws/testing/aws_test_harness.h>

#define UNUSED(x) (void)(x)

static struct aws_mutex mutex = AWS_MUTEX_INIT;
static struct aws_condition_variable condition_variable = AWS_CONDITION_VARIABLE_INIT;

static int on_send_data_complete_error_code = 0;

static void s_on_send_data_complete(int error_code, void *user_data) {
    UNUSED(user_data);
    on_send_data_complete_error_code = error_code;
}

static void s_on_connection_complete(void *user_data) {
    UNUSED(user_data);
    aws_mutex_lock(&mutex);
    aws_condition_variable_notify_one(&condition_variable);
    aws_mutex_unlock(&mutex);
}

static void s_on_connection_shutdown(void *user_data) {
    UNUSED(user_data);
}

static void s_on_data_receive(const struct aws_byte_buf *data, void *user_data) {
    AWS_LOGF_INFO(AWS_LS_IOTDEVICE_SECURE_TUNNELING, "Client received data:");

    struct aws_allocator *allocator = (struct aws_allocator *)user_data;

    struct aws_byte_cursor data_cursor = aws_byte_cursor_from_buf(data);
    struct aws_byte_buf data_to_print;
    aws_byte_buf_init(&data_to_print, allocator, data->len + 1); /* +1 for null terminator */
    aws_byte_buf_append(&data_to_print, &data_cursor);
    aws_byte_buf_append_null_terminator(&data_to_print);
    AWS_LOGF_INFO(AWS_LS_IOTDEVICE_SECURE_TUNNELING, "%s", (char *)data_to_print.buffer);

    aws_byte_buf_clean_up(&data_to_print);
}

// static void s_on_stream_start(void *user_data) {
//     UNUSED(user_data);
//     AWS_LOGF_INFO(AWS_LS_IOTDEVICE_SECURE_TUNNELING, "Client received StreamStart.");
// }

// static void s_on_stream_reset(void *user_data) {
//     UNUSED(user_data);
//     AWS_LOGF_INFO(AWS_LS_IOTDEVICE_SECURE_TUNNELING, "Client received StreamReset.");
// }

static void s_on_session_reset(void *user_data) {
    UNUSED(user_data);
    AWS_LOGF_INFO(AWS_LS_IOTDEVICE_SECURE_TUNNELING, "Client received SessionReset.");
}

enum aws_secure_tunneling_local_proxy_mode s_local_proxy_mode_from_c_str(const char *local_proxy_mode) {
    if (strcmp(local_proxy_mode, "src") == 0) {
        return AWS_SECURE_TUNNELING_SOURCE_MODE;
    }
    return AWS_SECURE_TUNNELING_DESTINATION_MODE;
}

static void s_init_secure_tunneling_connection_config(
    struct aws_allocator *allocator,
    struct aws_client_bootstrap *bootstrap,
    struct aws_socket_options *socket_options,
    const char *access_token,
    enum aws_secure_tunneling_local_proxy_mode local_proxy_mode,
    const char *endpoint,
    const char *root_ca,
    struct aws_secure_tunnel_options *config) {

    AWS_ZERO_STRUCT(*config);
    config->allocator = allocator;
    config->bootstrap = bootstrap;
    config->socket_options = socket_options;

    config->access_token = aws_byte_cursor_from_c_str(access_token);
    config->local_proxy_mode = local_proxy_mode;
    config->endpoint_host = aws_byte_cursor_from_c_str(endpoint);
    config->root_ca = root_ca;

    config->on_connection_complete = s_on_connection_complete;
    config->on_connection_shutdown = s_on_connection_shutdown;
    config->on_send_data_complete = s_on_send_data_complete;
    config->on_data_receive = s_on_data_receive;
    // config->on_stream_start = s_on_stream_start;
    // config->on_stream_reset = s_on_stream_reset;
    config->on_session_reset = s_on_session_reset;

    config->user_data = allocator;
}

int main(int argc, char **argv) {
    if (argc < 5) {
        printf(
            "3 args required, only %d passed. Usage:\n"
            "aws-c-iot-secure_tunneling-client [endpoint] [src|dest] [root_ca] [access_token]\n",
            argc - 1);
        return 1;
    }
    const char *endpoint = argv[1];
    enum aws_secure_tunneling_local_proxy_mode local_proxy_mode = s_local_proxy_mode_from_c_str(argv[2]);
    const char *root_ca = argv[3];
    const char *access_token = argv[4];

    struct aws_allocator *allocator = aws_mem_tracer_new(aws_default_allocator(), NULL, AWS_MEMTRACE_BYTES, 0);

    aws_http_library_init(allocator);
    aws_iotdevice_library_init(allocator);

    struct aws_logger_standard_options logger_options = {
        .level = AWS_LL_TRACE,
        .file = stdout,
    };
    struct aws_logger logger;
    aws_logger_init_standard(&logger, allocator, &logger_options);
    aws_logger_set(&logger);

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

    struct aws_socket_options socket_options;
    AWS_ZERO_STRUCT(socket_options);
    socket_options.connect_timeout_ms = 3000;
    socket_options.type = AWS_SOCKET_STREAM;
    socket_options.domain = AWS_SOCKET_IPV4;

    /* setup secure tunneling connection config */
    struct aws_secure_tunnel_options config;
    s_init_secure_tunneling_connection_config(
        allocator, bootstrap, &socket_options, access_token, local_proxy_mode, endpoint, root_ca, &config);

    /* Create a secure tunnel object and connect */
    struct aws_secure_tunnel *secure_tunnel = aws_secure_tunnel_new(&config);
    aws_secure_tunnel_start(secure_tunnel);

    /* wait here until the connection is done */
    aws_mutex_lock(&mutex);
    ASSERT_SUCCESS(aws_condition_variable_wait(&condition_variable, &mutex));
    aws_mutex_unlock(&mutex);

    if (local_proxy_mode == AWS_SECURE_TUNNELING_SOURCE_MODE) {
        // AWS_RETURN_ERROR_IF2(aws_secure_tunnel_stream_start(secure_tunnel) == AWS_OP_SUCCESS, AWS_OP_ERR);

        int cLen = 500000;
        char *payload = malloc(cLen + 1);
        memset(payload, 'a', cLen);
        payload[cLen] = 0;
        // struct aws_byte_cursor cur = aws_byte_cursor_from_c_str(payload);
        // AWS_RETURN_ERROR_IF2(aws_secure_tunnel_send_data(secure_tunnel, &cur) == AWS_OP_SUCCESS, AWS_OP_ERR);

        // AWS_RETURN_ERROR_IF2(aws_secure_tunnel_stream_reset(secure_tunnel) == AWS_OP_SUCCESS, AWS_OP_ERR);
        ASSERT_SUCCESS(aws_condition_variable_wait(&condition_variable, &mutex));
    } else if (local_proxy_mode == AWS_SECURE_TUNNELING_DESTINATION_MODE) {
        /* Wait a little for data to show up */
        aws_thread_current_sleep((uint64_t)60 * 60 * 1000000000);
    }
    aws_thread_current_sleep((uint64_t)60 * 60 * 1000000000);

    /* clean up */
    aws_secure_tunnel_stop(secure_tunnel);
    aws_secure_tunnel_release(secure_tunnel);

    aws_client_bootstrap_release(bootstrap);
    aws_host_resolver_release(resolver);
    aws_event_loop_group_release(elg);
    aws_logger_clean_up(&logger);
    aws_iotdevice_library_clean_up();
    aws_http_library_clean_up();

    ASSERT_UINT_EQUALS(0, aws_mem_tracer_count(allocator));
    allocator = aws_mem_tracer_destroy(allocator);
    ASSERT_NOT_NULL(allocator);

    return AWS_OP_SUCCESS;
}
