#include <aws/common/condition_variable.h>
#include <aws/common/mutex.h>
#include <aws/http/http.h>
#include <aws/io/channel_bootstrap.h>
#include <aws/io/event_loop.h>
#include <aws/io/socket.h>
#include <aws/iotdevice/iotdevice.h>
#include <aws/iotdevice/secure_tunneling.h>
#include <aws/testing/aws_test_harness.h>
#include <unistd.h>

#define UNUSED(x) (void)(x)

static struct aws_mutex mutex = AWS_MUTEX_INIT;
static struct aws_condition_variable condition_variable = AWS_CONDITION_VARIABLE_INIT;

static void s_on_connection_complete(const struct aws_secure_tunnel *secure_tunnel) {
    UNUSED(secure_tunnel);

    aws_mutex_lock(&mutex);
    aws_condition_variable_notify_one(&condition_variable);
    aws_mutex_unlock(&mutex);
}

static void s_on_data_receive(const struct aws_secure_tunnel *secure_tunnel, const struct aws_byte_buf *data) {
    /* Didn't want to copy to a null terminated string. So just print out each character */
    for (size_t i = 0; i < data->len; i++) {
        printf("%c", data->buffer[i]);
    }
    printf("\n");
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
    struct aws_secure_tunneling_connection_config *config) {

    AWS_ZERO_STRUCT(*config);
    config->allocator = allocator;
    config->bootstrap = bootstrap;
    config->socket_options = socket_options;
    config->access_token = aws_byte_cursor_from_c_str(access_token);
    config->local_proxy_mode = local_proxy_mode;
    config->endpoint_host = aws_byte_cursor_from_c_str(endpoint);

    config->on_connection_complete = s_on_connection_complete;
    config->on_data_receive = s_on_data_receive;
    /* TODO: Initialize the rest of the callbacks */
}

int main(int argc, char **argv) {
    if (argc < 4) {
        printf(
            "3 args required, only %d passed. Usage:\n"
            "aws-c-iot-secure_tunneling-client [endpoint] [src|dest] [access_token]\n",
            argc - 1);
        return 1;
    }
    const char *endpoint = argv[1];
    enum aws_secure_tunneling_local_proxy_mode local_proxy_mode = s_local_proxy_mode_from_c_str(argv[2]);
    const char *access_token = argv[3];

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
    struct aws_host_resolver *resolver = aws_host_resolver_new_default(allocator, 8, elg, NULL);
    struct aws_client_bootstrap_options bootstrap_options = {
        .event_loop_group = elg,
        .host_resolver = resolver,
    };
    struct aws_client_bootstrap *bootstrap = aws_client_bootstrap_new(allocator, &bootstrap_options);

    struct aws_socket_options socket_options;
    AWS_ZERO_STRUCT(socket_options);
    socket_options.connect_timeout_ms = 3000;
    socket_options.type = AWS_SOCKET_STREAM;
    socket_options.domain = AWS_SOCKET_IPV6;

    /* setup secure tunneling connection config */
    struct aws_secure_tunneling_connection_config config;
    s_init_secure_tunneling_connection_config(
        allocator, bootstrap, &socket_options, access_token, local_proxy_mode, endpoint, &config);

    /* Create a secure tunnel object and connect */
    struct aws_secure_tunnel *secure_tunnel = aws_secure_tunnel_new(&config);
    secure_tunnel->vtable.connect(secure_tunnel);

    /* wait here until the connection is done */
    aws_mutex_lock(&mutex);
    ASSERT_SUCCESS(aws_condition_variable_wait(&condition_variable, &mutex));
    aws_mutex_unlock(&mutex);

    if (local_proxy_mode == AWS_SECURE_TUNNELING_DESTINATION_MODE) {
        /* Wait a little for data to show up */
        sleep(60);
    }

    /* clean up */
    secure_tunnel->vtable.close(secure_tunnel);
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
