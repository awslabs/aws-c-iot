/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/common/clock.h>
#include <aws/common/command_line_parser.h>
#include <aws/common/condition_variable.h>
#include <aws/common/hash_table.h>
#include <aws/common/log_channel.h>
#include <aws/common/log_formatter.h>
#include <aws/common/log_writer.h>
#include <aws/common/mutex.h>
#include <aws/common/string.h>

#include <aws/io/channel_bootstrap.h>
#include <aws/io/event_loop.h>
#include <aws/io/logging.h>
#include <aws/io/socket.h>
#include <aws/io/stream.h>
#include <aws/io/tls_channel_handler.h>
#include <aws/io/uri.h>

#include <aws/http/http.h>

#include <aws/iotdevice/private/secure_tunneling_impl.h>
#include <aws/iotdevice/private/secure_tunneling_operations.h>
#include <aws/iotdevice/secure_tunneling.h>

#define SLEEP_TIME_NS 1000000000
#define MAX_WEBSOCKET_PAYLOAD 131076

struct app_ctx {
    struct aws_allocator *allocator;
    struct aws_secure_tunnel *secure_tunnel;
    struct aws_mutex lock;
    struct aws_condition_variable signal;
    struct aws_uri uri;
    uint16_t port;
    const char *cacert;
    const char *access_token;
    const char *access_token_file;
    const char *client_token;
    const char *client_token_file;
    int connect_timeout;
    enum aws_secure_tunneling_local_proxy_mode local_proxy_mode;

    struct aws_tls_connection_options tls_connection_options;

    const char *log_filename;
    enum aws_log_level log_level;
};

static void s_usage(int exit_code) {

    fprintf(stderr, "usage: securetunnel [options] endpoint\n");
    fprintf(stderr, " endpoint: url to connect to\n");
    fprintf(stderr, " access-token: token for secure tunnel\n");
    fprintf(stderr, " access-token-file: File containing token for secure tunnel\n");
    fprintf(stderr, "\n Options:\n\n");
    fprintf(stderr, " client-token: token for secure tunnel\n");
    fprintf(stderr, " client-token-file: File containing token for secure tunnel\n");
    fprintf(stderr, "      --cacert FILE: path to a CA certficate file.\n");
    fprintf(stderr, "      --connect-timeout INT: time in milliseconds to wait for a connection.\n");
    fprintf(stderr, "  -s, --source: use secure tunnel client in source mode.\n");
    fprintf(stderr, "  -d, --destination: use secure tunnel client in destination mode.\n");
    fprintf(stderr, "  -l, --log FILE: dumps logs to FILE instead of stderr.\n");
    fprintf(stderr, "  -v, --verbose: ERROR|INFO|DEBUG|TRACE: log level to configure. Default is none.\n");
    fprintf(stderr, "  -w, --websockets: use mqtt-over-websockets rather than direct mqtt\n");
    fprintf(stderr, "  -h, --help\n");
    fprintf(stderr, "            Display this message and quit.\n");
    exit(exit_code);
}

static struct aws_cli_option s_long_options[] = {
    {"cacert", AWS_CLI_OPTIONS_REQUIRED_ARGUMENT, NULL, 'a'},
    {"access-token", AWS_CLI_OPTIONS_REQUIRED_ARGUMENT, NULL, 't'},
    {"access-token-file", AWS_CLI_OPTIONS_REQUIRED_ARGUMENT, NULL, 'T'},
    {"client-token", AWS_CLI_OPTIONS_REQUIRED_ARGUMENT, NULL, 'c'},
    {"client-token-file", AWS_CLI_OPTIONS_REQUIRED_ARGUMENT, NULL, 'C'},
    {"source", AWS_CLI_OPTIONS_REQUIRED_ARGUMENT, NULL, 's'},
    {"destination", AWS_CLI_OPTIONS_REQUIRED_ARGUMENT, NULL, 'd'},
    {"connect-timeout", AWS_CLI_OPTIONS_REQUIRED_ARGUMENT, NULL, 'f'},
    {"log", AWS_CLI_OPTIONS_REQUIRED_ARGUMENT, NULL, 'l'},
    {"verbose", AWS_CLI_OPTIONS_REQUIRED_ARGUMENT, NULL, 'v'},
    {"help", AWS_CLI_OPTIONS_NO_ARGUMENT, NULL, 'h'},
    {"endpoint", AWS_CLI_OPTIONS_REQUIRED_ARGUMENT, NULL, 'E'},
    /* Per getopt(3) the last element of the array has to be filled with all zeros */
    {NULL, AWS_CLI_OPTIONS_NO_ARGUMENT, NULL, 0},
};

static void s_parse_options(int argc, char **argv, struct app_ctx *ctx) {
    bool uri_found = false;

    while (true) {
        int option_index = 0;
        int c = aws_cli_getopt_long(argc, argv, "a:t:T:c:C:s:d:f:l:v:h:", s_long_options, &option_index);
        if (c == -1) {
            break;
        }

        switch (c) {
            case 0:
                /* getopt_long() returns 0 if an option.flag is non-null */
                break;
            case 'a':
                ctx->cacert = aws_cli_optarg;
                break;
            case 't':
                ctx->access_token = aws_cli_optarg;
                break;
            case 'T':
                ctx->access_token_file = aws_cli_optarg;
                break;
            case 'c':
                ctx->client_token = aws_cli_optarg;
                break;
            case 'C':
                ctx->client_token_file = aws_cli_optarg;
                break;
            case 's':
                ctx->local_proxy_mode = AWS_SECURE_TUNNELING_SOURCE_MODE;
                break;
            case 'd':
                ctx->local_proxy_mode = AWS_SECURE_TUNNELING_DESTINATION_MODE;
                break;
            case 'f':
                ctx->connect_timeout = atoi(aws_cli_optarg);
                break;
            case 'l':
                ctx->log_filename = aws_cli_optarg;
                break;
            case 'v':
                if (!strcmp(aws_cli_optarg, "TRACE")) {
                    ctx->log_level = AWS_LL_TRACE;
                } else if (!strcmp(aws_cli_optarg, "INFO")) {
                    ctx->log_level = AWS_LL_INFO;
                } else if (!strcmp(aws_cli_optarg, "DEBUG")) {
                    ctx->log_level = AWS_LL_DEBUG;
                } else if (!strcmp(aws_cli_optarg, "ERROR")) {
                    ctx->log_level = AWS_LL_ERROR;
                } else if (!strcmp(aws_cli_optarg, "WARN")) {
                    ctx->log_level = AWS_LL_WARN;
                } else {
                    fprintf(stderr, "unsupported log level %s.\n", aws_cli_optarg);
                    s_usage(1);
                }
                break;
            case 'h':
                s_usage(0);
                break;
            case 0x02: {
                struct aws_byte_cursor uri_cursor = aws_byte_cursor_from_c_str(aws_cli_positional_arg);
                if (aws_uri_init_parse(&ctx->uri, ctx->allocator, &uri_cursor)) {
                    fprintf(
                        stderr,
                        "Failed to parse uri %s with error %s\n",
                        (char *)uri_cursor.ptr,
                        aws_error_debug_str(aws_last_error()));
                    s_usage(1);
                }
                uri_found = true;
                break;
            }

            default:
                fprintf(stderr, "Unknown option\n");
                s_usage(1);
        }
    }

    if (!uri_found) {
        fprintf(stderr, "A URI for the request must be supplied.\n");
        s_usage(1);
    }
}

static void s_on_message_received(const struct aws_secure_tunnel_message_view *message, void *user_data) {
    (void)user_data;
    if (message->service_id != NULL) {
        if (message->payload != NULL) {
            printf(
                "\nMessage received on service id: '" PRInSTR "' with payload: '" PRInSTR "'\n",
                AWS_BYTE_CURSOR_PRI(*message->service_id),
                AWS_BYTE_CURSOR_PRI(*message->payload));
        } else {
            printf(
                "\nMessage received on service id: '" PRInSTR "' with no payload\n",
                AWS_BYTE_CURSOR_PRI(*message->service_id));
        }
    } else if (message->payload != NULL) {
        printf("\nMessage received with payload: '" PRInSTR "'\n", AWS_BYTE_CURSOR_PRI(*message->payload));
    }
}

static void s_on_connection_complete(
    const struct aws_secure_tunnel_connection_view *connection_view,
    int error_code,
    void *user_data) {
    (void)connection_view;
    printf(
        "\nSecure Tunnel Client received s_on_connection_complete callback with error_code:%d (%s)\n",
        error_code,
        aws_error_name(error_code));
    struct app_ctx *ctx = user_data;
    struct aws_secure_tunnel *secure_tunnel = ctx->secure_tunnel;

    if (secure_tunnel->config->local_proxy_mode == AWS_SECURE_TUNNELING_DESTINATION_MODE) {
        printf("\nConnected in Destination Mode\n");
    } else {
        printf("\nConnected in Source Mode\nSending Stream Start\n");
        struct aws_byte_cursor service_id_cur = aws_byte_cursor_from_c_str("ssh");
        struct aws_secure_tunnel_message_view message_data = {.service_id = &service_id_cur};
        // struct aws_secure_tunnel_message_view message_data = {};

        printf("\nSending Stream Start Message\n");
        aws_secure_tunnel_stream_start(secure_tunnel, &message_data);
    }
}

static void s_on_connection_shutdown(int error_code, void *user_data) {
    (void)user_data;
    printf(
        "\nSecure Tunnel Client received s_on_connection_shutdown callback with error_code:%d (%s)\n",
        error_code,
        aws_error_name(error_code));
}

static void s_on_stream_start(
    const struct aws_secure_tunnel_message_view *message_view,
    int error_code,
    void *user_data) {
    (void)user_data;
    (void)error_code;
    if (message_view->service_id != NULL) {
        printf(
            "\nSecure Tunnel Client received s_on_stream_start callback with service id:" PRInSTR " stream id:%d",
            AWS_BYTE_CURSOR_PRI(*message_view->service_id),
            message_view->stream_id);
    }
    struct app_ctx *app_ctx_user = user_data;
    struct aws_secure_tunnel *secure_tunnel = app_ctx_user->secure_tunnel;
    if (secure_tunnel->config->local_proxy_mode == AWS_SECURE_TUNNELING_DESTINATION_MODE) {
        printf("\nStream Start recieved in Destination Mode\n");

        struct aws_byte_cursor payload_cur = aws_byte_cursor_from_c_str("TEST PAYLOAD");
        struct aws_secure_tunnel_message_view message_data = {
            .payload = &payload_cur,
            .service_id = message_view->service_id,
        };

        printf("\nSending Data Message\n");
        aws_secure_tunnel_send_message(secure_tunnel, &message_data);
    }
}

static void s_on_stream_reset(
    const struct aws_secure_tunnel_message_view *message_view,
    int error_code,
    void *user_data) {
    (void)user_data;
    (void)error_code;
    if (message_view->service_id != NULL) {
        printf(
            "\nSecure Tunnel Client received s_on_stream_reset callback with service id:" PRInSTR " stream id:%d",
            AWS_BYTE_CURSOR_PRI(*message_view->service_id),
            message_view->stream_id);
    }
}

static void s_on_send_data_complete(int error_code, void *user_data) {
    (void)user_data;
    printf(
        "\nSecure Tunnel Client received s_on_send_data_complete callback with error_code:%d (%s)\n",
        error_code,
        aws_error_name(error_code));
}

int main(int argc, char **argv) {

    /*****************************************************************************************************************
     *                                    Initialize
     *****************************************************************************************************************/
    struct aws_allocator *allocator = aws_mem_tracer_new(aws_default_allocator(), NULL, AWS_MEMTRACE_STACKS, 15);

    aws_io_library_init(allocator);
    aws_http_library_init(allocator);
    aws_iotdevice_library_init(allocator);

    struct app_ctx app_ctx;
    AWS_ZERO_STRUCT(app_ctx);
    app_ctx.allocator = allocator;
    app_ctx.signal = (struct aws_condition_variable)AWS_CONDITION_VARIABLE_INIT;
    app_ctx.connect_timeout = 3000;
    aws_mutex_init(&app_ctx.lock);
    app_ctx.port = 1883; /* STEVE TODO NOT NECESSARY */

    s_parse_options(argc, argv, &app_ctx);
    if (app_ctx.uri.port) {
        app_ctx.port = app_ctx.uri.port;
    }

    struct aws_logger logger;
    AWS_ZERO_STRUCT(logger);

    struct aws_logger_standard_options options = {
        .level = app_ctx.log_level,
    };

    if (app_ctx.log_level) {
        if (app_ctx.log_filename) {
            if (remove(app_ctx.log_filename)) {
                fprintf(stderr, "\nDeleted existing log\n");
            } else {
                fprintf(stderr, "\nFailed to delete existing log\n");
            }
            options.filename = app_ctx.log_filename;
        } else {
            options.file = stderr;
        }

        if (aws_logger_init_standard(&logger, allocator, &options)) {
            fprintf(stderr, "Failed to initialize logger with error %s\n", aws_error_debug_str(aws_last_error()));
            exit(1);
        }

        aws_logger_set(&logger);
    }

    struct aws_event_loop_group *el_group = aws_event_loop_group_new_default(allocator, 2, NULL);

    struct aws_host_resolver_default_options resolver_options = {
        .el_group = el_group,
        .max_entries = 8,
    };

    struct aws_host_resolver *resolver = aws_host_resolver_new_default(allocator, &resolver_options);

    struct aws_client_bootstrap_options bootstrap_options = {
        .event_loop_group = el_group,
        .host_resolver = resolver,
    };

    struct aws_client_bootstrap *bootstrap = aws_client_bootstrap_new(allocator, &bootstrap_options);

    struct aws_socket_options socket_options = {
        .type = AWS_SOCKET_STREAM,
        .connect_timeout_ms = (uint32_t)app_ctx.connect_timeout,
        .keep_alive_timeout_sec = 0,
        .keepalive = false,
        .keep_alive_interval_sec = 0,
    };

    /*****************************************************************************************************************
     *                                    Create Secure Tunnel
     *****************************************************************************************************************/

    /* ACCESS TOKEN */
    struct aws_byte_cursor access_token;
    AWS_ZERO_STRUCT(access_token);

    struct aws_byte_buf access_token_tmp;
    AWS_ZERO_STRUCT(access_token_tmp);
    if (app_ctx.access_token_file) {
        if (aws_byte_buf_init_from_file(&access_token_tmp, allocator, app_ctx.access_token_file)) {
            goto error;
        }
        access_token = aws_byte_cursor_from_buf(&access_token_tmp);
    }
    if (access_token.ptr == NULL) {
        access_token = aws_byte_cursor_from_array(app_ctx.access_token, strlen(app_ctx.access_token));
    }

    /* CLIENT TOKEN */
    struct aws_byte_cursor client_token;
    AWS_ZERO_STRUCT(client_token);
    struct aws_byte_buf client_token_tmp;
    AWS_ZERO_STRUCT(client_token_tmp);
    if (app_ctx.client_token_file) {
        if (aws_byte_buf_init_from_file(&client_token_tmp, allocator, app_ctx.client_token_file)) {
            goto error;
        }
        client_token = aws_byte_cursor_from_buf(&client_token_tmp);
    } else if (app_ctx.client_token != NULL) {
        client_token = aws_byte_cursor_from_array(app_ctx.client_token, strlen(app_ctx.client_token));
    }

    /* SECURE TUNNEL OPTIONS */
    struct aws_secure_tunnel_options secure_tunnel_options = {
        .endpoint_host = app_ctx.uri.host_name,
        .bootstrap = bootstrap,
        .socket_options = &socket_options,
        .access_token = access_token,
        .client_token = client_token,
        .on_message_received = &s_on_message_received,
        .on_connection_complete = &s_on_connection_complete,
        .on_connection_shutdown = &s_on_connection_shutdown,
        .on_stream_start = &s_on_stream_start,
        .on_stream_reset = &s_on_stream_reset,
        .on_send_data_complete = &s_on_send_data_complete,
        .local_proxy_mode = app_ctx.local_proxy_mode,
        .user_data = &app_ctx,
    };

    printf("\nCreating Secure Tunnel\n");
    struct aws_secure_tunnel *secure_tunnel = aws_secure_tunnel_new(allocator, &secure_tunnel_options);
    app_ctx.secure_tunnel = secure_tunnel;

    printf("\nStarting Secure Tunnel\n");
    aws_secure_tunnel_start(secure_tunnel);

    uint64_t start_1_sleep_time_sec = 30;
    bool is_keep_running = true;

    do {

        printf("\nRunning secure tunnel for %llu seconds\n", start_1_sleep_time_sec);
        aws_thread_current_sleep(SLEEP_TIME_NS * start_1_sleep_time_sec);

    } while (is_keep_running);

    uint16_t payload_size = (rand() % MAX_WEBSOCKET_PAYLOAD) + 1;
    uint8_t payload_data[MAX_WEBSOCKET_PAYLOAD];

    struct aws_byte_cursor payload_cur = {
        .ptr = payload_data,
        .len = payload_size,
    };

    struct aws_byte_cursor service_id_cur = aws_byte_cursor_from_c_str("ssh");

    struct aws_secure_tunnel_message_view message_data = {
        .stream_id = 0,
        .payload = &payload_cur,
        .service_id = &service_id_cur,
    };

    printf("\nSending Data Message\n");
    aws_secure_tunnel_send_message(secure_tunnel, &message_data);

    printf("\nRunning secure tunnel for %llu seconds\n", start_1_sleep_time_sec);
    aws_thread_current_sleep(SLEEP_TIME_NS * start_1_sleep_time_sec);

    printf("\nStopping Secure Tunnel\n");
    aws_secure_tunnel_stop(secure_tunnel);

    uint64_t stop_1_sleep_time_sec = 30;
    printf("\nSleeping after STOP for %llu seconds\n", stop_1_sleep_time_sec);
    aws_thread_current_sleep(SLEEP_TIME_NS * stop_1_sleep_time_sec);

    printf("\nStarting Secure Tunnel Again\n");
    aws_secure_tunnel_start(secure_tunnel);

    uint64_t start_2_sleep_time_sec = 120;
    printf("\nRunning secure tunnel for %llu seconds\n", start_2_sleep_time_sec);
    aws_thread_current_sleep(SLEEP_TIME_NS * start_2_sleep_time_sec);

    printf("\nStopping Secure Tunnel again\n");
    aws_secure_tunnel_stop(secure_tunnel);

    /* CLEAN UP */
    aws_secure_tunnel_release(secure_tunnel);
    aws_client_bootstrap_release(bootstrap);
    aws_host_resolver_release(resolver);
    aws_event_loop_group_release(el_group);
    aws_byte_buf_clean_up(&client_token_tmp);
    aws_byte_buf_clean_up(&access_token_tmp);

    aws_thread_join_all_managed();

    const size_t outstanding_bytes = aws_mem_tracer_bytes(allocator);
    printf("\n\nSummary:\n\n");
    printf("  Outstanding bytes: %zu\n\n", outstanding_bytes);

    if (app_ctx.log_level) {
        aws_logger_set(NULL);
        aws_logger_clean_up(&logger);
    }

    aws_uri_clean_up(&app_ctx.uri);

    aws_http_library_clean_up();
    aws_io_library_clean_up();
    aws_iotdevice_library_clean_up();

    const size_t leaked_bytes = aws_mem_tracer_bytes(allocator);
    if (leaked_bytes) {
        struct aws_logger memory_logger;
        AWS_ZERO_STRUCT(memory_logger);

        aws_logger_init_noalloc(&memory_logger, aws_default_allocator(), &options);
        aws_logger_set(&memory_logger);

        aws_mqtt_library_init(aws_default_allocator());

        printf("Writing memory leaks to log.\n");
        aws_mem_tracer_dump(allocator);

        aws_logger_set(NULL);
        aws_logger_clean_up(&memory_logger);

        aws_mqtt_library_clean_up();
    } else {
        printf("Finished, with no memory leaks\n");
    }

    aws_mem_tracer_destroy(allocator);

    return 0;

error:
    return 1;
}
