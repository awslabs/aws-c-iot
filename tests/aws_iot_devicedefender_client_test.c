/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/common/array_list.h>
#include <aws/common/byte_buf.h>
#include <aws/common/error.h>
#include <aws/common/zero.h>
#include <aws/mqtt/client.h>
#include <aws/mqtt/mqtt.h>

#include <aws/io/channel.h>
#include <aws/io/channel_bootstrap.h>
#include <aws/io/event_loop.h>
#include <aws/io/logging.h>
#include <aws/io/socket.h>
#include <aws/io/socket_channel_handler.h>
#include <aws/io/tls_channel_handler.h>

#include <aws/iotdevice/device_defender.h>
#include <aws/iotdevice/iotdevice.h>

#include <aws/common/condition_variable.h>
#include <aws/common/device_random.h>
#include <aws/common/mutex.h>
#include <aws/common/string.h>
#include <aws/common/thread.h>
#include <aws/common/uuid.h>

#include <aws/testing/aws_test_harness.h>

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#ifdef WIN32
#    include <Windows.h>
#    define sleep Sleep
#else
#    include <unistd.h>
#endif

struct aws_iotdevice_defender_task *defender_task = NULL;
struct aws_mutex stop_mutex = AWS_MUTEX_INIT;
struct aws_condition_variable failure_stop_cv = AWS_CONDITION_VARIABLE_INIT;
struct aws_condition_variable *process_stop_cv;

const char s_client_id_prefix[] = "c-defender-agent-reference";

struct connection_args {
    struct aws_allocator *allocator;

    struct aws_mutex *mutex;
    struct aws_condition_variable *condition_variable;

    struct aws_mqtt_client_connection *connection;

    struct aws_iotdevice_defender_task_config *task_config;
    struct aws_event_loop *defender_event_loop;
};

static void s_mqtt_on_connection_complete(
    struct aws_mqtt_client_connection *connection,
    int error_code,
    enum aws_mqtt_connect_return_code return_code,
    bool session_present,
    void *userdata) {
    (void)connection;
    (void)error_code;
    (void)return_code;
    (void)session_present;
    struct connection_args *args = (struct connection_args *)userdata;

    AWS_FATAL_ASSERT(error_code == AWS_ERROR_SUCCESS);
    AWS_FATAL_ASSERT(return_code == AWS_MQTT_CONNECT_ACCEPTED);
    AWS_FATAL_ASSERT(session_present == false);

    AWS_FATAL_ASSERT(
        AWS_OP_SUCCESS ==
        aws_iotdevice_defender_task_create(&defender_task, args->task_config, connection, args->defender_event_loop));
    AWS_FATAL_ASSERT(defender_task != NULL);
}

static void s_on_connection_interrupted(struct aws_mqtt_client_connection *connection, int error_code, void *userdata) {
    (void)connection;
    (void)userdata;
    (void)error_code;
}

static void s_on_resubscribed(
    struct aws_mqtt_client_connection *connection,
    uint16_t packet_id,
    const struct aws_array_list *topic_subacks,
    int error_code,
    void *userdata) {
    (void)connection;
    (void)packet_id;
    (void)userdata;

    AWS_FATAL_ASSERT(error_code == AWS_ERROR_SUCCESS);

    size_t num_topics = aws_array_list_length(topic_subacks);
    for (size_t i = 0; i < num_topics; ++i) {
        struct aws_mqtt_topic_subscription sub_i;
        aws_array_list_get_at(topic_subacks, &sub_i, i);
        AWS_FATAL_ASSERT(sub_i.qos != AWS_MQTT_QOS_FAILURE);
    }
}

static void s_on_connection_resumed(
    struct aws_mqtt_client_connection *connection,
    enum aws_mqtt_connect_return_code return_code,
    bool session_present,
    void *userdata) {
    (void)connection;
    (void)userdata;
    (void)return_code;

    if (!session_present) {
        uint16_t packet_id = aws_mqtt_resubscribe_existing_topics(connection, s_on_resubscribed, NULL);
        AWS_FATAL_ASSERT(packet_id);
    }
}

static void s_mqtt_on_disconnect(struct aws_mqtt_client_connection *connection, void *userdata) {
    (void)connection;
    struct connection_args *args = userdata;

    aws_mqtt_client_connection_release(args->connection);
    args->connection = NULL;

    aws_mutex_lock(args->mutex);
    aws_condition_variable_notify_one(args->condition_variable);
    aws_mutex_unlock(args->mutex);
}

static int get_number_metric(double *out, void *userdata) {
    (void)userdata;
    *out = 42;
    return AWS_OP_SUCCESS;
}

static int get_number_list_metric(struct aws_array_list *to_write_list, void *userdata) {
    (void)userdata;
    double number = 64;
    aws_array_list_push_back(to_write_list, &number);
    number = 128;
    aws_array_list_push_back(to_write_list, &number);
    number = 256;
    aws_array_list_push_back(to_write_list, &number);

    return AWS_OP_SUCCESS;
}

static int get_string_list_metric(struct aws_array_list *to_write_list, void *userdata) {
    struct connection_args *args = userdata;
    struct aws_allocator *allocator = args->allocator;
    struct aws_string *string_value = aws_string_new_from_c_str(allocator, "foo");
    aws_array_list_push_back(to_write_list, &string_value);
    string_value = aws_string_new_from_c_str(allocator, "bar");
    aws_array_list_push_back(to_write_list, &string_value);
    string_value = aws_string_new_from_c_str(allocator, "donkey");
    aws_array_list_push_back(to_write_list, &string_value);

    return AWS_OP_SUCCESS;
}

static int get_ip_list_metric(struct aws_array_list *to_write_list, void *userdata) {
    struct connection_args *args = userdata;
    struct aws_allocator *allocator = args->allocator;
    struct aws_string *ip_value = aws_string_new_from_c_str(allocator, "127.0.0.1");
    aws_array_list_push_back(to_write_list, &ip_value);
    ip_value = aws_string_new_from_c_str(allocator, "192.168.1.100");
    aws_array_list_push_back(to_write_list, &ip_value);
    ip_value = aws_string_new_from_c_str(allocator, "08:00:27:d1:ea:38");
    /* intentionally showing different way of constructing strings is still managed correctly in report */
    AWS_STRING_FROM_LITERAL(example_ipv6, "2001:db8:3333:4444:5555:6666:7777:8888");
    aws_array_list_push_back(to_write_list, &example_ipv6);
    AWS_STRING_FROM_LITERAL(ipv6, "fe80::843:a8ff:fe18:a879");
    aws_array_list_push_back(to_write_list, &ipv6);

    return AWS_OP_SUCCESS;
}

void s_report_accepted(const struct aws_byte_cursor *payload, void *userdata) {
    (void)userdata;
    printf("Report submission accepted reply: " PRInSTR "\n", AWS_BYTE_CURSOR_PRI(*payload));
}

void s_report_rejected(const struct aws_byte_cursor *payload, void *userdata) {
    (void)userdata;
    printf("Report submission rejected reply: " PRInSTR "\n", AWS_BYTE_CURSOR_PRI(*payload));
}

void s_task_failure(bool is_task_stopped, int error_code, void *userdata) {
    (void)userdata;
    printf("Defender task failed: %s\n", aws_error_name(error_code));

    if (is_task_stopped) {
        aws_condition_variable_notify_one(&failure_stop_cv);
    }
}

int main(int argc, char **argv) {
    if (argc < 5) {
        printf(
            "4 args required, only %d passed. Usage:\n"
            "aws-c-mqtt-iot-client [endpoint] [certificate] [private_key] [root_ca]\n",
            argc - 1);
        return 1;
    }

    const char *endpoint = argv[1];
    const char *cert = argv[2];
    const char *private_key = argv[3];
    const char *root_ca = argv[4];

    struct aws_allocator *allocator = aws_mem_tracer_new(aws_default_allocator(), NULL, AWS_MEMTRACE_BYTES, 0);

    struct aws_mutex mutex = AWS_MUTEX_INIT;
    struct aws_condition_variable condition_variable = AWS_CONDITION_VARIABLE_INIT;
    process_stop_cv = &condition_variable;

    struct connection_args args;
    AWS_ZERO_STRUCT(args);
    args.allocator = allocator;
    args.mutex = &mutex;
    args.condition_variable = &condition_variable;

    aws_iotdevice_library_init(args.allocator);

    struct aws_logger_standard_options logger_options = {
        .level = AWS_LL_TRACE,
        .file = stdout,
    };

    struct aws_logger logger;
    aws_logger_init_standard(&logger, args.allocator, &logger_options);
    aws_logger_set(&logger);

    struct aws_event_loop_group *elg = aws_event_loop_group_new_default(args.allocator, 1, NULL);
    /* defender task explicitly gets told which event loop to work on */
    args.defender_event_loop = aws_event_loop_group_get_next_loop(elg);

    struct aws_host_resolver_default_options host_resolver_default_options;
    AWS_ZERO_STRUCT(host_resolver_default_options);
    host_resolver_default_options.max_entries = 8;
    host_resolver_default_options.el_group = elg;
    host_resolver_default_options.shutdown_options = NULL;
    host_resolver_default_options.system_clock_override_fn = NULL;
    struct aws_host_resolver *resolver = aws_host_resolver_new_default(args.allocator, &host_resolver_default_options);
    struct aws_client_bootstrap_options bootstrap_options = {
        .event_loop_group = elg,
        .host_resolver = resolver,
    };
    struct aws_client_bootstrap *bootstrap = aws_client_bootstrap_new(args.allocator, &bootstrap_options);

    struct aws_tls_ctx_options tls_ctx_opt;
    ASSERT_SUCCESS(aws_tls_ctx_options_init_client_mtls_from_path(&tls_ctx_opt, args.allocator, cert, private_key));
    ASSERT_SUCCESS(aws_tls_ctx_options_set_alpn_list(&tls_ctx_opt, "x-amzn-mqtt-ca"));
    ASSERT_SUCCESS(aws_tls_ctx_options_override_default_trust_store_from_path(&tls_ctx_opt, NULL, root_ca));

    struct aws_tls_ctx *tls_ctx = aws_tls_client_ctx_new(args.allocator, &tls_ctx_opt);
    ASSERT_NOT_NULL(tls_ctx);

    aws_tls_ctx_options_clean_up(&tls_ctx_opt);

    struct aws_tls_connection_options tls_con_opt;
    aws_tls_connection_options_init_from_ctx(&tls_con_opt, tls_ctx);

    struct aws_socket_options socket_options;
    AWS_ZERO_STRUCT(socket_options);
    socket_options.connect_timeout_ms = 3000;
    socket_options.type = AWS_SOCKET_STREAM;
    socket_options.domain = AWS_SOCKET_IPV6;

    struct aws_mqtt_client *client = aws_mqtt_client_new(args.allocator, bootstrap);

    struct aws_byte_cursor host_name_cur = aws_byte_cursor_from_c_str(endpoint);
    args.connection = aws_mqtt_client_connection_new(client);

    ASSERT_SUCCESS(aws_mqtt_client_connection_set_connection_interruption_handlers(
        args.connection, s_on_connection_interrupted, NULL, s_on_connection_resumed, NULL));

    char client_id[128];
    struct aws_byte_buf client_id_buf = aws_byte_buf_from_empty_array(client_id, AWS_ARRAY_SIZE(client_id));

    aws_byte_buf_write(&client_id_buf, (const uint8_t *)s_client_id_prefix, AWS_ARRAY_SIZE(s_client_id_prefix));

    struct aws_uuid uuid;
    aws_uuid_init(&uuid);
    aws_uuid_to_str(&uuid, &client_id_buf);

    struct aws_byte_cursor client_id_cur = aws_byte_cursor_from_buf(&client_id_buf);
    struct aws_byte_cursor thing_name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("RaspberryPi");
    struct aws_iotdevice_defender_task_config *task_config = NULL;
    ASSERT_SUCCESS(aws_iotdevice_defender_config_create(&task_config, allocator, &thing_name, AWS_IDDRF_JSON));
    args.task_config = task_config;

    ASSERT_SUCCESS(aws_iotdevice_defender_config_set_report_accepted_fn(task_config, s_report_accepted));
    ASSERT_SUCCESS(aws_iotdevice_defender_config_set_report_rejected_fn(task_config, s_report_rejected));
    ASSERT_SUCCESS(aws_iotdevice_defender_config_set_task_failure_fn(task_config, s_task_failure));

    struct aws_byte_cursor name_metric_number = aws_byte_cursor_from_c_str("TestCustomMetricNumber");
    aws_iotdevice_defender_config_register_number_metric(task_config, &name_metric_number, get_number_metric, &args);

    struct aws_byte_cursor name_metric_number_list = aws_byte_cursor_from_c_str("TestCustomMetricNumberList");
    aws_iotdevice_defender_config_register_number_list_metric(
        task_config, &name_metric_number_list, get_number_list_metric, &args);

    struct aws_byte_cursor name_metric_string_list = aws_byte_cursor_from_c_str("TestCustomMetricStringList");
    aws_iotdevice_defender_config_register_string_list_metric(
        task_config, &name_metric_string_list, get_string_list_metric, &args);

    struct aws_byte_cursor name_metric_ip_list = aws_byte_cursor_from_c_str("TestCustomMetricIpList");
    aws_iotdevice_defender_config_register_ip_list_metric(task_config, &name_metric_ip_list, get_ip_list_metric, &args);

    struct aws_mqtt_connection_options conn_options = {
        .host_name = host_name_cur,
        .port = 8883,
        .socket_options = &socket_options,
        .tls_options = &tls_con_opt,
        .client_id = client_id_cur,
        .keep_alive_time_secs = 0,
        .ping_timeout_ms = 0,
        .on_connection_complete = s_mqtt_on_connection_complete,
        .user_data = &args,
        .clean_session = true,
    };

    aws_mqtt_client_connection_connect(args.connection, &conn_options);
    aws_tls_connection_options_clean_up(&tls_con_opt);

    aws_mutex_lock(&stop_mutex);
    ASSERT_SUCCESS(aws_condition_variable_wait(&condition_variable, &stop_mutex));
    aws_mutex_unlock(&stop_mutex);

    aws_iotdevice_defender_task_clean_up(defender_task);

    aws_mqtt_client_connection_disconnect(args.connection, s_mqtt_on_disconnect, &args);

    aws_mqtt_client_release(client);

    aws_client_bootstrap_release(bootstrap);

    aws_host_resolver_release(resolver);
    aws_event_loop_group_release(elg);

    aws_tls_ctx_release(tls_ctx);

    aws_logger_clean_up(&logger);

    aws_iotdevice_library_clean_up();

    ASSERT_UINT_EQUALS(0, aws_mem_tracer_count(allocator));
    allocator = aws_mem_tracer_destroy(allocator);
    ASSERT_NOT_NULL(allocator);

    return AWS_OP_SUCCESS;
}
