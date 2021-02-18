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

#include <stdio.h>
#include <stdlib.h>
#ifdef WIN32
#    include <Windows.h>
#    define sleep Sleep
#else
#    include <unistd.h>
#endif

struct aws_iotdevice_defender_v1_task *defender_task = NULL;

const char s_client_id_prefix[] = "c-defender-agent-reference";

struct connection_args {
    struct aws_allocator *allocator;

    struct aws_mutex *mutex;
    struct aws_condition_variable *condition_variable;

    struct aws_mqtt_client_connection *connection;

    struct aws_iotdevice_defender_report_task_config task_config;
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
    struct connection_args *connection_args = (struct connection_args *)userdata;

    AWS_FATAL_ASSERT(error_code == AWS_ERROR_SUCCESS);
    AWS_FATAL_ASSERT(return_code == AWS_MQTT_CONNECT_ACCEPTED);
    AWS_FATAL_ASSERT(session_present == false);

    printf("Client connected...");

    defender_task = aws_iotdevice_defender_v1_report_task(connection_args->allocator, &connection_args->task_config);
    AWS_FATAL_ASSERT(defender_task != NULL);
}

static void s_on_connection_interrupted(struct aws_mqtt_client_connection *connection, int error_code, void *userdata) {

    (void)connection;
    (void)userdata;
    printf("CONNECTION INTERRUPTED error_code=%d\n", error_code);
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
    printf("RESUBSCRIBE_COMPLETE. error_code=%d num_topics=%zu\n", error_code, num_topics);
    for (size_t i = 0; i < num_topics; ++i) {
        struct aws_mqtt_topic_subscription sub_i;
        aws_array_list_get_at(topic_subacks, &sub_i, i);
        printf("  topic=" PRInSTR " qos=%d\n", AWS_BYTE_CURSOR_PRI(sub_i.topic), sub_i.qos);
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

    printf("CONNECTION RESUMED return_code=%d session_present=%d\n", return_code, session_present);
    if (!session_present) {
        printf("RESUBSCRIBING...");
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

/**
 * Example function to get number data
 */
static int get_number_metric(int64_t *out, void *userdata) {
    (void)userdata;
    *out = 42;             /* the answer to everything right? */
    return AWS_OP_SUCCESS; /* let the caller know we wrote the data successfully */
}

static int get_number_list_metric(struct aws_array_list *to_write_list, void *userdata) {
    (void)userdata;
    int64_t number = 64;
    aws_array_list_push_back(to_write_list, &number);
    number = 128;
    aws_array_list_push_back(to_write_list, &number);
    number = 256;
    aws_array_list_push_back(to_write_list, &number);

    return AWS_OP_SUCCESS;
}

static int get_string_list_metric(struct aws_array_list *to_write_list, void *userdata) {
    struct aws_allocator *allocator = (struct aws_allocator *)userdata;
    struct aws_string *string_value = aws_string_new_from_c_str(allocator, "foo");
    aws_array_list_push_back(to_write_list, &string_value);
    string_value = aws_string_new_from_c_str(allocator, "bar");
    aws_array_list_push_back(to_write_list, &string_value);
    string_value = aws_string_new_from_c_str(allocator, "donkey");
    aws_array_list_push_back(to_write_list, &string_value);

    return AWS_OP_SUCCESS;
}

static int get_ip_list_metric(struct aws_array_list *to_write_list, void *userdata) {
    struct aws_allocator *allocator = (struct aws_allocator *)userdata;
    struct aws_string *ip_value = aws_string_new_from_c_str(allocator, "127.0.0.1");
    aws_array_list_push_back(to_write_list, &ip_value);
    ip_value = aws_string_new_from_c_str(allocator, "192.168.1.100");
    aws_array_list_push_back(to_write_list, &ip_value);
    ip_value = aws_string_new_from_c_str(allocator, "08:00:27:d1:ea:38");
    aws_array_list_push_back(to_write_list, &ip_value);

    return AWS_OP_SUCCESS;
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

    struct connection_args args;
    AWS_ZERO_STRUCT(args);
    args.allocator = allocator;
    args.mutex = &mutex;
    args.condition_variable = &condition_variable;

    aws_mqtt_library_init(args.allocator);
    aws_iotdevice_library_init(args.allocator);

    struct aws_logger_standard_options logger_options = {
        .level = AWS_LL_TRACE,
        .file = stdout,
    };

    struct aws_logger logger;
    aws_logger_init_standard(&logger, args.allocator, &logger_options);
    aws_logger_set(&logger);

    struct aws_event_loop_group *elg = aws_event_loop_group_new_default(args.allocator, 1, NULL);
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

    struct aws_iotdevice_defender_report_task_config task_config = {
        .userdata = NULL,
        .task_cancelled_fn = NULL,
        .connection = args.connection,
        .event_loop = aws_event_loop_group_get_next_loop(elg),
        .netconn_sample_period_ns = 5ull * 60ull * 1000000000ull,
        .report_format = AWS_IDDRF_JSON,
        .thing_name =
            AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("RaspberryPi"), /* TODO: make cli arg so policies can work */
        .task_period_ns = 5ull * 60ull * 1000000000ull};
    args.task_config = task_config;
    aws_array_list_init_dynamic(&args.task_config.custom_metrics, allocator, 0, sizeof(struct defender_custom_metric *));

    ASSERT_SUCCESS(aws_iotdevice_defender_register_number_metric(&args.task_config, allocator, "TestCustomMetricNumber",
                                                                                                                                get_number_metric, allocator));

    ASSERT_SUCCESS(aws_iotdevice_defender_register_number_list_metric(&args.task_config, allocator, "TestCustomMetricNumberList",
                                                                                                                                        get_number_list_metric, allocator));

    ASSERT_SUCCESS(aws_iotdevice_defender_register_string_list_metric(&args.task_config, allocator, "TestCustomMetricStringList",
                                                                                                                                get_string_list_metric, allocator));

    ASSERT_SUCCESS(aws_iotdevice_defender_register_ip_list_metric(&args.task_config, allocator, "TestCustomMetricIpList",
																 get_ip_list_metric, allocator));
    struct aws_mqtt_connection_options conn_options = {.host_name = host_name_cur,
                                                       .port = 8883,
                                                       .socket_options = &socket_options,
                                                       .tls_options = &tls_con_opt,
                                                       .client_id = client_id_cur,
                                                       .keep_alive_time_secs = 0,
                                                       .ping_timeout_ms = 0,
                                                       .on_connection_complete = s_mqtt_on_connection_complete,
                                                       .user_data = &args,
                                                       .clean_session = true};
    aws_array_list_init_dynamic(
        &args.task_config.custom_metrics, allocator, 0, sizeof(struct defender_custom_metric *));

    const struct aws_byte_cursor name_metric_number = aws_byte_cursor_from_c_str("TestCustomMetricNumber");
    ASSERT_SUCCESS(aws_iotdevice_defender_register_number_metric(
        &args.task_config, allocator, &name_metric_number, get_number_metric, allocator));

    const struct aws_byte_cursor name_metric_number_list = aws_byte_cursor_from_c_str("TestCustomMetricNumberList");
    ASSERT_SUCCESS(aws_iotdevice_defender_register_number_list_metric(
        &args.task_config, allocator, &name_metric_number_list, get_number_list_metric, allocator));

    const struct aws_byte_cursor name_metric_string_list = aws_byte_cursor_from_c_str("TestCustomMetricStringList");
    ASSERT_SUCCESS(aws_iotdevice_defender_register_string_list_metric(
        &args.task_config, allocator, &name_metric_string_list, get_string_list_metric, allocator));

    const struct aws_byte_cursor name_metric_ip_list = aws_byte_cursor_from_c_str("TestCustomMetricIpList");
    ASSERT_SUCCESS(aws_iotdevice_defender_register_ip_list_metric(
        &args.task_config, allocator, &name_metric_ip_list, get_ip_list_metric, allocator));

    struct aws_mqtt_connection_options conn_options = {.host_name = host_name_cur,
                                                       .port = 8883,
                                                       .socket_options = &socket_options,
                                                       .tls_options = &tls_con_opt,
                                                       .client_id = client_id_cur,
                                                       .keep_alive_time_secs = 0,
                                                       .ping_timeout_ms = 0,
                                                       .on_connection_complete = s_mqtt_on_connection_complete,
                                                       .user_data = &args,
                                                       .clean_session = true};

    aws_mqtt_client_connection_connect(args.connection, &conn_options);
    aws_tls_connection_options_clean_up(&tls_con_opt);

    // TODO: Revisit wait condition
    aws_mutex_lock(&mutex);
    ASSERT_SUCCESS(aws_condition_variable_wait(&condition_variable, &mutex));
    aws_mutex_unlock(&mutex);

    aws_mqtt_client_connection_disconnect(args.connection, s_mqtt_on_disconnect, &args);

    aws_mqtt_client_release(client);

    aws_client_bootstrap_release(bootstrap);

    aws_host_resolver_release(resolver);
    aws_event_loop_group_release(elg);

    aws_tls_ctx_release(tls_ctx);

    aws_logger_clean_up(&logger);

    aws_iotdevice_library_clean_up();
    aws_mqtt_library_clean_up();

    ASSERT_UINT_EQUALS(0, aws_mem_tracer_count(allocator));
    allocator = aws_mem_tracer_destroy(allocator);
    ASSERT_NOT_NULL(allocator);

    return AWS_OP_SUCCESS;
}
