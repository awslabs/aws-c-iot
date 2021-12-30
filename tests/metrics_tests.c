/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/common/byte_buf.h>
#include <aws/common/condition_variable.h>
#include <aws/common/mutex.h>
#include <aws/common/string.h>
#include <aws/common/thread.h>
#include <aws/io/channel_bootstrap.h>
#include <aws/io/event_loop.h>
#include <aws/io/host_resolver.h>
#include <aws/io/socket.h>
#include <aws/iotdevice/device_defender.h>
#include <aws/iotdevice/external/cJSON.h>
#include <aws/iotdevice/private/network.h>
#include <aws/mqtt/client.h>
#include <aws/mqtt/mqtt.h>
#include <aws/mqtt/private/mqtt_client_test_helper.h>
#include <aws/testing/aws_test_harness.h>

#ifdef AWS_OS_LINUX
#    include <errno.h>
#    include <fcntl.h>
#endif /* AWS_OS_LINUX */

const char *TM_NUMBER = "TestMetricNumber";
const char *TM_NUMBER_LIST = "TestMetricNumberList";
const char *TM_STRING_LIST = "TestMetricStringList";
const char *TM_IP_LIST = "TestMetricIpList";
const char *TM_NUMBER_FAIL = "TestMetricNumberFail";
const char *TM_NUMBER_LIST_FAIL = "TestMetricNumberListFail";
const char *TM_STRING_LIST_FAIL = "TestMetricStringListFail";
const char *TM_IP_LIST_FAIL = "TestMetricIpListFail";

struct mqtt_connection_test_data {
    struct aws_allocator *allocator;
    struct aws_client_bootstrap *client_bootstrap;
    struct aws_event_loop_group *el_group;
    struct aws_host_resolver *host_resolver;
    struct aws_socket_endpoint endpoint;
    struct aws_mqtt_client *mqtt_client;
    struct aws_mqtt_client_connection *mqtt_connection;
    struct aws_socket_options socket_options;
    struct aws_condition_variable cvar;
    struct aws_mutex lock;
    struct aws_byte_buf payload;
    bool task_stopped;

    /* the following two are only set if the publish failure callback is invoked */
    bool task_stopped_from_failure;
    int failure_error_code;
};

static struct mqtt_connection_test_data mqtt_test_data = {0};

static int validate_devicedefender_record(const char *value) {
    cJSON *report = cJSON_Parse(value);
    ASSERT_NOT_NULL(report);

    cJSON *header = cJSON_GetObjectItemCaseSensitive(report, "header");
    ASSERT_TRUE(cJSON_IsObject(header));
    cJSON *id = cJSON_GetObjectItem(header, "report_id");
    ASSERT_TRUE(cJSON_IsNumber(id));
    ASSERT_TRUE(id->valueint >= 0);
    cJSON *version = cJSON_GetObjectItem(header, "version");
    ASSERT_STR_EQUALS("1.0", cJSON_GetStringValue(version));

    cJSON *metrics = cJSON_GetObjectItemCaseSensitive(report, "metrics");

    cJSON *tcpPorts = cJSON_GetObjectItem(metrics, "listening_tcp_ports");
    ASSERT_TRUE(cJSON_IsObject(tcpPorts));
    ASSERT_TRUE(cJSON_IsArray(cJSON_GetObjectItem(tcpPorts, "ports")));

    cJSON *udpPorts = cJSON_GetObjectItem(metrics, "listening_udp_ports");
    ASSERT_TRUE(cJSON_IsObject(udpPorts));
    ASSERT_TRUE(cJSON_IsArray(cJSON_GetObjectItem(udpPorts, "ports")));

    cJSON *netstats = cJSON_GetObjectItem(metrics, "network_stats");
    ASSERT_TRUE(cJSON_IsObject(netstats));

    cJSON *connections = cJSON_GetObjectItem(metrics, "tcp_connections");
    ASSERT_TRUE(cJSON_IsObject(connections));
    cJSON *established = cJSON_GetObjectItem(connections, "established_connections");
    ASSERT_TRUE(cJSON_IsObject(established));
    ASSERT_TRUE(cJSON_IsArray(cJSON_GetObjectItem(established, "connections")));

    cJSON_Delete(report);
    return AWS_OP_SUCCESS;
}

const int64_t cm_number = 42;
const int64_t cm_number_list[] = {64, 128, 256};
const char *cm_string_list[] = {"foo", "bar", "donkey"};
const char *cm_ip_list[] = {
    "127.0.0.1",
    "192.168.1.100",
    "2001:db8:3333:4444:5555:6666:7777:8888",
    "fe80::843:a8ff:fe18:a879",
};

#define dd_value_len 256
static int validate_devicedefender_custom_record(const char *json_report) {
    char value_to_cmp[dd_value_len]; /* increase size if we ever need larger */
    cJSON *report = cJSON_Parse(json_report);
    ASSERT_NOT_NULL(report);

    cJSON *custom_metrics = cJSON_GetObjectItemCaseSensitive(report, "custom_metrics");
    ASSERT_TRUE(cJSON_IsObject(custom_metrics));

    cJSON *number_metric = cJSON_GetObjectItemCaseSensitive(custom_metrics, "TestMetricNumber");
    ASSERT_TRUE(cJSON_IsArray(number_metric));
    cJSON *number_metric_container = cJSON_GetArrayItem(number_metric, 0);
    ASSERT_TRUE(cJSON_IsObject(number_metric_container));
    cJSON *number_obj = cJSON_GetObjectItemCaseSensitive(number_metric_container, "number");
    cJSON_PrintPreallocated(number_obj, value_to_cmp, dd_value_len, cJSON_False);
    ASSERT_STR_EQUALS("42", value_to_cmp);

    cJSON *number_metric_fail = cJSON_GetObjectItemCaseSensitive(custom_metrics, "TestMetricNumberFail");
    ASSERT_NULL(number_metric_fail);

    cJSON *number_list_metric = cJSON_GetObjectItemCaseSensitive(custom_metrics, "TestMetricNumberList");
    ASSERT_TRUE(cJSON_IsArray(number_list_metric));
    cJSON *number_list_metric_container = cJSON_GetArrayItem(number_list_metric, 0);
    ASSERT_TRUE(cJSON_IsObject(number_list_metric_container));
    cJSON *number_list_array = cJSON_GetObjectItemCaseSensitive(number_list_metric_container, "number_list");
    ASSERT_TRUE(cJSON_IsArray(number_list_array));
    cJSON_PrintPreallocated(cJSON_GetArrayItem(number_list_array, 0), value_to_cmp, dd_value_len, cJSON_False);
    ASSERT_STR_EQUALS("64", value_to_cmp);
    cJSON_PrintPreallocated(cJSON_GetArrayItem(number_list_array, 1), value_to_cmp, dd_value_len, cJSON_False);
    ASSERT_STR_EQUALS("128", value_to_cmp);
    cJSON_PrintPreallocated(cJSON_GetArrayItem(number_list_array, 2), value_to_cmp, dd_value_len, cJSON_False);
    ASSERT_STR_EQUALS("256", value_to_cmp);

    cJSON *number_list_metric_fail = cJSON_GetObjectItemCaseSensitive(custom_metrics, "TestMetricNumberListFail");
    ASSERT_NULL(number_list_metric_fail);

    cJSON *string_list_metric = cJSON_GetObjectItemCaseSensitive(custom_metrics, "TestMetricStringList");
    ASSERT_TRUE(cJSON_IsArray(string_list_metric));
    cJSON *string_list_metric_container = cJSON_GetArrayItem(string_list_metric, 0);
    ASSERT_TRUE(cJSON_IsObject(string_list_metric_container));
    cJSON *string_list_array = cJSON_GetObjectItemCaseSensitive(string_list_metric_container, "string_list");
    ASSERT_TRUE(cJSON_IsArray(string_list_array));
    ASSERT_STR_EQUALS(cm_string_list[0], cJSON_GetStringValue(cJSON_GetArrayItem(string_list_array, 0)));
    cJSON_PrintPreallocated(cJSON_GetArrayItem(string_list_array, 1), value_to_cmp, dd_value_len, cJSON_False);
    ASSERT_STR_EQUALS(cm_string_list[1], cJSON_GetStringValue(cJSON_GetArrayItem(string_list_array, 1)));
    cJSON_PrintPreallocated(cJSON_GetArrayItem(string_list_array, 2), value_to_cmp, dd_value_len, cJSON_False);
    ASSERT_STR_EQUALS(cm_string_list[2], cJSON_GetStringValue(cJSON_GetArrayItem(string_list_array, 2)));

    cJSON *string_list_metric_fail = cJSON_GetObjectItemCaseSensitive(custom_metrics, "TestMetricStringListFail");
    ASSERT_NULL(string_list_metric_fail);

    cJSON *ip_list_metric = cJSON_GetObjectItemCaseSensitive(custom_metrics, "TestMetricIpList");
    ASSERT_TRUE(cJSON_IsArray(ip_list_metric));
    cJSON *ip_list_metric_container = cJSON_GetArrayItem(ip_list_metric, 0);
    ASSERT_TRUE(cJSON_IsObject(ip_list_metric_container));
    cJSON *ip_list_array = cJSON_GetObjectItemCaseSensitive(ip_list_metric_container, "ip_list");
    ASSERT_TRUE(cJSON_IsArray(ip_list_array));
    ASSERT_STR_EQUALS(cm_ip_list[0], cJSON_GetStringValue(cJSON_GetArrayItem(ip_list_array, 0)));
    cJSON_PrintPreallocated(cJSON_GetArrayItem(ip_list_array, 1), value_to_cmp, dd_value_len, cJSON_False);
    ASSERT_STR_EQUALS(cm_ip_list[1], cJSON_GetStringValue(cJSON_GetArrayItem(ip_list_array, 1)));
    cJSON_PrintPreallocated(cJSON_GetArrayItem(ip_list_array, 2), value_to_cmp, dd_value_len, cJSON_False);
    ASSERT_STR_EQUALS(cm_ip_list[2], cJSON_GetStringValue(cJSON_GetArrayItem(ip_list_array, 2)));
    cJSON_PrintPreallocated(cJSON_GetArrayItem(ip_list_array, 3), value_to_cmp, dd_value_len, cJSON_False);
    ASSERT_STR_EQUALS(cm_ip_list[3], cJSON_GetStringValue(cJSON_GetArrayItem(ip_list_array, 3)));

    cJSON *ip_list_metric_fail = cJSON_GetObjectItemCaseSensitive(custom_metrics, "TestMetricIpListFail");
    ASSERT_NULL(ip_list_metric_fail);

    cJSON_Delete(report);
    return AWS_OP_SUCCESS;
}

static int get_number_metric_fail(int64_t *out, void *userdata) {
    (void)userdata;
    *out = cm_number;
    return AWS_OP_ERR;
}

static int get_number_metric(int64_t *out, void *userdata) {
    (void)userdata;
    *out = cm_number;
    return AWS_OP_SUCCESS; /* let the caller know we wrote the data successfully */
}

static int get_number_metric_slow(int64_t *out, void *userdata) {
    (void)userdata;
    *out = cm_number;
    /* 2 seconds */
    aws_thread_current_sleep(2000000000);
    return AWS_OP_SUCCESS; /* let the caller know we wrote the data successfully */
}

static int get_number_list_metric_fail(struct aws_array_list *to_write_list, void *userdata) {
    (void)userdata;
    int64_t number = cm_number_list[0];
    aws_array_list_push_back(to_write_list, &number);
    number = cm_number_list[1];
    aws_array_list_push_back(to_write_list, &number);
    number = cm_number_list[2];
    aws_array_list_push_back(to_write_list, &number);

    return AWS_OP_ERR;
}

static int get_number_list_metric(struct aws_array_list *to_write_list, void *userdata) {
    (void)userdata;
    int64_t number = cm_number_list[0];
    aws_array_list_push_back(to_write_list, &number);
    number = cm_number_list[1];
    aws_array_list_push_back(to_write_list, &number);
    number = cm_number_list[2];
    aws_array_list_push_back(to_write_list, &number);

    return AWS_OP_SUCCESS;
}

static int get_string_list_metric_fail(struct aws_array_list *to_write_list, void *userdata) {
    struct mqtt_connection_test_data *test_data = userdata;
    struct aws_allocator *allocator = test_data->allocator;
    struct aws_string *string_value = aws_string_new_from_c_str(allocator, cm_string_list[0]);
    aws_array_list_push_back(to_write_list, &string_value);
    string_value = aws_string_new_from_c_str(allocator, cm_string_list[1]);
    aws_array_list_push_back(to_write_list, &string_value);
    string_value = aws_string_new_from_c_str(allocator, cm_string_list[2]);
    aws_array_list_push_back(to_write_list, &string_value);

    return AWS_OP_ERR;
}

static int get_string_list_metric(struct aws_array_list *to_write_list, void *userdata) {
    struct mqtt_connection_test_data *test_data = userdata;
    struct aws_allocator *allocator = test_data->allocator;
    struct aws_string *string_value = aws_string_new_from_c_str(allocator, cm_string_list[0]);
    aws_array_list_push_back(to_write_list, &string_value);
    string_value = aws_string_new_from_c_str(allocator, cm_string_list[1]);
    aws_array_list_push_back(to_write_list, &string_value);
    string_value = aws_string_new_from_c_str(allocator, cm_string_list[2]);
    aws_array_list_push_back(to_write_list, &string_value);

    return AWS_OP_SUCCESS;
}

static int get_ip_list_metric_fail(struct aws_array_list *to_write_list, void *userdata) {
    struct mqtt_connection_test_data *test_data = userdata;
    struct aws_allocator *allocator = test_data->allocator;
    struct aws_string *ip_value = aws_string_new_from_c_str(allocator, cm_ip_list[0]);
    aws_array_list_push_back(to_write_list, &ip_value);
    ip_value = aws_string_new_from_c_str(allocator, cm_ip_list[1]);
    aws_array_list_push_back(to_write_list, &ip_value);
    ip_value = aws_string_new_from_c_str(allocator, cm_ip_list[2]);
    aws_array_list_push_back(to_write_list, &ip_value);
    ip_value = aws_string_new_from_c_str(allocator, cm_ip_list[3]);
    aws_array_list_push_back(to_write_list, &ip_value);

    return AWS_OP_ERR;
}

static int get_ip_list_metric(struct aws_array_list *to_write_list, void *userdata) {
    struct mqtt_connection_test_data *test_data = userdata;
    struct aws_allocator *allocator = test_data->allocator;
    struct aws_string *ip_value = aws_string_new_from_c_str(allocator, cm_ip_list[0]);
    aws_array_list_push_back(to_write_list, &ip_value);
    ip_value = aws_string_new_from_c_str(allocator, cm_ip_list[1]);
    aws_array_list_push_back(to_write_list, &ip_value);
    ip_value = aws_string_new_from_c_str(allocator, cm_ip_list[2]);
    aws_array_list_push_back(to_write_list, &ip_value);
    ip_value = aws_string_new_from_c_str(allocator, cm_ip_list[3]);
    aws_array_list_push_back(to_write_list, &ip_value);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(devicedefender_task_unsupported_report_format, s_devicedefender_task_unsupported_report_format);
static int s_devicedefender_task_unsupported_report_format(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    struct aws_iotdevice_defender_task_config *config = NULL;
    struct aws_byte_cursor thing_name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("TestThing");
    ASSERT_FAILS(aws_iotdevice_defender_config_create(&config, allocator, &thing_name, AWS_IDDRF_CBOR));

    ASSERT_UINT_EQUALS(AWS_ERROR_IOTDEVICE_DEFENDER_UNSUPPORTED_REPORT_FORMAT, aws_last_error());
    aws_reset_error();

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(devicedefender_get_system_network_total, s_devicedefender_get_system_network_total);
static int s_devicedefender_get_system_network_total(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    struct aws_iotdevice_network_ifconfig ifconfig;
    AWS_ZERO_STRUCT(ifconfig);

    struct aws_iotdevice_network_iface {
        struct aws_allocator *allocator;
        char iface_name[16];
        char ipv4_addr_str[16];
        struct aws_iotdevice_metric_network_transfer metrics;
    };

    char ipv4_addr_1[16] = "192.168.0.0";
    struct aws_iotdevice_network_iface iface1 = {
        .metrics = {.bytes_in = 16, .bytes_out = 16, .packets_in = 16, .packets_out = 16}};

    char ipv4_addr_2[16] = "172.168.0.1";
    struct aws_iotdevice_network_iface iface2 = {
        .metrics = {.bytes_in = 4, .bytes_out = 8, .packets_in = 16, .packets_out = 24}};

    aws_hash_table_init(
        &ifconfig.iface_name_to_info,
        allocator,
        sizeof(struct aws_iotdevice_network_iface),
        aws_hash_c_string,
        aws_hash_callback_c_str_eq,
        NULL,
        NULL);

    aws_hash_table_put(&ifconfig.iface_name_to_info, ipv4_addr_1, &iface1, NULL);
    aws_hash_table_put(&ifconfig.iface_name_to_info, ipv4_addr_2, &iface2, NULL);

    struct aws_iotdevice_metric_network_transfer totals = {
        .bytes_in = 0, .bytes_out = 0, .packets_in = 0, .packets_out = 0};

    get_system_network_total(&totals, &ifconfig);

    ASSERT_INT_EQUALS((uint64_t)20, totals.bytes_in);
    ASSERT_INT_EQUALS((uint64_t)24, totals.bytes_out);
    ASSERT_INT_EQUALS((uint64_t)32, totals.packets_in);
    ASSERT_INT_EQUALS((uint64_t)40, totals.packets_out);

    aws_hash_table_clean_up(&ifconfig.iface_name_to_info);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(devicedefender_get_network_connections, s_devicedefender_get_network_connections);
static int s_devicedefender_get_network_connections(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    struct aws_iotdevice_network_ifconfig ifconfig;
    AWS_ZERO_STRUCT(ifconfig);
    ASSERT_SUCCESS(get_network_config_and_transfer(&ifconfig, allocator));

#ifdef AWS_OS_LINUX
    /* Regression test: Check that get_network_config_and_transfer didn't
     * accidentally close file descriptor 0 (aka stdin) */
    errno = 0;
    bool file_descriptor_0_is_closed = (fcntl(0, F_GETFD) == -1) && (errno != 0);
    ASSERT_FALSE(file_descriptor_0_is_closed);
#endif /* AWS_OS_LINUX */

    struct aws_array_list net_conns;
    AWS_ZERO_STRUCT(net_conns);
    aws_array_list_init_dynamic(&net_conns, allocator, 5, sizeof(struct aws_iotdevice_metric_net_connection));
    ASSERT_SUCCESS(get_network_connections(&net_conns, &ifconfig, allocator));

    for (size_t i = 0; i < net_conns.length; ++i) {
        struct aws_iotdevice_metric_net_connection *con = NULL;
        if (aws_array_list_get_at_ptr(&net_conns, (void **)&con, i)) {
            continue;
        }
        if (con->local_interface) {
            aws_string_destroy(con->local_interface);
        }
        if (con->remote_address) {
            aws_string_destroy(con->remote_address);
        }
    }
    aws_array_list_clean_up(&net_conns);
    aws_hash_table_clean_up(&ifconfig.iface_name_to_info);

    return AWS_OP_SUCCESS;
}

static int s_setup_mqtt_test_data_fn(struct aws_allocator *allocator, void *ctx) {
    aws_mqtt_library_init(allocator);

    struct mqtt_connection_test_data *state_test_data = ctx;
    AWS_ZERO_STRUCT(*state_test_data);

    state_test_data->allocator = allocator;
    state_test_data->el_group = aws_event_loop_group_new_default(allocator, 1, NULL);
    struct aws_host_resolver_default_options host_resolver_default_options;
    AWS_ZERO_STRUCT(host_resolver_default_options);
    host_resolver_default_options.max_entries = 1;
    host_resolver_default_options.el_group = state_test_data->el_group;
    host_resolver_default_options.shutdown_options = NULL;
    host_resolver_default_options.system_clock_override_fn = NULL;
    state_test_data->host_resolver = aws_host_resolver_new_default(allocator, &host_resolver_default_options);

    struct aws_client_bootstrap_options bootstrap_options = {
        .event_loop_group = state_test_data->el_group,
        .host_resolver = state_test_data->host_resolver,
    };

    state_test_data->client_bootstrap = aws_client_bootstrap_new(allocator, &bootstrap_options);
    state_test_data->mqtt_client = aws_mqtt_client_new(allocator, state_test_data->client_bootstrap);
    state_test_data->mqtt_connection = aws_mqtt_client_connection_new(state_test_data->mqtt_client);

    ASSERT_SUCCESS(aws_condition_variable_init(&state_test_data->cvar));
    ASSERT_SUCCESS(aws_mutex_init(&state_test_data->lock));
    state_test_data->task_stopped = false;

    return AWS_OP_SUCCESS;
}

static int s_clean_up_mqtt_test_data_fn(struct aws_allocator *allocator, int setup_result, void *ctx) {
    (void)allocator;

    if (!setup_result) {
        struct mqtt_connection_test_data *state_test_data = ctx;

        aws_mqtt_client_connection_release(state_test_data->mqtt_connection);
        aws_mqtt_client_release(state_test_data->mqtt_client);
        aws_client_bootstrap_release(state_test_data->client_bootstrap);
        aws_host_resolver_release(state_test_data->host_resolver);
        aws_event_loop_group_release(state_test_data->el_group);

        aws_thread_join_all_managed();

        if (aws_byte_buf_is_valid(&state_test_data->payload)) {
            aws_byte_buf_clean_up(&state_test_data->payload);
        }
    }

    aws_iotdevice_library_clean_up();
    aws_mqtt_library_clean_up();
    return AWS_OP_SUCCESS;
}

static void s_devicedefender_cb(void *userdata) {
    struct mqtt_connection_test_data *state_test_data = userdata;

    aws_mutex_lock(&state_test_data->lock);
    state_test_data->task_stopped = true;
    aws_mutex_unlock(&state_test_data->lock);
    aws_condition_variable_notify_one(&state_test_data->cvar);
}

AWS_TEST_CASE_FIXTURE(
    devicedefender_success_test,
    s_setup_mqtt_test_data_fn,
    s_devicedefender_success_test,
    s_clean_up_mqtt_test_data_fn,
    &mqtt_test_data);

static int s_publish_fn_copy_report(struct aws_byte_cursor payload, void *userdata) {
    struct mqtt_connection_test_data *state_test_data = userdata;

    aws_byte_buf_init_copy_from_cursor(&state_test_data->payload, state_test_data->allocator, payload);
    return AWS_OP_SUCCESS;
}

static int s_devicedefender_success_test(struct aws_allocator *allocator, void *ctx) {
    (void)allocator;
    struct mqtt_connection_test_data *state_test_data = ctx;
    aws_iotdevice_library_init(state_test_data->allocator);

    struct aws_iotdevice_defender_task_config *task_config = NULL;
    struct aws_byte_cursor thing_name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("TestSuccessThing");
    /* We are setting this error to verify that it has no impact on a successful
       return value of task config creation */
    aws_raise_error(AWS_ERROR_IOTDEVICE_DEFENDER_UNSUPPORTED_REPORT_FORMAT);
    ASSERT_SUCCESS(aws_iotdevice_defender_config_create(&task_config, allocator, &thing_name, AWS_IDDRF_JSON));

    aws_iotdevice_defender_config_set_callback_userdata(task_config, ctx);
    aws_iotdevice_defender_config_set_task_cancelation_fn(task_config, s_devicedefender_cb);
    aws_iotdevice_defender_config_set_task_period_ns(task_config, 1000000000UL);

    struct aws_iotdevice_defender_task *defender_task = NULL;
    ASSERT_SUCCESS(aws_iotdevice_defender_task_create_ex(
        &defender_task,
        task_config,
        s_publish_fn_copy_report,
        aws_event_loop_group_get_next_loop(state_test_data->el_group)));
    AWS_FATAL_ASSERT(defender_task != NULL);

    aws_iotdevice_defender_config_clean_up(task_config);
    task_config = NULL;

    /* clean up is also a cancel */
    aws_iotdevice_defender_task_clean_up(defender_task);
    defender_task = NULL;

    struct aws_byte_cursor payload = aws_byte_cursor_from_buf(&state_test_data->payload);
    validate_devicedefender_record((const char *)payload.ptr);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE_FIXTURE(
    devicedefender_custom_metrics_success_test,
    s_setup_mqtt_test_data_fn,
    s_devicedefender_custom_metrics_success_test,
    s_clean_up_mqtt_test_data_fn,
    &mqtt_test_data);

static int s_devicedefender_custom_metrics_success_test(struct aws_allocator *allocator, void *ctx) {
    (void)allocator;
    struct mqtt_connection_test_data *state_test_data = ctx;

    aws_iotdevice_library_init(state_test_data->allocator);
    struct aws_byte_cursor thing_name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("TestCustomMetricSuccessThing");
    struct aws_iotdevice_defender_task_config *task_config = NULL;
    ASSERT_SUCCESS(aws_iotdevice_defender_config_create(&task_config, allocator, &thing_name, AWS_IDDRF_JSON));

    aws_iotdevice_defender_config_set_callback_userdata(task_config, ctx);
    aws_iotdevice_defender_config_set_task_cancelation_fn(task_config, s_devicedefender_cb);
    aws_iotdevice_defender_config_set_task_period_ns(task_config, 1000000000UL);

    /* register working metrics */
    const struct aws_byte_cursor name_metric_number = aws_byte_cursor_from_c_str(TM_NUMBER);
    ASSERT_SUCCESS(
        aws_iotdevice_defender_config_register_number_metric(task_config, &name_metric_number, get_number_metric, ctx));

    const struct aws_byte_cursor name_metric_number_list = aws_byte_cursor_from_c_str(TM_NUMBER_LIST);
    ASSERT_SUCCESS(aws_iotdevice_defender_config_register_number_list_metric(
        task_config, &name_metric_number_list, get_number_list_metric, ctx));

    const struct aws_byte_cursor name_metric_string_list = aws_byte_cursor_from_c_str(TM_STRING_LIST);
    ASSERT_SUCCESS(aws_iotdevice_defender_config_register_string_list_metric(
        task_config, &name_metric_string_list, get_string_list_metric, ctx));

    const struct aws_byte_cursor name_metric_ip_list = aws_byte_cursor_from_c_str(TM_IP_LIST);
    ASSERT_SUCCESS(aws_iotdevice_defender_config_register_ip_list_metric(
        task_config, &name_metric_ip_list, get_ip_list_metric, ctx));

    /* register metrics with failing callbacks */
    const struct aws_byte_cursor name_metric_number_fail = aws_byte_cursor_from_c_str(TM_NUMBER_FAIL);
    ASSERT_SUCCESS(aws_iotdevice_defender_config_register_number_metric(
        task_config, &name_metric_number_fail, get_number_metric_fail, ctx));

    const struct aws_byte_cursor name_metric_number_list_fail = aws_byte_cursor_from_c_str(TM_NUMBER_LIST_FAIL);
    ASSERT_SUCCESS(aws_iotdevice_defender_config_register_number_list_metric(
        task_config, &name_metric_number_list_fail, get_number_list_metric_fail, ctx));

    const struct aws_byte_cursor name_metric_string_list_fail = aws_byte_cursor_from_c_str(TM_STRING_LIST_FAIL);
    ASSERT_SUCCESS(aws_iotdevice_defender_config_register_string_list_metric(
        task_config, &name_metric_string_list_fail, get_string_list_metric_fail, ctx));

    const struct aws_byte_cursor name_metric_ip_list_fail = aws_byte_cursor_from_c_str(TM_IP_LIST_FAIL);
    ASSERT_SUCCESS(aws_iotdevice_defender_config_register_ip_list_metric(
        task_config, &name_metric_ip_list_fail, get_ip_list_metric_fail, ctx));

    struct aws_iotdevice_defender_task *defender_task = NULL;
    ASSERT_SUCCESS(aws_iotdevice_defender_task_create_ex(
        &defender_task,
        task_config,
        s_publish_fn_copy_report,
        aws_event_loop_group_get_next_loop(state_test_data->el_group)));
    AWS_FATAL_ASSERT(defender_task != NULL);

    aws_iotdevice_defender_config_clean_up(task_config);
    task_config = NULL;

    aws_iotdevice_defender_task_clean_up(defender_task);

    ASSERT_TRUE(state_test_data->task_stopped);

    struct aws_byte_cursor payload = aws_byte_cursor_from_buf(&state_test_data->payload);
    validate_devicedefender_custom_record((const char *)payload.ptr);

    return AWS_OP_SUCCESS;
}

void s_task_cancel_callback_called(void *userdata) {
    struct mqtt_connection_test_data *test_data = userdata;
    test_data->task_stopped = true;
}

AWS_TEST_CASE_FIXTURE(
    devicedefender_stop_while_running_test,
    s_setup_mqtt_test_data_fn,
    s_devicedefender_stop_while_running,
    s_clean_up_mqtt_test_data_fn,
    &mqtt_test_data);

static int s_devicedefender_stop_while_running(struct aws_allocator *allocator, void *ctx) {
    (void)allocator;
    struct mqtt_connection_test_data *state_test_data = ctx;

    aws_iotdevice_library_init(state_test_data->allocator);
    struct aws_byte_cursor thing_name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("TestCustomMetricSuccessThing");
    struct aws_iotdevice_defender_task_config *task_config = NULL;
    ASSERT_SUCCESS(aws_iotdevice_defender_config_create(&task_config, allocator, &thing_name, AWS_IDDRF_JSON));

    aws_iotdevice_defender_config_set_callback_userdata(task_config, ctx);
    aws_iotdevice_defender_config_set_task_cancelation_fn(task_config, s_devicedefender_cb);
    aws_iotdevice_defender_config_set_task_period_ns(task_config, 1000000000UL);

    /* use a slow metric getter to ensure cancel of the stop will wait */
    const struct aws_byte_cursor name_metric_number = aws_byte_cursor_from_c_str(TM_NUMBER);
    ASSERT_SUCCESS(aws_iotdevice_defender_config_register_number_metric(
        task_config, &name_metric_number, get_number_metric_slow, ctx));

    struct aws_iotdevice_defender_task *defender_task = NULL;
    ASSERT_SUCCESS(aws_iotdevice_defender_task_create_ex(
        &defender_task,
        task_config,
        s_publish_fn_copy_report,
        aws_event_loop_group_get_next_loop(state_test_data->el_group)));
    AWS_FATAL_ASSERT(defender_task != NULL);

    aws_iotdevice_defender_config_clean_up(task_config);
    task_config = NULL;

    aws_iotdevice_defender_task_clean_up(defender_task);
    defender_task = NULL;

    ASSERT_TRUE(state_test_data->task_stopped);

    // The third packet is the report publish
    uint16_t packet_id = 3;
    struct aws_byte_buf payload;
    AWS_ZERO_STRUCT(payload);
    aws_mqtt_client_get_payload_for_outstanding_publish_packet(
        state_test_data->mqtt_connection, packet_id, allocator, &payload);
    validate_devicedefender_record((const char *)payload.buffer);
    return AWS_OP_SUCCESS;
}

static int s_publish_fn_fails(struct aws_byte_cursor payload, void *userdata) {
    (void)payload;
    (void)userdata;
    return AWS_OP_ERR;
}

static void s_task_failure_fn(bool is_task_stopped, int error_code, void *userdata) {
    struct mqtt_connection_test_data *test_data = userdata;
    test_data->task_stopped_from_failure = is_task_stopped;
    test_data->failure_error_code = error_code;
}

AWS_TEST_CASE_FIXTURE(
    devicedefender_publish_failure_callback_invoked,
    s_setup_mqtt_test_data_fn,
    s_devicedefender_publish_failure_callback_invoked,
    s_clean_up_mqtt_test_data_fn,
    &mqtt_test_data);
static int s_devicedefender_publish_failure_callback_invoked(struct aws_allocator *allocator, void *ctx) {
    (void)allocator;
    struct mqtt_connection_test_data *state_test_data = ctx;

    aws_iotdevice_library_init(state_test_data->allocator);
    struct aws_byte_cursor thing_name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("TestCustomMetricSuccessThing");
    struct aws_iotdevice_defender_task_config *task_config = NULL;
    ASSERT_SUCCESS(aws_iotdevice_defender_config_create(&task_config, allocator, &thing_name, AWS_IDDRF_JSON));

    aws_iotdevice_defender_config_set_callback_userdata(task_config, ctx);
    aws_iotdevice_defender_config_set_task_cancelation_fn(task_config, s_devicedefender_cb);
    aws_iotdevice_defender_config_set_task_period_ns(task_config, 1000000000UL);
    aws_iotdevice_defender_config_set_task_failure_fn(task_config, s_task_failure_fn);

    const struct aws_byte_cursor name_metric_number = aws_byte_cursor_from_c_str(TM_NUMBER);
    ASSERT_SUCCESS(
        aws_iotdevice_defender_config_register_number_metric(task_config, &name_metric_number, get_number_metric, ctx));

    struct aws_iotdevice_defender_task *defender_task = NULL;
    ASSERT_SUCCESS(aws_iotdevice_defender_task_create_ex(
        &defender_task,
        task_config,
        s_publish_fn_fails,
        aws_event_loop_group_get_next_loop(state_test_data->el_group)));
    AWS_FATAL_ASSERT(defender_task != NULL);

    aws_iotdevice_defender_config_clean_up(task_config);
    task_config = NULL;

    aws_iotdevice_defender_task_clean_up(defender_task);
    defender_task = NULL;

    ASSERT_TRUE(state_test_data->task_stopped);

    return AWS_OP_SUCCESS;
}
