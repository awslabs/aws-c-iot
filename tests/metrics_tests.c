/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */
#include "mqtt_mock_structs.h"
#include <aws/iotdevice/device_defender.h>
#include <aws/iotdevice/external/cJSON.h>
#include <aws/iotdevice/private/network.h>
#include <aws/testing/aws_test_harness.h>

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

/* Test Cases */

AWS_TEST_CASE(devicedefender_task_unsupported_report_format, s_devicedefender_task_unsupported_report_format);
static int s_devicedefender_task_unsupported_report_format(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    const struct aws_iotdevice_defender_report_task_config config = {
        .connection = NULL,
        .thing_name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("TestThing"),
        .event_loop = NULL,
        .report_format = AWS_IDDRF_CBOR,
        .task_period_ns = 0,
        .netconn_sample_period_ns = 0,
        .task_canceled_fn = NULL,
        .cancelation_userdata = NULL};

    ASSERT_NULL(aws_iotdevice_defender_v1_report_task(allocator, &config));
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

    struct aws_array_list net_conns;
    AWS_ZERO_STRUCT(net_conns);
    aws_array_list_init_dynamic(&net_conns, allocator, 5, sizeof(struct aws_iotdevice_metric_net_connection));
    ASSERT_SUCCESS(get_network_connections(&net_conns, &ifconfig, allocator));

    size_t entries = aws_hash_table_get_entry_count(&ifconfig.iface_name_to_info);
    ASSERT_TRUE(entries <= net_conns.length);

    for (size_t i = 0; i < net_conns.length; ++i) {
        struct aws_iotdevice_metric_net_connection *con = NULL;
        if (aws_array_list_get_at_ptr(&net_conns, (void **)&con, i)) {
            continue;
        }
        /* Release allocated strings in connection struct */
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

struct mqtt_connection_test_data {
    struct aws_allocator *allocator;
    struct aws_client_bootstrap *client_bootstrap;
    struct aws_event_loop_group *el_group;
    struct aws_host_resolver *host_resolver;
    struct aws_socket_endpoint endpoint;
    struct aws_mqtt_client *mqtt_client;
    struct aws_mqtt_client_connection *mqtt_connection;
    struct aws_socket_options socket_options;
};

static struct mqtt_connection_test_data mqtt_test_data = {0};

static int s_setup_mqtt_test_data_fn(struct aws_allocator *allocator, void *ctx) {
    aws_mqtt_library_init(allocator);

    struct mqtt_connection_test_data *state_test_data = ctx;
    AWS_ZERO_STRUCT(*state_test_data);

    state_test_data->allocator = allocator;
    state_test_data->el_group = aws_event_loop_group_new_default(allocator, 1, NULL);
    state_test_data->host_resolver = aws_host_resolver_new_default(allocator, 1, state_test_data->el_group, NULL);

    struct aws_client_bootstrap_options bootstrap_options = {
        .event_loop_group = state_test_data->el_group,
        .host_resolver = state_test_data->host_resolver,
    };

    state_test_data->client_bootstrap = aws_client_bootstrap_new(allocator, &bootstrap_options);
    state_test_data->mqtt_client = aws_mqtt_client_new(allocator, state_test_data->client_bootstrap);
    state_test_data->mqtt_connection = aws_mqtt_client_connection_new(state_test_data->mqtt_client);

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
        ASSERT_SUCCESS(aws_global_thread_creator_shutdown_wait_for(10));
    }

    aws_mqtt_library_clean_up();
    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE_FIXTURE(
    devicedefender_success_test,
    s_setup_mqtt_test_data_fn,
    s_devicedefender_success_test,
    s_clean_up_mqtt_test_data_fn,
    &mqtt_test_data);

static int s_devicedefender_success_test(struct aws_allocator *allocator, void *ctx) {
    (void)allocator;
    struct mqtt_connection_test_data *state_test_data = ctx;

    aws_iotdevice_library_init(state_test_data->allocator);

    struct aws_iotdevice_defender_report_task_config task_config = {
        .cancelation_userdata = NULL,
        .task_canceled_fn = NULL,
        .connection = state_test_data->mqtt_connection,
        .event_loop = aws_event_loop_group_get_next_loop(state_test_data->el_group),
        .netconn_sample_period_ns = 1000000000ul,
        .report_format = AWS_IDDRF_JSON,
        .thing_name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("TestSuccessThing"),
        .task_period_ns = 1000000000ul};

    struct aws_iotdevice_defender_v1_task *defender_task = NULL;
    defender_task = aws_iotdevice_defender_v1_report_task(state_test_data->allocator, &task_config);
    AWS_FATAL_ASSERT(defender_task != NULL);

    struct aws_condition_variable test = AWS_CONDITION_VARIABLE_INIT;
    struct aws_mutex lock = AWS_MUTEX_INIT;
    // Allow device defender agent to run
    aws_condition_variable_wait_for(&test, &lock, 1000000000UL);

    aws_iotdevice_defender_v1_stop_task(defender_task);
    aws_condition_variable_wait_for(&test, &lock, 1000000000UL);

    int count = 1;
    struct aws_string *publish_topic;
    struct aws_byte_cursor payload;
    aws_mutex_lock(&state_test_data->mqtt_connection->synced_data.lock);
    for (struct aws_linked_list_node *iter =
             aws_linked_list_begin(&state_test_data->mqtt_connection->synced_data.pending_requests_list);
         iter != aws_linked_list_end(&state_test_data->mqtt_connection->synced_data.pending_requests_list);
         iter = aws_linked_list_next(iter)) {

        struct aws_mqtt_outstanding_request *request =
            AWS_CONTAINER_OF(iter, struct aws_mqtt_outstanding_request, list_node);

        // Subscribe packets
        if (count < 3) {
            struct subscribe_task_arg sub = *(struct subscribe_task_arg *)request->send_request_ud;
            struct subscribe_task_topic *topic = NULL;
            aws_array_list_get_at(&sub.topics, &topic, 0);
            // TODO: Seems these may be leaked in aws-c-mqtt
            aws_string_destroy(topic->filter);
            aws_mem_release(request->allocator, topic);
        }

        // The third packet is the report publish
        if (count == 3) {
            struct publish_task_arg pub = *(struct publish_task_arg *)request->send_request_ud;
            publish_topic = aws_string_new_from_string(state_test_data->allocator, pub.topic_string);
            payload = aws_byte_cursor_from_c_str((const char *)pub.payload.ptr);
        }

        // Since there's no connection, complete the requests for cleanup
        request->on_complete(
            request->connection, request->packet_id, AWS_ERROR_MQTT_CONNECTION_DESTROYED, request->on_complete_ud);
        request->completed = true;

        count++;
    }
    aws_mutex_unlock(&state_test_data->mqtt_connection->synced_data.lock);

    // Validate the publish message topic and payload
    ASSERT_TRUE(aws_string_eq_c_str(publish_topic, "$aws/things/TestSuccessThing/defender/metrics/json"));
    aws_string_destroy(publish_topic);
    validate_devicedefender_record((const char *)payload.ptr);

    aws_condition_variable_clean_up(&test);
    aws_mutex_clean_up(&lock);
    aws_iotdevice_library_clean_up();

    return AWS_OP_SUCCESS;
}
