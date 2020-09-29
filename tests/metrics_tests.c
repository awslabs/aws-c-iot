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
#include "mqtt_mock_server_handler.h"
#include <aws/common/clock.h>
#include <aws/common/condition_variable.h>
#include <aws/io/channel_bootstrap.h>
#include <aws/io/event_loop.h>
#include <aws/io/host_resolver.h>
#include <aws/iotdevice/device_defender.h>
#include <aws/iotdevice/external/cJSON.h>
#include <aws/mqtt/private/client_impl.h>
#include <aws/testing/aws_test_harness.h>

#ifdef _WIN32
#    define LOCAL_SOCK_TEST_PATTERN "\\\\.\\pipe\\testsock%llu"
#else
#    define LOCAL_SOCK_TEST_PATTERN "testsock%llu.sock"
#endif

static const int TEST_LOG_SUBJECT = 60001;

struct received_publish_packet {
    struct aws_byte_buf topic;
    struct aws_byte_buf payload;
};

struct mqtt_connection_state_test {
    struct aws_allocator *allocator;
    struct aws_channel *server_channel;
    struct aws_channel_handler *test_channel_handler;
    struct aws_client_bootstrap *client_bootstrap;
    struct aws_server_bootstrap *server_bootstrap;
    struct aws_event_loop_group *el_group;
    struct aws_host_resolver *host_resolver;
    struct aws_socket_endpoint endpoint;
    struct aws_socket *listener;
    struct aws_mqtt_client *mqtt_client;
    struct aws_mqtt_client_connection *mqtt_connection;
    struct aws_socket_options socket_options;
    bool session_present;
    bool connection_completed;
    bool client_disconnect_completed;
    bool server_disconnect_completed;
    bool connection_interrupted;
    bool connection_resumed;
    bool subscribe_completed;
    bool listener_destroyed;
    int interruption_error;
    enum aws_mqtt_connect_return_code mqtt_return_code;
    int error;
    struct aws_condition_variable cvar;
    struct aws_mutex lock;
    /* any published messages from mock server, that you may not subscribe to. (Which should not happen in real life) */
    struct aws_array_list any_published_messages; /* list of struct received_publish_packet */
    size_t any_publishes_received;
    size_t expected_any_publishes;
    /* the published messages from mock server, that you did subscribe to. */
    struct aws_array_list published_messages; /* list of struct received_publish_packet */
    size_t publishes_received;
    size_t expected_publishes;

    size_t ops_completed;
    size_t expected_ops_completed;
};

static struct mqtt_connection_state_test test_data = {0};

static void s_on_any_publish_received(
    struct aws_mqtt_client_connection *connection,
    const struct aws_byte_cursor *topic,
    const struct aws_byte_cursor *payload,
    void *userdata);

static void s_on_incoming_channel_setup_fn(
    struct aws_server_bootstrap *bootstrap,
    int error_code,
    struct aws_channel *channel,
    void *user_data) {
    (void)bootstrap;
    struct mqtt_connection_state_test *state_test_data = user_data;

    state_test_data->error = error_code;

    if (!error_code) {
        aws_mutex_lock(&state_test_data->lock);
        state_test_data->server_disconnect_completed = false;
        aws_mutex_unlock(&state_test_data->lock);
        AWS_LOGF_DEBUG(TEST_LOG_SUBJECT, "server channel setup completed");

        state_test_data->server_channel = channel;
        struct aws_channel_slot *test_handler_slot = aws_channel_slot_new(channel);
        aws_channel_slot_insert_end(channel, test_handler_slot);
        mqtt_mock_server_handler_update_slot(state_test_data->test_channel_handler, test_handler_slot);
        aws_channel_slot_set_handler(test_handler_slot, state_test_data->test_channel_handler);
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
    struct mqtt_connection_state_test *state_test_data = user_data;
    aws_mutex_lock(&state_test_data->lock);
    state_test_data->server_disconnect_completed = true;
    AWS_LOGF_DEBUG(TEST_LOG_SUBJECT, "server channel shutdown completed");
    aws_mutex_unlock(&state_test_data->lock);
    aws_condition_variable_notify_one(&state_test_data->cvar);
}

static void s_on_listener_destroy(struct aws_server_bootstrap *bootstrap, void *user_data) {
    (void)bootstrap;
    struct mqtt_connection_state_test *state_test_data = user_data;
    aws_mutex_lock(&state_test_data->lock);
    state_test_data->listener_destroyed = true;
    aws_mutex_unlock(&state_test_data->lock);
    aws_condition_variable_notify_one(&state_test_data->cvar);
}

static bool s_is_listener_destroyed(void *arg) {
    struct mqtt_connection_state_test *state_test_data = arg;
    return state_test_data->listener_destroyed;
}

static void s_wait_on_listener_cleanup(struct mqtt_connection_state_test *state_test_data) {
    aws_mutex_lock(&state_test_data->lock);
    aws_condition_variable_wait_pred(
        &state_test_data->cvar, &state_test_data->lock, s_is_listener_destroyed, state_test_data);
    aws_mutex_unlock(&state_test_data->lock);
}

static void s_on_connection_interrupted(struct aws_mqtt_client_connection *connection, int error_code, void *userdata) {
    (void)connection;
    (void)error_code;
    struct mqtt_connection_state_test *state_test_data = userdata;

    aws_mutex_lock(&state_test_data->lock);
    state_test_data->connection_interrupted = true;
    state_test_data->interruption_error = error_code;
    aws_mutex_unlock(&state_test_data->lock);
    AWS_LOGF_DEBUG(TEST_LOG_SUBJECT, "connection interrupted");
    aws_condition_variable_notify_one(&state_test_data->cvar);
}

static void s_on_connection_resumed(
    struct aws_mqtt_client_connection *connection,
    enum aws_mqtt_connect_return_code return_code,
    bool session_present,
    void *userdata) {
    (void)connection;
    (void)return_code;
    (void)session_present;
    AWS_LOGF_DEBUG(TEST_LOG_SUBJECT, "reconnect completed");

    struct mqtt_connection_state_test *state_test_data = userdata;

    aws_mutex_lock(&state_test_data->lock);
    state_test_data->connection_resumed = true;
    aws_mutex_unlock(&state_test_data->lock);
    aws_condition_variable_notify_one(&state_test_data->cvar);
}

/** sets up a unix domain socket server and socket options. Creates an mqtt connection configured to use
 * the domain socket.
 */
static int s_setup_mqtt_server_fn(struct aws_allocator *allocator, void *ctx) {
    aws_mqtt_library_init(allocator);

    struct mqtt_connection_state_test *state_test_data = ctx;

    AWS_ZERO_STRUCT(*state_test_data);

    state_test_data->allocator = allocator;
    state_test_data->el_group = aws_event_loop_group_new_default(allocator, 1, NULL);

    state_test_data->test_channel_handler = new_mqtt_mock_server(allocator);
    ASSERT_NOT_NULL(state_test_data->test_channel_handler);

    state_test_data->server_bootstrap = aws_server_bootstrap_new(allocator, state_test_data->el_group);
    ASSERT_NOT_NULL(state_test_data->server_bootstrap);

    struct aws_socket_options socket_options = {
        .connect_timeout_ms = 100,
        .domain = AWS_SOCKET_LOCAL,
    };

    state_test_data->socket_options = socket_options;
    ASSERT_SUCCESS(aws_condition_variable_init(&state_test_data->cvar));
    ASSERT_SUCCESS(aws_mutex_init(&state_test_data->lock));

    uint64_t timestamp = 0;
    ASSERT_SUCCESS(aws_sys_clock_get_ticks(&timestamp));

    snprintf(
        state_test_data->endpoint.address,
        sizeof(state_test_data->endpoint.address),
        LOCAL_SOCK_TEST_PATTERN,
        (long long unsigned)timestamp);

    struct aws_server_socket_channel_bootstrap_options server_bootstrap_options = {
        .bootstrap = state_test_data->server_bootstrap,
        .host_name = state_test_data->endpoint.address,
        .port = state_test_data->endpoint.port,
        .socket_options = &state_test_data->socket_options,
        .incoming_callback = s_on_incoming_channel_setup_fn,
        .shutdown_callback = s_on_incoming_channel_shutdown_fn,
        .destroy_callback = s_on_listener_destroy,
        .user_data = state_test_data,
    };
    state_test_data->listener = aws_server_bootstrap_new_socket_listener(&server_bootstrap_options);

    ASSERT_NOT_NULL(state_test_data->listener);

    state_test_data->host_resolver = aws_host_resolver_new_default(allocator, 1, state_test_data->el_group, NULL);

    struct aws_client_bootstrap_options bootstrap_options = {
        .event_loop_group = state_test_data->el_group,
        .user_data = state_test_data,
        .host_resolver = state_test_data->host_resolver,
    };

    state_test_data->client_bootstrap = aws_client_bootstrap_new(allocator, &bootstrap_options);

    state_test_data->mqtt_client = aws_mqtt_client_new(allocator, state_test_data->client_bootstrap);
    state_test_data->mqtt_connection = aws_mqtt_client_connection_new(state_test_data->mqtt_client);
    ASSERT_NOT_NULL(state_test_data->mqtt_connection);

    ASSERT_SUCCESS(aws_mqtt_client_connection_set_connection_interruption_handlers(
        state_test_data->mqtt_connection,
        s_on_connection_interrupted,
        state_test_data,
        s_on_connection_resumed,
        state_test_data));

    ASSERT_SUCCESS(aws_mqtt_client_connection_set_on_any_publish_handler(
        state_test_data->mqtt_connection, s_on_any_publish_received, state_test_data));

    ASSERT_SUCCESS(aws_array_list_init_dynamic(
        &state_test_data->published_messages, allocator, 4, sizeof(struct received_publish_packet)));
    ASSERT_SUCCESS(aws_array_list_init_dynamic(
        &state_test_data->any_published_messages, allocator, 4, sizeof(struct received_publish_packet)));
    return AWS_OP_SUCCESS;
}

static void s_received_publish_packet_list_clean_up(struct aws_array_list *list) {
    for (size_t i = 0; i < aws_array_list_length(list); ++i) {
        struct received_publish_packet *val_ptr = NULL;
        aws_array_list_get_at_ptr(list, (void **)&val_ptr, i);
        aws_byte_buf_clean_up(&val_ptr->payload);
        aws_byte_buf_clean_up(&val_ptr->topic);
    }
    aws_array_list_clean_up(list);
}

static int s_clean_up_mqtt_server_fn(struct aws_allocator *allocator, int setup_result, void *ctx) {
    (void)allocator;

    if (!setup_result) {
        struct mqtt_connection_state_test *state_test_data = ctx;

        s_received_publish_packet_list_clean_up(&state_test_data->published_messages);
        s_received_publish_packet_list_clean_up(&state_test_data->any_published_messages);
        aws_mqtt_client_connection_release(state_test_data->mqtt_connection);
        aws_mqtt_client_release(state_test_data->mqtt_client);
        aws_client_bootstrap_release(state_test_data->client_bootstrap);
        aws_host_resolver_release(state_test_data->host_resolver);
        aws_server_bootstrap_destroy_socket_listener(state_test_data->server_bootstrap, state_test_data->listener);
        s_wait_on_listener_cleanup(state_test_data);
        aws_server_bootstrap_release(state_test_data->server_bootstrap);
        aws_event_loop_group_release(state_test_data->el_group);
        destroy_mqtt_mock_server(state_test_data->test_channel_handler);
        ASSERT_SUCCESS(aws_global_thread_creator_shutdown_wait_for(10));
    }

    aws_mqtt_library_clean_up();
    return AWS_OP_SUCCESS;
}

static void s_on_connection_complete_fn(
    struct aws_mqtt_client_connection *connection,
    int error_code,
    enum aws_mqtt_connect_return_code return_code,
    bool session_present,
    void *userdata) {
    (void)connection;
    struct mqtt_connection_state_test *state_test_data = userdata;
    aws_mutex_lock(&state_test_data->lock);

    state_test_data->session_present = session_present;
    state_test_data->mqtt_return_code = return_code;
    state_test_data->error = error_code;
    state_test_data->connection_completed = true;
    aws_mutex_unlock(&state_test_data->lock);

    aws_condition_variable_notify_one(&state_test_data->cvar);
}

static bool s_is_connection_completed(void *arg) {
    struct mqtt_connection_state_test *state_test_data = arg;
    return state_test_data->connection_completed;
}

static void s_wait_for_connection_to_complete(struct mqtt_connection_state_test *state_test_data) {
    aws_mutex_lock(&state_test_data->lock);
    aws_condition_variable_wait_pred(
        &state_test_data->cvar, &state_test_data->lock, s_is_connection_completed, state_test_data);
    state_test_data->connection_completed = false;
    aws_mutex_unlock(&state_test_data->lock);
}

void s_on_disconnect_fn(struct aws_mqtt_client_connection *connection, void *userdata) {
    (void)connection;
    struct mqtt_connection_state_test *state_test_data = userdata;
    aws_mutex_lock(&state_test_data->lock);
    state_test_data->client_disconnect_completed = true;
    aws_mutex_unlock(&state_test_data->lock);

    aws_condition_variable_notify_one(&state_test_data->cvar);
}

static bool s_is_disconnect_completed(void *arg) {
    struct mqtt_connection_state_test *state_test_data = arg;
    return state_test_data->client_disconnect_completed && state_test_data->server_disconnect_completed;
}

static void s_wait_for_disconnect_to_complete(struct mqtt_connection_state_test *state_test_data) {
    aws_mutex_lock(&state_test_data->lock);
    aws_condition_variable_wait_pred(
        &state_test_data->cvar, &state_test_data->lock, s_is_disconnect_completed, state_test_data);
    state_test_data->client_disconnect_completed = false;
    state_test_data->server_disconnect_completed = false;
    aws_mutex_unlock(&state_test_data->lock);
}

static void s_on_any_publish_received(
    struct aws_mqtt_client_connection *connection,
    const struct aws_byte_cursor *topic,
    const struct aws_byte_cursor *payload,
    void *userdata) {
    (void)connection;
    struct mqtt_connection_state_test *state_test_data = userdata;

    struct aws_byte_buf payload_cp;
    aws_byte_buf_init_copy_from_cursor(&payload_cp, state_test_data->allocator, *payload);
    struct aws_byte_buf topic_cp;
    aws_byte_buf_init_copy_from_cursor(&topic_cp, state_test_data->allocator, *topic);
    struct received_publish_packet received_packet = {.payload = payload_cp, .topic = topic_cp};

    aws_mutex_lock(&state_test_data->lock);
    aws_array_list_push_back(&state_test_data->any_published_messages, &received_packet);
    state_test_data->any_publishes_received++;
    aws_mutex_unlock(&state_test_data->lock);
    aws_condition_variable_notify_one(&state_test_data->cvar);
}

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

AWS_TEST_CASE_FIXTURE(
    devicedefender_task_success,
    s_setup_mqtt_server_fn,
    s_devicedefender_task_success,
    s_clean_up_mqtt_server_fn,
    &test_data)

static int s_devicedefender_task_success(struct aws_allocator *allocator, void *ctx) {
    struct mqtt_connection_state_test *state_test_data = ctx;

    aws_iotdevice_library_init(allocator);

    struct aws_mqtt_connection_options connection_options = {
        .user_data = state_test_data,
        .clean_session = false,
        .client_id = aws_byte_cursor_from_c_str("client1234"),
        .host_name = aws_byte_cursor_from_c_str(state_test_data->endpoint.address),
        .socket_options = &state_test_data->socket_options,
        .on_connection_complete = s_on_connection_complete_fn,
    };

    ASSERT_SUCCESS(aws_mqtt_client_connection_connect(state_test_data->mqtt_connection, &connection_options));
    s_wait_for_connection_to_complete(state_test_data);

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
    defender_task = aws_iotdevice_defender_v1_report_task(allocator, &task_config);
    AWS_FATAL_ASSERT(defender_task != NULL);

    mqtt_mock_server_wait_for_publishes_received(state_test_data->test_channel_handler, 1, 1000000000);

    aws_iotdevice_defender_v1_stop_task(defender_task);

    mqtt_mock_server_wait_for_unsubscribe_received(state_test_data->test_channel_handler, 2, 1000000000);

    ASSERT_SUCCESS(
        aws_mqtt_client_connection_disconnect(state_test_data->mqtt_connection, s_on_disconnect_fn, state_test_data));
    s_wait_for_disconnect_to_complete(state_test_data);

    /* Decode all received packets by mock server */
    ASSERT_SUCCESS(mqtt_mock_server_decode_packets(state_test_data->test_channel_handler));

    /* First packet is a CONNECT */
    struct mqtt_decoded_packet *received_packet =
        mqtt_mock_server_get_decoded_packet(state_test_data->test_channel_handler, 0);
    ASSERT_UINT_EQUALS(AWS_MQTT_PACKET_CONNECT, received_packet->type);

    /* Second packet should be a subscribe */
    struct aws_byte_cursor dd_accepted_sub_topic =
        aws_byte_cursor_from_c_str("$aws/things/TestSuccessThing/defender/metrics/json/accepted");
    received_packet = mqtt_mock_server_get_decoded_packet(state_test_data->test_channel_handler, 1);
    ASSERT_UINT_EQUALS(AWS_MQTT_PACKET_SUBSCRIBE, received_packet->type);
    ASSERT_UINT_EQUALS(1, aws_array_list_length(&received_packet->sub_topic_filters));
    struct aws_mqtt_subscription val;
    ASSERT_SUCCESS(aws_array_list_front(&received_packet->sub_topic_filters, &val));
    ASSERT_TRUE(aws_byte_cursor_eq(&val.topic_filter, &dd_accepted_sub_topic));

    /* Third packet should be a subscribe */
    struct aws_byte_cursor dd_rejected_sub_topic =
        aws_byte_cursor_from_c_str("$aws/things/TestSuccessThing/defender/metrics/json/rejected");
    received_packet = mqtt_mock_server_get_decoded_packet(state_test_data->test_channel_handler, 2);
    ASSERT_UINT_EQUALS(AWS_MQTT_PACKET_SUBSCRIBE, received_packet->type);
    ASSERT_UINT_EQUALS(1, aws_array_list_length(&received_packet->sub_topic_filters));
    ASSERT_SUCCESS(aws_array_list_front(&received_packet->sub_topic_filters, &val));
    ASSERT_TRUE(aws_byte_cursor_eq(&val.topic_filter, &dd_rejected_sub_topic));

    /* Fourth packet should be a publish with the devicedefender report */
    struct aws_byte_cursor dd_report_sub_topic =
        aws_byte_cursor_from_c_str("$aws/things/TestSuccessThing/defender/metrics/json");
    received_packet = mqtt_mock_server_get_decoded_packet(state_test_data->test_channel_handler, 3);
    ASSERT_UINT_EQUALS(AWS_MQTT_PACKET_PUBLISH, received_packet->type);
    ASSERT_TRUE(aws_byte_cursor_eq(&received_packet->topic_name, &dd_report_sub_topic));

    struct aws_byte_cursor abc = received_packet->publish_payload;
    validate_devicedefender_record((const char *)abc.ptr);

    aws_iotdevice_library_clean_up();

    return AWS_OP_SUCCESS;
}