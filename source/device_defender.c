/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/common/array_list.h>
#include <aws/common/assert.h>
#include <aws/common/byte_buf.h>
#include <aws/common/error.h>
#include <aws/common/macros.h>
#include <aws/iotdevice/device_defender.h>
#include <aws/iotdevice/external/cJSON.h>
#include <aws/iotdevice/iotdevice.h>
#include <aws/iotdevice/private/network.h>

#include <aws/common/allocator.h>
#include <aws/common/atomics.h>
#include <aws/common/clock.h>
#include <aws/common/hash_table.h>
#include <aws/common/logging.h>
#include <aws/common/string.h>
#include <aws/common/task_scheduler.h>
#include <aws/io/event_loop.h>
#include <aws/mqtt/client.h>

/**
 * of a custom metric's data that needs to be populated into a report
 *
 * Data union only needs to physically point to a single number, and single list.
 */
struct defender_custom_metric_data {
    struct defender_custom_metric *metric;
    union {
        int64_t number;
        struct aws_array_list list;
    } data;
    int callback_result;
};

struct aws_iotdevice_defender_v1_task {
    struct aws_allocator *allocator;
    struct aws_task task;
    struct aws_iotdevice_defender_report_task_config config;
    struct aws_iotdevice_metric_network_transfer previous_net_xfer;
    struct aws_byte_buf report_topic_name;
    struct aws_byte_buf report_accepted_topic_name;
    struct aws_byte_buf report_rejected_topic_name;
    bool has_previous_net_xfer;
    struct aws_atomic_var task_cancelled;
};

static void s_mqtt_on_suback(
    struct aws_mqtt_client_connection *connection,
    uint16_t packet_id,
    const struct aws_byte_cursor *topic,
    enum aws_mqtt_qos qos,
    int error_code,
    void *userdata) {
    (void)connection;
    if (error_code != AWS_ERROR_SUCCESS) {
        AWS_LOGF_ERROR(
            AWS_LS_IOTDEVICE_DEFENDER_TASK,
            "id=%p: Suback callback error with packet id: %d; topic " PRInSTR "; error: %s",
            userdata,
            packet_id,
            AWS_BYTE_CURSOR_PRI(*topic),
            aws_error_name(error_code));
    } else {
        AWS_LOGF_DEBUG(
            AWS_LS_IOTDEVICE_DEFENDER_TASK,
            "id=%p: Suback callback succeeded with packet id: %d; topic " PRInSTR,
            userdata,
            packet_id,
            AWS_BYTE_CURSOR_PRI(*topic));
    }

    if (qos == AWS_MQTT_QOS_FAILURE) {
        AWS_LOGF_ERROR(
            AWS_LS_IOTDEVICE_DEFENDER_TASK,
            "id=%p: Suback packet error response for packet id: %d; topic " PRInSTR,
            userdata,
            packet_id,
            AWS_BYTE_CURSOR_PRI(*topic));
    }
}

static void s_on_report_puback(
    struct aws_mqtt_client_connection *connection,
    uint16_t packet_id,
    int error_code,
    void *userdata) {
    (void)connection;
    (void)packet_id;
    (void)error_code;
    if (error_code != AWS_ERROR_SUCCESS) {
        AWS_LOGF_ERROR(
            AWS_LS_IOTDEVICE_DEFENDER_TASK,
            "id=%p: Publish packet %d failed with error: %s",
            userdata,
            packet_id,
            aws_error_name(error_code));
    }
}

static void s_on_report_response_rejected(
    struct aws_mqtt_client_connection *connection,
    const struct aws_byte_cursor *topic,
    const struct aws_byte_cursor *payload,
    bool dup,
    enum aws_mqtt_qos qos,
    bool retain,
    void *userdata) {
    (void)connection;
    (void)payload;
    (void)dup;
    (void)qos;
    (void)retain;
    AWS_LOGF_ERROR(
        AWS_LS_IOTDEVICE_DEFENDER_TASK,
        "id=%p: Report rejected from topic: " PRInSTR "\nRejection payload: " PRInSTR,
        userdata,
        AWS_BYTE_CURSOR_PRI(*topic),
        AWS_BYTE_CURSOR_PRI(*payload));
}

static void s_on_report_response_accepted(
    struct aws_mqtt_client_connection *connection,
    const struct aws_byte_cursor *topic,
    const struct aws_byte_cursor *payload,
    bool dup,
    enum aws_mqtt_qos qos,
    bool retain,
    void *userdata) {
    (void)connection;
    (void)payload;
    (void)dup;
    (void)qos;
    (void)retain;
    AWS_LOGF_DEBUG(
        AWS_LS_IOTDEVICE_DEFENDER_TASK,
        "id=%p: Report accepted on topic: " PRInSTR,
        userdata,
        AWS_BYTE_CURSOR_PRI(*topic));
}

static int s_get_metric_report_json(
    struct aws_byte_buf *json_out,
    struct aws_iotdevice_defender_v1_task *task,
    uint64_t report_id,
    const struct aws_iotdevice_metric_network_transfer *net_xfer,
    const struct aws_array_list *net_conns,
    size_t custom_metrics_len,
    const struct defender_custom_metric_data *custom_metrics_data) {
    int return_value = AWS_OP_ERR;
    struct cJSON *root = cJSON_CreateObject();
    if (root == NULL) {
        goto cleanup;
    }
    struct cJSON *header = cJSON_CreateObject();
    if (header == NULL) {
        goto cleanup;
    }
    cJSON_AddItemToObject(root, "header", header);
    if (NULL == cJSON_AddNumberToObject(header, "report_id", (double)report_id)) {
        goto cleanup;
    }

    if (NULL == cJSON_AddStringToObject(header, "version", "1.0")) {
        goto cleanup;
    }

    struct cJSON *metrics = cJSON_CreateObject();
    if (metrics == NULL) {
        goto cleanup;
    }
    cJSON_AddItemToObject(root, "metrics", metrics);

    struct cJSON *listening_tcp_ports = cJSON_CreateObject();
    if (listening_tcp_ports == NULL) {
        goto cleanup;
    }
    cJSON_AddItemToObject(metrics, "listening_tcp_ports", listening_tcp_ports);

    struct cJSON *tcp_listen_ports = cJSON_CreateArray();
    if (tcp_listen_ports == NULL) {
        goto cleanup;
    }
    cJSON_AddItemToObject(listening_tcp_ports, "ports", tcp_listen_ports);

    struct cJSON *tcp_connections = cJSON_CreateObject();
    if (tcp_connections == NULL) {
        goto cleanup;
    }
    cJSON_AddItemToObject(metrics, "tcp_connections", tcp_connections);

    struct cJSON *established_tcp_conns = cJSON_CreateObject();
    if (established_tcp_conns == NULL) {
        goto cleanup;
    }
    cJSON_AddItemToObject(tcp_connections, "established_connections", established_tcp_conns);

    struct cJSON *est_connections = cJSON_CreateArray();
    if (est_connections == NULL) {
        goto cleanup;
    }
    cJSON_AddItemToObject(established_tcp_conns, "connections", est_connections);

    struct cJSON *listening_udp_ports = cJSON_CreateObject();
    if (listening_udp_ports == NULL) {
        goto cleanup;
    }
    cJSON_AddItemToObject(metrics, "listening_udp_ports", listening_udp_ports);

    struct cJSON *udp_ports = cJSON_CreateArray();
    if (udp_ports == NULL) {
        goto cleanup;
    }
    cJSON_AddItemToObject(listening_udp_ports, "ports", udp_ports);

    int total_listening_tcp_ports = 0;
    int total_established_tcp_conns = 0;
    int total_udp_listeners = 0;
    const size_t net_conn_sz = aws_array_list_length(net_conns);
    for (size_t tcp_index = 0; tcp_index < net_conn_sz; ++tcp_index) {
        struct aws_iotdevice_metric_net_connection *net_conn = NULL;
        aws_array_list_get_at_ptr(net_conns, (void **)&net_conn, tcp_index);
        if (net_conn->state == AWS_IDNCS_ESTABLISHED && net_conn->protocol == AWS_IDNP_TCP) {
            total_established_tcp_conns++;
            struct cJSON *conn = cJSON_CreateObject();
            if (conn == NULL) {
                goto cleanup;
            }
            cJSON_AddItemToArray(est_connections, conn);
            if (NULL == cJSON_AddStringToObject(conn, "local_interface", aws_string_c_str(net_conn->local_interface))) {
                goto cleanup;
            }
            if (NULL == cJSON_AddNumberToObject(conn, "local_port", net_conn->local_port)) {
                goto cleanup;
            }
            char remote_addr[22];
            snprintf(remote_addr, 22, "%s:%u", aws_string_c_str(net_conn->remote_address), net_conn->remote_port);
            if (NULL == cJSON_AddStringToObject(conn, "remote_addr", remote_addr)) {
                goto cleanup;
            }
        } else if (net_conn->state == AWS_IDNCS_LISTEN && net_conn->protocol == AWS_IDNP_TCP) {
            total_listening_tcp_ports++;
            struct cJSON *conn = cJSON_CreateObject();
            if (conn == NULL) {
                goto cleanup;
            }
            cJSON_AddItemToArray(tcp_listen_ports, conn);
            if (NULL == cJSON_AddStringToObject(conn, "interface", aws_string_c_str(net_conn->local_interface))) {
                goto cleanup;
            }
            if (NULL == cJSON_AddNumberToObject(conn, "port", net_conn->local_port)) {
                goto cleanup;
            }
        } else if (net_conn->state == AWS_IDNCS_LISTEN && net_conn->protocol == AWS_IDNP_UDP) {
            ++total_udp_listeners;
            struct cJSON *conn = cJSON_CreateObject();
            if (conn == NULL) {
                goto cleanup;
            }
            cJSON_AddItemToArray(udp_ports, conn);
            if (NULL == cJSON_AddStringToObject(conn, "interface", aws_string_c_str(net_conn->local_interface))) {
                goto cleanup;
            }
            if (NULL == cJSON_AddNumberToObject(conn, "port", net_conn->local_port)) {
                goto cleanup;
            }
        }
    }

    if (NULL == cJSON_AddNumberToObject(established_tcp_conns, "total", total_established_tcp_conns)) {
        goto cleanup;
    }
    if (NULL == cJSON_AddNumberToObject(listening_tcp_ports, "total", total_listening_tcp_ports)) {
        goto cleanup;
    }
    if (NULL == cJSON_AddNumberToObject(listening_udp_ports, "total", (double)total_udp_listeners)) {
        goto cleanup;
    }

    struct cJSON *network_stats = cJSON_CreateObject();
    if (network_stats == NULL) {
        goto cleanup;
    }
    cJSON_AddItemToObject(metrics, "network_stats", network_stats);

    if (NULL == cJSON_AddNumberToObject(network_stats, "bytes_in", net_xfer != NULL ? (double)net_xfer->bytes_in : 0)) {
        goto cleanup;
    }
    if (NULL ==
        cJSON_AddNumberToObject(network_stats, "bytes_out", net_xfer != NULL ? (double)net_xfer->bytes_out : 0)) {
        goto cleanup;
    }
    if (NULL ==
        cJSON_AddNumberToObject(network_stats, "packets_in", net_xfer != NULL ? (double)net_xfer->packets_in : 0)) {
        goto cleanup;
    }
    if (NULL ==
        cJSON_AddNumberToObject(network_stats, "packets_out", net_xfer != NULL ? (double)net_xfer->packets_out : 0)) {
        goto cleanup;
    }

    if (custom_metrics_len != 0) {
        struct cJSON *custom_metrics = cJSON_CreateObject();
        if (NULL == custom_metrics) {
            goto cleanup;
        }
        cJSON_AddItemToObject(root, "custom_metrics", custom_metrics);

        size_t list_size = 0;
        struct cJSON *array_item = NULL;
        struct cJSON *item = NULL;
        struct cJSON *json_list = NULL;
        struct cJSON *spurious_array_container = NULL;
        for (size_t metric_index = 0; metric_index < custom_metrics_len; ++metric_index) {
            spurious_array_container = cJSON_CreateArray();
            if (NULL == spurious_array_container) {
                goto cleanup;
            }
            cJSON_AddItemToObject(
                custom_metrics,
                aws_string_c_str(custom_metrics_data[metric_index].metric->metric_name),
                spurious_array_container);

            item = cJSON_CreateObject();
            if (NULL == item) {
                goto cleanup;
            }
            cJSON_AddItemToArray(spurious_array_container, item);

            switch (custom_metrics_data[metric_index].metric->type) {
                case DD_METRIC_NUMBER:
                    cJSON_AddNumberToObject(item, "number", (double)custom_metrics_data[metric_index].data.number);
                    break;
                case DD_METRIC_NUMBER_LIST:
                    list_size = aws_array_list_length(&custom_metrics_data[metric_index].data.list);
                    json_list = cJSON_CreateArray();
                    if (NULL == json_list) {
                        goto cleanup;
                    }
                    cJSON_AddItemToObject(item, "number_list", json_list);
                    for (size_t num_index = 0; num_index < list_size; ++num_index) {
                        int64_t number = 0;
                        aws_array_list_get_at(&custom_metrics_data[metric_index].data.list, &number, num_index);
                        array_item = cJSON_CreateNumber((double)number);
                        cJSON_AddItemToArray(json_list, array_item);
                    }
                    break;
                case DD_METRIC_STRING_LIST:
                    list_size = aws_array_list_length(&custom_metrics_data[metric_index].data.list);
                    json_list = cJSON_CreateArray();
                    if (NULL == json_list) {
                        goto cleanup;
                    }
                    cJSON_AddItemToObject(item, "string_list", json_list);
                    for (size_t string_index = 0; string_index < list_size; ++string_index) {
                        struct aws_string *string_value = NULL;
                        aws_array_list_get_at(
                            &custom_metrics_data[metric_index].data.list, &string_value, string_index);
                        array_item = cJSON_CreateString(aws_string_c_str(string_value));
                        cJSON_AddItemToArray(json_list, array_item);
                    }
                    break;
                case DD_METRIC_IP_LIST:
                    list_size = aws_array_list_length(&custom_metrics_data[metric_index].data.list);
                    json_list = cJSON_CreateArray();
                    if (NULL == json_list) {
                        goto cleanup;
                    }
                    cJSON_AddItemToObject(item, "ip_list", json_list);
                    for (size_t ip_index = 0; ip_index < list_size; ++ip_index) {
                        struct aws_string *ip_value = NULL;
                        aws_array_list_get_at(&custom_metrics_data[metric_index].data.list, &ip_value, ip_index);
                        array_item = cJSON_CreateString(aws_string_c_str(ip_value));
                        cJSON_AddItemToArray(json_list, array_item);
                    }
                    break;
                case DD_METRIC_UNKNOWN:
                default:
                    AWS_LOGF_WARN(
                        AWS_LS_IOTDEVICE_DEFENDER_TASK,
                        "id=%p: Unknown custom metrics type found during report generation: %d, name %s",
                        (void *)task,
                        custom_metrics_data[metric_index].metric->type,
                        aws_string_c_str(custom_metrics_data[metric_index].metric->metric_name));
                    continue;
                    break;
            }
        }
    }

    const size_t remaining_capacity = json_out->capacity - json_out->len;
    char *write_start = (char *)json_out->buffer + json_out->len;
    if (!cJSON_PrintPreallocated(root, write_start, (int)remaining_capacity, false)) {
        AWS_LOGF_ERROR(AWS_LS_IOTDEVICE_DEFENDER_TASK, "id=%p: Failed to print defender report JSON", (void *)task);
        goto cleanup;
    }

    return_value = AWS_OP_SUCCESS;
    json_out->len += strlen(write_start);

cleanup:
    if (root) {
        cJSON_Delete(root);
    }
    if (return_value != AWS_OP_SUCCESS) {
        aws_raise_error(AWS_ERROR_IOTDEVICE_DEFENDER_REPORT_SERIALIZATION_FAILURE);
    }
    return return_value;
}

static uint64_t s_defender_report_id_epoch_time_ms(struct aws_iotdevice_defender_v1_task *defender_task) {
    AWS_PRECONDITION(defender_task != NULL);
    uint64_t now;
    int return_code = 0;
    if (AWS_OP_SUCCESS != (return_code = aws_event_loop_current_clock_time(defender_task->config.event_loop, &now))) {
        AWS_LOGF_WARN(
                  AWS_LS_IOTDEVICE_DEFENDER_TASK,
            "id=%p: Error generating report ID from aws_event_loop_current_clock_time(): %s",
            (void *)defender_task,
            aws_error_name(return_code));
        return 0;
    }
    return aws_timestamp_convert(now, AWS_TIMESTAMP_NANOS, AWS_TIMESTAMP_MILLIS, NULL);
}

/**
 * Allocates the memory associated with collecting metric data each defender task run
 */
static int s_init_custom_metric_data(
    struct defender_custom_metric_data *custom_metric_data,
    struct aws_iotdevice_defender_v1_task *defender_task) {
    AWS_PRECONDITION(custom_metric_data != NULL);
    AWS_PRECONDITION(defender_task != NULL);
    struct aws_allocator *allocator = defender_task->allocator;
    const size_t custom_metrics_len = aws_array_list_length(&defender_task->config.custom_metrics);
    for (size_t metric_index = 0; metric_index < custom_metrics_len; ++metric_index) {
        struct defender_custom_metric_data *metric_data = &custom_metric_data[metric_index];
        aws_array_list_get_at(&defender_task->config.custom_metrics, (void *)&metric_data->metric, metric_index);

        struct defender_custom_metric *metric = metric_data->metric;
        switch (metric->type) {
            case DD_METRIC_NUMBER: /* nothing to do here */
                break;
            case DD_METRIC_NUMBER_LIST:
                aws_array_list_init_dynamic(&custom_metric_data[metric_index].data.list, allocator, 0, sizeof(int64_t));
                break;
            case DD_METRIC_STRING_LIST:
                /* fall through */
            case DD_METRIC_IP_LIST:
                aws_array_list_init_dynamic(
                    &custom_metric_data[metric_index].data.list, allocator, 0, sizeof(struct aws_string *));
                break;
            case DD_METRIC_UNKNOWN:
            default:
                return aws_raise_error(AWS_ERROR_IOTDEVICE_DEFENDER_UNKNOWN_CUSTOM_METRIC_TYPE);
        }
    }

    return AWS_OP_SUCCESS;
}

/**
 * Cleans up the memory associated with collecting metric data each defender task run
 *
 * Nests into list types to free memory of items if they need to be destroyed
 */
static void s_clean_up_metric_data(
    struct defender_custom_metric_data *metrics_data,
    struct aws_iotdevice_defender_v1_task *defender_task) {
    AWS_PRECONDITION(metrics_data != NULL);
    AWS_PRECONDITION(defender_task != NULL);

    const size_t custom_metrics_len = aws_array_list_length(&defender_task->config.custom_metrics);
    for (size_t metric_index = 0; metric_index < custom_metrics_len; ++metric_index) {
        size_t list_size = 0; /* set only if we have a list type */
        switch (metrics_data[metric_index].metric->type) {
            case DD_METRIC_NUMBER: /* nothing to do here */
                break;
            case DD_METRIC_STRING_LIST:
                /* fall through */
            case DD_METRIC_IP_LIST:
                list_size = aws_array_list_length(&metrics_data[metric_index].data.list);
                for (size_t item_index = 0; item_index < list_size; ++item_index) {
                    struct aws_string *string_or_ip_entry;
                    aws_array_list_get_at(
                        &metrics_data[metric_index].data.list, (void *)&string_or_ip_entry, item_index);
                    aws_string_destroy(string_or_ip_entry);
                }
                /* fall through */
            case DD_METRIC_NUMBER_LIST:
                aws_array_list_clean_up(&metrics_data[metric_index].data.list);
                break;
            case DD_METRIC_UNKNOWN:
            default:
                break;
        }
    }
}


static void s_get_custom_metrics_data(const struct aws_iotdevice_defender_v1_task *defender_task,
                                      struct defender_custom_metric_data *custom_metric_data,
                                      const size_t custom_metrics_len) {
    if (custom_metrics_len != 0) {
        for (size_t metric_index = 0; metric_index < custom_metrics_len; ++metric_index) {
            aws_array_list_get_at(
                &defender_task->config.custom_metrics,
                (void *)&custom_metric_data[metric_index].metric,
                metric_index);

            AWS_LOGF_DEBUG(
                AWS_LS_IOTDEVICE_DEFENDER_TASK,
                "id=%p Retrieving value for custom metric %s",
                (void *)defender_task,
                aws_string_c_str(custom_metric_data[metric_index].metric->metric_name));

            switch (custom_metric_data[metric_index].metric->type) {
                case DD_METRIC_NUMBER:
                    custom_metric_data[metric_index].callback_result =
                        custom_metric_data[metric_index].metric->supplier_fn.get_number_fn(
                            &custom_metric_data[metric_index].data.number,
                            custom_metric_data[metric_index].metric->userdata);
                    break;
                case DD_METRIC_NUMBER_LIST:
                    custom_metric_data[metric_index].callback_result =
                        custom_metric_data[metric_index].metric->supplier_fn.get_number_list_fn(
                            &custom_metric_data[metric_index].data.list,
                            custom_metric_data[metric_index].metric->userdata);
                    break;
                case DD_METRIC_STRING_LIST:
                    custom_metric_data[metric_index].callback_result =
                        custom_metric_data[metric_index].metric->supplier_fn.get_string_list_fn(
                            &custom_metric_data[metric_index].data.list,
                            custom_metric_data[metric_index].metric->userdata);
                    break;
                case DD_METRIC_IP_LIST:
                    custom_metric_data[metric_index].callback_result =
                        custom_metric_data[metric_index].metric->supplier_fn.get_ip_list_fn(
                            &custom_metric_data[metric_index].data.list,
                            custom_metric_data[metric_index].metric->userdata);
                    break;
                case DD_METRIC_UNKNOWN:
                default:
                    AWS_LOGF_ERROR(
                        AWS_LS_IOTDEVICE_DEFENDER_TASK,
                        "id=%p: Cannot retreive metric for unknown metric type: %d, name: %s",
                        (void *)defender_task,
                        custom_metric_data[metric_index].metric->type,
                        aws_string_c_str(custom_metric_data[metric_index].metric->metric_name));
                    continue;
                    break;
            }
        }
    }
}

static void s_reporting_task_fn(struct aws_task *task, void *userdata, enum aws_task_status status) {
    struct aws_iotdevice_defender_v1_task *defender_task = (struct aws_iotdevice_defender_v1_task *)userdata;
    struct aws_allocator *allocator = defender_task->allocator;
    struct aws_iotdevice_network_ifconfig ifconfig;
    AWS_ZERO_STRUCT(ifconfig);
    const size_t custom_metrics_len = aws_array_list_length(&defender_task->config.custom_metrics);
    struct defender_custom_metric_data *custom_metric_data =
        aws_mem_acquire(allocator, sizeof(struct defender_custom_metric_data) * custom_metrics_len);
    struct aws_byte_buf json_report;
    AWS_ZERO_STRUCT(json_report);
    int return_code = 0;

    if (status == AWS_TASK_STATUS_RUN_READY) {
        const size_t task_cancelled = aws_atomic_load_int(&defender_task->task_cancelled);
        if (task_cancelled) {
            AWS_LOGF_DEBUG(
                AWS_LS_IOTDEVICE_DEFENDER_TASK,
                "id=%p: DeviceDefender reporting task cancel requested",
                (void *)defender_task);
            aws_event_loop_cancel_task(defender_task->config.event_loop, task);
        } else {
            AWS_LOGF_DEBUG(
                AWS_LS_IOTDEVICE_DEFENDER_TASK, "id=%p: Running DeviceDefender reporting task", (void *)defender_task);

            if (AWS_OP_SUCCESS != (return_code = get_network_config_and_transfer(&ifconfig, allocator))) {
                AWS_LOGF_ERROR(
                    AWS_LS_IOTDEVICE_DEFENDER_TASK,
                    "id=%p: Failed to retrieve network configuration: %s",
                    (void *)defender_task,
                    aws_error_name(return_code));
                goto cleanup;
            }
            struct aws_iotdevice_metric_network_transfer totals = {
                .bytes_in = 0, .bytes_out = 0, .packets_in = 0, .packets_out = 0};
            get_system_network_total(&totals, &ifconfig);

            struct aws_array_list net_conns;
            AWS_ZERO_STRUCT(net_conns);
            aws_array_list_init_dynamic(&net_conns, allocator, 5, sizeof(struct aws_iotdevice_metric_net_connection));
            if (AWS_OP_SUCCESS != (return_code = get_network_connections(&net_conns, &ifconfig, allocator))) {
                AWS_LOGF_ERROR(
                    AWS_LS_IOTDEVICE_DEFENDER_TASK,
                    "id=%p: Failed to get network connection data: %s",
                    (void *)defender_task,
                    aws_error_name(return_code));
                goto cleanup;
            }

            if (AWS_OP_SUCCESS != s_init_custom_metric_data(custom_metric_data, defender_task)) {
                goto cleanup;
            }

            /* per metric retrieval errors do not result in failure */
            s_get_custom_metrics_data(defender_task, custom_metric_data, custom_metrics_len);

            uint64_t report_id = s_defender_report_id_epoch_time_ms(defender_task);
            /* TODO: come up with something better than allocating max size of MQTT message allowed by AWS IoT */
            uint8_t json_buffer_space[262144];
            json_report = aws_byte_buf_from_empty_array(json_buffer_space, 262144);
            struct aws_iotdevice_metric_network_transfer *ptr_delta_xfer = NULL;
            struct aws_iotdevice_metric_network_transfer delta_xfer;
            AWS_ZERO_STRUCT(delta_xfer);

            if (defender_task->has_previous_net_xfer) {
                delta_xfer.bytes_in = 0;
                delta_xfer.bytes_out = 0;
                delta_xfer.packets_in = 0;
                delta_xfer.packets_out = 0;

                get_network_total_delta(&delta_xfer, &defender_task->previous_net_xfer, &totals);
                ptr_delta_xfer = &delta_xfer;

            } else {
                defender_task->has_previous_net_xfer = true;
            }
            if (AWS_OP_SUCCESS != s_get_metric_report_json(
                                      &json_report,
                                      defender_task,
                                      report_id,
                                      ptr_delta_xfer,
                                      &net_conns,
                                      custom_metrics_len,
                                      custom_metric_data)) {
            }

            defender_task->previous_net_xfer.bytes_in = totals.bytes_in;
            defender_task->previous_net_xfer.bytes_out = totals.bytes_out;
            defender_task->previous_net_xfer.packets_in = totals.packets_in;
            defender_task->previous_net_xfer.packets_out = totals.packets_out;

            struct aws_byte_cursor report_topic = aws_byte_cursor_from_buf(&defender_task->report_topic_name);
            struct aws_byte_cursor report = aws_byte_cursor_from_buf(&json_report);

            AWS_LOGF_TRACE(
                AWS_LS_IOTDEVICE_DEFENDER_TASK,
                "id=%p: Full report: " PRInSTR,
                (void *)defender_task,
                AWS_BYTE_CURSOR_PRI(report));

            uint16_t report_packet_id = aws_mqtt_client_connection_publish(
                defender_task->config.connection,
                &report_topic,
                AWS_MQTT_QOS_AT_LEAST_ONCE,
                false,
                &report,
                s_on_report_puback,
                defender_task);

            if (report_packet_id != 0) {
                AWS_LOGF_DEBUG(
                    AWS_LS_IOTDEVICE_DEFENDER_TASK,
                    "id=%p: Report packet_id %d published on topic " PRInSTR,
                    (void *)defender_task,
                    report_packet_id,
                    AWS_BYTE_CURSOR_PRI(report_topic));
            } else {
                AWS_LOGF_ERROR(
                    AWS_LS_IOTDEVICE_DEFENDER_TASK,
                    "id=%p: Report failed to publish on topic " PRInSTR,
                    (void *)defender_task,
                    AWS_BYTE_CURSOR_PRI(report_topic));
                defender_task->config.rejected_report_fn(aws_last_error(), NULL, defender_task->config.userdata);
            }

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

            uint64_t now;
            aws_event_loop_current_clock_time(defender_task->config.event_loop, &now);
            aws_event_loop_schedule_task_future(
                defender_task->config.event_loop, task, now + defender_task->config.task_period_ns);
        }
    } else if (status == AWS_TASK_STATUS_CANCELED) {
        AWS_LOGF_DEBUG(
            AWS_LS_IOTDEVICE_DEFENDER_TASK, "id=%p: Reporting task cancelled, cleaning up", (void *)defender_task);

        struct aws_byte_cursor accepted_topic = aws_byte_cursor_from_buf(&defender_task->report_accepted_topic_name);
        aws_mqtt_client_connection_unsubscribe(defender_task->config.connection, &accepted_topic, NULL, NULL);
        struct aws_byte_cursor rejected_topic = aws_byte_cursor_from_buf(&defender_task->report_rejected_topic_name);
        aws_mqtt_client_connection_unsubscribe(defender_task->config.connection, &rejected_topic, NULL, NULL);

        void *cancel_userdata = defender_task->config.userdata;
        aws_byte_buf_clean_up(&defender_task->report_topic_name);
        aws_byte_buf_clean_up(&defender_task->report_accepted_topic_name);
        aws_byte_buf_clean_up(&defender_task->report_rejected_topic_name);

        if (defender_task->config.task_cancelled_fn != NULL) {
            defender_task->config.task_cancelled_fn(cancel_userdata);
        }

        aws_mem_release(allocator, defender_task);
    } else {
        AWS_LOGF_WARN(
            AWS_LS_IOTDEVICE_DEFENDER_TASK,
            "id=%p: Reporting task in unknown run state being ignored",
            (void *)defender_task);
        /* TODO: revise if reschedule or cancellation is appropriate here */
        uint64_t now;
        aws_event_loop_current_clock_time(defender_task->config.event_loop, &now);
        aws_event_loop_schedule_task_future(
            defender_task->config.event_loop, task, now + defender_task->config.task_period_ns);
    }

    goto cleanup;

cleanup:
    s_clean_up_metric_data(custom_metric_data, defender_task);

    if (aws_hash_table_is_valid(&ifconfig.iface_name_to_info)) {
        aws_hash_table_clean_up(&ifconfig.iface_name_to_info);
    }
}

/**
 * Creates DeviceDefender task based on the configuration structure details
 * passed in, and immediately starts the task to recur until
 * aws_iotdevice_defender_v1_stop_task() is called
 *
 * Any custom metrics must have been added to the configuration object before
 * invoking this function.
 *
 *
 */
struct aws_iotdevice_defender_v1_task *aws_iotdevice_defender_v1_report_task(
    struct aws_allocator *allocator,
    const struct aws_iotdevice_defender_report_task_config *config) {
    AWS_PRECONDITION(aws_allocator_is_valid(allocator));
    AWS_PRECONDITION(config != NULL);
    bool failure = false;
    struct aws_iotdevice_defender_v1_task *defender_task = NULL;

    if (config->report_format != AWS_IDDRF_JSON) {
        AWS_LOGF_ERROR(AWS_LS_IOTDEVICE_DEFENDER_TASK, "Unsupported DeviceDefender detect report format detected.");
        aws_raise_error(AWS_ERROR_IOTDEVICE_DEFENDER_UNSUPPORTED_REPORT_FORMAT);
        failure = true;
        goto cleanup;
    }

    defender_task = (struct aws_iotdevice_defender_v1_task *)aws_mem_acquire(
        allocator, sizeof(struct aws_iotdevice_defender_v1_task));
    AWS_ZERO_STRUCT(*defender_task);
    if (defender_task == NULL) {
        aws_raise_error(aws_last_error());
        failure = true;
        goto cleanup;
    }

    defender_task->allocator = allocator;
    defender_task->previous_net_xfer.bytes_in = 0;
    defender_task->previous_net_xfer.bytes_out = 0;
    defender_task->previous_net_xfer.packets_in = 0;
    defender_task->previous_net_xfer.packets_out = 0;
    defender_task->has_previous_net_xfer = false;
    defender_task->config = *config;

    aws_atomic_store_int(&defender_task->task_cancelled, 0);

    if (!aws_array_list_is_valid(&defender_task->config.custom_metrics)) {
        aws_raise_error(AWS_ERROR_IOTDEVICE_DEFENDER_INVALID_TASK_CONFIG);
        failure = true;
        goto cleanup;
    }

    const size_t thing_name_len = strlen((const char *)config->thing_name.ptr);
    const char pub_topic_base[37] = "$aws/things/%s/defender/metrics/json";
    const size_t pub_topic_len = 36 + thing_name_len;
    const char accepted_topic_base[46] = "$aws/things/%s/defender/metrics/json/accepted";
    const char rejected_topic_base[46] = "$aws/things/%s/defender/metrics/json/rejected";
    const size_t accepted_rejected_topic_len = 45 + thing_name_len;

    if (AWS_OP_SUCCESS != aws_byte_buf_init(&defender_task->report_topic_name, allocator, pub_topic_len - 1)) {
        failure = true;
        goto cleanup;
    }
    snprintf(
        (char *)defender_task->report_topic_name.buffer,
        defender_task->report_topic_name.capacity,
        pub_topic_base,
        (char *)defender_task->config.thing_name.ptr);
    defender_task->report_topic_name.len = strlen((const char *)defender_task->report_topic_name.buffer);

    if (AWS_OP_SUCCESS !=
        aws_byte_buf_init(&defender_task->report_accepted_topic_name, allocator, accepted_rejected_topic_len - 1)) {
        failure = true;
        goto cleanup;
    }
    snprintf(
        (char *)defender_task->report_accepted_topic_name.buffer,
        defender_task->report_accepted_topic_name.capacity,
        accepted_topic_base,
        (char *)defender_task->config.thing_name.ptr);
    defender_task->report_accepted_topic_name.len =
        strlen((const char *)defender_task->report_accepted_topic_name.buffer);

    if (AWS_OP_SUCCESS !=
        aws_byte_buf_init(&defender_task->report_rejected_topic_name, allocator, accepted_rejected_topic_len - 1)) {
        failure = true;
        goto cleanup;
    }
    snprintf(
        (char *)defender_task->report_rejected_topic_name.buffer,
        defender_task->report_rejected_topic_name.capacity,
        rejected_topic_base,
        (char *)defender_task->config.thing_name.ptr);
    defender_task->report_rejected_topic_name.len =
        strlen((const char *)defender_task->report_rejected_topic_name.buffer);

    const struct aws_byte_cursor accepted_cursor = aws_byte_cursor_from_buf(&defender_task->report_accepted_topic_name);
    uint16_t sub_accepted_packet_id = aws_mqtt_client_connection_subscribe(
        defender_task->config.connection,
        &accepted_cursor,
        AWS_MQTT_QOS_AT_LEAST_ONCE,
        &s_on_report_response_accepted,
        defender_task,
        NULL,
        s_mqtt_on_suback,
        defender_task);
    if (sub_accepted_packet_id != 0) {
        AWS_LOGF_DEBUG(
            AWS_LS_IOTDEVICE_DEFENDER_TASK,
            "id=%p: subscription packet_id [%d] for accepted topic " PRInSTR,
            (void *)defender_task,
            sub_accepted_packet_id,
            AWS_BYTE_BUF_PRI(defender_task->report_accepted_topic_name));
    } else {
        AWS_LOGF_ERROR(
            AWS_LS_IOTDEVICE_DEFENDER_TASK,
            "id=%p: Failed to send subscription packet for topic: " PRInSTR,
            (void *)defender_task,
            AWS_BYTE_BUF_PRI(defender_task->report_accepted_topic_name));
    }

    const struct aws_byte_cursor rejected_cursor = aws_byte_cursor_from_buf(&defender_task->report_rejected_topic_name);
    uint16_t sub_rejected_packet_id = aws_mqtt_client_connection_subscribe(
        defender_task->config.connection,
        &rejected_cursor,
        AWS_MQTT_QOS_AT_LEAST_ONCE,
        &s_on_report_response_rejected,
        defender_task,
        NULL,
        s_mqtt_on_suback,
        defender_task);

    if (sub_accepted_packet_id != 0) {
        AWS_LOGF_TRACE(
            AWS_LS_IOTDEVICE_DEFENDER_TASK,
            "id=%p: subscription packet_id [%d] for rejected topic " PRInSTR,
            (void *)defender_task,
            sub_rejected_packet_id,
            AWS_BYTE_BUF_PRI(defender_task->report_rejected_topic_name));
    } else {
        AWS_LOGF_ERROR(
            AWS_LS_IOTDEVICE_DEFENDER_TASK,
            "id=%p: Failed to send subscription packet for rejected topic: " PRInSTR,
            (void *)defender_task,
            AWS_BYTE_BUF_PRI(defender_task->report_rejected_topic_name));
    }

    aws_task_init(&defender_task->task, s_reporting_task_fn, defender_task, "DeviceDefenderReportTask");
cleanup:
    if (failure) {
        if (defender_task != NULL) {
            aws_mem_release(allocator, defender_task);
        }
        return NULL;
    }

    AWS_LOGF_TRACE(
                   AWS_LS_IOTDEVICE_DEFENDER_TASK, "id=%p: Scheduling defender task for first run", (void *)defender_task);
    aws_event_loop_schedule_task_now(defender_task->config.event_loop, &defender_task->task);

    return defender_task;
}

void aws_iotdevice_defender_v1_stop_task(struct aws_iotdevice_defender_v1_task *defender_task) {
    aws_atomic_store_int(&defender_task->task_cancelled, 1);
}

int aws_iotdevice_defender_register_number_metric(
    struct aws_iotdevice_defender_report_task_config *task_config,
    struct aws_allocator *allocator,
    const struct aws_byte_cursor *metric_name,
    aws_iotdevice_defender_get_number_fn *supplier,
    void *userdata) {
    AWS_PRECONDITION(task_config != NULL);
    AWS_PRECONDITION(metric_name != NULL);
    AWS_PRECONDITION(supplier != NULL);

    struct defender_custom_metric *custom_metric = aws_mem_acquire(allocator, sizeof(struct defender_custom_metric));
    custom_metric->type = DD_METRIC_NUMBER;
    custom_metric->metric_name = aws_string_new_from_cursor(allocator, metric_name);
    custom_metric->supplier_fn.get_number_fn = supplier;
    custom_metric->userdata = userdata;

    if (AWS_OP_SUCCESS != aws_array_list_push_back(&task_config->custom_metrics, &custom_metric)) {
        AWS_LOGF_ERROR(
            AWS_LS_IOTDEVICE_DEFENDER_TASK,
            "id=%p: Failed to add number custom metric " PRInSTR,
            (void *)task_config,
            AWS_BYTE_CURSOR_PRI(*metric_name)); /* wrong subject */
        return AWS_OP_ERR;
    }

    return AWS_OP_SUCCESS;
}

int aws_iotdevice_defender_register_number_list_metric(
    struct aws_iotdevice_defender_report_task_config *task_config,
    struct aws_allocator *allocator,
    const struct aws_byte_cursor *metric_name,
    aws_iotdevice_defender_get_number_list_fn *supplier,
    void *userdata) {
    AWS_PRECONDITION(task_config != NULL)
    AWS_PRECONDITION(metric_name != NULL);
    AWS_PRECONDITION(supplier != NULL);

    struct defender_custom_metric *custom_metric = aws_mem_acquire(allocator, sizeof(struct defender_custom_metric));
    custom_metric->type = DD_METRIC_NUMBER_LIST;
    custom_metric->metric_name = aws_string_new_from_cursor(allocator, metric_name);
    custom_metric->supplier_fn.get_number_list_fn = supplier;
    custom_metric->userdata = userdata;

    if (AWS_OP_SUCCESS != aws_array_list_push_back(&task_config->custom_metrics, &custom_metric)) {
        AWS_LOGF_ERROR(
            AWS_LS_IOTDEVICE_DEFENDER_TASK,
            "id=%p: Failed to add number list custom metric " PRInSTR,
            (void *)task_config,
            AWS_BYTE_CURSOR_PRI(*metric_name)); /* wrong subject */
        return AWS_OP_ERR;
    }

    return AWS_OP_SUCCESS;
}

int aws_iotdevice_defender_register_string_list_metric(
    struct aws_iotdevice_defender_report_task_config *task_config,
    struct aws_allocator *allocator,
    const struct aws_byte_cursor *metric_name,
    aws_iotdevice_defender_get_string_list_fn *supplier,
    void *userdata) {
    AWS_PRECONDITION(task_config != NULL);
    AWS_PRECONDITION(metric_name != NULL);
    AWS_PRECONDITION(supplier != NULL);

    struct defender_custom_metric *custom_metric = aws_mem_acquire(allocator, sizeof(struct defender_custom_metric));
    custom_metric->type = DD_METRIC_STRING_LIST;
    custom_metric->metric_name = aws_string_new_from_cursor(allocator, metric_name);
    custom_metric->supplier_fn.get_string_list_fn = supplier;
    custom_metric->userdata = userdata;

    if (AWS_OP_SUCCESS != aws_array_list_push_back(&task_config->custom_metrics, &custom_metric)) {
        AWS_LOGF_ERROR(
            AWS_LS_IOTDEVICE_DEFENDER_TASK,
            "id=%p: Failed to add string list custom metric " PRInSTR,
            (void *)task_config,
            AWS_BYTE_CURSOR_PRI(*metric_name)); /* wrong subject */
        return AWS_OP_ERR;
    }

    return AWS_OP_SUCCESS;
}

int aws_iotdevice_defender_register_ip_list_metric(
    struct aws_iotdevice_defender_report_task_config *task_config,
    struct aws_allocator *allocator,
    const struct aws_byte_cursor *metric_name,
    aws_iotdevice_defender_get_ip_list_fn *supplier,
    void *userdata) {
    AWS_PRECONDITION(task_config != NULL);
    AWS_PRECONDITION(metric_name != NULL);
    AWS_PRECONDITION(supplier != NULL);

    struct defender_custom_metric *custom_metric = aws_mem_acquire(allocator, sizeof(struct defender_custom_metric));
    custom_metric->type = DD_METRIC_IP_LIST;
    custom_metric->metric_name = aws_string_new_from_cursor(allocator, metric_name);
    custom_metric->supplier_fn.get_string_list_fn = supplier;
    custom_metric->userdata = userdata;

    if (AWS_OP_SUCCESS != aws_array_list_push_back(&task_config->custom_metrics, &custom_metric)) {
        AWS_LOGF_ERROR(
            AWS_LS_IOTDEVICE_DEFENDER_TASK,
            "id=%p: Failed to add IP list custom metric " PRInSTR,
            (void *)task_config,
            AWS_BYTE_CURSOR_PRI(*metric_name)); /* wrong subject */
        return AWS_OP_ERR;
    }

    return AWS_OP_SUCCESS;
}
