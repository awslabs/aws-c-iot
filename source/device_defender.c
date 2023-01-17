/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/iotdevice/device_defender.h>

#include <aws/common/condition_variable.h>
#include <aws/common/json.h>
#include <aws/common/mutex.h>
#include <aws/common/thread.h>
#include <aws/iotdevice/private/network.h>

#include <aws/common/array_list.h>
#include <aws/common/clock.h>
#include <aws/common/hash_table.h>
#include <aws/common/string.h>
#include <aws/common/task_scheduler.h>

#include <aws/io/event_loop.h>

#include <aws/mqtt/client.h>

/**
 * Update s_copy_task_config() and aws_iotdevice_defender_config_destroy()
 * when adding new members
 */
struct aws_iotdevice_defender_task_config {
    struct aws_allocator *allocator;
    struct aws_string *thing_name;
    struct aws_array_list custom_metrics;
    size_t custom_metrics_len;
    enum aws_iotdevice_defender_report_format report_format;
    uint64_t task_period_ns;
    aws_iotdevice_defender_task_canceled_fn *task_canceled_fn;
    aws_iotdevice_defender_task_failure_fn *task_failure_fn;
    aws_iotdevice_defender_report_accepted_fn *accepted_report_fn;
    aws_iotdevice_defender_report_rejected_fn *rejected_report_fn;
    void *callback_userdata;
};

/**
 * Instantiation of a custom metric to be collected when generating a metric report.
 */
struct defender_custom_metric {
    enum defender_custom_metric_type type;
    struct aws_string *metric_name;
    void *metric_cb_userdata;
    union {
        aws_iotdevice_defender_get_number_fn *get_number_fn;
        aws_iotdevice_defender_get_number_list_fn *get_number_list_fn;
        aws_iotdevice_defender_get_string_list_fn *get_string_list_fn;
        aws_iotdevice_defender_get_ip_list_fn *get_ip_list_fn;
    } supplier_fn;
};

/**
 * Result of a custom metric's data collection callback function that needs to be
 * populated into a report
 *
 * Data union only needs to physically point to a single number and a single list.
 */
struct defender_custom_metric_data {
    struct defender_custom_metric *metric;
    union {
        double number;
        struct aws_array_list list;
    } data;
    int callback_result;
};

struct aws_iotdevice_defender_task {
    struct aws_allocator *allocator;
    struct aws_ref_count ref_count;
    struct aws_event_loop *event_loop;
    struct aws_task task;
    struct aws_iotdevice_defender_task_config config;
    aws_iotdevice_defender_publish_fn *publish_fn;
    struct aws_mqtt_client_connection *connection;
    struct aws_iotdevice_metric_network_transfer previous_net_xfer;
    struct aws_string *publish_report_topic_name;
    struct aws_string *report_accepted_topic_name;
    struct aws_string *report_rejected_topic_name;
    bool has_previous_net_xfer;
    bool is_task_canceled;
    struct aws_mutex task_cancel_mutex;
    struct aws_condition_variable cv_task_canceled;
};

struct defender_report_publish_context {
    struct aws_byte_buf json_report;
    struct aws_byte_cursor json_report_cursor;
    struct aws_iotdevice_defender_task *defender_task;
    struct aws_allocator *allocator;
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

static void s_report_publish_context_clean_up(struct defender_report_publish_context *report_context) {
    AWS_PRECONDITION(report_context);
    struct aws_allocator *allocator = report_context->allocator;
    if (aws_byte_buf_is_valid(&report_context->json_report)) {
        aws_byte_buf_clean_up(&report_context->json_report);
    }

    aws_ref_count_release(&report_context->defender_task->ref_count);

    aws_mem_release(allocator, report_context);
}

void s_invoke_failure_callback(
    struct aws_iotdevice_defender_task_config *task_config,
    bool is_task_stopped,
    int error_code) {
    AWS_PRECONDITION(task_config != NULL);
    AWS_PRECONDITION(error_code != AWS_ERROR_SUCCESS);
    if (task_config->task_failure_fn) {
        task_config->task_failure_fn(is_task_stopped, error_code, task_config->callback_userdata);
    }
}

static void s_on_report_puback(
    struct aws_mqtt_client_connection *connection,
    uint16_t packet_id,
    int error_code,
    void *userdata) {
    (void)connection;
    (void)packet_id;
    AWS_PRECONDITION(userdata);
    struct defender_report_publish_context *report_context = userdata;
    struct aws_iotdevice_defender_task *defender_task = report_context->defender_task;
    if (error_code != AWS_ERROR_SUCCESS) {
        AWS_LOGF_ERROR(
            AWS_LS_IOTDEVICE_DEFENDER_TASK,
            "id=%p: Publish packet %d failed with error: %s",
            (void *)defender_task,
            packet_id,
            aws_error_name(error_code));
        s_invoke_failure_callback(
            &report_context->defender_task->config, false, AWS_ERROR_IOTDEVICE_DEFENDER_PUBLISH_FAILURE);
    }
    s_report_publish_context_clean_up(report_context);
}

static int s_mqtt_report_publish_fn(struct aws_byte_cursor report, void *userdata) {
    AWS_PRECONDITION(userdata != NULL);
    AWS_PRECONDITION(aws_byte_cursor_is_valid(&report));

    int result = AWS_OP_ERR;
    struct aws_iotdevice_defender_task *defender_task = userdata;
    struct defender_report_publish_context *report_context =
        aws_mem_calloc(defender_task->allocator, 1, sizeof(struct defender_report_publish_context));

    report_context->allocator = defender_task->allocator;
    report_context->defender_task = defender_task;

    /* Make sure defender task stays alive until publish completes one way or another */
    aws_ref_count_acquire(&defender_task->ref_count);

    /* must copy the report data and make into a byte_cursor to use it for MQTT publish */
    if (aws_byte_buf_init_copy_from_cursor(&report_context->json_report, defender_task->allocator, report)) {
        goto done;
    }

    report_context->json_report_cursor = aws_byte_cursor_from_buf(&report_context->json_report);

    struct aws_byte_cursor report_topic = aws_byte_cursor_from_string(defender_task->publish_report_topic_name);

    uint16_t report_packet_id = aws_mqtt_client_connection_publish(
        defender_task->connection,
        &report_topic,
        AWS_MQTT_QOS_AT_LEAST_ONCE,
        false,
        &report_context->json_report_cursor,
        s_on_report_puback,
        report_context);
    if (report_packet_id == 0) {
        AWS_LOGF_ERROR(
            AWS_LS_IOTDEVICE_DEFENDER_TASK,
            "id=%p: Report failed to publish on topic " PRInSTR,
            (void *)defender_task,
            AWS_BYTE_CURSOR_PRI(report_topic));
        goto done;
    }

    /* publish success means we do not clean up the report context until the publish callback completes */
    AWS_LOGF_DEBUG(
        AWS_LS_IOTDEVICE_DEFENDER_TASK,
        "id=%p: Report packet_id %d published on topic " PRInSTR,
        (void *)defender_task,
        report_packet_id,
        AWS_BYTE_CURSOR_PRI(report_topic));

    result = AWS_OP_SUCCESS;

done:

    if (result == AWS_OP_ERR) {
        s_report_publish_context_clean_up(report_context);
    }

    return result;
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
    (void)dup;
    (void)qos;
    (void)retain;
    struct aws_iotdevice_defender_task *defender_task = userdata;
    AWS_LOGF_ERROR(
        AWS_LS_IOTDEVICE_DEFENDER_TASK,
        "id=%p: report rejected from topic: " PRInSTR "\nRejection payload: " PRInSTR,
        userdata,
        AWS_BYTE_CURSOR_PRI(*topic),
        AWS_BYTE_CURSOR_PRI(*payload));
    if (defender_task->config.rejected_report_fn) {
        defender_task->config.rejected_report_fn(payload, defender_task->config.callback_userdata);
    }
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
    (void)dup;
    (void)qos;
    (void)retain;
    struct aws_iotdevice_defender_task *defender_task = userdata;
    AWS_LOGF_DEBUG(
        AWS_LS_IOTDEVICE_DEFENDER_TASK,
        "id=%p: Report accepted on topic: " PRInSTR,
        (void *)defender_task,
        AWS_BYTE_CURSOR_PRI(*topic));
    if (defender_task->config.accepted_report_fn) {
        defender_task->config.accepted_report_fn(payload, defender_task->config.callback_userdata);
    }
}

static int s_get_metric_report_json(
    struct aws_byte_buf *json_out,
    struct aws_iotdevice_defender_task *task,
    uint64_t report_id,
    const struct aws_iotdevice_metric_network_transfer *net_xfer,
    const struct aws_array_list *net_conns,
    size_t custom_metrics_len,
    const struct defender_custom_metric_data *custom_metrics_data) {
    int return_value = AWS_OP_ERR;

    struct aws_allocator *allocator = aws_default_allocator();

    struct aws_json_value *root = aws_json_value_new_object(allocator);
    if (root == NULL) {
        goto cleanup;
    }

    struct aws_json_value *header = aws_json_value_new_object(allocator);
    if (aws_json_value_add_to_object(root, aws_byte_cursor_from_c_str("header"), header) == AWS_OP_ERR) {
        goto cleanup;
    }
    if (aws_json_value_add_to_object(
            header, aws_byte_cursor_from_c_str("report_id"), aws_json_value_new_number(allocator, (double)report_id)) ==
        AWS_OP_ERR) {
        goto cleanup;
    }
    if (aws_json_value_add_to_object(
            header,
            aws_byte_cursor_from_c_str("version"),
            aws_json_value_new_string(allocator, aws_byte_cursor_from_c_str("1.0"))) == AWS_OP_ERR) {
        goto cleanup;
    }

    struct aws_json_value *metrics = aws_json_value_new_object(allocator);
    if (aws_json_value_add_to_object(root, aws_byte_cursor_from_c_str("metrics"), metrics) == AWS_OP_ERR) {
        goto cleanup;
    }

    struct aws_json_value *listening_tcp_ports = aws_json_value_new_object(allocator);
    if (aws_json_value_add_to_object(metrics, aws_byte_cursor_from_c_str("listening_tcp_ports"), listening_tcp_ports) ==
        AWS_OP_ERR) {
        goto cleanup;
    }

    struct aws_json_value *tcp_listen_ports = aws_json_value_new_array(allocator);
    if (aws_json_value_add_to_object(listening_tcp_ports, aws_byte_cursor_from_c_str("ports"), tcp_listen_ports) ==
        AWS_OP_ERR) {
        goto cleanup;
    }

    struct aws_json_value *tcp_connections = aws_json_value_new_object(allocator);
    if (aws_json_value_add_to_object(metrics, aws_byte_cursor_from_c_str("tcp_connections"), tcp_connections) ==
        AWS_OP_ERR) {
        goto cleanup;
    }

    struct aws_json_value *established_tcp_conns = aws_json_value_new_object(allocator);
    if (aws_json_value_add_to_object(
            tcp_connections, aws_byte_cursor_from_c_str("established_connections"), established_tcp_conns) ==
        AWS_OP_ERR) {
        goto cleanup;
    }

    struct aws_json_value *est_connections = aws_json_value_new_array(allocator);
    if (aws_json_value_add_to_object(
            established_tcp_conns, aws_byte_cursor_from_c_str("connections"), est_connections) == AWS_OP_ERR) {
        goto cleanup;
    }

    struct aws_json_value *listening_udp_ports = aws_json_value_new_object(allocator);
    if (aws_json_value_add_to_object(metrics, aws_byte_cursor_from_c_str("listening_udp_ports"), listening_udp_ports) ==
        AWS_OP_ERR) {
        goto cleanup;
    }

    struct aws_json_value *udp_ports = aws_json_value_new_array(allocator);
    if (aws_json_value_add_to_object(listening_udp_ports, aws_byte_cursor_from_c_str("ports"), udp_ports) ==
        AWS_OP_ERR) {
        goto cleanup;
    }

    int total_listening_tcp_ports = 0;
    int total_established_tcp_conns = 0;
    int total_udp_listeners = 0;
    const size_t net_conn_sz = aws_array_list_length(net_conns);
    for (size_t tcp_index = 0; tcp_index < net_conn_sz; ++tcp_index) {
        struct aws_iotdevice_metric_net_connection *net_conn = NULL;
        aws_array_list_get_at_ptr(net_conns, (void **)&net_conn, tcp_index);
        if (net_conn->state == AWS_IDNCS_ESTABLISHED && net_conn->protocol == AWS_IDNP_TCP) {
            total_established_tcp_conns++;

            struct aws_json_value *conn = aws_json_value_new_object(allocator);
            if (conn == NULL) {
                goto cleanup;
            }
            aws_json_value_add_array_element(est_connections, conn);

            if (aws_json_value_add_to_object(
                    conn,
                    aws_byte_cursor_from_c_str("local_interface"),
                    aws_json_value_new_string(
                        allocator, aws_byte_cursor_from_c_str(aws_string_c_str(net_conn->local_interface)))) ==
                AWS_OP_ERR) {
                goto cleanup;
            }

            if (aws_json_value_add_to_object(
                    conn,
                    aws_byte_cursor_from_c_str("local_port"),
                    aws_json_value_new_number(allocator, net_conn->local_port)) == AWS_OP_ERR) {
                goto cleanup;
            }

            char remote_addr[22];
            snprintf(remote_addr, 22, "%s:%u", aws_string_c_str(net_conn->remote_address), net_conn->remote_port);
            if (aws_json_value_add_to_object(
                    conn,
                    aws_byte_cursor_from_c_str("remote_addr"),
                    aws_json_value_new_string(allocator, aws_byte_cursor_from_c_str(remote_addr))) == AWS_OP_ERR) {
                goto cleanup;
            }
        } else if (net_conn->state == AWS_IDNCS_LISTEN) {
            if (net_conn->protocol == AWS_IDNP_TCP) {
                total_listening_tcp_ports++;
            } else if (net_conn->protocol == AWS_IDNP_UDP) {
                ++total_udp_listeners;
            } else {
                continue; // skip
            }

            struct aws_json_value *conn = aws_json_value_new_object(allocator);
            if (conn == NULL) {
                goto cleanup;
            }
            aws_json_value_add_array_element(tcp_listen_ports, conn);

            if (aws_json_value_add_to_object(
                    conn,
                    aws_byte_cursor_from_c_str("interface"),
                    aws_json_value_new_string(allocator, aws_byte_cursor_from_string(net_conn->local_interface))) ==
                AWS_OP_ERR) {
                goto cleanup;
            }
            if (aws_json_value_add_to_object(
                    conn,
                    aws_byte_cursor_from_c_str("port"),
                    aws_json_value_new_number(allocator, net_conn->local_port)) == AWS_OP_ERR) {
                goto cleanup;
            }
        }
    }

    if (aws_json_value_add_to_object(
            established_tcp_conns,
            aws_byte_cursor_from_c_str("total"),
            aws_json_value_new_number(allocator, total_established_tcp_conns)) == AWS_OP_ERR) {
        goto cleanup;
    }
    if (aws_json_value_add_to_object(
            listening_tcp_ports,
            aws_byte_cursor_from_c_str("total"),
            aws_json_value_new_number(allocator, total_listening_tcp_ports)) == AWS_OP_ERR) {
        goto cleanup;
    }
    if (aws_json_value_add_to_object(
            listening_udp_ports,
            aws_byte_cursor_from_c_str("total"),
            aws_json_value_new_number(allocator, total_udp_listeners)) == AWS_OP_ERR) {
        goto cleanup;
    }

    struct aws_json_value *network_stats = aws_json_value_new_object(allocator);
    if (aws_json_value_add_to_object(metrics, aws_byte_cursor_from_c_str("network_stats"), network_stats) ==
        AWS_OP_ERR) {
        goto cleanup;
    }

    if (aws_json_value_add_to_object(
            network_stats,
            aws_byte_cursor_from_c_str("bytes_in"),
            aws_json_value_new_number(allocator, net_xfer != NULL ? (double)net_xfer->bytes_in : 0)) == AWS_OP_ERR) {
        goto cleanup;
    }
    if (aws_json_value_add_to_object(
            network_stats,
            aws_byte_cursor_from_c_str("bytes_out"),
            aws_json_value_new_number(allocator, net_xfer != NULL ? (double)net_xfer->bytes_out : 0)) == AWS_OP_ERR) {
        goto cleanup;
    }
    if (aws_json_value_add_to_object(
            network_stats,
            aws_byte_cursor_from_c_str("packets_in"),
            aws_json_value_new_number(allocator, net_xfer != NULL ? (double)net_xfer->packets_in : 0)) == AWS_OP_ERR) {
        goto cleanup;
    }
    if (aws_json_value_add_to_object(
            network_stats,
            aws_byte_cursor_from_c_str("packets_out"),
            aws_json_value_new_number(allocator, net_xfer != NULL ? (double)net_xfer->packets_out : 0)) == AWS_OP_ERR) {
        goto cleanup;
    }

    if (custom_metrics_len != 0) {
        struct aws_json_value *custom_metrics = aws_json_value_new_object(allocator);
        if (aws_json_value_add_to_object(root, aws_byte_cursor_from_c_str("custom_metrics"), custom_metrics) ==
            AWS_OP_ERR) {
            goto cleanup;
        }

        size_t list_size = 0;
        struct aws_json_value *json_value = NULL;
        struct aws_json_value *item = NULL;
        struct aws_json_value *json_list = NULL;
        struct aws_json_value *spurious_array_container = NULL;
        for (size_t metric_index = 0; metric_index < custom_metrics_len; ++metric_index) {
            if (custom_metrics_data[metric_index].callback_result != AWS_OP_SUCCESS) {
                // if the collection of a metric failed, do not output it to the report
                continue;
            }

            spurious_array_container = aws_json_value_new_array(allocator);
            if (aws_json_value_add_to_object(
                    custom_metrics,
                    aws_byte_cursor_from_string(custom_metrics_data[metric_index].metric->metric_name),
                    spurious_array_container)) {
                goto cleanup;
            }

            item = aws_json_value_new_object(allocator);
            if (item == NULL) {
                goto cleanup;
            }
            aws_json_value_add_array_element(spurious_array_container, item);

            if (custom_metrics_data[metric_index].metric->type == DD_METRIC_NUMBER) {
                if (aws_json_value_add_to_object(
                        item,
                        aws_byte_cursor_from_c_str("number"),
                        aws_json_value_new_number(allocator, custom_metrics_data[metric_index].data.number)) ==
                    AWS_OP_ERR) {
                    goto cleanup;
                }
            } else if (custom_metrics_data[metric_index].metric->type == DD_METRIC_NUMBER_LIST) {
                list_size = aws_array_list_length(&custom_metrics_data[metric_index].data.list);
                json_list = aws_json_value_new_array(allocator);
                if (aws_json_value_add_to_object(item, aws_byte_cursor_from_c_str("number_list"), json_list) ==
                    AWS_OP_ERR) {
                    goto cleanup;
                }
                for (size_t num_index = 0; num_index < list_size; ++num_index) {
                    double number = 0;
                    aws_array_list_get_at(&custom_metrics_data[metric_index].data.list, &number, num_index);
                    json_value = aws_json_value_new_number(allocator, number);
                    aws_json_value_add_array_element(json_list, json_value);
                }
            } else if (
                custom_metrics_data[metric_index].metric->type == DD_METRIC_STRING_LIST ||
                custom_metrics_data[metric_index].metric->type == DD_METRIC_IP_LIST) {
                list_size = aws_array_list_length(&custom_metrics_data[metric_index].data.list);
                if (custom_metrics_data[metric_index].metric->type == DD_METRIC_STRING_LIST) {
                    json_list = aws_json_value_new_array(allocator);
                    if (aws_json_value_add_to_object(item, aws_byte_cursor_from_c_str("string_list"), json_list) ==
                        AWS_OP_ERR) {
                        goto cleanup;
                    }
                } else {
                    json_list = aws_json_value_new_array(allocator);
                    if (aws_json_value_add_to_object(item, aws_byte_cursor_from_c_str("ip_list"), json_list) ==
                        AWS_OP_ERR) {
                        goto cleanup;
                    }
                }
                for (size_t list_index = 0; list_index < list_size; ++list_index) {
                    struct aws_string *list_value = NULL;
                    aws_array_list_get_at(&custom_metrics_data[metric_index].data.list, &list_value, list_index);
                    json_value = aws_json_value_new_string(allocator, aws_byte_cursor_from_string(list_value));
                    aws_json_value_add_array_element(json_list, json_value);
                }
            } else {
                AWS_LOGF_WARN(
                    AWS_LS_IOTDEVICE_DEFENDER_TASK,
                    "id=%p: Unknown custom metrics type found during report generation: %d, name %s",
                    (void *)task,
                    custom_metrics_data[metric_index].metric->type,
                    aws_string_c_str(custom_metrics_data[metric_index].metric->metric_name));
                continue;
            }
        }
    }

    struct aws_byte_buf json_report_buf;
    aws_byte_buf_init(&json_report_buf, task->allocator, 0);
    aws_byte_buf_append_json_string(root, &json_report_buf);
    struct aws_byte_cursor json_report_cursor = aws_byte_cursor_from_buf(&json_report_buf);
    if (AWS_OP_SUCCESS != aws_byte_buf_init_copy_from_cursor(json_out, task->allocator, json_report_cursor)) {
        s_invoke_failure_callback(&task->config, false, AWS_ERROR_IOTDEVICE_DEFENDER_REPORT_SERIALIZATION_FAILURE);
        return_value = AWS_OP_ERR;
    } else {
        return_value = AWS_OP_SUCCESS;
    }
    aws_byte_buf_clean_up_secure(&json_report_buf);

cleanup:
    if (root) {
        aws_json_value_destroy(root);
    }
    if (return_value != AWS_OP_SUCCESS) {
        aws_raise_error(AWS_ERROR_IOTDEVICE_DEFENDER_REPORT_SERIALIZATION_FAILURE);
    }
    return return_value;
}

static uint64_t s_defender_report_id_epoch_time_ms(struct aws_iotdevice_defender_task *defender_task) {
    AWS_PRECONDITION(defender_task != NULL);
    uint64_t now;
    int return_code = 0;
    if (AWS_OP_SUCCESS != (return_code = aws_event_loop_current_clock_time(defender_task->event_loop, &now))) {
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
    struct aws_iotdevice_defender_task *defender_task) {
    AWS_PRECONDITION(defender_task != NULL);

    if (custom_metric_data) {
        struct aws_allocator *allocator = defender_task->allocator;
        const size_t custom_metrics_len = defender_task->config.custom_metrics_len;

        for (size_t metric_index = 0; metric_index < custom_metrics_len; ++metric_index) {
            struct defender_custom_metric_data *metric_data = &custom_metric_data[metric_index];
            aws_array_list_get_at(&defender_task->config.custom_metrics, (void **)&metric_data->metric, metric_index);

            struct defender_custom_metric *metric = metric_data->metric;
            switch (metric->type) {
                case DD_METRIC_NUMBER: /* nothing to do here */
                    break;
                case DD_METRIC_NUMBER_LIST:
                    aws_array_list_init_dynamic(
                        &custom_metric_data[metric_index].data.list, allocator, 0, sizeof(double));
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
    }

    return AWS_OP_SUCCESS;
}

/**
 * Cleans up the memory associated with collecting metric data each defender task run
 *
 * Nests into list types to free memory of items if they need to be destroyed
 */
static void s_clean_up_custom_metric_data(
    struct aws_allocator *allocator,
    struct defender_custom_metric_data *custom_metrics_data,
    const size_t custom_metrics_len) {
    AWS_PRECONDITION(allocator != NULL);

    if (custom_metrics_data) {
        for (size_t metric_index = 0; metric_index < custom_metrics_len; ++metric_index) {
            size_t list_size = 0; /* set only if we have a list type */
            /* if metric is a NULL ptr, then data was never populated and it is not safe to
               dereference pointer to metric as it is NULL */
            if (custom_metrics_data[metric_index].metric) {
                switch (custom_metrics_data[metric_index].metric->type) {
                    case DD_METRIC_NUMBER: /* nothing to do here */
                        break;
                    case DD_METRIC_STRING_LIST:
                    /* fall through */
                    case DD_METRIC_IP_LIST:
                        list_size = aws_array_list_length(&custom_metrics_data[metric_index].data.list);
                        for (size_t item_index = 0; item_index < list_size; ++item_index) {
                            struct aws_string *string_or_ip_entry;
                            aws_array_list_get_at(
                                &custom_metrics_data[metric_index].data.list, (void *)&string_or_ip_entry, item_index);
                            aws_string_destroy(string_or_ip_entry);
                        }
                        aws_array_list_clean_up(
                            &custom_metrics_data[metric_index].data.list); // Destory the list when finished
                        break;
                    case DD_METRIC_NUMBER_LIST:
                        aws_array_list_clean_up(&custom_metrics_data[metric_index].data.list);
                        break;
                    case DD_METRIC_UNKNOWN:
                    default:
                        break;
                }
            }
        }
        aws_mem_release(allocator, custom_metrics_data);
    }
}

static void s_get_custom_metrics_data(
    const struct aws_iotdevice_defender_task *defender_task,
    struct defender_custom_metric_data *custom_metric_data,
    const size_t custom_metrics_len) {
    if (custom_metrics_len != 0) {
        for (size_t metric_index = 0; metric_index < custom_metrics_len; ++metric_index) {
            aws_array_list_get_at(
                &defender_task->config.custom_metrics, (void *)&custom_metric_data[metric_index].metric, metric_index);

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
                            custom_metric_data[metric_index].metric->metric_cb_userdata);
                    break;
                case DD_METRIC_NUMBER_LIST:
                    custom_metric_data[metric_index].callback_result =
                        custom_metric_data[metric_index].metric->supplier_fn.get_number_list_fn(
                            &custom_metric_data[metric_index].data.list,
                            custom_metric_data[metric_index].metric->metric_cb_userdata);
                    break;
                case DD_METRIC_STRING_LIST:
                    custom_metric_data[metric_index].callback_result =
                        custom_metric_data[metric_index].metric->supplier_fn.get_string_list_fn(
                            &custom_metric_data[metric_index].data.list,
                            custom_metric_data[metric_index].metric->metric_cb_userdata);
                    break;
                case DD_METRIC_IP_LIST:
                    custom_metric_data[metric_index].callback_result =
                        custom_metric_data[metric_index].metric->supplier_fn.get_ip_list_fn(
                            &custom_metric_data[metric_index].data.list,
                            custom_metric_data[metric_index].metric->metric_cb_userdata);
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

/**
 * Differs in the public version in that it only cleans up the members and not the
 * entire structure itself. When cleaning up the defender_task internals, it must clean
 * up the copy of the config, but the config struct is part of the defender_task
 * so its memory isn't freed along with the internals
 */
void s_defender_config_clean_up_internals(struct aws_iotdevice_defender_task_config *config) {
    AWS_PRECONDITION(config != NULL);
    aws_string_destroy(config->thing_name);
    for (size_t metrics_index = 0; metrics_index < config->custom_metrics_len; ++metrics_index) {
        struct defender_custom_metric *metric = NULL;
        aws_array_list_get_at(&config->custom_metrics, (void **)&metric, metrics_index);
        aws_string_destroy(metric->metric_name);
        aws_mem_release(config->allocator, metric);
    }
    aws_array_list_clean_up(&config->custom_metrics);
}

/* Final memory clean up when ref count hits zero */
void s_defender_task_clean_up_final(struct aws_iotdevice_defender_task *defender_task) {
    aws_string_destroy(defender_task->publish_report_topic_name);
    aws_string_destroy(defender_task->report_accepted_topic_name);
    aws_string_destroy(defender_task->report_rejected_topic_name);

    aws_mutex_clean_up(&defender_task->task_cancel_mutex);
    aws_condition_variable_clean_up(&defender_task->cv_task_canceled);

    s_defender_config_clean_up_internals(&defender_task->config);
    aws_mem_release(defender_task->allocator, defender_task);
}

void s_defender_task_clean_up(struct aws_iotdevice_defender_task *defender_task) {
    AWS_PRECONDITION(defender_task != NULL);

    if (defender_task->connection) {
        struct aws_byte_cursor accepted_topic = aws_byte_cursor_from_string(defender_task->report_accepted_topic_name);
        aws_mqtt_client_connection_unsubscribe(defender_task->connection, &accepted_topic, NULL, NULL);
        struct aws_byte_cursor rejected_topic = aws_byte_cursor_from_string(defender_task->report_rejected_topic_name);
        aws_mqtt_client_connection_unsubscribe(defender_task->connection, &rejected_topic, NULL, NULL);
    }

    aws_ref_count_release(&defender_task->ref_count);
}

static void s_serialize_and_publish_defender_report(
    struct aws_iotdevice_defender_task *defender_task,
    struct aws_iotdevice_metric_network_transfer *totals,
    struct aws_iotdevice_metric_network_transfer *delta_xfer,
    struct aws_array_list *net_conns,
    const size_t custom_metrics_len,
    struct defender_custom_metric_data *custom_metric_data) {
    uint64_t report_id = s_defender_report_id_epoch_time_ms(defender_task);
    struct aws_byte_buf json_report_buf;
    AWS_ZERO_STRUCT(json_report_buf);

    if (AWS_OP_SUCCESS == s_get_metric_report_json(
                              &json_report_buf,
                              defender_task,
                              report_id,
                              delta_xfer,
                              net_conns,
                              custom_metrics_len,
                              custom_metric_data)) {
        defender_task->previous_net_xfer.bytes_in = totals->bytes_in;
        defender_task->previous_net_xfer.bytes_out = totals->bytes_out;
        defender_task->previous_net_xfer.packets_in = totals->packets_in;
        defender_task->previous_net_xfer.packets_out = totals->packets_out;

        struct aws_byte_cursor report = aws_byte_cursor_from_buf(&json_report_buf);

        AWS_LOGF_TRACE(
            AWS_LS_IOTDEVICE_DEFENDER_TASK,
            "id=%p: Full report: " PRInSTR,
            (void *)defender_task,
            AWS_BYTE_CURSOR_PRI(report));

        void *userdata = defender_task->connection ? defender_task : defender_task->config.callback_userdata;
        if (AWS_OP_ERR == defender_task->publish_fn(report, userdata)) {
            s_invoke_failure_callback(&defender_task->config, false, AWS_ERROR_IOTDEVICE_DEFENDER_PUBLISH_FAILURE);
            AWS_LOGF_DEBUG(
                AWS_LS_IOTDEVICE_DEFENDER_TASK,
                "id=%p: Failed to publish report: %s",
                (void *)defender_task,
                aws_error_name(aws_last_error()));
        } else {
            AWS_LOGF_DEBUG(
                AWS_LS_IOTDEVICE_DEFENDER_TASK, "id=%p: Successfully published report", (void *)defender_task);
        }
        aws_byte_buf_clean_up(&json_report_buf);
    }
}

static void s_reporting_task_fn(struct aws_task *task, void *userdata, enum aws_task_status status) {
    struct aws_iotdevice_defender_task *defender_task = (struct aws_iotdevice_defender_task *)userdata;
    struct aws_allocator *allocator = defender_task->allocator;
    struct aws_iotdevice_network_ifconfig ifconfig;
    AWS_ZERO_STRUCT(ifconfig);
    const size_t custom_metrics_len = aws_array_list_length(&defender_task->config.custom_metrics);
    struct defender_custom_metric_data *custom_metric_data =
        custom_metrics_len == 0
            ? NULL
            : aws_mem_calloc(allocator, custom_metrics_len, sizeof(struct defender_custom_metric_data));
    int return_code = 0;

    if (status == AWS_TASK_STATUS_RUN_READY) {
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

        /* serialize and publish MAY not publish successfully, but in the event
           of failure, it will handle cleaning up the memory it allocated and
           and invoke the task failure callback. If it succeeeds, task completion
           deferred until puback packet for the report is recieved. */
        s_serialize_and_publish_defender_report(
            defender_task, &totals, ptr_delta_xfer, &net_conns, custom_metrics_len, custom_metric_data);

        for (size_t interface_index = 0; interface_index < net_conns.length; ++interface_index) {
            struct aws_iotdevice_metric_net_connection *con = NULL;
            if (aws_array_list_get_at_ptr(&net_conns, (void **)&con, interface_index)) {
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
        aws_event_loop_current_clock_time(defender_task->event_loop, &now);
        aws_event_loop_schedule_task_future(
            defender_task->event_loop, task, now + defender_task->config.task_period_ns);
    } else if (status == AWS_TASK_STATUS_CANCELED) {
        AWS_LOGF_DEBUG(
            AWS_LS_IOTDEVICE_DEFENDER_TASK, "id=%p: Reporting task cancelled, cleaning up", (void *)defender_task);

        if (defender_task->config.task_canceled_fn != NULL) {
            defender_task->config.task_canceled_fn(defender_task->config.callback_userdata);
        }
        /* cleanup of task memory happens in task cleanup or stop function */
    } else {
        s_invoke_failure_callback(&defender_task->config, false, AWS_ERROR_IOTDEVICE_DEFENDER_UNKNOWN_TASK_STATUS);
        uint64_t now;
        aws_event_loop_current_clock_time(defender_task->event_loop, &now);
        aws_event_loop_schedule_task_future(
            defender_task->event_loop, task, now + defender_task->config.task_period_ns);
    }

cleanup:
    s_clean_up_custom_metric_data(allocator, custom_metric_data, custom_metrics_len);

    if (aws_hash_table_is_valid(&ifconfig.iface_name_to_info)) {
        aws_hash_table_clean_up(&ifconfig.iface_name_to_info);
    }
}

int aws_iotdevice_defender_config_create(
    struct aws_iotdevice_defender_task_config **config_out,
    struct aws_allocator *allocator,
    const struct aws_byte_cursor *thing_name,
    enum aws_iotdevice_defender_report_format report_format) {
    AWS_PRECONDITION(config_out != NULL);
    AWS_PRECONDITION(aws_allocator_is_valid(allocator));
    AWS_PRECONDITION(aws_byte_cursor_is_valid(thing_name));

    struct aws_iotdevice_defender_task_config *config = NULL;

    if (report_format != AWS_IDDRF_JSON) {
        aws_raise_error(AWS_ERROR_IOTDEVICE_DEFENDER_UNSUPPORTED_REPORT_FORMAT);
        goto error_return;
    }

    config = aws_mem_calloc(allocator, 1, sizeof(struct aws_iotdevice_defender_task_config));

    config->thing_name = aws_string_new_from_cursor(allocator, thing_name);
    config->allocator = allocator;
    config->report_format = report_format;
    config->callback_userdata = NULL;
    config->task_canceled_fn = NULL;
    config->rejected_report_fn = NULL;
    config->accepted_report_fn = NULL;
    /* defaults here will be consistent across any language on top */
    config->task_period_ns = 5ULL * 60ULL * 1000000000ULL;
    aws_array_list_init_dynamic(&config->custom_metrics, allocator, 0, sizeof(struct defender_custom_metric *));
    config->custom_metrics_len = 0;

    *config_out = config;
    return AWS_OP_SUCCESS;

error_return:
    aws_mem_release(allocator, config);

    return AWS_OP_ERR;
}

void aws_iotdevice_defender_config_clean_up(struct aws_iotdevice_defender_task_config *config) {
    AWS_PRECONDITION(config != NULL);
    struct aws_allocator *allocator = config->allocator;
    AWS_ASSERT(aws_allocator_is_valid(allocator));
    /* assign caller ptr to NULL */
    if (config) {
        s_defender_config_clean_up_internals(config);
        aws_mem_release(allocator, config);
    }
}

struct aws_string *s_build_topic(
    struct aws_allocator *allocator,
    const struct aws_string *thing_name,
    struct aws_byte_cursor prefix,
    struct aws_byte_cursor suffix) {
    AWS_PRECONDITION(aws_allocator_is_valid(allocator));
    AWS_PRECONDITION(aws_string_is_valid(thing_name));
    AWS_PRECONDITION(aws_byte_cursor_is_valid(&prefix));
    AWS_PRECONDITION(aws_byte_cursor_is_valid(&suffix));

    struct aws_byte_buf topic_buffer;
    if (AWS_OP_SUCCESS != aws_byte_buf_init(&topic_buffer, allocator, prefix.len + suffix.len + thing_name->len)) {
        return NULL;
    }
    aws_byte_buf_append(&topic_buffer, &prefix);
    struct aws_byte_cursor thing_name_cursor = aws_byte_cursor_from_string(thing_name);
    aws_byte_buf_append(&topic_buffer, &thing_name_cursor);
    aws_byte_buf_append(&topic_buffer, &suffix);

    struct aws_string *topic_string = aws_string_new_from_buf(allocator, &topic_buffer);
    aws_byte_buf_clean_up(&topic_buffer);
    return topic_string;
}

int s_copy_task_config(
    struct aws_iotdevice_defender_task_config *dest_config,
    const struct aws_iotdevice_defender_task_config *src_config) {
    AWS_PRECONDITION(dest_config != NULL);
    AWS_PRECONDITION(src_config != NULL);

    struct aws_allocator *allocator = src_config->allocator;
    dest_config->allocator = src_config->allocator;
    dest_config->custom_metrics_len = src_config->custom_metrics_len;
    dest_config->thing_name = aws_string_new_from_string(src_config->allocator, src_config->thing_name);

    dest_config->callback_userdata = src_config->callback_userdata;
    dest_config->task_canceled_fn = src_config->task_canceled_fn;
    dest_config->accepted_report_fn = src_config->accepted_report_fn;
    dest_config->rejected_report_fn = src_config->rejected_report_fn;
    dest_config->task_period_ns = src_config->task_period_ns;

    if (AWS_OP_SUCCESS != aws_array_list_init_dynamic(
                              &dest_config->custom_metrics,
                              dest_config->allocator,
                              dest_config->custom_metrics_len,
                              sizeof(struct defender_custom_metric *))) {
        return AWS_OP_ERR;
    }

    for (size_t metric_index = 0; metric_index < dest_config->custom_metrics_len; ++metric_index) {
        struct defender_custom_metric *metric_dest =
            aws_mem_calloc(allocator, 1, sizeof(struct defender_custom_metric));
        struct defender_custom_metric *metric_src = NULL;
        aws_array_list_get_at(&src_config->custom_metrics, (void **)&metric_src, metric_index);
        metric_dest->metric_name = aws_string_new_from_string(allocator, metric_src->metric_name);
        metric_dest->metric_cb_userdata = metric_src->metric_cb_userdata;
        metric_dest->type = metric_src->type;
        metric_dest->supplier_fn = metric_src->supplier_fn;
        aws_array_list_push_back(&dest_config->custom_metrics, &metric_dest);
    }
    return AWS_OP_SUCCESS;
}

static void s_delete_dd_task(void *data) {
    struct aws_iotdevice_defender_task *task = data;
    s_defender_task_clean_up_final(task);
}

static int s_defender_task_create(
    struct aws_iotdevice_defender_task **task_out,
    const struct aws_iotdevice_defender_task_config *config,
    aws_iotdevice_defender_publish_fn *publish_fn,
    struct aws_mqtt_client_connection *connection,
    struct aws_event_loop *event_loop) {
    AWS_PRECONDITION(task_out != NULL);
    AWS_PRECONDITION(config != NULL);
    AWS_PRECONDITION(publish_fn != NULL);
    AWS_PRECONDITION(event_loop != NULL);

    int return_code = AWS_OP_ERR;
    struct aws_allocator *allocator = config->allocator;
    struct aws_iotdevice_defender_task *defender_task = NULL;

    if (config->report_format != AWS_IDDRF_JSON) {
        AWS_LOGF_ERROR(AWS_LS_IOTDEVICE_DEFENDER_TASK, "Unsupported DeviceDefender detect report format detected.");
        aws_raise_error(AWS_ERROR_IOTDEVICE_DEFENDER_UNSUPPORTED_REPORT_FORMAT);
        goto cleanup;
    }

    defender_task =
        (struct aws_iotdevice_defender_task *)aws_mem_calloc(allocator, 1, sizeof(struct aws_iotdevice_defender_task));
    if (defender_task == NULL) {
        aws_raise_error(aws_last_error());
        goto cleanup;
    }

    defender_task->allocator = allocator;
    defender_task->event_loop = event_loop;
    defender_task->publish_fn = publish_fn;
    defender_task->connection = connection;
    defender_task->previous_net_xfer.bytes_in = 0;
    defender_task->previous_net_xfer.bytes_out = 0;
    defender_task->previous_net_xfer.packets_in = 0;
    defender_task->previous_net_xfer.packets_out = 0;
    defender_task->has_previous_net_xfer = false;
    defender_task->is_task_canceled = false;
    aws_ref_count_init(&defender_task->ref_count, defender_task, s_delete_dd_task);

    if (AWS_OP_SUCCESS != aws_mutex_init(&defender_task->task_cancel_mutex)) {
        goto cleanup;
    }
    if (AWS_OP_SUCCESS != aws_condition_variable_init(&defender_task->cv_task_canceled)) {
        goto cleanup;
    }

    if (AWS_OP_SUCCESS != s_copy_task_config(&defender_task->config, config)) {
        goto cleanup;
    }
    if (!aws_array_list_is_valid(&defender_task->config.custom_metrics)) {
        aws_raise_error(AWS_ERROR_IOTDEVICE_DEFENDER_INVALID_TASK_CONFIG);
        goto cleanup;
    }

    if (connection != NULL) {
        struct aws_byte_cursor prefix = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("$aws/things/");
        struct aws_byte_cursor publish_suffix = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("/defender/metrics/json");
        struct aws_byte_cursor accepted_suffix =
            AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("/defender/metrics/json/accepted");
        struct aws_byte_cursor rejected_suffix =
            AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("/defender/metrics/json/rejected");
        defender_task->publish_report_topic_name = s_build_topic(allocator, config->thing_name, prefix, publish_suffix);
        defender_task->report_accepted_topic_name =
            s_build_topic(allocator, config->thing_name, prefix, accepted_suffix);
        defender_task->report_rejected_topic_name =
            s_build_topic(allocator, config->thing_name, prefix, rejected_suffix);

        const struct aws_byte_cursor accepted_cursor =
            aws_byte_cursor_from_string(defender_task->report_accepted_topic_name);
        uint16_t sub_accepted_packet_id = aws_mqtt_client_connection_subscribe(
            defender_task->connection,
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
                "id=%p: subscription packet_id [%d] for accepted topic %s",
                (void *)defender_task,
                sub_accepted_packet_id,
                aws_string_c_str(defender_task->report_accepted_topic_name));
        } else {
            AWS_LOGF_ERROR(
                AWS_LS_IOTDEVICE_DEFENDER_TASK,
                "id=%p: Failed to send subscription packet for topic: %s",
                (void *)defender_task,
                aws_string_c_str(defender_task->report_accepted_topic_name));
        }

        const struct aws_byte_cursor rejected_cursor =
            aws_byte_cursor_from_string(defender_task->report_rejected_topic_name);
        uint16_t sub_rejected_packet_id = aws_mqtt_client_connection_subscribe(
            defender_task->connection,
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
                "id=%p: subscription packet_id [%d] for rejected topic %s",
                (void *)defender_task,
                sub_rejected_packet_id,
                aws_string_c_str(defender_task->report_rejected_topic_name));
        } else {
            AWS_LOGF_ERROR(
                AWS_LS_IOTDEVICE_DEFENDER_TASK,
                "id=%p: Failed to send subscription packet for rejected topic: %s",
                (void *)defender_task,
                aws_string_c_str(defender_task->report_rejected_topic_name));
        }
    }

    aws_task_init(&defender_task->task, s_reporting_task_fn, defender_task, "DeviceDefenderReportTask");
    *task_out = defender_task;

    AWS_LOGF_TRACE(
        AWS_LS_IOTDEVICE_DEFENDER_TASK, "id=%p: Scheduling defender task for first run", (void *)defender_task);
    aws_event_loop_schedule_task_now(event_loop, &defender_task->task);

    return_code = AWS_OP_SUCCESS;
cleanup:
    if (return_code == AWS_OP_ERR && defender_task != NULL) {
        s_defender_task_clean_up(defender_task);
    }

    return return_code;
}

int aws_iotdevice_defender_task_create_ex(
    struct aws_iotdevice_defender_task **task_out,
    const struct aws_iotdevice_defender_task_config *config,
    aws_iotdevice_defender_publish_fn *publish_fn,
    struct aws_event_loop *event_loop) {
    return s_defender_task_create(task_out, config, publish_fn, NULL, event_loop);
}

int aws_iotdevice_defender_task_create(
    struct aws_iotdevice_defender_task **task_out,
    const struct aws_iotdevice_defender_task_config *config,
    struct aws_mqtt_client_connection *connection,
    struct aws_event_loop *event_loop) {
    AWS_PRECONDITION(connection != NULL);
    return s_defender_task_create(task_out, config, s_mqtt_report_publish_fn, connection, event_loop);
}

/**
 * Function gets scheduled on the same event loop at the defender task itself so it cannot
 * run at the same time as that task outside of the cancelled status.
 */
static void s_cancel_defender_task(struct aws_task *task, void *arg, enum aws_task_status task_status) {
    (void)task;
    (void)task_status;
    /* unsure if it makes sense to check this cancellation task to see if it was canceled */
    struct aws_iotdevice_defender_task *defender_task = arg;
    /* proper invocation here will block and run */
    aws_event_loop_cancel_task(defender_task->event_loop, &defender_task->task);

    aws_mutex_lock(&defender_task->task_cancel_mutex);
    defender_task->is_task_canceled = true;
    aws_condition_variable_notify_one(&defender_task->cv_task_canceled);
    aws_mutex_unlock(&defender_task->task_cancel_mutex);
}

static bool s_is_cancellation_complete(void *arg) {
    struct aws_iotdevice_defender_task *defender_task = arg;

    return defender_task->is_task_canceled;
}

void aws_iotdevice_defender_task_clean_up(struct aws_iotdevice_defender_task *defender_task) {
    AWS_PRECONDITION(defender_task != NULL);

    struct aws_task cancel_task;
    aws_task_init(&cancel_task, s_cancel_defender_task, defender_task, "cancel_defender_task");
    aws_event_loop_schedule_task_now(defender_task->event_loop, &cancel_task);
    aws_mutex_lock(&defender_task->task_cancel_mutex);
    aws_condition_variable_wait_pred(
        &defender_task->cv_task_canceled, &defender_task->task_cancel_mutex, s_is_cancellation_complete, defender_task);
    aws_mutex_unlock(&defender_task->task_cancel_mutex);

    s_defender_task_clean_up(defender_task);
}

void aws_iotdevice_defender_config_register_number_metric(
    struct aws_iotdevice_defender_task_config *task_config,
    const struct aws_byte_cursor *metric_name,
    aws_iotdevice_defender_get_number_fn *supplier,
    void *userdata) {
    AWS_PRECONDITION(task_config != NULL);
    AWS_PRECONDITION(metric_name != NULL);
    AWS_PRECONDITION(supplier != NULL);

    struct aws_allocator *allocator = task_config->allocator;
    struct defender_custom_metric *custom_metric = aws_mem_calloc(allocator, 1, sizeof(struct defender_custom_metric));
    custom_metric->type = DD_METRIC_NUMBER;
    custom_metric->metric_name = aws_string_new_from_cursor(allocator, metric_name);
    custom_metric->supplier_fn.get_number_fn = supplier;
    custom_metric->metric_cb_userdata = userdata;

    aws_array_list_push_back(&task_config->custom_metrics, &custom_metric);
    task_config->custom_metrics_len++;
}

void aws_iotdevice_defender_config_register_number_list_metric(
    struct aws_iotdevice_defender_task_config *task_config,
    const struct aws_byte_cursor *metric_name,
    aws_iotdevice_defender_get_number_list_fn *supplier,
    void *userdata) {
    AWS_PRECONDITION(task_config != NULL);
    AWS_PRECONDITION(metric_name != NULL);
    AWS_PRECONDITION(supplier != NULL);

    struct aws_allocator *allocator = task_config->allocator;
    struct defender_custom_metric *custom_metric = aws_mem_calloc(allocator, 1, sizeof(struct defender_custom_metric));
    custom_metric->type = DD_METRIC_NUMBER_LIST;
    custom_metric->metric_name = aws_string_new_from_cursor(allocator, metric_name);
    custom_metric->supplier_fn.get_number_list_fn = supplier;
    custom_metric->metric_cb_userdata = userdata;

    aws_array_list_push_back(&task_config->custom_metrics, &custom_metric);
    task_config->custom_metrics_len++;
}

void aws_iotdevice_defender_config_register_string_list_metric(
    struct aws_iotdevice_defender_task_config *task_config,
    const struct aws_byte_cursor *metric_name,
    aws_iotdevice_defender_get_string_list_fn *supplier,
    void *userdata) {
    AWS_PRECONDITION(task_config != NULL);
    AWS_PRECONDITION(metric_name != NULL);
    AWS_PRECONDITION(supplier != NULL);

    struct aws_allocator *allocator = task_config->allocator;
    struct defender_custom_metric *custom_metric = aws_mem_calloc(allocator, 1, sizeof(struct defender_custom_metric));
    custom_metric->type = DD_METRIC_STRING_LIST;
    custom_metric->metric_name = aws_string_new_from_cursor(allocator, metric_name);
    custom_metric->supplier_fn.get_string_list_fn = supplier;
    custom_metric->metric_cb_userdata = userdata;

    aws_array_list_push_back(&task_config->custom_metrics, &custom_metric);
    task_config->custom_metrics_len++;
}

void aws_iotdevice_defender_config_register_ip_list_metric(
    struct aws_iotdevice_defender_task_config *task_config,
    const struct aws_byte_cursor *metric_name,
    aws_iotdevice_defender_get_ip_list_fn *supplier,
    void *userdata) {
    AWS_PRECONDITION(task_config != NULL);
    AWS_PRECONDITION(metric_name != NULL);
    AWS_PRECONDITION(supplier != NULL);

    struct aws_allocator *allocator = task_config->allocator;
    struct defender_custom_metric *custom_metric = aws_mem_calloc(allocator, 1, sizeof(struct defender_custom_metric));
    custom_metric->type = DD_METRIC_IP_LIST;
    custom_metric->metric_name = aws_string_new_from_cursor(allocator, metric_name);
    custom_metric->supplier_fn.get_string_list_fn = supplier;
    custom_metric->metric_cb_userdata = userdata;

    aws_array_list_push_back(&task_config->custom_metrics, &custom_metric);
    task_config->custom_metrics_len++;
}

int aws_iotdevice_defender_config_set_task_cancelation_fn(
    struct aws_iotdevice_defender_task_config *config,
    aws_iotdevice_defender_task_canceled_fn *cancel_fn) {
    AWS_PRECONDITION(config != NULL);
    /* allow setting to null */
    config->task_canceled_fn = cancel_fn;
    return AWS_OP_SUCCESS;
}

int aws_iotdevice_defender_config_set_task_failure_fn(
    struct aws_iotdevice_defender_task_config *config,
    aws_iotdevice_defender_task_failure_fn *failure_fn) {
    AWS_PRECONDITION(config != NULL);
    /* allow setting to null */
    config->task_failure_fn = failure_fn;
    return AWS_OP_SUCCESS;
}

int aws_iotdevice_defender_config_set_report_accepted_fn(
    struct aws_iotdevice_defender_task_config *config,
    aws_iotdevice_defender_report_accepted_fn *accepted_fn) {
    AWS_PRECONDITION(config != NULL);
    /* allow setting to null */
    config->accepted_report_fn = accepted_fn;
    return AWS_OP_SUCCESS;
}

int aws_iotdevice_defender_config_set_report_rejected_fn(
    struct aws_iotdevice_defender_task_config *config,
    aws_iotdevice_defender_report_rejected_fn *rejected_fn) {
    AWS_PRECONDITION(config != NULL);
    /* allow setting to null */
    config->rejected_report_fn = rejected_fn;
    return AWS_OP_SUCCESS;
}

int aws_iotdevice_defender_config_set_task_period_ns(
    struct aws_iotdevice_defender_task_config *config,
    uint64_t task_period_ns) {
    AWS_PRECONDITION(config != NULL);
    /* allow setting to null, and any value (low or high) */
    config->task_period_ns = task_period_ns;
    return AWS_OP_SUCCESS;
}

/* Note: return value perhaps will never have relevance */
int aws_iotdevice_defender_config_set_callback_userdata(
    struct aws_iotdevice_defender_task_config *config,
    void *userdata) {
    AWS_PRECONDITION(config != NULL);
    /* allow setting to null, and any value (low or high) */
    config->callback_userdata = userdata;
    return AWS_OP_SUCCESS;
}
