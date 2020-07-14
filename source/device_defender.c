/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/iotdevice/device_defender.h>
#include <aws/iotdevice/external/cJSON.h>
#include <aws/iotdevice/private/network.h>

#include <aws/common/allocator.h>
#include <aws/common/atomics.h>
#include <aws/common/byte_buf.h>
#include <aws/common/clock.h>
#include <aws/common/hash_table.h>
#include <aws/common/logging.h>
#include <aws/common/string.h>
#include <aws/common/task_scheduler.h>
#include <aws/io/event_loop.h>
#include <aws/mqtt/client.h>

struct aws_iotdevice_defender_v1_task {
    struct aws_allocator *allocator;
    struct aws_task task;
    struct aws_iotdevice_defender_report_task_config config;
    struct aws_iotdevice_metric_network_transfer previous_net_xfer;
    struct aws_byte_buf report_topic_name;
    struct aws_byte_buf report_accepted_topic_name;
    struct aws_byte_buf report_rejected_topic_name;
    bool has_previous_net_xfer;
    struct aws_atomic_var task_canceled; /* flag value switches to non-zero when canceled */
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
            userdata, packet_id, AWS_BYTE_CURSOR_PRI(*topic), aws_error_name(error_code));
    } else {
        AWS_LOGF_TRACE(
            AWS_LS_IOTDEVICE_DEFENDER_TASK,
            "id=%p: Suback callback succeeded with packet id: %d; topic " PRInSTR,
            userdata, packet_id, AWS_BYTE_CURSOR_PRI(*topic));
    }


    if (qos == AWS_MQTT_QOS_FAILURE) {
        AWS_LOGF_ERROR(
            AWS_LS_IOTDEVICE_DEFENDER_TASK,
            "id=%p: Suback packet error response for packet id: %d; topic " PRInSTR,
            userdata, packet_id, AWS_BYTE_CURSOR_PRI(*topic));
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
            userdata, packet_id, aws_error_name(error_code));
    }
}

static void s_on_report_response_rejected(
    struct aws_mqtt_client_connection *connection,
    const struct aws_byte_cursor *topic,
    const struct aws_byte_cursor *payload,
    void *userdata) {
    (void)connection;
    (void)payload;
    AWS_LOGF_ERROR(
        AWS_LS_IOTDEVICE_DEFENDER_TASK,
        "id=%p: Report rejected from topic: " PRInSTR,
        userdata, AWS_BYTE_CURSOR_PRI(*topic));

    printf("Rejection payload: " PRInSTR, AWS_BYTE_CURSOR_PRI(*payload));
}

static void s_on_report_response_accepted(
    struct aws_mqtt_client_connection *connection,
    const struct aws_byte_cursor *topic,
    const struct aws_byte_cursor *payload,
    void *userdata) {
    (void)connection;
    (void)payload;
    AWS_LOGF_TRACE(
        AWS_LS_IOTDEVICE_DEFENDER_TASK,
        "id=%p: Report accepted on topic: " PRInSTR,
        userdata, AWS_BYTE_CURSOR_PRI(*topic));
}

static int s_get_metric_report_json(
    struct aws_byte_buf *json_out,
    struct aws_iotdevice_defender_v1_task *task,
    uint64_t report_id,
    const struct aws_iotdevice_metric_network_transfer *net_xfer,
    const struct aws_array_list *net_conns) {
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

    if (NULL == cJSON_AddNumberToObject(tcp_connections, "total", total_established_tcp_conns)) {
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
    if (NULL == cJSON_AddNumberToObject(network_stats, "bytes_out", net_xfer != NULL ? (double)net_xfer->bytes_out : 0)) {
        goto cleanup;
    }
    if (NULL == cJSON_AddNumberToObject(network_stats, "packets_in", net_xfer != NULL ? (double)net_xfer->packets_in : 0)) {
        goto cleanup;
    }
    if (NULL == cJSON_AddNumberToObject(network_stats, "packets_out", net_xfer != NULL ? (double)net_xfer->packets_out : 0)) {
        goto cleanup;
    }

    const size_t remaining_capacity = json_out->capacity - json_out->len;
    char *write_start = (char *)json_out->buffer + json_out->len;
    if (!cJSON_PrintPreallocated(root, write_start, (int)remaining_capacity, false)) {
        AWS_LOGF_ERROR(AWS_LS_IOTDEVICE_DEFENDER_TASK, "id=%p: Failed to print defender report JSON", (void *)task);
        return_value = AWS_OP_ERR;
    } else {
        return_value = AWS_OP_SUCCESS;
        json_out->len += strlen(write_start);
    }

cleanup:
    if (root) {
        cJSON_Delete(root);
    }
    if (return_value != AWS_OP_SUCCESS) {
        return aws_raise_error(AWS_ERROR_IOTDEVICE_DEFENDER_REPORT_SERIALIZATION_FAILURE);
    }
    return return_value;
}

/**
 * Report_id generated using epoch time.
 */
static uint64_t s_defender_report_id_epoch_time_ms(struct aws_iotdevice_defender_v1_task *defender_task) {
    AWS_PRECONDITION(defender_task != NULL);
    uint64_t now;
    int return_code = 0;
    if (AWS_OP_SUCCESS != (return_code = aws_event_loop_current_clock_time(defender_task->config.event_loop, &now))) {
        AWS_LOGF_TRACE(
            AWS_LS_IOTDEVICE_DEFENDER_TASK,
            "id=%p: Error generating report ID from aws_event_loop_current_clock_time(): %s",
            (void *)defender_task,
            aws_error_name(return_code));
        return 0;
    }
    return now / 1000000; /* convert nanoseconds to millis */
}

static void s_reporting_task_fn(struct aws_task *task, void *userdata, enum aws_task_status status) {
    struct aws_iotdevice_defender_v1_task *defender_task = (struct aws_iotdevice_defender_v1_task *)userdata;
    struct aws_allocator *allocator = defender_task->allocator;
    struct aws_iotdevice_network_ifconfig ifconfig;
    AWS_ZERO_STRUCT(ifconfig);
    struct aws_byte_buf json_report;
    AWS_ZERO_STRUCT(json_report);
    int return_code = 0;

    if (status == AWS_TASK_STATUS_RUN_READY) {
        /* check if a cancelation has been requested the normal way (not from the task scheduler) */
        /* note: the actual cancelation logic still happens on AWS_TASK_STATUS_CANCEL and thus the cancelation_fn could
         * theoretically be overwritten by then */

        const size_t task_canceled = aws_atomic_load_int(&defender_task->task_canceled);
        if (task_canceled) {
            AWS_LOGF_TRACE(
                AWS_LS_IOTDEVICE_DEFENDER_TASK,
                "id=%p: DeviceDefender reporting task cancel requested",
                (void *)defender_task);
            aws_event_loop_cancel_task(defender_task->config.event_loop, task);
        } else {
            AWS_LOGF_TRACE(
                AWS_LS_IOTDEVICE_DEFENDER_TASK, "id=%p: Running DeviceDefender reporting task", (void *)defender_task);

            if (AWS_OP_SUCCESS != (return_code = get_network_config_and_transfer(&ifconfig, allocator))) {
                AWS_LOGF_ERROR(
                    AWS_LS_IOTDEVICE_DEFENDER_TASK,
                    "id=%p: Failed to retrieve network configuration: %s",
                    (void *)defender_task,
                    aws_error_name(return_code));
                return;
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
                return;
            }

            uint64_t report_id = s_defender_report_id_epoch_time_ms(defender_task);
            /* TODO: come up with something better than allocating max size of MQTT message allowed by AWS IoT */
            uint8_t json_buffer_space[262144];
            json_report = aws_byte_buf_from_empty_array(json_buffer_space, 262144);
            struct aws_iotdevice_metric_network_transfer *ptr_delta_xfer = NULL;
            struct aws_iotdevice_metric_network_transfer delta_xfer;
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
            if (AWS_OP_SUCCESS != s_get_metric_report_json(&json_report, defender_task, report_id, ptr_delta_xfer, &net_conns)) {

            }

            defender_task->previous_net_xfer.bytes_in = totals.bytes_in;
            defender_task->previous_net_xfer.bytes_out = totals.bytes_out;
            defender_task->previous_net_xfer.packets_in = totals.packets_in;
            defender_task->previous_net_xfer.packets_out = totals.packets_out;

            struct aws_byte_cursor report_topic = aws_byte_cursor_from_buf(&defender_task->report_topic_name);
            struct aws_byte_cursor report = aws_byte_cursor_from_buf(&json_report);

            AWS_LOGF_TRACE(AWS_LS_IOTDEVICE_DEFENDER_TASK,
                "id=%p: Full report: " PRInSTR, (void *)defender_task, AWS_BYTE_CURSOR_PRI(report));

            uint16_t report_packet_id = aws_mqtt_client_connection_publish(defender_task->config.connection,
                &report_topic, AWS_MQTT_QOS_AT_LEAST_ONCE, false, &report, s_on_report_puback, defender_task);

            if (report_packet_id != 0) {
                AWS_LOGF_TRACE(
                    AWS_LS_IOTDEVICE_DEFENDER_TASK,
                    "id=%p: Report packet_id %d published on topic " PRInSTR,
                    (void *)defender_task, report_packet_id, AWS_BYTE_CURSOR_PRI(report_topic));
            } else {
                AWS_LOGF_ERROR(
                    AWS_LS_IOTDEVICE_DEFENDER_TASK,
                    "id=%p: Report failed to publish on topic " PRInSTR,
                    (void *)defender_task, AWS_BYTE_CURSOR_PRI(report_topic));
            }

            aws_array_list_clean_up(&net_conns);

            uint64_t now;
            aws_event_loop_current_clock_time(defender_task->config.event_loop, &now);
            aws_event_loop_schedule_task_future(
                defender_task->config.event_loop, task, now + defender_task->config.task_period_ns);
        }
    } else if (status == AWS_TASK_STATUS_CANCELED) {
        AWS_LOGF_TRACE(
            AWS_LS_IOTDEVICE_DEFENDER_TASK, "id=%p: Reporting task canceled, cleaning up", (void *)defender_task);

        /* intentionally dropping response handling and packet IDs */
        struct aws_byte_cursor accepted_topic = aws_byte_cursor_from_buf(&defender_task->report_accepted_topic_name);
        aws_mqtt_client_connection_unsubscribe(defender_task->config.connection,
            &accepted_topic, NULL, NULL);
        struct aws_byte_cursor rejected_topic = aws_byte_cursor_from_buf(&defender_task->report_rejected_topic_name);
        aws_mqtt_client_connection_unsubscribe(defender_task->config.connection,
            &rejected_topic, NULL, NULL);

        void *cancel_userdata = defender_task->config.cancelation_userdata;
        aws_mem_release(allocator, defender_task);
        /* totally fine if this function ptr is NULL */
        if (defender_task->config.task_canceled_fn != NULL) {
            defender_task->config.task_canceled_fn(cancel_userdata);
        }
    } else {
        AWS_LOGF_WARN(
            AWS_LS_IOTDEVICE_DEFENDER_TASK,
            "id=%p: Reporting task in unknown run state being ignored",
            (void *)defender_task);
        /* TODO: revise if reschedule or cancelation is appropriate here */
        uint64_t now;
        aws_event_loop_current_clock_time(defender_task->config.event_loop, &now);
        aws_event_loop_schedule_task_future(
            defender_task->config.event_loop, task, now + defender_task->config.task_period_ns);
    }
}

/**
 * Creates a new reporting task for Device Defender metrics
 */
struct aws_iotdevice_defender_v1_task *aws_iotdevice_defender_v1_run_task(
    struct aws_allocator *allocator,
    const struct aws_iotdevice_defender_report_task_config *config) {
    AWS_PRECONDITION(aws_allocator_is_valid(allocator));
    AWS_PRECONDITION(config != NULL);
    bool failure = false;

    if (config->report_format != AWS_IDDRF_JSON) {
        AWS_LOGF_ERROR(AWS_LS_IOTDEVICE_DEFENDER_TASK, "Unsupported DeviceDefender detect report format detected.");
        aws_raise_error(AWS_ERROR_UNSUPPORTED_OPERATION);
        failure = true;
        goto cleanup;
    }

    /* to be freed on task cancellation, maybe within the task itself? */
    /* struct aws_iotdevice_defender_v1_task *defender_task = (struct aws_iotdevice_defender_v1_task *)aws_mem_calloc(
        allocator, 1, sizeof(struct aws_iotdevice_defender_v1_task)); */
    struct aws_iotdevice_defender_v1_task *defender_task = (struct aws_iotdevice_defender_v1_task *)aws_mem_acquire(
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
    aws_atomic_store_int(&defender_task->task_canceled, 0);

    /* derive the topics we will be publishing to and potentially reading the responses on */
    const char *pub_topic_base = "$aws/things/%s/defender/metrics/json";
    const char *accepted_topic_base = "$aws/things/%s/defender/metrics/json/accepted";
    const char *rejected_topic_base = "$aws/things/%s/defender/metrics/json/rejected";

    if (AWS_OP_SUCCESS !=
        aws_byte_buf_init(
            &defender_task->report_topic_name,
            allocator,
            strlen((const char *)config->thing_name.ptr) + strlen((const char *)pub_topic_base) - 1)) {
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
        aws_byte_buf_init(
            &defender_task->report_accepted_topic_name,
            allocator,
            strlen((const char *)config->thing_name.ptr) + strlen((const char *)accepted_topic_base) - 1)) {
        failure = true;
        goto cleanup;
    }
    snprintf(
        (char *)defender_task->report_accepted_topic_name.buffer,
        defender_task->report_accepted_topic_name.capacity,
        accepted_topic_base,
        (char *)defender_task->config.thing_name.ptr);
    defender_task->report_accepted_topic_name.len = strlen((const char *)defender_task->report_accepted_topic_name.buffer);

    if (AWS_OP_SUCCESS !=
        aws_byte_buf_init(
            &defender_task->report_rejected_topic_name,
            allocator,
            strlen((const char *)config->thing_name.ptr) + strlen((const char *)rejected_topic_base) - 1)) {
        failure = true;
        goto cleanup;
    }
    snprintf(
        (char *)defender_task->report_rejected_topic_name.buffer,
        defender_task->report_rejected_topic_name.capacity,
        rejected_topic_base,
        (char *)defender_task->config.thing_name.ptr);
    defender_task->report_rejected_topic_name.len = strlen((const char *)defender_task->report_rejected_topic_name.buffer);

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
        AWS_LOGF_TRACE(
            AWS_LS_IOTDEVICE_DEFENDER_TASK, "id=%p: subscription packet_id [%d] for accepted topic " PRInSTR, (void *)defender_task, sub_accepted_packet_id,
                AWS_BYTE_BUF_PRI(defender_task->report_accepted_topic_name));
    }
    else {
        /* log error, but subscription not necessary to publish messages */
        AWS_LOGF_ERROR(
            AWS_LS_IOTDEVICE_DEFENDER_TASK, "id=%p: Failed to send subscription packet for topic: " PRInSTR, (void *)defender_task,
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
            AWS_LS_IOTDEVICE_DEFENDER_TASK, "id=%p: subscription packet_id [%d] for rejected topic " PRInSTR, (void *)defender_task, sub_rejected_packet_id,
                AWS_BYTE_BUF_PRI(defender_task->report_rejected_topic_name));
    }
    else {
        /* log error, but subscription not necessary to publish messages */
        AWS_LOGF_ERROR(
            AWS_LS_IOTDEVICE_DEFENDER_TASK, "id=%p: Failed to send subscription packet for rejected topic: " PRInSTR, (void *)defender_task,
            AWS_BYTE_BUF_PRI(defender_task->report_rejected_topic_name));
    }

    aws_task_init(&defender_task->task, s_reporting_task_fn, defender_task, "DeviceDefenderReportTask");
cleanup:
    if (failure) {
        aws_mem_release(allocator, defender_task);
        defender_task = NULL;
    }

    AWS_LOGF_TRACE(
        AWS_LS_IOTDEVICE_DEFENDER_TASK, "id=%p: Running defender task for the first time", (void *)defender_task);
    aws_event_loop_schedule_task_now(defender_task->config.event_loop, &defender_task->task);

    return defender_task;
}

/**
 * Cancels the running task reporting Device Defender metrics
 */
void aws_iotdevice_defender_v1_stop_task(struct aws_iotdevice_defender_v1_task *defender_task) {
    /* this will trigger proper callback fn set on creation */
    aws_atomic_store_int(&defender_task->task_canceled, 1);
}
