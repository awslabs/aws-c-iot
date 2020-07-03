/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/iotdevice/device_defender.h>
#include <aws/iotdevice/external/cJSON.h>
#include <aws/iotdevice/private/network.h>

#include <aws/common/atomics.h>
#include <aws/common/allocator.h>
#include <aws/common/clock.h>
#include <aws/common/hash_table.h>
#include <aws/common/string.h>
#include <aws/common/task_scheduler.h>
#include <aws/io/event_loop.h>
#include <aws/mqtt/mqtt.h>

struct aws_iotdevice_defender_report_task_config {
    struct aws_event_loop *event_loop; /* event loop to schedule task on continuously */
    unsigned int report_format;        /* only JSON supported for now */
    uint64_t initial_report_id;        /* Initial report_id value for uniqueness, monotonically increasing */
    uint64_t task_period_ns;           /* how frequently do we send out a report. Service limit is once every 5m */
    uint64_t netconn_sample_period_ns; /* how frequently we sample for established connections and listening ports */
};

struct aws_iotdevice_defender_v1_task {
    struct aws_allocator *allocator;
    struct aws_task task;
    struct aws_iotdevice_defender_report_task_config config;
    size_t proc_net_tcp_size_hint;
    size_t proc_net_udp_size_hint;
    struct aws_iotdevice_metric_network_transfer previous_net_xfer;
    bool has_previous_net_xfer;
    struct aws_atomic_var task_canceled_fn; /* aws_iotdevice_defender_v1_task_canceled_fn */
};

static int s_get_metric_report_json(
    struct aws_byte_buf *json_out,
    const struct aws_iotdevice_metric_network_transfer *net_xfer,
    const struct aws_array_list *tcp_conns,
    const struct aws_array_list *udp_conns) {
    (void)json_out;
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
    cJSON_AddNumberToObject(header, "report_id", 1001);
    cJSON_AddStringToObject(header, "version", "1.0");

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

    int total_listening_tcp_ports = 0;
    int total_established_tcp_conns = 0;
    const size_t tcp_conn_sz = aws_array_list_length(tcp_conns);
    for (size_t tcp_index = 0; tcp_index < tcp_conn_sz; ++tcp_index) {
        struct aws_iotdevice_metric_net_connection *tcp_conn = NULL;
        aws_array_list_get_at_ptr(tcp_conns, (void **)&tcp_conn, tcp_index);
        if (tcp_conn->state == AWS_IDNCS_ESTABLISHED) {
            total_established_tcp_conns++;
            struct cJSON *conn = cJSON_CreateObject();
            cJSON_AddItemToArray(est_connections, conn);
            cJSON_AddStringToObject(conn, "interface", aws_string_c_str(tcp_conn->local_interface));
            cJSON_AddNumberToObject(conn, "port", tcp_conn->local_port);
            char remote_addr[22];
            snprintf(remote_addr, 22, "%s:%u", aws_string_c_str(tcp_conn->remote_address), tcp_conn->remote_port);
            cJSON_AddStringToObject(conn, "remote_addr", remote_addr);
        } else if (tcp_conn->state == AWS_IDNCS_LISTEN) {
            total_listening_tcp_ports++;
            struct cJSON *conn = cJSON_CreateObject();
            cJSON_AddItemToArray(tcp_listen_ports, conn);
            cJSON_AddStringToObject(conn, "interface", aws_string_c_str(tcp_conn->local_interface));
            cJSON_AddNumberToObject(conn, "port", tcp_conn->local_port);
        }
    }

    cJSON_AddNumberToObject(tcp_connections, "total", total_established_tcp_conns);
    cJSON_AddNumberToObject(listening_tcp_ports, "total", total_listening_tcp_ports);

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

    const size_t total_udp_listeners = aws_array_list_length(udp_conns);
    for (size_t udp_index = 0; udp_index < total_udp_listeners; ++udp_index) {
        struct aws_iotdevice_metric_net_connection *udp_conn = NULL;
        aws_array_list_get_at_ptr(udp_conns, (void **)&udp_conn, udp_index);
        struct cJSON *conn = cJSON_CreateObject();
        cJSON_AddItemToArray(udp_ports, conn);
        cJSON_AddStringToObject(conn, "interface", aws_string_c_str(udp_conn->local_interface));
        cJSON_AddNumberToObject(conn, "port", udp_conn->local_port);
    }
    cJSON_AddNumberToObject(listening_udp_ports, "total", (double)total_udp_listeners);

    if (net_xfer != NULL) {
        struct cJSON *network_stats = cJSON_CreateObject();
        if (network_stats == NULL) {
            goto cleanup;
        }
        cJSON_AddItemToObject(metrics, "network_stats", network_stats);

        cJSON_AddNumberToObject(network_stats, "bytes_in", (double)net_xfer->bytes_in);
        cJSON_AddNumberToObject(network_stats, "bytes_out", (double)net_xfer->bytes_out);
        cJSON_AddNumberToObject(network_stats, "packets_in", (double)net_xfer->packets_in);
        cJSON_AddNumberToObject(network_stats, "packets_out", (double)net_xfer->packets_out);
    }

    char *json = cJSON_Print(root);
    if (json == NULL) {
        goto cleanup;
    }

    json_out->buffer = (uint8_t *)json;
    json_out->capacity = json_out->len = strlen(json) * sizeof(char);

cleanup:
    if (root) {
        cJSON_Delete(root);
    }
    return return_value;
}

static void s_reporting_task_fn(struct aws_task *task, void *userdata, enum aws_task_status status) {
    (void)task;
    struct aws_iotdevice_defender_v1_task *defender_task = (struct aws_iotdevice_defender_v1_task *)userdata;
    struct aws_allocator *allocator = defender_task->allocator;
    struct aws_byte_buf net_tcp;
    AWS_ZERO_STRUCT(net_tcp);
    struct aws_byte_buf net_udp;
    AWS_ZERO_STRUCT(net_udp);
    struct aws_iotdevice_network_ifconfig ifconfig;
    AWS_ZERO_STRUCT(ifconfig);
    struct aws_byte_buf json_report;
    AWS_ZERO_STRUCT(json_report);
    int return_code = 0;

    if (status == AWS_TASK_STATUS_RUN_READY) {

        if (AWS_OP_SUCCESS != (return_code = get_network_config_and_transfer(&ifconfig, allocator))) {
            AWS_LOGF_ERROR(AWS_LS_IOTDEVICE_DEFENDER_TASK,
                "id=%p: Failed to retrieve network configuration: %s", (void *)defender_task, aws_error_name(return_code));
                return;
        }

        if (AWS_OP_SUCCESS != (return_code = read_proc_net_from_file(&net_tcp, allocator, defender_task->proc_net_tcp_size_hint, "/proc/net/tcp"))) {
            AWS_LOGF_ERROR(AWS_LS_IOTDEVICE_DEFENDER_TASK,
                "id=%p: Failed to retrieve network configuration: %s", (void *)defender_task, aws_error_name(return_code));
                return;
        }

        if (AWS_OP_SUCCESS != (return_code = read_proc_net_from_file(&net_udp, allocator, defender_task->proc_net_udp_size_hint, "/proc/net/udp"))) {
            AWS_LOGF_ERROR(AWS_LS_IOTDEVICE_DEFENDER_TASK,
                "id=%p: Failed to retrieve network configuration: %s", (void *)defender_task, aws_error_name(return_code));
                return;
        }

        struct aws_array_list tcp_conns;
        AWS_ZERO_STRUCT(tcp_conns);
        struct aws_array_list udp_conns;
        AWS_ZERO_STRUCT(udp_conns);

        aws_array_list_init_dynamic(&tcp_conns, allocator, 5, sizeof(struct aws_iotdevice_metric_net_connection));
        struct aws_byte_cursor net_tcp_cursor = aws_byte_cursor_from_buf(&net_tcp);
        if (AWS_OP_SUCCESS != get_net_connections(&tcp_conns, allocator, &ifconfig, &net_tcp_cursor, false)) {
        }

        struct aws_byte_cursor net_udp_cursor = aws_byte_cursor_from_buf(&net_udp);
        aws_array_list_init_dynamic(&udp_conns, allocator, 5, sizeof(struct aws_iotdevice_metric_net_connection));
        if (AWS_OP_SUCCESS != get_net_connections(&udp_conns, allocator, &ifconfig, &net_udp_cursor, true)) {
        }

        struct aws_iotdevice_metric_network_transfer totals = {
            .bytes_in = 0, .bytes_out = 0, .packets_in = 0, .packets_out = 0};
        get_system_network_total(&totals, &ifconfig);

        if (defender_task->has_previous_net_xfer) {
            struct aws_iotdevice_metric_network_transfer delta_xfer;
            delta_xfer.bytes_in = 0;
            delta_xfer.bytes_out = 0;
            delta_xfer.packets_in = 0;
            delta_xfer.packets_out = 0;

            get_network_total_delta(&delta_xfer, &defender_task->previous_net_xfer, &totals);
            s_get_metric_report_json(&json_report, &delta_xfer, &tcp_conns, &udp_conns);
        } else {
            defender_task->has_previous_net_xfer = true;
            s_get_metric_report_json(&json_report, NULL, &tcp_conns, &udp_conns);
        }
        defender_task->previous_net_xfer.bytes_in = totals.bytes_in;
        defender_task->previous_net_xfer.bytes_out = totals.bytes_out;
        defender_task->previous_net_xfer.packets_in = totals.packets_in;
        defender_task->previous_net_xfer.packets_out = totals.packets_out;

        uint64_t now;
        aws_event_loop_current_clock_time(defender_task->config.event_loop, &now);
        aws_event_loop_schedule_task_future(
            defender_task->config.event_loop, task, now + defender_task->config.task_period_ns);
    } else if (status == AWS_TASK_STATUS_CANCELED) {
        printf("Task was cancelled!\n");
    } else {
        // do cleanup for the task here
    }

    aws_byte_buf_clean_up(&json_report);

    if (net_tcp.allocator) {
        aws_byte_buf_clean_up(&net_tcp);
    }
    if (net_udp.allocator) {
        aws_byte_buf_clean_up(&net_udp);
    }
}

/**
 * Creates a new reporting task for Device Defender metrics
 */
struct aws_iotdevice_defender_v1_task *aws_iotdevice_defender_run_v1_task(
    struct aws_allocator *allocator,
    const struct aws_iotdevice_defender_report_task_config *config,
    aws_iotdevice_defender_v1_task_canceled_fn *task_canceled_fn) {

    /* to be freed on task cancellation, maybe within the task itself? */
    struct aws_iotdevice_defender_v1_task *defender_task = (struct aws_iotdevice_defender_v1_task *)aws_mem_calloc(
        allocator, 1, sizeof(struct aws_iotdevice_defender_v1_task));
    if (defender_task == NULL) {
        aws_raise_error(aws_last_error()); /* is this valid? */
        return NULL;
    }

    defender_task->allocator = allocator;
    defender_task->previous_net_xfer.bytes_in = 0;
    defender_task->previous_net_xfer.bytes_out = 0;
    defender_task->previous_net_xfer.packets_in = 0;
    defender_task->previous_net_xfer.packets_out = 0;
    defender_task->has_previous_net_xfer = false;
    defender_task->config = *config;
    defender_task->proc_net_tcp_size_hint = 4096;
    defender_task->proc_net_udp_size_hint = 4096;
    aws_atomic_store_ptr(&defender_task->task_canceled_fn, (void *)task_canceled_fn);

    aws_task_init(&defender_task->task, s_reporting_task_fn, defender_task, "DeviceDefenderReportTask");

    return AWS_OP_SUCCESS;
}

/**
 * Cancels the running task reporting Device Defender metrics
 */
void aws_iotdevice_stop_defender_v1_task(struct aws_iotdevice_defender_v1_task *defender_task) {
    /* callback fn param for stop/shutdown completed, and clean memory in callback */
    (void)defender_task;
}
