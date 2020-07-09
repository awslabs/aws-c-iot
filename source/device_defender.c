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
    struct aws_iotdevice_metric_network_transfer previous_net_xfer;
    bool has_previous_net_xfer;
    struct aws_atomic_var task_canceled_fn; /* aws_iotdevice_defender_v1_task_canceled_fn */
};

static int s_get_metric_report_json(
    struct aws_byte_buf *json_out,
    const struct aws_iotdevice_metric_network_transfer *net_xfer,
    const struct aws_array_list *net_conns) {
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
            cJSON_AddStringToObject(conn, "interface", aws_string_c_str(net_conn->local_interface));
            cJSON_AddNumberToObject(conn, "port", net_conn->local_port);
            char remote_addr[22];
            snprintf(remote_addr, 22, "%s:%u", aws_string_c_str(net_conn->remote_address), net_conn->remote_port);
            cJSON_AddStringToObject(conn, "remote_addr", remote_addr);
        } else if (net_conn->state == AWS_IDNCS_LISTEN && net_conn->protocol == AWS_IDNP_TCP) {
            total_listening_tcp_ports++;
            struct cJSON *conn = cJSON_CreateObject();
            if (conn == NULL) {
                goto cleanup;
            }
            cJSON_AddItemToArray(tcp_listen_ports, conn);
            cJSON_AddStringToObject(conn, "interface", aws_string_c_str(net_conn->local_interface));
            cJSON_AddNumberToObject(conn, "port", net_conn->local_port);
        } else if (net_conn->state == AWS_IDNCS_LISTEN && net_conn->protocol == AWS_IDNP_UDP) {
            ++total_udp_listeners;
            struct cJSON *conn = cJSON_CreateObject();
            if (conn == NULL) {
                goto cleanup;
            }
            cJSON_AddItemToArray(udp_ports, conn);
            cJSON_AddStringToObject(conn, "interface", aws_string_c_str(net_conn->local_interface));
            cJSON_AddNumberToObject(conn, "port", net_conn->local_port);
        }
    }

    cJSON_AddNumberToObject(tcp_connections, "total", total_established_tcp_conns);
    cJSON_AddNumberToObject(listening_tcp_ports, "total", total_listening_tcp_ports);
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
    if(return_value != AWS_OP_SUCCESS) {
        return aws_raise_error(return_value);
    }
    return return_value;
}

static void s_reporting_task_fn(struct aws_task *task, void *userdata, enum aws_task_status status) {
    (void)task;
    struct aws_iotdevice_defender_v1_task *defender_task = (struct aws_iotdevice_defender_v1_task *)userdata;
    struct aws_allocator *allocator = defender_task->allocator;

    struct aws_iotdevice_network_ifconfig ifconfig;
    AWS_ZERO_STRUCT(ifconfig);
    struct aws_byte_buf json_report;
    AWS_ZERO_STRUCT(json_report);
    int return_code = 0;

    if (status == AWS_TASK_STATUS_RUN_READY) {
        /* check if a cancelation has been requested the normal way (not from the task scheduler) */
        aws_iotdevice_defender_v1_task_canceled_fn *task_canceled_fn = (aws_iotdevice_defender_v1_task_canceled_fn *)aws_atomic_load_ptr(&defender_task->task_canceled_fn);
        if (!task_canceled_fn) {
            /* TODO : run cleanups */
        }
        else {
            if (AWS_OP_SUCCESS != (return_code = get_network_config_and_transfer(&ifconfig, allocator))) {
                AWS_LOGF_ERROR(AWS_LS_IOTDEVICE_DEFENDER_TASK,
                    "id=%p: Failed to retrieve network configuration: %s", (void *)defender_task, aws_error_name(return_code));
                    return;
            }
            struct aws_iotdevice_metric_network_transfer totals = {
                .bytes_in = 0, .bytes_out = 0, .packets_in = 0, .packets_out = 0};
            get_system_network_total(&totals, &ifconfig);


            struct aws_array_list net_conns;
            AWS_ZERO_STRUCT(net_conns);
            aws_array_list_init_dynamic(&net_conns, allocator, 5, sizeof(struct aws_iotdevice_metric_net_connection));
            if (AWS_OP_SUCCESS != (return_code = get_net_connections(&net_conns, allocator, &ifconfig))) {
                AWS_LOGF_ERROR(AWS_LS_IOTDEVICE_DEFENDER_TASK,
                    "id=%p: Failed to get network connection data: %s", (void *)defender_task, aws_error_name(return_code));
                    return;
            }

            if (defender_task->has_previous_net_xfer) {
                struct aws_iotdevice_metric_network_transfer delta_xfer;
                delta_xfer.bytes_in = 0;
                delta_xfer.bytes_out = 0;
                delta_xfer.packets_in = 0;
                delta_xfer.packets_out = 0;

                get_network_total_delta(&delta_xfer, &defender_task->previous_net_xfer, &totals);
                s_get_metric_report_json(&json_report, &delta_xfer, &net_conns);
            } else {
                defender_task->has_previous_net_xfer = true;
                s_get_metric_report_json(&json_report, NULL, &net_conns);
            }
            defender_task->previous_net_xfer.bytes_in = totals.bytes_in;
            defender_task->previous_net_xfer.bytes_out = totals.bytes_out;
            defender_task->previous_net_xfer.packets_in = totals.packets_in;
            defender_task->previous_net_xfer.packets_out = totals.packets_out;

            uint64_t now;
            aws_event_loop_current_clock_time(defender_task->config.event_loop, &now);
            aws_event_loop_schedule_task_future(
                defender_task->config.event_loop, task, now + defender_task->config.task_period_ns);
        }

    } else if (status == AWS_TASK_STATUS_CANCELED) {
        printf("Task was cancelled!\n");
    } else {
        // do cleanup for the task here
    }

    aws_byte_buf_clean_up(&json_report);
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
