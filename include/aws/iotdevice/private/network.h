/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#pragma once

#include <aws/common/hash_table.h>
#include <aws/common/byte_buf.h>

#include <net/if.h>

struct aws_iotdevice_metric_network_transfer {
    uint64_t bytes_in;
    uint64_t bytes_out;
    uint64_t packets_in;
    uint64_t packets_out;
};

struct aws_iotdevice_metric_net_connection {
    struct aws_string *remote_address;
    uint16_t remote_port;
    const char *local_interface;
    uint16_t local_port;
    uint16_t state;
};

enum aws_iotdevice_network_connection_state {
    ESTABLISHED = 1, LISTEN = 10
};

struct aws_iotdevice_network_iface {
    char    iface_name[IFNAMSIZ];
    char    ipv4_addr_str[16];
    struct aws_iotdevice_metric_network_transfer metrics;
};

struct aws_iotdevice_network_ifconfig {
    /* cstr:IPV4 address -> aws_iotdevice_network_iface:instance */
    struct aws_hash_table iface_name_to_info;
};

/* internal candidate */
struct aws_iotdevice_defender_task_ctx {
    struct aws_allocator *allocator;
    struct aws_iotdevice_metric_network_transfer previous_xfer_totals;
    bool has_previous_xfer;
    uint64_t reschedule_period;
    uint64_t report_id;
};

/* library internal */
int sum_iface_transfer_metrics(void *context, struct aws_hash_element *p_element);

void get_system_network_total(
        struct aws_iotdevice_metric_network_transfer *total,
        struct aws_iotdevice_network_ifconfig *ifconfig);
int get_network_config_and_transfer(
    struct aws_iotdevice_network_ifconfig *ifconfig,
    struct aws_allocator *allocator);
int read_proc_net_from_file(struct aws_byte_buf *out_buf, struct aws_allocator *allocator, size_t size_hint, const char *filename);
int get_net_connections(
        struct aws_array_list *net_conns, struct aws_allocator *allocator,
        const struct aws_iotdevice_network_ifconfig *ifconfig,
        const struct aws_byte_cursor *proc_net_data, bool is_udp);
void get_network_total_delta(
        struct aws_iotdevice_metric_network_transfer *delta,
        struct aws_iotdevice_metric_network_transfer *prev_total,
        struct aws_iotdevice_metric_network_transfer *curr_total);

