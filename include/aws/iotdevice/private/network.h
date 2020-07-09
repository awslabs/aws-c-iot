/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#ifndef _AWS_IOTDEVICE_NETWORK_H_
#define _AWS_IOTDEVICE_NETWORK_H_

#include <aws/common/hash_table.h>

#include <stdbool.h>
#include <stdint.h>

/* externally defined types */
struct aws_allocator;
struct aws_array_list;
struct aws_byte_buf;
struct aws_byte_cursor;
struct aws_hash_element;
struct aws_string;


enum aws_iotdevice_network_protocol { AWS_IDNP_UKNOWN, AWS_IDNP_TCP, AWS_IDNP_UDP };

enum aws_iotdevice_network_connection_state { AWS_IDNCS_UNKNOWN = 0, AWS_IDNCS_ESTABLISHED = 1, AWS_IDNCS_LISTEN = 10 };

struct aws_iotdevice_metric_network_transfer {
    uint64_t bytes_in;
    uint64_t bytes_out;
    uint64_t packets_in;
    uint64_t packets_out;
};

struct aws_iotdevice_metric_net_connection {
    struct aws_string *remote_address;
    uint16_t remote_port;
    struct aws_string *local_interface;
    uint16_t local_port;
    uint16_t state;
    uint16_t protocol;
};

struct aws_iotdevice_network_iface;

struct aws_iotdevice_network_ifconfig {
    /* cstr:IPV4 address -> aws_iotdevice_network_iface:instance */
    struct aws_hash_table iface_name_to_info;
};

/* internal candidate */
struct aws_iotdevice_defender_task_ctx;

/* library internal */
int sum_iface_transfer_metrics(void *context, struct aws_hash_element *p_element);

void get_system_network_total(
    struct aws_iotdevice_metric_network_transfer *total,
    struct aws_iotdevice_network_ifconfig *ifconfig);

int get_network_config_and_transfer(struct aws_iotdevice_network_ifconfig *ifconfig, struct aws_allocator *allocator);

int get_net_connections(
    struct aws_array_list *net_conns,
    struct aws_allocator *allocator,
    const struct aws_iotdevice_network_ifconfig *ifconfig);

void get_network_total_delta(
    struct aws_iotdevice_metric_network_transfer *delta,
    struct aws_iotdevice_metric_network_transfer *prev_total,
    struct aws_iotdevice_metric_network_transfer *curr_total);

#endif
