/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#ifndef AWS_IOTDEVICE_NETWORK_H
#define AWS_IOTDEVICE_NETWORK_H

#include <aws/iotdevice/iotdevice.h>

#include <aws/common/hash_table.h>

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
    struct aws_hash_table iface_name_to_info;
};

AWS_EXTERN_C_BEGIN

AWS_IOTDEVICE_API
void get_system_network_total(
    struct aws_iotdevice_metric_network_transfer *total,
    struct aws_iotdevice_network_ifconfig *ifconfig);

AWS_IOTDEVICE_API
int get_network_config_and_transfer(struct aws_iotdevice_network_ifconfig *ifconfig, struct aws_allocator *allocator);

AWS_IOTDEVICE_API
int get_network_connections(
    struct aws_array_list *net_conns,
    struct aws_iotdevice_network_ifconfig *ifconfig,
    struct aws_allocator *allocator);

AWS_IOTDEVICE_API
void get_network_total_delta(
    struct aws_iotdevice_metric_network_transfer *delta,
    struct aws_iotdevice_metric_network_transfer *prev_total,
    struct aws_iotdevice_metric_network_transfer *curr_total);

AWS_EXTERN_C_END

#endif
