/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#include <aws/common/error.h>

#include <aws/iotdevice/private/network.h>

struct aws_iotdevice_network_iface {};

void get_system_network_total(
    struct aws_iotdevice_metric_network_transfer *total,
    struct aws_iotdevice_network_ifconfig *ifconfig) {}

int get_network_config_and_transfer(struct aws_iotdevice_network_ifconfig *ifconfig, struct aws_allocator *allocator) {
    return AWS_ERROR_UNIMPLEMENTED;
}

int get_net_connections(
    struct aws_array_list *net_conns,
    struct aws_allocator *allocator,
    const struct aws_iotdevice_network_ifconfig *ifconfig) {
    return AWS_ERROR_UNIMPLEMENTED;
}

void get_network_total_delta(
    struct aws_iotdevice_metric_network_transfer *delta,
    struct aws_iotdevice_metric_network_transfer *prev_total,
    struct aws_iotdevice_metric_network_transfer *curr_total) {
    return AWS_ERROR_UNIMPLEMENTED;
}
