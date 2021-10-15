/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/iotdevice/private/network.h>

struct aws_iotdevice_network_iface {
    int __dummy;
};

void get_system_network_total(
    struct aws_iotdevice_metric_network_transfer *total,
    struct aws_iotdevice_network_ifconfig *ifconfig) {
    (void)total;
    (void)ifconfig;
}

int get_network_config_and_transfer(struct aws_iotdevice_network_ifconfig *ifconfig, struct aws_allocator *allocator) {
    (void)ifconfig;
    (void)allocator;
    return aws_raise_error(AWS_ERROR_UNIMPLEMENTED);
}

int get_network_connections(
    struct aws_array_list *net_conns,
    struct aws_iotdevice_network_ifconfig *ifconfig,
    struct aws_allocator *allocator) {
    (void)net_conns;
    (void)ifconfig;
    (void)allocator;
    return aws_raise_error(AWS_ERROR_UNIMPLEMENTED);
}

void get_network_total_delta(
    struct aws_iotdevice_metric_network_transfer *delta,
    struct aws_iotdevice_metric_network_transfer *prev_total,
    struct aws_iotdevice_metric_network_transfer *curr_total) {
    (void)delta;
    (void)prev_total;
    (void)curr_total;
}
