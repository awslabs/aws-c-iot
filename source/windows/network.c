/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#include <aws/common/error.h>

/* library internal */
int sum_iface_transfer_metrics(void *context, struct aws_hash_element *p_element) {
    return AWS_ERROR_UNIMPLEMENTED;
}

void get_system_network_total(
    struct aws_iotdevice_metric_network_transfer *total,
    struct aws_iotdevice_network_ifconfig *ifconfig) {}

int get_network_config_and_transfer(struct aws_iotdevice_network_ifconfig *ifconfig, struct aws_allocator *allocator) {
    return AWS_ERROR_UNIMPLEMENTED;
}

int read_proc_net_from_file(
    struct aws_byte_buf *out_buf,
    struct aws_allocator *allocator,
    size_t size_hint,
    const char *filename) {
    return AWS_ERROR_UNIMPLEMENTED;
}

int get_net_connections(
    struct aws_array_list *net_conns,
    struct aws_allocator *allocator,
    const struct aws_iotdevice_network_ifconfig *ifconfig,
    const struct aws_byte_cursor *proc_net_data,
    bool is_udp) {
    return AWS_ERROR_UNIMPLEMENTED;
}

void get_network_total_delta(
    struct aws_iotdevice_metric_network_transfer *delta,
    struct aws_iotdevice_metric_network_transfer *prev_total,
    struct aws_iotdevice_metric_network_transfer *curr_total) {}
