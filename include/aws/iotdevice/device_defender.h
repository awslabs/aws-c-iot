/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#ifndef AWS_IOTDEVICE_DEFENDER_H
#define AWS_IOTDEVICE_DEFENDER_H

#include <aws/common/byte_buf.h>
#include <aws/iotdevice/iotdevice.h>

struct aws_array_list;
struct aws_hash_table;
struct aws_logger;
struct aws_string;
struct aws_task;
struct aws_event_loop;
struct aws_mqtt_client_connection;

typedef void(aws_iotdevice_defender_v1_task_cancelled_fn)(void *userdata);

enum aws_iotdevice_defender_report_format { AWS_IDDRF_JSON, AWS_IDDRF_SHORT_JSON, AWS_IDDRF_CBOR };

struct aws_iotdevice_defender_v1_task;

struct aws_iotdevice_defender_report_task_config {
    struct aws_mqtt_client_connection *connection;
    struct aws_byte_cursor thing_name;
    struct aws_event_loop *event_loop;
    enum aws_iotdevice_defender_report_format report_format;
    uint64_t task_period_ns;
    uint64_t netconn_sample_period_ns;
    aws_iotdevice_defender_v1_task_cancelled_fn *task_cancelled_fn;
    void *cancellation_userdata;
};

AWS_EXTERN_C_BEGIN

/**
 * Creates a new reporting task for Device Defender metrics
 */
AWS_IOTDEVICE_API
struct aws_iotdevice_defender_v1_task *aws_iotdevice_defender_v1_report_task(
    struct aws_allocator *allocator,
    const struct aws_iotdevice_defender_report_task_config *config);

/**
 * Cancels the running task reporting Device Defender metrics
 */
AWS_IOTDEVICE_API
void aws_iotdevice_defender_v1_stop_task(struct aws_iotdevice_defender_v1_task *defender_task);

AWS_EXTERN_C_END

#endif
