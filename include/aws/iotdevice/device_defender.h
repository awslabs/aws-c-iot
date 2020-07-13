/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#ifndef _AWS_IOTDEVICE_DEFENDER_H_
#define _AWS_IOTDEVICE_DEFENDER_H_

#include <aws/common/logging.h>
#include <aws/iotdevice/iotdevice.h>

struct aws_array_list;
struct aws_hash_table;
struct aws_logger;
struct aws_string;
struct aws_task;
struct aws_event_loop;
struct aws_mqtt_client_connection;

/**
 * Called when a connection is closed, right before any resources are deleted
 **/
typedef void(aws_iotdevice_defender_v1_task_canceled_fn)(void *userdata);

enum aws_iotdevice_defender_report_format { AWS_IDDRF_JSON, AWS_IDDRF_SHORT_JSON, AWS_IDDRF_CBOR };

struct aws_iotdevice_defender_v1_task;

struct aws_iotdevice_defender_report_task_config {
    struct aws_mqtt_client_connection *connection;           /* mqtt connection to use to send report messages */
    struct aws_event_loop *event_loop;                       /* event loop to schedule task on continuously */
    enum aws_iotdevice_defender_report_format report_format; /* only JSON supported for now */
    uint64_t task_period_ns;           /* how frequently do we send out a report. Service limit is once every 5m */
    uint64_t netconn_sample_period_ns; /* how frequently we sample for established connections and listening ports */
    aws_iotdevice_defender_v1_task_canceled_fn *task_canceled_fn;
    void *cancelation_userdata;
};

AWS_EXTERN_C_BEGIN

/**
 * Creates a new reporting task for Device Defender metrics
 */
AWS_IOTDEVICE_API
struct aws_iotdevice_defender_v1_task *aws_iotdevice_defender_run_v1_task(
    struct aws_allocator *allocator,
    const struct aws_iotdevice_defender_report_task_config *config);

/**
 * Cancels the running task reporting Device Defender metrics
 */
AWS_IOTDEVICE_API
void aws_iotdevice_stop_defender_v1_task(struct aws_iotdevice_defender_v1_task *defender_task);

AWS_EXTERN_C_END

#endif
