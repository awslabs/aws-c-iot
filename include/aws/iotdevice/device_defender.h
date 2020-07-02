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

enum aws_iotdevice_defender_report_format { AWS_IDDRF_JSON, AWS_IDDRF_SHORT_JSON, AWS_IDDRF_CBOR };

struct aws_iotdevice_defender_v1_task;
struct aws_iotdevice_defender_report_task_config;

AWS_EXTERN_C_BEGIN

/**
 * Initializes internal datastructures used by aws-c-iot.
 * Must be called before using any functionality in aws-c-iot.
 */
AWS_IOTDEVICE_API
void aws_iotdevice_library_init(struct aws_allocator *allocator);

/**
 * Shuts down the internal datastructures used by aws-c-iot
 */
AWS_IOTDEVICE_API
void aws_iotdevice_library_clean_up(void);

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
