/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#pragma once

#include <aws/iotdevice/exports.h>
#include <aws/common/array_list.h>
#include <aws/io/event_loop.h>
#include <aws/common/hash_table.h>
#include <aws/common/logging.h>
#include <aws/common/string.h>
#include <aws/common/task_scheduler.h>

#include <net/if.h>

#define AWS_C_IOTDEVICE_PACKAGE_ID 11

enum aws_iotdevice_defender_report_format {
    JSON,
    SHORT_JSON,
    CBOR
};

enum aws_iotdevice_error {
    AWS_ERROR_IOTDEVICE_INVALID_RESERVED_BITS = AWS_ERROR_ENUM_BEGIN_RANGE(AWS_C_IOTDEVICE_PACKAGE_ID),
    AWS_ERROR_IOTDEVICE_DEFENDER_INVALID_REPORT_INTERVAL,
    AWS_ERROR_IOTDEVICE_DEFENDER_UNSUPPORTED_REPORT_FORMAT,

    AWS_ERROR_END_IOTDEVICE_RANGE = AWS_ERROR_ENUM_END_RANGE(AWS_C_IOTDEVICE_PACKAGE_ID),
};

enum aws_iotdevice_log_subject {
    AWS_LS_IOTDEVICE_GENERAL = AWS_LOG_SUBJECT_BEGIN_RANGE(AWS_C_IOTDEVICE_PACKAGE_ID),
    AWS_LS_IOTDEVICE_DEFENDER
};

struct aws_iotdevice_defender_report_task_config {
    struct aws_event_loop *event_loop;  /* event loop to schedule task on continuously */
    unsigned int report_format;         /* only JSON supported for now */
    uint64_t initial_report_id;         /* Initial report_id value for uniqueness, monotonically increasing */
    uint64_t task_period_ns;            /* how frequently do we send out a report. Service limit is once every 5m */
    uint64_t netconn_sample_period_ns;  /* how frequently we sample for established connections and listening ports */
};

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
int aws_iotdevice_start_defender_v1_task(
        struct aws_task *defender_task,
        struct aws_allocator *allocator,
        const struct aws_iotdevice_defender_report_task_config *config);

/**
 * Cancels the running task reporting Device Defender metrics
 */
AWS_IOTDEVICE_API
int aws_iotdevice_stop_defender_v1_task(struct aws_task *defender_task);


AWS_EXTERN_C_END

