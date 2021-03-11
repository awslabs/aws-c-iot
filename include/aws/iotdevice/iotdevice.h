/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#ifndef AWS_IOTDEVICE_H
#define AWS_IOTDEVICE_H

#include <aws/common/error.h>
#include <aws/common/logging.h>
#include <aws/iotdevice/exports.h>

#define AWS_C_IOTDEVICE_PACKAGE_ID 13

enum aws_iotdevice_error {
    AWS_ERROR_IOTDEVICE_INVALID_RESERVED_BITS = AWS_ERROR_ENUM_BEGIN_RANGE(AWS_C_IOTDEVICE_PACKAGE_ID),
    AWS_ERROR_IOTDEVICE_DEFENDER_INVALID_REPORT_INTERVAL,
    AWS_ERROR_IOTDEVICE_DEFENDER_UNSUPPORTED_REPORT_FORMAT,
    AWS_ERROR_IOTDEVICE_DEFENDER_REPORT_SERIALIZATION_FAILURE,
    AWS_ERROR_IOTDEVICE_DEFENDER_UNKNOWN_CUSTOM_METRIC_TYPE,
    AWS_ERROR_IOTDEVICE_DEFENDER_INVALID_TASK_CONFIG,
    AWS_ERROR_IOTDEVICE_DEFENDER_PUBLISH_FAILURE,

    AWS_ERROR_IOTDEVICE_SECUTRE_TUNNELING_INVALID_STREAM,
    AWS_ERROR_IOTDEVICE_SECUTRE_TUNNELING_INCORRECT_MODE,

    AWS_ERROR_END_IOTDEVICE_RANGE = AWS_ERROR_ENUM_END_RANGE(AWS_C_IOTDEVICE_PACKAGE_ID),
};

enum aws_iotdevice_log_subject {
    AWS_LS_IOTDEVICE_DEFENDER_TASK = AWS_LOG_SUBJECT_BEGIN_RANGE(AWS_C_IOTDEVICE_PACKAGE_ID),
    AWS_LS_IOTDEVICE_DEFENDER_TASK_CONFIG,
    AWS_LS_IOTDEVICE_NETWORK_CONFIG,
    AWS_LS_IOTDEVICE_SECURE_TUNNELING,
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

AWS_EXTERN_C_END

#endif
