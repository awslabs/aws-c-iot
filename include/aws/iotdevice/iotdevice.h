/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#ifndef _AWS_IOTDEVICE__H_
#define _AWS_IOTDEVICE__H_

#include <aws/common/error.h>
#include <aws/common/logging.h>
#include <aws/iotdevice/exports.h>

#define AWS_C_IOTDEVICE_PACKAGE_ID 11

enum aws_iotdevice_error {
    AWS_ERROR_IOTDEVICE_INVALID_RESERVED_BITS = AWS_ERROR_ENUM_BEGIN_RANGE(AWS_C_IOTDEVICE_PACKAGE_ID),
    AWS_ERROR_IOTDEVICE_DEFENDER_INVALID_REPORT_INTERVAL,
    AWS_ERROR_IOTDEVICE_DEFENDER_UNSUPPORTED_REPORT_FORMAT,

    AWS_ERROR_END_IOTDEVICE_RANGE = AWS_ERROR_ENUM_END_RANGE(AWS_C_IOTDEVICE_PACKAGE_ID),
};

enum aws_iotdevice_log_subject {
    AWS_LS_IOTDEVICE_DEFENDER_TASK = AWS_LOG_SUBJECT_BEGIN_RANGE(AWS_C_IOTDEVICE_PACKAGE_ID),
};

#endif
