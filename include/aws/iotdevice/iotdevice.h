/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#ifndef AWS_IOTDEVICE_H
#define AWS_IOTDEVICE_H

#include <aws/iotdevice/exports.h>

#include <aws/mqtt/mqtt.h>

AWS_PUSH_SANE_WARNING_LEVEL

#define AWS_C_IOTDEVICE_PACKAGE_ID 13

enum aws_iotdevice_error {
    AWS_ERROR_IOTDEVICE_INVALID_RESERVED_BITS = AWS_ERROR_ENUM_BEGIN_RANGE(AWS_C_IOTDEVICE_PACKAGE_ID),
    AWS_ERROR_IOTDEVICE_DEFENDER_INVALID_REPORT_INTERVAL,
    AWS_ERROR_IOTDEVICE_DEFENDER_UNSUPPORTED_REPORT_FORMAT,
    AWS_ERROR_IOTDEVICE_DEFENDER_REPORT_SERIALIZATION_FAILURE,
    AWS_ERROR_IOTDEVICE_DEFENDER_UNKNOWN_CUSTOM_METRIC_TYPE,
    AWS_ERROR_IOTDEVICE_DEFENDER_INVALID_TASK_CONFIG,
    AWS_ERROR_IOTDEVICE_DEFENDER_PUBLISH_FAILURE,
    AWS_ERROR_IOTDEVICE_DEFENDER_UNKNOWN_TASK_STATUS,

    AWS_ERROR_IOTDEVICE_SECURE_TUNNELING_INVALID_STREAM_ID,
    AWS_ERROR_IOTDEVICE_SECURE_TUNNELING_INVALID_CONNECTION_ID,
    AWS_ERROR_IOTDEVICE_SECURE_TUNNELING_INVALID_SERVICE_ID,
    AWS_ERROR_IOTDEVICE_SECURE_TUNNELING_INCORRECT_MODE,
    AWS_ERROR_IOTDEVICE_SECURE_TUNNELING_BAD_SERVICE_ID,
    AWS_ERROR_IOTDEVICE_SECURE_TUNNELING_DATA_OPTIONS_VALIDATION,
    AWS_ERROR_IOTDEVICE_SECURE_TUNNELING_STREAM_OPTIONS_VALIDATION,
    AWS_ERROR_IOTDEVICE_SECURE_TUNNELING_SECURE_TUNNEL_TERMINATED,
    AWS_ERROR_IOTDEVICE_SECURE_TUNNELING_WEBSOCKET_TIMEOUT,
    AWS_ERROR_IOTDEVICE_SECURE_TUNNELING_PING_RESPONSE_TIMEOUT,
    AWS_ERROR_IOTDEVICE_SECURE_TUNNELING_OPERATION_FAILED_DUE_TO_DISCONNECTION,
    AWS_ERROR_IOTDEVICE_SECURE_TUNNELING_OPERATION_PROCESSING_FAILURE,
    AWS_ERROR_IOTDEVICE_SECURE_TUNNELING_OPERATION_FAILED_DUE_TO_OFFLINE_QUEUE_POLICY,
    AWS_ERROR_IOTDEVICE_SECURE_TUNNELING_UNEXPECTED_HANGUP,
    AWS_ERROR_IOTDEVICE_SECURE_TUNNELING_USER_REQUESTED_STOP,
    /* NOTE Leave the old name for compatibility. */
    AWS_ERROR_IOTDEVICE_SECURE_TUNNELING_PROTOCOL_VERSION_MISSMATCH,
    AWS_ERROR_IOTDEVICE_SECURE_TUNNELING_PROTOCOL_VERSION_MISMATCH =
        AWS_ERROR_IOTDEVICE_SECURE_TUNNELING_PROTOCOL_VERSION_MISSMATCH,
    AWS_ERROR_IOTDEVICE_SECURE_TUNNELING_TERMINATED,
    AWS_ERROR_IOTDEVICE_SECURE_TUNNELING_DECODE_FAILURE,
    AWS_ERROR_IOTDEVICE_SECURE_TUNNELING_DATA_NO_ACTIVE_CONNECTION,
    AWS_ERROR_IOTDEVICE_SECURE_TUNNELING_DATA_PROTOCOL_VERSION_MISMATCH,
    AWS_ERROR_IOTDEVICE_SECURE_TUNNELING_INACTIVE_SERVICE_ID,
    AWS_ERROR_IOTDEVICE_SECURE_TUNNELING_ENCODE_FAILURE,

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
AWS_POP_SANE_WARNING_LEVEL

#endif
