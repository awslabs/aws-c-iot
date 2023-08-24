/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#include <aws/iotdevice/iotdevice.h>

#include <aws/common/json.h>
#include <aws/common/thread.h>

/*******************************************************************************
 * Library Init
 ******************************************************************************/

#define AWS_DEFINE_ERROR_INFO_IOTDEVICE(C, ES) AWS_DEFINE_ERROR_INFO(C, ES, "libaws-c-iotdevice")
/* clang-format off */
static struct aws_error_info s_errors[] = {
    AWS_DEFINE_ERROR_INFO_IOTDEVICE(
        AWS_ERROR_IOTDEVICE_INVALID_RESERVED_BITS,
        "Bits marked as reserved were incorrectly set"),
    AWS_DEFINE_ERROR_INFO_IOTDEVICE(
        AWS_ERROR_IOTDEVICE_DEFENDER_INVALID_REPORT_INTERVAL,
        "Invalid defender task reporting interval. Must be greater than 5 minutes."),
    AWS_DEFINE_ERROR_INFO_IOTDEVICE(
        AWS_ERROR_IOTDEVICE_DEFENDER_UNSUPPORTED_REPORT_FORMAT,
        "Unknown format value selected for defender reporting task."),
    AWS_DEFINE_ERROR_INFO_IOTDEVICE(
        AWS_ERROR_IOTDEVICE_DEFENDER_REPORT_SERIALIZATION_FAILURE,
        "Error serializing report for publishing."),
    AWS_DEFINE_ERROR_INFO_IOTDEVICE(
        AWS_ERROR_IOTDEVICE_DEFENDER_UNKNOWN_CUSTOM_METRIC_TYPE,
        "Unknown custom metric type found in reporting task."),
    AWS_DEFINE_ERROR_INFO_IOTDEVICE(
        AWS_ERROR_IOTDEVICE_DEFENDER_INVALID_TASK_CONFIG,
        "Invalid configuration detected in defender reporting task config. Check prior errors."),
    AWS_DEFINE_ERROR_INFO_IOTDEVICE(
        AWS_ERROR_IOTDEVICE_DEFENDER_PUBLISH_FAILURE,
        "Mqtt client error while attempting to publish defender report."),
    AWS_DEFINE_ERROR_INFO_IOTDEVICE(
         AWS_ERROR_IOTDEVICE_DEFENDER_UNKNOWN_TASK_STATUS,
        "Device defender task was invoked with an unknown task status."),

    AWS_DEFINE_ERROR_INFO_IOTDEVICE(
        AWS_ERROR_IOTDEVICE_SECURE_TUNNELING_INVALID_STREAM_ID,
        "Secure Tunnel invalid stream id."),
    AWS_DEFINE_ERROR_INFO_IOTDEVICE(
        AWS_ERROR_IOTDEVICE_SECURE_TUNNELING_INVALID_CONNECTION_ID,
        "Secure Tunnel invalid connection id."),
    AWS_DEFINE_ERROR_INFO_IOTDEVICE(
        AWS_ERROR_IOTDEVICE_SECURE_TUNNELING_INVALID_SERVICE_ID,
        "Secure Tunnel invalid service id."),
    AWS_DEFINE_ERROR_INFO_IOTDEVICE(
        AWS_ERROR_IOTDEVICE_SECURE_TUNNELING_INCORRECT_MODE,
        "Secure Tunnel stream cannot be started while in Destination Mode."),
    AWS_DEFINE_ERROR_INFO_IOTDEVICE(
        AWS_ERROR_IOTDEVICE_SECURE_TUNNELING_BAD_SERVICE_ID,
        "Secure Tunnel stream start request with bad service id."),
    AWS_DEFINE_ERROR_INFO_IOTDEVICE(
        AWS_ERROR_IOTDEVICE_SECURE_TUNNELING_DATA_OPTIONS_VALIDATION,
        "Invalid Secure Tunnel data message options value."),
    AWS_DEFINE_ERROR_INFO_IOTDEVICE(
        AWS_ERROR_IOTDEVICE_SECURE_TUNNELING_STREAM_OPTIONS_VALIDATION,
        "Invalid Secure Tunnel stream options value."),
    AWS_DEFINE_ERROR_INFO_IOTDEVICE(
        AWS_ERROR_IOTDEVICE_SECURE_TUNNELING_SECURE_TUNNEL_TERMINATED,
        "Secure Tunnel terminated by user request."),
    AWS_DEFINE_ERROR_INFO_IOTDEVICE(
        AWS_ERROR_IOTDEVICE_SECURE_TUNNELING_WEBSOCKET_TIMEOUT,
        "Remote endpoint did not respond to connect request before timeout exceeded."),
    AWS_DEFINE_ERROR_INFO_IOTDEVICE(
        AWS_ERROR_IOTDEVICE_SECURE_TUNNELING_PING_RESPONSE_TIMEOUT,
        "Remote endpoint did not respond to a PINGREQ before timeout exceeded."),
    AWS_DEFINE_ERROR_INFO_IOTDEVICE(
        AWS_ERROR_IOTDEVICE_SECURE_TUNNELING_OPERATION_FAILED_DUE_TO_DISCONNECTION,
        "Secure Tunnel operation failed due to disconnected state."),
    AWS_DEFINE_ERROR_INFO_IOTDEVICE(
        AWS_ERROR_IOTDEVICE_SECURE_TUNNELING_OPERATION_PROCESSING_FAILURE,
        "Error while processing secure tunnel operational state."),
    AWS_DEFINE_ERROR_INFO_IOTDEVICE(
        AWS_ERROR_IOTDEVICE_SECURE_TUNNELING_OPERATION_FAILED_DUE_TO_OFFLINE_QUEUE_POLICY,
        "Secure Tunnel operation failed due to offline queue policy."),
    AWS_DEFINE_ERROR_INFO_IOTDEVICE(
        AWS_ERROR_IOTDEVICE_SECURE_TUNNELING_UNEXPECTED_HANGUP,
        "The connection was closed unexpectedly."),
    AWS_DEFINE_ERROR_INFO_IOTDEVICE(
        AWS_ERROR_IOTDEVICE_SECURE_TUNNELING_USER_REQUESTED_STOP,
        "Secure Tunnel connection interrupted by user request."),
    AWS_DEFINE_ERROR_INFO_IOTDEVICE(
        AWS_ERROR_IOTDEVICE_SECURE_TUNNELING_PROTOCOL_VERSION_MISMATCH,
        "Secure Tunnel connection interrupted due to a protocol version mismatch."),
    AWS_DEFINE_ERROR_INFO_IOTDEVICE(
        AWS_ERROR_IOTDEVICE_SECURE_TUNNELING_TERMINATED,
        "Secure Tunnel terminated by user request."),
    AWS_DEFINE_ERROR_INFO_IOTDEVICE(
        AWS_ERROR_IOTDEVICE_SECURE_TUNNELING_DECODE_FAILURE,
        "Error occured while decoding an incoming message." ),
    AWS_DEFINE_ERROR_INFO_IOTDEVICE(
        AWS_ERROR_IOTDEVICE_SECURE_TUNNELING_DATA_NO_ACTIVE_CONNECTION,
        "DATA message processing failed due to no active connection found." ),
    AWS_DEFINE_ERROR_INFO_IOTDEVICE(
        AWS_ERROR_IOTDEVICE_SECURE_TUNNELING_DATA_PROTOCOL_VERSION_MISMATCH,
        "DATA message processing failed due to a protocol version mismatch." ),
    AWS_DEFINE_ERROR_INFO_IOTDEVICE(
        AWS_ERROR_IOTDEVICE_SECURE_TUNNELING_INACTIVE_SERVICE_ID,
        "Secure Tunnel operation failed due to using inactive service id." ),
};
/* clang-format on */
#undef AWS_DEFINE_ERROR_INFO_IOTDEVICE

static struct aws_error_info_list s_error_list = {
    .error_list = s_errors,
    .count = AWS_ARRAY_SIZE(s_errors),
};

/* clang-format off */
        static struct aws_log_subject_info s_logging_subjects[] = {
            DEFINE_LOG_SUBJECT_INFO(AWS_LS_IOTDEVICE_DEFENDER_TASK, "iotdevice-defender", "IoT DeviceDefender"),
            DEFINE_LOG_SUBJECT_INFO(AWS_LS_IOTDEVICE_DEFENDER_TASK_CONFIG, "iotdevice-defender-config", "IoT DeviceDefender Task Config"),
            DEFINE_LOG_SUBJECT_INFO(AWS_LS_IOTDEVICE_NETWORK_CONFIG, "iotdevice-network", "IoT Device Network"),
            DEFINE_LOG_SUBJECT_INFO(AWS_LS_IOTDEVICE_SECURE_TUNNELING, "iotdevice-st", "IoT Secure Tunneling"),
        };
/* clang-format on */

static struct aws_log_subject_info_list s_logging_subjects_list = {
    .subject_list = s_logging_subjects,
    .count = AWS_ARRAY_SIZE(s_logging_subjects),
};

static bool s_iotdevice_library_initialized = false;

void aws_iotdevice_library_init(struct aws_allocator *allocator) {
    AWS_PRECONDITION(aws_allocator_is_valid(allocator));

    if (!s_iotdevice_library_initialized) {
        s_iotdevice_library_initialized = true;

        aws_mqtt_library_init(allocator);
        aws_register_error_info(&s_error_list);
        aws_register_log_subject_info_list(&s_logging_subjects_list);
    }
}

void aws_iotdevice_library_clean_up(void) {
    if (s_iotdevice_library_initialized) {
        s_iotdevice_library_initialized = false;

        aws_thread_join_all_managed();

        aws_unregister_error_info(&s_error_list);
        aws_unregister_log_subject_info_list(&s_logging_subjects_list);

        aws_mqtt_library_clean_up();
    }
}
