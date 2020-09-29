/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#include <aws/iotdevice/external/cJSON.h>
#include <aws/iotdevice/iotdevice.h>

#include <aws/common/allocator.h>
#include <aws/common/logging.h>

static struct aws_allocator *s_library_allocator = NULL;

static void *s_cJSONAlloc(size_t sz) {
    return aws_mem_acquire(s_library_allocator, sz);
}

static void s_cJSONFree(void *ptr) {
    aws_mem_release(s_library_allocator, ptr);
}

/*******************************************************************************
 * Library Init
 ******************************************************************************/

/* Incomplete: error code definitions aren't exhaustive by any means and are not used well in the code */
#define AWS_DEFINE_ERROR_INFO_IOTDEVICE(C, ES) AWS_DEFINE_ERROR_INFO(C, ES, "libaws-c-iotdevice")
/* clang-format off */
static struct aws_error_info s_errors[] = {
    AWS_DEFINE_ERROR_INFO_IOTDEVICE(
        AWS_ERROR_IOTDEVICE_DEFENDER_INVALID_REPORT_INTERVAL,
        "Invalid defender task reporting interval. Must be greater than 5 minutes"),
    AWS_DEFINE_ERROR_INFO_IOTDEVICE(
        AWS_ERROR_IOTDEVICE_DEFENDER_UNSUPPORTED_REPORT_FORMAT,
        "Unknown format value selected for defender reporting task"),
    AWS_DEFINE_ERROR_INFO_IOTDEVICE(
        AWS_ERROR_IOTDEVICE_DEFENDER_REPORT_SERIALIZATION_FAILURE,
        "Error serializing report for publishing"),
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
            DEFINE_LOG_SUBJECT_INFO(AWS_LS_IOTDEVICE_NETWORK_CONFIG, "iotdevice-network", "IoT Device Network")
        };
/* clang-format on */

static struct aws_log_subject_info_list s_logging_subjects_list = {
    .subject_list = s_logging_subjects,
    .count = AWS_ARRAY_SIZE(s_logging_subjects),
};

static bool s_iotdevice_library_initialized = false;

/**
 * Initializes internal datastructures used by aws-c-iot.
 * Must be called before using any functionality in aws-c-iot.
 */
void aws_iotdevice_library_init(struct aws_allocator *allocator) {
    AWS_PRECONDITION(aws_allocator_is_valid(allocator));

    if (!s_iotdevice_library_initialized) {
        s_library_allocator = allocator;

        aws_register_error_info(&s_error_list);
        aws_register_log_subject_info_list(&s_logging_subjects_list);

        struct cJSON_Hooks allocation_hooks = {.malloc_fn = s_cJSONAlloc, .free_fn = s_cJSONFree};
        cJSON_InitHooks(&allocation_hooks);

        s_iotdevice_library_initialized = true;
    }
}

/**
 * Shuts down the internal data structures used by aws-c-iot
 */
void aws_iotdevice_library_clean_up(void) {
    if (s_iotdevice_library_initialized) {
        s_library_allocator = NULL;

        aws_unregister_error_info(&s_error_list);
        aws_unregister_log_subject_info_list(&s_logging_subjects_list);

        s_iotdevice_library_initialized = false;
    }
}
