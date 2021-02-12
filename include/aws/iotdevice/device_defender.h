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

/**
 * User callback type invoked when DeviceDefender task has completed cancellation. After a request
 * to stop the task, this signals the completion of the cancellation and no further user callbacks will
 * be invoked.
 */
typedef void(aws_iotdevice_defender_v1_task_cancelled_fn)(void *userdata);

/**
 * User callback type invoked when a report fails to submit.
 *
 * There are two possibilities for failed submission:
 *  1. The MQTT client fails to publish the message and returns an error code. In this
 *     scenario, the client_error_code will be a value other than  AWS_OP_SUCCESS. The
 *     rejected_message_payload parameter will be NULL.
 *  2. After a successful publish, a reply is recieved on the respective MQTT rejected
 *     topic with a message. In this scenario, the client_error_code will be
 *     AWS_OP_SUCCESS, and rejected_message_payload will contain the payload of the
 *     rejected message recieved.
 */
typedef void(aws_iotdevice_defender_report_rejected_fn)(int client_error_code,
                                                        struct aws_byte_cursor *rejected_message_payload,
                                                        void *userdata);

/**
 * User callback type invoked to retrieve a number type custom metric
 */
typedef int(aws_iotdevice_defender_get_number_fn)(int64_t *const value, void *userdata);

/**
 * User callback type invoked to retrieve a number list custom metric
 */
typedef int(aws_iotdevice_defender_get_number_list_fn)(struct aws_array_list *const number_list, void *userdata);

/**
 * User callback type invoked to retrieve a string list custom metric
 */
typedef int(aws_iotdevice_defender_get_string_list_fn)(struct aws_array_list *const string_list, void *userdata);

/**
 * User callback type invoked to retrieve a ip list custom metric
 */
typedef int(aws_iotdevice_defender_get_ip_list_fn)(struct aws_array_list *const ip_list, void *userdata);

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
    aws_iotdevice_defender_report_rejected_fn *rejected_report_fn;
    void *userdata;
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

/**
 * Registers a number custom metric to the Device Defender task.
 *
 * Undefined behavior if a custom metric is added while the defender task is running
 */
AWS_IOTDEVICE_API
int aws_iotdevice_defender_register_number_metric(struct aws_iotdevice_defender_v1_task *defender_task,
												   const char *metric_name,
		     				                       aws_iotdevice_defender_get_number_fn *supplier,
												   void *userdata);

/**
 * Registers a number list custom metric to the Device Defender task.
 *
 * Undefined behavior if a custom metric is added while the defender task is running
 */
AWS_IOTDEVICE_API
int aws_iotdevice_defender_register_number_list_metric(struct aws_iotdevice_defender_v1_task *defender_task,
												   const char *metric_name,
		     				                       aws_iotdevice_defender_get_number_list_fn *supplier,
												   void *userdata);

/**
 * Registers a string list custom metric to the Device Defender task.
 *
 * Undefined behavior if a custom metric is added while the defender task is running
 */
AWS_IOTDEVICE_API
int aws_iotdevice_defender_register_string_list_metric(struct aws_iotdevice_defender_v1_task *defender_task,
												   const char *metric_name,
												   aws_iotdevice_defender_get_string_list_fn *supplier,
												   void *userdata);

/**
 * Registers an IP list custom metric to the Device Defender task.
 *
 * Undefined behavior if a custom metric is added while the defender task is running
 */
AWS_IOTDEVICE_API
int aws_iotdevice_defender_register_ip_list_metric(struct aws_iotdevice_defender_v1_task *defender_task,
												   const char *metric_name,
		     				                       aws_iotdevice_defender_get_ip_list_fn *supplier,
												   void *userdata);

AWS_EXTERN_C_END

#endif
