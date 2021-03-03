/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#ifndef AWS_IOTDEVICE_DEFENDER_H
#define AWS_IOTDEVICE_DEFENDER_H

#include <aws/iotdevice/iotdevice.h>

struct aws_byte_cursor;
struct aws_array_list;
struct aws_event_loop;
struct aws_mqtt_client_connection;

/**
 * User callback type invoked when DeviceDefender task has completed cancellation. After a request
 * to stop the task, this signals the completion of the cancellation and no further user callbacks will
 * be invoked.
 */
typedef void(aws_iotdevice_defender_task_canceled_fn)(void *userdata);

/**
 * User callback type invoked when a report fails to submit.
 *
 * There are two possibilities for failed submission:
 *  1. The MQTT client fails to publish the message and returns an error code. In this
 *     scenario, the client_error_code will be a value other than  AWS_ERROR_SUCCESS. The
 *     rejected_message_payload parameter will be NULL.
 *  2. After a successful publish, a reply is received on the respective MQTT rejected
 *     topic with a message. In this scenario, the client_error_code will be
 *     AWS_ERROR_SUCCESS, and rejected_message_payload will contain the payload of the
 *     rejected message received.
 */
typedef void(aws_iotdevice_defender_report_rejected_fn)(
    int client_error_code,
    struct aws_byte_cursor *rejected_message_payload,
    void *userdata);

/**
 * User callback type invoked when the subscribed device defender topic for accepted
 * reports receives a message.
 */
typedef void(aws_iotdevice_defender_report_accepted_fn)(
    struct aws_byte_cursor *accepted_message_payload,
    void *userdata);

/**
 * User callback type invoked to retrieve a number type custom metric.
 *
 * returns: AWS_OP_SUCCESS if the custom metric was successfully added to the task config
 */
typedef int(aws_iotdevice_defender_get_number_fn)(int64_t *const value, void *userdata);

/**
 * User callback type invoked to retrieve a number list custom metric
 *
 * List provided will already be initialized and caller must push items into the list
 * of type int64_t.
 *
 * returns: AWS_OP_SUCCESS if the custom metric was successfully added to the task config
 */
typedef int(aws_iotdevice_defender_get_number_list_fn)(struct aws_array_list *const number_list, void *userdata);

/**
 * User callback type invoked to retrieve a string list custom metric
 *
 * List provided will already be initialized and caller must push items into the list
 * of type (struct aws_string *). String allocated that are placed into the list are
 * destroyed by the defender task after it is done with the list.
 *
 * returns: AWS_OP_SUCCESS if the custom metric was successfully added to the task config
 */
typedef int(aws_iotdevice_defender_get_string_list_fn)(struct aws_array_list *const string_list, void *userdata);

/**
 * User callback type invoked to retrieve an ip list custom metric
 *
 * List provided will already be initialized and caller must push items into the list
 * of type (struct aws_string *). String allocated that are placed into the list are
 * destroyed by the defender task after it is done with the list.
 *
 * returns: AWS_OP_SUCCESS if the custom metric was successfully added to the task config
 */
typedef int(aws_iotdevice_defender_get_ip_list_fn)(struct aws_array_list *const ip_list, void *userdata);

enum aws_iotdevice_defender_report_format { AWS_IDDRF_JSON, AWS_IDDRF_SHORT_JSON, AWS_IDDRF_CBOR };

/**
 * Change name if this needs external exposure. Needed to keep track of how to
 * interpret instantiated metrics, and cast the supplier_fn correctly.
 */
enum defender_custom_metric_type {
    DD_METRIC_UNKNOWN,
    DD_METRIC_NUMBER,      /* int64_t */
    DD_METRIC_NUMBER_LIST, /* aws_array_list: int64_t */
    DD_METRIC_STRING_LIST, /* aws_array_list: struct aws_string */
    DD_METRIC_IP_LIST      /* aws_array_list: struct aws_string */
};

struct aws_iotdevice_defender_task;
struct aws_iotdevice_defender_task_config;

AWS_EXTERN_C_BEGIN

/**
 * Creates a new reporting task config for Device Defender metrics collection
 *
 * @param    config_out     output to write a pointer to a task configuration.
 *                          Will write non-NULL if successful in creating the
 *                          the task configuration. Will write NULL if there is
 *                          an error during creation
 * @param    allocator      allocator to use for the task configuration's
 *                          internal data, and the task itself when started
 * @param    thing_name     thing name the task config is reporting for
 * @param    report_format  report format to produce when publishing to IoT
 * @returns  AWS_OP_SUCCESS and config_out will be non-NULL. Returns an error code
 *                          otherwise
 */
AWS_IOTDEVICE_API
int aws_iotdevice_defender_config_create(
    struct aws_iotdevice_defender_task_config **config_out,
    struct aws_allocator *allocator,
    const struct aws_byte_cursor *thing_name,
    enum aws_iotdevice_defender_report_format report_format);

/**
 * Destroys a new reporting task for Device Defender metrics
 *
 * @param    config    defender task configuration
 */
AWS_IOTDEVICE_API
void aws_iotdevice_defender_config_destroy(
    struct aws_iotdevice_defender_task_config **config);

/**
 * Sets the task cancelation callback function to invoke when the task
 * is canceled and not going to be scheduled to run. This is a suggestion
 * of when it is OK to close or free resources kept around while the task
 * is running.
 *
 * @param    config       defender task configuration
 * @param    cancel_fn    cancelation callback function
 * @returns    AWS_OP_SUCCESS when the task cancelation callback has been
 *             set. Returns an error if the callback was not set
 */
AWS_IOTDEVICE_API
int aws_iotdevice_defender_config_set_task_cancelation_fn(
    struct aws_iotdevice_defender_task_config *config,
    aws_iotdevice_defender_task_canceled_fn *cancel_fn);

/**
 * Sets the report rejected callback function to invoke when
 * is canceled and not going to be scheduled to run. This is a suggestion
 * of when it is OK to close or free resources kept around while the task
 * is running.
 *
 * @param    config         defender task configuration
 * @param    accepted_fn    accepted report callback function
 * @returns    AWS_OP_SUCCESS when the report accepted callback has been
 *             set. Returns an error if the callback was not set
 */
AWS_IOTDEVICE_API
int aws_iotdevice_defender_config_set_report_accepted_fn(
    struct aws_iotdevice_defender_task_config *config,
    aws_iotdevice_defender_report_accepted_fn *accepted_fn);

/**
 * Sets the report rejected callback function to invoke when
 * is canceled and not going to be scheduled to run. This is a suggestion
 * of when it is OK to close or free resources kept around while the task
 * is running.
 *
 * @param    config         defender task configuration
 * @param    rejected_fn    rejected report callback function
 * @returns    AWS_OP_SUCCESS when the report rejected callback has been
 *             set. Returns an error if the callback was not set
 */
AWS_IOTDEVICE_API
int aws_iotdevice_defender_config_set_report_rejected_fn(
    struct aws_iotdevice_defender_task_config *config,
    aws_iotdevice_defender_report_rejected_fn *rejected_fn);

/**
 * Sets the period of the device defender task
 *
 * @param    config            defender task configuration
 * @param    task_period_ns    how much time in nanoseconds between defender
 *                             task runs
 * @returns   AWS_OP_SUCCESS when the property has been set properly. Returns
 *            an error code if the value was not able to be set.
 */
AWS_IOTDEVICE_API
int aws_iotdevice_defender_config_set_task_period_ns(
    struct aws_iotdevice_defender_task_config *config,
    uint64_t task_period_ns);

/**
 * Sets the userdata for the device defender task's callback functions
 *
 * @param    config      defender task configuration
 * @param    userdata    how much time in nanoseconds between defender
 *                       task runs
 * @returns   AWS_OP_SUCCESS when the property has been set properly. Returns
 *            an error code if the value was not able to be set
 */
AWS_IOTDEVICE_API
int aws_iotdevice_defender_config_set_callback_userdata(
    struct aws_iotdevice_defender_task_config *config,
    void *userdata);

/**
 * Adds number custom metric to the Device Defender task configuration.
 * Has no impact on a defender task already started using the configuration.
 *
 * @param    task_config    the defender task configuration to register the metric to
 * @param    metric_name    UTF8 byte string of the metric name
 * @param    supplier       callback function to produce the metric value when
 *                          requested at report generation time
 * @param    userdata       specific callback data for the supplier callback function
 * @returns    AWS_OP_SUCCESS if the custom metric has been associated with the
 *             task configuration successfully
 */
AWS_IOTDEVICE_API
int aws_iotdevice_defender_config_register_number_metric(
    struct aws_iotdevice_defender_task_config *task_config,
    const struct aws_byte_cursor *metric_name,
    aws_iotdevice_defender_get_number_fn *supplier,
    void *userdata);

/**
 * Adds number list custom metric to the Device Defender task configuration.
 * Has no impact on a defender task already started using the configuration.
 *
 * @param    task_config    the defender task configuration to register the metric to
 * @param    metric_name    UTF8 byte string of the metric name
 * @param    supplier       callback function to produce the metric value when
 *                          requested at report generation time
 * @param    userdata       specific callback data for the supplier callback function
 * @returns    AWS_OP_SUCCESS if the custom metric has been associated with the
 *             task configuration successfully
 */
AWS_IOTDEVICE_API
int aws_iotdevice_defender_config_register_number_list_metric(
    struct aws_iotdevice_defender_task_config *task_config,
    const struct aws_byte_cursor *metric_name,
    aws_iotdevice_defender_get_number_list_fn *supplier,
    void *userdata);

/**
 * Adds string list custom metric to the Device Defender task configuration.
 * Has no impact on a defender task already started using the configuration.
 *
 * @param    task_config    the defender task configuration to register the metric to
 * @param    metric_name    UTF8 byte string of the metric name
 * @param    supplier       callback function to produce the metric value when
 *                          requested at report generation time
 * @param    userdata       specific callback data for the supplier callback function
 * @returns    AWS_OP_SUCCESS if the custom metric has been associated with the
 *             task configuration successfully
 */
AWS_IOTDEVICE_API
int aws_iotdevice_defender_config_register_string_list_metric(
    struct aws_iotdevice_defender_task_config *task_config,
    const struct aws_byte_cursor *metric_name,
    aws_iotdevice_defender_get_string_list_fn *supplier,
    void *userdata);

/**
 * Adds IP list custom metric to the Device Defender task configuration.
 * Has no impact on a defender task already started using the configuration.
 *
 * @param    task_config    the defender task configuration to register the metric to
 * @param    metric_name    UTF8 byte string of the metric name
 * @param    supplier       callback function to produce the metric value when
 *                          requested at report generation time
 * @param    userdata       specific callback data for the supplier callback function
 * @returns    AWS_OP_SUCCESS if the custom metric has been associated with the
 *             task configuration successfully
 */
AWS_IOTDEVICE_API
int aws_iotdevice_defender_config_register_ip_list_metric(
    struct aws_iotdevice_defender_task_config *task_config,
    const struct aws_byte_cursor *metric_name,
    aws_iotdevice_defender_get_ip_list_fn *supplier,
    void *userdata);

/**
 * Creates and starts a new Device Defender reporting task
 *
 * @param    task_out      output parameter to set to point to the defender task
 * @param    config        defender task configuration to use to start the task
 * @param    connection    mqtt connection to use to publish reports to
 * @param    event_loop    IoT device thing name used to determine the MQTT
 *                         topic to publish the report to and listen for accepted
 *                         or rejected responses
 */
AWS_IOTDEVICE_API
int aws_iotdevice_defender_start_task(
    struct aws_iotdevice_defender_task **task_out,
    const struct aws_iotdevice_defender_task_config *config,
    struct aws_mqtt_client_connection *connection,
    struct aws_event_loop *event_loop);

/**
 * Cancels the running task reporting Device Defender metrics
 */
AWS_IOTDEVICE_API
void aws_iotdevice_defender_stop_task(struct aws_iotdevice_defender_task *defender_task);

AWS_EXTERN_C_END

#endif
