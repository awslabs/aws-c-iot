/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#ifndef AWS_IOTDEVICE_SECURE_TUNNELING_OPERATION_H
#define AWS_IOTDEVICE_SECURE_TUNNELING_OPERATION_H

#include <aws/common/byte_buf.h>
#include <aws/common/linked_list.h>
#include <aws/common/ref_count.h>
#include <aws/iotdevice/private/serializer.h>
#include <aws/iotdevice/secure_tunneling.h>

/*********************************************************************************************************************
 * Operations
 ********************************************************************************************************************/

struct aws_secure_tunnel_operation;

enum aws_secure_tunnel_operation_type {
    AWS_STOT_NONE,
    AWS_STOT_PING,
    AWS_STOT_MESSAGE,
    AWS_STOT_STREAM_RESET,
    AWS_STOT_STREAM_START,
    AWS_STOT_CONNECTION_START,
    AWS_STOT_CONNECTION_RESET,
};

struct aws_service_id_element {
    struct aws_allocator *allocator;
    struct aws_byte_cursor service_id_cur;
    struct aws_string *service_id_string;
    int32_t stream_id;
    struct aws_hash_table connection_ids;
};

struct aws_connection_id_element {
    struct aws_allocator *allocator;
    uint32_t connection_id;
};

/* Basic vtable for all secure tunnel operations.  Implementations are per-message type */
struct aws_secure_tunnel_operation_vtable {
    void (*aws_secure_tunnel_operation_completion_fn)(
        struct aws_secure_tunnel_operation *operation,
        int error_code,
        const void *completion_view);

    /* Set the stream id of outgoing st_msg based on current service id */
    int (*aws_secure_tunnel_operation_assign_stream_id_fn)(
        struct aws_secure_tunnel_operation *operation,
        struct aws_secure_tunnel *secure_tunnel);

    /* Set the stream id of outgoing STREAM START message to +1 of the currently set stream id */
    int (*aws_secure_tunnel_operation_set_next_stream_id_fn)(
        struct aws_secure_tunnel_operation *operation,
        struct aws_secure_tunnel *secure_tunnel);

    /* Set the connection id of outbound CONNECTION START as active for the Source device */
    int (*aws_secure_tunnel_operation_set_connection_start_id)(
        struct aws_secure_tunnel_operation *operation,
        struct aws_secure_tunnel *secure_tunnel);

    /* Perform actions on outbound message before sending it */
    void (*aws_secure_tunnel_operation_prepare_message_for_send_fn)(
        struct aws_secure_tunnel_operation *operation,
        struct aws_secure_tunnel *secure_tunnel);
};

/**
 * This is the base structure for all secure tunnel operations.  It includes the type, a ref count, and list management.
 */
struct aws_secure_tunnel_operation {
    const struct aws_secure_tunnel_operation_vtable *vtable;
    struct aws_ref_count ref_count;
    struct aws_linked_list_node node;

    enum aws_secure_tunnel_operation_type operation_type;
    const struct aws_secure_tunnel_message_view *message_view;

    /* Size of the secure tunnel message this operation represents */
    size_t message_size;

    void *impl;
};

struct aws_secure_tunnel_operation_message {
    struct aws_secure_tunnel_operation base;
    struct aws_allocator *allocator;

    struct aws_secure_tunnel_message_storage options_storage;
};

struct aws_secure_tunnel_operation_pingreq {
    struct aws_secure_tunnel_operation base;
    struct aws_allocator *allocator;
};

AWS_EXTERN_C_BEGIN

/* Operation Base */

AWS_IOTDEVICE_API struct aws_secure_tunnel_operation *aws_secure_tunnel_operation_acquire(
    struct aws_secure_tunnel_operation *operation);

AWS_IOTDEVICE_API struct aws_secure_tunnel_operation *aws_secure_tunnel_operation_release(
    struct aws_secure_tunnel_operation *operation);

AWS_IOTDEVICE_API void aws_secure_tunnel_operation_complete(
    struct aws_secure_tunnel_operation *operation,
    int error_code,
    const void *associated_view);

AWS_IOTDEVICE_API void aws_secure_tunnel_operation_assign_stream_id(
    struct aws_secure_tunnel_operation *operation,
    struct aws_secure_tunnel *secure_tunnel);

AWS_IOTDEVICE_API int32_t
    aws_secure_tunnel_operation_get_stream_id(const struct aws_secure_tunnel_operation *operation);

AWS_IOTDEVICE_API int32_t *aws_secure_tunnel_operation_get_stream_id_address(
    const struct aws_secure_tunnel_operation *operation);

/* Message */

AWS_IOTDEVICE_API
int aws_secure_tunnel_message_view_validate(const struct aws_secure_tunnel_message_view *message_view);

AWS_IOTDEVICE_API
void aws_secure_tunnel_message_view_log(
    const struct aws_secure_tunnel_message_view *message_view,
    enum aws_log_level level);

AWS_IOTDEVICE_API
int aws_secure_tunnel_message_storage_init(
    struct aws_secure_tunnel_message_storage *message_storage,
    struct aws_allocator *allocator,
    const struct aws_secure_tunnel_message_view *message_options,
    enum aws_secure_tunnel_operation_type type);

AWS_IOTDEVICE_API
void aws_secure_tunnel_message_storage_clean_up(struct aws_secure_tunnel_message_storage *message_storage);

AWS_IOTDEVICE_API
struct aws_secure_tunnel_operation_message *aws_secure_tunnel_operation_message_new(
    struct aws_allocator *allocator,
    const struct aws_secure_tunnel *secure_tunnel,
    const struct aws_secure_tunnel_message_view *message_options,
    enum aws_secure_tunnel_operation_type type);

/* Ping */

AWS_IOTDEVICE_API
struct aws_secure_tunnel_operation_pingreq *aws_secure_tunnel_operation_pingreq_new(struct aws_allocator *allocator);

/* Secure Tunnel Storage Options */

/**
 * Raises exception and returns AWS_OP_ERR if options are missing required parameters.
 */
AWS_IOTDEVICE_API
int aws_secure_tunnel_options_validate(const struct aws_secure_tunnel_options *options);

/**
 * Destroy options storage, and release any references held.
 */
AWS_IOTDEVICE_API
void aws_secure_tunnel_options_storage_destroy(struct aws_secure_tunnel_options_storage *storage);

/**
 * Create persistent storage for aws_secure_tunnel_options.
 * Makes a deep copy of (or acquires reference to) any data referenced by options,
 */
AWS_IOTDEVICE_API
struct aws_secure_tunnel_options_storage *aws_secure_tunnel_options_storage_new(
    struct aws_allocator *allocator,
    const struct aws_secure_tunnel_options *options);

AWS_IOTDEVICE_API
void aws_secure_tunnel_connections_destroy(struct aws_secure_tunnel_connections *storage);

AWS_IOTDEVICE_API
struct aws_secure_tunnel_connections *aws_secure_tunnel_connections_new(struct aws_allocator *allocator);

AWS_IOTDEVICE_API
void aws_secure_tunnel_options_storage_log(
    const struct aws_secure_tunnel_options_storage *options_storage,
    enum aws_log_level level);

AWS_IOTDEVICE_API
const char *aws_secure_tunnel_operation_type_to_c_string(enum aws_secure_tunnel_operation_type operation_type);

/* Data Tunnel Pair */

AWS_IOTDEVICE_API
void aws_secure_tunnel_data_tunnel_pair_destroy(struct data_tunnel_pair *pair);

AWS_IOTDEVICE_API
struct data_tunnel_pair *aws_secure_tunnel_data_tunnel_pair_new(
    struct aws_allocator *allocator,
    const struct aws_secure_tunnel *secure_tunnel,
    const struct aws_secure_tunnel_message_view *message_view);

AWS_IOTDEVICE_API
struct aws_service_id_element *aws_service_id_element_new(
    struct aws_allocator *allocator,
    const struct aws_byte_cursor *service_id,
    int32_t stream_id);

AWS_IOTDEVICE_API
void aws_connection_id_destroy(void *data);

AWS_IOTDEVICE_API
struct aws_connection_id_element *aws_connection_id_element_new(
    struct aws_allocator *allocator,
    uint32_t connection_id);

AWS_EXTERN_C_END

#endif /* AWS_IOTDEVICE_SECURE_TUNNELING_OPERATION_H */
