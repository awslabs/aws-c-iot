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
#include <aws/iotdevice/secure_tunneling_message_storage.h>

/*********************************************************************************************************************
 * Operations
 ********************************************************************************************************************/

struct aws_secure_tunnel_operation;

enum aws_secure_tunnel_operation_type {
    AWS_STOT_NONE,
    AWS_STOT_CONNECT,
    AWS_STOT_PING,
    AWS_STOT_DATA,
    AWS_STOT_STREAM_RESET,
    AWS_STOT_STREAM_START
};

/* Basic vtable for all secure tunnel operations.  Implementations are per-message type */
struct aws_secure_tunnel_operation_vtable {
    void (*aws_secure_tunnel_operation_completion_fn)(
        struct aws_secure_tunnel_operation *operation,
        int error_code,
        const void *completion_view);

    /* Set the stream id of outgoing st_msg */
    void (*aws_secure_tunnel_operation_set_stream_id_fn)(
        struct aws_secure_tunnel_operation *operation,
        struct aws_secure_tunnel *secure_tunnel);

    /* Get the stream id from an address */
    int32_t *(*aws_secure_tunnel_operation_get_stream_id_address_fn)(
        const struct aws_secure_tunnel_operation *operation);
};

/**
 * This is the base structure for all secure tunnel operations.  It includes the type, a ref count, and list management.
 */
struct aws_secure_tunnel_operation {
    const struct aws_secure_tunnel_operation_vtable *vtable;
    struct aws_ref_count ref_count;
    struct aws_linked_list_node node;

    enum aws_secure_tunnel_operation_type operation_type;
    const void *message_view;

    /* Size of the secure tunnel message this operation represents */
    size_t message_size;

    void *impl;
};

struct aws_secure_tunnel_operation_data {
    struct aws_secure_tunnel_operation base;
    struct aws_allocator *allocator;

    struct aws_secure_tunnel_message_data_storage options_storage;
};

AWS_EXTERN_C_BEGIN

/* Operation Base */

AWS_IOTDEVICE_API struct aws_secure_tunnel_operation *aws_secure_tunnel_operation_acquire(
    struct aws_secure_tunnel_operation *operation);

AWS_IOTDEVICE_API struct aws_secure_tunnel_operation *aws_secure_tunnel_operation_release(
    struct aws_secure_tunnel_operation *operation);

AWS_IOTDEVICE_API void *aws_secure_tunnel_operation_complete(
    struct aws_secure_tunnel_operation *operation,
    int error_code,
    const void *associated_view);

AWS_IOTDEVICE_API void aws_secure_tunnel_operation_set_stream_id(
    struct aws_secure_tunnel_operation *operation,
    struct aws_secure_tunnel *secure_tunnel);

AWS_IOTDEVICE_API int32_t
    aws_secure_tunnel_operation_get_stream_id(const struct aws_secure_tunnel_operation *operation);

AWS_IOTDEVICE_API int32_t *aws_secure_tunnel_operation_get_stream_id_address(
    const struct aws_secure_tunnel_operation *operation);

/* Data */

AWS_IOTDEVICE_API
void aws_secure_tunnel_message_data_view_log(
    const struct aws_secure_tunnel_message_data_view *data_view,
    enum aws_log_level level);

AWS_IOTDEVICE_API
struct aws_secure_tunnel_operation_data *aws_secure_tunnel_operation_data_new(
    struct aws_allocator *allocator,
    const struct aws_secure_tunnel *secure_tunnel,
    const struct aws_secure_tunnel_message_data_view *data_options);

AWS_IOTDEVICE_API
const char *aws_secure_tunnel_operation_type_to_c_string(enum aws_secure_tunnel_operation_type operation_type);

/* Stream */

/* STEVE TODO add stream to API */
// AWS_IOTDEVICE_API
// struct aws_secure_tunnel_operation_data *aws_secure_tunnel_operation_stream_new(
//     struct aws_allocator *allocator,
//     const struct aws_secure_tunnel *secure_tunnel,
//     const struct aws_secure_tunnel_message_stream_view *stream_options);

AWS_EXTERN_C_END

#endif /* AWS_IOTDEVICE_SECURE_TUNNELING_OPERATION_H */
