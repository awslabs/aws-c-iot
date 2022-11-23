/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#ifndef AWS_IOTDEVICE_SECURE_TUNNELING_MESSAGE_STORAGE_H
#define AWS_IOTDEVICE_SECURE_TUNNELING_MESSAGE_STORAGE_H

#include <aws/iotdevice/private/serializer.h>
#include <aws/iotdevice/secure_tunneling.h>

struct aws_secure_tunnel_message_data_storage {
    struct aws_allocator *allocator;
    struct aws_secure_tunnel_message_data_view storage_view;

    int32_t stream_id;
    struct aws_byte_cursor service_id;
    struct aws_byte_cursor payload;

    struct aws_byte_buf storage;
};

struct aws_secure_tunnel_message_stream_storage {
    struct aws_allocator *allocator;
    struct aws_secure_tunnel_message_stream_view storage_view;

    int32_t stream_id;
    struct aws_byte_cursor service_id;

    struct aws_byte_buf storage;
};

AWS_EXTERN_C_BEGIN

/* Data */

AWS_IOTDEVICE_API
int aws_secure_tunnel_message_data_storage_init(
    struct aws_secure_tunnel_message_data_storage *data_storage,
    struct aws_allocator *allocator,
    const struct aws_secure_tunnel_message_data_view *data_options);

AWS_IOTDEVICE_API
int aws_secure_tunnel_message_data_storage_init_from_external_storage(
    struct aws_secure_tunnel_message_data_storage *data_storage,
    struct aws_allocator *allocator);

AWS_IOTDEVICE_API
void aws_secure_tunnel_message_data_storage_clean_up(struct aws_secure_tunnel_message_data_storage *data_storage);

/* Stream */

AWS_IOTDEVICE_API
int aws_secure_tunnel_message_stream_storage_init(
    struct aws_secure_tunnel_message_stream_storage *stream_storage,
    struct aws_allocator *allocator,
    const struct aws_secure_tunnel_message_stream_view *stream_options);

AWS_IOTDEVICE_API
int aws_secure_tunnel_message_stream_storage_init_from_external_storage(
    struct aws_secure_tunnel_message_stream_storage *stream_storage,
    struct aws_allocator *allocator);

AWS_IOTDEVICE_API
void aws_secure_tunnel_message_stream_storage_clean_up(struct aws_secure_tunnel_message_stream_storage *stream_storage);

AWS_EXTERN_C_END

#endif /* AWS_IOTDEVICE_SECURE_TUNNELING_MESSAGE_STORAGE_H */
