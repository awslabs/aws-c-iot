/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#ifndef AWS_IOTDEVICE_SERIALIZER_H
#define AWS_IOTDEVICE_SERIALIZER_H

#include <aws/iotdevice/iotdevice.h>
#include <aws/iotdevice/private/secure_tunneling_impl.h>
#include <aws/iotdevice/secure_tunneling.h>

#include <aws/common/byte_buf.h>

#define AWS_IOT_ST_FIELD_NUMBER_SHIFT 3

#define AWS_IOT_ST_MAXIMUM_VARINT 268435455
#define AWS_IOT_ST_MAXIMUM_1_BYTE_VARINT_VALUE 128
#define AWS_IOT_ST_MAXIMUM_2_BYTE_VARINT_VALUE 16384
#define AWS_IOT_ST_MAXIMUM_3_BYTE_VARINT_VALUE 2097152
#define AWS_IOT_ST_MAX_PAYLOAD_SIZE (63 * 1024)

enum aws_secure_tunnel_field_number {
    AWS_SECURE_TUNNEL_FN_TYPE = 1,
    AWS_SECURE_TUNNEL_FN_STREAM_ID = 2,
    AWS_SECURE_TUNNEL_FN_IGNORABLE = 3,
    AWS_SECURE_TUNNEL_FN_PAYLOAD = 4,
    AWS_SECURE_TUNNEL_FN_SERVICE_ID = 5,
    AWS_SECURE_TUNNEL_FN_AVAILABLE_SERVICE_IDS = 6,
    AWS_SECURE_TUNNEL_FN_CONNECTION_ID = 7,
};

enum aws_secure_tunnel_protocol_buffer_wire_type {
    AWS_SECURE_TUNNEL_PBWT_VARINT = 0,           /* int32, int64, uint32, uint64, sint32, sint64, bool, enum */
    AWS_SECURE_TUNNEL_PBWT_64_BIT = 1,           /* fixed64, sfixed64, double */
    AWS_SECURE_TUNNEL_PBWT_LENGTH_DELIMITED = 2, /* string, bytes, embedded messages, packed repeated fields */
    AWS_SECURE_TUNNEL_PBWT_START_GROUP = 3,      /* groups (deprecated) */
    AWS_SECURE_TUNNEL_PBWT_END_GROUP = 4,        /* groups (deprecated) */
    AWS_SECURE_TUNNEL_PBWT_32_BIT = 5,           /* fixed32, sfixed32, float */
};

typedef void(aws_secure_tunnel_on_message_received_fn)(
    struct aws_secure_tunnel *secure_tunnel,
    struct aws_secure_tunnel_message_view *message_view);

AWS_EXTERN_C_BEGIN

AWS_IOTDEVICE_API
int aws_iot_st_msg_serialize_from_view(
    struct aws_byte_buf *buffer,
    struct aws_allocator *allocator,
    const struct aws_secure_tunnel_message_view *message_view);

AWS_IOTDEVICE_API
int aws_secure_tunnel_deserialize_message_from_cursor(
    struct aws_secure_tunnel *secure_tunnel,
    struct aws_byte_cursor *cursor,
    aws_secure_tunnel_on_message_received_fn *on_message_received);

AWS_EXTERN_C_END

#endif
