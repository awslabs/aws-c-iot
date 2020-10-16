/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#ifndef AWS_IOTDEVICE_SERIALIZER_H
#define AWS_IOTDEVICE_SERIALIZER_H

#include <aws/common/byte_buf.h>
#include <aws/iotdevice/exports.h>

#define AWS_IOT_ST_MESSAGE_TYPEFIELD 1
#define AWS_IOT_ST_MESSAGE_STREAMID 2
#define AWS_IOT_ST_MESSAGE_IGNORABLE 3
#define AWS_IOT_ST_MESSAGE_PAYLOAD 4
#define AWS_IOT_ST_VARINT_WIRE 0
#define AWS_IOT_ST_VARINT_LENGTHDELIM_WIRE 2

#define AWS_IOT_ST_FIELD_NUMBER_SHIFT 3

#define AWS_IOT_ST_MESSAGE_DEFAULT_STREAMID 0
#define AWS_IOT_ST_MESSAGE_DEFAULT_IGNORABLE 0
#define AWS_IOT_ST_MESSAGE_DEFAULT_TYPE 0
#define AWS_IOT_ST_MESSAGE_DEFAULT_PAYLOAD 0

#define AWS_IOT_ST_STREAMID_FIELD_NUMBER 2
#define AWS_IOT_ST_IGNORABLE_FIELD_NUMBER 3
#define AWS_IOT_ST_TYPE_FIELD_NUMBER 1
#define AWS_IOT_ST_PAYLOAD_FIELD_NUMBER 4

#define AWS_IOT_ST_DEFAULT_ALLO 60
#define AWS_IOT_ST_MAX_MESSAGE_SIZE 64000
#define AWS_IOT_ST_BLOCK_SIZE 1

enum aws_iot_st_message_type { UNKNOWN, DATA, STREAM_START, STREAM_RESET, SESSION_RESET };

struct aws_iot_st_msg {
    enum aws_iot_st_message_type type;
    int32_t stream_id;
    int ignorable;
    struct aws_byte_buf payload;
};

AWS_IOTDEVICE_API
int aws_iot_st_msg_serialize_from_struct(
    struct aws_byte_buf *buffer,
    struct aws_allocator *allocator,
    struct aws_iot_st_msg message);
AWS_IOTDEVICE_API
int aws_iot_st_msg_deserialize_from_cursor(
    struct aws_iot_st_msg *message,
    struct aws_byte_cursor *cursor,
    struct aws_allocator *allocator);
#endif
