/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#include <aws/iotdevice/private/serializer.h>

#include <aws/common/assert.h>
#include <aws/common/byte_buf.h>
#include <aws/common/error.h>

#include <stdio.h>

static int s_iot_st_encode_varint_uint32_t(struct aws_byte_buf *buffer, uint32_t n) {
    // & 2's comp   lement
    // ~0x7F == b-10000000
    while (n & ~0x7F) {
        AWS_RETURN_ERROR_IF2(
            // 0xFF == b11111111
            // 0x80 == b10000000
            aws_byte_buf_append_byte_dynamic_secure(buffer, (uint8_t)(n & 0xFF) | 0x80) == AWS_OP_SUCCESS,
            AWS_OP_ERR);
        n = n >> 7;
    }
    AWS_RETURN_ERROR_IF2(aws_byte_buf_append_byte_dynamic_secure(buffer, (uint8_t)n) == AWS_OP_SUCCESS, AWS_OP_ERR);
    return AWS_OP_SUCCESS;
}

static int s_iot_st_encode_varint_negative_uint32_t(struct aws_byte_buf *buffer, uint32_t n) {
    int byte_count = 0;
    // & 2's complement
    // ~0x7F == b-10000000
    while (n & ~0x7F) {
        AWS_RETURN_ERROR_IF2(
            // 0xFF == b11111111
            // 0x80 == b10000000
            aws_byte_buf_append_byte_dynamic_secure(buffer, (uint8_t)(n & 0xFF) | 0x80) == AWS_OP_SUCCESS,
            AWS_OP_ERR);
        n = n >> 7;
        byte_count += 1;
    }
    // Last Byte Math
    int count = 0;
    while (!(n & 0x80)) {
        n = n << 1;
        count += 1;
    }
    for (int i = 0; i < count; i++) {
        n = n >> 1;
        n = n | 0x80;
    }
    AWS_RETURN_ERROR_IF2(aws_byte_buf_append_byte_dynamic_secure(buffer, (uint8_t)n) == AWS_OP_SUCCESS, AWS_OP_ERR);
    for (int i = 0; i < 10 - byte_count - 2; i++) {
        AWS_RETURN_ERROR_IF2(aws_byte_buf_append_byte_dynamic_secure(buffer, 0xFF) == AWS_OP_SUCCESS, AWS_OP_ERR);
    }
    AWS_RETURN_ERROR_IF2(aws_byte_buf_append_byte_dynamic_secure(buffer, 0x1) == AWS_OP_SUCCESS, AWS_OP_ERR);
    return AWS_OP_SUCCESS;
}

static int s_iot_st_encode_varint_pos(struct aws_byte_buf *buffer, int32_t n) {
    if (n > 0) {
        return s_iot_st_encode_varint_uint32_t(buffer, (uint32_t)n);
    } else if (n < 0) {
        return s_iot_st_encode_varint_negative_uint32_t(buffer, (uint32_t)n);
    }
    return AWS_OP_ERR;
}

static int s_iot_st_decode_varint_uint32_t(struct aws_byte_cursor *cursor, uint32_t *result) {
    int bits = 0;
    // Continue while the first bit is one
    // 0x80 == b10000000
    uint32_t castPtrValue;
    while ((*cursor->ptr & 0x80)) {
        castPtrValue = *cursor->ptr;
        // Zero out the first bit
        // 0x7F == b01111111
        *result += ((castPtrValue & 0x7F) << bits);
        AWS_RETURN_ERROR_IF2(aws_byte_cursor_advance(cursor, 1).ptr != NULL, AWS_OP_ERR);
        bits += 7;
    }
    castPtrValue = *cursor->ptr;
    AWS_RETURN_ERROR_IF2(aws_byte_cursor_advance(cursor, 1).ptr != NULL, AWS_OP_ERR);
    // Zero out the first bit
    // 0x7F == b01111111
    *result += ((castPtrValue & 0x7F) << bits);
    return AWS_OP_SUCCESS;
}

static int s_iot_st_encode_varint(
    const uint8_t field_number,
    const uint8_t wire_type,
    const int32_t value,
    struct aws_byte_buf *buffer) {
    const uint8_t field_and_wire_type = (field_number << AWS_IOT_ST_FIELD_NUMBER_SHIFT) + wire_type;
    AWS_RETURN_ERROR_IF2(
        aws_byte_buf_append_byte_dynamic_secure(buffer, field_and_wire_type) == AWS_OP_SUCCESS, AWS_OP_ERR);
    return s_iot_st_encode_varint_pos(buffer, value);
}

static int s_iot_st_encode_lengthdelim(
    const uint8_t field_number,
    const uint8_t wire_type,
    struct aws_byte_buf *payload,
    struct aws_byte_buf *buffer) {
    const uint8_t field_and_wire_type = (field_number << AWS_IOT_ST_FIELD_NUMBER_SHIFT) + wire_type;
    aws_byte_buf_append_byte_dynamic_secure(buffer, field_and_wire_type);
    s_iot_st_encode_varint_uint32_t(buffer, (uint32_t)payload->len);
    struct aws_byte_cursor temp = aws_byte_cursor_from_array(payload->buffer, payload->len);
    return aws_byte_buf_append_dynamic_secure(buffer, &temp);
}

static int s_iot_st_encode_streamid(int32_t data, struct aws_byte_buf *buffer) {
    return s_iot_st_encode_varint(AWS_IOT_ST_MESSAGE_STREAMID, AWS_IOT_ST_VARINT_WIRE, data, buffer);
}

static int s_iot_st_encode_ignorable(int32_t data, struct aws_byte_buf *buffer) {
    return s_iot_st_encode_varint(AWS_IOT_ST_MESSAGE_IGNORABLE, AWS_IOT_ST_VARINT_WIRE, data, buffer);
}

static int s_iot_st_encode_type(int32_t data, struct aws_byte_buf *buffer) {
    return s_iot_st_encode_varint(AWS_IOT_ST_MESSAGE_TYPEFIELD, AWS_IOT_ST_VARINT_WIRE, data, buffer);
}

static int s_iot_st_encode_payload(struct aws_byte_buf *payload, struct aws_byte_buf *buffer) {
    return s_iot_st_encode_lengthdelim(AWS_IOT_ST_MESSAGE_PAYLOAD, AWS_IOT_ST_VARINT_LENGTHDELIM_WIRE, payload, buffer);
}

int aws_iot_st_msg_serialize_from_struct(
    struct aws_byte_buf *buffer,
    struct aws_allocator *allocator,
    struct aws_iot_st_msg message) {
    if (aws_byte_buf_init(buffer, allocator, AWS_IOT_ST_DEFAULT_ALLO + message.payload.len) != AWS_OP_SUCCESS) {
        return AWS_OP_ERR;
    }

    if (message.type != AWS_IOT_ST_MESSAGE_DEFAULT_TYPE) {
        if (s_iot_st_encode_type(message.type, buffer) != AWS_OP_SUCCESS) {
            goto cleanup;
        }
    }
    if (message.streamId != AWS_IOT_ST_MESSAGE_DEFAULT_STREAMID) {
        if (s_iot_st_encode_streamid(message.streamId, buffer) != AWS_OP_SUCCESS) {
            goto cleanup;
        }
    }
    if (message.ignorable != AWS_IOT_ST_MESSAGE_DEFAULT_IGNORABLE) {
        if (s_iot_st_encode_ignorable(message.ignorable, buffer) != AWS_OP_SUCCESS) {
            goto cleanup;
        }
    }
    if (message.payload.len != AWS_IOT_ST_MESSAGE_DEFAULT_PAYLOAD) {
        if (s_iot_st_encode_payload(&message.payload, buffer) != AWS_OP_SUCCESS) {
            goto cleanup;
        }
    }
    AWS_RETURN_ERROR_IF2(buffer->capacity < AWS_IOT_ST_MAX_MESSAGE_SIZE, AWS_ERROR_INVALID_BUFFER_SIZE);
    return AWS_OP_SUCCESS;

cleanup:
    aws_byte_buf_clean_up(buffer);
    return AWS_OP_ERR;
}

static int s_aws_st_decode_lengthdelim(struct aws_byte_cursor *cursor, struct aws_byte_buf *buffer, int length) {
    struct aws_byte_cursor temp = aws_byte_cursor_from_array(cursor->ptr, length);
    AWS_RETURN_ERROR_IF2(aws_byte_buf_append_dynamic_secure(buffer, &temp) == 0, AWS_OP_ERR);
    return AWS_OP_SUCCESS;
}

int aws_iot_st_msg_deserialize_from_cursor(
    struct aws_iot_st_msg *message,
    struct aws_byte_cursor *cursor,
    struct aws_allocator *allocator) {
    AWS_RETURN_ERROR_IF2(cursor->len < AWS_IOT_ST_MAX_MESSAGE_SIZE, AWS_ERROR_INVALID_BUFFER_SIZE);
    uint8_t wire_type;
    uint8_t field_number;
    int length;
    while ((aws_byte_cursor_is_valid(cursor)) && (cursor->len > 0)) {
        // wire_type is only the first 3 bits, Zeroing out the first 5
        // 0x07 == 00000111
        wire_type = *cursor->ptr & 0x07;
        field_number = (*cursor->ptr) >> 3;
        aws_byte_cursor_advance(cursor, 1);

        if (field_number == AWS_IOT_ST_STREAMID_FIELD_NUMBER && wire_type == AWS_IOT_ST_VARINT_WIRE) {
            uint32_t res = 0;
            if (s_iot_st_decode_varint_uint32_t(cursor, &res) != AWS_OP_SUCCESS) {
                return AWS_OP_ERR;
            }
            message->streamId = res;
        } else if (field_number == AWS_IOT_ST_IGNORABLE_FIELD_NUMBER && wire_type == AWS_IOT_ST_VARINT_WIRE) {
            uint32_t res = 0;
            if (s_iot_st_decode_varint_uint32_t(cursor, &res) != AWS_OP_SUCCESS) {
                return AWS_OP_ERR;
            }
            message->ignorable = res;
        } else if (field_number == AWS_IOT_ST_TYPE_FIELD_NUMBER && wire_type == AWS_IOT_ST_VARINT_WIRE) {
            uint32_t res = 0;
            if (s_iot_st_decode_varint_uint32_t(cursor, &res) != AWS_OP_SUCCESS) {
                return AWS_OP_ERR;
            }
            message->type = res;
        } else if (field_number == AWS_IOT_ST_PAYLOAD_FIELD_NUMBER && wire_type == AWS_IOT_ST_VARINT_LENGTHDELIM_WIRE) {
            uint32_t res = 0;
            if (s_iot_st_decode_varint_uint32_t(cursor, &res) != AWS_OP_SUCCESS) {
                return AWS_OP_ERR;
            }
            length = res;
            if (aws_byte_buf_init(&message->payload, allocator, length) != AWS_OP_SUCCESS) {
                return AWS_OP_ERR;
            }

            if (s_aws_st_decode_lengthdelim(cursor, &message->payload, length) != AWS_OP_SUCCESS) {
                goto cleanup;
            }
            aws_byte_cursor_advance(cursor, length);
        }
    }
    return AWS_OP_SUCCESS;
cleanup:
    aws_byte_buf_clean_up(&message->payload);
    return AWS_OP_ERR;
}
