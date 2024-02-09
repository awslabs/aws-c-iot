/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#include <aws/common/string.h>
#include <aws/iotdevice/private/secure_tunneling_operations.h>
#include <aws/iotdevice/private/serializer.h>

/*****************************************************************************************************************
 *                                               ENCODING
 *****************************************************************************************************************/

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

static int s_iot_st_encode_byte_range(
    const uint8_t field_number,
    const uint8_t wire_type,
    const struct aws_byte_cursor *payload,
    struct aws_byte_buf *buffer) {
    const uint8_t field_and_wire_type = (field_number << AWS_IOT_ST_FIELD_NUMBER_SHIFT) + wire_type;
    aws_byte_buf_append_byte_dynamic_secure(buffer, field_and_wire_type);
    s_iot_st_encode_varint_uint32_t(buffer, (uint32_t)payload->len);
    struct aws_byte_cursor temp = aws_byte_cursor_from_array(payload->ptr, payload->len);
    return aws_byte_buf_append_dynamic_secure(buffer, &temp);
}

static int s_iot_st_encode_stream_id(int32_t data, struct aws_byte_buf *buffer) {
    return s_iot_st_encode_varint(AWS_SECURE_TUNNEL_FN_STREAM_ID, AWS_SECURE_TUNNEL_PBWT_VARINT, data, buffer);
}

static int s_iot_st_encode_connection_id(uint32_t data, struct aws_byte_buf *buffer) {
    return s_iot_st_encode_varint(AWS_SECURE_TUNNEL_FN_CONNECTION_ID, AWS_SECURE_TUNNEL_PBWT_VARINT, data, buffer);
}

static int s_iot_st_encode_ignorable(int32_t data, struct aws_byte_buf *buffer) {
    return s_iot_st_encode_varint(AWS_SECURE_TUNNEL_FN_IGNORABLE, AWS_SECURE_TUNNEL_PBWT_VARINT, data, buffer);
}

static int s_iot_st_encode_type(int32_t data, struct aws_byte_buf *buffer) {
    return s_iot_st_encode_varint(AWS_SECURE_TUNNEL_FN_TYPE, AWS_SECURE_TUNNEL_PBWT_VARINT, data, buffer);
}

static int s_iot_st_encode_payload(const struct aws_byte_cursor *payload, struct aws_byte_buf *buffer) {
    return s_iot_st_encode_byte_range(
        AWS_SECURE_TUNNEL_FN_PAYLOAD, AWS_SECURE_TUNNEL_PBWT_LENGTH_DELIMITED, payload, buffer);
}

static int s_iot_st_encode_service_id(const struct aws_byte_cursor *service_id, struct aws_byte_buf *buffer) {
    return s_iot_st_encode_byte_range(
        AWS_SECURE_TUNNEL_FN_SERVICE_ID, AWS_SECURE_TUNNEL_PBWT_LENGTH_DELIMITED, service_id, buffer);
}

static int s_iot_st_encode_service_ids(const struct aws_byte_cursor *service_id, struct aws_byte_buf *buffer) {
    return s_iot_st_encode_byte_range(
        AWS_SECURE_TUNNEL_FN_AVAILABLE_SERVICE_IDS, AWS_SECURE_TUNNEL_PBWT_LENGTH_DELIMITED, service_id, buffer);
}

static int s_iot_st_get_varint_size(size_t value, size_t *encode_size) {
    if (value > AWS_IOT_ST_MAXIMUM_VARINT) {
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }

    if (value < AWS_IOT_ST_MAXIMUM_1_BYTE_VARINT_VALUE) {
        *encode_size = 1;
    } else if (value < AWS_IOT_ST_MAXIMUM_2_BYTE_VARINT_VALUE) {
        *encode_size = 2;
    } else if (value < AWS_IOT_ST_MAXIMUM_3_BYTE_VARINT_VALUE) {
        *encode_size = 3;
    } else {
        *encode_size = 4;
    }

    return AWS_OP_SUCCESS;
}

static int s_iot_st_compute_message_length(
    const struct aws_secure_tunnel_message_view *message,
    size_t *message_length) {
    size_t local_length = 0;

    /*
     * 1 byte type key
     * 1 byte type varint
     */
    local_length += 2;

    if (message->stream_id != 0) {
        /*
         * 1 byte stream_id key
         * 1-4 byte stream_id varint
         */
        size_t stream_id_length = 0;

        if (s_iot_st_get_varint_size((uint32_t)message->stream_id, &stream_id_length)) {
            return AWS_OP_ERR;
        }

        local_length += (1 + stream_id_length);
    }

    if (message->connection_id != 0) {
        /*
         * 1 byte connection_id key
         * 1-4 byte connection_id varint
         */

        size_t connection_id_length = 0;

        if (s_iot_st_get_varint_size(message->connection_id, &connection_id_length)) {
            return AWS_OP_ERR;
        }

        local_length += (1 + connection_id_length);
    }

    if (message->ignorable != 0) {
        /*
         * 1 byte ignorable key
         * 1 byte ignorable varint
         */
        local_length += 2;
    }

    if (message->payload != NULL && message->payload->len != 0) {
        /*
         * 1 byte key
         * 1-4 byte payload length varint
         * n bytes payload.len
         */
        size_t payload_length = 0;
        if (s_iot_st_get_varint_size((uint32_t)message->payload->len, &payload_length)) {
            return AWS_OP_ERR;
        }
        local_length += (1 + message->payload->len + payload_length);
    }

    if (message->service_id != NULL && message->service_id->len != 0) {
        /*
         * 1 byte key
         * 1-4 byte payload length varint
         * n bytes service_id.len
         */
        size_t service_id_length = 0;
        if (s_iot_st_get_varint_size((uint32_t)message->service_id->len, &service_id_length)) {
            return AWS_OP_ERR;
        }
        local_length += (1 + message->service_id->len + service_id_length);
    }

    if (message->service_id_2 != NULL && message->service_id_2->len != 0) {
        /*
         * 1 byte key
         * 1-4 byte payload length varint
         * n bytes service_id.len
         */
        size_t service_id_length_2 = 0;
        if (s_iot_st_get_varint_size((uint32_t)message->service_id_2->len, &service_id_length_2)) {
            return AWS_OP_ERR;
        }
        local_length += (1 + message->service_id_2->len + service_id_length_2);
    }

    if (message->service_id_3 != NULL && message->service_id_3->len != 0) {
        /*
         * 1 byte key
         * 1-4 byte payload length varint
         * n bytes service_id.len
         */
        size_t service_id_length_3 = 0;
        if (s_iot_st_get_varint_size((uint32_t)message->service_id_3->len, &service_id_length_3)) {
            return AWS_OP_ERR;
        }
        local_length += (1 + message->service_id_3->len + service_id_length_3);
    }

    *message_length = local_length;
    return AWS_OP_SUCCESS;
}

int aws_iot_st_msg_serialize_from_view(
    struct aws_byte_buf *buffer,
    struct aws_allocator *allocator,
    const struct aws_secure_tunnel_message_view *message_view) {
    size_t message_total_length = 0;
    if (s_iot_st_compute_message_length(message_view, &message_total_length)) {
        return AWS_OP_ERR;
    }

    AWS_LOGF_DEBUG(
        AWS_LS_IOTDEVICE_SECURE_TUNNELING,
        "id=%p: serializing message from view of size %zu.",
        (void *)message_view,
        message_total_length);

    if (aws_byte_buf_init(buffer, allocator, message_total_length) != AWS_OP_SUCCESS) {
        return AWS_OP_ERR;
    }

    if (message_view->type != AWS_SECURE_TUNNEL_MT_UNKNOWN) {
        if (s_iot_st_encode_type(message_view->type, buffer)) {
            goto cleanup;
        }
    } else {
        AWS_LOGF_ERROR(AWS_LS_IOTDEVICE_SECURE_TUNNELING, "Message missing type during encoding");
        goto cleanup;
    }

    if (message_view->stream_id != 0) {
        if (s_iot_st_encode_stream_id(message_view->stream_id, buffer)) {
            goto cleanup;
        }
    }

    if (message_view->connection_id != 0) {
        if (s_iot_st_encode_connection_id(message_view->connection_id, buffer)) {
            goto cleanup;
        }
    }

    if (message_view->ignorable != 0) {
        if (s_iot_st_encode_ignorable(message_view->ignorable, buffer)) {
            goto cleanup;
        }
    }

    if (message_view->payload != NULL) {
        if (s_iot_st_encode_payload(message_view->payload, buffer)) {
            goto cleanup;
        }
    }

    if (message_view->type == AWS_SECURE_TUNNEL_MT_SERVICE_IDS) {
        if (message_view->service_id != 0) {
            if (s_iot_st_encode_service_ids(message_view->service_id, buffer)) {
                goto cleanup;
            }
        }
        if (message_view->service_id_2 != 0) {
            if (s_iot_st_encode_service_ids(message_view->service_id_2, buffer)) {
                goto cleanup;
            }
        }
        if (message_view->service_id_3 != 0) {
            if (s_iot_st_encode_service_ids(message_view->service_id_3, buffer)) {
                goto cleanup;
            }
        }
    } else if (message_view->service_id != NULL) {
        if (s_iot_st_encode_service_id(message_view->service_id, buffer)) {
            goto cleanup;
        }
    }

    return AWS_OP_SUCCESS;

cleanup:
    aws_byte_buf_clean_up(buffer);
    return AWS_OP_ERR;
}

/*****************************************************************************************************************
 *                                               DECODING
 *****************************************************************************************************************/

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
        AWS_RETURN_ERROR_IF2(
            aws_byte_cursor_advance(cursor, 1).ptr != NULL, AWS_ERROR_IOTDEVICE_SECURE_TUNNELING_DECODE_FAILURE);
        bits += 7;
    }
    castPtrValue = *cursor->ptr;
    AWS_RETURN_ERROR_IF2(
        aws_byte_cursor_advance(cursor, 1).ptr != NULL, AWS_ERROR_IOTDEVICE_SECURE_TUNNELING_DECODE_FAILURE);
    // Zero out the first bit
    // 0x7F == b01111111
    *result += ((castPtrValue & 0x7F) << bits);
    return AWS_OP_SUCCESS;
}

int aws_secure_tunnel_deserialize_varint_from_cursor_to_message(
    struct aws_byte_cursor *cursor,
    uint8_t field_number,
    struct aws_secure_tunnel_message_view *message) {
    uint32_t result = 0;

    if (s_iot_st_decode_varint_uint32_t(cursor, &result)) {
        return AWS_OP_ERR;
    }

    switch (field_number) {
        case AWS_SECURE_TUNNEL_FN_TYPE:
            message->type = result;
            break;
        case AWS_SECURE_TUNNEL_FN_STREAM_ID:
            message->stream_id = result;
            break;
        case AWS_SECURE_TUNNEL_FN_IGNORABLE:
            message->ignorable = result;
            break;
        case AWS_SECURE_TUNNEL_FN_CONNECTION_ID:
            message->connection_id = result;
            break;
        default:
            AWS_LOGF_WARN(
                AWS_LS_IOTDEVICE_SECURE_TUNNELING,
                "id=%p: Unexpected field number in message encountered.",
                (void *)message);
            /* Unexpected field_number */
            break;
    }

    return AWS_OP_SUCCESS;
}

int aws_secure_tunnel_deserialize_message_from_cursor(
    struct aws_secure_tunnel *secure_tunnel,
    struct aws_byte_cursor *cursor,
    aws_secure_tunnel_on_message_received_fn *on_message_received) {

    AWS_LOGF_DEBUG(
        AWS_LS_IOTDEVICE_SECURE_TUNNELING,
        "id=%p: deserializing message from cursor of size %zu.",
        (void *)secure_tunnel,
        cursor->len);

    uint8_t wire_type;
    uint8_t field_number;
    struct aws_secure_tunnel_message_view message_view;
    AWS_ZERO_STRUCT(message_view);

    struct aws_byte_cursor payload_cur;
    AWS_ZERO_STRUCT(payload_cur);

    int service_ids_set = 0;
    struct aws_byte_cursor service_id_1_cur;
    struct aws_byte_cursor service_id_2_cur;
    struct aws_byte_cursor service_id_3_cur;
    AWS_ZERO_STRUCT(service_id_1_cur);
    AWS_ZERO_STRUCT(service_id_2_cur);
    AWS_ZERO_STRUCT(service_id_3_cur);

    while ((aws_byte_cursor_is_valid(cursor)) && (cursor->len > 0)) {
        // wire_type is only the first 3 bits, Zeroing out the first 5
        // 0x07 == 00000111
        wire_type = *cursor->ptr & 0x07;
        field_number = (*cursor->ptr) >> 3;
        aws_byte_cursor_advance(cursor, 1);

        /* ignorable defaults to false unless set to true in the incoming message*/
        message_view.ignorable = false;

        switch (wire_type) {
            case AWS_SECURE_TUNNEL_PBWT_VARINT:
                if (aws_secure_tunnel_deserialize_varint_from_cursor_to_message(cursor, field_number, &message_view)) {
                    goto error;
                }
                break;

            case AWS_SECURE_TUNNEL_PBWT_LENGTH_DELIMITED: {

                uint32_t length = 0;
                if (s_iot_st_decode_varint_uint32_t(cursor, &length)) {
                    goto error;
                }

                switch (field_number) {
                    case AWS_SECURE_TUNNEL_FN_PAYLOAD:
                        payload_cur = aws_byte_cursor_advance(cursor, length);
                        message_view.payload = &payload_cur;
                        break;

                    case AWS_SECURE_TUNNEL_FN_SERVICE_ID:
                        service_id_1_cur = aws_byte_cursor_advance(cursor, length);
                        message_view.service_id = &service_id_1_cur;
                        break;

                    case AWS_SECURE_TUNNEL_FN_AVAILABLE_SERVICE_IDS:
                        switch (service_ids_set) {
                            case 0:
                                service_id_1_cur = aws_byte_cursor_advance(cursor, length);
                                message_view.service_id = &service_id_1_cur;
                                break;
                            case 1:
                                service_id_2_cur = aws_byte_cursor_advance(cursor, length);
                                message_view.service_id_2 = &service_id_2_cur;
                                break;
                            case 2:
                                service_id_3_cur = aws_byte_cursor_advance(cursor, length);
                                message_view.service_id_3 = &service_id_3_cur;
                                break;
                            default:
                                goto error;
                                break;
                        }
                        service_ids_set++;
                        break;
                }
            } break;

                /* These wire types are unexpected and should result in an error log */
            case AWS_SECURE_TUNNEL_PBWT_64_BIT:
            case AWS_SECURE_TUNNEL_PBWT_START_GROUP:
            case AWS_SECURE_TUNNEL_PBWT_END_GROUP:
            case AWS_SECURE_TUNNEL_PBWT_32_BIT:
                AWS_LOGF_ERROR(
                    AWS_LS_IOTDEVICE_SECURE_TUNNELING,
                    "id=%p: Unexpected wire type in message encountered.",
                    (void *)secure_tunnel);
                goto error;
                break;
        }
    }

    on_message_received(secure_tunnel, &message_view);

    return AWS_OP_SUCCESS;

error:
    return aws_raise_error(AWS_ERROR_IOTDEVICE_SECURE_TUNNELING_DECODE_FAILURE);
}
