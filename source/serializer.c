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

static int s_iot_st_encode_stream_id(int32_t data, struct aws_byte_buf *buffer) {
    return s_iot_st_encode_varint(AWS_SECURE_TUNNEL_FN_STREAM_ID, AWS_SECURE_TUNNEL_PBWT_VARINT, data, buffer);
}

static int s_iot_st_encode_ignorable(int32_t data, struct aws_byte_buf *buffer) {
    return s_iot_st_encode_varint(AWS_SECURE_TUNNEL_FN_IGNORABLE, AWS_SECURE_TUNNEL_PBWT_VARINT, data, buffer);
}

static int s_iot_st_encode_type(int32_t data, struct aws_byte_buf *buffer) {
    return s_iot_st_encode_varint(AWS_SECURE_TUNNEL_FN_TYPE, AWS_SECURE_TUNNEL_PBWT_VARINT, data, buffer);
}

static int s_iot_st_encode_payload(struct aws_byte_buf *payload, struct aws_byte_buf *buffer) {
    return s_iot_st_encode_lengthdelim(
        AWS_SECURE_TUNNEL_FN_PAYLOAD, AWS_SECURE_TUNNEL_PBWT_LENGTH_DELIMINTED, payload, buffer);
}

static int s_iot_st_encode_service_id(struct aws_byte_buf *service_id, struct aws_byte_buf *buffer) {
    return s_iot_st_encode_lengthdelim(
        AWS_SECURE_TUNNEL_FN_SERVICE_ID, AWS_SECURE_TUNNEL_PBWT_LENGTH_DELIMINTED, service_id, buffer);
}

static int s_iot_st_encode_connection_id(uint32_t data, struct aws_byte_buf *buffer) {
    return s_iot_st_encode_varint(AWS_SECURE_TUNNEL_FN_CONNECTION_ID, AWS_SECURE_TUNNEL_PBWT_VARINT, data, buffer);
}

static int s_iot_st_get_varint_size(size_t value, size_t *encode_size) {
    if (value > AWS_IOT_ST_MAXIMUM_VARINT) {
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }

    if (value < 128) {
        *encode_size = 1;
    } else if (value < 16384) {
        *encode_size = 2;
    } else if (value < 2097152) {
        *encode_size = 3;
    } else {
        *encode_size = 4;
    }

    return AWS_OP_SUCCESS;
}

static int s_iot_st_compute_message_length(const struct aws_iot_st_msg *message, size_t *message_length) {
    fprintf(stdout, "\ns_iot_st_compute_message_length()\ntype: %d\n", message->type);
    size_t local_length = 0;

    /*
     * 1 byte type key
     * 1 byte type varint
     */
    local_length += 2;

    if (message->stream_id != 0) {
        /*
         * 1 byte steram_id key
         * 1-4 byte stream_id varint
         */
        size_t stream_id_length = 0;

        if (s_iot_st_get_varint_size((uint32_t)message->stream_id, &stream_id_length)) {
            return AWS_OP_ERR;
        }

        local_length += (1 + stream_id_length);
        fprintf(stdout, "adding stream_id:%d total:%zu\n", message->stream_id, local_length);
    }

    if (message->ignorable != 0) {
        /*
         * 1 byte ignorable key
         * 1 byte ignorable varint
         */
        local_length += 2;
        fprintf(stdout, "adding ignorable total:%zu\n", local_length);
    }

    if (message->payload.len != 0) {
        /*
         * 1 byte key
         * 1-4 byte payload length varint
         * n bytes payload.len
         */
        size_t payload_length = 0;
        if (s_iot_st_get_varint_size((uint32_t)message->payload.len, &payload_length)) {
            return AWS_OP_ERR;
        }
        local_length += (1 + message->payload.len + payload_length);
        fprintf(stdout, "adding message total:%zu\n", local_length);
    }

    if (message->service_id.len != 0) {
        /*
         * 1 byte key
         * 1-4 byte payload length varint
         * n bytes service_id.len
         */
        size_t service_id_length = 0;
        if (s_iot_st_get_varint_size((uint32_t)message->service_id.len, &service_id_length)) {
            return AWS_OP_ERR;
        }
        local_length += (1 + message->service_id.len + service_id_length);
        fprintf(stdout, "adding service_id total:%zu\n", local_length);
    }

    if (message->connection_id != 0) {
        /*
         * 1 byte connection_id key
         * 1-4 byte connection_id varint
         */
        size_t connection_id_length = 0;

        if (s_iot_st_get_varint_size((uint32_t)message->connection_id, &connection_id_length)) {
            return AWS_OP_ERR;
        }

        local_length += (1 + connection_id_length);
        fprintf(stdout, "adding connection_id total:%zu\n", local_length);
    }

    *message_length = local_length;
    return AWS_OP_SUCCESS;
}

int aws_iot_st_msg_serialize_from_struct(
    struct aws_byte_buf *buffer,
    struct aws_allocator *allocator,
    struct aws_iot_st_msg message) {
    fprintf(stdout, "\naws_iot_st_msg_serialize_from_struct()\n");

    size_t message_total_length = 0;
    if (s_iot_st_compute_message_length(&message, &message_total_length)) {
        return AWS_OP_ERR;
    }

    if (aws_byte_buf_init(buffer, allocator, message_total_length) != AWS_OP_SUCCESS) {
        return AWS_OP_ERR;
    }

    if (message.type != AWS_SECURE_TUNNEL_MT_UNKNOWN) {
        if (s_iot_st_encode_type(message.type, buffer)) {
            goto cleanup;
        }
    }

    fprintf(stdout, "message type encoded. buf length: %zu\n", buffer->len);

    if (message.stream_id != 0) {
        if (s_iot_st_encode_stream_id(message.stream_id, buffer)) {
            goto cleanup;
        }
    }
    fprintf(stdout, "stream id encoded. buf length: %zu\n", buffer->len);

    if (message.ignorable != 0) {
        if (s_iot_st_encode_ignorable(message.ignorable, buffer)) {
            goto cleanup;
        }
    }
    fprintf(stdout, "ignorable encoded. buf length: %zu\n", buffer->len);

    if (message.payload.len != 0) {
        if (s_iot_st_encode_payload(&message.payload, buffer)) {
            goto cleanup;
        }
    }
    fprintf(stdout, "payload encoded. buf length: %zu\n", buffer->len);

    if (message.service_id.len != 0) {
        if (s_iot_st_encode_service_id(&message.service_id, buffer)) {
            goto cleanup;
        }
    }
    fprintf(stdout, "service id encoded. buf length: %zu\n", buffer->len);

    if (message.connection_id != 0) {
        if (s_iot_st_encode_connection_id(message.connection_id, buffer)) {
            goto cleanup;
        }
    }
    fprintf(stdout, "connection id encoded. buf length: %zu\n", buffer->len);

    AWS_RETURN_ERROR_IF2(buffer->capacity < AWS_IOT_ST_MAX_MESSAGE_SIZE, AWS_ERROR_INVALID_BUFFER_SIZE);
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

static int s_aws_st_decode_lengthdelim(struct aws_byte_cursor *cursor, struct aws_byte_buf *buffer, int length) {
    struct aws_byte_cursor temp = aws_byte_cursor_from_array(cursor->ptr, length);
    AWS_RETURN_ERROR_IF2(aws_byte_buf_append_dynamic_secure(buffer, &temp) == 0, AWS_OP_ERR);
    return AWS_OP_SUCCESS;
}

int aws_secure_tunnel_deserialize_message_from_cursor(
    struct aws_secure_tunnel *secure_tunnel,
    struct aws_secure_tunnel_message_view *message,
    struct aws_byte_cursor *cursor,
    aws_secure_tunnel_on_message_received_fn *on_message_received) {
    printf("\n\naws_secure_tunnel_deserialize_message_from_cursor()\n\n");
    AWS_RETURN_ERROR_IF2(cursor->len < AWS_IOT_ST_MAX_MESSAGE_SIZE, AWS_ERROR_INVALID_BUFFER_SIZE);
    uint8_t wire_type;
    uint8_t field_number;
    struct aws_byte_buf payload_buf;
    struct aws_byte_buf service_id_buf;
    struct aws_byte_buf available_service_id_buf;

    AWS_ZERO_STRUCT(payload_buf);
    AWS_ZERO_STRUCT(service_id_buf);
    int service_ids_set = 0;

    while ((aws_byte_cursor_is_valid(cursor)) && (cursor->len > 0)) {
        // wire_type is only the first 3 bits, Zeroing out the first 5
        // 0x07 == 00000111
        wire_type = *cursor->ptr & 0x07;
        field_number = (*cursor->ptr) >> 3;
        aws_byte_cursor_advance(cursor, 1);

        /* ignorable defaults to false unless set to true in the incoming message*/
        message->ignorable = false;

        switch (wire_type) {
            case AWS_SECURE_TUNNEL_PBWT_VARINT: {
                uint32_t res = 0;
                if (s_iot_st_decode_varint_uint32_t(cursor, &res)) {
                    return AWS_OP_ERR;
                }

                switch (field_number) {
                    case AWS_SECURE_TUNNEL_FN_TYPE:
                        message->type = res;
                        break;
                    case AWS_SECURE_TUNNEL_FN_STREAM_ID:
                        message->stream_id = res;
                        break;
                    case AWS_SECURE_TUNNEL_FN_IGNORABLE:
                        message->ignorable = res;
                        break;
                    default:
                        /* Unexpected field_number */
                        break;
                }
            } break;

            case AWS_SECURE_TUNNEL_PBWT_LENGTH_DELIMINTED: {
                uint32_t length = 0;
                if (s_iot_st_decode_varint_uint32_t(cursor, &length)) {
                    goto error;
                }

                switch (field_number) {
                    case AWS_SECURE_TUNNEL_FN_PAYLOAD:
                        if (aws_byte_buf_init(&payload_buf, secure_tunnel->allocator, length) ||
                            s_aws_st_decode_lengthdelim(cursor, &payload_buf, length)) {
                            goto error;
                        }
                        aws_byte_cursor_advance(cursor, length);
                        message->payload = aws_byte_cursor_from_buf(&payload_buf);
                        break;

                    case AWS_SECURE_TUNNEL_FN_SERVICE_ID:
                        if (aws_byte_buf_init(&service_id_buf, secure_tunnel->allocator, length) ||
                            s_aws_st_decode_lengthdelim(cursor, &service_id_buf, length)) {
                            goto error;
                        }
                        aws_byte_cursor_advance(cursor, length);
                        message->service_id = aws_byte_cursor_from_buf(&service_id_buf);
                        break;

                    case AWS_SECURE_TUNNEL_FN_AVAILABLE_SERVICE_IDS:
                        AWS_ZERO_STRUCT(available_service_id_buf);
                        if (aws_byte_buf_init(&available_service_id_buf, secure_tunnel->allocator, length) ||
                            s_aws_st_decode_lengthdelim(cursor, &available_service_id_buf, length)) {
                            goto error;
                        }
                        aws_byte_cursor_advance(cursor, length);
                        switch (service_ids_set) {
                            case 0:
                                if (secure_tunnel->config->service_id_1) {
                                    aws_string_destroy(secure_tunnel->config->service_id_1);
                                }
                                secure_tunnel->config->service_id_1 =
                                    aws_string_new_from_buf(secure_tunnel->allocator, &available_service_id_buf);
                                break;
                            case 1:
                                if (secure_tunnel->config->service_id_2) {
                                    aws_string_destroy(secure_tunnel->config->service_id_2);
                                }
                                secure_tunnel->config->service_id_2 =
                                    aws_string_new_from_buf(secure_tunnel->allocator, &available_service_id_buf);
                                break;
                            case 2:
                                if (secure_tunnel->config->service_id_3) {
                                    aws_string_destroy(secure_tunnel->config->service_id_3);
                                }
                                secure_tunnel->config->service_id_3 =
                                    aws_string_new_from_buf(secure_tunnel->allocator, &available_service_id_buf);
                                break;
                            default:
                                aws_byte_buf_clean_up(&available_service_id_buf);
                                goto error;
                                break;
                        }

                        aws_byte_buf_clean_up(&available_service_id_buf);
                        service_ids_set++;
                        break;
                }
            } break;

                /* These wire types are unexpected and should result in an error log */
            case AWS_SECURE_TUNNEL_PBWT_64_BIT:
            case AWS_SECURE_TUNNEL_PBWT_START_GROUP:
            case AWS_SECURE_TUNNEL_PBWT_END_GROUP:
            case AWS_SECURE_TUNNEL_PBWT_32_BIT:
                goto error;
                break;
        }
    }

    on_message_received(secure_tunnel, message);
    aws_byte_buf_clean_up(&payload_buf);
    aws_byte_buf_clean_up(&service_id_buf);
    return AWS_OP_SUCCESS;

error:
    aws_byte_buf_clean_up(&payload_buf);
    aws_byte_buf_clean_up(&service_id_buf);
    return AWS_OP_ERR;
}

const char *aws_secure_tunnel_message_type_to_c_string(enum aws_secure_tunnel_message_type message_type) {
    switch (message_type) {
        case AWS_SECURE_TUNNEL_MT_UNKNOWN:
            return "UNKNOWN";

        case AWS_SECURE_TUNNEL_MT_DATA:
            return "DATA";

        case AWS_SECURE_TUNNEL_MT_STREAM_START:
            return "STREAM START";

        case AWS_SECURE_TUNNEL_MT_STREAM_RESET:
            return "STREAM RESET";

        case AWS_SECURE_TUNNEL_MT_SESSION_RESET:
            return "SESSION RESET";

        case AWS_SECURE_TUNNEL_MT_SERVICE_IDS:
            return "SERVICE IDS";

        case AWS_SECURE_TUNNEL_MT_CONNECTION_START:
            return "CONNECTION START";

        case AWS_SECURE_TUNNEL_MT_CONNECTION_RESET:
            return "CONNECTION RESET";

        default:
            return "UNKNOWN";
    }
}
