/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#ifndef AWS_IOTDEVICE_SERIALIZER_H
#define AWS_IOTDEVICE_SERIALIZER_H

#include <aws/iotdevice/iotdevice.h>

#include <aws/common/byte_buf.h>

#define AWS_IOT_ST_FIELD_NUMBER_SHIFT 3

#define AWS_IOT_ST_MAXIMUM_VARINT 268435455
#define AWS_IOT_ST_MAX_MESSAGE_SIZE 64 * 1024
#define AWS_IOT_ST_MAX_PAYLOAD_SIZE 64512


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
    AWS_SECURE_TUNNEL_PBWT_VARINT = 0,            /* int32, int64, uint32, uint64, sint32, sint64, bool, enum */
    AWS_SECURE_TUNNEL_PBWT_64_BIT = 1,            /* fixed64, sfixed64, double */
    AWS_SECURE_TUNNEL_PBWT_LENGTH_DELIMINTED = 2, /* string, bytes, embedded messages, packed repeated fields */
    AWS_SECURE_TUNNEL_PBWT_START_GROUP = 3,       /* groups (deprecated) */
    AWS_SECURE_TUNNEL_PBWT_END_GROUP = 4,         /* groups (deprecated) */
    AWS_SECURE_TUNNEL_PBWT_32_BIT = 5,            /* fixed32, sfixed32, float */
};

/**
 * Type of IoT Secure Tunnel message.
 * Enum values match IoT Secure Tunneling Local Proxy V3 Websocket Protocol Guide values.
 *
 * https://github.com/aws-samples/aws-iot-securetunneling-localproxy/blob/main/V3WebSocketProtocolGuide.md
 */
enum aws_secure_tunnel_message_type {
    AWS_SECURE_TUNNEL_MT_UNKNOWN = 0,

    /**
     * Data messages carry a payload with a sequence of bytes to write to the the active data stream
     */
    AWS_SECURE_TUNNEL_MT_DATA = 1,

    /**
     * StreamStart is the first message sent to start and establish a new and active data stream. This should only be
     * sent from a Source to a Destination.
     */
    AWS_SECURE_TUNNEL_MT_STREAM_START = 2,

    /**
     * StreamReset messages convey that the data stream has ended, either in error, or closed intentionally for the
     * tunnel peer. It is also sent to the source tunnel peer if an attempt to establish a new data stream fails on the
     * destination side.
     */
    AWS_SECURE_TUNNEL_MT_STREAM_RESET = 3,

    /**
     * SessionReset messages can only originate from Secure Tunneling service if an internal data transmission error is
     * detected. This will result in all active streams being closed.
     */
    AWS_SECURE_TUNNEL_MT_SESSION_RESET = 4,

    /**
     * ServiceIDs messages can only originate from the Secure Tunneling service and carry a list of unique service IDs
     * used when opening a tunnel with services.
     */
    AWS_SECURE_TUNNEL_MT_SERVICE_IDS = 5,

    /**
     * ConnectionStart is the message sent to start and establish a new and active connection when the stream has been
     * established and there's one active connection in the stream.
     */
    AWS_SECURE_TUNNEL_MT_CONNECTION_START = 6,

    /**
     * ConnectionReset messages convey that the connection has ended, either in error, or closed intentionally for the
     * tunnel peer.
     */
    AWS_SECURE_TUNNEL_MT_CONNECTION_RESET = 7
};

/**
 * A single IoT Secure Tunnel Message
 */
struct aws_iot_st_msg {
    enum aws_secure_tunnel_message_type type;
    int32_t stream_id;
    int ignorable;
    struct aws_byte_buf payload;
    struct aws_byte_buf service_id;
    uint32_t connection_id;
};

AWS_EXTERN_C_BEGIN

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

AWS_EXTERN_C_END

#endif
