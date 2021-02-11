/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#ifndef AWS_IOTDEVICE_IOT_TESTING_H
#define AWS_IOTDEVICE_IOT_TESTING_H

#include <aws/iotdevice/private/serializer.h>

struct aws_byte_buf;
struct aws_byte_cursor;
struct aws_secure_tunnel;
struct aws_websocket;
struct aws_websocket_client_connection_options;
struct aws_websocket_send_frame_options;

AWS_EXTERN_C_BEGIN

AWS_IOTDEVICE_API
int secure_tunneling_init_send_frame(
    struct aws_websocket_send_frame_options *frame_options,
    struct aws_secure_tunnel *secure_tunnel,
    const struct aws_byte_cursor *data,
    enum aws_iot_st_message_type type);

AWS_IOTDEVICE_API
void init_websocket_client_connection_options(
    struct aws_secure_tunnel *secure_tunnel,
    struct aws_websocket_client_connection_options *websocket_options);

AWS_IOTDEVICE_API
int secure_tunneling_init_send_frame(
    struct aws_websocket_send_frame_options *frame_options,
    struct aws_secure_tunnel *secure_tunnel,
    const struct aws_byte_cursor *data,
    enum aws_iot_st_message_type type);

AWS_IOTDEVICE_API
bool secure_tunneling_send_data_call(struct aws_websocket *websocket, struct aws_byte_buf *out_buf, void *user_data);

AWS_EXTERN_C_END

#endif /* AWS_IOTDEVICE_IOT_TESTING_H */
