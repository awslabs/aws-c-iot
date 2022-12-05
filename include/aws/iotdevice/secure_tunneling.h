/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#ifndef AWS_IOTDEVICE_SECURE_TUNNELING_H
#define AWS_IOTDEVICE_SECURE_TUNNELING_H

#include <aws/common/byte_buf.h>
#include <aws/iotdevice/iotdevice.h>

#define AWS_IOT_ST_SPLIT_MESSAGE_SIZE 15000

enum aws_secure_tunneling_local_proxy_mode { AWS_SECURE_TUNNELING_SOURCE_MODE, AWS_SECURE_TUNNELING_DESTINATION_MODE };

struct aws_secure_tunnel;
struct aws_websocket;
struct aws_websocket_incoming_frame;
struct aws_http_proxy_options;

/*
 * Views
 */

/**
 * Read-only snapshot of Data Message
 */

struct aws_secure_tunnel_message_data_view {
    int32_t stream_id;
    struct aws_byte_cursor service_id;
    struct aws_byte_cursor payload;
};

/**
 * Read-only snapshot of Stream Message
 * Used with Stream Start and Stream Reset message types
 */
struct aws_secure_tunnel_message_stream_view {
    int32_t stream_id;
    const struct aws_byte_cursor *service_id;
};

/* Callbacks */
typedef void(aws_secure_tunneling_on_connection_complete_fn)(void *user_data);
typedef void(aws_secure_tunneling_on_connection_shutdown_fn)(void *user_data);
typedef void(aws_secure_tunneling_on_send_data_complete_fn)(int error_code, void *user_data);
typedef void(aws_secure_tunneling_on_data_receive_fn)(const struct aws_byte_buf *data, void *user_data);
typedef void(aws_secure_tunneling_on_data_receive_v3_fn)(
    const struct aws_byte_cursor service_id,
    int connection_id,
    const struct aws_byte_buf *data,
    void *user_data);
typedef void(aws_secure_tunneling_on_stream_start_fn)(void *user_data);
typedef void(aws_secure_tunneling_on_stream_reset_fn)(void *user_data);
typedef void(aws_secure_tunneling_on_session_reset_fn)(void *user_data);
typedef void(aws_secure_tunneling_on_termination_complete_fn)(void *user_data);

struct aws_secure_tunnel_options {
    struct aws_allocator *allocator;
    struct aws_client_bootstrap *bootstrap;
    const struct aws_socket_options *socket_options;
    const struct aws_http_proxy_options *http_proxy_options;

    struct aws_byte_cursor access_token;
    struct aws_byte_cursor endpoint_host;
    enum aws_secure_tunneling_local_proxy_mode local_proxy_mode;
    const char *root_ca;
    const char *service_id_1;
    const char *service_id_2;
    const char *service_id_3;

    aws_secure_tunneling_on_connection_complete_fn *on_connection_complete;
    aws_secure_tunneling_on_connection_shutdown_fn *on_connection_shutdown;
    aws_secure_tunneling_on_send_data_complete_fn *on_send_data_complete;
    aws_secure_tunneling_on_data_receive_fn *on_data_receive;
    aws_secure_tunneling_on_data_receive_v3_fn *on_data_receive_v3;
    aws_secure_tunneling_on_stream_start_fn *on_stream_start;
    aws_secure_tunneling_on_stream_reset_fn *on_stream_reset;
    aws_secure_tunneling_on_session_reset_fn *on_session_reset;
    aws_secure_tunneling_on_termination_complete_fn *on_termination_complete;

    void *user_data;
};

/**
 * Signature of callback to invoke when a DISCONNECT is fully written to the socket (or fails to be)
 */
typedef void(aws_secure_tunnel_disconnect_completion_fn)(int error_code, void *complete_ctx);

/**
 * Public completion callback options for the DISCONNECT operation
 */
struct aws_secure_tunnel_disconnect_completion_options {
    aws_secure_tunnel_disconnect_completion_fn *completion_callback;
    void *completion_user_data;
}

/* deprecated: "_config" is renamed "_options" for consistency with similar code in the aws-c libraries */
#define aws_secure_tunneling_connection_config aws_secure_tunnel_options

/**
 * Persistent storage for aws_secure_tunnel_options.
 */
struct aws_secure_tunnel_options_storage;

AWS_EXTERN_C_BEGIN

AWS_IOTDEVICE_API
struct aws_secure_tunnel *aws_secure_tunnel_new(const struct aws_secure_tunnel_options *options);

AWS_IOTDEVICE_API
struct aws_secure_tunnel *aws_secure_tunnel_acquire(struct aws_secure_tunnel *secure_tunnel);

AWS_IOTDEVICE_API
int aws_secure_tunnel_get_connection_error_code(struct aws_secure_tunnel *secure_tunnel);

AWS_IOTDEVICE_API
void aws_secure_tunnel_release(struct aws_secure_tunnel *secure_tunnel);

AWS_IOTDEVICE_API
int aws_secure_tunnel_connect(struct aws_secure_tunnel *secure_tunnel);

AWS_IOTDEVICE_API
int aws_secure_tunnel_close(struct aws_secure_tunnel *secure_tunnel);

AWS_IOTDEVICE_API
int aws_secure_tunnel_send_data(struct aws_secure_tunnel *secure_tunnel, const struct aws_byte_cursor *data);

AWS_IOTDEVICE_API
int aws_secure_tunnel_send_data_v2(
    struct aws_secure_tunnel *secure_tunnel,
    const struct aws_secure_tunnel_message_data_view *data_options);

AWS_IOTDEVICE_API
int aws_secure_tunnel_stream_start(struct aws_secure_tunnel *secure_tunnel);

AWS_IOTDEVICE_API
int aws_secure_tunnel_stream_start_v2(
    struct aws_secure_tunnel *secure_tunnel,
    const struct aws_byte_cursor *service_id_data);

AWS_IOTDEVICE_API
int aws_secure_tunnel_stream_reset(struct aws_secure_tunnel *secure_tunnel);

/**
 * Raises exception and returns AWS_OP_ERR if options are missing required parameters.
 */
AWS_IOTDEVICE_API
int aws_secure_tunnel_options_validate(const struct aws_secure_tunnel_options *options);

/**
 * Create persistent storage for aws_secure_tunnel_options.
 * Makes a deep copy of (or acquires reference to) any data referenced by options,
 */
AWS_IOTDEVICE_API
struct aws_secure_tunnel_options_storage *aws_secure_tunnel_options_storage_new(
    const struct aws_secure_tunnel_options *options);

/**
 * Destroy options storage, and release any references held.
 */
AWS_IOTDEVICE_API
void aws_secure_tunnel_options_storage_destroy(struct aws_secure_tunnel_options_storage *storage);

/**
 * Return pointer to options struct stored within.
 */
AWS_IOTDEVICE_API
const struct aws_secure_tunnel_options *aws_secure_tunnel_options_storage_get(
    const struct aws_secure_tunnel_options_storage *storage);

/* Making this exposed public to verify testing in the sdk layer */
AWS_IOTDEVICE_API
bool on_websocket_incoming_frame_payload(
    struct aws_websocket *websocket,
    const struct aws_websocket_incoming_frame *frame,
    struct aws_byte_cursor data,
    void *user_data);

AWS_EXTERN_C_END

#endif /* AWS_IOTDEVICE_SECURE_TUNNELING_H */
