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
 * Read-only snapshot of secure tunnel Message
 */

struct aws_secure_tunnel_message_view {
    int32_t stream_id;
    struct aws_byte_cursor service_id;
    struct aws_byte_cursor payload;
};

/* Callbacks */
typedef void(aws_secure_tunneling_on_connection_complete_fn)(void *user_data);
typedef void(aws_secure_tunneling_on_connection_shutdown_fn)(void *user_data);
typedef void(aws_secure_tunneling_on_send_data_complete_fn)(int error_code, void *user_data);
typedef void(aws_secure_tunneling_on_data_receive_fn)(const struct aws_byte_buf *data, void *user_data);
typedef void(
    aws_secure_tunneling_on_data_receive_new_fn)(const struct aws_secure_tunnel_message_view *message, void *user_data);
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
    /* Steve TODO we only support destination mode so this can be removed outside of testing */
    enum aws_secure_tunneling_local_proxy_mode local_proxy_mode;
    const char *root_ca;
    const char *service_id_1;
    const char *service_id_2;
    const char *service_id_3;

    aws_secure_tunneling_on_connection_complete_fn *on_connection_complete;
    aws_secure_tunneling_on_connection_shutdown_fn *on_connection_shutdown;
    aws_secure_tunneling_on_send_data_complete_fn *on_send_data_complete;
    aws_secure_tunneling_on_data_receive_fn *on_data_receive;
    aws_secure_tunneling_on_data_receive_new_fn *on_data_receive_new;
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
};

/* deprecated: "_config" is renamed "_options" for consistency with similar code in the aws-c libraries */
#define aws_secure_tunneling_connection_config aws_secure_tunnel_options

/**
 * Persistent storage for aws_secure_tunnel_options.
 */
struct aws_secure_tunnel_options_storage;

AWS_EXTERN_C_BEGIN

/**
 * Creates a new secure tunnel
 *
 * @param options secure tunnel configuration
 * @return a new secure tunnel or NULL
 */
AWS_IOTDEVICE_API
struct aws_secure_tunnel *aws_secure_tunnel_new(const struct aws_secure_tunnel_options *options);

/**
 * Acquires a reference to a secure tunnel
 *
 * @param secure_tunnel secure tunnel to acquire a reference to. May be NULL
 * @return what was passed in as the secure tunnel (a client or NULL)
 */
AWS_IOTDEVICE_API
struct aws_secure_tunnel *aws_secure_tunnel_acquire(struct aws_secure_tunnel *secure_tunnel);

/**
 * Release a reference to a secure tunnel. When the secure tunnel ref count drops to zero, the secure tunnel
 * will automatically trigger a stop and once the stop completes, the secure tunnel will delete itself.
 *
 * @param secure_tunnel secure tunnel to release a reference to. May be NULL
 * @return NULL
 */
AWS_IOTDEVICE_API
void aws_secure_tunnel_release(struct aws_secure_tunnel *secure_tunnel);

/* TODO STEVE NEW replace aws_secure_tunnel_connect and put it in a state where it wants to be connected */
/**
 * Asynchronous notify to the secure tunnel that you want it to attempt to connect.
 * The secure tunnel will attempt to stay connected.
 *
 * @param secure_tunnel secure tunnel to start
 * @return success/failure in the synchronous logic that kicks off the start process
 */
AWS_IOTDEVICE_API
int aws_secure_tunnel_start(struct aws_secure_tunnel *secure_tunnel);

/* TODO STEVE NEW replace aws_secure_tunnel_close and put it in a state where it wants to be disconnected */
/**
 * Asynchronous notify to the secure tunnel that you want it to transition to the stopped state. When the
 * secure tunnel reaches the stopped state, all session state is erased.
 *
 * @param secure_tunnel secure tunnel to stop
 * @return success/failure in the synchronous logic that kicks off the start process
 */
AWS_IOTDEVICE_API
int aws_secure_tunnel_stop(struct aws_secure_tunnel *secure_tunnel);

/* TODO STEVE depricate in favor of aws_secure_tunnel_start */
AWS_IOTDEVICE_API
int aws_secure_tunnel_connect(struct aws_secure_tunnel *secure_tunnel);

/* TODO STEVE depricate in favor of aws_secure_tunnel_stop */
AWS_IOTDEVICE_API
int aws_secure_tunnel_close(struct aws_secure_tunnel *secure_tunnel);

/* TODO STEVE depricate/replace with new API below */
AWS_IOTDEVICE_API
int aws_secure_tunnel_send_data(struct aws_secure_tunnel *secure_tunnel, const struct aws_byte_cursor *data);

/**
 * Queues a message operation in a secure tunnel
 *
 * @param secure_tunnel secure tunnel to queue a message for
 * @param message_options configuration options for the message operation
 * @return success/failure in the synchronous logic that kicks off the message operation
 */
AWS_IOTDEVICE_API
int aws_secure_tunnel_send_message_new(
    struct aws_secure_tunnel *secure_tunnel,
    const struct aws_secure_tunnel_message_view *message_options);

/* TODO STEVE depricate/remove. Destination device does not send a stream start. Keep only for internal testing */
AWS_IOTDEVICE_API
int aws_secure_tunnel_stream_start(struct aws_secure_tunnel *secure_tunnel);

/* TODO STEVE see above. Remove or leave solely for testing purposes */
AWS_IOTDEVICE_API
int aws_secure_tunnel_stream_start_new(
    struct aws_secure_tunnel *secure_tunnel,
    const struct aws_secure_tunnel_message_view *message_options);

/* Making this exposed public to verify testing in the sdk layer */
AWS_IOTDEVICE_API
bool on_websocket_incoming_frame_payload(
    struct aws_websocket *websocket,
    const struct aws_websocket_incoming_frame *frame,
    struct aws_byte_cursor data,
    void *user_data);

AWS_EXTERN_C_END

#endif /* AWS_IOTDEVICE_SECURE_TUNNELING_H */
