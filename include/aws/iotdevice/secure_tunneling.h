/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#ifndef AWS_IOTDEVICE_SECURE_TUNNELING_H
#define AWS_IOTDEVICE_SECURE_TUNNELING_H

#include <aws/common/byte_buf.h>
#include <aws/iotdevice/iotdevice.h>

#define AWS_IOT_ST_SPLIT_MESSAGE_SIZE 15000

struct aws_secure_tunnel;
struct aws_websocket;
struct aws_websocket_incoming_frame;
struct aws_http_proxy_options;

/* STEVE TODO remove or move to private. We only support Destination Mode */
enum aws_secure_tunneling_local_proxy_mode { AWS_SECURE_TUNNELING_SOURCE_MODE, AWS_SECURE_TUNNELING_DESTINATION_MODE };

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
 * Read-only snapshot of a Secure Tunnel Message
 */
struct aws_secure_tunnel_message_view {

    enum aws_secure_tunnel_message_type type;

    /**
     * If a message is received and its type is unrecognized, and this field is set to true, it is ok for the tunnel
     * client to ignore the message safely. If this field is unset, it must be considered as false.
     */
    bool ignorable;

    int32_t stream_id;

    /**
     * Secure tunnel multiplexing identifier
     */
    struct aws_byte_cursor service_id;
    struct aws_byte_cursor payload;
};

/* Callbacks */

/**
 * Signature of callback to invoke on received messages
 */
typedef void(
    aws_secure_tunnel_message_received_fn)(const struct aws_secure_tunnel_message_view *message, void *user_data);

/* STEVE TODO Old callbacks can probably be removed */
typedef void(aws_secure_tunneling_on_connection_complete_fn)(void *user_data);
typedef void(aws_secure_tunneling_on_connection_shutdown_fn)(void *user_data);
typedef void(aws_secure_tunneling_on_send_data_complete_fn)(int error_code, void *user_data);
typedef void(aws_secure_tunneling_on_data_receive_fn)(const struct aws_byte_buf *data, void *user_data);
typedef void(aws_secure_tunneling_on_stream_start_fn)(
    const struct aws_secure_tunnel_message_view *message,
    int error_code,
    void *user_data);
typedef void(aws_secure_tunneling_on_stream_reset_fn)(
    const struct aws_secure_tunnel_message_view *message,
    int error_code,
    void *user_data);
typedef void(aws_secure_tunneling_on_session_reset_fn)(void *user_data);
typedef void(aws_secure_tunneling_on_termination_complete_fn)(void *user_data);

/**
 * Basic Secure Tunnel configuration struct.
 *
 * Contains connection properties for the creation of a Secure Tunnel
 */
struct aws_secure_tunnel_options {
    struct aws_allocator *allocator;

    /**
     * Host to establish Secure Tunnel connection to
     */
    struct aws_byte_cursor endpoint_host;

    /**
     * Secure Tunnel bootstrap to use whenever Secure Tunnel establishes a connection
     */
    struct aws_client_bootstrap *bootstrap;

    /**
     * Socket options to use whenever this Secure Tunnel establishes a connection
     */
    const struct aws_socket_options *socket_options;

    /**
     * (Optional) Http proxy options to use whenever this Secure Tunnel establishes a connection
     */
    const struct aws_http_proxy_options *http_proxy_options;

    /**
     * Access Token used to establish a Secure Tunnel connection
     */
    struct aws_byte_cursor access_token;

    /**
     * (Optional) Client Token used to re-establish a Secure Tunnel connection after the one-time use access token has
     * been used. If one is not provided, it will automatically be generated and re-used on subsequent reconnects.
     */
    struct aws_byte_cursor client_token;

    const char *root_ca;

    aws_secure_tunnel_message_received_fn *on_message_received;

    void *user_data;

    /* Steve TODO we only support destination mode so this can be removed outside of testing */
    enum aws_secure_tunneling_local_proxy_mode local_proxy_mode;
    aws_secure_tunneling_on_connection_complete_fn *on_connection_complete;
    aws_secure_tunneling_on_connection_shutdown_fn *on_connection_shutdown;
    aws_secure_tunneling_on_send_data_complete_fn *on_send_data_complete;
    aws_secure_tunneling_on_data_receive_fn *on_data_receive;
    aws_secure_tunneling_on_stream_start_fn *on_stream_start;
    aws_secure_tunneling_on_stream_reset_fn *on_stream_reset;
    aws_secure_tunneling_on_session_reset_fn *on_session_reset;
    aws_secure_tunneling_on_termination_complete_fn *on_termination_complete;
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

/**
 * Queues a message operation in a secure tunnel
 *
 * @param secure_tunnel secure tunnel to queue a message for
 * @param message_options configuration options for the message operation
 * @return success/failure in the synchronous logic that kicks off the message operation
 */
AWS_IOTDEVICE_API
int aws_secure_tunnel_send_message(
    struct aws_secure_tunnel *secure_tunnel,
    const struct aws_secure_tunnel_message_view *message_options);

//***********************************************************************************************************************
/* STEVE TODO REMOVE OR HIDE ALL BELOW */
//***********************************************************************************************************************

/* TODO STEVE depricate/replace new aws_secure_tunnel_send_message_new */
AWS_IOTDEVICE_API
int aws_secure_tunnel_send_data(struct aws_secure_tunnel *secure_tunnel, const struct aws_byte_cursor *data);

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
