/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#ifndef AWS_IOTDEVICE_SECURE_TUNNELING_IMPL_H
#define AWS_IOTDEVICE_SECURE_TUNNELING_IMPL_H

#include <aws/iotdevice/secure_tunneling.h>

#include <aws/common/condition_variable.h>
#include <aws/common/mutex.h>
#include <aws/common/task_scheduler.h>
#include <aws/http/proxy.h>
#include <aws/io/socket.h>
#include <aws/io/tls_channel_handler.h>

/**
 * The various states that the secure tunnel can be in. A secure tunnel has both a current state and a desired state.
 * Desired state is only allowed to be one of {STOPPED, CONNECTED, TERMINATED}. The secure tunnel transitions states
 * based on either
 *  (1) changes in desired state, or
 *  (2) external events.
 *
 * Most states are interruptible (in the sense of a change in desired state causing an immediate change in state) but
 * CONNECTING and CHANNEL_SHUTDOWN cannot be interrupted due to waiting for an asynchronous callback (that has no
 * cancel) to complete.
 */
enum aws_secure_tunnel_state {
    /*
     * The secure tunnel is not connected and not waiting for anything to happen.
     *
     * Next States:
     *    CONNECTING - if the user invokes Connect() on the secure tunnel
     *    TERMINATED - if the user releases the last ref count on the secure tunnel
     */
    AWS_STS_STOPPED,

    /*
     * The secure tunnel is attempting to connect to a remote endpoint, and is waiting for channel setup to complete.
     * This state is not interruptible by any means other than channel setup completion.
     *
     * Next States:
     *    SECURE_TUNNEL_CONNECT - if the channel completes setup with no error and desired state is still CONNECTED
     *    CHANNEL_SHUTDOWN - if the channel completes setup with no error, but desired state is not CONNECTED
     *    PENDING_RECONNECT - if the channel fails to complete setup and desired state is still CONNECTED
     *    STOPPED - if the channel fails to complete setup and desired state is not CONNECTED
     */
    AWS_STS_CONNECTING,

    /*
     * The secure tunnel is attempting to connect through the AWS Secure Tunnel Service via a WebSocket handshake.
     *
     * Next States:
     *    CONNECTED - if WebSocket handshake is successful and desired state is still CONNECTED
     *    CHANNEL_SHUTDOWN - On send/encode errors, read/decode errors, unsuccessful WebSocket Handshake,
     *       desired state is no longer CONNECTED
     *    PENDING_RECONNECT - unexpected channel shutdown completion and desired state still CONNECTED
     *    STOPPED - unexpected channel shutdown completion and desired state no longer CONNECTED
     */
    AWS_STS_SECURE_TUNNEL_CONNECT,

    /*
     * The secure tunnel is ready to perform user-requested operations.
     *
     * Next States:
     *    CHANNEL_SHUTDOWN - On send/encode errors, read/decode errors, WebSocket disconnect, desired state
     *       no longer CONNECTED, PINGRESP timeout
     *    PENDING_RECONNECT - unexpected channel shutdown completion and desired state still CONNECTED
     *    STOPPED - unexpected channel shutdown completion and desired state no longer CONNECTED
     */
    AWS_STS_CONNECTED,

    /*
     * The secure tunnel is attempt to shut down a connection cleanly by finishing the current operation and then
     * transmitting a STREAM RESET message to all open streams.
     *
     * Next States:
     *    CHANNEL_SHUTDOWN - on successful (or unsuccessful) send of STREAM RESET messages
     *    PENDING_RECONNECT - unexpected channel shutdown completion and desired state still CONNECTED
     *    STOPPED - unexpected channel shutdown completion and desired state no longer CONNECTED
     */
    AWS_STS_CLEAN_DISCONNECT,

    /*
     * The secure tunnel is waiting for the io channel to completely shut down.  This state is not interruptible.
     *
     * Next States:
     *    PENDING_RECONNECT - the io channel has shut down and desired state is still CONNECTED
     *    STOPPED - the io channel has shut down and desired state is not CONNECTED
     */
    AWS_STS_CHANNEL_SHUTDOWN,

    /*
     * The secure tunnel is waiting for the reconnect timer to expire before attempting to connect again.
     *
     * Next States:
     *    CONNECTING - the reconnect timer has expired and desired state is still CONNECTED
     *    STOPPED - desired state is no longer CONNECTED
     */
    AWS_STS_PENDING_RECONNECT,

    /*
     * The secure tunnel is performing final shutdown and release of all resources.  This state is only realized for
     * a non-observable instant of time (transition out of STOPPED).
     */
    AWS_STS_TERMINATED
};

/**
 * Signature of the continuation function to be called after user-code transforms a websocket handshake request
 */
typedef void(aws_secure_tunnel_transform_websocket_handshake_complete_fn)(
    struct aws_http_message *request,
    int error_code,
    void *complete_ctx);

/**
 * Signature of the websocket handshake request transformation function.  After transformation, the completion
 * function must be invoked to send the request.
 */
typedef void(aws_secure_tunnel_transform_websocket_handshake_fn)(
    struct aws_http_message *request,
    void *user_data,
    aws_secure_tunnel_transform_websocket_handshake_complete_fn *complete_fn,
    void *complete_ctx);

/*
 * Secure tunnel configuration
 */
struct aws_secure_tunnel_options_storage {

    // struct aws_secure_tunnel_options options;
    struct aws_allocator *allocator;
    struct aws_secure_tunnel *secure_tunnel;

    /* backup */

    struct aws_client_bootstrap *bootstrap;
    struct aws_socket_options socket_options;
    struct aws_http_proxy_options http_proxy_options;
    struct aws_http_proxy_config *http_proxy_config;
    struct aws_byte_cursor access_token;

    aws_secure_tunnel_transform_websocket_handshake_fn *websocket_handshake_transform;
    void *websocket_handshake_transform_user_data;
    enum aws_secure_tunneling_local_proxy_mode local_proxy_mode;

    struct aws_string *endpoint_host;
    struct aws_string *root_ca;

    /* Store contents of all aws_byte_cursors within single buffer */
    struct aws_byte_buf cursor_storage;

    /* Stream related info */
    int32_t stream_id;
    struct aws_string *service_id_1;
    int32_t service_id_1_stream_id;
    struct aws_string *service_id_2;
    int32_t service_id_2_stream_id;
    struct aws_string *service_id_3;
    int32_t service_id_3_stream_id;
};

struct data_tunnel_pair {
    struct aws_byte_buf buf;
    struct aws_byte_cursor cur;
    const struct aws_secure_tunnel *secure_tunnel;
    bool length_prefix_written;
};

/* Secure Tunnel stream information */
struct aws_secure_tunnel_stream {
    struct aws_string *service_id;
    int32_t stream_id;
    /* for use with V3 */
    uint32_t connection_id;
};

struct aws_secure_tunnel_vtable {
    /* aws_high_res_clock_get_ticks */
    uint64_t (*get_current_time_fn)(void);

    /* aws_channel_shutdown */
    int (*channel_shutdown_fn)(struct aws_channel *channel, int error_code);

    /* aws_websocket_client_connect */
    int (*websocket_connect_fn)(const struct aws_websocket_client_connection_options *options);

    /* aws_http_proxy_new_socket_channel */
    int (*http_proxy_new_socket_channel_fn)(
        struct aws_socket_channel_bootstrap_options *channel_options,
        const struct aws_http_proxy_options *proxy_options);

    /* aws_client_bootstrap_new_socket_channel */
    int (*client_bootstrap_new_socket_channel_fn)(struct aws_socket_channel_bootstrap_options *options);

    int (*connect)(struct aws_secure_tunnel *secure_tunnel);
    int (*send_data)(struct aws_secure_tunnel *secure_tunnel, const struct aws_byte_cursor *data);
    int (*send_data_v2)(
        struct aws_secure_tunnel *secure_tunnel,
        const struct aws_secure_tunnel_message_data_view *data_options);
    int (*send_stream_start)(struct aws_secure_tunnel *secure_tunnel);
    int (*send_stream_start_v2)(struct aws_secure_tunnel *secure_tunnel, const struct aws_byte_cursor *service_id_data);
    int (*send_stream_reset)(struct aws_secure_tunnel *secure_tunnel);
    int (*close)(struct aws_secure_tunnel *secure_tunnel);
};

struct aws_websocket_client_connection_options;
struct aws_websocket_send_frame_options;

struct aws_websocket_vtable {
    int (*client_connect)(const struct aws_websocket_client_connection_options *options);
    int (*send_frame)(struct aws_websocket *websocket, const struct aws_websocket_send_frame_options *options);
    void (*close)(struct aws_websocket *websocket, bool free_scarce_resources_immediately);
    void (*release)(struct aws_websocket *websocket);
};

struct aws_secure_tunnel {
    /* Static settings */
    struct aws_allocator *allocator;
    struct aws_secure_tunnel_options_storage *config;
    struct aws_secure_tunnel_options *options;
    struct aws_tls_ctx *tls_ctx;
    struct aws_tls_connection_options tls_con_opt;

    const struct aws_secure_tunnel_vtable vtable;
    struct aws_websocket_vtable websocket_vtable;

    struct aws_ref_count ref_count;

    /* Used to check connection state */
    bool isConnected;

    /*
     * Temporary state-related data.
     *
     * clean_disconnect_error_code - the CLEAN_DISCONNECT state takes time to complete and we want to be able
     * to pass an error code from a prior event to the channel shutdown.  This holds the "override" error code
     * that we'd like to shutdown the channel with while CLEAN_DISCONNECT is processed.
     */
    int clean_disconnect_error_code;
    /*
     * handshake_request exists between the transform completion timepoint and the websocket setup callback.
     */
    struct aws_http_message *handshake_request;

    /*
     * Event loop all the secure tunnel's tasks will be pinned to, ensuring serialization and
     * concurrency safety.
     */
    struct aws_event_loop *loop;

    /* Channel handler information */
    struct aws_channel_handler handler;
    struct aws_channel_slot *slot;

    /* Dynamic data */

    /*
     * What state is the secure tunnel working towards?
     */
    enum aws_secure_tunnel_state desired_state;

    /*
     * What is the secure tunnel's current state?
     */
    enum aws_secure_tunnel_state current_state;

    struct aws_websocket *websocket;

    /* Stores what has been received but not processed */
    struct aws_byte_buf received_data;

    /* Error code of last connection attempt */
    int connection_error_code;

    /*
     * The recurrent task that runs all secure tunnel's logic outside of external event callbacks.  Bound to the secure
     * tunnel's event loop.
     */
    struct aws_task service_task;

    /*
     * Tracks when the secure tunnel's service task is next schedule to run.  Is zero if the task is not scheduled to
     * run or we are in the middle of a service (so technically not scheduled too).
     */
    uint64_t next_service_task_run_time;

    /*
     * When should the secure tunnel next attempt to reconnect?  Only used by PENDING_RECONNECT state.
     */
    uint64_t next_reconnect_time_ns;

    /*
     * When should the secure tunnel reset current_reconnect_delay_interval_ms to the minimum value?  Only relevant to
     * the CONNECTED state.
     */
    uint64_t next_reconnect_delay_reset_time_ns;

    /*
     * When should we shut down the channel due to failure to receive a websocket handshake?  Only relevant during the
     * SECURE_TUNNEL_CONNECT state.
     */
    uint64_t next_secure_tunnel_websocket_connect_timeout_time;

    /*
     * True if the secure tunnel's service task is running.  Used to skip service task reevaluation due to state changes
     * while running the service task.  Reevaluation will occur at the very end of the service.
     */
    bool in_service;

    struct aws_linked_list queued_operations;
    struct aws_linked_list write_completion_operations;
    struct aws_secure_tunnel_operation *current_operation;

    /*
     * Is there an io message in transit (to the socket) that has not invoked its write completion callback yet?
     * The secure tunnel implementation only allows one in-transit message at a time, and so if this is true, we don't
     * send additional ones/
     */
    bool pending_write_completion;

    /*
     * When should the next PINGREQ be sent?
     */
    uint64_t next_ping_time;

    /*
     * When should we shut down the channel due to failure to receive a PINGRESP?  Only non-zero when an outstanding
     * PINGREQ has not been answered.
     */
    uint64_t next_ping_timeout_time;

    /* Steve todo remove this and use next_ping_time above with tasks */
    /* The secure tunneling endpoint ELB drops idle connect after 1 minute. We need to send a ping periodically to keep
     * the connection */

    // struct ping_task_context *ping_task_context;
};

#endif /* AWS_IOTDEVICE_SECURE_TUNNELING_IMPL_H */
