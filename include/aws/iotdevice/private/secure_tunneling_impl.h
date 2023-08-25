/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#ifndef AWS_IOTDEVICE_SECURE_TUNNELING_IMPL_H
#define AWS_IOTDEVICE_SECURE_TUNNELING_IMPL_H

#include <aws/iotdevice/secure_tunneling.h>

#include <aws/common/condition_variable.h>
#include <aws/common/hash_table.h>
#include <aws/common/mutex.h>
#include <aws/common/task_scheduler.h>
#include <aws/http/proxy.h>
#include <aws/http/websocket.h>
#include <aws/io/host_resolver.h>
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
 * CONNECTING cannot be interrupted due to waiting for an asynchronous callback (that has no
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
     * The secure tunnel is attempting to connect to a remote endpoint and establish a WebSocket upgrade. This state is
     * not interruptible by any means other than WebSocket setup completion.
     *
     * Next States:
     *    CONNECTED - if WebSocket handshake is successful and desired state is still CONNECTED
     *    WEBSOCKET_SHUTDOWN - if the WebSocket completes setup with no error but desired state is not CONNECTED
     *    PENDING_RECONNECT - if the WebSocket fails to complete setup and desired state is still CONNECTED
     *    STOPPED - if the WebSocket fails to complete setup and desired state is not CONNECTED
     */
    AWS_STS_CONNECTING,

    /*
     * The secure tunnel is ready to perform user-requested operations.
     *
     * Next States:
     *    WEBSOCKET_SHUTDOWN - desired state is no longer CONNECTED
     *    PENDING_RECONNECT - unexpected WebSocket shutdown completion and desired state still CONNECTED
     *    STOPPED - unexpected WebSocket shutdown completion and desired state no longer CONNECTED
     */
    AWS_STS_CONNECTED,

    /*
     * The secure tunnel is attempting to shut down a WebSocket connection cleanly by finishing the current operation
     * and then transmitting a STREAM RESET message to all open streams.
     *
     * Next States:
     *    WEBSOCKET_SHUTDOWN - on sucessful (or unsuccessful) disconnection
     *    PENDING_RECONNECT - unexpected WebSocket shutdown completion and desired state still CONNECTED
     *    STOPPED - unexpected WebSocket shutdown completion and desired state no longer CONNECTED
     */
    AWS_STS_CLEAN_DISCONNECT,

    /*
     * The secure tunnel is waiting for the WebSocket to completely shut down.  This state is not interruptible.
     *
     * Next States:
     *    PENDING_RECONNECT - the WebSocket has shut down and desired state is still CONNECTED
     *    STOPPED - the WebSocket has shut down and desired state is not CONNECTED
     */
    AWS_STS_WEBSOCKET_SHUTDOWN,

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

struct data_tunnel_pair {
    struct aws_allocator *allocator;
    struct aws_byte_buf buf;
    struct aws_byte_cursor cur;
    enum aws_secure_tunnel_message_type type;
    const struct aws_secure_tunnel *secure_tunnel;
    bool length_prefix_written;
};

struct aws_secure_tunnel_message_storage {
    struct aws_allocator *allocator;
    struct aws_secure_tunnel_message_view storage_view;

    struct aws_byte_cursor service_id;
    struct aws_byte_cursor payload;

    struct aws_byte_buf storage;
};

/*
 * Secure tunnel configuration
 */
struct aws_secure_tunnel_options_storage {
    struct aws_allocator *allocator;

    /* backup */

    struct aws_client_bootstrap *bootstrap;
    struct aws_socket_options socket_options;
    struct aws_http_proxy_options http_proxy_options;
    struct aws_http_proxy_config *http_proxy_config;
    struct aws_string *access_token;
    struct aws_string *client_token;

    struct aws_string *endpoint_host;

    /* Callbacks */
    aws_secure_tunnel_message_received_fn *on_message_received;
    aws_secure_tunneling_on_connection_complete_fn *on_connection_complete;
    aws_secure_tunneling_on_connection_shutdown_fn *on_connection_shutdown;
    aws_secure_tunneling_on_stream_start_fn *on_stream_start;
    aws_secure_tunneling_on_stream_reset_fn *on_stream_reset;
    aws_secure_tunneling_on_connection_start_fn *on_connection_start;
    aws_secure_tunneling_on_connection_reset_fn *on_connection_reset;
    aws_secure_tunneling_on_session_reset_fn *on_session_reset;
    aws_secure_tunneling_on_stopped_fn *on_stopped;
    aws_secure_tunneling_on_send_message_complete_fn *on_send_message_complete;

    aws_secure_tunneling_on_termination_complete_fn *on_termination_complete;
    void *secure_tunnel_on_termination_user_data;

    void *user_data;
    enum aws_secure_tunneling_local_proxy_mode local_proxy_mode;
};

struct aws_secure_tunnel_connections {
    struct aws_allocator *allocator;

    uint8_t protocol_version;

    /* Used for streams not using multiplexing (service ids) */
    int32_t stream_id;
    struct aws_hash_table connection_ids;

    /* Table containing streams using multiplexing (service ids) */
    struct aws_hash_table service_ids;

    /* Message used for initializing a stream upon a reconnect due to a protocol version mismatch */
    struct aws_secure_tunnel_message_storage *restore_stream_message_view;
    struct aws_secure_tunnel_message_storage restore_stream_message;
};

struct aws_secure_tunnel_vtable {
    /* aws_high_res_clock_get_ticks */
    uint64_t (*get_current_time_fn)(void);

    /* For test verification */
    int (*aws_websocket_client_connect_fn)(const struct aws_websocket_client_connection_options *options);

    /* For test verification */
    int (*aws_websocket_send_frame_fn)(
        struct aws_websocket *websocket,
        const struct aws_websocket_send_frame_options *options);

    /* For test verification */
    void (*aws_websocket_release_fn)(struct aws_websocket *websocket);

    /* For test verification */
    void (*aws_websocket_close_fn)(struct aws_websocket *websocket, bool free_scarce_resources_immediately);

    void *vtable_user_data;
};

struct aws_secure_tunnel {
    /* Static settings */
    struct aws_allocator *allocator;
    struct aws_ref_count ref_count;

    const struct aws_secure_tunnel_vtable *vtable;

    /*
     * Secure tunnel configuration
     */
    struct aws_secure_tunnel_options_storage *config;

    /*
     * Stores connection related information
     */
    struct aws_secure_tunnel_connections *connections;

    struct aws_tls_ctx *tls_ctx;
    struct aws_tls_connection_options tls_con_opt;

    struct aws_host_resolution_config host_resolution_config;

    /*
     * The recurrent task that runs all secure tunnel logic outside of external event callbacks.  Bound to the secure
     * tunnel's event loop.
     */
    struct aws_task service_task;

    /*
     * Tracks when the secure tunnel's service task is next schedule to run.  Is zero if the task is not scheduled to
     * run or we are in the middle of a service (so technically not scheduled too).
     */
    uint64_t next_service_task_run_time;

    /*
     * True if the secure tunnel's service task is running.  Used to skip service task reevaluation due to state changes
     * while running the service task.  Reevaluation will occur at the very end of the service.
     */
    bool in_service;

    /*
     * Event loop all the secure tunnel's tasks will be pinned to, ensuring serialization and
     * concurrency safety.
     */
    struct aws_event_loop *loop;

    /*
     * What state is the secure tunnel working towards?
     */
    enum aws_secure_tunnel_state desired_state;

    /*
     * What is the secure tunnel's current state?
     */
    enum aws_secure_tunnel_state current_state;

    /*
     * handshake_request exists between the transform completion timepoint and the websocket setup callback.
     */
    struct aws_http_message *handshake_request;

    /* Dynamic data */

    struct aws_websocket *websocket;

    /* Stores what has been received but not processed */
    struct aws_byte_buf received_data;

    /*
     * When should the secure tunnel next attempt to reconnect?  Only used by PENDING_RECONNECT state.
     */
    uint64_t next_reconnect_time_ns;

    /*
     * How many consecutive reconnect failures have we experienced?
     */
    uint64_t reconnect_count;

    struct aws_linked_list queued_operations;
    struct aws_secure_tunnel_operation *current_operation;

    /*
     * Is there a WebSocket message in transit (to the socket) that has not invoked its write completion callback yet?
     * The secure tunnel implementation only allows one in-transit message at a time, and so if this is true, we don't
     * send additional ones/
     */
    bool pending_write_completion;

    /*
     * When should the next PINGREQ be sent?
     * The secure tunneling endpoint ELB drops idle connect after 1 minute. we need to send a ping periodically to keep
     * the connection alive.
     */
    uint64_t next_ping_time;
};

AWS_EXTERN_C_BEGIN

/*
 * Override the vtable used by the secure tunnel; useful for mocking certain scenarios.
 */
AWS_IOTDEVICE_API void aws_secure_tunnel_set_vtable(
    struct aws_secure_tunnel *secure_tunnel,
    const struct aws_secure_tunnel_vtable *vtable);

/*
 * Gets the default vtable used by the secure tunnel.  In order to mock something, we start with the default and then
 * mutate it selectively to achieve the scenario we're interested in.
 */
AWS_IOTDEVICE_API const struct aws_secure_tunnel_vtable *aws_secure_tunnel_get_default_vtable(void);

/*
 * For testing purposes. This message type should only be sent due to internal logic.
 */
AWS_IOTDEVICE_API
int aws_secure_tunnel_connection_reset(
    struct aws_secure_tunnel *secure_tunnel,
    const struct aws_secure_tunnel_message_view *message_options);

AWS_EXTERN_C_END

#endif /* AWS_IOTDEVICE_SECURE_TUNNELING_IMPL_H */
