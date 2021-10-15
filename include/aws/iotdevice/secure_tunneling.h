#ifndef AWS_IOTDEVICE_SECURE_TUNNELING_H
#define AWS_IOTDEVICE_SECURE_TUNNELING_H

#include <aws/iotdevice/iotdevice.h>

#include <aws/common/byte_buf.h>

#define AWS_IOT_ST_SPLIT_MESSAGE_SIZE 15000

enum aws_secure_tunneling_local_proxy_mode { AWS_SECURE_TUNNELING_SOURCE_MODE, AWS_SECURE_TUNNELING_DESTINATION_MODE };

struct aws_secure_tunnel;
struct aws_websocket;
struct aws_websocket_incoming_frame;

/* Callbacks */
typedef void(aws_secure_tunneling_on_connection_complete_fn)(void *user_data);
typedef void(aws_secure_tunneling_on_connection_shutdown_fn)(void *user_data);
typedef void(aws_secure_tunneling_on_send_data_complete_fn)(int error_code, void *user_data);
typedef void(aws_secure_tunneling_on_data_receive_fn)(const struct aws_byte_buf *data, void *user_data);
typedef void(aws_secure_tunneling_on_stream_start_fn)(void *user_data);
typedef void(aws_secure_tunneling_on_stream_reset_fn)(void *user_data);
typedef void(aws_secure_tunneling_on_session_reset_fn)(void *user_data);

struct aws_secure_tunneling_connection_options {
    struct aws_allocator *allocator;
    struct aws_client_bootstrap *bootstrap;
    struct aws_socket_options *socket_options;

    struct aws_byte_cursor access_token;
    enum aws_secure_tunneling_local_proxy_mode local_proxy_mode;
    struct aws_byte_cursor endpoint_host;
    const char *root_ca;

    aws_secure_tunneling_on_connection_complete_fn *on_connection_complete;
    aws_secure_tunneling_on_connection_shutdown_fn *on_connection_shutdown;
    aws_secure_tunneling_on_send_data_complete_fn *on_send_data_complete;
    aws_secure_tunneling_on_data_receive_fn *on_data_receive;
    aws_secure_tunneling_on_stream_start_fn *on_stream_start;
    aws_secure_tunneling_on_stream_reset_fn *on_stream_reset;
    aws_secure_tunneling_on_session_reset_fn *on_session_reset;

    void *user_data;
};

/* deprecated: "_config" is renamed "_options" for consistency with similar code in the aws-c libraries */
#define aws_secure_tunneling_connection_config aws_secure_tunneling_connection_options

/**
 * Persistent storage for aws_secure_tunneling_connection_options.
 */
struct aws_secure_tunneling_connection_options_storage;

AWS_EXTERN_C_BEGIN

AWS_IOTDEVICE_API
struct aws_secure_tunnel *aws_secure_tunnel_new(
    const struct aws_secure_tunneling_connection_options *connection_config);

AWS_IOTDEVICE_API
struct aws_secure_tunnel *aws_secure_tunnel_acquire(struct aws_secure_tunnel *secure_tunnel);

AWS_IOTDEVICE_API
void aws_secure_tunnel_release(struct aws_secure_tunnel *secure_tunnel);

AWS_IOTDEVICE_API
int aws_secure_tunnel_connect(struct aws_secure_tunnel *secure_tunnel);

AWS_IOTDEVICE_API
int aws_secure_tunnel_close(struct aws_secure_tunnel *secure_tunnel);

AWS_IOTDEVICE_API
int aws_secure_tunnel_send_data(struct aws_secure_tunnel *secure_tunnel, const struct aws_byte_cursor *data);

AWS_IOTDEVICE_API
int aws_secure_tunnel_stream_start(struct aws_secure_tunnel *secure_tunnel);

AWS_IOTDEVICE_API
int aws_secure_tunnel_stream_reset(struct aws_secure_tunnel *secure_tunnel);

/**
 * Raises exception and returns AWS_OP_ERR if options are missing required parameters.
 */
AWS_IOTDEVICE_API
int aws_secure_tunneling_connection_options_validate(const struct aws_secure_tunneling_connection_options *options);

/**
 * Create persistent storage for aws_secure_tunneling_connection_options
 */
AWS_IOTDEVICE_API
struct aws_secure_tunneling_connection_options_storage *aws_secure_tunneling_connection_options_storage_new(
    const struct aws_secure_tunneling_connection_options *options);

AWS_IOTDEVICE_API
void aws_secure_tunneling_connection_options_storage_destroy(
    struct aws_secure_tunneling_connection_options_storage *storage);

/**
 * Return options struct stored within.
 */
AWS_IOTDEVICE_API
const struct aws_secure_tunneling_connection_options *aws_secure_tunneling_connection_options_storage_get(
    const struct aws_secure_tunneling_connection_options_storage *storage);

/* Making this exposed public to verify testing in the sdk layer */
AWS_IOTDEVICE_API
bool on_websocket_incoming_frame_payload(
    struct aws_websocket *websocket,
    const struct aws_websocket_incoming_frame *frame,
    struct aws_byte_cursor data,
    void *user_data);

AWS_EXTERN_C_END

#endif /* AWS_IOTDEVICE_SECURE_TUNNELING_H */
