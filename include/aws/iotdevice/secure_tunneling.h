#ifndef AWS_IOTDEVICE_SECURE_TUNNELING_H
#define AWS_IOTDEVICE_SECURE_TUNNELING_H

#include <aws/common/byte_buf.h>
#include <aws/common/condition_variable.h>
#include <aws/common/mutex.h>
#include <aws/common/task_scheduler.h>
#include <aws/io/tls_channel_handler.h>
#include <aws/iotdevice/exports.h>
#include <aws/iotdevice/iotdevice.h>

#define AWS_IOT_ST_SPLIT_MESSAGE_SIZE 15000

enum aws_secure_tunneling_local_proxy_mode { AWS_SECURE_TUNNELING_SOURCE_MODE, AWS_SECURE_TUNNELING_DESTINATION_MODE };

struct aws_secure_tunnel;
struct aws_websocket_incoming_frame;
struct ping_task_context;

struct data_tunnel_pair {
    struct aws_byte_buf buf;
    struct aws_byte_cursor cur;
    const struct aws_secure_tunnel *secure_tunnel;
    bool length_prefix_written;
};

/* APIs */
typedef int(aws_secure_tunneling_connect_fn)(struct aws_secure_tunnel *secure_tunnel);
typedef int(
    aws_secure_tunneling_send_data_fn)(struct aws_secure_tunnel *secure_tunnel, const struct aws_byte_cursor *data);
typedef int(aws_secure_tunneling_send_stream_start_fn)(struct aws_secure_tunnel *secure_tunnel);
typedef int(aws_secure_tunneling_send_stream_reset_fn)(struct aws_secure_tunnel *secure_tunnel);
typedef int(aws_secure_tunneling_close_fn)(struct aws_secure_tunnel *secure_tunnel);

/* Callbacks */
typedef void(aws_secure_tunneling_on_connection_complete_fn)(void *user_data);
typedef void(aws_secure_tunneling_on_connection_shutdown_fn)(void *user_data);
typedef void(aws_secure_tunneling_on_send_data_complete_fn)(int error_code, void *user_data);
typedef void(aws_secure_tunneling_on_data_receive_fn)(const struct aws_byte_buf *data, void *user_data);
typedef void(aws_secure_tunneling_on_stream_start_fn)(void *user_data);
typedef void(aws_secure_tunneling_on_stream_reset_fn)(void *user_data);
typedef void(aws_secure_tunneling_on_session_reset_fn)(void *user_data);

struct aws_secure_tunnel_vtable {
    aws_secure_tunneling_connect_fn *connect;
    aws_secure_tunneling_send_data_fn *send_data;
    aws_secure_tunneling_send_stream_start_fn *send_stream_start;
    aws_secure_tunneling_send_stream_reset_fn *send_stream_reset;
    aws_secure_tunneling_close_fn *close;
};

struct aws_secure_tunneling_connection_config {
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

struct aws_secure_tunnel {
    /* Static settings */
    struct aws_secure_tunneling_connection_config config;
    struct aws_tls_ctx *tls_ctx;
    struct aws_tls_connection_options tls_con_opt;
    struct aws_secure_tunnel_vtable vtable;

    /* Used only during initial websocket setup. Otherwise, should be NULL */
    struct aws_http_message *handshake_request;

    /* Dynamic data */
    int32_t stream_id;
    struct aws_websocket *websocket;

    /* Stores what has been received but not processed */
    struct aws_byte_buf received_data;

    /* The secure tunneling endpoint ELB drops idle connect after 1 minute. We need to send a ping periodically to keep
     * the connection */

    /* Shared State, making websocket send data sync */
    bool can_send_data;
    struct aws_mutex send_data_mutex;
    struct aws_condition_variable send_data_condition_variable;

    struct ping_task_context *ping_task_context;
};

AWS_EXTERN_C_BEGIN

AWS_IOTDEVICE_API
struct aws_secure_tunnel *aws_secure_tunnel_new(const struct aws_secure_tunneling_connection_config *connection_config);

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

/* Making this exposed public to verify testing in the sdk layer */
AWS_IOTDEVICE_API
bool on_websocket_incoming_frame_payload(
    struct aws_websocket *websocket,
    const struct aws_websocket_incoming_frame *frame,
    struct aws_byte_cursor data,
    void *user_data);

AWS_EXTERN_C_END

#endif /* AWS_IOTDEVICE_SECURE_TUNNELING_H */
