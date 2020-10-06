#ifndef AWS_IOTDEVICE_SECURE_TUNNELING_H
#define AWS_IOTDEVICE_SECURE_TUNNELING_H

#include <aws/common/byte_buf.h>

/* TODO: Add to exports.h */
#define AWS_SECURE_TUNNELING_API

enum aws_secure_tunneling_local_proxy_mode { AWS_SECURE_TUNNELING_SOURCE_MODE, AWS_SECURE_TUNNELING_DESTINATION_MODE };

struct aws_secure_tunnel;

/* APIs */
typedef int (aws_secure_tunneling_send_data_fn)(struct aws_secure_tunnel *secure_tunnel, const struct aws_byte_buf* data);
typedef int (aws_secure_tunneling_send_stream_start_fn)(struct aws_secure_tunnel *secure_tunnel);
typedef int (aws_secure_tunneling_send_stream_reset_fn)(struct aws_secure_tunnel *secure_tunnel);
typedef int (aws_secure_tunneling_close_fn)(struct aws_secure_tunnel *secure_tunnel);

struct aws_secure_tunnel_vtable {
    aws_secure_tunneling_send_data_fn *aws_secure_tunneling_send_data;
    aws_secure_tunneling_send_stream_start_fn *aws_secure_tunneling_send_stream_start;
    aws_secure_tunneling_send_stream_reset_fn *aws_secure_tunneling_send_stream_reset;
    aws_secure_tunneling_close_fn *aws_secure_tunneling_close;
};

struct aws_secure_tunnel {
    int32_t stream_id;
    struct aws_websocket *websocket;
    struct aws_secure_tunnel_vtable *vtable;
};

/* Callbacks */
typedef void(aws_secure_tunneling_on_connection_complete_fn)(struct aws_secure_tunnel *secure_tunnel);
typedef void(aws_secure_tunneling_on_data_receive_fn)(struct aws_secure_tunnel *secure_tunnel, const struct aws_byte_buf *data);
typedef void(aws_secure_tunneling_on_stream_start_fn)(struct aws_secure_tunnel *secure_tunnel);
typedef void(aws_secure_tunneling_on_stream_reset_fn)(struct aws_secure_tunnel *secure_tunnel);
typedef void(aws_secure_tunneling_on_close_fn)(struct aws_secure_tunnel *secure_tunnel, int32_t close_code);

struct aws_secure_tunneling_connection_config {
    struct aws_allocator *allocator;
    struct aws_client_bootstrap *bootstrap;
    struct aws_socket_options *socket_options;

    struct aws_byte_cursor access_token;
    enum aws_secure_tunneling_local_proxy_mode local_proxy_mode;
    struct aws_byte_cursor endpoint_host;

    aws_secure_tunneling_on_connection_complete_fn *on_connection_complete;
    aws_secure_tunneling_on_data_receive_fn *on_data_receive;
    aws_secure_tunneling_on_stream_start_fn *on_stream_start;
    aws_secure_tunneling_on_stream_reset_fn *on_stream_reset;
    aws_secure_tunneling_on_close_fn *on_close;
};

AWS_SECURE_TUNNELING_API
int aws_secure_tunneling_connect(const struct aws_secure_tunneling_connection_config *connection_config);

#endif /* AWS_IOTDEVICE_SECURE_TUNNELING_H */
