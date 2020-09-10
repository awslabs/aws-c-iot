#ifndef AWS_IOTDEVICE_SECURE_TUNNELING_H
#define AWS_IOTDEVICE_SECURE_TUNNELING_H

#include <aws/common/byte_buf.h>

enum aws_secure_tunneling_local_proxy_mode {
    AWS_SECURE_TUNNELING_SOURCE,
    AWS_SECURE_TUNNELING_DESTINATION
};

typedef void(aws_secure_tunneling_data_msg_receive_fn)(int stream_id, const struct aws_byte_buf* data);
typedef void(aws_secure_tunneling_control_msg_receive_fn)(int stream_id);
typedef void(aws_secure_tunneling_close_fn)(int stream_id, int close_code);

struct aws_secure_tunneling_connection_config {
    const char *access_token;
    enum aws_secure_tunneling_local_proxy_mode mode;
    const char *regional_endpoint;

    aws_secure_tunneling_data_msg_receive_fn *on_data_receive;
    aws_secure_tunneling_control_msg_receive_fn *on_stream_start;
    aws_secure_tunneling_control_msg_receive_fn *on_stream_reset;
    aws_secure_tunneling_close_fn *on_close;
};

int aws_secure_tunneling_connect(const struct aws_secure_tunneling_connection_config *config);  // returns stream_id
void aws_secure_tunneling_send_data(int stream_id, const struct aws_byte_buf* data);
void aws_secure_tunneling_send_stream_start(int stream_id);
void aws_secure_tunneling_send_stream_reset(int stream_id);
void aws_secure_tunneling_close(int stream_id);

#endif // AWS_IOTDEVICE_SECURE_TUNNELING_H
