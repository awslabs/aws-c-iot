#ifndef AWS_IOTDEVICE_SECURE_TUNNELING_H
#define AWS_IOTDEVICE_SECURE_TUNNELING_H

#include <aws/common/byte_buf.h>

enum aws_secure_tunneling_local_proxy_mode {
    AWS_SECURE_TUNNELING_SOURCE_MODE,
    AWS_SECURE_TUNNELING_DESTINATION_MODE
};

typedef void(aws_secure_tunneling_on_connection_complete_fn)(int32_t stream_id);
typedef void(aws_secure_tunneling_on_data_receive_fn)(int32_t stream_id, const struct aws_byte_buf* data);
typedef void(aws_secure_tunneling_on_stream_start_fn)(int32_t stream_id);
typedef void(aws_secure_tunneling_on_stream_reset_fn)(int32_t stream_id);
typedef void(aws_secure_tunneling_on_close_fn)(int32_t stream_id, int32_t close_code);

struct aws_secure_tunneling_connection_config {
    struct aws_allocator *allocator;

    struct aws_byte_cursor access_token;
    enum aws_secure_tunneling_local_proxy_mode mode;
    struct aws_byte_cursor endpoint_host;

    aws_secure_tunneling_on_connection_complete_fn *on_connection_complete;
    aws_secure_tunneling_on_data_receive_fn *on_data_receive;
    aws_secure_tunneling_on_stream_start_fn *on_stream_start;
    aws_secure_tunneling_on_stream_reset_fn *on_stream_reset;
    aws_secure_tunneling_on_close_fn *on_close;
};

int aws_secure_tunneling_connect(const struct aws_secure_tunneling_connection_config *config);
int aws_secure_tunneling_send_data(int32_t stream_id, const struct aws_byte_buf* data);
int aws_secure_tunneling_send_stream_start(int32_t stream_id);
int aws_secure_tunneling_send_stream_reset(int32_t stream_id);
int aws_secure_tunneling_close(int32_t stream_id);

#endif /* AWS_IOTDEVICE_SECURE_TUNNELING_H */