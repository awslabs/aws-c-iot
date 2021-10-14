/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#ifndef AWS_IOTDEVICE_SECURE_TUNNELING_IMPL_H
#define AWS_IOTDEVICE_SECURE_TUNNELING_IMPL_H

#include <aws/iotdevice/secure_tunneling.h>

#include <aws/common/condition_variable.h>
#include <aws/common/mutex.h>
#include <aws/io/tls_channel_handler.h>

struct aws_secure_tunnel {
    /* Static settings */
    struct aws_allocator *alloc;
    struct aws_secure_tunneling_connection_options_storage *options_storage;
    struct aws_secure_tunneling_connection_options *options;
    struct aws_tls_ctx *tls_ctx;
    struct aws_tls_connection_options tls_con_opt;
    struct aws_secure_tunnel_vtable vtable;

    struct aws_ref_count ref_count;

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

#endif /* AWS_IOTDEVICE_SECURE_TUNNELING_IMPL_H */
