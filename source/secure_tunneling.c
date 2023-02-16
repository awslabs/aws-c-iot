/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/iotdevice/private/secure_tunneling_impl.h>
#include <aws/iotdevice/private/secure_tunneling_operations.h>

#include <aws/common/clock.h>
#include <aws/common/string.h>
#include <aws/http/proxy.h>
#include <aws/http/request_response.h>
#include <aws/http/websocket.h>
#include <aws/io/channel_bootstrap.h>
#include <aws/io/event_loop.h>
#include <aws/io/socket.h>
#include <aws/iotdevice/private/serializer.h>
#include <inttypes.h>
#include <math.h>

#define MAX_WEBSOCKET_PAYLOAD 131076
#define INVALID_STREAM_ID 0
#define PAYLOAD_BYTE_LENGTH_PREFIX 2
#define MIN_RECONNECT_DELAY_MS 1000
#define MAX_RECONNECT_DELAY_MS 120000
#define PING_TASK_INTERVAL ((uint64_t)20 * 1000000000)
#define WEBSOCKET_HEADER_NAME_ACCESS_TOKEN "access-token"
#define WEBSOCKET_HEADER_NAME_CLIENT_TOKEN "client-token"
#define WEBSOCKET_HEADER_NAME_PROTOCOL "Sec-WebSocket-Protocol"
#define WEBSOCKET_HEADER_PROTOCOL_VALUE "aws.iot.securetunneling-2.0"

static void s_change_current_state(struct aws_secure_tunnel *secure_tunnel, enum aws_secure_tunnel_state next_state);
void aws_secure_tunnel_operational_state_clean_up(struct aws_secure_tunnel *secure_tunnel);
static int s_aws_secure_tunnel_change_desired_state(
    struct aws_secure_tunnel *secure_tunnel,
    enum aws_secure_tunnel_state desired_state);
static void s_complete_operation_list(
    struct aws_secure_tunnel *secure_tunnel,
    struct aws_linked_list *operation_list,
    int error_code);

static int s_secure_tunneling_send(
    struct aws_secure_tunnel *secure_tunnel,
    const struct aws_secure_tunnel_message_view *message_view);

static void s_reevaluate_service_task(struct aws_secure_tunnel *secure_tunnel);

const char *aws_secure_tunnel_state_to_c_string(enum aws_secure_tunnel_state state) {
    switch (state) {
        case AWS_STS_STOPPED:
            return "STOPPED";

        case AWS_STS_CONNECTING:
            return "CONNECTING";

        case AWS_STS_CONNECTED:
            return "CONNECTED";

        case AWS_STS_CLEAN_DISCONNECT:
            return "CLEAN_DISCONNECT";

        case AWS_STS_WEBSOCKET_SHUTDOWN:
            return "WEBSOCKET_SHUTDOWN";

        case AWS_STS_PENDING_RECONNECT:
            return "PENDING_RECONNECT";

        case AWS_STS_TERMINATED:
            return "TERMINATED";

        default:
            return "UNKNOWN";
    }
}

static const char *s_get_proxy_mode_string(enum aws_secure_tunneling_local_proxy_mode local_proxy_mode) {
    if (local_proxy_mode == AWS_SECURE_TUNNELING_SOURCE_MODE) {
        return "source";
    }
    return "destination";
}

static int s_reset_service_id(void *context, struct aws_hash_element *p_element) {
    (void)context;
    struct aws_service_id_element *service_id_elem = p_element->value;
    service_id_elem->stream_id = INVALID_STREAM_ID;
    return AWS_COMMON_HASH_TABLE_ITER_CONTINUE;
}

/*********************************************************************************************************************
 * Secure Tunnel Clean Up
 ********************************************************************************************************************/

static void s_secure_tunnel_final_destroy(struct aws_secure_tunnel *secure_tunnel) {
    if (secure_tunnel == NULL) {
        return;
    }

    aws_secure_tunneling_on_termination_complete_fn *on_termination_complete = NULL;
    void *termination_complete_user_data = NULL;
    if (secure_tunnel->config != NULL) {
        on_termination_complete = secure_tunnel->config->on_termination_complete;
        termination_complete_user_data = secure_tunnel->config->user_data;
    }

    aws_secure_tunnel_operational_state_clean_up(secure_tunnel);

    /* Clean up all memory */
    aws_secure_tunnel_options_storage_destroy(secure_tunnel->config);
    aws_http_message_release(secure_tunnel->handshake_request);
    aws_byte_buf_clean_up(&secure_tunnel->received_data);
    aws_tls_connection_options_clean_up(&secure_tunnel->tls_con_opt);
    aws_tls_ctx_release(secure_tunnel->tls_ctx);
    aws_mem_release(secure_tunnel->allocator, secure_tunnel);

    if (on_termination_complete != NULL) {
        (*on_termination_complete)(termination_complete_user_data);
    }
}

static void s_on_secure_tunnel_zero_ref_count(void *user_data) {
    struct aws_secure_tunnel *secure_tunnel = user_data;
    s_aws_secure_tunnel_change_desired_state(secure_tunnel, AWS_STS_TERMINATED);
}

/*****************************************************************************************************************
 *                                    RECEIVE MESSAGE HANDLING
 *****************************************************************************************************************/

/*
 * Close and reset all stream ids
 */
static void s_reset_secure_tunnel(struct aws_secure_tunnel *secure_tunnel) {
    AWS_LOGF_INFO(AWS_LS_IOTDEVICE_SECURE_TUNNELING, "id=%p: Secure tunnel session reset.", (void *)secure_tunnel);

    secure_tunnel->config->stream_id = INVALID_STREAM_ID;
    aws_hash_table_foreach(&secure_tunnel->config->service_ids, s_reset_service_id, NULL);
    secure_tunnel->received_data.len = 0; /* Drop any incomplete secure tunnel frame */
}

static bool s_aws_secure_tunnel_stream_id_check_match(
    struct aws_secure_tunnel *secure_tunnel,
    const struct aws_byte_cursor *service_id,
    int32_t stream_id) {
    /* No service id means V1 protocol is being used */
    if (service_id->len == 0) {
        return (secure_tunnel->config->stream_id == stream_id);
    }

    struct aws_hash_element *elem = NULL;
    aws_hash_table_find(&secure_tunnel->config->service_ids, service_id, &elem);
    if (elem == NULL) {
        AWS_LOGF_WARN(
            AWS_LS_IOTDEVICE_SECURE_TUNNELING,
            "id=%p: Secure tunnel stream id check request for unsupported service_id: " PRInSTR,
            (void *)secure_tunnel,
            AWS_BYTE_CURSOR_PRI(*service_id));
        return false;
    }

    struct aws_service_id_element *service_id_elem = elem->value;
    return (stream_id == service_id_elem->stream_id);
}

static int s_aws_secure_tunnel_set_stream_id(
    struct aws_secure_tunnel *secure_tunnel,
    const struct aws_byte_cursor *service_id,
    int32_t stream_id) {
    /* No service id means V1 protocol is being used */
    if (service_id == NULL || service_id->len == 0) {
        secure_tunnel->config->stream_id = stream_id;
        AWS_LOGF_INFO(
            AWS_LS_IOTDEVICE_SECURE_TUNNELING,
            "id=%p: Secure tunnel stream_id set to %d",
            (void *)secure_tunnel,
            stream_id);
        return AWS_OP_SUCCESS;
    }

    struct aws_hash_element *elem = NULL;
    aws_hash_table_find(&secure_tunnel->config->service_ids, service_id, &elem);
    if (elem == NULL) {
        AWS_LOGF_WARN(
            AWS_LS_IOTDEVICE_SECURE_TUNNELING,
            "id=%p: Secure tunnel request for unsupported service_id: " PRInSTR,
            (void *)secure_tunnel,
            AWS_BYTE_CURSOR_PRI(*service_id));
        return false;
    }

    struct aws_service_id_element *replacement_elem =
        aws_service_id_element_new(secure_tunnel->allocator, service_id, stream_id);

    aws_hash_table_put(&secure_tunnel->config->service_ids, &replacement_elem->service_id_cur, replacement_elem, NULL);
    AWS_LOGF_INFO(
        AWS_LS_IOTDEVICE_SECURE_TUNNELING,
        "id=%p: Secure tunnel service_id '" PRInSTR "' stream_id set to %d",
        (void *)secure_tunnel,
        AWS_BYTE_CURSOR_PRI(*service_id),
        stream_id);

    return AWS_OP_SUCCESS;
}

static void s_aws_secure_tunnel_on_stream_start_received(
    struct aws_secure_tunnel *secure_tunnel,
    struct aws_secure_tunnel_message_view *message_view) {
    int result = s_aws_secure_tunnel_set_stream_id(secure_tunnel, message_view->service_id, message_view->stream_id);
    if (secure_tunnel->config->on_stream_start) {
        secure_tunnel->config->on_stream_start(message_view, result, secure_tunnel->config->user_data);
    }
}

static void s_aws_secure_tunnel_on_stream_reset_received(
    struct aws_secure_tunnel *secure_tunnel,
    struct aws_secure_tunnel_message_view *message_view) {
    int result = AWS_OP_SUCCESS;
    if (s_aws_secure_tunnel_stream_id_check_match(secure_tunnel, message_view->service_id, message_view->stream_id)) {
        result = s_aws_secure_tunnel_set_stream_id(secure_tunnel, message_view->service_id, INVALID_STREAM_ID);
    }
    if (secure_tunnel->config->on_stream_reset) {
        secure_tunnel->config->on_stream_reset(message_view, result, secure_tunnel->config->user_data);
    }
}

static void s_aws_secure_tunnel_on_session_reset_received(struct aws_secure_tunnel *secure_tunnel) {
    s_reset_secure_tunnel(secure_tunnel);
    if (secure_tunnel->config->on_session_reset) {
        secure_tunnel->config->on_session_reset(secure_tunnel->config->user_data);
    }
}

static void s_aws_secure_tunnel_on_service_ids_received(
    struct aws_secure_tunnel *secure_tunnel,
    struct aws_secure_tunnel_message_view *message_view) {

    aws_hash_table_clear(&secure_tunnel->config->service_ids);

    if (message_view->service_id != NULL) {
        struct aws_service_id_element *service_id_1_elem =
            aws_service_id_element_new(secure_tunnel->allocator, message_view->service_id, INVALID_STREAM_ID);
        aws_hash_table_put(
            &secure_tunnel->config->service_ids, &service_id_1_elem->service_id_cur, service_id_1_elem, NULL);
        AWS_LOGF_INFO(
            AWS_LS_IOTDEVICE_SECURE_TUNNELING,
            "id=%p: secure tunnel service id 1 set to: " PRInSTR,
            (void *)secure_tunnel,
            AWS_BYTE_CURSOR_PRI(*message_view->service_id));
        if (message_view->service_id_2 != NULL) {
            struct aws_service_id_element *service_id_2_elem =
                aws_service_id_element_new(secure_tunnel->allocator, message_view->service_id_2, INVALID_STREAM_ID);
            aws_hash_table_put(
                &secure_tunnel->config->service_ids, &service_id_2_elem->service_id_cur, service_id_2_elem, NULL);
            AWS_LOGF_INFO(
                AWS_LS_IOTDEVICE_SECURE_TUNNELING,
                "id=%p: secure tunnel service id 2 set to: " PRInSTR,
                (void *)secure_tunnel,
                AWS_BYTE_CURSOR_PRI(*message_view->service_id_2));
            if (message_view->service_id_3 != NULL) {
                struct aws_service_id_element *service_id_3_elem =
                    aws_service_id_element_new(secure_tunnel->allocator, message_view->service_id_3, INVALID_STREAM_ID);
                aws_hash_table_put(
                    &secure_tunnel->config->service_ids, &service_id_3_elem->service_id_cur, service_id_3_elem, NULL);
                AWS_LOGF_INFO(
                    AWS_LS_IOTDEVICE_SECURE_TUNNELING,
                    "id=%p: secure tunnel service id 3 set to: " PRInSTR,
                    (void *)secure_tunnel,
                    AWS_BYTE_CURSOR_PRI(*message_view->service_id_3));
            }
        }
    }

    struct aws_secure_tunnel_connection_view connection_view;
    AWS_ZERO_STRUCT(connection_view);
    connection_view.service_id_1 = message_view->service_id;
    connection_view.service_id_2 = message_view->service_id_2;
    connection_view.service_id_3 = message_view->service_id_3;

    /* A connection can only be used once available service ids are established with the secure tunnel. */
    if (secure_tunnel->config->on_connection_complete) {
        secure_tunnel->config->on_connection_complete(
            &connection_view, AWS_ERROR_SUCCESS, secure_tunnel->config->user_data);
    }
}

static void s_aws_secure_tunnel_connected_on_message_received(
    struct aws_secure_tunnel *secure_tunnel,
    struct aws_secure_tunnel_message_view *message_view) {
    aws_secure_tunnel_message_view_log(message_view, AWS_LL_DEBUG);
    switch (message_view->type) {
        case AWS_SECURE_TUNNEL_MT_DATA:
            if (secure_tunnel->config->on_message_received) {
                secure_tunnel->config->on_message_received(message_view, secure_tunnel->config->user_data);
            }
            break;
        case AWS_SECURE_TUNNEL_MT_STREAM_START:
            s_aws_secure_tunnel_on_stream_start_received(secure_tunnel, message_view);
            break;
        case AWS_SECURE_TUNNEL_MT_STREAM_RESET:
            s_aws_secure_tunnel_on_stream_reset_received(secure_tunnel, message_view);
            break;
        case AWS_SECURE_TUNNEL_MT_SESSION_RESET:
            s_aws_secure_tunnel_on_session_reset_received(secure_tunnel);
            break;
        case AWS_SECURE_TUNNEL_MT_SERVICE_IDS:
            s_aws_secure_tunnel_on_service_ids_received(secure_tunnel, message_view);
            break;
        case AWS_SECURE_TUNNEL_MT_CONNECTION_START:
        case AWS_SECURE_TUNNEL_MT_CONNECTION_RESET:
        case AWS_SECURE_TUNNEL_MT_UNKNOWN:
        default:
            if (!message_view->ignorable) {
                AWS_LOGF_WARN(
                    AWS_LS_IOTDEVICE_SECURE_TUNNELING,
                    "Encountered an unknown but un-ignorable message. type=%s",
                    aws_secure_tunnel_message_type_to_c_string(message_view->type));
            }
            break;
    }
}

static void s_process_received_data(struct aws_secure_tunnel *secure_tunnel) {
    struct aws_byte_buf *received_data = &secure_tunnel->received_data;
    struct aws_byte_cursor cursor = aws_byte_cursor_from_buf(received_data);
    uint16_t data_length = 0;
    /*
     * If there are at least two bytes for the data_length, but not enough data for a complete secure tunnel frame, we
     * don't want to move `cursor`.
     */
    struct aws_byte_cursor tmp_cursor = cursor;
    while (aws_byte_cursor_read_be16(&tmp_cursor, &data_length) && tmp_cursor.len >= data_length) {
        cursor = tmp_cursor;

        struct aws_byte_cursor st_frame = {.len = data_length, .ptr = cursor.ptr};
        aws_byte_cursor_advance(&cursor, data_length);
        tmp_cursor = cursor;

        if (aws_secure_tunnel_deserialize_message_from_cursor(
                secure_tunnel, &st_frame, &s_aws_secure_tunnel_connected_on_message_received)) {
            int error_code = aws_last_error();
            AWS_LOGF_ERROR(
                AWS_LS_IOTDEVICE_SECURE_TUNNELING,
                "id=%p: failed to deserialize message with error %d(%s)",
                (void *)secure_tunnel,
                error_code,
                aws_error_debug_str(error_code));
        }
    }

    if (cursor.ptr != received_data->buffer) {
        /* Move unprocessed data to the beginning */
        received_data->len = 0;
        aws_byte_buf_append(received_data, &cursor);
    }
}

/*****************************************************************************************************************
 *                                    SEND MESSAGE HANDLING
 *****************************************************************************************************************/

static void s_secure_tunneling_websocket_on_send_data_complete_callback(
    struct aws_websocket *websocket,
    int error_code,
    void *user_data) {
    (void)websocket;
    struct data_tunnel_pair *pair = user_data;
    struct aws_secure_tunnel *secure_tunnel = (struct aws_secure_tunnel *)pair->secure_tunnel;
    if (secure_tunnel->config->on_send_data_complete) {
        secure_tunnel->config->on_send_data_complete(error_code, pair->secure_tunnel->config->user_data);
    }
    aws_secure_tunnel_data_tunnel_pair_destroy(pair);
    secure_tunnel->pending_write_completion = false;
}

static bool secure_tunneling_websocket_stream_outgoing_payload(
    struct aws_websocket *websocket,
    struct aws_byte_buf *out_buf,
    void *user_data) {
    (void)websocket;
    struct data_tunnel_pair *pair = user_data;
    size_t space_available = out_buf->capacity - out_buf->len;

    if ((pair->length_prefix_written == false) && (space_available >= PAYLOAD_BYTE_LENGTH_PREFIX)) {
        if (aws_byte_buf_write_be16(out_buf, (int16_t)pair->buf.len) == false) {
            AWS_LOGF_ERROR(AWS_LS_IOTDEVICE_SECURE_TUNNELING, "Failure writing buffer length prefix to out_buf");
            return false;
        }
        pair->length_prefix_written = true;
        space_available = out_buf->capacity - out_buf->len;
    }

    if (pair->length_prefix_written == true) {
        pair->cur = aws_byte_buf_write_to_capacity(out_buf, &pair->cur);
    }

    return true;
}

static void s_init_websocket_frame_options(
    struct data_tunnel_pair *pair,
    struct aws_websocket_send_frame_options *frame_options) {
    AWS_ZERO_STRUCT(*frame_options);
    frame_options->payload_length = pair->buf.len + PAYLOAD_BYTE_LENGTH_PREFIX;
    frame_options->user_data = pair;
    frame_options->stream_outgoing_payload = secure_tunneling_websocket_stream_outgoing_payload;
    frame_options->on_complete = s_secure_tunneling_websocket_on_send_data_complete_callback;
    frame_options->opcode = AWS_WEBSOCKET_OPCODE_BINARY;
    frame_options->fin = true;
}

int secure_tunneling_init_send_frame(
    struct aws_secure_tunnel *secure_tunnel,
    struct aws_websocket_send_frame_options *frame_options,
    const struct aws_secure_tunnel_message_view *message_view) {

    struct data_tunnel_pair *pair =
        aws_secure_tunnel_data_tunnel_pair_new(secure_tunnel->allocator, secure_tunnel, message_view);

    if (!pair) {
        return AWS_OP_ERR;
    }

    s_init_websocket_frame_options(pair, frame_options);
    return AWS_OP_SUCCESS;
}

static int s_secure_tunneling_send(
    struct aws_secure_tunnel *secure_tunnel,
    const struct aws_secure_tunnel_message_view *message_view) {
    struct aws_websocket_send_frame_options frame_options;
    if (secure_tunneling_init_send_frame(secure_tunnel, &frame_options, message_view)) {
        return AWS_OP_ERR;
    }

    /* Prevent further operations that attempt to write to the WebSocket until current operation is completed */
    secure_tunnel->pending_write_completion = true;
    return aws_websocket_send_frame(secure_tunnel->websocket, &frame_options);
}

/*****************************************************************************************************************
 *                                    Websocket
 *****************************************************************************************************************/
typedef int(
    websocket_send_frame)(struct aws_websocket *websocket, const struct aws_websocket_send_frame_options *options);

static bool s_on_websocket_incoming_frame_begin(
    struct aws_websocket *websocket,
    const struct aws_websocket_incoming_frame *frame,
    void *user_data) {
    (void)websocket;
    (void)frame;
    (void)user_data;
    return true;
}

static bool s_on_websocket_incoming_frame_payload(
    struct aws_websocket *websocket,
    const struct aws_websocket_incoming_frame *frame,
    struct aws_byte_cursor data,
    void *user_data) {

    (void)websocket;
    (void)frame;

    if (data.len > 0) {
        struct aws_secure_tunnel *secure_tunnel = user_data;
        aws_byte_buf_append(&secure_tunnel->received_data, &data);
        s_process_received_data(secure_tunnel);
    }

    return true;
}

static bool s_on_websocket_incoming_frame_complete(
    struct aws_websocket *websocket,
    const struct aws_websocket_incoming_frame *frame,
    int error_code,
    void *user_data) {
    (void)websocket;
    (void)frame;

    if (error_code) {
        AWS_LOGF_ERROR(
            AWS_LS_IOTDEVICE_SECURE_TUNNELING,
            "id=%p: Error on s_on_websocket_incoming_frame_complete() with error %d(%s).",
            (void *)user_data,
            error_code,
            aws_error_debug_str(error_code));
    }

    return true;
}

static void s_secure_tunnel_shutdown(struct aws_client_bootstrap *bootstrap, int error_code, void *user_data) {
    (void)bootstrap;
    struct aws_secure_tunnel *secure_tunnel = user_data;

    if (error_code == AWS_ERROR_SUCCESS) {
        error_code = AWS_ERROR_IOTDEVICE_SECURE_TUNNELING_UNEXPECTED_HANGUP;
    }

    /* fail current and all pending operations */
    if (secure_tunnel->current_operation != NULL) {
        aws_linked_list_push_front(&secure_tunnel->queued_operations, &secure_tunnel->current_operation->node);
        secure_tunnel->current_operation = NULL;
    }

    if (!aws_linked_list_empty(&secure_tunnel->queued_operations)) {
        s_complete_operation_list(
            secure_tunnel,
            &secure_tunnel->queued_operations,
            AWS_ERROR_IOTDEVICE_SECURE_TUNNELING_OPERATION_FAILED_DUE_TO_OFFLINE_QUEUE_POLICY);
    }
}

/* Normal call to shutdown the websocket */
static void s_secure_tunnel_shutdown_websocket(struct aws_secure_tunnel *secure_tunnel, int error_code) {
    (void)error_code;
    if (secure_tunnel->current_state != AWS_STS_CONNECTED && secure_tunnel->current_state != AWS_STS_CLEAN_DISCONNECT) {
        AWS_LOGF_ERROR(
            AWS_LS_IOTDEVICE_SECURE_TUNNELING,
            "id=%p: secure tunnel websocket shutdown invoked from unexpected state %d(%s)",
            (void *)secure_tunnel,
            (int)secure_tunnel->current_state,
            aws_secure_tunnel_state_to_c_string(secure_tunnel->current_state));
        return;
    }

    s_change_current_state(secure_tunnel, AWS_STS_WEBSOCKET_SHUTDOWN);
}

/* Called by websocket when it's destroyed or manually on failed websocket creation */
static void s_on_websocket_shutdown(struct aws_websocket *websocket, int error_code, void *user_data) {
    struct aws_secure_tunnel *secure_tunnel = user_data;
    s_secure_tunnel_shutdown(secure_tunnel->config->bootstrap, error_code, secure_tunnel);

    aws_websocket_release(websocket);
    websocket = NULL;

    if (secure_tunnel->config->on_connection_shutdown) {
        secure_tunnel->config->on_connection_shutdown(error_code, secure_tunnel->config->user_data);
    }

    if (secure_tunnel->desired_state == AWS_STS_CONNECTED) {
        s_change_current_state(secure_tunnel, AWS_STS_PENDING_RECONNECT);
    } else {
        s_change_current_state(secure_tunnel, AWS_STS_STOPPED);
    }
}

static void s_secure_tunnel_setup(struct aws_client_bootstrap *bootstrap, int error_code, void *user_data) {
    (void)bootstrap;
    struct aws_secure_tunnel *secure_tunnel = user_data;

    if (error_code != AWS_OP_SUCCESS) {
        if (secure_tunnel->config->on_connection_complete) {
            if (secure_tunnel->config->on_connection_complete) {
                secure_tunnel->config->on_connection_complete(NULL, error_code, secure_tunnel->config->user_data);
            }
        }
        s_on_websocket_shutdown(secure_tunnel->websocket, error_code, secure_tunnel);
        return;
    }

    AWS_FATAL_ASSERT(secure_tunnel->current_state == AWS_STS_CONNECTING);
    AWS_FATAL_ASSERT(aws_event_loop_thread_is_callers_thread(secure_tunnel->loop));

    if (secure_tunnel->desired_state != AWS_STS_CONNECTED) {
        aws_raise_error(AWS_ERROR_IOTDEVICE_SECURE_TUNNELING_USER_REQUESTED_STOP);
        goto error;
    }

    s_change_current_state(secure_tunnel, AWS_STS_CONNECTED);

    return;
error:
    s_on_websocket_shutdown(secure_tunnel->websocket, error_code, secure_tunnel);
}

/* Called on successful or failed websocket setup attempt */
static void s_on_websocket_setup(const struct aws_websocket_on_connection_setup_data *setup, void *user_data) {
    struct aws_secure_tunnel *secure_tunnel = user_data;
    secure_tunnel->handshake_request = aws_http_message_release(secure_tunnel->handshake_request);

    /* Setup callback contract is: if error_code is non-zero then websocket is NULL. */
    AWS_FATAL_ASSERT((setup->error_code != 0) == (setup->websocket == NULL));

    secure_tunnel->websocket = setup->websocket;

    /* Report a failed WebSocket Upgrade attempt */
    if (setup->error_code && secure_tunnel->config->on_connection_complete) {
        secure_tunnel->config->on_connection_complete(NULL, setup->error_code, secure_tunnel->config->user_data);
    }

    /* Failed/Successful websocket creation and associated errors logged by "websocket-setup" */

    s_secure_tunnel_setup(secure_tunnel->config->bootstrap, setup->error_code, secure_tunnel);
}

struct aws_secure_tunnel_websocket_transform_complete_task {
    struct aws_task task;
    struct aws_allocator *allocator;
    struct aws_secure_tunnel *secure_tunnel;
    int error_code;
    struct aws_http_message *handshake;
};

void s_websocket_transform_complete_task_fn(struct aws_task *task, void *arg, enum aws_task_status status) {
    (void)task;

    struct aws_secure_tunnel_websocket_transform_complete_task *websocket_transform_complete_task = arg;
    if (status != AWS_TASK_STATUS_RUN_READY) {
        goto done;
    }

    struct aws_secure_tunnel *secure_tunnel = websocket_transform_complete_task->secure_tunnel;

    aws_http_message_release(secure_tunnel->handshake_request);
    secure_tunnel->handshake_request = aws_http_message_acquire(websocket_transform_complete_task->handshake);

    int error_code = websocket_transform_complete_task->error_code;
    if (error_code == 0 && secure_tunnel->desired_state == AWS_STS_CONNECTED) {
        struct aws_websocket_client_connection_options websocket_options = {
            .allocator = secure_tunnel->allocator,
            .bootstrap = secure_tunnel->config->bootstrap,
            .socket_options = &secure_tunnel->config->socket_options,
            .tls_options = &secure_tunnel->tls_con_opt,
            .host = aws_byte_cursor_from_string(secure_tunnel->config->endpoint_host),
            .port = 443,
            .handshake_request = secure_tunnel->handshake_request,
            .manual_window_management = false,
            .user_data = secure_tunnel,
            .requested_event_loop = secure_tunnel->loop,

            .on_connection_setup = s_on_websocket_setup,
            .on_connection_shutdown = s_on_websocket_shutdown,
            .on_incoming_frame_begin = s_on_websocket_incoming_frame_begin,
            .on_incoming_frame_payload = s_on_websocket_incoming_frame_payload,
            .on_incoming_frame_complete = s_on_websocket_incoming_frame_complete,
        };

        if (secure_tunnel->config->http_proxy_config != NULL) {
            websocket_options.proxy_options = &secure_tunnel->config->http_proxy_options;
        }

        if (aws_websocket_client_connect(&websocket_options)) {
            AWS_LOGF_ERROR(
                AWS_LS_IOTDEVICE_SECURE_TUNNELING,
                "id=%p: Failed to initiate websocket connection.",
                (void *)secure_tunnel);
            error_code = aws_last_error();
            goto error;
        }

        goto done;
    } else {
        if (error_code == AWS_ERROR_SUCCESS) {
            AWS_ASSERT(secure_tunnel->desired_state != AWS_STS_CONNECTED);
            error_code = AWS_ERROR_IOTDEVICE_SECURE_TUNNELING_USER_REQUESTED_STOP;
        }
    }

error:;
    struct aws_websocket_on_connection_setup_data websocket_setup = {.error_code = error_code};
    s_on_websocket_setup(&websocket_setup, secure_tunnel);

done:
    aws_http_message_release(websocket_transform_complete_task->handshake);
    aws_secure_tunnel_release(websocket_transform_complete_task->secure_tunnel);
    aws_mem_release(websocket_transform_complete_task->allocator, websocket_transform_complete_task);
}

static int s_handshake_add_header(
    const struct aws_secure_tunnel *secure_tunnel,
    struct aws_http_message *handshake,
    struct aws_http_header header) {
    if (aws_http_message_add_header(handshake, header)) {
        AWS_LOGF_ERROR(
            AWS_LS_IOTDEVICE_SECURE_TUNNELING,
            "id=%p: Failed to add header to websocket handshake request",
            (void *)secure_tunnel);
        return AWS_OP_ERR;
    }
    AWS_LOGF_TRACE(
        AWS_LS_IOTDEVICE_SECURE_TUNNELING,
        "id=%p: Added header " PRInSTR " " PRInSTR " to websocket request",
        (void *)secure_tunnel,
        AWS_BYTE_CURSOR_PRI(header.name),
        AWS_BYTE_CURSOR_PRI(header.value));
    return AWS_OP_SUCCESS;
}

static struct aws_http_message *s_new_handshake_request(const struct aws_secure_tunnel *secure_tunnel) {
    char path[50];
    snprintf(
        path,
        sizeof(path),
        "/tunnel?local-proxy-mode=%s",
        s_get_proxy_mode_string(secure_tunnel->config->local_proxy_mode));

    struct aws_http_message *handshake = aws_http_message_new_websocket_handshake_request(
        secure_tunnel->allocator,
        aws_byte_cursor_from_c_str(path),
        aws_byte_cursor_from_string(secure_tunnel->config->endpoint_host));

    if (handshake == NULL) {
        AWS_LOGF_ERROR(
            AWS_LS_IOTDEVICE_SECURE_TUNNELING, "id=%p: Failed to generate handshake request.", (void *)secure_tunnel);
        goto error;
    }

    /* Secure Tunnel specific headers */
    struct aws_http_header header_protocol = {
        .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL(WEBSOCKET_HEADER_NAME_PROTOCOL),
        .value = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL(WEBSOCKET_HEADER_PROTOCOL_VALUE),
    };
    if (s_handshake_add_header(secure_tunnel, handshake, header_protocol)) {
        goto error;
    }

    struct aws_http_header header_access_token = {
        .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL(WEBSOCKET_HEADER_NAME_ACCESS_TOKEN),
        .value = aws_byte_cursor_from_string(secure_tunnel->config->access_token),
    };
    if (s_handshake_add_header(secure_tunnel, handshake, header_access_token)) {
        goto error;
    }

    if (secure_tunnel->config->client_token) {
        struct aws_http_header header_client_token = {
            .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL(WEBSOCKET_HEADER_NAME_CLIENT_TOKEN),
            .value = aws_byte_cursor_from_string(secure_tunnel->config->client_token),
        };
        if (s_handshake_add_header(secure_tunnel, handshake, header_client_token)) {
            goto error;
        }
    }

    return handshake;

error:
    aws_http_message_release(handshake);
    return NULL;
}

static int s_websocket_connect(struct aws_secure_tunnel *secure_tunnel) {
    AWS_ASSERT(secure_tunnel);

    struct aws_http_message *handshake = s_new_handshake_request(secure_tunnel);
    if (handshake == NULL) {
        goto error;
    }

    AWS_LOGF_TRACE(
        AWS_LS_IOTDEVICE_SECURE_TUNNELING, "id=%p: Transforming websocket handshake request.", (void *)secure_tunnel);

    struct aws_secure_tunnel_websocket_transform_complete_task *task =
        aws_mem_calloc(secure_tunnel->allocator, 1, sizeof(struct aws_secure_tunnel_websocket_transform_complete_task));

    aws_task_init(
        &task->task, s_websocket_transform_complete_task_fn, (void *)task, "WebsocketHandshakeTransformComplete");
    task->allocator = secure_tunnel->allocator;
    task->secure_tunnel = aws_secure_tunnel_acquire(secure_tunnel);
    task->error_code = AWS_OP_SUCCESS;
    task->handshake = handshake;

    aws_event_loop_schedule_task_now(secure_tunnel->loop, &task->task);

    return AWS_OP_SUCCESS;

error:
    return AWS_OP_ERR;
}

static void s_reset_ping(struct aws_secure_tunnel *secure_tunnel) {
    uint64_t now = (*secure_tunnel->vtable->get_current_time_fn)();
    secure_tunnel->next_ping_time = aws_add_u64_saturating(now, PING_TASK_INTERVAL);

    AWS_LOGF_DEBUG(
        AWS_LS_IOTDEVICE_SECURE_TUNNELING,
        "id=%p: next PING scheduled for time %" PRIu64,
        (void *)secure_tunnel,
        secure_tunnel->next_ping_time);
}

/*********************************************************************************************************************
 * State Related
 ********************************************************************************************************************/

static void s_aws_secure_tunnel_operational_state_reset(
    struct aws_secure_tunnel *secure_tunnel,
    int completion_error_code) {
    s_complete_operation_list(secure_tunnel, &secure_tunnel->queued_operations, completion_error_code);
}

static void s_change_current_state_to_stopped(struct aws_secure_tunnel *secure_tunnel) {
    secure_tunnel->current_state = AWS_STS_STOPPED;

    s_aws_secure_tunnel_operational_state_reset(
        secure_tunnel, AWS_ERROR_IOTDEVICE_SECURE_TUNNELING_USER_REQUESTED_STOP);

    /* Stop works as a complete session wipe, and so the next time we connect, we want it to be clean */
    s_reset_secure_tunnel(secure_tunnel);

    if (secure_tunnel->config->on_stopped) {
        secure_tunnel->config->on_stopped(secure_tunnel->config->user_data);
    }
}

static void s_change_current_state_to_connecting(struct aws_secure_tunnel *secure_tunnel) {
    AWS_ASSERT(
        secure_tunnel->current_state == AWS_STS_STOPPED || secure_tunnel->current_state == AWS_STS_PENDING_RECONNECT);

    secure_tunnel->current_state = AWS_STS_CONNECTING;

    int result = s_websocket_connect(secure_tunnel);

    if (result) {
        int error_code = aws_last_error();
        AWS_LOGF_INFO(
            AWS_LS_IOTDEVICE_SECURE_TUNNELING,
            "id=%p: failed to kick off connection with error %d(%s)",
            (void *)secure_tunnel,
            error_code,
            aws_error_debug_str(error_code));

        s_change_current_state(secure_tunnel, AWS_STS_PENDING_RECONNECT);
    }
}

static void s_change_current_state_to_connected(struct aws_secure_tunnel *secure_tunnel) {
    AWS_FATAL_ASSERT(secure_tunnel->current_state == AWS_STS_CONNECTING);

    secure_tunnel->current_state = AWS_STS_CONNECTED;
    secure_tunnel->pending_write_completion = false;
    secure_tunnel->reconnect_count = 0;

    /*
     * TODO Any rejoin logic can be implemented here. Secure Tunnel does not handle any rejoin state.
     * We may opt to send disconnects to existing non-zero stream IDs to notify that the server has reconnected.
     */

    s_reset_ping(secure_tunnel);
}

static void s_change_current_state_to_clean_disconnect(struct aws_secure_tunnel *secure_tunnel) {
    AWS_FATAL_ASSERT(secure_tunnel->current_state == AWS_STS_CONNECTED);

    secure_tunnel->current_state = AWS_STS_CLEAN_DISCONNECT;
}

static void s_change_current_state_to_websocket_shutdown(struct aws_secure_tunnel *secure_tunnel) {
    enum aws_secure_tunnel_state current_state = secure_tunnel->current_state;
    AWS_FATAL_ASSERT(
        current_state == AWS_STS_CONNECTING || current_state == AWS_STS_CONNECTED ||
        current_state == AWS_STS_CLEAN_DISCONNECT);

    if (secure_tunnel->websocket) {
        aws_websocket_close(secure_tunnel->websocket, false);
    } else {
        s_on_websocket_shutdown(secure_tunnel->websocket, AWS_ERROR_UNKNOWN, secure_tunnel);
    }

    secure_tunnel->current_state = AWS_STS_WEBSOCKET_SHUTDOWN;
}

static void s_update_reconnect_delay_for_pending_reconnect(struct aws_secure_tunnel *secure_tunnel) {

    uint64_t delay_ms = MIN_RECONNECT_DELAY_MS;
    delay_ms = delay_ms << (int)secure_tunnel->reconnect_count;

    delay_ms = aws_min_u64(delay_ms, MAX_RECONNECT_DELAY_MS);
    uint64_t now = (*secure_tunnel->vtable->get_current_time_fn)();

    secure_tunnel->next_reconnect_time_ns =
        aws_add_u64_saturating(now, aws_timestamp_convert(delay_ms, AWS_TIMESTAMP_MILLIS, AWS_TIMESTAMP_NANOS, NULL));

    AWS_LOGF_DEBUG(
        AWS_LS_IOTDEVICE_SECURE_TUNNELING,
        "id=%p: next connection attempt in %" PRIu64 " milliseconds",
        (void *)secure_tunnel,
        delay_ms);

    secure_tunnel->reconnect_count++;
}

static void s_change_current_state_to_pending_reconnect(struct aws_secure_tunnel *secure_tunnel) {
    secure_tunnel->current_state = AWS_STS_PENDING_RECONNECT;

    s_update_reconnect_delay_for_pending_reconnect(secure_tunnel);
}

static void s_change_current_state_to_terminated(struct aws_secure_tunnel *secure_tunnel) {
    secure_tunnel->current_state = AWS_STS_TERMINATED;

    s_secure_tunnel_final_destroy(secure_tunnel);
}

static void s_change_current_state(struct aws_secure_tunnel *secure_tunnel, enum aws_secure_tunnel_state next_state) {
    AWS_ASSERT(next_state != secure_tunnel->current_state);
    if (next_state == secure_tunnel->current_state) {
        return;
    }

    AWS_LOGF_DEBUG(
        AWS_LS_IOTDEVICE_SECURE_TUNNELING,
        "id=%p: switching current state from %s to %s",
        (void *)secure_tunnel,
        aws_secure_tunnel_state_to_c_string(secure_tunnel->current_state),
        aws_secure_tunnel_state_to_c_string(next_state));

    switch (next_state) {
        case AWS_STS_STOPPED:
            s_change_current_state_to_stopped(secure_tunnel);
            break;
        case AWS_STS_CONNECTING:
            s_change_current_state_to_connecting(secure_tunnel);
            break;
        case AWS_STS_CONNECTED:
            s_change_current_state_to_connected(secure_tunnel);
            break;
        case AWS_STS_CLEAN_DISCONNECT:
            s_change_current_state_to_clean_disconnect(secure_tunnel);
            break;
        case AWS_STS_WEBSOCKET_SHUTDOWN:
            s_change_current_state_to_websocket_shutdown(secure_tunnel);
            break;
        case AWS_STS_PENDING_RECONNECT:
            s_change_current_state_to_pending_reconnect(secure_tunnel);
            break;
        case AWS_STS_TERMINATED:
            s_change_current_state_to_terminated(secure_tunnel);
            return;
    }

    s_reevaluate_service_task(secure_tunnel);
}

static bool s_is_valid_desired_state(enum aws_secure_tunnel_state desired_state) {
    switch (desired_state) {
        case AWS_STS_STOPPED:
        case AWS_STS_CONNECTED:
        case AWS_STS_TERMINATED:
            return true;
        default:
            return false;
    }
}

struct aws_secure_tunnel_change_desired_state_task {
    struct aws_task task;
    struct aws_allocator *allocator;
    struct aws_secure_tunnel *secure_tunnel;
    enum aws_secure_tunnel_state desired_state;
};

static void s_change_state_task_fn(struct aws_task *task, void *arg, enum aws_task_status status) {
    (void)task;

    struct aws_secure_tunnel_change_desired_state_task *change_state_task = arg;
    struct aws_secure_tunnel *secure_tunnel = change_state_task->secure_tunnel;
    enum aws_secure_tunnel_state desired_state = change_state_task->desired_state;
    if (status != AWS_TASK_STATUS_RUN_READY) {
        goto done;
    }

    if (secure_tunnel->desired_state != desired_state) {
        AWS_LOGF_INFO(
            AWS_LS_IOTDEVICE_SECURE_TUNNELING,
            "id=%p: changing desired secure_tunnel state from %s to %s",
            (void *)secure_tunnel,
            aws_secure_tunnel_state_to_c_string(secure_tunnel->desired_state),
            aws_secure_tunnel_state_to_c_string(desired_state));

        secure_tunnel->desired_state = desired_state;

        s_reevaluate_service_task(secure_tunnel);
    }

done:

    if (desired_state != AWS_STS_TERMINATED) {
        aws_secure_tunnel_release(secure_tunnel);
    }

    aws_mem_release(change_state_task->allocator, change_state_task);
}

static struct aws_secure_tunnel_change_desired_state_task *s_aws_secure_tunnel_change_desired_state_task_new(
    struct aws_allocator *allocator,
    struct aws_secure_tunnel *secure_tunnel,
    enum aws_secure_tunnel_state desired_state) {

    struct aws_secure_tunnel_change_desired_state_task *change_state_task =
        aws_mem_calloc(allocator, 1, sizeof(struct aws_secure_tunnel_change_desired_state_task));
    if (change_state_task == NULL) {
        return NULL;
    }

    aws_task_init(&change_state_task->task, s_change_state_task_fn, (void *)change_state_task, "ChangeStateTask");
    change_state_task->allocator = secure_tunnel->allocator;
    change_state_task->secure_tunnel =
        (desired_state == AWS_STS_TERMINATED) ? secure_tunnel : aws_secure_tunnel_acquire(secure_tunnel);
    change_state_task->desired_state = desired_state;

    return change_state_task;
}

static int s_aws_secure_tunnel_change_desired_state(
    struct aws_secure_tunnel *secure_tunnel,
    enum aws_secure_tunnel_state desired_state) {
    AWS_FATAL_ASSERT(secure_tunnel != NULL);
    AWS_FATAL_ASSERT(secure_tunnel->loop != NULL);

    if (!s_is_valid_desired_state(desired_state)) {
        AWS_LOGF_ERROR(
            AWS_LS_IOTDEVICE_SECURE_TUNNELING,
            "id=%p: invalid desired state argument %d(%s)",
            (void *)secure_tunnel,
            (int)desired_state,
            aws_secure_tunnel_state_to_c_string(desired_state));

        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }

    struct aws_secure_tunnel_change_desired_state_task *task =
        s_aws_secure_tunnel_change_desired_state_task_new(secure_tunnel->allocator, secure_tunnel, desired_state);

    if (task == NULL) {
        AWS_LOGF_ERROR(
            AWS_LS_IOTDEVICE_SECURE_TUNNELING,
            "id=%p: failed to create change desired state task",
            (void *)secure_tunnel);
        return AWS_OP_ERR;
    }

    aws_event_loop_schedule_task_now(secure_tunnel->loop, &task->task);

    return AWS_OP_SUCCESS;
}

/*********************************************************************************************************************
 * vtable functions
 ********************************************************************************************************************/

static uint64_t s_aws_high_res_clock_get_ticks_proxy(void) {
    uint64_t current_time = 0;
    AWS_FATAL_ASSERT(aws_high_res_clock_get_ticks(&current_time) == AWS_OP_SUCCESS);

    return current_time;
}

static struct aws_secure_tunnel_vtable s_default_secure_tunnel_vtable = {
    .get_current_time_fn = s_aws_high_res_clock_get_ticks_proxy,
};

/*********************************************************************************************************************
 * Operations
 ********************************************************************************************************************/

static void s_complete_operation(
    struct aws_secure_tunnel *secure_tunnel,
    struct aws_secure_tunnel_operation *operation,
    int error_code,
    const void *view) {
    (void)secure_tunnel;

    aws_secure_tunnel_operation_complete(operation, error_code, view);
    aws_secure_tunnel_operation_release(operation);
}

static void s_complete_operation_list(
    struct aws_secure_tunnel *secure_tunnel,
    struct aws_linked_list *operation_list,
    int error_code) {

    struct aws_linked_list_node *node = aws_linked_list_begin(operation_list);
    while (node != aws_linked_list_end(operation_list)) {
        struct aws_secure_tunnel_operation *operation =
            AWS_CONTAINER_OF(node, struct aws_secure_tunnel_operation, node);

        node = aws_linked_list_next(node);

        s_complete_operation(secure_tunnel, operation, error_code, NULL);
    }

    /* we've released everything, so reset the list to empty */
    aws_linked_list_init(operation_list);
}

/*
 * Check whether secure tunnel currently has work left to do based on its current state
 */
static bool s_aws_secure_tunnel_has_pending_operational_work(const struct aws_secure_tunnel *secure_tunnel) {
    if (aws_linked_list_empty(&secure_tunnel->queued_operations)) {
        return false;
    }

    struct aws_linked_list_node *next_operation_node = aws_linked_list_front(&secure_tunnel->queued_operations);
    struct aws_secure_tunnel_operation *next_operation =
        AWS_CONTAINER_OF(next_operation_node, struct aws_secure_tunnel_operation, node);

    switch (secure_tunnel->current_state) {
        case AWS_STS_CLEAN_DISCONNECT:
            /* Except for finishing the current operation, only allowed to send STREAM RESET messages in this state
             */
            return next_operation->operation_type == AWS_STOT_STREAM_RESET;

        case AWS_STS_CONNECTED:
            return true;

        default:
            return false;
    }
}

static uint64_t s_aws_secure_tunnel_compute_operational_state_service_time(
    struct aws_secure_tunnel *secure_tunnel,
    uint64_t now) {

    /* If a message is in transit down the WebSocket, then wait for it to complete */
    if (secure_tunnel->pending_write_completion) {
        return 0;
    }

    /* If we're in the middle of something, keep going */
    if (secure_tunnel->current_operation != NULL) {
        return now;
    }

    /* If nothing is queued, there's nothing to do */
    if (!s_aws_secure_tunnel_has_pending_operational_work(secure_tunnel)) {
        return 0;
    }

    AWS_FATAL_ASSERT(!aws_linked_list_empty(&secure_tunnel->queued_operations));

    struct aws_linked_list_node *next_operation_node = aws_linked_list_front(&secure_tunnel->queued_operations);
    struct aws_secure_tunnel_operation *next_operation =
        AWS_CONTAINER_OF(next_operation_node, struct aws_secure_tunnel_operation, node);

    AWS_FATAL_ASSERT(next_operation != NULL);

    /* now unless outside of allowed states */
    switch (secure_tunnel->current_state) {
        case AWS_STS_CLEAN_DISCONNECT:
        case AWS_STS_CONNECTED:
            return now;

        default:
            /* no outbound traffic is allowed outside of the above states */
            return 0;
    }
}

static bool s_aws_secure_tunnel_should_service_operational_state(
    struct aws_secure_tunnel *secure_tunnel,
    uint64_t now) {
    return now == s_aws_secure_tunnel_compute_operational_state_service_time(secure_tunnel, now);
}

int aws_secure_tunnel_service_operational_state(struct aws_secure_tunnel *secure_tunnel) {
    const struct aws_secure_tunnel_vtable *vtable = secure_tunnel->vtable;
    uint64_t now = (*vtable->get_current_time_fn)();

    /* Should we write data? */
    bool should_service = s_aws_secure_tunnel_should_service_operational_state(secure_tunnel, now);
    if (!should_service) {
        return AWS_OP_SUCCESS;
    }

    int operational_error_code = AWS_ERROR_SUCCESS;

    do {
        /* if no current operation, pull one in and setup encode */
        if (secure_tunnel->current_operation == NULL) {
            /*
             * Loop through queued operations until we run out or find a good one.
             */
            struct aws_secure_tunnel_operation *next_operation = NULL;

            if (!aws_linked_list_empty(&secure_tunnel->queued_operations)) {
                struct aws_linked_list_node *next_operation_node =
                    aws_linked_list_pop_front(&secure_tunnel->queued_operations);

                next_operation = AWS_CONTAINER_OF(next_operation_node, struct aws_secure_tunnel_operation, node);

                secure_tunnel->current_operation = next_operation;
            }
        }

        struct aws_secure_tunnel_operation *current_operation = secure_tunnel->current_operation;
        if (current_operation == NULL) {
            break;
        }
        int error_code = AWS_OP_SUCCESS;

        switch (current_operation->operation_type) {
            case AWS_STOT_PING:;
                /*
                 * Currently, pings are sent to keep the websocket alive but we do not receive responses from the
                 * secure tunnel service until a src is also connected. This is a known bug that is in their
                 * backlog. Once it is fixed, we should implement ping timeout checks to determine whether we are
                 * still connected to the secure tunnel through WebSocket.
                 */
                struct aws_websocket_send_frame_options frame_options;
                AWS_ZERO_STRUCT(frame_options);
                frame_options.opcode = AWS_WEBSOCKET_OPCODE_PING;
                frame_options.fin = true;
                aws_websocket_send_frame(secure_tunnel->websocket, &frame_options);

                break;
            case AWS_STOT_MESSAGE:
                /* If a data message attempts to be sent on an unopen stream, discard it. */
                if ((*current_operation->vtable->aws_secure_tunnel_operation_assign_stream_id_fn)(
                        current_operation, secure_tunnel)) {

                    error_code = aws_last_error();

                    if (current_operation->message_view->service_id) {
                        AWS_LOGF_DEBUG(
                            AWS_LS_IOTDEVICE_SECURE_TUNNELING,
                            "id=%p: failed to assign service id '" PRInSTR
                            "' DATA message a stream id with error %d(%s)",
                            (void *)secure_tunnel,
                            AWS_BYTE_CURSOR_PRI(*current_operation->message_view->service_id),
                            error_code,
                            aws_error_debug_str(error_code));
                    } else {
                        AWS_LOGF_DEBUG(
                            AWS_LS_IOTDEVICE_SECURE_TUNNELING,
                            "id=%p: failed to assign V1 DATA message a stream id with error %d(%s)",
                            (void *)secure_tunnel,
                            error_code,
                            aws_error_debug_str(error_code));
                    }
                } else {
                    /* Send the Data message through the WebSocket */
                    if (s_secure_tunneling_send(secure_tunnel, current_operation->message_view)) {
                        error_code = aws_last_error();
                        AWS_LOGF_ERROR(
                            AWS_LS_IOTDEVICE_SECURE_TUNNELING,
                            "id=%p: failed to send DATA message with error %d(%s)",
                            (void *)secure_tunnel,
                            error_code,
                            aws_error_debug_str(error_code));
                    }
                    aws_secure_tunnel_message_view_log(current_operation->message_view, AWS_LL_DEBUG);
                }

                break;

            case AWS_STOT_STREAM_START:
                if ((*current_operation->vtable->aws_secure_tunnel_operation_set_next_stream_id_fn)(
                        current_operation, secure_tunnel)) {
                    error_code = aws_last_error();
                    AWS_LOGF_DEBUG(
                        AWS_LS_IOTDEVICE_SECURE_TUNNELING,
                        "id=%p: failed to send STREAM START message with error %d(%s)",
                        (void *)secure_tunnel,
                        error_code,
                        aws_error_debug_str(error_code));
                } else {
                    /* Send the Stream Start message through the WebSocket */
                    if (s_secure_tunneling_send(secure_tunnel, current_operation->message_view)) {
                        error_code = aws_last_error();
                    }
                    aws_secure_tunnel_message_view_log(current_operation->message_view, AWS_LL_DEBUG);
                }
                break;

            case AWS_STOT_STREAM_RESET:

                if ((*current_operation->vtable->aws_secure_tunnel_operation_assign_stream_id_fn)(
                        current_operation, secure_tunnel)) {
                    error_code = aws_last_error();
                    AWS_LOGF_DEBUG(
                        AWS_LS_IOTDEVICE_SECURE_TUNNELING,
                        "id=%p: failed to send STREAM RESET message with error %d(%s)",
                        (void *)secure_tunnel,
                        error_code,
                        aws_error_debug_str(error_code));
                } else {
                    /* Send the Stream Reset message through the WebSocket */
                    if (s_secure_tunneling_send(secure_tunnel, current_operation->message_view)) {
                        error_code = aws_last_error();
                    } else {
                        s_aws_secure_tunnel_set_stream_id(
                            secure_tunnel, current_operation->message_view->service_id, INVALID_STREAM_ID);
                    }
                    aws_secure_tunnel_message_view_log(current_operation->message_view, AWS_LL_DEBUG);
                }

                break;

            case AWS_STOT_NONE:
                break;
        }

        s_complete_operation(secure_tunnel, current_operation, AWS_OP_SUCCESS, NULL);
        secure_tunnel->current_operation = NULL;

        now = (*vtable->get_current_time_fn)();
        should_service = s_aws_secure_tunnel_should_service_operational_state(secure_tunnel, now);
    } while (should_service);

    if (operational_error_code != AWS_ERROR_SUCCESS) {
        return aws_raise_error(operational_error_code);
    }

    return AWS_OP_SUCCESS;
}

void aws_secure_tunnel_operational_state_clean_up(struct aws_secure_tunnel *secure_tunnel) {
    AWS_ASSERT(secure_tunnel->current_operation == NULL);

    s_aws_secure_tunnel_operational_state_reset(secure_tunnel, AWS_ERROR_IOTDEVICE_SECURE_TUNNELING_TERMINATED);
}

static void s_enqueue_operation_back(
    struct aws_secure_tunnel *secure_tunnel,
    struct aws_secure_tunnel_operation *operation) {
    AWS_LOGF_DEBUG(
        AWS_LS_IOTDEVICE_SECURE_TUNNELING,
        "id=%p: enqueuing %s operation to back",
        (void *)secure_tunnel,
        aws_secure_tunnel_operation_type_to_c_string(operation->operation_type));

    aws_linked_list_push_back(&secure_tunnel->queued_operations, &operation->node);

    s_reevaluate_service_task(secure_tunnel);
}

static void s_enqueue_operation_front(
    struct aws_secure_tunnel *secure_tunnel,
    struct aws_secure_tunnel_operation *operation) {
    AWS_LOGF_DEBUG(
        AWS_LS_IOTDEVICE_SECURE_TUNNELING,
        "id=%p: enqueuing %s operation to front",
        (void *)secure_tunnel,
        aws_secure_tunnel_operation_type_to_c_string(operation->operation_type));

    aws_linked_list_push_front(&secure_tunnel->queued_operations, &operation->node);

    s_reevaluate_service_task(secure_tunnel);
}

struct aws_secure_tunnel_submit_operation_task {
    struct aws_task task;
    struct aws_allocator *allocator;
    struct aws_secure_tunnel *secure_tunnel;
    struct aws_secure_tunnel_operation *operation;
};

static void s_secure_tunnel_submit_operation_task_fn(struct aws_task *task, void *arg, enum aws_task_status status) {
    (void)task;

    int completion_error_code = AWS_ERROR_IOTDEVICE_SECURE_TUNNELING_SECURE_TUNNEL_TERMINATED;
    struct aws_secure_tunnel_submit_operation_task *submit_operation_task = arg;

    /*
     * Take a ref to the operation that represents the secure tunnel taking ownership
     * If we subsequently reject it (task cancel), then the operation completion
     * will undo this ref acquisition.
     */
    aws_secure_tunnel_operation_acquire(submit_operation_task->operation);

    if (status != AWS_TASK_STATUS_RUN_READY) {
        goto error;
    }

    /*
     * If we're offline fail it immediately.
     */
    struct aws_secure_tunnel *secure_tunnel = submit_operation_task->secure_tunnel;
    if (secure_tunnel->current_state != AWS_STS_CONNECTED) {
        completion_error_code = AWS_ERROR_IOTDEVICE_SECURE_TUNNELING_OPERATION_FAILED_DUE_TO_DISCONNECTION;
        goto error;
    }

    s_enqueue_operation_back(submit_operation_task->secure_tunnel, submit_operation_task->operation);

    goto done;

error:
    s_complete_operation(NULL, submit_operation_task->operation, completion_error_code, NULL);

done:
    aws_secure_tunnel_operation_release(submit_operation_task->operation);
    aws_secure_tunnel_release(submit_operation_task->secure_tunnel);

    aws_mem_release(submit_operation_task->allocator, submit_operation_task);
}

static int s_submit_operation(struct aws_secure_tunnel *secure_tunnel, struct aws_secure_tunnel_operation *operation) {
    struct aws_secure_tunnel_submit_operation_task *submit_task =
        aws_mem_calloc(secure_tunnel->allocator, 1, sizeof(struct aws_secure_tunnel_submit_operation_task));
    if (submit_task == NULL) {
        return AWS_OP_ERR;
    }

    aws_task_init(
        &submit_task->task, s_secure_tunnel_submit_operation_task_fn, submit_task, "SecureTunnelSubmitOperation");
    submit_task->allocator = secure_tunnel->allocator;
    submit_task->secure_tunnel = aws_secure_tunnel_acquire(secure_tunnel);
    submit_task->operation = operation;

    aws_event_loop_schedule_task_now(secure_tunnel->loop, &submit_task->task);

    return AWS_OP_SUCCESS;
}

/*********************************************************************************************************************
 * Service Timing
 ********************************************************************************************************************/

static uint64_t s_min_non_0_64(uint64_t a, uint64_t b) {
    if (a == 0) {
        return b;
    }

    if (b == 0) {
        return a;
    }

    return aws_min_u64(a, b);
}

/*
 * next_service_time == 0 means to not service the secure tunnel, i.e. a state that only cares about external events
 *
 * This includes connecting and channel shutdown.  Terminated is also included, but it's a state that only exists
 * instantaneously before final destruction.
 */
static uint64_t s_compute_next_service_time_secure_tunnel_stopped(
    struct aws_secure_tunnel *secure_tunnel,
    uint64_t now) {
    /* have we been told to connect or terminate? */
    if (secure_tunnel->desired_state != AWS_STS_STOPPED) {
        return now;
    }

    return 0;
}

static uint64_t s_compute_next_service_time_secure_tunnel_connecting(
    struct aws_secure_tunnel *secure_tunnel,
    uint64_t now) {
    (void)secure_tunnel;
    (void)now;

    return 0;
}

static uint64_t s_compute_next_service_time_secure_tunnel_connected(
    struct aws_secure_tunnel *secure_tunnel,
    uint64_t now) {
    /* TODO check against ping timeout once pong is implemented by secure tunnel service */
    uint64_t next_service_time = secure_tunnel->next_ping_time;

    if (secure_tunnel->desired_state != AWS_STS_CONNECTED) {
        next_service_time = now;
    }

    uint64_t operation_processing_time = s_aws_secure_tunnel_compute_operational_state_service_time(secure_tunnel, now);

    next_service_time = s_min_non_0_64(operation_processing_time, next_service_time);

    return next_service_time;
}

static uint64_t s_compute_next_service_time_secure_tunnel_clean_disconnect(
    struct aws_secure_tunnel *secure_tunnel,
    uint64_t now) {
    return s_aws_secure_tunnel_compute_operational_state_service_time(secure_tunnel, now);
}

static uint64_t s_compute_next_service_time_secure_tunnel_websocket_shutdown(
    struct aws_secure_tunnel *secure_tunnel,
    uint64_t now) {
    (void)secure_tunnel;
    (void)now;

    return 0;
}

static uint64_t s_compute_next_service_time_secure_tunnel_pending_reconnect(
    struct aws_secure_tunnel *secure_tunnel,
    uint64_t now) {
    if (secure_tunnel->desired_state != AWS_STS_CONNECTED) {
        return now;
    }

    return secure_tunnel->next_reconnect_time_ns;
}

static uint64_t s_compute_next_service_time_by_current_state(struct aws_secure_tunnel *secure_tunnel, uint64_t now) {

    switch (secure_tunnel->current_state) {
        case AWS_STS_STOPPED:
            return s_compute_next_service_time_secure_tunnel_stopped(secure_tunnel, now);
        case AWS_STS_CONNECTING:
            return s_compute_next_service_time_secure_tunnel_connecting(secure_tunnel, now);
        case AWS_STS_CONNECTED:
            return s_compute_next_service_time_secure_tunnel_connected(secure_tunnel, now);
        case AWS_STS_CLEAN_DISCONNECT:
            return s_compute_next_service_time_secure_tunnel_clean_disconnect(secure_tunnel, now);
        case AWS_STS_WEBSOCKET_SHUTDOWN:
            return s_compute_next_service_time_secure_tunnel_websocket_shutdown(secure_tunnel, now);
        case AWS_STS_PENDING_RECONNECT:
            return s_compute_next_service_time_secure_tunnel_pending_reconnect(secure_tunnel, now);
        case AWS_STS_TERMINATED:
            return 0;
    }

    return 0;
}

static void s_reevaluate_service_task(struct aws_secure_tunnel *secure_tunnel) {
    /*
     * This causes the secure tunnel to only reevaluate service schedule time at the end of the service call or in
     * a callback from an external event.
     */
    if (secure_tunnel->in_service) {
        return;
    }

    uint64_t now = (*secure_tunnel->vtable->get_current_time_fn)();
    uint64_t next_service_time = s_compute_next_service_time_by_current_state(secure_tunnel, now);

    /*
     * This catches both the case when there's an existing service schedule and we either want to not
     * perform it (next_service_time == 0) or need to run service at a different time than the current scheduled
     * time.
     */
    if (next_service_time != secure_tunnel->next_service_task_run_time &&
        secure_tunnel->next_service_task_run_time > 0) {
        aws_event_loop_cancel_task(secure_tunnel->loop, &secure_tunnel->service_task);
        secure_tunnel->next_service_task_run_time = 0;

        AWS_LOGF_TRACE(
            AWS_LS_IOTDEVICE_SECURE_TUNNELING,
            "id=%p: cancelling previously scheduled service task",
            (void *)secure_tunnel);
    }

    if (next_service_time > 0 && (next_service_time < secure_tunnel->next_service_task_run_time ||
                                  secure_tunnel->next_service_task_run_time == 0)) {
        aws_event_loop_schedule_task_future(secure_tunnel->loop, &secure_tunnel->service_task, next_service_time);

        AWS_LOGF_TRACE(
            AWS_LS_IOTDEVICE_SECURE_TUNNELING,
            "id=%p: scheduled service task for time %" PRIu64,
            (void *)secure_tunnel,
            next_service_time);
    }

    secure_tunnel->next_service_task_run_time = next_service_time;
}

/*********************************************************************************************************************
 * Update Loop
 ********************************************************************************************************************/

static int s_aws_secure_tunnel_queue_ping(struct aws_secure_tunnel *secure_tunnel) {
    s_reset_ping(secure_tunnel);

    AWS_LOGF_DEBUG(AWS_LS_IOTDEVICE_SECURE_TUNNELING, "id=%p: queuing PING", (void *)secure_tunnel);

    struct aws_secure_tunnel_operation_pingreq *pingreq_op =
        aws_secure_tunnel_operation_pingreq_new(secure_tunnel->allocator);
    s_enqueue_operation_front(secure_tunnel, &pingreq_op->base);

    return AWS_OP_SUCCESS;
}

static bool s_service_state_stopped(struct aws_secure_tunnel *secure_tunnel) {
    enum aws_secure_tunnel_state desired_state = secure_tunnel->desired_state;
    if (desired_state == AWS_STS_CONNECTED) {
        s_change_current_state(secure_tunnel, AWS_STS_CONNECTING);
    } else if (desired_state == AWS_STS_TERMINATED) {
        s_change_current_state(secure_tunnel, AWS_STS_TERMINATED);
        return true;
    }
    return false;
}

static void s_service_state_connecting(struct aws_secure_tunnel *secure_tunnel, uint64_t now) {
    (void)secure_tunnel;
    (void)now;
}

static void s_service_state_connected(struct aws_secure_tunnel *secure_tunnel, uint64_t now) {
    enum aws_secure_tunnel_state desired_state = secure_tunnel->desired_state;
    if (desired_state != AWS_STS_CONNECTED) {
        AWS_LOGF_INFO(
            AWS_LS_IOTDEVICE_SECURE_TUNNELING,
            "id=%p: channel shutdown due to user Stop request",
            (void *)secure_tunnel);
        s_secure_tunnel_shutdown_websocket(secure_tunnel, AWS_ERROR_IOTDEVICE_SECURE_TUNNELING_USER_REQUESTED_STOP);
        return;
    }

    if (now >= secure_tunnel->next_ping_time) {
        if (s_aws_secure_tunnel_queue_ping(secure_tunnel)) {
            int error_code = aws_last_error();
            AWS_LOGF_ERROR(
                AWS_LS_IOTDEVICE_SECURE_TUNNELING,
                "id=%p: failed to queue PINGREQ with error %d(%s)",
                (void *)secure_tunnel,
                error_code,
                aws_error_debug_str(error_code));
            s_secure_tunnel_shutdown_websocket(secure_tunnel, error_code);
            return;
        }
    }

    if (aws_secure_tunnel_service_operational_state(secure_tunnel)) {
        int error_code = aws_last_error();
        AWS_LOGF_ERROR(
            AWS_LS_IOTDEVICE_SECURE_TUNNELING,
            "id=%p: failed to service CONNECTED operation queue with error %d(%s)",
            (void *)secure_tunnel,
            error_code,
            aws_error_debug_str(error_code));
        s_secure_tunnel_shutdown_websocket(secure_tunnel, error_code);
        return;
    }
}

static void s_service_state_clean_disconnect(struct aws_secure_tunnel *secure_tunnel, uint64_t now) {
    (void)now;
    if (aws_secure_tunnel_service_operational_state(secure_tunnel)) {
        int error_code = aws_last_error();
        AWS_LOGF_ERROR(
            AWS_LS_IOTDEVICE_SECURE_TUNNELING,
            "id=%p: failed to service CLEAN_DISCONNECT operation queue with error %d(%s)",
            (void *)secure_tunnel,
            error_code,
            aws_error_debug_str(error_code));
        s_secure_tunnel_shutdown_websocket(secure_tunnel, error_code);
        return;
    }
}

static void s_service_state_pending_reconnect(struct aws_secure_tunnel *secure_tunnel, uint64_t now) {
    if (secure_tunnel->desired_state != AWS_STS_CONNECTED) {
        s_change_current_state(secure_tunnel, AWS_STS_STOPPED);
        return;
    }

    if (now >= secure_tunnel->next_reconnect_time_ns) {
        s_change_current_state(secure_tunnel, AWS_STS_CONNECTING);
        return;
    }
}

static void s_secure_tunnel_service_task_fn(struct aws_task *task, void *arg, enum aws_task_status status) {
    (void)task;
    if (status != AWS_TASK_STATUS_RUN_READY) {
        return;
    }

    struct aws_secure_tunnel *secure_tunnel = arg;
    secure_tunnel->next_service_task_run_time = 0;
    secure_tunnel->in_service = true;

    uint64_t now = (*secure_tunnel->vtable->get_current_time_fn)();
    bool terminated = false;
    switch (secure_tunnel->current_state) {
        case AWS_STS_STOPPED:
            terminated = s_service_state_stopped(secure_tunnel);
            break;
        case AWS_STS_CONNECTING:
            s_service_state_connecting(secure_tunnel, now);
            break;
        case AWS_STS_CONNECTED:
            s_service_state_connected(secure_tunnel, now);
            break;
        case AWS_STS_CLEAN_DISCONNECT:
            s_service_state_clean_disconnect(secure_tunnel, now);
            break;
        case AWS_STS_PENDING_RECONNECT:
            s_service_state_pending_reconnect(secure_tunnel, now);
            break;
        default:
            break;
    }

    /*
     * We can only enter the terminated state from stopped.  If we do so, the secure tunnel memory is now freed and
     * we will crash if we access anything anymore.
     */
    if (terminated) {
        return;
    }

    /* we're not scheduled anymore, reschedule as needed */
    secure_tunnel->in_service = false;
    s_reevaluate_service_task(secure_tunnel);
}

/*********************************************************************************************************************
 * API Calls
 ********************************************************************************************************************/

struct aws_secure_tunnel *aws_secure_tunnel_new(
    struct aws_allocator *allocator,
    const struct aws_secure_tunnel_options *options) {
    AWS_FATAL_ASSERT(options != NULL);
    AWS_FATAL_ASSERT(allocator != NULL);

    struct aws_secure_tunnel *secure_tunnel = aws_mem_calloc(allocator, 1, sizeof(struct aws_secure_tunnel));
    if (secure_tunnel == NULL) {
        return NULL;
    }

    aws_task_init(&secure_tunnel->service_task, s_secure_tunnel_service_task_fn, secure_tunnel, "SecureTunnelService");

    secure_tunnel->allocator = allocator;
    secure_tunnel->vtable = &s_default_secure_tunnel_vtable;

    aws_ref_count_init(&secure_tunnel->ref_count, secure_tunnel, s_on_secure_tunnel_zero_ref_count);

    aws_linked_list_init(&secure_tunnel->queued_operations);
    secure_tunnel->current_operation = NULL;

    /* store options */
    secure_tunnel->config = aws_secure_tunnel_options_storage_new(allocator, options);
    if (secure_tunnel->config == NULL) {
        goto error;
    }

    /* all secure tunnel activity will take place on this event loop */
    secure_tunnel->loop = aws_event_loop_group_get_next_loop(secure_tunnel->config->bootstrap->event_loop_group);
    if (secure_tunnel->loop == NULL) {
        goto error;
    }

    secure_tunnel->desired_state = AWS_STS_STOPPED;
    secure_tunnel->current_state = AWS_STS_STOPPED;

    /* tls setup */
    struct aws_tls_ctx_options tls_ctx_opt;
    AWS_ZERO_STRUCT(tls_ctx_opt);
    aws_tls_ctx_options_init_default_client(&tls_ctx_opt, secure_tunnel->allocator);

    if (options->root_ca != NULL) {
        if (aws_tls_ctx_options_override_default_trust_store_from_path(&tls_ctx_opt, NULL, options->root_ca)) {
            goto error;
        }
    }

    secure_tunnel->tls_ctx = aws_tls_client_ctx_new(allocator, &tls_ctx_opt);
    if (secure_tunnel->tls_ctx == NULL) {
        goto error;
    }

    /* tls_connection_options */
    aws_tls_connection_options_init_from_ctx(&secure_tunnel->tls_con_opt, secure_tunnel->tls_ctx);
    if (aws_tls_connection_options_set_server_name(
            &secure_tunnel->tls_con_opt, allocator, (struct aws_byte_cursor *)&options->endpoint_host)) {
        goto error;
    }

    aws_tls_ctx_options_clean_up(&tls_ctx_opt);

    /* Connection reset */
    secure_tunnel->config->stream_id = INVALID_STREAM_ID;

    aws_hash_table_foreach(&secure_tunnel->config->service_ids, s_reset_service_id, NULL);

    secure_tunnel->handshake_request = NULL;
    secure_tunnel->websocket = NULL;

    aws_byte_buf_init(&secure_tunnel->received_data, allocator, MAX_WEBSOCKET_PAYLOAD);

    aws_secure_tunnel_options_storage_log(secure_tunnel->config, AWS_LL_DEBUG);

    return secure_tunnel;

error:
    aws_tls_ctx_options_clean_up(&tls_ctx_opt);
    aws_secure_tunnel_release(secure_tunnel);
    return NULL;
}

struct aws_secure_tunnel *aws_secure_tunnel_acquire(struct aws_secure_tunnel *secure_tunnel) {
    if (secure_tunnel != NULL) {
        aws_ref_count_acquire(&secure_tunnel->ref_count);
    }
    return secure_tunnel;
}

void aws_secure_tunnel_release(struct aws_secure_tunnel *secure_tunnel) {
    if (secure_tunnel != NULL) {
        aws_ref_count_release(&secure_tunnel->ref_count);
    }
}

int aws_secure_tunnel_start(struct aws_secure_tunnel *secure_tunnel) {
    return s_aws_secure_tunnel_change_desired_state(secure_tunnel, AWS_STS_CONNECTED);
}

int aws_secure_tunnel_stop(struct aws_secure_tunnel *secure_tunnel) {
    AWS_LOGF_DEBUG(
        AWS_LS_IOTDEVICE_SECURE_TUNNELING, "id=%p: Stopping secure tunnel immediately", (void *)secure_tunnel);
    return s_aws_secure_tunnel_change_desired_state(secure_tunnel, AWS_STS_STOPPED);
}

int aws_secure_tunnel_send_message(
    struct aws_secure_tunnel *secure_tunnel,
    const struct aws_secure_tunnel_message_view *message_options) {
    AWS_PRECONDITION(secure_tunnel != NULL);
    AWS_PRECONDITION(message_options != NULL);

    struct aws_secure_tunnel_operation_message *message_op = aws_secure_tunnel_operation_message_new(
        secure_tunnel->allocator, secure_tunnel, message_options, AWS_STOT_MESSAGE);

    if (message_op == NULL) {
        return AWS_OP_ERR;
    }

    AWS_LOGF_DEBUG(
        AWS_LS_IOTDEVICE_SECURE_TUNNELING,
        "id=%p: Submitting MESSAGE operation (%p)",
        (void *)secure_tunnel,
        (void *)message_op);

    if (s_submit_operation(secure_tunnel, &message_op->base)) {
        goto error;
    }

    return AWS_OP_SUCCESS;

error:
    aws_secure_tunnel_operation_release(&message_op->base);
    return AWS_OP_ERR;
}

int aws_secure_tunnel_stream_start(
    struct aws_secure_tunnel *secure_tunnel,
    const struct aws_secure_tunnel_message_view *message_options) {
    AWS_PRECONDITION(secure_tunnel != NULL);
    AWS_PRECONDITION(message_options != NULL);

    if (secure_tunnel->config->local_proxy_mode == AWS_SECURE_TUNNELING_DESTINATION_MODE) {
        AWS_LOGF_ERROR(AWS_LS_IOTDEVICE_SECURE_TUNNELING, "Stream Start can only be sent from source mode");
        return AWS_ERROR_IOTDEVICE_SECURE_TUNNELING_INCORRECT_MODE;
    }

    struct aws_secure_tunnel_operation_message *message_op = aws_secure_tunnel_operation_message_new(
        secure_tunnel->allocator, secure_tunnel, message_options, AWS_STOT_STREAM_START);

    if (message_op == NULL) {
        return AWS_OP_ERR;
    }

    AWS_LOGF_DEBUG(
        AWS_LS_IOTDEVICE_SECURE_TUNNELING,
        "id=%p: Submitting STREAM START operation (%p)",
        (void *)secure_tunnel,
        (void *)message_op);

    if (s_submit_operation(secure_tunnel, &message_op->base)) {
        goto error;
    }

    return AWS_OP_SUCCESS;

error:
    aws_secure_tunnel_operation_release(&message_op->base);
    return AWS_OP_ERR;
}

int aws_secure_tunnel_stream_reset(
    struct aws_secure_tunnel *secure_tunnel,
    const struct aws_secure_tunnel_message_view *message_options) {
    AWS_PRECONDITION(secure_tunnel != NULL);
    AWS_PRECONDITION(message_options != NULL);

    struct aws_secure_tunnel_operation_message *message_op = aws_secure_tunnel_operation_message_new(
        secure_tunnel->allocator, secure_tunnel, message_options, AWS_STOT_STREAM_RESET);

    if (message_op == NULL) {
        return AWS_OP_ERR;
    }

    AWS_LOGF_DEBUG(
        AWS_LS_IOTDEVICE_SECURE_TUNNELING,
        "id=%p: Submitting STREAM RESET operation (%p)",
        (void *)secure_tunnel,
        (void *)message_op);

    if (s_submit_operation(secure_tunnel, &message_op->base)) {
        goto error;
    }

    return AWS_OP_SUCCESS;

error:
    aws_secure_tunnel_operation_release(&message_op->base);
    return AWS_OP_ERR;
}
