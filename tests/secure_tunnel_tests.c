/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/iotdevice/iotdevice.h>
#include <aws/iotdevice/private/secure_tunneling_impl.h>
#include <aws/iotdevice/private/secure_tunneling_operations.h>
#include <aws/iotdevice/private/serializer.h>
#include <aws/iotdevice/secure_tunneling.h>

#include <aws/common/allocator.h>
#include <aws/common/byte_buf.h>
#include <aws/common/clock.h>
#include <aws/common/error.h>
#include <aws/common/string.h>
#include <aws/http/websocket.h>
#include <aws/io/channel_bootstrap.h>
#include <aws/io/event_loop.h>
#include <aws/io/host_resolver.h>
#include <aws/io/socket.h>
#include <aws/testing/aws_test_harness.h>

#define PAYLOAD_BYTE_LENGTH_PREFIX 2
AWS_STATIC_STRING_FROM_LITERAL(s_access_token, "IAmAnAccessToken");
AWS_STATIC_STRING_FROM_LITERAL(s_client_token, "IAmAClientToken");
AWS_STATIC_STRING_FROM_LITERAL(s_endpoint_host, "IAmAnEndpointHost");
AWS_STATIC_STRING_FROM_LITERAL(s_service_id_1, "ServiceId1");
AWS_STATIC_STRING_FROM_LITERAL(s_service_id_2, "ServiceId2");
AWS_STATIC_STRING_FROM_LITERAL(s_service_id_3, "ServiceId3");
AWS_STATIC_STRING_FROM_LITERAL(s_service_id_wrong, "ServiceIdWrong");
AWS_STATIC_STRING_FROM_LITERAL(s_payload_text, "IAmABunchOfPayloadText");

#ifdef _WIN32
#    define LOCAL_SOCK_TEST_PATTERN "\\\\.\\pipe\\testsock%llu"
#else
#    define LOCAL_SOCK_TEST_PATTERN "testsock%llu.sock"
#endif

static uint8_t s_too_long_for_uint16[UINT16_MAX + 1];

static struct aws_byte_cursor s_payload_cursor_max_size_exceeded = {
    .ptr = s_too_long_for_uint16,
    .len = AWS_IOT_ST_MAX_PAYLOAD_SIZE + 1,
};

static struct aws_byte_cursor s_payload_cursor_max_size = {
    .ptr = s_too_long_for_uint16,
    .len = AWS_IOT_ST_MAX_PAYLOAD_SIZE,
};

struct aws_secure_tunnel_mock_websocket_vtable {
    aws_websocket_on_connection_setup_fn *on_connection_setup_fn;
    aws_websocket_on_connection_shutdown_fn *on_connection_shutdown_fn;
    aws_websocket_on_incoming_frame_begin_fn *on_incoming_frame_begin_fn;
    aws_websocket_on_incoming_frame_payload_fn *on_incoming_frame_payload_fn;
    aws_websocket_on_incoming_frame_complete_fn *on_incoming_frame_complete_fn;
};

struct aws_secure_tunnel_mock_test_fixture_options {
    struct aws_secure_tunnel_options *secure_tunnel_options;
    struct aws_secure_tunnel_mock_websocket_vtable *websocket_function_table;

    void *mock_server_user_data;
};

struct secure_tunnel_test_options {
    struct aws_secure_tunnel_options secure_tunnel_options;
    struct aws_secure_tunnel_mock_websocket_vtable websocket_function_table;
};

static void s_secure_tunnel_test_init_default_options(
    struct secure_tunnel_test_options *test_options,
    enum aws_secure_tunneling_local_proxy_mode local_proxy_mode) {
    struct aws_secure_tunnel_options local_secure_tunnel_options = {
        .endpoint_host = aws_byte_cursor_from_string(s_endpoint_host),
        .access_token = aws_byte_cursor_from_string(s_access_token),
        .local_proxy_mode = local_proxy_mode,
    };
    test_options->secure_tunnel_options = local_secure_tunnel_options;
}

typedef int(aws_secure_tunnel_mock_test_fixture_header_check_fn)(
    const struct aws_http_headers *request_headers,
    void *user_data);

typedef void(aws_secure_tunnel_mock_test_fixture_on_message_received_fn)(
    struct aws_secure_tunnel *secure_tunnel,
    struct aws_secure_tunnel_message_view *message_view);

struct aws_secure_tunnel_mock_test_fixture {
    struct aws_allocator *allocator;

    struct aws_event_loop_group *secure_tunnel_elg;
    struct aws_host_resolver *host_resolver;
    struct aws_client_bootstrap *secure_tunnel_bootstrap;
    struct aws_socket_endpoint endpoint;
    struct aws_socket_options socket_options;

    struct aws_secure_tunnel_mock_websocket_vtable *websocket_function_table;
    void *mock_server_user_data;

    struct aws_secure_tunnel *secure_tunnel;
    struct aws_secure_tunnel_vtable secure_tunnel_vtable;

    aws_secure_tunnel_mock_test_fixture_header_check_fn *header_check;
    aws_secure_tunnel_mock_test_fixture_on_message_received_fn *on_server_message_received;
    struct aws_mutex lock;
    struct aws_condition_variable signal;
    bool listener_destroyed;
    bool secure_tunnel_connected;
    bool secure_tunnel_terminated;
    bool secure_tunnel_connected_succesfully;
    bool secure_tunnel_connection_shutdown;
    bool secure_tunnel_connection_failed;
    bool secure_tunnel_stream_started;
    bool secure_tunnel_bad_stream_request;
    bool secure_tunnel_stream_reset_received;
    bool secure_tunnel_connection_started;
    bool secure_tunnel_bad_connection_request;
    bool secure_tunnel_connection_reset_received;
    bool secure_tunnel_session_reset_received;

    struct aws_byte_buf last_message_payload_buf;

    /* The following fields are intended to validate things from the mocked secure tunnel perspective. */
    int secure_tunnel_message_received_count;
    int secure_tunnel_message_sent_count;
    int secure_tunnel_stream_started_count;
    int secure_tunnel_stream_started_count_target;
    int secure_tunnel_connection_started_count;
    int secure_tunnel_connection_started_count_target;
    int secure_tunnel_message_received_count_target;
    int secure_tunnel_message_sent_count_target;
    int secure_tunnel_message_sent_connection_reset_count;
    int secure_tunnel_message_sent_data_count;
    int secure_tunnel_message_previous_data_value;
    bool secure_tunnel_messages_received_in_order;

    bool on_send_message_complete_fired;
    int on_send_message_complete_fired_cnt;
    struct {
        enum aws_secure_tunnel_message_type type;
        int error_code;
    } on_send_message_complete_result;
};

static bool s_secure_tunnel_check_active_stream_id(
    struct aws_secure_tunnel *secure_tunnel,
    struct aws_byte_cursor *service_id,
    int32_t stream_id) {
    if (service_id == NULL) {
        return secure_tunnel->connections->stream_id == stream_id;
    }

    struct aws_hash_element *elem = NULL;
    aws_hash_table_find(&secure_tunnel->connections->service_ids, service_id, &elem);
    if (elem == NULL) {
        return false;
    }

    struct aws_service_id_element *service_id_elem = elem->value;
    if (service_id_elem->stream_id != stream_id) {
        return false;
    }

    return true;
}

static bool s_secure_tunnel_check_active_connection_id(
    struct aws_secure_tunnel *secure_tunnel,
    struct aws_byte_cursor *service_id,
    int32_t stream_id,
    uint32_t connection_id) {
    struct aws_hash_table *table_to_check = NULL;
    if (service_id) {
        struct aws_hash_element *elem = NULL;
        aws_hash_table_find(&secure_tunnel->connections->service_ids, service_id, &elem);
        if (elem == NULL) {
            return false;
        }
        struct aws_service_id_element *service_id_elem = elem->value;
        table_to_check = &service_id_elem->connection_ids;
    } else {
        if (secure_tunnel->connections->stream_id != stream_id) {
            return false;
        }
        table_to_check = &secure_tunnel->connections->connection_ids;
    }

    struct aws_hash_element *connection_elem = NULL;
    aws_hash_table_find(table_to_check, &connection_id, &connection_elem);
    if (connection_elem == NULL) {
        return false;
    }

    return true;
}

/*****************************************************************************************************************
 *                                    SECURE TUNNEL CALLBACKS
 *****************************************************************************************************************/

static void s_on_test_secure_tunnel_connection_complete(
    const struct aws_secure_tunnel_connection_view *connection_view,
    int error_code,
    void *user_data) {
    (void)connection_view;
    struct aws_secure_tunnel_mock_test_fixture *test_fixture = user_data;

    aws_mutex_lock(&test_fixture->lock);
    if (error_code == 0 && test_fixture->secure_tunnel_connected == false) {
        test_fixture->secure_tunnel_connection_shutdown = false;
        test_fixture->secure_tunnel_connected_succesfully = true;
        test_fixture->secure_tunnel_connected = true;
    } else {
        test_fixture->secure_tunnel_connection_failed = true;
    }
    aws_condition_variable_notify_all(&test_fixture->signal);
    aws_mutex_unlock(&test_fixture->lock);
}

static void s_on_test_secure_tunnel_connection_shutdown(int error_code, void *user_data) {
    (void)error_code;
    struct aws_secure_tunnel_mock_test_fixture *test_fixture = user_data;

    aws_mutex_lock(&test_fixture->lock);
    test_fixture->secure_tunnel_connection_shutdown = true;
    test_fixture->secure_tunnel_connected = false;
    test_fixture->secure_tunnel_connected_succesfully = false;
    test_fixture->secure_tunnel_stream_started = false;
    aws_condition_variable_notify_all(&test_fixture->signal);
    aws_mutex_unlock(&test_fixture->lock);
}

static void s_on_test_secure_tunnel_message_received(
    const struct aws_secure_tunnel_message_view *message,
    void *user_data) {
    struct aws_secure_tunnel_mock_test_fixture *test_fixture = user_data;
    aws_mutex_lock(&test_fixture->lock);
    test_fixture->secure_tunnel_message_received_count++;
    aws_byte_buf_clean_up(&test_fixture->last_message_payload_buf);
    aws_byte_buf_init(&test_fixture->last_message_payload_buf, test_fixture->allocator, message->payload->len);
    struct aws_byte_cursor payload_cur = {
        .ptr = message->payload->ptr,
        .len = message->payload->len,
    };
    aws_byte_buf_write_from_whole_cursor(&test_fixture->last_message_payload_buf, payload_cur);
    aws_condition_variable_notify_all(&test_fixture->signal);
    aws_mutex_unlock(&test_fixture->lock);
}

static void s_on_test_secure_tunnel_send_message_complete(
    enum aws_secure_tunnel_message_type type,
    int error_code,
    void *user_data) {
    struct aws_secure_tunnel_mock_test_fixture *test_fixture = user_data;

    aws_mutex_lock(&test_fixture->lock);
    test_fixture->on_send_message_complete_fired = true;
    test_fixture->on_send_message_complete_fired_cnt++;
    test_fixture->on_send_message_complete_result.type = type;
    test_fixture->on_send_message_complete_result.error_code = error_code;
    aws_condition_variable_notify_all(&test_fixture->signal);
    aws_mutex_unlock(&test_fixture->lock);
}

static void s_on_test_secure_tunnel_on_session_reset(void *user_data) {
    struct aws_secure_tunnel_mock_test_fixture *test_fixture = user_data;

    aws_mutex_lock(&test_fixture->lock);
    test_fixture->secure_tunnel_session_reset_received = true;
    aws_condition_variable_notify_all(&test_fixture->signal);
    aws_mutex_unlock(&test_fixture->lock);
}

static void s_on_test_secure_tunnel_on_stopped(void *user_data) {
    (void)user_data;
}

static void s_on_test_secure_tunnel_termination(void *user_data) {
    struct aws_secure_tunnel_mock_test_fixture *test_fixture = user_data;

    aws_mutex_lock(&test_fixture->lock);
    test_fixture->secure_tunnel_terminated = true;
    aws_condition_variable_notify_all(&test_fixture->signal);
    aws_mutex_unlock(&test_fixture->lock);
}

static void s_on_test_secure_tunnel_on_stream_reset(
    const struct aws_secure_tunnel_message_view *message,
    int error_code,
    void *user_data) {
    (void)message;
    (void)error_code;

    struct aws_secure_tunnel_mock_test_fixture *test_fixture = user_data;

    aws_mutex_lock(&test_fixture->lock);
    test_fixture->secure_tunnel_stream_reset_received = true;
    aws_condition_variable_notify_all(&test_fixture->signal);
    aws_mutex_unlock(&test_fixture->lock);
}

static void s_on_test_secure_tunnel_on_stream_start(
    const struct aws_secure_tunnel_message_view *message,
    int error_code,
    void *user_data) {
    (void)message;

    struct aws_secure_tunnel_mock_test_fixture *test_fixture = user_data;

    aws_mutex_lock(&test_fixture->lock);
    if (error_code == AWS_OP_SUCCESS) {
        test_fixture->secure_tunnel_stream_started = true;
        test_fixture->secure_tunnel_stream_started_count++;
    } else {
        test_fixture->secure_tunnel_bad_stream_request = true;
    }
    aws_condition_variable_notify_all(&test_fixture->signal);
    aws_mutex_unlock(&test_fixture->lock);
}

static void s_on_test_secure_tunnel_on_connection_start(
    const struct aws_secure_tunnel_message_view *message,
    int error_code,
    void *user_data) {
    (void)message;

    struct aws_secure_tunnel_mock_test_fixture *test_fixture = user_data;

    aws_mutex_lock(&test_fixture->lock);
    if (error_code == AWS_OP_SUCCESS) {
        test_fixture->secure_tunnel_connection_started = true;
        test_fixture->secure_tunnel_connection_started_count++;
    } else {
        test_fixture->secure_tunnel_bad_connection_request = true;
    }
    aws_condition_variable_notify_all(&test_fixture->signal);
    aws_mutex_unlock(&test_fixture->lock);
}

static void s_on_test_secure_tunnel_on_connection_reset(
    const struct aws_secure_tunnel_message_view *message,
    int error_code,
    void *user_data) {
    (void)message;
    (void)error_code;

    struct aws_secure_tunnel_mock_test_fixture *test_fixture = user_data;

    aws_mutex_lock(&test_fixture->lock);
    test_fixture->secure_tunnel_connection_reset_received = true;
    aws_condition_variable_notify_all(&test_fixture->signal);
    aws_mutex_unlock(&test_fixture->lock);
}

/*****************************************************************************************************************
 *                                    SECURE TUNNEL STATUS CHECKS
 *****************************************************************************************************************/

static bool s_has_secure_tunnel_terminated(void *arg) {
    struct aws_secure_tunnel_mock_test_fixture *test_fixture = arg;
    return test_fixture->secure_tunnel_terminated;
}

static void s_wait_for_secure_tunnel_terminated(struct aws_secure_tunnel_mock_test_fixture *test_fixture) {
    aws_mutex_lock(&test_fixture->lock);
    aws_condition_variable_wait_pred(
        &test_fixture->signal, &test_fixture->lock, s_has_secure_tunnel_terminated, test_fixture);
    aws_mutex_unlock(&test_fixture->lock);
}

static bool s_has_secure_tunnel_connected_succesfully(void *arg) {
    struct aws_secure_tunnel_mock_test_fixture *test_fixture = arg;
    return test_fixture->secure_tunnel_connected_succesfully;
}

static void s_wait_for_connected_successfully(struct aws_secure_tunnel_mock_test_fixture *test_fixture) {
    aws_mutex_lock(&test_fixture->lock);
    aws_condition_variable_wait_pred(
        &test_fixture->signal, &test_fixture->lock, s_has_secure_tunnel_connected_succesfully, test_fixture);
    aws_mutex_unlock(&test_fixture->lock);
}

static bool s_has_secure_tunnel_connection_shutdown(void *arg) {
    struct aws_secure_tunnel_mock_test_fixture *test_fixture = arg;
    return test_fixture->secure_tunnel_connection_shutdown;
}

static void s_wait_for_connection_shutdown(struct aws_secure_tunnel_mock_test_fixture *test_fixture) {
    aws_mutex_lock(&test_fixture->lock);
    aws_condition_variable_wait_pred(
        &test_fixture->signal, &test_fixture->lock, s_has_secure_tunnel_connection_shutdown, test_fixture);
    aws_mutex_unlock(&test_fixture->lock);
}

static bool s_has_secure_tunnel_stream_started(void *arg) {
    struct aws_secure_tunnel_mock_test_fixture *test_fixture = arg;
    return test_fixture->secure_tunnel_stream_started;
}

static void s_wait_for_stream_started(struct aws_secure_tunnel_mock_test_fixture *test_fixture) {
    aws_mutex_lock(&test_fixture->lock);
    aws_condition_variable_wait_pred(
        &test_fixture->signal, &test_fixture->lock, s_has_secure_tunnel_stream_started, test_fixture);
    aws_mutex_unlock(&test_fixture->lock);
}

static bool s_has_secure_tunnel_connection_started(void *arg) {
    struct aws_secure_tunnel_mock_test_fixture *test_fixture = arg;
    return test_fixture->secure_tunnel_connection_started;
}

static void s_wait_for_connection_started(struct aws_secure_tunnel_mock_test_fixture *test_fixture) {
    aws_mutex_lock(&test_fixture->lock);
    aws_condition_variable_wait_pred(
        &test_fixture->signal, &test_fixture->lock, s_has_secure_tunnel_connection_started, test_fixture);
    aws_mutex_unlock(&test_fixture->lock);
}

static bool s_has_secure_tunnel_bad_connection_started(void *arg) {
    struct aws_secure_tunnel_mock_test_fixture *test_fixture = arg;
    return test_fixture->secure_tunnel_bad_connection_request;
}

static void s_wait_for_bad_connection_started(struct aws_secure_tunnel_mock_test_fixture *test_fixture) {
    aws_mutex_lock(&test_fixture->lock);
    aws_condition_variable_wait_pred(
        &test_fixture->signal, &test_fixture->lock, s_has_secure_tunnel_bad_connection_started, test_fixture);
    aws_mutex_unlock(&test_fixture->lock);
}

static bool s_has_secure_tunnel_connection_reset_message_sent(void *arg) {
    struct aws_secure_tunnel_mock_test_fixture *test_fixture = arg;
    return test_fixture->secure_tunnel_message_sent_connection_reset_count > 0;
}

static void s_wait_for_connection_reset_message_sent(struct aws_secure_tunnel_mock_test_fixture *test_fixture) {
    aws_mutex_lock(&test_fixture->lock);
    aws_condition_variable_wait_pred(
        &test_fixture->signal, &test_fixture->lock, s_has_secure_tunnel_connection_reset_message_sent, test_fixture);
    aws_mutex_unlock(&test_fixture->lock);
}

static bool s_has_secure_tunnel_connection_reset_received(void *arg) {
    struct aws_secure_tunnel_mock_test_fixture *test_fixture = arg;
    return test_fixture->secure_tunnel_connection_reset_received;
}

static void s_wait_for_connection_reset_received(struct aws_secure_tunnel_mock_test_fixture *test_fixture) {
    aws_mutex_lock(&test_fixture->lock);
    aws_condition_variable_wait_pred(
        &test_fixture->signal, &test_fixture->lock, s_has_secure_tunnel_connection_reset_received, test_fixture);
    aws_mutex_unlock(&test_fixture->lock);
}

static bool s_has_secure_tunnel_bad_stream_request(void *arg) {
    struct aws_secure_tunnel_mock_test_fixture *test_fixture = arg;
    return test_fixture->secure_tunnel_bad_stream_request;
}

static void s_wait_for_bad_stream_request(struct aws_secure_tunnel_mock_test_fixture *test_fixture) {
    aws_mutex_lock(&test_fixture->lock);
    aws_condition_variable_wait_pred(
        &test_fixture->signal, &test_fixture->lock, s_has_secure_tunnel_bad_stream_request, test_fixture);
    aws_mutex_unlock(&test_fixture->lock);
}

static bool s_has_secure_tunnel_stream_reset_received(void *arg) {
    struct aws_secure_tunnel_mock_test_fixture *test_fixture = arg;
    return test_fixture->secure_tunnel_stream_reset_received;
}

static void s_wait_for_stream_reset_received(struct aws_secure_tunnel_mock_test_fixture *test_fixture) {
    aws_mutex_lock(&test_fixture->lock);
    aws_condition_variable_wait_pred(
        &test_fixture->signal, &test_fixture->lock, s_has_secure_tunnel_stream_reset_received, test_fixture);
    aws_mutex_unlock(&test_fixture->lock);
}

static bool s_has_secure_tunnel_n_stream_started(void *arg) {
    struct aws_secure_tunnel_mock_test_fixture *test_fixture = arg;
    return test_fixture->secure_tunnel_stream_started_count == test_fixture->secure_tunnel_stream_started_count_target;
}

static void s_wait_for_n_stream_started(struct aws_secure_tunnel_mock_test_fixture *test_fixture) {
    aws_mutex_lock(&test_fixture->lock);
    aws_condition_variable_wait_pred(
        &test_fixture->signal, &test_fixture->lock, s_has_secure_tunnel_n_stream_started, test_fixture);
    aws_mutex_unlock(&test_fixture->lock);
}

static bool s_has_secure_tunnel_session_reset_received(void *arg) {
    struct aws_secure_tunnel_mock_test_fixture *test_fixture = arg;
    return test_fixture->secure_tunnel_session_reset_received;
}

static void s_wait_for_session_reset_received(struct aws_secure_tunnel_mock_test_fixture *test_fixture) {
    aws_mutex_lock(&test_fixture->lock);
    aws_condition_variable_wait_pred(
        &test_fixture->signal, &test_fixture->lock, s_has_secure_tunnel_session_reset_received, test_fixture);
    aws_mutex_unlock(&test_fixture->lock);
}

static bool s_has_secure_tunnel_n_messages_received(void *arg) {
    struct aws_secure_tunnel_mock_test_fixture *test_fixture = arg;
    return test_fixture->secure_tunnel_message_received_count ==
           test_fixture->secure_tunnel_message_received_count_target;
}

static void s_wait_for_n_messages_received(struct aws_secure_tunnel_mock_test_fixture *test_fixture) {
    aws_mutex_lock(&test_fixture->lock);
    aws_condition_variable_wait_pred(
        &test_fixture->signal, &test_fixture->lock, s_has_secure_tunnel_n_messages_received, test_fixture);
    aws_mutex_unlock(&test_fixture->lock);
}

static bool s_has_secure_tunnel_on_send_message_complete_fired(void *arg) {
    struct aws_secure_tunnel_mock_test_fixture *test_fixture = arg;
    return test_fixture->on_send_message_complete_fired;
}

static void s_wait_for_on_send_message_complete_fired(struct aws_secure_tunnel_mock_test_fixture *test_fixture) {
    aws_mutex_lock(&test_fixture->lock);
    aws_condition_variable_wait_pred(
        &test_fixture->signal, &test_fixture->lock, s_has_secure_tunnel_on_send_message_complete_fired, test_fixture);
    /* Reset flag for the next message. */
    test_fixture->on_send_message_complete_fired = false;
    aws_mutex_unlock(&test_fixture->lock);
}

/*****************************************************************************************************************
 *                                    WEBSOCKET MOCK FUNCTIONS
 *****************************************************************************************************************/

/* Task that simulates a WebSocket payload receiving. */
struct aws_secure_tunnel_mock_websocket_receive_frame_payload_task {
    struct aws_task task;
    struct aws_secure_tunnel_mock_test_fixture *test_fixture;
    struct aws_byte_buf data_buf;
    struct aws_byte_buf out_buf;
};

static void s_secure_tunneling_mock_websocket_receive_frame_payload_task_fn(
    struct aws_task *task,
    void *arg,
    enum aws_task_status status) {

    (void)task;

    struct aws_secure_tunnel_mock_websocket_receive_frame_payload_task *receive_task = arg;
    if (status != AWS_TASK_STATUS_RUN_READY) {
        return;
    }

    struct aws_byte_cursor data_cur = aws_byte_cursor_from_buf(&receive_task->out_buf);
    receive_task->test_fixture->websocket_function_table->on_incoming_frame_payload_fn(
        NULL, NULL, data_cur, receive_task->test_fixture->secure_tunnel);

    aws_byte_buf_clean_up(&receive_task->out_buf);
    aws_byte_buf_clean_up(&receive_task->data_buf);
    aws_mem_release(receive_task->test_fixture->allocator, receive_task);
}

/* Serialize a message view and initialize a task for the event loop. The task then will simulate receiving the
 * WebSocket data.
 * NOTE In the actual environment, WebSocket operations and the secure tunnel are assigned to the same loop. We can
 * reproduce this by "receiving" messages from the mocked WebSocket in the same event loop the secure tunnel uses. This
 * way we don't need to worry about race conditions appearing in the tests that are not possible during the actual
 * execution.
 */
void aws_secure_tunnel_send_mock_message(
    struct aws_secure_tunnel_mock_test_fixture *test_fixture,
    const struct aws_secure_tunnel_message_view *message_view) {

    struct aws_secure_tunnel_mock_websocket_receive_frame_payload_task *receive_task = aws_mem_calloc(
        test_fixture->secure_tunnel->allocator,
        1,
        sizeof(struct aws_secure_tunnel_mock_websocket_receive_frame_payload_task));

    aws_task_init(
        &receive_task->task,
        s_secure_tunneling_mock_websocket_receive_frame_payload_task_fn,
        (void *)receive_task,
        "MockWebSocketSendMessageFromServer");

    receive_task->test_fixture = test_fixture;

    struct aws_byte_cursor data_cur;

    aws_iot_st_msg_serialize_from_view(&receive_task->data_buf, test_fixture->allocator, message_view);
    data_cur = aws_byte_cursor_from_buf(&receive_task->data_buf);
    aws_byte_buf_init(&receive_task->out_buf, test_fixture->allocator, data_cur.len + PAYLOAD_BYTE_LENGTH_PREFIX);
    aws_byte_buf_write_be16(&receive_task->out_buf, (uint16_t)receive_task->data_buf.len);
    aws_byte_buf_write_to_capacity(&receive_task->out_buf, &data_cur);

    aws_event_loop_schedule_task_now(test_fixture->secure_tunnel->loop, &receive_task->task);
}

int aws_websocket_client_connect_mock_fn(const struct aws_websocket_client_connection_options *options) {
    struct aws_secure_tunnel *secure_tunnel = options->user_data;
    struct aws_secure_tunnel_mock_test_fixture *test_fixture = secure_tunnel->config->user_data;

    if (!options->handshake_request) {
        AWS_LOGF_ERROR(
            AWS_LS_HTTP_WEBSOCKET_SETUP,
            "id=static: Invalid connection options, missing required request for websocket client handshake.");
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }

    const struct aws_http_headers *request_headers = aws_http_message_get_headers(options->handshake_request);
    if (test_fixture->header_check) {
        ASSERT_SUCCESS(test_fixture->header_check(request_headers, test_fixture));
    }

    test_fixture->websocket_function_table->on_connection_setup_fn = options->on_connection_setup;
    test_fixture->websocket_function_table->on_connection_shutdown_fn = options->on_connection_shutdown;
    test_fixture->websocket_function_table->on_incoming_frame_begin_fn = options->on_incoming_frame_begin;
    test_fixture->websocket_function_table->on_incoming_frame_payload_fn = options->on_incoming_frame_payload;
    test_fixture->websocket_function_table->on_incoming_frame_complete_fn = options->on_incoming_frame_complete;

    void *pointer = test_fixture;
    struct aws_websocket_on_connection_setup_data websocket_setup = {.error_code = AWS_ERROR_SUCCESS,
                                                                     .websocket = pointer};

    (test_fixture->websocket_function_table->on_connection_setup_fn)(&websocket_setup, secure_tunnel);
    secure_tunnel->websocket = pointer;

    struct aws_byte_cursor service_1 = aws_byte_cursor_from_string(s_service_id_1);
    struct aws_byte_cursor service_2 = aws_byte_cursor_from_string(s_service_id_2);
    struct aws_byte_cursor service_3 = aws_byte_cursor_from_string(s_service_id_3);

    struct aws_secure_tunnel_message_view service_ids_message = {
        .type = AWS_SECURE_TUNNEL_MT_SERVICE_IDS,
        .service_id = &service_1,
        .service_id_2 = &service_2,
        .service_id_3 = &service_3,
    };

    aws_secure_tunnel_send_mock_message(test_fixture, &service_ids_message);

    return AWS_OP_SUCCESS;
}

/* Mock for a server-side code receiving WebSocket frames. */
void aws_secure_tunnel_test_on_message_received(
    struct aws_secure_tunnel *secure_tunnel,
    struct aws_secure_tunnel_message_view *message_view) {
    (void)message_view;
    struct aws_secure_tunnel_mock_test_fixture *test_fixture = secure_tunnel->config->user_data;

    aws_mutex_lock(&test_fixture->lock);
    test_fixture->secure_tunnel_message_sent_count++;
    switch (message_view->type) {
        case AWS_SECURE_TUNNEL_MT_DATA:
            test_fixture->secure_tunnel_message_sent_data_count++;
            break;
        case AWS_SECURE_TUNNEL_MT_CONNECTION_RESET:
            test_fixture->secure_tunnel_message_sent_connection_reset_count++;
            break;
        default:
            break;
    }
    aws_condition_variable_notify_all(&test_fixture->signal);
    aws_mutex_unlock(&test_fixture->lock);
}

void aws_secure_tunnel_test_on_message_received_with_order_validation(
    struct aws_secure_tunnel *secure_tunnel,
    struct aws_secure_tunnel_message_view *message_view) {
    (void)message_view;
    struct aws_secure_tunnel_mock_test_fixture *test_fixture = secure_tunnel->config->user_data;

    aws_mutex_lock(&test_fixture->lock);
    test_fixture->secure_tunnel_message_sent_count++;
    int data_value;
    switch (message_view->type) {
        case AWS_SECURE_TUNNEL_MT_DATA:
            test_fixture->secure_tunnel_message_sent_data_count++;
            data_value = (int)strtol((const char *)message_view->payload->ptr, NULL, 10);
            if (test_fixture->secure_tunnel_message_previous_data_value > 0 &&
                data_value != test_fixture->secure_tunnel_message_previous_data_value + 1) {
                /* We cannot assert in this callback, log error and set corresponding fail flag instead. */
                fprintf(
                    stderr,
                    "ERROR: secure tunnel expected %d, received %d\n",
                    test_fixture->secure_tunnel_message_previous_data_value + 1,
                    data_value);
                test_fixture->secure_tunnel_messages_received_in_order = false;
            }
            test_fixture->secure_tunnel_message_previous_data_value = data_value;
            break;
        case AWS_SECURE_TUNNEL_MT_CONNECTION_RESET:
            test_fixture->secure_tunnel_message_sent_connection_reset_count++;
            break;
        default:
            break;
    }
    aws_condition_variable_notify_all(&test_fixture->signal);
    aws_mutex_unlock(&test_fixture->lock);
}

struct aws_secure_tunnel_mock_websocket_send_frame_task {
    struct aws_task task;
    struct aws_secure_tunnel_mock_test_fixture *test_fixture;
    struct data_tunnel_pair *pair;
    aws_websocket_outgoing_frame_complete_fn *on_complete;
};

static void s_secure_tunneling_mock_websocket_send_frame_task_fn(
    struct aws_task *task,
    void *arg,
    enum aws_task_status status) {

    (void)task;

    struct aws_secure_tunnel_mock_websocket_send_frame_task *send_task = arg;
    if (status != AWS_TASK_STATUS_RUN_READY) {
        return;
    }

    struct aws_secure_tunnel_mock_test_fixture *test_fixture = send_task->test_fixture;

    aws_secure_tunnel_deserialize_message_from_cursor(
        test_fixture->secure_tunnel, &send_task->pair->cur, test_fixture->on_server_message_received);

    send_task->on_complete((struct aws_websocket *)test_fixture, AWS_OP_SUCCESS, send_task->pair);

    aws_mem_release(test_fixture->allocator, send_task);
}

int aws_websocket_send_frame_mock_fn(
    struct aws_websocket *websocket,
    const struct aws_websocket_send_frame_options *options) {

    if (options->opcode == AWS_WEBSOCKET_OPCODE_PING) {
        return AWS_OP_SUCCESS;
    }

    void *pointer = websocket;
    struct aws_secure_tunnel_mock_test_fixture *test_fixture = pointer;

    struct aws_secure_tunnel_mock_websocket_send_frame_task *send_task = aws_mem_calloc(
        test_fixture->secure_tunnel->allocator, 1, sizeof(struct aws_secure_tunnel_mock_websocket_send_frame_task));

    aws_task_init(
        &send_task->task,
        s_secure_tunneling_mock_websocket_send_frame_task_fn,
        (void *)send_task,
        "MockWebSocketSendMessageFromClient");

    send_task->test_fixture = test_fixture;
    send_task->pair = options->user_data;
    send_task->on_complete = options->on_complete;

    /* TODO Schedule in 10 ms. */
    aws_event_loop_schedule_task_now(test_fixture->secure_tunnel->loop, &send_task->task);

    return AWS_OP_SUCCESS;
}

void aws_websocket_release_mock_fn(struct aws_websocket *websocket) {
    (void)websocket;
}

void aws_websocket_close_mock_fn(struct aws_websocket *websocket, bool free_scarce_resources_immediately) {
    (void)free_scarce_resources_immediately;
    void *pointer = websocket;
    struct aws_secure_tunnel_mock_test_fixture *test_fixture = pointer;
    test_fixture->websocket_function_table->on_connection_shutdown_fn(websocket, 0, test_fixture->secure_tunnel);
}

/*****************************************************************************************************************
 *                                    TEST FIXTURE
 *****************************************************************************************************************/

int aws_secure_tunnel_mock_test_fixture_init(
    struct aws_secure_tunnel_mock_test_fixture *test_fixture,
    struct aws_allocator *allocator,
    struct aws_secure_tunnel_mock_test_fixture_options *options) {

    AWS_ZERO_STRUCT(*test_fixture);
    test_fixture->allocator = allocator;

    aws_mutex_init(&test_fixture->lock);
    aws_condition_variable_init(&test_fixture->signal);

    test_fixture->websocket_function_table = options->websocket_function_table;
    test_fixture->mock_server_user_data = options->mock_server_user_data;

    struct aws_socket_options socket_options = {
        .connect_timeout_ms = 1000,
        .domain = AWS_SOCKET_LOCAL,
    };

    test_fixture->socket_options = socket_options;

    test_fixture->secure_tunnel_elg = aws_event_loop_group_new_default(allocator, 4, NULL);
    ASSERT_NOT_NULL(test_fixture->secure_tunnel_elg);

    struct aws_host_resolver_default_options resolver_options = {
        .el_group = test_fixture->secure_tunnel_elg,
        .max_entries = 1,
    };
    test_fixture->host_resolver = aws_host_resolver_new_default(allocator, &resolver_options);
    ASSERT_NOT_NULL(test_fixture->host_resolver);

    struct aws_client_bootstrap_options bootstrap_options = {
        .event_loop_group = test_fixture->secure_tunnel_elg,
        .user_data = test_fixture,
        .host_resolver = test_fixture->host_resolver,
    };

    test_fixture->secure_tunnel_bootstrap = aws_client_bootstrap_new(allocator, &bootstrap_options);
    ASSERT_NOT_NULL(test_fixture->secure_tunnel_bootstrap);

    uint64_t timestamp = 0;
    ASSERT_SUCCESS(aws_sys_clock_get_ticks(&timestamp));

    snprintf(
        test_fixture->endpoint.address,
        sizeof(test_fixture->endpoint.address),
        LOCAL_SOCK_TEST_PATTERN,
        (long long unsigned)timestamp);

    options->secure_tunnel_options->endpoint_host = aws_byte_cursor_from_c_str(test_fixture->endpoint.address);
    options->secure_tunnel_options->bootstrap = test_fixture->secure_tunnel_bootstrap;
    options->secure_tunnel_options->socket_options = &test_fixture->socket_options;
    options->secure_tunnel_options->access_token = aws_byte_cursor_from_string(s_access_token);
    options->secure_tunnel_options->user_data = test_fixture;

    /* Secure Tunnel Callbacks */
    options->secure_tunnel_options->on_connection_complete = s_on_test_secure_tunnel_connection_complete;
    options->secure_tunnel_options->on_connection_shutdown = s_on_test_secure_tunnel_connection_shutdown;
    options->secure_tunnel_options->on_message_received = s_on_test_secure_tunnel_message_received;
    options->secure_tunnel_options->on_send_message_complete = s_on_test_secure_tunnel_send_message_complete;
    options->secure_tunnel_options->on_session_reset = s_on_test_secure_tunnel_on_session_reset;
    options->secure_tunnel_options->on_stopped = s_on_test_secure_tunnel_on_stopped;
    options->secure_tunnel_options->on_stream_reset = s_on_test_secure_tunnel_on_stream_reset;
    options->secure_tunnel_options->on_stream_start = s_on_test_secure_tunnel_on_stream_start;
    options->secure_tunnel_options->on_connection_start = s_on_test_secure_tunnel_on_connection_start;
    options->secure_tunnel_options->on_connection_reset = s_on_test_secure_tunnel_on_connection_reset;
    options->secure_tunnel_options->on_termination_complete = s_on_test_secure_tunnel_termination;
    options->secure_tunnel_options->secure_tunnel_on_termination_user_data = test_fixture;

    test_fixture->secure_tunnel = aws_secure_tunnel_new(allocator, options->secure_tunnel_options);
    ASSERT_NOT_NULL(test_fixture->secure_tunnel);

    /* Replace Secure Tunnel's vtable functions */
    test_fixture->secure_tunnel_vtable = *aws_secure_tunnel_get_default_vtable();
    test_fixture->secure_tunnel_vtable.aws_websocket_client_connect_fn = aws_websocket_client_connect_mock_fn;
    test_fixture->secure_tunnel_vtable.aws_websocket_send_frame_fn = aws_websocket_send_frame_mock_fn;
    test_fixture->secure_tunnel_vtable.aws_websocket_release_fn = aws_websocket_release_mock_fn;
    test_fixture->secure_tunnel_vtable.aws_websocket_close_fn = aws_websocket_close_mock_fn;
    test_fixture->secure_tunnel_vtable.vtable_user_data = test_fixture;

    test_fixture->on_server_message_received = aws_secure_tunnel_test_on_message_received;
    test_fixture->secure_tunnel_messages_received_in_order = true;

    aws_secure_tunnel_set_vtable(test_fixture->secure_tunnel, &test_fixture->secure_tunnel_vtable);

    return AWS_OP_SUCCESS;
}

void aws_secure_tunnel_mock_test_init(
    struct aws_allocator *allocator,
    struct secure_tunnel_test_options *test_options,
    struct aws_secure_tunnel_mock_test_fixture *test_fixture,
    enum aws_secure_tunneling_local_proxy_mode local_proxy_mode) {

    aws_http_library_init(allocator);
    aws_iotdevice_library_init(allocator);

    s_secure_tunnel_test_init_default_options(test_options, local_proxy_mode);

    test_options->secure_tunnel_options.client_token = aws_byte_cursor_from_string(s_client_token);

    struct aws_secure_tunnel_mock_test_fixture_options test_fixture_options = {
        .secure_tunnel_options = &test_options->secure_tunnel_options,
        .websocket_function_table = &test_options->websocket_function_table,
    };

    aws_secure_tunnel_mock_test_fixture_init(test_fixture, allocator, &test_fixture_options);
}

void aws_secure_tunnel_mock_test_clean_up(struct aws_secure_tunnel_mock_test_fixture *test_fixture) {
    aws_secure_tunnel_release(test_fixture->secure_tunnel);
    s_wait_for_secure_tunnel_terminated(test_fixture);

    aws_client_bootstrap_release(test_fixture->secure_tunnel_bootstrap);
    aws_host_resolver_release(test_fixture->host_resolver);

    aws_event_loop_group_release(test_fixture->secure_tunnel_elg);

    aws_byte_buf_clean_up(&test_fixture->last_message_payload_buf);
    aws_mutex_clean_up(&test_fixture->lock);
    aws_condition_variable_clean_up(&test_fixture->signal);

    aws_iotdevice_library_clean_up();
    aws_http_library_clean_up();
    aws_iotdevice_library_clean_up();
}

/*********************************************************************************************************************
 * TESTS
 ********************************************************************************************************************/

int secure_tunneling_access_token_check(const struct aws_http_headers *request_headers, void *user_data) {
    (void)user_data;
    struct aws_byte_cursor access_token_cur;
    if (aws_http_headers_get(request_headers, aws_byte_cursor_from_c_str("access-token"), &access_token_cur)) {
        AWS_LOGF_ERROR(
            AWS_LS_HTTP_WEBSOCKET_SETUP,
            "id=static: Websocket handshake request is missing required 'access-token' header");
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }
    ASSERT_CURSOR_VALUE_STRING_EQUALS(access_token_cur, s_access_token);
    return AWS_OP_SUCCESS;
}

static int s_secure_tunneling_functionality_connect_test_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    struct secure_tunnel_test_options test_options;
    struct aws_secure_tunnel_mock_test_fixture test_fixture;
    aws_secure_tunnel_mock_test_init(allocator, &test_options, &test_fixture, AWS_SECURE_TUNNELING_DESTINATION_MODE);
    struct aws_secure_tunnel *secure_tunnel = test_fixture.secure_tunnel;

    test_fixture.header_check = secure_tunneling_access_token_check;

    ASSERT_SUCCESS(aws_secure_tunnel_start(secure_tunnel));
    s_wait_for_connected_successfully(&test_fixture);

    ASSERT_SUCCESS(aws_secure_tunnel_stop(secure_tunnel));
    s_wait_for_connection_shutdown(&test_fixture);

    aws_secure_tunnel_mock_test_clean_up(&test_fixture);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(secure_tunneling_functionality_connect_test, s_secure_tunneling_functionality_connect_test_fn)

int secure_tunneling_client_token_check(const struct aws_http_headers *request_headers, void *user_data) {
    (void)user_data;
    struct aws_byte_cursor client_token_cur;
    if (aws_http_headers_get(request_headers, aws_byte_cursor_from_c_str("client-token"), &client_token_cur)) {
        AWS_LOGF_ERROR(
            AWS_LS_HTTP_WEBSOCKET_SETUP,
            "id=static: Websocket handshake request is missing required 'client-token' header");
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }
    ASSERT_CURSOR_VALUE_STRING_EQUALS(client_token_cur, s_client_token);
    return AWS_OP_SUCCESS;
}

static int s_secure_tunneling_functionality_client_token_test_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    struct secure_tunnel_test_options test_options;
    struct aws_secure_tunnel_mock_test_fixture test_fixture;
    aws_secure_tunnel_mock_test_init(allocator, &test_options, &test_fixture, AWS_SECURE_TUNNELING_DESTINATION_MODE);
    struct aws_secure_tunnel *secure_tunnel = test_fixture.secure_tunnel;

    test_fixture.header_check = secure_tunneling_client_token_check;

    ASSERT_SUCCESS(aws_secure_tunnel_start(secure_tunnel));
    s_wait_for_connected_successfully(&test_fixture);

    ASSERT_SUCCESS(aws_secure_tunnel_stop(secure_tunnel));
    s_wait_for_connection_shutdown(&test_fixture);

    aws_secure_tunnel_mock_test_clean_up(&test_fixture);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(secure_tunneling_functionality_client_token_test, s_secure_tunneling_functionality_client_token_test_fn)

int aws_websocket_client_connect_fail_once_fn(const struct aws_websocket_client_connection_options *options) {
    struct aws_secure_tunnel *secure_tunnel = options->user_data;
    struct aws_secure_tunnel_mock_test_fixture *test_fixture = secure_tunnel->config->user_data;
    bool is_connection_failed_once = false;

    aws_mutex_lock(&test_fixture->lock);
    is_connection_failed_once = test_fixture->secure_tunnel_connection_failed;
    aws_mutex_unlock(&test_fixture->lock);

    if (is_connection_failed_once) {
        if (!options->handshake_request) {
            AWS_LOGF_ERROR(
                AWS_LS_HTTP_WEBSOCKET_SETUP,
                "id=static: Invalid connection options, missing required request for websocket client handshake.");
            return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
        }

        const struct aws_http_headers *request_headers = aws_http_message_get_headers(options->handshake_request);
        if (test_fixture->header_check) {
            ASSERT_SUCCESS(test_fixture->header_check(request_headers, test_fixture));
        }

        test_fixture->websocket_function_table->on_connection_setup_fn = options->on_connection_setup;
        test_fixture->websocket_function_table->on_connection_shutdown_fn = options->on_connection_shutdown;
        test_fixture->websocket_function_table->on_incoming_frame_begin_fn = options->on_incoming_frame_begin;
        test_fixture->websocket_function_table->on_incoming_frame_payload_fn = options->on_incoming_frame_payload;
        test_fixture->websocket_function_table->on_incoming_frame_complete_fn = options->on_incoming_frame_complete;

        void *pointer = test_fixture;
        struct aws_websocket_on_connection_setup_data websocket_setup = {.error_code = AWS_ERROR_SUCCESS,
                                                                         .websocket = pointer};

        (test_fixture->websocket_function_table->on_connection_setup_fn)(&websocket_setup, secure_tunnel);

        struct aws_byte_cursor service_1 = aws_byte_cursor_from_string(s_service_id_1);
        struct aws_byte_cursor service_2 = aws_byte_cursor_from_string(s_service_id_2);
        struct aws_byte_cursor service_3 = aws_byte_cursor_from_string(s_service_id_3);

        struct aws_secure_tunnel_message_view service_ids_message = {
            .type = AWS_SECURE_TUNNEL_MT_SERVICE_IDS,
            .service_id = &service_1,
            .service_id_2 = &service_2,
            .service_id_3 = &service_3,
        };

        aws_secure_tunnel_send_mock_message(test_fixture, &service_ids_message);

        return AWS_OP_SUCCESS;
    } else {
        return AWS_OP_ERR;
    }
}

static int s_secure_tunneling_fail_and_retry_connection_test_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    struct secure_tunnel_test_options test_options;
    struct aws_secure_tunnel_mock_test_fixture test_fixture;
    aws_secure_tunnel_mock_test_init(allocator, &test_options, &test_fixture, AWS_SECURE_TUNNELING_DESTINATION_MODE);
    struct aws_secure_tunnel *secure_tunnel = test_fixture.secure_tunnel;

    test_fixture.secure_tunnel_vtable = *aws_secure_tunnel_get_default_vtable();
    test_fixture.secure_tunnel_vtable.aws_websocket_client_connect_fn = aws_websocket_client_connect_fail_once_fn;
    test_fixture.secure_tunnel_vtable.aws_websocket_send_frame_fn = aws_websocket_send_frame_mock_fn;
    test_fixture.secure_tunnel_vtable.aws_websocket_release_fn = aws_websocket_release_mock_fn;
    test_fixture.secure_tunnel_vtable.aws_websocket_close_fn = aws_websocket_close_mock_fn;
    test_fixture.secure_tunnel_vtable.vtable_user_data = &test_fixture;

    ASSERT_SUCCESS(aws_secure_tunnel_start(secure_tunnel));
    s_wait_for_connected_successfully(&test_fixture);

    ASSERT_SUCCESS(aws_secure_tunnel_stop(secure_tunnel));
    s_wait_for_connection_shutdown(&test_fixture);

    aws_secure_tunnel_mock_test_clean_up(&test_fixture);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(secure_tunneling_fail_and_retry_connection_test, s_secure_tunneling_fail_and_retry_connection_test_fn)

static int s_secure_tunneling_store_service_ids_test_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    struct secure_tunnel_test_options test_options;
    struct aws_secure_tunnel_mock_test_fixture test_fixture;
    aws_secure_tunnel_mock_test_init(allocator, &test_options, &test_fixture, AWS_SECURE_TUNNELING_DESTINATION_MODE);
    struct aws_secure_tunnel *secure_tunnel = test_fixture.secure_tunnel;

    ASSERT_SUCCESS(aws_secure_tunnel_start(secure_tunnel));
    s_wait_for_connected_successfully(&test_fixture);

    /* check that service ids have been stored */
    struct aws_hash_element *elem = NULL;
    struct aws_byte_cursor service_id_1_cur = aws_byte_cursor_from_string(s_service_id_1);
    aws_hash_table_find(&secure_tunnel->connections->service_ids, &service_id_1_cur, &elem);
    ASSERT_NOT_NULL(elem);
    elem = NULL;
    struct aws_byte_cursor service_id_2_cur = aws_byte_cursor_from_string(s_service_id_2);
    aws_hash_table_find(&secure_tunnel->connections->service_ids, &service_id_2_cur, &elem);
    ASSERT_NOT_NULL(elem);
    elem = NULL;
    struct aws_byte_cursor service_id_3_cur = aws_byte_cursor_from_string(s_service_id_3);
    aws_hash_table_find(&secure_tunnel->connections->service_ids, &service_id_3_cur, &elem);
    ASSERT_NOT_NULL(elem);

    ASSERT_SUCCESS(aws_secure_tunnel_stop(secure_tunnel));
    s_wait_for_connection_shutdown(&test_fixture);

    aws_secure_tunnel_mock_test_clean_up(&test_fixture);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(secure_tunneling_store_service_ids_test, s_secure_tunneling_store_service_ids_test_fn)

static int s_secure_tunneling_receive_stream_start_test_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    struct secure_tunnel_test_options test_options;
    struct aws_secure_tunnel_mock_test_fixture test_fixture;
    aws_secure_tunnel_mock_test_init(allocator, &test_options, &test_fixture, AWS_SECURE_TUNNELING_DESTINATION_MODE);
    struct aws_secure_tunnel *secure_tunnel = test_fixture.secure_tunnel;

    ASSERT_SUCCESS(aws_secure_tunnel_start(secure_tunnel));
    s_wait_for_connected_successfully(&test_fixture);

    /* Create and send a stream start message from the server to the destination client */
    struct aws_byte_cursor service_1 = aws_byte_cursor_from_string(s_service_id_1);
    struct aws_secure_tunnel_message_view stream_start_message_view = {
        .type = AWS_SECURE_TUNNEL_MT_STREAM_START,
        .service_id = &service_1,
        .stream_id = 1,
    };
    aws_secure_tunnel_send_mock_message(&test_fixture, &stream_start_message_view);

    /* Wait and confirm that a stream has been started */
    s_wait_for_stream_started(&test_fixture);

    /* check that service id stream has been set properly */
    ASSERT_TRUE(s_secure_tunnel_check_active_stream_id(
        secure_tunnel, stream_start_message_view.service_id, stream_start_message_view.stream_id));

    ASSERT_SUCCESS(aws_secure_tunnel_stop(secure_tunnel));
    s_wait_for_connection_shutdown(&test_fixture);

    aws_secure_tunnel_mock_test_clean_up(&test_fixture);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(secure_tunneling_receive_stream_start_test, s_secure_tunneling_receive_stream_start_test_fn)

static int s_secure_tunneling_rejected_service_id_stream_start_test_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    struct secure_tunnel_test_options test_options;
    struct aws_secure_tunnel_mock_test_fixture test_fixture;
    aws_secure_tunnel_mock_test_init(allocator, &test_options, &test_fixture, AWS_SECURE_TUNNELING_DESTINATION_MODE);
    struct aws_secure_tunnel *secure_tunnel = test_fixture.secure_tunnel;

    ASSERT_SUCCESS(aws_secure_tunnel_start(secure_tunnel));
    s_wait_for_connected_successfully(&test_fixture);

    /* Create and send a bad stream start message from the server to the destination client */
    struct aws_byte_cursor service_id = aws_byte_cursor_from_string(s_service_id_wrong);
    struct aws_secure_tunnel_message_view stream_start_message_view = {
        .type = AWS_SECURE_TUNNEL_MT_STREAM_START,
        .service_id = &service_id,
        .stream_id = 1,
    };
    aws_secure_tunnel_send_mock_message(&test_fixture, &stream_start_message_view);

    /* Wait and confirm that a bad stream request was received */
    s_wait_for_bad_stream_request(&test_fixture);

    ASSERT_SUCCESS(aws_secure_tunnel_stop(secure_tunnel));
    s_wait_for_connection_shutdown(&test_fixture);

    aws_secure_tunnel_mock_test_clean_up(&test_fixture);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(
    secure_tunneling_rejected_service_id_stream_start_test,
    s_secure_tunneling_rejected_service_id_stream_start_test_fn)

static int s_secure_tunneling_close_stream_on_stream_reset_test_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    struct secure_tunnel_test_options test_options;
    struct aws_secure_tunnel_mock_test_fixture test_fixture;
    aws_secure_tunnel_mock_test_init(allocator, &test_options, &test_fixture, AWS_SECURE_TUNNELING_DESTINATION_MODE);
    struct aws_secure_tunnel *secure_tunnel = test_fixture.secure_tunnel;

    ASSERT_SUCCESS(aws_secure_tunnel_start(secure_tunnel));
    s_wait_for_connected_successfully(&test_fixture);

    /* Create and send a stream start message from the server to the destination client */
    struct aws_byte_cursor service_1 = aws_byte_cursor_from_string(s_service_id_1);
    struct aws_secure_tunnel_message_view stream_start_message_view = {
        .type = AWS_SECURE_TUNNEL_MT_STREAM_START,
        .service_id = &service_1,
        .stream_id = 1,
    };
    aws_secure_tunnel_send_mock_message(&test_fixture, &stream_start_message_view);

    /* Wait and confirm that a stream has been started */
    s_wait_for_stream_started(&test_fixture);

    /* Check that stream is active */
    ASSERT_TRUE(s_secure_tunnel_check_active_stream_id(secure_tunnel, &service_1, 1));

    /* Send a stream reset message from the server to the destination client */
    stream_start_message_view.type = AWS_SECURE_TUNNEL_MT_STREAM_RESET;

    aws_secure_tunnel_send_mock_message(&test_fixture, &stream_start_message_view);

    /* Wait for a stream reset to have been received */
    s_wait_for_stream_reset_received(&test_fixture);

    /* Check that stream id has been reset */
    ASSERT_TRUE(s_secure_tunnel_check_active_stream_id(secure_tunnel, &service_1, 0));

    ASSERT_SUCCESS(aws_secure_tunnel_stop(secure_tunnel));
    s_wait_for_connection_shutdown(&test_fixture);

    aws_secure_tunnel_mock_test_clean_up(&test_fixture);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(
    secure_tunneling_close_stream_on_stream_reset_test,
    s_secure_tunneling_close_stream_on_stream_reset_test_fn)

static int s_secure_tunneling_ignore_stream_reset_for_inactive_stream_test_fn(
    struct aws_allocator *allocator,
    void *ctx) {
    (void)ctx;
    struct secure_tunnel_test_options test_options;
    struct aws_secure_tunnel_mock_test_fixture test_fixture;
    aws_secure_tunnel_mock_test_init(allocator, &test_options, &test_fixture, AWS_SECURE_TUNNELING_DESTINATION_MODE);
    struct aws_secure_tunnel *secure_tunnel = test_fixture.secure_tunnel;

    ASSERT_SUCCESS(aws_secure_tunnel_start(secure_tunnel));
    s_wait_for_connected_successfully(&test_fixture);

    /* Create and send a stream start message from the server to the destination client */
    struct aws_byte_cursor service_1 = aws_byte_cursor_from_string(s_service_id_1);
    struct aws_secure_tunnel_message_view stream_start_message_view = {
        .type = AWS_SECURE_TUNNEL_MT_STREAM_START,
        .service_id = &service_1,
        .stream_id = 1,
    };
    aws_secure_tunnel_send_mock_message(&test_fixture, &stream_start_message_view);

    /* Wait and confirm that a stream has been started */
    s_wait_for_stream_started(&test_fixture);

    /* Check that stream is active */
    ASSERT_TRUE(s_secure_tunnel_check_active_stream_id(secure_tunnel, &service_1, 1));

    /* Send a stream reset message for a different stream id from the server to the destination client */
    struct aws_secure_tunnel_message_view stream_reset_message_view = {
        .type = AWS_SECURE_TUNNEL_MT_STREAM_RESET,
        .service_id = &service_1,
        .stream_id = 2,
    };

    aws_secure_tunnel_send_mock_message(&test_fixture, &stream_reset_message_view);

    /* Stream reset is ignored by client on an inactive stream id. Wait for client to process the message that should be
     * ignored. */
    aws_thread_current_sleep(aws_timestamp_convert(1, AWS_TIMESTAMP_SECS, AWS_TIMESTAMP_NANOS, NULL));

    /* Check that stream is still active */
    ASSERT_TRUE(s_secure_tunnel_check_active_stream_id(secure_tunnel, &service_1, 1));

    ASSERT_SUCCESS(aws_secure_tunnel_stop(secure_tunnel));
    s_wait_for_connection_shutdown(&test_fixture);

    aws_secure_tunnel_mock_test_clean_up(&test_fixture);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(
    secure_tunneling_ignore_stream_reset_for_inactive_stream_test,
    s_secure_tunneling_ignore_stream_reset_for_inactive_stream_test_fn)

static int s_secure_tunneling_session_reset_test_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    struct secure_tunnel_test_options test_options;
    struct aws_secure_tunnel_mock_test_fixture test_fixture;
    aws_secure_tunnel_mock_test_init(allocator, &test_options, &test_fixture, AWS_SECURE_TUNNELING_DESTINATION_MODE);
    struct aws_secure_tunnel *secure_tunnel = test_fixture.secure_tunnel;

    ASSERT_SUCCESS(aws_secure_tunnel_start(secure_tunnel));
    s_wait_for_connected_successfully(&test_fixture);

    /* Create and send a stream start message from the server to the destination client */
    struct aws_byte_cursor service_1 = aws_byte_cursor_from_string(s_service_id_1);
    struct aws_byte_cursor service_2 = aws_byte_cursor_from_string(s_service_id_2);
    struct aws_byte_cursor service_3 = aws_byte_cursor_from_string(s_service_id_3);
    struct aws_secure_tunnel_message_view stream_start_message_view = {
        .type = AWS_SECURE_TUNNEL_MT_STREAM_START,
        .service_id = &service_1,
        .stream_id = 1,
    };

    aws_secure_tunnel_send_mock_message(&test_fixture, &stream_start_message_view);
    stream_start_message_view.service_id = &service_2;
    aws_secure_tunnel_send_mock_message(&test_fixture, &stream_start_message_view);
    stream_start_message_view.service_id = &service_3;
    aws_secure_tunnel_send_mock_message(&test_fixture, &stream_start_message_view);

    test_fixture.secure_tunnel_stream_started_count_target = 3;
    s_wait_for_n_stream_started(&test_fixture);

    /* check that stream ids have been set */
    ASSERT_TRUE(s_secure_tunnel_check_active_stream_id(secure_tunnel, &service_1, 1));
    ASSERT_TRUE(s_secure_tunnel_check_active_stream_id(secure_tunnel, &service_2, 1));
    ASSERT_TRUE(s_secure_tunnel_check_active_stream_id(secure_tunnel, &service_3, 1));

    /* Create and send a session reset message from the server to the destination client */
    struct aws_secure_tunnel_message_view reset_message_view = {
        .type = AWS_SECURE_TUNNEL_MT_SESSION_RESET,
    };
    aws_secure_tunnel_send_mock_message(&test_fixture, &reset_message_view);

    s_wait_for_session_reset_received(&test_fixture);

    /* Check that stream ids have been reset */
    ASSERT_TRUE(s_secure_tunnel_check_active_stream_id(secure_tunnel, &service_1, 0));
    ASSERT_TRUE(s_secure_tunnel_check_active_stream_id(secure_tunnel, &service_2, 0));
    ASSERT_TRUE(s_secure_tunnel_check_active_stream_id(secure_tunnel, &service_3, 0));

    ASSERT_SUCCESS(aws_secure_tunnel_stop(secure_tunnel));
    s_wait_for_connection_shutdown(&test_fixture);

    aws_secure_tunnel_mock_test_clean_up(&test_fixture);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(secure_tunneling_session_reset_test, s_secure_tunneling_session_reset_test_fn)

static int s_secure_tunneling_serializer_data_message_test_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    struct secure_tunnel_test_options test_options;
    struct aws_secure_tunnel_mock_test_fixture test_fixture;
    aws_secure_tunnel_mock_test_init(allocator, &test_options, &test_fixture, AWS_SECURE_TUNNELING_DESTINATION_MODE);
    struct aws_secure_tunnel *secure_tunnel = test_fixture.secure_tunnel;

    ASSERT_SUCCESS(aws_secure_tunnel_start(secure_tunnel));
    s_wait_for_connected_successfully(&test_fixture);

    /* Create and send a stream start message from the server to the destination client */
    struct aws_byte_cursor service_1 = aws_byte_cursor_from_string(s_service_id_1);
    struct aws_secure_tunnel_message_view stream_start_message_view = {
        .type = AWS_SECURE_TUNNEL_MT_STREAM_START,
        .service_id = &service_1,
        .stream_id = 1,
    };
    aws_secure_tunnel_send_mock_message(&test_fixture, &stream_start_message_view);

    /* Wait and confirm that a stream has been started */
    s_wait_for_stream_started(&test_fixture);
    ASSERT_TRUE(s_secure_tunnel_check_active_stream_id(secure_tunnel, &service_1, 1));

    /* Create and send a data message from the server to the destination client */
    struct aws_byte_cursor payload_cur = aws_byte_cursor_from_string(s_payload_text);
    struct aws_secure_tunnel_message_view data_message_view = {
        .type = AWS_SECURE_TUNNEL_MT_DATA,
        .service_id = &service_1,
        .stream_id = 1,
        .payload = &payload_cur,
    };

    aws_secure_tunnel_send_mock_message(&test_fixture, &data_message_view);
    test_fixture.secure_tunnel_message_received_count_target = 1;
    s_wait_for_n_messages_received(&test_fixture);

    struct aws_byte_cursor payload_comp_cur = {
        .ptr = test_fixture.last_message_payload_buf.buffer,
        .len = test_fixture.last_message_payload_buf.len,
    };
    ASSERT_CURSOR_VALUE_STRING_EQUALS(payload_comp_cur, s_payload_text);

    ASSERT_SUCCESS(aws_secure_tunnel_stop(secure_tunnel));
    s_wait_for_connection_shutdown(&test_fixture);

    aws_secure_tunnel_mock_test_clean_up(&test_fixture);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(secure_tunneling_serializer_data_message_test, s_secure_tunneling_serializer_data_message_test_fn)

static int s_secure_tunneling_max_payload_test_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    struct secure_tunnel_test_options test_options;
    struct aws_secure_tunnel_mock_test_fixture test_fixture;
    aws_secure_tunnel_mock_test_init(allocator, &test_options, &test_fixture, AWS_SECURE_TUNNELING_DESTINATION_MODE);
    struct aws_secure_tunnel *secure_tunnel = test_fixture.secure_tunnel;

    ASSERT_SUCCESS(aws_secure_tunnel_start(secure_tunnel));
    s_wait_for_connected_successfully(&test_fixture);

    /* Create and send a stream start message from the server to the destination client */
    struct aws_byte_cursor service_1 = aws_byte_cursor_from_string(s_service_id_1);
    struct aws_secure_tunnel_message_view stream_start_message_view = {
        .type = AWS_SECURE_TUNNEL_MT_STREAM_START,
        .service_id = &service_1,
        .stream_id = 1,
    };
    aws_secure_tunnel_send_mock_message(&test_fixture, &stream_start_message_view);

    /* Wait and confirm that a stream has been started */
    s_wait_for_stream_started(&test_fixture);
    ASSERT_TRUE(s_secure_tunnel_check_active_stream_id(secure_tunnel, &service_1, 1));

    struct aws_secure_tunnel_message_view data_message_view = {
        .type = AWS_SECURE_TUNNEL_MT_DATA,
        .stream_id = 0,
        .service_id = &service_1,
        .payload = &s_payload_cursor_max_size,
    };

    aws_secure_tunnel_send_message(secure_tunnel, &data_message_view);

    ASSERT_SUCCESS(aws_secure_tunnel_stop(secure_tunnel));
    s_wait_for_connection_shutdown(&test_fixture);

    aws_secure_tunnel_mock_test_clean_up(&test_fixture);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(secure_tunneling_max_payload_test, s_secure_tunneling_max_payload_test_fn)

static int s_secure_tunneling_max_payload_exceed_test_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    struct secure_tunnel_test_options test_options;
    struct aws_secure_tunnel_mock_test_fixture test_fixture;
    aws_secure_tunnel_mock_test_init(allocator, &test_options, &test_fixture, AWS_SECURE_TUNNELING_DESTINATION_MODE);
    struct aws_secure_tunnel *secure_tunnel = test_fixture.secure_tunnel;

    ASSERT_SUCCESS(aws_secure_tunnel_start(secure_tunnel));
    s_wait_for_connected_successfully(&test_fixture);

    /* Create and send a stream start message from the server to the destination client */
    struct aws_byte_cursor service_1 = aws_byte_cursor_from_string(s_service_id_1);
    struct aws_secure_tunnel_message_view stream_start_message_view = {
        .type = AWS_SECURE_TUNNEL_MT_STREAM_START,
        .service_id = &service_1,
        .stream_id = 1,
    };
    aws_secure_tunnel_send_mock_message(&test_fixture, &stream_start_message_view);

    /* Wait and confirm that a stream has been started */
    s_wait_for_stream_started(&test_fixture);
    ASSERT_TRUE(s_secure_tunnel_check_active_stream_id(secure_tunnel, &service_1, 1));

    struct aws_secure_tunnel_message_view data_message_view = {
        .type = AWS_SECURE_TUNNEL_MT_DATA,
        .stream_id = 0,
        .service_id = &service_1,
        .connection_id = 1,
        .payload = &s_payload_cursor_max_size_exceeded,
    };

    int result = aws_secure_tunnel_send_message(secure_tunnel, &data_message_view);

    ASSERT_INT_EQUALS(result, AWS_ERROR_IOTDEVICE_SECURE_TUNNELING_DATA_OPTIONS_VALIDATION);

    ASSERT_SUCCESS(aws_secure_tunnel_stop(secure_tunnel));
    s_wait_for_connection_shutdown(&test_fixture);

    aws_secure_tunnel_mock_test_clean_up(&test_fixture);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(secure_tunneling_max_payload_exceed_test, s_secure_tunneling_max_payload_exceed_test_fn)

/* Test that messages sent by a user one after another without delay are actually being sent to server. */
static int s_secure_tunneling_subsequent_writes_test_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    struct secure_tunnel_test_options test_options;
    struct aws_secure_tunnel_mock_test_fixture test_fixture;
    aws_secure_tunnel_mock_test_init(allocator, &test_options, &test_fixture, AWS_SECURE_TUNNELING_DESTINATION_MODE);
    struct aws_secure_tunnel *secure_tunnel = test_fixture.secure_tunnel;

    test_fixture.on_server_message_received = aws_secure_tunnel_test_on_message_received_with_order_validation;

    ASSERT_SUCCESS(aws_secure_tunnel_start(secure_tunnel));
    s_wait_for_connected_successfully(&test_fixture);

    /* Create and send a stream start message from the server to the destination client */
    struct aws_byte_cursor service_1 = aws_byte_cursor_from_string(s_service_id_1);
    struct aws_secure_tunnel_message_view stream_start_message_view = {
        .type = AWS_SECURE_TUNNEL_MT_STREAM_START,
        .service_id = &service_1,
        .stream_id = 1,
    };
    aws_secure_tunnel_send_mock_message(&test_fixture, &stream_start_message_view);

    /* Wait and confirm that a stream has been started */
    s_wait_for_stream_started(&test_fixture);
    ASSERT_TRUE(s_secure_tunnel_check_active_stream_id(secure_tunnel, &service_1, 1));

    int total_messages = 100;
    for (int i = 0; i < total_messages; ++i) {
        uint8_t buf[16];
        struct aws_byte_cursor s_payload_buf = {
            .ptr = buf,
            .len = 16,
        };

        snprintf((char *)buf, sizeof(buf), "%d", i);

        struct aws_secure_tunnel_message_view data_message_view = {
            .type = AWS_SECURE_TUNNEL_MT_DATA,
            .stream_id = 0,
            .service_id = &service_1,
            .payload = &s_payload_buf,
        };

        int result = aws_secure_tunnel_send_message(secure_tunnel, &data_message_view);
        ASSERT_INT_EQUALS(result, AWS_OP_SUCCESS);
    }

    /* 1 second must be enough to send few messages. */
    aws_thread_current_sleep(aws_timestamp_convert(1, AWS_TIMESTAMP_SECS, AWS_TIMESTAMP_NANOS, NULL));

    ASSERT_INT_EQUALS(test_fixture.on_send_message_complete_fired_cnt, total_messages);
    ASSERT_TRUE(test_fixture.secure_tunnel_messages_received_in_order);

    ASSERT_SUCCESS(aws_secure_tunnel_stop(secure_tunnel));
    s_wait_for_connection_shutdown(&test_fixture);

    aws_secure_tunnel_mock_test_clean_up(&test_fixture);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(secure_tunneling_subsequent_writes, s_secure_tunneling_subsequent_writes_test_fn)

static int s_secure_tunneling_receive_connection_start_test_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    struct secure_tunnel_test_options test_options;
    struct aws_secure_tunnel_mock_test_fixture test_fixture;
    aws_secure_tunnel_mock_test_init(allocator, &test_options, &test_fixture, AWS_SECURE_TUNNELING_DESTINATION_MODE);
    struct aws_secure_tunnel *secure_tunnel = test_fixture.secure_tunnel;

    ASSERT_SUCCESS(aws_secure_tunnel_start(secure_tunnel));
    s_wait_for_connected_successfully(&test_fixture);

    /* Create and send a stream start message from the server to the destination client */
    struct aws_byte_cursor service_1 = aws_byte_cursor_from_string(s_service_id_1);
    struct aws_secure_tunnel_message_view stream_start_message_view = {
        .type = AWS_SECURE_TUNNEL_MT_STREAM_START,
        .service_id = &service_1,
        .stream_id = 1,
        .connection_id = 1,
    };
    aws_secure_tunnel_send_mock_message(&test_fixture, &stream_start_message_view);

    /* Wait and confirm that a stream has been started */
    s_wait_for_stream_started(&test_fixture);
    ASSERT_TRUE(s_secure_tunnel_check_active_connection_id(secure_tunnel, &service_1, 1, 1));

    struct aws_secure_tunnel_message_view connection_start_message_view = {
        .type = AWS_SECURE_TUNNEL_MT_CONNECTION_START,
        .service_id = &service_1,
        .stream_id = 1,
        .connection_id = 2,
    };
    aws_secure_tunnel_send_mock_message(&test_fixture, &connection_start_message_view);

    /* Wait and confirm that a connection has been started */
    s_wait_for_connection_started(&test_fixture);
    ASSERT_TRUE(s_secure_tunnel_check_active_connection_id(secure_tunnel, &service_1, 1, 2));

    ASSERT_SUCCESS(aws_secure_tunnel_stop(secure_tunnel));
    s_wait_for_connection_shutdown(&test_fixture);

    aws_secure_tunnel_mock_test_clean_up(&test_fixture);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(secure_tunneling_receive_connection_start_test, s_secure_tunneling_receive_connection_start_test_fn)

static int s_secure_tunneling_ignore_inactive_stream_message_test_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    struct secure_tunnel_test_options test_options;
    struct aws_secure_tunnel_mock_test_fixture test_fixture;
    aws_secure_tunnel_mock_test_init(allocator, &test_options, &test_fixture, AWS_SECURE_TUNNELING_DESTINATION_MODE);
    struct aws_secure_tunnel *secure_tunnel = test_fixture.secure_tunnel;

    ASSERT_SUCCESS(aws_secure_tunnel_start(secure_tunnel));
    s_wait_for_connected_successfully(&test_fixture);

    /* Create and send a stream start message from the server to the destination client */
    struct aws_byte_cursor service_1 = aws_byte_cursor_from_string(s_service_id_1);
    struct aws_secure_tunnel_message_view stream_start_message_view = {
        .type = AWS_SECURE_TUNNEL_MT_STREAM_START,
        .service_id = &service_1,
        .stream_id = 1,
    };
    aws_secure_tunnel_send_mock_message(&test_fixture, &stream_start_message_view);

    /* Wait and confirm that a stream has been started */
    s_wait_for_stream_started(&test_fixture);
    s_secure_tunnel_check_active_stream_id(secure_tunnel, &service_1, 1);

    /* Create and send a data message on a different stream id from the server to the destination client */
    struct aws_byte_cursor payload_cur = aws_byte_cursor_from_string(s_payload_text);
    struct aws_secure_tunnel_message_view data_message_view = {
        .type = AWS_SECURE_TUNNEL_MT_DATA,
        .service_id = &service_1,
        .stream_id = 2,
        .payload = &payload_cur,
    };

    aws_secure_tunnel_send_mock_message(&test_fixture, &data_message_view);

    /* Messages on inactive streams are ignored and no callback is emitted. Wait for client to process and ignore
     * message */
    aws_thread_current_sleep(aws_timestamp_convert(1, AWS_TIMESTAMP_SECS, AWS_TIMESTAMP_NANOS, NULL));
    ASSERT_INT_EQUALS(test_fixture.secure_tunnel_message_received_count, 0);

    ASSERT_SUCCESS(aws_secure_tunnel_stop(secure_tunnel));
    s_wait_for_connection_shutdown(&test_fixture);

    aws_secure_tunnel_mock_test_clean_up(&test_fixture);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(
    secure_tunneling_ignore_inactive_stream_message_test,
    s_secure_tunneling_ignore_inactive_stream_message_test_fn)

static int s_secure_tunneling_ignore_inactive_connection_id_message_test_fn(
    struct aws_allocator *allocator,
    void *ctx) {
    (void)ctx;
    struct secure_tunnel_test_options test_options;
    struct aws_secure_tunnel_mock_test_fixture test_fixture;
    aws_secure_tunnel_mock_test_init(allocator, &test_options, &test_fixture, AWS_SECURE_TUNNELING_DESTINATION_MODE);
    struct aws_secure_tunnel *secure_tunnel = test_fixture.secure_tunnel;

    ASSERT_SUCCESS(aws_secure_tunnel_start(secure_tunnel));
    s_wait_for_connected_successfully(&test_fixture);

    /* Create and send a stream start message from the server to the destination client */
    struct aws_byte_cursor service_1 = aws_byte_cursor_from_string(s_service_id_1);
    struct aws_secure_tunnel_message_view stream_start_message_view = {
        .type = AWS_SECURE_TUNNEL_MT_STREAM_START,
        .service_id = &service_1,
        .stream_id = 1,
        .connection_id = 2,
    };
    aws_secure_tunnel_send_mock_message(&test_fixture, &stream_start_message_view);

    /* Wait and confirm that a stream has been started */
    s_wait_for_stream_started(&test_fixture);
    ASSERT_TRUE(s_secure_tunnel_check_active_connection_id(secure_tunnel, &service_1, 1, 2));

    /* Create and send a data message on a different stream id from the server to the destination client */
    struct aws_byte_cursor payload_cur = aws_byte_cursor_from_string(s_payload_text);
    struct aws_secure_tunnel_message_view data_message_view = {
        .type = AWS_SECURE_TUNNEL_MT_DATA,
        .service_id = &service_1,
        .stream_id = 2,
        .connection_id = 4,
        .payload = &payload_cur,
    };

    aws_secure_tunnel_send_mock_message(&test_fixture, &data_message_view);

    /* Messages on inactive streams are ignored and no callback is emitted. Wait for client to process and ignore
     * message */
    aws_thread_current_sleep(aws_timestamp_convert(1, AWS_TIMESTAMP_SECS, AWS_TIMESTAMP_NANOS, NULL));
    ASSERT_INT_EQUALS(test_fixture.secure_tunnel_message_received_count, 0);

    ASSERT_SUCCESS(aws_secure_tunnel_stop(secure_tunnel));
    s_wait_for_connection_shutdown(&test_fixture);

    aws_secure_tunnel_mock_test_clean_up(&test_fixture);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(
    secure_tunneling_ignore_inactive_connection_id_message_test,
    s_secure_tunneling_ignore_inactive_connection_id_message_test_fn)

static int s_secure_tunneling_v1_to_v2_stream_start_test_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    struct secure_tunnel_test_options test_options;
    struct aws_secure_tunnel_mock_test_fixture test_fixture;
    aws_secure_tunnel_mock_test_init(allocator, &test_options, &test_fixture, AWS_SECURE_TUNNELING_DESTINATION_MODE);
    struct aws_secure_tunnel *secure_tunnel = test_fixture.secure_tunnel;

    ASSERT_SUCCESS(aws_secure_tunnel_start(secure_tunnel));
    s_wait_for_connected_successfully(&test_fixture);

    /* Create and send a stream start message from the server to the destination client */
    struct aws_byte_cursor service_2 = aws_byte_cursor_from_string(s_service_id_2);
    struct aws_secure_tunnel_message_view stream_start_message_view = {
        .type = AWS_SECURE_TUNNEL_MT_STREAM_START,
        .stream_id = 1,
    };
    aws_secure_tunnel_send_mock_message(&test_fixture, &stream_start_message_view);

    /* Wait and confirm that a stream has been started */
    s_wait_for_stream_started(&test_fixture);
    ASSERT_TRUE(s_secure_tunnel_check_active_stream_id(secure_tunnel, NULL, 1));

    struct aws_secure_tunnel_message_view stream_start_message_view_2 = {
        .type = AWS_SECURE_TUNNEL_MT_STREAM_START,
        .service_id = &service_2,
        .stream_id = 1,
    };

    aws_secure_tunnel_send_mock_message(&test_fixture, &stream_start_message_view_2);

    /* Client should disconnect, clear previous V1 connection and stream, reconnect, and start a V2 stream */

    s_wait_for_connection_shutdown(&test_fixture);
    s_wait_for_connected_successfully(&test_fixture);

    /* Check that the established stream is cleared */
    ASSERT_TRUE(s_secure_tunnel_check_active_stream_id(secure_tunnel, NULL, 0));

    s_wait_for_stream_started(&test_fixture);
    ASSERT_TRUE(s_secure_tunnel_check_active_stream_id(secure_tunnel, &service_2, 1));

    ASSERT_SUCCESS(aws_secure_tunnel_stop(secure_tunnel));
    s_wait_for_connection_shutdown(&test_fixture);

    aws_secure_tunnel_mock_test_clean_up(&test_fixture);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(secure_tunneling_v1_to_v2_stream_start_test, s_secure_tunneling_v1_to_v2_stream_start_test_fn)

static int s_secure_tunneling_v1_to_v3_stream_start_test_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    struct secure_tunnel_test_options test_options;
    struct aws_secure_tunnel_mock_test_fixture test_fixture;
    aws_secure_tunnel_mock_test_init(allocator, &test_options, &test_fixture, AWS_SECURE_TUNNELING_DESTINATION_MODE);
    struct aws_secure_tunnel *secure_tunnel = test_fixture.secure_tunnel;

    ASSERT_SUCCESS(aws_secure_tunnel_start(secure_tunnel));
    s_wait_for_connected_successfully(&test_fixture);

    /* Create and send a stream start message from the server to the destination client */
    struct aws_byte_cursor service_1 = aws_byte_cursor_from_string(s_service_id_1);
    struct aws_secure_tunnel_message_view stream_start_message_view = {
        .type = AWS_SECURE_TUNNEL_MT_STREAM_START,
        .stream_id = 1,
    };
    aws_secure_tunnel_send_mock_message(&test_fixture, &stream_start_message_view);

    /* Wait and confirm that a stream has been started */
    s_wait_for_stream_started(&test_fixture);
    ASSERT_TRUE(s_secure_tunnel_check_active_stream_id(secure_tunnel, NULL, 1));

    struct aws_secure_tunnel_message_view stream_start_message_view_2 = {
        .type = AWS_SECURE_TUNNEL_MT_STREAM_START,
        .service_id = &service_1,
        .stream_id = 1,
        .connection_id = 3,
    };

    aws_secure_tunnel_send_mock_message(&test_fixture, &stream_start_message_view_2);

    /* Client should disconnect, clear previous V1 connection and stream, reconnect, and start a V3 stream */

    s_wait_for_connection_shutdown(&test_fixture);
    s_wait_for_connected_successfully(&test_fixture);

    /* Check that the established stream is cleared */
    ASSERT_TRUE(s_secure_tunnel_check_active_stream_id(secure_tunnel, NULL, 0));

    s_wait_for_stream_started(&test_fixture);
    ASSERT_TRUE(s_secure_tunnel_check_active_connection_id(secure_tunnel, &service_1, 1, 3));

    ASSERT_SUCCESS(aws_secure_tunnel_stop(secure_tunnel));
    s_wait_for_connection_shutdown(&test_fixture);

    aws_secure_tunnel_mock_test_clean_up(&test_fixture);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(secure_tunneling_v1_to_v3_stream_start_test, s_secure_tunneling_v1_to_v3_stream_start_test_fn)

static int s_secure_tunneling_v2_to_v1_stream_start_test_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    struct secure_tunnel_test_options test_options;
    struct aws_secure_tunnel_mock_test_fixture test_fixture;
    aws_secure_tunnel_mock_test_init(allocator, &test_options, &test_fixture, AWS_SECURE_TUNNELING_DESTINATION_MODE);
    struct aws_secure_tunnel *secure_tunnel = test_fixture.secure_tunnel;

    ASSERT_SUCCESS(aws_secure_tunnel_start(secure_tunnel));
    s_wait_for_connected_successfully(&test_fixture);

    /* Create and send a v2 stream start message from the server to the destination client */
    struct aws_byte_cursor service_1 = aws_byte_cursor_from_string(s_service_id_1);
    struct aws_secure_tunnel_message_view stream_start_message_view = {
        .type = AWS_SECURE_TUNNEL_MT_STREAM_START,
        .service_id = &service_1,
        .stream_id = 1,
    };
    aws_secure_tunnel_send_mock_message(&test_fixture, &stream_start_message_view);

    /* Wait and confirm that a stream has been started */
    s_wait_for_stream_started(&test_fixture);
    ASSERT_TRUE(s_secure_tunnel_check_active_stream_id(secure_tunnel, &service_1, 1));

    struct aws_secure_tunnel_message_view stream_start_message_view_2 = {
        .type = AWS_SECURE_TUNNEL_MT_STREAM_START,
        .stream_id = 2,
    };
    aws_secure_tunnel_send_mock_message(&test_fixture, &stream_start_message_view_2);

    /* Client should disconnect, clear previous V2 connection and stream, reconnect, and start a V1 stream */

    s_wait_for_connection_shutdown(&test_fixture);
    s_wait_for_connected_successfully(&test_fixture);

    /* Confirm that previous stream has been closed */
    ASSERT_TRUE(s_secure_tunnel_check_active_stream_id(secure_tunnel, &service_1, 0));

    /* Wait and confirm that a stream has been started */
    s_wait_for_stream_started(&test_fixture);
    ASSERT_TRUE(s_secure_tunnel_check_active_stream_id(secure_tunnel, NULL, 2));

    ASSERT_SUCCESS(aws_secure_tunnel_stop(secure_tunnel));
    s_wait_for_connection_shutdown(&test_fixture);

    aws_secure_tunnel_mock_test_clean_up(&test_fixture);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(secure_tunneling_v2_to_v1_stream_start_test, s_secure_tunneling_v2_to_v1_stream_start_test_fn)

static int s_secure_tunneling_v3_to_v1_stream_start_test_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    struct secure_tunnel_test_options test_options;
    struct aws_secure_tunnel_mock_test_fixture test_fixture;
    aws_secure_tunnel_mock_test_init(allocator, &test_options, &test_fixture, AWS_SECURE_TUNNELING_DESTINATION_MODE);
    struct aws_secure_tunnel *secure_tunnel = test_fixture.secure_tunnel;

    ASSERT_SUCCESS(aws_secure_tunnel_start(secure_tunnel));
    s_wait_for_connected_successfully(&test_fixture);

    /* Create and send a v2 stream start message from the server to the destination client */
    struct aws_byte_cursor service_1 = aws_byte_cursor_from_string(s_service_id_1);
    struct aws_secure_tunnel_message_view stream_start_message_view = {
        .type = AWS_SECURE_TUNNEL_MT_STREAM_START,
        .service_id = &service_1,
        .stream_id = 1,
        .connection_id = 2,
    };
    aws_secure_tunnel_send_mock_message(&test_fixture, &stream_start_message_view);

    /* Wait and confirm that a stream has been started */
    s_wait_for_stream_started(&test_fixture);
    ASSERT_TRUE(s_secure_tunnel_check_active_connection_id(secure_tunnel, &service_1, 1, 2));

    struct aws_secure_tunnel_message_view stream_start_message_view_2 = {
        .type = AWS_SECURE_TUNNEL_MT_STREAM_START,
        .stream_id = 2,
    };
    aws_secure_tunnel_send_mock_message(&test_fixture, &stream_start_message_view_2);

    /* Client should disconnect, clear previous V3 connection and stream, reconnect, and start a V1 stream */

    s_wait_for_connection_shutdown(&test_fixture);
    s_wait_for_connected_successfully(&test_fixture);

    /* Check that the established stream is cleared */
    ASSERT_FALSE(s_secure_tunnel_check_active_connection_id(secure_tunnel, &service_1, 1, 2));

    /* Wait and confirm that a stream has been started */
    s_wait_for_stream_started(&test_fixture);
    /* Check that V1 Stream is established */
    ASSERT_TRUE(s_secure_tunnel_check_active_stream_id(secure_tunnel, NULL, 2));

    ASSERT_SUCCESS(aws_secure_tunnel_stop(secure_tunnel));
    s_wait_for_connection_shutdown(&test_fixture);

    aws_secure_tunnel_mock_test_clean_up(&test_fixture);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(secure_tunneling_v3_to_v1_stream_start_test, s_secure_tunneling_v3_to_v1_stream_start_test_fn)

static int s_secure_tunneling_v1_stream_start_v3_message_reset_test_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    struct secure_tunnel_test_options test_options;
    struct aws_secure_tunnel_mock_test_fixture test_fixture;
    aws_secure_tunnel_mock_test_init(allocator, &test_options, &test_fixture, AWS_SECURE_TUNNELING_DESTINATION_MODE);
    struct aws_secure_tunnel *secure_tunnel = test_fixture.secure_tunnel;

    ASSERT_SUCCESS(aws_secure_tunnel_start(secure_tunnel));
    s_wait_for_connected_successfully(&test_fixture);

    /* Create and send a stream start message from the server to the destination client */
    struct aws_byte_cursor service_1 = aws_byte_cursor_from_string(s_service_id_1);
    struct aws_secure_tunnel_message_view stream_start_message_view = {
        .type = AWS_SECURE_TUNNEL_MT_STREAM_START,
        .stream_id = 1,
    };
    aws_secure_tunnel_send_mock_message(&test_fixture, &stream_start_message_view);

    /* Wait and confirm that a stream has been started */
    s_wait_for_stream_started(&test_fixture);
    ASSERT_TRUE(s_secure_tunnel_check_active_stream_id(secure_tunnel, NULL, 1));

    struct aws_byte_cursor payload_cur = aws_byte_cursor_from_string(s_payload_text);
    struct aws_secure_tunnel_message_view data_message_view = {
        .type = AWS_SECURE_TUNNEL_MT_DATA,
        .service_id = &service_1,
        .stream_id = 1,
        .payload = &payload_cur,
        .connection_id = 3,
    };
    aws_secure_tunnel_send_mock_message(&test_fixture, &data_message_view);

    /* On receipt of an unexpected protocol version message, Client should disconnect/reconnect and clear all streams */

    s_wait_for_connection_shutdown(&test_fixture);
    s_wait_for_connected_successfully(&test_fixture);

    /* Check that the established stream is cleared */
    ASSERT_TRUE(s_secure_tunnel_check_active_stream_id(secure_tunnel, NULL, 0));

    ASSERT_SUCCESS(aws_secure_tunnel_stop(secure_tunnel));
    s_wait_for_connection_shutdown(&test_fixture);

    aws_secure_tunnel_mock_test_clean_up(&test_fixture);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(
    secure_tunneling_v1_stream_start_v3_message_reset_test,
    s_secure_tunneling_v1_stream_start_v3_message_reset_test_fn)

static int s_secure_tunneling_v2_stream_start_connection_start_reset_test_fn(
    struct aws_allocator *allocator,
    void *ctx) {
    (void)ctx;
    struct secure_tunnel_test_options test_options;
    struct aws_secure_tunnel_mock_test_fixture test_fixture;
    aws_secure_tunnel_mock_test_init(allocator, &test_options, &test_fixture, AWS_SECURE_TUNNELING_DESTINATION_MODE);
    struct aws_secure_tunnel *secure_tunnel = test_fixture.secure_tunnel;

    ASSERT_SUCCESS(aws_secure_tunnel_start(secure_tunnel));
    s_wait_for_connected_successfully(&test_fixture);

    /* Create and send a stream start message from the server to the destination client */
    struct aws_byte_cursor service_1 = aws_byte_cursor_from_string(s_service_id_1);
    struct aws_secure_tunnel_message_view stream_start_message_view = {
        .type = AWS_SECURE_TUNNEL_MT_STREAM_START,
        .service_id = &service_1,
        .stream_id = 1,
    };
    aws_secure_tunnel_send_mock_message(&test_fixture, &stream_start_message_view);

    /* Wait and confirm that a stream has been started */
    s_wait_for_stream_started(&test_fixture);
    ASSERT_TRUE(s_secure_tunnel_check_active_stream_id(secure_tunnel, &service_1, 1));

    struct aws_secure_tunnel_message_view connection_start_message_view = {
        .type = AWS_SECURE_TUNNEL_MT_CONNECTION_START,
        .service_id = &service_1,
        .stream_id = 1,
        .connection_id = 3,
    };
    aws_secure_tunnel_send_mock_message(&test_fixture, &connection_start_message_view);

    /* Client should disconnect and reconnect with no active streams on receiving a wrong version connection start */

    s_wait_for_connection_shutdown(&test_fixture);
    s_wait_for_connected_successfully(&test_fixture);

    /* pause to process a new connection */
    aws_thread_current_sleep(aws_timestamp_convert(1, AWS_TIMESTAMP_SECS, AWS_TIMESTAMP_NANOS, NULL));

    /* Check that the established stream is cleared */
    ASSERT_TRUE(s_secure_tunnel_check_active_stream_id(secure_tunnel, &service_1, 0));

    ASSERT_SUCCESS(aws_secure_tunnel_stop(secure_tunnel));
    s_wait_for_connection_shutdown(&test_fixture);

    aws_secure_tunnel_mock_test_clean_up(&test_fixture);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(
    secure_tunneling_v2_stream_start_connection_start_reset_test,
    s_secure_tunneling_v2_stream_start_connection_start_reset_test_fn)

static int s_secure_tunneling_close_stream_on_connection_reset_test_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    struct secure_tunnel_test_options test_options;
    struct aws_secure_tunnel_mock_test_fixture test_fixture;
    aws_secure_tunnel_mock_test_init(allocator, &test_options, &test_fixture, AWS_SECURE_TUNNELING_DESTINATION_MODE);
    struct aws_secure_tunnel *secure_tunnel = test_fixture.secure_tunnel;

    ASSERT_SUCCESS(aws_secure_tunnel_start(secure_tunnel));
    s_wait_for_connected_successfully(&test_fixture);

    /* Create and send a v3 stream start message from the server to the destination client */
    struct aws_byte_cursor service_1 = aws_byte_cursor_from_string(s_service_id_1);
    struct aws_secure_tunnel_message_view stream_start_message_view = {
        .type = AWS_SECURE_TUNNEL_MT_STREAM_START,
        .service_id = &service_1,
        .stream_id = 1,
        .connection_id = 2,
    };
    aws_secure_tunnel_send_mock_message(&test_fixture, &stream_start_message_view);

    /* Wait and confirm that a stream has been started */
    s_wait_for_stream_started(&test_fixture);
    ASSERT_TRUE(s_secure_tunnel_check_active_connection_id(secure_tunnel, &service_1, 1, 2));

    /* Send a connection start */
    struct aws_secure_tunnel_message_view connection_start_message_view = {
        .type = AWS_SECURE_TUNNEL_MT_CONNECTION_START,
        .service_id = &service_1,
        .stream_id = 1,
        .connection_id = 3,
    };
    aws_secure_tunnel_send_mock_message(&test_fixture, &connection_start_message_view);

    s_wait_for_connection_started(&test_fixture);
    /* Check that connections has been started */
    ASSERT_TRUE(s_secure_tunnel_check_active_connection_id(secure_tunnel, &service_1, 1, 3));

    /* Send a connection reset */
    struct aws_secure_tunnel_message_view connection_reset_message_view = {
        .type = AWS_SECURE_TUNNEL_MT_CONNECTION_RESET,
        .service_id = &service_1,
        .stream_id = 1,
        .connection_id = 3,
    };
    aws_secure_tunnel_send_mock_message(&test_fixture, &connection_reset_message_view);

    s_wait_for_connection_reset_received(&test_fixture);

    /* Check that connection has been closed */
    ASSERT_FALSE(s_secure_tunnel_check_active_connection_id(secure_tunnel, &service_1, 1, 3));

    ASSERT_SUCCESS(aws_secure_tunnel_stop(secure_tunnel));
    s_wait_for_connection_shutdown(&test_fixture);

    aws_secure_tunnel_mock_test_clean_up(&test_fixture);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(
    secure_tunneling_close_stream_on_connection_reset_test,
    s_secure_tunneling_close_stream_on_connection_reset_test_fn)

static int s_secure_tunneling_existing_connection_start_send_reset_test_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    struct secure_tunnel_test_options test_options;
    struct aws_secure_tunnel_mock_test_fixture test_fixture;
    aws_secure_tunnel_mock_test_init(allocator, &test_options, &test_fixture, AWS_SECURE_TUNNELING_DESTINATION_MODE);
    struct aws_secure_tunnel *secure_tunnel = test_fixture.secure_tunnel;

    ASSERT_SUCCESS(aws_secure_tunnel_start(secure_tunnel));
    s_wait_for_connected_successfully(&test_fixture);

    /* Create and send a v3 stream start message from the server to the destination client */
    struct aws_byte_cursor service_1 = aws_byte_cursor_from_string(s_service_id_1);
    struct aws_secure_tunnel_message_view stream_start_message_view = {
        .type = AWS_SECURE_TUNNEL_MT_STREAM_START,
        .service_id = &service_1,
        .stream_id = 1,
        .connection_id = 2,
    };
    aws_secure_tunnel_send_mock_message(&test_fixture, &stream_start_message_view);

    /* Wait and confirm that a stream has been started */
    s_wait_for_stream_started(&test_fixture);

    /* Send a CONNECTION START on existing connection id */
    struct aws_secure_tunnel_message_view connection_start_message_view = {
        .type = AWS_SECURE_TUNNEL_MT_CONNECTION_START,
        .service_id = &service_1,
        .stream_id = 1,
        .connection_id = 2,
    };
    aws_secure_tunnel_send_mock_message(&test_fixture, &connection_start_message_view);

    /* Wait and confirm that a bad connection request was received */
    s_wait_for_bad_connection_started(&test_fixture);

    s_wait_for_connection_reset_message_sent(&test_fixture);

    /* check that stream with connection id has been closed properly */
    struct aws_hash_element *elem = NULL;
    aws_hash_table_find(&secure_tunnel->connections->service_ids, stream_start_message_view.service_id, &elem);
    ASSERT_NOT_NULL(elem);
    struct aws_service_id_element *service_id_elem = elem->value;
    ASSERT_INT_EQUALS((int)aws_hash_table_get_entry_count(&service_id_elem->connection_ids), 0);

    ASSERT_SUCCESS(aws_secure_tunnel_stop(secure_tunnel));
    s_wait_for_connection_shutdown(&test_fixture);

    aws_secure_tunnel_mock_test_clean_up(&test_fixture);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(
    secure_tunneling_existing_connection_start_send_reset_test,
    s_secure_tunneling_existing_connection_start_send_reset_test_fn)

static int s_secure_tunneling_send_v2_data_message_on_v1_connection_test_fn(
    struct aws_allocator *allocator,
    void *ctx) {
    (void)ctx;
    struct secure_tunnel_test_options test_options;
    struct aws_secure_tunnel_mock_test_fixture test_fixture;
    aws_secure_tunnel_mock_test_init(allocator, &test_options, &test_fixture, AWS_SECURE_TUNNELING_DESTINATION_MODE);
    struct aws_secure_tunnel *secure_tunnel = test_fixture.secure_tunnel;

    ASSERT_SUCCESS(aws_secure_tunnel_start(secure_tunnel));
    s_wait_for_connected_successfully(&test_fixture);

    /* Create and send a V1 StreamStart message from the server to the destination client */
    struct aws_secure_tunnel_message_view stream_start_message_view = {
        .type = AWS_SECURE_TUNNEL_MT_STREAM_START,
        .stream_id = 1,
    };
    aws_secure_tunnel_send_mock_message(&test_fixture, &stream_start_message_view);

    /* Wait and confirm that a stream has been started */
    s_wait_for_stream_started(&test_fixture);
    ASSERT_TRUE(s_secure_tunnel_check_active_stream_id(secure_tunnel, NULL, 1));

    /* Create and send a V2 DATA message, this should fail with PROTOCOL VERSION MISMATCH error */
    struct aws_byte_cursor service_1 = aws_byte_cursor_from_string(s_service_id_1);
    struct aws_secure_tunnel_message_view data_message_view = {
        .type = AWS_SECURE_TUNNEL_MT_DATA,
        .stream_id = 0,
        .service_id = &service_1,
        .payload = &s_payload_cursor_max_size,
    };
    int result = aws_secure_tunnel_send_message(secure_tunnel, &data_message_view);
    ASSERT_INT_EQUALS(result, AWS_OP_SUCCESS);

    s_wait_for_on_send_message_complete_fired(&test_fixture);

    /* Confirm that no messages have gone out from the client */
    ASSERT_INT_EQUALS(test_fixture.secure_tunnel_message_sent_count, 0);

    /* Ensure that the established stream was not affected by the message */
    ASSERT_TRUE(s_secure_tunnel_check_active_stream_id(secure_tunnel, NULL, 1));

    ASSERT_SUCCESS(aws_secure_tunnel_stop(secure_tunnel));
    s_wait_for_connection_shutdown(&test_fixture);

    aws_secure_tunnel_mock_test_clean_up(&test_fixture);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(
    secure_tunneling_send_v2_data_message_on_v1_connection_test,
    s_secure_tunneling_send_v2_data_message_on_v1_connection_test_fn)

static int s_secure_tunneling_send_v3_data_message_on_v1_connection_test_fn(
    struct aws_allocator *allocator,
    void *ctx) {
    (void)ctx;
    struct secure_tunnel_test_options test_options;
    struct aws_secure_tunnel_mock_test_fixture test_fixture;
    aws_secure_tunnel_mock_test_init(allocator, &test_options, &test_fixture, AWS_SECURE_TUNNELING_DESTINATION_MODE);
    struct aws_secure_tunnel *secure_tunnel = test_fixture.secure_tunnel;

    ASSERT_SUCCESS(aws_secure_tunnel_start(secure_tunnel));
    s_wait_for_connected_successfully(&test_fixture);

    /* Create and send a V1 StreamStart message from the server to the destination client */
    struct aws_secure_tunnel_message_view stream_start_message_view = {
        .type = AWS_SECURE_TUNNEL_MT_STREAM_START,
        .stream_id = 1,
    };
    aws_secure_tunnel_send_mock_message(&test_fixture, &stream_start_message_view);

    /* Wait and confirm that a stream has been started */
    s_wait_for_stream_started(&test_fixture);
    ASSERT_TRUE(s_secure_tunnel_check_active_stream_id(secure_tunnel, NULL, 1));

    /* Create and send a V3 DATA message, this should fail with PROTOCOL VERSION MISMATCH error */
    struct aws_byte_cursor service_1 = aws_byte_cursor_from_string(s_service_id_1);
    struct aws_secure_tunnel_message_view data_message_view = {
        .type = AWS_SECURE_TUNNEL_MT_DATA,
        .stream_id = 0,
        .service_id = &service_1,
        .connection_id = 3,
        .payload = &s_payload_cursor_max_size,
    };
    int result = aws_secure_tunnel_send_message(secure_tunnel, &data_message_view);
    ASSERT_INT_EQUALS(result, AWS_OP_SUCCESS);

    s_wait_for_on_send_message_complete_fired(&test_fixture);

    /* Confirm that no messages have gone out from the client */
    ASSERT_INT_EQUALS(test_fixture.secure_tunnel_message_sent_count, 0);

    /* Confirm that on_send_message_complete callback was fired */
    ASSERT_INT_EQUALS(test_fixture.on_send_message_complete_result.type, AWS_SECURE_TUNNEL_MT_DATA);
    ASSERT_INT_EQUALS(
        test_fixture.on_send_message_complete_result.error_code,
        AWS_ERROR_IOTDEVICE_SECURE_TUNNELING_DATA_PROTOCOL_VERSION_MISMATCH);

    /* Ensure that the established stream was not affected by the message */
    ASSERT_TRUE(s_secure_tunnel_check_active_stream_id(secure_tunnel, NULL, 1));

    ASSERT_SUCCESS(aws_secure_tunnel_stop(secure_tunnel));
    s_wait_for_connection_shutdown(&test_fixture);

    aws_secure_tunnel_mock_test_clean_up(&test_fixture);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(
    secure_tunneling_send_v3_data_message_on_v1_connection_test,
    s_secure_tunneling_send_v3_data_message_on_v1_connection_test_fn)

static int s_secure_tunneling_send_v1_data_message_on_v2_connection_test_fn(
    struct aws_allocator *allocator,
    void *ctx) {
    (void)ctx;
    struct secure_tunnel_test_options test_options;
    struct aws_secure_tunnel_mock_test_fixture test_fixture;
    aws_secure_tunnel_mock_test_init(allocator, &test_options, &test_fixture, AWS_SECURE_TUNNELING_DESTINATION_MODE);
    struct aws_secure_tunnel *secure_tunnel = test_fixture.secure_tunnel;

    ASSERT_SUCCESS(aws_secure_tunnel_start(secure_tunnel));
    s_wait_for_connected_successfully(&test_fixture);

    /* Create and send a V2 StreamStart message from the server to the destination client */
    struct aws_byte_cursor service_1 = aws_byte_cursor_from_string(s_service_id_1);
    struct aws_secure_tunnel_message_view stream_start_message_view = {
        .type = AWS_SECURE_TUNNEL_MT_STREAM_START,
        .service_id = &service_1,
        .stream_id = 1,
    };
    aws_secure_tunnel_send_mock_message(&test_fixture, &stream_start_message_view);

    /* Wait and confirm that a stream has been started */
    s_wait_for_stream_started(&test_fixture);
    ASSERT_TRUE(s_secure_tunnel_check_active_stream_id(secure_tunnel, &service_1, 1));

    /* Create and send a V1 DATA message, this should fail with PROTOCOL VERSION MISMATCH error */
    struct aws_secure_tunnel_message_view data_message_view = {
        .type = AWS_SECURE_TUNNEL_MT_DATA,
        .stream_id = 0,
        .payload = &s_payload_cursor_max_size,
    };
    int result = aws_secure_tunnel_send_message(secure_tunnel, &data_message_view);
    ASSERT_INT_EQUALS(result, AWS_OP_SUCCESS);

    s_wait_for_on_send_message_complete_fired(&test_fixture);

    /* Confirm that no messages have gone out from the client */
    ASSERT_INT_EQUALS(test_fixture.secure_tunnel_message_sent_count, 0);

    /* Confirm that on_send_message_complete callback was fired */
    ASSERT_INT_EQUALS(test_fixture.on_send_message_complete_result.type, AWS_SECURE_TUNNEL_MT_DATA);
    ASSERT_INT_EQUALS(
        test_fixture.on_send_message_complete_result.error_code,
        AWS_ERROR_IOTDEVICE_SECURE_TUNNELING_DATA_PROTOCOL_VERSION_MISMATCH);

    /* Ensure that the established stream was not affected by the message */
    ASSERT_TRUE(s_secure_tunnel_check_active_stream_id(secure_tunnel, &service_1, 1));

    ASSERT_SUCCESS(aws_secure_tunnel_stop(secure_tunnel));
    s_wait_for_connection_shutdown(&test_fixture);

    aws_secure_tunnel_mock_test_clean_up(&test_fixture);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(
    secure_tunneling_send_v1_data_message_on_v2_connection_test,
    s_secure_tunneling_send_v1_data_message_on_v2_connection_test_fn)

static int s_secure_tunneling_send_v3_data_message_on_v2_connection_test_fn(
    struct aws_allocator *allocator,
    void *ctx) {
    (void)ctx;
    struct secure_tunnel_test_options test_options;
    struct aws_secure_tunnel_mock_test_fixture test_fixture;
    aws_secure_tunnel_mock_test_init(allocator, &test_options, &test_fixture, AWS_SECURE_TUNNELING_DESTINATION_MODE);
    struct aws_secure_tunnel *secure_tunnel = test_fixture.secure_tunnel;

    ASSERT_SUCCESS(aws_secure_tunnel_start(secure_tunnel));
    s_wait_for_connected_successfully(&test_fixture);

    /* Create and send a V2 StreamStart message from the server to the destination client */
    struct aws_byte_cursor service_1 = aws_byte_cursor_from_string(s_service_id_1);
    struct aws_secure_tunnel_message_view stream_start_message_view = {
        .type = AWS_SECURE_TUNNEL_MT_STREAM_START,
        .service_id = &service_1,
        .stream_id = 1,
    };
    aws_secure_tunnel_send_mock_message(&test_fixture, &stream_start_message_view);

    /* Wait and confirm that a stream has been started */
    s_wait_for_stream_started(&test_fixture);
    ASSERT_TRUE(s_secure_tunnel_check_active_stream_id(secure_tunnel, &service_1, 1));

    /* Create and send a V3 DATA message, this should fail with PROTOCOL VERSION MISMATCH error */
    struct aws_secure_tunnel_message_view data_message_view = {
        .type = AWS_SECURE_TUNNEL_MT_DATA,
        .stream_id = 0,
        .service_id = &service_1,
        .connection_id = 3,
        .payload = &s_payload_cursor_max_size,
    };
    int result = aws_secure_tunnel_send_message(secure_tunnel, &data_message_view);
    ASSERT_INT_EQUALS(result, AWS_OP_SUCCESS);

    s_wait_for_on_send_message_complete_fired(&test_fixture);

    /* Confirm that no messages have gone out from the client */
    ASSERT_INT_EQUALS(test_fixture.secure_tunnel_message_sent_count, 0);

    /* Confirm that on_send_message_complete callback was fired */
    ASSERT_INT_EQUALS(test_fixture.on_send_message_complete_result.type, AWS_SECURE_TUNNEL_MT_DATA);
    ASSERT_INT_EQUALS(
        test_fixture.on_send_message_complete_result.error_code,
        AWS_ERROR_IOTDEVICE_SECURE_TUNNELING_DATA_PROTOCOL_VERSION_MISMATCH);

    /* Ensure that the established stream was not affected by the message */
    ASSERT_TRUE(s_secure_tunnel_check_active_stream_id(secure_tunnel, &service_1, 1));

    ASSERT_SUCCESS(aws_secure_tunnel_stop(secure_tunnel));
    s_wait_for_connection_shutdown(&test_fixture);

    aws_secure_tunnel_mock_test_clean_up(&test_fixture);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(
    secure_tunneling_send_v3_data_message_on_v2_connection_test,
    s_secure_tunneling_send_v3_data_message_on_v2_connection_test_fn)

static int s_secure_tunneling_send_v1_data_message_on_v3_connection_test_fn(
    struct aws_allocator *allocator,
    void *ctx) {
    (void)ctx;
    struct secure_tunnel_test_options test_options;
    struct aws_secure_tunnel_mock_test_fixture test_fixture;
    aws_secure_tunnel_mock_test_init(allocator, &test_options, &test_fixture, AWS_SECURE_TUNNELING_DESTINATION_MODE);
    struct aws_secure_tunnel *secure_tunnel = test_fixture.secure_tunnel;

    ASSERT_SUCCESS(aws_secure_tunnel_start(secure_tunnel));
    s_wait_for_connected_successfully(&test_fixture);

    /* Create and send a V3 StreamStart message from the server to the destination client */
    struct aws_byte_cursor service_1 = aws_byte_cursor_from_string(s_service_id_1);
    struct aws_secure_tunnel_message_view stream_start_message_view = {
        .type = AWS_SECURE_TUNNEL_MT_STREAM_START,
        .service_id = &service_1,
        .stream_id = 1,
        .connection_id = 3,
    };
    aws_secure_tunnel_send_mock_message(&test_fixture, &stream_start_message_view);

    /* Wait and confirm that a stream has been started */
    s_wait_for_stream_started(&test_fixture);
    ASSERT_TRUE(s_secure_tunnel_check_active_stream_id(secure_tunnel, &service_1, 1));

    /* Create and send a V1 DATA message, this should fail with PROTOCOL VERSION MISMATCH error */
    struct aws_secure_tunnel_message_view data_message_view = {
        .type = AWS_SECURE_TUNNEL_MT_DATA,
        .stream_id = 0,
        .payload = &s_payload_cursor_max_size,
    };
    int result = aws_secure_tunnel_send_message(secure_tunnel, &data_message_view);
    ASSERT_INT_EQUALS(result, AWS_OP_SUCCESS);

    s_wait_for_on_send_message_complete_fired(&test_fixture);

    /* Confirm that no messages have gone out from the client */
    ASSERT_INT_EQUALS(test_fixture.secure_tunnel_message_sent_count, 0);

    /* Confirm that on_send_message_complete callback was fired */
    ASSERT_INT_EQUALS(test_fixture.on_send_message_complete_result.type, AWS_SECURE_TUNNEL_MT_DATA);
    ASSERT_INT_EQUALS(
        test_fixture.on_send_message_complete_result.error_code,
        AWS_ERROR_IOTDEVICE_SECURE_TUNNELING_DATA_PROTOCOL_VERSION_MISMATCH);

    /* Ensure that the established stream was not affected by the message */
    ASSERT_TRUE(s_secure_tunnel_check_active_stream_id(secure_tunnel, &service_1, 1));

    ASSERT_SUCCESS(aws_secure_tunnel_stop(secure_tunnel));
    s_wait_for_connection_shutdown(&test_fixture);

    aws_secure_tunnel_mock_test_clean_up(&test_fixture);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(
    secure_tunneling_send_v1_data_message_on_v3_connection_test,
    s_secure_tunneling_send_v1_data_message_on_v3_connection_test_fn)

static int s_secure_tunneling_send_v2_data_message_on_v3_connection_test_fn(
    struct aws_allocator *allocator,
    void *ctx) {
    (void)ctx;
    struct secure_tunnel_test_options test_options;
    struct aws_secure_tunnel_mock_test_fixture test_fixture;
    aws_secure_tunnel_mock_test_init(allocator, &test_options, &test_fixture, AWS_SECURE_TUNNELING_DESTINATION_MODE);
    struct aws_secure_tunnel *secure_tunnel = test_fixture.secure_tunnel;

    ASSERT_SUCCESS(aws_secure_tunnel_start(secure_tunnel));
    s_wait_for_connected_successfully(&test_fixture);

    /* Create and send a V3 StreamStart message from the server to the destination client */
    struct aws_byte_cursor service_1 = aws_byte_cursor_from_string(s_service_id_1);
    struct aws_secure_tunnel_message_view stream_start_message_view = {
        .type = AWS_SECURE_TUNNEL_MT_STREAM_START,
        .service_id = &service_1,
        .stream_id = 1,
        .connection_id = 3,
    };
    aws_secure_tunnel_send_mock_message(&test_fixture, &stream_start_message_view);

    /* Wait and confirm that a stream has been started */
    s_wait_for_stream_started(&test_fixture);
    ASSERT_TRUE(s_secure_tunnel_check_active_stream_id(secure_tunnel, &service_1, 1));

    /* Create and send a V2 DATA message, this should fail with PROTOCOL VERSION MISMATCH error */
    struct aws_secure_tunnel_message_view data_message_view = {
        .type = AWS_SECURE_TUNNEL_MT_DATA,
        .stream_id = 0,
        .service_id = &service_1,
        .payload = &s_payload_cursor_max_size,
    };
    int result = aws_secure_tunnel_send_message(secure_tunnel, &data_message_view);
    ASSERT_INT_EQUALS(result, AWS_OP_SUCCESS);

    s_wait_for_on_send_message_complete_fired(&test_fixture);

    /* Confirm that no messages have gone out from the client */
    ASSERT_INT_EQUALS(test_fixture.secure_tunnel_message_sent_count, 0);

    /* Confirm that on_send_message_complete callback was fired */
    ASSERT_INT_EQUALS(test_fixture.on_send_message_complete_result.type, AWS_SECURE_TUNNEL_MT_DATA);
    ASSERT_INT_EQUALS(
        test_fixture.on_send_message_complete_result.error_code,
        AWS_ERROR_IOTDEVICE_SECURE_TUNNELING_DATA_PROTOCOL_VERSION_MISMATCH);

    /* Ensure that the established stream was not affected by the message */
    ASSERT_TRUE(s_secure_tunnel_check_active_stream_id(secure_tunnel, &service_1, 1));

    ASSERT_SUCCESS(aws_secure_tunnel_stop(secure_tunnel));
    s_wait_for_connection_shutdown(&test_fixture);

    aws_secure_tunnel_mock_test_clean_up(&test_fixture);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(
    secure_tunneling_send_v2_data_message_on_v3_connection_test,
    s_secure_tunneling_send_v2_data_message_on_v3_connection_test_fn)

static int s_secure_tunneling_send_v2_data_message_on_incorrect_v2_connection_test_fn(
    struct aws_allocator *allocator,
    void *ctx) {

    (void)ctx;

    struct secure_tunnel_test_options test_options;
    struct aws_secure_tunnel_mock_test_fixture test_fixture;
    aws_secure_tunnel_mock_test_init(allocator, &test_options, &test_fixture, AWS_SECURE_TUNNELING_DESTINATION_MODE);
    struct aws_secure_tunnel *secure_tunnel = test_fixture.secure_tunnel;

    ASSERT_SUCCESS(aws_secure_tunnel_start(secure_tunnel));
    s_wait_for_connected_successfully(&test_fixture);

    /* Create and send a V2 StreamStart message from the server to the destination client */
    struct aws_byte_cursor service_1 = aws_byte_cursor_from_string(s_service_id_1);
    struct aws_secure_tunnel_message_view stream_start_message_view = {
        .type = AWS_SECURE_TUNNEL_MT_STREAM_START,
        .service_id = &service_1,
        .stream_id = 1,
    };
    aws_secure_tunnel_send_mock_message(&test_fixture, &stream_start_message_view);

    /* Wait and confirm that a stream has been started */
    s_wait_for_stream_started(&test_fixture);
    ASSERT_TRUE(s_secure_tunnel_check_active_stream_id(secure_tunnel, &service_1, 1));

    /* Create and send a V2 DATA message with incorrect service ID,
     * this should fail with INVALID SERVICE ID error */
    struct aws_byte_cursor service_2 = aws_byte_cursor_from_string(s_service_id_2);
    struct aws_secure_tunnel_message_view data_message_view = {
        .type = AWS_SECURE_TUNNEL_MT_DATA,
        .stream_id = 0,
        .service_id = &service_2,
        .payload = &s_payload_cursor_max_size,
    };

    int result = aws_secure_tunnel_send_message(secure_tunnel, &data_message_view);
    ASSERT_INT_EQUALS(result, AWS_OP_SUCCESS);

    s_wait_for_on_send_message_complete_fired(&test_fixture);

    /* Confirm that no messages have gone out from the client */
    ASSERT_INT_EQUALS(test_fixture.secure_tunnel_message_sent_count, 0);

    /* Confirm that on_send_message_complete callback was fired */
    ASSERT_INT_EQUALS(test_fixture.on_send_message_complete_result.type, AWS_SECURE_TUNNEL_MT_DATA);
    ASSERT_INT_EQUALS(
        test_fixture.on_send_message_complete_result.error_code,
        AWS_ERROR_IOTDEVICE_SECURE_TUNNELING_INACTIVE_SERVICE_ID);

    /* Ensure that the established stream was not affected by the message */
    ASSERT_TRUE(s_secure_tunnel_check_active_stream_id(secure_tunnel, &service_1, 1));

    ASSERT_SUCCESS(aws_secure_tunnel_stop(secure_tunnel));
    s_wait_for_connection_shutdown(&test_fixture);

    aws_secure_tunnel_mock_test_clean_up(&test_fixture);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(
    secure_tunneling_send_v2_data_message_on_incorrect_v2_connection_test,
    s_secure_tunneling_send_v2_data_message_on_incorrect_v2_connection_test_fn)

static int s_secure_tunneling_send_v3_data_message_on_incorrect_v3_connection_test_fn(
    struct aws_allocator *allocator,
    void *ctx) {

    (void)ctx;

    struct secure_tunnel_test_options test_options;
    struct aws_secure_tunnel_mock_test_fixture test_fixture;
    aws_secure_tunnel_mock_test_init(allocator, &test_options, &test_fixture, AWS_SECURE_TUNNELING_DESTINATION_MODE);
    struct aws_secure_tunnel *secure_tunnel = test_fixture.secure_tunnel;

    ASSERT_SUCCESS(aws_secure_tunnel_start(secure_tunnel));
    s_wait_for_connected_successfully(&test_fixture);

    /* Create and send a V3 StreamStart message from the server to the destination client */
    struct aws_byte_cursor service_1 = aws_byte_cursor_from_string(s_service_id_1);
    struct aws_secure_tunnel_message_view stream_start_message_view = {
        .type = AWS_SECURE_TUNNEL_MT_STREAM_START,
        .service_id = &service_1,
        .stream_id = 1,
        .connection_id = 2,
    };
    aws_secure_tunnel_send_mock_message(&test_fixture, &stream_start_message_view);

    /* Wait and confirm that a stream has been started */
    s_wait_for_stream_started(&test_fixture);
    ASSERT_TRUE(s_secure_tunnel_check_active_stream_id(secure_tunnel, &service_1, 1));

    /* Create and send a V3 DATA message with incorrect service ID,
     * this should fail with INVALID CONNECTION ID error */
    struct aws_secure_tunnel_message_view data_message_view = {
        .type = AWS_SECURE_TUNNEL_MT_DATA,
        .stream_id = 0,
        .service_id = &service_1,
        .connection_id = 3,
        .payload = &s_payload_cursor_max_size,
    };

    int result = aws_secure_tunnel_send_message(secure_tunnel, &data_message_view);
    ASSERT_INT_EQUALS(result, AWS_OP_SUCCESS);

    s_wait_for_on_send_message_complete_fired(&test_fixture);

    /* Confirm that no messages have gone out from the client */
    ASSERT_INT_EQUALS(test_fixture.secure_tunnel_message_sent_count, 0);

    /* Confirm that on_send_message_complete callback was fired */
    ASSERT_INT_EQUALS(test_fixture.on_send_message_complete_result.type, AWS_SECURE_TUNNEL_MT_DATA);
    ASSERT_INT_EQUALS(
        test_fixture.on_send_message_complete_result.error_code,
        AWS_ERROR_IOTDEVICE_SECURE_TUNNELING_INVALID_CONNECTION_ID);

    /* Ensure that the established stream was not affected by the message */
    ASSERT_TRUE(s_secure_tunnel_check_active_stream_id(secure_tunnel, &service_1, 1));

    ASSERT_SUCCESS(aws_secure_tunnel_stop(secure_tunnel));
    s_wait_for_connection_shutdown(&test_fixture);

    aws_secure_tunnel_mock_test_clean_up(&test_fixture);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(
    secure_tunneling_send_v3_data_message_on_incorrect_v3_connection_test,
    s_secure_tunneling_send_v3_data_message_on_incorrect_v3_connection_test_fn)

static int s_secure_tunneling_send_v1_data_message_with_no_active_connection_test_fn(
    struct aws_allocator *allocator,
    void *ctx) {

    (void)ctx;

    struct secure_tunnel_test_options test_options;
    struct aws_secure_tunnel_mock_test_fixture test_fixture;
    aws_secure_tunnel_mock_test_init(allocator, &test_options, &test_fixture, AWS_SECURE_TUNNELING_DESTINATION_MODE);
    struct aws_secure_tunnel *secure_tunnel = test_fixture.secure_tunnel;

    ASSERT_SUCCESS(aws_secure_tunnel_start(secure_tunnel));
    s_wait_for_connected_successfully(&test_fixture);

    /* Create and send a V1 DATA message,
     * this should fail with INVALID CONNECTION ID error */
    struct aws_secure_tunnel_message_view data_message_view = {
        .type = AWS_SECURE_TUNNEL_MT_DATA,
        .stream_id = 0,
        .payload = &s_payload_cursor_max_size,
    };

    int result = aws_secure_tunnel_send_message(secure_tunnel, &data_message_view);
    ASSERT_INT_EQUALS(result, AWS_OP_SUCCESS);

    s_wait_for_on_send_message_complete_fired(&test_fixture);

    /* Confirm that no messages have gone out from the client */
    ASSERT_INT_EQUALS(test_fixture.secure_tunnel_message_sent_count, 0);

    /* Confirm that on_send_message_complete callback was fired */
    ASSERT_INT_EQUALS(test_fixture.on_send_message_complete_result.type, AWS_SECURE_TUNNEL_MT_DATA);
    ASSERT_INT_EQUALS(
        test_fixture.on_send_message_complete_result.error_code,
        AWS_ERROR_IOTDEVICE_SECURE_TUNNELING_DATA_NO_ACTIVE_CONNECTION);

    ASSERT_SUCCESS(aws_secure_tunnel_stop(secure_tunnel));
    s_wait_for_connection_shutdown(&test_fixture);

    aws_secure_tunnel_mock_test_clean_up(&test_fixture);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(
    secure_tunneling_send_v1_data_message_with_no_active_connection_test,
    s_secure_tunneling_send_v1_data_message_with_no_active_connection_test_fn)

static int s_secure_tunneling_send_v3_stream_start_message_test_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    struct secure_tunnel_test_options test_options;
    struct aws_secure_tunnel_mock_test_fixture test_fixture;
    aws_secure_tunnel_mock_test_init(allocator, &test_options, &test_fixture, AWS_SECURE_TUNNELING_SOURCE_MODE);
    struct aws_secure_tunnel *secure_tunnel = test_fixture.secure_tunnel;

    ASSERT_SUCCESS(aws_secure_tunnel_start(secure_tunnel));
    s_wait_for_connected_successfully(&test_fixture);

    /* Create and send a V3 STREAM_START message to the server */
    struct aws_byte_cursor service_1 = aws_byte_cursor_from_string(s_service_id_1);
    struct aws_secure_tunnel_message_view stream_start_message_view = {
        .type = AWS_SECURE_TUNNEL_MT_STREAM_START,
        .service_id = &service_1,
        .stream_id = 0,
        .connection_id = 2,
    };
    aws_secure_tunnel_stream_start(test_fixture.secure_tunnel, &stream_start_message_view);

    /* Wait and confirm that a stream has been started */
    s_wait_for_on_send_message_complete_fired(&test_fixture);

    /* Confirm that the message has been sent */
    ASSERT_INT_EQUALS(test_fixture.secure_tunnel_message_sent_count, 1);

    /* Confirm that on_send_message_complete callback was fired */
    ASSERT_INT_EQUALS(test_fixture.on_send_message_complete_result.type, AWS_SECURE_TUNNEL_MT_STREAM_START);
    ASSERT_INT_EQUALS(test_fixture.on_send_message_complete_result.error_code, AWS_ERROR_SUCCESS);

    /* Ensure that the established connection is active */
    ASSERT_TRUE(s_secure_tunnel_check_active_connection_id(secure_tunnel, &service_1, 1, 2));

    /* Create and send a V3 DATA message */
    struct aws_secure_tunnel_message_view data_message_view = {
        .type = AWS_SECURE_TUNNEL_MT_DATA,
        .stream_id = 0,
        .service_id = &service_1,
        .connection_id = 2,
        .payload = &s_payload_cursor_max_size,
    };

    int result = aws_secure_tunnel_send_message(secure_tunnel, &data_message_view);
    ASSERT_INT_EQUALS(result, AWS_OP_SUCCESS);

    /* Since there is no feedback on successful sending, simply sleep. */
    aws_thread_current_sleep(aws_timestamp_convert(1, AWS_TIMESTAMP_SECS, AWS_TIMESTAMP_NANOS, NULL));

    /* Confirm that the message has been sent */
    ASSERT_INT_EQUALS(test_fixture.secure_tunnel_message_sent_count, 2);

    /* Ensure that the established connection is still active */
    ASSERT_TRUE(s_secure_tunnel_check_active_connection_id(secure_tunnel, &service_1, 1, 2));

    ASSERT_SUCCESS(aws_secure_tunnel_stop(secure_tunnel));
    s_wait_for_connection_shutdown(&test_fixture);

    aws_secure_tunnel_mock_test_clean_up(&test_fixture);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(
    secure_tunneling_send_v3_stream_start_message_test,
    s_secure_tunneling_send_v3_stream_start_message_test_fn)

static int s_secure_tunneling_send_v3_stream_start_message_with_reset_test_fn(
    struct aws_allocator *allocator,
    void *ctx) {
    (void)ctx;

    struct secure_tunnel_test_options test_options;
    struct aws_secure_tunnel_mock_test_fixture test_fixture;
    aws_secure_tunnel_mock_test_init(allocator, &test_options, &test_fixture, AWS_SECURE_TUNNELING_SOURCE_MODE);
    struct aws_secure_tunnel *secure_tunnel = test_fixture.secure_tunnel;

    ASSERT_SUCCESS(aws_secure_tunnel_start(secure_tunnel));
    s_wait_for_connected_successfully(&test_fixture);

    /* Create and send a V2 STREAM_START message to the server */
    struct aws_byte_cursor service_1 = aws_byte_cursor_from_string(s_service_id_1);
    struct aws_secure_tunnel_message_view stream_start_v2_message_view = {
        .type = AWS_SECURE_TUNNEL_MT_STREAM_START,
        .service_id = &service_1,
        .stream_id = 0,
    };
    ASSERT_INT_EQUALS(
        aws_secure_tunnel_stream_start(test_fixture.secure_tunnel, &stream_start_v2_message_view), AWS_OP_SUCCESS);

    /* Wait and confirm that a stream has been started */
    s_wait_for_on_send_message_complete_fired(&test_fixture);

    /* Confirm that the message has been sent */
    ASSERT_INT_EQUALS(test_fixture.secure_tunnel_message_sent_count, 1);

    /* Confirm that on_send_message_complete callback was fired */
    ASSERT_INT_EQUALS(test_fixture.on_send_message_complete_result.type, AWS_SECURE_TUNNEL_MT_STREAM_START);
    ASSERT_INT_EQUALS(test_fixture.on_send_message_complete_result.error_code, AWS_ERROR_SUCCESS);

    /* Ensure that the established stream is active */
    ASSERT_TRUE(s_secure_tunnel_check_active_stream_id(secure_tunnel, &service_1, 1));

    /* Create and send a V3 STREAM_START message to the server */
    struct aws_byte_cursor service_2 = aws_byte_cursor_from_string(s_service_id_2);
    struct aws_secure_tunnel_message_view stream_start_v3_message_view = {
        .type = AWS_SECURE_TUNNEL_MT_STREAM_START,
        .service_id = &service_2,
        .stream_id = 0,
        .connection_id = 2,
    };
    ASSERT_INT_EQUALS(
        aws_secure_tunnel_stream_start(test_fixture.secure_tunnel, &stream_start_v3_message_view), AWS_OP_SUCCESS);

    /* Wait and confirm that a stream has been started */
    s_wait_for_on_send_message_complete_fired(&test_fixture);

    /* Confirm that the message has been sent */
    ASSERT_INT_EQUALS(test_fixture.secure_tunnel_message_sent_count, 1);

    /* Confirm that on_send_message_complete callback was fired */
    ASSERT_INT_EQUALS(test_fixture.on_send_message_complete_result.type, AWS_SECURE_TUNNEL_MT_STREAM_START);
    ASSERT_INT_EQUALS(
        test_fixture.on_send_message_complete_result.error_code,
        AWS_ERROR_IOTDEVICE_SECURE_TUNNELING_PROTOCOL_VERSION_MISMATCH);

    /* Ensure that the old stream is still active */
    ASSERT_TRUE(s_secure_tunnel_check_active_stream_id(secure_tunnel, &service_1, 1));

    ASSERT_SUCCESS(aws_secure_tunnel_stop(secure_tunnel));
    s_wait_for_connection_shutdown(&test_fixture);

    aws_secure_tunnel_mock_test_clean_up(&test_fixture);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(
    secure_tunneling_send_v3_stream_start_message_with_reset_test,
    s_secure_tunneling_send_v3_stream_start_message_with_reset_test_fn)

static int s_secure_tunneling_send_v3_connection_start_message_test_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    struct secure_tunnel_test_options test_options;
    struct aws_secure_tunnel_mock_test_fixture test_fixture;
    aws_secure_tunnel_mock_test_init(allocator, &test_options, &test_fixture, AWS_SECURE_TUNNELING_SOURCE_MODE);
    struct aws_secure_tunnel *secure_tunnel = test_fixture.secure_tunnel;

    ASSERT_SUCCESS(aws_secure_tunnel_start(secure_tunnel));
    s_wait_for_connected_successfully(&test_fixture);

    /* Create and send a V3 StreamStart message to the server */
    struct aws_byte_cursor service_1 = aws_byte_cursor_from_string(s_service_id_1);
    struct aws_secure_tunnel_message_view stream_start_message_view = {
        .type = AWS_SECURE_TUNNEL_MT_STREAM_START,
        .service_id = &service_1,
        .stream_id = 0,
        .connection_id = 2,
    };
    aws_secure_tunnel_stream_start(test_fixture.secure_tunnel, &stream_start_message_view);

    /* Wait and confirm that a stream has been started */
    s_wait_for_on_send_message_complete_fired(&test_fixture);

    /* Confirm that the message has been sent */
    ASSERT_INT_EQUALS(test_fixture.secure_tunnel_message_sent_count, 1);

    /* Confirm that on_send_message_complete callback was fired */
    ASSERT_INT_EQUALS(test_fixture.on_send_message_complete_result.type, AWS_SECURE_TUNNEL_MT_STREAM_START);
    ASSERT_INT_EQUALS(test_fixture.on_send_message_complete_result.error_code, AWS_ERROR_SUCCESS);

    ASSERT_TRUE(s_secure_tunnel_check_active_connection_id(secure_tunnel, &service_1, 1, 2));

    /* Create and send a V3 CONNECTION_START message to the server */
    struct aws_secure_tunnel_message_view connection_start_message_view = {
        .type = AWS_SECURE_TUNNEL_MT_CONNECTION_START,
        .service_id = &service_1,
        .stream_id = 0,
        .connection_id = 3,
    };
    aws_secure_tunnel_connection_start(test_fixture.secure_tunnel, &connection_start_message_view);

    /* Wait and confirm that a stream has been started */
    s_wait_for_on_send_message_complete_fired(&test_fixture);

    /* Confirm that the message has been sent */
    ASSERT_INT_EQUALS(test_fixture.secure_tunnel_message_sent_count, 2);

    /* Confirm that on_send_message_complete callback was fired */
    ASSERT_INT_EQUALS(test_fixture.on_send_message_complete_result.type, AWS_SECURE_TUNNEL_MT_CONNECTION_START);
    ASSERT_INT_EQUALS(test_fixture.on_send_message_complete_result.error_code, AWS_ERROR_SUCCESS);

    /* Confirm that the both connections are active */
    ASSERT_TRUE(s_secure_tunnel_check_active_connection_id(secure_tunnel, &service_1, 1, 2));
    ASSERT_TRUE(s_secure_tunnel_check_active_connection_id(secure_tunnel, &service_1, 1, 3));

    /* Create and send a V3 DATA message to the first connection */
    struct aws_secure_tunnel_message_view data_message_view = {
        .type = AWS_SECURE_TUNNEL_MT_DATA,
        .stream_id = 0,
        .service_id = &service_1,
        .connection_id = 2,
        .payload = &s_payload_cursor_max_size,
    };

    int result = aws_secure_tunnel_send_message(secure_tunnel, &data_message_view);
    ASSERT_INT_EQUALS(result, AWS_OP_SUCCESS);

    /* Send a V3 DATA message to the second connection */
    data_message_view.connection_id = 3;
    result = aws_secure_tunnel_send_message(secure_tunnel, &data_message_view);
    ASSERT_INT_EQUALS(result, AWS_OP_SUCCESS);

    /* Since there is no feedback on successful sending, simply sleep. */
    aws_thread_current_sleep(aws_timestamp_convert(1, AWS_TIMESTAMP_SECS, AWS_TIMESTAMP_NANOS, NULL));

    /* Confirm that the messages have been sent */
    ASSERT_INT_EQUALS(test_fixture.secure_tunnel_message_sent_count, 4);

    /* Ensure that the established connections are still active */
    ASSERT_TRUE(s_secure_tunnel_check_active_connection_id(secure_tunnel, &service_1, 1, 2));
    ASSERT_TRUE(s_secure_tunnel_check_active_connection_id(secure_tunnel, &service_1, 1, 3));

    ASSERT_SUCCESS(aws_secure_tunnel_stop(secure_tunnel));
    s_wait_for_connection_shutdown(&test_fixture);

    aws_secure_tunnel_mock_test_clean_up(&test_fixture);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(
    secure_tunneling_send_v3_connection_start_message_test,
    s_secure_tunneling_send_v3_connection_start_message_test_fn)
