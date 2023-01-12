/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/common/ref_count.h>
#include <aws/common/string.h>
#include <aws/iotdevice/private/secure_tunneling_impl.h>
#include <aws/iotdevice/private/secure_tunneling_operations.h>
#include <aws/iotdevice/secure_tunneling.h>
#include <inttypes.h>

#define MAX_PAYLOAD_SIZE 64512
/*********************************************************************************************************************
 * Operation base
 ********************************************************************************************************************/

struct aws_secure_tunnel_operation *aws_secure_tunnel_operation_acquire(struct aws_secure_tunnel_operation *operation) {
    if (operation == NULL) {
        return NULL;
    }

    aws_ref_count_acquire(&operation->ref_count);

    return operation;
}

struct aws_secure_tunnel_operation *aws_secure_tunnel_operation_release(struct aws_secure_tunnel_operation *operation) {
    if (operation != NULL) {
        aws_ref_count_release(&operation->ref_count);
    }

    return NULL;
}

void *aws_secure_tunnel_operation_complete(
    struct aws_secure_tunnel_operation *operation,
    int error_code,
    const void *associated_view) {
    AWS_FATAL_ASSERT(operation->vtable != NULL);

    if (operation->vtable->aws_secure_tunnel_operation_completion_fn != NULL) {
        (*operation->vtable->aws_secure_tunnel_operation_completion_fn)(operation, error_code, associated_view);
    }
}

void aws_secure_tunnel_operation_set_stream_id(
    struct aws_secure_tunnel_operation *operation,
    struct aws_secure_tunnel *secure_tunnel) {
    AWS_FATAL_ASSERT(operation->vtable != NULL);
    if (operation->vtable->aws_secure_tunnel_operation_set_stream_id_fn != NULL) {
        (*operation->vtable->aws_secure_tunnel_operation_set_stream_id_fn)(operation, secure_tunnel);
    }
}

int32_t aws_secure_tunnel_operation_get_stream_id(const struct aws_secure_tunnel_operation *operation) {
    AWS_FATAL_ASSERT(operation->vtable != NULL);
    if (operation->vtable->aws_secure_tunnel_operation_get_stream_id_address_fn != NULL) {
        int32_t *stream_id_ptr = (*operation->vtable->aws_secure_tunnel_operation_get_stream_id_address_fn)(operation);
        if (stream_id_ptr != NULL) {
            return *stream_id_ptr;
        }
    }

    return 0;
}

int32_t *aws_secure_tunnel_operation_get_stream_id_address(const struct aws_secure_tunnel_operation *operation) {
    AWS_FATAL_ASSERT(operation->vtable != NULL);
    if (operation->vtable->aws_secure_tunnel_operation_get_stream_id_address_fn != NULL) {
        return (*operation->vtable->aws_secure_tunnel_operation_get_stream_id_address_fn)(operation);
    }

    return NULL;
}

static struct aws_secure_tunnel_operation_vtable s_empty_operation_vtable = {
    .aws_secure_tunnel_operation_completion_fn = NULL,
    .aws_secure_tunnel_operation_set_stream_id_fn = NULL,
    .aws_secure_tunnel_operation_get_stream_id_address_fn = NULL,
};

/*********************************************************************************************************************
 * Connect
 ********************************************************************************************************************/
/* STEVE TODO Connect Operation Implementation */

/*********************************************************************************************************************
 * Message
 ********************************************************************************************************************/

int aws_secure_tunnel_message_view_validate(const struct aws_secure_tunnel_message_view *message_view) {
    if (message_view == NULL) {
        AWS_LOGF_ERROR(AWS_LS_IOTDEVICE_SECURE_TUNNELING, "null message options");
        return aws_raise_error(AWS_ERROR_IOTDEVICE_SECURE_TUNNELING_DATA_OPTIONS_VALIDATION);
    }

    if (message_view->stream_id != 0) {
        AWS_LOGF_ERROR(
            AWS_LS_IOTDEVICE_SECURE_TUNNELING,
            "id=%p: aws_secure_tunnel_message_view - stream id must be 0",
            (void *)message_view);
        return aws_raise_error(AWS_ERROR_IOTDEVICE_SECURE_TUNNELING_DATA_OPTIONS_VALIDATION);
    }

    if (message_view->payload.len > MAX_PAYLOAD_SIZE) {
        AWS_LOGF_ERROR(
            AWS_LS_IOTDEVICE_SECURE_TUNNELING,
            "id=%p: aws_secure_tunnel_message_view - payload too long",
            (void *)message_view);
        return aws_raise_error(AWS_ERROR_IOTDEVICE_SECURE_TUNNELING_DATA_OPTIONS_VALIDATION);
    }

    return AWS_OP_SUCCESS;
}

void aws_secure_tunnel_message_view_log(
    const struct aws_secure_tunnel_message_view *message_view,
    enum aws_log_level level) {
    struct aws_logger *log_handle = aws_logger_get_conditional(AWS_LS_IOTDEVICE_SECURE_TUNNELING, level);
    if (log_handle == NULL) {
        return;
    }

    AWS_LOGUF(
        log_handle,
        level,
        AWS_LS_IOTDEVICE_SECURE_TUNNELING,
        "id=%p: aws_secure_tunnel_message_view stream_id set to %d",
        (void *)message_view,
        (int)message_view->stream_id);

    if (message_view->service_id.len > 0) {
        AWS_LOGUF(
            log_handle,
            level,
            AWS_LS_IOTDEVICE_SECURE_TUNNELING,
            "id=%p: aws_secure_tunnel_message_view service_id set to" PRInSTR,
            (void *)message_view,
            AWS_BYTE_CURSOR_PRI(message_view->service_id));
    } else {
        AWS_LOGUF(
            log_handle,
            level,
            AWS_LS_IOTDEVICE_SECURE_TUNNELING,
            "id=%p: aws_secure_tunnel_message_view service_id not set",
            (void *)message_view);
    }

    AWS_LOGUF(
        log_handle,
        level,
        AWS_LS_IOTDEVICE_SECURE_TUNNELING,
        "id=%p: aws_secure_tunnel_message_view payload set containing %zu bytes",
        (void *)message_view,
        (int)message_view->payload.len);
}

static size_t s_aws_secure_tunnel_message_compute_storage_size(
    const struct aws_secure_tunnel_message_view *message_view) {
    size_t storage_size = message_view->payload.len;
    storage_size += message_view->service_id.len;

    return storage_size;
}

int aws_secure_tunnel_message_storage_init(
    struct aws_secure_tunnel_message_storage *message_storage,
    struct aws_allocator *allocator,
    const struct aws_secure_tunnel_message_view *message_options) {

    AWS_ZERO_STRUCT(*message_storage);
    size_t storage_capacity = s_aws_secure_tunnel_message_compute_storage_size(message_options);
    if (aws_byte_buf_init(&message_storage->storage, allocator, storage_capacity)) {
        return AWS_OP_ERR;
    }

    struct aws_secure_tunnel_message_view *storage_view = &message_storage->storage_view;

    storage_view->type = message_options->type;
    storage_view->ignorable = message_options->ignorable;
    storage_view->stream_id = message_options->stream_id;

    storage_view->service_id = message_options->service_id;
    if (aws_byte_buf_append_and_update(&message_storage->storage, &storage_view->service_id)) {
        return AWS_OP_ERR;
    }

    storage_view->payload = message_options->payload;
    if (aws_byte_buf_append_and_update(&message_storage->storage, &storage_view->payload)) {
        return AWS_OP_ERR;
    }

    return AWS_OP_SUCCESS;
}

void aws_secure_tunnel_message_storage_clean_up(struct aws_secure_tunnel_message_storage *message_storage) {
    aws_byte_buf_clean_up(&message_storage->storage);
}

static void s_aws_secure_tunnel_operation_message_set_stream_id(
    struct aws_secure_tunnel_operation *operation,
    struct aws_secure_tunnel *secure_tunnel) {

    struct aws_secure_tunnel_operation_message *message_op = operation->impl;
    int32_t stream_id = 0;

    struct aws_secure_tunnel_message_storage *message_storage = &message_op->options_storage;

    if (message_storage->service_id.len > 0) {
        struct aws_string *service_id = NULL;
        service_id = aws_string_new_from_cursor(secure_tunnel->allocator, &message_storage->service_id);

        if (secure_tunnel->config->service_id_1 != NULL &&
            aws_string_compare(secure_tunnel->config->service_id_1, service_id) == 0) {
            stream_id = secure_tunnel->config->service_id_1_stream_id;
        } else if (
            secure_tunnel->config->service_id_2 != NULL &&
            aws_string_compare(secure_tunnel->config->service_id_2, service_id) == 0) {
            stream_id = secure_tunnel->config->service_id_2_stream_id;
        } else if (
            secure_tunnel->config->service_id_3 != NULL &&
            aws_string_compare(secure_tunnel->config->service_id_3, service_id) == 0) {
            stream_id = secure_tunnel->config->service_id_3_stream_id;
        } else {
            /* service_id doesn't match any existing service id*/
            AWS_LOGF_ERROR(
                AWS_LS_IOTDEVICE_SECURE_TUNNELING,
                "id=%p: aws_message_storage - invalid service_id:%s",
                (void *)message_storage,
                aws_string_c_str(service_id));
            /* STEVE TODO should we throw something or just log the error here? */
        }
        aws_string_destroy(service_id);
    } else {
        stream_id = secure_tunnel->config->stream_id;
    }

    message_op->options_storage.storage_view.stream_id = stream_id;
}

static int32_t *s_aws_secure_tunnel_operation_message_get_stream_id_address_fn(
    const struct aws_secure_tunnel_operation *operation) {
    struct aws_secure_tunnel_operation_message *message_op = operation->impl;
    return &message_op->options_storage.storage_view.stream_id;
}

static struct aws_secure_tunnel_operation_vtable s_message_operation_vtable = {
    .aws_secure_tunnel_operation_set_stream_id_fn = s_aws_secure_tunnel_operation_message_set_stream_id,
    .aws_secure_tunnel_operation_get_stream_id_address_fn =
        s_aws_secure_tunnel_operation_message_get_stream_id_address_fn,
};

static void s_destroy_operation_message(void *object) {
    if (object == NULL) {
        return;
    }

    struct aws_secure_tunnel_operation_message *message_op = object;

    aws_secure_tunnel_message_storage_clean_up(&message_op->options_storage);

    aws_mem_release(message_op->allocator, message_op);
}

struct aws_secure_tunnel_operation_message *aws_secure_tunnel_operation_message_new(
    struct aws_allocator *allocator,
    const struct aws_secure_tunnel *secure_tunnel,
    const struct aws_secure_tunnel_message_view *message_options) {
    (void)secure_tunnel;
    AWS_PRECONDITION(allocator != NULL);
    AWS_PRECONDITION(message_options != NULL);

    if (aws_secure_tunnel_message_message_view_validate(message_options)) {
        return NULL;
    }

    struct aws_secure_tunnel_operation_message *message_op =
        aws_mem_calloc(allocator, 1, sizeof(struct aws_secure_tunnel_operation_message));
    if (message_op == NULL) {
        return NULL;
    }

    message_op->allocator = allocator;
    message_op->base.vtable = &s_message_operation_vtable;
    aws_ref_count_init(&message_op->base.ref_count, message_op, s_destroy_operation_message);
    message_op->base.impl = message_op;

    if (aws_secure_tunnel_message_message_storage_init(&message_op->options_storage, allocator, message_options)) {
        goto error;
    }

    message_op->base.message_view = &message_op->options_storage.storage_view;

    return message_op;

error:

    aws_secure_tunnel_operation_release(&message_op->base);

    return NULL;
}

/*********************************************************************************************************************
 * Secure Tunnel Storage Options
 ********************************************************************************************************************/

/*
 * Validation of options on creation of a new secure tunnel
 */
int aws_secure_tunnel_options_validate(const struct aws_secure_tunnel_options *options) {
    AWS_ASSERT(options && options->allocator);
    if (options->bootstrap == NULL) {
        AWS_LOGF_ERROR(AWS_LS_IOTDEVICE_SECURE_TUNNELING, "bootstrap cannot be NULL");
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }
    if (options->socket_options == NULL) {
        AWS_LOGF_ERROR(AWS_LS_IOTDEVICE_SECURE_TUNNELING, "socket options cannot be NULL");
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }
    if (options->access_token.len == 0) {
        AWS_LOGF_ERROR(AWS_LS_IOTDEVICE_SECURE_TUNNELING, "access token is required");
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }
    if (options->endpoint_host.len == 0) {
        AWS_LOGF_ERROR(AWS_LS_IOTDEVICE_SECURE_TUNNELING, "endpoint host is required");
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }

    return AWS_OP_SUCCESS;
}

void aws_secure_tunnel_options_storage_log(
    const struct aws_secure_tunnel_options_storage *options_storage,
    enum aws_log_level level) {
    struct aws_logger *log_handle = aws_logger_get_conditional(AWS_LS_IOTDEVICE_SECURE_TUNNELING, level);
    if (log_handle == NULL) {
        return;
    }

    AWS_LOGUF(
        log_handle,
        level,
        AWS_LS_IOTDEVICE_SECURE_TUNNELING,
        "id=%p: aws_secure_tunnel_options_storage host name set to %s",
        (void *)options_storage,
        aws_string_c_str(options_storage->endpoint_host));

    AWS_LOGUF(
        log_handle,
        level,
        AWS_LS_IOTDEVICE_SECURE_TUNNELING,
        "id=%p: aws_secure_tunnel_options_storage bootstrap set to (%p)",
        (void *)options_storage,
        (void *)options_storage->bootstrap);

    AWS_LOGUF(
        log_handle,
        level,
        AWS_LS_IOTDEVICE_SECURE_TUNNELING,
        "id=%p: aws_secure_tunnel_options_storage socket options set to: type = %d, domain = %d, connect_timeout_ms = "
        "%" PRIu32,
        (void *)options_storage,
        (int)options_storage->socket_options.type,
        (int)options_storage->socket_options.domain,
        options_storage->socket_options.connect_timeout_ms);

    if (options_storage->socket_options.keepalive) {
        AWS_LOGUF(
            log_handle,
            level,
            AWS_LS_IOTDEVICE_SECURE_TUNNELING,
            "id=%p: aws_secure_tunnel_options_storage socket keepalive options set to: keep_alive_interval_sec = "
            "%" PRIu16 ", "
            "keep_alive_timeout_sec = %" PRIu16 ", keep_alive_max_failed_probes = %" PRIu16,
            (void *)options_storage,
            options_storage->socket_options.keep_alive_interval_sec,
            options_storage->socket_options.keep_alive_timeout_sec,
            options_storage->socket_options.keep_alive_max_failed_probes);
    }

    if (options_storage->http_proxy_config != NULL) {
        AWS_LOGUF(
            log_handle,
            level,
            AWS_LS_IOTDEVICE_SECURE_TUNNELING,
            "id=%p: aws_secure_tunnel_options_storage using http proxy:",
            (void *)options_storage);

        AWS_LOGUF(
            log_handle,
            level,
            AWS_LS_IOTDEVICE_SECURE_TUNNELING,
            "id=%p: aws_secure_tunnel_options_storage http proxy host name set to " PRInSTR,
            (void *)options_storage,
            AWS_BYTE_CURSOR_PRI(options_storage->http_proxy_options.host));

        AWS_LOGUF(
            log_handle,
            level,
            AWS_LS_IOTDEVICE_SECURE_TUNNELING,
            "id=%p: aws_secure_tunnel_options_storage http proxy port set to %" PRIu16,
            (void *)options_storage,
            options_storage->http_proxy_options.port);

        if (options_storage->http_proxy_options.proxy_strategy != NULL) {
            AWS_LOGUF(
                log_handle,
                level,
                AWS_LS_IOTDEVICE_SECURE_TUNNELING,
                "id=%p: aws_secure_tunnel_options_storage http proxy strategy set to (%p)",
                (void *)options_storage,
                (void *)options_storage->http_proxy_options.proxy_strategy);
        }
    }

    if (options_storage->websocket_handshake_transform != NULL) {
        AWS_LOGUF(
            log_handle,
            level,
            AWS_LS_IOTDEVICE_SECURE_TUNNELING,
            "id=%p: aws_secure_tunnel_options_storage enabling websockets",
            (void *)options_storage);

        AWS_LOGUF(
            log_handle,
            level,
            AWS_LS_IOTDEVICE_SECURE_TUNNELING,
            "id=%p: aws_secure_tunnel_options_storage websocket handshake transform user data set to (%p)",
            (void *)options_storage,
            options_storage->websocket_handshake_transform_user_data);
    } else {
        AWS_LOGUF(
            log_handle,
            level,
            AWS_LS_IOTDEVICE_SECURE_TUNNELING,
            "id=%p: aws_secure_tunnel_options_storage disabling websockets",
            (void *)options_storage);
    }

    bool is_service_id_used = false;

    if (options_storage->service_id_1 != NULL) {
        is_service_id_used = true;
        AWS_LOGUF(
            log_handle,
            level,
            AWS_LS_IOTDEVICE_SECURE_TUNNELING,
            "id=%p: aws_secure_tunnel_options_storage service id 1:%s",
            (void *)options_storage,
            aws_string_c_str(options_storage->service_id_1));
    }

    if (options_storage->service_id_2 != NULL) {
        is_service_id_used = true;
        AWS_LOGUF(
            log_handle,
            level,
            AWS_LS_IOTDEVICE_SECURE_TUNNELING,
            "id=%p: aws_secure_tunnel_options_storage service id 2:%s",
            (void *)options_storage,
            aws_string_c_str(options_storage->service_id_2));
    }

    if (options_storage->service_id_3 != NULL) {
        is_service_id_used = true;
        AWS_LOGUF(
            log_handle,
            level,
            AWS_LS_IOTDEVICE_SECURE_TUNNELING,
            "id=%p: aws_secure_tunnel_options_storage service id 3:%s",
            (void *)options_storage,
            aws_string_c_str(options_storage->service_id_3));
    }

    if (!is_service_id_used) {
        AWS_LOGUF(
            log_handle,
            level,
            AWS_LS_IOTDEVICE_SECURE_TUNNELING,
            "id=%p: aws_secure_tunnel_options_storage no service id set",
            (void *)options_storage);
    }
}

/*
 * Clean up stored secure tunnel config
 */
void aws_secure_tunnel_options_storage_destroy(struct aws_secure_tunnel_options_storage *storage) {
    if (storage == NULL) {
        return;
    }

    aws_client_bootstrap_release(storage->bootstrap);
    aws_http_proxy_config_destroy(storage->http_proxy_config);
    aws_string_destroy(storage->endpoint_host);
    aws_string_destroy(storage->access_token);
    aws_string_destroy(storage->service_id_1);
    aws_string_destroy(storage->service_id_2);
    aws_string_destroy(storage->service_id_3);
    aws_mem_release(storage->allocator, storage);
}

/*
 * Copy and store secure tunnel options
 */
struct aws_secure_tunnel_options_storage *aws_secure_tunnel_options_storage_new(
    const struct aws_secure_tunnel_options *options) {
    AWS_PRECONDITION(options != NULL);
    AWS_PRECONDITION(options->allocator != NULL);

    if (aws_secure_tunnel_options_validate(options)) {
        return NULL;
    }

    struct aws_allocator *allocator = options->allocator;

    struct aws_secure_tunnel_options_storage *storage =
        aws_mem_calloc(allocator, 1, sizeof(struct aws_secure_tunnel_options_storage));

    storage->allocator = options->allocator;
    storage->socket_options = *options->socket_options;
    storage->endpoint_host = aws_string_new_from_cursor(allocator, &options->endpoint_host);
    if (storage->endpoint_host == NULL) {
        goto error;
    }

    storage->access_token = aws_string_new_from_cursor(allocator, &options->access_token);
    if (storage->access_token == NULL) {
        goto error;
    }

    /* STEVE TODO can be removed except for testing */
    storage->local_proxy_mode = options->local_proxy_mode;

    /* acquire reference to everything that's ref-counted */
    storage->bootstrap = aws_client_bootstrap_acquire(options->bootstrap);

    if (options->http_proxy_options != NULL) {
        storage->http_proxy_config =
            aws_http_proxy_config_new_from_proxy_options(allocator, options->http_proxy_options);
        if (storage->http_proxy_config == NULL) {
            goto error;
        }

        aws_http_proxy_options_init_from_config(&storage->http_proxy_options, storage->http_proxy_config);
    }

    if (options->service_id_1 != NULL) {
        storage->service_id_1 = aws_string_new_from_c_str(allocator, options->service_id_1);
    }

    if (options->service_id_2 != NULL) {
        storage->service_id_2 = aws_string_new_from_c_str(allocator, options->service_id_2);
    }

    if (options->service_id_3 != NULL) {
        storage->service_id_3 = aws_string_new_from_c_str(allocator, options->service_id_3);
    }

    storage->on_message_received = options->on_message_received;
    storage->user_data = options->user_data;

    /* STEVE TODO these can probably be deprecated/removed as client only supports destination mode */
    storage->local_proxy_mode = options->local_proxy_mode;
    storage->on_connection_complete = options->on_connection_complete;
    storage->on_connection_shutdown = options->on_connection_shutdown;
    storage->on_send_data_complete = options->on_send_data_complete;
    storage->on_data_receive = options->on_data_receive;
    storage->on_stream_start = options->on_stream_start;
    storage->on_stream_reset = options->on_stream_reset;
    storage->on_session_reset = options->on_session_reset;
    storage->on_termination_complete = options->on_termination_complete;

    return storage;

error:
    aws_secure_tunnel_options_storage_destroy(storage);
    return NULL;
}

const char *aws_secure_tunnel_operation_type_to_c_string(enum aws_secure_tunnel_operation_type operation_type) {
    switch (operation_type) {
        case AWS_STOT_NONE:
            return "NONE";
        case AWS_STOT_CONNECT:
            return "CONNECT";
        case AWS_STOT_PING:
            return "PING";
        case AWS_STOT_DATA:
            return "DATA";
        case AWS_STOT_STREAM_RESET:
            return "STREAM RESET";
        case AWS_STOT_STREAM_START:
            return "STREAM START";
        default:
            return "UNKNOWN";
    }
}
