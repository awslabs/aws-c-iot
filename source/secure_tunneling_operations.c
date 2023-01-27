/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/common/logging.h>
#include <aws/common/ref_count.h>
#include <aws/common/string.h>
#include <aws/common/uuid.h>
#include <aws/io/channel_bootstrap.h>
#include <aws/iotdevice/private/secure_tunneling_impl.h>
#include <aws/iotdevice/private/secure_tunneling_operations.h>
#include <aws/iotdevice/secure_tunneling.h>
#include <inttypes.h>

#define MAX_PAYLOAD_SIZE 64512
#define INVALID_STREAM_ID 0
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

void aws_secure_tunnel_operation_complete(
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

static struct aws_secure_tunnel_operation_vtable s_empty_operation_vtable = {
    .aws_secure_tunnel_operation_completion_fn = NULL,
    .aws_secure_tunnel_operation_set_stream_id_fn = NULL,
    .aws_secure_tunnel_operation_set_next_stream_id_fn = NULL,
};

/*********************************************************************************************************************
 * Message
 ********************************************************************************************************************/

int aws_secure_tunnel_message_view_validate(const struct aws_secure_tunnel_message_view *message_view) {
    if (message_view == NULL) {
        AWS_LOGF_ERROR(AWS_LS_IOTDEVICE_SECURE_TUNNELING, "null message options");
        return aws_raise_error(AWS_ERROR_IOTDEVICE_SECURE_TUNNELING_DATA_OPTIONS_VALIDATION);
    }

    if (message_view->type == AWS_SECURE_TUNNEL_MT_DATA && message_view->stream_id != 0) {
        AWS_LOGF_ERROR(
            AWS_LS_IOTDEVICE_SECURE_TUNNELING,
            "id=%p: aws_secure_tunnel_message_view stream id for DATA MESSAGES must be 0",
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
        message_view->payload.len);
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
    const struct aws_secure_tunnel_message_view *message_options,
    enum aws_secure_tunnel_operation_type type) {

    AWS_ZERO_STRUCT(*message_storage);
    size_t storage_capacity = s_aws_secure_tunnel_message_compute_storage_size(message_options);
    if (aws_byte_buf_init(&message_storage->storage, allocator, storage_capacity)) {
        return AWS_OP_ERR;
    }

    struct aws_secure_tunnel_message_view *storage_view = &message_storage->storage_view;

    storage_view->type = message_options->type;
    storage_view->ignorable = message_options->ignorable;
    storage_view->stream_id = message_options->stream_id;

    switch (type) {
        case AWS_STOT_DATA:
            storage_view->type = AWS_SECURE_TUNNEL_MT_DATA;
            break;
        case AWS_STOT_STREAM_START:
            storage_view->type = AWS_SECURE_TUNNEL_MT_STREAM_START;
            break;
        case AWS_STOT_STREAM_RESET:
            storage_view->type = AWS_SECURE_TUNNEL_MT_STREAM_RESET;
            break;
        default:
            storage_view->type = AWS_SECURE_TUNNEL_MT_UNKNOWN;
            break;
    }

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

/* Sets the stream id on outbound message based on the service id (or lack of for V1) to the current one being used. */
static int s_aws_secure_tunnel_operation_message_set_stream_id(
    struct aws_secure_tunnel_operation *operation,
    struct aws_secure_tunnel *secure_tunnel) {

    struct aws_secure_tunnel_operation_message *message_op = operation->impl;
    int32_t stream_id = INVALID_STREAM_ID;

    struct aws_secure_tunnel_message_view *message_view = &message_op->options_storage.storage_view;

    if (message_view->service_id.len > 0) {
        struct aws_string *service_id = NULL;
        service_id = aws_string_new_from_cursor(secure_tunnel->allocator, &message_view->service_id);

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
            AWS_LOGF_DEBUG(
                AWS_LS_IOTDEVICE_SECURE_TUNNELING,
                "id=%p: invalid service_id:%s attempted to be used with an outbound message",
                (void *)message_view,
                aws_string_c_str(service_id));
            stream_id = INVALID_STREAM_ID;
        }
        aws_string_destroy(service_id);
    } else {
        stream_id = secure_tunnel->config->stream_id;
    }

    if (stream_id == INVALID_STREAM_ID) {
        return aws_raise_error(AWS_ERROR_IOTDEVICE_SECURE_TUNNELING_INVALID_STREAM);
    }

    message_op->options_storage.storage_view.stream_id = stream_id;
    return AWS_OP_SUCCESS;
}

/*
 * Check the outbound stream start service id (or lack of one for V1) and set the secure tunnel and stream start
 * message's stream id to the next value.
 */
static int s_aws_secure_tunnel_operation_message_set_next_stream_id(
    struct aws_secure_tunnel_operation *operation,
    struct aws_secure_tunnel *secure_tunnel) {

    struct aws_secure_tunnel_operation_message *message_op = operation->impl;
    int32_t stream_id = INVALID_STREAM_ID;

    struct aws_secure_tunnel_message_view *message_view = &message_op->options_storage.storage_view;

    if (message_view->service_id.len > 0) {
        struct aws_string *service_id = NULL;
        service_id = aws_string_new_from_cursor(secure_tunnel->allocator, &message_view->service_id);

        if (secure_tunnel->config->service_id_1 != NULL &&
            aws_string_compare(secure_tunnel->config->service_id_1, service_id) == 0) {
            stream_id = secure_tunnel->config->service_id_1_stream_id + 1;
            secure_tunnel->config->service_id_1_stream_id = stream_id;
        } else if (
            secure_tunnel->config->service_id_2 != NULL &&
            aws_string_compare(secure_tunnel->config->service_id_2, service_id) == 0) {
            stream_id = secure_tunnel->config->service_id_2_stream_id + 1;
            secure_tunnel->config->service_id_2_stream_id = stream_id;
        } else if (
            secure_tunnel->config->service_id_3 != NULL &&
            aws_string_compare(secure_tunnel->config->service_id_3, service_id) == 0) {
            stream_id = secure_tunnel->config->service_id_3_stream_id + 1;
            secure_tunnel->config->service_id_3_stream_id = stream_id;
        } else {
            /* service_id doesn't match any existing service id*/
            AWS_LOGF_DEBUG(
                AWS_LS_IOTDEVICE_SECURE_TUNNELING,
                "id=%p: invalid service_id:%s attempted to be used with an outbound message",
                (void *)message_view,
                aws_string_c_str(service_id));
            stream_id = INVALID_STREAM_ID;
        }
        aws_string_destroy(service_id);
    } else {
        stream_id = secure_tunnel->config->stream_id + 1;
        secure_tunnel->config->stream_id = stream_id;
    }

    if (stream_id == INVALID_STREAM_ID) {
        return aws_raise_error(AWS_ERROR_IOTDEVICE_SECURE_TUNNELING_INVALID_STREAM);
    }

    message_op->options_storage.storage_view.stream_id = stream_id;
    return AWS_OP_SUCCESS;
}

static struct aws_secure_tunnel_operation_vtable s_message_operation_vtable = {
    .aws_secure_tunnel_operation_set_stream_id_fn = s_aws_secure_tunnel_operation_message_set_stream_id,
    .aws_secure_tunnel_operation_set_next_stream_id_fn = s_aws_secure_tunnel_operation_message_set_next_stream_id,
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
    const struct aws_secure_tunnel_message_view *message_options,
    enum aws_secure_tunnel_operation_type type) {
    (void)secure_tunnel;
    AWS_PRECONDITION(allocator != NULL);
    AWS_PRECONDITION(message_options != NULL);

    if (aws_secure_tunnel_message_view_validate(message_options)) {
        return NULL;
    }

    struct aws_secure_tunnel_operation_message *message_op =
        aws_mem_calloc(allocator, 1, sizeof(struct aws_secure_tunnel_operation_message));
    if (message_op == NULL) {
        return NULL;
    }

    message_op->allocator = allocator;
    message_op->base.vtable = &s_message_operation_vtable;
    message_op->base.operation_type = type;
    aws_ref_count_init(&message_op->base.ref_count, message_op, s_destroy_operation_message);
    message_op->base.impl = message_op;

    if (aws_secure_tunnel_message_storage_init(&message_op->options_storage, allocator, message_options, type)) {
        goto error;
    }

    message_op->base.message_view = &message_op->options_storage.storage_view;

    return message_op;

error:

    aws_secure_tunnel_operation_release(&message_op->base);

    return NULL;
}

/*********************************************************************************************************************
 * Pingreq
 ********************************************************************************************************************/

static void s_destroy_operation_pingreq(void *object) {
    if (object == NULL) {
        return;
    }

    struct aws_secure_tunnel_operation_pingreq *pingreq_op = object;
    aws_mem_release(pingreq_op->allocator, pingreq_op);
}

struct aws_secure_tunnel_operation_pingreq *aws_secure_tunnel_operation_pingreq_new(struct aws_allocator *allocator) {
    AWS_PRECONDITION(allocator != NULL);

    struct aws_secure_tunnel_operation_pingreq *pingreq_op =
        aws_mem_calloc(allocator, 1, sizeof(struct aws_secure_tunnel_operation_pingreq));
    if (pingreq_op == NULL) {
        return NULL;
    }

    pingreq_op->allocator = allocator;
    pingreq_op->base.vtable = &s_empty_operation_vtable;
    pingreq_op->base.operation_type = AWS_STOT_PING;
    aws_ref_count_init(&pingreq_op->base.ref_count, pingreq_op, s_destroy_operation_pingreq);
    pingreq_op->base.impl = pingreq_op;

    return pingreq_op;
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
    aws_string_destroy(storage->client_token);
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

    /*
     * Client token is provided to the secure tunnel service alongside the access token.
     * The access token is one-time use unless coupled with a client token. The pair can be used together
     * for reconnects. If the user provides one, we will use that. If one is not provided, we will generate
     * one for use with this access token to handle reconnecting on disconnections.
     */
    if (options->client_token.len > 0) {
        storage->client_token = aws_string_new_from_cursor(allocator, &options->client_token);
        if (storage->client_token == NULL) {
            goto error;
        }
    } else {
        struct aws_uuid uuid;
        if (aws_uuid_init(&uuid)) {
            AWS_LOGF_ERROR(
                AWS_LS_IOTDEVICE_SECURE_TUNNELING,
                "Failed to initiate an uuid struct: %s",
                aws_error_str(aws_last_error()));
            goto error;
        }
        char uuid_str[AWS_UUID_STR_LEN] = {0};
        struct aws_byte_buf uuid_buf = aws_byte_buf_from_array(uuid_str, sizeof(uuid_str));
        uuid_buf.len = 0;
        if (aws_uuid_to_str(&uuid, &uuid_buf)) {
            AWS_LOGF_ERROR(
                AWS_LS_IOTDEVICE_SECURE_TUNNELING, "Failed to stringify uuid: %s", aws_error_str(aws_last_error()));
            goto error;
        }
        storage->client_token = aws_string_new_from_buf(allocator, &uuid_buf);
    }

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

    storage->on_message_received = options->on_message_received;
    storage->user_data = options->user_data;

    storage->local_proxy_mode = options->local_proxy_mode;
    storage->on_connection_complete = options->on_connection_complete;
    storage->on_connection_shutdown = options->on_connection_shutdown;
    storage->on_send_data_complete = options->on_send_data_complete;
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
