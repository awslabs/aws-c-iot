/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/common/ref_count.h>
#include <aws/common/string.h>
#include <aws/iotdevice/private/secure_tunneling_impl.h>
#include <aws/iotdevice/private/secure_tunneling_operations.h>
#include <aws/iotdevice/secure_tunneling.h>

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

/* STEVE TODO set the stream_id based on the service id */
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

// static struct aws_secure_tunnel_operation_vtable s_empty_operation_vtable = {
//     .aws_secure_tunnel_operation_completion_fn = NULL,
//     .aws_secure_tunnel_operation_set_stream_id_fn = NULL,
//     .aws_secure_tunnel_operation_get_stream_id_address_fn = NULL,
// };

/*********************************************************************************************************************
 * data
 ********************************************************************************************************************/

static void s_aws_secure_tunnel_operation_data_set_stream_id(
    struct aws_secure_tunnel_operation *operation,
    struct aws_secure_tunnel *secure_tunnel) {

    struct aws_secure_tunnel_operation_data *data_op = operation->impl;
    int32_t stream_id = 0;

    struct aws_secure_tunnel_message_data_storage *data_storage = &data_op->options_storage;

    if (data_storage->service_id.len > 0) {
        struct aws_string *service_id = NULL;
        service_id = aws_string_new_from_cursor(secure_tunnel->allocator, &data_storage->service_id);

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
        }
    } else {
        stream_id = secure_tunnel->config->stream_id;
    }

    data_op->options_storage.storage_view.stream_id = stream_id;
}

static int32_t *s_aws_secure_tunnel_operation_data_get_stream_id_address_fn(
    const struct aws_secure_tunnel_operation *operation) {
    struct aws_secure_tunnel_operation_data *data_op = operation->impl;
    return &data_op->options_storage.storage_view.stream_id;
}

static struct aws_secure_tunnel_operation_vtable s_data_operation_vtable = {
    .aws_secure_tunnel_operation_set_stream_id_fn = s_aws_secure_tunnel_operation_data_set_stream_id,
    .aws_secure_tunnel_operation_get_stream_id_address_fn = s_aws_secure_tunnel_operation_data_get_stream_id_address_fn,
};

int aws_secure_tunnel_message_data_view_validate(const struct aws_secure_tunnel_message_data_view *data_view) {
    if (data_view == NULL) {
        AWS_LOGF_ERROR(AWS_LS_IOTDEVICE_SECURE_TUNNELING, "null DATA message options");
        return aws_raise_error(AWS_ERROR_IOTDEVICE_SECURE_TUNNELING_DATA_OPTIONS_VALIDATION);
    }

    if (data_view->stream_id != 0) {
        AWS_LOGF_ERROR(
            AWS_LS_IOTDEVICE_SECURE_TUNNELING,
            "id=%p: aws_secure_tunnel_message_data_view - stream id must be 0",
            (void *)data_view);
        return aws_raise_error(AWS_ERROR_IOTDEVICE_SECURE_TUNNELING_DATA_OPTIONS_VALIDATION);
    }

    if (data_view->service_id.len <= 0) {
        AWS_LOGF_ERROR(
            AWS_LS_IOTDEVICE_SECURE_TUNNELING,
            "id=%p: aws_secure_tunnel_message_data_view - Service Id cannot be empty",
            (void *)data_view);
        return aws_raise_error(AWS_ERROR_IOTDEVICE_SECURE_TUNNELING_DATA_OPTIONS_VALIDATION);
    }

    if (data_view->payload.len > MAX_PAYLOAD_SIZE) {
        AWS_LOGF_ERROR(
            AWS_LS_IOTDEVICE_SECURE_TUNNELING,
            "id=%p: aws_secure_tunnel_message_data_view - payload too long",
            (void *)data_view);
        return aws_raise_error(AWS_ERROR_IOTDEVICE_SECURE_TUNNELING_DATA_OPTIONS_VALIDATION);
    }

    return AWS_OP_SUCCESS;
}

void aws_secure_tunnel_message_data_view_log(
    const struct aws_secure_tunnel_message_data_view *data_view,
    enum aws_log_level level) {

    struct aws_logger *temp_logger = aws_logger_get();
    if (temp_logger == NULL ||
        temp_logger->vtable->get_log_level(temp_logger, AWS_LS_IOTDEVICE_SECURE_TUNNELING) < level) {
        return;
    }

    AWS_LOGF(
        level,
        AWS_LS_IOTDEVICE_SECURE_TUNNELING,
        "(%p) aws_secure_tunnel_message_data_view stream id set to %d",
        (void *)data_view,
        (int)data_view->stream_id);

    AWS_LOGF(
        level,
        AWS_LS_IOTDEVICE_SECURE_TUNNELING,
        "id=%p: aws_secure_tunnel_message_data_view service id set to \"" PRInSTR "\"",
        (void *)data_view,
        AWS_BYTE_CURSOR_PRI(data_view->service_id));
}

static size_t s_aws_secure_tunnel_message_data_compute_storage_size(
    const struct aws_secure_tunnel_message_data_view *data_view) {
    size_t storage_size = data_view->payload.len;
    storage_size += data_view->service_id.len;

    return storage_size;
}

int aws_secure_tunnel_message_data_storage_init(
    struct aws_secure_tunnel_message_data_storage *data_storage,
    struct aws_allocator *allocator,
    const struct aws_secure_tunnel_message_data_view *data_options) {

    AWS_ZERO_STRUCT(*data_storage);
    size_t storage_capacity = s_aws_secure_tunnel_message_data_compute_storage_size(data_options);
    if (aws_byte_buf_init(&data_storage->storage, allocator, storage_capacity)) {
        return AWS_OP_ERR;
    }

    struct aws_secure_tunnel_message_data_view *storage_view = &data_storage->storage_view;

    storage_view->stream_id = data_options->stream_id;

    storage_view->service_id = data_options->service_id;
    if (aws_byte_buf_append_and_update(&data_storage->storage, &storage_view->service_id)) {
        return AWS_OP_ERR;
    }

    storage_view->payload = data_options->payload;
    if (aws_byte_buf_append_and_update(&data_storage->storage, &storage_view->payload)) {
        return AWS_OP_ERR;
    }

    return AWS_OP_SUCCESS;
}

void aws_secure_tunnel_message_data_storage_clean_up(struct aws_secure_tunnel_message_data_storage *data_storage) {
    aws_byte_buf_clean_up(&data_storage->storage);
}

static void s_destroy_operation_data(void *object) {
    if (object == NULL) {
        return;
    }

    struct aws_secure_tunnel_operation_data *data_op = object;

    aws_secure_tunnel_message_data_storage_clean_up(&data_op->options_storage);

    aws_mem_release(data_op->allocator, data_op);
}

struct aws_secure_tunnel_operation_data *aws_secure_tunnel_operation_data_new(
    struct aws_allocator *allocator,
    const struct aws_secure_tunnel *secure_tunnel,
    const struct aws_secure_tunnel_message_data_view *data_options) {
    (void)secure_tunnel;
    AWS_PRECONDITION(allocator != NULL);
    AWS_PRECONDITION(data_options != NULL);

    if (aws_secure_tunnel_message_data_view_validate(data_options)) {
        return NULL;
    }

    struct aws_secure_tunnel_operation_data *data_op =
        aws_mem_calloc(allocator, 1, sizeof(struct aws_secure_tunnel_operation_data));
    if (data_op == NULL) {
        return NULL;
    }

    data_op->allocator = allocator;
    data_op->base.vtable = &s_data_operation_vtable;
    aws_ref_count_init(&data_op->base.ref_count, data_op, s_destroy_operation_data);
    data_op->base.impl = data_op;

    if (aws_secure_tunnel_message_data_storage_init(&data_op->options_storage, allocator, data_options)) {
        goto error;
    }

    data_op->base.message_view = &data_op->options_storage.storage_view;

    return data_op;

error:

    aws_secure_tunnel_operation_release(&data_op->base);

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

// int aws_secure_tunnel_packet_data_storage_init_from_external_storage(
//     struct aws_secure_tunnel_packet_data_storage *data_storage,
//     struct aws_allocator *allocator) {
//     AWS_ZERO_STRUCT(*data_storage);

//     if (aws_secure_tunnel_user_property_set_init(&publish_storage->user_properties, allocator)) {
//         return AWS_OP_ERR;
//     }

//     if (aws_array_list_init_dynamic(&publish_storage->subscription_identifiers, allocator, 0, sizeof(uint32_t))) {
//         return AWS_OP_ERR;
//     }

//     return AWS_OP_SUCCESS;
// }

// AWS_IOTDEVICE_API
// int aws_secure_tunnel_packet_stream_storage_init(
//     struct aws_secure_tunnel_packet_stream_storage *stream_storage,
//     struct aws_allocator *allocator,
//     const struct aws_secure_tunnel_packet_stream_view *stream_options);

// AWS_IOTDEVICE_API
// int aws_secure_tunnel_packet_stream_storage_init_from_external_storage(
//     struct aws_secure_tunnel_packet_stream_storage *stream_storage,
//     struct aws_allocator *allocator);

// AWS_IOTDEVICE_API
// int aws_secure_tunnel_packet_stream_storage_clean_up(struct aws_secure_tunnel_packet_stream_storage *stream_storage);
