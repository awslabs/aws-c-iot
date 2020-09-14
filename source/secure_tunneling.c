#include <aws/iotdevice/secure_tunneling.h>
#include <aws/http/websocket.h>
#include <aws/common/hash_table.h>

/* 
 * Hash map to keep track of streams
 */
static struct aws_hash_table s_stream_map = {.p_impl = NULL};

struct stream_id_key {
    int stream_id;
};

struct stream_info {
    /* TODO: define what is store in the hash map value */
    int to_do;
};

static uint64_t s_hash(const void *key) {
    const struct stream_id_key *map_key = key;
    return map_key->stream_id;
}

static bool s_hash_eq(const void *a, const void *b) {
    const struct stream_id_key *map_key_a = a;
    const struct stream_id_key *map_key_b = b;
    return map_key_a->stream_id == map_key_b->stream_id;
}

static void s_hash_destroy(void *key_or_value) {
    aws_mem_release(aws_default_allocator(), key_or_value);
}

static void s_init_stream_map(void) {
    if (s_stream_map.p_impl != NULL) {
        return;
    }

    aws_hash_table_init(&s_stream_map, aws_default_allocator(), 1, s_hash, s_hash_eq, s_hash_destroy, s_hash_destroy);
}

/*
 * Connection
 */
static int s_next_stream_id = 0;
static int s_get_next_stream_id(void) {
    return s_next_stream_id++;
}

static void s_on_websocket_setup(
    struct aws_websocket *websocket,
    int error_code,
    int handshake_response_status,
    const struct aws_http_header *handshake_response_header_array,
    size_t num_handshake_response_headers,
    void *user_data) {

    struct aws_secure_tunneling_connection_config *config = user_data;

    /* Add to hash map */
    s_init_stream_map();
    struct stream_id_key *k = aws_mem_calloc(aws_default_allocator(), 1, sizeof(struct stream_id_key));
    k->stream_id = s_get_next_stream_id();
    struct stream_info *v = aws_mem_calloc(aws_default_allocator(), 1, sizeof(struct stream_info));
    /* TODO: populate stream_info */
    int was_created = 0;
    aws_hash_table_put(&s_stream_map, k, v, &was_created);

    config->on_connection_complete(k->stream_id);
}

static void s_on_websocket_shutdown(struct aws_websocket *websocket, int error_code, void *user_data) {

}

static void s_init_websocket_client_connection_options(
    const struct aws_secure_tunneling_connection_config *config,
    struct aws_websocket_client_connection_options *websocket_options) {

    /* TODO: populate websocket_options */
    websocket_options->allocator = config->allocator;
    // websocket_options->bootstrap
    // websocket_options->socket_options
    websocket_options->host = config->endpoint_host;

    struct aws_byte_cursor path = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("/"); /* TODO: What is the path? */
    websocket_options->handshake_request = aws_http_message_new_websocket_handshake_request(
        config->allocator,
        path,
        config->endpoint_host);

    // websocket_options->initial_window_size
    websocket_options->user_data = (struct aws_secure_tunneling_connection_config*) config;
    websocket_options->on_connection_setup = s_on_websocket_setup;
    websocket_options->on_connection_shutdown = s_on_websocket_shutdown;
    // websocket_options->on_incoming_frame_begin
    // websocket_options->on_incoming_frame_payload
    // websocket_options->on_incoming_frame_complete
    websocket_options->manual_window_management = false;
}

/* TODO: tag with some API? */
int aws_secure_tunneling_connect(const struct aws_secure_tunneling_connection_config *config) {
    struct aws_websocket_client_connection_options websocket_options;
    s_init_websocket_client_connection_options(config, &websocket_options);

    if (aws_websocket_client_connect(&websocket_options)) {

    }

    return 0;
}

int aws_secure_tunneling_close(int32_t stream_id) {
    struct stream_id_key k = {.stream_id = stream_id};
    int was_present;
    aws_hash_table_remove(&s_stream_map, &k, NULL, &was_present);

    /* TODO: what else to clean up? */

    return 0;
}
