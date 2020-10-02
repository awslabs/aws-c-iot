#ifndef AWS_C_IOT_MQTT_MOCK_STRUCTS_H
#define AWS_C_IOT_MQTT_MOCK_STRUCTS_H

#include <aws/common/condition_variable.h>
#include <aws/common/mutex.h>
#include <aws/io/channel_bootstrap.h>
#include <aws/io/event_loop.h>
#include <aws/io/host_resolver.h>
#include <aws/io/message_pool.h>
#include <aws/io/socket.h>
#include <aws/io/tls_channel_handler.h>
#include <aws/mqtt/client.h>

enum aws_mqtt_packet_type {
    /* reserved = 0, */
    AWS_MQTT_PACKET_CONNECT = 1,
    AWS_MQTT_PACKET_CONNACK,
    AWS_MQTT_PACKET_PUBLISH,
    AWS_MQTT_PACKET_PUBACK,
    AWS_MQTT_PACKET_PUBREC,
    AWS_MQTT_PACKET_PUBREL,
    AWS_MQTT_PACKET_PUBCOMP,
    AWS_MQTT_PACKET_SUBSCRIBE,
    AWS_MQTT_PACKET_SUBACK,
    AWS_MQTT_PACKET_UNSUBSCRIBE,
    AWS_MQTT_PACKET_UNSUBACK,
    AWS_MQTT_PACKET_PINGREQ,
    AWS_MQTT_PACKET_PINGRESP,
    AWS_MQTT_PACKET_DISCONNECT,
    /* reserved = 15, */
};

struct aws_mqtt_fixed_header {
    enum aws_mqtt_packet_type packet_type;
    size_t remaining_length;
    uint8_t flags;
};

struct aws_mqtt_packet_publish {
    struct aws_mqtt_fixed_header fixed_header;

    /* Variable header */
    uint16_t packet_identifier;
    struct aws_byte_cursor topic_name;

    /* Payload */
    struct aws_byte_cursor payload;
};

struct publish_task_arg {
    struct aws_mqtt_client_connection *connection;
    struct aws_string *topic_string;
    struct aws_byte_cursor topic;
    enum aws_mqtt_qos qos;
    bool retain;
    struct aws_byte_cursor payload;
    /* Packet to populate */
    struct aws_mqtt_packet_publish publish;
    aws_mqtt_op_complete_fn *on_complete;
    void *userdata;
};

struct aws_mqtt_packet_subscribe {
    /* Fixed header */
    struct aws_mqtt_fixed_header fixed_header;

    /* Variable header */
    uint16_t packet_identifier;

    /* Payload */
    /* List of aws_mqtt_subscription */
    struct aws_array_list topic_filters;
};

struct subscribe_task_topic {
    struct aws_mqtt_client_connection *connection;

    struct aws_mqtt_topic_subscription request;
    struct aws_string *filter;
    bool is_local;
};

struct subscribe_task_arg {

    struct aws_mqtt_client_connection *connection;

    /* list of subscribe_task_topic *s */
    struct aws_array_list topics;

    /* Packet to populate */
    struct aws_mqtt_packet_subscribe subscribe;

    /* true if transaction was committed to the topic tree, false requires a retry */
    bool tree_updated;

    struct {
        aws_mqtt_suback_multi_fn *multi;
        aws_mqtt_suback_fn *single;
    } on_suback;
    void *on_suback_ud;
};

typedef enum aws_mqtt_client_request_state(
    aws_mqtt_send_request_fn)(uint16_t packet_id, bool is_first_attempt, void *userdata);

struct aws_mqtt_outstanding_request {
    struct aws_linked_list_node list_node;

    struct aws_allocator *allocator;
    struct aws_mqtt_client_connection *connection;

    struct aws_channel_task timeout_task;

    uint16_t packet_id;
    bool initiated;
    bool completed;
    bool cancelled;
    aws_mqtt_send_request_fn *send_request;
    void *send_request_ud;
    aws_mqtt_op_complete_fn *on_complete;
    void *on_complete_ud;
};

struct aws_mqtt_topic_tree {
    struct aws_mqtt_topic_node *root;
    struct aws_allocator *allocator;
};

enum aws_mqtt_client_connection_state {
    AWS_MQTT_CLIENT_STATE_CONNECTING,
    AWS_MQTT_CLIENT_STATE_CONNECTED,
    AWS_MQTT_CLIENT_STATE_RECONNECTING,
    AWS_MQTT_CLIENT_STATE_DISCONNECTING,
    AWS_MQTT_CLIENT_STATE_DISCONNECTED,
};

struct aws_mqtt_client_connection {

    struct aws_allocator *allocator;
    struct aws_ref_count ref_count;
    struct aws_mqtt_client *client;

    /* Channel handler information */
    struct aws_channel_handler handler;
    struct aws_channel_slot *slot;

    /* The host information, changed by user when state is AWS_MQTT_CLIENT_STATE_DISCONNECTED */
    struct aws_string *host_name;
    uint16_t port;
    struct aws_tls_connection_options tls_options;
    struct aws_socket_options socket_options;

    /* Connect parameters */
    struct aws_byte_buf client_id;
    bool clean_session;
    uint16_t keep_alive_time_secs;
    uint64_t request_timeout_ns;
    struct aws_string *username;
    struct aws_string *password;
    struct {
        struct aws_byte_buf topic;
        enum aws_mqtt_qos qos;
        bool retain;
        struct aws_byte_buf payload;
    } will;
    struct {
        uint64_t current;      /* seconds */
        uint64_t min;          /* seconds */
        uint64_t max;          /* seconds */
        uint64_t next_attempt; /* milliseconds */
    } reconnect_timeouts;
    /* User connection callbacks */
    aws_mqtt_client_on_connection_complete_fn *on_connection_complete;
    void *on_connection_complete_ud;
    aws_mqtt_client_on_connection_interrupted_fn *on_interrupted;
    void *on_interrupted_ud;
    aws_mqtt_client_on_connection_resumed_fn *on_resumed;
    void *on_resumed_ud;
    aws_mqtt_client_publish_received_fn *on_any_publish;
    void *on_any_publish_ud;
    aws_mqtt_client_on_disconnect_fn *on_disconnect;
    void *on_disconnect_ud;

    /* Connection tasks. */
    struct aws_mqtt_reconnect_task *reconnect_task;
    struct aws_channel_task ping_task;

    /**
     * Number of times this connection has successfully CONNACK-ed, used
     * to ensure on_connection_completed is sent on the first completed
     * CONNECT/CONNACK cycle
     */
    size_t connection_count;
    bool use_tls; /* Only used by main thread */

    /* Only the event-loop thread may touch this data */
    struct {

        /* If an incomplete packet arrives, store the data here. */
        struct aws_byte_buf pending_packet;

        bool waiting_on_ping_response;

        /* Keeps track of all open subscriptions */
        /* TODO: The subscriptions are liveing with the connection object. So if the connection disconnect from one
         * endpoint and connect with another endpoint, the subscription tree will still be the same as before. */
        struct aws_mqtt_topic_tree subscriptions;

    } thread_data;

    /* Any thread may touch this data, but the lock must be held (unless it's an atomic) */
    struct {
        /* Note: never fire user callback with lock hold. */
        struct aws_mutex lock;

        /* The state of the connection */
        enum aws_mqtt_client_connection_state state;

        /**
         * Memory pool for all aws_mqtt_outstanding_request.
         */
        struct aws_memory_pool requests_pool;

        /**
         * Store all requests that is not completed including the pending requests.
         *
         * hash table from uint16_t (packet_id) to aws_mqtt_outstanding_request
         */
        struct aws_hash_table outstanding_requests_table;

        /**
         * List of all requests that cannot be scheduled until the connection comes online.
         * TODO: make the size of the list configurable. Stop it from from ever-growing
         */
        struct aws_linked_list pending_requests_list;
    } synced_data;

    struct {
        aws_mqtt_transform_websocket_handshake_fn *handshake_transformer;
        void *handshake_transformer_ud;
        aws_mqtt_validate_websocket_handshake_fn *handshake_validator;
        void *handshake_validator_ud;
        bool enabled;

        struct {
            struct aws_byte_buf host;
            struct aws_byte_buf auth_username;
            struct aws_byte_buf auth_password;
            struct aws_tls_connection_options tls_options;
        } * proxy;
        struct aws_http_proxy_options *proxy_options;

        struct aws_http_message *handshake_request;
    } websocket;
};

#endif // AWS_C_IOT_MQTT_MOCK_STRUCTS_H
