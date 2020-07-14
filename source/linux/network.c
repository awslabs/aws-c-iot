/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/iotdevice/iotdevice.h>
#include <aws/iotdevice/private/network.h>

#include <aws/common/byte_buf.h>
#include <aws/common/error.h>
#include <aws/common/hash_table.h>
#include <aws/common/logging.h>
#include <aws/common/string.h>
#include <aws/io/io.h>

#include <arpa/inet.h>
#include <errno.h>
#include <ifaddrs.h>
#include <linux/if_link.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define IFACE_NAME_SIZE IFNAMSIZ
#define IPV4_ADDRESS_SIZE 16
#define PORT_STRING_SIZE 6

static size_t s_proc_net_tcp_size_hint = 4096;
static size_t s_proc_net_udp_size_hint = 4096;
/* sets hint value by multiplying read proc_net file size with this number */
static float PROC_NET_HINT_FACTOR = 1.1f;

struct aws_iotdevice_network_iface {
    char iface_name[IFACE_NAME_SIZE];
    char ipv4_addr_str[IPV4_ADDRESS_SIZE];
    struct aws_iotdevice_metric_network_transfer metrics;
};

int s_hashfn_foreach_total_iface_transfer_metrics(void *context, struct aws_hash_element *p_element) {
    AWS_PRECONDITION(context != NULL);
    AWS_PRECONDITION(p_element != NULL);
    struct aws_iotdevice_metric_network_transfer *total = (struct aws_iotdevice_metric_network_transfer *)context;
    struct aws_iotdevice_network_iface *iface = p_element->value;

    total->bytes_in += iface->metrics.bytes_in;
    total->bytes_out += iface->metrics.bytes_out;
    total->packets_in += iface->metrics.packets_in;
    total->packets_out += iface->metrics.packets_out;

    return AWS_COMMON_HASH_TABLE_ITER_CONTINUE;
}

/* based on linux  */
enum linux_network_connection_state { LINUX_NCS_UNKNOWN = 0, LINUX_NCS_ESTABLISHED = 1, LINUX_NCS_LISTEN = 10 };

static uint16_t map_network_state(uint16_t linux_state) {
    switch (linux_state) {
        case LINUX_NCS_LISTEN:
            return AWS_IDNCS_LISTEN;
            break;
        case LINUX_NCS_ESTABLISHED:
            return AWS_IDNCS_ESTABLISHED;
            break;
        default:
            return AWS_IDNCS_UNKNOWN;
            break;
    }
}

static void s_hex_addr_to_ip_str(char *ip_out, size_t ip_max_len, const char *hex_addr) {
    uint32_t addr_num = (uint32_t)strtoul(hex_addr, NULL, 16);
    struct in_addr addr;
    addr.s_addr = addr_num;
    char *s = inet_ntoa(addr);

    snprintf(ip_out, ip_max_len, "%s", s);
}

void get_system_network_total(
    struct aws_iotdevice_metric_network_transfer *total,
    struct aws_iotdevice_network_ifconfig *ifconfig) {
    int return_code = aws_hash_table_foreach(
        &ifconfig->iface_name_to_info, s_hashfn_foreach_total_iface_transfer_metrics, (void *)total);
    if (AWS_OP_SUCCESS != return_code) {
    }
}

void get_network_total_delta(
    struct aws_iotdevice_metric_network_transfer *delta,
    struct aws_iotdevice_metric_network_transfer *prev_total,
    struct aws_iotdevice_metric_network_transfer *curr_total) {
    AWS_PRECONDITION(delta != NULL);
    AWS_PRECONDITION(prev_total != NULL);
    AWS_PRECONDITION(curr_total != NULL);

    delta->bytes_in = curr_total->bytes_in - prev_total->bytes_in;
    delta->bytes_out = curr_total->bytes_out - prev_total->bytes_out;
    delta->packets_in = curr_total->packets_in - prev_total->packets_in;
    delta->packets_out = curr_total->packets_out - prev_total->packets_out;
}

/**
 * This file read is not terribly efficient if not enough bytes are allocated up front.
 */
int read_proc_net_from_file(
    struct aws_byte_buf *out_buf,
    struct aws_allocator *allocator,
    size_t size_hint,
    const char *filename) {
    AWS_ZERO_STRUCT(*out_buf);
    int return_value = AWS_OP_ERR;

    if (aws_byte_buf_init(out_buf, allocator, size_hint)) {
        return aws_raise_error(aws_last_error());
    }

    FILE *fp = fopen(filename, "r");
    if (fp) {
        size_t read = fread(out_buf->buffer, 1, out_buf->capacity, fp);
        out_buf->len += read;
        while (read == size_hint) {
            int aws_error = 0;
            if (AWS_OP_SUCCESS != (aws_error = aws_byte_buf_reserve_relative(out_buf, size_hint))) {
                return_value = aws_error;
                goto cleanup;
            }
            /* double size hint increase if we need to do it again */
            size_hint += size_hint;
            read = fread(out_buf->buffer + out_buf->len, 1, size_hint, fp);
        }
        if (ferror(fp)) {
            return_value = aws_translate_and_raise_io_error(errno);
            goto cleanup;
        }
        return_value = AWS_OP_SUCCESS;
    }

cleanup:
    fclose(fp);
    if (AWS_OP_SUCCESS != return_value) {
        aws_byte_buf_clean_up_secure(out_buf);
        return aws_raise_error(return_value);
    }

    return return_value;
}

int get_net_connections_from_proc_buf(
    struct aws_array_list *net_conns,
    struct aws_allocator *allocator,
    struct aws_byte_cursor *proc_net_data,
    const struct aws_iotdevice_network_ifconfig *ifconfig,
    enum aws_iotdevice_network_protocol protocol) {
    AWS_PRECONDITION(net_conns != NULL);
    AWS_PRECONDITION(allocator != NULL);
    AWS_PRECONDITION(ifconfig != NULL);
    AWS_PRECONDITION(aws_byte_cursor_is_valid(proc_net_data));

    int return_value = AWS_OP_SUCCESS;
    struct aws_array_list lines;
    AWS_ZERO_STRUCT(lines);

    aws_array_list_init_dynamic(&lines, allocator, 10, sizeof(struct aws_byte_cursor));
    aws_byte_cursor_split_on_char(proc_net_data, '\n', &lines);

    /* first line is header text info */
    aws_array_list_pop_front_n(&lines, 1);
    /* last line is empty */
    aws_array_list_pop_back(&lines);

    struct aws_byte_cursor line;
    while (AWS_OP_SUCCESS == aws_array_list_front(&lines, &line)) {
        aws_array_list_pop_front(&lines);

        char local_addr_h[9];
        char local_port_h[6];
        char remote_addr_h[9];
        char remote_port_h[6];
        char state_h[3];
        int tokens_read = sscanf(
            (const char *)line.ptr,
            "%*s %8s %*c %4s %8s %*c %4s %2s %*s",
            local_addr_h,
            local_port_h,
            remote_addr_h,
            remote_port_h,
            state_h);

        if (tokens_read == 5) {
            uint16_t state = strtol(state_h, NULL, 16);
            if (state == LINUX_NCS_ESTABLISHED || state == LINUX_NCS_LISTEN) {
                struct aws_iotdevice_metric_net_connection *connection =
                    aws_mem_acquire(allocator, sizeof(struct aws_iotdevice_metric_net_connection));
                if (connection == NULL) {
                    return_value = AWS_OP_ERR;
                    AWS_LOGF_ERROR(
                        AWS_LS_IOTDEVICE_NETWORK_CONFIG,
                        "id=%p: Could not allocate memory for network connection",
                        (void *)ifconfig);
                    goto cleanup;
                }

                char local_addr[IPV4_ADDRESS_SIZE];
                char remote_addr[IPV4_ADDRESS_SIZE];
                s_hex_addr_to_ip_str(local_addr, IPV4_ADDRESS_SIZE, local_addr_h);
                s_hex_addr_to_ip_str(remote_addr, IPV4_ADDRESS_SIZE, remote_addr_h);
                connection->local_port = strtol(local_port_h, NULL, 16);
                connection->remote_port = strtol(remote_port_h, NULL, 16);
                connection->state = map_network_state(strtol(state_h, NULL, 16));

                struct aws_hash_element *element;
                int return_code = aws_hash_table_find(&ifconfig->iface_name_to_info, local_addr, &element);
                if (element == NULL || return_code != AWS_OP_SUCCESS) {
                    /* TODO: element == NULL seems to be the failure mode. When might return code matter? Log it? */
                    AWS_LOGF_WARN(
                        AWS_LS_IOTDEVICE_NETWORK_CONFIG,
                        "id=%p: Could not retrieve interface mapping for address: %s",
                        (void *)ifconfig,
                        local_addr);
                    continue;
                }

                struct aws_iotdevice_network_iface *iface = (struct aws_iotdevice_network_iface *)element->value;
                connection->local_interface = aws_string_new_from_c_str(allocator, iface->iface_name);
                if (!connection->local_interface) {
                    return_value = AWS_OP_ERR;
                    AWS_LOGF_ERROR(
                        AWS_LS_IOTDEVICE_NETWORK_CONFIG,
                        "id=%p: Could not allocate memory for connection local address",
                        (void *)ifconfig);
                    goto cleanup;
                }
                connection->remote_address = aws_string_new_from_c_str(allocator, remote_addr);
                if (!connection->remote_address) {
                    return_value = AWS_OP_ERR;
                    AWS_LOGF_ERROR(
                        AWS_LS_IOTDEVICE_NETWORK_CONFIG,
                        "id=%p: Could not allocate memory for connection remote address",
                        (void *)ifconfig);
                    goto cleanup;
                }
                connection->protocol = protocol;

                if (AWS_OP_SUCCESS != aws_array_list_push_back(net_conns, connection)) {
                    goto cleanup;
                }
            }
        } else {
            AWS_LOGF_WARN(AWS_LS_IOTDEVICE_NETWORK_CONFIG, "id=%p: Bad line in /proc/net/*** file", (void *)ifconfig);
        }
    }

cleanup:
    aws_array_list_clean_up(&lines);

    return return_value;
}

int get_network_connections(struct aws_array_list *net_conns, struct aws_iotdevice_network_ifconfig *ifconfig, struct aws_allocator *allocator) {
    struct aws_byte_buf net_tcp;
    AWS_ZERO_STRUCT(net_tcp);
    struct aws_byte_buf net_udp;
    AWS_ZERO_STRUCT(net_udp);
    int return_code = AWS_OP_ERR;

    if (AWS_OP_SUCCESS != read_proc_net_from_file(&net_tcp, allocator, s_proc_net_tcp_size_hint, "/proc/net/tcp")) {
        AWS_LOGF_ERROR(
            AWS_LS_IOTDEVICE_NETWORK_CONFIG,
            "id=%p: Failed to retrieve network configuration: %s",
            (void *)ifconfig,
            aws_error_name(aws_last_error()));
        return_code = AWS_OP_ERR;
        goto cleanup;
    }
    /* hint on read size next go around */
    s_proc_net_tcp_size_hint = net_tcp.len * PROC_NET_HINT_FACTOR;

    if (AWS_OP_SUCCESS != read_proc_net_from_file(&net_udp, allocator, s_proc_net_udp_size_hint, "/proc/net/udp")) {
        AWS_LOGF_ERROR(
            AWS_LS_IOTDEVICE_NETWORK_CONFIG,
            "id=%p: Failed to retrieve network configuration: %s",
            (void *)ifconfig,
            aws_error_name(aws_last_error()));
        return_code = AWS_OP_ERR;
        goto cleanup;
    }
    /* hint on read size next go around */
    s_proc_net_udp_size_hint = net_udp.len * PROC_NET_HINT_FACTOR;

    struct aws_byte_cursor net_tcp_cursor = aws_byte_cursor_from_buf(&net_tcp);
    if (AWS_OP_SUCCESS !=
        get_net_connections_from_proc_buf(net_conns, allocator, &net_tcp_cursor, ifconfig, AWS_IDNP_TCP)) {
        AWS_LOGF_ERROR(
            AWS_LS_IOTDEVICE_NETWORK_CONFIG,
            "id=%p: Failed to parse network connections from /proc/net/tcp",
            (void *)ifconfig);
            /* intentionally not considered an error right now */
    }

    struct aws_byte_cursor net_udp_cursor = aws_byte_cursor_from_buf(&net_udp);
    if (AWS_OP_SUCCESS !=
        get_net_connections_from_proc_buf(net_conns, allocator, &net_udp_cursor, ifconfig, AWS_IDNP_UDP)) {
        AWS_LOGF_ERROR(
            AWS_LS_IOTDEVICE_NETWORK_CONFIG,
            "id=%p: Failed to parse network connections from /proc/net/udp",
            (void *)ifconfig);
            /* intentionally not considered an error right now */
    }
    return_code = AWS_OP_SUCCESS;

cleanup:
    if (net_tcp.allocator) {
        aws_byte_buf_clean_up(&net_tcp);
    }
    if (net_udp.allocator) {
        aws_byte_buf_clean_up(&net_udp);
    }

    return return_code;
}

int get_network_config_and_transfer(struct aws_iotdevice_network_ifconfig *ifconfig, struct aws_allocator *allocator) {
    if (AWS_OP_SUCCESS != aws_hash_table_init(
                              &ifconfig->iface_name_to_info,
                              allocator,
                              sizeof(struct aws_iotdevice_network_iface),
                              aws_hash_c_string,
                              aws_hash_callback_c_str_eq,
                              NULL,
                              NULL)) {
        return AWS_OP_ERR;
    }
    int result = AWS_OP_ERR;
    struct aws_iotdevice_network_iface *iface = NULL;
    int fd = 0;
    struct ifaddrs *address_info = NULL;
    if (getifaddrs(&address_info)) {
        AWS_LOGF_ERROR(
            AWS_LS_IOTDEVICE_NETWORK_CONFIG, "id=%p: getifaddrs() failed: %s", (void *)ifconfig, strerror(errno));
        result = AWS_OP_ERR;
        goto cleanup;
    }
    struct ifaddrs *address = address_info;
    while (address) {
        if (address->ifa_addr == NULL || address->ifa_data == NULL) {
            goto next_interface;
        }

        struct ifreq ifr;
        AWS_ZERO_STRUCT(ifr);

        strncpy(ifr.ifr_name, address->ifa_name, IFNAMSIZ);
        fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd == -1) {
            AWS_LOGF_ERROR(
                AWS_LS_IOTDEVICE_NETWORK_CONFIG,
                "id=%p: socket(AF_INET, SOCK_DGRAM, 0) failed: %s",
                (void *)ifconfig,
                strerror(errno));
            result = AWS_OP_ERR;
            goto cleanup;
        }
        if (ioctl(fd, SIOCGIFADDR, &ifr) == -1) {
            AWS_LOGF_WARN(
                AWS_LS_IOTDEVICE_NETWORK_CONFIG,
                "id=%p: iotctl(fd, SIOCGIFADDR, ...) failed to get interface address: %s",
                (void *)ifconfig,
                strerror(errno));
            goto next_interface;
        }

        iface = aws_mem_calloc(allocator, 1, sizeof(struct aws_iotdevice_network_iface));

        if (ifr.ifr_addr.sa_family == AF_INET) {
            inet_ntop(AF_INET, &((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr, iface->ipv4_addr_str, 16);
        }
        strncpy(iface->iface_name, ifr.ifr_name, IFACE_NAME_SIZE);

        if (address->ifa_data) {
            struct rtnl_link_stats *stats = address->ifa_data;
            iface->metrics.bytes_in = stats->rx_bytes;
            iface->metrics.bytes_out = stats->tx_bytes;
            iface->metrics.packets_in = stats->rx_packets;
            iface->metrics.packets_out = stats->tx_packets;
        }

        if (AWS_OP_SUCCESS !=
            (result = aws_hash_table_put(&ifconfig->iface_name_to_info, iface->ipv4_addr_str, iface, NULL))) {
            AWS_LOGF_ERROR(
                AWS_LS_IOTDEVICE_NETWORK_CONFIG,
                "id=%p: network interface address to interface info add to map failed: %s",
                (void *)ifconfig,
                aws_error_name(result));
            result = AWS_OP_ERR;
            goto cleanup;
        }
    next_interface:
        close(fd);
        fd = 0;
        address = address->ifa_next;
    } /* while */
    result = AWS_OP_SUCCESS;

cleanup:
    if (address_info) {
        freeifaddrs(address_info);
    }
    if (fd) {
        close(fd);
    }
    return result;
}
