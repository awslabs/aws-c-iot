/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/iotdevice/private/network.h>

#include <aws/common/byte_buf.h>
#include <aws/common/error.h>
#include <aws/common/string.h>
#include <aws/io/io.h>

#include <arpa/inet.h>
#include <errno.h>
#include <ifaddrs.h>
#include <linux/if_link.h>
#include <netinet/in.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <unistd.h>

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
    aws_hash_table_foreach(&ifconfig->iface_name_to_info, s_hashfn_foreach_total_iface_transfer_metrics, (void *)total);
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
 * This file read is not terribly efficient if not enough bytes are allocated up front
 */
int read_proc_net_from_file(
    struct aws_byte_buf *out_buf,
    struct aws_allocator *allocator,
    size_t size_hint,
    const char *filename) {
    AWS_ZERO_STRUCT(*out_buf);

    if (aws_byte_buf_init(out_buf, allocator, size_hint)) {
        aws_raise_error(aws_last_error());
    }

    FILE *fp = fopen(filename, "r");
    if (fp) {
        size_t read = fread(out_buf->buffer, 1, out_buf->capacity, fp);
        out_buf->len += read;
        while (read == size_hint) {
            if (aws_byte_buf_reserve_relative(out_buf, size_hint)) {
                aws_secure_zero(out_buf->buffer, out_buf->len);
                aws_byte_buf_clean_up(out_buf);
            }
            read = fread(&out_buf->buffer[out_buf->len], 1, size_hint, fp);
            out_buf->len += read;
        }
        if (ferror(fp)) {
            return aws_raise_error(AWS_IO_FILE_VALIDATION_FAILURE);
        }
        fclose(fp);
        return AWS_OP_SUCCESS;
    }

    printf("static: Failed to open file %s with errno %d", filename, errno);
    return aws_translate_and_raise_io_error(errno);
}

int get_net_connections(
    struct aws_array_list *net_conns,
    struct aws_allocator *allocator,
    const struct aws_iotdevice_network_ifconfig *ifconfig,
    const struct aws_byte_cursor *proc_net_data,
    bool is_udp) {
    AWS_PRECONDITION(net_conns != NULL);
    AWS_PRECONDITION(allocator != NULL);
    AWS_PRECONDITION(ifconfig != NULL);
    AWS_PRECONDITION(aws_byte_cursor_is_valid(proc_net_data));

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
        char local_port_h[5];
        char remote_addr_h[9];
        char remote_port_h[5];
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
            if (state == ESTABLISHED || state == LISTEN || is_udp) {
                struct aws_iotdevice_metric_net_connection *connection =
                    aws_mem_acquire(allocator, sizeof(struct aws_iotdevice_metric_net_connection));
                if (connection == NULL) {
                    printf("Could not allocate connection memory...\n");
                }

                char local_addr[16];
                char remote_addr[16];
                s_hex_addr_to_ip_str(local_addr, 16, local_addr_h);
                s_hex_addr_to_ip_str(remote_addr, 16, remote_addr_h);
                connection->local_port = strtol(local_port_h, NULL, 16);
                connection->remote_port = strtol(remote_port_h, NULL, 16);
                connection->state = strtol(state_h, NULL, 16);

                struct aws_hash_element *element;
                aws_hash_table_find(&ifconfig->iface_name_to_info, local_addr, &element);
                if (element == NULL) {
                    printf("Could not find interface mapping for key: %s\n", local_addr);
                    continue;
                }

                struct aws_iotdevice_network_iface *iface = (struct aws_iotdevice_network_iface *)element->value;
                connection->local_interface = iface->iface_name;
                connection->remote_address = aws_string_new_from_c_str(allocator, remote_addr);

                aws_array_list_push_back(net_conns, connection);
            }
        } else {
            printf("Bad line in /proc/net/**p file...\n");
        }
    }

    return AWS_OP_SUCCESS;
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
        printf("getifaddrs() failed: %s\n", strerror(errno));
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
            printf("Couldn't open socket: %s\n", strerror(errno));
            result = AWS_OP_ERR;
            goto cleanup;
        }
        if (ioctl(fd, SIOCGIFADDR, &ifr) == -1) {
            printf("Couldn't get the interface address for %s: %s\n", ifr.ifr_name, strerror(errno));
            goto next_interface;
        }

        iface = aws_mem_acquire(allocator, sizeof(struct aws_iotdevice_network_iface));
        AWS_ZERO_STRUCT(*iface);

        if (ifr.ifr_addr.sa_family == AF_INET) {
            inet_ntop(AF_INET, &((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr, iface->ipv4_addr_str, 16);
        }
        strncpy(iface->iface_name, ifr.ifr_name, IFNAMSIZ);

        if (address->ifa_data) {
            struct rtnl_link_stats *stats = address->ifa_data;
            iface->metrics.bytes_in = stats->rx_bytes;
            iface->metrics.bytes_out = stats->tx_bytes;
            iface->metrics.packets_in = stats->rx_packets;
            iface->metrics.packets_out = stats->tx_packets;
        }

        if (AWS_OP_SUCCESS !=
            (result = aws_hash_table_put(&ifconfig->iface_name_to_info, iface->ipv4_addr_str, iface, NULL))) {
            printf("Error putting entry into map: %d\n", result);
            goto cleanup;
        } else {
            result = AWS_OP_SUCCESS;
        }

    next_interface:
        close(fd);
        fd = 0;
        address = address->ifa_next;
    } /* while */

cleanup:
    if (address_info) {
        freeifaddrs(address_info);
    }
    if (fd) {
        close(fd);
    }
    return result;
}
