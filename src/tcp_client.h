/**
 * tcp_client.h - TCP client header for STB eBPF Probe
 * 
 * This module handles non-blocking TCP connection to Windows relay server
 * with buffered send and automatic reconnection.
 * 
 * Features:
 * - Non-blocking TCP connect
 * - Exponential backoff reconnect (1s, 2s, 4s, max 30s)
 * - MSG_NOSIGNAL to prevent SIGPIPE
 * - Send JSON lines (\n delimited)
 */

#ifndef _STB_TCP_CLIENT_H
#define _STB_TCP_CLIENT_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <time.h>

/* Include configuration */
#include "config.h"
#include "../include/common.h"

/* ==================== Data Structures ==================== */

/**
 * struct tcp_client - TCP client context
 * 
 * Contains all state needed to manage TCP connection
 * to Windows relay server.
 */
struct tcp_client {
    int sock_fd;                   /* Socket file descriptor */
    char server_ip[16];           /* Server IP address */
    int server_port;               /* Server port */
    int is_connected;             /* Connection status */
    int is_nonblocking;           /* Non-blocking mode */
    
    /* Reconnect state */
    int reconnect_retries;         /* Current retry count */
    int reconnect_delay_ms;        /* Current delay (exponential backoff) */
    __u64 last_reconnect_time;    /* Timestamp of last reconnect attempt */
    int auto_reconnect;           /* Enable auto-reconnect */
    
    /* Send buffer */
    char send_buffer[TCP_SEND_BUFFER_SIZE];  /* Send buffer */
    int send_buffer_len;          /* Data length in send buffer */
    
    /* Statistics */
    __u64 bytes_sent;             /* Total bytes sent */
    __u64 bytes_lost;             /* Total bytes lost (connection drop) */
    __u64 connect_count;          /* Number of successful connections */
    __u64 reconnect_count;        /* Number of reconnections */
};

/* ==================== Function Declarations ==================== */

/**
 * tcp_client_init - Initialize TCP client
 * 
 * @server_ip: Relay server IP address
 * @server_port: Relay server port
 * @auto_reconnect: Enable automatic reconnection
 * 
 * Returns: Pointer to tcp_client struct, or NULL on failure
 */
struct tcp_client *tcp_client_init(const char *server_ip,
                                    int server_port,
                                    int auto_reconnect);

/**
 * tcp_client_connect - Connect to relay server
 * 
 * @client: TCP client context
 * 
 * Returns: 0 on success, -1 on failure
 * 
 * Note: Uses non-blocking connect with select() timeout.
 */
int tcp_client_connect(struct tcp_client *client);

/**
 * tcp_client_disconnect - Disconnect from relay server
 * 
 * @client: TCP client context
 */
void tcp_client_disconnect(struct tcp_client *client);

/**
 * tcp_client_reconnect - Reconnect with exponential backoff
 * 
 * @client: TCP client context
 * 
 * Returns: 0 on success, -1 if should not reconnect yet
 */
int tcp_client_reconnect(struct tcp_client *client);

/**
 * tcp_client_send - Send data to relay server
 * 
 * @client: TCP client context
 * @data: Data to send
 * @len: Data length
 * 
 * Returns: Number of bytes sent, -1 on failure
 * 
 * Note: Uses MSG_NOSIGNAL to prevent SIGPIPE.
 *       Appends \n if not present.
 */
int tcp_client_send(struct tcp_client *client,
                     const char *data, int len);

/**
 * tcp_client_send_line - Send a line (with \n delimiter)
 * 
 * @client: TCP client context
 * @line: Line to send (without \n)
 * 
 * Returns: Number of bytes sent, -1 on failure
 */
int tcp_client_send_line(struct tcp_client *client, const char *line);

/**
 * tcp_client_flush - Flush send buffer
 * 
 * @client: TCP client context
 * 
 * Returns: Number of bytes flushed, -1 on failure
 */
int tcp_client_flush(struct tcp_client *client);

/**
 * tcp_client_is_connected - Check if client is connected
 * 
 * @client: TCP client context
 * 
 * Returns: 1 if connected, 0 if not
 */
int tcp_client_is_connected(struct tcp_client *client);

/**
 * tcp_client_cleanup - Cleanup and free TCP client resources
 * 
 * @client: TCP client context
 */
void tcp_client_cleanup(struct tcp_client *client);

/**
 * tcp_client_get_stats - Get TCP client statistics
 * 
 * @client: TCP client context
 * @bytes_sent: Output - bytes sent
 * @bytes_lost: Output - bytes lost
 * @connect_count: Output - connect count
 * @reconnect_count: Output - reconnect count
 */
void tcp_client_get_stats(struct tcp_client *client,
                           __u64 *bytes_sent,
                           __u64 *bytes_lost,
                           __u64 *connect_count,
                           __u64 *reconnect_count);

/**
 * tcp_client_print_stats - Print TCP client statistics
 * 
 * @client: TCP client context
 */
void tcp_client_print_stats(struct tcp_client *client);

/* ==================== Utility Functions ==================== */

/**
 * set_nonblocking - Set socket to non-blocking mode
 * 
 * @sock_fd: Socket file descriptor
 * 
 * Returns: 0 on success, -1 on failure
 */
int set_nonblocking(int sock_fd);

/**
 * set_blocking - Set socket to blocking mode
 * 
 * @sock_fd: Socket file descriptor
 * 
 * Returns: 0 on success, -1 on failure
 */
int set_blocking(int sock_fd);

#endif /* _STB_TCP_CLIENT_H */
