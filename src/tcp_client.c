/**
 * tcp_client.c - TCP client implementation for STB eBPF Probe
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

#include "tcp_client.h"

/* ==================== Internal Helper Functions ==================== */

/**
 * calculate_backoff_delay - Calculate exponential backoff delay
 * 
 * @retry_count: Current retry count
 * @base_delay_ms: Base delay in milliseconds
 * @max_delay_ms: Maximum delay in milliseconds
 * 
 * Returns: Delay in milliseconds
 */
static int calculate_backoff_delay(int retry_count,
                                    int base_delay_ms,
                                    int max_delay_ms) {
    if (retry_count <= 0) {
        return base_delay_ms;
    }
    
    /* Calculate delay = base * 2^retry_count */
    int delay = base_delay_ms << retry_count;  /* base * 2^retry */
    
    /* Cap at max_delay */
    if (delay > max_delay_ms || delay <= 0) {  /* Overflow check */
        delay = max_delay_ms;
    }
    
    return delay;
}

/**
 * tcp_client_try_connect - Try to connect (non-blocking)
 * 
 * @client: TCP client context
 * 
 * Returns: 0 on success, -1 on failure (with errno set)
 * 
 * Note: This function creates socket, sets non-blocking mode,
 *       and attempts connect. If connect returns EINPROGRESS,
 *       it waits with select() for completion.
 */
static int tcp_client_try_connect(struct tcp_client *client) {
    if (!client) {
        errno = EINVAL;
        return -1;
    }
    
    /* Create socket */
    client->sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (client->sock_fd < 0) {
        perror("socket failed");
        return -1;
    }
    
    /* Set non-blocking mode */
    if (set_nonblocking(client->sock_fd) != 0) {
        perror("set_nonblocking failed");
        close(client->sock_fd);
        client->sock_fd = -1;
        return -1;
    }

    /* SIGPIPE is handled by signal(SIGPIPE, SIG_IGN) in main.c */

    /* Setup server address */
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(client->server_port);
    
    if (inet_pton(AF_INET, client->server_ip, &server_addr.sin_addr) != 1) {
        fprintf(stderr, "Invalid server IP: %s\n", client->server_ip);
        close(client->sock_fd);
        client->sock_fd = -1;
        errno = EINVAL;
        return -1;
    }
    
    /* Attempt non-blocking connect */
    int ret = connect(client->sock_fd, 
                       (struct sockaddr *)&server_addr,
                       sizeof(server_addr));
    
    if (ret == 0) {
        /* Connected immediately (unlikely for non-blocking) */
        client->is_connected = 1;
        if (LOG_LEVEL >= 2) {
            printf("[INFO] Connected to %s:%d\n", 
                   client->server_ip, client->server_port);
        }
        return 0;
    }
    
    if (errno == EINPROGRESS) {
        /* Connection in progress, wait for completion with select() */
        fd_set write_fds;
        FD_ZERO(&write_fds);
        FD_SET(client->sock_fd, &write_fds);
        
        struct timeval timeout;
        timeout.tv_sec = 5;  /* 5 second timeout */
        timeout.tv_usec = 0;
        
        ret = select(client->sock_fd + 1, NULL, &write_fds, NULL, &timeout);
        
        if (ret < 0) {
            perror("select failed during connect");
            close(client->sock_fd);
            client->sock_fd = -1;
            return -1;
        }
        
        if (ret == 0) {
            /* Timeout */
            if (LOG_LEVEL >= 1) {
                fprintf(stderr, "[WARN] Connect timeout to %s:%d\n",
                        client->server_ip, client->server_port);
            }
            close(client->sock_fd);
            client->sock_fd = -1;
            errno = ETIMEDOUT;
            return -1;
        }
        
        /* Check if connection succeeded */
        int so_error;
        socklen_t len = sizeof(so_error);
        if (getsockopt(client->sock_fd, SOL_SOCKET, SO_ERROR, 
                        &so_error, &len) != 0) {
            perror("getsockopt failed");
            close(client->sock_fd);
            client->sock_fd = -1;
            return -1;
        }
        
        if (so_error != 0) {
            if (LOG_LEVEL >= 1) {
                fprintf(stderr, "[WARN] Connect failed to %s:%d: %s\n",
                        client->server_ip, client->server_port,
                        strerror(so_error));
            }
            close(client->sock_fd);
            client->sock_fd = -1;
            errno = so_error;
            return -1;
        }
        
        /* Connection successful */
        client->is_connected = 1;
        if (LOG_LEVEL >= 2) {
            printf("[INFO] Connected to %s:%d\n", 
                   client->server_ip, client->server_port);
        }
        return 0;
    }
    
    /* Connect failed immediately */
    if (LOG_LEVEL >= 1) {
        fprintf(stderr, "[WARN] Connect failed to %s:%d: %s\n",
                client->server_ip, client->server_port, strerror(errno));
    }
    close(client->sock_fd);
    client->sock_fd = -1;
    return -1;
}

/* ==================== Public API Implementation ==================== */

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
                                     int auto_reconnect) {
    if (!server_ip || server_port <= 0 || server_port > 65535) {
        fprintf(stderr, "Invalid server_ip or server_port\n");
        return NULL;
    }
    
    struct tcp_client *client = malloc(sizeof(struct tcp_client));
    if (!client) {
        perror("malloc failed for tcp_client");
        return NULL;
    }
    
    /* Initialize */
    memset(client, 0, sizeof(struct tcp_client));
    strncpy(client->server_ip, server_ip, sizeof(client->server_ip) - 1);
    client->server_ip[sizeof(client->server_ip) - 1] = '\0';
    client->server_port = server_port;
    client->sock_fd = -1;
    client->is_connected = 0;
    client->is_nonblocking = 1;
    client->auto_reconnect = auto_reconnect;
    client->reconnect_retries = 0;
    client->reconnect_delay_ms = RECONNECT_INITIAL_DELAY_MS;
    client->last_reconnect_time = 0;
    client->send_buffer_len = 0;
    client->bytes_sent = 0;
    client->bytes_lost = 0;
    client->connect_count = 0;
    client->reconnect_count = 0;
    
    if (LOG_LEVEL >= 2) {
        printf("[INFO] TCP client initialized (server=%s:%d, auto_reconnect=%d)\n",
               server_ip, server_port, auto_reconnect);
    }
    
    return client;
}

/**
 * tcp_client_connect - Connect to relay server
 * 
 * @client: TCP client context
 * 
 * Returns: 0 on success, -1 on failure
 */
int tcp_client_connect(struct tcp_client *client) {
    if (!client) {
        errno = EINVAL;
        return -1;
    }
    
    if (client->is_connected) {
        if (LOG_LEVEL >= 3) {
            printf("[DEBUG] Already connected\n");
        }
        return 0;
    }
    
    if (LOG_LEVEL >= 2) {
        printf("[INFO] Connecting to %s:%d...\n", 
               client->server_ip, client->server_port);
    }
    
    int ret = tcp_client_try_connect(client);
    if (ret == 0) {
        /* Success */
        client->connect_count++;
        client->reconnect_retries = 0;
        client->reconnect_delay_ms = RECONNECT_INITIAL_DELAY_MS;
        return 0;
    }
    
    return -1;
}

/**
 * tcp_client_disconnect - Disconnect from relay server
 * 
 * @client: TCP client context
 */
void tcp_client_disconnect(struct tcp_client *client) {
    if (!client) {
        return;
    }
    
    if (client->sock_fd >= 0) {
        /* Flush any remaining data */
        if (client->send_buffer_len > 0) {
            tcp_client_flush(client);
        }
        
        close(client->sock_fd);
        client->sock_fd = -1;
    }
    
    client->is_connected = 0;
    
    if (LOG_LEVEL >= 2) {
        printf("[INFO] Disconnected from %s:%d\n", 
               client->server_ip, client->server_port);
    }
}

/**
 * tcp_client_reconnect - Reconnect with exponential backoff
 * 
 * @client: TCP client context
 * 
 * Returns: 0 on success, -1 if should not reconnect yet
 */
int tcp_client_reconnect(struct tcp_client *client) {
    if (!client) {
        return -1;
    }
    
    if (!client->auto_reconnect) {
        if (LOG_LEVEL >= 2) {
            printf("[INFO] Auto-reconnect disabled\n");
        }
        return -1;
    }
    
    /* Check if we should attempt reconnect (based on delay) */
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    __u64 now_ms = (__u64)now.tv_sec * 1000ULL + now.tv_nsec / 1000000ULL;
    
    if (client->last_reconnect_time > 0) {
        __u64 elapsed = now_ms - client->last_reconnect_time;
        if (elapsed < (__u64)client->reconnect_delay_ms) {
            /* Too early to reconnect */
            return -1;
        }
    }
    
    /* Update last reconnect time */
    client->last_reconnect_time = now_ms;
    
    /* Check max retries */
    if (client->reconnect_retries >= RECONNECT_MAX_RETRIES) {
        if (LOG_LEVEL >= 1) {
            fprintf(stderr, "[WARN] Max reconnect retries (%d) exceeded\n",
                    RECONNECT_MAX_RETRIES);
        }
        return -1;
    }
    
    if (LOG_LEVEL >= 2) {
        printf("[INFO] Reconnecting (attempt %d, delay=%dms)...\n",
               client->reconnect_retries + 1, client->reconnect_delay_ms);
    }
    
    /* Disconnect first */
    tcp_client_disconnect(client);
    
    /* Attempt reconnect */
    int ret = tcp_client_connect(client);
    
    if (ret == 0) {
        /* Success */
        client->reconnect_count++;
        client->reconnect_retries = 0;
        client->reconnect_delay_ms = RECONNECT_INITIAL_DELAY_MS;
        
        if (LOG_LEVEL >= 2) {
            printf("[INFO] Reconnected successfully\n");
        }
        
        return 0;
    } else {
        /* Failed - update backoff */
        client->reconnect_retries++;
        client->reconnect_delay_ms = calculate_backoff_delay(
            client->reconnect_retries,
            RECONNECT_INITIAL_DELAY_MS,
            RECONNECT_MAX_DELAY_MS
        );
        
        if (LOG_LEVEL >= 1) {
            fprintf(stderr, "[WARN] Reconnect failed (retry %d, next delay=%dms)\n",
                    client->reconnect_retries, client->reconnect_delay_ms);
        }
        
        return -1;
    }
}

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
                      const char *data, int len) {
    if (!client || !data || len <= 0) {
        errno = EINVAL;
        return -1;
    }
    
    if (!client->is_connected) {
        if (client->auto_reconnect) {
            tcp_client_reconnect(client);
        }
        if (!client->is_connected) {
            errno = ENOTCONN;
            return -1;
        }
    }
    
    /* Wrap data in HTTP POST request for data-ingest service */
    char http_buf[65536];
    int http_len = snprintf(http_buf, sizeof(http_buf),
        "POST /api/v1/ingest HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %d\r\n"
        "Connection: keep-alive\r\n"
        "\r\n%.*s",
        client->server_ip, len, len, data);
    
    if (http_len <= 0 || http_len >= (int)sizeof(http_buf)) {
        errno = EMSGSIZE;
        return -1;
    }

    /* Use send() with MSG_NOSIGNAL */
    int flags = MSG_NOSIGNAL;
    int total_sent = 0;
    
    while (total_sent < http_len) {
        int ret = send(client->sock_fd, http_buf + total_sent, http_len - total_sent, flags);
        
        if (ret < 0) {
            if (errno == EINTR) continue;
            
            if (errno == EPIPE || errno == ECONNRESET || errno == ENOTCONN) {
                if (LOG_LEVEL >= 1) {
                    fprintf(stderr, "[WARN] Connection lost during send: %s\n",
                            strerror(errno));
                }
                client->is_connected = 0;
                client->bytes_lost += (http_len - total_sent);
                if (client->auto_reconnect) {
                    tcp_client_reconnect(client);
                }
                return -1;
            }
            
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                fd_set write_fds;
                FD_ZERO(&write_fds);
                FD_SET(client->sock_fd, &write_fds);
                struct timeval timeout;
                timeout.tv_sec = 5;
                timeout.tv_usec = 0;
                int sel_ret = select(client->sock_fd + 1, NULL, &write_fds, NULL, &timeout);
                if (sel_ret > 0) continue;
                return total_sent > 0 ? total_sent : -1;
            }
            
            return total_sent > 0 ? total_sent : -1;
        }
        
        total_sent += ret;
    }
    
    client->bytes_sent += total_sent;
    
    /* Read HTTP response (non-blocking drain) */
    char resp_buf[1024];
    fd_set read_fds;
    FD_ZERO(&read_fds);
    FD_SET(client->sock_fd, &read_fds);
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 200000;
    if (select(client->sock_fd + 1, &read_fds, NULL, NULL, &tv) > 0) {
        recv(client->sock_fd, resp_buf, sizeof(resp_buf) - 1, 0);
    }
    
    return total_sent;
}

/**
 * tcp_client_send_line - Send a line (with \n delimiter)
 * 
 * @client: TCP client context
 * @line: Line to send (without \n)
 * 
 * Returns: Number of bytes sent, -1 on failure
 */
int tcp_client_send_line(struct tcp_client *client, const char *line) {
    if (!client || !line) {
        errno = EINVAL;
        return -1;
    }
    
    return tcp_client_send(client, line, strlen(line));
}

/**
 * tcp_client_flush - Flush send buffer
 * 
 * @client: TCP client context
 * 
 * Returns: Number of bytes flushed, -1 on failure
 * 
 * Note: This function sends any data in the internal send buffer.
 *       Currently, we don't use an internal buffer (send() directly),
 *       but this function is here for future use.
 */
int tcp_client_flush(struct tcp_client *client) {
    if (!client) {
        errno = EINVAL;
        return -1;
    }
    
    if (client->send_buffer_len <= 0) {
        return 0;  /* Nothing to flush */
    }
    
    int ret = tcp_client_send(client, client->send_buffer, 
                               client->send_buffer_len);
    
    if (ret > 0) {
        /* Partial send */
        if (ret < client->send_buffer_len) {
            memmove(client->send_buffer, client->send_buffer + ret,
                     client->send_buffer_len - ret);
            client->send_buffer_len -= ret;
        } else {
            client->send_buffer_len = 0;
        }
    }
    
    return ret;
}

/**
 * tcp_client_is_connected - Check if client is connected
 * 
 * @client: TCP client context
 * 
 * Returns: 1 if connected, 0 if not
 */
int tcp_client_is_connected(struct tcp_client *client) {
    if (!client) {
        return 0;
    }
    
    /* Verify socket is still connected */
    if (client->is_connected && client->sock_fd >= 0) {
        /* Try to peek to check connection */
        char peek_buf;
        int ret = recv(client->sock_fd, &peek_buf, 1, MSG_PEEK | MSG_DONTWAIT);
        if (ret == 0 || (ret < 0 && errno != EAGAIN && errno != EWOULDBLOCK)) {
            /* Connection closed or error */
            client->is_connected = 0;
            return 0;
        }
        return 1;
    }
    
    return 0;
}

/**
 * tcp_client_cleanup - Cleanup and free TCP client resources
 * 
 * @client: TCP client context
 */
void tcp_client_cleanup(struct tcp_client *client) {
    if (!client) {
        return;
    }
    
    /* Disconnect first */
    tcp_client_disconnect(client);
    
    /* Free client struct */
    free(client);
    
    if (LOG_LEVEL >= 2) {
        printf("[INFO] TCP client cleaned up\n");
    }
}

/* ==================== Statistics ==================== */

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
                            __u64 *reconnect_count) {
    if (!client) {
        if (bytes_sent) *bytes_sent = 0;
        if (bytes_lost) *bytes_lost = 0;
        if (connect_count) *connect_count = 0;
        if (reconnect_count) *reconnect_count = 0;
        return;
    }
    
    if (bytes_sent) *bytes_sent = client->bytes_sent;
    if (bytes_lost) *bytes_lost = client->bytes_lost;
    if (connect_count) *connect_count = client->connect_count;
    if (reconnect_count) *reconnect_count = client->reconnect_count;
}

/**
 * tcp_client_print_stats - Print TCP client statistics
 * 
 * @client: TCP client context
 */
void tcp_client_print_stats(struct tcp_client *client) {
    if (!client) {
        printf("TCP Client Statistics: N/A (client is NULL)\n");
        return;
    }
    
    printf("=== TCP Client Statistics ===\n");
    printf("Server: %s:%d\n", client->server_ip, client->server_port);
    printf("Connected: %s\n", client->is_connected ? "Yes" : "No");
    printf("Bytes sent: %llu\n", client->bytes_sent);
    printf("Bytes lost: %llu\n", client->bytes_lost);
    printf("Connect count: %llu\n", client->connect_count);
    printf("Reconnect count: %llu\n", client->reconnect_count);
    printf("Reconnect retries: %d\n", client->reconnect_retries);
    printf("Reconnect delay: %d ms\n", client->reconnect_delay_ms);
    printf("===========================\n");
}

/* ==================== Utility Functions ==================== */

/**
 * set_nonblocking - Set socket to non-blocking mode
 * 
 * @sock_fd: Socket file descriptor
 * 
 * Returns: 0 on success, -1 on failure
 */
int set_nonblocking(int sock_fd) {
    int flags = fcntl(sock_fd, F_GETFL, 0);
    if (flags < 0) {
        perror("fcntl(F_GETFL) failed");
        return -1;
    }
    
    if (fcntl(sock_fd, F_SETFL, flags | O_NONBLOCK) != 0) {
        perror("fcntl(F_SETFL) failed");
        return -1;
    }
    
    return 0;
}

/**
 * set_blocking - Set socket to blocking mode
 * 
 * @sock_fd: Socket file descriptor
 * 
 * Returns: 0 on success, -1 on failure
 */
int set_blocking(int sock_fd) {
    int flags = fcntl(sock_fd, F_GETFL, 0);
    if (flags < 0) {
        perror("fcntl(F_GETFL) failed");
        return -1;
    }
    
    if (fcntl(sock_fd, F_SETFL, flags & ~O_NONBLOCK) != 0) {
        perror("fcntl(F_SETFL) failed");
        return -1;
    }
    
    return 0;
}

/**
 * disable_sigpipe - Disable SIGPIPE signal for socket
 * 
 * @sock_fd: Socket file descriptor
 *
 * Returns: 0 on success, -1 on failure
 */
