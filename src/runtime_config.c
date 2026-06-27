/**
 * runtime_config.c - Runtime configuration implementation
 *
 * Reads STB_RELAY_IP, STB_RELAY_PORT, STB_PROBE_ID, STB_LOG_LEVEL from env.
 * Falls back to compile-time defaults in config.h.
 */

#include "runtime_config.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

void config_load_from_env(struct stb_config *cfg) {
    const char *v;

    strncpy(cfg->relay_server_ip, RELAY_SERVER_IP, sizeof(cfg->relay_server_ip) - 1);
    cfg->relay_server_port = RELAY_SERVER_PORT;
    strncpy(cfg->probe_id, PROBE_ID, sizeof(cfg->probe_id) - 1);
    cfg->log_level = LOG_LEVEL;

    v = getenv("STB_RELAY_IP");
    if (v && v[0]) strncpy(cfg->relay_server_ip, v, sizeof(cfg->relay_server_ip) - 1);

    v = getenv("STB_RELAY_PORT");
    if (v && v[0]) cfg->relay_server_port = atoi(v);

    v = getenv("STB_PROBE_ID");
    if (v && v[0]) strncpy(cfg->probe_id, v, sizeof(cfg->probe_id) - 1);

    v = getenv("STB_LOG_LEVEL");
    if (v && v[0]) cfg->log_level = atoi(v);

    printf("[INFO] Config: server=%s:%d probe_id=%s log=%d\n",
           cfg->relay_server_ip, cfg->relay_server_port,
           cfg->probe_id, cfg->log_level);
}
