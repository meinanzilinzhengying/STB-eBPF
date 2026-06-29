/**
 * runtime_config.h - Runtime configuration (env var overrides)
 *
 * Supports: STB_RELAY_IP, STB_RELAY_PORT, STB_PROBE_ID, STB_LOG_LEVEL
 */

#ifndef _STB_RUNTIME_CONFIG_H
#define _STB_RUNTIME_CONFIG_H

#include "config.h"

struct stb_config {
    char relay_server_ip[64];
    int relay_server_port;
    char probe_id[64];
    int log_level;
};

void config_load_from_env(struct stb_config *cfg);

#endif /* _STB_RUNTIME_CONFIG_H */
