#pragma once

#include <common/all.h>

#include <stdio.h>
#include <stdlib.h>
#include <libconfig.h>
#include <string.h>

#include <arpa/inet.h>

#include <loader/utils/helpers.h>

#define CONFIG_DEFAULT_PATH "/etc/xdpfwd/xdpfwd.conf"

struct fwd_rule_cfg
{
    int set;
    int enabled;
    int log;

    char* bind_ip;
    u16 bind_port;
    char* protocol;

    char* dst_ip;
    u16 dst_port;
} typedef fwd_rule_cfg_t;

struct config
{
    int verbose;
    char *log_file;
    unsigned int pin_maps : 1;
    int update_time;
    unsigned int no_stats : 1;
    unsigned int stats_per_second : 1;
    int stdout_update_time;

    int interfaces_cnt;
    char* interfaces[MAX_INTERFACES];

    int rules_cnt;
    fwd_rule_cfg_t rules[MAX_FWD_RULES];
} typedef config__t; // config_t is taken by libconfig -.-

struct config_overrides
{
    int verbose;
    const char* log_file;
    const char* interface;
    int pin_maps;
    int update_time;
    int no_stats;
    int stats_per_second;
    int stdout_update_time;
} typedef config_overrides_t;

void set_cfg_defaults(config__t *cfg);
void set_fwd_rule_defaults(fwd_rule_cfg_t* rule);

void print_config(config__t* cfg);
void print_fwd_rule(fwd_rule_cfg_t* rule, int idx);

int load_config(config__t *cfg, const char* cfg_file, config_overrides_t* overrides);
int save_cfg(config__t* cfg, const char* file_path);

int open_cfg(FILE** file, const char *file_name);
int close_cfg(FILE* file);
int read_cfg(FILE* file, char** buffer);
int parse_cfg(config__t *cfg, const char* data, config_overrides_t* overrides);

int get_next_available_fwd_rule_index(config__t* cfg);

int get_fwd_rule_index(config__t* cfg, const char* bind_ip, u16 bind_port, const char* protocol);

#include <loader/utils/logging.h>