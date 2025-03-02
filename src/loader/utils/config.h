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

    const char* bind_ip;
    u16 bind_port;
    const char* bind_protocol;

    const char* dst_ip;
    u16 dst_port;
} typedef fwd_rule_cfg_t;

struct config
{
    int verbose;
    char *log_file;
    char *interface;
    unsigned int pin_maps : 1;
    int update_time;
    unsigned int no_stats : 1;
    unsigned int stats_per_second : 1;
    int stdout_update_time;

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

void SetCfgDefaults(config__t *cfg);
void SetRuleDefaults(fwd_rule_cfg_t* rule);

void PrintConfig(config__t* cfg);
void PrintRule(fwd_rule_cfg_t* rule, int idx);

int LoadConfig(config__t *cfg, const char* cfg_file, config_overrides_t* overrides);
int SaveCfg(config__t* cfg, const char* file_path);

int OpenCfg(FILE** file, const char *file_name);
int CloseCfg(FILE* file);
int ReadCfg(FILE* file, char** buffer);
int ParseCfg(config__t *cfg, const char* data, config_overrides_t* overrides);

int GetNextAvailableFwdRuleIndex(config__t* cfg);

#include <loader/utils/logging.h>