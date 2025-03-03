#pragma once

#include <common/all.h>

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>

#include <string.h>

struct cli
{
    const char* cfg_file;
    int help;
    int save;

    int enabled;
    int log;

    const char* bind_ip;
    int bind_port;
    const char* protocol;

    const char* dst_ip;
    int dst_port;
} typedef cli_t;

void parse_cli(cli_t* cmd, int argc, char* argv[]);