#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>

struct cli
{
    const char* cfg_file;
    int help;
    int save;

    const char* bind_ip;
    int bind_port;
    const char* protocol;
} typedef cli_t;

void parse_cli(cli_t* cli, int argc, char* argv[]);