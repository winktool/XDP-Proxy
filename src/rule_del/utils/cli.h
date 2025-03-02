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
    const char* bind_protocol;
} typedef cli_t;

void ParseCli(cli_t* cmd, int argc, char* argv[]);