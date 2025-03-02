#include <common/all.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <loader/utils/xdp.h>
#include <loader/utils/config.h>

#include <rule_add/utils/cli.h>

// These are required due to being extern with Loader.
// To Do: Figure out a way to not require the below without requiring separate object files.
int cont = 0;
int doing_stats = 0;

int main(int argc, char *argv[])
{
    int ret;

    // Parse command line.
    cli_t cli = {0};
    cli.cfg_file = CONFIG_DEFAULT_PATH;

    ParseCli(&cli, argc, argv);

    if (!cli.help)
    {
        printf("Parsed command line...\n");
    }
    else
    {
        printf("Usage: xdpfw-add [OPTIONS]\n\n");

        printf("OPTIONS:\n");
        printf("  -c, --cfg         The path to the config file (default /etc/xdpfw/xdpfw.conf).\n");
        printf("  -s, --save        Saves the new config to file system.\n");

        return EXIT_SUCCESS;
    }

    // Check for config file path.
    if (cli.save && (!cli.cfg_file || strlen(cli.cfg_file) < 1))
    {
        fprintf(stderr, "[ERROR] CFG file not specified or empty.\n");

        return EXIT_FAILURE;
    }

    // Load config.
    config__t cfg = {0};
    
    if (cli.save)
    {
        if ((ret = LoadConfig(&cfg, cli.cfg_file, NULL)) != 0)
        {
            fprintf(stderr, "[ERROR] Failed to load config at '%s' (%d)\n", cli.cfg_file, ret);

            return EXIT_FAILURE;
        }

        printf("Loaded config...\n");
    }

    if (cli.save)
    {
        // Save config.
        printf("Saving config...\n");

        if ((ret = SaveCfg(&cfg, cli.cfg_file)) != 0)
        {
            fprintf(stderr, "[ERROR] Failed to save config.\n");

            return EXIT_FAILURE;
        }
    }

    printf("Success! Exiting.\n");

    return EXIT_SUCCESS;
}