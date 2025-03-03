#include <common/all.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <loader/utils/xdp.h>
#include <loader/utils/config.h>

#include <rule_del/utils/cli.h>

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

    parse_cli(&cli, argc, argv);

    if (!cli.help)
    {
        printf("Parsed command line...\n");
    }
    else
    {
        printf("Usage: xdpfwd-del [OPTIONS]\n\n");

        printf("OPTIONS:\n");
        printf("  -c, --cfg <file>                  The path to the config file (default /etc/xdpfwd/xdpfwd.conf).\n");
        printf("  -s, --save                        Saves the new config to file system.\n");
        printf("  -h, --help                        Prints this help message.\n\n");

        printf("  -b, --bind-ip <ip>                The bind IP address of the forward rule to delete.\n");
        printf("  -x, --bind-port <port>            The bind port of the forward rule to delete.\n");
        printf("  -p, --protocol <tcp/udp/icmp>     The protocol of the forward rule to delete.\n");

        return EXIT_SUCCESS;
    }

    // Check for config file path.
    if (cli.save && (!cli.cfg_file || strlen(cli.cfg_file) < 1))
    {
        fprintf(stderr, "[ERROR] CFG file not specified or empty. This is required for current mode or options set.\n");

        return EXIT_FAILURE;
    }

    if (!cli.bind_ip)
    {
        fprintf(stderr, "[ERROR] Bind IP is required! Please use -b, --bind-ip CLI arguments.\n");

        return EXIT_FAILURE;
    }

    if (!cli.protocol)
    {
        fprintf(stderr, "[ERROR] Protocol is required! Please use -p, --protocol CLI arguments.\n");

        return EXIT_FAILURE;
    }

    char bind_ip[INET_ADDRSTRLEN];
    strncpy(bind_ip, cli.bind_ip, sizeof(bind_ip) - 1);
    bind_ip[sizeof(bind_ip) - 1] = '\0';

    char protocol[24];
    strncpy(protocol, cli.protocol, sizeof(protocol) - 1);
    protocol[sizeof(protocol) - 1] = '\0';

    int map_fwd_rules = get_map_pin_fd(XDP_MAP_PIN_DIR, "map_fwd_rules");

    if (map_fwd_rules < 0)
    {
        fprintf(stderr, "[ERROR] Failed to find 'map_fwd_rules' map.\n");

        return EXIT_FAILURE;
    }

    fwd_rule_cfg_t rule = {0};
    rule.bind_ip = strdup(bind_ip);
    rule.bind_port = cli.bind_port;
    rule.protocol = strdup(protocol);

    if ((ret = delete_fwd_rule(map_fwd_rules, &rule)) != 0)
    {
        fprintf(stderr, "[ERROR] Failed to delete forward rule '%s:%d' (%s) (%d).\n", bind_ip, cli.bind_port, protocol, ret);

        if (!cli.save)
        {
            return EXIT_FAILURE;
        }
    }
    else
    {
        printf("Deleted forward rule '%s:%d' (%s)!\n", bind_ip, cli.bind_port, protocol);
    }

    if (cli.save)
    {
        config__t cfg = {0};
    
        if ((ret = load_config(&cfg, cli.cfg_file, NULL)) != 0)
        {
            fprintf(stderr, "[ERROR] Failed to load config at '%s' (%d)\n", cli.cfg_file, ret);

            return EXIT_FAILURE;
        }

        printf("Loaded config...\n");

        int idx = get_fwd_rule_index(&cfg, bind_ip, cli.bind_port, protocol);

        if (idx < 0)
        {
            printf("[WARNING] Failed to find forward rule in config file. Not saving config.\n");
        }
        else
        {
            fwd_rule_cfg_t* rule = &cfg.rules[idx];
            set_fwd_rule_defaults(rule);

            // Save config.
            printf("Saving config...\n");

            if ((ret = save_cfg(&cfg, cli.cfg_file)) != 0)
            {
                fprintf(stderr, "[ERROR] Failed to save config.\n");

                return EXIT_FAILURE;
            }
        }
    }

    printf("Success! Exiting.\n");

    return EXIT_SUCCESS;
}