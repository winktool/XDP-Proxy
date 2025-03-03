#include <rule_del/utils/cli.h>

const struct option opts[] =
{
    { "cfg", required_argument, NULL, 'c' },
    { "help", no_argument, NULL, 'h' },
    { "save", no_argument, NULL, 's' },

    { "bind-ip", required_argument, NULL, 'b' },
    { "bind-port", required_argument, NULL, 'x' },
    { "protocol", required_argument, NULL, 'p' },

    { NULL, 0, NULL, 0 }
};

void parse_cli(cli_t* cli, int argc, char* argv[])
{
    int c;

    while ((c = getopt_long(argc, argv, "c:hsb:x:p:", opts, NULL)) != -1)
    {
        switch (c)
        {
            case 'c':
                cli->cfg_file = optarg;

                break;

            case 'h':
                cli->help = 1;

                break;

            case 's':
                cli->save = 1;

                break;

            case 'b':
                cli->bind_ip = optarg;

                break;

            case 'x':
                cli->bind_port = atoi(optarg);

                break;

            case 'p':
                cli->protocol = optarg;

                break;
            
            case '?':
                fprintf(stderr, "Missing argument option...\n");

                break;

            default:
                break;
        }
    }
}