#include <rule_del/utils/cli.h>

const struct option opts[] =
{
    { "cfg", required_argument, NULL, 'c' },
    { "help", no_argument, NULL, 'h' },

    { "save", no_argument, NULL, 's' },

    { NULL, 0, NULL, 0 }
};

void ParseCli(cli_t* cli, int argc, char* argv[])
{
    int c;

    while ((c = getopt_long(argc, argv, "c:hs", opts, NULL)) != -1)
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
            
            case '?':
                fprintf(stderr, "Missing argument option...\n");

                break;

            default:
                break;
        }
    }
}