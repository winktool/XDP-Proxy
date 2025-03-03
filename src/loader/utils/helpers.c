#include <loader/utils/helpers.h>

/**
 * Prints help menu.
 * 
 * @return void
 */
void print_help_menu()
{
    printf("Usage: xdpfwd [OPTIONS]\n\n");

    printf("  -c, --config <file>           Config file location (default: /etc/xdpfwd/xdpfwd.conf).\n");
    printf("  -o, --offload                 Load the XDP program in hardware/offload mode.\n");
    printf("  -s, --skb                     Force the XDP program to load with SKB mode instead of DRV.\n");
    printf("  -t, --time <seconds>          Duration to run the program (seconds). 0 or unset = infinite.\n");
    printf("  -l, --list                    Print config details including rules (exits after execution).\n");
    printf("  -h, --help                    Show this help message.\n\n");
    
    printf("  -v, --verbose <lvl>           Override config's verbose value.\n");
    printf("      --log-file <file>         Override config's log file value.\n");
    printf("  -i, --interface <name>        Override config's interface value.\n");
    printf("  -u, --update-time <time>      Override config's update time value.\n");
    printf("  -n, --no-stats <1/0>          Override config's no stats value.\n");
    printf("      --stats-ps <1/0>          Override config's stats per second value.\n");
    printf("      --stdout-ut <time>        Override config's stdout update time value.\n");
}

/**
 * Handles signals from user.
 * 
 * @param code Signal code.
 * 
 * @return void
 */
void signal_hndl(int code)
{
    cont = 0;
}

/**
 * Parses an IP string with CIDR support. Stores IP in network byte order in ip.ip and CIDR in ip.cidr.
 * 
 * @param ip The IP string.
 * 
 * @return Returns an IP structure with IP and CIDR. 
 */
ip_range_t parse_ip_range(const char *ip)
{
    ip_range_t ret = {0};
    ret.cidr = 32;

    char ip_copy[INET_ADDRSTRLEN + 3];
    strncpy(ip_copy, ip, sizeof(ip_copy) - 1);
    ip_copy[sizeof(ip_copy) - 1] = '\0';

    char *token = strtok((char *) ip_copy, "/");

    if (token)
    {
        ret.ip = inet_addr(token);

        token = strtok(NULL, "/");

        if (token)
        {
            ret.cidr = (u8) strtoul(token, NULL, 10);
        }
    }

    return ret;
}

/**
 * Retrieves protocol name by ID.
 * 
 * @param id The protocol ID
 * 
 * @return The protocol string. 
 */
const char* get_protocol_str_by_id(int id)
{
    switch (id)
    {
        case IPPROTO_TCP:
            return "TCP";

        case IPPROTO_UDP:
            return "UDP";
        
        case IPPROTO_ICMP:
            return "ICMP";
    }

    return "N/A";
}

/**
 * Retrieves the protocol ID by name.
 * 
 * @param name The protocol name.
 * 
 * @return The protocol ID or -1 on failure.
 */
int get_protocol_id_by_str(char* name)
{
    lower_str(name);

    if (strcmp(name, "tcp") == 0)
    {
        return IPPROTO_TCP;
    }
    else if (strcmp(name, "udp") == 0)
    {
        return IPPROTO_UDP;
    }
    else if (strcmp(name, "icmp") == 0)
    {
        return IPPROTO_ICMP;
    }

    return -1;
}

/**
 * Prints tool name and author.
 * 
 * @return void
 */
void print_tool_info()
{
    printf(" __  ______  ____    ____                      \n");
    printf(" \\ \\/ /  _ \\|  _ \\  |  _ \\ _ __ _____  ___   _ \n");
    printf("  \\  /| | | | |_) | | |_) | '__/ _ \\ \\/ / | | |\n");
    printf("  /  \\| |_| |  __/  |  __/| | | (_) >  <| |_| |\n");
    printf(" /_/\\_\\____/|_|     |_|   |_|  \\___/_/\\_\\\\__, |\n");
    printf("                                         |___/ \n\n");
}

/**
 * Retrieves nanoseconds since system boot.
 * 
 * @return The current nanoseconds since the system last booted.
 */
u64 get_boot_nano_time()
{
    struct sysinfo sys;
    sysinfo(&sys);

    return sys.uptime * 1e9;
}

/**
 * Simply lower-cases a string.
 * 
 * @param str Pointer to the full string we want to lower-case.
 * 
 * @return void
 */
void lower_str(char *str) 
{
    for (char *p = str; *p; p++) 
    {
        *p = tolower(*p);
    }
}
