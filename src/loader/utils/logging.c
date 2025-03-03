#include <loader/utils/logging.h>

/**
 * Prints a log message to stdout/stderr along with a file if specified.
 * 
 * @param req_lvl The required level for this message.
 * @param cur_lvl The current verbose level.
 * @param error If 1, sets pipe to stderr instead of stdout.
 * @param msg The log message.
 * @param args A VA list of arguments for the message.
 * 
 * @return void
 */
static void log_msgRaw(int req_lvl, int cur_lvl, int error, const char* log_path, const char* msg, va_list args)
{
    if (cur_lvl < req_lvl)
    {
        return;
    }

    FILE* pipe = stdout;

    if (error)
    {
        pipe = stderr;
    }

    // We need to format the message.
    va_list args_copy;
    va_copy(args_copy, args);
    int len = vsnprintf(NULL, 0, msg, args_copy);
    va_end(args_copy);

    if (len < 0)
    {
        return;
    }

    char f_msg[len + 1];
    vsnprintf(f_msg, sizeof(f_msg), msg, args);

    char full_msg[len + 6 + 1];
    snprintf(full_msg, sizeof(full_msg), "[%d] %s", req_lvl, f_msg);

    // If we're calculating stats, we need to prepend a new line.
    if (doing_stats)
    {
        printf("\033[F");
        
        fprintf(pipe, "\n%s\n", full_msg);

    }
    else
    {
        fprintf(pipe, "%s\n", full_msg);
    }

    if (log_path != NULL)
    {
        FILE* log_file = fopen(log_path, "a");

        if (!log_file)
        {
            return;
        }

        time_t now = time(NULL);
        struct tm* tm_val = localtime(&now);

        if (!tm_val)
        {
            fclose(log_file);

            return;
        }

        char log_file_msg[len + 22 + 1];

        snprintf(log_file_msg, sizeof(log_file_msg), "[%02d-%02d-%02d %02d:%02d:%02d]%s", tm_val->tm_year % 100, tm_val->tm_mon + 1, tm_val->tm_mday,
        tm_val->tm_hour, tm_val->tm_min, tm_val->tm_sec, full_msg);

        fprintf(log_file, "%s\n", log_file_msg);

        fclose(log_file);
    }
}

/**
 * Prints a log message using log_msgRaw().
 * 
 * @param cfg A pointer to the config structure.
 * @param req_lvl The required level for this message.
 * @param error Whether this is an error.
 * @param msg The log message with format support.
 * 
 * @return void
 */
void log_msg(config__t* cfg, int req_lvl, int error, const char* msg, ...)
{
    va_list args;
    va_start(args, msg);

    log_msgRaw(req_lvl, cfg->verbose, error, (const char*)cfg->log_file, msg, args);

    va_end(args);
}

/**
 * Polls the forward rules map ringbuffer.
 * 
 * @param rb A pointer to the ringbuffer.
 * 
 * @return void
 */
void poll_fwd_rules_rb(struct ring_buffer* rb)
{
    if (rb)
    {
        ring_buffer__poll(rb, RB_TIMEOUT);
    }
}

/**
 * Callback for BPF ringbuffer event (rules logging).
 * 
 * @param ctx The context (should be config__t*).
 * @param data The event data (should be fwd_rule_log_event_t*).
 * @param sz The event data size.
 * 
 * @return 0 on success or 1 on failure.
 */
int handle_fwd_rules_rb_event(void* ctx, void* data, size_t sz)
{
    config__t* cfg = (config__t*)ctx;
    fwd_rule_log_event_t* e = (fwd_rule_log_event_t*)data;

    u16 port = ntohs(e->port);

    char src_ip_str[INET6_ADDRSTRLEN];
    u16 src_port = ntohs(e->src_port);

    char bind_ip_str[INET6_ADDRSTRLEN];
    u16 bind_port = ntohs(e->bind_port);

    const char* protocol_str = get_protocol_str_by_id(e->protocol);

    char dst_ip_str[INET6_ADDRSTRLEN];
    u16 dst_port = ntohs(e->dst_port);

    inet_ntop(AF_INET, &e->src_ip, src_ip_str, sizeof(src_ip_str));
    inet_ntop(AF_INET, &e->bind_ip, bind_ip_str, sizeof(bind_ip_str));
    inet_ntop(AF_INET, &e->dst_ip, dst_ip_str, sizeof(dst_ip_str));

    log_msg(cfg, 0, 0, "[FWD] Created %s connection '%s:%d' => '%s:%d' (to '%s:%d'). Using source port %d...", protocol_str, src_ip_str, src_port, bind_ip_str, bind_port, dst_ip_str, dst_port, port);

    return 0;
}