#include <loader/utils/config.h>

/**
 * Loads the config from the file system.
 * 
 * @param cfg A pointer to the config structure.
 * @param cfg_file The path to the config file.
 * @param overrides Overrides to use instead of config values.
 * 
 * @return 0 on success or 1 on error.
 */
int LoadConfig(config__t *cfg, const char* cfg_file, config_overrides_t* overrides)
{
    int ret;
    
    FILE *file = NULL;
    
    // Open config file.
    if ((ret = OpenCfg(&file, cfg_file)) != 0 || file == NULL)
    {
        fprintf(stderr, "Error opening config file.\n");
        
        return ret;
    }

    SetCfgDefaults(cfg);

    memset(cfg->rules, 0, sizeof(cfg->rules));

    char* buffer = NULL;

    // Read config.
    if ((ret = ReadCfg(file, &buffer)) != 0)
    {
        fprintf(stderr, "Error reading config file.\n");

        CloseCfg(file);

        return ret;
    }

    // Parse config.
    if ((ret = ParseCfg(cfg, buffer, overrides)) != 0)
    {
        fprintf(stderr, "Error parsing config file.\n");

        CloseCfg(file);

        return ret;
    }

    free(buffer);

    if ((ret = CloseCfg(file)) != 0)
    {
        fprintf(stderr, "Error closing config file.\n");

        return ret;
    }

    return EXIT_SUCCESS;
}

/**
 * Opens the config file.
 * 
 * @param file_name Path to config file.
 * 
 * @return 0 on success or 1 on error.
 */
int OpenCfg(FILE** file, const char *file_name)
{
    // Close any existing files.
    if (*file != NULL)
    {
        fclose(*file);

        *file = NULL;
    }

    *file = fopen(file_name, "r");

    if (*file == NULL)
    {
        return 1;
    }

    return 0;
}

/**
 * Close config file.
 * 
 * @param file A pointer to the file to close.
 * 
 * @param return 0 on success or error value of fclose().
 */
int CloseCfg(FILE* file)
{
    return fclose(file);
}

/**
 * Reads contents from the config file.
 * 
 * @param file The file pointer.
 * @param buffer The buffer to store the data in (manually allocated).
 */
int ReadCfg(FILE* file, char** buffer)
{
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    rewind(file);

    if (file_size <= 0)
    {
        return 1;
    }

    *buffer = malloc(file_size + 1);

    if (*buffer == NULL)
    {
        return 1;
    }

    size_t read = fread(*buffer, 1, file_size, file);
    (*buffer)[read] = '\0';

    return 0;
}

/**
 * Read the config file and stores values in config structure.
 * 
 * @param cfg A pointer to the config structure.
 * @param data The config data.
 * @param overrides Overrides to use instead of config values.
 * 
 * @return 0 on success or 1/-1 on error.
 */
int ParseCfg(config__t *cfg, const char* data, config_overrides_t* overrides)
{
    // Initialize config.
    config_t conf;
    config_setting_t *setting;

    config_init(&conf);

    // Attempt to read the config.
    if (config_read_string(&conf, data) == CONFIG_FALSE)
    {
        LogMsg(cfg, 0, 1, "Error from LibConfig when reading file - %s (Line %d)", config_error_text(&conf), config_error_line(&conf));

        config_destroy(&conf);

        return EXIT_FAILURE;
    }

    int verbose;

    if (config_lookup_int(&conf, "verbose", &verbose) == CONFIG_TRUE || (overrides && overrides->verbose > -1))
    {
        if (overrides && overrides->verbose > -1)
        {
            cfg->verbose = overrides->verbose;
        }
        else
        {
            cfg->verbose = verbose;
        }
    }

    const char* log_file;

    if (config_lookup_string(&conf, "log_file", &log_file) == CONFIG_TRUE || (overrides && overrides->log_file != NULL))
    {
        // We must free previous value to prevent memory leak.
        if (cfg->log_file != NULL)
        {
            free(cfg->log_file);
            cfg->log_file = NULL;
        }

        if (overrides && overrides->log_file != NULL)
        {
            if (strlen(overrides->log_file) > 0)
            {
                cfg->log_file = strdup(overrides->log_file);
                
            }
            else
            {
                cfg->log_file = NULL;
            }
        }
        else
        {
            if (strlen(log_file) > 0)
            {
                cfg->log_file = strdup(log_file);
            }
            else
            {
                cfg->log_file = NULL;
            }
        }
    }

    // Get interface.
    const char *interface;

    if (config_lookup_string(&conf, "interface", &interface) == CONFIG_TRUE || (overrides && overrides->interface != NULL))
    {
        // We must free previous value to prevent memory leak.
        if (cfg->interface != NULL)
        {
            free(cfg->interface);
            cfg->interface = NULL;
        }

        if (overrides && overrides->interface != NULL)
        {
            cfg->interface = strdup(overrides->interface);
        }
        else
        {
            cfg->interface = strdup(interface);
        }
    }

    // Pin BPF maps.
    int pin_maps;

    if (config_lookup_bool(&conf, "pin_maps", &pin_maps) == CONFIG_TRUE || (overrides && overrides->pin_maps > -1))
    {
        if (overrides && overrides->pin_maps > -1)
        {
            cfg->pin_maps = overrides->pin_maps;
        }
        else
        {
            cfg->pin_maps = pin_maps;
        }
    }

    // Get auto update time.
    int update_time;

    if (config_lookup_int(&conf, "update_time", &update_time) == CONFIG_TRUE || (overrides && overrides->update_time > -1))
    {
        if (overrides && overrides->update_time > -1)
        {
            cfg->update_time = overrides->update_time;
        }
        else
        {
            cfg->update_time = update_time;
        }
    }

    // Get no stats.
    int no_stats;

    if (config_lookup_bool(&conf, "no_stats", &no_stats) == CONFIG_TRUE || (overrides && overrides->no_stats > -1))
    {
        if (overrides && overrides->no_stats > -1)
        {
            cfg->no_stats = overrides->no_stats;
        }
        else
        {
            cfg->no_stats = no_stats;
        }
    }

    // Stats per second.
    int stats_per_second;

    if (config_lookup_bool(&conf, "stats_per_second", &stats_per_second) == CONFIG_TRUE || (overrides && overrides->stats_per_second > -1))
    {
        if (overrides && overrides->stats_per_second > -1)
        {
            cfg->stats_per_second = overrides->stats_per_second;
        }
        else
        {
            cfg->stats_per_second = stats_per_second;
        }
    }

    // Get stdout update time.
    int stdout_update_time;

    if (config_lookup_int(&conf, "stdout_update_time", &stdout_update_time) == CONFIG_TRUE || (overrides && overrides->stdout_update_time > -1))
    {
        if (overrides && overrides->stdout_update_time > -1)
        {
            cfg->stdout_update_time = overrides->stdout_update_time;
        }
        else
        {
            cfg->stdout_update_time = stdout_update_time;
        }
    }

    // Read forward rules.
    setting = config_lookup(&conf, "rules");

    if (setting && config_setting_is_list(setting))
    {
        for (int i = 0; i < config_setting_length(setting); i++)
        {
            fwd_rule_cfg_t* rule = &cfg->rules[i];

            config_setting_t* rule_cfg = config_setting_get_elem(setting, i);

            if (rule == NULL || rule_cfg == NULL)
            {
                LogMsg(cfg, 0, 1, "[WARNING] Failed to read forward rule at index #%d. 'rule' or 'rule_cfg' is NULL (make sure you didn't exceed the maximum rules allowed!)...");

                continue;
            }

            // Enabled.
            int enabled;

            if (config_setting_lookup_bool(rule_cfg, "enabled",  &enabled) == CONFIG_TRUE)
            {
                rule->enabled = enabled;
            }

            // Log.
            int log;

            if (config_setting_lookup_bool(rule_cfg, "log", &log) == CONFIG_TRUE)
            {
                rule->log = log;
            }

            // Bind IP.
            const char* bind_ip;

            if (config_setting_lookup_string(rule_cfg, "bind_ip", &bind_ip) == CONFIG_TRUE)
            {
                rule->bind_ip = strdup(bind_ip);
            }

            // Bind port.
            int bind_port;

            if (config_setting_lookup_int(rule_cfg, "bind_port", &bind_port) == CONFIG_TRUE)
            {
                rule->bind_port = bind_port;
            }

            // Bind protocol.
            const char* bind_protocol;

            if (config_setting_lookup_string(rule_cfg, "bind_protocol", &bind_protocol) == CONFIG_TRUE)
            {
                rule->bind_protocol = strdup(bind_protocol);
            }

            // Destination IP.
            const char* dst_ip;

            if (config_setting_lookup_string(rule_cfg, "dst_ip", &dst_ip) == CONFIG_TRUE)
            {
                rule->dst_ip = strdup(dst_ip);
            }

            // Destination port.
            int dst_port;

            if (config_setting_lookup_int(rule_cfg, "dst_port", &dst_port) == CONFIG_TRUE)
            {
                rule->dst_port = dst_port;
            }

            rule->set = 1;
        }
    }

    config_destroy(&conf);

    return EXIT_SUCCESS;
}

/**
 * Saves config to file system.
 * 
 * @param cfg A pointer to the config.
 * @param file_path The file path to store the config into.
 * 
 * @param return 0 on success or 1 on failure.
 */
int SaveCfg(config__t* cfg, const char* file_path)
{
    config_t conf;
    config_setting_t *root, *setting;

    FILE* file;

    config_init(&conf);
    root = config_root_setting(&conf);

    // Add verbose.
    setting = config_setting_add(root, "verbose", CONFIG_TYPE_INT);
    config_setting_set_int(setting, cfg->verbose);

    // Add log file.
    if (cfg->log_file)
    {
        setting = config_setting_add(root, "log_file", CONFIG_TYPE_STRING);
        config_setting_set_string(setting, cfg->log_file);
    }

    // Add interface.
    if (cfg->interface)
    {
        setting = config_setting_add(root, "interface", CONFIG_TYPE_STRING);
        config_setting_set_string(setting, cfg->interface);
    }

    // Add pin maps.
    setting = config_setting_add(root, "pin_maps", CONFIG_TYPE_BOOL);
    config_setting_set_bool(setting, cfg->pin_maps);

    // Add update time.
    setting = config_setting_add(root, "update_time", CONFIG_TYPE_INT);
    config_setting_set_int(setting, cfg->update_time);

    // Add no stats.
    setting = config_setting_add(root, "no_stats", CONFIG_TYPE_BOOL);
    config_setting_set_bool(setting, cfg->no_stats);

    // Add stats per second.
    setting = config_setting_add(root, "stats_per_second", CONFIG_TYPE_BOOL);
    config_setting_set_bool(setting, cfg->stats_per_second);

    // Add stdout update time.
    setting = config_setting_add(root, "stdout_update_time", CONFIG_TYPE_INT);
    config_setting_set_int(setting, cfg->stdout_update_time);

    // Add forward rules.
    config_setting_t* rules = config_setting_add(root, "rules", CONFIG_TYPE_LIST);

    if (rules)
    {
        for (int i = 0; i < MAX_FWD_RULES; i++)
        {
            fwd_rule_cfg_t* rule = &cfg->rules[i];

            if (!rule->set)
            {
                continue;
            }

            config_setting_t* rule_cfg = config_setting_add(rules, NULL, CONFIG_TYPE_GROUP);

            if (rule_cfg)
            {
                // Add enabled setting.
                config_setting_t* enabled = config_setting_add(rule_cfg, "enabled", CONFIG_TYPE_BOOL);
                config_setting_set_bool(enabled, rule->enabled);

                // Add log setting.
                config_setting_t* log = config_setting_add(rule_cfg, "log", CONFIG_TYPE_BOOL);
                config_setting_set_bool(log, rule->log);

                // Add bind IP.
                if (rule->bind_ip)
                {
                    config_setting_t* bind_ip = config_setting_add(rule_cfg, "bind_p", CONFIG_TYPE_STRING);
                    config_setting_set_string(bind_ip, rule->bind_ip);
                }

                // Add bind port.
                config_setting_t* bind_port = config_setting_add(rule_cfg, "bind_port", CONFIG_TYPE_INT);
                config_setting_set_int(bind_port, rule->bind_port);

                // Add bind protocol.
                if (rule->bind_protocol)
                {
                    config_setting_t* bind_protocol = config_setting_add(rule_cfg, "bind_protocol", CONFIG_TYPE_STRING);
                    config_setting_set_string(bind_protocol, rule->bind_protocol);
                }

                // Add destination IP.
                if (rule->dst_ip)
                {
                    config_setting_t* dst_ip = config_setting_add(rule_cfg, "dst_ip", CONFIG_TYPE_STRING);
                    config_setting_set_string(dst_ip, rule->dst_ip);
                }

                // Add destination port.
                config_setting_t* dst_port = config_setting_add(rule_cfg, "dst_port", CONFIG_TYPE_INT);
                config_setting_set_int(dst_port, rule->dst_port);
            }
        }
    }

    // Write config to file.
    file = fopen(file_path, "w");

    if (!file)
    {
        config_destroy(&conf);

        return 1;
    }

    config_write(&conf, file);

    fclose(file);
    config_destroy(&conf);

    return 0;
}

/**
 * Sets the default values for a forward rule.
 * 
 * @param rule A pointer to the forward rule.
 * 
 * @return void
 */
void SetRuleDefaults(fwd_rule_cfg_t* rule)
{
    rule->set = 0;
    rule->enabled = 1;

    rule->log = 0;

    if (rule->bind_ip)
    {
        free((void*)rule->bind_ip);
    }

    rule->bind_ip = NULL;

    rule->bind_port = 0;

    if (rule->bind_protocol)
    {
        free((void*)rule->bind_protocol);
    }

    rule->bind_protocol = NULL;

    if (rule->dst_ip)
    {
        free((void*)rule->dst_ip);
    }

    rule->dst_ip = NULL;

    rule->dst_port = 0;
}

/**
 * Sets the config structure's default values.
 * 
 * @param cfg A pointer to the config structure.
 * 
 * @return void
 */
void SetCfgDefaults(config__t* cfg)
{
    cfg->verbose = 2;
    cfg->log_file = strdup("/var/log/xdpfw.log");
    cfg->update_time = 0;
    cfg->interface = NULL;
    cfg->pin_maps = 1;
    cfg->no_stats = 0;
    cfg->stats_per_second = 0;
    cfg->stdout_update_time = 1000;

    for (int i = 0; i < MAX_FWD_RULES; i++)
    {
        fwd_rule_cfg_t* rule = &cfg->rules[i];

        SetRuleDefaults(rule);
    }
}

/**
 * Prints a forward rule.
 * 
 * @param rule A pointer to the forward rule.
 * @param idx The current index.
 * 
 * @return void
 */
void PrintRule(fwd_rule_cfg_t* rule, int idx)
{
    printf("\tRule #%d\n", idx);
    printf("\t\tEnabled => %d\n", rule->enabled);
    printf("\t\tLog => %d\n\n", rule->log);

    printf("\t\tBind IP => %s\n", rule->bind_ip);
    printf("\t\tBind Port => %d\n", rule->bind_port);
    printf("\t\tBind Protocol => %s\n\n", rule->bind_protocol);

    printf("\t\tDestination IP => %s\n", rule->dst_ip);
    printf("\t\tDestination Port => %d\n", rule->dst_port);
}

/**
 * Prints config settings.
 * 
 * @param cfg A pointer to the config structure.
 * 
 * @return void
 */
void PrintConfig(config__t* cfg)
{
    char* interface = "N/A";

    if (cfg->interface != NULL)
    {
        interface = cfg->interface;
    }

    char* log_file = "N/A";

    if (cfg->log_file != NULL)
    {
        log_file = cfg->log_file;
    }

    printf("Printing config...\n");
    printf("General Settings\n");
    
    printf("\tVerbose => %d\n", cfg->verbose);
    printf("\tLog File => %s\n", log_file);
    printf("\tInterface Name => %s\n", interface);
    printf("\tPin BPF Maps => %d\n", cfg->pin_maps);
    printf("\tUpdate Time => %d\n", cfg->update_time);
    printf("\tNo Stats => %d\n", cfg->no_stats);
    printf("\tStats Per Second => %d\n", cfg->stats_per_second);
    printf("\tStdout Update Time => %d\n\n", cfg->stdout_update_time);

    printf("Rules\n");

    for (int i = 0; i < MAX_FWD_RULES; i++)
    {
        fwd_rule_cfg_t* rule = &cfg->rules[i];

        if (!rule->set)
        {
            break;
        }

        PrintRule(rule, i + 1);

        printf("\n\n");
    }
}

/**
 * Retrieves next available rule index.
 * 
 * @param cfg A pointer to the config structure.
 * 
 * @return The next available index or -1 if there are no available indexes.
 */
int GetNextAvailableRuleIndex(config__t* cfg)
{
    for (int i = 0; i < MAX_FWD_RULES; i++)
    {
        fwd_rule_cfg_t* rule = &cfg->rules[i];

        if (rule->set)
        {
            continue;
        }

        return i;
    }

    return -1;
}