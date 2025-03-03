#include <loader/utils/stats.h>

struct timespec last_update_time = {0};

u64 last_forwarded = 0;
u64 last_passed = 0;
u64 last_dropped = 0;

/**
 * Calculates and displays packet counters/stats.
 * 
 * @param map_stats The stats map BPF FD.
 * @param cpus The amount of CPUs the host has.
 * @param per_second Calculate packet counters per second (PPS).
 * 
 * @return 0 on success or 1 on failure.
 */
int calc_stats(int map_stats, int cpus, int per_second)
{
    u32 key = 0;

    stats_t stats[MAX_CPUS];
    memset(stats, 0, sizeof(stats));

    u64 forwarded = 0;
    u64 passed = 0;
    u64 dropped = 0;
    
    if (bpf_map_lookup_elem(map_stats, &key, stats) != 0)
    {
        return EXIT_FAILURE;
    }

    for (int i = 0; i < cpus; i++)
    {
        if (&stats[i] == NULL)
        {
            continue;
        }

        forwarded += stats[i].forwarded;
        passed += stats[i].passed;
        dropped += stats[i].dropped;
    }

    u64 forwarded_val = forwarded;
    u64 passed_val = passed;
    u64 dropped_val = dropped;

    if (per_second)
    {
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        
        double elapsed_time = (now.tv_sec - last_update_time.tv_sec) +
                              (now.tv_nsec - last_update_time.tv_nsec) / 1e9; 

        if (elapsed_time > 0)
        {
            forwarded_val = (forwarded - last_forwarded) / elapsed_time;
            passed_val = (passed - last_passed) / elapsed_time;
            dropped_val = (dropped - last_dropped) / elapsed_time;
        }

        last_forwarded = forwarded;
        last_passed = passed;
        last_dropped = dropped;

        last_update_time = now;
    }

    char forwarded_str[12];
    char passed_str[12];
    char dropped_str[12];

    if (per_second)
    {
        snprintf(forwarded_str, sizeof(forwarded_str), "%llu PPS", forwarded_val);
        snprintf(passed_str, sizeof(passed_str), "%llu PPS", passed_val);
        snprintf(dropped_str, sizeof(dropped_str), "%llu PPS", dropped_val);
    }
    else
    {
        snprintf(forwarded_str, sizeof(forwarded_str), "%llu", forwarded_val);
        snprintf(passed_str, sizeof(passed_str), "%llu", passed_val);
        snprintf(dropped_str, sizeof(dropped_str), "%llu", dropped_val);
    }
    
    printf("\r\033[1;32mForwarded:\033[0m %s  |  ", forwarded_str);
    printf("\033[1;34mPassed:\033[0m %s  |  ", passed_str);
    printf("\033[1;31mDropped:\033[0m %s", dropped_str);

    fflush(stdout);    

    return EXIT_SUCCESS;
}