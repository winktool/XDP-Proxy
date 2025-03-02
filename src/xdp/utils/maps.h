#pragma once

#include <common/all.h>

#include <xdp/utils/helpers.h>

struct 
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, stats_t);
} map_stats SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_FWD_RULES);
    __type(key, struct forward_key);
    __type(value, struct forward_info);
} map_fwd_rules SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, (MAX_FWD_RULES * (MAX_PORT - (MIN_PORT - 1))));
    __type(key, struct port_key);
    __type(value, struct connection);
} map_tcp_conns SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, (MAX_FWD_RULES * (MAX_PORT - (MIN_PORT - 1))));
    __type(key, struct port_key);
    __type(value, struct connection);
} map_udp_conns SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_CONNECTIONS);
    __type(key, struct conn_key);
    __type(value, u16);
} map_connections SEC(".maps");

#ifdef ENABLE_RULE_LOGGING
struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 16);
} map_fwd_rules_log SEC(".maps");
#endif