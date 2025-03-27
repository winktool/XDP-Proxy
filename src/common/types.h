#pragma once

#include <common/int_types.h>

struct stats
{
    u64 forwarded;
    u64 passed;
    u64 dropped;
} typedef stats_t;

struct fwd_rule_key
{
    u32 ip;
    u16 port;

    u8 protocol;

} typedef fwd_rule_key_t;

struct fwd_rule_val
{
    int log;

    u32 dst_ip;
    u16 dst_port;
} typedef fwd_rule_val_t;

struct port_key
{
    u32 bind_ip;
    u8 protocol;
    
    u16 port;
} typedef port_key_t;

struct port_val
{
    u32 src_ip;
    u16 src_port;

    u16 bind_port;

    u64 last_seen;
    u64 first_seen;
    u64 count;
} typedef port_val_t;

struct conn_key
{
    u32 src_ip;
    u16 src_port;
    u32 bind_ip;
    u16 bind_port;
    u8 protocol;
} typedef conn_key_t;

struct conn_val
{
    u32 src_ip;
    u16 src_port;

    u16 bind_port;

    u16 port;

#ifdef CONNECTION_COUNTERS
    u64 first_seen;
    u64 last_seen;

    u64 count;
#endif
} typedef conn_val_t;

struct fwd_rule_log_event
{
    u64 ts;

    int type;

    u16 port;

    u32 src_ip;
    u16 src_port;

    u32 bind_ip;
    u16 bind_port;
    u8 protocol;

    u32 dst_ip;
    u16 dst_port;
} typedef fwd_rule_log_event_t;