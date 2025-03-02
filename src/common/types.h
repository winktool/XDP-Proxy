#pragma once

#include <common/int_types.h>

struct stats
{
    u64 forwarded;
    u64 passed;
} typedef stats_t;

struct fwd_rule
{
    u32 bind_ip;
    u16 bind_port;
    u8 bind_protocol;

    u32 dst_ip;
    u16 dst_port;
} typedef fwd_rule_t;

struct fwd_rule_log_event
{
    u64 ts;

    u32 src_ip;
    u16 src_port;

    u32 bind_ip;
    u16 bind_port;
    u8 bind_protocol;

    u32 dst_ip;
    u16 dst_port;
} typedef fwd_rule_log_event_t;