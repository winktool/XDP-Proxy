#pragma once

// The maximum forward rules allowed.
#define MAX_FWD_RULES 256

// The port range to use when selecting an available source port.
// MAX_PORT - (MIN_PORT - 1) = The maximum amount of concurrent connections.
#define MIN_PORT 500
#define MAX_PORT 520

// Enables forward rule logging.
#define ENABLE_RULE_LOGGING

// Counts packets sent back to the client towards "forwarded" stat counter. 
//#define STATS_COUNT_FWD_BACK

// If enabled, performs a FIB lookup on the route table when forwarding packets.
// Otherwise, the ethernet source and destination MAC addresses are swapped.
#define ENABLE_FIB_LOOKUPS

// Maximum interfaces the firewall can attach to.
#define MAX_INTERFACES 6