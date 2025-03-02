#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/in.h>
#include <stdatomic.h>

#include <common/all.h>

#include <xdp/utils/forward.h>
#include <xdp/utils/logging.h>
#include <xdp/utils/helpers.h>
#include <xdp/utils/csum.h>

#include <xdp/utils/maps.h>

struct 
{
    __uint(priority, 10);
    __uint(XDP_PASS, 1);
} XDP_RUN_CONFIG(xdp_prog_main);

SEC("xdp_prog")
int xdp_prog_main(struct xdp_md *ctx)
{
    // Initialize packet information.
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Initialize Ethernet header.
    struct ethhdr *eth = data;

    // Check Ethernet header.
    if (unlikely(eth + 1 > (struct ethhdr *)data_end))
    {
        return XDP_DROP;
    }

    // If not IPv4, pass down network stack. Will be adding IPv6 support later on.
    if (eth->h_proto != htons(ETH_P_IP))
    {
        return XDP_PASS;
    }

    // Initialize IP header.
    struct iphdr *iph = data + sizeof(struct ethhdr);

    // Check IP header.
    if (unlikely(iph + 1 > (struct iphdr *)data_end))
    {
        return XDP_DROP;
    }

    // We only support TCP, UDP, and ICMP for forwarding at this moment.
    if (iph->protocol != IPPROTO_TCP && iph->protocol != IPPROTO_UDP && iph->protocol != IPPROTO_ICMP)
    {
        return XDP_PASS;
    }

    // Get layer-4 protocol information.
    struct udphdr *udph = NULL;
    struct tcphdr *tcph = NULL;
    struct icmphdr *icmph = NULL;

    u16 portkey = 0;

    switch (iph->protocol)
    {
        case IPPROTO_TCP:
            tcph = data + sizeof(struct ethhdr) + (iph->ihl * 4);

            if (tcph + 1 > (struct tcphdr *)data_end)
            {
                return XDP_DROP;
            }

            break;

        case IPPROTO_UDP:
            udph = data + sizeof(struct ethhdr) + (iph->ihl * 4);

            if (udph + 1 > (struct udphdr *)data_end)
            {
                return XDP_DROP;
            }

            break;

        case IPPROTO_ICMP:
            icmph = data + sizeof(struct ethhdr) + (iph->ihl * 4);

            if (icmph + 1 > (struct icmphdr *)data_end)
            {
                return XDP_DROP;
            }

            break;
    }

    portkey = (tcph) ? tcph->dest : (udph) ? udph->dest : 0;

    // Choose which map we're using.
    void* map = (tcph) ? (void *)&map_tcp_conns : (udph) ? (void*)&map_udp_conns : NULL;

    // Construct forward key.
    struct forward_key fwdkey = {0};
    
    fwdkey.bindaddr = iph->daddr;
    fwdkey.protocol = iph->protocol;
    fwdkey.bindport = portkey;
    
    struct forward_info *fwdinfo = bpf_map_lookup_elem(&map_fwd_rules, &fwdkey);

    if (fwdinfo)
    {
        if (!map && !icmph)
        {
            return XDP_PASS;
        }

        u64 now = bpf_ktime_get_ns();

        // Ensure we aren't actually receiving replies back from the destination address on the same bind and source port. Or ICMP replies.
        if (iph->saddr == fwdinfo->destaddr)
        {
            goto reply;
        }

        // Check if we have an existing connection.
        struct conn_key connkey = {0};

        connkey.clientaddr = iph->saddr;
        connkey.clientport = (tcph) ? tcph->source : (udph) ? udph->source : 0;
        connkey.bindaddr = iph->daddr;
        connkey.bindport = portkey;
        connkey.protocol = iph->protocol;

        // Check for existing connection with UDP/TCP.
        if (map)
        {
            u16 *connport = bpf_map_lookup_elem(&map_connections, &connkey);

            if (connport)
            {
                // Now attempt to retrieve connection from port map.
                struct port_key pkey = {0};
                pkey.bindaddr = iph->daddr;
                pkey.destaddr = fwdinfo->destaddr;
                pkey.port = *connport;

                struct connection *conn = bpf_map_lookup_elem(map, &pkey);

                if (conn)
                {
                    // Update connection stats before forwarding packet.
                    conn->lastseen = now;
                    conn->count++;

                    // Forward the packet!
                    if (conn->clientport == connkey.clientport)
                    {
                        return forwardpacket4(fwdinfo, conn, ctx);
                    }
                    else
                    {
                        bpf_map_delete_elem(map, &pkey);
                    }                    
                }
            }
        }

        u16 porttouse = 0;

        if (map)
        {
            u64 last = UINT64_MAX;

            // Creating the port_key struct outside of the loop and assigning bind address should save some CPU cycles.
            struct port_key pkey = {0};
            pkey.bindaddr = iph->daddr;
            pkey.destaddr = fwdinfo->destaddr;
            
            for (u16 i = MIN_PORT; i <= MAX_PORT; i++)
            {
                pkey.port = htons(i);

                struct connection *newconn = bpf_map_lookup_elem(map, &pkey);

                if (!newconn)
                {
                    porttouse = i;

                    break;
                }
                else
                {
                    // For some reason when trying to divide by any number (such as 1000000000 to get the actual PPS), the BPF verifier doesn't like that.
                    // Doesn't matter though and perhaps better we don't divide since that's one less calculation to worry about.
                    u64 pps = (newconn->lastseen - newconn->firstseen) / newconn->count;

                    // We'll want to replace the most inactive connection.
                    if (last > pps)
                    {
                        porttouse = i;
                        last = pps;
                    }
                }
            }
        }

        if (porttouse > 0 || icmph)
        {
            u16 port = 0;

            if (map)
            {
                // Insert information about connection.
                struct conn_key nconnkey = {0};
                nconnkey.bindaddr = iph->daddr;
                nconnkey.bindport = portkey;
                nconnkey.clientaddr = iph->saddr;
                nconnkey.clientport = connkey.clientport;
                nconnkey.protocol = iph->protocol;

                port = htons(porttouse);

                bpf_map_update_elem(&map_connections, &nconnkey, &port, BPF_ANY);
            }

            // Insert new connection into port map.
            struct port_key npkey = {0};
            npkey.bindaddr = iph->daddr;
            npkey.destaddr = fwdinfo->destaddr;
            npkey.port = port;

            struct connection newconn = {0};
            newconn.clientaddr = iph->saddr;
            newconn.clientport = connkey.clientport;
            newconn.firstseen = now;
            newconn.lastseen = now;
            newconn.count = 1;
            newconn.bindport = portkey;
            newconn.port = port;

            if (map)
            {
                bpf_map_update_elem(map, &npkey, &newconn, BPF_ANY);
            }

            // Finally, forward packet.
            return forwardpacket4(fwdinfo, &newconn, ctx);
        }
    }
    else
    {
        reply:;
        
        // Look for packets coming back from bind addresses.
        portkey = (tcph) ? tcph->dest : (udph) ? udph->dest : 0;

        if (map)
        {
            struct port_key pkey = {0};
            pkey.bindaddr = iph->daddr;
            pkey.destaddr = iph->saddr;
            pkey.port = portkey;

            // Find out what the client IP is.
            struct connection *conn = bpf_map_lookup_elem(map, &pkey);

            if (conn)
            {
                // Now forward packet back to actual client.
                return forwardpacket4(NULL, conn, ctx);
            }
        }
        else if (icmph && icmph->type == ICMP_ECHOREPLY)
        {
            // Handle ICMP replies.
            struct connection newconn = {0};
            
            return forwardpacket4(NULL, &newconn, ctx);
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";