#include <xdp/utils/forward.h>

/**
 * Forwards an IPv4 packet from or back to the client.
 * 
 * @param info A pointer to a forward_info struct that represents what forwarding rule we're sending to. If NULL, will indicate we're sending back to the client.
 * @param conn A pointer to a connection struct that represents the connection we're forwarding to or back to.
 * @param ctx A pointer to the xdp_md struct containing all packet information.
 * 
 * @return XDP_TX (sends packet back out TX path).
 */
static __always_inline int forwardpacket4(struct forward_info *info, struct connection *conn, struct xdp_md *ctx)
{
    // Redefine packet and check headers.
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;

    if (eth + 1 > (struct ethhdr *)data_end)
    {
        return XDP_DROP;
    }

    struct iphdr *iph = data + sizeof(struct ethhdr);

    if (iph + 1 > (struct iphdr *)data_end)
    {
        return XDP_DROP;
    }

    // Swap ethernet source and destination MAC addresses.
    swapeth(eth);

    // Define ICMP header, but set it to NULL.
    struct icmphdr *icmph = NULL;

    if (iph->protocol == IPPROTO_ICMP)
    {
        icmph = data + sizeof(struct ethhdr) + (iph->ihl * 4);

        if (icmph + 1 > (struct icmphdr *)data_end)
        {
            return XDP_DROP;
        }
    }

    // Swap IP addresses.
    u32 oldsrcaddr = iph->saddr;
    u32 olddestaddr = iph->daddr;

    iph->saddr = iph->daddr;

    if (info)
    {
        iph->daddr = info->destaddr;
    }
    else
    {
        if (!icmph)
        {
            iph->daddr = conn->clientaddr;
        }
    }

    // Handle ICMP protocol.
    if (icmph)
    {
        if (info)
        {
            // We'll want to add the client's unsigned 32-bit (4 bytes) IP address to the ICMP data so we know where to send it when it replies back.
            // First, let's add four bytes to the packet.
            if (bpf_xdp_adjust_tail(ctx, (int)sizeof(u32)))
            {
                return XDP_DROP;
            }

            // We need to redefine packet and check headers again.
            data = (void *)(long)ctx->data;
            data_end = (void *)(long)ctx->data_end;

            eth = data;

            if (eth + 1 > (struct ethhdr *)data_end)
            {
                return XDP_DROP;
            }

            iph = data + sizeof(struct ethhdr);

            if (iph + 1 > (struct iphdr *)data_end)
            {
                return XDP_DROP;
            }

            icmph = data + sizeof(struct ethhdr) + (iph->ihl * 4);

            if (icmph + 1 > (struct icmphdr *)data_end)
            {
                return XDP_DROP;
            }

            // Now let's add the new data.

            // Unfortunately, we can't start from the packet end (data_end) pointer. Therefore, we must calculate the length of the packet and use the data pointer. Thanks for the help, Srivats! (https://lore.kernel.org/bpf/CANzUK5-g9wLiwUF88em4uVzMja_aR4xj9yzMS_ZObNKjvX6C6g@mail.gmail.com/)
            unsigned int len = (ctx->data_end - ctx->data);

            if (data + len > data_end)
            {
                return XDP_DROP;
            }

            unsigned int off = (len - sizeof(u32)) & 0x3fff;

            u32 *icmpdata = data + off;

            if (icmpdata + 1 > (u32 *)data_end)
            {
                return XDP_DROP;
            }

            memcpy(icmpdata, &conn->clientaddr, sizeof(u32));

            // We'll want to add four bytes to the IP header.
            iph->tot_len = htons(ntohs(iph->tot_len) + sizeof(u32));

            // Recalculate ICMP checksum.
            icmph->checksum = csum_diff4(0, conn->clientaddr, icmph->checksum);
        }
        else
        {
            // When sending packets back, we'll want to get the client IP address from the ICMP data (last four bytes).
            // First ensure the ICMP data is enough.
            if (icmph + sizeof(u32) > (struct icmphdr *)data_end)
            {
                return XDP_PASS;
            }
            
            // Now access the data.
            unsigned int len = (ctx->data_end - ctx->data);

            if (data + len > data_end)
            {
                return XDP_DROP;
            }

            unsigned int off = (len - sizeof(u32)) & 0x3fff;

            u32 *clientaddr = data + off;

            if (clientaddr + 1 > (u32 *)data_end)
            {
                return XDP_DROP;
            }

            iph->daddr = *clientaddr;
            
            // Now we'll want to remove the additional four bytes we added when forwarding.
            if (bpf_xdp_adjust_tail(ctx, 0 - (int)sizeof(u32)))
            {
                return XDP_DROP;
            }

            // We need to redefine packet and check headers again.
            data = (void *)(long)ctx->data;
            data_end = (void *)(long)ctx->data_end;

            eth = data;

            if (eth + 1 > (struct ethhdr *)data_end)
            {
                return XDP_DROP;
            }

            iph = data + sizeof(struct ethhdr);

            if (iph + 1 > (struct iphdr *)data_end)
            {
                return XDP_DROP;
            }

            icmph = data + sizeof(struct ethhdr) + (iph->ihl * 4);

            if (icmph + 1 > (struct icmphdr *)data_end)
            {
                return XDP_DROP;
            }

            // Remove four bytes from the IP header's total length.
            iph->tot_len = htons(ntohs(iph->tot_len) - sizeof(u32));

            // Recalculate ICMP checksum.
            icmph->checksum = csum_diff4(iph->daddr, 0, icmph->checksum);
        }
    }
    
    // Handle protocol.
    if (iph->protocol == IPPROTO_TCP)
    {
        struct tcphdr *tcph = data + sizeof(struct ethhdr) + (iph->ihl * 4);

        // Check header.
        if (tcph + 1 > (struct tcphdr *)data_end)
        {
            return XDP_DROP;
        }

        // Handle ports.
        u16 oldsrcport = tcph->source;
        u16 olddestport = tcph->dest;

        if (info)
        {
            tcph->source = conn->port;
            tcph->dest = info->destport;
        }
        else
        {
            tcph->source = conn->bindport;
            tcph->dest = conn->clientport;
        }
        
        // Recalculate checksum.
        tcph->check = csum_diff4(olddestaddr, iph->daddr, tcph->check);
        tcph->check = csum_diff4(oldsrcaddr, iph->saddr, tcph->check);

        tcph->check = csum_diff4(oldsrcport, tcph->source, tcph->check);
        tcph->check = csum_diff4(olddestport, tcph->dest, tcph->check);
    }
    else if (iph->protocol == IPPROTO_UDP)
    {
        struct udphdr *udph = data + sizeof(struct ethhdr) + (iph->ihl * 4);

        // Check header.
        if (udph + 1 > (struct udphdr *)data_end)
        {
            return XDP_DROP;
        }

        // Handle ports.
        u16 oldsrcport = udph->source;
        u16 olddestport = udph->dest;

        if (info)
        {
            udph->source = conn->port;
            udph->dest = info->destport;
        }
        else
        {
            udph->source = conn->bindport;
            udph->dest = conn->clientport;
        }

        // Recalculate checksum.
        udph->check = csum_diff4(olddestaddr, iph->daddr, udph->check);
        udph->check = csum_diff4(oldsrcaddr, iph->saddr, udph->check);

        udph->check = csum_diff4(oldsrcport, udph->source, udph->check);
        udph->check = csum_diff4(olddestport, udph->dest, udph->check);
    }

    // Recalculate IP checksum and send packet back out TX path.
    update_iph_checksum(iph);

    return XDP_TX;
}