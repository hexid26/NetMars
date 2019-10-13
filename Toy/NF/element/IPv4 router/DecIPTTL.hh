#include "packet.hh"
#include "net.hh"

bool DecIPTTL(int input_port, Packet *pkt)
{
    struct ether_header *ethh = (struct ether_header *)pkt->data();
    struct iphdr *iph = (struct iphdr *)(ethh + 1);
    uint32_t sum;

    if (iph->ttl <= 1)
    {
        pkt->kill();
        return false;
    }

    // Decrement TTL.
    iph->ttl--;
    sum = (~ntohs(iph->check) & 0xFFFF) + 0xFEFF;
    iph->check = ~htons(sum + (sum >> 16));
    return true;
}