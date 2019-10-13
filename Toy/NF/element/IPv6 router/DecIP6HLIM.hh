#include "packet.hh"
#include "net.hh"

int DecIP6HLIM(int input_port, Packet *pkt)
{
    struct ether_header *ethh = (struct ether_header *)pkt->data();
    struct ip6_hdr *iph = (struct ip6_hdr *)(ethh + 1);
    uint32_t checksum;

    if (iph->ip6_hlim <= 1)
    {
        pkt->kill();
        return 0;
    }

    // Decrement TTL.
    iph->ip6_hlim--;

    // output(0).push(pkt);
    return 0;
}