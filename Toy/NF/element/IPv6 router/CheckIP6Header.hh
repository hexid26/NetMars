#include "packet.hh"
#include "net.hh"

int CheckIP6Header(int input_port, Packet *pkt)
{
    struct ether_header *ethh = (struct ether_header *)pkt->data();
    struct ip6_hdr *iph = (struct ip6_hdr *)(ethh + 1);

    // Validate the packet header.
    if (ntohs(ethh->ether_type) != ETHER_TYPE_IPV6)
    {
        pkt->kill();
        return 0;
    }

    if ((iph->ip6_vfc & 0xf0) >> 4 != 6)
    { // get the first 4 bits.
        pkt->kill();
        return 0;
    }

    // TODO: Discard illegal source addresses.
    return 0; // output port number: 0
}