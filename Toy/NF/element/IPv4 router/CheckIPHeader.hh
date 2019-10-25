#include "packet.hh"
#include "net.hh"

bool CheckIPHeader(int input_port, Packet *pkt)
{
    struct ether_header *ethh = (struct ether_header *)pkt->data();
    struct iphdr *iph = (struct iphdr *)(ethh + 1);

    if (ntohs(ethh->ether_type) != ETHER_TYPE_IPV4)
    {
        //CheckIPHeader: invalid packet type
        pkt->kill();
        return false;
    }

    if ((iph->version != 4) || (iph->ihl < 5))
    {
        // CheckIPHeader: invalid packet - ver
        pkt->kill();
        return false;
    }

    if ((iph->ihl * 4) > ntohs(iph->tot_len))
    {
        // CheckIPHeader: invalid packet - total len
        pkt->kill();
        return false;
    }

    // TODO: Discard illegal source addresses.

    if (ip_fast_csum(iph, iph->ihl) != 0)
    {
        pkt->kill();
    }
}