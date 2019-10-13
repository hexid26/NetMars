#include "packet.hh"
#include "net.hh"

void direct_lookup(
    const uint16_t *TBL24, const uint16_t *TBLlong,
    const uint32_t ip, uint16_t *dest)
{
    uint16_t temp_dest;
    temp_dest = TBL24[ip >> 8];
    if (temp_dest & 0x8000u)
    {
        int index2 = (((uint32_t)(temp_dest & 0x7fff)) << 8) + (ip & 0xff);
        temp_dest = TBLlong[index2];
    }
    *dest = temp_dest;
}

int IPlookup(int input_port, Packet *pkt)
{
    struct ether_header *ethh = (struct ether_header *)pkt->data();
    struct ipv4_hdr *iph = (struct ipv4_hdr *)(ethh + 1);
    uint32_t dest_addr = ntohl(iph->dst_addr);
    uint16_t lookup_result = 0xffff;

    uint16_t *TBL24;
    uint16_t *TBLlong;

    direct_lookup(TBL24, TBLlong, dest_addr, &lookup_result);
    if (lookup_result == 0xffff)
    {
        /* Could not find destination. Use the second output for "error" packets. */
        pkt->kill();
        return 0;
    }

    // #ifdef NBA_IPFWD_RR_NODE_LOCAL
    // unsigned iface_in = anno_get(&pkt->anno, NBA_ANNO_IFACE_IN);
    // unsigned n = (iface_in <= ((unsigned) num_tx_ports / 2) - 1) ? 0 : (num_tx_ports / 2);
    // rr_port = (rr_port + 1) % (num_tx_ports / 2) + n;
    // #else
    // rr_port = (rr_port + 1) % (num_tx_ports);
    // #endif
    // anno_set(&pkt->anno, NBA_ANNO_IFACE_OUT, rr_port);
    // output(0).push(pkt);
    // return 0;
}
