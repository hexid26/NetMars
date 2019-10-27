#include "packet.hh"
#include "net.hh"
#define ETHER_GROUP_ADDR 0x01 /**< Multicast or broadcast Eth. address. */

/**
 * Check if an Ethernet address is a unicast address.
 *
 * @param ea
 *   A pointer to a ether_addr structure containing the ethernet address
 *   to check.
 * @return
 *   True  (1) if the given ethernet address is a unicast address;
 *   false (0) otherwise.
 */
static inline int is_unicast_ether_addr(const uint8_t  *ea)
{
    return (ea[0] & ETHER_GROUP_ADDR) == 0;
}

void DropBroadcasts(int input_port, Packet *pkt)
{
    struct ether_header *ethh = (struct ether_header *)pkt->data();
    if (is_unicast_ether_addr(ethh->ether_dhost))
    {
        //output(0).push(pkt);
    }
    else
    {
        //Drop broadcasts
    }
}