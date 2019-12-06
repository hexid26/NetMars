#pragma once
#include "Packet.hpp"

#define ETHER_GROUP_ADDR 0x01 /**< Multicast or broadcast Eth. address. */

/**
 * Check if an Ethernet address is a unicast address.单播地址
 *
 * @param ea
 *   A pointer to a ether_addr structure containing the ethernet address
 *   to check.
 * @return
 *   True  (1) if the given ethernet address is a unicast address;
 *   false (0) otherwise.
 */

class DropBroadcasts
{

public:
    //此函数用于判断目的硬件地址是否是一个单播地址
    static inline int is_unicast_ether_addr(const uint8_t *ea)
    {
        return (ea[0] & ETHER_GROUP_ADDR) == 0;
    }

    int process(int input_port, Packet *pkt)
    {
        cout << "\n>>1.正在测试DropBroadcasts模块..." << endl;
        struct ether_header *ethh = (struct ether_header *)pkt->data();
        if (is_unicast_ether_addr(ethh->ether_dhost))
        {
            //output(0).push(pkt);
            cout << "这是一个单播地址" << endl;
            return 0;
        }
        else
        {
            //Drop broadcasts广播
            cout << "这是一个广播地址,无效包" << endl;
            return 1;
        }
    }
};
