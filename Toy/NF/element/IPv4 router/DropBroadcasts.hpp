#pragma once
#include "Packet.hpp"
#include "auxiliary.hpp"

#define ETHER_GROUP_ADDR 0x01 /**< Multicast or broadcast Eth. address. */

extern int ipv4_thread_rem;
class DropBroadcasts
{
public:
    //此函数用于判断目的硬件地址是否是一个单播地址
    static inline int is_unicast_ether_addr(const uint8_t *ea)
    {
        return (ea[0] & ETHER_GROUP_ADDR) == 0;
    }

    static void drop_broadcasts(Packet **pkt, int thread_size)
    {
        // printf("\n>>1.正在测试DropBroadcasts模块...\n");
        for (int i = 0; i < thread_size; i++)
        {
            struct ether_header *ethh = (struct ether_header *)pkt[i]->data();
            if (is_unicast_ether_addr(ethh->ether_dhost))
            {
                // printf("这是一个单播地址\n");
                pkt[i]->is_save = true;
            }
            else
            {
                // printf("这是一个广播地址,无效包\n");
                pkt[i]->is_save = false;
            }
        }
    }

    void process(Packet **pkt, int batch_size)
    {
        std::thread pth[AVAIL_THREAD_NUM];
        for (int i = 0; i < AVAIL_THREAD_NUM; i++)
        {
            int packet_num = batch_size / (int)AVAIL_THREAD_NUM;
            if (i < ipv4_thread_rem)
                packet_num++;
            pth[i] = std::thread(drop_broadcasts,
                                 pkt + i * packet_num,
                                 packet_num);
            pth[i].join();
        }
    }
};
