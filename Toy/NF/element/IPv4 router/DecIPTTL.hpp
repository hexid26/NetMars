#pragma once
#include "Packet.hpp"

extern int ipv4_thread_rem;
class DecIPTTL
{
public:
    static void dec_ip_ttl(Packet **pkt, int thread_size)
    {
        // printf("\n>>4.正在测试DecIPTTL模块...\n");
        for (int i = 0; i < thread_size; i++)
        {
            if (pkt[i]->is_save == true)
            {
                struct ether_header *ethh = (struct ether_header *)pkt[i]->data();
                struct iphdr *iph = (struct iphdr *)(ethh + 1);
                uint32_t sum;
                if (iph->ttl <= 1)
                {
                    //ttl已为0，丢弃
                    pkt[i]->is_save = false;
                    continue;
                }
                // printf("输入时的ttl为：%d\n", int(iph->ttl));
                iph->ttl--;
                // printf("输出时的ttl为：%d\n", int(iph->ttl));
                // printf("更改前的校验和：%d\n", int(iph->check));
                sum = (~ntohs(iph->check) & 0xFFFF) + 0xFEFF;
                iph->check = ~htons(sum + (sum >> 16));
                // printf("更改后的校验和：%d\n", int(iph->check));
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
            pth[i] = std::thread(dec_ip_ttl,
                                 pkt + i * packet_num,
                                 packet_num);
            pth[i].join();
        }
    }
};
