#pragma once
#include "Packet.hpp"

extern int ipv4_thread_rem;
class CheckIPHeader
{
public:
    //此函数用于快速判断IP头的校验值是否正确，若正确应该返回0
    static uint16_t ip_fast_csum(const void *iph, unsigned int ihl)
    {
        unsigned int sum;
        asm("  movl (%1), %0\n"
            "  subl $4, %2\n"
            "  jbe 2f\n"
            "  addl 4(%1), %0\n"
            "  adcl 8(%1), %0\n"
            "  adcl 12(%1), %0\n"
            "1: adcl 16(%1), %0\n"
            "  lea 4(%1), %1\n"
            "  decl %2\n"
            "  jne      1b\n"
            "  adcl $0, %0\n"
            "  movl %0, %2\n"
            "  shrl $16, %0\n"
            "  addw %w2, %w0\n"
            "  adcl $0, %0\n"
            "  notl %0\n"
            "2:"
            /* Since the input registers which are loaded with iph and ih
           are modified, we must also specify them as outputs, or gcc
           will assume they contain their original values. */
            : "=r"(sum), "=r"(iph), "=r"(ihl)
            : "1"(iph), "2"(ihl)
            : "memory");
        return (uint16_t)sum;
    }

    static void check_ip_header(Packet **pkt, int thread_size)
    {
        // printf("\n>>2.正在测试CheckIPHeader模块...\n");
        for (int i = 0; i < thread_size; i++)
        {
            if (pkt[i]->is_save == true)
            {
                struct ether_header *ethh = (struct ether_header *)pkt[i]->data();
                struct iphdr *iph = (struct iphdr *)(ethh + 1);
                if (ntohs(ethh->ether_type) != ETHER_TYPE_IPV4)
                {
                    // printf("不是IPV4的包。\n");
                    pkt[i]->is_save = false;
                    continue;
                }
                if ((iph->version != 4) || (iph->ihl < 5))
                {
                    // printf("非法的包——版本，丢弃。\n");
                    pkt[i]->is_save = false;
                    continue;
                }
                if ((iph->ihl * 4) > ntohs(iph->tot_len))
                {
                    printf("非法的包——IP数据报长度，丢弃。\n");
                    pkt[i]->is_save = false;
                    continue;
                }
                // TODO: Discard illegal source addresses.
                if (ip_fast_csum(iph, iph->ihl) != 0)
                {
                    // printf("IP头校验不合法，丢弃。\n");
                    pkt[i]->is_save = false;
                }
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
            pth[i] = std::thread(check_ip_header,
                                 pkt + i * packet_num,
                                 packet_num);
            pth[i].join();
        }
    }
};
