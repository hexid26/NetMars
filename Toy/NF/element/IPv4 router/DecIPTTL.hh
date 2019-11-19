#pragma once
#include "Packet.hh"

class DecIPTTL
{
public:
    bool process(int input_port, Packet *pkt)
    {
        cout << "\n>>4.正在测试DecIPTTL模块..." << endl;
        struct ether_header *ethh = (struct ether_header *)pkt->data();
        struct iphdr *iph = (struct iphdr *)(ethh + 1);
        uint32_t sum;

        if (iph->ttl <= 1)
        {
            //pkt->kill();
            //ttl已为0，丢弃。
            return false;
        }

        // Decrement TTL.
        cout << "输入时的ttl为：";
        cout << int(iph->ttl) << endl;

        iph->ttl--;

        cout << "输出时的ttl为：";
        cout << int(iph->ttl) << endl;

        //更改校验和
        cout << "更改前的校验和：";
        cout << iph->check << endl;

        sum = (~ntohs(iph->check) & 0xFFFF) + 0xFEFF;
        iph->check = ~htons(sum + (sum >> 16));

        cout << "更改后的校验和：";
        cout << iph->check << endl;
        return true;
    }
};
