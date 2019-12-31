#pragma once
#include "Packet.hpp"

// Input packet: assumes encaped
// +----------+---------------+--------+----+------------+---------+-------+---------------------+
// | Ethernet | IP(proto=ESP) |  ESP   | IP |  payload   | padding | extra | HMAC-SHA1 signature |
// +----------+---------------+--------+----+------------+---------+-------+---------------------+
// ^ethh      ^iph            ^esph    ^encaped_iph
//                            ^payload_out
//                            ^encapsulated
//                            <===== authenticated part (payload_len) =====>
extern int ipsec_thread_rem;

void ipsec_hsha1_encryption_get_cuda_kernel(
    uint8_t *pac_data, const int total_len, const int batch_size,
    const unsigned int *pac_sign, uint8_t *hmac_key);

class IPsecAuthHMACSHA1
{
private:
    int num_tunnels;                    /* Maximum number of IPsec tunnels */
    static struct hmac_sa_entry *flows; // used in CPU.

public:
    IPsecAuthHMACSHA1()
    {
        // std::cout << "\n>>3.正在测试IPsecAuthHMACSHA1模块..." << std::endl;
        // We assume the size of hmac_key is less than 64 bytes.
        num_tunnels = 1024;
        int size = sizeof(struct hmac_sa_entry) * num_tunnels;
        void *ptr = new char *[size];
        assert(ptr != NULL);
        memset(ptr, 0xcd, size);
        flows = (struct hmac_sa_entry *)ptr;
    }

    static void ipsec_auth(Packet **pkt, int thread_size)
    {
        for (int i = 0; i < thread_size; i++)
        {
            if (pkt[i]->is_save == true)
            {
                // TODO: check if input pkt is encapulated or not.
                struct ether_header *ethh = (struct ether_header *)(pkt[i]->data());
                struct iphdr *iph = (struct iphdr *)(ethh + 1);
                unsigned char *payload_out = (unsigned char *)((uint8_t *)ethh + sizeof(struct ether_header) + sizeof(struct iphdr));
                int payload_len = (ntohs(iph->tot_len) - (iph->ihl * 4) - SHA_DIGEST_LENGTH);
                struct hmac_sa_entry *sa_entry = &flows[0];
                sa_entry->entry_idx = 0xcd;
                uint8_t *hmac_key = sa_entry->hmac_key;

                printf("处理前的hash消息摘要为\n");
                for (int i = 0; i < SHA_DIGEST_LENGTH; i++)
                {
                    printf("%d ", int(*(payload_out + payload_len + i)));
                }
                printf("\n");

                uint8_t hmac_buf[2048];
                uint8_t isum[SHA_DIGEST_LENGTH];
                memmove(hmac_buf + 64, payload_out, payload_len);
                for (int i = 0; i < 8; i++)
                {
                    *((uint64_t *)hmac_buf + i) = 0x3636363636363636LLU ^ *((uint64_t *)hmac_key + i);
                }
                SHA1(hmac_buf, 64 + payload_len, isum);
                memmove(hmac_buf + 64, isum, SHA_DIGEST_LENGTH);
                for (int i = 0; i < 8; i++)
                {
                    *((uint64_t *)hmac_buf + i) = 0x5c5c5c5c5c5c5c5cLLU ^ *((uint64_t *)hmac_key + i);
                }
                SHA1(hmac_buf, 64 + SHA_DIGEST_LENGTH, payload_out + payload_len);

                printf("结果会保存在包的HMAC-SHA1 signature部分，并覆盖之前的内容，hash消息摘要为\n");
                for (int i = 0; i < SHA_DIGEST_LENGTH; i++)
                {
                    printf("%d ", int(*(payload_out + payload_len + i)));
                }
                printf("\n");
                // TODO: correctness check..
                //IPsecAuthHMACSHA1对于Packet包的所有更改全部是通过指针操作内存(uint8_t*形式的字符流)实现的
            }
        }
    }

    void process(bool IsGPU, Packet **pkt, int batch_size)
    {
        if (!IsGPU)
        {
            std::thread pth[AVAIL_THREAD_NUM];
            for (int i = 0; i < AVAIL_THREAD_NUM; i++)
            {
                int packet_num = batch_size / (int)AVAIL_THREAD_NUM;
                if (i < ipsec_thread_rem)
                    packet_num++;
                pth[i] = std::thread(ipsec_auth,
                                     pkt + i * packet_num,
                                     packet_num);
                pth[i].join();
            }
        }
        else
        {
            int total_len = 0;
            for (int i = 0; i < batch_size; i++)
            {
                total_len += (int)(pkt[i]->plen);
            }
            uint8_t *pac_data = (uint8_t *)malloc(sizeof(uint8_t) * total_len);
            unsigned int *pac_sign = (unsigned int *)malloc(sizeof(unsigned int) * batch_size);
            uint8_t *p_pac_data = pac_data;
            int sign = 0;
            for (int i = 0; i < batch_size; i++)
            {
                pac_sign[i] = sign;
                int pac_len = (int)(pkt[i]->plen);
                memcpy(p_pac_data, pkt[i]->data(), pac_len);
                p_pac_data += pac_len;
                sign += pac_len;

                struct ether_header *ethh = (struct ether_header *)(pkt[i]->data());
                struct iphdr *iph = (struct iphdr *)(ethh + 1);
                unsigned char *payload_out = (unsigned char *)((uint8_t *)ethh + sizeof(struct ether_header) + sizeof(struct iphdr));
                int payload_len = (ntohs(iph->tot_len) - (iph->ihl * 4) - SHA_DIGEST_LENGTH);
                printf("处理前的hash消息摘要为\n");
                for (int i = 0; i < SHA_DIGEST_LENGTH; i++)
                {
                    printf("%d ", int(*(payload_out + payload_len + i)));
                }
                printf("\n");
            }

            struct hmac_sa_entry *sa_entry = &flows[0];
            sa_entry->entry_idx = 0xcd;

            ipsec_hsha1_encryption_get_cuda_kernel(pac_data, total_len, batch_size, pac_sign, sa_entry->hmac_key);

            for (int i = 0; i < batch_size; i++)
            {
                struct ether_header *ethh = (struct ether_header *)(pac_data + pac_sign[i]);
                struct iphdr *iph = (struct iphdr *)(ethh + 1);
                unsigned char *payload_out = (unsigned char *)((uint8_t *)ethh + sizeof(struct ether_header) + sizeof(struct iphdr));
                int payload_len = (ntohs(iph->tot_len) - (iph->ihl * 4) - SHA_DIGEST_LENGTH);
                printf("结果会保存在包的HMAC-SHA1 signature部分，并覆盖之前的内容，hash消息摘要为\n");
                for (int i = 0; i < SHA_DIGEST_LENGTH; i++)
                {
                    printf("%d ", int(*(payload_out + payload_len + i)));
                }
                printf("\n");
            }
        }
    }
};

struct hmac_sa_entry *IPsecAuthHMACSHA1::flows;