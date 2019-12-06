#pragma once
#include "Packet.hpp"
#include <vector>
#include <string>
#include <unordered_map>

#ifdef USE_CUDA
void ipsec_hsha1_encryption_get_cuda_kernel(
    uint8_t *enc_payload_base,
    uint32_t length,
    uint8_t *hmac_key,
    uint8_t *sha_digest);
#endif
// Input packet: assumes encaped
// +----------+---------------+--------+----+------------+---------+-------+---------------------+
// | Ethernet | IP(proto=ESP) |  ESP   | IP |  payload   | padding | extra | HMAC-SHA1 signature |
// +----------+---------------+--------+----+------------+---------+-------+---------------------+
// ^ethh      ^iph            ^esph    ^encaped_iph
//                            ^payload_out
//                            ^encapsulated
//                            <===== authenticated part (payload_len) =====>

class IPsecAuthHMACSHA1
{
protected:
    /* Maximum number of IPsec tunnels */
    int num_tunnels;
    struct hmac_sa_entry *flows = nullptr; // used in CPU.
public:
    /* CPU-only method */
    int process(int input_port, Packet *pkt)
    {
        cout << "\n>>3.正在测试IPsecAuthHMACSHA1模块..." << endl;
        // We assume the size of hmac_key is less than 64 bytes.
        // TODO: check if input pkt is encapulated or not.
        num_tunnels = 1024;
        int size = sizeof(struct hmac_sa_entry) * num_tunnels;
        void *ptr = new char *[size];
        assert(ptr != NULL);
        memset(ptr, 0xcd, size);
        flows = (struct hmac_sa_entry *)ptr;

        struct ether_header *ethh = (struct ether_header *)(pkt->data());
        struct iphdr *iph = (struct iphdr *)(ethh + 1);
        // struct esphdr *esph = (struct esphdr *)(iph + 1);
        // uint8_t *encaped_iph = (uint8_t *)esph + sizeof(*esph);
        unsigned char *payload_out = (unsigned char *)((uint8_t *)ethh + sizeof(struct ether_header) + sizeof(struct iphdr));
        int payload_len = (ntohs(iph->tot_len) - (iph->ihl * 4) - SHA_DIGEST_LENGTH);
        cout << "需要认证的部分包括ESP头、封装后的IP头（原始IP头）、payload、extra几个部分，长度为：" << payload_len << endl;
        uint8_t isum[SHA_DIGEST_LENGTH];
        uint8_t hmac_buf[2048];
        struct hmac_sa_entry *sa_entry;
        uint8_t *hmac_key;
        cout << "已找到当前包的哈希消息认证结构（该结构中的值在初始化时由人为指定）：" << endl;
        sa_entry = &flows[anno_get(&pkt->anno, NBA_ANNO_IPSEC_FLOW_ID)];
        sa_entry->entry_idx = 0xcd;
        hmac_key = sa_entry->hmac_key;
        cout << "其中hmac_key内容如下：" << endl;

        cout << "\thmac_key：";
        for (int i = 0; i < 5; i++)
        {
            cout << (int)(sa_entry->hmac_key[i]) << " ";
        }
        cout << "...(共64个)" << endl;

        printf("处理前的hash消息摘要为\n");
        for (int i = 0; i < SHA_DIGEST_LENGTH; i++)
        {
            printf("%d ", int(*(payload_out + payload_len + i)));
        }
        printf("\n");
#ifdef USE_CUDA
        uint8_t *sha_digest = (uint8_t *)malloc(sizeof(uint8_t) * SHA_DIGEST_LENGTH);
        ipsec_hsha1_encryption_get_cuda_kernel((uint8_t *)payload_out, payload_len, hmac_key, sha_digest);
        for (int i = 0; i < SHA_DIGEST_LENGTH; i++)
        {
            *(payload_out + payload_len + i) = *(sha_digest + i);
        }
#else
        cout << "正在将需要认证的部分拷贝至hmac_buf数组第64位之后..." << endl;
        memmove(hmac_buf + 64, payload_out, payload_len);
        cout << "对hmac_key数组中的前8个字符作运算1并拷贝至hmac_buf数组前8位..." << endl;
        for (int i = 0; i < 8; i++)
            *((uint64_t *)hmac_buf + i) = 0x3636363636363636LLU ^ *((uint64_t *)hmac_key + i);
        cout << "正在利用SHA1(安全散列算法1)生成hmac_buf前" << 64 + payload_len << "个字节的散列值（消息摘要）" << endl;
        SHA1(hmac_buf, 64 + payload_len, isum);
        cout << "结果保存在isum中，为:" << endl;
        for (int i = 0; i < SHA_DIGEST_LENGTH; i++)
        {
            cout << int(isum[i]) << " ";
        }
        cout << "\n正在将isum(" << SHA_DIGEST_LENGTH << "个字节）中的内容拷贝至hmac_buf数组第64位之后..." << endl;
        memmove(hmac_buf + 64, isum, SHA_DIGEST_LENGTH);
        cout << "对hmac_key数组中的前8个字符作运算2并拷贝至hmac_buf数组前8位..." << endl;
        for (int i = 0; i < 8; i++)
        {
            *((uint64_t *)hmac_buf + i) = 0x5c5c5c5c5c5c5c5cLLU ^ *((uint64_t *)hmac_key + i);
        }
        cout << "正在利用SHA1(安全散列算法1)生成hmac_buf前" << 64 + SHA_DIGEST_LENGTH << "个字节的散列值（消息摘要）" << endl;
        SHA1(hmac_buf, 64 + SHA_DIGEST_LENGTH, payload_out + payload_len);
#endif
        printf("结果会保存在包的HMAC-SHA1 signature部分，并覆盖之前的内容，hash消息摘要为\n");
        for (int i = 0; i < SHA_DIGEST_LENGTH; i++)
        {
            printf("%d ", int(*(payload_out + payload_len + i)));
        }
        printf("\n");
        // TODO: correctness check..
        //IPsecAuthHMACSHA1对于Packet包的所有更改全部是通过指针操作内存(uint8_t*形式的字符流)实现的
        //所以可以通过pkt->puint8访问IPsecAuthHMACSHA1处理后的结果
        return 0;
    }
};
