#pragma once
#include "Packet.hpp"
#include "aes_ctr.hpp"
#include "aes_locl.hpp"
#include <vector>
#include <unordered_map>

//#define USE_CUDA
#ifdef USE_CUDA
void ipsec_aes_encryption_get_cuda_kernel(
    uint8_t *iv,
    uint8_t *enc_payload,
    uint32_t length,
    AES_KEY *aes_key);
#endif
// Input packet: assumes ESP encaped, but payload not encrypted yet.
// +----------+---------------+--------+----+------------+---------+-------+---------------------+
// | Ethernet | IP(proto=ESP) |  ESP   | IP |  payload   | padding | extra | HMAC-SHA1 signature |
// +----------+---------------+--------+----+------------+---------+-------+---------------------+
// ^ethh      ^iph            ^esph    ^encrypt_ptr
//                                     <===== to be encrypted with AES ====>

class IPsecAES
{
protected:
    int num_tunnels; //Maximum number of IPsec tunnels
    /* Per-thread pointers, which points to the node local storage variables. */
    struct aes_sa_entry *flows = nullptr; // used in CPU.
public:
    /* CPU-only method */
    int process(int input_port, Packet *pkt)
    {
        cout << "\n>>2.正在测试IPsecAES模块..." << endl;
        num_tunnels = 1024;
        int size = sizeof(struct aes_sa_entry) * num_tunnels;
        void *ptr = new char *[size];
        assert(ptr != NULL);
        memset(ptr, 0xcd, size);
        flows = (struct aes_sa_entry *)ptr;

        struct ether_header *ethh = (struct ether_header *)(pkt->data());
        struct iphdr *iph = (struct iphdr *)(ethh + 1);
        struct esphdr *esph = (struct esphdr *)(iph + 1);
        uint8_t ecount_buf[AES_BLOCK_SIZE] = {0};
        // TODO: support decrpytion.
        uint8_t *encrypt_ptr = (uint8_t *)esph + sizeof(*esph);
        int encrypted_len = ntohs(iph->tot_len) - sizeof(struct iphdr) - sizeof(struct esphdr) - SHA_DIGEST_LENGTH;
        cout << "需要加密的长度包含四个部分：原始的IP头、payload和padding以及extra，总长度encrypted_len为:" << encrypted_len << endl;
        int pad_len = AES_BLOCK_SIZE - (encrypted_len + 2) % AES_BLOCK_SIZE;
        cout << "在其后添加新的padding部分，长度为：" << pad_len << endl;
        int enc_size = encrypted_len + pad_len + 2; // additional two bytes mean the "extra" part.
        cout << "在其后添加新的extra部分，长度为：" << 2 << endl;
        cout << "加上新的padding部分和extra部分，enc_size长度为：" << enc_size << endl;
        // int err = 0;
        struct aes_sa_entry *sa_entry = NULL;
        if (anno_isset(&pkt->anno, NBA_ANNO_IPSEC_FLOW_ID))
        {
            unsigned mode = 0;

            cout << "已找到当前包的AES加密结构（该结构中的值在初始化时由人为指定）：" << endl;
            sa_entry = &flows[anno_get(&pkt->anno, NBA_ANNO_IPSEC_FLOW_ID)];
            sa_entry->aes_key_t.rounds = 0xcd;

            printf("其中AES_KEY内容如下：\n");
            printf("\trd_key：");
            for (int i = 0; i < 5; i++)
            {
                printf("%d ", sa_entry->aes_key_t.rd_key[i]);
            }
            printf("...(共60个)\n");
            printf("\trounds：%d\n", sa_entry->aes_key_t.rounds);

            for (int i = 0; i < encrypted_len; i++)
            {
                printf("%d ", (int)encrypt_ptr[i]);
            }
            printf("|");
            for (int i = 0; i < pad_len + 2; i++)
            {
                printf("%d ", (int)encrypt_ptr[encrypted_len + i]);
            }
            printf("|");
            for (int i = pad_len + 2; i < SHA_DIGEST_LENGTH - pad_len - 2; i++)
            {
                printf("%d ", (int)encrypt_ptr[encrypted_len + i]);
            }
            printf("\n");
#ifdef USE_CUDA
            ipsec_aes_encryption_get_cuda_kernel(esph->esp_iv, encrypt_ptr, enc_size, &sa_entry->aes_key_t);
#else
            printf("正在采用AES加密结构中的AES_KEY和AES ctr128加密算法对原始的IP头、payload、padding、extra进行加密...\n");
            AES_ctr128_encrypt(encrypt_ptr, encrypt_ptr, enc_size, &sa_entry->aes_key_t, esph->esp_iv, ecount_buf, &mode);
#endif
            for (int i = 0; i < encrypted_len; i++)
            {
                printf("%d ", (int)encrypt_ptr[i]);
            }
            printf("|");
            for (int i = 0; i < pad_len + 2; i++)
            {
                printf("%d ", (int)encrypt_ptr[encrypted_len + i]);
            }
            printf("|");
            for (int i = pad_len + 2; i < SHA_DIGEST_LENGTH - pad_len - 2; i++)
            {
                printf("%d ", (int)encrypt_ptr[encrypted_len + i]);
            }
            printf("\n");
            //IPsecAES对于Packet包的所有更改全部是通过指针操作内存(uint8_t*形式的字符流)实现的
            //所以可以通过pkt->puint8访问IPsecAES处理后的结果
        }
        return 0;
    }
};
