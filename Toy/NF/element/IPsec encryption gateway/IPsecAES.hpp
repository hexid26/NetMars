#pragma once
#include "Packet.hpp"
#include "aes_ctr.hpp"

// Input packet: assumes ESP encaped, but payload not encrypted yet.
// +----------+---------------+--------+----+------------+---------+-------+---------------------+
// | Ethernet | IP(proto=ESP) |  ESP   | IP |  payload   | padding | extra | HMAC-SHA1 signature |
// +----------+---------------+--------+----+------------+---------+-------+---------------------+
// ^ethh      ^iph            ^esph    ^encrypt_ptr
//                                     <===== to be encrypted with AES ====>
extern int ipsec_thread_rem;

void ipsec_aes_encryption_get_cuda_kernel(
    uint8_t *pac_data, const int total_len, const int batch_size,
    const unsigned int *pac_sign, AES_KEY *aes_key);

class IPsecAES
{
private:
    int num_tunnels;                   //Maximum number of IPsec tunnels
    static struct aes_sa_entry *flows; // used in CPU.
public:
    IPsecAES()
    {
        // std::cout << "\n>>2.正在测试IPsecAES模块..." << std::endl;
        num_tunnels = 1024;
        int size = sizeof(struct aes_sa_entry) * num_tunnels;
        void *ptr = new char *[size];
        assert(ptr != NULL);
        memset(ptr, 0xcd, size);
        flows = (struct aes_sa_entry *)ptr;
    }

    static void print_encrypt(uint8_t *encrypt_ptr, int encrypted_len, int pad_len)
    {
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
    }

    static void ipsec_aes(Packet **pkt, int thread_size)
    {
        for (int i = 0; i < thread_size; i++)
        {
            if (pkt[i]->is_save == true)
            {
                struct ether_header *ethh = (struct ether_header *)(pkt[i]->data());
                struct iphdr *iph = (struct iphdr *)(ethh + 1);
                struct esphdr *esph = (struct esphdr *)(iph + 1);
                // TODO: support decryption.
                uint8_t *encrypt_ptr = (uint8_t *)esph + sizeof(struct esphdr);
                int encrypted_len = ntohs(iph->tot_len) - sizeof(struct iphdr) - sizeof(struct esphdr) - SHA_DIGEST_LENGTH;
                int pad_len = AES_BLOCK_SIZE - (encrypted_len + 2) % AES_BLOCK_SIZE;
                int enc_size = encrypted_len + pad_len + 2; // additional two bytes mean the "extra" part.
                struct aes_sa_entry *sa_entry = &flows[0];
                sa_entry->aes_key_t.rounds = 0xcd;
                print_encrypt(encrypt_ptr, encrypted_len, pad_len);
                unsigned mode = 0;
                uint8_t ecount_buf[AES_BLOCK_SIZE] = {0};
                AES_ctr128_encrypt(encrypt_ptr, encrypt_ptr, enc_size, &sa_entry->aes_key_t, esph->esp_iv, ecount_buf, &mode);
                print_encrypt(encrypt_ptr, encrypted_len, pad_len);
                //IPsecAES对于Packet包的所有更改全部是通过指针操作内存(uint8_t*形式的字符流)实现的
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
                pth[i] = std::thread(ipsec_aes,
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
                struct esphdr *esph = (struct esphdr *)(iph + 1);
                uint8_t *encrypt_ptr = (uint8_t *)esph + sizeof(struct esphdr);
                int encrypted_len = ntohs(iph->tot_len) - sizeof(struct iphdr) - sizeof(struct esphdr) - SHA_DIGEST_LENGTH;
                int pad_len = AES_BLOCK_SIZE - (encrypted_len + 2) % AES_BLOCK_SIZE;
                print_encrypt(encrypt_ptr, encrypted_len, pad_len);
            }

            struct aes_sa_entry *sa_entry = &flows[0];
            sa_entry->aes_key_t.rounds = 0xcd;
            ipsec_aes_encryption_get_cuda_kernel(pac_data, total_len, batch_size, pac_sign, &sa_entry->aes_key_t);

            for (int i = 0; i < batch_size; i++)
            {
                struct ether_header *ethh = (struct ether_header *)(pac_data + pac_sign[i]);
                struct iphdr *iph = (struct iphdr *)(ethh + 1);
                struct esphdr *esph = (struct esphdr *)(iph + 1);
                uint8_t *encrypt_ptr = (uint8_t *)esph + sizeof(struct esphdr);
                int encrypted_len = ntohs(iph->tot_len) - sizeof(struct iphdr) - sizeof(struct esphdr) - SHA_DIGEST_LENGTH;
                int pad_len = AES_BLOCK_SIZE - (encrypted_len + 2) % AES_BLOCK_SIZE;
                print_encrypt(encrypt_ptr, encrypted_len, pad_len);
            }
        }
    }
};

struct aes_sa_entry *IPsecAES::flows;