#include "packet.hh"
#include "net.hh"

enum : int
{
    HMAC_KEY_SIZE = 64,
};

struct alignas(8) hmac_sa_entry
{
    uint8_t hmac_key[HMAC_KEY_SIZE];
    int entry_idx;
};

int IPsecAuthHMACSHA1(int input_port, Packet *pkt)
{
    // We assume the size of hmac_key is less than 64 bytes.
    // TODO: check if input pkt is encapulated or not.
    struct ether_header *ethh = (struct ether_header *)pkt->data();
    struct iphdr *iph = (struct iphdr *)(ethh + 1);
    struct esphdr *esph = (struct esphdr *)(iph + 1);
    uint8_t *encaped_iph = (uint8_t *)esph + sizeof(*esph);

    unsigned char *payload_out = (unsigned char *)((uint8_t *)ethh + sizeof(struct ether_header) + sizeof(struct iphdr));
    int payload_len = (ntohs(iph->tot_len) - (iph->ihl * 4) - SHA_DIGEST_LENGTH);
    uint8_t isum[SHA_DIGEST_LENGTH];
    uint8_t hmac_buf[2048];
    struct hmac_sa_entry *sa_entry;

    uint8_t *hmac_key;
    if (anno_isset(&pkt->anno, NBA_ANNO_IPSEC_FLOW_ID))
    {
        // sa_entry = &flows[anno_get(&pkt->anno, NBA_ANNO_IPSEC_FLOW_ID)];
        hmac_key = sa_entry->hmac_key;

        //rte_memcpy(hmac_buf + 64, payload_out, payload_len);
        for (int i = 0; i < 8; i++)
            *((uint64_t *)hmac_buf + i) = 0x3636363636363636LLU ^ *((uint64_t *)hmac_key + i);
        SHA1(hmac_buf, 64 + payload_len, isum);

        //rte_memcpy(hmac_buf + 64, isum, SHA_DIGEST_LENGTH);
        for (int i = 0; i < 8; i++)
        {
            *((uint64_t *)hmac_buf + i) = 0x5c5c5c5c5c5c5c5cLLU ^ *((uint64_t *)hmac_key + i);
        }
        SHA1(hmac_buf, 64 + SHA_DIGEST_LENGTH, payload_out + payload_len);
        // TODO: correctness check..
    }
    else
    {
        pkt->kill();
        return 0;
    }
    // output(0).push(pkt);
    return 0;
}