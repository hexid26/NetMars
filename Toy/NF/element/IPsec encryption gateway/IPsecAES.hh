#include "packet.hh"
#include "net.hh"

#define anno_isset(anno_item, anno_id) (anno_item != nullptr && (anno_item)->bitmask & (1 << anno_id))

// void AES_ctr128_encrypt(uint8_t *, uint8_t *, int, AES_KEY *, uint8_t *, uint8_t *, unsigned *){

// };

int IPsecAES(int input_port, Packet *pkt)
{
    struct ether_header *ethh = (struct ether_header *)pkt->data();
    struct iphdr *iph = (struct iphdr *)(ethh + 1);
    struct esphdr *esph = (struct esphdr *)(iph + 1);
    uint8_t ecount_buf[AES_BLOCK_SIZE] = {0};

    // TODO: support decrpytion.
    uint8_t *encrypt_ptr = (uint8_t *)esph + sizeof(*esph);
    int encrypted_len = ntohs(iph->tot_len) - sizeof(struct iphdr) - sizeof(struct esphdr) - SHA_DIGEST_LENGTH;
    int pad_len = AES_BLOCK_SIZE - (encrypted_len + 2) % AES_BLOCK_SIZE;
    int enc_size = encrypted_len + pad_len + 2; // additional two bytes mean the "extra" part.
    int err = 0;
    struct aes_sa_entry *sa_entry = NULL;

    if (anno_isset(&pkt->anno, NBA_ANNO_IPSEC_FLOW_ID))
    {
        //sa_entry = &flows[anno_get(&pkt->anno, NBA_ANNO_IPSEC_FLOW_ID)];
        unsigned mode = 0;
#ifdef USE_OPENSSL_EVP
        int cipher_body_len = 0;
        int cipher_add_len = 0;
        memcpy(sa_entry->evpctx.iv, esph->esp_iv, AES_BLOCK_SIZE);
        if (EVP_EncryptUpdate(&sa_entry->evpctx, encrypt_ptr, &cipher_body_len, encrypt_ptr, encrypted_len) != 1)
            fprintf(stderr, "IPsecAES: EVP_EncryptUpdate() - %s\n", ERR_error_string(ERR_get_error(), NULL));
        if (EVP_EncryptFinal(&sa_entry->evpctx, encrypt_ptr + cipher_body_len, &cipher_add_len) != 1)
            fprintf(stderr, "IPsecAES: EVP_EncryptFinal() - %s\n", ERR_error_string(ERR_get_error(), NULL));
#else
        AES_ctr128_encrypt(encrypt_ptr, encrypt_ptr, enc_size, &sa_entry->aes_key_t, esph->esp_iv, ecount_buf, &mode);
#endif
    }
    else
    {
        pkt->kill();
        return 0;
    }
    // output(0).push(pkt);
    return 0;
}