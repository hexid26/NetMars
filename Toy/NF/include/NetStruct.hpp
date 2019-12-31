#pragma once
#include <iostream>
#include <stdio.h>
#include <assert.h>
#include <string.h>

#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#define ESP_IV_LENGTH 16
#define HMAC_KEY_SIZE 64
#define ETHER_TYPE_IPV4 ETHERTYPE_IP
#define TBL24_SIZE ((1 << 24) + 1) //2^24
#define TBLLONG_SIZE ((1 << 24) + 1)
#define IGNORED_IP 0xFFffFFffu

struct ipaddr_pair
{
    uint32_t src_addr;
    uint32_t dest_addr;
    bool operator==(const ipaddr_pair &other) const
    {
        return (src_addr == other.src_addr && dest_addr == other.dest_addr);
    }
};

namespace std
{
template <>
struct hash<ipaddr_pair>
{
public:
    std::size_t operator()(ipaddr_pair const &p) const
    {
        return std::hash<uint64_t>()((((uint64_t)p.src_addr) << 32) | (p.dest_addr));
    }
};
} // namespace std

struct ipv4_hdr
{
    uint8_t version_ihl;      /**< version and header length */
    uint8_t type_of_service;  /**< type of service */
    uint16_t total_length;    /**< length of packet */
    uint16_t packet_id;       /**< packet ID */
    uint16_t fragment_offset; /**< fragmentation offset */
    uint8_t time_to_live;     /**< time to live */
    uint8_t next_proto_id;    /**< protocol ID */
    uint16_t hdr_checksum;    /**< header checksum */
    uint32_t src_addr;        /**< source address */
    uint32_t dst_addr;        /**< destination address */
};

struct esphdr
{
    uint32_t esp_spi;              /* Security Parameters Index */
    uint32_t esp_rpl;              /* Replay counter */
    uint8_t esp_iv[ESP_IV_LENGTH]; /* initial vector */
};

struct espencap_sa_entry
{
    uint32_t spi;                      /* Security Parameters Index */
    uint32_t rpl; /* Replay counter */ // XXX: is this right to use this one?
    uint32_t gwaddr;                   // XXX: not used yet; when this value is used?
    uint64_t entry_idx;
};

struct alignas(8) hmac_sa_entry
{
    uint8_t hmac_key[HMAC_KEY_SIZE];
    int entry_idx;
};

struct evp_cipher_ctx_st
{
    const EVP_CIPHER *cipher;
    //ENGINE *engine;       /* functional reference if 'cipher' is ENGINE-provided */
    void *engine;
    int encrypt; /* encrypt or decrypt */
    int buf_len; /* number we have left */

    unsigned char oiv[EVP_MAX_IV_LENGTH];    /* original iv */
    unsigned char iv[EVP_MAX_IV_LENGTH];     /* working iv */
    unsigned char buf[EVP_MAX_BLOCK_LENGTH]; /* saved partial block */
    int num;                                 /* used by cfb/ofb/ctr mode */

    void *app_data;      /* application stuff */
    int key_len;         /* May change for variable length cipher */
    unsigned long flags; /* Various flags */
    void *cipher_data;   /* per EVP data */
    int final_used;
    int block_mask;
    unsigned char final[EVP_MAX_BLOCK_LENGTH]; /* possible final block */
} /* EVP_CIPHER_CTX */;

struct alignas(8) aes_sa_entry
{
    AES_KEY aes_key_t; // Prepared for AES library function.
    EVP_CIPHER_CTX evpctx;
    int entry_idx; // Index of current flow: value for verification.
};