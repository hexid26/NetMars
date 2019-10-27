#pragma once
#include <iostream>
#include <assert.h>
#include <string.h>
#include <cstdint>
#include <cassert>
#include <stdint.h>
#include <unordered_map>

#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>

#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>

using namespace std;

#define ETHER_TYPE_IPV4 0x0800
#define ETHER_TYPE_IPV6 0x86DD
#define anno_isset(anno_item, anno_id) (anno_item != nullptr && (anno_item)->bitmask & (1 << anno_id))

struct ipaddr_pair
{
    uint32_t src_addr;
    uint32_t dest_addr;
    bool operator==(const ipaddr_pair &other) const
    {
        return (src_addr == other.src_addr && dest_addr == other.dest_addr);
    }
};
/* We need to define custom hash function for our key.
 * Just borrow the hash function for 64-bit integer as the key is a simple
 * pair of two 32-bit integers. */
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

enum
{
    // TODO: Shouldn't it be 16(= AES_BLOCK_SIZE)? why it was set to 8?
    ESP_IV_LENGTH = 16
};

enum : int
{
    HMAC_KEY_SIZE = 64,
};

enum PacketAnnotationKind : unsigned
{
    NBA_ANNO_IFACE_IN = 0,
    NBA_ANNO_IFACE_OUT,
    NBA_ANNO_TIMESTAMP,
    NBA_ANNO_BATCH_ID,
    NBA_ANNO_IPSEC_FLOW_ID,
    NBA_ANNO_IPSEC_IV1,
    NBA_ANNO_IPSEC_IV2,
    //End of PacketAnnotationKind
    NBA_MAX_ANNOTATION_SET_SIZE
};

enum BatchAnnotationKind : unsigned
{
    NBA_BANNO_LB_DECISION = 0,
    //End of BatchAnnotationKind
    NBA_MAX_BANNOTATION_SET_SIZE
};

struct annotation_set
{
    uint64_t bitmask;
    int64_t values[NBA_MAX_ANNOTATION_SET_SIZE];
    static_assert((unsigned)NBA_MAX_ANNOTATION_SET_SIZE >= (unsigned)NBA_MAX_BANNOTATION_SET_SIZE,
                  "The number of packet annotations must be larger than that of batch annotations.");
};

static inline void anno_set(struct annotation_set *anno_item, unsigned anno_id, int64_t value)
{
    anno_item->bitmask |= (1 << anno_id);
    anno_item->values[anno_id] = value;
}

static inline int64_t anno_get(struct annotation_set *anno_item, unsigned anno_id)
{
    return anno_item->values[anno_id];
}

/**
 * IPv4 Header
 */
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
    /* Security Parameters Index */
    uint32_t esp_spi;
    /* Replay counter */
    uint32_t esp_rpl;
    /* initial vector */
    uint8_t esp_iv[ESP_IV_LENGTH];
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
    // Below two variables have same value.
    uint8_t aes_key[AES_BLOCK_SIZE]; // Used in CUDA encryption.
    AES_KEY aes_key_t;               // Prepared for AES library function.
    EVP_CIPHER_CTX evpctx;
    int entry_idx; // Index of current flow: value for verification.
};

struct alignas(8) hmac_sa_entry
{
    uint8_t hmac_key[HMAC_KEY_SIZE];
    int entry_idx;
};