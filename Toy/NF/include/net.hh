#include <arpa/inet.h>

#include <aes_ctr.hh>
#include <openssl/ossl_typ.h>
#include <openssl/sha.h>

#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>

#define anno_isset(anno_item, anno_id) (anno_item != nullptr && (anno_item)->bitmask & (1 << anno_id))

#define EVP_MAX_IV_LENGTH 16
#define EVP_MAX_BLOCK_LENGTH 32

#define ETHER_TYPE_IPV4 0x0800
#define ETHER_TYPE_IPV6 0x86DD

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

enum
{
    // TODO: Shouldn't it be 16(= AES_BLOCK_SIZE)? why it was set to 8?
    ESP_IV_LENGTH = 16
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

enum : int
{
    HMAC_KEY_SIZE = 64,
};

struct alignas(8) aes_block_info
{
    int pkt_idx;
    int block_idx;
    int pkt_offset;
    int magic;
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

struct alignas(8) hmac_aes_sa_entry
{
    // Below two variables have same value.
    uint8_t aes_key[AES_BLOCK_SIZE]; // Used in CUDA encryption.
    AES_KEY aes_key_t;               // Prepared for AES library function.
    EVP_CIPHER_CTX evpctx;
    int entry_idx; // Index of current flow: value for varification.
    uint8_t hmac_key[HMAC_KEY_SIZE];
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

uint16_t ip_fast_csum(const void *iph, unsigned int ihl)
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