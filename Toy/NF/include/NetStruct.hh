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
#include <openssl/ossl_typ.h>
#include <openssl/hmac.h>

#define EVP_MAX_IV_LENGTH 16
#define EVP_MAX_BLOCK_LENGTH 32

#define ETHER_TYPE_IPV4 0x0800
#define ETHER_TYPE_IPV6 0x86DD

using namespace std;

#define anno_isset(anno_item, anno_id) (anno_item != nullptr && (anno_item)->bitmask & (1 << anno_id))

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

static inline void anno_set(struct annotation_set *anno_item,
                            unsigned anno_id,
                            int64_t value)
{
    anno_item->bitmask |= (1 << anno_id);
    anno_item->values[anno_id] = value;
}

static inline int64_t anno_get(struct annotation_set *anno_item,
                               unsigned anno_id)
{
    return anno_item->values[anno_id];
}

/**
 * IPv4 address pair to be used as hash-table keys.
 */
struct ipaddr_pair
{
    uint32_t src_addr;
    uint32_t dest_addr;
    ipaddr_pair() {}
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

struct alignas(8) hmac_sa_entry
{
    uint8_t hmac_key[HMAC_KEY_SIZE];
    int entry_idx;
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

/* Common object types */
typedef union {
    void *ptr;
#ifdef USE_PHI
    cl_mem clmem;
#endif
#ifdef USE_KNAPP
    struct knapp_memobj m;
#endif
} dev_mem_t;

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























#define NBA_MAX_NODELOCALSTORAGE_ENTRIES (16)
class NodeLocalStorage
{
    /**
     * NodeLocalStorage is a node-version of thread local storage.
     * Elements can use this to store per-node information, such as
     * routing tables.  The storage unit is mapped with a string key
     * for convenience.  The keys from different elements must not
     * overlap as this implementation does not have separate namespaces
     * for each element instances.
     *
     * The elements must use the methods of this class only on
     * initialization steps, and must NOT use them in the data-path.
     * They must keep the pointers and rwlocks retrieved during
     * initialization step to use them in the data-path.
     * It is optional for elements to use rwlocks.  It is recommended
     * to use them only if the storage needs to be updated inside the
     * data-path.
     * TODO: add multiple types of storage, such as RCU-backed ones.
     *
     * alloc() method must be called inside initialize_per_node() method
     * of elements, and get_alloc() / get_rwlock() methods should be
     * called inside configure() method which is called per thread ( =
     * per element instance).
     */
protected:
    unsigned _node_id;
    //rte_rwlock_t *_rwlocks[NBA_MAX_NODELOCALSTORAGE_ENTRIES];
    void *_pointers[NBA_MAX_NODELOCALSTORAGE_ENTRIES];
    unordered_map<string, int> _keys;
    // rte_spinlock_t _node_lock;

public:
    NodeLocalStorage(unsigned node_id)
    {
        _node_id = node_id;
        for (int i = 0; i < NBA_MAX_NODELOCALSTORAGE_ENTRIES; i++)
        {
            _pointers[i] = NULL;
            //_rwlocks[i] = NULL;
        }
        // rte_spinlock_init(&_node_lock);
    }

    virtual ~NodeLocalStorage()
    {
        // TODO: free all existing entries.
    }

    int alloc(const char *key, size_t size)
    {
        // rte_spinlock_lock(&_node_lock);
        size_t kid = _keys.size();
        assert(kid < NBA_MAX_NODELOCALSTORAGE_ENTRIES);
        _keys.insert(std::pair<std::string, int>(key, kid));

        // void *ptr = rte_malloc_socket("nls_alloc", size, CACHE_LINE_SIZE, _node_id);
        void *ptr = new char *[size];
        assert(ptr != NULL);
        memset(ptr, 0xcd, size);
        size_t real_size = 0;
        //assert(0 == rte_malloc_validate(ptr, &real_size));
        _pointers[kid] = ptr;
        // RTE_LOG(DEBUG, ELEM, "NLS[%u]: malloc req size %'lu bytes, real size %'lu bytes\n", _node_id, size, real_size);

        //rte_rwlock_t *rwlock = (rte_rwlock_t *) rte_malloc_socket("nls_lock", sizeof(rte_rwlock_t), 64, _node_id);
        //assert(rwlock != NULL);
        //rte_rwlock_init(rwlock);
        //_rwlocks[kid] = rwlock;

        // rte_spinlock_unlock(&_node_lock);
        return kid;
    }

    void *get_alloc(const char *key)
    {
        // rte_spinlock_lock(&_node_lock);
        assert(_keys.find(key) != _keys.end());
        int kid = _keys[key];
        void *ptr = _pointers[kid];
        // rte_spinlock_unlock(&_node_lock);
        return ptr;
    }

    // rte_rwlock_t *get_rwlock(const char *key)
    // {
    //     rte_spinlock_lock(&_node_lock);
    //     assert(_keys.find(key) != _keys.end());
    //     int kid = _keys[key];
    //     //rte_rwlock_t *lock = _rwlocks[kid];
    //     rte_spinlock_unlock(&_node_lock);
    //     //return lock;
    //     return nullptr;
    // }

    // void free(const char *key)
    // {
    //     rte_spinlock_lock(&_node_lock);
    //     assert(_keys.find(key) != _keys.end());
    //     int kid = _keys[key];
    //     void *ptr = _pointers[kid];
    //     rte_free(ptr);
    //     //delete (char*)ptr;
    //     //rte_rwlock_t *rwlock = _rwlocks[kid];
    //     //rte_free(rwlock);
    //     _pointers[kid] = NULL;
    //     rte_spinlock_unlock(&_node_lock);
    //     // TODO: remove entry from _pointers, _rwlocks, and _keys.
    //     // But we do not implement it because usually node-local
    //     // storage is alloccated-once and used-forever.
    // }
};

class comp_thread_context
{
public:
    // comp_thread_context();
    // virtual ~comp_thread_context();
    void stop_rx();
    void resume_rx();

    void build_element_graph(const char *config); // builds element graph
    void initialize_graph_global();
    void initialize_graph_per_node();
    void initialize_graph_per_thread();
    // void initialize_offloadables_per_node(ComputeDevice *device);
    void io_tx_new(void *data, size_t len, int out_port);

public:
    struct ev_async *terminate_watcher;
    // CountedBarrier *thread_init_barrier;
    // CondVar *ready_cond;
    bool *ready_flag;
    // Lock *elemgraph_lock;
    NodeLocalStorage *node_local_storage;

    // char _reserved1[64]; /* prevent false-sharing */

    // struct ev_loop *loop;
    // struct core_location loc;
    // unsigned num_tx_ports;
    // unsigned num_nodes;
    // unsigned num_coproc_ppdepth;
    // unsigned num_combatch_size;
    // unsigned num_batchpool_size;
    // unsigned num_taskpool_size;
    // unsigned task_completion_queue_size;
    // bool preserve_latency;

    // struct rte_mempool *batch_pool;
    // struct rte_mempool *dbstate_pool;
    // struct rte_mempool *task_pool;
    // struct rte_mempool *packet_pool;
    // ElementGraph *elem_graph;
    // SystemInspector *inspector;
    // FixedRing<ComputeContext *> *cctx_list;
    // PacketBatch *input_batch;
    // DataBlock *datablock_registry[NBA_MAX_DATABLOCKS];

    // bool stop_task_batching;
    // struct rte_ring *rx_queue;
    // struct ev_async *rx_watcher;
    // struct coproc_thread_context *coproc_ctx;

    // char _reserved2[64]; /* prevent false-sharing */

    // struct io_thread_context *io_ctx;
    // std::unordered_map<std::string, ComputeDevice *> *named_offload_devices;
    // std::vector<ComputeDevice*> *offload_devices;
    // struct rte_ring *offload_input_queues[NBA_MAX_COPROCESSORS]; /* ptr to per-device task input queue */

    // char _reserved3[64]; /* prevent false-sharing */

    // struct rte_ring *task_completion_queue; /* to receive completed offload tasks */
    // struct ev_async *task_completion_watcher;
    // struct ev_check *check_watcher;
} __cache_aligned;

comp_thread_context *ctx;