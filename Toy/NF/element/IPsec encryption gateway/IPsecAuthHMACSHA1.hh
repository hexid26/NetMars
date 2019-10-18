#include "Packet.hpp"
#include <vector>
#include <string>
#include <unordered_map>

/* Array which stores per-tunnel HMAC key for each tunnel.
 * It is copied to each node's node local storage during per-node initialization
 * and freed in per-thread initialization.*/
struct hmac_sa_entry *hmac_sa_entry_array;
/* Map which stores (src-dst pair, tunnel index).
 * It is copied to each node's node local storage during per-node initialization*/
unordered_map<struct ipaddr_pair, int> hmac_sa_table;

class IPsecAuthHMACSHA1
{
protected:
    /* Maximum number of IPsec tunnels */
    int num_tunnels;
    int dummy_index;
    unordered_map<struct ipaddr_pair, int> *h_sa_table; // tunnel lookup is done in CPU only. No need for GPU ptr.
    struct hmac_sa_entry *flows = nullptr;              // used in CPU.
    dev_mem_t *flows_d;                                 // points to the device buffer.

private:
    const int idx_pkt_offset = 0;
    const int idx_hmac_key_indice = 1;

public:
    IPsecAuthHMACSHA1()
    {
        num_tunnels = 0;
        dummy_index = 0;
    }
    ~IPsecAuthHMACSHA1() {}
    const char *class_name() const { return "IPsecAuthHMACSHA1"; }
    const char *port_count() const { return "1/1"; }

    int initialize()
    {
        // Get ptr for CPU & GPU pkt processing from the node-local storage.
        /* Storage for host ipsec tunnel index table */
        h_sa_table = (unordered_map<struct ipaddr_pair, int> *)ctx->node_local_storage->get_alloc("h_hmac_sa_table");
        /* Storage for host hmac key array */
        flows = (struct hmac_sa_entry *)ctx->node_local_storage->get_alloc("h_hmac_flows");
        /* Get device pointer from the node local storage. */
        flows_d = (dev_mem_t *)ctx->node_local_storage->get_alloc("d_hmac_flows_ptr");
        if (hmac_sa_entry_array != NULL)
        {
            free(hmac_sa_entry_array);
            hmac_sa_entry_array = NULL;
        }
        return 0;
    }

    int initialize_global()
    {
        // generate global table and array only once per element class.
        struct ipaddr_pair pair;
        struct hmac_sa_entry *entry;
        assert(num_tunnels != 0);
        hmac_sa_entry_array = (struct hmac_sa_entry *)malloc(sizeof(struct hmac_sa_entry) * num_tunnels);
        for (int i = 0; i < num_tunnels; i++)
        {
            pair.src_addr = 0x0a000001u;
            pair.dest_addr = 0x0a000000u | (i + 1); // (rand() % 0xffffff);
            auto result = hmac_sa_table.insert(make_pair<ipaddr_pair &, int &>(pair, i));
            assert(result.second == true);
            entry = &hmac_sa_entry_array[i];
            entry->entry_idx = i;
            // rte_memcpy(&entry->hmac_key, "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd", HMAC_KEY_SIZE);
            //!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
        }
        return 0;
    };

    int initialize_per_node()
    {
        unordered_map<struct ipaddr_pair, int> *temp_table = NULL;
        struct hmac_sa_entry *temp_array = NULL;
        struct ipaddr_pair key;
        int value, size;
        /* Storage for host ipsec tunnel index table */
        size = sizeof(unordered_map<struct ipaddr_pair, int>);
        ctx->node_local_storage->alloc("h_hmac_sa_table", size);
        temp_table = (unordered_map<struct ipaddr_pair, int> *)ctx->node_local_storage->get_alloc("h_hmac_sa_table");
        // new (temp_table) unordered_map<struct ipaddr_pair, int>();
        for (auto iter = hmac_sa_table.begin(); iter != hmac_sa_table.end(); iter++)
        {
            key = iter->first;
            value = iter->second;
            temp_table->insert(make_pair<ipaddr_pair &, int &>(key, value));
        }
        /* Storage for host hmac key array */
        size = sizeof(struct hmac_sa_entry) * num_tunnels;
        ctx->node_local_storage->alloc("h_hmac_flows", size);
        temp_array = (struct hmac_sa_entry *)ctx->node_local_storage->get_alloc("h_hmac_flows");
        assert(hmac_sa_entry_array != NULL);
        // rte_memcpy(temp_array, hmac_sa_entry_array, size);
        //!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
        /* Storage for pointer, which points hmac key array in device */
        ctx->node_local_storage->alloc("d_hmac_flows_ptr", sizeof(dev_mem_t));
        return 0;
    }

    int configure(comp_thread_context *ctx, vector<string> &args)
    {
        num_tunnels = 1024; // TODO: this value must be come from configuration.
        return 0;
    }

    /* CPU-only method */
    int process(int input_port, Packet *pkt)
    {
        // We assume the size of hmac_key is less than 64 bytes.
        // TODO: check if input pkt is encapulated or not.
        struct ether_header *ethh = (struct ether_header *)(&pkt->ethh);
        struct iphdr *iph = (struct iphdr *)(ethh + 1);
        struct esphdr *esph = (struct esphdr *)(iph + 1);
        uint8_t *encaped_iph = (uint8_t *)esph + sizeof(*esph);
        unsigned char *payload_out = (unsigned char *)((uint8_t *)ethh + sizeof(struct ether_header) + sizeof(struct iphdr));
        int payload_len = (ntohs(iph->tot_len) - (iph->ihl * 4) - SHA_DIGEST_LENGTH);
        uint8_t isum[SHA_DIGEST_LENGTH];
        uint8_t hmac_buf[2048];
        struct hmac_sa_entry *sa_entry;
        uint8_t *hmac_key;
        sa_entry = &flows[anno_get(&pkt->anno, NBA_ANNO_IPSEC_FLOW_ID)];
        hmac_key = sa_entry->hmac_key;
        // rte_memcpy(hmac_buf + 64, payload_out, payload_len);
        for (int i = 0; i < 8; i++)
            *((uint64_t *)hmac_buf + i) = 0x3636363636363636LLU ^ *((uint64_t *)hmac_key + i);
        SHA1(hmac_buf, 64 + payload_len, isum);
        // rte_memcpy(hmac_buf + 64, isum, SHA_DIGEST_LENGTH);
        for (int i = 0; i < 8; i++)
        {
            *((uint64_t *)hmac_buf + i) = 0x5c5c5c5c5c5c5c5cLLU ^ *((uint64_t *)hmac_key + i);
        }
        SHA1(hmac_buf, 64 + SHA_DIGEST_LENGTH, payload_out + payload_len);
        // TODO: correctness check..
        return 0;
    }
};
// Input packet: assumes encaped
// +----------+---------------+--------+----+------------+---------+-------+---------------------+
// | Ethernet | IP(proto=ESP) |  ESP   | IP |  payload   | padding | extra | HMAC-SHA1 signature |
// +----------+---------------+--------+----+------------+---------+-------+---------------------+
// ^ethh      ^iph            ^esph    ^encaped_iph
//                            ^payload_out
//                            ^encapsulated
//                            <===== authenticated part (payload_len) =====>