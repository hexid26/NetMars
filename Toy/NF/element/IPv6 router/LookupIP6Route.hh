#include <iostream>
#include "packet.hh"
#include "net.hh"
#include "routing_v6.hh"

RoutingTableV6 *_table_ptr;

union uint128_t {
    uint32_t u32[4];
    uint64_t u64[2];
    uint8_t u8[16];

    void set_ignored()
    {
        u64[0] = 0xffffffffffffffffu;
        u64[1] = 0xffffffffffffffffu;
    }

    bool is_ignored()
    {
        return u64[0] == 0xffffffffffffffffu && u64[0] == 0xffffffffffffffffu;
    }
};

inline bool operator==(const uint128_t &key1, const uint128_t &key2)
{
    return key1.u64[0] == key2.u64[0] && key1.u64[1] == key2.u64[1];
}
inline bool operator!=(const uint128_t &key1, const uint128_t &key2)
{
    return key1.u64[0] != key2.u64[0] || key1.u64[1] != key2.u64[1];
}

static uint64_t ntohll(uint64_t val)
{
    return ((((val) >> 56) & 0x00000000000000ff) | (((val) >> 40) & 0x000000000000ff00) |
            (((val) >> 24) & 0x0000000000ff0000) | (((val) >> 8) & 0x00000000ff000000) |
            (((val) << 8) & 0x000000ff00000000) | (((val) << 24) & 0x0000ff0000000000) |
            (((val) << 40) & 0x00ff000000000000) | (((val) << 56) & 0xff00000000000000));
}

int LookupIP6Route(int input_port, Packet *pkt)
{
    struct ether_header *ethh = (struct ether_header *)pkt->data();
    struct ip6_hdr *ip6h = (struct ip6_hdr *)(ethh + 1);
    uint128_t dest_addr;
    uint16_t lookup_result = 0xffff;
    std::swap(dest_addr.u64[0], dest_addr.u64[1]);
    dest_addr.u64[1] = ntohll(dest_addr.u64[1]);
    dest_addr.u64[0] = ntohll(dest_addr.u64[0]);

    // TODO: make an interface to set these locks to be
    // automatically handled by process_batch() method.
    //rte_rwlock_read_lock(_rwlock_ptr);

    //_table_ptr = (RoutingTableV6*)ctx->node_local_storage->get_alloc("ipv6_table");

    lookup_result = _table_ptr->lookup((reinterpret_cast<uint128_t *>(&dest_addr)));
    //rte_rwlock_read_unlock(_rwlock_ptr);

    if (lookup_result == 0xffff)
    {
        /* Could not find destination. Use the second output for "error" packets. */
        pkt->kill();
        return 0;
    }

    // #ifdef NBA_IPFWD_RR_NODE_LOCAL
    // unsigned iface_in = anno_get(&pkt->anno, NBA_ANNO_IFACE_IN);
    // unsigned n = (iface_in <= ((unsigned) num_tx_ports / 2) - 1) ? 0 : (num_tx_ports / 2);
    // rr_port = (rr_port + 1) % (num_tx_ports / 2) + n;
    // #else
    // rr_port = (rr_port + 1) % (num_tx_ports);
    // #endif
    // anno_set(&pkt->anno, NBA_ANNO_IFACE_OUT, rr_port);
    // output(0).push(pkt);
    // return 0;
}