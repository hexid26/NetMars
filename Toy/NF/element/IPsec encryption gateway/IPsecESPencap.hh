#include "Packet.hh"
#include <random>
#include <vector>
#include <functional>
#include <emmintrin.h>

class IPsecESPencap
{
private:
	struct espencap_sa_entry
	{
		uint32_t spi;					   /* Security Parameters Index */
		uint32_t rpl; /* Replay counter */ // XXX: is this right to use this one?
		uint32_t gwaddr;				   // XXX: not used yet; when this value is used?
		uint64_t entry_idx;
	};
	int num_tunnels;														//Maximum number of IPsec tunnels
	unordered_map<struct ipaddr_pair, struct espencap_sa_entry *> sa_table; //Hash table which stores per-flow values for each tunnel
	function<uint64_t()> rand;												//A random function.
	struct espencap_sa_entry *sa_table_linear[1024];						//A temporary hack to allow all flows to be processed.
	uint64_t tunnel_counter;

public:
	int initialize()
	{
		num_tunnels = 1024;
		rand = bind(uniform_int_distribution<uint64_t>{}, mt19937_64());
		// TODO: Version of ip pkt (4 or 6), src & dest addr of encapsulated pkt should be delivered from configuation.
		assert(num_tunnels != 0);
		for (int i = 0; i < num_tunnels; i++)
		{
			struct ipaddr_pair pair;
			pair.src_addr = 0x0a000001u;
			pair.dest_addr = 0x0a000000u | (i + 1); // (rand() % 0xffffff);
			struct espencap_sa_entry *entry = new struct espencap_sa_entry;
			entry->spi = rand() % 0xffffffffu;
			entry->rpl = rand() % 0xffffffffu;
			entry->gwaddr = 0x0a000001u;
			entry->entry_idx = i;
			auto result = sa_table.insert(make_pair<ipaddr_pair &, espencap_sa_entry *&>(pair, entry));
			assert(result.second == true);
			sa_table_linear[i] = entry;
		}
		return 0;
	}

	int process(int input_port, Packet *pkt)
	{
		// Temp: Assumes input packet is always IPv4 packet.
		// TODO: make it to handle IPv6 also.
		// TODO: Set src & dest of encapped pkt to ip addrs from configuration.
		initialize();
		struct ether_header *ethh = (struct ether_header *)(&pkt->ethh);
		// if (ntohs(ethh->ether_type) != ETHER_TYPE_IPV4)	how to use ntohs()?
		if (ethh->ether_type != ETHER_TYPE_IPV4)
		{
			return 0;
		}
		struct iphdr *iph = (struct iphdr *)(&pkt->iph);
		struct ipaddr_pair pair;
		// pair.src_addr = ntohl(iph->saddr);	how to use ntohl()?
		pair.src_addr = iph->saddr;
		// pair.dest_addr = ntohl(iph->daddr);	how to use ntohl()?
		pair.dest_addr = iph->daddr;
		auto sa_item = sa_table.find(pair);
		struct espencap_sa_entry *sa_entry = NULL;
		if (sa_item != sa_table.end())
		{
			sa_entry = sa_item->second;
			assert(sa_entry->entry_idx < 1024u);
		}
		else
		{
			return 0;
			// FIXME: this is to encrypt all traffic regardless sa_entry lookup results.
			//        (just for worst-case performance tests)
			//unsigned f = (tunnel_counter ++) % num_tunnels;
			//sa_entry = sa_table_linear[f];
			//anno_set(&pkt->anno, NBA_ANNO_IPSEC_FLOW_ID, f);
			//assert(f < 1024u);
		}
		// int ip_len = ntohs(iph->tot_len);	how to use ntohs()?
		int ip_len = iph->tot_len;
		int pad_len = AES_BLOCK_SIZE - (ip_len + 2) % AES_BLOCK_SIZE;
		int enc_size = ip_len + pad_len + 2; // additional two bytes mean the "extra" part.
		int extended_ip_len = (short)(sizeof(struct iphdr) + enc_size + sizeof(struct esphdr) + SHA_DIGEST_LENGTH);
		int length_to_extend = extended_ip_len - ip_len;
		assert(0 == (enc_size % AES_BLOCK_SIZE));
		struct esphdr *esph = (struct esphdr *)(iph + 1);
		uint8_t *encapped_iph = (uint8_t *)esph + sizeof(*esph);
		uint8_t *esp_trail = encapped_iph + ip_len;
		// Hack for latency measurement experiments.
		uintptr_t latency_ptr = 0;
		constexpr uintptr_t latency_offset = sizeof(struct ether_header) + sizeof(struct ipv4_hdr) + sizeof(struct udphdr);
		static_assert(sizeof(struct udphdr) + sizeof(uint16_t) + sizeof(uint64_t) <= sizeof(struct esphdr) + sizeof(ipv4_hdr),
					  "Encryption may overwrite latency!");
		memmove(encapped_iph, iph, ip_len);	// copy the IP header and payload.
		memset(esp_trail, 0, pad_len);		   // clear the padding.
		esp_trail[pad_len] = (uint8_t)pad_len; // store pad_len at the second byte from last.
		esp_trail[pad_len + 1] = 0x04;		   // store IP-in-IP protocol id at the last byte.
		// Fill the ESP header.
		esph->esp_spi = sa_entry->spi;
		esph->esp_rpl = sa_entry->rpl;
		// Generate random IV.
		// uint64_t iv_first_half = rand();
		// uint64_t iv_second_half = rand();
		// __m128i new_iv = _mm_set_epi64((__m64)iv_first_half, (__m64)iv_second_half);
		// _mm_storeu_si128((__m128i *)esph->esp_iv, new_iv);
		iph->ihl = (20 >> 2); // standard IP header size.
		iph->tot_len = htons(extended_ip_len);
		iph->protocol = 0x32; // mark that this packet contains a secured payload.
		iph->check = 0;		  // ignoring previous checksum.
		iph->check = ip_fast_csum(iph, iph->ihl);
		return 0;
	}
};

// Input packet: (pkt_in)
// +----------+---------------+---------+
// | Ethernet | IP(proto=UDP) | payload |
// +----------+---------------+---------+
// ^ethh      ^iph
//
// Input packet when latency measurement: (pkt_in)
// +----------+---------------+-------+-------------------------------+---------+
// | Ethernet | IP(proto=UDP) |  UDP  | 16-bit key + 64-bit timestamp | padding |
// +----------+---------------+-------+-------------------------------+---------+
// ^ethh      ^iph                    ^latency_ptr
// The position of latency_ptr is overwritten after prepending the ESP header.
//
// Output packet: (pkt_out)
// +----------+---------------+--------+----+------------+---------+-------+---------------------+
// | Ethernet | IP(proto=ESP) |  ESP   | IP |  payload   | padding | extra | HMAC-SHA1 signature |
// +----------+---------------+--------+----+------------+---------+-------+---------------------+
//      14            20          16     20                pad_len     2    SHA_DIGEST_LENGTH = 20
// ^ethh      ^iph            ^esph    ^encapped_iph     ^esp_trail
//