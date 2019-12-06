#pragma once
#include "Packet.hpp"
#include <random>
#include <vector>
#include <functional>
#include <emmintrin.h>
#include <unordered_map>

// Input packet: (pkt_in)
// +----------+---------------+---------+
// | Ethernet | IP(proto=UDP) | payload |
// +----------+---------------+---------+
// ^ethh      ^iph
//
// Output packet: (pkt_out)
// +----------+---------------+--------+----+------------+---------+-------+---------------------+
// | Ethernet | IP(proto=ESP) |  ESP   | IP |  payload   | padding | extra | HMAC-SHA1 signature |
// +----------+---------------+--------+----+------------+---------+-------+---------------------+
//      14            20          24     20                pad_len     2    SHA_DIGEST_LENGTH = 20
// ^ethh      ^iph            ^esph    ^encapped_iph     ^esp_trail

//此函数用于计算IP头的校验值
static uint16_t ip_fast_csum(const void *iph, unsigned int ihl)
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
	int num_tunnels;								 //Maximum number of IPsec tunnels
	function<uint64_t()> rand;						 //A random function.
	struct espencap_sa_entry *sa_table_linear[1024]; //A temporary hack to allow all flows to be processed.

public:
	int process(int input_port, Packet *pkt)
	{
		cout << "\n>>1.正在测试IPsecESPencap模块..." << endl;
		/*建立了一个Hash表，<源-目的IP地址对，ESP封装结构>*/
		//Hash table which stores per-flow values for each tunnel
		unordered_map<struct ipaddr_pair, struct espencap_sa_entry *> sa_table;
		num_tunnels = 1024;
		rand = bind(uniform_int_distribution<uint64_t>{}, mt19937_64());
		// TODO: Version of ip pkt (4 or 6), src & dest addr of encapsulated pkt should be delivered from configuation.
		assert(num_tunnels != 0);
		for (int i = 0; i < num_tunnels; i++)
		{
			//Hash表中源IP地址是相同的，而目的IP地址是随机生成的
			struct ipaddr_pair pair;
			pair.src_addr = 0xc0a80001u;
			pair.dest_addr = 0xc0a80000u | (i + 1); // (rand() % 0xffffff);
			//生成ESP封装结构
			struct espencap_sa_entry *entry = new struct espencap_sa_entry;
			entry->spi = rand() % 0xffffffffu;
			entry->rpl = rand() % 0xffffffffu;
			//指定IP网关地址
			entry->gwaddr = 0xc0a80001u;
			entry->entry_idx = i;
			//插入<源-目的IP地址对，ESP封装结构>并构建Hash表
			auto result = sa_table.insert(make_pair<ipaddr_pair &, espencap_sa_entry *&>(pair, entry));
			assert(result.second == true);
			sa_table_linear[i] = entry;
		}
		// Temp: Assumes input packet is always IPv4 packet.
		// TODO: make it to handle IPv6 also.
		// TODO: Set src & dest of encapped pkt to ip addrs from configuration.

		//pkt->data()可以得到uint8_t形式的包数据流
		struct ether_header *ethh = (struct ether_header *)(pkt->data());
		cout << "以太网类型：" << hex << "0x" << setw(4) << setfill('0') << ntohs(ethh->ether_type) << endl;
		if (ntohs(ethh->ether_type) != ETHER_TYPE_IPV4)
		{
			return 0;
		}
		struct iphdr *iph = (struct iphdr *)(ethh + 1);
		struct ipaddr_pair pair;

		cout << "网络字节顺序源IP地址：";
		for (int i = 0; i < 4; i++)
		{
			cout << dec << (int)u32tu8(iph->saddr)[i];
			if (i != 3)
				cout << ".";
		}
		cout << "\n网络字节顺序目的IP地址：";
		for (int i = 0; i < 4; i++)
		{
			cout << dec << (int)u32tu8(iph->daddr)[i];
			if (i != 3)
				cout << ".";
		}

		pair.src_addr = ntohl(iph->saddr);
		pair.dest_addr = ntohl(iph->daddr);

		cout << "\n主机字节顺序源IP地址：";
		for (int i = 0; i < 4; i++)
		{
			cout << dec << (int)u32tu8(pair.src_addr)[i];
			if (i != 3)
				cout << ".";
		}
		cout << "\n主机字节顺序目的IP地址：";
		for (int i = 0; i < 4; i++)
		{
			cout << dec << (int)u32tu8(pair.dest_addr)[i];
			if (i != 3)
				cout << ".";
		}

		//在<源-目的IP地址对，ESP封装结构>Hash表中查找输入的源-目的IP地址对并得到对应的ESP封装结构
		auto sa_item = sa_table.find(pair);
		struct espencap_sa_entry *sa_entry = NULL;
		if (sa_item != sa_table.end())
		{
			cout << "\n在Hash表中已找到当前包对应的ESP封装结构" << endl;
			sa_entry = sa_item->second;
			anno_set(&pkt->anno, NBA_ANNO_IPSEC_FLOW_ID, sa_entry->entry_idx);
			assert(sa_entry->entry_idx < 1024u);

			cout << "\tspi:" << sa_entry->spi << endl;
			cout << "\trpl:" << sa_entry->rpl << endl;
			cout << "\tgwaddr:" << sa_entry->gwaddr << endl;
			cout << "\tentry_idx:" << sa_entry->entry_idx << endl;
		}
		else
		{
			return 1;
			// FIXME: this is to encrypt all traffic regardless sa_entry lookup results.
			//        (just for worst-case performance tests)
			//unsigned f = (tunnel_counter ++) % num_tunnels;
			//sa_entry = sa_table_linear[f];
			//anno_set(&pkt->anno, NBA_ANNO_IPSEC_FLOW_ID, f);
			//assert(f < 1024u);
		}
		int ip_len = ntohs(iph->tot_len);
		cout << "IP数据报长度（IP头+payload）：" << ip_len << "字节" << endl;
		int pad_len = AES_BLOCK_SIZE - (ip_len + 2) % AES_BLOCK_SIZE;
		cout << "padding长度：" << pad_len << "字节" << endl;
		int enc_size = ip_len + pad_len + 2; // additional two bytes mean the "extra" part.
		cout << "extra长度：" << 2 << "字节" << endl;
		cout << "HAMC-SHA1 signature长度：" << SHA_DIGEST_LENGTH << "字节" << endl;
		int extended_ip_len = (short)(sizeof(struct iphdr) + enc_size + sizeof(struct esphdr) + SHA_DIGEST_LENGTH);
		cout << "ESP头长度：" << sizeof(struct esphdr) << "字节" << endl;
		cout << "带有ESP协议的新IP头长度：" << sizeof(struct iphdr) << "字节" << endl;
		cout << "拓展后IP数据报长度=带有ESP协议的新IP头长度+ESP头长度+IP数据报长度+padding长度+extra长度+HAMC-SHA1 signature长度=" << extended_ip_len << "字节" << endl;
		// int length_to_extend = extended_ip_len - ip_len;
		assert(0 == (enc_size % AES_BLOCK_SIZE));
		struct esphdr *esph = (struct esphdr *)(iph + 1);
		uint8_t *encapped_iph = (uint8_t *)esph + sizeof(*esph);
		uint8_t *esp_trail = encapped_iph + ip_len;
		// Hack for latency measurement experiments.
		// uintptr_t latency_ptr = 0;
		// constexpr uintptr_t latency_offset = sizeof(struct ether_header) + sizeof(struct ipv4_hdr) + sizeof(struct udphdr);
		static_assert(sizeof(struct udphdr) + sizeof(uint16_t) + sizeof(uint64_t) <= sizeof(struct esphdr) + sizeof(ipv4_hdr),
					  "Encryption may overwrite latency!");
		cout << "正在将原始IP头和payload的数据后移..." << endl;
		memmove(encapped_iph, iph, ip_len); // copy the IP header and payload.
		cout << "正在将padding部分初始化为0..." << endl;
		memset(esp_trail, 0, pad_len); // clear the padding.
		cout << "正在用" << pad_len << "和" << 0x04 << "填充extra部分..." << endl;
		esp_trail[pad_len] = (uint8_t)pad_len; // store pad_len at the second byte from last.
		esp_trail[pad_len + 1] = 0x04;		   // store IP-in-IP protocol id at the last byte.
		cout << "正在新IP头和原始IP头之间插入ESP头..." << endl;
		// Fill the ESP header.
		esph->esp_spi = sa_entry->spi;
		esph->esp_rpl = sa_entry->rpl;
		cout << "\tesp_spi:" << sa_entry->spi << endl;
		cout << "\tesp_rpl:" << sa_entry->rpl << endl;
		// Generate random IV.
		uint64_t iv_first_half = rand();
		uint64_t iv_second_half = rand();
		__m128i new_iv = _mm_set_epi64((__m64)iv_first_half, (__m64)iv_second_half);
		cout << "\tesp_iv:";
		_mm_storeu_si128((__m128i *)esph->esp_iv, new_iv);
		for (int i = 0; i < 16; i++)
		{
			cout << (int)esph->esp_iv[i];
			if (i != 15)
			{
				cout << " ";
			}
			else
				cout << endl;
		}
		iph->ihl = (20 >> 2); // standard IP header size.
		cout << "正在更新IP头的ihl为" << iph->ihl << endl;
		iph->tot_len = htons(extended_ip_len);
		cout << "正在更新IP头的tot_len（IP数据包的长度）为" << extended_ip_len << endl;
		iph->protocol = 0x32; // mark that this packet contains a secured payload.
		cout << "正在更新IP头的协议为0x" << hex << (int)iph->protocol << "（指示该包含有被加密的payload）" << endl;
		iph->check = 0; // ignoring previous checksum.
		iph->check = ip_fast_csum(iph, iph->ihl);
		cout << "计算IP头的校验值为" << dec << iph->check << endl;

		//IPsecESPencap对于Packet包的所有更改全部是通过指针操作内存(uint8_t*形式的字符流)实现的
		//所以可以通过pkt->puint8访问IPsecESPencap处理后的结果
		return 0;
	}
};
