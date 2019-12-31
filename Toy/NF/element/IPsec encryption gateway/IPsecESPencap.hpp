#pragma once
#include "Packet.hpp"
#include "auxiliary.hpp"
#include <random>
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
extern int ipsec_thread_rem;

class IPsecESPencap
{
private:
	int num_tunnels;					   //Maximum number of IPsec tunnels
	static std::function<uint64_t()> rand; //A random function.
	static std::unordered_map<struct ipaddr_pair, struct espencap_sa_entry *> sa_table;

public:
	IPsecESPencap()
	{
		// std::cout << "\n>>1.正在测试IPsecESPencap模块..." << std::endl;
		/*建立了一个Hash表，<源-目的IP地址对，ESP封装结构>*/
		//Hash table which stores per-flow values for each tunnel
		num_tunnels = 1024;
		rand = std::bind(std::uniform_int_distribution<uint64_t>{}, std::mt19937_64());
		// TODO: Version of ip pkt (4 or 6), src & dest addr of encapsulated pkt should be delivered from configuation.
		assert(num_tunnels != 0);
		for (int i = 0; i < num_tunnels; i++)
		{
			//Hash表中源IP地址是相同的，而目的IP地址是随机生成的
			struct ipaddr_pair pair;
			pair.src_addr = 0xc0a80001u;
			pair.dest_addr = 0xc0a80000u | (i + 1); // (frand() % 0xffffff);
			//生成ESP封装结构
			struct espencap_sa_entry *entry = new struct espencap_sa_entry;
			entry->spi = rand() % 0xffffffffu;
			entry->rpl = rand() % 0xffffffffu;
			//指定IP网关地址
			entry->gwaddr = 0xc0a80001u;
			entry->entry_idx = i;
			//插入<源-目的IP地址对，ESP封装结构>并构建Hash表
			auto result = sa_table.insert(std::make_pair<ipaddr_pair &, espencap_sa_entry *&>(pair, entry));
			assert(result.second == true);
		}
		// Temp: Assumes input packet is always IPv4 packet.
		// TODO: make it to handle IPv6 also.
		// TODO: Set src & dest of encapped pkt to ip addrs from configuration.
	}

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

	static void ipsec_esp(Packet **pkt, int thread_size)
	{
		for (int i = 0; i < thread_size; i++)
		{
			if (pkt[i]->is_save == true)
			{
				struct ether_header *ethh = (struct ether_header *)(pkt[i]->data());
				// std::cout << "以太网类型：" << std::hex << "0x" << std::setw(4) << std::setfill('0') << ntohs(ethh->ether_type) << std::endl;
				if (ntohs(ethh->ether_type) != ETHER_TYPE_IPV4)
				{
					pkt[i]->is_save = false;
					continue;
				}
				struct iphdr *iph = (struct iphdr *)(ethh + 1);
				struct ipaddr_pair pair;
				pair.src_addr = ntohl(iph->saddr);
				pair.dest_addr = ntohl(iph->daddr);
				//在<源-目的IP地址对，ESP封装结构>Hash表中查找输入的源-目的IP地址对并得到对应的ESP封装结构
				auto sa_item = sa_table.find(pair);
				struct espencap_sa_entry *sa_entry = NULL;
				if (sa_item != sa_table.end())
				{
					sa_entry = sa_item->second;
					assert(sa_entry->entry_idx < 1024u);
					// std::cout << "\tspi:" << sa_entry->spi << std::endl;
					// std::cout << "\trpl:" << sa_entry->rpl << std::endl;
					// std::cout << "\tgwaddr:" << sa_entry->gwaddr << std::endl;
					// std::cout << "\tentry_idx:" << sa_entry->entry_idx << std::endl;
				}
				else
				{
					//在Hash表中找不到当前包对应的ESP封装结构
					continue;
				}
				int ip_len = ntohs(iph->tot_len);
				int pad_len = AES_BLOCK_SIZE - (ip_len + 2) % AES_BLOCK_SIZE;
				int enc_size = ip_len + pad_len + 2; // additional two bytes mean the "extra" part.
				int extended_ip_len = sizeof(struct iphdr) + enc_size + sizeof(struct esphdr) + SHA_DIGEST_LENGTH;
				int length_to_extend = extended_ip_len - ip_len;
				//拓展包的字符流（接口设计）
				uint8_t *new_pac_data = (uint8_t *)malloc(sizeof(uint8_t) * (pkt[i]->plen + length_to_extend));
				memcpy(new_pac_data, pkt[i]->data(), pkt[i]->plen);
				free(pkt[i]->puint8);
				pkt[i]->puint8 = new_pac_data;
				pkt[i]->plen += length_to_extend;
				ethh = (struct ether_header *)(pkt[i]->data());
				iph = (struct iphdr *)(ethh + 1);

				assert(0 == (enc_size % AES_BLOCK_SIZE));
				struct esphdr *esph = (struct esphdr *)(iph + 1);
				uint8_t *encapped_iph = (uint8_t *)esph + sizeof(struct esphdr);
				uint8_t *esp_trail = encapped_iph + ip_len;

				memmove(encapped_iph, iph, ip_len);	// copy the IP header and payload.
				memset(esp_trail, 0, pad_len);		   // clear the padding.
				esp_trail[pad_len] = (uint8_t)pad_len; // store pad_len at the second byte from last.
				esp_trail[pad_len + 1] = 0x04;		   // store IP-in-IP protocol id at the last byte.
				// Fill the ESP header.
				esph->esp_spi = sa_entry->spi;
				esph->esp_rpl = sa_entry->rpl;
				// std::cout << "\tesp_spi:" << sa_entry->spi << std::endl;
				// std::cout << "\tesp_rpl:" << sa_entry->rpl << std::endl;
				// Generate random IV.
				uint64_t iv_first_half = rand();
				uint64_t iv_second_half = rand();
				__m128i new_iv = _mm_set_epi64((__m64)iv_first_half, (__m64)iv_second_half);
				_mm_storeu_si128((__m128i *)esph->esp_iv, new_iv);
				// standard IP header size.
				iph->ihl = (20 >> 2);
				iph->tot_len = htons(extended_ip_len);
				iph->protocol = 0x32; // mark that this packet contains a secured payload.
				iph->check = 0;		  // ignoring previous checksum.
				iph->check = ip_fast_csum(iph, iph->ihl);
				//IPsecESPencap对于Packet包的所有更改全部是通过指针操作内存(uint8_t*形式的字符流)实现的
			}
		}
	}

	void process(Packet **pkt, int batch_size)
	{
		std::thread pth[AVAIL_THREAD_NUM];
		for (int i = 0; i < AVAIL_THREAD_NUM; i++)
		{
			int packet_num = batch_size / (int)AVAIL_THREAD_NUM;
			if (i < ipsec_thread_rem)
				packet_num++;
			pth[i] = std::thread(ipsec_esp,
								 pkt + i * packet_num,
								 packet_num);
			pth[i].join();
		}
	}
};

std::function<uint64_t()> IPsecESPencap::rand;
std::unordered_map<struct ipaddr_pair, struct espencap_sa_entry *> IPsecESPencap::sa_table;