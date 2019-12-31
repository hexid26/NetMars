#pragma once
#include "Packet.hpp"
#include "auxiliary.hpp"
#include <unordered_map>
#include <fstream>
#include <unistd.h>

#define get_TBL24_size() TBL24_SIZE
#define get_TBLlong_size() TBLLONG_SIZE

typedef std::unordered_map<uint32_t, uint16_t> route_hash_t;

extern int ipv4_thread_rem;

void ipv4_route_lookup_get_cuda_kernel(
    const uint16_t *TBL24, const uint16_t *TBLlong,
    const uint8_t *pac_data, const int total_len, const int batch_size,
    const unsigned int *pac_sign, uint16_t *lookup_result);

class IPlookup
{
private:
    route_hash_t hash_tables[33];
    char curr_path[256];
    bool isNF;
    static uint16_t *u16_TBL24;
    static uint16_t *u16_TBLlong;

public:
    IPlookup()
    {
        // Loading IP forwarding table from file.
        // TODO: load it from parsed configuration.
        const char *filename = "routing_info.txt"; // TODO: remove it or change it to configuration..
        getcwd(curr_path, 256);
        printf("element::IPlookup: Loading the routing table entries from %s\n", filename);
        load_rib_from_file(hash_tables, filename);

        int size1 = sizeof(uint16_t) * get_TBL24_size();
        int size2 = sizeof(uint16_t) * get_TBLlong_size();
        void *ptr1 = new char *[size1];
        void *ptr2 = new char *[size2];
        assert(ptr1 != NULL);
        assert(ptr2 != NULL);
        memset(ptr1, 0xcd, size1);
        memset(ptr2, 0xcd, size2);
        u16_TBL24 = (uint16_t *)ptr1;
        u16_TBLlong = (uint16_t *)ptr2;
        build_direct_fib(hash_tables, u16_TBL24, u16_TBLlong);
    }

    //此函数用于向tables中添加下一跳地址
    int add_route(
        route_hash_t *tables, uint32_t addr,
        uint16_t len, uint16_t nexthop)
    {
        tables[len][addr] = nexthop;
        return 0;
    }

    //此函数用于从routing_info.txt生成tables，其中下一跳的地址带有随机性
    int load_rib_from_file(
        route_hash_t *tables, const char *filename)
    {
        isNF = false;
        FILE *fp;
        char buf[256];
        for (int i = 0; i < 256; i++)
        {
            if (curr_path[i] == 'N' && curr_path[i + 1] == 'F' && curr_path[i + 2] == '\0')
            {
                isNF = true;
                strcat(curr_path, "/element/IPv4 router");
                break;
            }
            if (curr_path[i] == '\0')
            {
                break;
            }
        }
        strcat(curr_path, "/");
        strcat(curr_path, filename);
        fp = fopen(curr_path, "r");

        if (fp == NULL)
        {
            printf("IpCPULookup element: error during opening file \'%s\'.: %s\n", filename, strerror(errno));
        }
        assert(fp != NULL);

        while (fgets(buf, 256, fp))
        {
            char *str_addr = strtok(buf, "/");
            char *str_len = strtok(NULL, "\n");
            assert(str_len != NULL);

            uint32_t addr = ntohl(inet_addr(str_addr));
            uint16_t len = atoi(str_len);

            add_route(tables, addr, len, rand() % 65532 + 1);
        }
        fclose(fp);
        return 0;
    }

    //DIR-24-8-BASIC将IPv4地址空间分为长度分别为24 和8的两部分(TBL24和TBLlong)
    //此函数用于从tables生成TBL24表和TBLlong表
    int build_direct_fib(
        const route_hash_t *tables,
        uint16_t *TBL24, uint16_t *TBLlong)
    {
        memset(TBL24, 0, TBL24_SIZE * sizeof(uint16_t));
        memset(TBLlong, 0, TBLLONG_SIZE * sizeof(uint16_t));
        unsigned int current_TBLlong = 0;

        for (unsigned i = 0; i <= 24; i++)
        {
            for (auto it = tables[i].begin(); it != tables[i].end(); it++)
            {
                uint32_t addr = (*it).first;
                uint16_t dest = (uint16_t)(0xffffu & (uint64_t)(*it).second);
                uint32_t start = addr >> 8;
                uint32_t end = start + (0x1u << (24 - i));
                for (unsigned k = start; k < end; k++)
                    TBL24[k] = dest;
            }
        }

        for (unsigned i = 25; i <= 32; i++)
        {
            for (auto it = tables[i].begin(); it != tables[i].end(); it++)
            {
                uint32_t addr = (*it).first;
                uint16_t dest = (uint16_t)(0x0000ffff & (uint64_t)(*it).second);
                uint16_t dest24 = TBL24[addr >> 8];
                if (((uint16_t)dest24 & 0x8000u) == 0)
                {
                    uint32_t start = current_TBLlong + (addr & 0x000000ff);
                    uint32_t end = start + (0x00000001u << (32 - i));

                    for (unsigned j = current_TBLlong; j <= current_TBLlong + 256; j++)
                    {
                        if (j < start || j >= end)
                            TBLlong[j] = dest24;
                        else
                            TBLlong[j] = dest;
                    }
                    TBL24[addr >> 8] = (uint16_t)(current_TBLlong >> 8) | 0x8000u;
                    current_TBLlong += 256;
                    assert(current_TBLlong <= TBLLONG_SIZE);
                }
                else
                {
                    uint32_t start = ((uint32_t)dest24 & 0x7fffu) * 256 + (addr & 0x000000ff);
                    uint32_t end = start + (0x00000001u << (32 - i));

                    for (unsigned j = start; j < end; j++)
                        TBLlong[j] = dest;
                }
            }
        }
        return 0;
    }

    void write_table_to_file()
    {
        getcwd(curr_path, 256);
        if (isNF)
        {
            strcat(curr_path, "/element/IPv4 router");
        }
        strcat(curr_path, "/");
        strcat(curr_path, "TBL24.txt");
        std::ofstream TBL24_out(curr_path);
        getcwd(curr_path, 256);
        if (isNF)
        {
            strcat(curr_path, "/element/IPv4 router");
        }
        strcat(curr_path, "/");
        strcat(curr_path, "TBLlong.txt");
        std::ofstream TBLlong_out(curr_path);
        printf("正在生成TBL24.txt，这可能需要很长的时间...\n");
        for (int i = 0; i < get_TBL24_size(); i++)
        {
            TBL24_out << u16_TBL24[i] << std::endl;
        }
        TBL24_out.close();
        printf("正在生成TBLlong.txt，这可能需要很长的时间...\n");
        for (int i = 0; i < get_TBLlong_size(); i++)
        {
            TBLlong_out << u16_TBLlong[i] << std::endl;
        }
        TBLlong_out.close();
    }

    static void print_lookup_result(uint16_t lookup_result)
    {
        char *next_hop = (char *)malloc(sizeof(char) * 4);
        sprintf(next_hop, "%04x", lookup_result);
        char next_ip1[3], next_ip2[3];
        next_ip1[0] = next_hop[0];
        next_ip1[1] = next_hop[1];
        next_ip2[0] = next_hop[2];
        next_ip2[1] = next_hop[3];
        next_ip1[2] = next_ip2[2] = '\0';
        int _next_ip1 = 0, _next_ip2 = 0;
        sscanf(next_ip1, "%x", &_next_ip1);
        sscanf(next_ip2, "%x", &_next_ip2);
        printf("下一跳网络地址:0x%s\n", next_hop);
        // printf("%d.%d\n", _next_ip1, _next_ip2);
        printf("十进制:%u\n", lookup_result);
        if (lookup_result == 0)
        {
            // printf("指向默认缺省路由\n");
        }
        free(next_hop);
    }

    static void ip_lookup(Packet **pkt, int thread_size)
    {
        // printf("\n>>3.正在测试IPlookup模块...\n");
        for (int i = 0; i < thread_size; i++)
        {
            if (pkt[i]->is_save == true)
            {
                struct ether_header *ethh = (struct ether_header *)pkt[i]->data();
                struct ipv4_hdr *iph = (struct ipv4_hdr *)(ethh + 1);
                uint16_t lookup_result = 0xffff;
                printf("%u\n", iph->dst_addr);
                uint32_t dest_addr = ntohl(iph->dst_addr);
                uint16_t temp_dest = u16_TBL24[dest_addr >> 8];
                if (temp_dest & 0x8000u)
                {
                    int index2 = (((uint32_t)(temp_dest & 0x7fff)) << 8) + (dest_addr & 0xff);
                    temp_dest = u16_TBLlong[index2];
                }
                lookup_result = temp_dest;
                if (lookup_result == 0xffff)
                {
                    // printf("Could not find destination.\n");
                    continue;
                }
                print_lookup_result(lookup_result);
            }
        }
    }

    void process(bool IsGPU, Packet **pkt, int batch_size)
    {
        if (!IsGPU)
        {
            std::thread pth[AVAIL_THREAD_NUM];
            for (int i = 0; i < AVAIL_THREAD_NUM; i++)
            {
                int packet_num = batch_size / (int)AVAIL_THREAD_NUM;
                if (i < ipv4_thread_rem)
                    packet_num++;
                pth[i] = std::thread(ip_lookup,
                                     pkt + i * packet_num,
                                     packet_num);
                pth[i].join();
            }
        }
        else
        {
            int total_len = 0;
            for (int i = 0; i < batch_size; i++)
            {
                total_len += (int)(pkt[i]->plen);
            }
            uint8_t *pac_data = (uint8_t *)malloc(sizeof(uint8_t) * total_len);
            unsigned int *pac_sign = (unsigned int *)malloc(sizeof(unsigned int) * batch_size);
            uint8_t *p_pac_data = pac_data;
            int sign = 0;
            for (int i = 0; i < batch_size; i++)
            {
                pac_sign[i] = sign;
                int pac_len = (int)(pkt[i]->plen);
                memcpy(p_pac_data, pkt[i]->data(), pac_len);
                p_pac_data += pac_len;
                sign += pac_len;
            }

            uint16_t *lookup_result = (uint16_t *)malloc(sizeof(uint16_t) * batch_size);
            ipv4_route_lookup_get_cuda_kernel(u16_TBL24, u16_TBLlong, pac_data, total_len, batch_size, pac_sign, lookup_result);
            for (int i = 0; i < batch_size; i++)
            {
                print_lookup_result(lookup_result[i]);
            }
        }
    }
};

uint16_t *IPlookup::u16_TBL24;
uint16_t *IPlookup::u16_TBLlong;