#pragma once
#include <stdlib.h>
#include <unistd.h>
#include <fstream>
#include "Packet.hh"

#define TBL24_SIZE ((1 << 24) + 1)  // 2^24
#define TBLLONG_SIZE ((1 << 24) + 1)
static inline int get_TBL24_size() { return TBL24_SIZE; }
static inline int get_TBLlong_size() { return TBLLONG_SIZE; }

typedef std::unordered_map<uint32_t, uint16_t> route_hash_t;

class IPlookup {
 protected:
  int num_tx_ports;      // Variable to store # of tx port from computation thread.
  unsigned int rr_port;  // Round-robin port #
  route_hash_t tables[33];
  uint16_t *TBL24;
  uint16_t *TBLlong;
  char curr_path[256];
  bool isNF;

 public:
  //此函数用于向tables中添加下一跳地址
  int add_route(route_hash_t *tables, uint32_t addr, uint16_t len, uint16_t nexthop) {
    tables[len][addr] = nexthop;
    return 0;
  }

  //此函数用于从routing_info.txt生成tables，其中下一跳的地址带有随机性
  int load_rib_from_file(route_hash_t *tables, const char *filename) {
    isNF = false;
    FILE *fp;
    char buf[256];
    for (int i = 0; i < 256; i++) {
      if (curr_path[i] == 'N' && curr_path[i + 1] == 'F' && curr_path[i + 2] == '\0') {
        isNF = true;
        strcat(curr_path, "/element/IPv4 router");
        break;
      }
      if (curr_path[i] == '\0') {
        break;
      }
    }
    strcat(curr_path, "/");
    strcat(curr_path, filename);
    fp = fopen(curr_path, "r");

    if (fp == NULL) {
      printf("IpCPULookup element: error during opening file \'%s\'.: %s\n", filename, strerror(errno));
    }
    assert(fp != NULL);

    while (fgets(buf, 256, fp)) {
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

  // DIR-24-8-BASIC将IPv4地址空间分为长度分别为24 和8的两部分(TBL24和TBLlong)
  //此函数用于从tables生成TBL24表和TBLlong表
  int build_direct_fib(const route_hash_t *tables, uint16_t *TBL24, uint16_t *TBLlong) {
    // build_fib() is called for each node sequencially, before comp thread starts.
    // No rwlock protection is needed.
    memset(TBL24, 0, TBL24_SIZE * sizeof(uint16_t));
    memset(TBLlong, 0, TBLLONG_SIZE * sizeof(uint16_t));
    unsigned int current_TBLlong = 0;

    for (unsigned i = 0; i <= 24; i++) {
      for (auto it = tables[i].begin(); it != tables[i].end(); it++) {
        uint32_t addr = (*it).first;
        uint16_t dest = (uint16_t)(0xffffu & (uint64_t)(*it).second);
        uint32_t start = addr >> 8;
        uint32_t end = start + (0x1u << (24 - i));
        for (unsigned k = start; k < end; k++) TBL24[k] = dest;
      }
    }

    for (unsigned i = 25; i <= 32; i++) {
      for (auto it = tables[i].begin(); it != tables[i].end(); it++) {
        uint32_t addr = (*it).first;
        uint16_t dest = (uint16_t)(0x0000ffff & (uint64_t)(*it).second);
        uint16_t dest24 = TBL24[addr >> 8];
        if (((uint16_t)dest24 & 0x8000u) == 0) {
          uint32_t start = current_TBLlong + (addr & 0x000000ff);
          uint32_t end = start + (0x00000001u << (32 - i));

          for (unsigned j = current_TBLlong; j <= current_TBLlong + 256; j++) {
            if (j < start || j >= end)
              TBLlong[j] = dest24;
            else
              TBLlong[j] = dest;
          }
          TBL24[addr >> 8] = (uint16_t)(current_TBLlong >> 8) | 0x8000u;
          current_TBLlong += 256;
          assert(current_TBLlong <= TBLLONG_SIZE);
        } else {
          uint32_t start = ((uint32_t)dest24 & 0x7fffu) * 256 + (addr & 0x000000ff);
          uint32_t end = start + (0x00000001u << (32 - i));

          for (unsigned j = start; j < end; j++) TBLlong[j] = dest;
        }
      }
    }
    return 0;
  }

  int initialize() {
    // Loading IP forwarding table from file.
    // TODO: load it from parsed configuration.

    const char *filename = "routing_info.txt";  // TODO: remove it or change it to configuration..
    getcwd(curr_path, 256);
    printf("element::IPlookup: Loading the routing table entries from %s\n", filename);
    load_rib_from_file(tables, filename);

    int size1 = sizeof(uint16_t) * get_TBL24_size();
    int size2 = sizeof(uint16_t) * get_TBLlong_size();
    void *ptr1 = new char *[size1];
    void *ptr2 = new char *[size2];
    assert(ptr1 != NULL);
    assert(ptr2 != NULL);
    memset(ptr1, 0xcd, size1);
    memset(ptr2, 0xcd, size2);
    TBL24 = (uint16_t *)ptr1;
    TBLlong = (uint16_t *)ptr2;
    build_direct_fib(tables, TBL24, TBLlong);
    return 0;
  }

  //此函数用于在TBL24表和TBLlong表中查找结果
  void direct_lookup(const uint16_t *TBL24, const uint16_t *TBLlong, const uint32_t ip, uint16_t *dest) {
    uint16_t temp_dest;
    temp_dest = TBL24[ip >> 8];
    if (temp_dest & 0x8000u) {
      int index2 = (((uint32_t)(temp_dest & 0x7fff)) << 8) + (ip & 0xff);
      temp_dest = TBLlong[index2];
    }
    *dest = temp_dest;
  }

  /* CPU-only method */
  int process(int input_port, Packet *pkt) {
    cout << "\n>>3.正在测试IPlookup模块..." << endl;
    // num_tx_ports = 0;
    // rr_port = 0;
    initialize();

    //创建TBL24.txt和TBLlong.txt
    // getcwd(curr_path, 256);
    // if (isNF)
    // {
    //     strcat(curr_path, "/element/IPv4 router");
    // }
    // strcat(curr_path, "/");
    // strcat(curr_path, "TBL24.txt");
    // ofstream TBL24_out(curr_path);
    // getcwd(curr_path, 256);
    // if (isNF)
    // {
    //     strcat(curr_path, "/element/IPv4 router");
    // }
    // strcat(curr_path, "/");
    // strcat(curr_path, "TBLlong.txt");
    // ofstream TBLlong_out(curr_path);
    // cout << "正在生成TBL24.txt，这可能需要很长的时间..." << endl;
    // for (int i = 0; i < get_TBL24_size(); i++)
    // {
    //     TBL24_out << TBL24[i] << endl;
    // }
    // TBL24_out.close();
    // cout << "正在生成TBLlong.txt，这可能需要很长的时间..." << endl;
    // for (int i = 0; i < get_TBLlong_size(); i++)
    // {
    //     TBLlong_out << TBLlong[i] << endl;
    // }
    // TBLlong_out.close();

    struct ether_header *ethh = (struct ether_header *)pkt->data();
    struct ipv4_hdr *iph = (struct ipv4_hdr *)(ethh + 1);
    uint32_t dest_addr = ntohl(iph->dst_addr);
    uint16_t lookup_result = 0xffff;

    direct_lookup(TBL24, TBLlong, dest_addr, &lookup_result);
    if (lookup_result == 0xffff) {
      //路由查找失败
      cout << "Could not find destination." << endl;
      /* Could not find destination. Use the second output for "error" packets. */
      return 0;
    }
    char *next_hop = new char[4];
    sprintf(next_hop, "%04x", lookup_result);
    cout << "下一跳网络地址:0x" << next_hop << endl;
    cout << "十进制:" << lookup_result << endl;
    if (lookup_result == 0) {
      cout << "指向默认缺省路由" << endl;
    }

    // #ifdef NBA_IPFWD_RR_NODE_LOCAL
    //         unsigned iface_in = anno_get(&pkt->anno, NBA_ANNO_IFACE_IN);
    //         unsigned n = (iface_in <= ((unsigned)num_tx_ports / 2) - 1) ? 0 : (num_tx_ports / 2);
    //         rr_port = (rr_port + 1) % (num_tx_ports / 2) + n;
    // #else
    //         rr_port = (rr_port + 1) % (num_tx_ports);
    // #endif
    //         anno_set(&pkt->anno, NBA_ANNO_IFACE_OUT, rr_port);
    return 0;
  }
};