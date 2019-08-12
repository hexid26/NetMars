#include <iostream>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <unistd.h>

#include "PKT_Filter.hpp"
#include "PKT_Ring.hpp"

#define NETMAP_WITH_LIBS
#define NETMAP_WITH_DEBUG
#include <net/netmap_user.h>

unsigned long long pkt_sum = 0; // 收包总数
unsigned long long tcp_sum = 0; // tcp包总数
unsigned long long udp_sum = 0; // udp包总数

void ctrl_c_handler(int singal) {
  printf(
      "\n============================================================\nPkt Sum = %llu; TCP + IP = (%llu :: %llu, "
      "%llu)\n",
      pkt_sum, tcp_sum + udp_sum, tcp_sum, udp_sum);
  exit(1);
}

void show_help_info() {
  printf("可使用参数：[-i ethX]\n");
  printf("    默认使用网卡 enp7s0，程序会自动加入 /R 后缀\n");
  printf("可使用参数：[-c NUM]\n");
  printf("    pkt_ring 容量，默认 1000 个包\n");
  printf("可使用参数：[-w int]\n");
  printf("    默认暂停 3 秒，等待若干秒（ netmap 启动需要时间）\n");
  printf("\n");
  exit(0);
}

// * 处理 interface 的接口名字， 根据情况在后面补上“/R”
inline std::string process_suffix(std::string str) {
  int pos_slash = str.find_last_of('/');
  if (pos_slash == std::string::npos) {
    str = str + "/Rx";
  } else {
    str = str.substr(0, pos_slash) + "/Rx";
  }
  return str;
}

// * 收包处理函数
static void receive_packets(struct netmap_ring *ring, PKT_Ring *pkt_ring, PKT_Filter *pkt_filter) {
  int slot_idx;
  char *buf;
  // // int pkt_len;

  // 遍历所有的槽位
  while (!nm_ring_empty(ring)) {
    slot_idx = ring->cur;
    buf = NETMAP_BUF(ring, ring->slot[slot_idx].buf_idx); // buf 就是收到的报文
    // unsigned int pkt_len = ring->slot[slot_idx].len;      // pkt_len 是当前报文长度
    pkt_sum++; // 统计收包个数

    // * 打印数据包信息
    /* printf("Packets %llu，Length %d Bytes\n", pkt_sum, pkt_len);
    pkt_filter->print_MacInfo(buf);
    pkt_filter->print_IPInfo(buf); */

    // * 统计最大包的长度
    static unsigned int max_pkt_length = 0; // 测试最大的以太网帧长度
    if (max_pkt_length < ring->slot[slot_idx].len) {
      max_pkt_length = ring->slot[slot_idx].len;
      printf("\ndebug::max_pkt_length = %u\n", max_pkt_length);
    }

    // * 判断UDP，TCP并打印
    switch (pkt_filter->is_TCPorUDP(buf)) {
    case 1:
      tcp_sum++;
      printf("Pkt Sum = %llu; TCP Sum = %llu; UDP Sum = %llu\r", pkt_sum, tcp_sum, udp_sum);
      break;
    case 2:
      udp_sum++;
      printf("Pkt Sum = %llu; TCP Sum = %llu; UDP Sum = %llu\r", pkt_sum, tcp_sum, udp_sum);
      break;
    default:
      break;
    }

    if (pkt_ring->push(buf) < 0) {
      printf(
          "\n============================================================\nPkt Sum = %llu; TCP + IP = (%llu :: %llu, "
          "%llu)\n",
          pkt_sum, tcp_sum + udp_sum, tcp_sum, udp_sum);
      free(pkt_ring);
      exit(1);
    }
    ring->head = ring->cur = nm_ring_next(ring, slot_idx); // 下一个槽位
  }

  fflush(stdout);
}

int main(int argc, char *argv[]) {
  // * ctrl + c 中断时的输出
  signal(SIGINT, ctrl_c_handler);
  struct nm_desc *d = NULL;
  struct pollfd fds;
  struct netmap_ring *ring;
  int pkt_ring_capacity = 1000;
  int rx_queue_idx;
  int para_res;
  std::string if_name = "enp7s0";
  int wait_secs = 3;

  // 设置参数
  while ((para_res = getopt(argc, argv, "hi:w:c:")) != -1) {
    switch (para_res) {
    case 'i':
      if_name = std::string(optarg);
      break;
    case 'w':
      wait_secs = std::stoi(std::string(optarg));
      break;
    case 'c':
      pkt_ring_capacity = std::stoi(std::string(optarg));
      break;
    case 'h':
      show_help_info();
      break;
    default:
      break;
    }
  }
  PKT_Ring *pkt_ring = new PKT_Ring("test", pkt_ring_capacity);
  PKT_Filter *pkt_filter = new PKT_Filter;
  if_name = "netmap:" + if_name;
  if_name = process_suffix(if_name);
  printf("DEBUG::interface name = %s\n", if_name.c_str());
  d = nm_open(if_name.c_str(), NULL, 0, 0); // 注意格式，netmap:ehtX
  if (d == NULL) {
    printf("ERROR::nm_open 运行失败\n");
    exit(-1);
  }

  fds.fd = d->fd;
  fds.events = POLLIN;
  printf("INFO::等待 %d 秒以确保 netmap 启动\n", wait_secs);
  sleep(3);
  printf("INFO::启动完成\n");

  while (1) {
    if (poll(&fds, 1, 1) < 0) {
      perror("poll()");
      exit(1);
    }

    // 遍历所有的接收队列
    for (rx_queue_idx = d->first_rx_ring; rx_queue_idx <= d->last_rx_ring; rx_queue_idx++) {
      ring = NETMAP_RXRING(d->nifp, rx_queue_idx);
      receive_packets(ring, pkt_ring, pkt_filter); // 处理 ring
    }
  }
}
