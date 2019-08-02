#include <iostream>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <unistd.h>

#include "Packet_Head.hpp"

#define NETMAP_WITH_LIBS
#define NETMAP_WITH_DEBUG
#include <net/netmap_user.h>

unsigned long long pkt_sum = 0; // 收包总数
unsigned long long tcp_sum = 0; // tcp包总数
unsigned long long udp_sum = 0; // udp包总数

void show_help_info() {
  printf("可使用参数：[-i ethX]\n");
  printf("    默认使用网卡 enp7s0，程序会自动加入 /R 后缀\n");
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
static void receive_packets(struct netmap_ring *ring) {
  int slot_idx;
  char *buf;
  // // int pkt_len;

  // 遍历所有的槽位
  while (!nm_ring_empty(ring)) {
    slot_idx = ring->cur;
    buf = NETMAP_BUF(ring, ring->slot[slot_idx].buf_idx);  // buf 就是收到的报文
    // // pkt_len = ring->slot[slot_idx].len;                    // pkt_len 是当前报文长度
    ring->head = ring->cur = nm_ring_next(ring, slot_idx); // 下一个槽位
    pkt_sum++;                                             // 统计收包个数

    // //printf("Packets %ld，Length %d Bytes\n", pkt_sum, pkt_len);
    // // print_MacInfo(buf);
    // print_IPInfo(buf);

    //判断UDP，TCP并打印
    switch (is_TCPorUDP(buf)) {
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
  }
  fflush(stdout);
}

int main(int argc, char *argv[]) {
  struct nm_desc *d = NULL;
  struct pollfd fds;
  struct netmap_ring *ring;
  int rx_queue_idx;
  int para_res;
  std::string if_name = "enp7s0";
  int wait_secs = 3;

  // 设置参数
  while ((para_res = getopt(argc, argv, "hi:w:")) != -1) {
    switch (para_res) {
    case 'i':
      if_name = std::string(optarg);
      break;
    case 'w':
      wait_secs = std::stoi(std::string(optarg));
      break;
    case 'h':
      show_help_info();
      break;
    default:
      break;
    }
  }
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
      receive_packets(ring); // 处理 ring
    }
  }
}
