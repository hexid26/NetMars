#ifndef __PACKET_HEAD_FUNCTION__
#define __PACKET_HEAD_FUNCTION__

#include <iomanip>
#include <sstream>
#include <stdio.h>
#include <string>

// * 数据帧定义，头14个字节，尾4个字节（尾部不用管）
typedef struct _MAC_FRAME_HEADER
{
  u_int8_t mac_DstMacAddress[6]; // 目的mac地址
  u_int8_t mac_SrcMacAddress[6]; // 源mac地址
  u_int16_t mac_EtherType;       // 上一层协议类型，如0x0800代表上一层是IP协议，0x0806为arp
} mac_frame_header;

// * IP 头定义，共 20 个字节
typedef struct _IP_HEADER
{
  u_int8_t ip_VersionAndIHL; // 版本信息(前4位)，头长度(后4位)
  u_int8_t ip_DSCPwithECN;   // 服务类型8位
  u_int16_t ip_TotalLength;  // 数据包长度
  u_int16_t ip_PacketID;     // 数据包标识
  u_int16_t ip_Flagsinfo;    // 分片使用
  u_int8_t ip_TTL;           // 存活时间
  u_int8_t ip_Protocol;      // 协议类型
  u_int16_t ip_CheckSum;     // 校验和
  u_int8_t ip_SrcIP[4];      // 源ip
  u_int8_t ip_DstIP[4];      // 目的ip
} ip_frame_header;

// * TCP头定义，共 20 个字节
typedef struct _TCP_HEADER
{
  u_int16_t tcp_SrcPort;          // 源端口号16bit
  u_int16_t tcp_DstPort;          // 目的端口号16bit
  u_int32_t tcp_SequNum;          // 序列号32bit
  u_int32_t tcp_AcknowledgeNum;   // 确认号32bit
  u_int16_t tcp_HeaderLenAndFlag; // 前4位：TCP头长度；中6位：保留；后6位：标志位
  u_int16_t tcp_WindowSize;       // 窗口大小16bit
  u_int16_t tcp_CheckSum;         // 检验和16bit
  u_int16_t tcp_surgentPointer;   // 紧急数据偏移量16bit
} tcp_frame_header;

// * TCP 报头后续选项定义
typedef struct _TCP_OPTIONS
{
  u_int8_t tcp_opt_kind;
  u_int8_t tcp_opt_Length;
  u_int8_t tcp_opt_Context[32];
} tcp_frame_options;

// * UDP头定义，共 8 个字节 (UDP 包最少 8 个字节)
typedef struct _UDP_HEADER
{
  u_int16_t udp_SrcPort;   // 源端口号16bit
  u_int16_t udp_DstPort;   // 目的端口号16bit
  u_int16_t udp_PktLength; // 数据包总长度16bit
  u_int16_t udp_CheckSum;  // 校验和16bit
} udp_frame_header;

// * 将 int 格式化成 0x 开头的 hex string，方便输出
template <typename T>
std::string int_to_hex(T i)
{
  std::stringstream stream;
  stream << "0x" << std::setfill('0') << std::setw(sizeof(T) * 2) << std::hex << i;
  return stream.str();
}

// * 根据以太网帧（mac 报头）判断上层协议类型
void print_MacInfo(char *buffer)
{
  // ! 详情参见 Wiki https://en.m.wikipedia.org/wiki/EtherType 和 Documents 下的相关文档
  // ! 注意高低位反序
  mac_frame_header *mac_ptr = (mac_frame_header *)buffer;
  std::string ether_type = "";
  switch (mac_ptr->mac_EtherType)
  {
  case 0x0008:
    ether_type = "IPv4";
    break;
  case 0x0608:
    ether_type = "ARP";
    break;
  case 0x9b80:
    ether_type = "AppleTalk(Ethertalk)";
    break;
  case 0xf38:
    ether_type = "AARP";
    break;
  case 0xDD86:
    ether_type = "IPv6";
    break;
  case 0x0888:
    ether_type = "Flow Control";
    break;
  case 0xcc88:
    ether_type = "LLDP";
    break;
  case 0x0689:
    ether_type = "FCoE";
    break;
  case 0x1489:
    ether_type = "FCoE Initialization";
    break;
  case 0x0090:
    ether_type = "Ethernet Testing";
    break;
  default:
    ether_type = "Untreated type: " + int_to_hex(mac_ptr->mac_EtherType);
    break;
  }
  printf(" MAC frame INFO :: %x:%x:%x:%x:%x:%x to %x:%x:%x:%x:%x:%x, EtherTpye = %s\n", mac_ptr->mac_SrcMacAddress[0],
         mac_ptr->mac_SrcMacAddress[1], mac_ptr->mac_SrcMacAddress[2], mac_ptr->mac_SrcMacAddress[3],
         mac_ptr->mac_SrcMacAddress[4], mac_ptr->mac_SrcMacAddress[5], mac_ptr->mac_DstMacAddress[0],
         mac_ptr->mac_DstMacAddress[1], mac_ptr->mac_DstMacAddress[2], mac_ptr->mac_DstMacAddress[3],
         mac_ptr->mac_DstMacAddress[4], mac_ptr->mac_DstMacAddress[5], ether_type.c_str());
  return;
}

// * 交换 uint16_t 的高低位
inline uint16_t uint16_swap(uint16_t number) { return number >> 8 | number << 8; }
// * 交换 uint32_t 的高低位
inline uint32_t uint32_swap(uint32_t number)
{
  return (number << 24) | ((number & 0x00f0) << 8) | ((number & 0x0f00) >> 8) | (number >> 24);
}

// * 打印 UDP 包的信息
void print_UDPInfo(char *buffer)
{
  udp_frame_header *udp_ptr = (udp_frame_header *)buffer;
  uint16_t data_len = uint16_swap(udp_ptr->udp_PktLength) - 8;
  printf(" UDP frame INFO :: port %u to %u, data length = %u bytes, checksum = 0x%X\n",
         uint16_swap(udp_ptr->udp_SrcPort), uint16_swap(udp_ptr->udp_DstPort), data_len,
         uint16_swap(udp_ptr->udp_CheckSum));
  printf(" UDP data = %.*s\n", data_len, (char *)buffer + 8);
  return;
}

// * 打印 TCP 包的信息
void print_TCPInfo(char *buffer, uint16_t tcp_frame_length)
{
  tcp_frame_header *tcp_ptr = (tcp_frame_header *)buffer;
  // ! TCP 报文中本身不包含其长度，但是可以通过 ip 报文中的长度计算得到
  // ! 已传入，tcp_frame_length 即为当前 tcp 包的总长度，减去 tcp 的报文头长度即为数据长度
  bool URG_flag;
  bool ACK_flag;
  bool PSH_flag;
  bool PST_flag;
  bool SYN_flag;
  bool FIN_flag;
  uint16_t HeaderLenAndFlag = tcp_ptr->tcp_HeaderLenAndFlag;
  uint8_t HeaderLen;
  HeaderLen = (HeaderLenAndFlag >> 12) * 4;
  uint16_t data_len = tcp_frame_length - HeaderLen;

  URG_flag = (HeaderLenAndFlag >> 5) & 0x01;
  ACK_flag = (HeaderLenAndFlag >> 4) & 0x01;
  PSH_flag = (HeaderLenAndFlag >> 3) & 0x01;
  PST_flag = (HeaderLenAndFlag >> 2) & 0x01;
  SYN_flag = (HeaderLenAndFlag >> 1) & 0x01;
  FIN_flag = HeaderLenAndFlag & 0x01;

  printf(" TCP frame INFO :: port %u to %u, data length = %u bytes, checksum = 0x%X, \n                   Sequence Number = %u, Acknowledgment Number = %u, WindowSize = %u, \n",
         uint16_swap(tcp_ptr->tcp_SrcPort), uint16_swap(tcp_ptr->tcp_DstPort), data_len,
         uint16_swap(tcp_ptr->tcp_CheckSum), uint32_swap(tcp_ptr->tcp_SequNum),
         uint32_swap(tcp_ptr->tcp_AcknowledgeNum), uint16_swap(tcp_ptr->tcp_WindowSize));
  printf("                   URG_flag = %d, ACK_flag = %d, PSH_flag = %d, PST_flag = %d, SYN_flag = %d, FIN_flag = %d\n",
         URG_flag, ACK_flag, PSH_flag, PST_flag, SYN_flag, FIN_flag);
  printf(" TCP data = %.*s\n", data_len, (char *)buffer + HeaderLen);
  return;
}

// * 打印 IP 包的信息
void print_IPInfo(char *buffer)
{
  mac_frame_header *mac_ptr = (mac_frame_header *)buffer;
  if (mac_ptr->mac_EtherType != 0x0008)
  {
    print_MacInfo(buffer);
    return;
  }
  uint8_t version;
  ip_frame_header *ip_ptr = (ip_frame_header *)(buffer + 14); // ! skip 14 bytes of mac header
  std::string protocal = "";
  version = ip_ptr->ip_VersionAndIHL >> 4;
  uint8_t IHL = (ip_ptr->ip_VersionAndIHL & 0x0f) * 4;
  uint16_t ip_frame_length = uint16_swap(ip_ptr->ip_TotalLength);
  switch (ip_ptr->ip_Protocol)
  {
  case 1:
    protocal = "ICMP";
    break;
  case 2:
    protocal = "IGMP";
    break;
  case 6:
    protocal = "TCP";
    break;
  case 17:
    protocal = "UDP";
    break;
  case 41:
    protocal = "ENCAP";
    break;
  case 89:
    protocal = "OSPF";
    break;
  case 132:
    protocal = "SCTP";
    break;
  default:
    protocal = "Untreated protocal: " + std::to_string(ip_ptr->ip_Protocol);
    break;
  }
  printf(
      " IP frame INFO :: %d.%d.%d.%d to %d.%d.%d.%d\n                  Version = %d; Total Length = %d; Header Length "
      "= %d\n",
      ip_ptr->ip_SrcIP[0], ip_ptr->ip_SrcIP[1], ip_ptr->ip_SrcIP[2], ip_ptr->ip_SrcIP[3], ip_ptr->ip_DstIP[0],
      ip_ptr->ip_DstIP[1], ip_ptr->ip_DstIP[2], ip_ptr->ip_DstIP[3], version, ip_frame_length, IHL);
  printf("                  Header checksum = 0x%X; Protocal = %s\n", uint16_swap(ip_ptr->ip_CheckSum),
         protocal.c_str());
  if (protocal == "UDP")
  {
    print_UDPInfo((char *)ip_ptr + IHL);
  }
  else if (protocal == "TCP")
  {
    print_TCPInfo((char *)ip_ptr + IHL, ip_frame_length - IHL);
  }
  return;
}

#endif