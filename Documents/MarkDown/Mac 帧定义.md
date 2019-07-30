# **Mac 帧定义**

mac （以太网帧）报头有 14 字节，其定义如下

```
0               7,8               15,16    -    17
+-------------------------------------------------+
|  des mac addr  |   src mac addr   |  EtherType  |
+-------------------------------------------------+
```

---

## **报头结构说明**

定义 | 说明
:--  | :--
des mac addr | 目的 mac 地址
src mac addr | 源 mac 地址

---

## **EtherTpye 说明**

EtherTpye 表示以太网帧的功能协议。具体定义如下表：

定义 | 说明
:--  | :--
**0x0008** | ***Internet Protocol version 4 (IPv4)***
**0x0608** | ***Address Resolution Protocol (ARP)***
**0x4208** | Wake-on-LAN
**0xF022** | Audio Video Transport Protocol as defined in IEEE Std 1722-2011
**0xF322** | IETF TRILL Protocol
**0x0360** | DECnet Phase IV
**0x3580** | Reverse Address Resolution Protocol
**0x9B80** | ***AppleTalk (Ethertalk)***
**0xF380** | ***AppleTalk Address Resolution Protocol (AARP)***
**0x0081** | VLAN-tagged frame (IEEE 802.1Q) & Shortest Path Bridging IEEE 802.1aq
**0x3781** | IPX
**0x3881** | IPX
**0x0482** | QNX Qnet
**0xDD86** | ***Internet Protocol Version 6 (IPv6)***
**0x0888** | ***Ethernet flow control***
**0x0988** | Slow Protocols (IEEE 802.3)
**0x1988** | CobraNet
**0x4788** | MPLS unicast
**0x4888** | MPLS multicast
**0x6388** | PPPoE Discovery Stage
**0x6488** | PPPoE Session Stage
**0x7088** | Jumbo Frames
**0x7B88** | HomePlug 1.0 MME
**0x8E88** | EAP over LAN (IEEE 802.1X)
**0x9288** | PROFINET Protocol
**0x9A88** | HyperSCSI (SCSI over Ethernet)
**0xA288** | ATA over Ethernet
**0xA488** | EtherCAT Protocol
**0xA888** | IEEE Std 802.1QService VLAN tag identifier (S-Tag)
**0xAB88** | Ethernet Powerlink
**0xCC88** | ***链路层发现协议 (LLDP)***
**0xCD88** | SERCOS III
**0xE188** | HomePlug AV MME
**0xE388** | Media Redundancy Protocol (IEC62439-2)
**0xE588** | MAC security (IEEE 802.1AE)
**0xE788** | Provider Backbone Bridges (PBB) (IEEE 802.1ah)
**0xF788** | Precision Time Protocol (PTP) over Ethernet (IEEE 1588)
**0x0289** | IEEE 802.1ag Connectivity Fault Management (CFM) Protocol / ITU-T Recommendation Y.1731 (OAM)
**0x0689** | ***Fibre Channel over Ethernet (FCoE)***
**0x1489** | ***FCoE Initialization Protocol***
**0x1589** | RDMA over Converged Ethernet (RoCE)
**0x2F89** | High-availability Seamless Redundancy (HSR)
**0x0090** | ***Ethernet Configuration Testing Protocol***
**0x0091** | VLAN-tagged (IEEE 802.1Q) frame with double tagging
