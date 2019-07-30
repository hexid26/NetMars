# **IP 报头定义**

## **报头格式**

IP 报头长度默认 20 字节，根据附加选项可以更长。其定义如下表：

<style type="text/css">
.tg  {border-collapse:collapse;border-spacing:0;}
.tg td{font-family:Arial, sans-serif;font-size:14px;padding:10px 5px;border-style:solid;border-width:1px;overflow:hidden;word-break:normal;border-color:black;}
.tg th{font-family:Arial, sans-serif;font-size:14px;font-weight:normal;padding:10px 5px;border-style:solid;border-width:1px;overflow:hidden;word-break:normal;border-color:black;}
.tg .tg-3shr{font-size:16px;font-family:"Times New Roman", Times, serif !important;;background-color:#34ff34;color:#000000;border-color:#000000;text-align:center;vertical-align:top}
.tg .tg-gud7{font-size:16px;font-family:"Times New Roman", Times, serif !important;;background-color:#fd6864;color:#000000;border-color:#000000;text-align:center;vertical-align:top}
.tg .tg-dyv1{font-size:16px;font-family:"Times New Roman", Times, serif !important;;background-color:#ffffff;color:#000000;border-color:#000000;text-align:center;vertical-align:top}
</style>
<table class="tg">
  <tr>
    <th class="tg-gud7">Offsets</th>
    <th class="tg-gud7">Octer</th>
    <th class="tg-gud7" colspan="8">0</th>
    <th class="tg-gud7" colspan="8">1</th>
    <th class="tg-gud7" colspan="8">2</th>
    <th class="tg-gud7" colspan="8">3</th>
  </tr>
  <tr>
    <td class="tg-3shr">Octet</td>
    <td class="tg-3shr">Bits</td>
    <td class="tg-dyv1">0</td>
    <td class="tg-dyv1">1</td>
    <td class="tg-dyv1">2</td>
    <td class="tg-dyv1">3</td>
    <td class="tg-dyv1">4</td>
    <td class="tg-dyv1">5</td>
    <td class="tg-dyv1">6</td>
    <td class="tg-dyv1">7</td>
    <td class="tg-dyv1">8</td>
    <td class="tg-dyv1">9</td>
    <td class="tg-dyv1">10</td>
    <td class="tg-dyv1">11</td>
    <td class="tg-dyv1">12</td>
    <td class="tg-dyv1">13</td>
    <td class="tg-dyv1">14</td>
    <td class="tg-dyv1">15</td>
    <td class="tg-dyv1">16</td>
    <td class="tg-dyv1">17</td>
    <td class="tg-dyv1">18</td>
    <td class="tg-dyv1">19</td>
    <td class="tg-dyv1">20</td>
    <td class="tg-dyv1">21</td>
    <td class="tg-dyv1">22</td>
    <td class="tg-dyv1">23</td>
    <td class="tg-dyv1">24</td>
    <td class="tg-dyv1">25</td>
    <td class="tg-dyv1">26</td>
    <td class="tg-dyv1">27</td>
    <td class="tg-dyv1">28</td>
    <td class="tg-dyv1">29</td>
    <td class="tg-dyv1">30</td>
    <td class="tg-dyv1">31</td>
  </tr>
  <tr>
    <td class="tg-3shr">0</td>
    <td class="tg-3shr">0</td>
    <td class="tg-dyv1" colspan="4">Version</td>
    <td class="tg-dyv1" colspan="4">IHL</td>
    <td class="tg-dyv1" colspan="6">DSCP</td>
    <td class="tg-dyv1" colspan="2">ECN</td>
    <td class="tg-dyv1" colspan="16">Total Length</td>
  </tr>
  <tr>
    <td class="tg-3shr">0</td>
    <td class="tg-3shr">32</td>
    <td class="tg-dyv1" colspan="16">Identification</td>
    <td class="tg-dyv1" colspan="3">Flags</td>
    <td class="tg-dyv1" colspan="13">Fragment Offset</td>
  </tr>
  <tr>
    <td class="tg-3shr">8</td>
    <td class="tg-3shr">64</td>
    <td class="tg-dyv1" colspan="8">Time To Live</td>
    <td class="tg-dyv1" colspan="8">Protocol</td>
    <td class="tg-dyv1" colspan="16">Header Checksum</td>
  </tr>
  <tr>
    <td class="tg-3shr">12</td>
    <td class="tg-3shr">96</td>
    <td class="tg-dyv1" colspan="32">Src IP Address</td>
  </tr>
  <tr>
    <td class="tg-3shr">16</td>
    <td class="tg-3shr">128</td>
    <td class="tg-dyv1" colspan="32">Des IP Address</td>
  </tr>
  <tr>
    <td class="tg-3shr">20</td>
    <td class="tg-3shr">160</td>
    <td class="tg-dyv1" colspan="32" rowspan="4">Options(if IHL &gt; 5)</td>
  </tr>
  <tr>
    <td class="tg-3shr">24</td>v
    <td class="tg-3shr">192</td>
  </tr>
  <tr>
    <td class="tg-3shr">28</td>
    <td class="tg-3shr">224</td>
  </tr>
  <tr>
    <td class="tg-3shr">32</td>
    <td class="tg-3shr">256</td>
  </tr>
</table>

---

## **定义说明**

IP 报头中个字段的具体定义如下表：

**定义** | **说明**
:-- | :--
**Version** | IP 协议版本，IPv4 为 4
**Internet Header Length (IHL)** | 说明首部有多少32位字（4字节），一般为 5（20 字节）
**Differentiated Services (DSCP)** | 在使用区分服务时，这个字段才起作用(例如 VoIP)，一般不用
**Explicit Congestion Notification (ECN)** | 不丢弃报文的同时通知对方网络拥塞的发生
**Total Length** | 报文总长，包含首部和数据，单位为字节
**Identification** | 用来唯一地标识一个报文的所有分片，用来重组报文
**Flags** | 位0：保留，必须为0<br>位1：禁止分片(DF=0允许分片)<br>位2：更多分片(1 有分片；0 最后一个分片)
**Fragment Offset** | 指明了每个分片相对于原始报文开头的偏移量，以8字节作单位
**Time To Live (TTL)** | 跳数计数器，最大 255
**Protocol** | 该报文数据区使用的协议（[IANA](https://zh.wikipedia.org/wiki/IANA), [Protocal List](https://zh.wikipedia.org/wiki/IP协议号列表)）
**Header Checksum** | 首部检验和，不包括数据部分<br>如果不一致，此报文将会被丢弃
**Src IP Address** | 源 IP 地址
**Des IP Address** | 目的 IP 地址
**Options** | 额外选项，如果 IHL > 5，这里才会有数据<br>数据大小为 IHL * 4 - 20 Bytes

---

## **Protocal 协议字段说明**

Protocal 协议字段定义了该网络包所使用的上层协议。具体定义参见 [Protocal List](https://zh.wikipedia.org/wiki/IP协议号列表)。这里给出常见的协议字段。

**协议字段值** | **协议名** | **缩写**
:-: | :-: | :-:
1 | [互联网控制消息协议](https://zh.wikipedia.org/wiki/互联网控制消息协议) |  ICMP
2 | [互联网组管理协议](https://zh.wikipedia.org/wiki/互联网组管理协议) |  IGMP
6 | [传输控制协议](https://zh.wikipedia.org/wiki/传输控制协议) |  TCP
17 | [用户数据报协议](https://zh.wikipedia.org/wiki/用户数据报协议) |  UDP
41 | [IPv6封装](https://zh.wikipedia.org/wiki/IPv6) |  ENCAP
89 | [开放式最短路径优先](https://zh.wikipedia.org/wiki/开放式最短路径优先) |  OSPF
132 | [流控制传输协议](https://zh.wikipedia.org/wiki/流控制传输协议) |  SCTP


