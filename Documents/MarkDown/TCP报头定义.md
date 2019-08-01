# **TCP 报头定义**

## **报头格式**

IP 报头长度默认 20 字节，根据附加选项可以更长。其定义如下表：

<style type="text/css">
.tg  {border-collapse:collapse;border-spacing:0;}
.tg td{font-family:Arial, sans-serif;font-size:14px;padding:10px 5px;border-style:solid;border-width:1px;overflow:hidden;word-break:normal;border-color:black;}
.tg th{font-family:Arial, sans-serif;font-size:14px;font-weight:normal;padding:10px 5px;border-style:solid;border-width:1px;overflow:hidden;word-break:normal;border-color:black;}
.tg .tg-08qx{background-color:#34ff34;color:#000000;border-color:inherit;text-align:center;vertical-align:top}
.tg .tg-qddy{background-color:#fe0000;color:#000000;border-color:inherit;text-align:center;vertical-align:top}
.tg .tg-af47{font-size:16px;font-family:"Times New Roman", Times, serif !important;;background-color:#ffffff;color:#000000;border-color:#000000;text-align:center;vertical-align:top}
</style>
<table class="tg">
  <tr>
    <th class="tg-qddy">Offsets</th>
    <th class="tg-qddy">Octer</th>
    <th class="tg-qddy" colspan="8">0</th>
    <th class="tg-qddy" colspan="8">1</th>
    <th class="tg-qddy" colspan="8">2</th>
    <th class="tg-qddy" colspan="8">3</th>
  </tr>
  <tr>
    <td class="tg-08qx">Octet</td>
    <td class="tg-08qx">Bits<br></td>
    <td class="tg-af47">0</td>
    <td class="tg-af47">1</td>
    <td class="tg-af47">2</td>
    <td class="tg-af47">3</td>
    <td class="tg-af47">4</td>
    <td class="tg-af47">5</td>
    <td class="tg-af47">6</td>
    <td class="tg-af47">7</td>
    <td class="tg-af47">8</td>
    <td class="tg-af47">9</td>
    <td class="tg-af47">10</td>
    <td class="tg-af47">11</td>
    <td class="tg-af47">12</td>
    <td class="tg-af47">13</td>
    <td class="tg-af47">14</td>
    <td class="tg-af47">15</td>
    <td class="tg-af47">16</td>
    <td class="tg-af47">17</td>
    <td class="tg-af47">18</td>
    <td class="tg-af47">19</td>
    <td class="tg-af47">20</td>
    <td class="tg-af47">21</td>
    <td class="tg-af47">22<br></td>
    <td class="tg-af47">23</td>
    <td class="tg-af47">24</td>
    <td class="tg-af47">25</td>
    <td class="tg-af47">26</td>
    <td class="tg-af47">27</td>
    <td class="tg-af47">28</td>
    <td class="tg-af47">29</td>
    <td class="tg-af47">30</td>
    <td class="tg-af47">31</td>
  </tr>
  <tr>
    <td class="tg-08qx">0</td>
    <td class="tg-08qx">0</td>
    <td class="tg-af47" colspan="16">Source Port</td>
    <td class="tg-af47" colspan="16">Destination port</td>
  </tr>
  <tr>
    <td class="tg-08qx">0</td>
    <td class="tg-08qx">32<br></td>
    <td class="tg-af47" colspan="32">Sequence Number</td>
  </tr>
  <tr>
    <td class="tg-08qx">8</td>
    <td class="tg-08qx">64</td>
    <td class="tg-af47" colspan="32">Acknowledgment   Number</td>
  </tr>
  <tr>
    <td class="tg-08qx">12</td>
    <td class="tg-08qx">96</td>
    <td class="tg-af47" colspan="4">HeaderLen</td>
    <td class="tg-af47" colspan="6">Reserved</td>
    <td class="tg-af47">URG</td>
    <td class="tg-af47">ACK</td>
    <td class="tg-af47">PSH</td>
    <td class="tg-af47">RST</td>
    <td class="tg-af47">SYN</td>
    <td class="tg-af47">FIN</td>
    <td class="tg-af47" colspan="16">WindowSize</td>
  </tr>
  <tr>
    <td class="tg-08qx">16</td>
    <td class="tg-08qx">128</td>
    <td class="tg-af47" colspan="16"><span style="font-weight:400;font-style:normal">Checksum</span></td>
    <td class="tg-af47" colspan="16">Urgent  Pointer</td>
  </tr>
  <tr>
    <td class="tg-08qx">20</td>
    <td class="tg-08qx">160</td>
    <td class="tg-af47" colspan="32" rowspan="4"><span style="font-weight:400;font-style:normal">Options(if HL &gt; 5)</span></td>
  </tr>
  <tr>
    <td class="tg-08qx">24</td>
    <td class="tg-08qx">192</td>
  </tr>
  <tr>
    <td class="tg-08qx">28</td>
    <td class="tg-08qx">224</td>
  </tr>
  <tr>
    <td class="tg-08qx">32</td>
    <td class="tg-08qx">256</td>
  </tr>
</table>

---

## **定义说明**

TCP 报头中个字段的具体定义如下表：

**定义** | **说明**
:-- | :--
**Source Port** | 16位的源端口其中包含初始化通信的端口<br>源端口和源IP地址的作用是标示报问的返回地址
**Destination port** | 16位的目的端口域定义传输的目的<br>这个端口指明报文接收计算机上的应用程序地址接口
**Sequence　Number** | 表示本报文段所发送数据的第一个字节的编号 
**Acknowledgment  Number** | 表示接收方期望收到发送方下一个报文段的第一个字节数据的编号
**HeaderLen** | TCP首部长度<br>表示TCP报文段中数据部分在整个TCP报文段中的位置<br>该字段的单位是32位字，即：4个字节
**Reserved** | 保留位，6位值域，这些位必须是0<br>为了将来定义新的用途所保留
**URG** | 表示本报文段中发送的数据是否包含紧急数据<br>URG=1，表示有紧急数据<br>后面的紧急指针字段只有当URG=1时才有效
**ACK** | 确认标志,表示是否前面的确认号字段是否有效<br>ACK=1，表示有效<br>只有当ACK=1时，前面的确认号字段才有效<br>TCP规定，连接建立后，ACK必须为1
**PSH** | 推标志,告诉对方收到该报文段后是否应该立即把数据推送给上层<br>如果为1，则表示对方应当立即把数据提交给上层，而不是缓存起来
**RST** | 复位标志<br>只有当RST=1时才有用<br>如果你收到一个RST=1的报文，说明你与主机的连接出现了严重错误（如主机崩溃），必须释放连接，然后再重新建立连接
**SYN** | 同步标志,建立连接时使用，用来同步序号<br>当SYN=1，ACK=0时，表示这是一个请求建立连接的报文段<br>当SYN=1，ACK=1时，表示对方同意建立连接<br>SYN=1，说明这是一个请求建立连接或同意建立连接的报文,只有在前两次握手中SYN才置为1
**FIN** | 结束标志,标记数据是否发送完毕<br>如果FIN=1，就相当于告诉对方：“我的数据已经发送完毕，你可以释放连接了”
**WindowSize** | 窗口大小,用来表示想收到的每个TCP数据段的大小
**Checksum** | 首部检验和，校验和校验整个TCP报文段，包括TCP首部和TCP数据<br>如果不一致，此报文将会被丢弃
**Urgent  Pointer** | 标记紧急数据在数据字段中的位置,在URG标志设置了时才有效
**Options** | 额外选项，如果 HL > 5，这里才会有数据<br>数据大小为 HL * 4 - 20 Bytes

---

## **Options 部分的应用**
**定义** | **说明**
:-- | :--
**MSS最大报文段长度(Maxium Segment Size)** | 指明数据字段的最大长度，数据字段的长度加上TCP首部的长度才等于整个TCP报文段的长度<br>MSS值指示自己期望对方发送TCP报文段时那个数据字段的长度<br>通信双方可以有不同的MSS值,如果未填写，默认采用536字节<br>MSS出现在SYN=1的报文段中。
**窗口扩大选项(Windows Scaling)** | 由于TCP首部的窗口大小字段长度是16位，所以其表示的最大数是65535<br>但是随着时延和带宽比较大的通信产生（如卫星通信），需要更大的窗口来满足性能和吞吐率，所以产生了这个窗口扩大选项
**SACK选择确认项(Selective Acknowledgements)** | 用来确保只重传缺少的报文段，而不是重传所有报文段
**时间戳选项（Timestamps)** | 用来计算RTT(往返时间)<br>发送方发送TCP报文时，把当前的时间值放入时间戳字段，接收方收到后发送确认报文时，把这个时间戳字段的值复制到确认报文中，当发送方收到确认报文后即可计算出RTT<br>使用时间戳字段就很容易区分相同序列号的不同报文
**NOP(NO-Operation)** | 要求选项部分中的每种选项长度必须是4字节的倍数，不足的则用NOP填充<br>同时也可以用来分割不同的选项字段,如窗口扩大选项和SACK之间用NOP隔开