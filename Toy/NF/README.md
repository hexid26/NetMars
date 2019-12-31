# NF介绍

* **IPv4 router**
</br>DropBroadcasts模块
</br>CheckIPHeader模块
</br>IPlookup模块
</br>DecIPTTL模块
* **IPsec encryption gateway**
</br>IPsecESPencap模块
</br>IPsecAES模块
</br>IPsecAuthHMACSHA1模块
* **IDS**
</br>ACMatch模块
</br>PCREMatch模块

## 注意事项

* 1.必须安装的额外组件有Openssl、PCRE和CUDA
* 2.重构并优化了CPU的多线程和GPU的并行计算
* 3.每个NF文件夹下均有各自的Makefile文件
* 4.可以通过更改include/Packet.hpp中的参数来修改网络包数据
* 5.PCREMatch模块GPU版本适配有待改善

## 下一步

对接真实的网络数据流并开展实验测试
