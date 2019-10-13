# 介绍
1.大部分代码来源于NBA项目，参考了dpdk的源代码。
https://github.com/ANLAB-KAIST/NBA/tree/master/elements
2.include里面是相关的头文件定义。
3.element里面是各个NF,每个NF按照论文分成几个element，每个element对应一个头文件。

# 注意
代码还不完全，NF暂时还不能运行，IP router中涉及路由表的部分（TBL24和TBLlong）还在研究，IPsec还有部分结构没弄清楚。
