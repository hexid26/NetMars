# 介绍

1. 大部分代码来源于[NBA项目](https://github.com/ANLAB-KAIST/NBA/tree/master/elements)，参考了dpdk的源代码。
2. include 里面是相关的头文件定义。
3. element 里面是各个 NF，每个NF按照论文分成几个element，每个element对应一个头文件。

# 注意
运行IPsec encryption gateway/main.cc即可正常使用IPsec encryption gateway功能，程序会输出相关数据的值，可以在include/Packet.hh中调节测试包的相关参数。

task.json中的参数设定如下：
            "args": [
                "-g",
                "${file}",
                "-o",
                "${fileDirname}/${fileBasenameNoExtension}",
                "-I",
                "${workspaceFolder}/include",
                "-lssl",
                "-lcrypto",
            ],

## **TODOList**

### **2019-10-19 之前完成以下内容**

* 朱安东
- [ ] 按照我的这个模板
- [ ] 自己添加

* 谭超
- [ ] 按照我的这个模板
- [ ] 自己添加
