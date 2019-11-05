# 介绍

目前包含以下三个NF的CPU版本：
IPv4 router
IPsec encryption gateway
IDS

# 注意

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
                "-lpcre",
		]

## **TODOList**

### **2019-10-19 之前完成以下内容**

* 朱安东
- [ ] 按照我的这个模板
- [ ] 自己添加

* 谭超
- [ ] 按照我的这个模板
- [ ] 自己添加
