# 介绍

1.IPv4 router
	IPlookup模块GPU已实现
2.IPsec encryption gateway
	IPsecAES模块GPU已实现
	IPsecAuthHMACSHA1模块GPU已实现
3.IDS
	ACMatch模块GPU已实现
	PCREMatch模块GPU未实现

# 注意

1.必须安装的额外组件有Openssl、PCRE和CUDA
2.每个NF文件夹下均有各自的Makefile文件
3.可以通过更改include/Packet.hpp中的参数来修改网络包数据
4.IPv4 router通过IPlookup.hpp中的#define USE_CUDA控制是否使用GPU
5.IPsec encryption gateway通过IPsecAES.hpp中的#define USE_CUDA控制是否使用GPU
6.IDS通过ACMatch.hpp中的#define USE_CUDA控制是否使用GPU

# 下一步

考虑GPU版NF中批处理的调度问题
