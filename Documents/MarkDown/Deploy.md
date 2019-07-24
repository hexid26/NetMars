# **netmap** 的部署

本范例在 `Ubuntu LTS 18.04` 上部署，kernel 版本为 `4.15.0-54-generic`。

## **准备工作**

相关开发包不在此，中途碰到需要的依赖请自行安装。

```s
sudo apt-get install linux-headers-4.15.0-54 linux-source-4.15.0
```

源码保存路径在 `/usr/src/linux-source-4.15.0`，解压缩后得到完整源码，假定路径为 **`/usr/src/linux-source-4.15.0/linux-source-4.15.0`**（重要）。

在源码路径下输入一下命令为编译 netmap Module 做好准备：

```s
sudo make oldconfig
sudo make modules_prepare
```

## **编译&安装**

在 netmap 源码目录下，进入 `LINUX` 目录。

进行编译前的配置：

```shell
./configure --kernel-dir=/usr/src/linux-source-4.15.0/linux-source-4.15.0/ --kernel-sources=/usr/src/linux-source-4.15.0/linux-source-4.15.0/ --kernel-version=4.15.0-54-generic --select-version=ixgbevf:4.6.1 --select-version=i40e:2.8.43 --select-version=e1000e:3.4.2.4 --select-version=igb:5.3.5.36
```

1. 其中，kernel 的路径都指向之前下载后进行处理过的源码路径；
2. `--kernel-version` 指向的路径和 `/lib/modules/` 下的路径同名（**重要**）；
3. `--select-version` 指定修改版驱动适配的版本号，在 git 的提交注释中查到。
cd 
编译 `make`

安装 `sudo make install`

重启加载新内核

启动之后用一下命令检查网卡驱动

```s
sudo ethtool -i ethX
```

## **使用注意事项**

●　**pkt-gen**

使用之前需要关闭流控制功能并开启混淆模式

```s
sudo ethtool -A ethX autoneg off rx off tx off
sudo ifconfig ethX promisc
```
## **遗留问题**

virtio_net.c 这个驱动无法正确被识别，说的是 patch 可能不适用，需要在 github 上开启 issue 询问。

`sudo make install` 会报错，找不到个别文件，但是和 netmap 主体没有关系，不影响使用。
