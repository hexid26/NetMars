# **netmap 简介**

●　**netmap** - a framework for fast packet I/O  
●　**VALE** - VirtuAl Local Ethernet using the netmap API  
●　**netmap pipes** - shared memory packet transport channels  

## **特点**

客户端程序可以动态将 NIC 切换至 `netmap` 模式，对原始数据包（raw packets）进行转发。数据包被缓存在映射后的内存空间中个，实现了数据包的零拷贝。同时通过 **`batch`** 操作，让每次软终端可以对 **`Rx` `Tx`** 队列中的多个数据包进行处理，降低了每个数据包处理时的成本，并提高了数据处理的效率。

`netmap` 的优势，快、效率高，内存占用资源少，并支持两种工作模式 **`non-blocking`** 和 **`blocking`**。

- **`non-blocking`**
两种方式：[ioctl](http://manpages.ubuntu.com/manpages/bionic/man2/ioctl.2.html) 和 同步（**`synchronization`**）。

- **`blocking`**
使用文件描述符访问，通过标准操作系统协议栈命令：[select](http://manpages.ubuntu.com/manpages/bionic/man2/select.2.html)、[poll](http://manpages.ubuntu.com/manpages/bionic/man2/poll.2.html)、[epoll](http://manpages.ubuntu.com/manpages/bionic/man2/epoll.2.html)、和 [kqueue](http://manpages.ubuntu.com/manpages/bionic/man2/kqueue.2.html)。

## **数据结构**
映射内存的详细信息可以参见 `<sys/net/netmap.h>`, 属于 `netmap` API 的一部分。其中主要的结构体如下。

- **`netmap_if`**
```C
struct netmap_if (one per interface)
    struct netmap_if {
        ...
        const uint32_t   ni_flags;      /* properties              */
        ...
        const uint32_t   ni_tx_rings;   /* NIC tx rings            */
        const uint32_t   ni_rx_rings;   /* NIC rx rings            */
        uint32_t         ni_bufs_head;  /* head of extra bufs list */
        ...
    };
    ...
}
```

- **`netmap_ring`**
```c
struct netmap_ring (one per ring)
    struct netmap_ring {
        ...
        const uint32_t num_slots;   /* slots in each ring            */
        const uint32_t nr_buf_size; /* size of each buffer           */
        ...
        uint32_t       head;        /* (u) first buf owned by user   */
        uint32_t       cur;         /* (u) wakeup position           */
        const uint32_t tail;        /* (k) first buf owned by kernel */
        ...
        uint32_t       flags;
        struct timeval ts;          /* (k) time of last rxsync()     */
        ...
        struct netmap_slot slot[0]; /* array of slots                */
    }
    ...
}
```

- **`netmap_slot`**
```
struct netmap_slot (one per buffer)

    struct netmap_slot {
        uint32_t buf_idx;           /* buffer index                 */
        uint16_t len;               /* packet length                */
        uint16_t flags;             /* buf changed, etc.            */
        uint64_t ptr;               /* address for indirect buffers */
    };
}

  Describes a packet buffer, which normally is identified by an index and resides in the mmapped region.

    packet buffers
      Fixed size (normally 2 KB) packet buffers allocated by the kernel.
```

## **相关细节**

●　**Rings**

　　环形队列，拥有三个指针（head，cur，tail）。有一个 `slot` 一直保持为空。`Ring` 的大小*不能为 2 的次方*。

- `head`  
用户空间的第一个 `slot`
- `cur`  
Wakeup point。当 `tail` 超过 `cur` 时，`select/poll` 才可以使用。
- `tail`  
Kernel 中保留队列中的第一个 `slot`。

数据 `[head, tail - 1]` 在用户空间（用户操作），数据 `[tail, head - 1]` 在核态（netmap 内核操作，例如收/发包）。


