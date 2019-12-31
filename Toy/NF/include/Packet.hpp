#pragma once
#include "NetStruct.hpp"
#include <iomanip>

uint8_t _dh[6] = {0x00, 0x0c, 0x29, 0x99, 0x76, 0xb1};
uint8_t _sh[6] = {0x00, 0x50, 0x56, 0xfe, 0xdd, 0x68};

static uint32_t tran_ip_addr(std::string ip)
{
    char *result8 = (char *)malloc(sizeof(char) * 8);
    char *p = result8;
    char temp[3];
    temp[2] = '\0';
    char *ips = strtok((char *)ip.c_str(), ".");
    while (ips != NULL)
    {
        sprintf(temp, "%02x", atoi(ips));
        (*p++) = temp[0];
        (*p++) = temp[1];
        ips = strtok(NULL, ".");
    }
    *p = '\0';
    uint32_t result = 0;
    sscanf(result8, "%x", &result);
    free(result8);
    return result;
}

//此函数用于将uint16_t分割成2个uint8_t
static void u16tu8(uint16_t u16, uint8_t *pu8)
{
    pu8[1] = (uint8_t)(u16 & 0xff);
    pu8[0] = (uint8_t)((u16 - pu8[1]) / 0x100);
}

//此函数用于将uint32_t分割成4个uint8_t
static void u32tu8(uint32_t u32, uint8_t *pu8)
{
    uint16_t t1, t2;
    t1 = (uint16_t)(u32 & 0xffff);
    t2 = (uint16_t)((u32 - t1) / 0x10000);
    u16tu8(t2, pu8);
    u16tu8(t1, pu8 + 2);
}

//此函数用于计算IP头的校验值
static uint16_t GetIpCheckSum(uint8_t *ptr, int size)
{
    int cksum = 0;
    int index = 0;
    *(ptr + 10) = 0;
    *(ptr + 11) = 0;
    if (size % 2 != 0)
        return 0;
    while (index < size)
    {
        cksum += *(ptr + index + 1);
        cksum += *(ptr + index) << 8;
        index += 2;
    }
    while (cksum > 0xffff)
    {
        cksum = (cksum >> 16) + (cksum & 0xffff);
    }
    return ~cksum;
}

//自定义Packet结构用于简单的测试
//该Packet结构在运输层以UDP协议为例
class Packet
{
public:
    uint8_t *puint8;
    uint16_t plen;
    struct ether_header ethh; //14bytes
    struct iphdr iph;         //20bytes
    struct udphdr uph;        //8bytes
    uint8_t *pdata;
    uint16_t data_len;
    bool is_save;
    Packet()
    {
        puint8 = NULL;
        pdata = NULL;
        is_save = true;
        generate_data();
        set_udphdr();
        set_iphdr();
        set_ether_header();
        tran_uint8_flow();
        // print_info();
    }
    ~Packet()
    {
        if (puint8)
        {
            free(puint8);
            puint8 = NULL;
        }
        if (pdata)
        {
            free(pdata);
            pdata = NULL;
        }
    }
    void set_ether_header()
    {
        for (int i = 0; i < 6; i++)
        {
            (ethh.ether_dhost)[i] = _dh[i];
            (ethh.ether_shost)[i] = _sh[i];
        }
        ethh.ether_type = ETHER_TYPE_IPV4;
    }
    void set_iphdr()
    {
        iph.version = 4;
        iph.ihl = 5;
        iph.tos = 0;
        iph.tot_len = data_len + 20 + 8;
        iph.id = 0x8d2f;
        iph.frag_off = 0x0000;
        iph.ttl = 0x80;
        iph.protocol = 0x11;
        iph.check = 0;
        iph.saddr = tran_ip_addr("192.168.0.1");
        iph.daddr = tran_ip_addr("192.168.0.8");

        uint8_t *p_ip = (uint8_t *)malloc(sizeof(uint8_t) * sizeof(struct iphdr));
        uint8_t *_p_ip = p_ip;
        *(_p_ip++) = iph.version * 16 + iph.ihl;
        *(_p_ip++) = iph.tos;

        uint8_t *temp = (uint8_t *)malloc(sizeof(uint8_t) * 4);
        u16tu8(iph.tot_len, temp);
        for (int i = 0; i < 2; i++)
        {
            *(_p_ip++) = temp[i];
        }
        u16tu8(iph.id, temp);
        for (int i = 0; i < 2; i++)
        {
            *(_p_ip++) = temp[i];
        }
        u16tu8(iph.frag_off, temp);
        for (int i = 0; i < 2; i++)
        {
            *(_p_ip++) = temp[i];
        }
        *(_p_ip++) = iph.ttl;
        *(_p_ip++) = iph.protocol;
        u16tu8(iph.check, temp);
        for (int i = 0; i < 2; i++)
        {
            *(_p_ip++) = temp[i];
        }
        u32tu8(iph.saddr, temp);
        for (int i = 0; i < 4; i++)
        {
            *(_p_ip++) = temp[i];
        }
        u32tu8(iph.daddr, temp);
        for (int i = 0; i < 4; i++)
        {
            *(_p_ip++) = temp[i];
        }
        iph.check = GetIpCheckSum(p_ip, sizeof(iph));
        free(temp);
        free(p_ip);
        p_ip = NULL;
    }
    void set_udphdr()
    {
        uph.uh_sport = 443;
        uph.uh_dport = 59622;
        uph.len = data_len + 8;
        uph.check = 0xcb2d;
        // uph.dest;
        // uph.source;
        // uph.uh_sum;
        // uph.uh_ulen;
    }
    void generate_data()
    {
        // int is_random;
        // std::cout << "是否需要随机生成数据部分？需要请输入1，自行输入数据部分请输入0；" << endl;
        // cin >> is_random;
        // if (is_random == 0)
        // {
        //     input_data(_data_len);
        //     return;
        // }
        data_len = rand() % (548 - 18 + 1) + 18;
        pdata = (uint8_t *)malloc(sizeof(uint8_t) * data_len);
        // printf("\n>>[测试包]\n数据部分：");
        for (int i = 0; i < data_len; i++)
        {
            while (1) //剔除反斜杆
            {
                pdata[i] = rand() % (126 - 32 + 1) + 32;
                if (pdata[i] != 92)
                    break;
            }
            // printf("%d ", (int)pdata[i]);
        }
        // printf("\n");
    }

    //可输入数据包数据部分（20字节）
    void input_data(int _data_len)
    {
        data_len = _data_len;
        pdata = (uint8_t *)malloc(sizeof(uint8_t) * data_len);
        printf("\n>>[测试包]\n请输入数据部分(%d个字符，勿输入反斜杠)：", _data_len);
        for (int i = 0; i < data_len; i++)
        {
            scanf("%c", &pdata[i]);
            printf("%d ", (int)pdata[i]);
        }
        printf("\n");
    }

    //通过tran_uint8_flow函数可以将Packet中的内容转换为uint8_t字符流，模拟网络中传输的真实数据流结构
    void tran_uint8_flow()
    {
        plen = 14 + iph.tot_len;
        puint8 = (uint8_t *)malloc(sizeof(uint8_t) * plen);
        uint8_t *p = puint8;
        for (int i = 0; i < 6; i++)
        {
            *(p++) = ethh.ether_dhost[i];
        }
        for (int i = 0; i < 6; i++)
        {
            *(p++) = ethh.ether_shost[i];
        }
        uint8_t *temp = (uint8_t *)malloc(sizeof(uint8_t) * 4);
        u16tu8(ethh.ether_type, temp);
        for (int i = 0; i < 2; i++)
        {
            *(p++) = temp[i];
        }
        *(p++) = iph.version * 16 + iph.ihl;
        *(p++) = iph.tos;
        u16tu8(iph.tot_len, temp);
        for (int i = 0; i < 2; i++)
        {
            *(p++) = temp[i];
        }
        u16tu8(iph.id, temp);
        for (int i = 0; i < 2; i++)
        {
            *(p++) = temp[i];
        }
        u16tu8(iph.frag_off, temp);
        for (int i = 0; i < 2; i++)
        {
            *(p++) = temp[i];
        }
        *(p++) = iph.ttl;
        *(p++) = iph.protocol;
        u16tu8(iph.check, temp);
        for (int i = 0; i < 2; i++)
        {
            *(p++) = temp[i];
        }
        u32tu8(iph.saddr, temp);
        for (int i = 0; i < 4; i++)
        {
            *(p++) = temp[i];
        }
        u32tu8(iph.daddr, temp);
        for (int i = 0; i < 4; i++)
        {
            *(p++) = temp[i];
        }
        u16tu8(uph.uh_sport, temp);
        for (int i = 0; i < 2; i++)
        {
            *(p++) = temp[i];
        }
        u16tu8(uph.uh_dport, temp);
        for (int i = 0; i < 2; i++)
        {
            *(p++) = temp[i];
        }
        u16tu8(uph.len, temp);
        for (int i = 0; i < 2; i++)
        {
            *(p++) = temp[i];
        }
        u16tu8(uph.check, temp);
        for (int i = 0; i < 2; i++)
        {
            *(p++) = temp[i];
        }
        free(temp);
        for (int i = 0; i < data_len; i++)
        {
            *(p++) = pdata[i];
        }
    }
    unsigned char *data()
    {
        return puint8;
    }
    void print_info()
    {
        std::cout << "源主机地址：";
        for (int i = 0; i < 6; i++)
        {
            std::cout << std::setw(2) << std::setfill('0') << std::hex << (int)ethh.ether_shost[i];
            if (i != 5)
                std::cout << ":";
        }
        std::cout << "\n目的主机地址：";
        for (int i = 0; i < 6; i++)
        {
            std::cout << std::setw(2) << std::setfill('0') << std::hex << (int)ethh.ether_dhost[i];
            if (i != 5)
                std::cout << ":";
        }
        uint8_t *temp = (uint8_t *)malloc(sizeof(uint8_t) * 4);
        u32tu8(iph.saddr, temp);
        std::cout << "\n源IP地址：";
        for (int i = 0; i < 4; i++)
        {
            std::cout << std::dec << (int)temp[i];
            if (i != 3)
                std::cout << ".";
        }
        u32tu8(iph.daddr, temp);
        std::cout << "\n目的IP地址：";
        for (int i = 0; i < 4; i++)
        {
            std::cout << std::dec << (int)temp[i];
            if (i != 3)
                std::cout << ".";
        }
        std::cout << std::endl;
        free(temp);
    }
};