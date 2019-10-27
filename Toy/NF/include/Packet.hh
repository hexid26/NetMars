#pragma once
#include "NetStruct.hh"
#include <stdlib.h>
#include <iomanip>

uint8_t _dh[6] = {0x00, 0x0c, 0x29, 0x99, 0x76, 0xb1};
uint8_t _sh[6] = {0x00, 0x50, 0x56, 0xfe, 0xdd, 0x68};

//此函数用于将uint16_t分割成2个uint8_t
uint8_t *u16tu8(uint16_t u16)
{
    uint8_t *pu8 = new uint8_t[2];
    pu8[1] = (uint8_t)(u16 & 0xff);
    pu8[0] = (uint8_t)((u16 - pu8[1]) / 0x100);
    return pu8;
}

//此函数用于将uint32_t分割成4个uint8_t
uint8_t *u32tu8(uint32_t u32)
{
    uint8_t *pu8 = new uint8_t[4];
    uint16_t t1, t2;
    t1 = (uint16_t)(u32 & 0xffff);
    t2 = (uint16_t)((u32 - t1) / 0x10000);
    pu8[0] = u16tu8(t2)[0];
    pu8[1] = u16tu8(t2)[1];
    pu8[2] = u16tu8(t1)[0];
    pu8[3] = u16tu8(t1)[1];
    return pu8;
}

//自定义Packet结构用于简单的测试
//该Packet结构在运输层以UDP协议为例
class Packet
{
public:
    uint8_t *puint8;
    struct ether_header ethh; //14bytes
    struct iphdr iph;         //20bytes
    struct udphdr uph;        //8bytes
    uint8_t *pdata;
    uint16_t plen;
    struct annotation_set anno;
    Packet()
    {
        generate_data(20);//限制数据部分20个字节
        set_udphdr();
        set_iphdr();
        set_ether_header();
        tran_uint8_flow();
        print_info();
    }
    void set_ether_header()
    {
        for (int i = 0; i < 6; i++)
        {
            (ethh.ether_dhost)[i] = _dh[i];
            (ethh.ether_shost)[i] = _sh[i];
        }
        ethh.ether_type = 0x0800;
        // ethh.ether_type = htons(0x0800);
    }
    void set_iphdr()
    {
        iph.version = 4;
        iph.ihl = 5;
        iph.tos = 0;
        // iph.tot_len = htons(plen + 20 + 8);
        iph.tot_len = plen + 20 + 8;
        iph.id = 0x8d2f;
        iph.frag_off = 0x0000;
        iph.ttl = 0x80;
        iph.protocol = 0x11;
        iph.check = 0x107f;
        iph.saddr = 0xc0a80001u;
        iph.daddr = 0xc0a80002u;
    }
    void set_udphdr()
    {
        uph.uh_sport = 443;
        uph.uh_dport = 59622;
        uph.len = plen + 8;
        uph.check = 0xcb2d;
        // uph.dest;
        // uph.source;
        // uph.uh_sum;
        // uph.uh_ulen;
    }
    void generate_data(int _plen)
    {
        plen = _plen;
        pdata = new uint8_t[plen];
        cout << "\n>>[测试包]\n数据部分：";
        for (int i = 0; i < plen; i++)
        {
            pdata[i] = rand() % (126 - 32 + 1) + 32;
            cout<<(int)pdata[i]<<" ";
        }
        cout<<endl;
    }
    //通过tran_uint8_flow函数可以将Packet中的内容转换为uint8_t字符流，模拟网络中传输的真实数据流结构
    void tran_uint8_flow()
    {
        puint8 = new uint8_t[14 + ntohs(iph.tot_len)];
        uint8_t *p = puint8;
        for (int i = 0; i < 6; i++)
        {
            *(p++) = ethh.ether_dhost[i];
        }
        for (int i = 0; i < 6; i++)
        {
            *(p++) = ethh.ether_shost[i];
        }
        for (int i = 0; i < 2; i++)
        {
            *(p++) = u16tu8(ethh.ether_type)[i];
        }
        *(p++) = iph.version * 10 + iph.ihl;
        *(p++) = iph.tos;
        for (int i = 0; i < 2; i++)
        {
            *(p++) = u16tu8(iph.tot_len)[i];
        }
        for (int i = 0; i < 2; i++)
        {
            *(p++) = u16tu8(iph.id)[i];
        }
        for (int i = 0; i < 2; i++)
        {
            *(p++) = u16tu8(iph.frag_off)[i];
        }
        *(p++) = iph.ttl;
        *(p++) = iph.protocol;
        for (int i = 0; i < 2; i++)
        {
            *(p++) = u16tu8(iph.check)[i];
        }
        for (int i = 0; i < 4; i++)
        {
            *(p++) = u32tu8(iph.saddr)[i];
        }
        for (int i = 0; i < 4; i++)
        {
            *(p++) = u32tu8(iph.daddr)[i];
        }
        for (int i = 0; i < 2; i++)
        {
            *(p++) = u16tu8(uph.uh_sport)[i];
        }
        for (int i = 0; i < 2; i++)
        {
            *(p++) = u16tu8(uph.uh_dport)[i];
        }
        for (int i = 0; i < 2; i++)
        {
            *(p++) = u16tu8(uph.len)[i];
        }
        for (int i = 0; i < 2; i++)
        {
            *(p++) = u16tu8(uph.check)[i];
        }
        for (int i = 0; i < plen; i++)
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
        cout << "源主机地址：";
        for (int i = 0; i < 6; i++)
        {
            cout << setw(2) << setfill('0') << hex << (int)ethh.ether_shost[i];
            if (i != 5)
                cout << ":";
        }
        cout << "\n目的主机地址：";
        for (int i = 0; i < 6; i++)
        {
            cout << setw(2) << setfill('0') << hex << (int)ethh.ether_dhost[i];
            if (i != 5)
                cout << ":";
        }
        cout << "\n源IP地址：";
        for (int i = 0; i < 4; i++)
        {
            cout << dec << (int)u32tu8(iph.saddr)[i];
            if (i != 3)
                cout << ".";
        }
        cout << "\n目的IP地址：";
        for (int i = 0; i < 4; i++)
        {
            cout << dec << (int)u32tu8(iph.daddr)[i];
            if (i != 3)
                cout << ".";
        }
        cout << endl;
    }
};