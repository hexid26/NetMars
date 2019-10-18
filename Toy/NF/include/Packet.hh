#include "NetStruct.hh"
#include <stdlib.h>

uint8_t _dh[6] = {0x00, 0x0c, 0x29, 0x99, 0x76, 0xb1};
uint8_t _sh[6] = {0x00, 0x50, 0x56, 0xfe, 0xdd, 0x68};
class Packet
{
public:
    struct ether_header ethh; //14bytes
    struct iphdr iph;         //20bytes
    struct udphdr uph;        //8bytes
    uint8_t *pdata;
    uint16_t plen;
    Packet()
    {
        generate_data();
        set_udphdr();
        set_iphdr();
        set_ether_header();
    }
    void set_ether_header()
    {
        for (int i = 0; i < 6; i++)
        {
            (ethh.ether_dhost)[i] = _dh[i];
            (ethh.ether_shost)[i] = _sh[i];
        }
        ethh.ether_type = 0x0800;
    }
    void set_iphdr()
    {
        iph.version = 4;
        iph.ihl = 5;
        iph.tos = 0;
        iph.tot_len = plen + 20 + 8;
        iph.id = 0x8d2f;
        iph.frag_off = 0x0000;
        iph.ttl = 0x80;
        iph.protocol = 0x11;
        iph.check = 0x107f;
        iph.saddr = 0x0a000001u;
        iph.daddr = 0x0a00000au;
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
    void generate_data()
    {
        plen = rand() % 540 + 1;
        pdata = new uint8_t[plen];
        for (int i = 0; i < plen; i++)
        {
            pdata[i] = rand() % (126 - 32 + 1) + 32;
        }
    }
};