#include "auxiliary.hpp"
#include "NetStruct.hpp"

// #define SHA1_THREADS_PER_BLK 32

#define MAX_AUTHENTICATED_PART 1024

extern "C"
{
    __device__ static uint32_t swap(uint32_t v)
    {
        return ((v & 0x000000ffU) << 24) | ((v & 0x0000ff00U) << 8) | ((v & 0x00ff0000U) >> 8) | ((v & 0xff000000U) >> 24);
    }

    typedef struct hash_digest
    {
        uint32_t h1;
        uint32_t h2;
        uint32_t h3;
        uint32_t h4;
        uint32_t h5;
    } hash_digest_t;

#define HMAC

    __inline__ __device__ static void getBlock(char *buf, int offset, int len, uint32_t *dest)
    {
        uint32_t *tmp;
        unsigned int tempbuf[16];

        tmp = (uint32_t *)(buf + offset);
        //printf("%d %d\n", offset, len);
        if (offset + 64 <= len)
        {
            //printf("--0--\n");
#pragma unroll 16
            for (int i = 0; i < 16; i++)
            {
                dest[i] = swap(tmp[i]);
            }
        }
        else if (len > offset && (len - offset) < 56)
        { //case 1 enough space in last block for padding
            //prtinf("--1--\n");
            int i;
            for (i = 0; i < (len - offset) / 4; i++)
            {

                //printf("%d %d\n",offset,i);
                //printf("%p %p\n", buf, dest);

                //tempbuf[i] = buf[i];
                tempbuf[i] = swap(tmp[i]);
            }
            //printf("len%%4 %d\n",len%4);
            switch (len % 4)
            {
            case 0:
                tempbuf[i] = swap(0x00000080);
                i++;
                break;
            case 1:
                tempbuf[i] = swap(0x00008000 | (tmp[i] & 0x000000FF));
                i++;
                break;
            case 2:
                tempbuf[i] = swap(0x00800000 | (tmp[i] & 0x0000FFFF));
                i++;
                break;
            case 3:
                tempbuf[i] = swap(0x80000000 | (tmp[i] & 0x00FFFFFF));
                i++;
                break;
            };
            for (; i < 14; i++)
            {
                tempbuf[i] = 0;
            }
#pragma unroll 14
            for (i = 0; i < 14; i++)
            {
                dest[i] = tempbuf[i];
            }
            dest[14] = 0x00000000;
#ifndef HMAC
            dest[15] = len * 8;
#else
            dest[15] = (len + 64) * 8;
#endif
        }
        else if (len > offset && (len - offset) >= 56)
        { //case 2 not enough space in last block (containing message) for padding
            //printf("--2--\n");
            int i;
            for (i = 0; i < (len - offset) / 4; i++)
            {
                tempbuf[i] = swap(tmp[i]);
            }
            switch (len % 4)
            {
            case 0:
                tempbuf[i] = swap(0x00000080);
                i++;
                break;
            case 1:
                tempbuf[i] = swap(0x00008000 | (tmp[i] & 0x000000FF));
                i++;
                break;
            case 2:
                tempbuf[i] = swap(0x00800000 | (tmp[i] & 0x0000FFFF));
                i++;
                break;
            case 3:
                tempbuf[i] = swap(0x80000000 | (tmp[i] & 0x00FFFFFF));
                i++;
                break;
            };

            for (; i < 16; i++)
            {
                tempbuf[i] = 0x00000000;
            }

#pragma unroll 16
            for (i = 0; i < 16; i++)
            {
                dest[i] = tempbuf[i];
            }
        }
        else if (offset == len)
        { //message end is aligned in 64 bytes
            //printf("--3--\n");
            dest[0] = swap(0x00000080);
#pragma unroll 13
            for (int i = 1; i < 14; i++)
                dest[i] = 0x00000000;
            dest[14] = 0x00000000;
#ifndef HMAC
            dest[15] = len * 8;
#else
            dest[15] = (len + 64) * 8;
#endif
        }
        else if (offset > len)
        {   //the last block in case 2
            //printf("--4--\n");
#pragma unroll 14
            for (int i = 0; i < 14; i++)
                dest[i] = 0x00000000;
            dest[14] = 0x00000000;
#ifndef HMAC
            dest[15] = len * 8;
#else
            dest[15] = (len + 64) * 8;
#endif
        }
        else
        {
            printf("Not supposed to happen\n");
        }
    }

    __device__ static void computeSHA1Block(char *in, uint32_t *w, int offset, int len,
                                            hash_digest_t &h)
    {
        uint32_t a = h.h1;
        uint32_t b = h.h2;
        uint32_t c = h.h3;
        uint32_t d = h.h4;
        uint32_t e = h.h5;
        uint32_t f;
        uint32_t k;
        uint32_t temp;

        getBlock(in, offset, len, w);

        //for (int i = 0; i < 16 ; i++) {
        //  printf("%0X\n", w[i]);
        //}
        //printf("\n");

        k = 0x5A827999;
        //0 of 0-20
        f = (b & c) | ((~b) & d);
        temp = ((a << 5) | (a >> 27)) + f + e + k + w[0];
        e = d;
        d = c;
        c = (b << 30) | (b >> 2);
        b = a;
        a = temp;

        w[0] = w[13] ^ w[8] ^ w[2] ^ w[0];
        w[0] = w[0] << 1 | w[0] >> 31;

        //1 of 0-20
        f = (b & c) | ((~b) & d);
        temp = ((a << 5) | (a >> 27)) + f + e + k + w[1];
        e = d;
        d = c;
        c = (b << 30) | (b >> 2);
        b = a;
        a = temp;

        w[1] = w[14] ^ w[9] ^ w[3] ^ w[1];
        w[1] = w[1] << 1 | w[1] >> 31;

        //2 of 0-20
        f = (b & c) | ((~b) & d);
        temp = ((a << 5) | (a >> 27)) + f + e + k + w[2];
        e = d;
        d = c;
        c = (b << 30) | (b >> 2);
        b = a;
        a = temp;

        w[2] = w[15] ^ w[10] ^ w[4] ^ w[2];
        w[2] = w[2] << 1 | w[2] >> 31;

        //3 of 0-20
        f = (b & c) | ((~b) & d);
        temp = ((a << 5) | (a >> 27)) + f + e + k + w[3];
        e = d;
        d = c;
        c = (b << 30) | (b >> 2);
        b = a;
        a = temp;

        w[3] = w[0] ^ w[11] ^ w[5] ^ w[3];
        w[3] = w[3] << 1 | w[3] >> 31;

        //4 of 0-20
        f = (b & c) | ((~b) & d);
        temp = ((a << 5) | (a >> 27)) + f + e + k + w[4];
        e = d;
        d = c;
        c = (b << 30) | (b >> 2);
        b = a;
        a = temp;

        w[4] = w[1] ^ w[12] ^ w[6] ^ w[4];
        w[4] = w[4] << 1 | w[4] >> 31;

        //5 of 0-20
        f = (b & c) | ((~b) & d);
        temp = ((a << 5) | (a >> 27)) + f + e + k + w[5];
        e = d;
        d = c;
        c = (b << 30) | (b >> 2);
        b = a;
        a = temp;

        w[5] = w[2] ^ w[13] ^ w[7] ^ w[5];
        w[5] = w[5] << 1 | w[5] >> 31;

        //6 of 0-20
        f = (b & c) | ((~b) & d);
        temp = ((a << 5) | (a >> 27)) + f + e + k + w[6];
        e = d;
        d = c;
        c = (b << 30) | (b >> 2);
        b = a;
        a = temp;

        w[6] = w[3] ^ w[14] ^ w[8] ^ w[6];
        w[6] = w[6] << 1 | w[6] >> 31;

        //7 of 0-20
        f = (b & c) | ((~b) & d);
        temp = ((a << 5) | (a >> 27)) + f + e + k + w[7];
        e = d;
        d = c;
        c = (b << 30) | (b >> 2);
        b = a;
        a = temp;

        w[7] = w[4] ^ w[15] ^ w[9] ^ w[7];
        w[7] = w[7] << 1 | w[7] >> 31;

        //8 of 0-20
        f = (b & c) | ((~b) & d);
        temp = ((a << 5) | (a >> 27)) + f + e + k + w[8];
        e = d;
        d = c;
        c = (b << 30) | (b >> 2);
        b = a;
        a = temp;

        w[8] = w[5] ^ w[0] ^ w[10] ^ w[8];
        w[8] = w[8] << 1 | w[8] >> 31;

        //9 of 0-20
        f = (b & c) | ((~b) & d);
        temp = ((a << 5) | (a >> 27)) + f + e + k + w[9];
        e = d;
        d = c;
        c = (b << 30) | (b >> 2);
        b = a;
        a = temp;

        w[9] = w[6] ^ w[1] ^ w[11] ^ w[9];
        w[9] = w[9] << 1 | w[9] >> 31;

        //10 of 0-20
        f = (b & c) | ((~b) & d);
        temp = ((a << 5) | (a >> 27)) + f + e + k + w[10];
        e = d;
        d = c;
        c = (b << 30) | (b >> 2);
        b = a;
        a = temp;

        w[10] = w[7] ^ w[2] ^ w[12] ^ w[10];
        w[10] = w[10] << 1 | w[10] >> 31;

        //11 of 0-20
        f = (b & c) | ((~b) & d);
        temp = ((a << 5) | (a >> 27)) + f + e + k + w[11];
        e = d;
        d = c;
        c = (b << 30) | (b >> 2);
        b = a;
        a = temp;

        w[11] = w[8] ^ w[3] ^ w[13] ^ w[11];
        w[11] = w[11] << 1 | w[11] >> 31;

        //12 of 0-20
        f = (b & c) | ((~b) & d);
        temp = ((a << 5) | (a >> 27)) + f + e + k + w[12];
        e = d;
        d = c;
        c = (b << 30) | (b >> 2);
        b = a;
        a = temp;

        w[12] = w[9] ^ w[4] ^ w[14] ^ w[12];
        w[12] = w[12] << 1 | w[12] >> 31;

        //13 of 0-20
        f = (b & c) | ((~b) & d);
        temp = ((a << 5) | (a >> 27)) + f + e + k + w[13];
        e = d;
        d = c;
        c = (b << 30) | (b >> 2);
        b = a;
        a = temp;

        w[13] = w[10] ^ w[5] ^ w[15] ^ w[13];
        w[13] = w[13] << 1 | w[13] >> 31;

        //14 of 0-20
        f = (b & c) | ((~b) & d);
        temp = ((a << 5) | (a >> 27)) + f + e + k + w[14];
        e = d;
        d = c;
        c = (b << 30) | (b >> 2);
        b = a;
        a = temp;

        w[14] = w[11] ^ w[6] ^ w[0] ^ w[14];
        w[14] = w[14] << 1 | w[14] >> 31;

        //15 of 0-20
        f = (b & c) | ((~b) & d);
        temp = ((a << 5) | (a >> 27)) + f + e + k + w[15];
        e = d;
        d = c;
        c = (b << 30) | (b >> 2);
        b = a;
        a = temp;

        w[15] = w[12] ^ w[7] ^ w[1] ^ w[15];
        w[15] = w[15] << 1 | w[15] >> 31;

        //16 of 0-20
        f = (b & c) | ((~b) & d);
        temp = ((a << 5) | (a >> 27)) + f + e + k + w[0];
        e = d;
        d = c;
        c = (b << 30) | (b >> 2);
        b = a;
        a = temp;

        w[0] = w[13] ^ w[8] ^ w[2] ^ w[0];
        w[0] = w[0] << 1 | w[0] >> 31;

        //17 of 0-20
        f = (b & c) | ((~b) & d);
        temp = ((a << 5) | (a >> 27)) + f + e + k + w[1];
        e = d;
        d = c;
        c = (b << 30) | (b >> 2);
        b = a;
        a = temp;

        w[1] = w[14] ^ w[9] ^ w[3] ^ w[1];
        w[1] = w[1] << 1 | w[1] >> 31;

        //18 of 0-20
        f = (b & c) | ((~b) & d);
        temp = ((a << 5) | (a >> 27)) + f + e + k + w[2];
        e = d;
        d = c;
        c = (b << 30) | (b >> 2);
        b = a;
        a = temp;

        w[2] = w[15] ^ w[10] ^ w[4] ^ w[2];
        w[2] = w[2] << 1 | w[2] >> 31;

        //19 of 0-20
        f = (b & c) | ((~b) & d);
        temp = ((a << 5) | (a >> 27)) + f + e + k + w[3];
        e = d;
        d = c;
        c = (b << 30) | (b >> 2);
        b = a;
        a = temp;

        w[3] = w[0] ^ w[11] ^ w[5] ^ w[3];
        w[3] = w[3] << 1 | w[3] >> 31;

        k = 0x6ED9EBA1;
        //20 of 20-40
        f = b ^ c ^ d;
        temp = ((a << 5) | (a >> 27)) + f + e + k + w[4];
        e = d;
        d = c;
        c = (b << 30) | (b >> 2);
        b = a;
        a = temp;

        w[4] = w[1] ^ w[12] ^ w[6] ^ w[4];
        w[4] = w[4] << 1 | w[4] >> 31;

        //21 of 20-40
        f = b ^ c ^ d;
        temp = ((a << 5) | (a >> 27)) + f + e + k + w[5];
        e = d;
        d = c;
        c = (b << 30) | (b >> 2);
        b = a;
        a = temp;

        w[5] = w[2] ^ w[13] ^ w[7] ^ w[5];
        w[5] = w[5] << 1 | w[5] >> 31;

        //22 of 20-40
        f = b ^ c ^ d;
        temp = ((a << 5) | (a >> 27)) + f + e + k + w[6];
        e = d;
        d = c;
        c = (b << 30) | (b >> 2);
        b = a;
        a = temp;

        w[6] = w[3] ^ w[14] ^ w[8] ^ w[6];
        w[6] = w[6] << 1 | w[6] >> 31;

        //23 of 20-40
        f = b ^ c ^ d;
        temp = ((a << 5) | (a >> 27)) + f + e + k + w[7];
        e = d;
        d = c;
        c = (b << 30) | (b >> 2);
        b = a;
        a = temp;

        w[7] = w[4] ^ w[15] ^ w[9] ^ w[7];
        w[7] = w[7] << 1 | w[7] >> 31;

        //24 of 20-40
        f = b ^ c ^ d;
        temp = ((a << 5) | (a >> 27)) + f + e + k + w[8];
        e = d;
        d = c;
        c = (b << 30) | (b >> 2);
        b = a;
        a = temp;

        w[8] = w[5] ^ w[0] ^ w[10] ^ w[8];
        w[8] = w[8] << 1 | w[8] >> 31;

        //25 of 20-40
        f = b ^ c ^ d;
        temp = ((a << 5) | (a >> 27)) + f + e + k + w[9];
        e = d;
        d = c;
        c = (b << 30) | (b >> 2);
        b = a;
        a = temp;

        w[9] = w[6] ^ w[1] ^ w[11] ^ w[9];
        w[9] = w[9] << 1 | w[9] >> 31;

        //26 of 20-40
        f = b ^ c ^ d;
        temp = ((a << 5) | (a >> 27)) + f + e + k + w[10];
        e = d;
        d = c;
        c = (b << 30) | (b >> 2);
        b = a;
        a = temp;

        w[10] = w[7] ^ w[2] ^ w[12] ^ w[10];
        w[10] = w[10] << 1 | w[10] >> 31;

        //27 of 20-40
        f = b ^ c ^ d;
        temp = ((a << 5) | (a >> 27)) + f + e + k + w[11];
        e = d;
        d = c;
        c = (b << 30) | (b >> 2);
        b = a;
        a = temp;

        w[11] = w[8] ^ w[3] ^ w[13] ^ w[11];
        w[11] = w[11] << 1 | w[11] >> 31;

        //28 of 20-40
        f = b ^ c ^ d;
        temp = ((a << 5) | (a >> 27)) + f + e + k + w[12];
        e = d;
        d = c;
        c = (b << 30) | (b >> 2);
        b = a;
        a = temp;

        w[12] = w[9] ^ w[4] ^ w[14] ^ w[12];
        w[12] = w[12] << 1 | w[12] >> 31;

        //29 of 20-40
        f = b ^ c ^ d;
        temp = ((a << 5) | (a >> 27)) + f + e + k + w[13];
        e = d;
        d = c;
        c = (b << 30) | (b >> 2);
        b = a;
        a = temp;

        w[13] = w[10] ^ w[5] ^ w[15] ^ w[13];
        w[13] = w[13] << 1 | w[13] >> 31;

        //30 of 20-40
        f = b ^ c ^ d;
        temp = ((a << 5) | (a >> 27)) + f + e + k + w[14];
        e = d;
        d = c;
        c = (b << 30) | (b >> 2);
        b = a;
        a = temp;

        w[14] = w[11] ^ w[6] ^ w[0] ^ w[14];
        w[14] = w[14] << 1 | w[14] >> 31;

        //31 of 20-40
        f = b ^ c ^ d;
        temp = ((a << 5) | (a >> 27)) + f + e + k + w[15];
        e = d;
        d = c;
        c = (b << 30) | (b >> 2);
        b = a;
        a = temp;

        w[15] = w[12] ^ w[7] ^ w[1] ^ w[15];
        w[15] = w[15] << 1 | w[15] >> 31;

        //32 of 20-40
        f = b ^ c ^ d;
        temp = ((a << 5) | (a >> 27)) + f + e + k + w[0];
        e = d;
        d = c;
        c = (b << 30) | (b >> 2);
        b = a;
        a = temp;

        w[0] = w[13] ^ w[8] ^ w[2] ^ w[0];
        w[0] = w[0] << 1 | w[0] >> 31;

        //33 of 20-40
        f = b ^ c ^ d;
        temp = ((a << 5) | (a >> 27)) + f + e + k + w[1];
        e = d;
        d = c;
        c = (b << 30) | (b >> 2);
        b = a;
        a = temp;

        w[1] = w[14] ^ w[9] ^ w[3] ^ w[1];
        w[1] = w[1] << 1 | w[1] >> 31;

        //34 of 20-40
        f = b ^ c ^ d;
        temp = ((a << 5) | (a >> 27)) + f + e + k + w[2];
        e = d;
        d = c;
        c = (b << 30) | (b >> 2);
        b = a;
        a = temp;

        w[2] = w[15] ^ w[10] ^ w[4] ^ w[2];
        w[2] = w[2] << 1 | w[2] >> 31;

        //35 of 20-40
        f = b ^ c ^ d;
        temp = ((a << 5) | (a >> 27)) + f + e + k + w[3];
        e = d;
        d = c;
        c = (b << 30) | (b >> 2);
        b = a;
        a = temp;

        w[3] = w[0] ^ w[11] ^ w[5] ^ w[3];
        w[3] = w[3] << 1 | w[3] >> 31;

        //36 of 20-40
        f = b ^ c ^ d;
        temp = ((a << 5) | (a >> 27)) + f + e + k + w[4];
        e = d;
        d = c;
        c = (b << 30) | (b >> 2);
        b = a;
        a = temp;

        w[4] = w[1] ^ w[12] ^ w[6] ^ w[4];
        w[4] = w[4] << 1 | w[4] >> 31;

        //37 of 20-40
        f = b ^ c ^ d;
        temp = ((a << 5) | (a >> 27)) + f + e + k + w[5];
        e = d;
        d = c;
        c = (b << 30) | (b >> 2);
        b = a;
        a = temp;

        w[5] = w[2] ^ w[13] ^ w[7] ^ w[5];
        w[5] = w[5] << 1 | w[5] >> 31;

        //38 of 20-40
        f = b ^ c ^ d;
        temp = ((a << 5) | (a >> 27)) + f + e + k + w[6];
        e = d;
        d = c;
        c = (b << 30) | (b >> 2);
        b = a;
        a = temp;

        w[6] = w[3] ^ w[14] ^ w[8] ^ w[6];
        w[6] = w[6] << 1 | w[6] >> 31;

        //39 of 20-40
        f = b ^ c ^ d;
        temp = ((a << 5) | (a >> 27)) + f + e + k + w[7];
        e = d;
        d = c;
        c = (b << 30) | (b >> 2);
        b = a;
        a = temp;

        w[7] = w[4] ^ w[15] ^ w[9] ^ w[7];
        w[7] = w[7] << 1 | w[7] >> 31;

        k = 0x8F1BBCDC;
        //40 of 40-60
        f = (b & c) | (b & d) | (c & d);
        temp = ((a << 5) | (a >> 27)) + f + e + k + w[8];
        e = d;
        d = c;
        c = (b << 30) | (b >> 2);
        b = a;
        a = temp;

        w[8] = w[5] ^ w[0] ^ w[10] ^ w[8];
        w[8] = w[8] << 1 | w[8] >> 31;

        //41 of 40-60
        f = (b & c) | (b & d) | (c & d);
        temp = ((a << 5) | (a >> 27)) + f + e + k + w[9];
        e = d;
        d = c;
        c = (b << 30) | (b >> 2);
        b = a;
        a = temp;

        w[9] = w[6] ^ w[1] ^ w[11] ^ w[9];
        w[9] = w[9] << 1 | w[9] >> 31;

        //42 of 40-60
        f = (b & c) | (b & d) | (c & d);
        temp = ((a << 5) | (a >> 27)) + f + e + k + w[10];
        e = d;
        d = c;
        c = (b << 30) | (b >> 2);
        b = a;
        a = temp;

        w[10] = w[7] ^ w[2] ^ w[12] ^ w[10];
        w[10] = w[10] << 1 | w[10] >> 31;

        //43 of 40-60
        f = (b & c) | (b & d) | (c & d);
        temp = ((a << 5) | (a >> 27)) + f + e + k + w[11];
        e = d;
        d = c;
        c = (b << 30) | (b >> 2);
        b = a;
        a = temp;

        w[11] = w[8] ^ w[3] ^ w[13] ^ w[11];
        w[11] = w[11] << 1 | w[11] >> 31;

        //44 of 40-60
        f = (b & c) | (b & d) | (c & d);
        temp = ((a << 5) | (a >> 27)) + f + e + k + w[12];
        e = d;
        d = c;
        c = (b << 30) | (b >> 2);
        b = a;
        a = temp;

        w[12] = w[9] ^ w[4] ^ w[14] ^ w[12];
        w[12] = w[12] << 1 | w[12] >> 31;

        //45 of 40-60
        f = (b & c) | (b & d) | (c & d);
        temp = ((a << 5) | (a >> 27)) + f + e + k + w[13];
        e = d;
        d = c;
        c = (b << 30) | (b >> 2);
        b = a;
        a = temp;

        w[13] = w[10] ^ w[5] ^ w[15] ^ w[13];
        w[13] = w[13] << 1 | w[13] >> 31;

        //46 of 40-60
        f = (b & c) | (b & d) | (c & d);
        temp = ((a << 5) | (a >> 27)) + f + e + k + w[14];
        e = d;
        d = c;
        c = (b << 30) | (b >> 2);
        b = a;
        a = temp;

        w[14] = w[11] ^ w[6] ^ w[0] ^ w[14];
        w[14] = w[14] << 1 | w[14] >> 31;

        //47 of 40-60
        f = (b & c) | (b & d) | (c & d);
        temp = ((a << 5) | (a >> 27)) + f + e + k + w[15];
        e = d;
        d = c;
        c = (b << 30) | (b >> 2);
        b = a;
        a = temp;

        w[15] = w[12] ^ w[7] ^ w[1] ^ w[15];
        w[15] = w[15] << 1 | w[15] >> 31;

        //48 of 40-60
        f = (b & c) | (b & d) | (c & d);
        temp = ((a << 5) | (a >> 27)) + f + e + k + w[0];
        e = d;
        d = c;
        c = (b << 30) | (b >> 2);
        b = a;
        a = temp;

        w[0] = w[13] ^ w[8] ^ w[2] ^ w[0];
        w[0] = w[0] << 1 | w[0] >> 31;

        //49 of 40-60
        f = (b & c) | (b & d) | (c & d);
        temp = ((a << 5) | (a >> 27)) + f + e + k + w[1];
        e = d;
        d = c;
        c = (b << 30) | (b >> 2);
        b = a;
        a = temp;

        w[1] = w[14] ^ w[9] ^ w[3] ^ w[1];
        w[1] = w[1] << 1 | w[1] >> 31;

        //50 of 40-60
        f = (b & c) | (b & d) | (c & d);
        temp = ((a << 5) | (a >> 27)) + f + e + k + w[2];
        e = d;
        d = c;
        c = (b << 30) | (b >> 2);
        b = a;
        a = temp;

        w[2] = w[15] ^ w[10] ^ w[4] ^ w[2];
        w[2] = w[2] << 1 | w[2] >> 31;

        //51 of 40-60
        f = (b & c) | (b & d) | (c & d);
        temp = ((a << 5) | (a >> 27)) + f + e + k + w[3];
        e = d;
        d = c;
        c = (b << 30) | (b >> 2);
        b = a;
        a = temp;

        w[3] = w[0] ^ w[11] ^ w[5] ^ w[3];
        w[3] = w[3] << 1 | w[3] >> 31;

        //52 of 40-60
        f = (b & c) | (b & d) | (c & d);
        temp = ((a << 5) | (a >> 27)) + f + e + k + w[4];
        e = d;
        d = c;
        c = (b << 30) | (b >> 2);
        b = a;
        a = temp;

        w[4] = w[1] ^ w[12] ^ w[6] ^ w[4];
        w[4] = w[4] << 1 | w[4] >> 31;

        //53 of 40-60
        f = (b & c) | (b & d) | (c & d);
        temp = ((a << 5) | (a >> 27)) + f + e + k + w[5];
        e = d;
        d = c;
        c = (b << 30) | (b >> 2);
        b = a;
        a = temp;

        w[5] = w[2] ^ w[13] ^ w[7] ^ w[5];
        w[5] = w[5] << 1 | w[5] >> 31;

        //54 of 40-60
        f = (b & c) | (b & d) | (c & d);
        temp = ((a << 5) | (a >> 27)) + f + e + k + w[6];
        e = d;
        d = c;
        c = (b << 30) | (b >> 2);
        b = a;
        a = temp;

        w[6] = w[3] ^ w[14] ^ w[8] ^ w[6];
        w[6] = w[6] << 1 | w[6] >> 31;

        //55 of 40-60
        f = (b & c) | (b & d) | (c & d);
        temp = ((a << 5) | (a >> 27)) + f + e + k + w[7];
        e = d;
        d = c;
        c = (b << 30) | (b >> 2);
        b = a;
        a = temp;

        w[7] = w[4] ^ w[15] ^ w[9] ^ w[7];
        w[7] = w[7] << 1 | w[7] >> 31;

        //56 of 40-60
        f = (b & c) | (b & d) | (c & d);
        temp = ((a << 5) | (a >> 27)) + f + e + k + w[8];
        e = d;
        d = c;
        c = (b << 30) | (b >> 2);
        b = a;
        a = temp;

        w[8] = w[5] ^ w[0] ^ w[10] ^ w[8];
        w[8] = w[8] << 1 | w[8] >> 31;

        //57 of 40-60
        f = (b & c) | (b & d) | (c & d);
        temp = ((a << 5) | (a >> 27)) + f + e + k + w[9];
        e = d;
        d = c;
        c = (b << 30) | (b >> 2);
        b = a;
        a = temp;

        w[9] = w[6] ^ w[1] ^ w[11] ^ w[9];
        w[9] = w[9] << 1 | w[9] >> 31;

        //58 of 40-60
        f = (b & c) | (b & d) | (c & d);
        temp = ((a << 5) | (a >> 27)) + f + e + k + w[10];
        e = d;
        d = c;
        c = (b << 30) | (b >> 2);
        b = a;
        a = temp;

        w[10] = w[7] ^ w[2] ^ w[12] ^ w[10];
        w[10] = w[10] << 1 | w[10] >> 31;

        //59 of 40-60
        f = (b & c) | (b & d) | (c & d);
        temp = ((a << 5) | (a >> 27)) + f + e + k + w[11];
        e = d;
        d = c;
        c = (b << 30) | (b >> 2);
        b = a;
        a = temp;

        w[11] = w[8] ^ w[3] ^ w[13] ^ w[11];
        w[11] = w[11] << 1 | w[11] >> 31;

        k = 0xCA62C1D6;

        //60 of 60-64
        f = b ^ c ^ d;
        temp = ((a << 5) | (a >> 27)) + f + e + k + w[12];
        e = d;
        d = c;
        c = (b << 30) | (b >> 2);
        b = a;
        a = temp;

        w[12] = w[9] ^ w[4] ^ w[14] ^ w[12];
        w[12] = w[12] << 1 | w[12] >> 31;

        //61 of 60-64
        f = b ^ c ^ d;
        temp = ((a << 5) | (a >> 27)) + f + e + k + w[13];
        e = d;
        d = c;
        c = (b << 30) | (b >> 2);
        b = a;
        a = temp;

        w[13] = w[10] ^ w[5] ^ w[15] ^ w[13];
        w[13] = w[13] << 1 | w[13] >> 31;

        //62 of 60-64
        f = b ^ c ^ d;
        temp = ((a << 5) | (a >> 27)) + f + e + k + w[14];
        e = d;
        d = c;
        c = (b << 30) | (b >> 2);
        b = a;
        a = temp;

        w[14] = w[11] ^ w[6] ^ w[0] ^ w[14];
        w[14] = w[14] << 1 | w[14] >> 31;

        //63 of 60-64
        f = b ^ c ^ d;
        temp = ((a << 5) | (a >> 27)) + f + e + k + w[15];
        e = d;
        d = c;
        c = (b << 30) | (b >> 2);
        b = a;
        a = temp;

        w[15] = w[12] ^ w[7] ^ w[1] ^ w[15];
        w[15] = w[15] << 1 | w[15] >> 31;

        //64 of 64-80
        f = b ^ c ^ d;
        temp = ((a << 5) | (a >> 27)) + f + e + k + w[0];
        e = d;
        d = c;
        c = (b << 30) | (b >> 2);
        b = a;
        a = temp;

        //65 of 64-80
        f = b ^ c ^ d;
        temp = ((a << 5) | (a >> 27)) + f + e + k + w[1];
        e = d;
        d = c;
        c = (b << 30) | (b >> 2);
        b = a;
        a = temp;

        //66 of 64-80
        f = b ^ c ^ d;
        temp = ((a << 5) | (a >> 27)) + f + e + k + w[2];
        e = d;
        d = c;
        c = (b << 30) | (b >> 2);
        b = a;
        a = temp;

        //67 of 64-80
        f = b ^ c ^ d;
        temp = ((a << 5) | (a >> 27)) + f + e + k + w[3];
        e = d;
        d = c;
        c = (b << 30) | (b >> 2);
        b = a;
        a = temp;

        //68 of 64-80
        f = b ^ c ^ d;
        temp = ((a << 5) | (a >> 27)) + f + e + k + w[4];
        e = d;
        d = c;
        c = (b << 30) | (b >> 2);
        b = a;
        a = temp;

        //69 of 64-80
        f = b ^ c ^ d;
        temp = ((a << 5) | (a >> 27)) + f + e + k + w[5];
        e = d;
        d = c;
        c = (b << 30) | (b >> 2);
        b = a;
        a = temp;

        //70 of 64-80
        f = b ^ c ^ d;
        temp = ((a << 5) | (a >> 27)) + f + e + k + w[6];
        e = d;
        d = c;
        c = (b << 30) | (b >> 2);
        b = a;
        a = temp;

        //71 of 64-80
        f = b ^ c ^ d;
        temp = ((a << 5) | (a >> 27)) + f + e + k + w[7];
        e = d;
        d = c;
        c = (b << 30) | (b >> 2);
        b = a;
        a = temp;

        //72 of 64-80
        f = b ^ c ^ d;
        temp = ((a << 5) | (a >> 27)) + f + e + k + w[8];
        e = d;
        d = c;
        c = (b << 30) | (b >> 2);
        b = a;
        a = temp;

        //73 of 64-80
        f = b ^ c ^ d;
        temp = ((a << 5) | (a >> 27)) + f + e + k + w[9];
        e = d;
        d = c;
        c = (b << 30) | (b >> 2);
        b = a;
        a = temp;

        //74 of 64-80
        f = b ^ c ^ d;
        temp = ((a << 5) | (a >> 27)) + f + e + k + w[10];
        e = d;
        d = c;
        c = (b << 30) | (b >> 2);
        b = a;
        a = temp;

        //75 of 64-80
        f = b ^ c ^ d;
        temp = ((a << 5) | (a >> 27)) + f + e + k + w[11];
        e = d;
        d = c;
        c = (b << 30) | (b >> 2);
        b = a;
        a = temp;

        //76 of 64-80
        f = b ^ c ^ d;
        temp = ((a << 5) | (a >> 27)) + f + e + k + w[12];
        e = d;
        d = c;
        c = (b << 30) | (b >> 2);
        b = a;
        a = temp;

        //77 of 64-80
        f = b ^ c ^ d;
        temp = ((a << 5) | (a >> 27)) + f + e + k + w[13];
        e = d;
        d = c;
        c = (b << 30) | (b >> 2);
        b = a;
        a = temp;

        //78 of 64-80
        f = b ^ c ^ d;
        temp = ((a << 5) | (a >> 27)) + f + e + k + w[14];
        e = d;
        d = c;
        c = (b << 30) | (b >> 2);
        b = a;
        a = temp;

        //79 of 64-80
        f = b ^ c ^ d;
        temp = ((a << 5) | (a >> 27)) + f + e + k + w[15];
        e = d;
        d = c;
        c = (b << 30) | (b >> 2);
        b = a;
        a = temp;

        h.h1 += a;
        h.h2 += b;
        h.h3 += c;
        h.h4 += d;
        h.h5 += e;
    }
    /*
 some how *pad = *pad++ ^ *key++
 was optimized and does not work correctly in GPU oTL.
 */
    __device__ static void xorpads(uint32_t *pad, const uint32_t *key)
    {
#pragma unroll 16
        for (int i = 0; i < 16; i++)
            *(pad + i) = *(pad + i) ^ *(key + i);
    }

    uint32_t opad[16] =
        {
            0x5c5c5c5c,
            0x5c5c5c5c,
            0x5c5c5c5c,
            0x5c5c5c5c,
            0x5c5c5c5c,
            0x5c5c5c5c,
            0x5c5c5c5c,
            0x5c5c5c5c,
            0x5c5c5c5c,
            0x5c5c5c5c,
            0x5c5c5c5c,
            0x5c5c5c5c,
            0x5c5c5c5c,
            0x5c5c5c5c,
            0x5c5c5c5c,
            0x5c5c5c5c,
    };
    uint32_t ipad[16] =
        {
            0x36363636,
            0x36363636,
            0x36363636,
            0x36363636,
            0x36363636,
            0x36363636,
            0x36363636,
            0x36363636,
            0x36363636,
            0x36363636,
            0x36363636,
            0x36363636,
            0x36363636,
            0x36363636,
            0x36363636,
            0x36363636,
    };

    // in: start pointer of the data to be authenticated by hsha1.
    // out: start pointer of the data where hsha1 signature will be recorded.
    // length: length of the data to be authenticated by hsha1.
    // key: hmac key.
    __device__ static void HMAC_SHA1(uint32_t *in, uint32_t *out, uint32_t length,
                                     const char *key)
    {
        uint32_t w_register[16];

        uint32_t *w = w_register; //w_shared + 16*threadIdx.x;
        hash_digest_t h;

        for (int i = 0; i < 16; i++)
            w[i] = 0x36363636;
        xorpads(w, (uint32_t *)(key));

        h.h1 = 0x67452301;
        h.h2 = 0xEFCDAB89;
        h.h3 = 0x98BADCFE;
        h.h4 = 0x10325476;
        h.h5 = 0xC3D2E1F0;

        //SHA1 compute on ipad
        computeSHA1Block((char *)w, w, 0, 64, h);

        //SHA1 compute on mesage
        int num_iter = (length + 63 + 9) / 64;
        for (int i = 0; i < num_iter; i++)
            computeSHA1Block((char *)in, w, i * 64, length, h);

        *(out) = swap(h.h1);
        *(out + 1) = swap(h.h2);
        *(out + 2) = swap(h.h3);
        *(out + 3) = swap(h.h4);
        *(out + 4) = swap(h.h5);

        h.h1 = 0x67452301;
        h.h2 = 0xEFCDAB89;
        h.h3 = 0x98BADCFE;
        h.h4 = 0x10325476;
        h.h5 = 0xC3D2E1F0;

        for (int i = 0; i < 16; i++)
            w[i] = 0x5c5c5c5c;

        xorpads(w, (uint32_t *)(key));

        //SHA 1 compute on opads
        computeSHA1Block((char *)w, w, 0, 64, h);

        //SHA 1 compute on (hash of ipad|m)
        computeSHA1Block((char *)out, w, 0, 20, h);

        *(out) = swap(h.h1);
        *(out + 1) = swap(h.h2);
        *(out + 2) = swap(h.h3);
        *(out + 3) = swap(h.h4);
        *(out + 4) = swap(h.h5);
    }

    __device__ static inline uint16_t u8tu16(uint8_t *data)
    {
        uint16_t result = 0;
        for (int i = 0; i < 2; i++)
        {
            result += data[i] * pow(16, 2 - 2 * i);
        }
        return result;
    }

    __global__ static void computeHMAC_SHA1(
        const int batch_size,
        const int block_num_y,
        uint8_t *__restrict__ dev_enc_payload,
        uint8_t *__restrict__ pac_data,
        unsigned int *__restrict__ pac_sign,
        uint8_t *__restrict__ hmac_key)
    {
        int I = blockIdx.x * blockDim.x + threadIdx.x;
        int J = blockIdx.y * blockDim.y + threadIdx.y;
        int N = I * block_num_y * blockDim.y + J;

        if (N < batch_size)
        {
            uint8_t *enc_payload = pac_data + pac_sign[N] + sizeof(struct ether_header) +
                                   sizeof(struct iphdr);
            uint8_t *ip_len = pac_data + pac_sign[N] + sizeof(struct ether_header) +
                              2 * sizeof(uint8_t);
            uint8_t ip_ihl = (pac_data + pac_sign[N] + sizeof(struct ether_header))[0];
            int length = (u8tu16(ip_len) - ((int)ip_ihl % 16 * 4) - SHA_DIGEST_LENGTH);
            if (length > MAX_AUTHENTICATED_PART)
            {
                printf("External error, payload length too long.");
            }
            assert(length < MAX_AUTHENTICATED_PART);
            for (int i = 0; i < length; i++)
            {
                *(dev_enc_payload + i) = *(enc_payload + i);
            }
            if (dev_enc_payload != NULL && length != 0)
            {
                HMAC_SHA1((uint32_t *)(dev_enc_payload),
                          (uint32_t *)(dev_enc_payload + length),
                          length, (const char *)hmac_key);
                for (int i = 0; i < SHA_DIGEST_LENGTH; i++)
                {
                    *(enc_payload + length + i) = *(dev_enc_payload + length + i);
                }
            }
        }
        __syncthreads();
    }
}

void ipsec_hsha1_encryption_get_cuda_kernel(
    uint8_t *pac_data, const int total_len, const int batch_size,
    const unsigned int *pac_sign, uint8_t *hmac_key)
{
    // CheckGPUinfo();

    //定义device变量
    uint8_t *dev_hmac_key;
    uint8_t *dev_pac_data;
    uint8_t *dev_enc_payload;
    unsigned int *dev_pac_sign;

    //申请device内存
    cudaMalloc((void **)&dev_pac_data, total_len * sizeof(uint8_t));
    cudaMalloc((void **)&dev_pac_sign, batch_size * sizeof(unsigned int));
    cudaMalloc((void **)&dev_enc_payload, MAX_AUTHENTICATED_PART * sizeof(uint8_t));
    cudaMalloc((void **)&dev_hmac_key, HMAC_KEY_SIZE * sizeof(uint8_t));

    //将host数据拷贝到device
    cudaMemcpy(dev_pac_data, pac_data, total_len * sizeof(uint8_t), cudaMemcpyHostToDevice);
    cudaMemcpy(dev_pac_sign, pac_sign, batch_size * sizeof(unsigned int), cudaMemcpyHostToDevice);
    cudaMemcpy(dev_hmac_key, hmac_key, HMAC_KEY_SIZE * sizeof(uint8_t), cudaMemcpyHostToDevice);

    //定义kernel的执行配置
    dim3 threads_per_block(16, 16);
    float block_x = sqrt((float)batch_size) / (float)threads_per_block.x;
    int block_num_x = (block_x == int(block_x) ? block_x : int(block_x) + 1);
    float block_y = sqrt((float)batch_size) / (float)threads_per_block.y;
    int block_num_y = (block_y == int(block_y) ? block_y : int(block_y) + 1);
    dim3 block_num(block_num_x, block_num_y);
    computeHMAC_SHA1<<<block_num, threads_per_block>>>(
        batch_size, block_num_y, dev_enc_payload,
        dev_pac_data, dev_pac_sign, dev_hmac_key);
    cudaDeviceSynchronize();

    //将device的结果拷贝到host
    cudaMemcpy(pac_data, dev_pac_data, total_len * sizeof(uint8_t), cudaMemcpyDeviceToHost);

    cudaFree(dev_pac_data);
    cudaFree(dev_pac_sign);
    cudaFree(dev_hmac_key);
}