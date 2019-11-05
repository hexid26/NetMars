#pragma once
#include "Packet.hh"
#include <pcre.h>
#define PATTERN_STRING_MAXSIZE 256
#define OVECCOUNT 30 /* should be a multiple of 3 */

class PCREMatch
{
private:
    char **pattern;   //PCRE模式库
    int pattern_nums; //模式的个数
    char curr_path[256];
    bool isNF;

public:
    int load_pcrepl_from_file(const char *filename)
    {
        isNF = false;
        FILE *fp;
        int i = 0;
        char buf[PATTERN_STRING_MAXSIZE];

        for (int i = 0; i < 256; i++)
        {
            if (curr_path[i] == 'N' && curr_path[i + 1] == 'F' && curr_path[i + 2] == '\0')
            {
                isNF = true;
                strcat(curr_path, "/element/IDS");
                break;
            }
            if (curr_path[i] == '\0')
            {
                break;
            }
        }
        strcat(curr_path, "/");
        strcat(curr_path, filename);
        fp = fopen(curr_path, "r");
        if (fp == NULL)
        {
            printf("PCREMatch element: error during opening file \'%s\'.: %s\n", filename, strerror(errno));
        }
        assert(fp != NULL);

        while (fgets(buf, PATTERN_STRING_MAXSIZE, fp))
        {
            for (int j = 0; j < PATTERN_STRING_MAXSIZE; j++)
            {
                if (buf[j] == '\n')
                {
                    pattern[i][j] = '\0';
                    break;
                }
                pattern[i][j] = buf[j];
                if (buf[j] == '\0')
                {
                    break;
                }
            }
            i++;
        }
        fclose(fp);
        return 0;
    }

    int process(int input_port, Packet *pkt)
    {
        cout << "\n>>2.正在测试PCREMatch模块..." << endl;
        pattern_nums = 6; //模式的个数

        pattern = new char *[pattern_nums];
        for (int i = 0; i < pattern_nums; i++)
        {
            pattern[i] = new char[PATTERN_STRING_MAXSIZE];
        }
        //导入已有的PCRE模式库
        const char *filename = "pcre_pattern_lib.txt";
        getcwd(curr_path, 256);
        printf("element::PCREMatch: Loading the routing table entries from %s\n", filename);
        load_pcrepl_from_file(filename);

        //导入网络测试数据包
        struct ether_header *ethh = (struct ether_header *)(pkt->data());
        struct iphdr *iph = (struct iphdr *)(ethh + 1);
        int ip_len = ntohs(iph->tot_len);
        uint8_t *dataload = (uint8_t *)iph + sizeof(struct iphdr) + sizeof(struct udphdr);
        int data_len = ip_len - sizeof(struct iphdr) - sizeof(struct udphdr);
        char *src = new char[data_len];
        for (int i = 0; i < data_len; i++)
        {
            src[i] = (char)dataload[i];
            cout << src[i];
        }
        cout << endl;
        src[data_len] = '\0';

        pcre *re;
        const char *error;
        int erroffset, ovector[OVECCOUNT];

        for (int i = 0; i < pattern_nums; i++)
        {
            cout << "pattern" << i + 1 << ":" << pattern[i] << endl;
            re = pcre_compile(pattern[i], // pattern, 输入参数，将要被编译的字符串形式的正则表达式
                              0,          // options, 输入参数，用来指定编译时的一些选项
                              &error,     // errptr, 输出参数，用来输出错误信息
                              &erroffset, // erroffset, 输出参数，pattern中出错位置的偏移量
                              NULL);      // tableptr, 输入参数，用来指定字符表，一般情况用NULL
            // 返回值：被编译好的正则表达式的pcre内部表示结构
            if (re == NULL)
            { //返回错误信息
                printf("PCRE compilation failed at offset %d: %s\n", erroffset, error);
                pcre_free(re); //释放内存
                return 1;
            }
            int rc = pcre_exec(re,          // code, 输入参数，用pcre_compile编译好的正则表达结构的指针
                               NULL,        // extra, 输入参数，用来向pcre_exec传一些额外的数据信息的结构的指针
                               src,         // subject, 输入参数，要被用来匹配的字符串
                               strlen(src), // length, 输入参数， 要被用来匹配的字符串的指针
                               0,           // startoffset, 输入参数，用来指定subject从什么位置开始被匹配的偏移量
                               0,           // options, 输入参数， 用来指定匹配过程中的一些选项
                               ovector,     // ovector, 输出参数，用来返回匹配位置偏移量的数组
                               OVECCOUNT);  // ovecsize, 输入参数， 用来返回匹配位置偏移量的数组的最大大小
            // 返回值：匹配成功返回非负数，没有匹配返回负数
            if (rc < 0) //如果没有匹配
            {
                if (rc == PCRE_ERROR_NOMATCH)
                    printf("没有匹配到攻击模式...\n");
                else
                    printf("Matching error %d\n", rc);
            }
            else //如果匹配到
            {
                printf("已匹配到攻击模式...\n\n");
                for (int j = 0; j < rc; j++)
                { //分别取出捕获分组 $0整个正则公式 $1第一个()
                    char *substring_start = src + ovector[2 * j];
                    int substring_length = ovector[2 * j + 1] - ovector[2 * j];
                    printf("$%2d: %.*s\n", j, substring_length, substring_start);
                }
            }
        }
        pcre_free(re); //释放内存
        return 0;
    }
};