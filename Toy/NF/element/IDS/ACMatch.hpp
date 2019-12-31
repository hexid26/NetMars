#pragma once
#include "Packet.hpp"
#include "auxiliary.hpp"
#include "ac.hpp"
#include <fstream>
#include <unistd.h>

#define RULE_STRING_MAXSIZE 256

extern int ids_thread_rem;

void ids_acmatch_get_cuda_kernel(
    ac_machine_t *cacm,
    const uint8_t *pac_data,
    const unsigned int *pac_sign,
    const int total_len,
    const int batch_size,
    const int rule_nums);

class ACMatch
{
private:
    static ac_machine_t cacm;
    static char **rule_argv; //AC规则库
    static int rule_nums;    //规则的个数
    char curr_path[256];
    bool isNF;

public:
    ACMatch()
    {
        rule_nums = 21; //规则的个数

        rule_argv = new char *[rule_nums];
        char *rule_data = new char[rule_nums * RULE_STRING_MAXSIZE];
        for (int i = 0; i < rule_nums; i++)
        {
            rule_argv[i] = &rule_data[i * RULE_STRING_MAXSIZE];
        }

        //导入已有的AC规则库
        const char *filename = "ac_rule_lib.txt";
        getcwd(curr_path, 256);
        printf("element::ACMatch: Loading the routing table entries from %s\n", filename);
        load_acrl_from_file(filename);

        ac_build_machine(&cacm, rule_argv, rule_nums, 0);
#ifdef _G4C_AC_TEST_
        dump_c_acm(&cacm);
#endif
    }

    int load_acrl_from_file(const char *filename)
    {
        isNF = false;
        FILE *fp;
        int I = 0;
        char buf[RULE_STRING_MAXSIZE];

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
            printf("ACMatch element: error during opening file \'%s\'.: %s\n", filename, strerror(errno));
        }
        assert(fp != NULL);

        while (fgets(buf, RULE_STRING_MAXSIZE, fp))
        {
            for (int j = 0; j < RULE_STRING_MAXSIZE; j++)
            {
                if (buf[j] == '\n')
                {
                    rule_argv[I][j] = '\0';
                    break;
                }
                rule_argv[I][j] = buf[j];
                if (buf[j] == '\0')
                {
                    break;
                }
            }
            I++;
        }
        fclose(fp);
        return 0;
    }

    void free()
    {
        ac_release_machine(&cacm);
    }

    void print_acrl()
    {
        for (int i = 0; i < rule_nums; i++)
        {
            for (int j = 0; j < RULE_STRING_MAXSIZE; j++)
            {
                std::cout << rule_argv[i][j];
            }
            std::cout << endl;
        }
    }

    static void ac_match_main(Packet **pkt, int batch_packet_num, int num_thread)
    {
        for (int num = 0; num < batch_packet_num; num++)
        {
            if (pkt[num]->is_save == true)
            {
                //导入网络测试数据包
                struct ether_header *ethh = (struct ether_header *)pkt[num]->data();
                struct iphdr *iph = (struct iphdr *)(ethh + 1);
                int ip_len = ntohs(iph->tot_len);
                uint8_t *dataload = (uint8_t *)iph + sizeof(struct iphdr) + sizeof(struct udphdr);
                int data_len = ip_len - sizeof(struct iphdr) - sizeof(struct udphdr);
                unsigned int *res = new unsigned int[rule_nums + 2];
                memset(res, 0, sizeof(unsigned int) * (rule_nums + 2));
                // int r = ac_match(packet_data, strlen(packet_data), res, 0, &cacm);
                int r = ac_match((char *)dataload, data_len, res, 0, &cacm);
                printf("num_thread: %d  packet: %d\n", num_thread, num + 1);

                if (r > 0)
                {
                    printf("ACMatch模块发现入侵字段！  ");
                    for (int i = 0; i < rule_nums; i++)
                    {
                        if (ac_res_found(res[i]))
                            printf("Matched %s at %u.\n", rule_argv[i], ac_res_location(res[i]));
                    }
                    //ACMatch匹配到ac_rule_lib中的字符串
                    continue;
                }
                printf("ACMatch模块没有检测到入侵字段！\n"); //该网络数据包是安全的
            }
        }
        printf("\n");
    }

    void process(bool IsGPU, Packet **pkt, int batch_size)
    {
        if (!IsGPU)
        {
            thread pth[AVAIL_THREAD_NUM];

            for (int i = 0; i < AVAIL_THREAD_NUM; i++)
            {
                int packet_num = batch_size / (int)AVAIL_THREAD_NUM;
                if (i < ids_thread_rem)
                    packet_num++;
                pth[i] = thread(ac_match_main,
                                pkt + i * packet_num,
                                packet_num,
                                i + 1);
                pth[i].join();
            }
        }
        else
        {
            int total_len = 0;
            for (int i = 0; i < batch_size; i++)
            {
                total_len += (int)(pkt[i]->plen);
            }
            uint8_t *pac_data = (uint8_t *)malloc(sizeof(uint8_t) * total_len);
            unsigned int *pac_sign = (unsigned int *)malloc(sizeof(unsigned int) * (batch_size - 1));
            uint8_t *p_pac_data = pac_data;
            pac_sign[0] = 0;
            for (int i = 0; i < batch_size; i++)
            {
                int pac_len = (int)(pkt[i]->plen);
                memcpy(p_pac_data, pkt[i]->data(), pac_len);
                p_pac_data += pac_len;
                pac_sign[i] = pac_sign[(i - 1 > 0 ? i - 1 : 0)] + pac_len;
            }
            ids_acmatch_get_cuda_kernel(&cacm, pac_data, pac_sign, total_len, batch_size, rule_nums);
        }
    }
};

ac_machine_t ACMatch::cacm;
char **ACMatch::rule_argv;
int ACMatch::rule_nums;
