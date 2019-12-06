#pragma once
#include "Packet.hpp"
#include "ac.hpp"
#include <unistd.h>
#include <fstream>

#define RULE_STRING_MAXSIZE 256
//#define USE_CUDA
#ifdef USE_CUDA
void ids_acmatch_get_cuda_kernel(
    ac_machine_t *cacm,
    char *packet_data,
    int data_len,
    int rule_nums);
#endif

class ACMatch
{
private:
    ac_machine_t cacm;
    char **rule_argv; //AC规则库
    int rule_nums;    //规则的个数
    char curr_path[256];
    bool isNF;

public:
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

    void initial_acmatch()
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

        // ACMachine acm;
        // vector<ACState *>::iterator ite;
        // ac_build_goto(rule_argv, rule_nums, &acm);
        // ac_build_failure(&acm);
        // ac_build_transition(&acm);

        ac_build_machine(&cacm, rule_argv, rule_nums, 0);
#ifdef _G4C_AC_TEST_
        dump_c_acm(&cacm);
#endif
    }

    int process(int input_port, Packet *pkt)
    {
        cout << "\n>>1.正在测试ACMatch模块..." << endl;
        initial_acmatch();

        //导入网络测试数据包
        struct ether_header *ethh = (struct ether_header *)(pkt->data());
        struct iphdr *iph = (struct iphdr *)(ethh + 1);
        int ip_len = ntohs(iph->tot_len);
        uint8_t *dataload = (uint8_t *)iph + sizeof(struct iphdr) + sizeof(struct udphdr);
        int data_len = ip_len - sizeof(struct iphdr) - sizeof(struct udphdr);
        char *packet_data = (char *)malloc(sizeof(char) * data_len);
        for (int i = 0; i < data_len; i++)
        {
            packet_data[i] = (char)dataload[i];
        }
        packet_data[data_len] = '\0';

#ifdef USE_CUDA
        ids_acmatch_get_cuda_kernel(&cacm, packet_data, data_len, rule_nums);
#else
        unsigned int *res = new unsigned int[rule_nums + 2];
        memset(res, 0, sizeof(unsigned int) * (rule_nums + 2));
        int r = ac_match(packet_data, strlen(packet_data), res, 0, &cacm);
        printf("Matches: %d\n", r);
        if (r > 0)
        {
            printf("ACMatch模块发现入侵字段！\n");
            for (int i = 0; i < rule_nums; i++)
            {
                if (ac_res_found(res[i]))
                    printf("Matched %s at %u.\n", rule_argv[i], ac_res_location(res[i]));
            }
            //ACMatch匹配到ac_rule_lib中的字符串
            return 1;
        }
        printf("ACMatch模块没有检测到入侵字段！\n");
        //该网络数据包是安全的
#endif
        ac_release_machine(&cacm);
        return 0;
    }

    void print_acrl()
    {
        for (int i = 0; i < rule_nums; i++)
        {
            for (int j = 0; j < RULE_STRING_MAXSIZE; j++)
            {
                cout << rule_argv[i][j];
            }
            cout << endl;
        }
    }
};
