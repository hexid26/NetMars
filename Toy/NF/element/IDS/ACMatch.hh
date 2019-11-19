#pragma once
#include <stdlib.h>
#include <unistd.h>
#include <fstream>
#include "Packet.hh"
#include "ac.hh"
#define RULE_STRING_MAXSIZE 256

class ACMatch {
 private:
  char **argv;    // AC规则库
  int rule_nums;  //规则的个数
  char curr_path[256];
  bool isNF;

 public:
  int load_acrl_from_file(const char *filename) {
    isNF = false;
    FILE *fp;
    int i = 1;
    char buf[RULE_STRING_MAXSIZE];

    for (int i = 0; i < 256; i++) {
      if (curr_path[i] == 'N' && curr_path[i + 1] == 'F' && curr_path[i + 2] == '\0') {
        isNF = true;
        strcat(curr_path, "/element/IDS");
        break;
      }
      if (curr_path[i] == '\0') {
        break;
      }
    }
    strcat(curr_path, "/");
    strcat(curr_path, filename);
    fp = fopen(curr_path, "r");
    if (fp == NULL) {
      printf("ACMatch element: error during opening file \'%s\'.: %s\n", filename, strerror(errno));
    }
    assert(fp != NULL);

    while (fgets(buf, RULE_STRING_MAXSIZE, fp)) {
      for (int j = 0; j < RULE_STRING_MAXSIZE; j++) {
        if (buf[j] == '\n') {
          argv[i][j] = '\0';
          break;
        }
        argv[i][j] = buf[j];
        if (buf[j] == '\0') {
          break;
        }
      }
      i++;
    }
    fclose(fp);
    return 0;
  }

  int process(int input_port, Packet *pkt) {
    cout << "\n>>1.正在测试ACMatch模块..." << endl;
    rule_nums = 21;  //规则的个数

    int argc = rule_nums + 2;
    argv = new char *[argc];
    for (int i = 1; i <= rule_nums; i++) {
      argv[i] = new char[RULE_STRING_MAXSIZE];
    }

    //导入已有的AC规则库
    const char *filename = "ac_rule_lib.txt";
    getcwd(curr_path, 256);
    printf("element::ACMatch: Loading the routing table entries from %s\n", filename);
    load_acrl_from_file(filename);

    //导入网络测试数据包
    struct ether_header *ethh = (struct ether_header *)(pkt->data());
    struct iphdr *iph = (struct iphdr *)(ethh + 1);
    int ip_len = ntohs(iph->tot_len);
    uint8_t *dataload = (uint8_t *)iph + sizeof(struct iphdr) + sizeof(struct udphdr);
    int data_len = ip_len - sizeof(struct iphdr) - sizeof(struct udphdr);
    argv[argc - 1] = new char[data_len];
    for (int i = 0; i < data_len; i++) {
      argv[argc - 1][i] = (char)dataload[i];
    }
    argv[argc - 1][data_len] = '\0';

    ACMachine acm;
    // vector<ACState *>::iterator ite;
    ac_machine_t cacm;

    ac_build_goto(argv + 1, argc - 2, &acm);
    ac_build_failure(&acm);
    ac_build_transition(&acm);

    ac_build_machine(&cacm, argv + 1, argc - 2, 0);
#ifdef _G4C_AC_TEST_
    dump_c_acm(&cacm);
#endif

    // 	for (ite = acm.states.begin(); ite != acm.states.end(); ++ite)
    // 		;//dump_state(*ite, argv+1);

    unsigned int *res = new unsigned int[argc];
    memset(res, 0, sizeof(unsigned int) * argc);
    int r = ac_match(argv[argc - 1], strlen(argv[argc - 1]), res, 0, &cacm);
    printf("Matches: %d\n", r);

    if (r > 0) {
      printf("ACMatch模块发现入侵字段！\n");
      for (int i = 0; i <= argc - 2; i++) {
        if (ac_res_found(res[i])) printf("Matched %s at %u.\n", argv[i + 1], ac_res_location(res[i]));
      }
      // ACMatch匹配到ac_rule_lib中的字符串
      return 1;
    }

    ac_release_machine(&cacm);
    printf("ACMatch模块没有检测到入侵字段！\n");
    //该网络数据包是安全的
    return 0;
  }

  void print_acrl() {
    for (int i = 1; i < rule_nums + 1; i++) {
      for (int j = 0; j < RULE_STRING_MAXSIZE; j++) {
        cout << argv[i][j];
      }
      cout << endl;
    }
  }
};
