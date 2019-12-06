#include "auxiliary.hpp"
#include "ac.hpp"

#define RULE_STRING_MAXSIZE 256
#define dev_acm_pattern(pacm, pid) ((pacm)->dim1_patterns + (pid)*RULE_STRING_MAXSIZE)

extern "C"
{
    __device__ static int dev_strlen(const char *str)
    {
        int count = 0;
        while (*str)
        {
            count++;
            str++;
        }
        return count;
    }

    __device__ static int dev_ac_match(char *str, int len, unsigned int *res, int once, ac_machine_t *acm)
    {
        int nm = 0;
        char c;
        ac_state_t *st = acm_state(acm, 0);
        for (int i = 0; i < len; i++)
        {
            c = str[i];
            if (c < 0)
                return -1;
            int nid = acm_state_transitions(acm, st->id)[(int)c];
            st = acm_state(acm, nid);
            if (st->noutput > 0)
            {
                if (res)
                {
                    for (int j = 0; j < st->noutput; j++)
                    {
                        int ot = acm_state_output(acm, st->output)[j];
                        res[ot] = 0x80000000 |
                                  (i + 1 - dev_strlen(dev_acm_pattern(acm, ot)));
                    }
                }
                if (!nm && once)
                {
                    return st->noutput;
                }
                nm += st->noutput;
            }
        }
        return nm;
    }

    /* The GPU kernel. */
    __global__ static void ids_acmatch_cuda(
        ac_machine_t *__restrict__ p_cacm,
        char *__restrict__ packet_data,
        int data_len,
        int rule_nums,
        unsigned int *__restrict__ res)
    {
        int r = dev_ac_match(packet_data, dev_strlen(packet_data), res, 0, p_cacm);
        printf("Matches: %d\n", r);
        if (r > 0)
        {
            printf("ACMatch模块发现入侵字段！\n");
            for (int i = 0; i < rule_nums; i++)
            {
                if (ac_res_found(res[i]))
                    printf("Matched %s at %u.\n", p_cacm->dim1_patterns + i * RULE_STRING_MAXSIZE, ac_res_location(res[i]));
            }
            //ACMatch匹配到ac_rule_lib中的字符串
        }
        printf("ACMatch模块没有检测到入侵字段！\n");
        //该网络数据包是安全的
    }
}

void ids_acmatch_get_cuda_kernel(
    ac_machine_t *cacm,
    char *packet_data,
    int data_len,
    int rule_nums)
{
    printf("\nGPU加速中,获取设备信息：\n");
    CheckGPUinfo();

    //定义host变量
    unsigned int *res = (unsigned int *)malloc(sizeof(unsigned int) * (rule_nums + 2));
    memset(res, 0, sizeof(unsigned int) * (rule_nums + 2));

    //定义device变量
    unsigned int *dev_res;
    ac_machine_t *dev_cacm;
    ac_state_t *dev_states;
    int *dev_transitions;
    int *dev_outputs;
    char *dev_dim1_patterns;
    char *dev_packet_data;

    //将二维数组压平
    cacm->dim1_patterns = (char *)malloc(sizeof(char) * RULE_STRING_MAXSIZE * cacm->npatterns);
    for (int i = 0; i < cacm->npatterns; i++)
    {
        for (int j = 0; j < RULE_STRING_MAXSIZE; j++)
        {
            cacm->dim1_patterns[i * RULE_STRING_MAXSIZE + j] = cacm->patterns[i][j];
        }
    }

    //1.分配设备结构体变量
    cudaMalloc((void **)&dev_cacm, sizeof(ac_machine_t));

    //2.分配设备指针
    cudaMalloc((void **)&dev_res, sizeof(unsigned int) * (rule_nums + 2));
    cudaMalloc((void **)&dev_states, sizeof(ac_state_t) * cacm->nstates);
    cudaMalloc((void **)&dev_transitions, sizeof(int) * cacm->nstates * AC_ALPHABET_SIZE);
    cudaMalloc((void **)&dev_outputs, sizeof(int) * cacm->noutputs);
    cudaMalloc((void **)&dev_dim1_patterns, sizeof(char) * RULE_STRING_MAXSIZE * cacm->npatterns);
    cudaMalloc((void **)&dev_packet_data, sizeof(char) * data_len);

    //3.将指针内容从主机复制到设备
    cudaMemcpy(dev_res, res, sizeof(unsigned int) * (rule_nums + 2), cudaMemcpyHostToDevice);
    cudaMemcpy(dev_states, cacm->states, sizeof(ac_state_t) * cacm->nstates, cudaMemcpyHostToDevice);
    cudaMemcpy(dev_transitions, cacm->transitions, sizeof(int) * cacm->nstates * AC_ALPHABET_SIZE, cudaMemcpyHostToDevice);
    cudaMemcpy(dev_outputs, cacm->outputs, sizeof(int) * cacm->noutputs, cudaMemcpyHostToDevice);
    cudaMemcpy(dev_dim1_patterns, cacm->dim1_patterns, sizeof(char) * RULE_STRING_MAXSIZE * cacm->npatterns, cudaMemcpyHostToDevice);
    cudaMemcpy(dev_packet_data, packet_data, sizeof(char) * data_len, cudaMemcpyHostToDevice);

    //4.指向主机结构中的设备指针
    cacm->states = dev_states;
    cacm->transitions = dev_transitions;
    cacm->outputs = dev_outputs;
    cacm->dim1_patterns = dev_dim1_patterns;

    //5.将结构体从主机复制到设备
    cudaMemcpy(dev_cacm, cacm, sizeof(ac_machine_t), cudaMemcpyHostToDevice);

    //定义kernel的执行配置
    // dim3 blockSize(256);
    // dim3 gridSize((8 + blockSize.x - 1) / blockSize.x);
    ids_acmatch_cuda<<<1, 1>>>(dev_cacm, dev_packet_data, data_len, rule_nums, dev_res);
    cudaDeviceSynchronize();

    cudaFree(dev_cacm);
    cudaFree(dev_states);
    cudaFree(dev_transitions);
    cudaFree(dev_outputs);
    cudaFree(dev_dim1_patterns);
    cudaFree(dev_packet_data);
}