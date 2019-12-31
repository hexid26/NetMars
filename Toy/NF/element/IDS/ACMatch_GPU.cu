#include "auxiliary.hpp"
#include "NetStruct.hpp"
#include "ac.hpp"

#define RULE_STRING_MAXSIZE 256
#define dev_acm_pattern(pacm, pid) ((pacm)->dim1_patterns + (pid)*RULE_STRING_MAXSIZE)

extern "C"
{
    __device__ int dev_strlen(const char *str)
    {

        int count = 0;
        while (*str)
        {
            count++;
            str++;
        }
        return count;
    }

    __device__ static int dev_ac_match(
        uint8_t *str, int len,
        unsigned int *res, int once,
        ac_machine_t *acm)
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
        uint8_t *__restrict__ pac_data,
        unsigned int *__restrict__ pac_sign,
        int rule_nums,
        unsigned int *__restrict__ res,
        const int block_num_y,
        const int batch_size)
    {
        int I = blockIdx.x * blockDim.x + threadIdx.x;
        int J = blockIdx.y * blockDim.y + threadIdx.y;
        int N = I * block_num_y * blockDim.y + J;

        if (N < batch_size)
        {
            //定位每个包的数据部分
            uint8_t *p_pac_data = pac_data + pac_sign[N] + 
                                    sizeof(struct ether_header) + 
                                    sizeof(struct ipv4_hdr) + 
                                    sizeof(struct udphdr);
            //计算每个包的数据部分长度
            int p_pac_datalen = pac_sign[N + 1] - pac_sign[N] -
                                sizeof(struct ether_header) -
                                sizeof(struct ipv4_hdr) -
                                sizeof(struct udphdr);

            int r = dev_ac_match(p_pac_data, p_pac_datalen, res, 0, p_cacm);

            if (r > 0)
            {
                //ACMatch匹配到ac_rule_lib中的字符串
                for (int i = 0; i < rule_nums; i++)
                {
                    if (ac_res_found(res[i]))
                        printf("packet: %d  ACMatch模块发现入侵字段！ Matched %s at %u.\n", N, p_cacm->dim1_patterns + i * RULE_STRING_MAXSIZE, ac_res_location(res[i]));
                }
            }
        }
    }
}

void ids_acmatch_get_cuda_kernel(
    ac_machine_t *cacm,
    const uint8_t *pac_data,
    const unsigned int *pac_sign,
    const int total_len,
    const int batch_size,
    const int rule_nums)
{
    // CheckGPUinfo();

    //定义host变量
    unsigned int *res = (unsigned int *)malloc(sizeof(unsigned int) * (rule_nums + 2));
    memset(res, 0, sizeof(unsigned int) * (rule_nums + 2));

    //定义device变量
    ac_machine_t *dev_cacm;
    ac_state_t *dev_states;
    int *dev_transitions;
    int *dev_outputs;
    char *dev_dim1_patterns;

    uint8_t *dev_pac_data;
    unsigned int *dev_pac_sign;
    unsigned int *dev_res;

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
    cudaMalloc((void **)&dev_states, sizeof(ac_state_t) * cacm->nstates);
    cudaMalloc((void **)&dev_transitions, sizeof(int) * cacm->nstates * AC_ALPHABET_SIZE);
    cudaMalloc((void **)&dev_outputs, sizeof(int) * cacm->noutputs);
    cudaMalloc((void **)&dev_dim1_patterns, sizeof(char) * RULE_STRING_MAXSIZE * cacm->npatterns);

    cudaMalloc((void **)&dev_pac_data, sizeof(uint8_t) * total_len);
    cudaMalloc((void **)&dev_pac_sign, sizeof(unsigned int) * (batch_size - 1));
    cudaMalloc((void **)&dev_res, sizeof(unsigned int) * (rule_nums + 2));

    //3.将指针内容从主机复制到设备
    cudaMemcpy(dev_states, cacm->states, sizeof(ac_state_t) * cacm->nstates, cudaMemcpyHostToDevice);
    cudaMemcpy(dev_transitions, cacm->transitions, sizeof(int) * cacm->nstates * AC_ALPHABET_SIZE, cudaMemcpyHostToDevice);
    cudaMemcpy(dev_outputs, cacm->outputs, sizeof(int) * cacm->noutputs, cudaMemcpyHostToDevice);
    cudaMemcpy(dev_dim1_patterns, cacm->dim1_patterns, sizeof(char) * RULE_STRING_MAXSIZE * cacm->npatterns, cudaMemcpyHostToDevice);

    cudaMemcpy(dev_pac_data, pac_data, sizeof(uint8_t) * total_len, cudaMemcpyHostToDevice);
    cudaMemcpy(dev_pac_sign, pac_sign, sizeof(unsigned int) * (batch_size - 1), cudaMemcpyHostToDevice);
    cudaMemcpy(dev_res, res, sizeof(unsigned int) * (rule_nums + 2), cudaMemcpyHostToDevice);

    //4.指向主机结构中的设备指针
    cacm->states = dev_states;
    cacm->transitions = dev_transitions;
    cacm->outputs = dev_outputs;
    cacm->dim1_patterns = dev_dim1_patterns;

    //5.将结构体从主机复制到设备
    cudaMemcpy(dev_cacm, cacm, sizeof(ac_machine_t), cudaMemcpyHostToDevice);

    //定义kernel的执行配置
    dim3 threads_per_block(16, 16);
    float block_x = sqrt((float)batch_size) / (float)threads_per_block.x;
    int block_num_x = (block_x == int(block_x) ? block_x : int(block_x) + 1);
    float block_y = sqrt((float)batch_size) / (float)threads_per_block.y;
    int block_num_y = (block_y == int(block_y) ? block_y : int(block_y) + 1);
    dim3 block_num(block_num_x, block_num_y);
    ids_acmatch_cuda<<<block_num, threads_per_block>>>(
        dev_cacm,
        dev_pac_data,
        dev_pac_sign,
        rule_nums,
        dev_res,
        block_num_y,
        batch_size);
    cudaDeviceSynchronize();

    cudaFree(dev_cacm);
    cudaFree(dev_states);
    cudaFree(dev_transitions);
    cudaFree(dev_outputs);
    cudaFree(dev_dim1_patterns);

    cudaFree(dev_pac_data);
    cudaFree(dev_pac_sign);
    cudaFree(dev_res);
}