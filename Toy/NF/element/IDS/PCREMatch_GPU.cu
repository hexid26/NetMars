#include "auxiliary.hpp"
#include "pcre_exec.hpp"

#define PATTERN_STRING_MAXSIZE 256
#define OVECCOUNT 30 /* should be a multiple of 3 */

#define COMPILE_WORK_SIZE (2048 * LINK_SIZE)
#define NAMED_GROUP_LIST_SIZE 20

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

    //释放内存
    __device__ void dev_pcre_free(pcre *re)
    {
        //         if (re == NULL)
        //             return;
        // #ifdef SUPPORT_JIT
        //         if ((extra->flags & PCRE_EXTRA_EXECUTABLE_JIT) != 0 &&
        //             extra->executable_jit != NULL)
        //             PRIV(jit_free)
        //             (extra->executable_jit);
        // #endif
        //         PUBL(free)(re);
    }

    // __device__ int dev_pcre_exec(const pcre *argument_re,
    //                              const pcre_extra *extra_data,
    //                              PCRE_SPTR subject,
    //                              int length,
    //                              int start_offset,
    //                              int options,
    //                              int *offsets,
    //                              int offsetcount);
    // {
    //     //         if (re == NULL)
    //     //             return;
    //     // #ifdef SUPPORT_JIT
    //     //         if ((extra->flags & PCRE_EXTRA_EXECUTABLE_JIT) != 0 &&
    //     //             extra->executable_jit != NULL)
    //     //             PRIV(jit_free)
    //     //             (extra->executable_jit);
    //     // #endif
    //     //         PUBL(free)(re);
    // }

    __global__ static void ids_pcrematch_exec_cuda(
        pcre *re,
        char *__restrict__ src,
        char *__restrict__ dim1_pattern,
        int pattern_nums)
    {
        int ovector[OVECCOUNT];
        if (re == NULL)
        { //返回错误信息
            printf("PCRE compilation failed at offset \n");
            dev_pcre_free(re); //释放内存
        }
        int rc = dev_pcre_exec(re,              // code, 输入参数，用dev_pcre_compile编译好的正则表达结构的指针
                               NULL,            // extra, 输入参数，用来向dev_pcre_exec传一些额外的数据信息的结构的指针
                               src,             // subject, 输入参数，要被用来匹配的字符串
                               dev_strlen(src), // length, 输入参数， 要被用来匹配的字符串的指针
                               0,               // startoffset, 输入参数，用来指定subject从什么位置开始被匹配的偏移量
                               0,               // options, 输入参数， 用来指定匹配过程中的一些选项
                               ovector,         // ovector, 输出参数，用来返回匹配位置偏移量的数组
                               OVECCOUNT);      // ovecsize, 输入参数， 用来返回匹配位置偏移量的数组的最大大小
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

        //dev_pcre_free(re); //释放内存
    }

}

void ids_pcrematch_exec_get_cuda_kernel(pcre *re, char *src, int data_len, char **pattern, int pattern_nums)
{
    

    //定义host变量
    char *dim1_pattern = (char *)malloc(sizeof(char) * pattern_nums * PATTERN_STRING_MAXSIZE);

    //将二维数组压平
    for (int i = 0; i < pattern_nums; i++)
    {
        for (int j = 0; j < PATTERN_STRING_MAXSIZE; j++)
        {
            dim1_pattern[i * PATTERN_STRING_MAXSIZE + j] = pattern[i][j];
        }
    }

    //定义device变量
    pcre *dev_re;
    char *dev_src;
    char *dev_pattern;

    //分配设备空间
    cudaMalloc((void **)&dev_re, sizeof(pcre));
    cudaMalloc((void **)&dev_src, sizeof(char) * data_len);
    cudaMalloc((void **)&dev_pattern, sizeof(char) * pattern_nums * PATTERN_STRING_MAXSIZE);

    //从主机复制到设备
    cudaMemcpy(dev_re, re, sizeof(pcre), cudaMemcpyHostToDevice);
    cudaMemcpy(dev_src, src, sizeof(char) * data_len, cudaMemcpyHostToDevice);
    cudaMemcpy(dev_pattern, dim1_pattern, sizeof(char) * pattern_nums * PATTERN_STRING_MAXSIZE, cudaMemcpyHostToDevice);

    //定义kernel的执行配置
    // dim3 blockSize(256);
    // dim3 gridSize((8 + blockSize.x - 1) / blockSize.x);
    ids_pcrematch_exec_cuda<<<1, 1>>>(dev_re, dev_src, dev_pattern, pattern_nums);
    cudaDeviceSynchronize();

    cudaFree(dev_re);
    cudaFree(dev_src);
    cudaFree(dev_pattern);
}