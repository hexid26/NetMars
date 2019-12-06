#include "auxiliary.hpp"
#include <pcre.h>

#define PATTERN_STRING_MAXSIZE 256
#define OVECCOUNT 30 /* should be a multiple of 3 */

extern "C"
{
    __device__ int dev_strlen(const char *str);

    // __global__ static void ids_pcrematch_cuda(
    //     char *__restrict__ src,
    //     char *__restrict__ dim1_pattern,
    //     int pattern_nums)
    // {
        // pcre *re;
        // const char *error;
        // int erroffset;
        // int ovector[OVECCOUNT];
        // for (int i = 0; i < pattern_nums; i++)
        // {
        //     re = pcre_compile(dim1_pattern + i * PATTERN_STRING_MAXSIZE, // pattern, 输入参数，将要被编译的字符串形式的正则表达式
        //                       0,                                         // options, 输入参数，用来指定编译时的一些选项
        //                       &error,                                    // errptr, 输出参数，用来输出错误信息
        //                       &erroffset,                                // erroffset, 输出参数，pattern中出错位置的偏移量
        //                       NULL);                                     // tableptr, 输入参数，用来指定字符表，一般情况用NULL
        //     // 返回值：被编译好的正则表达式的pcre内部表示结构
        //     if (re == NULL)
        //     { //返回错误信息
        //         printf("PCRE compilation failed at offset %d: %s\n", erroffset, error);
        //         pcre_free(re); //释放内存
        //     }
        //     int rc = pcre_exec(re,              // code, 输入参数，用pcre_compile编译好的正则表达结构的指针
        //                        NULL,            // extra, 输入参数，用来向pcre_exec传一些额外的数据信息的结构的指针
        //                        src,             // subject, 输入参数，要被用来匹配的字符串
        //                        dev_strlen(src), // length, 输入参数， 要被用来匹配的字符串的指针
        //                        0,               // startoffset, 输入参数，用来指定subject从什么位置开始被匹配的偏移量
        //                        0,               // options, 输入参数， 用来指定匹配过程中的一些选项
        //                        ovector,         // ovector, 输出参数，用来返回匹配位置偏移量的数组
        //                        OVECCOUNT);      // ovecsize, 输入参数， 用来返回匹配位置偏移量的数组的最大大小
        //     // 返回值：匹配成功返回非负数，没有匹配返回负数
        //     if (rc < 0) //如果没有匹配
        //     {
        //         if (rc == PCRE_ERROR_NOMATCH)
        //             printf("没有匹配到攻击模式...\n");
        //         else
        //             printf("Matching error %d\n", rc);
        //     }
        //     else //如果匹配到
        //     {
        //         printf("已匹配到攻击模式...\n\n");
        //         for (int j = 0; j < rc; j++)
        //         { //分别取出捕获分组 $0整个正则公式 $1第一个()
        //             char *substring_start = src + ovector[2 * j];
        //             int substring_length = ovector[2 * j + 1] - ovector[2 * j];
        //             printf("$%2d: %.*s\n", j, substring_length, substring_start);
        //         }
        //     }
        // }
        // pcre_free(re); //释放内存
    // }
}

void ids_pcrematch_get_cuda_kernel(char *src, int data_len, char **pattern, int pattern_nums)
{
    printf("\nGPU加速中\n");

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
    char *dev_src;
    char *dev_pattern;

    //分配设备空间
    cudaMalloc((void **)&dev_src, sizeof(char) * data_len);
    cudaMalloc((void **)&dev_pattern, sizeof(char) * pattern_nums * PATTERN_STRING_MAXSIZE);

    //从主机复制到设备
    cudaMemcpy(dev_src, src, sizeof(char) * data_len, cudaMemcpyHostToDevice);
    cudaMemcpy(dev_pattern, dim1_pattern, sizeof(char) * pattern_nums * PATTERN_STRING_MAXSIZE, cudaMemcpyHostToDevice);

    //定义kernel的执行配置
    // dim3 blockSize(256);
    // dim3 gridSize((8 + blockSize.x - 1) / blockSize.x);
    // ids_pcrematch_cuda<<<1, 1>>>(dev_src, dev_pattern, pattern_nums);
    cudaDeviceSynchronize();

    cudaFree(dev_src);
    cudaFree(dev_pattern);
}