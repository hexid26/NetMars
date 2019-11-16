#include "Array.hpp"
#include <stdio.h>
#include <time.h>

int main()
{
    printf("CPU单线程\n");
    printf("随机生成两个矩阵\n");
    ar[0].GeneraFromRand();
    ar[1].GeneraFromRand();
    // printf("将矩阵内容写入文件\n");
    // ar[0].PrintToFile("./ar1.txt");
    // ar[1].PrintToFile("./ar2.txt");
    // printf("读取两个矩阵\n");
    // ar[0].GeneraFromFile("./ar1.txt");
    // ar[1].GeneraFromFile("./ar2.txt");
    printf("[S]开始计时\n");
    clock_t start = clock();
    printf("矩阵相加\n");
    for (int i = 0; i < array_size; i++)
    {
        for (int j = 0; j < array_size; j++)
        {
            ar[2].data[i][j] = ar[0].data[i][j] + ar[1].data[i][j];
        }
    }
    printf("[E]结束计时\n");
    clock_t finish = clock();
    printf("串行计算用时%.2f秒\n", (double)(finish - start) / CLOCKS_PER_SEC);
    // ar[2].PrintToFile("./ar3.txt");
}
