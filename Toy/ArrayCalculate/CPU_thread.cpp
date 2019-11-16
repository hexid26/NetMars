#include "Array.hpp"
#include <stdio.h>
#include <time.h>
#include <thread>
#define thread_num 30

void func(int i)
{
    for (int k = i * (array_size / thread_num); k < (i + 1) * (array_size / thread_num); k++)
    {
        for (int j = 0; j < array_size; j++)
        {
            ar[2].data[k][j] = ar[0].data[k][j] + ar[1].data[k][j];
        }
    }
}

int main()
{
    printf("CPU多线程\n");
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
    printf("矩阵相加，建立了%d个线程\n", thread_num);
    for (int i = 0; i < thread_num; i++)
    {
        (new std::thread(func, i))->join();
    }
    printf("[E]结束计时\n");
    clock_t finish = clock();
    printf("并行计算用时%.2f秒\n", (double)(finish - start) / CLOCKS_PER_SEC);
    // ar[2].PrintToFile("./ar3.txt");
}
