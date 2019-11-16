#include "Array.hpp"
#include <cuda_runtime.h>

__global__ void array_calculate(Array *_ar)
{
    for (int i = 0; i < array_size; i++)
    {
        for (int j = 0; j < array_size; j++)
        {
            _ar[2].data[i][j] = _ar[0].data[i][j] + _ar[1].data[i][j];
        }
    }
}

int main()
{
    printf("GPU\n");
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
    Array *dev_ar;
    cudaMalloc((void **)&dev_ar, 3 * sizeof(Array));
    cudaMemcpy(dev_ar, ar, 3 * sizeof(Array), cudaMemcpyHostToDevice);
    array_calculate<<<1, 256>>>(dev_ar);
    cudaDeviceSynchronize();
    cudaMemcpy(ar, dev_ar, 3 * sizeof(Array), cudaMemcpyDeviceToHost);
    printf("[E]结束计时\n");
    clock_t finish = clock();
    printf("并行计算用时%.2f秒\n", (double)(finish - start) / CLOCKS_PER_SEC);
    cudaFree(dev_ar);
    // ar[2].PrintToFile("./ar3.txt");
}
