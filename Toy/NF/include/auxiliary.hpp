#pragma once
#include <sys/sysinfo.h>
#include <cuda_runtime.h>
#include <stdio.h>
#include <thread>
#include <string.h>

#define AVAIL_THREAD_NUM 3

static void CheckCPUinfo()
{
    printf("CPU信息：\n");
    FILE *fp;
    char *buffer = NULL;
    char content[256] = "";
    size_t len = 0;
    fp = fopen("/proc/cpuinfo", "rb");
    while (getline(&buffer, &len, fp) != -1)
    {
        if (strstr(buffer, "vendor_id") != NULL)
        {
            buffer[strlen(buffer) - 1] = 0;
            sscanf(buffer, "%*c%[^:]%*c%[^\n]", content, content);
            sscanf(content, "%*[ ]%s%*[ ]", content);
            printf("供应商名称：%s\n", content);
        }
        if (strstr(buffer, "model name") != NULL)
        {
            buffer[strlen(buffer) - 1] = 0;
            sscanf(buffer, "%*c%[^:]%*c%[^\n]", content, content);
            for (int i = 0; i < strlen(content) - 1; i++)
            {
                content[i] = content[i + 1];
            }
            content[strlen(content) - 1] = '\0';
            printf("设备型号信息：%s\n", content);
        }
        if (strstr(buffer, "cpu MHz") != NULL)
        {
            buffer[strlen(buffer) - 1] = 0;
            sscanf(buffer, "%*c%[^:]%*c%[^\n]", content, content);
            sscanf(content, "%*[ ]%s%*[ ]", content);
            printf("实际运行主频：%s MHz\n", content);
        }
        if (strstr(buffer, "cache size") != NULL)
        {
            buffer[strlen(buffer) - 1] = 0;
            sscanf(buffer, "%*c%[^:]%*c%[^\n]", content, content);
            sscanf(content, "%*[ ]%s%*[ ]", content);
            printf("二级缓存大小：%s KB\n", content);
        }
        if (strstr(buffer, "cpu cores") != NULL)
        {
            buffer[strlen(buffer) - 1] = 0;
            sscanf(buffer, "%*c%[^:]%*c%[^\n]", content, content);
            sscanf(content, "%*[ ]%s%*[ ]", content);
            printf("物理核心数量：%s\n", content);
            break;
        }
    }
    fclose(fp);
    printf("逻辑内核数量：%d\n", int(get_nprocs()));
    printf("最大线程数量：%d\n", int(std ::thread::hardware_concurrency()));
    fp = fopen("/proc/meminfo", "rb");
    while (getline(&buffer, &len, fp) != -1)
    {
        if (strstr(buffer, "MemTotal") != NULL)
        {
            buffer[strlen(buffer) - 1] = 0;
            sscanf(buffer, "%*c%[^:]%*c%[^\n]", content, content);
            sscanf(content, "%*[ ]%s%*[ ]", content);
            printf("系统内存大小：%s KB\n", content);
            break;
        }
    }
    fclose(fp);
}

static bool CheckGPUinfo()
{
    printf("GPU信息：\n");
    int count = 0;
    int i = 0;

    cudaGetDeviceCount(&count);
    if (count == 0)
    {
        fprintf(stderr, "There is no GPU device.\n");
        return false;
    }

    cudaDeviceProp prop;
    for (i = 0; i < count; i++) //逐个列出设备属性:
    {
        if (cudaGetDeviceProperties(&prop, i) == cudaSuccess)
        {
            if (prop.major >= 1)
            {
                break;
            }
        }
    }
    if (i == count)
    {
        fprintf(stderr, "There is no GPU device supporting CUDA.\n");
        return false;
    }
    cudaDeviceProp sDevProp = prop;
    printf("Device %d \n", i);
    printf("设备名称：%s\n", sDevProp.name);
    printf("全局内存大小：%f MB\n", float(sDevProp.totalGlobalMem / 1024) / 1024);
    printf("Block中共享内存的大小：%d KB\n", int(sDevProp.sharedMemPerBlock / 1024));
    printf("Block中32位寄存器的个数：%d\n", int(sDevProp.regsPerBlock));
    printf("Warp的大小：%d\n", int(sDevProp.warpSize));
    printf("内存中允许的最大间距字节数：%d KB\n", int(sDevProp.memPitch / 1024));
    printf("常量内存的大小：%d KB\n", int(sDevProp.totalConstMem) / 1024);
    printf("Block中最大的线程数：%d\n", int(sDevProp.maxThreadsPerBlock));
    printf("Block中各维度的最大线程数：( %d, %d, %d )\n", int(sDevProp.maxThreadsDim[0]),
           int(sDevProp.maxThreadsDim[1]), int(sDevProp.maxThreadsDim[2]));
    printf("Grid中各维度的最大Block数：( %d, %d, %d )\n", int(sDevProp.maxGridSize[0]),
           int(sDevProp.maxGridSize[1]), int(sDevProp.maxGridSize[2]));
    printf("设备计算能力的主要修订版号和最小修订版号：%d.%d\n", int(sDevProp.major), int(sDevProp.minor));
    printf("时钟速率：%d MHz\n", int(sDevProp.clockRate) / 1000);
    printf("设备上流多处理器SM的个数：%d\n", int(sDevProp.multiProcessorCount));
    printf("设备纹理对齐的要求：%d Bytes\n", int(sDevProp.textureAlignment));

    cudaSetDevice(i);

    printf("\n CUDA initialized.\n");
    return true;
}