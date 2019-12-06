#include "auxiliary.hpp"
#include "NetStruct.hpp"

extern "C"
{
    __device__ static inline uint32_t dev_ntohl(uint32_t n)
    {
        return ((n & 0xff000000) >> 24) | ((n & 0x00ff0000) >> 8) |
               ((n & 0x0000ff00) << 8) | ((n & 0x000000ff) << 24);
    }

    /* The GPU kernel. */
    __global__ static void ipv4_route_lookup_cuda(
        uint32_t daddr,
        uint16_t *__restrict__ lookup_result,
        uint16_t *__restrict__ TBL24_d,
        uint16_t *__restrict__ TBLlong_d)
    {
        if (daddr == IGNORED_IP) //16进制全为1，不正常
        {
            *lookup_result = 0;
        }
        else //正常，开始去表中查找地址
        {
            //返回在TBL24和TBLlong中的查找结果
            daddr = dev_ntohl(daddr);
            uint16_t temp_dest = TBL24_d[daddr >> 8];
            if (temp_dest & 0x8000u)
            {
                int index2 = (((uint32_t)(temp_dest & 0x7fff)) << 8) + (daddr & 0xff);
                temp_dest = TBLlong_d[index2];
            }
            *lookup_result = temp_dest;
        }
    }
}

void ipv4_route_lookup_get_cuda_kernel(
    const uint16_t *TBL24, const uint16_t *TBLlong,
    const uint32_t ip_addr, uint16_t *look_reslut)
{
    printf("\nGPU加速中,获取设备信息：\n");
    CheckGPUinfo();

    //定义device变量
    uint16_t *dev_TBL24, *dev_TBLlong, *dev_look_reslut;

    //申请device内存
    cudaMalloc((void **)&dev_TBL24, TBL24_SIZE * sizeof(uint16_t));
    cudaMalloc((void **)&dev_TBLlong, TBLLONG_SIZE * sizeof(uint16_t));
    cudaMalloc((void **)&dev_look_reslut, sizeof(uint16_t));

    //将host数据拷贝到device
    cudaMemcpy(dev_TBL24, TBL24, TBL24_SIZE * sizeof(uint16_t), cudaMemcpyHostToDevice);
    cudaMemcpy(dev_TBLlong, TBLlong, TBLLONG_SIZE * sizeof(uint16_t), cudaMemcpyHostToDevice);
    cudaMemcpy(dev_look_reslut, look_reslut, sizeof(uint16_t), cudaMemcpyHostToDevice);

    //定义kernel的执行配置
    // dim3 blockSize(256);
    // dim3 gridSize((8 + blockSize.x - 1) / blockSize.x);
    ipv4_route_lookup_cuda<<<1, 1>>>(ip_addr, dev_look_reslut, dev_TBL24, dev_TBLlong);
    cudaDeviceSynchronize();

    //将device的结果拷贝到host
    cudaMemcpy(look_reslut, dev_look_reslut, sizeof(uint16_t), cudaMemcpyDeviceToHost);

    cudaFree(dev_TBL24);
    cudaFree(dev_TBLlong);
    cudaFree(dev_look_reslut);
}