#include "NetStruct.hpp"
#include "auxiliary.hpp"

extern "C"
{
    __device__ static inline uint32_t u8tu32(uint8_t *data)
    {
        uint32_t result = 0;
        for (int i = 0; i < 4; i++)
        {
            result += data[i] * pow(16, 6 - 2 * i);
        }
        return result;
    }

    /* The GPU kernel. */
    __global__ static void ipv4_route_lookup_cuda(
        uint16_t *__restrict__ TBL24_d,
        uint16_t *__restrict__ TBLlong_d,
        const int batch_size,
        const int block_num_y,
        uint8_t *__restrict__ pac_data,
        unsigned int *__restrict__ pac_sign,
        uint16_t *__restrict__ lookup_result)
    {
        int I = blockIdx.x * blockDim.x + threadIdx.x;
        int J = blockIdx.y * blockDim.y + threadIdx.y;
        int N = I * block_num_y * blockDim.y + J;

        if (N < batch_size)
        {
            uint8_t *packet = pac_data + pac_sign[N] + sizeof(struct ether_header) +
                              sizeof(struct ipv4_hdr) - sizeof(uint32_t);
            uint32_t dstaddr = u8tu32(packet);
            lookup_result[N] = 0xffff;
            if (dstaddr == IGNORED_IP) //16进制全为1，不正常
            {
                lookup_result[N] = 0;
            }
            else //正常，开始去表中查找地址
            {
                //返回在TBL24和TBLlong中的查找结果
                uint16_t temp_dest = TBL24_d[dstaddr >> 8];
                if (temp_dest & 0x8000u)
                {
                    int index2 = (((uint32_t)(temp_dest & 0x7fff)) << 8) + (dstaddr & 0xff);
                    temp_dest = TBLlong_d[index2];
                }
                lookup_result[N] = temp_dest;
            }
        }
        __syncthreads();
    }
}

void ipv4_route_lookup_get_cuda_kernel(
    const uint16_t *TBL24, const uint16_t *TBLlong,
    const uint8_t *pac_data, const int total_len, const int batch_size,
    const unsigned int *pac_sign, uint16_t *lookup_result)
{
    // CheckGPUinfo();

    //定义device变量
    uint16_t *dev_TBL24, *dev_TBLlong, *dev_lookup_result;
    uint8_t *dev_pac_data;
    unsigned int *dev_pac_sign;

    //申请device内存
    cudaMalloc((void **)&dev_TBL24, TBL24_SIZE * sizeof(uint16_t));
    cudaMalloc((void **)&dev_TBLlong, TBLLONG_SIZE * sizeof(uint16_t));
    cudaMalloc((void **)&dev_lookup_result, batch_size * sizeof(uint16_t));
    cudaMalloc((void **)&dev_pac_data, total_len * sizeof(uint8_t));
    cudaMalloc((void **)&dev_pac_sign, batch_size * sizeof(unsigned int));

    //将host数据拷贝到device
    cudaMemcpy(dev_TBL24, TBL24, TBL24_SIZE * sizeof(uint16_t), cudaMemcpyHostToDevice);
    cudaMemcpy(dev_TBLlong, TBLlong, TBLLONG_SIZE * sizeof(uint16_t), cudaMemcpyHostToDevice);
    cudaMemcpy(dev_lookup_result, lookup_result, batch_size * sizeof(uint16_t), cudaMemcpyHostToDevice);
    cudaMemcpy(dev_pac_data, pac_data, total_len * sizeof(uint8_t), cudaMemcpyHostToDevice);
    cudaMemcpy(dev_pac_sign, pac_sign, batch_size * sizeof(unsigned int), cudaMemcpyHostToDevice);

    //定义kernel的执行配置
    dim3 threads_per_block(16, 16);
    float block_x = sqrt((float)batch_size) / (float)threads_per_block.x;
    int block_num_x = (block_x == int(block_x) ? block_x : int(block_x) + 1);
    float block_y = sqrt((float)batch_size) / (float)threads_per_block.y;
    int block_num_y = (block_y == int(block_y) ? block_y : int(block_y) + 1);
    dim3 block_num(block_num_x, block_num_y);
    ipv4_route_lookup_cuda<<<block_num, threads_per_block>>>(
        dev_TBL24, dev_TBLlong,
        batch_size, block_num_y,
        dev_pac_data, dev_pac_sign, dev_lookup_result);
    cudaDeviceSynchronize();

    //将device的结果拷贝到host
    cudaMemcpy(lookup_result, dev_lookup_result, batch_size * sizeof(uint16_t), cudaMemcpyDeviceToHost);

    cudaFree(dev_TBL24);
    cudaFree(dev_TBLlong);
    cudaFree(dev_lookup_result);
    cudaFree(dev_pac_data);
    cudaFree(dev_pac_sign);
}