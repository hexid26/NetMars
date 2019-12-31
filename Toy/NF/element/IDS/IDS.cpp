#include "ACMatch.hpp"
#include "PCREMatch.hpp"
#include "auxiliary.hpp"

int ids_thread_rem = 0;

int ids(int packet_num, int batch_size)
{
    ids_thread_rem = batch_size - AVAIL_THREAD_NUM * (batch_size / (int)AVAIL_THREAD_NUM);
    clock_t start = clock();
    assert(batch_size <= 1000000);
    Packet *pac[batch_size] = {NULL};

    ACMatch *acm = new ACMatch();
    PCREMatch *pcrem = new PCREMatch();

    printf("packet num : %d\n", packet_num);
    for (int i = 0, j = 0; i < packet_num; i++, j = (j + 1) % batch_size)
    {
        pac[j] = new Packet();
        if (j == batch_size - 1)
        {
            acm->process(true, pac, batch_size);
            // pcrem->process(false, pac, batch_size);

            for (int k = 0; k < batch_size; k++)
            {
                if (pac[k])
                {
                    delete pac[k];
                    pac[k] = NULL;
                }
            }
        }
    }

    // acm->free();

    clock_t finish = clock();
    printf("CPU用时%.2f秒\n", (double)(finish - start) / CLOCKS_PER_SEC);
}

int main()
{
    ids(20, 20);
}