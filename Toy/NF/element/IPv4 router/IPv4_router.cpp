#include "DropBroadcasts.hpp"
#include "CheckIPHeader.hpp"
#include "IPlookup.hpp"
#include "DecIPTTL.hpp"

int ipv4_thread_rem = 0;

int ipv4_router(int packet_num, int batch_size)
{
    assert(packet_num > 0);
    assert(batch_size > 0);
    assert(batch_size <= packet_num);
    ipv4_thread_rem = batch_size - AVAIL_THREAD_NUM * (batch_size / (int)AVAIL_THREAD_NUM);
    clock_t start = clock();
    assert(batch_size <= 1000000);
    Packet *pac[batch_size] = {NULL};
    DropBroadcasts *db = new DropBroadcasts();
    CheckIPHeader *ci = new CheckIPHeader();
    IPlookup *ipl = new IPlookup();
    DecIPTTL *di = new DecIPTTL();
    for (int i = 0, j = 0; i < packet_num; i++, j = (j + 1) % batch_size)
    {
        pac[j] = new Packet();
        if (j == batch_size - 1)
        {
            db->process(pac, batch_size);
            ci->process(pac, batch_size);
            ipl->process(false, pac, batch_size);
            di->process(pac, batch_size);
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
    clock_t finish = clock();
    printf("用时%.2f秒\n", (double)(finish - start) / CLOCKS_PER_SEC);
}

int main()
{
    ipv4_router(1, 1);
}
