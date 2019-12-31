#include "IPsecESPencap.hpp"
#include "IPsecAES.hpp"
#include "IPsecAuthHMACSHA1.hpp"

int ipsec_thread_rem = 0;

int ipsec(int packet_num, int batch_size)
{
    assert(packet_num > 0);
    assert(batch_size > 0);
    assert(batch_size <= packet_num);
    ipsec_thread_rem = batch_size - AVAIL_THREAD_NUM * (batch_size / (int)AVAIL_THREAD_NUM);
    clock_t start = clock();
    assert(batch_size <= 1000000);
    Packet *pac[batch_size] = {NULL};
    IPsecESPencap *ipsecesp = new IPsecESPencap();
    IPsecAES *ipsecaes = new IPsecAES();
    IPsecAuthHMACSHA1 *ipsecau = new IPsecAuthHMACSHA1();
    for (int i = 0, j = 0; i < packet_num; i++, j = (j + 1) % batch_size)
    {
        pac[j] = new Packet();
        if (j == batch_size - 1)
        {
            ipsecesp->process(pac, batch_size);
            ipsecaes->process(false, pac, batch_size);
            ipsecau->process(true, pac, batch_size);
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
    ipsec(1, 1);
}