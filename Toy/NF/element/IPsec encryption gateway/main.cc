#include "IPsecESPencap.hh"
#include "IPsecAES.hh"
#include "IPsecAuthHMACSHA1.hh"

int main()
{
    Packet pac;
    (new IPsecESPencap())->process(10087, &pac);
    (new IPsecAES())->process(10087, &pac);
    (new IPsecAuthHMACSHA1())->process(10087, &pac);
}