#include "IPsecESPencap.hpp"
#include "IPsecAES.hpp"
#include "IPsecAuthHMACSHA1.hpp"

int main()
{
    Packet pac;
    int result = (new IPsecESPencap())->process(10087, &pac);
    if (!result)
    {
        (new IPsecAES())->process(10087, &pac);
        (new IPsecAuthHMACSHA1())->process(10087, &pac);
    }
}
