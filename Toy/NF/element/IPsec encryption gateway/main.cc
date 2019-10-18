#include <iostream>
#include "IPsecESPencap.hh"
int main()
{
    Packet pac;
    (new IPsecESPencap())->process(10087, &pac);
}