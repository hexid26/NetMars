#include "ACMatch.hpp"
#include "PCREMatch.hpp"

int main()
{
    Packet pac;
    (new ACMatch)->process(10087, &pac);
    (new PCREMatch)->process(10087, &pac);
}
