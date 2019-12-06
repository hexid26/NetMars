#include "DropBroadcasts.hpp"
#include "CheckIPHeader.hpp"
#include "IPlookup.hpp"
#include "DecIPTTL.hpp"

int main()
{
    Packet pac;
    int result = (new DropBroadcasts())->process(10087, &pac);
    if (!result)
    {
        result = (new CheckIPHeader())->process(10087, &pac);
        if (result)
        {
            (new IPlookup())->process(10087, &pac);
            (new DecIPTTL())->process(10087, &pac);
        }
    }
}
