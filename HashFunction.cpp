

#include "HashFunction.h"

HashFunction::HashFunction()
{
    seed_     = 3193;
    scale_    = 719;
    hardener_ = 133824503;  
}

unsigned HashFunction::sfhashfcn_hash(unsigned char* d, int n)
{
    unsigned hash = seed_;
    while(n)
    {
        hash *=  scale_;
        hash += *d++;
        n--;
    }
    return hash ^ hardener_;
}

