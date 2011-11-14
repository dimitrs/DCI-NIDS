
#ifndef HASHFUNCTION_H
#define	HASHFUNCTION_H



/// Implements Snort's SFHASHFCN
class HashFunction
{
public:
    HashFunction();
    
    unsigned sfhashfcn_hash(unsigned char* d, int n);
    
private:
    int sf_nearest_prime(int n);

    unsigned seed_;
    unsigned scale_;
    unsigned hardener_;
  
};

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




#endif	/* HASHFUNCTION_H */

