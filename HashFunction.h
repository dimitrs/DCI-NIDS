
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


#endif	/* HASHFUNCTION_H */

