#ifndef STREAMS_H
#define	STREAMS_H

#define GCC_VERSION (__GNUC__ * 10000 \
                               + __GNUC_MINOR__ * 100 \
                               + __GNUC_PATCHLEVEL__)

#if GCC_VERSION > 40122
    #include <tr1/unordered_map>
    #define _hash_multimap std::tr1::unordered_multimap
#else
    #include <ext/hash_map>
    #define _hash_multimap __gnu_cxx::hash_multimap
#endif


#include "HashFunction.h"
//#include "DoStream.h"
class DoStream;
class SessionKey;

class Streams 
{
  public:
            
    static Streams* instance();
    
     /// Find a Node based on the key
    DoStream* const find_stream(const SessionKey& key);
    
    bool add_stream(const SessionKey& key, DoStream* stream);    
    
    bool remove_stream(const SessionKey& key);
    
  private:
    Streams();
    ~Streams();
        
    typedef _hash_multimap<unsigned long,DoStream*> StreamsMap;       
    typedef StreamsMap::value_type value_type;
    
    StreamsMap streams_;
    
    static Streams *inst_;
    
};


#endif	/* STREAMS_H */

