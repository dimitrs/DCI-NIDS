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


#include <boost/utility/singleton.hpp>

#include "DoStream.h"


struct SessionKey
{
    SessionKey() :
        port_l(0),
        port_h(0),
        vlan_tag(0),
        protocol(0),
        pad(0)
    {
        memset(ip_l, 0, sizeof(uint32_t)*4);
        memset(ip_h, 0, sizeof(uint32_t)*4);
    }
    
    uint32_t   ip_l[4]; /* Low IP */
    uint32_t   ip_h[4]; /* High IP */
    uint16_t   port_l; /* Low Port - 0 if ICMP */
    uint16_t   port_h; /* High Port - 0 if ICMP */
    uint16_t   vlan_tag;
    char        protocol;
    char        pad;
};


class Streams : private boost::singleton<Streams>
{
  public:
    
     /// Find a Node based on the key
    DoStream* const find_stream(const SessionKey& key);
    
    bool add_stream(const SessionKey& key, DoStream* stream);    
    
    bool remove_stream(const SessionKey& key);
    
  private:
    // We make friends with the singleton template to also
    // hide the constructor, this time:

    Streams(boost::restricted);
    template<class T, int DS> friend class boost::singleton;    
    
    
    typedef _hash_multimap<unsigned long,DoStream*> StreamsMap;       
    typedef StreamsMap::value_type value_type;
    
    StreamsMap streams_;
    
};

DoStream* const Streams::find_stream(const SessionKey& key)
{
    HashFunction hash();
    unsigned long hash = hash.sfhashfcn_hash(static_cast<char*>(key), sizeof(SessionKey));
        
    std::pair<StreamsMap::const_iterator, StreamsMap::const_iterator> p = streams_.equal_range(hash);
    for (StreamsMap::const_iterator i = p.first; i != p.second; i++) 
    {
        if (!memcmp((*i).second->key(), key, sizeof(SessionKey)))
        {
            return (*i).second;            
        }
    }
    return NULL;    
}

bool Streams::add_stream(const SessionKey& key, DoStream* stream)
{
    HashFunction hash();
    unsigned long hash = hash.sfhashfcn_hash(static_cast<char*>(key), sizeof(SessionKey));    
    if (streams_.insert(value_type(hash, stream)) != streams_.end()) 
    {
        return true;
    }
    return false;
}

bool Streams::remove_stream(const SessionKey& key)
{
    HashFunction hash();
    unsigned long hash = hash.sfhashfcn_hash(static_cast<char*>(key), sizeof(SessionKey));  
    
    std::pair<StreamsMap::iterator, StreamsMap::iterator> p = streams_.equal_range(hash);
    for (StreamsMap::iterator i = p.first; i != p.second; i++) 
    {
        if (!memcmp((*i).second->key(), key, sizeof(SessionKey)))
        {
            DoStream* stream = (*i).second;
            streams_.erase(i);
            delete stream;
            stream = NULL;
            return true;
        }
    }
        
    return false;
}



#endif	/* STREAMS_H */

