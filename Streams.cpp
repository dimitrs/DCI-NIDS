
#include "Streams.h"

Streams *Streams::inst_ = 0;

Streams::Streams()
{
}
    
Streams::~Streams()
{
}

Streams* Streams::instance()
{
  if (!inst_)
  {
      inst_ = new Streams();
  }
  return inst_;
}

DoStream* const Streams::find_stream(const SessionKey& key)
{
    HashFunction func;
    unsigned long hash = func.sfhashfcn_hash((unsigned char*)&key, sizeof(SessionKey));
        
    std::pair<StreamsMap::const_iterator, StreamsMap::const_iterator> p = streams_.equal_range(hash);
    for (StreamsMap::const_iterator i = p.first; i != p.second; i++) 
    {
        if (!memcmp((void*)(&(*i).second->key()), (void*)&key, sizeof(SessionKey)))
        {
            return (*i).second;            
        }
    }
    return NULL;    
}

bool Streams::add_stream(const SessionKey& key, DoStream* stream)
{
    HashFunction func;
    unsigned long hash = func.sfhashfcn_hash((unsigned char*)&key, sizeof(SessionKey));    
    if (streams_.insert(value_type(hash, stream)) != streams_.end()) 
    {
        return true;
    }
    return false;
}

bool Streams::remove_stream(const SessionKey& key)
{
    HashFunction func;
    unsigned long hash = func.sfhashfcn_hash((unsigned char*)&key, sizeof(SessionKey));  
    
    std::pair<StreamsMap::iterator, StreamsMap::iterator> p = streams_.equal_range(hash);
    for (StreamsMap::iterator i = p.first; i != p.second; i++) 
    {
        if (!memcmp((void*)&(*i).second->key(), (void*)&key, sizeof(SessionKey)))
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



