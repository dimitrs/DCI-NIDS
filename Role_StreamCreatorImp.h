
#ifndef STREAMCREATORIMP_H
#define	STREAMCREATORIMP_H

#include "DoStream.h"

#define COPY4(x, y) \
    x[0] = y[0]; x[1] = y[1]; x[2] = y[2]; x[3] = y[3];

// Will find whatever object is currently playing the IP object role
#define IP \
    ((static_cast<ContextStream*> (Context::currentContext_)->ip()))

#define TCP \
    ((static_cast<ContextStream*> (Context::currentContext_)->tcp()))

// Used by code within an object role to invoke member functions of the object role self, or this.
#define SELF \
    static_cast<const ConcreteDerived*>(this)

/// Implement Snort's Stream5ProcessTcp function
template <class ConcreteDerived> 
class Role_StreamCreatorImp : public  Role_StreamCreator
{
public:
    DoStream* const create();

private:
    DoStream* const getLWSession(SessionKey* const key);
    int getLWSessionKey(SessionKey* const key);    
    DoStream* const newLWSession(const SessionKey& key);
       
};

template <class ConcreteDerived>
DoStream* const Role_StreamCreatorImp<ConcreteDerived>::create()
{                    
    SessionKey key;
    DoStream* const lwssn = this->getLWSession(&key);
    if (lwssn) 
    {
       // policy = (Stream5TcpPolicy *)lwssn->policy;
    }

    //Stream5ProcessTcp(p, lwssn, policy, &key);
    return lwssn;
}


template <class ConcreteDerived> 
DoStream* const Role_StreamCreatorImp<ConcreteDerived>::getLWSession(SessionKey* const key)
{
    if (!this->getLWSessionKey(key)) 
    {
        return NULL;
    }
                
    DoStream* stream = Streams::instance()->find_stream(*key);
    if (stream)
    {
        if (stream->last_data_seen() < IP->getTime())
        {
            stream->last_data_seen(IP->getTime());
        }
    }
    else
    {
        stream = this->newLWSession(*key);
        stream->session_state(STREAM5_STATE_SYN);        
    }
    return stream;
}

        
template <class ConcreteDerived> 
int Role_StreamCreatorImp<ConcreteDerived>::getLWSessionKey(SessionKey* const key)
{    
    /* Because the key is going to be used for hash lookups,
     * the lower of the values of the IP address field is
     * stored in the key->ip_l and the port for that ip is
     * stored in key->port_l.
     */

    if (!key)
        return 0;
    
    IPaddr* const src = IP->srcip();
    IPaddr* const dst = IP->dstip();
    
    uint16_t sport = TCP->getSrcPort();
    uint16_t dport = TCP->getDstPort();
       
    // These comparisons are done in this fashion for performance reasons
    if (src < dst)
    {
        COPY4(key->ip_l, src->getAddr());
        COPY4(key->ip_h, dst->getAddr());
        key->port_l = sport;
        key->port_h = dport;
                
    }
    else if (src == dst)
    {
        COPY4(key->ip_l, src->getAddr());
        COPY4(key->ip_h, dst->getAddr());
        if (sport < dport)
        {
            key->port_l = sport;
            key->port_h = dport;
        }
        else
        {
            key->port_l = dport;
            key->port_h = sport;
        }
    }
    else
    {
        COPY4(key->ip_l, dst->getAddr());
        key->port_l = dport;
        COPY4(key->ip_h, src->getAddr());
        key->port_h = sport;
    }
    
    key->protocol = IP->getProto();
    key->pad = 0;
    key->vlan_tag = 0;
    return 1;
}


template <class ConcreteDerived> 
DoStream* const Role_StreamCreatorImp<ConcreteDerived>::newLWSession(const SessionKey& key)
{
    DoStream* stream = new DoStream;
    
    // Save the session key for future use 
    stream->key(key);
    stream->protocol(key.protocol);
    stream->last_data_seen(IP->getTime());
    
    Streams::instance()->add_stream(key, stream);
    
    return stream;
}







#endif	

