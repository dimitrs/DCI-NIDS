
#ifndef IPV4DECODER_H
#define	IPV4DECODER_H

#include "ContextTCP.h"


#define RULES \
    ((static_cast<ContextIP*> (Context::currentContext_)->rules()))


// Used by code within an object role to invoke member functions of the object role self, or this.
#define SELF \
    static_cast<const ConcreteDerived*>(this)

/// Implement a simplified version of Snort's DecodeIP function in decode.c
template <class ConcreteDerived> 
class Role_IPv4decoder : public Role_IPdecoder
{
public:
     Role_IPv4decoder() {}
     virtual ~Role_IPv4decoder() {}

    /// IPv6 Next Header / IPv4 Protocol field
    PROTO getProto() const;
    
    /// Total number of bytes including the IP header 
    u_int32_t getIPpktLength() const;
    
    u_int16_t getIPhdrLength() const;

    /// Number of bytes excluding the IP header
    u_int32_t getIPpayloadLength() const;

    /// IPv6 Identification: 0 (all zero bits)
    u_int16_t getID() const;

    /// Is this packet an IP fragment ?
    bool isFragment() const;
    bool isInitialFragment() const;
    bool isFinalFragment() const;
    u_int32_t getFragmentOffset() const;
    
    const uint8_t* getIPpayload() const;
    
    /// Source IP address
    IPaddr* const srcip();
    /// Destination IP address
    IPaddr* const dstip();
    
    /// Packet arrival time
    u_int64_t getTime() const;    

    void accept(const void* pkt);
      
private:
    static const short IP_OFFSET=0x1fff;
    static const short IP_MOREFRAG=0x2000;
    
};



template <class ConcreteDerived>
void Role_IPv4decoder<ConcreteDerived>::accept(const void* packet)
{
    const iphdr* ip = static_cast<const iphdr*>(packet);
    
    SELF->data(packet);
    
    SELF->srcip()->setAddr(ip->saddr);
    SELF->dstip()->setAddr(ip->daddr); 
        
    if (ip->protocol==6)
    {
        SELF->proto(TCP_PROTO);
    }
    else if (ip->protocol==17)
    {
        SELF->proto(UDP_PROTO);        
    }
    else {
        SELF->proto(UNKNOWN_PROTO);                
    }
    
    SELF->totallength(ntohs(ip->tot_len));
    SELF->headerLength(ip->ihl*4);
    SELF->id(ntohs(ip->id));
    SELF->frag_flag(ntohs(ip->frag_off) & 0x3fff);
    SELF->frag_offset(ntohs(ip->frag_off));
    
    // Apply IP header rules
    RULES->match();
                    
    if (Role_IPv4decoder<ConcreteDerived>::getProto() == TCP_PROTO)
    {
        ContextTCP context(SELF, packet);
        context.doit();       
    }
}

template <class ConcreteDerived>
PROTO Role_IPv4decoder<ConcreteDerived>::getProto() const
{
    return SELF->proto();
}

template <class ConcreteDerived>
u_int32_t Role_IPv4decoder<ConcreteDerived>::getIPpktLength() const
{
    return SELF->totallength();
}

template <class ConcreteDerived>
u_int16_t Role_IPv4decoder<ConcreteDerived>::getIPhdrLength() const
{
    return SELF->headerLength();
}

template <class ConcreteDerived>
u_int32_t Role_IPv4decoder<ConcreteDerived>::getIPpayloadLength() const
{
    return getIPpktLength()-getIPhdrLength();
}

template <class ConcreteDerived>
u_int16_t Role_IPv4decoder<ConcreteDerived>::getID() const
{
    return SELF->id();
}

template <class ConcreteDerived>
bool Role_IPv4decoder<ConcreteDerived>::isFragment() const
{
    return SELF->frag_flag();
}

template <class ConcreteDerived>
bool Role_IPv4decoder<ConcreteDerived>::isInitialFragment() const
{
    if (!SELF->frag_flag()) return false;
    
    if (SELF->frag_offset()) {
        return false;
    }
    else {
        return true;
    }
}

template <class ConcreteDerived>
bool Role_IPv4decoder<ConcreteDerived>::isFinalFragment() const
{
    if (!SELF->frag_flag()) return false;
    return (((SELF->frag_offset() & ~IP_OFFSET) & IP_MF) == 0);    
}

template <class ConcreteDerived>
u_int32_t Role_IPv4decoder<ConcreteDerived>::getFragmentOffset() const
{    
    return SELF->frag_offset();
}

template <class ConcreteDerived>
const uint8_t* Role_IPv4decoder<ConcreteDerived>::getIPpayload() const
{
    return SELF->data() + SELF->headerLength();    
}

template <class ConcreteDerived>
IPaddr* const Role_IPv4decoder<ConcreteDerived>::srcip() 
{
    return SELF->srcip();    
}

template <class ConcreteDerived>
IPaddr* const Role_IPv4decoder<ConcreteDerived>::dstip() 
{
    return SELF->dstip();    
}

template <class ConcreteDerived>
u_int64_t Role_IPv4decoder<ConcreteDerived>::getTime() const
{
    return SELF->time();
}



#endif	/* IPV4DECODER_H */

