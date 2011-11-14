
#ifndef IPV4DECODER_H
#define	IPV4DECODER_H

#include "Role_IPdecoder.h"
#include "ContextTCP.h"
#include "DoTCPpacket.h"
#include "DoTCPrules.h"


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
    
    void accept(const void* const pkt);
      
private:
    static const short IP_OFFSET=0x1fff;
    static const short IP_MOREFRAG=0x2000;
    
};

template <class ConcreteDerived>
void Role_IPv4decoder<ConcreteDerived>::accept(const void* const packet)
{
    SELF->ip(static_cast<const iphdr *>(packet));
    SELF->srcip()->setAddr(SELF->ip()->saddr);
    SELF->dstip()->setAddr(SELF->ip()->daddr); 
        
    if (Role_IPv4decoder<ConcreteDerived>::getProto() == TCP_PROTO)
    {
        DoTCPrules rules;
        DoTCPpacket tcp(packet);
        ContextTCP context(SELF, &tcp, &rules, packet);
        context.doit();       
    }
}

template <class ConcreteDerived>
PROTO Role_IPv4decoder<ConcreteDerived>::getProto() const
{
    if (SELF->ip()->protocol==6)
    {
         return TCP_PROTO;
    }
    else if (SELF->ip()->protocol==17)
    {
         return UDP_PROTO;
    }
    return UNKNOWN_PROTO;
}

template <class ConcreteDerived>
u_int32_t Role_IPv4decoder<ConcreteDerived>::getIPpktLength() const
{
    return ntohs(SELF->ip()->tot_len);
}

template <class ConcreteDerived>
u_int16_t Role_IPv4decoder<ConcreteDerived>::getIPhdrLength() const
{
    return SELF->ip()->ihl*4;
}

template <class ConcreteDerived>
u_int32_t Role_IPv4decoder<ConcreteDerived>::getIPpayloadLength() const
{
    return getIPpktLength()-getIPhdrLength();
}

template <class ConcreteDerived>
u_int16_t Role_IPv4decoder<ConcreteDerived>::getID() const
{
    return ntohs(SELF->ip()->id);
}

template <class ConcreteDerived>
bool Role_IPv4decoder<ConcreteDerived>::isFragment() const
{
    return ntohs(SELF->ip()->frag_off) & 0x3fff;
}

template <class ConcreteDerived>
bool Role_IPv4decoder<ConcreteDerived>::isInitialFragment() const
{
    // 32 is 0x00 in nework byte format
    if (SELF->ip()->frag_off==32)
    {
        return true;
    }
    return false;
}

template <class ConcreteDerived>
bool Role_IPv4decoder<ConcreteDerived>::isFinalFragment() const
{
    uint16_t offset = ntohs(SELF->ip()->frag_off);
    return (((offset & ~Role_IPv4decoder::IP_OFFSET) & IP_MF) == 0);
}

template <class ConcreteDerived>
u_int32_t Role_IPv4decoder<ConcreteDerived>::getFragmentOffset() const
{    
    int offset = ntohs(SELF->ip()->frag_off);
    offset &= Role_IPv4decoder::IP_OFFSET;
    offset <<= 3;  // offset is in 8-byte chunks
    return offset;
}

template <class ConcreteDerived>
const uint8_t* Role_IPv4decoder<ConcreteDerived>::getIPpayload() const
{
    return SELF->data() + getIPhdrLength();    
}

template <class ConcreteDerived>
IPaddr* const Role_IPv4decoder<ConcreteDerived>::srcip() const
{
    return SELF->srcip();    
}

template <class ConcreteDerived>
IPaddr* const Role_IPv4decoder<ConcreteDerived>::dstip() const
{
    return SELF->dstip();    
}

template <class ConcreteDerived>
u_int64_t Role_IPv4decoder<ConcreteDerived>::getTime() const
{
    return SELF->time();
}



#endif	/* IPV4DECODER_H */

