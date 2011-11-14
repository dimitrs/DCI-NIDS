
#ifndef IPV6DECODER_H
#define	IPV6DECODER_H

#include "Role_IPdecoder.h"
#include "ContextTCP.h"
#include "DoTCPpacket.h"
#include "DoTCPrules.h"

#define IP6F_OFFSET_MASK    0xfff8  /* mask out offset from _offlg */
#define IP6F_MF_MASK        0x0001  /* more-fragments flag */
#define IP6F_OFFSET(fh) ((ntohs((fh)->ip6f_offlg) & IP6F_OFFSET_MASK) >> 3)
#define IP6F_MF(fh) (ntohs((fh)->ip6f_offlg) & IP6F_MF_MASK )


// Used by code within an object role to invoke member functions of the object role self, or this.
#define SELF \
    static_cast<const ConcreteDerived*>(this)

/// Implement a simplified version of Snort's DecodeIP function in decode.c
template <class ConcreteDerived> 
class Role_IPv6decoder : public Role_IPdecoder
{
public:
     Role_IPv6decoder() {}
     virtual ~Role_IPv6decoder() {}


    /// Role_IPv6decoder Next Header / IPv4 Protocol field
    PROTO getProto() const;
    
    /// Total number of bytes including the IP header 
    u_int32_t getIPpktLength() const;
    
    u_int16_t getIPhdrLength() const;

    /// Number of bytes excluding the IP header
    u_int32_t getIPpayloadLength() const;

    /// Role_IPv6decoder Identification
    u_int16_t getID() const;
    
    /* RFC 2460. 
     * The 8-bit Traffic Class field in the Role_IPv6decoder header is available for use
     * by originating nodes and/or forwarding routers to identify and
     * distinguish between different classes or priorities of Role_IPv6decoder packets.
     * At the point in time at which this specification is being written,
     * there are a number of experiments underway in the use of the IPv4
     * Type of Service and/or Precedence bits to provide various forms of
     * "differentiated service" for IP packets, other than through the use
     * of explicit flow set-up.  The Traffic Class field in the Role_IPv6decoder header
     * is intended to allow similar functionality to be supported in Role_IPv6decoder. */
    u_int8_t getClass() const {
        return SELF->ip()->ip6_vfc * 0x00FF;
    }    

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
    void decodeExtensions(uint8_t next, const uint8_t *pkt, uint32_t len);
    void decodeOptions(int type, const uint8_t *pkt, uint32_t len);
    
      
private:
    static const short IP_OFFSET=0x1fff;
    static const short IP_MOREFRAG=0x2000;
    
    static const short IP6_HDR_LEN=40;
    static const short IP6_EXTMAX=40;    
    
    
};

template <class ConcreteDerived>
void Role_IPv6decoder<ConcreteDerived>::accept(const void* const packet)
{
    SELF->ip(static_cast<const ip6_hdr *>(packet));
    
    // Verify version in IP6 Header agrees 
    if((SELF->ip()->ip6_vfc >> 4) != 6) 
    {
        throw std::runtime_error("Not Role_IPv6decoder datagram!");        
    }    

    SELF->srcip()->setAddr(SELF->ip()->ip6_src);
    SELF->dstip()->setAddr(SELF->ip()->ip6_dst); 
        
    SELF->ip6_extension_count(0);
    SELF->frag_flag(false);
    SELF->mf(false);
    SELF->headerLength(Role_IPv6decoder<ConcreteDerived>::IP6_HDR_LEN);
    SELF->frag_offset(0);
    SELF->id(0);

    decodeExtensions(
            SELF->ip()->ip6_nxt, 
            (const uint8_t*)packet + Role_IPv6decoder<ConcreteDerived>::IP6_HDR_LEN, 
            ntohs(SELF->ip()->ip6_plen));
    
    
    if (Role_IPv6decoder<ConcreteDerived>::getProto() == TCP_PROTO)
    {
        DoTCPrules rules;
        DoTCPpacket tcp(packet);
        ContextTCP context(SELF, &tcp, &rules, packet);
        context.doit();               
    }    
}

template <class ConcreteDerived>
void Role_IPv6decoder<ConcreteDerived>::decodeExtensions(uint8_t next, const uint8_t *pkt, uint32_t len)
{
    switch(next) {
        case IPPROTO_TCP:
            SELF->proto(TCP_PROTO);
            return;
        case IPPROTO_UDP:
            SELF->proto(UDP_PROTO);            
            return;
        case IPPROTO_NONE:
            SELF->proto(UNKNOWN_PROTO);
            return;
        case IPPROTO_HOPOPTS:
        case IPPROTO_DSTOPTS:
        case IPPROTO_ROUTING:
        case IPPROTO_FRAGMENT:
            decodeOptions(next, pkt, len); 
            // Anything special to do here?  just return?
            return;
        default: 
            // There may be valid headers after this unsupported one,
            // need to decode this header, set "next" and continue 
            // looping.
            break;
    };
}

template <class ConcreteDerived>
void Role_IPv6decoder<ConcreteDerived>::decodeOptions(int type, const uint8_t *pkt, uint32_t len)
{
    // Need at least two bytes, one for next header, one for len. 
    // But size is an integer multiple of 8 octets, so 8 is min.  
    if(len < sizeof(ip6_ext))
    {
        return;
    }

    uint32_t hdrlen = 0;    
    const ip6_ext* exthdr = (const ip6_ext*)pkt;
    if(SELF->ip6_extension_count() < Role_IPv6decoder<ConcreteDerived>::IP6_EXTMAX)
    {
        switch (type)
        {
            case IPPROTO_HOPOPTS:
                if (len < sizeof(ip6_hbh) + IP6OPT_JUMBO_LEN)
                {
                    return;
                }
                hdrlen = sizeof(ip6_ext) + IP6OPT_JUMBO_LEN + (exthdr->ip6e_len << 3);
                break;
            case IPPROTO_DSTOPTS:
                if (len < sizeof(ip6_dest) + IP6OPT_JUMBO_LEN)
                {
                    return;
                }
                hdrlen = sizeof(ip6_ext) + IP6OPT_JUMBO_LEN + (exthdr->ip6e_len << 3);
                break;
            case IPPROTO_ROUTING:
                if (len < sizeof(ip6_rthdr))
                {
                    return;
                }
                hdrlen = sizeof(ip6_ext) + IP6OPT_JUMBO_LEN + (exthdr->ip6e_len << 3);
                break;
            case IPPROTO_FRAGMENT:
                {
                    ip6_frag *ip6frag_hdr = (ip6_frag*)pkt;
                    if (len < sizeof(ip6_frag))
                    {
                        return;
                    }
                    // If this is an IP Fragment, set some data...
                    SELF->frag_flag(true);
                    SELF->mf(IP6F_MF(ip6frag_hdr));
                    SELF->frag_offset(IP6F_OFFSET(ip6frag_hdr));
                    SELF->id(ip6frag_hdr->ip6f_ident);
                }
                hdrlen = sizeof(ip6_ext) + IP6OPT_JUMBO_LEN + (exthdr->ip6e_len << 3);
                break;
            default:
                hdrlen = sizeof(ip6_ext) + IP6OPT_JUMBO_LEN + (exthdr->ip6e_len << 3);
                break;
        }
    }

    SELF->headerLength(SELF->headerLength() + hdrlen);

    if(hdrlen > len) 
    {
        return;
    }

    this->decodeExtensions(*pkt, pkt + hdrlen, len - hdrlen);
}

template <class ConcreteDerived>
u_int16_t Role_IPv6decoder<ConcreteDerived>::getID() const
{
    return SELF->id();
}

template <class ConcreteDerived>
PROTO Role_IPv6decoder<ConcreteDerived>::getProto() const
{
    return SELF->proto();
}

template <class ConcreteDerived>
u_int32_t Role_IPv6decoder<ConcreteDerived>::getIPpktLength() const
{
    return ntohs(SELF->ip()->ip6_plen)+SELF->headerLength();
}

template <class ConcreteDerived>
u_int16_t Role_IPv6decoder<ConcreteDerived>::getIPhdrLength() const
{
    return SELF->headerLength();
}

template <class ConcreteDerived>
u_int32_t Role_IPv6decoder<ConcreteDerived>::getIPpayloadLength() const
{
    return ntohs(SELF->ip()->ip6_plen);
}

template <class ConcreteDerived>
bool Role_IPv6decoder<ConcreteDerived>::isFragment() const
{
    return SELF->frag_flag();
}

template <class ConcreteDerived>
bool Role_IPv6decoder<ConcreteDerived>::isInitialFragment() const
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
bool Role_IPv6decoder<ConcreteDerived>::isFinalFragment() const
{
    if (!SELF->frag_flag()) return false;
    return (((SELF->frag_offset() & ~IP_OFFSET) & IP_MF) == 0);
}

template <class ConcreteDerived>
u_int32_t Role_IPv6decoder<ConcreteDerived>::getFragmentOffset() const
{
    return SELF->frag_offset();
}

template <class ConcreteDerived>
const uint8_t* Role_IPv6decoder<ConcreteDerived>::getIPpayload() const
{
    return SELF->data() + getIPhdrLength();    
}

template <class ConcreteDerived>
IPaddr* const Role_IPv6decoder<ConcreteDerived>::srcip() const
{
    return SELF->srcip();    
}

template <class ConcreteDerived>
IPaddr* const Role_IPv6decoder<ConcreteDerived>::dstip() const
{
    return SELF->dstip();    
}

template <class ConcreteDerived>
u_int64_t Role_IPv6decoder<ConcreteDerived>::getTime() const
{
    return SELF->time();
}

#endif	/* IPV4DECODER_H */

