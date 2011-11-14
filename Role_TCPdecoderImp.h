
#ifndef TCPDECODERIMP_H
#define	TCPDECODERIMP_H

#include <netinet/tcp.h>

#include "Role_TCPdecoder.h"
#include "ContextIP.h"





// Used by code within an object role to invoke member functions of the object role self, or this.
#define SELF \
    static_cast<const ConcreteDerived*>(this)

///  Decode the TCP transport layer. 
template <class ConcreteDerived> 
class Role_TCPdecoderImpl : public Role_TCPdecoder
{
public:
    void accept(const void* pkt);
              
    inline bool isSyn() const { return SELF->tcp()->th_flags | TH_SYN; }
    inline bool isFin() const { return SELF->tcp()->th_flags | TH_FIN; }
    inline bool isAck() const { return SELF->tcp()->th_flags | TH_ACK; }
    inline bool isRst() const { return SELF->tcp()->th_flags | TH_RST; }
    inline bool isUrg() const { return SELF->tcp()->th_flags | TH_URG; }    
    inline bool isPush() const { return SELF->tcp()->th_flags | TH_PUSH; }
    
    inline u_char flags() const { return SELF->tcp()->th_flags; }
    inline tcp_seq seq() const { return SELF->tcp()->th_seq; }    
    inline u_int8_t offset() const { return (SELF->tcp()->th_off & 0xf0) >> 4; }        
    
    inline const uint8_t* getL4Payload() const { return SELF->data(); }   
    
    inline u_int16_t getSrcPort() const { return ntohs(SELF->tcp()->th_sport); }
    inline u_int16_t getDstPort() const { return ntohs(SELF->tcp()->th_dport); }
    
   

private:
   
    static const short TCP_HEADER_LEN=20;
};


template <class ConcreteDerived>
void Role_TCPdecoderImpl<ConcreteDerived>::accept(const void* const packet)
{
    // lay TCP on top of the data 
    SELF->tcp((tcphdr *)(IP->getIPpayload()));

    // multiply the payload offset value by 4 
    SELF->hlen(this->offset() << 2);
    
    uint32_t hlen = SELF->hlen();

    if(hlen < Role_TCPdecoderImpl::TCP_HEADER_LEN)
    {
        // TCP Data Offset < hlen
        return;
    }

    // if options are present, decode them 
    SELF->tcp_options_len((uint16_t)(hlen - TCP_HEADER_LEN));

    if(SELF->tcp_options_len() > 0)
    {
        // TODO
        //SELF->tcp_options_data(pkt + TCP_HEADER_LEN);
        //DecodeTCPOptions((uint8_t *) (pkt + TCP_HEADER_LEN), p->tcp_options_len, p);
    }
    else
    {
        SELF->tcp_option_count(0);
    }

    // set the data pointer and size 
    SELF->data(static_cast<const uint8_t*>(packet) + hlen);

    SELF->dsize(IP->getIPpktLength() - IP->getIPhdrLength() - hlen);
    
    // Apply TCP header rules  
    RULES->accept(packet);
    
    STREAM->accept(packet);    
       
}

#endif	/* TCPDECODERIMP_H */

