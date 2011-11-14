
#ifndef IPV4PACKET_H
#define	IPV4PACKET_H

#include <netinet/ip.h>

#include "Role_IPv4decoder.h"
#include "Role_IPrules.h"

class DoIPv4Packet : public Role_IPv4decoder<DoIPv4Packet>, public Role_IPrules<DoIPv4Packet>
{
    
public:
    DoIPv4Packet() :
        packet_(NULL), ip_(NULL), time_(0)
    {}
        
    inline void ip(const iphdr* ip) { ip_=ip; }        
    inline const iphdr* const ip() const { return ip_; }
    inline IPaddr* const srcip() { return &srcip_; }
    inline IPaddr* const dstip() { return &dstip_; }    
    inline const uint8_t* data() const { return static_cast<const uint8_t*>(packet_); }        

    inline time(uint64_t sec);
    inline uint64_t time() const { return time_; }    
    
protected:
    /// Underlying packet.
    const void* packet_;
    
    /// Underlying IP header.    
    const iphdr* ip_;    
        
    IPaddr srcip_;
    IPaddr dstip_;
    
    /// Packet arrival time
    uint64_t time_;
            
    static const short IP_OFFSET=0x1fff;
    static const short IP_MOREFRAG=0x2000;

};


#endif	/* IPV4PACKET_H */

