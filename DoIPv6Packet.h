#ifndef IPV6PACKET_H
#define	IPV6PACKET_H

#include "common.h"
#include "Role_IPv6decoder.h"
#include "Role_IPrules.h"

class DoIPv6Packet : 
    // These are the possible roles an IP packet can take on: 
    public Role_IPv6decoder<DoIPv6Packet>, 
    public Role_IPrules<DoIPv6Packet>
{
    
public:
    DoIPv6Packet() :
        packet_(NULL), ip_(NULL), time_(0)
    {}
        
    inline void ip(const ip6_hdr* ip) { ip_=ip; }        
    inline const ip6_hdr* const ip() const { return ip_; }
    
    inline IPaddr* const srcip() { return &srcip_; }
    inline IPaddr* const dstip() { return &dstip_; }  
    
    inline void proto(PROTO p) { proto_ = p; }
    inline PROTO proto() const { return proto_; }    

    inline void headerLength(uint32_t p) { headerLength_ = p; }
    inline uint32_t headerLength() const { return headerLength_; }    

    inline void ip6_extension_count(uint8_t p) { ip6_extension_count_ = p; }
    inline uint8_t ip6_extension_count() const { return ip6_extension_count_; }    

    inline void frag_flag(bool p) { frag_flag_ = p; }
    inline bool frag_flag() const { return frag_flag_; }    

    inline void mf(bool p) { mf_ = p; }
    inline bool mf() const { return mf_; }    

    inline void frag_offset(bool p) { frag_offset_ = p; }
    inline bool frag_offset() const { return frag_offset_; }   

    inline uint32_t id(uint32_t p) { id_ = p; }
    inline uint32_t id() const { return id_; }  
    
    inline void totallength(uint32_t p) { tot_len_ = p; }
    inline uint32_t totallength() const { return tot_len_; }    
    
    inline void data(const void* d) { packet_=d; }           
    inline const uint8_t* data() const { return static_cast<const uint8_t*>(packet_); }   
    
    inline void time(uint64_t sec);
    inline uint64_t time() const { return time_; }    
    
        
protected:
    /// Underlying packet.
    const void* packet_;
    
    /// Underlying IP header.        
    const ip6_hdr* ip_;
    
    IPaddr srcip_;
    IPaddr dstip_;
    
    /// Packet arrival time
    uint64_t time_;    
        
    PROTO proto_;
    
    /// Total header length in bytes
    uint32_t headerLength_;
    /// Pkt length
    uint32_t tot_len_;    
    /// number of extensions in this packet
    uint8_t ip6_extension_count_;  
    /// flag to indicate a fragmented packet 
    bool frag_flag_;
    /// more fragments flag 
    bool mf_; 
    /// fragment offset number
    uint16_t frag_offset_;
    /// Frag ID
    uint32_t id_;
        
};


#endif	/* IPV4PACKET_H */

