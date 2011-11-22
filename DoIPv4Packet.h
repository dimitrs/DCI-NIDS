
#ifndef IPV4PACKET_H
#define	IPV4PACKET_H

#include "Role_IPv4decoder.h"
#include "Role_IPrules.h"

class DoIPv4Packet : 
    // These are the possible roles an IP packet can take on: 
    public Role_IPv4decoder<DoIPv4Packet>, 
    public Role_IPrules<DoIPv4Packet>
{
    
public:
       
    DoIPv4Packet() :
        packet_(NULL), time_(0), tot_len_(0), headerLength_(0), frag_flag_(false),
        mf_(false), frag_offset_(0), id_(0)
    {}
        
    inline IPaddr* const srcip() { return &srcip_; }
    inline IPaddr* const dstip() { return &dstip_; }  
    
    inline void proto(PROTO p) { proto_ = p; }
    inline PROTO proto() const { return proto_; }    
        
    inline void totallength(uint32_t p) { tot_len_ = p; }
    inline uint32_t totallength() const { return tot_len_; }    

    inline void headerLength(uint32_t p) { headerLength_ = p; }
    inline uint32_t headerLength() const { return headerLength_; }    

    inline void frag_flag(bool p) { frag_flag_ = p; }
    inline bool frag_flag() const { return frag_flag_; }    

    inline void mf(bool p) { mf_ = p; }
    inline bool mf() const { return mf_; }    

    inline void frag_offset(bool p) { frag_offset_ = p; }
    inline bool frag_offset() const { return frag_offset_; }   

    inline uint32_t id(uint32_t p) { id_ = p; }
    inline uint32_t id() const { return id_; }  
    
    inline void data(const void* d) { packet_=d; }       
    inline const uint8_t* data() const { return static_cast<const uint8_t*>(packet_); }   
    
    inline void time(uint64_t sec);
    inline uint64_t time() const { return time_; }    
    
        
protected:
    /// Underlying packet.
    const void* packet_;
        
    IPaddr srcip_;
    IPaddr dstip_;
    
    /// Packet arrival time
    uint64_t time_;    
        
    PROTO proto_;
    
    /// Pkt length
    uint32_t tot_len_;
    /// Total header length in bytes
    uint32_t headerLength_;
    /// flag to indicate a fragmented packet 
    bool frag_flag_;
    /// more fragments flag 
    bool mf_; 
    /// fragment offset number
    uint16_t frag_offset_;
    /// Frag/Pkt ID
    uint32_t id_;

};


#endif	/* IPV4PACKET_H */

