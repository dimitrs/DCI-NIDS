
#ifndef TCPPACKET_H
#define	TCPPACKET_H

#include "Role_TCPdecoderImp.h"

class DoTCPpacket : public Role_TCPdecoderImpl<DoTCPpacket> 
{
 public:
    DoTCPpacket(const void*  packet) : 
        packet_(packet), tcp_(NULL)
    {}
        
    inline void tcp(tcphdr* h) { tcp_=h; }        
    inline const tcphdr* const tcp() const { return tcp_; }

    inline void hlen(uint32_t h) { hlen_=h; }        
    inline uint32_t hlen() const { return hlen_; }
    
    inline void dsize(uint16_t h) { dsize_ = h; }
    inline uint16_t dsize() const { return dsize_; }        

    inline void data(const uint8_t* d) { data_ = d; }
    inline const uint8_t* data() const { return data_; }        
        
    inline void tcp_options_len(uint16_t h) { tcp_options_len_ = h; }
    inline uint16_t tcp_options_len() const { return tcp_options_len_; }    

    inline void tcp_option_count(uint16_t h) { tcp_option_count_ = h; }
    inline uint8_t tcp_option_count() const { return tcp_option_count_; }    
    
private:
    const void* packet_;
    
    tcphdr* tcp_;
    
    /// TCP header length
    uint32_t hlen_;
    
    /// packet payload pointer 
    const uint8_t *data_;            
    
    uint16_t tcp_options_len_;
    uint8_t tcp_option_count_;    
    
    /// packet payload size 
    uint16_t dsize_;                 
};



#endif	
