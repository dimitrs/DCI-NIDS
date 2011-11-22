
#ifndef IPDECODER_H
#define	IPDECODER_H


#include "IPaddr.h"

typedef enum {
        TCP_PROTO=0,
        UDP_PROTO=1,
        UNKNOWN_PROTO
} PROTO;

class Role_IPdecoder
{
 public:
    
    Role_IPdecoder() {};

    virtual ~Role_IPdecoder() {}
     
     
    /// IPv6 Next Header / IPv4 Protocol field
    virtual PROTO getProto() const = 0;
    
    /// Total number of bytes including the IP header 
    virtual u_int32_t getIPpktLength() const = 0;
    
    virtual u_int16_t getIPhdrLength() const = 0;

    /// Number of bytes excluding the IP header
    virtual u_int32_t getIPpayloadLength() const = 0;

    /// IPv6 Identification: 0 (all zero bits)
    virtual u_int16_t getID() const = 0;

    /// Is this packet an IP fragment ?
    virtual bool isFragment() const = 0;
    virtual bool isInitialFragment() const = 0;
    virtual bool isFinalFragment() const = 0;
    virtual u_int32_t getFragmentOffset() const = 0;

    /// Get a ptr to the L4 header
    virtual const uint8_t* getIPpayload() const = 0;
    
    /// Source IP address
    virtual IPaddr* const srcip() = 0;
    /// Destination IP address
    virtual IPaddr* const dstip() = 0;
    
    /// Packet arrival time
    virtual u_int64_t getTime() const = 0;        
    
    
    virtual void accept(const void* pkt) = 0;
   
};


#endif	/* IPDECODER_H */

