
#ifndef TCPDECODER_H
#define	TCPDECODER_H

#include "common.h"

class Role_TCPdecoder
{
public:
    
    virtual void accept(const void* pkt) = 0;
    
    virtual bool isSyn() const = 0;
    virtual bool isFin() const = 0;
    virtual bool isAck() const = 0;
    virtual bool isRst() const = 0;
    virtual bool isUrg() const = 0;
    virtual bool isPush() const = 0;
    virtual u_char flags() const = 0;
    virtual u_int32_t seq() const = 0;
    virtual u_int8_t offset() const = 0;
    virtual u_int16_t getSrcPort() const = 0;
    virtual u_int16_t getDstPort() const = 0;
    
    
    
   
};

#endif	/* TCPDECODER_H */

