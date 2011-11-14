
#ifndef CONTEXTTCP_H
#define	CONTEXTTCP_H

#include <netinet/tcp.h>

#include "Role_IPdecoder.h"
#include "Role_TCPdecoder.h"
#include "Role_Rules.h"

enum RULE_NAMES {
    DECODE_TCP_NMAP_XMAS = 0,
    DECODE_DOS_NAPTHA,
    DECODE_SYN_TO_MULTICAST
    
                
};


/// Use case 2: A TCP/IP pkt
class ContextTCP : public Context
{
public:
    ContextTCP(Role_IPdecoder* ip, Role_TCPdecoder* tcp, Role_Rules* rules, const void* pkt) : 
        ip_(ip), tcp_(tcp), rules_(rules), pkt_(pkt)
    {
    }
        
    void doit()
    {
       tcp()->accept(pkt_);
    }    
    
    inline Role_IPdecoder* ip() { return ip_; }
    inline Role_TCPdecoder* tcp() { return tcp_; }
    inline Role_Rules* rules() { return rules_; }    
    inline Role_Stream* stream() { return stream_; }        
    
private:
    Role_IPdecoder* ip_;
    Role_TCPdecoder* tcp_;       
    Role_Rules* rules_;           
    Role_Stream* stream_;               
    const void* pkt_;
};

// Will find whatever object is currently playing the IP and TCP object roles
#define TCP \
    ((static_cast<ContextTCP*> (Context::currentContext_)->tcp()))

#define RULES \
    ((static_cast<ContextTCP*> (Context::currentContext_)->rules()))

#define STREAM \
    ((static_cast<ContextTCP*> (Context::currentContext_)->stream()))

#endif	/* CONTEXTTCP_H */

