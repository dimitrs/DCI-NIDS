
#ifndef CONTEXTTCP_H
#define	CONTEXTTCP_H

#include "Context.h"
#include "Role_IPdecoder.h"
#include "Role_TCPdecoder.h" 
#include "Role_Rules.h"


/// Use case 2: A TCP/IP pkt
class ContextTCP : public Context
{
public:
    ContextTCP(Role_IPdecoder* ip, const void* pkt);
    virtual ~ContextTCP();    
    
    void doit();
    
    inline Role_IPdecoder* ip() { return ip_; }
    inline Role_TCPdecoder* tcp() { return tcp_; }
    inline Role_Rules* rules() { return rules_; }    
    
private:
    Role_IPdecoder* ip_;
    Role_TCPdecoder* tcp_;       
    Role_Rules* rules_;           
    const void* pkt_;
};


#endif	/* CONTEXTTCP_H */

