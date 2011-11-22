

#include "ContextTCP.h"
#include "DoTCPpacket.h"
#include "DoTCPrules.h"

ContextTCP::ContextTCP(Role_IPdecoder* ip, const void* pkt) : 
    ip_(ip), tcp_(NULL), rules_(NULL), pkt_(pkt)
{
    DoTCPpacket* obj = new DoTCPpacket(pkt);
    tcp_ = obj; 
    
    DoTCPrules* r = new DoTCPrules;        
    rules_ = r;        
}

ContextTCP::~ContextTCP()
{
    if (tcp_) delete tcp_;
    tcp_=NULL;    
    if (rules_) delete rules_;
    rules_=NULL;        
}

void ContextTCP::doit()
{
    tcp()->accept(pkt_);
}    
