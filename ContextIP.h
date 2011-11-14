
#ifndef CONTEXTIP_H
#define	CONTEXTIP_H

#include "Context.h"

class Role_IPdecoder;
class Role_Rules;


/// Use case: IP pkt
class ContextIP : public Context
{
public:
    ContextIP(Role_IPdecoder* decode, Role_Rules* rules, const void* pkt) : 
        decode_(decode), rules_(rules), pkt_(pkt)
    {}
    
    void doit()
    {
       decode()->accept(pkt_);
    }    
        
    /// get the decoder role
    inline Role_IPdecoder* decode() { return decode_; }
    /// get the rule application role
    inline Role_Rules* rules() { return rules_; }
        
private:
    Role_IPdecoder* decode_;
    Role_Rules* rules_;      
    const void* pkt_;    
};


// Will find whatever object is currently playing the IP object role
#define IP \
    ((static_cast<ContextIP*> (Context::currentContext_)->decode()))


#endif	/* CONTEXTIP_H */

