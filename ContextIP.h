
#ifndef CONTEXTIP_H
#define	CONTEXTIP_H


#include "Context.h"
#include "Role_IPdecoder.h"
#include "Role_Rules.h" 


/// Use case: IP pkt
class ContextIP : public Context
{
public:
    ContextIP(Role_IPdecoder* decode, Role_Rules* rules, const void* pkt);

    ContextIP(const void* pkt);
    
    virtual ~ContextIP();    
        
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


#endif	/* CONTEXTIP_H */

