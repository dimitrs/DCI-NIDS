
#ifndef TCPRULES_H
#define	TCPRULES_H

#include "common.h"

enum RULE_NAMES {
    DECODE_TCP_NMAP_XMAS = 0,
    DECODE_DOS_NAPTHA,
    DECODE_SYN_TO_MULTICAST                
};

// Will find whatever object is currently playing the IP object role
#define IP \
    ((static_cast<ContextTCP*> (Context::currentContext_)->ip()))

// Will find whatever object is currently playing the TCP object roles
#define TCP \
    ((static_cast<ContextTCP*> (Context::currentContext_)->tcp()))

// Used by code within an object role to invoke member functions of the object role self, or this.
#define SELF \
    static_cast<const ConcreteDerived*>(this)


/// Could implement rule matching as described by Snort's fpdetect.c 
template <class ConcreteDerived> 
class Role_TCPrules : public Role_Rules
{
public:
   /// See if there are any rules that match 
   void match();
      
private:
};



template <class ConcreteDerived> 
void Role_TCPrules<ConcreteDerived>::match()
{
    if (SELF->hasRule(DECODE_TCP_NMAP_XMAS) || SELF->hasRule(DECODE_TCP_NMAP_XMAS))
    {
        if (TCP->isFin() || TCP->isPush() || TCP->isUrg())
        {
            if (TCP->isSyn() || TCP->isAck() || TCP->isRst())
            {
                //ErrorMessage("WARNING: XMAS Attack detected\n");
            }
            else 
            {
                //ErrorMessage("WARNING: NMAP XMAS Attack detected\n");
            }
        }
    }
       
    // check if only SYN is set
    if(TCP->flags() == TH_SYN)
    {
        if(SELF->hasRule(DECODE_DOS_NAPTHA))
        {
            if(TCP->seq() == 6060842)
            {
                if(IP->getID() == 413)
                {
                    //ErrorMessage("WARNING: DOS NAPTHA Vulnerability detected\n");
                }
            }
        }
    }

    if(TCP->isSyn())
    {
        if(SELF->hasRule(DECODE_SYN_TO_MULTICAST)) 
        {
            // Do stuff here
        }
    }
    
}

#endif	/* IPRULES_H */

