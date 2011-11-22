
#ifndef DO_TCPRULES_H
#define	DO_TCPRULES_H

#include "Role_TCPrules.h"

class DoTCPrules : public Role_TCPrules<DoTCPrules> 
{
 public:
    DoTCPrules() 
    {}
    
    bool hasRule(RULE_NAMES rule) const { return true; }
        
    
private:
};



#endif	
