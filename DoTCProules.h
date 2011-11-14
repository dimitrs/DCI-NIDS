
#ifndef TCPROULES_H
#define	TCPROULES_H

#include "Role_TCPrules.h"


class DoTCPrules : public Role_TCPrules<DoTCPrules> 
{
 public:
    DoTCPrules() 
    {}
        
    inline bool applyRule(int rule)
    {
        return true;
    }
    
private:
    
};



#endif	
