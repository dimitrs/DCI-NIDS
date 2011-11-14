
#ifndef IPRULES_H
#define	IPRULES_H

#include "Role_Rules.h"
#include "ContextIP.h"

// Used by code within an object role to invoke member functions of the object role self, or this.
#define SELF \
    static_cast<const ConcreteDerived*>(this)


/// Could implement rule matching as described by Snort's fpdetect.c 
template <class ConcreteDerived> 
class Role_IPrules : public Role_Rules
{
public:
   /// See if there are any ip_proto only rules that match 
   void accept(const void* pkt)
   {
       int proto = IP->getProto();       
   }
      
private:
};


#endif	/* IPRULES_H */

