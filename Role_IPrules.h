
#ifndef IPRULES_H
#define	IPRULES_H


// Will find whatever object is currently playing the IP object role
#define IP \
    ((static_cast<ContextIP*> (Context::currentContext_)->decode()))
    
// Used by code within an object role to invoke member functions of the object role self, or this.
#define SELF \
    static_cast<const ConcreteDerived*>(this)


/// Could implement rule matching as described by Snort's fpdetect.c 
template <class ConcreteDerived> 
class Role_IPrules : public Role_Rules
{
public:
   /// See if there are any ip_proto only rules that match 
   void match()
   {
       int proto = IP->getProto();       
       // ........
       // ........
       // ........
       // etc       
   }
      
private:
};


#endif	/* IPRULES_H */

