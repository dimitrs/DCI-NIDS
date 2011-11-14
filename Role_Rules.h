
#ifndef RULES_H
#define	RULES_H


class Role_Rules
{
public:
    
    virtual void accept(const void* pkt) = 0;
   
};

#endif	/* RULES_H */

