
#ifndef CONTEXT_H
#define	CONTEXT_H


/* There is only one Context executing at a time which makes it possible to 
 * maintain a single, “global” Context object pointer. Furthermore, 
 * the fact that the type of that context can be inferred by knowing what 
 * function is executing (since that Context is what started it off), 
 * we can safely use static casting to restore full Context type information 
 * to a generic pointer that stands in for all Context types
 */

class Context
{
    
public:
    Context();
    
    virtual ~Context();
    
    virtual void doit() = 0;
        
   
private:
    Context* parentContext_;

public:
    static Context* currentContext_;    
    
};



#endif	/* CONTEXT_H */

