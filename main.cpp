
#include <cstdlib>
#include <list>
#include <iostream>

//#define __USE_BSD	/* use bsd'ish ip header */
#define __FAVOR_BSD	/* use bsd'ish tcp header */

#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <arpa/inet.h>
#include <stdexcept>

#include "Context.h"
#include "IPaddr.h"


using namespace std;



/*

class Role1Methodless
{
public:
   virtual void method1(int arg) = 0;
   
};

class Role2Methodless
{
public:
   virtual void method1(int arg) = 0;
   
};



/// Use case 1
class ContextUseCase1 : public Context
{
public:
    ContextUseCase1(Role1Methodless* role1, Role2Methodless* role2) : 
        role1_(role1), role2_(role2)
    {
        Context::currentContext_ = this;
    }
    
    void doit()
    {
       role1()->method1(10);
    }    
    
    Role1Methodless* role1() { return role1_; }
    Role2Methodless* role2() { return role2_; }
    
    std::list<Role2Methodless*> role3() { return role3_; }    
    
private:
    Role1Methodless* role1_;
    Role2Methodless* role2_;   
    std::list<Role2Methodless*> role3_;
    
};


// Used by code within an object role to invoke member functions of the object role self, or this.
#define SELF \
    static_cast<const ConcreteDerived*>(this)

 // Will find whatever object is currently playing the object role of ROLE1
#define ROLE1 \
    ((Role1Methodless*) (static_cast<ContextUseCase1*> (Context::currentContext_)->role1()))

#define ROLE2 \
    ((Role2Methodless*) (static_cast<ContextUseCase1*> (Context::currentContext_)->role2()))

#define ROLE3 \
    ((std::list<Role2Methodless*>) (static_cast<ContextUseCase1*> (Context::currentContext_)->role3()))


template <class ConcreteDerived> 
class Role1 : public Role1Methodless
{
public:
   void method1(int arg)
   {
       std::cout << "Role1::method1\n" << std::endl;
       if (SELF->getX() < arg) {
       }
       ROLE2->method1(arg);
   }
      
private:
};


template <class ConcreteDerived> 
class Role2 : public Role2Methodless
{
public:
    void method1(int arg)
    {
        std::cout << "Role2::method1\n" << std::endl;
        if (SELF->getX() < arg) {
        }
        ROLE1->method1(arg);
        
        /// While object contexts are changing, dont keep an open 
        /// iterator on an external object. Make a local copy
        std::list<Role2Methodless*> role3 = ROLE3;
        
        std::list<Role2Methodless*>::iterator it = role3.begin();
        for (; it != role3.end(); it++) 
        {
            // Invoke another context
            // Context2 context(arg, SELF, ROLE1);
            // context.doIt();
            
        }
   }
      
private:
};


/ Object roles injected at compile time. That means that any possible injection 
  that might be needed at run time must be set up beforehand. As a consequence, 
  every class is decorated with every possible object role that it might play.
 /
class DomainObject : public Role1<DomainObject>, public Role2<DomainObject>
{
 public:
    void incX()
    {
        ++x_;
    }
        
    void decX()
    {
        --x_;
    }    
    
    int getX()
    {
        return x_;
    }
private:
    int x_;
};

class DomainObjectWithRole1 : 
    public Role1<DomainObject>
{
 public:
    void incX()
    {
        ++x_;
    }
        
    void decX()
    {
        --x_;
    }    
    
    int getX()
    {
        return x_;
    }
private:
    int x_;
};


/// Builds the context and offers an interface to trigger the context to run.
class Controller
{
public:
    Controller(DomainObject* source, DomainObject* sink) : 
        context_(source, sink)
    {
    }
        
    void start()
    {
        context_.doit();
    }
    
    
private:
    ContextUseCase1 context_;
    
};





/ The class representing the object roles is a collection of stateless, generic methods. 
  They must be able to work with a somewhat anonymously typed notion of this or self, 
  because the class with which the object role is composed determines the type of the object. 
  This trait represents the object role T, a role characterized by its methods t1 and t2. 
  Note that T presumes on the class into which it will be injected to support the method 
  void derivedClassFunction (int, int)
 /
template <class derived> 
class T
{
 public:
    virtual void derivedClassFunction(int, int) = 0;
    void t1(void) 
    {
        derivedClassFunction(1,2);
    }
    void t2(void) 
    {
    }
};




///////////////////////////////////////////////////////////////////////////////
// Methodless roles
///////////////////////////////////////////////////////////////////////////////






///////////////////////////////////////////////////////////////////////////////
// Contexts Use cases
///////////////////////////////////////////////////////////////////////////////




///////////////////////////////////////////////////////////////////////////////
// Object role traits
///////////////////////////////////////////////////////////////////////////////




#define ROLE2 \
    ((Role2Methodless*) (static_cast<ContextUseCase1*> (Context::currentContext_)->role2()))

#define ROLE3 \
    ((std::list<Role2Methodless*>) (static_cast<ContextUseCase1*> (Context::currentContext_)->role3()))





///////////////////////////////////////////////////////////////////////////////
// Domain objects
///////////////////////////////////////////////////////////////////////////////

*/


#include "DoIPv6Packet.h"
#include "DoIPv4Packet.h"
#include "ContextIP.h"

/// Builds the context and offers an interface to trigger the context to run.
class IPController
{
public:
    IPController() 
    {
    }
        
    void start()
    {
        void* packet;        
        if (((iphdr *)packet)->version == 4)
        {
            DoIPv4Packet ip;
            ContextIP context_(&ip, &ip, packet);        
            context_.doit();
        }
        else if (((iphdr *)packet)->version == 6)
        {
            DoIPv6Packet ip;
            ContextIP context_(&ip, &ip, packet);        
            context_.doit();
        }            
    }
    
    
private:

    
};


/*
 * 
 */
int main(int argc, char** argv) {
    IPController c;
    c.start();
    return 0;
}

