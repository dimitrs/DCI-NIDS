
#ifndef IPADDR_H
#define	IPADDR_H

#include "common.h"


/// Represents a IPv4 or IPv6 internet address.
struct IPaddr
{
    void setAddr(const u_int32_t& addr)
    {
        isIPv4_=true;
        addr_.s6_addr32[0] = addr;
        addr_.s6_addr32[1] = 0;
        addr_.s6_addr32[2] = 0;
        addr_.s6_addr32[3] = 0;   
    }

    void setAddr(const in6_addr& addr)
    {
        isIPv4_=false;
        addr_.s6_addr32[0] = addr.s6_addr32[0];
        addr_.s6_addr32[1] = addr.s6_addr32[1];
        addr_.s6_addr32[2] = addr.s6_addr32[2];
        addr_.s6_addr32[3] = addr.s6_addr32[3];
    }
    
    const u_int32_t* getAddr() const 
    {
        return &addr_.s6_addr32[0];
    }

    /// Compare two addresses for equality.
    bool operator == (const IPaddr &addr) const
    {
        if (isIPv4_)
        {
            return addr_.s6_addr32[0] == addr.addr_.s6_addr32[0];            
        }
        else
        {
            const u_int32_t *p1, *p2;
            p1 = &addr_.s6_addr32[0];
            p2 = &addr.addr_.s6_addr32[0];

            if(*p1 != *p2) return false;
            if(p1[1] != p2[1]) return false;
            if(p1[2] != p2[2]) return false;
            if(p1[3] != p2[3]) return false;

            return true;
        }
    }
    
    /// Compare two addresses for inequality.
    bool operator != (const IPaddr &addr) const
    {
        if (isIPv4_)
        {
            return addr_.s6_addr32[0] != addr.addr_.s6_addr32[0];            
        }
        else
        {
            const u_int32_t *p1, *p2;
            p1 = &addr_.s6_addr32[0];
            p2 = &addr.addr_.s6_addr32[0];

            if(*p1 != *p2) return true;
            if(p1[1] != p2[1]) return true;
            if(p1[2] != p2[2]) return true;
            if(p1[3] != p2[3]) return true;

            return false;
        }
    }

    bool operator < (const IPaddr& addr) const
    {
        if (isIPv4_)
        {
            return addr_.s6_addr32[0] < addr.addr_.s6_addr32[0];                        
        }
        else
        {
            const u_int32_t *p1, *p2;
            p1 = &addr_.s6_addr32[0];
            p2 = &addr.addr_.s6_addr32[0];

            if(*p1 < *p2) return true;
            else if(*p1 > *p2) return false;

            if(p1[1] < p2[1]) return true;
            else if(p1[1] > p2[1]) return false;

            if(p1[2] < p2[2]) return true;
            else if(p1[2] > p2[2]) return false;

            if(p1[3] < p2[3]) return true;
            else if(p1[3] > p2[3]) return false;

            return false;
        }
    }


protected:
    bool isIPv4_;

    /// The underlying representation of a IPv4/IPv6 stucture.
    in6_addr addr_;    
};


#endif	/* IPADDR_H */

