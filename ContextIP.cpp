
#include "ContextIP.h"
#include "DoIPv6Packet.h"
#include "Role_IPv6decoder.h"
#include "DoIPv4Packet.h"
#include "Role_IPv4decoder.h"

ContextIP::ContextIP(Role_IPdecoder* decode, Role_Rules* rules, const void* pkt) : 
    decode_(decode), rules_(rules), pkt_(pkt)
{
}

ContextIP::ContextIP(const void* packet) : 
    decode_(NULL), rules_(NULL), pkt_(packet)
{
    const iphdr* hdr = static_cast<const iphdr*>(packet);    
    if (hdr->version == 4)
    {
        DoIPv4Packet* obj = new DoIPv4Packet;         
        decode_ = obj; 
        rules_ = obj;
    }
    else if (hdr->version == 6)
    {
        DoIPv6Packet* obj = new DoIPv6Packet;         
        decode_ = obj; 
        rules_ = obj;
    } 
}

ContextIP::~ContextIP()
{
    if (decode_) delete decode_;
    decode_=NULL;    
}