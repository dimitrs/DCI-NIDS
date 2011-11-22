
#ifndef CONTEXTSTREAM_H
#define	CONTEXTSTREAM_H

#include "Context.h"
#include "Role_IPdecoder.h"
#include "Role_TCPdecoder.h"
#include "Role_Stream.h"
#include "Role_StreamCreator.h"

/// Use case 3: A UDP/TCP-IP 5-tuple stream
class ContextStream : public Context
{
public:
    ContextStream(Role_IPdecoder* ip, Role_TCPdecoder* tcp);
    virtual ~ContextStream();    
    
    void doit();
    
    inline Role_IPdecoder* ip() { return ip_; }
    inline Role_TCPdecoder* tcp() { return tcp_; }
    inline Role_Stream* stream() { return stream_; }  
    inline Role_StreamCreator* creator() { return creator_; }
    
private:
    Role_IPdecoder* ip_;
    Role_TCPdecoder* tcp_;       
    Role_Stream* stream_;               
    Role_StreamCreator* creator_;
};



#endif	

