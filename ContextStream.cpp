
#include "ContextStream.h"
#include "DoStream.h"
#include "Role_StreamCreatorImp.h"

ContextStream::ContextStream(Role_IPdecoder* ip, Role_TCPdecoder* tcp) : 
    ip_(ip), tcp_(tcp)
{
    creator_ = new Role_StreamCreatorImp;
}

ContextStream::~ContextStream()
{
    delete creator_;
}

void ContextStream::doit()
{
    DoStream* stream = creator()->create();
    stream_ = stream;
    stream->process();
}    
