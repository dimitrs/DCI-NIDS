
#include "ContextStream.h"
#include "DoStream.h"


ContextStream::ContextStream(Role_IPdecoder* ip, Role_TCPdecoder* tcp) : 
    ip_(ip), tcp_(tcp)//, creator_(tcp)
{
}

ContextStream::~ContextStream()
{
}

void ContextStream::doit()
{
    printf("1 llllll %p\n", creator());
    DoStream* stream = creator()->create();
    printf("2 llllll\n");    
    //Role_Stream* s = stream;
    stream->process();
}    
