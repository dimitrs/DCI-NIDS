
#ifndef ROLETCPSTREAM_H
#define	ROLETCPSTREAM_H


#include "Streams.h"
#include "ContextStream.h"
#include "Role_Stream.h"

#define SSNFLAG_RESET               0x00040000


// Will find whatever object is currently playing the IP object role
#define IP \
    ((static_cast<ContextStream*> (Context::currentContext_)->ip()))

// Used by code within an object role to invoke member functions of the object role self, or this.
#define SELF \
    static_cast<const ConcreteDerived*>(this)


/// Implement Snort's Stream5ProcessTcp function
template <class ConcreteDerived> 
class Role_TCPstream : public Role_Stream
{
public:
    virtual void process();

private:
    bool streamExpire();   
};


template <class ConcreteDerived> 
void Role_TCPstream<ConcreteDerived>::process()
{    
    if (!SELF)
    {
        return;
    }

    // Check if the session is expired.
    // Should be done before we do something with the packet...
    // ie, Insert a packet, or handle state change SYN, FIN, RST, etc.
    if ((SELF->session_state() & STREAM5_STATE_TIMEDOUT) || this->streamExpire())
    {
        SELF->session_flags(SELF->session_flags() | SSNFLAG_TIMEDOUT);
        // Session is timed out 
        if (SELF->session_flags() & SSNFLAG_RESET)
        {
            Streams::instance()->remove_stream(SELF->key());
            
            // TODO
            // If this one has been reset, delete the TCP portion, and start a new
            //TcpSessionCleanup(lwssn);
            //status = ProcessTcp(lwssn, p, &tdb, s5TcpPolicy);
        }
        else
        {
            // TODO
            // Not reset, simply time'd out.  Clean it up 
            //TcpSessionCleanup(lwssn);
            //status = ProcessTcp(lwssn, p, &tdb, s5TcpPolicy);
        }
    }
    else
    {
        // TODO
        // status = ProcessTcp(lwssn, p, &tdb, s5TcpPolicy);
    }

}

template <class ConcreteDerived> 
bool Role_TCPstream<ConcreteDerived>::streamExpire()
{
    if (SELF->expire_time() == 0)
    {
        // Not yet set, not expired 
        return false;
    }

    uint64_t pkttime = IP->getTime();
    if ((pkttime - SELF->expire_time()) > 0)
    {
        SELF->session_flags(SELF->session_flags() | SSNFLAG_TIMEDOUT);
        SELF->session_state(SELF->session_state() | STREAM5_STATE_TIMEDOUT);
        return true;
    }

    return false;
}



#endif	

