
#ifndef TCPSTREAM_H
#define	TCPSTREAM_H

#include "Role_Stream.h"
#include "ContextTCP.h"
#include "ContextIP.h"

#define COPY4(x, y) \
    x[0] = y[0]; x[1] = y[1]; x[2] = y[2]; x[3] = y[3];


// Used by code within an object role to invoke member functions of the object role self, or this.
#define SELF \
    static_cast<const ConcreteDerived*>(this)

/// Implement Snort's Stream5ProcessTcp function
template <class ConcreteDerived> 
class Role_TCPstream : public Role_Stream
{
public:
    void accept(const void* pkt);


private:
    DoStream* const getLWSession(SessionKey* const key);
    int getLWSessionKey(SessionKey* const key);
   
};

template <class ConcreteDerived>
void Role_TCPstream<ConcreteDerived>::accept(const void* const packet)
{                    
    SessionKey key;
    DoStream* const lwssn = this->getLWSession(&key);
    if (lwssn) 
    {
        policy = (Stream5TcpPolicy *)lwssn->policy;
    }

    Stream5ProcessTcp(p, lwssn, policy, &key);
}


template <class ConcreteDerived> 
DoStream* const Role_TCPstream<ConcreteDerived>::getLWSession(SessionKey* const key)
{
    if (!this->getLWSessionKey(key)) 
    {
        return NULL;
    }
                
    DoStream* const stream = Streams::instance().find_stream(key);
    if (stream)
    {
        /* This is a unique hnode, since the sfxhash finds the
         * same key before returning this node.
         */
        if (stream->last_data_seen() < p->pkth->ts.tv_sec)
        {
            stream->last_data_seen() = p->pkth->ts.tv_sec;
        }
    }
    return stream;
}

        
template <class ConcreteDerived> 
int Role_TCPstream<ConcreteDerived>::getLWSessionKey(SessionKey* const key)
{    
    /* Because the key is going to be used for hash lookups,
     * the lower of the values of the IP address field is
     * stored in the key->ip_l and the port for that ip is
     * stored in key->port_l.
     */

    if (!key)
        return 0;
    
    IPaddr* const src = IP->srcip();
    IPaddr* const dst = IP->dstip();
    
    uint16_t sport = TCP->getSrcPort();
    uint16_t dport = TCP->getDstPort();
       
    // These comparisons are done in this fashion for performance reasons
    if (src < dst)
    {
        COPY4(key->ip_l, src->getAddr());
        COPY4(key->ip_h, dst->getAddr());
        key->port_l = sport;
        key->port_h = dport;
                
    }
    else if (src == dst)
    {
        COPY4(key->ip_l, src->getAddr());
        COPY4(key->ip_h, dst->getAddr());
        if (sport < dport)
        {
            key->port_l = sport;
            key->port_h = dport;
        }
        else
        {
            key->port_l = dport;
            key->port_h = sport;
        }
    }
    else
    {
        COPY4(key->ip_l, dst->getAddr());
        key->port_l = dport;
        COPY4(key->ip_h, src->getAddr());
        key->port_h = sport;
    }
    
    key->protocol = IP->getProto();
    key->pad = 0;
    key->vlan_tag = 0;
    return 1;
}


template <class ConcreteDerived> 
DoStream* const Role_TCPstream<ConcreteDerived>::newLWSession(const SessionKey& key)
{
    DoStream* stream = new DoStream;
    
    // Save the session key for future use 
    stream->key(key);
    stream->protocol(key.protocol);
    stream->last_data_seen(p->pkth->ts.tv_sec);
    
    Streams::instance()->add_stream(key, stream);
    
    return stream;
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
        SELF->session_flags(SELF->session_flags() |= SSNFLAG_TIMEDOUT);
        SELF->session_state(SELF->session_state() |= STREAM5_STATE_TIMEDOUT);
        return true;
    }

    return false;
}



template <class ConcreteDerived> 
int Role_TCPstream<ConcreteDerived>::streamProcess(DoStream* const stream, SessionKey* const key)
{    
    if (stream == NULL)
    {
        if (TCP->isSyn() || !TCP->isAck())
        {
            // SYN only 
            stream = this->newLWSession(*key);            
            stream->session_state(STREAM5_STATE_SYN);
        }
        else
        {
            // Do nothing with this packet since we require a 3-way.
            // Wow that just sounds cool... Require a 3-way.  Hehe.
            return 0;
        }
    }
    
    if (!stream)
    {
        return -1;
    }

    // Check if the session is expired.
    // Should be done before we do something with the packet...
    // ie, Insert a packet, or handle state change SYN, FIN, RST, etc.
    if ((stream->session_state() & STREAM5_STATE_TIMEDOUT) || this->streamExpire())
    {
        stream->session_flags(stream->session_flags() |= SSNFLAG_TIMEDOUT);
        // Session is timed out 
        if (stream->session_flags() & SSNFLAG_RESET)
        {
            Streams::instance()->remove_stream(key);
            
            PRE_SESSION_CLEANUP(lwssn);
            PRE_SESSION_CLEANUP_TARGET(lwssn);

            /* If this one has been reset, delete the TCP
             * portion, and start a new. */
            TcpSessionCleanup(lwssn);

            POST_SESSION_CLEANUP("new data/reset");

            status = ProcessTcp(lwssn, p, &tdb, s5TcpPolicy);

            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "Finished Stream5 TCP cleanly!\n"
                    "---------------------------------------------------\n"););
        }
        else
        {
            PRE_SESSION_CLEANUP(lwssn);
            PRE_SESSION_CLEANUP_TARGET(lwssn);

            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "Stream5 TCP session timedout!\n"););

            /* Not reset, simply time'd out.  Clean it up */
            TcpSessionCleanup(lwssn);

            POST_SESSION_CLEANUP("new data/timedout");

            status = ProcessTcp(lwssn, p, &tdb, s5TcpPolicy);
        }
    }
    else
    {
        status = ProcessTcp(lwssn, p, &tdb, s5TcpPolicy);
        STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "Finished Stream5 TCP cleanly!\n"
                    "---------------------------------------------------\n"););
    }

    if (status != ACTION_LWSSN_DELETED)
    {
        MarkupPacketFlags(p, lwssn);
        Stream5SetExpire(p, lwssn, s5TcpPolicy->session_timeout);
    }

    PREPROC_PROFILE_END(s5TcpPerfStats);
    return 0;    
    
}

int Stream5ProcessTcp(Packet *p, Stream5LWSession *lwssn,
                      Stream5TcpPolicy *s5TcpPolicy, SessionKey *skey)
{
    TcpDataBlock tdb;
    int status;
    PROFILE_VARS;

    STREAM5_DEBUG_WRAP(
            char flagbuf[9];
            CreateTCPFlagString(p, flagbuf);
            DebugMessage((DEBUG_STREAM|DEBUG_STREAM_STATE),
                "Got TCP Packet 0x%X:%d ->  0x%X:%d %s\nseq: 0x%X   ack:0x%X  "
                "dsize: %lu\n"
                "active sessions: %lu\n",
                GET_SRC_IP(p),
                p->sp,
                GET_DST_IP(p),
                p->dp,
                flagbuf,
                ntohl(p->tcph->th_seq), ntohl(p->tcph->th_ack), p->dsize,
                sfxhash_count(tcp_lws_cache->hashTable));
            );

    PREPROC_PROFILE_START(s5TcpPerfStats);

    if (s5TcpPolicy == NULL)
    {
        /* Find an Tcp policy for this packet */
#ifdef SUP_IP6
        s5TcpPolicy = Stream5PolicyLookup(GET_DST_IP(p));
#else
        s5TcpPolicy = Stream5PolicyLookup(p->iph->ip_dst);
#endif

        if (!s5TcpPolicy)
        {
            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM, 
                                            "[Stream5] Could not find Tcp Policy context "
                                            "for IP %s\n", inet_ntoa(GET_DST_ADDR(p))););
            PREPROC_PROFILE_END(s5TcpPerfStats);
            return 0;
        }
    }

    if (isPacketFilterDiscard(p, (s5_tcp_eval_config->default_policy->flags &
                                  STREAM5_CONFIG_IGNORE_ANY)) == PORT_MONITOR_PACKET_DISCARD)
    {
        //ignore the packet
        STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM, 
                                        "[Stream5] %s:%d -> %s:%d Packet discarded due to port filtering\n",
                                        inet_ntoa(GET_SRC_ADDR(p)),p->sp,inet_ntoa(GET_DST_ADDR(p)),p->dp););

        UpdateFilteredPacketStats(&sfBase, IPPROTO_TCP);
        PREPROC_PROFILE_END(s5TcpPerfStats);
        return 0;
    }

    memset(&tdb, 0, sizeof(TcpDataBlock));
    SetupTcpDataBlock(&tdb, p);

#ifdef DEBUG_STREAM5
    PrintTcpDataBlock(&tdb);
#endif

    if (lwssn == NULL)
    {
        /* if require 3WHS, create Lightweight Session on SYN */
        if (s5TcpPolicy->flags & STREAM5_CONFIG_REQUIRE_3WHS)
        {
            if (TCP_ISFLAGSET(p->tcph, TH_SYN) &&
                !TCP_ISFLAGSET(p->tcph, TH_ACK))
            {
                /* SYN only */
                lwssn = NewLWSession(tcp_lws_cache, p, skey, (void *)s5TcpPolicy);
                lwssn->session_state = STREAM5_STATE_SYN;
                s5stats.total_tcp_sessions++;
            }
            else
            {
                /* If we're within the "startup" window, try to handle
                 * this packet as midstream pickup -- allows for
                 * connections that already existed before snort started.
                 */
                if (p->pkth->ts.tv_sec - firstPacketTime < s5TcpPolicy->hs_timeout)
                {
                    midstream_allowed = 1;
                    goto midstream_pickup_allowed;
                }
                else
                {
                    midstream_allowed = 0;
                }

                /* TODO: maybe look at drop stats before printing this
                 * warning -- or make this a configurable alert when
                 * requiring 3WAY. */
                DEBUG_WRAP(
                    DebugMessage(DEBUG_STREAM_STATE, "Stream5: Requiring 3-way "
                        "Handshake, but failed to retrieve session object "
                        "for non SYN packet.  Dropped SYN or hacker?\n"););

                /* 
                 * Do nothing with this packet since we require a 3-way.
                 * Wow that just sounds cool... Require a 3-way.  Hehe.
                 */
                return 0;
            }
        }
        else
        {
midstream_pickup_allowed:
            if (TCP_ISFLAGSET(p->tcph, (TH_SYN|TH_ACK)))
            {
                /* If we have a SYN/ACK */
                lwssn = NewLWSession(tcp_lws_cache, p, skey, (void *)s5TcpPolicy);
                s5stats.total_tcp_sessions++;
            }
            else if (p->dsize > 0)
            {
                /* If we have data -- missed the SYN/ACK
                 * somehow -- maybe just an incomplete PCAP.  */
                /* This handles data on SYN situations */
                lwssn = NewLWSession(tcp_lws_cache, p, skey, (void *)s5TcpPolicy);
                s5stats.total_tcp_sessions++;
            }
            else if ((Stream5PacketHasWscale(p) & TF_WSCALE) &&
                     TCP_ISFLAGSET(p->tcph, TH_SYN))
            {
                /* If we have a wscale option, need to save the
                 * option if its the first SYN from client. */
                lwssn = NewLWSession(tcp_lws_cache, p, skey, (void *)s5TcpPolicy);
                lwssn->session_state = STREAM5_STATE_SYN;
                s5stats.total_tcp_sessions++;
            }
            else
            {
                /* No data, no need to create session yet */
                /* This is done to handle SYN flood DoS attacks */
#ifdef DEBUG
                    if (TCP_ISFLAGSET(p->tcph, TH_SYN))
                    {
                        STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                            "Stream5: no data in packet (SYN only), no need to"
                            "create lightweight session.\n"););
                    }
                    else
                    {
                        STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                            "Stream5: no data in packet (non SYN/keep alive "
                            "ACK?), no need to create lightweight session.\n"););
                    }
#endif

                PREPROC_PROFILE_END(s5TcpPerfStats);
                return 0;
            }
        }
    }
    else
    {
        STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
            "Stream5: Retrieved existing session object.\n"););
    }

    if (!lwssn)
    {
        LogMessage("Stream5: Failed to retrieve session object.  Out of memory?\n");
        PREPROC_PROFILE_END(s5TcpPerfStats);
        return -1;
    }

    p->ssnptr = lwssn;

    /*
     * Check if the session is expired.
     * Should be done before we do something with the packet...
     * ie, Insert a packet, or handle state change SYN, FIN, RST, etc.
     */
    if ((lwssn->session_state & STREAM5_STATE_TIMEDOUT) ||
        Stream5Expire(p, lwssn))
    {
        lwssn->session_flags |= SSNFLAG_TIMEDOUT;
        /* Session is timed out */
        if (lwssn->session_flags & SSNFLAG_RESET)
        {
            PRE_SESSION_CLEANUP(lwssn);
            PRE_SESSION_CLEANUP_TARGET(lwssn);

            /* If this one has been reset, delete the TCP
             * portion, and start a new. */
            TcpSessionCleanup(lwssn);

            POST_SESSION_CLEANUP("new data/reset");

            status = ProcessTcp(lwssn, p, &tdb, s5TcpPolicy);

            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "Finished Stream5 TCP cleanly!\n"
                    "---------------------------------------------------\n"););
        }
        else
        {
            PRE_SESSION_CLEANUP(lwssn);
            PRE_SESSION_CLEANUP_TARGET(lwssn);

            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "Stream5 TCP session timedout!\n"););

            /* Not reset, simply time'd out.  Clean it up */
            TcpSessionCleanup(lwssn);

            POST_SESSION_CLEANUP("new data/timedout");

            status = ProcessTcp(lwssn, p, &tdb, s5TcpPolicy);
        }
    }
    else
    {
        status = ProcessTcp(lwssn, p, &tdb, s5TcpPolicy);
        STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "Finished Stream5 TCP cleanly!\n"
                    "---------------------------------------------------\n"););
    }

    if (status != ACTION_LWSSN_DELETED)
    {
        MarkupPacketFlags(p, lwssn);
        Stream5SetExpire(p, lwssn, s5TcpPolicy->session_timeout);
    }

    PREPROC_PROFILE_END(s5TcpPerfStats);
    return 0;
}

static uint32_t Stream5GetTcpTimestamp(Packet *p, uint32_t *ts)
{
    unsigned int i = 0;

    STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "Getting timestamp...\n"););
    while(i < p->tcp_option_count && i < TCP_OPTLENMAX)
    {
        if(p->tcp_options[i].code == TCPOPT_TIMESTAMP)
        {
            *ts = EXTRACT_32BITS(p->tcp_options[i].data);
            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                            "Found timestamp %lu\n", *ts););
            return TF_TSTAMP;
        }

        i++;
    }

    *ts = 0;

    STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "No timestamp...\n"););

    return TF_NONE;
}


#endif	

