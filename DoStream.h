
#ifndef DO_TCPSTREAM_H
#define	DO_TCPSTREAM_H


#define STREAM5_STATE_NONE                  0x0000
#define STREAM5_STATE_SYN                   0x0001
#define STREAM5_STATE_SYN_ACK               0x0002
#define STREAM5_STATE_ACK                   0x0004
#define STREAM5_STATE_ESTABLISHED           0x0008
#define STREAM5_STATE_DROP_CLIENT           0x0010
#define STREAM5_STATE_DROP_SERVER           0x0020
#define STREAM5_STATE_MIDSTREAM             0x0040
#define STREAM5_STATE_RESET                 0x0080
#define STREAM5_STATE_CLIENT_RESET          0x0100
#define STREAM5_STATE_SERVER_RESET          0x0200
#define STREAM5_STATE_TIMEDOUT              0x0400
#define STREAM5_STATE_UNREACH               0x0800
#define STREAM5_STATE_SENDER_SEEN           0x1000
#define STREAM5_STATE_RECEIVER_SEEN         0x2000
#define STREAM5_STATE_CLOSED                0x4000


#include "Role_TCPstream.h"

/// Stream Data
class DoStream : public Role_TCPstream<DoStream> 
{
 public:
    DoStream() :
        last_data_seen_(0),
        last_data_seen_(0),
        expire_time_(0),
        session_flags_(0),
        session_state_(0),
        client_port_(0),
        server_port_(0),
        ipprotocol_(0),
        application_protocol_(0),
        protocol_(0),
        direction_(0),
        ignore_direction_(0)
    {}
    
    inline void key(SessionKey p) { key_ = key; }
    inline const SessionKey& key() const { return key_; }    

    inline void last_data_seen(long p) { last_data_seen_ = p; }
    inline long last_data_seen() const { return last_data_seen_; }    

    inline void expire_time(uint64_t p) { expire_time_ = p; }
    inline uint64_t expire_time() const { return expire_time_; }    

    inline void session_flags(uint32_t p) { session_flags_ = p; }
    inline uint32_t session_flags() const { return session_flags_; }    

    inline void session_state(uint16_t p) { session_state_ = p; }
    inline uint16_t session_state() const { return session_state_; }    
    
    inline void client_port(uint16_t p) { client_port_ = p; }
    inline uint16_t client_port() const { return client_port_; }    

    inline void server_port(uint16_t p) { server_port_ = p; }
    inline uint16_t server_port() const { return server_port_; }    
    
    inline void server_port(uint16_t p) { server_port_ = p; }
    inline uint16_t server_port() const { return server_port_; }    

    inline void ipprotocol(uint16_t p) { ipprotocol_ = p; }
    inline uint16_t ipprotocol() const { return ipprotocol_; }    
    
    inline void application_protocol(uint16_t p) { application_protocol_ = p; }
    inline uint16_t application_protocol() const { return application_protocol_; }    

    inline void protocol(char p) { protocol_ = p; }
    inline char protocol() const { return protocol_; }    

    inline void direction(char p) { direction_ = p; }
    inline char direction() const { return direction_; }    

    /// flag to ignore traffic on this session 
    inline void ignore_direction(char p) { ignore_direction_ = p; }
    inline char ignore_direction() const { return ignore_direction_; }    
        
private:
    /// Organized by member size for compactness    
    
    SessionKey key_;

    in6_addr client_ip_; 
    in6_addr server_ip_;     

    // TODO
    //MemBucket  *proto_specific_data;
    //Stream5AppData *appDataList;
    //MemBucket *flowdata; /* add flowbits */
    //void *policy;

    long       last_data_seen_;
    uint64_t   expire_time_;

    // TODO
    //tSfPolicyUserContextId config;
    //tSfPolicyId policy_id;

    uint32_t   session_flags_;

    uint16_t   session_state_;

    uint16_t   client_port_;
    uint16_t   server_port_;


    int16_t    ipprotocol_;
    int16_t    application_protocol_;

    char       protocol_;
    char       direction_;
    char       ignore_direction_; // flag to ignore traffic on this session 
   
};



#endif	
