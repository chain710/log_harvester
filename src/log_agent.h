#ifndef _LOG_AGENT_H_
#define _LOG_AGENT_H_

//#include "timer_engine.h"
#include <string.h>
#include "app_interface.h"
#include "harvester.h"
#include "log_macros.h"
#include "http_parser.h"

#include <tr1/functional>

class http_parser_ctx
{
public:
    enum state
    {
        parse_none,
        parse_field, 
        parse_value,
    };

    http_parser_ctx() 
    {
        clear();
    }

    void clear()
    {
        parse_state_ = parse_none;
        msg_complete_ = 0;
        field_.clear();
        value_.clear();
        wskey_.clear();
    }

    int parse_state_;
    int msg_complete_;
    std::string field_;
    std::string value_;
    std::string wskey_;
};

class log_agent_t
{
public:
    class client_t
    {
    public:

        enum client_state_t
        {
            cst_init = 0,
            cst_handshaked = 1,
            cst_closed = 2,
        };

        client_t()
        {
            clear();
        }

        client_t(const client_t& m)
        {
            state_ = m.state_;
            parser_ = m.parser_;
            pctx_ = m.pctx_;
            mctx_ = m.mctx_;
            parser_.data = &pctx_;
        }

        void clear()
        {
            http_parser_init(&parser_, HTTP_REQUEST);
            pctx_.clear();
            parser_.data = &pctx_;
            state_ = cst_init;
            memset(&mctx_, 0, sizeof(mctx_));
        }

        int state_;
        http_parser parser_;
        http_parser_ctx pctx_;
        msgpack_context_t mctx_;
    };

    log_agent_t();

    ~log_agent_t() {}
    void handle_tick();
    int handle_msgpack(msgpack_context_t ctx, const char*, size_t);
    void set_container(void* c) { container_ = c; }
    void broadcast_newlog(const std::string& fn, const std::string& logline);

    // [{"pattern":xxxx }, ...]
    int load_log_pattern(const char* path);
    void watch_log_check(time_t now);
    
    //void handle_timer(int64_t v);
    time_t last_handle_reload_;
    //timer_engine_t timers_;
    void* container_;

    LogHarvester harvester_;

    typedef std::map<int, client_t> client_map_t;
    // TODO: clients 内元素何时销毁? timeout?
    client_map_t clients_;

    // logpattern -> fd
    class logfile_info_t
    {
    public:
        std::string path_;
        int fd_;
    };

    typedef std::map<std::string, logfile_info_t> log_pattern_map_t;
    log_pattern_map_t log_patterns_;
    time_t last_watch_log_check_time_;
};

#endif
