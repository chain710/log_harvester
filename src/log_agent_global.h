#ifndef _LOG_AGENT_GLOBAL_H_
#define _LOG_AGENT_GLOBAL_H_

#include <string>
#include <map>
#include <app_interface.h>

class log_agent_global_t
{
public:
    log_agent_global_t();

    int load_packtype( const char* path );

    int get_packtype( const msgpack_context_t& ctx ) const;
private:
    // dir_address -> packtype, default
    typedef std::map<std::string, int> packtype_map_t;
    packtype_map_t packtypes_;
    int default_packtype_;
};

#endif
