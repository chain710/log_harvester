#include "log_agent_global.h"
#include "log_macros.h"
#include <stdio.h>
#include <utility.h>
#include <netlink.h>
#include <json/json.h>

using namespace std;

log_agent_global_t::log_agent_global_t()
{
    default_packtype_ = -1;
}

int log_agent_global_t::load_packtype( const char* path )
{
    string json_raw;
    if (read_all_text(path, json_raw))
    {
        L_ERROR("read %s failed", path);
        return -1;
    }

    Json::Value conf_root;
    Json::Reader reader;
    bool succ = reader.parse(json_raw, conf_root);
    if (!succ)
    {
        L_ERROR("parse config(%s) failed, %s", path, reader.getFormattedErrorMessages().c_str());
        return -1;
    }

    if (!conf_root.isArray())
    {
        L_ERROR("json root is not array!%s", "");
        return -1;
    }

    packtypes_.clear();
    default_packtype_ = -1;
    char tmpkey[128];
    for (int i = 0; i < (int)conf_root.size(); ++i)
    {
        const string& addr = conf_root[i].get("address", "").asString();
        const string& role = conf_root[i].get("role", "").asString();
        int ptype = conf_root[i].get("type", 0).asInt();

        if ("client" == role)
        {
            snprintf(tmpkey, sizeof(tmpkey), "0_%s", addr.c_str());
            packtypes_[tmpkey] = ptype;
        }
        else if ("server" == role)
        {
            snprintf(tmpkey, sizeof(tmpkey), "1_%s", addr.c_str());
            packtypes_[tmpkey] = ptype;
        }
        else if ("default" == role)
        {
            default_packtype_ = ptype;
        }
        else
        {
            L_ERROR("undefined role %s", role.c_str());
        }
    }

    return 0;
}

int log_agent_global_t::get_packtype( const msgpack_context_t& ctx ) const
{
    char tmpkey[128];
    char addrstr[64];
    if (ctx.link_type_ == netlink_t::accept_link)
    {
        snprintf(tmpkey, sizeof(tmpkey), "1_%s", get_addr_str(ctx.local_, addrstr, sizeof(addrstr)));
    }
    else if (ctx.link_type_ == netlink_t::client_link)
    {
        snprintf(tmpkey, sizeof(tmpkey), "0_%s", get_addr_str(ctx.remote_, addrstr, sizeof(addrstr)));
    }
    else
    {
        return -1;
    }

    packtype_map_t::const_iterator it = packtypes_.find(tmpkey);
    if (it == packtypes_.end())
    {
        return default_packtype_;
    }

    return it->second;
}
