#include "log_agent.h"
#include "base64.h"
#include "sha1.h"
#include "websocket_codec.h"
#include "log_agent_global.h"
#include "log_agent.pb.h"
#include <utility.h>

#include <string.h>
#include <stdio.h>
#include <string>
#include <signal.h>
#include <inttypes.h>
#include <json/json.h>

using namespace std;
using namespace std::tr1;
using namespace log4cplus;
using namespace google::protobuf;

enum msgpack_type_t
{
    mt_websocket = 1, 
    mt_protobuf = 2,
};

enum endpoint_group_t
{
    egt_log_master = 1,
};

struct pack_info_t
{
    int type_;
};

//////////////////////////////////////////////////////////////////////////
// 全局变量
log_agent_global_t la_global_;
//////////////////////////////////////////////////////////////////////////

int parse_protobuf_msg(const void* data, size_t len, Message* msg)
{
    if (len < 1) return 0;
    const unsigned char* p = (const unsigned char* )data;
    int msglen = p[0];
    int offset = 1;
    if (254 == msglen)
    {
        if (len < offset+sizeof(unsigned short)) return -1;
        unsigned short *msglen2 = (unsigned short *)&p[offset];
        msglen = ntohs(*msglen2);
        offset += sizeof(unsigned short);
    }
    else if (255 == msglen)
    {
        if (len < offset+sizeof(int)) return -1;
        int *msglen2 = (int *)&p[offset];
        msglen = ntohl(*msglen2);
        offset += sizeof(int);
    }

    if ((int)len < msglen + offset) return -1;
    if (msg)
    {
        if (!msg->ParseFromArray(data, len)) return -2;
    }

    return offset + msglen;
}

int get_protobuf_msg_len(const char* data, size_t len)
{
    int ret = parse_protobuf_msg(data, len, NULL);
    if (ret < -1)
    {
        return ret;
    }
    else if (-1 == ret)
    {
        return ret;
    }
    else
    {
        return ret;
    }
}

int pack_protobuf_msg(void* data, size_t len, const Message& msg)
{
    if (len < 1) return -1;
    unsigned char* p = (unsigned char*)data;
    int msglen = msg.ByteSize();
    int offset = 1;
    if (msglen < 254)
    {
        p[0] = msglen;
    }
    else if (msglen < 65535)
    {
        p[0] = 254;
        if (len < offset + sizeof(unsigned short)) return -1;
        unsigned short* plen = (unsigned short*)&p[offset];
        *plen = htons(msglen);
        offset += sizeof(unsigned short);
    }
    else
    {
        p[0] = 255;
        if (len < offset + sizeof(int)) return -1;
        int* plen = (int*)&p[offset];
        *plen = htonl(msglen);
        offset += sizeof(int);
    }

    if ((int)len < offset + msglen) return -1;
    if (!msg.SerializeToArray(&p[offset], len - offset))
    {
        return -2;
    }

    return offset + msglen;
}

//////////////////////////////////////////////////////////////////////////
// http parser callbacks

int on_head_field(http_parser* p, const char *at, size_t length)
{
    http_parser_ctx* ctx = (http_parser_ctx*)p->data;
    if (ctx->parse_state_ != http_parser_ctx::parse_field)
    {
        if (ctx->field_ == "Sec-WebSocket-Key")
        {
            ctx->wskey_ = ctx->value_;
        }

        ctx->parse_state_ = http_parser_ctx::parse_field;
        ctx->field_.clear();
    }

    ctx->field_.append(at, length);

    return 0;
}

int on_head_value(http_parser* p, const char *at, size_t length)
{
    http_parser_ctx* ctx = (http_parser_ctx*) p->data;
    if (ctx->parse_state_ != http_parser_ctx::parse_value)
    {
        ctx->parse_state_ = http_parser_ctx::parse_value;
        ctx->value_.clear();
    }

    ctx->value_.append(at, length);

    return 0;
}

int on_head_complete(http_parser* p)
{
    http_parser_ctx* ctx = (http_parser_ctx*)p->data;
    ctx->parse_state_ = http_parser_ctx::parse_none;
    return 0;
}

int on_msg_complete(http_parser* p) 
{
    http_parser_ctx* ctx = (http_parser_ctx*)p->data;
    ctx->msg_complete_ = 1;
    return 0;
}
//////////////////////////////////////////////////////////////////////////

void StringReplace(const string& s, const string& oldsub,
                   const string& newsub, bool replace_all,
                   string* res) {
                       if (oldsub.empty()) {
                           res->append(s);  // if empty, append the given string.
                           return;
                       }

                       string::size_type start_pos = 0;
                       string::size_type pos;
                       do {
                           pos = s.find(oldsub, start_pos);
                           if (pos == string::npos) {
                               break;
                           }
                           res->append(s, start_pos, pos - start_pos);
                           res->append(newsub);
                           start_pos = pos + oldsub.size();  // start searching again after the "old"
                       } while (replace_all);
                       res->append(s, start_pos, s.length() - start_pos);
}

// ----------------------------------------------------------------------
// StringReplace()
//    Give me a string and two patterns "old" and "new", and I replace
//    the first instance of "old" in the string with "new", if it
//    exists.  If "global" is true; call this repeatedly until it
//    fails.  RETURN a new string, regardless of whether the replacement
//    happened or not.
// ----------------------------------------------------------------------

string StringReplace(const string& s, const string& oldsub,
                     const string& newsub, bool replace_all) {
                         string ret;
                         StringReplace(s, oldsub, newsub, replace_all, &ret);
                         return ret;
}

std::string get_real_filename( const std::string& file_pattern, time_t t )
{
    string fn = file_pattern;
    char tmp[16];
    struct tm *filetm;
    filetm = localtime(&t);
    if (NULL == filetm)
    {
        return fn;
    }

    strftime(tmp, sizeof(tmp), "%Y", filetm);
    fn = StringReplace(fn, "{YEAR}", tmp, true);
    strftime(tmp, sizeof(tmp), "%m", filetm);
    fn = StringReplace(fn, "{MONTH}", tmp, true);
    strftime(tmp, sizeof(tmp), "%d", filetm);
    fn = StringReplace(fn, "{DAY}", tmp, true);
    strftime(tmp, sizeof(tmp), "%H", filetm);
    fn = StringReplace(fn, "{HOUR}", tmp, true);
    strftime(tmp, sizeof(tmp), "%M", filetm);
    fn = StringReplace(fn, "{MIN}", tmp, true);

    return fn;
}

//////////////////////////////////////////////////////////////////////////
int log_agent_t::handle_websocket( msgpack_context_t ctx, const char* pack, size_t pack_len)
{
    client_map_t::iterator it = clients_.find(ctx.link_fd_);
    if (ctx.flag_ & mpf_new_connection)
    {
        if (it != clients_.end())
        {
            // 前一个linkfd已经被关闭了
            L_TRACE("close prev client object by fd %d", ctx.link_fd_);
            it->second.clear();
        }

        client_t& c = clients_[ctx.link_fd_];
        //c.clear();
        c.mctx_ = ctx;
        return 0;
    }

    if (ctx.flag_ & mpf_closed_by_peer)
    {
        if (it != clients_.end())
        {
            // 前一个linkfd已经被关闭了
            L_TRACE("closed by peer, clear fd %d data", ctx.link_fd_);
            it->second.clear();
        }

        return 0;
    }

    if (it == clients_.end())
    {
        L_ERROR("find no client by fd %d", ctx.link_fd_);
        return -1;
    }

    client_t& c = it->second;

    switch (c.state_)
    {
    case client_t::cst_init:
        {
            http_parser_settings settings;
            memset(&settings, 0, sizeof(settings));
            settings.on_header_field = on_head_field;
            settings.on_header_value = on_head_value;
            settings.on_message_complete = on_msg_complete;
            settings.on_headers_complete = on_head_complete;

            size_t nparsed = http_parser_execute(&c.parser_, &settings, pack, pack_len);
            L_DEBUG("parse %d bytes", (int)nparsed);
            if (0 == c.pctx_.msg_complete_)
            {
                L_ERROR("http header parse incompleted!%s", "");
                return -1;
            }

            string accept_raw = c.pctx_.wskey_;
            accept_raw.append("258EAFA5-E914-47DA-95CA-C5AB0DC85B11");

            unsigned char accept_sha1[20];
            sha1_buffer(accept_raw.c_str(), accept_raw.length(), accept_sha1);
            string accept_base64 = base64_encode(accept_sha1, sizeof(accept_sha1));

            L_DEBUG("wskey=%s", c.pctx_.wskey_.c_str());
            string msg("HTTP/1.1 101 Switching Protocols\r\n"
                "Upgrade: websocket\r\n"
                "Connection: Upgrade\r\n"
                "Sec-WebSocket-Accept: ");
            msg.append(accept_base64).append("\r\n\r\n");
            L_DEBUG("response(%s)\n", msg.c_str());

            c.state_ = client_t::cst_handshaked;
            return calypso_send_msgpack_by_ctx(opt_.msg_queue_, &ctx, msg.c_str(), msg.length());
        }
        break;
    case client_t::cst_handshaked:
        {
            ws_frame_t frame;
            int ret = parse_ws_frame(pack, pack_len, &frame, PWF_UNMASK_PAYLOAD);
            if (ret < 0)
            {
                L_ERROR("parse_ws_frame fail at %d", -ret);
                return -1;
            }

            if (0 == frame.head_.fin_)
            {
                L_ERROR("fragmentation not supported yet!%s", "");
                return -1;
            }

            int pack_len = 0;
            char pack_buffer[1024];
            bool need_close = false;
            switch (frame.head_.opcode_)
            {
            case WFOP_TEXT:
                L_DEBUG("recv text len=%"PRIu64" msg=%s", frame.payload_len_, frame.payload_);
                // TODO: check if hello package?
                break;
            case WFOP_BINARY:
                // hex
                L_DEBUG("recv binary len=%"PRIu64, frame.payload_len_);
                break;
            case WFOP_CLOSE:
                L_DEBUG("recv close%s", "");
                // 这里简单处理，直接关闭链路
                // The status code and any associated textual message are optional components of a Close frame.
                pack_len = pack_ws_frame(pack_buffer, sizeof(pack_buffer), WFOP_CLOSE, 0);
                c.state_ = client_t::cst_closed;
                need_close = true;
                break;
            case WFOP_PING:
                // response with pong
                L_DEBUG("recv ping%s", "");
                pack_len = pack_ws_frame(pack_buffer, sizeof(pack_buffer), WFOP_PONG, 0);
                break;
            case WFOP_PONG:
                // this is response for ping just sent(may not be used)
                L_DEBUG("recv pong%s", "");
                break;
            default:
                L_ERROR("unknown opcode %u", frame.head_.opcode_);
                break;
            }
            
            if (frame.payload_)
            {
                delete []frame.payload_;
                frame.payload_ = NULL;
            }

            if (pack_len > 0)
            {
                if (need_close)
                {
                    ctx.flag_ |= mpf_close_link;
                }
                
                return calypso_send_msgpack_by_ctx(opt_.msg_queue_, &ctx, pack_buffer, pack_len);
            }
        }
        break;
    case client_t::cst_closed:
        L_ERROR("this connection already closed!%s", "");
        return 0;
    default:
        L_ERROR("unknown state %d", c.state_);
        return -1;
    }

    return 0;
}

void log_agent_t::handle_tick()
{
    time_t now = time(NULL);
    if (calypso_need_reload(last_handle_reload_))
    {
        // process reload
        L_DEBUG("recv reload sig %u", (unsigned int)last_handle_reload_);
        last_handle_reload_ = now;
    }

    //timer_engine_t::timer_callback on_timer_func = std::tr1::bind(&demo_app_t::handle_timer, this, tr1::placeholders::_1);
    //timers_.walk(on_timer_func);
    harvester_.event_check();
    if (now - last_watch_log_check_time_ >= 3)
    {
        watch_log_check(now);
    }
}

void log_agent_t::broadcast_newlog( const std::string& fn, const std::string& logline )
{
    L_DEBUG("file %s has new log %s", fn.c_str(), logline.c_str());

    char msgbuf[2048];
    int packlen = pack_ws_frame(msgbuf, sizeof(msgbuf), WFOP_TEXT, logline.length());
    if (packlen < 0)
    {
        L_ERROR("pack_ws_frame failed %d", packlen);
        return;
    }

    packlen += snprintf(&msgbuf[packlen], sizeof(msgbuf)-packlen, "%s", logline.c_str());

    client_map_t::iterator it;
    for (it = clients_.begin(); it != clients_.end(); ++it)
    {
        calypso_send_msgpack_by_ctx(opt_.msg_queue_, &it->second.mctx_, msgbuf, packlen);
    }

    // 向其他log master发送新日志内容
    report_log_msg msg;
    msg.set_file(fn);
    msg.set_source("test");
    msg.add_logs(logline);

    packlen = pack_protobuf_msg(msgbuf, sizeof(msgbuf), msg);
    if (packlen < 0)
    {
        L_ERROR("pack_protobuf_msg failed %d", packlen);
        return;
    }

    calypso_send_msgpack_by_group(opt_.msg_queue_, egt_log_master, msgbuf, packlen);
}

log_agent_t::log_agent_t(app_init_option opt)
{
    last_handle_reload_ = 0;
    harvester_.reg_newlog_callback(bind(&log_agent_t::broadcast_newlog, this, placeholders::_1, placeholders::_2));
    harvester_.create();
    last_watch_log_check_time_ = 0;
    opt_ = opt;
}

int log_agent_t::load_log_pattern( const char* path )
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

    harvester_.clear_watchers();
    log_patterns_.clear();

    for (int i = 0; i < (int)conf_root.size(); ++i)
    {
        logfile_info_t& fileinfo = log_patterns_[conf_root[i].get("pattern", "").asString()];
        fileinfo.fd_ = -1;
        fileinfo.path_.clear();
    }

    watch_log_check(time(NULL));

    return 0;
}

void log_agent_t::watch_log_check(time_t now)
{
    last_watch_log_check_time_ = now;
    string filename;
    for (log_pattern_map_t::iterator it = log_patterns_.begin(); it != log_patterns_.end(); ++it)
    {
        filename = get_real_filename(it->first, now);
        if (filename != it->second.path_)
        {
            if (it->second.fd_ >= 0)
            {
                L_DEBUG("remove watch(%s)", it->second.path_.c_str());
                harvester_.remove_watcher(it->second.fd_);
            }

            it->second.path_ = filename;
            it->second.fd_ = harvester_.add_watch(filename);
            L_DEBUG("add watch(%s) ret %d", filename.c_str(), it->second.fd_);
        }
        else if (it->second.fd_ < 0)
        {
            it->second.fd_ = harvester_.add_watch(filename);
            L_DEBUG("add watch(%s) ret %d", filename.c_str(), it->second.fd_);
        }
        else if (now - harvester_.get_last_event_time(it->second.fd_) >= 60)
        {
            L_DEBUG("file %s idle too long, rewatch it", it->second.path_.c_str());
            harvester_.remove_watcher(it->second.fd_);
            it->second.fd_ = harvester_.add_watch(filename);
        }
    }
}

int log_agent_t::handle_msgpack( msgpack_context_t ctx, const char* pack, size_t pack_len )
{
    
    if (0 == pack_len)
    {
        // control msg
        client_map_t::iterator it = clients_.find(ctx.link_fd_);
        if (ctx.flag_ & mpf_new_connection)
        {
            if (it != clients_.end())
            {
                // 前一个linkfd已经被关闭了
                L_TRACE("close prev client object by fd %d", ctx.link_fd_);
                it->second.clear();
            }

            client_t& c = clients_[ctx.link_fd_];
            c.mctx_ = ctx;
            return 0;
        }
        else if (ctx.flag_ & mpf_closed_by_peer)
        {
            if (it != clients_.end())
            {
                // 前一个linkfd已经被关闭了
                L_TRACE("closed by peer, clear fd %d data", ctx.link_fd_);
                it->second.clear();
            }

            return 0;
        }
        else
        {
            L_ERROR("unknown control msg with packlen(%d)", (int)pack_len);
            return -1;
        }
    }

    size_t offset = sizeof(pack_info_t);
    if (ctx.extrabuf_len_ != (int)offset)
    {
        L_ERROR("invalid extrabuf!%s", "");
        return -1;
    }

    if (pack_len < offset)
    {
        L_ERROR("pack len %d too small, less than offset %d", (int)pack_len, (int)offset);
        return -1;
    }

    const pack_info_t* pinfo = (const pack_info_t*) pack;
    switch (pinfo->type_)
    {
    case mt_websocket: return handle_websocket(ctx, &pack[offset], pack_len - offset);
    case mt_protobuf: return handle_protobuf(ctx, &pack[offset], pack_len - offset);
    default:
        L_ERROR("undefined pack type %d", pinfo->type_);
        return -1;
    }

    return 0;
}

int log_agent_t::handle_protobuf( msgpack_context_t ctx, const char* pack, size_t pack_len )
{
    report_log_msg msg;
    int ret = parse_protobuf_msg(pack, pack_len, &msg);
    if (ret < 0)
    {
        L_ERROR("parse_protobuf_msg failed %d", ret);
        return -1;
    }

    for (int i = 0; i < msg.logs_size(); ++i)
    {
        broadcast_newlog(msg.file(), msg.logs(i));
    }

    return 0;
}

void* app_initialize( app_init_option opt )
{
    log_agent_t* r = new log_agent_t(opt);
    r->load_log_pattern("log_pattern.json");
    return r;
}

void app_finalize( void* app_inst )
{
    log_agent_t* app = (log_agent_t*) app_inst;
    delete app;
}

void app_handle_tick( void* app_inst )
{
    log_agent_t* app = (log_agent_t*) app_inst;
    app->handle_tick();
}

int app_get_msgpack_size( const msgpack_context_t* ctx, const char* data, size_t size, char* extrabuf, size_t* extrabuf_len )
{
    if (NULL == extrabuf_len || NULL == extrabuf)
    {
        L_ERROR("invalid provided extrabuf%s", "");
        return -1;
    }

    if (*extrabuf_len < sizeof(pack_info_t))
    {
        L_ERROR("not enough extrabuflen, need at least %d", (int)sizeof(pack_info_t));
        return -1;
    }

    pack_info_t pinfo;
    pinfo.type_ = la_global_.get_packtype(*ctx);
    memcpy(extrabuf, &pinfo, sizeof(pinfo));
    *extrabuf_len = sizeof(pinfo);

    switch (pinfo.type_)
    {
    case mt_websocket:
        {
            if (is_client_ws_frame(data, size))
            {
                int ret = get_ws_frame_len(data, size);
                if (ret < 0)
                {
                    L_ERROR("get_ws_frame_len error %d", ret);
                    return -1;
                }

                return ret;
            }

            string msg(data, size);
            size_t delim_pos = msg.find("\r\n\r\n");
            if (delim_pos == string::npos)
            {
                return 0;
            }

            L_DEBUG("find full http head, len=%d", (int)delim_pos+4);
            return delim_pos + 4;
        }
        break;
    case mt_protobuf:
        // [byte short short][protobuf]
        return get_protobuf_msg_len(data, size);
    default:
        L_ERROR("undefined pack type %d", pinfo.type_);
        return -1;
    }
}

int app_handle_msgpack( void* app_inst, const msgpack_context_t* ctx, const char* data, size_t size )
{
    log_agent_t* app = (log_agent_t*) app_inst;
    return app->handle_msgpack(*ctx, data, size);
}

//////////////////////////////////////////////////////////////////////////
// implement app callbacks

app_handler_t get_app_handler()
{
    app_handler_t h;
    memset(&h, 0, sizeof(h));
    h.init_ = app_initialize;
    h.fina_ = app_finalize;
    h.get_msgpack_size_ = app_get_msgpack_size;
    h.handle_msgpack_ = app_handle_msgpack;
    h.handle_tick_ = app_handle_tick;
    return h;
}

int app_global_init()
{
    L_TRACE("app_global_init%s", "");
    la_global_.load_packtype("packtype.json");
    return 0;
}

void app_global_reload()
{
    L_TRACE("app_global_reload%s", "");
    la_global_.load_packtype("packtype.json");
}

void app_global_fina()
{
    L_TRACE("app_global_fina%s", "");
}
