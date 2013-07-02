#ifndef _WEBSOCKET_CODEC_H_
#define _WEBSOCKET_CODEC_H_

#include <inttypes.h>
#include <stddef.h>

#define WS_MASK_LEN (4)
#define WS_FIXED_HEAD_LEN (2)

enum parse_ws_frame_flag_t
{
    PWF_UNMASK_PAYLOAD = 0x01,
};

enum ws_frame_opcode_t
{
    WFOP_FRAGMENT = 0,
    WFOP_TEXT = 1,
    WFOP_BINARY = 2,
    WFOP_CLOSE = 8,
    WFOP_PING = 9,
    WFOP_PONG = 10,
};

#pragma pack(1)
struct ws_frame_fixed_head_t {
    /*
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-------+-+-------------+-------------------------------+
    |F|R|R|R| opcode|M| Payload len |    Extended payload length    |
    |I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
    |N|V|V|V|       |S|             |   (if payload len==126/127)   |
    | |1|2|3|       |K|             |                               |
    +-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
    |     Extended payload length continued, if payload len == 127  |
    + - - - - - - - - - - - - - - - +-------------------------------+
    |                               |Masking-key, if MASK set to 1  |
    +-------------------------------+-------------------------------+
    | Masking-key (continued)       |          Payload Data         |
    +-------------------------------- - - - - - - - - - - - - - - - +
    :                     Payload Data continued ...                :
    + - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
    |                     Payload Data continued ...                |
    +---------------------------------------------------------------+
    */

    // CANNOT USE MEMCPY: The order of allocation of bit-fields within a unit (high-order to low-order or low-order to high-order) is implementation-defined.
    unsigned opcode_:4;
    unsigned rsv_:3;    // should be zero
    unsigned fin_:1;
    unsigned payload_len_:7;
    unsigned has_mask_:1;
};
#pragma pack(0)

struct ws_frame_t
{
    ws_frame_fixed_head_t head_;
    uint64_t payload_len_;
    char mask_[WS_MASK_LEN];
    char* payload_;
};

bool is_client_ws_frame(const char* data, size_t size);
// 获取websocket frame长度，返回<0出错，=0长度不足，>0frame长度
int get_ws_frame_len( const char* data, size_t size );
int parse_ws_frame(const char* data, size_t size, ws_frame_t* frame, unsigned int flag);
// 打包除了payload data之外的数据, 返回打包长度
int pack_ws_frame(char* out, size_t len, unsigned int opcode, size_t payload_len);

#endif // !_WEBSOCKET_CODEC_H_
