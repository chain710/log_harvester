#include "websocket_codec.h"
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>

//////////////////////////////////////////////////////////////////////////
uint64_t ntoh64(uint64_t input)
{
    uint64_t rval;
    uint8_t *data = (uint8_t *)&rval;

    data[0] = input >> 56;
    data[1] = input >> 48;
    data[2] = input >> 40;
    data[3] = input >> 32;
    data[4] = input >> 24;
    data[5] = input >> 16;
    data[6] = input >> 8;
    data[7] = input >> 0;

    return rval;
}

uint64_t hton64(uint64_t input)
{
    return (ntoh64(input));
}
//////////////////////////////////////////////////////////////////////////

void parse_ws_fixed_head(const char* data, ws_frame_fixed_head_t* out)
{
    // len(data) >= 2 && NULL != out
    const unsigned char* p = (const unsigned char* )data;
    out->fin_ = p[0] >> 7;
    out->rsv_ = (p[0] >> 4) & 0x07;
    out->opcode_ = p[0] & 0x0f;
    out->has_mask_ = p[1] >> 7;
    out->payload_len_ = p[1] & 0x7f;
}

bool is_client_ws_frame(const char* data, size_t size)
{
    if (size < sizeof(ws_frame_fixed_head_t))
    {
        return false;
    }

    ws_frame_fixed_head_t head;
    parse_ws_fixed_head(data, &head);
    return 0 == head.rsv_ && 1 == head.has_mask_;
}

int get_ws_frame_len( const char* data, size_t size )
{
    ws_frame_t frame;
    memset(&frame, 0, sizeof(frame));
    if (size < WS_FIXED_HEAD_LEN) return 0;
    parse_ws_fixed_head(data, &frame.head_);
    int offset = WS_FIXED_HEAD_LEN;
    if (frame.head_.payload_len_ < 126)
    {
        frame.payload_len_ = frame.head_.payload_len_;
    }
    else if (126 == frame.head_.payload_len_)
    {
        // ushort
        unsigned short* len = (unsigned short*)&data[offset];
        if (size < offset+sizeof(unsigned short)) return 0;
        frame.payload_len_ = ntohs(*len);
        offset += sizeof(unsigned short);
    }
    else
    {
        // 127 uint64
        uint64_t *len = (uint64_t *)&data[offset];
        if (size < offset+sizeof(uint64_t)) return 0;
        frame.payload_len_ = ntoh64(*len);
        offset += sizeof(uint64_t);
    }

    if (frame.head_.has_mask_)
    {
        offset += sizeof(frame.mask_);
    }

    if (size < offset + frame.payload_len_) return 0;
    return offset + frame.payload_len_;
}

int parse_ws_frame( const char* data, size_t size, ws_frame_t* frame, unsigned int flag )
{
    if (NULL == frame) return -1;
    memset(frame, sizeof(ws_frame_t), 0);
    if (size < WS_FIXED_HEAD_LEN) return -1;
    parse_ws_fixed_head(data, &frame->head_);
    int offset = WS_FIXED_HEAD_LEN;
    if (frame->head_.payload_len_ < 126)
    {
        frame->payload_len_ = frame->head_.payload_len_;
    }
    else if (126 == frame->head_.payload_len_)
    {
        // ushort
        unsigned short* len = (unsigned short*)&data[offset];
        if (size < offset+sizeof(unsigned short)) return -offset;
        frame->payload_len_ = ntohs(*len);
        offset += sizeof(unsigned short);
    }
    else
    {
        // 127 uint64
        uint64_t *len = (uint64_t *)&data[offset];
        if (size < offset+sizeof(uint64_t)) return -offset;
        frame->payload_len_ = ntoh64(*len);
        offset += sizeof(uint64_t);
    }

    if (frame->head_.has_mask_)
    {
        if (size < offset + sizeof(frame->mask_)) return -offset;
        memcpy(frame->mask_, &data[offset], sizeof(frame->mask_));
        offset += sizeof(frame->mask_);
    }

    if (size < offset + frame->payload_len_) return -offset;
    
    if (flag & PWF_UNMASK_PAYLOAD)
    {
        const char* payload = &data[offset];
        frame->payload_ = new char[frame->payload_len_+1];
        if (NULL == frame->payload_) return -1;
        frame->payload_[frame->payload_len_] = '\0';

        for (uint64_t i = 0; i < frame->payload_len_; ++i)
        {
            frame->payload_[i] = payload[i] ^ frame->mask_[i % sizeof(frame->mask_)];
        }
    }

    return offset + frame->payload_len_;
}

int pack_ws_frame( char* out, size_t len, unsigned int opcode, size_t payload_len )
{
    if (len < WS_FIXED_HEAD_LEN) return -1;
    int offset = WS_FIXED_HEAD_LEN;
    out[0] = 0x80 | (opcode & 0x0f);
    // has_mask_ = 0
    if (payload_len < 126)
    {
        out[1] = payload_len;
    }
    else if (payload_len < 65535)
    {
        out[1] = 126;
        unsigned short* plen = (unsigned short*)&out[offset];
        if (len < offset + sizeof(unsigned short)) return -1;
        *plen = htons(payload_len);
        offset += sizeof(unsigned short);
    }
    else
    {
        out[1] = 127;
        uint64_t* plen = (uint64_t*)&out[offset];
        if (len < offset + sizeof(uint64_t)) return -1;
        *plen = hton64(payload_len);
        offset += sizeof(uint64_t);
    }

    return offset;
}
