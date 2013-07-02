#ifndef _BASE64_CODEC_H_
#define _BASE64_CODEC_H_

#ifndef _BASE64_NONUSE_STL_

#include <string>

std::string base64_encode(unsigned char const* , unsigned int len);
std::string base64_decode(std::string const& s);
#else

// encode����ַ���(��д\0), ע�������outlen������\0, �൱����strlen(out)�Ľ��
// outlenҪ������out buffer�ĳ���
void base64_encode(unsigned char const* , unsigned int len, unsigned char *out, unsigned int& outlen);
// decode���buffer, outlen��������ĳ���
// outlenҪ������out buffer�ĳ���
void base64_decode(unsigned char const* , unsigned int len, unsigned char *out, unsigned int& outlen);

#endif

#endif

