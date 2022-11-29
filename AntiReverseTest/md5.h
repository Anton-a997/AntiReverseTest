#ifndef MD5_H
#define MD5_H

#include <stdint.h>

#define LEFTROTATE(x, c) (((x) << (c)) | ((x) >> (32 - (c))))

void md5(const uint8_t* initial_msg, size_t initial_len);

#endif   
