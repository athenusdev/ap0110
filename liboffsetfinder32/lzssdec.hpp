//
//  lzssdec.hpp
//  sockH3lix
//
//  Created by SXX on 2020/12/19.
//  Copyright © 2020 tihmstar. All rights reserved.
//

#ifndef _LZSSDEC_HPP
#define _LZSSDEC_HPP

#include <cstdint>

#ifdef __cplusplus

extern "C" int g_debug;
class __attribute__((visibility("hidden"))) lzssdecompress {
    enum { COPYFROMDICT, EXPECTINGFLAG, PROCESSFLAGBIT, EXPECTING2NDBYTE };
    int _state;
    uint8_t _flags;
    int _bitnr;
    uint8_t *_src, *_srcend;
    uint8_t *_dst, *_dstend;
    uint8_t _firstbyte;

    uint8_t *_dict;

    int _dictsize;
    int _maxmatch;
    int _copythreshold;

    int _dictptr;

    int _copyptr;
    int _copycount;

    int _inputoffset;
    int _outputoffset;
public:
    lzssdecompress();
    ~lzssdecompress();
    void reset();
    void decompress(uint8_t *dst, uint32_t dstlen, uint32_t *pdstused, uint8_t *src, uint32_t srclen, uint32_t *psrcused);
    void flush(uint8_t *dst, uint32_t dstlen, uint32_t *pdstused);
    void copyfromdict();
    void dumpcopydata();
    void addtodict(uint8_t c);
    void nextflagbit();
    void setcounter(uint8_t first, uint8_t second);
};

static const uint64_t lzss_magic = 0x636f6d706c7a7373;

struct lzss_hdr {
    uint64_t magic;
    uint32_t checksum;
    uint32_t size;
    uint32_t src_size;
    uint32_t unk1;
    uint8_t padding[0x168];
};

#ifdef __APPLE__

#include <libkern/OSByteOrder.h>

#define htobe16(x) OSSwapHostToBigInt16(x)
#define htole16(x) OSSwapHostToLittleInt16(x)
#define be16toh(x) OSSwapBigToHostInt16(x)
#define le16toh(x) OSSwapLittleToHostInt16(x)

#define htobe32(x) OSSwapHostToBigInt32(x)
#define htole32(x) OSSwapHostToLittleInt32(x)
#define be32toh(x) OSSwapBigToHostInt32(x)
#define le32toh(x) OSSwapLittleToHostInt32(x)

#define htobe64(x) OSSwapHostToBigInt64(x)
#define htole64(x) OSSwapHostToLittleInt64(x)
#define be64toh(x) OSSwapBigToHostInt64(x)
#define le64toh(x) OSSwapLittleToHostInt64(x)

#else
#include <endian.h>
#endif

#else
extern int g_debug;
#endif

#endif

