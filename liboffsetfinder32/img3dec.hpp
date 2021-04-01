//
//  img3dec.hpp
//  sockH3lix
//
//  Created by SXX on 2020/12/19.
//  Copyright © 2020 tihmstar. All rights reserved.
//

#ifndef img3dec_hpp
#define img3dec_hpp

#include <stdio.h>

typedef struct img3 img3;
typedef struct tag tag;

class img3decompress {
    FILE *file;
    off_t filesize;
    const char *key;
    const char *iv;
    uint8_t *mmapped;
    img3 *img3Header;
    int fd;
    char ident[5];
    char type[5];
    tag *tag;
    size_t lzss_size;
    size_t lzss_src_size;
    bool has_kbag;
    uint32_t ibuf_off = 0;
    lzssdecompress lzss;
    uint8_t *data;
public:
    img3decompress(FILE *inputfh, const char *key = nullptr, const char *iv = nullptr);
    ~img3decompress();
    inline size_t out_size() const noexcept {
        return lzss_size;
    }
    
    // Return false to indicate that the decompression encountered EoF
    bool decompress(uint8_t *out_buf, size_t &out_size);
};

int decompress_kernel_32(FILE *inputfh, void *&memory, size_t &size);

#endif /* img3dec_hpp */
