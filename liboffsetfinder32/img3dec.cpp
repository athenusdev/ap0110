//
//  img3dec.cpp
//  sockH3lix
//
//  Created by SXX on 2020/12/19.
//  Copyright © 2020 tihmstar. All rights reserved.
//

#if !__arm64__

#include <sys/mman.h>      // For mmap(2)
#include <sys/stat.h>      // For stat(2)
#include <unistd.h>        // For everything else
#include <fcntl.h>         // O_RDONLY
#include <stdio.h>         // printf!
#include <string.h>       // str*, mem*
#include <stdlib.h>       // exit..
#include <functional>
#include "lzssdec.hpp"
#include "img3dec.hpp"

#define kPropNameLength    32


typedef struct DeviceTreeNodeProperty {
    char                name[kPropNameLength];  // NUL terminated property name
    uint32_t            length;         // Length (bytes) of folloing prop value
    //  unsigned long       value[1];       // Variable length value of property
    // Padded to a multiple of a longword?
} DeviceTreeNodeProperty;

typedef struct OpaqueDTEntry {
    uint32_t            nProperties;    // Number of props[] elements (0 => end)
    uint32_t            nChildren;      // Number of children[] elements
    //  DeviceTreeNodeProperty      props[];// array size == nProperties
    //  DeviceTreeNode      children[];     // array size == nChildren
} DeviceTreeNode;

typedef struct img3 {
    uint32_t          magic;
    uint32_t       fullSize;
    uint32_t     sizeNoPack;
    uint32_t   sigCheckArea;
    uint32_t          ident;
    
} img3;

typedef struct tag {
    uint32_t          magic;
    uint32_t   total_length;
    uint32_t    data_length;
    unsigned char  data[0];
}  tag;

#define IMG3_MAGIC 0x496d6733
#define TAG_TYPE  0x54595045
#define TAG_DATA  0x44415441
#define TAG_VERS  0x56455253
#define TAG_SEPO  0x5345504f
#define TAG_CHIP  0x43484950
#define TAG_BORD  0x424f5244
#define TAG_KBAG  0x4b424147
#define TAG_SHSH  0x53485348
#define TAG_CERT  0x43455254

#define TYPE_DTRE 0x65727464


int g_Dump = 0;
void
dump (unsigned char *data, int len) {
    int i;
    for (i = 0 ; i < len; i++) {
        printf ("%02x ", data[i]);
    }
    
    
    printf ("\n");
    
}


void copyValue (char *dest, char *src, int length) {
    
    int i = 0;
    for (i = 0; src[i] || i < length; i++);
    
    if (i != length){  strcpy(dest, "(null)"); return;}
    memcpy(dest, src,length);
    
}



size_t
dumpTreeNode(DeviceTreeNode *Node, int indent) {
    char buffer[40960];
    char temp[10240];
    char *name = NULL;
    
    int prop = 0, child = 0;
    int i = 0;
    memset(buffer, '\0', 4096);
    
    DeviceTreeNodeProperty *dtp = (DeviceTreeNodeProperty * ) ((char*)Node + sizeof(DeviceTreeNode));
    
    char *offset = 0;
    for (prop = 0; prop < Node->nProperties; prop++) {
        temp[0] = '\0'; // strcat will do the rest
        for (i=0; i< indent ; i++) { strcat(temp,"|  "); }
        strcat (temp, "+--");
        strncat (buffer, temp, 1024);
        sprintf (temp, "%s %d bytes: ", dtp->name, dtp->length);
        strncat (buffer, temp, 1024);
        
        if (strcmp(dtp->name,"name") == 0) {
            name = (char *) &dtp->length + sizeof(uint32_t);
            strncat(buffer, name, dtp->length);
            strcat (buffer,"\n");
        }
        else
        {
            copyValue (temp, ((char *) &dtp->length) + sizeof(uint32_t), dtp->length);
            // Yeah, Yeah, Buffer overflows, etc.. :-)
            
            strcat (buffer, temp);
            strcat(buffer, "\n");
        }
        
        dtp =  (DeviceTreeNodeProperty*)(((char *) dtp) + sizeof(DeviceTreeNodeProperty) + dtp->length) ;
        
        // Align
        dtp =  (((long) dtp %4) ? (DeviceTreeNodeProperty*)(((char *) dtp)  + (4 - ((long)dtp) %4))   : dtp);
        
        offset = (char *) dtp;
    }
    
    for (i = 0; i < indent-1; i++) {
        printf("   ");
    }
    if (indent>1) {
        printf ("+--");
    }
    printf ("%s:\n", name);
    void (*_printf)(const char*) = (void(*)(const char*))printf;
    _printf(buffer);
    
    // Now do children:
    for (child = 0; child < Node->nChildren; child++)
    {
        offset+= dumpTreeNode ( (DeviceTreeNode *) offset, indent+1 );
    }
    
    return ( (char *) offset - (char*) Node);
}


void
doData (char *data, int tag, int len) {
    
    printf ("\tData of type 0x%x and length %d bytes\n",  tag, len);
    
    switch (tag) {
        case TYPE_DTRE: {
            DeviceTreeNode *dtn = (DeviceTreeNode *) data;
            //DeviceTreeNode *root = (DeviceTreeNode *) data;
            //int prop = 0;
            
            if (dtn->nProperties > 20) {
                printf ("\tMore than 20 properties? Did you hand me an encrypted file?\n");
                return;
            }
            
            
            printf ("\tDevice Tree with %d properties and %d children\n",
                    dtn->nProperties, dtn->nChildren);
            
            if (g_Dump) {
                printf ("Properties:\n");
                
                dumpTreeNode (dtn,1);
            }
            else { printf("\tUse -d to dump the device tree\n");}
        }
    }
}

#if 0
static int
decompress_img3_kernel(FILE *infile/*, FILE *outfile*/, std::function<bool(const uint8_t *, size_t, size_t total_size)> out_cb/*, bool (*out_cb)(const uint8_t *data, size_t size)*/, const char *key, const char *iv) {
    off_t filesize;
    
    char *mmapped;
    img3 *img3Header;
    int fd;
    char ident[5];
    char type[5];
    int retval = 0;
    tag  *tag;
    //FILE *out = outfile;
    //const char *filename = path;
    
    fseek(infile, 0L, SEEK_END);
    filesize = ftell(infile);
    fseek(infile, 0L, SEEK_SET);
    fd = fileno(infile);
    
    mmapped = (char*)mmap(NULL,
                   (size_t)filesize,  // size_t len,
                   PROT_READ, // int prot,
                   MAP_SHARED | MAP_FILE,  // int flags,
                   fd,        // int fd,
                   0);        // off_t offset);
    
    if (!mmapped) {
        perror ("mmap");
        close(fd);
        return -3;
    }
    
    img3Header = (img3 *) mmapped;
    
    if (img3Header->magic != IMG3_MAGIC) {
        fprintf(stderr,"File is not an IMG3 file!\n");
        munmap(mmapped, (size_t)filesize);
        close(fd);
        return -4;
    }
    
    
    ident[4] ='\0';
    for (int i = 0; i < 4; i++) {
        ident[i] = * (((char *)&(img3Header->ident)) + 3-i);
        
    }
    
    printf ("Ident: %s\n", ident);
    
    bool has_kbag = false;
    uint8_t *data = NULL;
    uint32_t data_len = 0;
    struct lzss_hdr *hdr;
    uint32_t lzss_src_size;
    
    tag = (struct tag *) (mmapped + sizeof(img3));
    while ( ((char *)tag) - ((char *) mmapped) < filesize ) {
        
        for (int i = 0; i < 4; i++) {
            ident[i] = * (((char *)&(tag->magic)) + 3 - i);
        }
        
        printf ("Tag: %s (%x) Length 0x%x\n", ident, tag->magic, tag->total_length);
        
        
        switch (tag->magic) {
            case TAG_TYPE:
                printf ("\tType: ");
                for (int i = 0; i < 4; i++) {
                    type[i] = * (((char *)&(tag->data)) + 3-i);
                }
                //printf ("%s\n", type);
                if (*(uint32_t *)&tag->data != 'krnl') {
                    retval = -5;
                    goto end;
                }
                break;
            case TAG_KBAG: {
                for (int i = 0 ; i < tag->total_length; i++) {
                    printf ("%02X", ((unsigned char *) &(tag->data))[i]);
                }
                has_kbag = true;
                printf("\n");
                break;
            }
            case  TAG_BORD:
                printf ("\tBoard: ");
                dump (tag->data,tag->data_length);
                break;
            case  TAG_VERS:
                printf ("\tVersion: ");
                printf ("%s\n", tag->data + 4);
                break;
            case  TAG_SEPO:
                printf ("\tSecurity Epoch: ");
                dump (tag->data,tag->data_length);
                break;
            case  TAG_CHIP:
                printf ("\tChip: ");
                dump (tag->data,tag->data_length);
                break;
            case  TAG_DATA:
                doData((char*)tag->data,  *((int *) type), (int)tag->data_length);
                data = tag->data;
                data_len = tag->data_length;
                break;
            default:
                break;
                
        }
        tag = reinterpret_cast<struct tag *>(( (char *) tag) + (tag->total_length));
    }
    
    hdr = (struct lzss_hdr *)data;
    if (be64toh(hdr->magic) != lzss_magic) {
        fprintf(stderr, "Invalid input - no lzss magic 0x%llx\n", hdr->magic);
        return 1;
    }
    lzss_src_size = be32toh(hdr->src_size);
    lzss_size = be32toh(hdr->size);
    if (lzss_src_size > data_len - sizeof(struct lzss_hdr)) {
        fprintf(stderr, "Invalid input - reports size larger than available\n");
        return 1;
    }
    data = (uint8_t *)(hdr + 1);
    if (!has_kbag) {
#define CHUNK 0x10000
        lzssdecompress lzss;
        uint8_t *obuf= (uint8_t*)malloc(CHUNK);
        uint32_t ibuf_off = 0;
        while (lzss_src_size > ibuf_off) {
            uint32_t chunk_r = (lzss_src_size - ibuf_off > CHUNK) ? (CHUNK) : (lzss_src_size - ibuf_off);
            uint32_t dstused;
            uint32_t srcused;
            lzss.decompress(obuf, CHUNK, &dstused, data + ibuf_off, chunk_r, &srcused);
            if (!out_cb(obuf, dstused， lzss_size)) {
                goto end;
            }
            //fwrite(obuf, 1, dstused, out);
            ibuf_off += srcused;
        }
        uint32_t dstused;
        lzss.flush(obuf, CHUNK, &dstused);
        out_cb(obuf, dstused, lzss_size);
        //fwrite(obuf, 1, dstused, out);
    }
    
end:
//    if (out != NULL) {
//        fclose(out);
//    }
    munmap(mmapped, (size_t)filesize);
    close(fd);
    return retval;
}
#endif

img3decompress::img3decompress(FILE *inputfh, const char *key, const char *iv) : file(inputfh), key(key), iv(iv) {
    fseek(inputfh, 0L, SEEK_END);
    filesize = ftell(inputfh);
    fseek(inputfh, 0L, SEEK_SET);
    fd = fileno(inputfh);
    
    mmapped = (uint8_t *)mmap(NULL, (size_t)filesize, PROT_READ, MAP_SHARED | MAP_FILE, fd, 0);
    if (!mmapped) {
        throw 1;
    }
    
    img3Header = (img3 *)mmapped;
    
    if (img3Header->magic != IMG3_MAGIC) {
        fprintf(stderr,"File is not an IMG3 file!\n");
        throw -4;
    }
    
    ident[4] ='\0';
    for (int i = 0; i < 4; i++) {
        ident[i] = * (((char *)&(img3Header->ident)) + 3-i);
    }
    
    printf ("Ident: %s\n", ident);
    
    has_kbag = false;
    data = NULL;
    uint32_t data_len = 0;
    struct lzss_hdr *hdr;
    
    tag = (struct tag *) (mmapped + sizeof(img3));
    while ( ((char *)tag) - ((char *) mmapped) < filesize ) {
        
        for (int i = 0; i < 4; i++) {
            ident[i] = * (((char *)&(tag->magic)) + 3 - i);
        }
        
        printf ("Tag: %s (%x) Length 0x%x\n", ident, tag->magic, tag->total_length);
        
        
        switch (tag->magic) {
            case TAG_TYPE:
                printf ("\tType: ");
                for (int i = 0; i < 4; i++) {
                    type[i] = * (((char *)&(tag->data)) + 3-i);
                }
                //printf ("%s\n", type);
                if (*(uint32_t *)&tag->data != 'krnl') {
                    //retval = -5;
                    //goto end;
                    throw -5;
                }
                break;
            case TAG_KBAG: {
                for (int i = 0 ; i < tag->total_length; i++) {
                    printf ("%02X", ((unsigned char *) &(tag->data))[i]);
                }
                has_kbag = true;
                printf("\n");
                break;
            }
            case  TAG_BORD:
                printf ("\tBoard: ");
                dump (tag->data,tag->data_length);
                break;
            case  TAG_VERS:
                printf ("\tVersion: ");
                printf ("%s\n", tag->data + 4);
                break;
            case  TAG_SEPO:
                printf ("\tSecurity Epoch: ");
                dump (tag->data,tag->data_length);
                break;
            case  TAG_CHIP:
                printf ("\tChip: ");
                dump (tag->data,tag->data_length);
                break;
            case  TAG_DATA:
                doData((char*)tag->data,  *((int *) type), (int)tag->data_length);
                data = tag->data;
                data_len = tag->data_length;
                break;
            default:
                break;
                
        }
        tag = reinterpret_cast<struct tag *>(( (char *) tag) + (tag->total_length));
    }
    
    hdr = (struct lzss_hdr *)data;
    if (be64toh(hdr->magic) != lzss_magic) {
        fprintf(stderr, "Invalid input - no lzss magic 0x%llx\n", hdr->magic);
        throw 1;
    }
    lzss_src_size = be32toh(hdr->src_size);
    lzss_size = be32toh(hdr->size);
    if (lzss_src_size > data_len - sizeof(struct lzss_hdr)) {
        fprintf(stderr, "Invalid input - reports size larger than available\n");
        throw 1;
    }
    data = (uint8_t *)(hdr + 1);
}

bool
img3decompress::decompress(uint8_t *out_buf, size_t &out_size) {
    if (!has_kbag) {
        if (lzss_src_size > ibuf_off) {
            uint32_t chunk_r = (lzss_src_size - ibuf_off > out_size) ? (out_size) : (lzss_src_size - ibuf_off);
            uint32_t srcused;
            uint32_t dstused;
            lzss.decompress(out_buf, out_size, &dstused, data + ibuf_off, chunk_r, &srcused);
            out_size = dstused;
            ibuf_off += srcused;
            return true;
        }
        uint32_t dstused;
        lzss.flush(out_buf, out_size, &dstused);
        if (dstused == 0) {
            return false;
        }
        out_size = dstused;
        return true;
    }
    return false;
}
#define CHUNK 0x10000
img3decompress::~img3decompress() {
    if (mmapped != NULL) {
        munmap(mmapped, (size_t)filesize);
    }
}

int
decompress_kernel_32(FILE *inputfh, FILE *outputfh) {
    try {
        img3decompress img3d(inputfh);
        uint8_t *buffer = (uint8_t*)malloc(CHUNK);
        size_t size = CHUNK;
        while (img3d.decompress(buffer, size)) {
            fwrite(buffer, 1, size, outputfh);
        }
    } catch(int e) {
        return e;
    }
    return 0;
}

int
decompress_kernel_32(FILE *inputfh, void *&memory, size_t &size) {
    try {
        img3decompress img3d(inputfh);
        size = img3d.out_size();
        memory = malloc(size);
        size_t i = 0;
        size_t chunk = CHUNK;
        while (img3d.decompress((uint8_t *)memory + i, chunk)) {
            i += chunk;
            chunk = CHUNK;
        }
    } catch(int e) {
        return e;
    }
    return 0;
}

#endif
