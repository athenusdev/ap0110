//
//  patchfinder32.c
//  sockH3lix
//
//  Created by SXX on 2020/12/20.
//  Copyright © 2020 tihmstar. All rights reserved.
//

#include "patchfinder32.h"
#include <stdlib.h>


#define HAS_BITS(a,b) (((a) & (b)) == (b))

static uint32_t
bit_range(uint32_t x, int start, int end) {
    x = (x << (31 - start)) >> (31 - start);
    x = (x >> end);
    return x;
}

static uint32_t
ror(uint32_t x, int places) {
    return (x >> places) | (x << (32 - places));
}

static int
thumb_expand_imm_c(uint16_t imm12) {
    if(bit_range(imm12, 11, 10) == 0) {
        switch(bit_range(imm12, 9, 8)) {
            case 0:
                return bit_range(imm12, 7, 0);
            case 1:
                return (bit_range(imm12, 7, 0) << 16) | bit_range(imm12, 7, 0);
            case 2:
                return (bit_range(imm12, 7, 0) << 24) | (bit_range(imm12, 7, 0) << 8);
            case 3:
                return (bit_range(imm12, 7, 0) << 24) | (bit_range(imm12, 7, 0) << 16) | (bit_range(imm12, 7, 0) << 8) | bit_range(imm12, 7, 0);
            default:
                return 0;
        }
    } else {
        uint32_t unrotated_value = 0x80 | bit_range(imm12, 6, 0);
        return ror(unrotated_value, bit_range(imm12, 11, 7));
    }
}

int
insn_is_32bit(uint16_t* i) {
    return (*i & 0xe000) == 0xe000 && (*i & 0x1800) != 0x0;
}


int
insn_is_add_reg(uint16_t* i) {
    if((*i & 0xFE00) == 0x1800)
        return 1;
    else if((*i & 0xFF00) == 0x4400)
        return 1;
    else if((*i & 0xFFE0) == 0xEB00)
        return 1;
    else
        return 0;
}

int
insn_add_reg_rd(uint16_t* i) {
    if((*i & 0xFE00) == 0x1800)
        return (*i & 7);
    else if((*i & 0xFF00) == 0x4400)
        return (*i & 7) | ((*i & 0x80) >> 4) ;
    else if((*i & 0xFFE0) == 0xEB00)
        return (*(i + 1) >> 8) & 0xF;
    else
        return 0;
}

int
insn_add_reg_rm(uint16_t* i) {
    if((*i & 0xFE00) == 0x1800)
        return (*i >> 6) & 7;
    else if((*i & 0xFF00) == 0x4400)
        return (*i >> 3) & 0xF;
    else if((*i & 0xFFE0) == 0xEB00)
        return *(i + 1) & 0xF;
    else
        return 0;
}

int
insn_is_mov_imm(uint16_t* i) {
    if((*i & 0xF800) == 0x2000)
        return 1;
    else if((*i & 0xFBEF) == 0xF04F && (*(i + 1) & 0x8000) == 0)
        return 1;
    else if((*i & 0xFBF0) == 0xF240 && (*(i + 1) & 0x8000) == 0)
        return 1;
    else
        return 0;
}

int
insn_mov_imm_rd(uint16_t* i) {
    if((*i & 0xF800) == 0x2000)
        return (*i >> 8) & 7;
    else if((*i & 0xFBEF) == 0xF04F && (*(i + 1) & 0x8000) == 0)
        return (*(i + 1) >> 8) & 0xF;
    else if((*i & 0xFBF0) == 0xF240 && (*(i + 1) & 0x8000) == 0)
        return (*(i + 1) >> 8) & 0xF;
    else
        return 0;
}

int
insn_mov_imm_imm(uint16_t* i) {
    if((*i & 0xF800) == 0x2000)
        return *i & 0xF;
    else if((*i & 0xFBEF) == 0xF04F && (*(i + 1) & 0x8000) == 0)
        return thumb_expand_imm_c(((*i & 0x0400) << 1) | ((*(i + 1) & 0x7000) >> 4) | (*(i + 1) & 0xFF));
    else if((*i & 0xFBF0) == 0xF240 && (*(i + 1) & 0x8000) == 0)
        return ((*i & 0xF) << 12) | ((*i & 0x0400) << 1) | ((*(i + 1) & 0x7000) >> 4) | (*(i + 1) & 0xFF);
    else
        return 0;
}

int
insn_is_movt(uint16_t* i) {
    return (*i & 0xFBF0) == 0xF2C0 && (*(i + 1) & 0x8000) == 0;
}

int
insn_movt_rd(uint16_t* i) {
    return (*(i + 1) >> 8) & 0xF;
}

int
insn_movt_imm(uint16_t* i) {
    return ((*i & 0xF) << 12) | ((*i & 0x0400) << 1) | ((*(i + 1) & 0x7000) >> 4) | (*(i + 1) & 0xFF);
}

int
insn_is_ldr_imm(uint16_t* i) {
    uint8_t opA = bit_range(*i, 15, 12);
    uint8_t opB = bit_range(*i, 11, 9);
    
    return opA == 6 && (opB & 4) == 4;
}

int
insn_is_ldr_literal(uint16_t *i) {
    return (*i >> 11) == 0b01001;
}

int
insn_is_adr(uint16_t *i) {
    return HAS_BITS(*i, 0b10100 << 11);
}


int
insn_is_pop(uint16_t *i) {
    return (*i >> 9) == 0b1011110;
}

int
insn_is_push(uint16_t *i) {
    return HAS_BITS(*i, 0b1011010 << 9);
}

int
insn_is_thumb2_pop(uint16_t *i) {
    return (*i == 0xe8bd);
}

int
insn_is_thumb2_tst(uint16_t *i) {
    return !insn_is_bl(i) && (((*i >> 5) & ~(0b100000)) == 0b11110000000);
}

int
insn_tst_imm(uint16_t *i) {
    return *(i+1) % (1<<8);
}

int
insn_is_thumb2_push(uint16_t *i) {
    return (*i == 0xe92d);
}

int
insn_is_thumb2_ldr(uint16_t *i) {
    return HAS_BITS(*i, 0b111110001101 << 4);
}

int
insn_ldr_imm_rt(uint16_t* i) {
    return (*i & 7);
}

int
insn_ldr_imm_imm(uint16_t* i) {
    return (((*i >> 6) & 0x1F) << 2);
}

int
insn_thumb2_ldr_imm_imm(uint16_t* i) {
    return *(i+1) % (1<<12);
}

int
insn_is_bl(uint16_t* i) {
    if ((*i & 0xf800) == 0xf000 && (*(i + 1) & 0xd000) == 0xd000) {
        return 1;
    } else if ((*i & 0xf800) == 0xf000 && (*(i + 1) & 0xd001) == 0xc000) {
        return 1;
    } else {
        return 0;
    }
}

int
insn_is_thumb2_branch(uint16_t *i) {
    return (*i >>11 == 0b11110) && (*(i+1)>>15 == 0b1);
}

int
insn_is_thumb_branch(uint16_t *i) {
    return ((*i >>11 == 0b11100) || (*i >>12 == 0b1101));
}

int
insn_is_thumb2_bne(uint16_t *i) {
    return HAS_BITS(*i >>6, 0b1111000001) && (*(i+1)>>15 == 0b1);
}

int
insn_is_thumb2_beqw(uint16_t *i) {
    return HAS_BITS(*i >>6, 0b1111000000) && (*(i+1)>>15 == 0b1);
}

int
insn_is_thumb2_orr(uint16_t *i) {
    return HAS_BITS((*i)>>5, 0b11110000010) && (*(i+1) >> 15 == 0);
}

int
insn_is_thumb2_strw(uint16_t *i) {
    return (*i >> 4) == 0b111110001100;
}

int
insn_is_thumb2_add(uint16_t *i) {
    return (((*i >> 5) & ~(1<<5)) == 0b11110001000 && (*(i+1) >> 15) == 0);
}

uint8_t
insn_thumb2_orr_rn(uint16_t *i) {
    return *i % (1<<4);
}

uint8_t
insn_ldr_literal_rt(uint16_t *i) {
    return (*i >> 8) % (1 << 3);
}

uint8_t
insn_ldr_literal_imm(uint16_t *i) {
    return *i % (1 << 8);
}

uint8_t
insn_adr_rd(uint16_t *i) {
    return (*i >> 8) % (1 << 3);
}

uint8_t
insn_adr_imm(uint16_t *i) {
    return *i % (1 << 8);
}

uint8_t
insn_thumb2_orr_rd(uint16_t *i) {
    return (*(i+1) >> 8) % (1 << 4);
}

uint8_t
insn_thumb2_orr_imm(uint16_t *i) {
    return *(i+1) % (1<<8);
}

uint8_t
insn_thumb2_strw_rn(uint16_t *i) {
    return *i % (1<<4);
}

uint8_t
insn_thumb2_strw_rt(uint16_t *i) {
    return *(i+1) >> 12;
}

uint8_t
insn_thumb2_strw_imm(uint16_t *i) {
    return *(i+1) % (1 << 12);
}

uint8_t
insn_thumb2_add_rn(uint16_t *i) {
    return *i % (1 << 4);
}

uint8_t
insn_thumb2_add_rd(uint16_t *i) {
    return (*(i+1) >> 8) % (1 << 4);
}

uint8_t
insn_thumb2_add_imm(uint16_t *i) {
    return *(i+1) % (1 << 8);
}

uint32_t
insn_thumb2_branch_imm(uint16_t *i) {
    uint32_t imm6 = (*i % (1<<6));
    uint32_t imm11 = *(i+1) % (1<<11);
    return (imm6<<11) | imm11;
}

uint32_t
insn_thumb_branch_imm(uint16_t *i) {
    if (*i >>11 == 0b11100) {
        return *i % (1<<11);
    }else{
        return *i % (1<<8);
    }
}

uint32_t
insn_bl_imm32(uint16_t* i) {
    uint16_t insn0 = *i;
    uint16_t insn1 = *(i + 1);
    uint32_t s = (insn0 >> 10) & 1;
    uint32_t j1 = (insn1 >> 13) & 1;
    uint32_t j2 = (insn1 >> 11) & 1;
    uint32_t i1 = ~(j1 ^ s) & 1;
    uint32_t i2 = ~(j2 ^ s) & 1;
    uint32_t imm10 = insn0 & 0x3ff;
    uint32_t imm11 = insn1 & 0x7ff;
    uint32_t imm32 = (imm11 << 1) | (imm10 << 12) | (i2 << 22) | (i1 << 23) | (s ? 0xff000000 : 0);
    return imm32;
}

uint16_t *
find_rel_branch_ref(uint16_t* start, size_t len, int step, int (*branch_check_func)(uint16_t*), int32_t (*branch_imm_func)(uint16_t*)) {
    for (uint16_t *i = start; len > sizeof(uint16_t); len -= abs(step) * sizeof(uint16_t), i += step) {
        if (branch_check_func(i)) {
            int32_t imm = (branch_imm_func(i)+2)*2;
            uint8_t *dst = imm + (uint8_t*)i;
            if (dst == (uint8_t*)start) {
                return i;
            }
        }
    }
    return 0;
}

uint16_t*
find_literal_ref(uint32_t region, uint8_t* kdata, size_t ksize, uint32_t address) {
    
    for (uint16_t *p = (uint16_t*)kdata; (uintptr_t)p < (uintptr_t)kdata + ksize; p++) {
        if (insn_add_reg_rm(p) == 15){
            int rd = insn_add_reg_rd(p);
            uint32_t val = 0;
            uint8_t* pc = (uint8_t*)((uint8_t*)p - kdata + region);
            for (uint16_t *pp = p; (uintptr_t)pp > (uintptr_t)kdata; pp--) {
                
                if (insn_is_32bit(pp) && insn_is_movt(pp) && insn_movt_rd(pp) == rd && !(val >> 16)){
                    val |= insn_movt_imm(pp) << 16;
                } else if (insn_is_32bit(pp) && insn_is_mov_imm(pp) && insn_mov_imm_rd(pp) == rd && !(val & ((1 << 16) - 1))){
                    val |= insn_mov_imm_imm(pp);
                } else if (insn_is_ldr_literal(pp) && insn_ldr_literal_rt(pp) == rd){
                    val = (insn_ldr_literal_imm(pp) * 4 + 2);
                    if (insn_is_32bit(pp))
                        val += 2;
                    val = *(uint32_t*)(((uintptr_t)p + val) & ~3);
                    break;
                } else if (insn_is_push(pp)){
                    val = 0;
                    break;
                }
                if (val >> 16 && (val & ((1 << 16) - 1)))
                    break;
            }
            if (!val) {
                continue;
            }
            uint8_t* ref = pc + 4 + val;
            if ((uintptr_t)ref == address + region)
                return p;
        }
    }
    return 0;
}
