//
//  patchfinder32.h
//  sockH3lix
//
//  Created by SXX on 2020/12/20.
//  Copyright © 2020 tihmstar. All rights reserved.
//

#ifndef patchfinder32_h
#define patchfinder32_h

#include <sys/cdefs.h>
#include <stdint.h>

__BEGIN_DECLS

int insn_is_32bit(uint16_t* i);

int insn_is_add_reg(uint16_t* i);
int insn_add_reg_rd(uint16_t* i);
int insn_add_reg_rm(uint16_t* i);

int insn_is_mov_imm(uint16_t* i);
int insn_mov_imm_rd(uint16_t* i);
int insn_mov_imm_imm(uint16_t* i);

int insn_is_movt(uint16_t* i);
int insn_movt_rd(uint16_t* i);
int insn_movt_imm(uint16_t* i);

int insn_is_ldr_imm(uint16_t* i);
int insn_ldr_imm_rt(uint16_t* i);
int insn_ldr_imm_imm(uint16_t* i);
int insn_thumb2_ldr_imm_imm(uint16_t* i);


int insn_is_bl(uint16_t* i);
int insn_is_thumb2_branch(uint16_t *i);
int insn_is_thumb_branch(uint16_t *i);
int insn_is_thumb2_bne(uint16_t *i);
int insn_is_thumb2_beqw(uint16_t *i);
int insn_is_thumb2_orr(uint16_t *i);
int insn_is_thumb2_strw(uint16_t *i);
int insn_is_thumb2_add(uint16_t *i);
int insn_is_ldr_literal(uint16_t *i);

int insn_is_adr(uint16_t *i);


uint8_t insn_thumb2_orr_rn(uint16_t *i);
uint8_t insn_thumb2_orr_rd(uint16_t *i);
uint8_t insn_thumb2_orr_imm(uint16_t *i);
uint8_t insn_thumb2_strw_rn(uint16_t *i);
uint8_t insn_thumb2_strw_rt(uint16_t *i);
uint8_t insn_thumb2_strw_imm(uint16_t *i);
uint8_t insn_thumb2_add_rn(uint16_t *i);
uint8_t insn_thumb2_add_rd(uint16_t *i);
uint8_t insn_thumb2_add_imm(uint16_t *i);
uint8_t insn_ldr_literal_rt(uint16_t *i);
uint8_t insn_ldr_literal_imm(uint16_t *i);
uint8_t insn_adr_rd(uint16_t *i);
uint8_t insn_adr_imm(uint16_t *i);

uint32_t insn_thumb2_branch_imm(uint16_t *i);
uint32_t insn_thumb_branch_imm(uint16_t *i);


uint32_t insn_bl_imm32(uint16_t* i);

int insn_is_pop(uint16_t *i);
int insn_is_push(uint16_t *i);
int insn_is_thumb2_ldr(uint16_t *i);
int insn_is_thumb2_pop(uint16_t *i);
int insn_is_thumb2_push(uint16_t *i);
int insn_is_thumb2_tst(uint16_t *i);
int insn_tst_imm(uint16_t *i);

uint16_t *find_literal_ref(uint32_t region, uint8_t* kdata, size_t ksize, uint32_t address);
uint16_t *
find_rel_branch_ref(uint16_t* start, size_t len, int step, int (*branch_check_func)(uint16_t*), int32_t (*branch_imm_func)(uint16_t*));

__END_DECLS

#endif /* patchfinder32_h */
