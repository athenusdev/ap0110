//
//  offsetfinder32.cpp
//  sockH3lix
//
//  Created by SXX on 2020/12/19.
//  Copyright © 2020 tihmstar. All rights reserved.
//

#if !__arm64__

#include "offsetfinder32.hpp"
#include "lzssdec.hpp"
#include <cstdio>
#include <cstdlib>
#include "img3dec.hpp"
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <cstring>
#include <cassert>
#include "patchfinder32.h"

#define find_str(base, ksize, str, null_end) (uint8_t*)memmem(base, ksize, str, null_end ? sizeof(str) : sizeof(str) - 1)

using namespace CR;
using patch = tihmstar::patchfinder64::patch;

static void
slide_ptr(patch *p, uintptr_t slide) {
    slide += *(uintptr_t*)p->_patch;
    memcpy((void*)p->_patch, &slide, 8);
}

offsetfinder32::offsetfinder32(const char *filename) {
    struct FILE_RAII {
        FILE *file;
        FILE_RAII(const char *c, const char *r) : file(fopen(c, r)) {
            if (file == NULL) {
                throw 1;
            }
        }
        ~FILE_RAII() {
            if (file != NULL) {
                fclose(file);
                file = NULL;
            }
        }
    };
    FILE_RAII file(filename, "r");
    
    struct DATA_RAII {
        void *data;
        ~DATA_RAII() {
            if (data != NULL) {
                free(data);
                data = NULL;
            }
        }
    };
    DATA_RAII kdata;
    size_t file_size;
    addr_t min = -1;
    addr_t max = 0;
    decompress_kernel_32(file.file, kdata.data, file_size);
    
    if (*(uint32_t*)kdata.data == MH_MAGIC) {
        const struct mach_header *hdr = (struct mach_header *)kdata.data;
        const uint8_t *q = (uint8_t*)kdata.data + sizeof(struct mach_header);
        
        for (uint32_t i = 0; i < hdr->ncmds; i++) {
            const struct load_command *cmd = (struct load_command *)q;
            if (cmd->cmd == LC_SEGMENT && ((struct segment_command *)q)->vmsize) {
                const struct segment_command *seg = (struct segment_command *)q;
                if (min > seg->vmaddr) {
                    min = seg->vmaddr;
                }
                if (max < seg->vmaddr + seg->vmsize) {
                    max = seg->vmaddr + seg->vmsize;
                }
                if (!strcmp(seg->segname, "__TEXT_EXEC")) {
                    xnucore_base = seg->vmaddr;
                    xnucore_size = seg->filesize;
                } else if (!strcmp(seg->segname, "__PLK_TEXT_EXEC")) {
                    prelink_base = seg->vmaddr;
                    prelink_size = seg->filesize;
                } else if (!strcmp(seg->segname, "__PPLTEXT")) {
                    pplcode_base = seg->vmaddr;
                    pplcode_size = seg->filesize;
                } else if (!strcmp(seg->segname, "__TEXT")) {
                    const struct section *sec = (struct section *)(seg + 1);
                    for (uint32_t j = 0; j < seg->nsects; j++) {
                        if (!strcmp(sec[j].sectname, "__cstring")) {
                            cstring_base = sec[j].addr;
                            cstring_size = sec[j].size;
                        } else if (!strcmp(sec[j].sectname, "__os_log")) {
                           oslstring_base = sec[j].addr;
                           oslstring_size = sec[j].size;
                        } else if (!strcmp(sec[j].sectname, "__const")) {
                           const_base = sec[j].addr;
                           const_size = sec[j].size;
                        }
                    }
                } else if (!strcmp(seg->segname, "__PRELINK_TEXT")) {
                    const struct section *sec = (struct section *)(seg + 1);
                    for (uint32_t j = 0; j < seg->nsects; j++) {
                        if (!strcmp(sec[j].sectname, "__text")) {
                            pstring_base = sec[j].addr;
                            pstring_size = sec[j].size;
                        }
                    }
                } else if (!strcmp(seg->segname, "__DATA")) {
                    const struct section *sec = (struct section *)(seg + 1);
                    for (uint32_t j = 0; j < seg->nsects; j++) {
                        if (!strcmp(sec[j].sectname, "__data")) {
                            data_base = sec[j].addr;
                            data_size = sec[j].size;
                        }
                    }
                }
            }
            if (cmd->cmd == LC_UNIXTHREAD) {
                uint32_t *ptr = (uint32_t *)(cmd + 1);
                uint32_t flavor = ptr[0];
                struct {
                    uint32_t    r[13];    /* General purpose register r0-r12 */
                    uint32_t    sp;        /* Stack pointer r13 */
                    uint32_t    lr;        /* Link register r14 */
                    uint32_t    pc;        /* Program counter r15 */
                    uint32_t    cpsr;        /* Current program status register */
                } *thread = (typeof(thread))(ptr + 2);
                
                if (flavor == 6) {
                    kernel_entry = thread->pc;
                }
            }
            q = q + cmd->cmdsize;
        }
        
        if (pstring_base == 0 && pstring_size == 0) {
            pstring_base = cstring_base;
            pstring_size = cstring_size;
        }
        if (prelink_base == 0 && prelink_size == 0) {
            prelink_base = xnucore_base;
            prelink_size = xnucore_size;
        }

        kerndumpbase = min;
        xnucore_base -= kerndumpbase;
        prelink_base -= kerndumpbase;
        pplcode_base -= kerndumpbase;
        cstring_base -= kerndumpbase;
        pstring_base -= kerndumpbase;
        oslstring_base -= kerndumpbase;
        data_base -= kerndumpbase;
        const_base -= kerndumpbase;
        kernel_size = max - min;
        
        printf("kernel_size: %zu\n", kernel_size);
        kernel = (uint8_t*)calloc(1, kernel_size);
        if (!kernel) {
            throw -8;
        }

        q = (uint8_t*)kdata.data + sizeof(struct mach_header);
        for (uint8_t i = 0; i < hdr->ncmds; i++) {
            const struct load_command *cmd = (struct load_command *)q;
            if (cmd->cmd == LC_SEGMENT) {
                const struct segment_command *seg = (struct segment_command *)q;
                //size_t sz = pread(fd, kernel + seg->vmaddr - min, seg->filesize, seg->fileoff);
                memcpy(kernel + seg->vmaddr - min, (uint8_t*)kdata.data + seg->fileoff, seg->filesize);
                /*if (sz != seg->filesize) {
                    free(kernel);
                    kernel = NULL;
                    throw -9;
                }*/
                if (!kernel_mh) {
                    kernel_mh = kernel + seg->vmaddr - min;
                }
                if (!strcmp(seg->segname, "__PPLDATA")) {
                    //auth_ptrs = true;
                } else if (!strcmp(seg->segname, "__LINKEDIT")) {
                    kernel_delta = seg->vmaddr - min - seg->fileoff;
                }
            }
            q = q + cmd->cmdsize;
        }
    }
    _bcopy = find_symbol("_bcopy");
    printf("%p\n", _bcopy);
    printf("%p\n", find_zone_map());
    printf("%p\n", find_kernel_map());
    printf("%p\n", find_realhost());
    printf("%p\n", find_kernel_task());
    printf("%zd\n", find_sizeof_task());
    printf("%d\n", find_proc_ucred());
    printf("%p\n", find_rop_add_r0_r0_0x40());
    printf("%p\n", find_IOFree());
    printf("%p\n", find_IOMalloc());
    printf("%lu\n", find_vtab_get_external_trap_for_index());
    
    _release_arm = _find_release_arm();
    _sbops = _find_sbops();
    _bcopy_phys = _find_bcopy_phys();
    _pmap_find_phys = _find_pmap_find_phys();
    _kernel_pmap = _find_kernel_pmap();
    
    _amfi_substrate_patch = _find_amfi_substrate_patch();
    _i_can_has_debugger_patch_off = _find_i_can_has_debugger_patch_off();
    _proc_enforce = _find_proc_enforce();
    _cs_enforcement_disable_amfi = _find_cs_enforcement_disable_amfi();
    _remount_patch_offset = _find_remount_patch_offset();
    _nosuid_off = _find_nosuid_off();
    _amfi_patch_offsets = _find_amfi_patch_offsets();
    _lwvm_patch_offsets = _find_lwvm_patch_offsets();
    printf("bcopy_phys %p\n", _bcopy_phys);
}

loc_t
offsetfinder32::find_symbol(const char *symbol) const {
    if (!symbol) {
        return 0;
    }
    
    unsigned i;
    const struct mach_header *hdr = (typeof(hdr))kernel_mh;
    const uint8_t *q;

/* XXX will only work on a decrypted kernel */
    if (!kernel_delta) {
        return 0;
    }
    /* XXX I should cache these.  ohwell... */
    q = (uint8_t *)(hdr + 1);
    for (i = 0; i < hdr->ncmds; i++) {
        const struct load_command *cmd = (struct load_command *)q;
        if (cmd->cmd == LC_SYMTAB) {
            const struct symtab_command *sym = (struct symtab_command *)q;
            const char *stroff = (const char *)kernel + sym->stroff + kernel_delta;
                const struct nlist *s = (struct nlist *)(kernel + sym->symoff + kernel_delta);
            for (uint32_t k = 0; k < sym->nsyms; k++) {
                if (s[k].n_type & N_STAB) {
                    continue;
                }
                if (s[k].n_value && (s[k].n_type & N_TYPE) != N_INDR) {
                    if (!strcmp(symbol, stroff + s[k].n_un.n_strx)) {
                        return (loc_t)s[k].n_value;
                    }
                }
            }
        }
        q = q + cmd->cmdsize;
    }
    return 0;
}

loc_t
offsetfinder32::find_zone_map() const {
    uint8_t *base = kernel;
    uint8_t *ptr = find_str(kernel, kernel_size, "zone_init", true);
    uint16_t *ref = find_literal_ref((uint32_t)linker_base(), kernel, kernel_size, ptr-(uint8_t*)kernel);
    
    uint32_t val = 0;
    int rd = -1;
    while (!(val >> 16 && (val & ((1<<16)-1)))){
        if (insn_is_mov_imm(ref)){
            int trd = insn_movt_rd(ref);
            if (rd != trd && rd != -1){
                ref++;
                continue;
            }
            else
                rd = trd;
            val |= insn_mov_imm_imm(ref++);
        }else if (insn_is_movt(ref)){
            int trd = insn_movt_rd(ref);
            if (rd != trd && rd != -1){
                ref++;
                continue;
            }else
                rd = trd;
            val |= insn_movt_imm(ref++) << 16;
        }
        ref++;
    }
    while (!insn_is_add_reg(ref))
        ref++;
    
    if (insn_add_reg_rd(ref) != rd || insn_add_reg_rm(ref) != 15)
        return 0;
    
    return (((uint8_t*)ref+4+val) - base) + linker_base();
}

uintptr_t
offsetfinder32::find_vtab_get_external_trap_for_index() const {
    uint32_t *vtab_IOUserClient = (uint32_t*)((find_symbol("__ZTV12IOUserClient") - linker_base()) + kernel);
    assert(vtab_IOUserClient != NULL);
    vtab_IOUserClient += 2;
    
    uint32_t getExternalTrapForIndex = (uint32_t)find_symbol("__ZN12IOUserClient23getExternalTrapForIndexEm");
    assert(getExternalTrapForIndex != 0);
    for (int i = 0; i < 0x200; i++) {
        if (vtab_IOUserClient[i]==getExternalTrapForIndex + 1) {
            return i;
        }
    }
    return -1;
}

loc_t
offsetfinder32::_find_kernel_map() const {
    return find_symbol("_kernel_map");
}

loc_t
offsetfinder32::find_realhost() const {
    uint8_t *n = find_symbol("_KUNCExecute");
    assert(n);
    uint16_t *ref = (uint16_t*)(n - linker_base() + kernel);

    uint32_t val = 0;
    int rd = -1;
    while (!(val >> 16 && (val & ((1 << 16) - 1)))){
        if (insn_is_mov_imm(ref)){
            int trd = insn_movt_rd(ref);
            if (rd != trd && rd != -1){
                ref++;
                continue;
            }else
                rd = trd;
            val |= insn_mov_imm_imm(ref++);
        }else if (insn_is_movt(ref)){
            int trd = insn_movt_rd(ref);
            if (rd != trd && rd != -1){
                ref++;
                continue;
            }else
                rd = trd;
            val |= insn_movt_imm(ref++) << 16;
        }
        ref++;
    }
    while (!insn_is_add_reg(ref))
        ref++;
    
    if (insn_add_reg_rd(ref) != rd || insn_add_reg_rm(ref) != 15)
        return 0;
    return (uint8_t*)ref - kernel + linker_base();
}

loc_t
offsetfinder32::find_kernel_task() const {
    return find_symbol("_kernel_task");
}

size_t
offsetfinder32::find_sizeof_task() const {
    uint8_t *base = kernel;
    size_t ksize = kernel_size;
    uint8_t *ptr = find_str(base, ksize, "tasks", true);
    uint16_t *ref = find_literal_ref((uint32_t)linker_base(), base, ksize, (uint32_t)(ptr - base));
    assert(ref);
    ref++;
    
    uint16_t *zinit = 0;
    
    zinit = (uint16_t*)(find_symbol("_zinit") - linker_base() + kernel);
    if (zinit) {
        
    } else if ((ptr = find_str(base, ksize, "zlog%d", true))){
        uint16_t *ref2 = find_literal_ref((uint32_t)linker_base(), base, ksize, (uint32_t)(ptr - base));
        if (ref2) {
            while (!insn_is_thumb2_push(--ref2));
            while (!insn_is_push(--ref2));
            zinit = ref2;
        }
    }

    uint16_t *bl = ref+2;
    while (!insn_is_bl(bl))
        bl++;
    
    while (!insn_is_mov_imm(ref))
        ref++;
    
    assert(insn_is_mov_imm(ref) && insn_is_bl(bl));
    
    if (zinit) {
        assert(insn_bl_imm32((uint16_t*)bl) + 4 + (uint8_t*)bl == (uint8_t*)zinit);
    } else {
        fprintf(stderr, "WARNING: can't find zinit. Can't verify sizeof_task\n");
    }
    
    return insn_mov_imm_imm(ref);
}

uint32_t
offsetfinder32::find_proc_ucred() const {
    loc_t s = find_symbol("_proc_ucred");
    assert(s != NULL);
    
    return (*(uint32_t *)(kernel + ((addr_t)s - kerndumpbase))) >> 16;
}

loc_t
offsetfinder32::find_rop_add_r0_r0_0x40() const {
    uint8_t *base = kernel;
    size_t ksize = kernel_size;
    uint8_t *p = find_str(base, ksize, "\x10\x46\x70\x47", false);
    if (!p) {
        return 0;
    }
    return (p - base) + linker_base();
}

loc_t
offsetfinder32::find_IOMalloc() const {
    return find_symbol("_IOMalloc");
}

loc_t
offsetfinder32::find_IOFree() const {
    return find_symbol("_IOFree");
}

loc_t
offsetfinder32::find_gPhysBase() const {
    //ml_static_ptovirt
    return (loc_t)0x80456118;
}

loc_t
offsetfinder32::_find_bcopy_phys() const {
    return find_symbol("_bcopy_phys");
}

loc_t
offsetfinder32::_find_pmap_find_phys() const {
    return find_symbol("_pmap_find_phys");
}

loc_t
offsetfinder32::_find_kernel_pmap() const {
    return find_symbol("_kernel_pmap");
}

loc_t
offsetfinder32::find_panic() const {
    return find_symbol("_panic");
}

loc_t
offsetfinder32::_find_release_arm() const {
    uint8_t *ptr = find_str(kernel, kernel_size, "RELEASE_ARM", false);
    return ptr - kernel + linker_base();
}

static uint16_t
*find_rel_beqw_source(uint8_t *base, uint16_t *ref, bool searchUp) {
    uint16_t *dst = ref;
    while (true) {
        if (searchUp) {
            while (!(insn_is_thumb2_beqw(--ref))) {}
        } else {
            while (!(insn_is_thumb2_beqw(++ref))) {}
        }
        uint32_t imm;
        
        imm = insn_thumb2_branch_imm(ref);
        
        if (imm + ref + 2 == dst) {
            return ref;
        }
    }
}

static uint16_t
*find_rel_branch_source(uint8_t *base, uint16_t *ref, bool searchUp) {
    uint16_t *dst = ref;
    while (true) {
        if (searchUp) {
            while (!(insn_is_thumb_branch(--ref))) {}
        } else {
            while (!(insn_is_thumb_branch(++ref))) {}
        }
        uint32_t imm;
        
        imm = insn_thumb_branch_imm(ref);
        
        if (imm + ref + 2 == dst) {
            return ref;
        }
    }
}

static constexpr uint8_t thumb_nop[2] = {0, 0xbf};
static constexpr uint8_t double_thumb_nop[4] = {0, 0xbf, 0, 0xbf};

patch
offsetfinder32::find_sandbox_patch() {
    uint8_t *base = kernel;
    size_t ksize = kernel_size;
    uint8_t *ptr = find_str(base, ksize, "process-exec denied while updating label", true);
    uint16_t *ref = find_literal_ref((uint32_t)linker_base(), base, ksize, (uint32_t)(ptr - base));
    
    for (int i = 0; i < 3; i++) {
        while(!insn_is_bl(--ref)) {}
    }
    
    --ref;
    uint16_t *beq_w = find_rel_beqw_source(base, ref, true);
    //iOS10.3.4 iPhone 5 0x80fc28da
    loc_t patch_loc = (loc_t)((uintptr_t)beq_w - (uintptr_t)kernel + (uintptr_t)linker_base());
    printf("sandbox patch: %p\n", patch_loc);
    
    return patch(patch_loc, double_thumb_nop, sizeof(double_thumb_nop));
}

std::vector<patch>
offsetfinder32::_find_amfi_substrate_patch() {
    uint8_t *base = kernel;
    size_t ksize = kernel_size;
    uint8_t *ptr = find_str(base, ksize, "AMFI: hook..execve() killing pid %u: %s", false);
    uint16_t *ref = find_literal_ref((uint32_t)linker_base(), base, ksize, (uint32_t)(ptr - base));
    uint16_t *funcend = ref;
    
    while (*(++funcend) != 0xbdf0) {}
    
    uint16_t *tst = funcend;
    while (!insn_is_thumb2_tst(--tst)) {}
    uint16_t *mov_r0 = funcend;
    while (*(--mov_r0) != 0x2000) {} //thumb movs r0, #0
    
    uint16_t *branch = find_rel_branch_source(base, mov_r0, true);
    uint16_t b = *branch - (mov_r0 - tst - 1);
    
    
    std::vector<patch> ret;
    ret.push_back(patch((loc_t)((uintptr_t)branch - (uintptr_t)base + (uintptr_t)linker_base()), (uint8_t *)&(b), 2));
    static const uint8_t patch_code[] = {0x20, 0xF4, 0x00, 0x70, 0x00, 0xBF};
    ret.push_back(patch((loc_t)((uintptr_t)tst - (uintptr_t)base + (uintptr_t)linker_base()), &patch_code, sizeof(patch_code)));
    return ret;
}

patch
offsetfinder32::_find_i_can_has_debugger_patch_off() {
    uint8_t *base = kernel;
    size_t ksize = kernel_size;
    uint8_t *ptr = find_str(base, ksize, "Darwin Kernel", false);
    ptr -= 4;
    return {(loc_t)((uintptr_t)ptr - (uintptr_t)base + (uintptr_t)linker_base()), "\x01", 1};
}

loc_t
offsetfinder32::_find_sbops() const {
    uint8_t *base = kernel;
    size_t ksize = kernel_size;
    uint8_t *ptr = find_str(base, ksize, "Seatbelt sandbox policy", false);
    loc_t str = (ptr - base) + linker_base();
    loc_t ref = (loc_t)memmem(kernel, kernel_size, &str, sizeof(str));
    return (loc_t)*(uintptr_t *)(ref + 12);
}

patch
offsetfinder32::_find_proc_enforce() {
    uint8_t *ptr = find_str(kernel, kernel_size, "Enforce MAC policy on process operations", false);
    loc_t value = ptr - kernel + linker_base();
    loc_t valref = (loc_t)memmem(kernel, kernel_size, (char*)&value, sizeof(value));
    loc_t proc_enforce_ptr = valref - (5 * sizeof(uint32_t));
    loc_t proc_enforce_val_loc = (loc_t)*(uint32_t *)proc_enforce_ptr;
    uint8_t mypatch = 1;
    return {proc_enforce_val_loc, &mypatch, 1};
}

patch
offsetfinder32::_find_cs_enforcement_disable_amfi() {
    uint8_t *ptr = find_str(kernel, kernel_size, "csflags", true);
    uint16_t *ref = find_literal_ref((uint32_t)linker_base(), kernel, kernel_size, (uint32_t)(ptr - kernel));
    uint16_t *cbz = ref;
    while (*(--cbz) != 0xb12c); //cbz r4, xxx
    uint16_t *movs = cbz;
    while (*(++movs) != 0x2000); //movs r0, #0
    uint16_t *mypatch = (uint16_t*)alloca(sizeof(uint16_t) * (movs - cbz));
    for (size_t i = 0; i < movs - cbz; i++) {
        mypatch[i] = *(uint16_t*)thumb_nop;
    }
    //0x807ebcca ~ 0x807ebcd2
    return {(loc_t)((uint8_t*)cbz - kernel + linker_base()), (uint8_t*)mypatch, sizeof(uint16_t) * (movs - cbz)};
}

static constexpr size_t syscall_entry_size = 12;

loc_t
offsetfinder32::_find_syscall0() const {
    static constexpr char sig_syscall_3[] = "\x06\x00\x00\x00\x03\x00\x0c\x00";
    uint8_t *ptr = find_str(kernel, kernel_size, sig_syscall_3, false);
    return (ptr - kernel) + linker_base() - 3 * syscall_entry_size + 8;
}

patch
offsetfinder32::_find_remount_patch_offset() {
    loc_t off = _find_syscall0();
    loc_t syscall_mac_mount = (loc_t)((uint32_t)((off + (424 - 1) * syscall_entry_size)) & ~1);
    loc_t __mac_mount = (loc_t)(*(uint32_t*)(syscall_mac_mount - linker_base() + kernel) & ~1);
    uint16_t *patchloc = (uint16_t *)(__mac_mount - linker_base() + kernel);
    while (!(*(++patchloc) == 0xf010 && *(patchloc + 1) == 0x0f40)) {}
    patchloc -= 2;
    //iOS 10.3.4 iPhone5 0x801030DA
    // ->
    //mov.w r0, #6
    static constexpr uint8_t mypatch[] = "\x4f\xf0\x06\x00";
    return {(uint8_t*)patchloc - kernel + linker_base(), mypatch, sizeof(mypatch) - 1};
}

std::vector<patch>
offsetfinder32::_find_nosuid_off() {
    uint8_t *ptr = find_str(kernel, kernel_size, "\"mount_common(): mount of %s filesystem failed with %d, but vnode list is not empty.\"", false);//0x8039b726
    uint16_t *ref = find_literal_ref((uint32_t)linker_base(), kernel, kernel_size, (uint32_t)(ptr - kernel));
    uint16_t *ldr = ref;
    while (!insn_is_thumb2_ldr(--ldr));
    
    //uint16_t *cbnz = find_rel_branch_source(kernel, ldr, true);
    uint16_t *bl_vfs_context_is64bit = ldr;
    loc_t _vfs_context_is64bit = find_symbol("_vfs_context_is64bit");
    while (!(insn_is_bl(--bl_vfs_context_is64bit) && (loc_t)(insn_bl_imm32(bl_vfs_context_is64bit) + (uint8_t*)bl_vfs_context_is64bit) - kernel + 4 + linker_base() == _vfs_context_is64bit)) {}
    //bl_vfs_context_is64bit 0x801020d4
    
    uint16_t *orr_w = bl_vfs_context_is64bit;
    while (*(--orr_w) != 0xf040 || *(orr_w + 1) != 0x0008); //orr.w r0, r0, #8
    
    uint16_t *orr = bl_vfs_context_is64bit;
    while (*(--orr) != 0xf040 || *(orr + 1) != 0x0108); //orr.w r1, r0, #8
    static constexpr uint8_t patch2[] = {0x01, 0x46, 0x00, 0xbf};
    
    //orr.w 0x801020b4 -> nop orr: 0x80102098 -> mov r1, r0
    return {
        {(uint8_t*)orr_w - kernel + linker_base(), double_thumb_nop, sizeof(double_thumb_nop)},
        {(uint8_t*)orr - kernel + linker_base(), patch2, sizeof(patch2)}
    };
}

patch
offsetfinder32::_find_amfi_patch_offsets() {
    //bl 0x807ebb38
    //sub_xxx 0x807ec480
    //memcmp_ptr 0x8080910c
    uint8_t *base = kernel;
    size_t ksize = kernel_size;
    //mov.w r0, #0
    //bx lr
    uint8_t *p = find_str(base, ksize, "\x4f\xf0\x00\x00\x70\x47", false);
    
    loc_t gadget = (p - base) + linker_base() + 1;//thumb mode
    loc_t memcmp_ptr = (loc_t)0x8080910c;
    return {memcmp_ptr, (loc_t)&gadget, sizeof(gadget), slide_ptr};
}

//find_nonceEnabler
patch
offsetfinder32::_find_lwvm_patch_offsets() {
    //dstfunc: 0x80cca16e
    loc_t _PE_i_ptr = (loc_t)0x80cd204c;
    //uint8_t *p = find_str(kernel, kernel_size, "\x01\x20\x70\x47", false);
    //loc_t gadget = (p - kernel) + linker_base() + 1;
    loc_t gadget = (loc_t)0x80cca194 + 1;
    return {_PE_i_ptr, (loc_t)&gadget, sizeof(gadget), slide_ptr};
}

#endif
