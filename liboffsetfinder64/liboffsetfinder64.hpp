//
//  offsetfinder64.hpp
//  offsetfinder64
//
//  Created by tihmstar on 10.01.18.
//  Copyright © 2018 tihmstar. All rights reserved.
//

#ifndef offsetfinder64_hpp
#define offsetfinder64_hpp

#include <string>
#include <stdint.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <mach-o/dyld_images.h>
#include <vector>

#include <stdlib.h>
#include <liboffsetfinder64/common.h>
#include <liboffsetfinder64/insn.hpp>
#include <liboffsetfinder64/exception.hpp>
#include <liboffsetfinder64/patch.hpp>

namespace tihmstar {
    class offsetfinder64 {
    public:
        enum tristate{
            kfalse = 0,
            ktrue = 1,
            kuninitialized = 2
        };
    private:
        bool _freeKernel;
        uint8_t *_kdata;
        size_t _ksize;
        patchfinder64::loc_t _kernel_entry;
        std::vector<patchfinder64::text_t> _segments;
        tristate _haveSymtab = kuninitialized;

        using loc_t = patchfinder64::loc_t;
        struct {
            loc_t _gPhysBase;
            loc_t _kernel_pmap;
            loc_t _cpacr_write;
            loc_t _idlesleep_str_loc;
            loc_t _deepsleep_str_loc;
            patchfinder64::patch _i_can_has_debugger_patch_off;
            std::vector<patchfinder64::patch> _nosuid_off;
            patchfinder64::patch _remount_patch_offset;
            patchfinder64::patch _lwvm_patch_offsets;
            patchfinder64::patch _proc_enforce;
            patchfinder64::patch _amfi_patch_offsets;
            patchfinder64::patch _cs_enforcement_disable_amfi;
            patchfinder64::patch _amfi_substrate_patch;
            patchfinder64::patch _nonceEnabler_patch;
            patchfinder64::loc_t _sbops;
            loc_t _release_arm;
            patchfinder64::loc_t _bcopy;
        };
        
        struct symtab_command *__symtab;
        void loadSegments();
        __attribute__((always_inline)) struct symtab_command *getSymtab();
        
    public:
        offsetfinder64(const char *filename);
        offsetfinder64(void* buf, size_t size);
        const void *kdata();
        patchfinder64::loc_t find_entry();
        const std::vector<patchfinder64::text_t> &segments(){return _segments;};
        bool haveSymbols();
        
        patchfinder64::loc_t memmem(const void *little, size_t little_len);
        
        patchfinder64::loc_t find_sym(const char *sym);
        patchfinder64::loc_t find_syscall0();
        uint64_t             find_register_value(patchfinder64::loc_t where, int reg, patchfinder64::loc_t startAddr = 0);
        
        /*------------------------ v0rtex -------------------------- */
        patchfinder64::loc_t find_zone_map();
        patchfinder64::loc_t find_kernel_map();
        patchfinder64::loc_t find_kernel_task();
        patchfinder64::loc_t find_realhost();
        patchfinder64::loc_t find_bzero();
        patchfinder64::loc_t _find_bcopy();
        patchfinder64::loc_t find_copyout();
        patchfinder64::loc_t find_copyin();
        patchfinder64::loc_t find_ipc_port_alloc_special();
        patchfinder64::loc_t find_ipc_kobject_set();
        patchfinder64::loc_t find_ipc_port_make_send();
        patchfinder64::loc_t find_chgproccnt();
        patchfinder64::loc_t find_kauth_cred_ref();
        patchfinder64::loc_t find_osserializer_serialize();
        patchfinder64::loc_t _find_release_arm();
        uint32_t             find_vtab_get_external_trap_for_index();
        uint32_t             find_vtab_get_retain_count();
        uint32_t             find_iouserclient_ipc();
        uint32_t             find_ipc_space_is_task();
        uint32_t             find_proc_ucred();
        uint32_t             find_task_bsd_info();
        uint32_t             find_vm_map_hdr();
        uint32_t             find_task_itk_self();
        uint32_t             find_task_itk_registered();
        uint32_t             find_sizeof_task();
        
        patchfinder64::loc_t find_rop_add_x0_x0_0x10();
        patchfinder64::loc_t find_rop_add_x0_x0_0x40();
        patchfinder64::loc_t find_rop_ldr_x0_x0_0x10();
        patchfinder64::loc_t find_IOMalloc();
        patchfinder64::loc_t find_IOFree();
        
        /*------------------------ kernelpatches -------------------------- */
        patchfinder64::patch _find_i_can_has_debugger_patch_off();
        patchfinder64::patch _find_lwvm_patch_offsets();
        patchfinder64::patch _find_remount_patch_offset();
        std::vector<patchfinder64::patch> _find_nosuid_off();
        patchfinder64::patch _find_proc_enforce();
        patchfinder64::patch _find_amfi_patch_offsets();
        patchfinder64::patch _find_cs_enforcement_disable_amfi();
        patchfinder64::patch _find_amfi_substrate_patch();
        patchfinder64::patch find_sandbox_patch();
        patchfinder64::loc_t _find_sbops();
        patchfinder64::patch _find_nonceEnabler_patch();
        patchfinder64::patch find_nonceEnabler_patch_nosym();
        
        inline std::vector<patchfinder64::patch> all_patches() {
            return {
                find_i_can_has_debugger_patch_off(),
                find_remount_patch_offset(),
                find_lwvm_patch_offsets(),
                _nosuid_off.at(0),
                _nosuid_off.at(1),
                find_proc_enforce(),
                find_amfi_patch_offsets(),
                find_cs_enforcement_disable_amfi(),
                find_amfi_substrate_patch(),
                find_nonceEnabler_patch()
            };
        }

        
        /*------------------------ KPP bypass -------------------------- */
        patchfinder64::loc_t _find_gPhysBase();
        patchfinder64::loc_t _find_kernel_pmap();
        patchfinder64::loc_t find_kernel_pmap_nosym();
        patchfinder64::loc_t _find_cpacr_write();
        patchfinder64::loc_t _find_idlesleep_str_loc();
        patchfinder64::loc_t _find_deepsleep_str_loc();
        
        inline patchfinder64::loc_t linker_base() {
            return (loc_t)0xfffffff007004000;
        }
        
        inline patchfinder64::loc_t find_bcopy() {
            return _bcopy;
        }
        inline patchfinder64::loc_t find_gPhysBase() {
            return _gPhysBase;
        }
        inline patchfinder64::loc_t find_kernel_pmap() {
            return _kernel_pmap;
        }
        inline patchfinder64::loc_t find_cpacr_write() {
            return _cpacr_write;
        }
        inline patchfinder64::loc_t find_idlesleep_str_loc() {
            return _idlesleep_str_loc;
        }
        inline patchfinder64::loc_t find_deepsleep_str_loc() {
            return _deepsleep_str_loc;
        }
        inline const patchfinder64::patch &find_i_can_has_debugger_patch_off() const {
            return _i_can_has_debugger_patch_off;
        }
        inline patchfinder64::patch find_lwvm_patch_offsets() {
            return _lwvm_patch_offsets;
        }
        constexpr inline const patchfinder64::patch &find_remount_patch_offset() const {
            return _remount_patch_offset;
        }
        constexpr inline const std::vector<patchfinder64::patch> &find_nosuid_off() const {
            return _nosuid_off;
        }
        inline patchfinder64::patch find_proc_enforce() {
            return _proc_enforce;
        }
        inline patchfinder64::patch find_amfi_patch_offsets() {
            return _amfi_patch_offsets;
        }
        inline patchfinder64::patch find_cs_enforcement_disable_amfi() {
            return _cs_enforcement_disable_amfi;
        }
        inline patchfinder64::patch find_amfi_substrate_patch() {
            return _amfi_substrate_patch;
        }
        constexpr inline patchfinder64::loc_t find_sbops() const {
            return _sbops;
        }
        inline patchfinder64::patch find_nonceEnabler_patch() {
            return _nonceEnabler_patch;
        }
        inline patchfinder64::loc_t find_release_arm() {
            return _release_arm;
        }

        /*------------------------ Util -------------------------- */
        patchfinder64::loc_t find_rootvnode();
        
        ~offsetfinder64();
    };
}



#endif /* offsetfinder64_hpp */
