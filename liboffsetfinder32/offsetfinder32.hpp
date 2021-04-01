//
//  offsetfinder32.hpp
//  sockH3lix
//
//  Created by SXX on 2020/12/19.
//  Copyright © 2020 tihmstar. All rights reserved.
//

#ifndef offsetfinder32_hpp
#define offsetfinder32_hpp

#include <cstdint>
#include <cstddef>
#include <liboffsetfinder64/patch.hpp>
#include <liboffsetfinder64/exception.hpp>

namespace CR {
    typedef uint8_t *loc_t;
    typedef uintptr_t addr_t;
    class offsetfinder32 {
    private:
        using patch = tihmstar::patchfinder64::patch;
        struct {
            loc_t _bcopy;
            loc_t _release_arm;
            loc_t _sbops;
            loc_t _bcopy_phys;
            loc_t _pmap_find_phys;
            loc_t _kernel_map;
            loc_t _kernel_pmap;
            patch _i_can_has_debugger_patch_off;
            std::vector<patch> _amfi_substrate_patch;
            patch _proc_enforce;
            patch _cs_enforcement_disable_amfi;
            patch _remount_patch_offset;
            std::vector<patch> _nosuid_off;
            patch _amfi_patch_offsets;
            patch _lwvm_patch_offsets;
        };
        uint8_t *kernel = NULL;
        size_t kernel_size = 0;
        addr_t xnucore_base = 0;
        addr_t xnucore_size = 0;
        addr_t prelink_base = 0;
        addr_t prelink_size = 0;
        addr_t pplcode_base = 0;
        addr_t pplcode_size = 0;
        addr_t cstring_base = 0;
        addr_t cstring_size = 0;
        addr_t pstring_base = 0;
        addr_t pstring_size = 0;
        addr_t kerndumpbase = -1;
        addr_t kernel_entry = 0;
        void *kernel_mh = 0;
        addr_t kernel_delta = 0;
        addr_t const_base = 0;
        addr_t const_size = 0;
        addr_t oslstring_base = 0;
        addr_t oslstring_size = 0;
        addr_t data_base = 0;
        addr_t data_size = 0;
        
        loc_t find_symbol(const char *symbol) const;
        loc_t _find_syscall0() const;
        
        std::vector<patch> _find_amfi_substrate_patch();
        patch _find_i_can_has_debugger_patch_off();
        patch _find_lwvm_patch_offsets();
        patch _find_proc_enforce();
        patch _find_cs_enforcement_disable_amfi();
        patch _find_remount_patch_offset();
        std::vector<patch> _find_nosuid_off();
        patch _find_amfi_patch_offsets();
        
        loc_t _find_release_arm() const;
        loc_t _find_kernel_map() const;
        loc_t _find_sbops() const;
        loc_t _find_bcopy_phys() const;
        loc_t _find_pmap_find_phys() const;
        loc_t _find_kernel_pmap() const;
    public:
        offsetfinder32(const char *filename);
        
        inline loc_t linker_base() const {
            return (loc_t)0x80001000;
        }
        
        constexpr inline loc_t find_kernel_map() const {
            return _kernel_map;
        }
        constexpr inline loc_t find_bcopy() const {
            return _bcopy;
        }
        constexpr inline loc_t find_release_arm() const {
            return _release_arm;
        }
        constexpr inline loc_t find_sbops() const {
            return _sbops;
        }
        constexpr inline loc_t find_bcopy_phys() const {
            return _bcopy_phys;
        }
        constexpr inline loc_t find_pmap_find_phys() const {
            return _pmap_find_phys;
        }
        constexpr inline loc_t find_kernel_pmap() const {
            return _kernel_pmap;
        }
        
        constexpr inline const patch &find_i_can_has_debugger_patch_off() const {
            return _i_can_has_debugger_patch_off;
        }
        
        
        loc_t find_zone_map() const;
        
        loc_t find_realhost() const;
        loc_t find_kernel_task() const;
        size_t find_sizeof_task() const;
        uint32_t find_proc_ucred() const;
        loc_t find_rop_add_r0_r0_0x40() const;
        loc_t find_IOMalloc() const;
        loc_t find_IOFree() const;
        loc_t find_panic() const;
        uintptr_t find_vtab_get_external_trap_for_index() const;
        
        loc_t find_gPhysBase() const;
        
        patch find_sandbox_patch();
        
        inline std::vector<patch> all_patches() const {
            return {
                _i_can_has_debugger_patch_off,
                _remount_patch_offset,
                _lwvm_patch_offsets,
                _nosuid_off[0],
                _nosuid_off[1],
                _proc_enforce,
                _cs_enforcement_disable_amfi,
                _amfi_patch_offsets,
                _amfi_substrate_patch[0],
                _amfi_substrate_patch[1],
            };
        }
    };

}

#endif /* offsetfinder32_h */
