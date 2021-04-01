//
//  kernel_memory.h
//  sock_port
//
//  Created by Jake James on 7/18/19.
//  Copyright © 2019 Jake James. All rights reserved.
//

#ifndef kernel_memory_h
#define kernel_memory_h

#include <stdio.h>
#include <mach/mach.h>
#include "common.h"
#include <stdbool.h>

__BEGIN_DECLS

kern_return_t mach_vm_allocate(vm_map_t target, mach_vm_address_t *address, mach_vm_size_t size, int flags);
kern_return_t mach_vm_read_overwrite(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size, mach_vm_address_t data, mach_vm_size_t *outsize);
kern_return_t mach_vm_write(vm_map_t target_task, mach_vm_address_t address, vm_offset_t data, mach_msg_type_number_t dataCnt);
kern_return_t mach_vm_deallocate(vm_map_t target, mach_vm_address_t address, mach_vm_size_t size);;
kern_return_t mach_vm_read(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size, vm_offset_t *data, mach_msg_type_number_t *dataCnt);
kern_return_t mach_vm_protect(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size, boolean_t set_maximum, vm_prot_t new_protection);

void init_kernel_memory(mach_port_t tfp0);

size_t kread(kptr_t where, void *p, size_t size);

#define rk32(where) kread_uint32(where)
#define rk64(where) kread_uint64(where)
#define rkptr(where) kread_uintptr(where)

size_t kwrite(kptr_t where, const void *p, size_t size);
uint64_t kread_uint64(kptr_t where);
uint32_t kread_uint32(kptr_t where);
uintptr_t kread_uintptr(kptr_t where);
size_t kwrite_uint64(kptr_t where, uint64_t value);
size_t kwrite_uint32(kptr_t where, uint32_t value);
size_t kwrite_uintptr(kptr_t where, uintptr_t value);

void wk32(kptr_t where, uint32_t what);
void wk64(kptr_t where, uint64_t what);

#define wk32(where, what) kwrite_uint32(where, what)
#define wk64(where, what) kwrite_uint64(where, what)
#if __arm64__
#define wkptr(where, what) wk64(where, what)
#else
#define wkptr(where, what) wk32(where, what)
#endif

void kfree(mach_vm_address_t address, vm_size_t size);
kptr_t kalloc(vm_size_t size);

kptr_t kmem_alloc(uint64_t size);
bool kmem_free(mach_vm_address_t kaddr, vm_size_t size);

uintptr_t find_port(mach_port_name_t port, kptr_t task_self);

kptr_t make_fake_task(kptr_t vm_map);
bool rkbuffer(kptr_t kaddr, void* buffer, size_t length);
bool wkbuffer(kptr_t kaddr, void* buffer, size_t length);

kern_return_t mach_vm_remap(
                            mach_port_name_t target,
                            mach_vm_address_t *address,
                            mach_vm_size_t size,
                            mach_vm_offset_t mask,
                            int flags,
                            mach_port_name_t src_task,
                            mach_vm_address_t src_address,
                            boolean_t copy,
                            vm_prot_t *cur_protection,
                            vm_prot_t *max_protection,
                            vm_inherit_t inheritance);

__END_DECLS

#endif /* kernel_memory_h */
