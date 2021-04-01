//
//  kernel_memory.c
//  sock_port
//
//  Created by Jake James on 7/18/19.
//  Copyright © 2019 Jake James. All rights reserved.
//

#include "kernel_memory.h"
#include <stdbool.h>
#include "offsets.h"

extern mach_port_t tfp0;

void init_kernel_memory(mach_port_t _tfp0) {
    tfp0 = _tfp0;
}

kptr_t kalloc(vm_size_t size) {
    return kmem_alloc(size);
}

void kfree(mach_vm_address_t address, vm_size_t size) {
    kmem_free((kptr_t)address, size);
}

size_t kread(kptr_t where, void *p, size_t size) {
    int rv;
    size_t offset = 0;
    while (offset < size) {
        mach_vm_size_t sz, chunk = 2048;
        if (chunk > size - offset) {
            chunk = size - offset;
        }
        rv = mach_vm_read_overwrite(tfp0, where + offset, chunk, (mach_vm_address_t)p + offset, &sz);
        if (rv || sz == 0) {
            printf("[-] error on kread("ADDR")\n", where);
            break;
        }
        offset += sz;
    }
    return offset;
}

size_t kwrite(kptr_t where, const void *p, size_t size) {
    int rv;
    size_t offset = 0;
    while (offset < size) {
        size_t chunk = 2048;
        if (chunk > size - offset) {
            chunk = size - offset;
        }
        rv = mach_vm_write(tfp0, where + offset, (vm_offset_t)p + offset, (int)chunk);
        if (rv) {
            printf("[-] error on kwrite("ADDR")\n", where);
            break;
        }
        offset += chunk;
    }
    return offset;
}

uintptr_t
find_port(mach_port_name_t port, kptr_t task_self) {
    uintptr_t task_addr = rkptr(task_self + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT));
    uintptr_t itk_space = rkptr(task_addr + koffset(KSTRUCT_OFFSET_TASK_ITK_SPACE));
    uintptr_t is_table = rkptr(itk_space + koffset(KSTRUCT_OFFSET_IPC_SPACE_IS_TABLE));
    
    uint32_t port_index = port >> 8;
    const int sizeof_ipc_entry_t = koffset(KSTRUCT_SIZE_IPC_ENTRY);
    
    uintptr_t port_addr = rkptr(is_table + (port_index * sizeof_ipc_entry_t));
    
    return port_addr;
}

uint64_t kread_uint64(kptr_t where){
    uint64_t value = 0;
    size_t sz = kread(where, &value, sizeof(value));
    return (sz == sizeof(value)) ? value : 0;
}

uint32_t kread_uint32(kptr_t where){
    uint32_t value = 0;
    size_t sz = kread(where, &value, sizeof(value));
    return (sz == sizeof(value)) ? value : 0;
}

uintptr_t kread_uintptr(kptr_t where){
    uintptr_t value = 0;
    size_t sz = kread(where, &value, sizeof(value));
    return (sz == sizeof(value)) ? value : 0;
}

size_t kwrite_uint64(kptr_t where, uint64_t value){
    return kwrite(where, &value, sizeof(value));
}

size_t kwrite_uint32(kptr_t where, uint32_t value){
    return kwrite(where, &value, sizeof(value));
}

size_t kwrite_uintptr(kptr_t where, uintptr_t value) {
    return kwrite(where, &value, sizeof(value));
}

kptr_t kmem_alloc(uint64_t size) {
    if (!MACH_PORT_VALID(tfp0)) {
        printf("attempt to allocate kernel memory before any kernel memory write primitives available");
        return 0;
    }

    kern_return_t err;
    mach_vm_address_t addr = 0;
    mach_vm_size_t ksize = round_page_kernel(size);
    err = mach_vm_allocate(tfp0, &addr, ksize, VM_FLAGS_ANYWHERE);
    if (err != KERN_SUCCESS) {
        printf("unable to allocate kernel memory via tfp0: %s %x", mach_error_string(err), err);
        return 0;
    }
    
    return (kptr_t)addr;
}

bool
kmem_free(mach_vm_address_t kaddr, vm_size_t size) {
    if (!MACH_PORT_VALID(tfp0)) {
        printf("attempt to deallocate kernel memory before any kernel memory write primitives available");
        return false;
    }
    
    kern_return_t err;
    mach_vm_size_t ksize = round_page_kernel(size);
    err = mach_vm_deallocate(tfp0, kaddr, ksize);
    if (err != KERN_SUCCESS) {
        printf("unable to deallocate kernel memory via tfp0: %s %x", mach_error_string(err), err);
        return false;
    }
    
    return true;
}

bool rkbuffer(kptr_t kaddr, void* buffer, size_t length) {
    if (!MACH_PORT_VALID(tfp0)) {
        printf("attempt to read kernel memory but no kernel memory read primitives available");
        return 0;
    }
    
    return (kread(kaddr, buffer, length) == length);
}

bool wkbuffer(kptr_t kaddr, void* buffer, size_t length) {
    if (!MACH_PORT_VALID(tfp0)) {
        printf("attempt to write to kernel memory before any kernel memory write primitives available");
        return false;
    }
    
    return (kwrite(kaddr, buffer, length) == length);
}
