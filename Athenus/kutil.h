//
//  kutil.h
//  sockH3lix
//
//  Created by SXX on 2020/7/25.
//  Copyright © 2020 tihmstar. All rights reserved.
//

#ifndef kexec_h
#define kexec_h

__BEGIN_DECLS

#include "sock_port_exploit.h"

struct port_kernel_context {
    uint32_t io_bits;
    uint32_t io_references;
    uint32_t ip_srights;
    uint32_t is_table_bits;
    uintptr_t ip_receiver;
    uintptr_t ip_kobject;
    //kport_t port;
};

kptr_t proc_struct_addr(void);
kptr_t get_address_of_port(kptr_t proc, mach_port_t port);
kptr_t make_fake_task(kptr_t vm_map);
void free_fake_task(kptr_t fake_task);
bool make_port_fake_task_port(mach_port_t port, kptr_t task_kaddr, struct port_kernel_context *save);
void restore_port(mach_port_t port, struct port_kernel_context *save);

bool init_kexec(void);
void term_kexec(void);
kptr_t kexec(kptr_t ptr, kptr_t x0, kptr_t x1, kptr_t x2, kptr_t x3, kptr_t x4, kptr_t x5, kptr_t x6);

kptr_t proc_struct_addr(void);
kptr_t get_address_of_port(kptr_t proc, mach_port_t port);


__END_DECLS

#endif /* kexec_h */
