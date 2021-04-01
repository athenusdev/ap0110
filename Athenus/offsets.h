#ifndef OFFSETS_H
#define OFFSETS_H

#include "common.h"             // kptr_t

__BEGIN_DECLS

typedef struct {
    kptr_t base;
    // Structure offsets
    kptr_t sizeof_task;
    //kptr_t task_itk_self;
    //kptr_t task_itk_registered;
    kptr_t task_bsd_info;
    kptr_t proc_ucred;
#ifdef __LP64__
    //kptr_t vm_map_hdr;
#endif
    //kptr_t ipc_space_is_task;
    //kptr_t realhost_special;
    //kptr_t iouserclient_ipc;
    //kptr_t vtab_get_retain_count;
    //kptr_t vtab_get_external_trap_for_index;
    // Data
    kptr_t zone_map;
    kptr_t kernel_map;
    kptr_t kernel_task;
    kptr_t realhost;
    // Code
    //kptr_t copyin;
    //kptr_t copyout;
    //kptr_t chgproccnt;
    //kptr_t kauth_cred_ref;
    //kptr_t ipc_port_alloc_special;
    //kptr_t ipc_kobject_set;
    //kptr_t ipc_port_make_send;
    //kptr_t osserializer_serialize;
#ifdef __LP64__
    //kptr_t rop_ldr_x0_x0_0x10;
#else
    //kptr_t rop_ldr_r0_r0_0xc;
#endif
} offsets_t;

offsets_t* get_offsets(void*);

enum kstruct_offset {
    /* struct task */
    KSTRUCT_OFFSET_TASK_LCK_MTX_TYPE,
    KSTRUCT_OFFSET_TASK_REF_COUNT,
    KSTRUCT_OFFSET_TASK_ACTIVE,
    KSTRUCT_OFFSET_TASK_VM_MAP,
    KSTRUCT_OFFSET_TASK_NEXT,
    KSTRUCT_OFFSET_TASK_PREV,
    KSTRUCT_OFFSET_TASK_ITK_SELF,
    KSTRUCT_OFFSET_TASK_ITK_SPACE,
    KSTRUCT_OFFSET_TASK_BSD_INFO,
    
    /* struct ipc_port */
    KSTRUCT_OFFSET_IPC_PORT_IO_BITS,
    KSTRUCT_OFFSET_IPC_PORT_IO_REFERENCES,
    KSTRUCT_OFFSET_IPC_PORT_IKMQ_BASE,
    KSTRUCT_OFFSET_IPC_PORT_MSG_COUNT,
    KSTRUCT_OFFSET_IPC_PORT_IP_RECEIVER,
    KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT,
    KSTRUCT_OFFSET_IPC_PORT_IP_PREMSG,
    KSTRUCT_OFFSET_IPC_PORT_IP_CONTEXT,
    KSTRUCT_OFFSET_IPC_PORT_IP_SRIGHTS,
    
    /* struct proc */
    KSTRUCT_OFFSET_PROC_PID,
    KSTRUCT_OFFSET_PROC_P_FD,
    KSTRUCT_OFFSET_PROC_TASK,
    
    /* struct filedesc */
    KSTRUCT_OFFSET_FILEDESC_FD_OFILES,
    
    /* struct fileproc */
    KSTRUCT_OFFSET_FILEPROC_F_FGLOB,
    
    /* struct fileglob */
    KSTRUCT_OFFSET_FILEGLOB_FG_DATA,
    
    /* struct socket */
    KSTRUCT_OFFSET_SOCKET_SO_PCB,
    
    /* struct pipe */
    KSTRUCT_OFFSET_PIPE_BUFFER,
    
    /* struct ipc_space */
    KSTRUCT_OFFSET_IPC_SPACE_IS_TABLE_SIZE,
    KSTRUCT_OFFSET_IPC_SPACE_IS_TABLE,
    
    /* struct host */
    KSTRUCT_OFFSET_HOST_SPECIAL,
    
    KFREE_ADDR_OFFSET,
    KSTRUCT_SIZE_IPC_ENTRY,
    KSTRUCT_OFFSET_IPC_ENTRY_IE_BITS,
};

struct cpu_cache_data {
    uint32_t mmu_i_cline;
    uint32_t mmu_csize;
    uint32_t mmu_cline;
    uint32_t mmu_nway;
    uint32_t mmu_i7set;
    uint32_t mmu_i7way;
    uint32_t mmu_i9way;
    uint32_t mmu_sway;
    uint32_t mmu_nset;
    uint32_t l2_csize;
    uint32_t l2_cline;
    uint32_t l2_nway;
    uint32_t l2_i7set;
    uint32_t l2_i7way;
    uint32_t l2_i9way;
    uint32_t l2_sway;
    uint32_t l2_nset;
};

int koffset(enum kstruct_offset offset);
void offsets_init(void);

extern uint32_t create_outsize;
extern size_t fake_task_size;

extern size_t get_add_x0_x0_0x40_ret(void);
extern size_t get_IOMalloc(void);
extern size_t get_zone_map_ref(void);
extern size_t get_IOFree(void);
extern size_t get_vtab_get_external_trap_for_index(void);
extern struct cpu_cache_data get_cache_data(void);

__END_DECLS

#endif
