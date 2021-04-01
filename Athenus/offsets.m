#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>

#import <stdio.h>
#import <stdlib.h>
#import <string.h>
#import <sys/sysctl.h>
#import <sys/utsname.h>
#include <mach/machine.h>
#import "offsets.h"

#define SYSTEM_VERSION_EQUAL_TO(v)                  ([[[UIDevice currentDevice] systemVersion] compare:v options:NSNumericSearch] == NSOrderedSame)
#define SYSTEM_VERSION_GREATER_THAN(v)              ([[[UIDevice currentDevice] systemVersion] compare:v options:NSNumericSearch] == NSOrderedDescending)
#define SYSTEM_VERSION_GREATER_THAN_OR_EQUAL_TO(v)  ([[[UIDevice currentDevice] systemVersion] compare:v options:NSNumericSearch] != NSOrderedAscending)
#define SYSTEM_VERSION_LESS_THAN(v)                 ([[[UIDevice currentDevice] systemVersion] compare:v options:NSNumericSearch] == NSOrderedAscending)
#define SYSTEM_VERSION_LESS_THAN_OR_EQUAL_TO(v)     ([[[UIDevice currentDevice] systemVersion] compare:v options:NSNumericSearch] != NSOrderedDescending)

int* offsets = NULL;

#if __arm64__

int kstruct_offsets_10_x[] = {
    0xb,   // KSTRUCT_OFFSET_TASK_LCK_MTX_TYPE,
    0x10,  // KSTRUCT_OFFSET_TASK_REF_COUNT,
    0x14,  // KSTRUCT_OFFSET_TASK_ACTIVE,
    0x20,  // KSTRUCT_OFFSET_TASK_VM_MAP,
    0x28,  // KSTRUCT_OFFSET_TASK_NEXT,
    0x30,  // KSTRUCT_OFFSET_TASK_PREV,
    0xd8,  // KSTRUCT_OFFSET_TASK_ITK_SELF,
    0x300, // KSTRUCT_OFFSET_TASK_ITK_SPACE,
    0x360, // KSTRUCT_OFFSET_TASK_BSD_INFO,
    
    0x0,   // KSTRUCT_OFFSET_IPC_PORT_IO_BITS,
    0x4,   // KSTRUCT_OFFSET_IPC_PORT_IO_REFERENCES,
    0x40,  // KSTRUCT_OFFSET_IPC_PORT_IKMQ_BASE,
    0x50,  // KSTRUCT_OFFSET_IPC_PORT_MSG_COUNT,
    0x60,  // KSTRUCT_OFFSET_IPC_PORT_IP_RECEIVER,
    0x68,  // KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT,
    0x88,  // KSTRUCT_OFFSET_IPC_PORT_IP_PREMSG,
    0x90,  // KSTRUCT_OFFSET_IPC_PORT_IP_CONTEXT,
    0xa0,  // KSTRUCT_OFFSET_IPC_PORT_IP_SRIGHTS,
    
    0x10,  // KSTRUCT_OFFSET_PROC_PID,
    0x108, // KSTRUCT_OFFSET_PROC_P_FD,
    0x18, // KSTRUCT_OFFSET_PROC_TASK
    
    0x0,   // KSTRUCT_OFFSET_FILEDESC_FD_OFILES
    
    0x8,   // KSTRUCT_OFFSET_FILEPROC_F_FGLOB
    
    0x38,  // KSTRUCT_OFFSET_FILEGLOB_FG_DATA
    
    0x10,  // KSTRUCT_OFFSET_SOCKET_SO_PCB
    
    0x10,  // KSTRUCT_OFFSET_PIPE_BUFFER
    
    0x14,  // KSTRUCT_OFFSET_IPC_SPACE_IS_TABLE_SIZE
    0x20,  // KSTRUCT_OFFSET_IPC_SPACE_IS_TABLE
    
    0x10, // KSTRUCT_OFFSET_HOST_SPECIAL
    
    0x6c,  // KFREE_ADDR_OFFSET,
    0x18, //KSTRUCT_SIZE_IPC_ENTRY
    0x8, // KSTRUCT_OFFSET_IPC_ENTRY_IE_BITS
};

int kstruct_offsets_11_0[] = {
    0xb,   // KSTRUCT_OFFSET_TASK_LCK_MTX_TYPE,
    0x10,  // KSTRUCT_OFFSET_TASK_REF_COUNT,
    0x14,  // KSTRUCT_OFFSET_TASK_ACTIVE,
    0x20,  // KSTRUCT_OFFSET_TASK_VM_MAP,
    0x28,  // KSTRUCT_OFFSET_TASK_NEXT,
    0x30,  // KSTRUCT_OFFSET_TASK_PREV,
    0xd8,  // KSTRUCT_OFFSET_TASK_ITK_SELF,
    0x308, // KSTRUCT_OFFSET_TASK_ITK_SPACE,
    0x368, // KSTRUCT_OFFSET_TASK_BSD_INFO,
    
    0x0,   // KSTRUCT_OFFSET_IPC_PORT_IO_BITS,
    0x4,   // KSTRUCT_OFFSET_IPC_PORT_IO_REFERENCES,
    0x40,  // KSTRUCT_OFFSET_IPC_PORT_IKMQ_BASE,
    0x50,  // KSTRUCT_OFFSET_IPC_PORT_MSG_COUNT,
    0x60,  // KSTRUCT_OFFSET_IPC_PORT_IP_RECEIVER,
    0x68,  // KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT,
    0x88,  // KSTRUCT_OFFSET_IPC_PORT_IP_PREMSG,
    0x90,  // KSTRUCT_OFFSET_IPC_PORT_IP_CONTEXT,
    0xa0,  // KSTRUCT_OFFSET_IPC_PORT_IP_SRIGHTS,
    
    0x10,  // KSTRUCT_OFFSET_PROC_PID,
    0x108, // KSTRUCT_OFFSET_PROC_P_FD
    0x18, // KSTRUCT_OFFSET_PROC_TASK
    
    0x0,   // KSTRUCT_OFFSET_FILEDESC_FD_OFILES
    
    0x8,   // KSTRUCT_OFFSET_FILEPROC_F_FGLOB
    
    0x38,  // KSTRUCT_OFFSET_FILEGLOB_FG_DATA
    
    0x10,  // KSTRUCT_OFFSET_SOCKET_SO_PCB
    
    0x10,  // KSTRUCT_OFFSET_PIPE_BUFFER
    
    0x14,  // KSTRUCT_OFFSET_IPC_SPACE_IS_TABLE_SIZE
    0x20,  // KSTRUCT_OFFSET_IPC_SPACE_IS_TABLE
    
    0x10, // KSTRUCT_OFFSET_HOST_SPECIAL
    
    0x6c,  // KFREE_ADDR_OFFSET,
    0x18, //KSTRUCT_SIZE_IPC_ENTRY
    0x8, // KSTRUCT_OFFSET_IPC_ENTRY_IE_BITS
};

int kstruct_offsets_11_3[] = {
    0xb,   // KSTRUCT_OFFSET_TASK_LCK_MTX_TYPE,
    0x10,  // KSTRUCT_OFFSET_TASK_REF_COUNT,
    0x14,  // KSTRUCT_OFFSET_TASK_ACTIVE,
    0x20,  // KSTRUCT_OFFSET_TASK_VM_MAP,
    0x28,  // KSTRUCT_OFFSET_TASK_NEXT,
    0x30,  // KSTRUCT_OFFSET_TASK_PREV,
    0xd8,  // KSTRUCT_OFFSET_TASK_ITK_SELF,
    0x308, // KSTRUCT_OFFSET_TASK_ITK_SPACE,
    0x368, // KSTRUCT_OFFSET_TASK_BSD_INFO,
    
    0x0,   // KSTRUCT_OFFSET_IPC_PORT_IO_BITS,
    0x4,   // KSTRUCT_OFFSET_IPC_PORT_IO_REFERENCES,
    0x40,  // KSTRUCT_OFFSET_IPC_PORT_IKMQ_BASE,
    0x50,  // KSTRUCT_OFFSET_IPC_PORT_MSG_COUNT,
    0x60,  // KSTRUCT_OFFSET_IPC_PORT_IP_RECEIVER,
    0x68,  // KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT,
    0x88,  // KSTRUCT_OFFSET_IPC_PORT_IP_PREMSG,
    0x90,  // KSTRUCT_OFFSET_IPC_PORT_IP_CONTEXT,
    0xa0,  // KSTRUCT_OFFSET_IPC_PORT_IP_SRIGHTS,
    
    0x10,  // KSTRUCT_OFFSET_PROC_PID,
    0x108, // KSTRUCT_OFFSET_PROC_P_FD
    0x18, // KSTRUCT_OFFSET_PROC_TASK
    
    0x0,   // KSTRUCT_OFFSET_FILEDESC_FD_OFILES
    
    0x8,   // KSTRUCT_OFFSET_FILEPROC_F_FGLOB
    
    0x38,  // KSTRUCT_OFFSET_FILEGLOB_FG_DATA
    
    0x10,  // KSTRUCT_OFFSET_SOCKET_SO_PCB
    
    0x10,  // KSTRUCT_OFFSET_PIPE_BUFFER
    
    0x14,  // KSTRUCT_OFFSET_IPC_SPACE_IS_TABLE_SIZE
    0x20,  // KSTRUCT_OFFSET_IPC_SPACE_IS_TABLE
    
    0x10, // KSTRUCT_OFFSET_HOST_SPECIAL
    
    0x7c,  // KFREE_ADDR_OFFSET,
    0x18, //KSTRUCT_SIZE_IPC_ENTRY
    0x8, // KSTRUCT_OFFSET_IPC_ENTRY_IE_BITS
};

int kstruct_offsets_12_0[] = {
    0xb,   // KSTRUCT_OFFSET_TASK_LCK_MTX_TYPE,
    0x10,  // KSTRUCT_OFFSET_TASK_REF_COUNT,
    0x14,  // KSTRUCT_OFFSET_TASK_ACTIVE,
    0x20,  // KSTRUCT_OFFSET_TASK_VM_MAP,
    0x28,  // KSTRUCT_OFFSET_TASK_NEXT,
    0x30,  // KSTRUCT_OFFSET_TASK_PREV,
    0xd8,  // KSTRUCT_OFFSET_TASK_ITK_SELF,
    0x300, // KSTRUCT_OFFSET_TASK_ITK_SPACE,
    0x358, // KSTRUCT_OFFSET_TASK_BSD_INFO,
    
    0x0,   // KSTRUCT_OFFSET_IPC_PORT_IO_BITS,
    0x4,   // KSTRUCT_OFFSET_IPC_PORT_IO_REFERENCES,
    0x40,  // KSTRUCT_OFFSET_IPC_PORT_IKMQ_BASE,
    0x50,  // KSTRUCT_OFFSET_IPC_PORT_MSG_COUNT,
    0x60,  // KSTRUCT_OFFSET_IPC_PORT_IP_RECEIVER,
    0x68,  // KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT,
    0x88,  // KSTRUCT_OFFSET_IPC_PORT_IP_PREMSG,
    0x90,  // KSTRUCT_OFFSET_IPC_PORT_IP_CONTEXT,
    0xa0,  // KSTRUCT_OFFSET_IPC_PORT_IP_SRIGHTS,
    
    0x60,  // KSTRUCT_OFFSET_PROC_PID,
    0x100, // KSTRUCT_OFFSET_PROC_P_FD
    0x10, // KSTRUCT_OFFSET_PROC_TASK
    
    0x0,   // KSTRUCT_OFFSET_FILEDESC_FD_OFILES
    
    0x8,   // KSTRUCT_OFFSET_FILEPROC_F_FGLOB
    
    0x38,  // KSTRUCT_OFFSET_FILEGLOB_FG_DATA
    
    0x10,  // KSTRUCT_OFFSET_SOCKET_SO_PCB
    
    0x10,  // KSTRUCT_OFFSET_PIPE_BUFFER
    
    0x14,  // KSTRUCT_OFFSET_IPC_SPACE_IS_TABLE_SIZE
    0x20,  // KSTRUCT_OFFSET_IPC_SPACE_IS_TABLE
    
    0x10, // KSTRUCT_OFFSET_HOST_SPECIAL
    
    0x7c,  // KFREE_ADDR_OFFSET
    0x18, //KSTRUCT_SIZE_IPC_ENTRY
    0x8, // KSTRUCT_OFFSET_IPC_ENTRY_IE_BITS
};

#else

static int kstruct_offsets_10_x[] = {
    0x7,   // KSTRUCT_OFFSET_TASK_LCK_MTX_TYPE,
    0x8,  // KSTRUCT_OFFSET_TASK_REF_COUNT,
    0xc,  // KSTRUCT_OFFSET_TASK_ACTIVE,
    0x14,  // KSTRUCT_OFFSET_TASK_VM_MAP,
    0x18,  // KSTRUCT_OFFSET_TASK_NEXT,
    0x1c,  // KSTRUCT_OFFSET_TASK_PREV,
    0x9c,  // KSTRUCT_OFFSET_TASK_ITK_SELF, //task_get_special_port
    0x1e8, // KSTRUCT_OFFSET_TASK_ITK_SPACE, needed //port_name_to_thread
    0x22c, // KSTRUCT_OFFSET_TASK_BSD_INFO, needed //get_bsdtask_info
    
    0x0,  // KSTRUCT_OFFSET_IPC_PORT_IO_BITS,
    0x4,  // KSTRUCT_OFFSET_IPC_PORT_IO_REFERENCES,
    0x30,  // KSTRUCT_OFFSET_IPC_PORT_IKMQ_BASE,
    0x3c,  // KSTRUCT_OFFSET_IPC_PORT_MSG_COUNT,
    0x44,  // KSTRUCT_OFFSET_IPC_PORT_IP_RECEIVER,
    0x48, // KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT, needed
    0x58,  // KSTRUCT_OFFSET_IPC_PORT_IP_PREMSG,
    0x5c,  // KSTRUCT_OFFSET_IPC_PORT_IP_CONTEXT,
    0x6c,  // KSTRUCT_OFFSET_IPC_PORT_IP_SRIGHTS, //ipc_port_release_send
    
    0x8,  // KSTRUCT_OFFSET_PROC_PID, needed
    0x9c, // KSTRUCT_OFFSET_PROC_P_FD, //proc_chrooted
    0xc, // KSTRUCT_OFFSET_PROC_TASK needed
    
    0x0,   // KSTRUCT_OFFSET_FILEDESC_FD_OFILES
    
    0x8,   // KSTRUCT_OFFSET_FILEPROC_F_FGLOB
    
    0x28,  // KSTRUCT_OFFSET_FILEGLOB_FG_DATA //mac_file_setxattr
    
    0x10,  // KSTRUCT_OFFSET_SOCKET_SO_PCB
    
    0x10,  // KSTRUCT_OFFSET_PIPE_BUFFER
    
    0xc,  // KSTRUCT_OFFSET_IPC_SPACE_IS_TABLE_SIZE
    0x14,  // KSTRUCT_OFFSET_IPC_SPACE_IS_TABLE needed
    
    0x8, // KSTRUCT_OFFSET_HOST_SPECIAL
    
    0x0,  // KFREE_ADDR_OFFSET,
    0x10, // KSTRUCT_SIZE_IPC_ENTRY needed
    0x4, // KSTRUCT_OFFSET_IPC_ENTRY_IE_BITS
};

#endif

int koffset(enum kstruct_offset offset) {
    if (offsets == NULL) {
        printf("need to call offsets_init() prior to querying offsets\n");
        offsets_init();
        return offsets[offset];
    }
    return offsets[offset];
}

uint32_t create_outsize;

void offsets_init() {
#if __arm64__
    if (SYSTEM_VERSION_GREATER_THAN_OR_EQUAL_TO(@"12.0")) {
        printf("[i] offsets selected for iOS 12.0 or above\n");
        offsets = kstruct_offsets_12_0;
        
#if __arm64e__
        offsets[8] = 0x368;
#endif
        create_outsize = 0xdd0;
    }
    
    else if (SYSTEM_VERSION_GREATER_THAN_OR_EQUAL_TO(@"11.3")) {
        printf("[i] offsets selected for iOS 11.3 or above\n");
        offsets = kstruct_offsets_11_3;
        create_outsize = 0xbc8;
    } else if (SYSTEM_VERSION_GREATER_THAN_OR_EQUAL_TO(@"11.1")) {
        printf("[i] offsets selected for iOS 11.1 or above\n");
        offsets = kstruct_offsets_11_3;
        create_outsize = 0xbc8;
    } else if (SYSTEM_VERSION_GREATER_THAN_OR_EQUAL_TO(@"11.0")) {
        printf("[i] offsets selected for iOS 11.0 to 11.0.3\n");
        offsets = kstruct_offsets_11_0;
        create_outsize = 0x6c8;
    } else
#endif
        if (SYSTEM_VERSION_GREATER_THAN_OR_EQUAL_TO(@"10.0")) {
        printf("[i] offsets selected for iOS 10.x\n");
        offsets = kstruct_offsets_10_x;
        create_outsize = 0x3c8;
    } else {
        printf("[-] iOS version too low, 10.0 required\n");
        exit(EXIT_FAILURE);
    }
}

extern struct cpu_cache_data get_cache_data(void) {
    static struct cpu_cache_data data;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        uint64_t family = 0;
        size_t size = sizeof(family);
        sysctlbyname("hw.cpufamily", &family, &size, NULL, 0);
        size_t l2size = 0;
        size = sizeof(l2size);
        sysctlbyname("hw.l2cachesize", &l2size, &size, NULL, 0);
        data.l2_csize = flsl(l2size) != ffsl(l2size) ? flsl(l2size) : flsl(l2size) - 1;
        //printf("l2 csize: %d\n", data.l2_csize);
        switch (family) {
            case CPUFAMILY_ARM_CYCLONE: //A7
            case CPUFAMILY_ARM_TYPHOON: //A8
                data.mmu_i_cline = 6;
                data.mmu_csize = 16;
                data.mmu_cline = 6;
                data.mmu_nway = 1;
                data.mmu_i7set = 6;
                data.mmu_i7way = 31;
                data.mmu_i9way = 31;
                data.mmu_sway = (data.mmu_csize - data.mmu_nway); //15
                data.mmu_nset = (data.mmu_sway - data.mmu_cline); //9
                //data.l2_csize = __ARM_L2CACHE_SIZE_LOG__;
                data.l2_cline = 6;
                data.l2_nway = 3;
                data.l2_i7set = 6;
                data.l2_i7way = 29;
                data.l2_i9way = 29;
                data.l2_sway = (data.l2_csize - data.l2_nway); 
                data.l2_nset = (data.l2_sway - data.l2_cline);
                break;
            case CPUFAMILY_ARM_TWISTER: //A9
                /*
            case CPUFAMILY_ARM_HURRICANE: //A10
                data.mmu_i_cline = 6;
                data.mmu_csize = 16;
                data.mmu_cline = 6;
                data.mmu_nway = 2;
                data.mmu_i7set = 6;
                data.mmu_i7way = 30;
                data.mmu_i9way = 30;
                data.mmu_sway = (data.mmu_csize - data.mmu_nway);
                data.mmu_nset = (data.mmu_sway - data.mmu_cline);
                //data.l2_csize = __ARM_L2CACHE_SIZE_LOG__;
                data.l2_cline = 6;
                data.l2_nway = 4;
                data.l2_i7set = 6;
                data.l2_i7way = 28;
                data.l2_i9way = 28;
                data.l2_sway = (data.l2_csize - data.l2_nway);
                data.l2_nset = (data.l2_sway - data.l2_cline);
                break;*/
            default:
                break;
        }
    });
    return data;
}

__attribute__((constructor)) static void
_fetch_cache_data() {
    get_cache_data();
}
