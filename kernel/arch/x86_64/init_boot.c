/**
 * \file
 * \brief x86-64 architecture initialization.
 */

/*
 * Copyright (c) 2007, 2008, 2009, 2010, 2011, ETH Zurich.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached LICENSE file.
 * If you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, Universitaetstrasse 6, CH-8092 Zurich. Attn: Systems Group.
 */

#include <kernel.h>
#include <string.h>
#include <stdio.h>
#include <paging_kernel_arch.h>
#include <elf/elf.h>
#include <init.h>
#include <irq.h>
#include <x86.h>
#include <serial.h>
#include <kernel_multiboot.h>
#include <syscall.h>
#include <getopt/getopt.h>
#include <exec.h>
#include <kputchar.h>
#include <systime.h>
#include <arch/x86/conio.h>
#include <arch/x86/pic.h>
#include <arch/x86/apic.h>
#include <arch/x86/mcheck.h>
#include <arch/x86/perfmon.h>
#include <arch/x86/rtc.h>
#include <target/x86/barrelfish_kpi/coredata_target.h>
#include <arch/x86/timing.h>
#include <arch/x86/startup_x86.h>
#include <arch/x86/start_aps.h>
#include <arch/x86/ipi_notify.h>
#include <barrelfish_kpi/cpu_arch.h>
#include <target/x86_64/barrelfish_kpi/cpu_target.h>
#include <coreboot.h>
#include <kcb.h>

#include <dev/xapic_dev.h> // XXX
#include <dev/ia32_dev.h>
#include <dev/amd64_dev.h>


struct global *global;
coreid_t my_core_id = 0;

/**
 * Used to store the address of global struct passed during boot across kernel
 * relocations.
 */
static uint64_t addr_global;

/**
 * \brief Kernel stack.
 *
 * This is the one and only kernel stack for a kernel instance.
 */
uintptr_t x86_64_kernel_stack[X86_64_KERNEL_STACK_SIZE/sizeof(uintptr_t)];

/**
 * \brief Global Task State Segment (TSS).
 *
 * This is the global, static and only Task State Segment (TSS). It is used
 * for interrupt and exception handling (stack setup) while in user-space.
 */
static struct task_state_segment tss __attribute__ ((aligned (4)));

/**
 * \brief Global Descriptor Table (GDT) for processor this kernel is running on.
 *
 * This descriptor table is completely static, as segments are basically
 * turned off in 64-bit mode. They map flat-mode code and stack segments for
 * both kernel- and user-space and the only Task State Segment (TSS).
 */
union segment_descriptor gdt[] __attribute__ ((aligned (4))) = {
    [NULL_SEL] = {   // Null segment
        .raw = 0
    },
    [KCODE_SEL] = {   // Kernel code segment
        .d = {
            .lo_limit = 0xffff,
            .lo_base = 0,
            .type = 0xa,
            .system_desc = 1,
            .privilege_level = SEL_KPL,
            .present = 1,
            .hi_limit = 0xf,
            .available = 0,
            .long_mode = 1,
            .operation_size = 0,
            .granularity = 1,
            .hi_base = 0
        }
    },
    [KSTACK_SEL] = {   // Kernel stack segment
        .d = {
            .lo_limit = 0xffff,
            .lo_base = 0,
            .type = 2,
            .system_desc = 1,
            .privilege_level = SEL_KPL,
            .present = 1,
            .hi_limit = 0xf,
            .available = 0,
            .long_mode = 1,
            .operation_size = 0,
            .granularity = 1,
            .hi_base = 0
        }
    },
    [USTACK_SEL] = {   // User stack segment
        .d = {
            .lo_limit = 0xffff,
            .lo_base = 0,
            .type = 2,
            .system_desc = 1,
            .privilege_level = SEL_UPL,
            .present = 1,
            .hi_limit = 0xf,
            .available = 0,
            .long_mode = 1,
            .operation_size = 0,
            .granularity = 1,
            .hi_base = 0
        }
    },
    [UCODE_SEL] = {   // User code segment
        .d = {
            .lo_limit = 0xffff,
            .lo_base = 0,
            .type = 0xa,
            .system_desc = 1,
            .privilege_level = SEL_UPL,
            .present = 1,
            .hi_limit = 0xf,
            .available = 0,
            .long_mode = 1,
            .operation_size = 0,
            .granularity = 1,
            .hi_base = 0
        }
    },
    [TSS_LO_SEL] = {   // Global Task State Segment (TSS), lower 8 bytes
        .sys_lo = {
            .lo_limit = sizeof(tss) & 0xffff,
            .type = SDT_SYSTSS,
            .privilege_level = SEL_KPL,
            .present = 1,
            .hi_limit = (sizeof(tss) >> 16) & 0xf,
            .available = 0,
            .granularity = 0,
        }
    },
    [TSS_HI_SEL] = {   // Global Task State Segment (TSS), upper 8 bytes
        .sys_hi = {
            .base = 0
        }
    },
    [LDT_LO_SEL] = {    // Local descriptor table (LDT), lower 8 bytes
        .sys_lo = {
            .lo_limit = 0, // # 4k pages (since granularity = 1)
            .lo_base = 0, // changed by context switch path when doing lldt
            .type = 2, // LDT
            .privilege_level = SEL_UPL,
            .present = 1,
            .hi_limit = 0,
            .available = 0,
            .granularity = 1,
            .hi_base = 0
        }
    },
    [LDT_HI_SEL] = {    // Local descriptor table (LDT), upper 8 bytes
        .sys_hi = {
            .base = 0 // changed by context switch path when doing lldt
        }
    },
};

union segment_descriptor *ldt_descriptor = &gdt[LDT_LO_SEL];






/**
 * \brief Architecture-specific initialization function.
 *
 * This function is called by the bootup code in boot.S to initialize
 * architecture-specific stuff. It is expected to call the kernel main
 * loop. This function never returns.
 *
 * The kernel expects one of two magic values in 'magic' that determine how it
 * has been booted. If 'magic' is #MULTIBOOT_INFO_MAGIC the kernel has been
 * booted by a (Multiboot-compliant) bootloader and this is the first image on
 * the boot CPU. It will relocate itself to a default position. If 'magic' is
 * #KERNEL_BOOT_MAGIC it has been booted by another image of itself and is
 * running on an (so-called) application CPU.
 *
 * This function sets up new page tables to alias the kernel
 * at #MEMORY_OFFSET. It also does any relocations necessary to the
 * "position-independent" code to make it run at the new location (e.g.
 * relocating the GOT). After all relocations, it calls text_init() of
 * the relocated image, which destroys the lower alias and may never return.
 *
 * For bsp kernels, the void pointer is of type multiboot_info, for application
 * CPUs, it is of type global. Global carries a pointer to multiboot_info.
 * Global also contains pointers to memory that is shared between kernels.
 *
 * \param magic         Boot magic value
 * \param pointer       Pointer to Multiboot Info or to Global structure
 */
void arch_init(uint64_t magic, void *pointer)
{
    // Sanitize the screen

    // Initialize serial, only initialize HW if we are
    // the first kernel
    serial_console_init((magic == MULTIBOOT_INFO_MAGIC));


    struct multiboot_info *mb = NULL;

    /*
     * If this is the boot image, make Multiboot information structure globally
     * known. Otherwise the passed value should equal the original structure.
     * If magic value does not match what we expect, we cannot proceed safely.
     */
    switch(magic) {
    case MULTIBOOT_INFO_MAGIC:
        mb = (struct multiboot_info *)pointer;

        // Construct the global structure and store its address to retrive it
        // across relocation
        memset(&global->locks, 0, sizeof(global->locks));
        addr_global            = (uint64_t)global;
        break;

    case KERNEL_BOOT_MAGIC:
        global = (struct global*)pointer;
        // Store the address of global to retrive it across relocation
        addr_global = (uint64_t)global;
        break;

    default:
        panic("Magic value does not match! (0x%x != 0x%lx != 0x%x)",
              KERNEL_BOOT_MAGIC, magic, MULTIBOOT_INFO_MAGIC);
        break;
    }

    /* determine page-aligned physical address past end of multiboot */
    lvaddr_t dest = (lvaddr_t)&_start_kernel;
    if (dest & (BASE_PAGE_SIZE - 1)) {
        dest &= ~(BASE_PAGE_SIZE - 1);
        dest += BASE_PAGE_SIZE;
    }

    // XXX: print kernel address for debugging with gdb
    printf("Kernel starting at address 0x%"PRIxLVADDR"\n",
           local_phys_to_mem(dest));

    printf("Booting Test done. Halting...\n");
    halt();
}
