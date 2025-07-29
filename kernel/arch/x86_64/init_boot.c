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
#include <arch/x86/start_aps.h>
#include <arch/x86/ipi_notify.h>
#include <barrelfish_kpi/cpu_arch.h>
#include <target/x86_64/barrelfish_kpi/cpu_target.h>
#include <coreboot.h>
#include <kcb.h>
#include <arch/x86_64/trace_test.h>

#include <dev/xapic_dev.h> // XXX
#include <dev/ia32_dev.h>
#include <dev/amd64_dev.h>

#define AP_BOOT_ADDR    0x8000  // Physical address for AP boot code (32KB)
#define AP_STARTING_UP  1
#define AP_STARTED      2
#define APIC_ICR_LO  0x300
#define APIC_ICR_HI  0x310

extern uint8_t x86_64_start_ap[];
extern uint8_t x86_64_start_ap_end[];
extern uint8_t x86_64_init_ap_absolute_entry[];
extern uint8_t x86_64_init_ap_global[];
extern uint8_t x86_64_init_ap_wait[];
extern uint8_t x86_64_init_ap_lock[];

struct global *global;
coreid_t my_core_id = 0;

volatile uint32_t *ap_wait_ptr = NULL;
volatile uint8_t *ap_lock_ptr = NULL;

/**
 * Used to store the address of global struct passed during boot across kernel
 * relocations.
 */
static uint64_t addr_global;

/// Current execution dispatcher (when in system call or exception)
struct dcb *dcb_current = NULL;

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

static void busy_wait_cycles(uint64_t cycles)
{
    uint64_t start, now;
    __asm__ volatile ("rdtsc" : "=A" (start));
    do {
        __asm__ volatile ("rdtsc" : "=A" (now));
    } while ((now - start) < cycles);
}

/**
 * Simple 2-level paging structures for basic memory management.
 * This is a simplified version for demonstration purposes.
 */

#if 0

/**
 * Page Directory Pointer Table (PDPT) - Level 1
 * Contains entries pointing to Page Directories
 */
static union x86_64_pdir_entry simple_pdpt[PTABLE_SIZE]
__attribute__ ((aligned(BASE_PAGE_SIZE)));

/**
 * Page Directory (PD) - Level 2  
 * Contains entries pointing to 2MB large pages
 */
static union x86_64_ptable_entry simple_pdir[PTABLE_SIZE]
__attribute__ ((aligned(BASE_PAGE_SIZE)));

/**
 * \brief Setup simple 2-level paging structure.
 *
 * This function sets up a basic 2-level paging structure that identity maps
 * the first 1GB of physical memory using 2MB large pages.
 * Level 1: PDPT (Page Directory Pointer Table)
 * Level 2: PD (Page Directory) with large pages
 */
static void simple_paging_init(void)
{
    printf("Setting up simple 2-level paging...\n");
    
    // Clear the paging structures
    memset(simple_pdpt, 0, sizeof(simple_pdpt));
    memset(simple_pdir, 0, sizeof(simple_pdir));
    
    // Set up PDPT entry 0 to point to our Page Directory
    paging_x86_64_map_table(&simple_pdpt[0], (lpaddr_t)simple_pdir);
    
    // Set up Page Directory entries to map first 1GB using 2MB large pages
    // This creates 512 entries of 2MB each = 1GB total
    for (int i = 0; i < PTABLE_SIZE; i++) {
        lpaddr_t phys_addr = (lpaddr_t)i * X86_64_MEM_PAGE_SIZE; // 2MB increments
        
        // Map each 2MB page with present, read/write, and large page flags
        paging_x86_64_map_large(&simple_pdir[i], phys_addr, 
                                PTABLE_PRESENT | PTABLE_READ_WRITE | PTABLE_USER_SUPERVISOR);
    }
    
    printf("2-level paging structure initialized.\n");

    uint64_t cr3_value = (uint64_t)simple_pdpt;
    
    printf("Loading page tables, setting CR3 to 0x%lx\n", cr3_value);
    
    __asm__ volatile (
        "movq %0, %%cr3"
        :
        : "r" (cr3_value)
        : "memory"
    );
    
    printf("Page tables loaded successfully\n");
}

static void page_table_write_test(void)
{
    printf("Performing page table write test...\n");
    __asm__ volatile ("cli");
    
    // Test writing to a specific page directory entry
    // Let's modify the entry for virtual address 0x400000 (4MB)
    int pdir_index = 2; // This maps virtual address 0x400000 (2 * 2MB)
    lpaddr_t test_phys_addr = 0x800000; // Map to physical address 8MB
    
    printf("Original PD[%d] entry: 0x%lx\n", pdir_index, simple_pdir[pdir_index].raw);
    
    // Write new mapping to page directory entry
    paging_x86_64_map_large(&simple_pdir[pdir_index], test_phys_addr,
                            PTABLE_PRESENT | PTABLE_READ_WRITE | PTABLE_USER_SUPERVISOR);
    __asm__ volatile (
        "movq %%cr3, %%rax\n\t"
        "movq %%rax, %%cr3"
        :
        :
        : "rax", "memory"
    );
    
    printf("Modified PD[%d] entry: 0x%lx\n", pdir_index, simple_pdir[pdir_index].raw);
    printf("This entry now maps virtual 0x400000 to physical 0x%lx\n", test_phys_addr);
    
    // Display some page table statistics
    int present_entries = 0;
    for (int i = 0; i < PTABLE_SIZE; i++) {
        if (simple_pdir[i].raw & PTABLE_PRESENT) {
            present_entries++;
        }
    }
    
    printf("Page table statistics:\n");
    printf("  - Total PD entries: %ld\n", PTABLE_SIZE);
    printf("  - Present entries: %d\n", present_entries);
    printf("  - Memory mapped: %d MB\n", present_entries * 2);
    printf("  - PDPT address: 0x%lx\n", (uint64_t)simple_pdpt);
    printf("  - PD address: 0x%lx\n", (uint64_t)simple_pdir);
    
    printf("Page table write test completed.\n");
}

/**
 * \brief Test reading from virtual address 0x400000
 *
 * This function attempts to read from virtual address 0x400000 to verify
 * that our page table mappings are working correctly.
 */
static void virtual_address_read_test(void)
{
    printf("Performing virtual address read test...\n");
    
    volatile uint64_t *test_addr = (volatile uint64_t *)0x400000;
    uint64_t read_value = 0;
    
    printf("Attempting to read from virtual address 0x400000...\n");
    
    // First, let's write a test pattern to the physical address that 0x400000 maps to
    // According to our mapping, 0x400000 should map to physical 0x800000
    volatile uint64_t *phys_addr = (volatile uint64_t *)0x400000;
    uint64_t test_pattern = 0xDEADBEEFCAFEBABE;
    
    printf("Writing test pattern 0x%lx to physical address 0x%lx\n", 
           test_pattern, (uint64_t)phys_addr);
    *phys_addr = test_pattern;
    
    // Now try to read from the virtual address
    printf("Reading from virtual address 0x%lx...\n", (uint64_t)test_addr);
    
    __asm__ volatile (
        "movq (%1), %0"
        : "=r" (read_value)
        : "r" (test_addr)
        : "memory"
    );
    
    printf("Read value: 0x%lx\n", read_value);
    
    if (read_value == test_pattern) {
        printf("SUCCESS: Virtual address translation working correctly!\n");
        printf("Virtual 0x400000 correctly maps to physical 0x800000\n");
    } else {
        printf("WARNING: Read value (0x%lx) doesn't match written pattern (0x%lx)\n", 
               read_value, test_pattern);
        printf("This might indicate a problem with the page table mapping\n");
    }
    
    // Additional verification - check page table entries
    printf("\nPage table verification:\n");
    printf("PDPT[0] entry: 0x%lx (should point to PD)\n", simple_pdpt[0].raw);
    printf("PD[2] entry: 0x%lx (should map to 0x800000 with flags)\n", simple_pdir[2].raw);
    
    // Decode the PD entry to show the physical address
    if (simple_pdir[2].raw & PTABLE_PRESENT) {
        lpaddr_t mapped_phys = simple_pdir[2].raw & X86_64_LARGE_PAGE_MASK;
        printf("PD[2] maps to physical address: 0x%lx\n", mapped_phys);
    }
    
    printf("Virtual address read test completed.\n");
}

#endif

static void send_init_ipi(uint8_t target_apic_id) {
    apic_send_init_assert(target_apic_id, 0);   // Assert INIT IPI
    busy_wait_cycles(20000000);
    apic_send_init_deassert();                  // Deassert INIT IPI
}

static void send_sipi_ipi(uint8_t target_apic_id, uint8_t vector) {
    apic_send_start_up(target_apic_id, 0, vector);
}

static bool start_ap(uint8_t target_apic_id, uint64_t entry) {

    assert(target_apic_id != apic_get_id());
    uint8_t *trampoline = (uint8_t *)X86_64_REAL_MODE_LINEAR_OFFSET;
    // Print the values of trampoline, start and size
    uint8_t *start = (uint8_t *)x86_64_start_ap;
    size_t size = (uint8_t *)x86_64_start_ap_end - (uint8_t *)x86_64_start_ap;
    printf("Trampoline address: 0x%lx\n", (uint64_t)trampoline);
    printf("Start address:      0x%lx\n", (uint64_t)start);
    printf("Start_ap_end address:      0x%lx\n", (uint64_t)x86_64_start_ap_end);
    printf("Trampoline size:    0x%lx\n", (uint64_t)size);

    // Check for possible overlap
    uint8_t *trampoline_end = trampoline + size;
    uint8_t *start_end = start + size;
    bool overlap = (trampoline < start_end) && (start < trampoline_end);
    if (overlap) {
        printf("WARNING: Trampoline and start_ap code regions overlap!\n");
    } else {
        printf("No overlap between trampoline and start_ap code regions.\n");
    }
    memcpy(trampoline, (uint8_t *)x86_64_start_ap, (uint8_t *)x86_64_start_ap_end - (uint8_t *)x86_64_start_ap);

    // Patch the absolute entry point (where AP jumps in long mode)
    uint64_t offset = (uint64_t)x86_64_init_ap_absolute_entry - (uint64_t)x86_64_start_ap;
    volatile uint64_t *absolute_entry_ptr = (volatile uint64_t *)(trampoline + offset);
    *absolute_entry_ptr = entry;

    // Patch the global pointer if needed
    offset = (uint64_t)x86_64_init_ap_global - (uint64_t)x86_64_start_ap;
    volatile uint64_t *ap_global_ptr = (volatile uint64_t *)(trampoline + offset);
    *ap_global_ptr = (uint64_t)global;

    // Patch the wait and lock variables
    offset = (uint64_t)x86_64_init_ap_wait - (uint64_t)x86_64_start_ap;
    ap_wait_ptr = (volatile uint32_t *)(trampoline + offset);
    *ap_wait_ptr = AP_STARTING_UP;



    offset = (uint64_t)x86_64_init_ap_lock - (uint64_t)x86_64_start_ap;
    ap_lock_ptr = (volatile uint8_t *)(trampoline + offset);
    *ap_lock_ptr = 0;

    // Send INIT IPI
    printf("Sending INIT IPI\n");
    send_init_ipi(target_apic_id);
    busy_wait_cycles(100000);

    printf("Sendint Startup IPO");

    // Send SIPI twice
    // uint8_t vector = AP_BOOT_ADDR >> 12;
    uint8_t vector =  X86_64_REAL_MODE_SEGMENT_TO_REAL_MODE_PAGE(X86_64_REAL_MODE_SEGMENT);
    send_sipi_ipi(target_apic_id, vector);
    busy_wait_cycles(100000);

    send_sipi_ipi(target_apic_id, vector);



    // Wait for AP to set the lock variable
    for (uint64_t i = 0; i < STARTUP_TIMEOUT; i++) {
        if (*ap_lock_ptr != 0) {
            break;
        }
    }

    // Check if AP started
    if (*ap_lock_ptr != 0) {
        while (*ap_wait_ptr != AP_STARTED);
        *ap_lock_ptr = 0;

        return true;
    }

    printf("APIC ID %d did not start\n", target_apic_id);

    return false;
}

void ap_entry_point(void) {
    printf("AP running on core %d!\n", apic_get_id());
    // Signal that this AP has started
    *ap_wait_ptr = AP_STARTED;
    // Enter main AP loop or scheduler
    halt();
}

/**
 * Bootup PML4, used to map both low (identity-mapped) memory and relocated
 * memory at the same time.
 */
static union x86_64_pdir_entry boot_pml4[PTABLE_SIZE]
__attribute__ ((aligned(BASE_PAGE_SIZE)));

/**
 * Bootup low-map PDPT and hi-map PDPT.
 */
static union x86_64_pdir_entry boot_pdpt[PTABLE_SIZE]
__attribute__ ((aligned(BASE_PAGE_SIZE)));
    // boot_pdpt[PTABLE_SIZE] __attribute__ ((aligned(BASE_PAGE_SIZE)));
    // boot_pdpt_hi[PTABLE_SIZE] __attribute__ ((aligned(BASE_PAGE_SIZE)));

/**
 * Bootup low-map PDIR, hi-map PDIR, and 1GB PDIR.
 */
static union x86_64_ptable_entry boot_pdir[PTABLE_SIZE]
__attribute__ ((aligned(BASE_PAGE_SIZE))),
    // boot_pdir_hi[PTABLE_SIZE] __attribute__ ((aligned(BASE_PAGE_SIZE))),
    boot_pdir_1GB[PTABLE_SIZE] __attribute__ ((aligned(BASE_PAGE_SIZE)));


/**
 * \brief Setup bootup page table.
 *
 * This function sets up the page table needed to boot the kernel
 * proper.  The table identity maps the first 1 GByte of physical
 * memory in order to have access to various data structures and the
 * first MByte containing bootloader-passed data structures. It also
 * identity maps the local copy of the kernel in low memory and
 * aliases it in kernel address space.
 *
 * \param base  Start address of kernel image in physical address space.
 * \param size  Size of kernel image.
 */
static void paging_init(lpaddr_t base, size_t size)
{
    lvaddr_t vbase = local_phys_to_mem(base);

    // Align base to kernel page size
    if(base & X86_64_MEM_PAGE_MASK) {
        size += base & X86_64_MEM_PAGE_MASK;
        base -= base & X86_64_MEM_PAGE_MASK;
    }

    // Align vbase to kernel page size
    if(vbase & X86_64_MEM_PAGE_MASK) {
        vbase -= vbase & X86_64_MEM_PAGE_MASK;
    }

    // Align size to kernel page size
    if(size & X86_64_MEM_PAGE_MASK) {
        size += X86_64_MEM_PAGE_SIZE - (size & X86_64_MEM_PAGE_MASK);
    }

    // XXX: Cannot currently map more than one table of pages
    assert(size <= X86_64_MEM_PAGE_SIZE * X86_64_PTABLE_SIZE);
/*     assert(size <= MEM_PAGE_SIZE); */

    for(size_t i = 0; i < size; i += X86_64_MEM_PAGE_SIZE,
            base += X86_64_MEM_PAGE_SIZE, vbase += X86_64_MEM_PAGE_SIZE) {
        // No kernel image above 4 GByte
        assert(base < ((lpaddr_t)4 << 30));

        // Identity-map the kernel's physical region, so we don't lose ground
        paging_x86_64_map_table(&boot_pml4[X86_64_PML4_BASE(base)], (lpaddr_t)boot_pdpt);
        paging_x86_64_map_table(&boot_pdpt[X86_64_PDPT_BASE(base)], (lpaddr_t)boot_pdir);
        paging_x86_64_map_large(&boot_pdir[X86_64_PDIR_BASE(base)], base, PTABLE_PRESENT
                                | PTABLE_READ_WRITE | PTABLE_USER_SUPERVISOR);
    }

    // Identity-map the first 1G of physical memory for bootloader data
    paging_x86_64_map_table(&boot_pml4[0], (lpaddr_t)boot_pdpt);
    paging_x86_64_map_table(&boot_pdpt[0], (lpaddr_t)boot_pdir_1GB);
    for (int i = 0; i < X86_64_PTABLE_SIZE; i++) {
        paging_x86_64_map_large(&boot_pdir_1GB[X86_64_PDIR_BASE(X86_64_MEM_PAGE_SIZE * i)],
                                X86_64_MEM_PAGE_SIZE * i, PTABLE_PRESENT
                                | PTABLE_READ_WRITE | PTABLE_USER_SUPERVISOR);
    }

    // Activate new page tables
    paging_x86_64_context_switch((lpaddr_t)boot_pml4);
}




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

    serial_console_putchar('A');
    serial_console_putchar('A');
    serial_console_putchar('\n');

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

    printf("Booting Test done.\n");
    
    // Alias kernel on top of memory, keep low memory
    paging_init((lpaddr_t)&_start_kernel, SIZE_KERNEL_IMAGE);

    printf("Paging Reset\n");
    paging_x86_64_reset();

    printf("Mapping First 8GB of Memory\n");
    if(paging_x86_64_map_memory(0, 4UL << 30) != 0) {
        panic("error while mapping physical memory!");
    }

    printf("setting up IDT\n");
    setup_default_idt();

    printf("setting up apic\n");
    apic_init();

    // simple_paging_init();

    // page_table_write_test();

    // virtual_address_read_test();

    for (uint8_t target_apic_id = 1; target_apic_id <= 3; target_apic_id++) {
        printf("Starting AP with APIC ID %d...\n", target_apic_id);
        if (start_ap(target_apic_id, (uint64_t)ap_entry_point)) {
            printf("AP %d started successfully!\n", target_apic_id);
        } else {
            printf("Failed to start AP %d\n", target_apic_id);
        }
    }

    halt();
}
