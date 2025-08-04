#include <arch/x86_64/paging_test_utils.h>

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

void write_pte(lpaddr_t source, size_t level, lvaddr_t virt_addr, lpaddr_t dest, bool valid){
    uint64_t flags = X86_64_PTABLE_PRESENT | X86_64_PTABLE_READ_WRITE; // todo: check for valid
    size_t index = -1;
    switch(level){
        case 2:
            index = X86_64_PDIR_BASE(virt_addr);
            break;
        case 3:
            index = X86_64_PTABLE_BASE(virt_addr);
            break;
        default:
            return;
    }
    // Convert physical address to virtual address to access the page table entry
    union x86_64_ptable_entry *pte = (union x86_64_ptable_entry *)local_phys_to_mem(source);
    paging_x86_64_map(&pte[index], dest, flags);
}


void read_memory(lvaddr_t addr){
    int value = *(int *)addr;
    printf("PTModel core %d: read_memory: addr = 0x%lx, value = 0x%x\n", my_core_id, addr, value);
}

void write_phys_memory(lpaddr_t addr, uint32_t value){
    uint64_t *pml4_virt = (uint64_t *)local_phys_to_mem((lpaddr_t)addr);
    *pml4_virt = value;
}

void invalidate_page(lvaddr_t addr){
    __asm__ volatile("invlpg (%0)" :: "r" (addr) : "memory");
}

void barrier(void){
    __asm__ volatile("mfence" : : : "memory");
}