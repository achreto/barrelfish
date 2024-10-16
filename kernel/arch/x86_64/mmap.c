/**
 * \file
 * \brief x86-64 kernel page-table setup
 */

/*
 * Copyright (c) 2007, 2008, 2009, 2010, ETH Zurich.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached LICENSE file.
 * If you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, Universitaetstrasse 6, CH-8092 Zurich. Attn: Systems Group.
 */

#include <kernel.h>
#include <sys_debug.h>
#include <syscall.h>
#include <paging_kernel_arch.h>
#include <barrelfish_kpi/syscalls.h>
#include <barrelfish_kpi/sys_debug.h>

#include <arbutus-monolyth/types.h>
#include <arbutus-monolyth/x8664pml4_unit.h>
#include <arbutus-monolyth/x8664pdpt_unit.h>
#include <arbutus-monolyth/x8664pdir_unit.h>
#include <arbutus-monolyth/x8664pagetable_unit.h>
#include <myos.h>

////////////////////////////////////////////////////////////////////////////////////////////////////
// !!! A HACK TO SEE WHETHER THE MONOLYTIC GENERATED CODE WORKS!
////////////////////////////////////////////////////////////////////////////////////////////////////

static lpaddr_t mem_base;
static lpaddr_t mem_limit;

void debug_mmap_init(lpaddr_t new_mem_base, size_t mem_bytes);
void debug_mmap_init(lpaddr_t new_mem_base, size_t mem_bytes) {
    printf("debug_mmap_init: new_mem_base = %lx, mem_bytes = %zu kB\n", new_mem_base, mem_bytes >> 10);
    mem_base = new_mem_base;
    mem_limit = new_mem_base + mem_bytes;
}


static inline lpaddr_t paging_x86_64_read_cr3(void)
{
    lpaddr_t pml4_base = 0;
    __asm volatile("mov %%cr3, %[pml4_base]"
                   : [pml4_base] "=r" (pml4_base)
                   :
                   );
    return pml4_base;
}


paddr_t memory_alloc(size_t sz, paddr_t align) {
    printf("debug_mmap:memory_alloc\n");
    assert(align == BASE_PAGE_SIZE && (sz & (align - 1)) == 0);
    if (mem_base + sz > mem_limit) {
        printf("debug_mmap:no memory!\n");
        return 0;
    }
    paddr_t ret = mem_base;
    mem_base += sz;
    return ret;
}

void memory_free(paddr_t pa, size_t sz) {
    // no-op fo rnow
}


struct sysret debug_mmap(lvaddr_t va, size_t sz, lpaddr_t pa);
struct sysret debug_mmap(lvaddr_t va, size_t sz, lpaddr_t pa) {
    printf("debug_mmap: va = %lx, sz = %zu kB, pa = %lx\n", va, sz >> 10, pa);

    lpaddr_t pml4_base = paging_x86_64_read_cr3();
    printf("debug_mmap: cr3 = %lx\n", pml4_base);
    pml4_base = pml4_base & 0x0000fffffffff000;
    printf("debug_mmap: pml4_base = %lx\n", pml4_base);

    x8664pml4__t pml4;
    x8664pml4_init(&pml4, pml4_base);

    flags_t flgs = {.readable = 1, .writable = 1, .usermode = 1};
    if (x8664pml4_map(&pml4, va, sz, flgs, pa) == sz) {
        return (struct sysret){ /*error*/ SYS_ERR_OK, /*value*/ va };
    } else {
        return (struct sysret){ /*error*/ SYS_ERR_VM_MAP_RIGHTS, /*value*/ -1 };
    }
}