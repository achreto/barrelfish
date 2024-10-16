/**
 * \file
 * \brief Test program for large page code
 */

/*
 * Copyright (c) 2024, ETH Zurich.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached LICENSE file.
 * If you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, Universitaetstrasse 6, CH-8092 Zurich. Attn: Systems Group.
 */

#include <barrelfish/barrelfish.h>
#include <stdio.h>

#include <myos.h>
#include <arbutus/x8664pml4_unit.h>
#include <arbutus/x8664pdpt_unit.h>
#include <arbutus/x8664pdir_unit.h>
#include <arbutus/x8664pagetable_unit.h>

#define VA_START (1UL << 41)

static errval_t new_frame(MyFrame *frame, size_t size)
{
    errval_t err;
    err = frame_alloc(&frame->cap, BASE_PAGE_SIZE, NULL);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_FRAME_ALLOC);
    }

    err = slot_alloc(&frame->mapping);
    if (err_is_fail(err)) {
        cap_destroy(frame->cap);
        return err_push(err, LIB_ERR_SLOT_ALLOC);
    }
    return SYS_ERR_OK;
}

#include <barrelfish_kpi/syscalls.h>
#include <barrelfish_kpi/sys_debug.h>
static errval_t sys_debug_mmap(lvaddr_t va, size_t sz, lpaddr_t pa)
{
    return syscall5(SYSCALL_DEBUG, DEBUG_MMAP, va, sz, pa).error;
}



int main(int argc, char *argv[])
{
    errval_t err;

    debug_printf("$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$\n");
    debug_printf("$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$\n");
    debug_printf("$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$\n");


    // allocate some frame
    MyFrame frame;
    err = new_frame(&frame, BASE_PAGE_SIZE);
    if (err_is_fail(err)) {
        USER_PANIC_ERR(err, "could not allocate frame");
    }

    // create the vnode to the vroot
    MyVNode vnode = { 0 };
    vnode.cap = cap_vroot;

    // create the pml4
    x8664pml4__t pml4;
    x8664pml4_init(&pml4, vnode);

    flags_t flgs = {.readable = 1, .writable = 1, .usermode = 1};

    printf("Mapping the frame at address 0x%lx\n", VA_START);
    size_t sz = x8664pml4_map(&pml4, VA_START, BASE_PAGE_SIZE, flgs, frame);
    if (sz != BASE_PAGE_SIZE) {
        USER_PANIC("x8664pml4_map failed");
    }

    debug_printf("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n");
    debug_printf("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n");

    printf("accessing memory...");
    uint64_t *addr = (uint64_t *)VA_START;
    printf("*addr = %lx\n", *addr);

    printf("*addr = 42\n");
    *addr = 42;
    printf("*addr = %lu\n", *addr);


    debug_printf("$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$\n");
    debug_printf("$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$\n");
    debug_printf("$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$\n");

    struct frame_identity thecap;
    err = cap_identify_mappable(frame.cap, &thecap);
    if (err_is_fail(err)) {
        USER_PANIC_ERR(err, "could not identify the frame");
    }
    addr = (uint64_t *)(VA_START << 1);
    err = sys_debug_mmap((lvaddr_t)addr, BASE_PAGE_SIZE, thecap.base);
    if (err_is_fail(err)) {
        USER_PANIC_ERR(err, "could not allocate frame");
    }

    debug_printf("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n");
    debug_printf("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n");

    printf("accessing memory...");
    printf("*addr = %lu\n", *addr);

    printf("*addr = 43\n");
    *addr = 43;
    printf("*addr = %lu\n", *addr);


    debug_printf("$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$\n");
    debug_printf("$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$\n");
    debug_printf("$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$\n");

    printf("Hello, world!\n");
    return 0;
}