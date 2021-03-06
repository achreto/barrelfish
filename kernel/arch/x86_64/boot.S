/**
 * \file
 * \brief Bootstrap the kernel.
 */

/*
 * Copyright (c) 2007, 2008, ETH Zurich.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached LICENSE file.
 * If you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, Universitaetstrasse 6, CH-8092 Zurich. Attn: Systems Group.
 */

#include <multiboot.h>

#ifdef __k1om__
#include <target/k1om/offsets_target.h>
#define KERNEL_STACK_SIZE K1OM_KERNEL_STACK_SIZE
#define KERNEL_STACK k1om_kernel_stack
#else
#include <target/x86_64/offsets_target.h>
#define KERNEL_STACK_SIZE X86_64_KERNEL_STACK_SIZE
#define KERNEL_STACK x86_64_kernel_stack
#endif

/* The flags for the Multiboot header */
#define MB_FLAGS (MULTIBOOT_HEADER_FLAG_MODS_PGALIGNED | MULTIBOOT_HEADER_FLAG_NEED_MEMINFO)

	.text
	.globl start, halt

	/* Multiboot header, 4-byte aligned */
	.align	4
	.long	MULTIBOOT_HEADER_MAGIC               /* magic */
	.long	MB_FLAGS                             /* flags */
	.long	-(MULTIBOOT_HEADER_MAGIC + MB_FLAGS) /* checksum */

start:
	/* Initialize the stack pointer */
	lea	(KERNEL_STACK + KERNEL_STACK_SIZE)(%rip), %rsp

	/* Reset EFLAGS */
	pushq	$0
	popf

	/* Enter architecture-specific init -- this should never return */
	movl	%eax, %edi	/* Multiboot magic value */
	movl	%ebx, %esi	/* Pointer to multiboot info struct */
	call	arch_init

	/* Halt -- this should never be reached */
halt:	hlt
	jmp	halt
