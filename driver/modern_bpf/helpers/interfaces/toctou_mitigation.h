// SPDX-License-Identifier: GPL-2.0-only OR MIT
/*
 * Copyright (C) 2025 The Falco Authors.
 *
 * This file is dual licensed under either the MIT or GPL 2. See MIT.txt
 * or GPL2.txt for full copies of the license.
 */

#pragma once

#include <helpers/interfaces/syscalls_dispatcher.h>

/**
 * @brief Tail call the TOCTOU mitigation program corresponding to the specified program code.
 *
 * @param ctx is the original program context
 * @param syscall_id is the original system call id that triggered the program
 * @param socketcall_network_syscall_id (network system calls only) is the id of the equivalent
 * 		  network system call issued through socketcall (e.g.: __NR_connect)
 * @param prog_code is the program code identifying the TOCTOU mitigation program to be called

 * @return never returns in case of success; otherwise, returns 0
 */
static __always_inline int toctou_mitigation__call_prog(
        void *ctx,
        uint32_t syscall_id,
        uint32_t socketcall_network_syscall_id,
        enum sys_enter_toctou_mitigation_prog_code prog_code) {
	int socketcall_syscall_id = -1;
	if(bpf_in_ia32_syscall()) {
#if defined(__TARGET_ARCH_x86)
		if(syscall_id == __NR_ia32_socketcall) {
			socketcall_syscall_id = __NR_ia32_socketcall;
		} else {
			syscall_id = maps__ia32_to_64(syscall_id);
			// Syscalls defined only on 32 bits are dropped here.
			if(syscall_id == (uint32_t)-1) {
				return 0;
			}
		}
#else
		return 0;
#endif
	} else {
#ifdef __NR_socketcall
		socketcall_syscall_id = __NR_socketcall;
#endif
	}

	// Convert the socketcall id into the network syscall id.
	// In this way the syscall will be treated exactly as the original one.
	if(syscall_id == socketcall_syscall_id) {
		syscall_id = socketcall_network_syscall_id;
		if(syscall_id == -1) {
			// We can't do anything since modern bpf filler jump table is syscall indexed.
			return 0;
		}
	}

	if(!syscalls_dispatcher__64bit_interesting_syscall(syscall_id)) {
		return 0;
	}

	if(syscalls_dispatcher__sampling_logic_enter(syscall_id)) {
		return 0;
	}

	bpf_tail_call(ctx, &syscall_enter_toctou_mitigation_tail_table, prog_code);
	bpf_printk("unable to tail call into TTM prog (prog_code: %d)", prog_code);
	return 0;
}
