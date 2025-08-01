// SPDX-License-Identifier: GPL-2.0-only OR MIT
/*
 * Copyright (C) 2025 The Falco Authors.
 *
 * This file is dual licensed under either the MIT or GPL 2. See MIT.txt
 * or GPL2.txt for full copies of the license.
 */

#include <helpers/interfaces/toctou_mitigation.h>
#include <helpers/interfaces/variable_size_event.h>

// This struct is defined according to the following format file:
// /sys/kernel/tracing/events/syscalls/sys_enter_connect/format
struct sys_enter_connect_args {
	uint64_t pad1;

	uint32_t __syscall_nr;
	uint32_t pad2;
	uint64_t fd;
	uint64_t uservaddr;
	uint64_t addrlen;
};

/*=============================== ENTER EVENT ===========================*/

SEC("tracepoint/syscalls/sys_enter_connect")
int connect_e(struct sys_enter_connect_args* ctx) {
#ifdef __NR_connect
	uint32_t socketcall_network_syscall_id = __NR_connect;
#else
	uint32_t socketcall_network_syscall_id = -1;
#endif
	return toctou_mitigation__call_prog(ctx,
	                                    ctx->__syscall_nr,
	                                    socketcall_network_syscall_id,
	                                    TTM_CONNECT_E);
}

SEC("tracepoint/syscalls/sys_enter_connect")
int ttm_connect_e(struct sys_enter_connect_args* ctx) {
	struct auxiliary_map* auxmap = auxmap__get();
	if(!auxmap) {
		return 0;
	}
	auxmap__preload_event_header(auxmap, PPME_SOCKET_CONNECT_E);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: fd (type: PT_FD) */
	int64_t socket_fd = (int64_t)(int32_t)ctx->fd;
	auxmap__store_s64_param(auxmap, socket_fd);

	/* Parameter 2: addr (type: PT_SOCKADDR) */
	unsigned long usrsockaddr = (unsigned long)ctx->uservaddr;
	uint16_t usrsockaddr_len = (uint16_t)ctx->addrlen;
	auxmap__store_sockaddr_param(auxmap, usrsockaddr, usrsockaddr_len);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	auxmap__finalize_event_header(auxmap);

	auxmap__submit_event(auxmap);

	return 0;
}

/*=============================== ENTER EVENT ===========================*/
