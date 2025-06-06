// SPDX-License-Identifier: GPL-2.0-only OR MIT
/*
 * Copyright (C) 2023 The Falco Authors.
 *
 * This file is dual licensed under either the MIT or GPL 2. See MIT.txt
 * or GPL2.txt for full copies of the license.
 */

#include <helpers/interfaces/fixed_size_event.h>

/*=============================== ENTER EVENT ===========================*/

SEC("tp_btf/sys_enter")
int BPF_PROG(setns_e, struct pt_regs *regs, long id) {
	struct ringbuf_struct ringbuf;
	if(!ringbuf__reserve_space(&ringbuf, SETNS_E_SIZE, PPME_SYSCALL_SETNS_E)) {
		return 0;
	}

	ringbuf__store_event_header(&ringbuf);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: fd (type: PT_FD) */
	int32_t fd = (int32_t)extract__syscall_argument(regs, 0);
	ringbuf__store_s64(&ringbuf, (int64_t)fd);

	/* Parameter 2: nstype (type: PT_FLAGS32) */
	unsigned long nstype = extract__syscall_argument(regs, 1);
	ringbuf__store_u32(&ringbuf, clone_flags_to_scap((int)nstype));

	/*=============================== COLLECT PARAMETERS  ===========================*/

	ringbuf__submit_event(&ringbuf);

	return 0;
}

/*=============================== ENTER EVENT ===========================*/

/*=============================== EXIT EVENT ===========================*/

SEC("tp_btf/sys_exit")
int BPF_PROG(setns_x, struct pt_regs *regs, long ret) {
	struct ringbuf_struct ringbuf;
	if(!ringbuf__reserve_space(&ringbuf, SETNS_X_SIZE, PPME_SYSCALL_SETNS_X)) {
		return 0;
	}

	ringbuf__store_event_header(&ringbuf);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: res (type: PT_FD)*/
	ringbuf__store_s64(&ringbuf, ret);

	/* Parameter 2: fd (type: PT_FD) */
	int32_t fd = (int32_t)extract__syscall_argument(regs, 0);
	ringbuf__store_s64(&ringbuf, (int64_t)fd);

	/* Parameter 3: nstype (type: PT_FLAGS32) */
	unsigned long nstype = extract__syscall_argument(regs, 1);
	ringbuf__store_u32(&ringbuf, clone_flags_to_scap((int)nstype));

	/*=============================== COLLECT PARAMETERS  ===========================*/

	ringbuf__submit_event(&ringbuf);

	return 0;
}

/*=============================== EXIT EVENT ===========================*/
