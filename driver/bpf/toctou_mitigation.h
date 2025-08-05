#pragma once
#include "terminate_filler_helpers.h"

// Notice: "ttm" stands for "TOCTOU mitigation".

static __always_inline int call_ttm_filler_wrapper(void *ctx, long syscall_id) {
	if(syscall_id < 0 || syscall_id >= SYSCALL_TABLE_SIZE) {
		return 0;
	}

	int socketcall_syscall_id = -1;
	if(bpf_in_ia32_syscall()) {
		// Right now we support 32-bit emulation only on x86.
		// We try to convert the 32-bit id into the 64-bit one.
#if defined(CONFIG_X86_64) && defined(CONFIG_IA32_EMULATION)
		if(syscall_id == __NR_ia32_socketcall) {
			socketcall_syscall_id = __NR_ia32_socketcall;
		} else {
			syscall_id = convert_ia32_to_64(syscall_id);
			// syscalls defined only on 32 bits are dropped here.
			if(syscall_id == -1) {
				return 0;
			}
		}
#else
		// Unsupported arch
		return 0;
#endif
	} else {
		// Right now only s390x supports it
#ifdef __NR_socketcall
		socketcall_syscall_id = __NR_socketcall;
#endif
	}

	// Now all syscalls on 32-bit should be converted to 64-bit apart from `socketcall`.
	// This one deserves a special treatment
	if(syscall_id == socketcall_syscall_id) {
		// We do not support socketcall on tracepoints.
		return 0;
	}

	if(!is_syscall_interesting(syscall_id)) {
		return 0;
	}

	const struct syscall_evt_pair *sc_evt = get_syscall_info(syscall_id);
	if(!sc_evt)
		return 0;

	ppm_event_code evt_type;
	int drop_flags;
	if(sc_evt->flags & UF_USED) {
		evt_type = sc_evt->enter_event_type;
		drop_flags = sc_evt->flags;
	} else {
		evt_type = PPME_GENERIC_E;
		drop_flags = UF_ALWAYS_DROP;
	}

	call_ttm_filler(ctx, ctx, evt_type, drop_flags, socketcall_syscall_id);
	return 0;
}

#define TTM_FILLER_RAW(x) \
	__bpf_section("tracepoint/filler/toctou/" #x) static __always_inline int bpf_ttm_##x(void *ctx)

#define TTM_ENTER_PROBE(tp_name, prog_name, ctx_type)                                   \
	__bpf_section("tracepoint/syscalls/sys_enter_" #tp_name) static __always_inline int \
	        bpf_ttm_##prog_name(ctx_type *ctx) {                                        \
		return call_ttm_filler_wrapper(ctx, ctx->__syscall_nr);                         \
	}                                                                                   \
                                                                                        \
	static __always_inline int __bpf_##prog_name(struct filler_data *data);             \
                                                                                        \
	__bpf_section("tracepoint/filler/toctou/" #prog_name) static __always_inline int    \
	        bpf_##prog_name(ctx_type *ctx) {                                            \
		struct filler_data data = {0};                                                  \
		int res = init_filler_data(ctx, &data, false);                                  \
		if(res == PPM_SUCCESS) {                                                        \
			if(!data.state->tail_ctx.len) {                                             \
				write_evt_hdr(&data);                                                   \
			}                                                                           \
			res = __bpf_##prog_name(&data);                                             \
		}                                                                               \
                                                                                        \
		if(res == PPM_SUCCESS) {                                                        \
			res = push_evt_frame(ctx, &data);                                           \
		}                                                                               \
		if(data.state) {                                                                \
			data.state->tail_ctx.prev_res = res;                                        \
		}                                                                               \
		bpf_tail_call(ctx, &ttm_tail_map, PPM_FILLER_terminate_filler);                 \
		bpf_printk("Can't tail call terminate TOCTOU mitigation filler\n");             \
		return 0;                                                                       \
	}                                                                                   \
                                                                                        \
	static __always_inline int __bpf_##prog_name(struct filler_data *data)

TTM_FILLER_RAW(terminate_filler) {
	return __bpf_terminate_filler(ctx);
}

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

TTM_ENTER_PROBE(connect, sys_connect_e, struct sys_enter_connect_args) {
	struct sys_enter_connect_args *ctx = data->ctx;

	/* Parameter 1: fd (type: PT_FD) */
	int64_t fd = (int64_t)(int32_t)ctx->fd;
	int res = bpf_push_s64_to_ring(data, fd);
	CHECK_RES(res);

	/* Get the sockaddr pointer and its length. */
	struct sockaddr __user *usrsockaddr = (struct sockaddr __user *)ctx->uservaddr;
	unsigned long usrsockaddr_len = (unsigned long)ctx->addrlen;

	long addr_size = 0;
	if(usrsockaddr != NULL && usrsockaddr_len != 0) {
		struct sockaddr *ksockaddr = (struct sockaddr *)data->tmp_scratch;
		/* Copy the address into kernel memory. */
		res = bpf_addr_to_kernel(usrsockaddr, usrsockaddr_len, ksockaddr);
		if(likely(res >= 0)) {
			/* Convert the fd into socket endpoint information. */
			addr_size = bpf_pack_addr(data, ksockaddr, usrsockaddr_len);
		}
	}

	/* Parameter 2: addr (type: PT_SOCKADDR) */
	data->curarg_already_on_frame = true;
	res = bpf_val_to_ring_len(data, 0, addr_size);
	return res;
}

// This struct is defined according to the following format file:
// /sys/kernel/tracing/events/syscalls/sys_enter_creat/format
struct sys_enter_creat_args {
	uint64_t pad;

	uint32_t __syscall_nr;
	uint64_t filename;
	uint64_t mode;
};

TTM_ENTER_PROBE(creat, sys_creat_e, struct sys_enter_creat_args) {
	struct sys_enter_creat_args *ctx = data->ctx;

	/* Parameter 1: name (type: PT_FSPATH) */
	unsigned long val = (unsigned long)ctx->filename;
	int res = bpf_val_to_ring_mem(data, val, USER);
	CHECK_RES(res);

	/* Parameter 2: mode (type: PT_UINT32) */
	unsigned long mode = (unsigned long)ctx->mode;
	mode = open_modes_to_scap(O_CREAT, mode);
	return bpf_push_u32_to_ring(data, mode);
}

// This struct is defined according to the following format file:
// /sys/kernel/tracing/events/syscalls/sys_enter_open/format
struct sys_enter_open_args {
	uint64_t pad1;

	uint32_t __syscall_nr;
	uint32_t pad2;
	uint64_t filename;
	uint64_t flags;
	uint64_t mode;
};

TTM_ENTER_PROBE(open, sys_open_e, struct sys_enter_open_args) {
	struct sys_enter_open_args *ctx = data->ctx;

	/* Parameter 1: name (type: PT_FSPATH) */
	unsigned long filename = (unsigned long)ctx->filename;
	int res = bpf_val_to_ring(data, filename);
	CHECK_RES(res);

	/* Parameter 2: flags (type: PT_FLAGS32) */
	uint32_t original_flags = (uint32_t)ctx->flags;
	uint32_t flags = open_flags_to_scap(original_flags);
	res = bpf_push_u32_to_ring(data, flags);
	CHECK_RES(res);

	/* Parameter 3: mode (type: PT_UINT32) */
	uint32_t mode = (uint32_t)ctx->mode;
	mode = open_modes_to_scap(original_flags, mode);
	return bpf_push_u32_to_ring(data, mode);
}

// This struct is defined according to the following format file:
// /sys/kernel/tracing/events/syscalls/sys_enter_openat2/format
struct sys_enter_openat2_args {
	uint64_t pad1;

	uint32_t __syscall_nr;
	uint32_t pad2;
	uint64_t dfd;
	uint64_t filename;
	uint64_t how;
	uint64_t usize;
};

TTM_ENTER_PROBE(openat2, sys_openat2_e, struct sys_enter_openat2_args) {
	struct sys_enter_openat2_args *ctx = data->ctx;

	/* Parameter 1: dirfd (type: PT_FD) */
	int64_t dirfd = (int64_t)(int32_t)ctx->dfd;
	if(dirfd == AT_FDCWD) {
		dirfd = PPM_AT_FDCWD;
	}
	int res = bpf_push_s64_to_ring(data, dirfd);
	CHECK_RES(res);

	/* Parameter 2: name (type: PT_FSRELPATH) */
	unsigned long path_pointer = (unsigned long)ctx->filename;
	res = bpf_val_to_ring(data, path_pointer);
	CHECK_RES(res);

	uint32_t resolve;
	uint32_t flags;
	uint32_t mode;
#ifdef __NR_openat2
	/* the `open_how` struct is defined since kernel version 5.6 */
	unsigned long open_how_pointer = (unsigned long)ctx->how;
	struct open_how how = {0};
	if(bpf_probe_read_user(&how, sizeof(struct open_how), (void *)open_how_pointer)) {
		return PPM_FAILURE_INVALID_USER_MEMORY;
	}
	flags = open_flags_to_scap(how.flags);
	mode = open_modes_to_scap(how.flags, how.mode);
	resolve = openat2_resolve_to_scap(how.resolve);
#else
	flags = 0;
	mode = 0;
	resolve = 0;
#endif

	/* Parameter 3: flags (type: PT_FLAGS32) */
	res = bpf_push_u32_to_ring(data, flags);
	CHECK_RES(res);

	/* Parameter 4: mode (type: PT_UINT32) */
	res = bpf_push_u32_to_ring(data, mode);
	CHECK_RES(res);

	/* Parameter 5: resolve (type: PT_FLAGS32) */
	return bpf_push_u32_to_ring(data, resolve);
}

// This struct is defined according to the following format file:
// /sys/kernel/tracing/events/syscalls/sys_enter_openat/format
struct sys_enter_openat_args {
	uint64_t pad1;

	uint32_t __syscall_nr;
	uint32_t pad2;
	uint64_t dfd;
	uint64_t filename;
	uint64_t flags;
	uint64_t mode;
};

TTM_ENTER_PROBE(openat, sys_openat_e, struct sys_enter_openat_args) {
	struct sys_enter_openat_args *ctx = data->ctx;

	/* Parameter 1: dirfd (type: PT_FD) */
	int64_t fd = (int64_t)(int32_t)ctx->dfd;
	if(fd == AT_FDCWD) {
		fd = PPM_AT_FDCWD;
	}
	int res = bpf_push_s64_to_ring(data, fd);
	CHECK_RES(res);

	/* Parameter 2: name (type: PT_FSRELPATH) */
	unsigned long filename_pointer = (unsigned long)ctx->filename;
	res = bpf_val_to_ring(data, filename_pointer);
	CHECK_RES(res);

	/* Parameter 3: flags (type: PT_FLAGS32) */
	unsigned long original_flags = (unsigned long)ctx->flags;
	unsigned long flags = open_flags_to_scap(original_flags);
	res = bpf_push_u32_to_ring(data, flags);
	CHECK_RES(res);

	/* Parameter 4: mode (type: PT_UINT32) */
	unsigned long mode = (unsigned long)ctx->mode;
	mode = open_modes_to_scap(original_flags, mode);
	return bpf_push_u32_to_ring(data, mode);
}
