// SPDX-License-Identifier: GPL-2.0-only OR MIT
/*
 * Copyright (C) 2023 The Falco Authors.
 *
 * This file is dual licensed under either the MIT or GPL 2. See MIT.txt
 * or GPL2.txt for full copies of the license.
 */

#include <helpers/interfaces/variable_size_event.h>

/* From linux tree: /include/trace/events/sched.h
 * TP_PROTO(struct task_struct *p, pid_t old_pid,
 *		 struct linux_binprm *bprm)
 */
#ifdef CAPTURE_SCHED_PROC_EXEC

enum extra_sched_proc_exec_codes {
	T1_SCHED_PROC_EXEC,
	T2_SCHED_PROC_EXEC,
	// add more codes here.
	T_SCHED_PROC_EXEC_MAX,
};

/*
 * FORWARD DECLARATIONS:
 * See the `BPF_PROG` macro in libbpf `libbpf/src/bpf_tracing.h`
 * #define BPF_PROG(name, args...)		\
 *    name(unsigned long long *ctx);	\
 */
int t1_sched_p_exec(unsigned long long *ctx);
int t2_sched_p_exec(unsigned long long *ctx);

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, T_SCHED_PROC_EXEC_MAX);
	__uint(key_size, sizeof(__u32));
	__array(values, int(void *));
} extra_sched_proc_exec_calls SEC(".maps") = {
        .values =
                {
                        [T1_SCHED_PROC_EXEC] = (void *)&t1_sched_p_exec,
                        [T2_SCHED_PROC_EXEC] = (void *)&t2_sched_p_exec,
                        // add more tail calls here.
                },
};

/* chose a short name for bpftool debugging*/
SEC("tp_btf/sched_process_exec")
int BPF_PROG(sched_p_exec, struct task_struct *p, pid_t old_pid, struct linux_binprm *bprm) {
	struct task_struct *task = get_current_task();
	uint32_t flags = 0;
	READ_TASK_FIELD_INTO(&flags, task, flags);

	/* We are not interested in kernel threads. */
	if(flags & PF_KTHREAD) {
		return 0;
	}

	struct auxiliary_map *auxmap = auxmap__get();
	if(!auxmap) {
		return 0;
	}
	auxmap__preload_event_header(auxmap, PPME_SYSCALL_EXECVE_19_X);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: res (type: PT_ERRNO) */
	/* Please note: if this tracepoint is called the `execve/execveat` call
	 * is correctly performed, so the return value will be always 0.
	 */
	auxmap__store_s64_param(auxmap, 0);

	unsigned long arg_start_pointer = 0;
	unsigned long arg_end_pointer = 0;

	/* `arg_start` points to the memory area where arguments start.
	 * We directly read charbufs from there, not pointers to charbufs!
	 * We will store charbufs directly from memory.
	 */
	READ_TASK_FIELD_INTO(&arg_start_pointer, task, mm, arg_start);
	READ_TASK_FIELD_INTO(&arg_end_pointer, task, mm, arg_end);

	/* Parameter 2: exe (type: PT_CHARBUF) */
	uint16_t exe_arg_len =
	        auxmap__store_charbuf_param(auxmap, arg_start_pointer, MAX_PROC_EXE, USER);

	/* Parameter 3: args (type: PT_CHARBUFARRAY) */
	unsigned long total_args_len = arg_end_pointer - arg_start_pointer;
	auxmap__store_charbufarray_as_bytebuf(auxmap,
	                                      arg_start_pointer + exe_arg_len,
	                                      total_args_len - exe_arg_len,
	                                      MAX_PROC_ARG_ENV - exe_arg_len);

	/* Parameter 4: tid (type: PT_PID) */
	/* this is called `tid` but it is the `pid`. */
	int64_t pid = (int64_t)extract__task_xid_nr(task, PIDTYPE_PID);
	auxmap__store_s64_param(auxmap, pid);

	/* Parameter 5: pid (type: PT_PID) */
	/* this is called `pid` but it is the `tgid`. */
	int64_t tgid = (int64_t)extract__task_xid_nr(task, PIDTYPE_TGID);
	auxmap__store_s64_param(auxmap, tgid);

	/* Parameter 6: ptid (type: PT_PID) */
	/* this is called `ptid` but it is the `pgid`. */
	int64_t pgid = (int64_t)extract__task_xid_nr(task, PIDTYPE_PGID);
	auxmap__store_s64_param(auxmap, pgid);

	/* Parameter 7: cwd (type: PT_CHARBUF) */
	/// TODO: right now we leave the current working directory empty like in the old probe.
	auxmap__store_empty_param(auxmap);

	/* Parameter 8: fdlimit (type: PT_UINT64) */
	unsigned long fdlimit = 0;
	extract__fdlimit(task, &fdlimit);
	auxmap__store_u64_param(auxmap, fdlimit);

	/* Parameter 9: pgft_maj (type: PT_UINT64) */
	unsigned long pgft_maj = 0;
	extract__pgft_maj(task, &pgft_maj);
	auxmap__store_u64_param(auxmap, pgft_maj);

	/* Parameter 10: pgft_min (type: PT_UINT64) */
	unsigned long pgft_min = 0;
	extract__pgft_min(task, &pgft_min);
	auxmap__store_u64_param(auxmap, pgft_min);

	struct mm_struct *mm = NULL;
	READ_TASK_FIELD_INTO(&mm, task, mm);

	/* Parameter 11: vm_size (type: PT_UINT32) */
	uint32_t vm_size = extract__vm_size(mm);
	auxmap__store_u32_param(auxmap, vm_size);

	/* Parameter 12: vm_rss (type: PT_UINT32) */
	uint32_t vm_rss = extract__vm_rss(mm);
	auxmap__store_u32_param(auxmap, vm_rss);

	/* Parameter 13: vm_swap (type: PT_UINT32) */
	uint32_t vm_swap = extract__vm_swap(mm);
	auxmap__store_u32_param(auxmap, vm_swap);

	/* Parameter 14: comm (type: PT_CHARBUF) */
	auxmap__store_charbuf_param(auxmap, (unsigned long)task->comm, TASK_COMM_LEN, KERNEL);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	bpf_tail_call(ctx, &extra_sched_proc_exec_calls, T1_SCHED_PROC_EXEC);
	return 0;
}

SEC("tp_btf/sched_process_exec")
int BPF_PROG(t1_sched_p_exec, struct task_struct *p, pid_t old_pid, struct linux_binprm *bprm) {
	struct auxiliary_map *auxmap = auxmap__get();
	if(!auxmap) {
		return 0;
	}

	/*=============================== COLLECT PARAMETERS  ===========================*/

	struct task_struct *task = get_current_task();

	/* Parameter 15: cgroups (type: PT_CHARBUFARRAY) */
	auxmap__store_cgroups_param(auxmap, task);

	unsigned long env_start_pointer = 0;
	unsigned long env_end_pointer = 0;

	READ_TASK_FIELD_INTO(&env_start_pointer, task, mm, env_start);
	READ_TASK_FIELD_INTO(&env_end_pointer, task, mm, env_end);

	/* Parameter 16: env (type: PT_CHARBUFARRAY) */
	auxmap__store_charbufarray_as_bytebuf(auxmap,
	                                      env_start_pointer,
	                                      env_end_pointer - env_start_pointer,
	                                      MAX_PROC_ARG_ENV);

	/* Parameter 17: tty (type: PT_UINT32) */
	uint32_t tty = exctract__tty(task);
	auxmap__store_u32_param(auxmap, (uint32_t)tty);

	/* Parameter 18: vpgid (type: PT_PID) */
	pid_t vpgid = extract__task_xid_vnr(task, PIDTYPE_PGID);
	auxmap__store_s64_param(auxmap, (int64_t)vpgid);

	/* Parameter 19: loginuid (type: PT_UID) */
	uint32_t loginuid;
	extract__loginuid(task, &loginuid);
	auxmap__store_u32_param(auxmap, (uint32_t)loginuid);

	/* Parameter 20: flags (type: PT_FLAGS32) */
	uint32_t flags = 0;
	struct inode *exe_inode = extract__exe_inode_from_task(task);
	struct file *exe_file = extract__exe_file_from_task(task);

	if(extract__exe_writable(task, exe_inode)) {
		flags |= PPM_EXE_WRITABLE;
	}
	enum ppm_overlay overlay = extract__overlay_layer(exe_file);
	if(overlay == PPM_OVERLAY_UPPER) {
		flags |= PPM_EXE_UPPER_LAYER;
	} else if(overlay == PPM_OVERLAY_LOWER) {
		flags |= PPM_EXE_LOWER_LAYER;
	}
	if(extract__exe_from_memfd(exe_file)) {
		flags |= PPM_EXE_FROM_MEMFD;
	}

	auxmap__store_u32_param(auxmap, flags);

	/* Parameter 21: cap_inheritable (type: PT_UINT64) */
	uint64_t cap_inheritable = extract__capability(task, CAP_INHERITABLE);
	auxmap__store_u64_param(auxmap, cap_inheritable);

	/* Parameter 22: cap_permitted (type: PT_UINT64) */
	uint64_t cap_permitted = extract__capability(task, CAP_PERMITTED);
	auxmap__store_u64_param(auxmap, cap_permitted);

	/* Parameter 23: cap_effective (type: PT_UINT64) */
	uint64_t cap_effective = extract__capability(task, CAP_EFFECTIVE);
	auxmap__store_u64_param(auxmap, cap_effective);

	/* Parameter 24: exe_file ino (type: PT_UINT64) */
	uint64_t ino = 0;
	extract__ino_from_inode(exe_inode, &ino);
	auxmap__store_u64_param(auxmap, ino);

	/* Parameter 25: exe_file ctime (last status change time, epoch value in nanoseconds) (type:
	 * PT_ABSTIME) */
	struct timespec64 time = {0, 0};
	if(bpf_core_field_exists(exe_inode->i_ctime)) {
		BPF_CORE_READ_INTO(&time, exe_inode, i_ctime);
	} else {
		struct inode___v6_6 *exe_inode_v6_6 = (void *)exe_inode;
		if(bpf_core_field_exists(exe_inode_v6_6->__i_ctime)) {
			BPF_CORE_READ_INTO(&time, exe_inode_v6_6, __i_ctime);
		} else {
			struct inode___v6_11 *exe_inode_v6_11 = (void *)exe_inode;
			BPF_CORE_READ_INTO(&time.tv_sec, exe_inode_v6_11, i_ctime_sec);
			BPF_CORE_READ_INTO(&time.tv_nsec, exe_inode_v6_11, i_ctime_nsec);
		}
	}
	auxmap__store_u64_param(auxmap, extract__epoch_ns_from_time(time));

	/* Parameter 26: exe_file mtime (last modification time, epoch value in nanoseconds) (type:
	 * PT_ABSTIME) */
	if(bpf_core_field_exists(exe_inode->i_mtime)) {
		BPF_CORE_READ_INTO(&time, exe_inode, i_mtime);
	} else {
		struct inode___v6_7 *exe_inode_v6_7 = (void *)exe_inode;
		if(bpf_core_field_exists(exe_inode_v6_7->__i_mtime)) {
			BPF_CORE_READ_INTO(&time, exe_inode_v6_7, __i_mtime);
		} else {
			struct inode___v6_11 *exe_inode_v6_11 = (void *)exe_inode;
			BPF_CORE_READ_INTO(&time.tv_sec, exe_inode_v6_11, i_mtime_sec);
			BPF_CORE_READ_INTO(&time.tv_nsec, exe_inode_v6_11, i_mtime_nsec);
		}
	}
	auxmap__store_u64_param(auxmap, extract__epoch_ns_from_time(time));

	/* Parameter 27: euid (type: PT_UID) */
	uint32_t euid;
	extract__euid(task, &euid);
	auxmap__store_u32_param(auxmap, euid);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	bpf_tail_call(ctx, &extra_sched_proc_exec_calls, T2_SCHED_PROC_EXEC);
	return 0;
}

SEC("tp_btf/sched_process_exec")
int BPF_PROG(t2_sched_p_exec, struct pt_regs *regs, long ret) {
	struct auxiliary_map *auxmap = auxmap__get();
	if(!auxmap) {
		return 0;
	}

	/*=============================== COLLECT PARAMETERS  ===========================*/

	struct task_struct *task = get_current_task();
	struct file *exe_file = extract__exe_file_from_task(task);

	/* Parameter 28: trusted_exepath (type: PT_FSPATH) */
	if(exe_file != NULL) {
		auxmap__store_d_path_approx(auxmap, &(exe_file->f_path));
	} else {
		auxmap__store_empty_param(auxmap);
	}

	/* Parameter 29: pgid (type: PT_PID) */
	auxmap__store_pgid(auxmap, task);

	/* Parameter 30: egid (type: PT_GID) */
	uint32_t egid;
	extract__egid(task, &egid);
	auxmap__store_u32_param(auxmap, egid);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	auxmap__finalize_event_header(auxmap);

	auxmap__submit_event(auxmap);
	return 0;
}

#endif /* CAPTURE_SCHED_PROC_EXEC */
