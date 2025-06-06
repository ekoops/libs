// SPDX-License-Identifier: GPL-2.0-only OR MIT
/*
 * Copyright (C) 2023 The Falco Authors.
 *
 * This file is dual licensed under either the MIT or GPL 2. See MIT.txt
 * or GPL2.txt for full copies of the license.
 */

#pragma once

#include <helpers/base/maps_getters.h>
#include <helpers/base/read_from_task.h>
#include <helpers/base/shared_size.h>
#include <driver/ppm_flag_helpers.h>

#if __has_include(<sys/syscall.h>)
#include <sys/syscall.h>
#endif

#define __NR_ia32_socketcall 102

/* Used to convert from page number to KB. */
#define DO_PAGE_SHIFT(x) (x) << (IOC_PAGE_SHIFT - 10)

/* This enum should simplify the capabilities extraction. */
enum capability_type {
	CAP_INHERITABLE = 0,
	CAP_PERMITTED = 1,
	CAP_EFFECTIVE = 2,
};

/* All the functions that are called in bpf to extract parameters
 * start with the `extract` prefix.
 */

///////////////////////////
// EXTRACT FROM SYSCALLS
///////////////////////////

/**
 * @brief Extract the syscall id starting from the registers
 *
 * @param regs pointer to the struct where we find the arguments
 * @return syscall id
 */
static __always_inline uint32_t extract__syscall_id(struct pt_regs *regs) {
#if defined(__TARGET_ARCH_x86)
	return (uint32_t)regs->orig_ax;
#elif defined(__TARGET_ARCH_arm64)
	return (uint32_t)regs->syscallno;
#elif defined(__TARGET_ARCH_s390)
	return (uint32_t)regs->int_code & 0xffff;
#elif defined(__TARGET_ARCH_powerpc)
	return (uint32_t)regs->gpr[0];
#else
	return 0;
#endif
}

static __always_inline bool bpf_in_ia32_syscall() {
	uint32_t status = 0;
	struct task_struct *task = get_current_task();

	// If task_struct has no embedded thread_info,
	// we cannot deduce anything. Just return.
	// NOTE: this means that emulated 32bit syscalls will
	// be parsed as 64bits syscalls.
	// However, our minimum supported kernel releases
	// already enforce that CONFIG_THREAD_INFO_IN_TASK is defined,
	// therefore we already show a warning to the user
	// when building against an unsupported kernel release.
	if(!bpf_core_field_exists(((struct task_struct *)0)->thread_info)) {
		return false;
	}

#if defined(__TARGET_ARCH_x86)
	READ_TASK_FIELD_INTO(&status, task, thread_info.status);
	return status & TS_COMPAT;
#elif defined(__TARGET_ARCH_arm64)
	READ_TASK_FIELD_INTO(&status, task, thread_info.flags);
	return status & _TIF_32BIT;
#elif defined(__TARGET_ARCH_s390)
	READ_TASK_FIELD_INTO(&status, task, thread_info.flags);
	return status & _TIF_31BIT;
#elif defined(__TARGET_ARCH_powerpc)
	READ_TASK_FIELD_INTO(&status, task, thread_info.flags);
	return status & _TIF_32BIT;
#else
	return false;
#endif
}

/**
 * @brief Extract a specific syscall argument
 *
 * @param regs pointer to the strcut where we find the arguments
 * @param idx index of the argument to extract
 * @return generic unsigned long value that can be a pointer to the arg
 * or directly the value, it depends on the type of arg.
 */
static __always_inline unsigned long extract__syscall_argument(struct pt_regs *regs, int idx) {
	unsigned long arg;
#if defined(__TARGET_ARCH_x86)
	if(bpf_in_ia32_syscall()) {
		switch(idx) {
		case 0:
			arg = BPF_CORE_READ(regs, bx);
			break;
		case 1:
			arg = BPF_CORE_READ(regs, cx);
			break;
		case 2:
			arg = BPF_CORE_READ(regs, dx);
			break;
		case 3:
			arg = BPF_CORE_READ(regs, si);
			break;
		case 4:
			arg = BPF_CORE_READ(regs, di);
			break;
		case 5:
			arg = BPF_CORE_READ(regs, bp);
			break;
		default:
			arg = 0;
		}
		return arg;
	}
#endif
	switch(idx) {
	case 0:
		arg = PT_REGS_PARM1_CORE_SYSCALL(regs);
		break;
	case 1:
		arg = PT_REGS_PARM2_CORE_SYSCALL(regs);
		break;
	case 2:
		arg = PT_REGS_PARM3_CORE_SYSCALL(regs);
		break;
	case 3:
		arg = PT_REGS_PARM4_CORE_SYSCALL(regs);
		break;
	case 4:
		arg = PT_REGS_PARM5_CORE_SYSCALL(regs);
		break;
	case 5:
		/* Not defined in libbpf, look at `definitions_helpers.h` */
		arg = PT_REGS_PARM6_CORE_SYSCALL(regs);
		break;
	default:
		arg = 0;
	}

	return arg;
}

/**
 * @brief Extract one ore more arguments related to a network / socket system call.
 *
 * This function takes into consideration whether the network system call has been
 * called directly (e.g. accept4) or through the socketcall system call multiplexer.
 * For the socketcall multiplexer, arguments are extracted from the second argument
 * of the socketcall system call.  See socketcall(2) for more information.
 *
 * @param argv Pointer to store up to @num arguments of size `unsigned long`
 * @param num Number of arguments to extract
 * @param regs Pointer to the struct pt_regs to access arguments and system call ID
 */
static __always_inline void extract__network_args(void *argv, int num, struct pt_regs *regs) {
#ifdef __NR_socketcall
	int id = extract__syscall_id(regs);
	if(id == __NR_socketcall) {
		unsigned long args_pointer = extract__syscall_argument(regs, 1);
		bpf_probe_read_user(argv, num * sizeof(unsigned long), (void *)args_pointer);
		return;
	}
#elif defined(__TARGET_ARCH_x86)
	int id = extract__syscall_id(regs);
	if(bpf_in_ia32_syscall() && id == __NR_ia32_socketcall) {
		// First read all arguments on 32 bits.
		uint32_t args_u32[6] = {};
		unsigned long args_pointer = extract__syscall_argument(regs, 1);
		bpf_probe_read_user(args_u32, num * sizeof(uint32_t), (void *)args_pointer);

		unsigned long *dst = (unsigned long *)argv;
		for(int i = 0; i < num; i++) {
			dst[i] = (unsigned long)args_u32[i];
		}
		return;
	}
#endif
	unsigned long *dst = (unsigned long *)argv;
	for(int i = 0; i < num; i++) {
		dst[i] = extract__syscall_argument(regs, i);
	}
}

///////////////////////////
// ENCODE DEVICE NUMBER
///////////////////////////

/**
 * @brief Encode device number with `MAJOR` and `MINOR` MACRO.
 *
 * Please note: **Used only inside this file**.
 *
 * @param dev device number extracted directly from the kernel.
 * @return encoded device number.
 */
static __always_inline dev_t encode_dev(dev_t dev) {
	unsigned int major = MAJOR(dev);
	unsigned int minor = MINOR(dev);

	return (minor & 0xff) | (major << 8) | ((minor & ~0xff) << 12);
}

///////////////////////////
// FILE EXTRACTION
///////////////////////////

/**
 * @brief Return `file` struct from a file descriptor.
 *
 * @param file_descriptor generic file descriptor.
 * @return struct file* pointer to the `struct file` associated with the
 * file descriptor. Return a NULL pointer in case of failure.
 */
static __always_inline struct file *extract__file_struct_from_fd(int32_t file_descriptor) {
	struct file *f = NULL;
	if(file_descriptor >= 0) {
		struct file **fds = NULL;
		struct fdtable *fdt = NULL;
		int max_fds = 0;

		struct task_struct *task = get_current_task();
		BPF_CORE_READ_INTO(&fdt, task, files, fdt);
		if(unlikely(fdt == NULL)) {
			return NULL;
		}

		// Try a bound check to avoid reading out of bounds.
		BPF_CORE_READ_INTO(&max_fds, fdt, max_fds);
		if(unlikely(file_descriptor >= max_fds)) {
			return NULL;
		}

		BPF_CORE_READ_INTO(&fds, fdt, fd);
		if(fds != NULL) {
			bpf_probe_read_kernel(&f, sizeof(struct file *), &fds[file_descriptor]);
		}
	}
	return f;
}

/**
 * \brief Extract the inode number from a file descriptor.
 *
 * @param fd generic file descriptor.
 * @param ino pointer to the inode number we have to fill.
 */
static __always_inline void extract__ino_from_fd(int32_t fd, uint64_t *ino) {
	struct file *f = extract__file_struct_from_fd(fd);
	if(!f) {
		return;
	}

	BPF_CORE_READ_INTO(ino, f, f_inode, i_ino);
}

/**
 * @brief Return the `f_inode` of task exe_file.
 *
 * @param task pointer to task struct.
 * @return `f_inode` of task exe_file.
 */
static __always_inline struct inode *extract__exe_inode_from_task(struct task_struct *task) {
	return BPF_CORE_READ(task, mm, exe_file, f_inode);
}

/**
 * @brief Return the `exe_file` of task mm.
 *
 * @param task pointer to task struct.
 * @return `f_inode` of task mm.
 */
static __always_inline struct file *extract__exe_file_from_task(struct task_struct *task) {
	return READ_TASK_FIELD(task, mm, exe_file);
}

/**
 * @brief Return the `i_ino` from f_inode.
 *
 * @param mm pointer to inode struct.
 * @param ino pointer to the inode number we have to fill.
 * @return `i_ino` from f_inode.
 */
static __always_inline void extract__ino_from_inode(struct inode *f_inode, uint64_t *ino) {
	BPF_CORE_READ_INTO(ino, f_inode, i_ino);
}

/**
 * @brief Return epoch in ns from struct timespec64.
 *
 * @param time timespec64 struct.
 * @return epoch in ns.
 */
static __always_inline uint64_t extract__epoch_ns_from_time(struct timespec64 time) {
	time64_t tv_sec = time.tv_sec;
	if(tv_sec < 0) {
		return 0;
	}
	return (tv_sec * (uint64_t)1000000000 + time.tv_nsec);
}

/**
 * \brief Extract the file mode created flag from a file descriptor.
 *
 * @param fd generic file descriptor.
 * @return PPM_O_F_CREATED if file is created.
 */
static __always_inline uint32_t extract__fmode_created_from_fd(int32_t fd) {
	if(fd < 0) {
		return 0;
	}

	struct file *f = extract__file_struct_from_fd(fd);
	if(!f) {
		return 0;
	}

	uint32_t mode = BPF_CORE_READ(f, f_mode);

	if(mode & FMODE_CREATED)
		return PPM_O_F_CREATED;

	return 0;
}

/**
 * @brief Extract the fd rlimit
 *
 * @param task pointer to the task struct.
 * @param fdlimit return value passed by reference.
 */
static __always_inline void extract__fdlimit(struct task_struct *task, unsigned long *fdlimit) {
	READ_TASK_FIELD_INTO(fdlimit, task, signal, rlim[RLIMIT_NOFILE].rlim_cur);
}

/////////////////////////
// CAPABILITIES EXTRACTION
////////////////////////

/**
 * @brief Extract capabilities
 *
 * Right now we support only 3 types of capabilities:
 * - cap_inheritable
 * - cap_permitted
 * - cap_effective
 *
 * To extract the specific capabilities use the enum defined by us
 * at the beginning of this file:
 * - CAP_INHERITABLE
 * - CAP_PERMITTED
 * - CAP_EFFECTIVE
 *
 * @param task pointer to task struct.
 * @param capability_type type of capability to extract defined by us.
 * @return PPM encoded capability value
 */
static __always_inline uint64_t extract__capability(struct task_struct *task,
                                                    enum capability_type capability_type) {
	kernel_cap_t cap_struct;
	unsigned long capability;

	switch(capability_type) {
	case CAP_INHERITABLE:
		BPF_CORE_READ_INTO(&cap_struct, task, cred, cap_inheritable);
		break;

	case CAP_PERMITTED:
		BPF_CORE_READ_INTO(&cap_struct, task, cred, cap_permitted);
		break;

	case CAP_EFFECTIVE:
		BPF_CORE_READ_INTO(&cap_struct, task, cred, cap_effective);
		break;

	default:
		return 0;
		break;
	}

	// Kernel 6.3 changed the kernel_cap_struct type from uint32_t[2] to uint64_t.
	// Luckily enough, it also changed field name from cap to val.
	if(bpf_core_field_exists(((struct kernel_cap_struct *)0)->cap)) {
		return capabilities_to_scap(((unsigned long)cap_struct.cap[1] << 32) | cap_struct.cap[0]);
	}
	kernel_cap_t___v6_3 *new_cap = (kernel_cap_t___v6_3 *)&cap_struct;
	return capabilities_to_scap(((unsigned long)new_cap->val));
}

/////////////////////////
// PIDS EXTRACION
////////////////////////

/**
 * @brief Return the pid struct according to the pid type chosen.
 *
 * @param task pointer to the task struct.
 * @param type pid type.
 * @return struct pid * pointer to the right pid struct.
 */
static __always_inline struct pid *extract__task_pid_struct(struct task_struct *task,
                                                            enum pid_type type) {
	struct pid *task_pid = NULL;
	switch(type) {
	/* we cannot take this info from signal struct. */
	case PIDTYPE_PID:
		READ_TASK_FIELD_INTO(&task_pid, task, thread_pid);
		break;
	default:
		READ_TASK_FIELD_INTO(&task_pid, task, signal, pids[type]);
		break;
	}
	return task_pid;
}

/**
 * @brief Returns the pid namespace in which the specified pid was allocated.
 *
 * @param pid pointer to the task pid struct.
 * @return struct pid_namespace* in which the specified pid was allocated.
 */
static __always_inline struct pid_namespace *extract__namespace_of_pid(struct pid *pid) {
	uint32_t level = 0;
	struct pid_namespace *ns = NULL;
	if(pid) {
		BPF_CORE_READ_INTO(&level, pid, level);
		BPF_CORE_READ_INTO(&ns, pid, numbers[level].ns);
	}
	return ns;
}

/**
 * @brief extract the `xid` (where x can be 'p', 't', ...) according to the
 * `pid struct` passed as parameter.
 *
 * @param pid pointer to the pid struct.
 * @param ns pointer to the namespace struct.
 * @return pid_t id seen from the pid namespace 'ns'.
 */
static __always_inline pid_t extract__xid_nr_seen_by_namespace(struct pid *pid,
                                                               struct pid_namespace *ns) {
	struct upid upid = {0};
	pid_t nr = 0;
	unsigned int pid_level = 0;
	unsigned int ns_level = 0;
	BPF_CORE_READ_INTO(&pid_level, pid, level);
	BPF_CORE_READ_INTO(&ns_level, ns, level);

	if(pid && ns_level <= pid_level) {
		BPF_CORE_READ_INTO(&upid, pid, numbers[ns_level]);
		if(upid.ns == ns) {
			nr = upid.nr;
		}
	}
	return nr;
}

/*
 * Definitions taken from `/include/linux/sched.h`.
 *
 * the helpers to get the task's different pids as they are seen
 * from various namespaces. In all these methods 'nr' stands for 'numeric'.
 *
 * extract_task_(X)id_nr()     : global id, i.e. the id seen from the init namespace;
 * extract_task_(X)id_vnr()    : virtual id, i.e. the id seen from the pid namespace of current.
 *
 */

/**
 * @brief Return the `xid` (where x can be `p`, `tg`, `pp` ...) seen from the
 *  init namespace.
 *
 * @param task pointer to task struct.
 * @param type pid type.
 * @return `xid` seen from the init namespace.
 */
static __always_inline pid_t extract__task_xid_nr(struct task_struct *task, enum pid_type type) {
	switch(type) {
	case PIDTYPE_PID:
		return READ_TASK_FIELD(task, pid);

	case PIDTYPE_TGID:
		return READ_TASK_FIELD(task, tgid);

	case PIDTYPE_PGID:
		return READ_TASK_FIELD(task, real_parent, pid);

	default:
		return 0;
	}
}

/**
 * @brief Return the `xid` (where x can be `p`, `tg`, `pp` ...) seen from the
 *  pid namespace of the current task.
 *
 * @param task pointer to task struct.
 * @param type pid type.
 * @return `xid` seen from the current task pid namespace.
 */
static __always_inline pid_t extract__task_xid_vnr(struct task_struct *task, enum pid_type type) {
	struct pid *pid_struct = extract__task_pid_struct(task, type);
	struct pid_namespace *pid_namespace_struct = extract__namespace_of_pid(pid_struct);
	return extract__xid_nr_seen_by_namespace(pid_struct, pid_namespace_struct);
}

/**
 * @brief Return the `start_time` of init task struct from pid namespace seen from
 *  pid namespace of the current task. Monotonic time in nanoseconds.
 *
 * @param task pointer to task struct.
 * @param type pid type.
 * @return `start_time` of init task struct from pid namespace seen from current task pid namespace.
 */
static __always_inline uint64_t extract__task_pidns_start_time(struct task_struct *task,
                                                               enum pid_type type,
                                                               long in_childtid) {
	// only perform lookup when clone/vfork/fork returns 0 (child process / childtid)
	if(in_childtid == 0) {
		struct pid *pid_struct = extract__task_pid_struct(task, type);
		struct pid_namespace *pid_namespace = extract__namespace_of_pid(pid_struct);
		return BPF_CORE_READ(pid_namespace, child_reaper, start_time);
	}
	return 0;
}

/////////////////////////
// PAGE INFO EXTRACION
////////////////////////

/**
 * @brief Extract major page fault number
 *
 * @param task pointer to task struct.
 * @param pgft_maj return value passed by reference.
 */
static __always_inline void extract__pgft_maj(struct task_struct *task, unsigned long *pgft_maj) {
	READ_TASK_FIELD_INTO(pgft_maj, task, maj_flt);
}

/**
 * @brief Extract minor page fault number
 *
 * @param task pointer to task struct.
 * @param pgft_min return value passed by reference.
 */
static __always_inline void extract__pgft_min(struct task_struct *task, unsigned long *pgft_min) {
	READ_TASK_FIELD_INTO(pgft_min, task, min_flt);
}

/**
 * @brief Extract total page size
 *
 * @param mm pointer to mm_struct.
 * @return number in KB
 */
static __always_inline unsigned long extract__vm_size(struct mm_struct *mm) {
	unsigned long vm_pages = 0;
	BPF_CORE_READ_INTO(&vm_pages, mm, total_vm);
	return DO_PAGE_SHIFT(vm_pages);
}

/**
 * @brief Extract resident page size
 *
 * @param mm pointer to mm_struct.
 * @return number in KB
 */
static __always_inline unsigned long extract__vm_rss(struct mm_struct *mm) {
	int64_t file_pages = 0;
	int64_t anon_pages = 0;
	int64_t shmem_pages = 0;

	/* In recent kernel versions
	 * (https://github.com/torvalds/linux/commit/f1a7941243c102a44e8847e3b94ff4ff3ec56f25) `struct
	 * mm_rss_stat` doesn't exist anymore.
	 */
	if(bpf_core_type_exists(struct mm_rss_stat)) {
		BPF_CORE_READ_INTO(&file_pages, mm, rss_stat.count[MM_FILEPAGES].counter);
		BPF_CORE_READ_INTO(&anon_pages, mm, rss_stat.count[MM_ANONPAGES].counter);
		BPF_CORE_READ_INTO(&shmem_pages, mm, rss_stat.count[MM_SHMEMPAGES].counter);
	} else {
		struct mm_struct___v6_2 *mm_v6_2 = (void *)mm;
		BPF_CORE_READ_INTO(&file_pages, mm_v6_2, rss_stat[MM_FILEPAGES].count);
		BPF_CORE_READ_INTO(&anon_pages, mm_v6_2, rss_stat[MM_ANONPAGES].count);
		BPF_CORE_READ_INTO(&shmem_pages, mm_v6_2, rss_stat[MM_SHMEMPAGES].count);
	}
	return DO_PAGE_SHIFT(file_pages + anon_pages + shmem_pages);
}

/**
 * @brief Extract swap page size
 *
 * @param mm pointer to mm_struct.
 * @return number in KB
 */
static __always_inline unsigned long extract__vm_swap(struct mm_struct *mm) {
	int64_t swap_entries = 0;
	if(bpf_core_type_exists(struct mm_rss_stat)) {
		BPF_CORE_READ_INTO(&swap_entries, mm, rss_stat.count[MM_SWAPENTS].counter);
	} else {
		struct mm_struct___v6_2 *mm_v6_2 = (void *)mm;
		BPF_CORE_READ_INTO(&swap_entries, mm_v6_2, rss_stat[MM_SWAPENTS].count);
	}
	return DO_PAGE_SHIFT(swap_entries);
}

/////////////////////////
// TTY EXTRACTION
////////////////////////

/**
 * @brief Extract encoded tty
 *
 * @param task pointer to task_struct.
 * @return encoded tty number
 */
static __always_inline uint32_t exctract__tty(struct task_struct *task) {
	struct signal_struct *signal;
	struct tty_struct *tty;
	struct tty_driver *driver;
	int major = 0;
	int minor_start = 0;
	int index = 0;

	/* Direct access of fields w/ READ_TASK_FIELD_INTO or READ_TASK_FIELD can
	cause issues for tty extraction. Adopt approach of incremental lookups and
	checks similar to driver-bpf */

	BPF_CORE_READ_INTO(&signal, task, signal);
	if(!signal) {
		return 0;
	}

	BPF_CORE_READ_INTO(&tty, signal, tty);
	if(!tty) {
		return 0;
	}

	BPF_CORE_READ_INTO(&driver, tty, driver);
	if(!driver) {
		return 0;
	}

	BPF_CORE_READ_INTO(&index, tty, index);
	BPF_CORE_READ_INTO(&major, driver, major);
	BPF_CORE_READ_INTO(&minor_start, driver, minor_start);
	return encode_dev(MKDEV(major, minor_start) + index);
}

/////////////////////////
// LOGINUID EXTRACTION
////////////////////////

/**
 * @brief Extract loginuid
 *
 * @param task pointer to task struct
 * @param loginuid return value by reference
 */
static __always_inline void extract__loginuid(struct task_struct *task, uint32_t *loginuid) {
	*loginuid = UINT32_MAX;

	if(bpf_core_field_exists(task->loginuid)) {
		READ_TASK_FIELD_INTO(loginuid, task, loginuid.val);
	} else {
		struct task_struct___cos *task_cos = (void *)task;

		if(bpf_core_field_exists(struct task_struct___cos, audit)) {
			BPF_CORE_READ_INTO(loginuid, task_cos, audit, loginuid.val);
		}
	}
}

/////////////////////////
// EXTRACT CLONE FLAGS
////////////////////////

/**
 * @brief To extract clone flags we need to read some info in the kernel
 *
 * @param task pointer to the task struct.
 * @param flags internal flag representation.
 * @return scap flag representation.
 */
static __always_inline unsigned long extract__clone_flags(struct task_struct *task,
                                                          unsigned long flags) {
	unsigned long ppm_flags = clone_flags_to_scap((int)flags);
	struct pid *pid = extract__task_pid_struct(task, PIDTYPE_PID);
	struct pid_namespace *ns = extract__namespace_of_pid(pid);
	unsigned int ns_level;
	BPF_CORE_READ_INTO(&ns_level, ns, level);

	if(ns_level != 0) {
		ppm_flags |= PPM_CL_CHILD_IN_PIDNS;
	} else {
		/* This alternative check is meaningful only for the parent and not for the child */
		struct pid_namespace *ns_children;
		READ_TASK_FIELD_INTO(&ns_children, task, nsproxy, pid_ns_for_children);

		if(ns_children != ns) {
			ppm_flags |= PPM_CL_CHILD_IN_PIDNS;
		}
	}
	return ppm_flags;
}

/////////////////////////
// UID EXTRACTION
////////////////////////

/**
 * @brief Extract euid
 *
 * @param task pointer to task struct
 * @param euid return value by reference
 */
static __always_inline void extract__euid(struct task_struct *task, uint32_t *euid) {
	*euid = UINT32_MAX;
	BPF_CORE_READ_INTO(euid, task, cred, euid.val);
}

/**
 * @brief Extract egid
 *
 * @param task pointer to task struct
 * @param egid return value by reference
 */
static __always_inline void extract__egid(struct task_struct *task, uint32_t *egid) {
	BPF_CORE_READ_INTO(egid, task, cred, egid.val);
}

/////////////////////////
// EXECVE FLAGS EXTRACTION
////////////////////////

static __always_inline enum ppm_overlay extract__overlay_layer(struct file *file) {
	struct dentry *dentry = (struct dentry *)BPF_CORE_READ(file, f_path.dentry);
	unsigned long sb_magic = BPF_CORE_READ(dentry, d_sb, s_magic);

	if(sb_magic != PPM_OVERLAYFS_SUPER_MAGIC) {
		return PPM_NOT_OVERLAY_FS;
	}

	char *vfs_inode = (char *)BPF_CORE_READ(dentry, d_inode);
	// We need to compute the size of the inode struct at load time since it can change between
	// kernel versions
	unsigned long inode_size = bpf_core_type_size(struct inode);
	if(!inode_size) {
		return PPM_OVERLAY_LOWER;
	}

	struct dentry *upper_dentry = NULL;
	bpf_probe_read_kernel(&upper_dentry, sizeof(upper_dentry), (char *)vfs_inode + inode_size);
	if(!upper_dentry) {
		return PPM_OVERLAY_LOWER;
	}

	if(BPF_CORE_READ(upper_dentry, d_inode, i_ino) != 0) {
		return PPM_OVERLAY_UPPER;
	}
	return PPM_OVERLAY_LOWER;
}

/*
 * Detect whether the file being referenced is an anonymous file created using memfd_create()
 * and is being executed by referencing its file descriptor (fd). This type of file does not
 * exist on disk and resides solely in memory, but it is treated as a legitimate file with an
 * inode object and other file attributes.
 *
 **/
static __always_inline bool extract__exe_from_memfd(struct file *file) {
	struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
	if(!dentry) {
		bpf_printk("extract__exe_from_memfd(): failed to get dentry");
		return false;
	}

	struct dentry *parent = BPF_CORE_READ(dentry, d_parent);
	if(!parent) {
		bpf_printk("extract__exe_from_memfd(): failed to get parent");
		return false;
	}

	if(parent != dentry) {
		return false;
	}

	const unsigned char *name = BPF_CORE_READ(dentry, d_name.name);
	if(!name) {
		bpf_printk("extract__exe_from_memfd(): failed to get name");
		return false;
	}

	const char expected_prefix[] = "memfd:";
	char memfd_name[sizeof(expected_prefix)] = {'\0'};

	if(bpf_probe_read_kernel_str(memfd_name, sizeof(memfd_name), name) != sizeof(expected_prefix)) {
		return false;
	}

	for(int i = 0; i < sizeof(expected_prefix); i++) {
		if(expected_prefix[i] != memfd_name[i]) {
			return false;
		}
	}

	return true;
}

/**
 * \brief Extract the device number and the inode number from a file descriptor.
 *
 * @param fd generic file descriptor.
 * @param dev pointer to the device number we have to fill.
 * @param ino pointer to the inode number we have to fill.
 * @param ol pointer to the overlay layer we have to fill.
 */
static __always_inline void extract__dev_ino_overlay_from_fd(int32_t fd,
                                                             dev_t *dev,
                                                             uint64_t *ino,
                                                             enum ppm_overlay *ol) {
	struct file *f = extract__file_struct_from_fd(fd);
	if(!f) {
		return;
	}

	struct inode *i = BPF_CORE_READ(f, f_inode);
	*ol = extract__overlay_layer(f);

	BPF_CORE_READ_INTO(dev, i, i_sb, s_dev);
	*dev = encode_dev(*dev);
	BPF_CORE_READ_INTO(ino, i, i_ino);
}

/* log(NGROUPS_MAX) = log(65536) */
#define MAX_GROUP_SEARCH_DEPTH 16

/* defined in /include/linux/user_namespace.h */
#define UID_GID_MAP_MAX_BASE_EXTENTS 5

/* UP means get NS id (uid/gid) from kuid/kgid */
static __always_inline uint32_t bpf_map_id_up(struct uid_gid_map *map, uint32_t id) {
	uint32_t first = 0;
	uint32_t last = 0;
	uint32_t nr_extents = BPF_CORE_READ(map, nr_extents);
	struct uid_gid_extent *extent = NULL;

	for(int j = 0; j < UID_GID_MAP_MAX_BASE_EXTENTS; j++) {
		if(j >= nr_extents) {
			break;
		}

		first = BPF_CORE_READ(map, extent[j].lower_first);
		last = first + BPF_CORE_READ(map, extent[j].count) - 1;
		if(id >= first && id <= last) {
			extent = &map->extent[j];
			break;
		}
	}

	/* Map the id or note failure */
	if(extent) {
		uint32_t first = BPF_CORE_READ(extent, first);
		uint32_t lower_first = BPF_CORE_READ(extent, lower_first);
		id = id - lower_first + first;
	} else {
		id = (uint32_t)-1;
	}

	return id;
}

static __always_inline bool groups_search(struct task_struct *task, uint32_t grp) {
	struct group_info *group_info = NULL;
	BPF_CORE_READ_INTO(&group_info, task, cred, group_info);
	if(!group_info) {
		return false;
	}

	unsigned int left = 0;
	unsigned int right = BPF_CORE_READ(group_info, ngroups);
	unsigned int mid = 0;
	uint32_t grp_mid = 0;

	for(int j = 0; j < MAX_GROUP_SEARCH_DEPTH; j++) {
		if(left >= right) {
			break;
		}

		mid = (left + right) / 2;
		BPF_CORE_READ_INTO(&grp_mid, group_info, gid[mid].val);

		if(grp > grp_mid) {
			left = mid + 1;
		} else if(grp < grp_mid) {
			right = mid;
		} else {
			return true;
		}
	}

	return false;
}

static __always_inline bool extract__exe_writable(struct task_struct *task, struct inode *inode) {
	umode_t i_mode = BPF_CORE_READ(inode, i_mode);
	uint32_t i_flags = BPF_CORE_READ(inode, i_flags);
	long unsigned int s_flags = BPF_CORE_READ(inode, i_sb, s_flags);

	/* Check superblock permissions, i.e. if the FS is read only */
	if((s_flags & SB_RDONLY) && (S_ISREG(i_mode) || S_ISDIR(i_mode) || S_ISLNK(i_mode))) {
		return false;
	}

	if(i_flags & S_IMMUTABLE) {
		return false;
	}

	uint32_t i_uid = BPF_CORE_READ(inode, i_uid.val);
	uint32_t i_gid = BPF_CORE_READ(inode, i_gid.val);

	uint32_t fsuid;
	uint32_t fsgid;
	BPF_CORE_READ_INTO(&fsuid, task, cred, fsuid.val);
	BPF_CORE_READ_INTO(&fsgid, task, cred, fsgid.val);

	/* HAS_UNMAPPED_ID() */
	if(i_uid == -1 || i_gid == -1) {
		return false;
	}

	/* inode_owner_or_capable check. If the owner matches the exe counts as writable */
	if(fsuid == i_uid) {
		return true;
	}

	// Basic file permission check -- this may not work in all cases as kernel functions are more
	// complex and take into account different types of ACLs which can use custom function pointers,
	// but I don't think we can inspect those in eBPF

	// basic acl_permission_check()

	// XXX this doesn't attempt to locate extra POSIX ACL checks (if supported by the kernel)

	umode_t mode = i_mode;

	if(i_uid == fsuid) {
		mode >>= 6;
	} else {
		bool in_group = false;

		if(i_gid == fsgid) {
			in_group = true;
		} else {
			in_group = groups_search(task, i_gid);
		}

		if(in_group) {
			mode >>= 3;
		}
	}

	if((MAY_WRITE & ~mode) == 0) {
		return true;
	}

	struct user_namespace *ns;
	BPF_CORE_READ_INTO(&ns, task, cred, user_ns);
	if(ns == NULL) {
		return false;
	}
	bool kuid_mapped = bpf_map_id_up(&ns->uid_map, i_uid) != (uint32_t)-1;
	bool kgid_mapped = bpf_map_id_up(&ns->gid_map, i_gid) != (uint32_t)-1;

	kernel_cap_t cap_struct = {0};
	BPF_CORE_READ_INTO(&cap_struct, task, cred, cap_effective);
	// Kernel 6.3 changed the kernel_cap_struct type from uint32_t[2] to uint64_t.
	// Luckily enough, it also changed field name from cap to val.
	if(bpf_core_field_exists(((struct kernel_cap_struct *)0)->cap)) {
		if(cap_raised(cap_struct, CAP_DAC_OVERRIDE) && kuid_mapped && kgid_mapped) {
			return true;
		}

		/* Check if the user is capable. Even if it doesn't own the file or the read bits are not
		 * set, root with CAP_FOWNER can do what it wants. */
		if(cap_raised(cap_struct, CAP_FOWNER) && kuid_mapped) {
			return true;
		}
	} else {
		kernel_cap_t___v6_3 *new_cap = (kernel_cap_t___v6_3 *)&cap_struct;
		if(cap_raised___v6_3(*new_cap, CAP_DAC_OVERRIDE) && kuid_mapped && kgid_mapped) {
			return true;
		}

		/* Check if the user is capable. Even if it doesn't own the file or the read bits are not
		 * set, root with CAP_FOWNER can do what it wants. */
		if(cap_raised___v6_3(*new_cap, CAP_FOWNER) && kuid_mapped) {
			return true;
		}
	}

	return false;
}

/**
 * @brief Return a socket pointer from a file pointer.
 * @param file pointer to the file struct.
 */
static __always_inline struct socket *get_sock_from_file(struct file *file) {
	if(file == NULL) {
		return NULL;
	}

	struct file_operations *fop = (struct file_operations *)BPF_CORE_READ(file, f_op);
	if(fop != maps__get_socket_file_ops()) {
		// We are not a socket.
		return NULL;
	}
	return (struct socket *)BPF_CORE_READ(file, private_data);
}

///////////////////////////
// EXTRACT FROM MSGHDR
///////////////////////////

/**
 * @brief Read the msghdr pointed by `msghdr_pointer` and store it in `msghdr` location.
 * @param msghdr pointer to the user_msghdr struct used to store the read msghdr.
 * @param msghdr_pointer pointer to the msghdr to be read.
 * @return 0 on success, or a negative error in case of failure.
 */
static __always_inline long extract__msghdr(struct user_msghdr *msghdr,
                                            unsigned long msghdr_pointer) {
	return bpf_probe_read_user((void *)msghdr,
	                           bpf_core_type_size(struct user_msghdr),
	                           (void *)msghdr_pointer);
}

/**
 * @brief Extract the size of a message extracted from an `iovec` struct array.
 * @param scratch_space pointer the scratch space on which iovecs are read.
 * @param scratch_space_size scratch space total size.
 * @param iov_pointer pointer to `iovec` struct array.
 * @param iov_cnt number of `iovec` structs.
 * @return the size of the message on success, or 0 in case of failure.
 */
static __always_inline uint32_t extract__iovec_size(void *scratch_space,
                                                    uint32_t scratch_space_size,
                                                    unsigned long iov_pointer,
                                                    unsigned long iov_cnt) {
	if(bpf_probe_read_user(scratch_space, scratch_space_size, (void *)iov_pointer)) {
		return 0;
	}

	uint32_t total_size_to_read = 0;
	const struct iovec *iovec = (const struct iovec *)scratch_space;
	for(int i = 0; i < MAX_IOVCNT; i++) {
		if(i == iov_cnt) {
			break;
		}
		total_size_to_read += iovec[i].iov_len;
	}
	return total_size_to_read;
}
