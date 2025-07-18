// SPDX-License-Identifier: GPL-2.0-only OR MIT
/*

Copyright (C) 2023 The Falco Authors.

This file is dual licensed under either the MIT or GPL 2. See MIT.txt
or GPL2.txt for full copies of the license.

*/
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/compat.h>
#include <linux/cdev.h>
#include <asm/unistd.h>
#include <net/sock.h>
#include <net/af_unix.h>
#include <net/compat.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/fdtable.h>
#include <linux/file.h>
#include <linux/fs_struct.h>
#include <linux/pid_namespace.h>
#include <linux/ptrace.h>
#include <linux/version.h>
#include <linux/module.h>
#include <linux/quota.h>
#include <linux/tty.h>
#include <linux/uaccess.h>
#include <linux/audit.h>
#ifdef CONFIG_CGROUPS
#include <linux/cgroup.h>
#endif
#include <asm/syscall.h>
#include "ppm_ringbuffer.h"
#include "ppm_events_public.h"
#include "ppm_events.h"
#include "ppm.h"
#include "ppm_flag_helpers.h"
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 18, 0)
#include <linux/bpf.h>
#endif
#include "kernel_hacks.h"
#include "systype_compat.h"

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 13, 0)
struct ovl_entry {
	struct dentry *__upperdentry;
	struct ovl_dir_cache *cache;
	union {
		struct {
			uint64_t version;
			const char *redirect;
			bool opaque;
			bool impure;
			bool copying;
		};
		struct rcu_head rcu;
	};
	unsigned numlower;
	struct path lowerstack[];
};
#endif

#define merge_64(hi, lo) ((((unsigned long long)(hi)) << 32) + ((lo) & 0xffffffffUL))

static enum ppm_overlay ppm_get_overlay_layer(struct file *file);

static inline struct pid_namespace *pid_ns_for_children(struct task_struct *task) {
#if(LINUX_VERSION_CODE < KERNEL_VERSION(3, 11, 0))
	return task->nsproxy->pid_ns;
#else
	return task->nsproxy->pid_ns_for_children;
#endif
}

/*
 * Detect whether the file being referenced is an anonymous file created using memfd_create()
 * and is being executed by referencing its file descriptor (fd). This type of file does not
 * exist on disk and resides solely in memory, but it is treated as a legitimate file with an
 * inode object and other file attributes.
 *
 **/
static inline uint32_t get_exe_from_memfd(const struct file *exe_file) {
#if defined(CONFIG_MEMFD_CREATE) && CONFIG_MEMFD_CREATE == 1
	const char expected_prefix[] = "memfd:";
	if(!(exe_file && exe_file->f_path.dentry &&
	     exe_file->f_path.dentry == exe_file->f_path.dentry->d_parent)) {
		return 0;
	}

	if(strncmp(exe_file->f_path.dentry->d_name.name,
	           expected_prefix,
	           sizeof(expected_prefix) - 1) == 0) {
		return PPM_EXE_FROM_MEMFD;
	}
#endif
	return 0;
}

int f_sys_generic(struct event_filler_arguments *args) {
	int res;
	long table_index = args->syscall_id - SYSCALL_TABLE_ID0;

	/*
	 * name
	 */

	if(likely(table_index >= 0 && table_index < SYSCALL_TABLE_SIZE)) {
		ppm_sc_code sc_code = g_syscall_table[table_index].ppm_sc;

		/*
		 * ID
		 */
		res = val_to_ring(args, sc_code, 0, false, 0);
		CHECK_RES(res);

		if(args->event_type == PPME_GENERIC_E) {
			/*
			 * nativeID
			 */
			res = val_to_ring(args, args->syscall_id, 0, false, 0);
			CHECK_RES(res);
		}
	} else {
		ASSERT(false);
		res = val_to_ring(args, (uint64_t) "<out of bound>", 0, false, 0);
		CHECK_RES(res);
	}

	return add_sentinel(args);
}

int f_sys_empty(struct event_filler_arguments *args) {
	return add_sentinel(args);
}

int f_sys_single(struct event_filler_arguments *args) {
	int res;
	unsigned long val;

	syscall_get_arguments_deprecated(args, 0, 1, &val);
	res = val_to_ring(args, val, 0, true, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_single_x(struct event_filler_arguments *args) {
	int res;
	int64_t retval;

	retval = (int64_t)(long)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_fstat_e(struct event_filler_arguments *args) {
	int res = 0;
	unsigned long val = 0;
	int64_t fd = 0;

	/* Parameter 1: fd (type: PT_FD) */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	fd = (int64_t)(int32_t)val;
	res = val_to_ring(args, fd, 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_fstat_x(struct event_filler_arguments *args) {
	int64_t retval;
	int res;
	unsigned long val;
	int64_t fd;

	/* Parameter 1: res (type: PT_ERRNO) */
	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 2: fd (type: PT_FD) */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	fd = (int64_t)(int32_t)val;
	res = val_to_ring(args, fd, 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

static inline void get_ino_from_fd(int64_t fd, uint64_t *ino) {
	struct files_struct *files;
	struct fdtable *fdt;
	struct inode *inode;
	struct file *file;

	if(fd < 0)
		return;

	files = current->files;
	if(unlikely(!files))
		return;

	spin_lock(&files->file_lock);
	fdt = files_fdtable(files);
	if(unlikely(fd > fdt->max_fds))
		goto out_unlock;

	file = fdt->fd[fd];
	if(unlikely(!file))
		goto out_unlock;

	inode = file_inode(file);
	if(unlikely(!inode))
		goto out_unlock;

	*ino = inode->i_ino;

out_unlock:
	spin_unlock(&files->file_lock);
	return;
}

static inline void get_dev_ino_overlay_from_fd(int64_t fd,
                                               uint32_t *dev,
                                               uint64_t *ino,
                                               enum ppm_overlay *ol) {
	struct files_struct *files;
	struct fdtable *fdt;
	struct inode *inode;
	struct super_block *sb;
	struct file *file;

	if(fd < 0)
		return;

	files = current->files;
	if(unlikely(!files))
		return;

	spin_lock(&files->file_lock);
	fdt = files_fdtable(files);
	if(unlikely(fd > fdt->max_fds))
		goto out_unlock;

	file = fdt->fd[fd];
	if(unlikely(!file))
		goto out_unlock;

	*ol = ppm_get_overlay_layer(file);

	inode = file_inode(file);
	if(unlikely(!inode))
		goto out_unlock;

	*ino = inode->i_ino;

	sb = inode->i_sb;
	if(unlikely(!sb))
		goto out_unlock;

	*dev = new_encode_dev(sb->s_dev);

out_unlock:
	spin_unlock(&files->file_lock);
	return;
}

static inline void get_fd_fmode_created(int64_t fd, unsigned long *flags) {
/* FMODE_CREATED flag was introduced in kernel 4.19 and it's not present in earlier versions */
#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 19, 0)
	struct files_struct *files;
	struct fdtable *fdt;
	struct file *file;

	if(fd < 0)
		return;

	files = current->files;
	if(unlikely(!files))
		return;

	spin_lock(&files->file_lock);
	fdt = files_fdtable(files);
	if(unlikely(fd > fdt->max_fds))
		goto out_unlock;

	file = fdt->fd[fd];
	if(unlikely(!file))
		goto out_unlock;

	if(file->f_mode & FMODE_CREATED)
		*flags |= PPM_O_F_CREATED;

out_unlock:
	spin_unlock(&files->file_lock);
#endif
	return;
}

int f_sys_open_e(struct event_filler_arguments *args) {
	unsigned long val;
	unsigned long flags;
	unsigned long modes;
	int res;

	/*
	 * name
	 */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	res = val_to_ring(args, val, 0, true, 0);
	CHECK_RES(res);

	/*
	 * Flags
	 * Note that we convert them into the ppm portable representation before pushing them to the
	 * ring
	 */
	syscall_get_arguments_deprecated(args, 1, 1, &flags);
	res = val_to_ring(args, open_flags_to_scap(flags), 0, false, 0);
	CHECK_RES(res);

	/*
	 *  mode
	 */
	syscall_get_arguments_deprecated(args, 2, 1, &modes);
	res = val_to_ring(args, open_modes_to_scap(flags, modes), 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_open_x(struct event_filler_arguments *args) {
	unsigned long val;
	unsigned long flags;
	unsigned long scap_flags;
	unsigned long modes;
	uint32_t dev = 0;
	uint64_t ino = 0;
	int res;
	int64_t retval;
	enum ppm_overlay ol = PPM_NOT_OVERLAY_FS;

	/*
	 * fd
	 */
	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	CHECK_RES(res);

	/*
	 * name
	 */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	res = val_to_ring(args, val, 0, true, 0);
	CHECK_RES(res);

	get_dev_ino_overlay_from_fd(retval, &dev, &ino, &ol);

	/*
	 * Flags
	 * Note that we convert them into the ppm portable representation before pushing them to the
	 * ring
	 */
	syscall_get_arguments_deprecated(args, 1, 1, &flags);
	scap_flags = open_flags_to_scap(flags);
	/* update scap flags if file is created */
	get_fd_fmode_created(retval, &scap_flags);
	if(ol == PPM_OVERLAY_UPPER) {
		scap_flags |= PPM_FD_UPPER_LAYER;
	} else if(ol == PPM_OVERLAY_LOWER) {
		scap_flags |= PPM_FD_LOWER_LAYER;
	}
	res = val_to_ring(args, scap_flags, 0, false, 0);
	CHECK_RES(res);

	/*
	 *  mode
	 */
	syscall_get_arguments_deprecated(args, 2, 1, &modes);
	res = val_to_ring(args, open_modes_to_scap(flags, modes), 0, false, 0);
	CHECK_RES(res);

	/*
	 *  dev
	 */
	res = val_to_ring(args, dev, 0, false, 0);
	CHECK_RES(res);

	/*
	 *  ino
	 */
	res = val_to_ring(args, ino, 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_read_e(struct event_filler_arguments *args) {
	unsigned long val = 0;
	int res = 0;
	int32_t fd = 0;

	/* Parameter 1: fd (type: PT_FD) */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	fd = (int32_t)val;
	res = val_to_ring(args, (int64_t)fd, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 2: size (type: PT_UINT32) */
	syscall_get_arguments_deprecated(args, 2, 1, &val);
	res = val_to_ring(args, val, 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_read_x(struct event_filler_arguments *args) {
	unsigned long val;
	int res;
	int64_t retval;

	// Retrieve the FD. It will be used for dynamic snaplen calculation.
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	args->fd = (int)val;

	/* Parameter 1: res (type: PT_ERRNO) */
	retval = (int64_t)(long)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 2: data (type: PT_BYTEBUF) */
	if(retval > 0) {
		// val now contains the pointer to the buffer
		syscall_get_arguments_deprecated(args, 1, 1, &val);
		args->enforce_snaplen = true;
		res = val_to_ring(args, val, retval, true, 0);
	} else {
		res = push_empty_param(args);
	}
	CHECK_RES(res);

	/* Parameter 3: fd (type: PT_FD) */
	res = val_to_ring(args, (int64_t)args->fd, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 4: size (type: PT_UINT32) */
	syscall_get_arguments_deprecated(args, 2, 1, &val);
	res = val_to_ring(args, val, 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_write_e(struct event_filler_arguments *args) {
	unsigned long val = 0;
	int res = 0;
	int32_t fd = 0;

	/* Parameter 1: fd (type: PT_FD) */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	fd = (int32_t)val;
	res = val_to_ring(args, (int64_t)fd, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 2: size (type: PT_UINT32) */
	syscall_get_arguments_deprecated(args, 2, 1, &val);
	res = val_to_ring(args, val, 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_write_x(struct event_filler_arguments *args) {
	unsigned long val;
	int res;
	int64_t retval;
	unsigned long bufsize;
	size_t size = 0;

	/*
	 * Retrieve the FD. It will be used for dynamic snaplen calculation.
	 */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	args->fd = (int)val;

	/* Parameter 1: res (type: PT_ERRNO) */
	retval = (int64_t)(long)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 2: data (type: PT_BYTEBUF) */
	/* Get the size from userspace paramater */
	syscall_get_arguments_deprecated(args, 2, 1, &size);
	bufsize = retval > 0 ? retval : size;
	syscall_get_arguments_deprecated(args, 1, 1, &val);
	args->enforce_snaplen = true;
	res = val_to_ring(args, val, bufsize, true, 0);
	CHECK_RES(res);

	/* Parameter 3: fd (type: PT_FD) */
	res = val_to_ring(args, (int64_t)args->fd, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 4: size (type: PT_UINT32) */
	res = val_to_ring(args, (uint32_t)size, 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

/*
 * get_mm_exe_file is only exported in some kernel versions
 */
static struct file *ppm_get_mm_exe_file(struct mm_struct *mm) {
	struct file *exe_file;

	/*
	 * The following if/else preprocessor directive is to cover for that change:
	 * https://github.com/torvalds/linux/commit/90f31d0ea88880f780574f3d0bb1a227c4c66ca3#diff-e37b5cb4c23f6ab27741c60ec48674eff0268624a228c9a1cddddb9e4ee2922dL709
	 * That was introduced in linux 4.1, but it's backported in some distro kernels.
	 * Luckily enough, `get_file_rcu` is a define, so we can check for it and use
	 * the safer version.
	 */
#if defined(get_file_rcu)
	rcu_read_lock();
	exe_file = rcu_dereference(mm->exe_file);
	if(exe_file && !get_file_rcu(exe_file))
		exe_file = NULL;
	rcu_read_unlock();
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(6, 7, 0)
	// Since linux 6.7.0, `get_file_rcu` is no more a define and takes a double pointer parameter.
	// See https://github.com/torvalds/linux/commit/0ede61d8589cc2d93aa78230d74ac58b5b8d0244.
	rcu_read_lock();
	exe_file = get_file_rcu(&mm->exe_file);
	rcu_read_unlock();
#else
	/* We need mmap_sem to protect against races with removal of
	 * VM_EXECUTABLE vmas */
	down_read(&mm->mmap_sem);
	exe_file = mm->exe_file;
	if(exe_file)
		get_file(exe_file);
	up_read(&mm->mmap_sem);
#endif

	return exe_file;
}

/*
 * get_mm_counter was not inline and exported between 3.0 and 3.4
 * https://github.com/torvalds/linux/commit/69c978232aaa99476f9bd002c2a29a84fa3779b5
 * Hence the crap in these two functions
 */
static unsigned long ppm_get_mm_counter(struct mm_struct *mm, int member) {
	long val = 0;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 4, 0)
	val = get_mm_counter(mm, member);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 34)
	val = atomic_long_read(&mm->rss_stat.count[member]);

	if(val < 0)
		val = 0;
#endif

	return val;
}

static unsigned long ppm_get_mm_swap(struct mm_struct *mm) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 34)
	return ppm_get_mm_counter(mm, MM_SWAPENTS);
#endif
	return 0;
}

static unsigned long ppm_get_mm_rss(struct mm_struct *mm) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 4, 0)
	return get_mm_rss(mm);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 34)
	return ppm_get_mm_counter(mm, MM_FILEPAGES) + ppm_get_mm_counter(mm, MM_ANONPAGES);
#else
	return get_mm_rss(mm);
#endif
	return 0;
}

#ifdef CONFIG_CGROUPS
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 34)
static int ppm_cgroup_path(const struct cgroup *cgrp, char *buf, int buflen) {
	char *start;
	struct dentry *dentry = rcu_dereference(cgrp->dentry);

	if(!dentry) {
		/*
		 * Inactive subsystems have no dentry for their root
		 * cgroup
		 */
		strcpy(buf, "/");
		return 0;
	}

	start = buf + buflen;

	*--start = '\0';
	for(;;) {
		int len = dentry->d_name.len;

		start -= len;
		if(start < buf)
			return -ENAMETOOLONG;
		memcpy(start, cgrp->dentry->d_name.name, len);
		cgrp = cgrp->parent;
		if(!cgrp)
			break;
		dentry = rcu_dereference(cgrp->dentry);
		if(!cgrp->parent)
			continue;
		if(--start < buf)
			return -ENAMETOOLONG;
		*start = '/';
	}
	memmove(buf, start, buf + buflen - start);
	return 0;
}
#endif

static int append_cgroup(const char *subsys_name, int subsys_id, char *buf, int *available) {
	int pathlen;
	int subsys_len;
	char *path;

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 15, 0) || LINUX_VERSION_CODE >= KERNEL_VERSION(4, 9, 0)
	int res;
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 12, 0)
	struct cgroup_subsys_state *css = task_css(current, subsys_id);
#else
	struct cgroup_subsys_state *css = task_subsys_state(current, subsys_id);
#endif

	if(!css) {
		ASSERT(false);
		return 1;
	}

	if(!css->cgroup) {
		ASSERT(false);
		return 1;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 9, 0)
	// According to
	// https://github.com/torvalds/linux/commit/4c737b41de7f4eef2a593803bad1b918dd718b10 cgroup_path
	// now returns an int again
	res = cgroup_path(css->cgroup, buf, *available);
	if(res < 0) {
		ASSERT(false);
		path = "NA";
	} else {
		path = buf;
	}
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 15, 0)
	path = cgroup_path(css->cgroup, buf, *available);
	if(!path) {
		ASSERT(false);
		path = "NA";
	}
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 34)
	res = cgroup_path(css->cgroup, buf, *available);
	if(res < 0) {
		ASSERT(false);
		path = "NA";
	} else {
		path = buf;
	}
#else
	res = ppm_cgroup_path(css->cgroup, buf, *available);
	if(res < 0) {
		ASSERT(false);
		path = "NA";
	} else {
		path = buf;
	}
#endif

	pathlen = strlen(path);
	subsys_len = strlen(subsys_name);
	if(subsys_len + 1 + pathlen + 1 > *available)
		return 1;

	memmove(buf + subsys_len + 1, path, pathlen);
	memcpy(buf, subsys_name, subsys_len);
	buf += subsys_len;
	*buf++ = '=';
	buf += pathlen;
	*buf++ = 0;
	*available -= (subsys_len + 1 + pathlen + 1);
	return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 15, 0)
#define SUBSYS(_x)                                                     \
	if(append_cgroup(#_x,                                              \
	                 _x##_cgrp_id,                                     \
	                 args->str_storage + STR_STORAGE_SIZE - available, \
	                 &available))                                      \
		goto cgroups_error;
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
#define IS_SUBSYS_ENABLED(option) IS_BUILTIN(option)
#define SUBSYS(_x)                                                     \
	if(append_cgroup(#_x,                                              \
	                 _x##_subsys_id,                                   \
	                 args->str_storage + STR_STORAGE_SIZE - available, \
	                 &available))                                      \
		goto cgroups_error;
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 7, 0)
#define IS_SUBSYS_ENABLED(option) IS_ENABLED(option)
#define SUBSYS(_x)                                                     \
	if(append_cgroup(#_x,                                              \
	                 _x##_subsys_id,                                   \
	                 args->str_storage + STR_STORAGE_SIZE - available, \
	                 &available))                                      \
		goto cgroups_error;
#else
#define SUBSYS(_x)                                                     \
	if(append_cgroup(#_x,                                              \
	                 _x##_subsys_id,                                   \
	                 args->str_storage + STR_STORAGE_SIZE - available, \
	                 &available))                                      \
		goto cgroups_error;
#endif

#endif

/* Takes in a NULL-terminated array of pointers to strings in userspace, and
 * concatenates them to a single \0-separated string. Return the length of these
 * strings with the final '\0' included.
 */
static int accumulate_argv_or_env(const void __user *argv, char *str_storage) {
	int len = 0;
	int ret = 0;
	const char __user *p = NULL;

	for(;;) {
		if(argv == NULL)
			break;

		if(unlikely(ppm_get_user(p, argv))) {
			/* We return what we read until now */
			break;
		}

		if(p == NULL)
			break;

		/* ppm_strncpy_from_user includes the trailing \0 */
		ret = ppm_strncpy_from_user(&str_storage[len], p, STR_STORAGE_SIZE - len);
		if(ret < 0) {
			/* We ignore the failed read. We will try to read from the same position in
			 * the next iteration.
			 */
			ret = 0;
		}

		len += ret;
		if(len >= STR_STORAGE_SIZE) {
			len = STR_STORAGE_SIZE;
			break;
		}

		argv += sizeof(argv);
	}

	if(len > 0) {
		str_storage[len - 1] = '\0';
	} else {
		str_storage[0] = '\0';
	}
	return len;
}

#ifdef CONFIG_COMPAT
/* compat version that deals correctly with 32bits pointers of argv */
static int compat_accumulate_argv_or_env(compat_uptr_t argv, char *str_storage) {
	int len = 0;
	int ret = 0;
	const char __user *p = NULL;
	for(;;) {
		compat_uptr_t compat_p = 0;

		if(compat_ptr(argv) == NULL)
			break;

		if(unlikely(ppm_get_user(compat_p, compat_ptr(argv)))) {
			/* We return what we read until now */
			break;
		}
		p = compat_ptr(compat_p);
		if(p == NULL)
			break;

		/* ppm_strncpy_from_user includes the trailing \0 */
		ret = ppm_strncpy_from_user(&str_storage[len], p, STR_STORAGE_SIZE - len);
		if(ret < 0) {
			/* We ignore the failed read. We will try to read from the same position in
			 * the next iteration.
			 */
			ret = 0;
		}

		len += ret;
		if(len >= STR_STORAGE_SIZE) {
			len = STR_STORAGE_SIZE;
			break;
		}

		argv += sizeof(argv);
	}

	if(len > 0) {
		str_storage[len - 1] = '\0';
	} else {
		str_storage[0] = '\0';
	}
	return len;
}
#endif

static uint32_t ppm_get_tty(void) {
	/* Locking of the signal structures seems too complicated across
	 * multiple kernel versions to get it right, so simply do protected
	 * memory accesses, and in the worst case we get some garbage,
	 * which is not the end of the world. In the vast majority of accesses,
	 * we'll be just fine.
	 */
	struct signal_struct *sig;
	struct tty_struct *tty;
	struct tty_driver *driver;
	int major;
	int minor_start;
	int index;
	uint32_t tty_nr = 0;

	sig = current->signal;
	if(!sig)
		return 0;

	if(unlikely(copy_from_kernel_nofault(&tty, &sig->tty, sizeof(tty))))
		return 0;

	if(!tty)
		return 0;

	if(unlikely(copy_from_kernel_nofault(&index, &tty->index, sizeof(index))))
		return 0;

	if(unlikely(copy_from_kernel_nofault(&driver, &tty->driver, sizeof(driver))))
		return 0;

	if(!driver)
		return 0;

	if(unlikely(copy_from_kernel_nofault(&major, &driver->major, sizeof(major))))
		return 0;

	if(unlikely(copy_from_kernel_nofault(&minor_start, &driver->minor_start, sizeof(minor_start))))
		return 0;

	tty_nr = new_encode_dev(MKDEV(major, minor_start) + index);

	return tty_nr;
}

static enum ppm_overlay ppm_get_overlay_layer(struct file *file) {
	// 3.18 is the Kernel version where overlayfs was introduced
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 18, 0)
	return PPM_NOT_OVERLAY_FS;
#else
	struct dentry *dentry = NULL;
	struct super_block *sb = NULL;
	struct dentry *upper_dentry = NULL;
	struct inode *upper_ino = NULL;

	if(!file) {
		return PPM_NOT_OVERLAY_FS;
	}

	dentry = file->f_path.dentry;
	if(!dentry) {
		return PPM_NOT_OVERLAY_FS;
	}

	sb = dentry->d_sb;
	if(!sb) {
		return PPM_NOT_OVERLAY_FS;
	}

	if(sb->s_magic != PPM_OVERLAYFS_SUPER_MAGIC) {
		return PPM_NOT_OVERLAY_FS;
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 13, 0)
	// New scope to avoid `ISO C90 forbids mixed declarations and code` error
	{
		struct ovl_entry *oe = (struct ovl_entry *)(dentry->d_fsdata);
		if(!oe) {
			return PPM_OVERLAY_LOWER;
		}
		upper_dentry = oe->__upperdentry;
	}
#else
	{
		char *vfs_inode = (char *)dentry->d_inode;
		if(!vfs_inode) {
			return PPM_OVERLAY_LOWER;
		}

		// Pointer arithmetics due to unexported ovl_inode struct
		// warning: this works if and only if the dentry pointer
		// is placed right after the inode struct
		// todo!: this is dangerous we should find a way to check it at compile time.
		upper_dentry = *(struct dentry **)(vfs_inode + sizeof(struct inode));
	}
#endif  // LINUX_VERSION_CODE < KERNEL_VERSION(4, 13, 0)
	if(!upper_dentry) {
		return PPM_OVERLAY_LOWER;
	}

	upper_ino = upper_dentry->d_inode;
	if(!upper_ino) {
		return PPM_OVERLAY_LOWER;
	}
	if(upper_ino->i_ino != 0) {
		return PPM_OVERLAY_UPPER;
	}
	return PPM_OVERLAY_LOWER;
#endif  // LINUX_VERSION_CODE < KERNEL_VERSION(3, 18, 0)
}

static inline int push_pgid(struct event_filler_arguments *args) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 24)
	// task_pgrp_nr_ns has been introduced in 2.6.24
	// https://elixir.bootlin.com/linux/v2.6.24/source/kernel/pid.c#L458
	return val_to_ring(args, task_pgrp_nr_ns(current, &init_pid_ns), 0, false, 0);
#else
	// https://elixir.bootlin.com/linux/v2.6.23/source/kernel/sys.c#L1543
	// we don't have the concept of pid namespace in this kernel version
	return val_to_ring(args, process_group(current), 0, false, 0);
#endif
}

int f_proc_startupdate(struct event_filler_arguments *args) {
	unsigned long val = 0;
	int res = 0;
	unsigned int exe_len = 0; /* the length of the executable string */
	int args_len = 0;         /*the combined length of the arguments string + executable string */
	struct mm_struct *mm = current->mm;
	int64_t retval;
	int ptid;
	long total_vm = 0;
	long total_rss = 0;
	long swap = 0;
	int available = STR_STORAGE_SIZE;
	const struct cred *cred;
	uint64_t pidns_init_start_time = 0;

#ifdef __NR_clone3
	struct clone_args cl_args;
#endif

	/*
	 * Make sure the operation was successful
	 */
	/* Parameter 1: res (type: PT_ERRNO) */
	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	CHECK_RES(res);

	if(unlikely(retval < 0 && args->event_type != PPME_SYSCALL_EXECVE_19_X &&
	            args->event_type != PPME_SYSCALL_EXECVEAT_X)) {
		/* The call failed, but this syscall has no exe, args
		 * anyway, so I report empty ones */
		*args->str_storage = 0;

		/* Parameter 2: exe (type: PT_CHARBUF) */
		res = val_to_ring(args, (uint64_t)(long)args->str_storage, 0, false, 0);
		CHECK_RES(res);

		/* Parameter 3: args (type: PT_CHARBUFARRAY) */
		res = val_to_ring(args, (int64_t)(long)args->str_storage, 0, false, 0);
		CHECK_RES(res);
	} else {
		if(likely(retval >= 0)) {
			/*
			 * The call succeeded. Get exe, args from the current
			 * process; put one \0-separated exe-args string into
			 * str_storage
			 */

			if(unlikely(!mm)) {
				args->str_storage[0] = 0;
				pr_info("f_proc_startupdate drop, mm=NULL\n");
				return PPM_FAILURE_BUG;
			}

			if(unlikely(!mm->arg_end)) {
				args->str_storage[0] = 0;
				pr_info("f_proc_startupdate drop, mm->arg_end=NULL\n");
				return PPM_FAILURE_BUG;
			}

			args_len = mm->arg_end - mm->arg_start;

			if(args_len) {
				if(args_len > STR_STORAGE_SIZE)
					args_len = STR_STORAGE_SIZE;

				if(unlikely(ppm_copy_from_user(args->str_storage,
				                               (const void __user *)mm->arg_start,
				                               args_len)))
					args_len = 0;
				else
					args->str_storage[args_len - 1] = 0;
			}
		} else {
			/*
			 * The execve or execveat call failed. We get exe, args from the
			 * input args; put one \0-separated exe-args string into
			 * str_storage
			 */
			args->str_storage[0] = 0;

			switch(args->event_type) {
			case PPME_SYSCALL_EXECVE_19_X:
				syscall_get_arguments_deprecated(args, 1, 1, &val);
				break;

			case PPME_SYSCALL_EXECVEAT_X:
				syscall_get_arguments_deprecated(args, 2, 1, &val);
				break;

			default:
				val = 0;
				break;
			}
#ifdef CONFIG_COMPAT
			if(unlikely(args->compat))
				args_len = compat_accumulate_argv_or_env((compat_uptr_t)val, args->str_storage);
			else
#endif
				args_len = accumulate_argv_or_env((const char __user *)val, args->str_storage);
		}

		if(args_len == 0)
			*args->str_storage = 0;

		exe_len = strnlen(args->str_storage, args_len);
		// we add the `\0` terminator
		if(exe_len < args_len)
			++exe_len;

		/* Parameter 2: exe (type: PT_CHARBUF) */
		res = val_to_ring(args, (uint64_t)(long)args->str_storage, 0, false, 0);
		CHECK_RES(res);

		/* Parameter 3: args (type: PT_CHARBUFARRAY) */
		res = val_to_ring(args,
		                  (int64_t)(long)args->str_storage + exe_len,
		                  args_len - exe_len,
		                  false,
		                  0);
		CHECK_RES(res);
	}

	/* Parameter 4: tid (type: PT_PID) */
	res = val_to_ring(args, (int64_t)current->pid, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 5: pid (type: PT_PID) */
	/* this is called `pid` but it is the `tgid`. */
	res = val_to_ring(args, (int64_t)current->tgid, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 6: ptid (type: PT_PID) */
	/* this is called `ptid` but it is the `pgid`. */
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 20)
	if(current->real_parent)
		ptid = current->real_parent->pid;
#else
	if(current->parent)
		ptid = current->parent->pid;
#endif
	else
		ptid = 0;

	res = val_to_ring(args, (int64_t)ptid, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 7: cwd (type: PT_CHARBUF) */
	/* Push empty to avoid breaking compatibility with the older event format. */
	res = push_empty_param(args);
	CHECK_RES(res);

	/* Parameter 8: fdlimit (type: PT_UINT64) */
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 20)
	res = val_to_ring(args, (int64_t)rlimit(RLIMIT_NOFILE), 0, false, 0);
#else
	res = val_to_ring(args, (int64_t)0, 0, false, 0);
#endif
	CHECK_RES(res);

	/* Parameter 9: pgft_maj (type: PT_UINT64) */
	res = val_to_ring(args, current->maj_flt, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 10: pgft_min (type: PT_UINT64) */
	res = val_to_ring(args, current->min_flt, 0, false, 0);
	CHECK_RES(res);

	if(mm) {
		total_vm = mm->total_vm << (PAGE_SHIFT - 10);
		total_rss = ppm_get_mm_rss(mm) << (PAGE_SHIFT - 10);
		swap = ppm_get_mm_swap(mm) << (PAGE_SHIFT - 10);
	}

	/* Parameter 11: vm_size (type: PT_UINT32) */
	res = val_to_ring(args, total_vm, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 12: vm_rss (type: PT_UINT32) */
	res = val_to_ring(args, total_rss, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 13: vm_swap (type: PT_UINT32) */
	res = val_to_ring(args, swap, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 14: comm (type: PT_CHARBUF) */
	res = val_to_ring(args, (uint64_t)current->comm, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 15: cgroups (type: PT_CHARBUFARRAY) */
	args->str_storage[0] = 0;
#ifdef CONFIG_CGROUPS
	rcu_read_lock();
#include <linux/cgroup_subsys.h>
cgroups_error:
	rcu_read_unlock();
#endif

	res = val_to_ring(args,
	                  (int64_t)(long)args->str_storage,
	                  STR_STORAGE_SIZE - available,
	                  false,
	                  0);
	CHECK_RES(res);

	if(args->event_type == PPME_SYSCALL_CLONE_20_X || args->event_type == PPME_SYSCALL_FORK_20_X ||
	   args->event_type == PPME_SYSCALL_VFORK_20_X || args->event_type == PPME_SYSCALL_CLONE3_X) {
		/*
		 * clone-only parameters
		 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 5, 0)
		uint32_t euid = from_kuid_munged(current_user_ns(), current_euid());
		uint32_t egid = from_kgid_munged(current_user_ns(), current_egid());
#elif LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 20)
		uint32_t euid = current_euid();
		uint32_t egid = current_egid();
#else
		uint32_t euid = current->euid;
		uint32_t egid = current->egid;
#endif
		int64_t in_pidns = 0;
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 20)
		struct pid_namespace *pidns = task_active_pid_ns(current);
#endif

		/*
		 * flags
		 */
		switch(args->event_type) {
		case PPME_SYSCALL_CLONE_20_X:
#ifdef CONFIG_S390
			syscall_get_arguments_deprecated(args, 1, 1, &val);
#else
			syscall_get_arguments_deprecated(args, 0, 1, &val);
#endif
			break;

		case PPME_SYSCALL_CLONE3_X:
#ifdef __NR_clone3
			syscall_get_arguments_deprecated(args, 0, 1, &val);
			res = ppm_copy_from_user(&cl_args, (void *)val, sizeof(struct clone_args));
			if(unlikely(res != 0)) {
				val = 0;
			} else {
				val = cl_args.flags;
			}
#else
			val = 0;
#endif
			break;

		default:
			val = 0;
			break;
		}

#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 20)
		if(pidns != &init_pid_ns || pid_ns_for_children(current) != pidns)
			in_pidns = PPM_CL_CHILD_IN_PIDNS;
#endif
		res = val_to_ring(args, (uint64_t)clone_flags_to_scap((int)val) | in_pidns, 0, false, 0);
		CHECK_RES(res);

		/*
		 * uid
		 */
		res = val_to_ring(args, euid, 0, false, 0);
		CHECK_RES(res);

		/*
		 * gid
		 */
		res = val_to_ring(args, egid, 0, false, 0);
		CHECK_RES(res);

		/*
		 * vtid
		 */
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 20)
		res = val_to_ring(args, task_pid_vnr(current), 0, false, 0);
#else
		/* Not relevant in old kernels */
		res = val_to_ring(args, 0, 0, false, 0);
#endif
		CHECK_RES(res);

		/*
		 * vpid
		 */
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 20)
		res = val_to_ring(args, task_tgid_vnr(current), 0, false, 0);
#else
		/* Not relevant in old kernels */
		res = val_to_ring(args, 0, 0, false, 0);
#endif
		CHECK_RES(res);

		/*
		 * pid_namespace init task start_time monotonic time in ns
		 * the field `start_time` was a `struct timespec` before this
		 * kernel version.
		 * https://elixir.bootlin.com/linux/v3.16/source/include/linux/sched.h#L1370
		 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 17, 0)
		// only perform lookup when clone/vfork/fork returns 0 (child process / childtid)
		if(retval == 0 && pidns && pidns->child_reaper) {
			pidns_init_start_time = pidns->child_reaper->start_time;
		}
		res = val_to_ring(args, pidns_init_start_time, 0, false, 0);
#else
		/* Not relevant in old kernels */
		res = val_to_ring(args, 0, 0, false, 0);
#endif
		CHECK_RES(res);

	} else if(args->event_type == PPME_SYSCALL_EXECVE_19_X ||
	          args->event_type == PPME_SYSCALL_EXECVEAT_X) {
		/*
		 * execve family parameters.
		 */
		long env_len = 0;
		uint32_t tty_nr = 0;
		bool exe_writable = false;
		enum ppm_overlay exe_layer = PPM_NOT_OVERLAY_FS;
		struct file *exe_file = NULL;
		uint32_t flags = 0;  // execve additional flags
		unsigned long i_ino = 0;
		unsigned long ctime = 0;
		unsigned long mtime = 0;
		uint32_t loginuid = UINT32_MAX;
		uint64_t cap_inheritable = 0;
		uint64_t cap_permitted = 0;
		uint64_t cap_effective = 0;
		uint32_t euid = UINT32_MAX;
		uint32_t egid = UINT32_MAX;
		char *buf = (char *)args->str_storage;
		char *trusted_exepath = NULL;

		if(likely(retval >= 0)) {
			/*
			 * Already checked for mm validity
			 */
			env_len = mm->env_end - mm->env_start;

			if(env_len) {
				if(env_len > STR_STORAGE_SIZE)
					env_len = STR_STORAGE_SIZE;

				if(unlikely(ppm_copy_from_user(args->str_storage,
				                               (const void __user *)mm->env_start,
				                               env_len)))
					env_len = 0;
				else
					args->str_storage[env_len - 1] = 0;
			}
		} else {
			/*
			 * The call failed, so get the env from the arguments
			 */
			switch(args->event_type) {
			case PPME_SYSCALL_EXECVE_19_X:
				syscall_get_arguments_deprecated(args, 2, 1, &val);
				break;

			case PPME_SYSCALL_EXECVEAT_X:
				syscall_get_arguments_deprecated(args, 3, 1, &val);
				break;

			default:
				val = 0;
				break;
			}
#ifdef CONFIG_COMPAT
			if(unlikely(args->compat))
				env_len = compat_accumulate_argv_or_env((compat_uptr_t)val, args->str_storage);
			else
#endif
				env_len = accumulate_argv_or_env((const char __user *)val, args->str_storage);
		}

		if(env_len == 0)
			*args->str_storage = 0;

		/* Parameter 16: env (type: PT_CHARBUFARRAY) */
		res = val_to_ring(args, (int64_t)(long)args->str_storage, env_len, false, 0);
		CHECK_RES(res);

		/* Parameter 17: tty (type: PT_INT32) */
		tty_nr = ppm_get_tty();
		res = val_to_ring(args, tty_nr, 0, false, 0);
		CHECK_RES(res);

		/* Parameter 18: vpgid (type: PT_PID) */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 24)
		res = val_to_ring(args,
		                  (int64_t)task_pgrp_nr_ns(current, task_active_pid_ns(current)),
		                  0,
		                  false,
		                  0);
#else
		res = val_to_ring(args, (int64_t)process_group(current), 0, false, 0);
#endif
		CHECK_RES(res);

		/* Parameter 19: loginuid (type: PT_UID) */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 5, 0)
		loginuid = from_kuid(current_user_ns(), audit_get_loginuid(current));
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 25)
		loginuid = audit_get_loginuid(current);
#else
		loginuid = audit_get_loginuid(current->audit_context);
#endif
		res = val_to_ring(args, loginuid, 0, false, 0);
		CHECK_RES(res);

		/*
		 * exe_writable, exe_upper_layer and exe_lower_layer flags
		 */

		exe_file = ppm_get_mm_exe_file(mm);

		if(exe_file != NULL) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 39)
			if(file_inode(exe_file) != NULL) {
				/* Support exe_writable */
#ifdef HAS_FS_MNT_IDMAP
				exe_writable |= (file_permission(exe_file, MAY_WRITE | MAY_NOT_BLOCK) == 0);
				exe_writable |=
				        inode_owner_or_capable(file_mnt_idmap(exe_file), file_inode(exe_file));
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
				exe_writable |= (inode_permission(current_user_ns(),
				                                  file_inode(exe_file),
				                                  MAY_WRITE | MAY_NOT_BLOCK) == 0);
				exe_writable |= inode_owner_or_capable(current_user_ns(), file_inode(exe_file));
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 1, 0)
				exe_writable |=
				        (inode_permission(file_inode(exe_file), MAY_WRITE | MAY_NOT_BLOCK) == 0);
				exe_writable |= inode_owner_or_capable(file_inode(exe_file));
#endif
				/*
				 * Kernels < 3.1.0 doesn't support the exe_writable flags due to the MAY_NOT_BLOCK
				 * not being available. This limitation is related to the fact that this function
				 * (f_sched_prog_exec) is in a RCU critical section: this means that this function
				 * (and its callee) MUST NOT call functions that can yield the processor (e.g.
				 * inode_permission that deep down in its call stack calls a down_read()). This is
				 * addressed after the Kernel 3.1.0 where the MAY_OT_BLOCK flag is introduced and
				 * avoids the processor to being yield.
				 */

				/* Support exe_upper_layer and exe_lower_layer */
				exe_layer = ppm_get_overlay_layer(exe_file);

				/* Support exe_from_memfd */
				flags |= get_exe_from_memfd(exe_file);

				/* Support inode number */
				i_ino = file_inode(exe_file)->i_ino;

				/* Support exe_file ctime
				 * During kernel versions `i_ctime` changed from `struct timespec` to `struct
				 * timespec64` but fields names should be always the same.
				 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
				{
					struct timespec64 inode_ctime;
					inode_ctime = inode_get_ctime(file_inode(exe_file));
					ctime = inode_ctime.tv_sec * (uint64_t)1000000000 + inode_ctime.tv_nsec;
				}
#else
				ctime = file_inode(exe_file)->i_ctime.tv_sec * (uint64_t)1000000000 +
				        file_inode(exe_file)->i_ctime.tv_nsec;
#endif
				/* Support exe_file mtime
				 * During kernel versions `i_mtime` changed from `struct timespec` to `struct
				 * timespec64` but fields names should be always the same.
				 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 7, 0)
				{
					struct timespec64 inode_mtime;
					inode_mtime = inode_get_mtime(file_inode(exe_file));
					mtime = inode_mtime.tv_sec * (uint64_t)1000000000 + inode_mtime.tv_nsec;
				}
#else
				mtime = file_inode(exe_file)->i_mtime.tv_sec * (uint64_t)1000000000 +
				        file_inode(exe_file)->i_mtime.tv_nsec;
#endif
			}
#endif
			/* Before freeing the exefile we catch the resolved path for symlink resolution */
			trusted_exepath = d_path(&exe_file->f_path, buf, PAGE_SIZE);
			fput(exe_file);
		}

		if(exe_writable) {
			flags |= PPM_EXE_WRITABLE;
		}

		if(exe_layer == PPM_OVERLAY_UPPER) {
			flags |= PPM_EXE_UPPER_LAYER;
		} else if(exe_layer == PPM_OVERLAY_LOWER) {
			flags |= PPM_EXE_LOWER_LAYER;
		}

		// write all the additional flags for execve family here...

		/* Parameter 20: flags (type: PT_FLAGS32) */
		res = val_to_ring(args, flags, 0, false, 0);
		CHECK_RES(res);

		/*
		 * capabilities
		 */
		cred = get_current_cred();
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 3, 0)
		cap_inheritable =
		        ((uint64_t)cred->cap_inheritable.cap[1] << 32) | cred->cap_inheritable.cap[0];
		cap_permitted = ((uint64_t)cred->cap_permitted.cap[1] << 32) | cred->cap_permitted.cap[0];
		cap_effective = ((uint64_t)cred->cap_effective.cap[1] << 32) | cred->cap_effective.cap[0];
#else
		cap_inheritable = (uint64_t)cred->cap_inheritable.val;
		cap_permitted = (uint64_t)cred->cap_permitted.val;
		cap_effective = (uint64_t)cred->cap_effective.val;
#endif
		put_cred(cred);

		/* Parameter 21: cap_inheritable (type: PT_UINT64) */
		res = val_to_ring(args, capabilities_to_scap(cap_inheritable), 0, false, 0);
		CHECK_RES(res);

		/* Parameter 22: cap_permitted (type: PT_UINT64) */
		res = val_to_ring(args, capabilities_to_scap(cap_permitted), 0, false, 0);
		CHECK_RES(res);

		/* Parameter 23: cap_effective (type: PT_UINT64) */
		res = val_to_ring(args, capabilities_to_scap(cap_effective), 0, false, 0);
		CHECK_RES(res);

		/*
		 * exe ino fields
		 */

		/* Parameter 24: exe_file ino (type: PT_UINT64) */
		res = val_to_ring(args, i_ino, 0, false, 0);
		CHECK_RES(res);

		/* Parameter 25: exe_file ctime (last status change time, epoch value in nanoseconds) (type:
		 * PT_ABSTIME) */
		res = val_to_ring(args, ctime, 0, false, 0);
		CHECK_RES(res);

		/* Parameter 26: exe_file mtime (last modification time, epoch value in nanoseconds) (type:
		 * PT_ABSTIME) */
		res = val_to_ring(args, mtime, 0, false, 0);
		CHECK_RES(res);

		/* Parameter 27: euid (type: PT_UID) */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 5, 0)
		euid = from_kuid_munged(current_user_ns(), current_euid());
#elif LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 20)
		euid = current_euid();
#else
		euid = current->euid;
#endif
		res = val_to_ring(args, euid, 0, false, 0);
		CHECK_RES(res);

		/* Parameter 28: trusted_exepath (type: PT_FSPATH) */
		res = val_to_ring(args, (unsigned long)trusted_exepath, 0, false, 0);
		CHECK_RES(res);

		/* Parameter 29: pgid (type: PT_PID) */
		res = push_pgid(args);
		CHECK_RES(res);

		/* Parameter 30: egid (type: PT_GID) */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 5, 0)
		egid = from_kgid_munged(current_user_ns(), current_egid());
#elif LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 20)
		egid = current_egid();
#else
		egid = current->egid;
#endif
		res = val_to_ring(args, egid, 0, false, 0);
		CHECK_RES(res);
	}
	return add_sentinel(args);
}

int f_sys_execve_e(struct event_filler_arguments *args) {
	unsigned long val;
	int res;

	/* Parameter 1: filename (type: PT_FSPATH) */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	res = val_to_ring(args, val, 0, true, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_execveat_e(struct event_filler_arguments *args) {
	int res;
	unsigned long val;
	unsigned long flags;
	int32_t fd;

	/*
	 * dirfd
	 */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	fd = (int32_t)val;
	if(fd == AT_FDCWD) {
		fd = PPM_AT_FDCWD;
	}

	res = val_to_ring(args, (int64_t)fd, 0, false, 0);
	CHECK_RES(res);

	/*
	 * pathname
	 */
	syscall_get_arguments_deprecated(args, 1, 1, &val);
	res = val_to_ring(args, val, 0, true, 0);
	CHECK_RES(res);

	/*
	 * flags
	 */
	syscall_get_arguments_deprecated(args, 4, 1, &val);
	flags = execveat_flags_to_scap(val);

	res = val_to_ring(args, flags, 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_socket_bind_e(struct event_filler_arguments *args) {
	int res = 0;
	int32_t fd = 0;
	unsigned long val = 0;

	syscall_get_arguments_deprecated(args, 0, 1, &val);

	/* Parameter 1: fd (type: PT_FD) */
	fd = (int32_t)val;
	res = val_to_ring(args, (int64_t)fd, 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_socket_bind_x(struct event_filler_arguments *args) {
	int res;
	int64_t retval;
	int err = 0;
	uint16_t size = 0;
	struct sockaddr __user *usrsockaddr;
	unsigned long val;
	struct sockaddr_storage address;
	char *targetbuf = args->str_storage;
	int32_t fd = 0;

	/* Parameter 1: res (type: PT_ERRNO) */
	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);

	/* Parameter 2: addr (type: PT_SOCKADDR) */
	syscall_get_arguments_deprecated(args, 1, 1, &val);

	usrsockaddr = (struct sockaddr __user *)val;

	/*
	 * Get the address len
	 */
	syscall_get_arguments_deprecated(args, 2, 1, &val);

	if(usrsockaddr != NULL && val != 0) {
		/*
		 * Copy the address
		 */
		err = addr_to_kernel(usrsockaddr, val, (struct sockaddr *)&address);
		if(likely(err >= 0)) {
			/*
			 * Convert the fd into socket endpoint information
			 */
			size = pack_addr((struct sockaddr *)&address, val, targetbuf, STR_STORAGE_SIZE);
		}
	}

	/*
	 * Copy the endpoint info into the ring
	 */
	res = val_to_ring(args, (uint64_t)targetbuf, size, false, 0);
	CHECK_RES(res);

	/* Parameter 3: fd (type: PT_FD) */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	fd = (int32_t)val;
	res = val_to_ring(args, (int64_t)fd, 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_connect_e(struct event_filler_arguments *args) {
	unsigned long val;
	int64_t fd;
	int res;
	struct sockaddr __user *usrsockaddr;
	unsigned long usrsockaddr_len;
	uint16_t addr_size = 0;
	char *targetbuf = args->str_storage;
	struct sockaddr_storage address;

	/* Parameter 1: fd (type: PT_FD) */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	fd = (int64_t)(int32_t)val;
	res = val_to_ring(args, fd, 0, true, 0);
	CHECK_RES(res);

	/* Get the sockaddr pointer and its length. */
	syscall_get_arguments_deprecated(args, 1, 1, &val);
	usrsockaddr = (struct sockaddr __user *)val;
	syscall_get_arguments_deprecated(args, 2, 1, &val);
	usrsockaddr_len = val;

	if(usrsockaddr != NULL && usrsockaddr_len != 0) {
		/* Copy the address into kernel memory. */
		res = addr_to_kernel(usrsockaddr, usrsockaddr_len, (struct sockaddr *)&address);
		if(likely(res >= 0)) {
			/* Convert the fd into socket endpoint information. */
			addr_size = pack_addr((struct sockaddr *)&address,
			                      usrsockaddr_len,
			                      targetbuf,
			                      STR_STORAGE_SIZE);
		}
	}

	/* Parameter 2: addr (type: PT_SOCKADDR) */
	res = val_to_ring(args, (uint64_t)targetbuf, addr_size, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_connect_x(struct event_filler_arguments *args) {
	int64_t retval;
	int res;
	unsigned long val;
	int fd;
	struct sockaddr __user *usrsockaddr;
	unsigned long usrsockaddr_len;
	struct sockaddr_storage address;
	struct sockaddr *ksockaddr = NULL;
	unsigned long sockaddr_len = 0;
	bool can_use_sockaddr_data = false;
	char *targetbuf = args->str_storage;
	uint16_t tuple_size = 0, addr_size = 0;

	/* Parameter 1: res (type: PT_ERRNO) */
	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	CHECK_RES(res);

	/* Get socket file descriptor, sockaddr pointer and length. */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	fd = (int64_t)(int32_t)val;
	syscall_get_arguments_deprecated(args, 1, 1, &val);
	usrsockaddr = (struct sockaddr __user *)val;
	syscall_get_arguments_deprecated(args, 2, 1, &usrsockaddr_len);

	/* Copy the user-provided sockaddr into kernel memory, if possible. */
	if(usrsockaddr != NULL && usrsockaddr_len != 0) {
		res = addr_to_kernel(usrsockaddr, usrsockaddr_len, (struct sockaddr *)&address);
		if(likely(res >= 0)) {
			ksockaddr = (struct sockaddr *)&address;
			sockaddr_len = usrsockaddr_len;
			can_use_sockaddr_data = true;
		}
	}

	/* Parameter 2: tuple (type: PT_SOCKTUPLE) */
	if(retval != 0 && retval != -EINPROGRESS) {
		res = push_empty_param(args);
	} else {
		/* Use the file descriptor (and possibly the sockaddr) to obtain the socket tuple.
		 * The socket tuple is stored into the provided target buffer. */
		tuple_size = fd_to_socktuple((int)fd,
		                             ksockaddr,
		                             sockaddr_len,
		                             can_use_sockaddr_data,
		                             false,
		                             targetbuf,
		                             STR_STORAGE_SIZE);

		res = val_to_ring(args, (uint64_t)(unsigned long)targetbuf, tuple_size, false, 0);
	}
	CHECK_RES(res);

	/* Parameter 3: fd (type: PT_FD) */
	res = val_to_ring(args, fd, 0, false, 0);
	CHECK_RES(res);

	if(can_use_sockaddr_data) {
		/* Encode the address and store it into the target buffer. */
		addr_size = pack_addr(ksockaddr, sockaddr_len, targetbuf, STR_STORAGE_SIZE);
	}

	/* Parameter 2: addr (type: PT_SOCKADDR) */
	res = val_to_ring(args, (uint64_t)targetbuf, addr_size, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_socketpair_x(struct event_filler_arguments *args) {
	int res;
	int64_t retval;
	unsigned long val;
	/* In case of failure we send invalid fd (-1) */
	int fds[2] = {-1, -1};
	int err;
	struct socket *sock;
	struct unix_sock *us;
	struct sock *speer;
	uint32_t domain;

	/* Parameter 1: res (type: PT_ERRNO) */
	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	CHECK_RES(res);

	/* In case of success we have 0. */
	if(likely(retval == 0)) {
		/* Get new sockets file descriptors. */
		syscall_get_arguments_deprecated(args, 3, 1, &val);
#ifdef CONFIG_COMPAT
		if(!args->compat) {
#endif
			if(unlikely(ppm_copy_from_user(fds, (const void __user *)val, sizeof(fds))))
				return PPM_FAILURE_INVALID_USER_MEMORY;
#ifdef CONFIG_COMPAT
		} else {
			if(unlikely(ppm_copy_from_user(fds, (const void __user *)compat_ptr(val), sizeof(fds))))
				return PPM_FAILURE_INVALID_USER_MEMORY;
		}
#endif

		/* Parameter 2: fd1 (type: PT_FD) */
		res = val_to_ring(args, (int64_t)fds[0], 0, false, 0);
		CHECK_RES(res);

		/* Parameter 3: fd2 (type: PT_FD) */
		res = val_to_ring(args, (int64_t)fds[1], 0, false, 0);
		CHECK_RES(res);

		/* Get socket source and peer address. */
		sock = sockfd_lookup(fds[0], &err);
		if(likely(sock != NULL)) {
			us = unix_sk(sock->sk);
			speer = us->peer;
			res = val_to_ring(args, (unsigned long)us, 0, false, 0);
			if(unlikely(res != PPM_SUCCESS)) {
				sockfd_put(sock);
				return res;
			}

			res = val_to_ring(args, (unsigned long)speer, 0, false, 0);
			if(unlikely(res != PPM_SUCCESS)) {
				sockfd_put(sock);
				return res;
			}

			sockfd_put(sock);
		} else {
			return err;
		}
	} else {
		res = val_to_ring(args, (int64_t)fds[0], 0, false, 0);
		CHECK_RES(res);

		res = val_to_ring(args, (int64_t)fds[1], 0, false, 0);
		CHECK_RES(res);

		res = val_to_ring(args, 0, 0, false, 0);
		CHECK_RES(res);

		res = val_to_ring(args, 0, 0, false, 0);
		CHECK_RES(res);
	}

	/* Parameter 2: domain (type: PT_ENUMFLAGS32) */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	domain = socket_family_to_scap((uint8_t)val);
	res = val_to_ring(args, val, 0, true, 0);
	CHECK_RES(res);

	/* Parameter 3: type (type: PT_UINT32) */
	syscall_get_arguments_deprecated(args, 1, 1, &val);
	res = val_to_ring(args, val, 0, true, 0);
	CHECK_RES(res);

	/* Parameter 4: proto (type: PT_UINT32) */
	syscall_get_arguments_deprecated(args, 2, 1, &val);
	res = val_to_ring(args, val, 0, true, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

static int parse_sockopt(struct event_filler_arguments *args,
                         int level,
                         int optname,
                         const void __user *optval,
                         int optlen) {
	int32_t val32 = 0;
	uint64_t val64 = 0;
	struct __aux_timeval tv = {0};

	if(level != SOL_SOCKET) {
		return val_to_ring(args, (unsigned long)optval, optlen, true, PPM_SOCKOPT_IDX_UNKNOWN);
	}

	switch(optname) {
#ifdef SO_ERROR
	case SO_ERROR:
		/* in case of failure we have to clear again the value */
		if(unlikely(ppm_copy_from_user(&val32, optval, sizeof(val32)))) {
			val32 = 0;
		}
		return val_to_ring(args, (int64_t)-val32, 0, false, PPM_SOCKOPT_IDX_ERRNO);
#endif

#ifdef SO_RCVTIMEO
	case SO_RCVTIMEO:
#endif
#if(defined(SO_RCVTIMEO_OLD) && !defined(SO_RCVTIMEO)) || \
        (defined(SO_RCVTIMEO_OLD) && (SO_RCVTIMEO_OLD != SO_RCVTIMEO))
	case SO_RCVTIMEO_OLD:
#endif
#if(defined(SO_RCVTIMEO_NEW) && !defined(SO_RCVTIMEO)) || \
        (defined(SO_RCVTIMEO_NEW) && (SO_RCVTIMEO_NEW != SO_RCVTIMEO))
	case SO_RCVTIMEO_NEW:
#endif
#ifdef SO_SNDTIMEO
	case SO_SNDTIMEO:
#endif
#if(defined(SO_SNDTIMEO_OLD) && !defined(SO_SNDTIMEO)) || \
        (defined(SO_SNDTIMEO_OLD) && (SO_SNDTIMEO_OLD != SO_SNDTIMEO))
	case SO_SNDTIMEO_OLD:
#endif
#if(defined(SO_SNDTIMEO_NEW) && !defined(SO_SNDTIMEO)) || \
        (defined(SO_SNDTIMEO_NEW) && (SO_SNDTIMEO_NEW != SO_SNDTIMEO))
	case SO_SNDTIMEO_NEW:
#endif
		if(unlikely(ppm_copy_from_user(&tv, optval, sizeof(tv)))) {
			tv.tv_sec = 0;
			tv.tv_usec = 0;
		}
		return val_to_ring(args,
		                   tv.tv_sec * SECOND_IN_NS + tv.tv_usec * USECOND_IN_NS,
		                   0,
		                   false,
		                   PPM_SOCKOPT_IDX_TIMEVAL);

#ifdef SO_COOKIE
	case SO_COOKIE:
		if(unlikely(ppm_copy_from_user(&val64, optval, sizeof(val64)))) {
			val64 = 0;
		}
		return val_to_ring(args, val64, 0, false, PPM_SOCKOPT_IDX_UINT64);
#endif

#ifdef SO_DEBUG
	case SO_DEBUG:
#endif
#ifdef SO_REUSEADDR
	case SO_REUSEADDR:
#endif
#ifdef SO_TYPE
	case SO_TYPE:
#endif
#ifdef SO_DONTROUTE
	case SO_DONTROUTE:
#endif
#ifdef SO_BROADCAST
	case SO_BROADCAST:
#endif
#ifdef SO_SNDBUF
	case SO_SNDBUF:
#endif
#ifdef SO_RCVBUF
	case SO_RCVBUF:
#endif
#ifdef SO_SNDBUFFORCE
	case SO_SNDBUFFORCE:
#endif
#ifdef SO_RCVBUFFORCE
	case SO_RCVBUFFORCE:
#endif
#ifdef SO_KEEPALIVE
	case SO_KEEPALIVE:
#endif
#ifdef SO_OOBINLINE
	case SO_OOBINLINE:
#endif
#ifdef SO_NO_CHECK
	case SO_NO_CHECK:
#endif
#ifdef SO_PRIORITY
	case SO_PRIORITY:
#endif
#ifdef SO_BSDCOMPAT
	case SO_BSDCOMPAT:
#endif
#ifdef SO_REUSEPORT
	case SO_REUSEPORT:
#endif
#ifdef SO_PASSCRED
	case SO_PASSCRED:
#endif
#ifdef SO_RCVLOWAT
	case SO_RCVLOWAT:
#endif
#ifdef SO_SNDLOWAT
	case SO_SNDLOWAT:
#endif
#ifdef SO_SECURITY_AUTHENTICATION
	case SO_SECURITY_AUTHENTICATION:
#endif
#ifdef SO_SECURITY_ENCRYPTION_TRANSPORT
	case SO_SECURITY_ENCRYPTION_TRANSPORT:
#endif
#ifdef SO_SECURITY_ENCRYPTION_NETWORK
	case SO_SECURITY_ENCRYPTION_NETWORK:
#endif
#ifdef SO_BINDTODEVICE
	case SO_BINDTODEVICE:
#endif
#ifdef SO_DETACH_FILTER
	case SO_DETACH_FILTER:
#endif
#ifdef SO_TIMESTAMP
	case SO_TIMESTAMP:
#endif
#ifdef SO_ACCEPTCONN
	case SO_ACCEPTCONN:
#endif
#ifdef SO_PEERSEC
	case SO_PEERSEC:
#endif
#ifdef SO_PASSSEC
	case SO_PASSSEC:
#endif
#ifdef SO_TIMESTAMPNS
	case SO_TIMESTAMPNS:
#endif
#ifdef SO_MARK
	case SO_MARK:
#endif
#ifdef SO_TIMESTAMPING
	case SO_TIMESTAMPING:
#endif
#ifdef SO_PROTOCOL
	case SO_PROTOCOL:
#endif
#ifdef SO_DOMAIN
	case SO_DOMAIN:
#endif
#ifdef SO_RXQ_OVFL
	case SO_RXQ_OVFL:
#endif
#ifdef SO_WIFI_STATUS
	case SO_WIFI_STATUS:
#endif
#ifdef SO_PEEK_OFF
	case SO_PEEK_OFF:
#endif
#ifdef SO_NOFCS
	case SO_NOFCS:
#endif
#ifdef SO_LOCK_FILTER
	case SO_LOCK_FILTER:
#endif
#ifdef SO_SELECT_ERR_QUEUE
	case SO_SELECT_ERR_QUEUE:
#endif
#ifdef SO_BUSY_POLL
	case SO_BUSY_POLL:
#endif
#ifdef SO_MAX_PACING_RATE
	case SO_MAX_PACING_RATE:
#endif
#ifdef SO_BPF_EXTENSIONS
	case SO_BPF_EXTENSIONS:
#endif
#ifdef SO_INCOMING_CPU
	case SO_INCOMING_CPU:
#endif
		if(unlikely(ppm_copy_from_user(&val32, optval, sizeof(val32)))) {
			val32 = 0;
		}
		return val_to_ring(args, val32, 0, false, PPM_SOCKOPT_IDX_UINT32);

	default:
		return val_to_ring(args, (unsigned long)optval, optlen, true, PPM_SOCKOPT_IDX_UNKNOWN);
	}
}

int f_sys_setsockopt_x(struct event_filler_arguments *args) {
	int res = 0;
	long retval = 0;
	unsigned long val[5] = {0};
	int32_t fd = 0;

	/* Parameter 1: res (type: PT_ERRNO) */
	retval = syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	CHECK_RES(res);

	/* Get all the five arguments */
	syscall_get_arguments_deprecated(args, 0, 5, val);

	/* Parameter 2: fd (type: PT_FD) */
	fd = (int32_t)val[0];
	res = val_to_ring(args, (int64_t)fd, 0, true, 0);
	CHECK_RES(res);

	/* Parameter 3: level (type: PT_ENUMFLAGS8) */
	res = val_to_ring(args, sockopt_level_to_scap(val[1]), 0, true, 0);
	CHECK_RES(res);

	/* Parameter 4: optname (type: PT_ENUMFLAGS8) */
	res = val_to_ring(args, sockopt_optname_to_scap(val[1], val[2]), 0, true, 0);
	CHECK_RES(res);

	/* Parameter 5: optval (type: PT_DYN) */
	res = parse_sockopt(args, val[1], val[2], (const void __user *)val[3], val[4]);
	CHECK_RES(res);

	/* Parameter 6: optlen (type: PT_UINT32) */
	res = val_to_ring(args, val[4], 0, true, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_getsockopt_x(struct event_filler_arguments *args) {
	int res = 0;
	int64_t retval = 0;
	uint32_t optlen = 0;
	int32_t fd = 0;
	unsigned long val[5] = {0};

	/* Get all the five arguments */
	syscall_get_arguments_deprecated(args, 0, 5, val);

	/* Parameter 1: res (type: PT_ERRNO) */
	retval = (int64_t)(long)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 2: fd (type: PT_FD) */
	fd = (int32_t)val[0];
	res = val_to_ring(args, (int64_t)fd, 0, true, 0);
	CHECK_RES(res);

	/* Parameter 3: level (type: PT_ENUMFLAGS8) */
	res = val_to_ring(args, sockopt_level_to_scap(val[1]), 0, true, 0);
	CHECK_RES(res);

	/* Parameter 4: optname (type: PT_ENUMFLAGS8) */
	res = val_to_ring(args, sockopt_optname_to_scap(val[1], val[2]), 0, true, 0);
	CHECK_RES(res);

	/* `optval` and `optlen` will be the ones provided by the user if the syscall fails
	 * otherwise they will refer to the real socket data since the kernel populated them.
	 */

	/* Extract optlen */
	if(unlikely(ppm_copy_from_user(&optlen, (const void __user *)val[4], sizeof(optlen)))) {
		optlen = 0;
	}

	/* Parameter 5: optval (type: PT_DYN) */
	res = parse_sockopt(args, val[1], val[2], (const void __user *)val[3], optlen);
	CHECK_RES(res);

	/* Parameter 6: optlen (type: PT_UINT32) */
	res = val_to_ring(args, optlen, 0, true, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_accept4_e(struct event_filler_arguments *args) {
	int res;

	/* Parameter 1: flags (type: PT_FLAGS32) */
	/*
	 * push the flags into the ring.
	 * XXX we don't support flags yet and so we just return zero
	 */
	/* res = val_to_ring(args, args->socketcall_args[3]); */
	res = val_to_ring(args, 0, 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_accept4_x(struct event_filler_arguments *args) {
	int res;
	int64_t fd;
	char *targetbuf = args->str_storage;
	uint16_t size = 0;
	unsigned long queuepct = 0;
	unsigned long ack_backlog = 0;
	unsigned long max_ack_backlog = 0;
	unsigned long srvskfd;
	int err = 0;
	struct socket *sock;

	/* Parameter 1: fd (type: PT_FD) */
	fd = (int64_t)(int32_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, fd, 0, false, 0);
	CHECK_RES(res);

	if(fd >= 0) {
		/*
		 * Convert the fd into socket endpoint information
		 */
		size = fd_to_socktuple(fd, NULL, 0, false, true, targetbuf, STR_STORAGE_SIZE);
		/*
		 * queuepct
		 */
		syscall_get_arguments_deprecated(args, 0, 1, &srvskfd);

		sock = sockfd_lookup(srvskfd, &err);

		if(sock && sock->sk) {
			ack_backlog = sock->sk->sk_ack_backlog;
			max_ack_backlog = sock->sk->sk_max_ack_backlog;
		}

		if(sock)
			sockfd_put(sock);

		if(max_ack_backlog)
			queuepct = (unsigned long)ack_backlog * 100 / max_ack_backlog;

		/* Parameter 2: tuple (type: PT_SOCKTUPLE) */
		res = val_to_ring(args, (uint64_t)targetbuf, size, false, 0);
		CHECK_RES(res);
	} else {
		/* Parameter 2: tuple (type: PT_SOCKTUPLE) */
		res = push_empty_param(args);
		CHECK_RES(res);
	}

	/* Parameter 3: queuepct (type: PT_UINT8) */
	res = val_to_ring(args, queuepct, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 4: queuelen (type: PT_UINT32) */
	res = val_to_ring(args, ack_backlog, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 5: queuemax (type: PT_UINT32) */
	res = val_to_ring(args, max_ack_backlog, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 6: flags (type: PT_FLAGS32) */
	/*
	 * push the flags into the ring.
	 * XXX we don't support flags yet and so we just return zero
	 */
	/* res = val_to_ring(args, args->socketcall_args[3]); */
	res = val_to_ring(args, 0, 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_accept_x(struct event_filler_arguments *args) {
	int res;
	int64_t fd;
	char *targetbuf = args->str_storage;
	uint16_t size = 0;
	unsigned long queuepct = 0;
	unsigned long ack_backlog = 0;
	unsigned long max_ack_backlog = 0;
	unsigned long srvskfd;
	int err = 0;
	struct socket *sock;

	/* Parameter 1: fd (type: PT_FD) */
	fd = (int64_t)(int32_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, fd, 0, false, 0);
	CHECK_RES(res);

	if(fd >= 0) {
		/*
		 * Convert the fd into socket endpoint information
		 */
		size = fd_to_socktuple(fd, NULL, 0, false, true, targetbuf, STR_STORAGE_SIZE);
		/*
		 * queuepct
		 */
		syscall_get_arguments_deprecated(args, 0, 1, &srvskfd);

		sock = sockfd_lookup(srvskfd, &err);

		if(sock && sock->sk) {
			ack_backlog = sock->sk->sk_ack_backlog;
			max_ack_backlog = sock->sk->sk_max_ack_backlog;
		}

		if(sock)
			sockfd_put(sock);

		if(max_ack_backlog)
			queuepct = (unsigned long)ack_backlog * 100 / max_ack_backlog;

		/* Parameter 2: tuple (type: PT_SOCKTUPLE) */
		res = val_to_ring(args, (uint64_t)targetbuf, size, false, 0);
		CHECK_RES(res);
	} else {
		/* Parameter 2: tuple (type: PT_SOCKTUPLE) */
		res = push_empty_param(args);
		CHECK_RES(res);
	}

	/* Parameter 3: queuepct (type: PT_UINT8) */
	res = val_to_ring(args, queuepct, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 4: queuelen (type: PT_UINT32) */
	res = val_to_ring(args, ack_backlog, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 5: queuemax (type: PT_UINT32) */
	res = val_to_ring(args, max_ack_backlog, 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_send_e(struct event_filler_arguments *args) {
	int res;
	unsigned long val;
	int64_t fd;
	uint32_t size;

	/* Parameter 1: fd (type: PT_FD) */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	fd = (int64_t)(int32_t)val;
	res = val_to_ring(args, fd, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 2: size (type: PT_UINT32) */
	syscall_get_arguments_deprecated(args, 2, 1, &val);
	size = (uint32_t)val;
	res = val_to_ring(args, size, 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_send_x(struct event_filler_arguments *args) {
	int res;
	int64_t retval;
	unsigned long val;
	int64_t fd;
	uint32_t size;
	unsigned long sent_data_pointer, bytes_to_read;
	char *targetbuf = args->str_storage;
	uint16_t tuple_size;

	/* Parameter 1: res (type: PT_ERRNO) */
	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	CHECK_RES(res);

	/* Extract fd and size syscall parameters */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	fd = (int64_t)(int32_t)val;
	syscall_get_arguments_deprecated(args, 2, 1, &val);
	size = (uint32_t)val;

	/* Parameter 2: data (type: PT_BYTEBUF) */
	/* If the syscall doesn't fail we use the return value as `size`
	 * otherwise we need to rely on the syscall parameter provided by the user.
	 */
	syscall_get_arguments_deprecated(args, 1, 1, &sent_data_pointer);
	bytes_to_read = retval > 0 ? retval : (unsigned long)size;
	args->fd = (int)fd;
	args->enforce_snaplen = true;
	res = val_to_ring(args, sent_data_pointer, bytes_to_read, true, 0);
	CHECK_RES(res);

	/* Parameter 3: fd (type: PT_FD) */
	res = val_to_ring(args, fd, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 4: size (type: PT_UINT32) */
	res = val_to_ring(args, size, 0, false, 0);
	CHECK_RES(res);

	if(retval < 0) {
		/* Parameter 5: tuple (type: PT_SOCKTUPLE) */
		res = push_empty_param(args);
		CHECK_RES(res);
		return add_sentinel(args);
	}

	/* Convert the fd into socket endpoint information */
	tuple_size = fd_to_socktuple((int)fd, NULL, 0, false, false, targetbuf, STR_STORAGE_SIZE);

	/* Parameter 5: tuple (type: PT_SOCKTUPLE) */
	res = val_to_ring(args, (uint64_t)(unsigned long)targetbuf, tuple_size, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_sendto_e(struct event_filler_arguments *args) {
	int res;
	unsigned long val;
	int64_t fd;
	uint32_t size;
	struct sockaddr __user *usrsockaddr;
	unsigned long usrsockaddr_len;
	struct sockaddr_storage address;
	struct sockaddr *ksockaddr = NULL;
	unsigned long sockaddr_len = 0;
	bool use_sockaddr = false;
	char *targetbuf = args->str_storage;
	uint16_t tuple_size = 0;

	/* Parameter 1: fd (type: PT_FD) */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	fd = (int64_t)(int32_t)val;
	res = val_to_ring(args, fd, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 2: size (type: PT_UINT32) */
	syscall_get_arguments_deprecated(args, 2, 1, &val);
	size = (uint32_t)val;
	res = val_to_ring(args, size, 0, false, 0);
	CHECK_RES(res);

	/* Get the address */
	syscall_get_arguments_deprecated(args, 4, 1, &val);
	usrsockaddr = (struct sockaddr __user *)val;

	/* Get the address len */
	syscall_get_arguments_deprecated(args, 5, 1, &usrsockaddr_len);

	if(usrsockaddr != NULL && usrsockaddr_len != 0) {
		/* Copy the address into kernel memory */
		res = addr_to_kernel(usrsockaddr, usrsockaddr_len, (struct sockaddr *)&address);
		if(likely(res >= 0)) {
			ksockaddr = (struct sockaddr *)&address;
			sockaddr_len = usrsockaddr_len;
			use_sockaddr = true;
		}
	}

	/* Convert the fd into socket endpoint information */
	tuple_size = fd_to_socktuple((int)fd,
	                             ksockaddr,
	                             sockaddr_len,
	                             use_sockaddr,
	                             false,
	                             targetbuf,
	                             STR_STORAGE_SIZE);

	/* Parameter 3: tuple (type: PT_SOCKTUPLE) */
	res = val_to_ring(args, (uint64_t)(unsigned long)targetbuf, tuple_size, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_sendto_x(struct event_filler_arguments *args) {
	int res;
	int64_t retval;
	unsigned long val;
	int64_t fd;
	uint32_t size;
	unsigned long sent_data_pointer, bytes_to_read;
	struct sockaddr __user *usrsockaddr;
	unsigned long usrsockaddr_len;
	struct sockaddr_storage address;
	struct sockaddr *ksockaddr = NULL;
	unsigned long sockaddr_len = 0;
	bool use_sockaddr = false;
	char *targetbuf = args->str_storage;
	uint16_t tuple_size = 0;

	/* Parameter 1: res (type: PT_ERRNO) */
	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	CHECK_RES(res);

	/* Extract fd and size syscall parameters */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	fd = (int64_t)(int32_t)val;
	syscall_get_arguments_deprecated(args, 2, 1, &val);
	size = (uint32_t)val;

	/* Parameter 2: data (type: PT_BYTEBUF) */
	/* If the syscall doesn't fail we use the return value as `size`
	 * otherwise we need to rely on the syscall parameter provided by the user.
	 */
	syscall_get_arguments_deprecated(args, 1, 1, &sent_data_pointer);
	bytes_to_read = retval > 0 ? retval : (unsigned long)size;
	args->fd = (int)fd;
	args->enforce_snaplen = true;
	res = val_to_ring(args, sent_data_pointer, bytes_to_read, true, 0);
	CHECK_RES(res);

	/* Parameter 3: fd (type: PT_FD) */
	res = val_to_ring(args, fd, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 4: size (type: PT_UINT32) */
	res = val_to_ring(args, size, 0, false, 0);
	CHECK_RES(res);

	if(retval < 0) {
		/* Parameter 5: tuple (type: PT_SOCKTUPLE) */
		res = push_empty_param(args);
		CHECK_RES(res);
		return add_sentinel(args);
	}

	/* Get the address */
	syscall_get_arguments_deprecated(args, 4, 1, &val);
	usrsockaddr = (struct sockaddr __user *)val;

	/* Get the address len */
	syscall_get_arguments_deprecated(args, 5, 1, &usrsockaddr_len);

	if(usrsockaddr != NULL && usrsockaddr_len != 0) {
		/* Copy the address into kernel memory */
		res = addr_to_kernel(usrsockaddr, usrsockaddr_len, (struct sockaddr *)&address);
		if(likely(res >= 0)) {
			ksockaddr = (struct sockaddr *)&address;
			sockaddr_len = usrsockaddr_len;
			use_sockaddr = true;
		}
	}

	/* Convert the fd into socket endpoint information */
	tuple_size = fd_to_socktuple((int)fd,
	                             ksockaddr,
	                             sockaddr_len,
	                             use_sockaddr,
	                             false,
	                             targetbuf,
	                             STR_STORAGE_SIZE);

	/* Parameter 3: tuple (type: PT_SOCKTUPLE) */
	res = val_to_ring(args, (uint64_t)(unsigned long)targetbuf, tuple_size, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_recv_x(struct event_filler_arguments *args) {
	int res;
	unsigned long val;
	int64_t retval;
	int64_t fd;
	unsigned long received_data_pointer, bytes_to_read;
	uint32_t size;
	char *targetbuf = args->str_storage;
	uint16_t tuple_size;

	/* Parameter 1: res (type: PT_ERRNO) */
	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	CHECK_RES(res);

	/* Extract fd parameter */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	fd = (int64_t)(int32_t)val;

	/* Parameter 2: data (type: PT_BYTEBUF) */
	/* Send an empty parameter if the syscall failed (or the return value is zero): indeed, in this
	 * case, the content of the buffer provided by the user remains untouched, and is not important.
	 */
	if(retval > 0) {
		syscall_get_arguments_deprecated(args, 1, 1, &received_data_pointer);
		bytes_to_read = retval;
		args->fd = (int)fd;
		args->enforce_snaplen = true;
		res = val_to_ring(args, received_data_pointer, bytes_to_read, true, 0);
	} else {
		res = push_empty_param(args);
	}
	CHECK_RES(res);

	/* Parameter 3: fd (type: PT_FD) */
	res = val_to_ring(args, fd, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 4: size (type: PT_UINT32) */
	syscall_get_arguments_deprecated(args, 2, 1, &val);
	size = (uint32_t)val;
	res = val_to_ring(args, size, 0, false, 0);
	CHECK_RES(res);

	if(retval < 0) {
		/* Parameter 5: tuple (type: PT_SOCKTUPLE) */
		res = push_empty_param(args);
		CHECK_RES(res);
		return add_sentinel(args);
	}

	/* Convert the fd into socket endpoint information */
	tuple_size = fd_to_socktuple((int)fd, NULL, 0, false, true, targetbuf, STR_STORAGE_SIZE);

	/* Parameter 5: tuple (type: PT_SOCKTUPLE) */
	res = val_to_ring(args, (uint64_t)(unsigned long)targetbuf, tuple_size, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_recvfrom_e(struct event_filler_arguments *args) {
	int res = 0;
	unsigned long val = 0;
	int32_t fd = 0;

	/* Parameter 1: fd (type: PT_FD) */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	fd = (int32_t)val;
	res = val_to_ring(args, (int64_t)fd, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 2: size (type: PT_UINT32) */
	syscall_get_arguments_deprecated(args, 2, 1, &val);
	res = val_to_ring(args, val, 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_recvfrom_x(struct event_filler_arguments *args) {
	int res;
	unsigned long val;
	int64_t retval;
	int64_t fd;
	uint16_t size;
	unsigned long received_data_pointer, bytes_to_read;
	struct sockaddr __user *usrsockaddr;
	void *usrsockaddr_len_pointer;
	unsigned long usrsockaddr_len;
	struct sockaddr_storage address;
	struct sockaddr *ksockaddr = NULL;
	unsigned long sockaddr_len = 0;
	bool use_sockaddr = false;
	char *targetbuf = args->str_storage;
	uint16_t tuple_size = 0;

	/* Parameter 1: res (type: PT_ERRNO) */
	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	CHECK_RES(res);

	/* Extract fd and size parameters */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	fd = (int64_t)(int32_t)val;
	syscall_get_arguments_deprecated(args, 2, 1, &val);
	size = (uint32_t)val;

	if(retval < 0) {
		/* Parameter 2: data (type: PT_BYTEBUF) */
		res = push_empty_param(args);
		CHECK_RES(res);

		/* Parameter 3: tuple (type: PT_SOCKTUPLE) */
		res = push_empty_param(args);
		CHECK_RES(res);

		/* Parameter 4: fd (type: PT_FD) */
		res = val_to_ring(args, fd, 0, false, 0);
		CHECK_RES(res);

		/* Parameter 5: size (type: PT_UINT32) */
		res = val_to_ring(args, size, 0, false, 0);
		CHECK_RES(res);

		return add_sentinel(args);
	}

	/* Handle successful system call path. */

	/* Parameter 2: data (type: PT_BYTEBUF) */
	syscall_get_arguments_deprecated(args, 1, 1, &received_data_pointer);
	bytes_to_read = retval;
	args->fd = (int)fd;
	args->enforce_snaplen = true;
	res = val_to_ring(args, received_data_pointer, bytes_to_read, true, 0);
	CHECK_RES(res);

	/* Get the address */
	syscall_get_arguments_deprecated(args, 4, 1, &val);
	usrsockaddr = (struct sockaddr __user *)val;

	/* Get the address len pointer */
	syscall_get_arguments_deprecated(args, 5, 1, &val);
	usrsockaddr_len_pointer = (void *)val;

	/* Evaluate socktuple, leveraging the user-provided sockaddr if possible */
	if(usrsockaddr != NULL && usrsockaddr_len_pointer != NULL) {
#ifdef CONFIG_COMPAT
		if(!args->compat) {
#endif
			if(unlikely(ppm_copy_from_user(&usrsockaddr_len,
			                               (const void __user *)usrsockaddr_len_pointer,
			                               sizeof(usrsockaddr_len)))) {
				return PPM_FAILURE_INVALID_USER_MEMORY;
			}
#ifdef CONFIG_COMPAT
		} else {
			if(unlikely(ppm_copy_from_user(
			           &usrsockaddr_len,
			           (const void __user *)compat_ptr((unsigned long)usrsockaddr_len_pointer),
			           sizeof(usrsockaddr_len)))) {
				return PPM_FAILURE_INVALID_USER_MEMORY;
			}
		}
#endif

		/* Copy the address into kernel memory */
		res = addr_to_kernel(usrsockaddr, usrsockaddr_len, (struct sockaddr *)&address);
		if(likely(res >= 0)) {
			ksockaddr = (struct sockaddr *)&address;
			sockaddr_len = usrsockaddr_len;
			use_sockaddr = true;
		}
	}

	/* Convert the fd into socket endpoint information */
	tuple_size = fd_to_socktuple((int)fd,
	                             ksockaddr,
	                             sockaddr_len,
	                             use_sockaddr,
	                             true,
	                             targetbuf,
	                             STR_STORAGE_SIZE);

	/* Parameter 3: tuple (type: PT_SOCKTUPLE) */
	res = val_to_ring(args, (uint64_t)(unsigned long)targetbuf, tuple_size, false, 0);
	CHECK_RES(res);

	/* Parameter 4: fd (type: PT_FD) */
	res = val_to_ring(args, fd, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 5: size (type: PT_UINT32) */
	res = val_to_ring(args, size, 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_sendmsg_e(struct event_filler_arguments *args) {
	int res;
	unsigned long val;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 19, 0)
	struct user_msghdr mh;
#else
	struct msghdr mh;
#endif
	char *targetbuf = args->str_storage;
	const struct iovec __user *iov;
#ifdef CONFIG_COMPAT
	const struct compat_iovec __user *compat_iov;
	struct compat_msghdr compat_mh;
#endif
	unsigned long iovcnt;
	int32_t fd = 0;
	uint16_t size = 0;
	int addrlen;
	int err = 0;
	struct sockaddr __user *usrsockaddr;
	struct sockaddr_storage address;

	/*
	 * fd
	 */
	syscall_get_arguments_deprecated(args, 0, 1, &val);

	fd = (int32_t)val;
	res = val_to_ring(args, (int64_t)fd, 0, false, 0);
	CHECK_RES(res);

	/*
	 * Retrieve the message header
	 */
	syscall_get_arguments_deprecated(args, 1, 1, &val);

#ifdef CONFIG_COMPAT
	if(!args->compat) {
#endif
		if(unlikely(ppm_copy_from_user(&mh, (const void __user *)val, sizeof(mh))))
			return PPM_FAILURE_INVALID_USER_MEMORY;

		/*
		 * size
		 */
		iov = (const struct iovec __user *)mh.msg_iov;
		iovcnt = mh.msg_iovlen;

		res = parse_readv_writev_bufs(args,
		                              iov,
		                              iovcnt,
		                              args->consumer->snaplen,
		                              PRB_FLAG_PUSH_SIZE | PRB_FLAG_IS_WRITE);

		CHECK_RES(res);

		/*
		 * tuple
		 */
		usrsockaddr = (struct sockaddr __user *)mh.msg_name;
		addrlen = mh.msg_namelen;
#ifdef CONFIG_COMPAT
	} else {
		if(unlikely(ppm_copy_from_user(&compat_mh,
		                               (const void __user *)compat_ptr(val),
		                               sizeof(compat_mh))))
			return PPM_FAILURE_INVALID_USER_MEMORY;

		/*
		 * size
		 */
		compat_iov = (const struct compat_iovec __user *)compat_ptr(compat_mh.msg_iov);
		iovcnt = compat_mh.msg_iovlen;

		res = compat_parse_readv_writev_bufs(args,
		                                     compat_iov,
		                                     iovcnt,
		                                     args->consumer->snaplen,
		                                     PRB_FLAG_PUSH_SIZE | PRB_FLAG_IS_WRITE);

		CHECK_RES(res);

		/*
		 * tuple
		 */
		usrsockaddr = (struct sockaddr __user *)compat_ptr(compat_mh.msg_name);
		addrlen = compat_mh.msg_namelen;
	}
#endif

	if(usrsockaddr != NULL && addrlen != 0) {
		/*
		 * Copy the address
		 */
		err = addr_to_kernel(usrsockaddr, addrlen, (struct sockaddr *)&address);
		if(likely(err >= 0)) {
			/*
			 * Convert the fd into socket endpoint information
			 */
			size = fd_to_socktuple(fd,
			                       (struct sockaddr *)&address,
			                       addrlen,
			                       true,
			                       false,
			                       targetbuf,
			                       STR_STORAGE_SIZE);
		}
	}

	/* Copy the endpoint info into the ring */
	res = val_to_ring(args, (uint64_t)(unsigned long)targetbuf, size, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_sendmsg_x(struct event_filler_arguments *args) {
	int res;
	unsigned long val;
	int64_t retval;
	int64_t fd;
	unsigned long mh_pointer;
	const struct iovec __user *iov;
#ifdef CONFIG_COMPAT
	const struct compat_iovec __user *compat_iov;
	struct compat_msghdr compat_mh;
#endif
	unsigned long iovcnt;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 19, 0)
	struct user_msghdr mh;
#else
	struct msghdr mh;
#endif
	int usrsockaddr_len;
	struct sockaddr __user *usrsockaddr;
	struct sockaddr_storage address;
	struct sockaddr *ksockaddr = NULL;
	unsigned long sockaddr_len = 0;
	bool use_sockaddr = false;
	char *targetbuf = args->str_storage;
	uint16_t tuple_size = 0;

	/* Parameter 1: res (type: PT_ERRNO) */
	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	CHECK_RES(res);

	/* Extract socket fd and msghdr pointer syscall parameters. */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	fd = (int64_t)(int32_t)val;
	syscall_get_arguments_deprecated(args, 1, 1, &mh_pointer);

	/* Parameter 2: data (type: PT_BYTEBUF) */
	/* Extract the content of msghdr and use it to derive the parameters. */
#ifdef CONFIG_COMPAT
	if(!args->compat) {
#endif
		if(unlikely(ppm_copy_from_user(&mh, (const void __user *)mh_pointer, sizeof(mh)))) {
			/* Parameter 2: data (type: PT_BYTEBUF) */
			res = push_empty_param(args);
			CHECK_RES(res);

			/* Parameter 3: fd (type: PT_FD) */
			res = val_to_ring(args, (int64_t)fd, 0, false, 0);
			CHECK_RES(res);

			/* Parameter 4: size (type: PT_UINT32) */
			res = push_empty_param(args);
			CHECK_RES(res);

			/* Parameter 5: tuple (type: PT_SOCKTUPLE) */
			res = push_empty_param(args);
			CHECK_RES(res);

			return add_sentinel(args);
		}

		iov = (const struct iovec __user *)mh.msg_iov;
		iovcnt = mh.msg_iovlen;

		/* Parameter 2: data (type: PT_BYTEBUF) */
		res = parse_readv_writev_bufs(args,
		                              iov,
		                              iovcnt,
		                              args->consumer->snaplen,
		                              PRB_FLAG_PUSH_DATA | PRB_FLAG_IS_WRITE);
		CHECK_RES(res);

		/* Parameter 3: fd (type: PT_FD) */
		res = val_to_ring(args, (int64_t)fd, 0, false, 0);
		CHECK_RES(res);

		/* Parameter 4: size (type: PT_UINT32) */
		res = parse_readv_writev_bufs(args,
		                              iov,
		                              iovcnt,
		                              args->consumer->snaplen,
		                              PRB_FLAG_PUSH_SIZE | PRB_FLAG_IS_WRITE);
		CHECK_RES(res);

		usrsockaddr = (struct sockaddr __user *)mh.msg_name;
		usrsockaddr_len = mh.msg_namelen;

#ifdef CONFIG_COMPAT
	} else {
		if(unlikely(ppm_copy_from_user(&compat_mh,
		                               (const void __user *)compat_ptr(mh_pointer),
		                               sizeof(compat_mh)))) {
			/* Parameter 2: data (type: PT_BYTEBUF) */
			res = push_empty_param(args);
			CHECK_RES(res);

			/* Parameter 3: fd (type: PT_FD) */
			res = val_to_ring(args, (int64_t)fd, 0, false, 0);
			CHECK_RES(res);

			/* Parameter 4: size (type: PT_UINT32) */
			res = push_empty_param(args);
			CHECK_RES(res);

			/* Parameter 5: tuple (type: PT_SOCKTUPLE) */
			res = push_empty_param(args);
			CHECK_RES(res);

			return add_sentinel(args);
		}

		compat_iov = (const struct compat_iovec __user *)compat_ptr(compat_mh.msg_iov);
		iovcnt = compat_mh.msg_iovlen;

		/* Parameter 2: data (type: PT_BYTEBUF) */
		res = compat_parse_readv_writev_bufs(args,
		                                     compat_iov,
		                                     iovcnt,
		                                     args->consumer->snaplen,
		                                     PRB_FLAG_PUSH_DATA | PRB_FLAG_IS_WRITE);
		CHECK_RES(res);

		/* Parameter 3: fd (type: PT_FD) */
		res = val_to_ring(args, (int64_t)fd, 0, false, 0);
		CHECK_RES(res);

		/* Parameter 4: size (type: PT_UINT32) */
		res = compat_parse_readv_writev_bufs(args,
		                                     compat_iov,
		                                     iovcnt,
		                                     args->consumer->snaplen,
		                                     PRB_FLAG_PUSH_SIZE | PRB_FLAG_IS_WRITE);
		CHECK_RES(res);

		usrsockaddr = (struct sockaddr __user *)compat_ptr(compat_mh.msg_name);
		usrsockaddr_len = compat_mh.msg_namelen;
	}
#endif

	if(retval < 0) {
		/* Parameter 5: tuple (type: PT_SOCKTUPLE) */
		res = push_empty_param(args);
		CHECK_RES(res);

		return add_sentinel(args);
	}

	if(usrsockaddr != NULL && usrsockaddr_len != 0) {
		/* Copy the address into kernel memory */
		res = addr_to_kernel(usrsockaddr, usrsockaddr_len, (struct sockaddr *)&address);
		if(likely(res >= 0)) {
			ksockaddr = (struct sockaddr *)&address;
			sockaddr_len = usrsockaddr_len;
			use_sockaddr = true;
		}
	}

	/* Convert the fd into socket endpoint information */
	tuple_size = fd_to_socktuple((int)fd,
	                             ksockaddr,
	                             sockaddr_len,
	                             use_sockaddr,
	                             false,
	                             targetbuf,
	                             STR_STORAGE_SIZE);

	/* Parameter 5: tuple (type: PT_SOCKTUPLE) */
	res = val_to_ring(args, (uint64_t)(unsigned long)targetbuf, tuple_size, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_sendmmsg_x(struct event_filler_arguments *args) {
	int res;
	unsigned long val;
	long retval;
	char *targetbuf = args->str_storage;
	const struct iovec __user *iov;
#ifdef CONFIG_COMPAT
	const struct compat_iovec __user *compat_iov;
	struct compat_mmsghdr compat_mmh;
#endif
	unsigned long iovcnt;
	int fd;
	uint16_t size = 0;
	int addrlen;
	int err = 0;
	struct sockaddr __user *usrsockaddr;
	struct sockaddr_storage address;

	struct mmsghdr mmh;
	struct mmsghdr *mmh_ptr;

	retval = syscall_get_return_value(current, args->regs);
	args->mmsg.count = retval;

	// Get fd, needed on all branches
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	fd = val;

	/* If the syscall fails we are not able to collect reliable params
	 * so we return empty ones.
	 */
	if(retval < 0) {
		/* Parameter 1: res (type: PT_ERRNO) */
		res = val_to_ring(args, retval, 0, false, 0);
		CHECK_RES(res);

		/* Parameter 2: fd (type: PT_FD) */
		res = val_to_ring(args, fd, 0, false, 0);
		CHECK_RES(res);

		/* Parameter 3: size (type: PT_UINT32) */
		res = val_to_ring(args, 0, 0, false, 0);
		CHECK_RES(res);

		/* Parameter 4: data (type: PT_BYTEBUF) */
		res = push_empty_param(args);
		CHECK_RES(res);

		/* Parameter 5: tuple (type: PT_SOCKTUPLE) */
		res = push_empty_param(args);
		CHECK_RES(res);

		return add_sentinel(args);
	}

	/*
	 * Retrieve the message header
	 */
	syscall_get_arguments_deprecated(args, 1, 1, &val);

	mmh_ptr = ((struct mmsghdr *)val) + args->mmsg.index;
#ifdef CONFIG_COMPAT
	if(!args->compat) {
#endif
		if(unlikely(ppm_copy_from_user(&mmh, (const void __user *)mmh_ptr, sizeof(mmh)))) {
			/* Parameter 1: res (type: PT_ERRNO) */
			res = val_to_ring(args, retval, 0, false, 0);
			CHECK_RES(res);

			/* Parameter 2: fd (type: PT_FD) */
			res = val_to_ring(args, fd, 0, false, 0);
			CHECK_RES(res);

			/* Parameter 3: size (type: PT_UINT32) */
			res = val_to_ring(args, 0, 0, false, 0);
			CHECK_RES(res);

			/* Parameter 4: data (type: PT_BYTEBUF) */
			res = push_empty_param(args);
			CHECK_RES(res);

			/* Parameter 5: tuple (type: PT_SOCKTUPLE) */
			res = push_empty_param(args);
			CHECK_RES(res);

			return add_sentinel(args);
		}

		/* Parameter 1: res (type: PT_ERRNO) */
		res = val_to_ring(args, mmh.msg_len, 0, false, 0);
		CHECK_RES(res);

		/* Parameter 2: fd (type: PT_FD) */
		res = val_to_ring(args, fd, 0, false, 0);
		CHECK_RES(res);

		iov = (const struct iovec __user *)mmh.msg_hdr.msg_iov;
		iovcnt = mmh.msg_hdr.msg_iovlen;

		/* Parameter 3: size (type: PT_UINT32) */
		/* Parameter 4: data (type: PT_BYTEBUF) */
		res = parse_readv_writev_bufs(args,
		                              iov,
		                              iovcnt,
		                              args->consumer->snaplen,
		                              PRB_FLAG_PUSH_ALL | PRB_FLAG_IS_WRITE);
		CHECK_RES(res);
#ifdef CONFIG_COMPAT
	} else {
		if(unlikely(ppm_copy_from_user(&compat_mmh,
		                               (const void __user *)compat_ptr((unsigned long)mmh_ptr),
		                               sizeof(compat_mmh)))) {
			/* Parameter 1: res (type: PT_ERRNO) */
			res = val_to_ring(args, retval, 0, false, 0);
			CHECK_RES(res);

			/* Parameter 2: fd (type: PT_FD) */
			res = val_to_ring(args, fd, 0, false, 0);
			CHECK_RES(res);

			/* Parameter 3: size (type: PT_UINT32) */
			res = val_to_ring(args, 0, 0, false, 0);
			CHECK_RES(res);

			/* Parameter 4: data (type: PT_BYTEBUF) */
			res = push_empty_param(args);
			CHECK_RES(res);

			/* Parameter 5: tuple (type: PT_SOCKTUPLE) */
			res = push_empty_param(args);
			CHECK_RES(res);

			return add_sentinel(args);
		}

		/* Parameter 1: res (type: PT_ERRNO) */
		res = val_to_ring(args, compat_mmh.msg_len, 0, false, 0);
		CHECK_RES(res);

		/* Parameter 2: fd (type: PT_FD) */
		res = val_to_ring(args, fd, 0, false, 0);
		CHECK_RES(res);

		compat_iov = (const struct compat_iovec __user *)compat_ptr(compat_mmh.msg_hdr.msg_iov);
		iovcnt = compat_mmh.msg_hdr.msg_iovlen;

		/* Parameter 3: size (type: PT_UINT32) */
		/* Parameter 4: data (type: PT_BYTEBUF) */
		res = compat_parse_readv_writev_bufs(args,
		                                     compat_iov,
		                                     iovcnt,
		                                     args->consumer->snaplen,
		                                     PRB_FLAG_PUSH_ALL | PRB_FLAG_IS_WRITE);
		CHECK_RES(res);
	}
#endif

	/* Parameter 5: tuple (type: PT_SOCKTUPLE) */
	usrsockaddr = (struct sockaddr __user *)mmh.msg_hdr.msg_name;
	addrlen = mmh.msg_hdr.msg_namelen;

	if(usrsockaddr != NULL && addrlen != 0) {
		/*
		 * Copy the address
		 */
		err = addr_to_kernel(usrsockaddr, addrlen, (struct sockaddr *)&address);
		if(likely(err >= 0)) {
			/*
			 * Convert the fd into socket endpoint information
			 */
			size = fd_to_socktuple(fd,
			                       (struct sockaddr *)&address,
			                       addrlen,
			                       true,
			                       false,
			                       targetbuf,
			                       STR_STORAGE_SIZE);
		}
	}

	/* Copy the endpoint info into the ring */
	res = val_to_ring(args, (uint64_t)(unsigned long)targetbuf, size, false, 0);
	return add_sentinel(args);
}

int f_sys_listen_e(struct event_filler_arguments *args) {
	unsigned long val = 0;
	int res = 0;
	int32_t fd = 0;
	int32_t backlog = 0;

	/* Parameter 1: fd (type: PT_FD) */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	fd = (int32_t)val;
	res = val_to_ring(args, (int64_t)fd, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 2: backlog (type: PT_INT32) */
	syscall_get_arguments_deprecated(args, 1, 1, &val);
	backlog = (int32_t)val;
	res = val_to_ring(args, (int32_t)backlog, 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_listen_x(struct event_filler_arguments *args) {
	int res;
	unsigned long val = 0;
	int64_t retval;
	int32_t fd = 0;
	int32_t backlog = 0;

	/* Parameter 1: res (type: PT_ERRNO) */
	retval = (int64_t)(long)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 2: fd (type: PT_FD) */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	fd = (int32_t)val;
	res = val_to_ring(args, (int64_t)fd, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 3: backlog (type: PT_INT32) */
	syscall_get_arguments_deprecated(args, 1, 1, &val);
	backlog = (int32_t)val;
	res = val_to_ring(args, (int32_t)backlog, 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_recvmsg_e(struct event_filler_arguments *args) {
	unsigned long val = 0;
	int res = 0;
	int32_t fd = 0;

	/* Parameter 1: fd (type: PT_FD)*/
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	fd = (int32_t)val;
	res = val_to_ring(args, (int64_t)fd, 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_recvmsg_x(struct event_filler_arguments *args) {
	int res;
	unsigned long val;
	int64_t retval;
	int64_t fd;
	unsigned long mh_pointer;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 19, 0)
	struct user_msghdr mh;
#else
	struct msghdr mh;
#endif
	const struct iovec __user *iov;
#ifdef CONFIG_COMPAT
	const struct compat_iovec __user *compat_iov;
	struct compat_msghdr compat_mh;
#endif
	unsigned long iovcnt;
	int usrsockaddr_len;
	struct sockaddr __user *usrsockaddr;
	struct sockaddr_storage address;
	struct sockaddr *ksockaddr = NULL;
	unsigned long sockaddr_len = 0;
	bool use_sockaddr = false;
	char *targetbuf = args->str_storage;
	uint16_t tuple_size = 0;

	/* Parameter 1: res (type: PT_ERRNO) */
	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	CHECK_RES(res);

	/* Extract fd syscall parameter for later usage. */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	fd = (int64_t)(int32_t)val;

	/* If the syscall fails we are not able to collect reliable params so we return empty ones. */
	if(retval < 0) {
		/* Parameter 2: size (type: PT_UINT32) */
		res = val_to_ring(args, 0, 0, false, 0);
		CHECK_RES(res);

		/* Parameter 3: data (type: PT_BYTEBUF) */
		res = push_empty_param(args);
		CHECK_RES(res);

		/* Parameter 4: tuple (type: PT_SOCKTUPLE) */
		res = push_empty_param(args);
		CHECK_RES(res);

		/* Parameter 5: msg_control (type: PT_BYTEBUF) */
		res = push_empty_param(args);
		CHECK_RES(res);

		/* Parameter 6: fd (type: PT_FD) */
		res = val_to_ring(args, fd, 0, false, 0);
		CHECK_RES(res);

		return add_sentinel(args);
	}

	/* Extract the content of msghdr and use it to derive the parameters. */
	syscall_get_arguments_deprecated(args, 1, 1, &mh_pointer);

#ifdef CONFIG_COMPAT
	if(!args->compat) {
#endif
		if(unlikely(ppm_copy_from_user(&mh, (const void __user *)mh_pointer, sizeof(mh)))) {
			return PPM_FAILURE_INVALID_USER_MEMORY;
		}

		/* Parameter 2: size (type: PT_UINT32) */
		/* Parameter 3: data (type: PT_BYTEBUF) */
		iov = (const struct iovec __user *)mh.msg_iov;
		iovcnt = mh.msg_iovlen;
		res = parse_readv_writev_bufs(args, iov, iovcnt, retval, PRB_FLAG_PUSH_ALL);
		CHECK_RES(res);

		/* Get the address pointer and length */
		usrsockaddr = (struct sockaddr __user *)mh.msg_name;
		usrsockaddr_len = mh.msg_namelen;

#ifdef CONFIG_COMPAT
	} else {
		if(unlikely(ppm_copy_from_user(&compat_mh,
		                               (const void __user *)compat_ptr(val),
		                               sizeof(compat_mh)))) {
			return PPM_FAILURE_INVALID_USER_MEMORY;
		}

		/* Parameter 2: size (type: PT_UINT32) */
		/* Parameter 3: data (type: PT_BYTEBUF) */
		compat_iov = (const struct compat_iovec __user *)compat_ptr(compat_mh.msg_iov);
		iovcnt = compat_mh.msg_iovlen;
		res = compat_parse_readv_writev_bufs(args, compat_iov, iovcnt, retval, PRB_FLAG_PUSH_ALL);
		CHECK_RES(res);

		/* Get the address pointer and length. */
		usrsockaddr = (struct sockaddr __user *)compat_ptr(compat_mh.msg_name);
		usrsockaddr_len = compat_mh.msg_namelen;
	}
#endif

	if(usrsockaddr != NULL && usrsockaddr_len != 0) {
		/* Copy the address into kernel memory. */
		res = addr_to_kernel(usrsockaddr, usrsockaddr_len, (struct sockaddr *)&address);
		if(likely(res >= 0)) {
			ksockaddr = (struct sockaddr *)&address;
			sockaddr_len = usrsockaddr_len;
			use_sockaddr = true;
		}
	}

	/* Convert the fd into socket endpoint information. */
	tuple_size = fd_to_socktuple((int)fd,
	                             ksockaddr,
	                             sockaddr_len,
	                             use_sockaddr,
	                             true,
	                             targetbuf,
	                             STR_STORAGE_SIZE);

	/* Parameter 4: tuple (type: PT_SOCKTUPLE) */
	res = val_to_ring(args, (uint64_t)(unsigned long)targetbuf, tuple_size, false, 0);
	CHECK_RES(res);

	/* Parameter 5: msg_control (type: PT_BYTEBUF) */
	if(mh.msg_control != NULL && mh.msg_controllen > 0) {
		res = val_to_ring(args, (uint64_t)mh.msg_control, (uint32_t)mh.msg_controllen, true, 0);
	} else {
		res = push_empty_param(args);
	}
	CHECK_RES(res);

	/* Parameter 6: fd (type: PT_FD) */
	res = val_to_ring(args, fd, 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_recvmmsg_x(struct event_filler_arguments *args) {
	int res;
	unsigned long val;
	int64_t retval;
	const struct iovec __user *iov;
#ifdef CONFIG_COMPAT
	const struct compat_iovec __user *compat_iov;
	struct compat_mmsghdr compat_mmh;
#endif
	unsigned long iovcnt;
	struct mmsghdr mmh;
	struct mmsghdr *mmh_ptr;
	char *targetbuf = args->str_storage;
	int fd;
	struct sockaddr __user *usrsockaddr;
	struct sockaddr_storage address;
	uint16_t size = 0;
	int addrlen;
	int err = 0;

	retval = (int64_t)syscall_get_return_value(current, args->regs);
	args->mmsg.count = retval;

	// Get fd, needed on all branches
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	fd = (int32_t)val;

	/* If the syscall fails we are not able to collect reliable params
	 * so we return empty ones.
	 */
	if(retval < 0) {
		/* Parameter 1: res (type: PT_ERRNO) */
		res = val_to_ring(args, retval, 0, false, 0);
		CHECK_RES(res);

		/* Parameter 2: fd (type: PT_FD) */
		res = val_to_ring(args, (int64_t)fd, 0, false, 0);
		CHECK_RES(res);

		/* Parameter 3: size (type: PT_UINT32) */
		res = val_to_ring(args, 0, 0, false, 0);
		CHECK_RES(res);

		/* Parameter 4: data (type: PT_BYTEBUF) */
		res = push_empty_param(args);
		CHECK_RES(res);

		/* Parameter 5: tuple (type: PT_SOCKTUPLE) */
		res = push_empty_param(args);
		CHECK_RES(res);

		/* Parameter 6: msg_control (type: PT_BYTEBUF) */
		res = push_empty_param(args);
		CHECK_RES(res);

		return add_sentinel(args);
	}

	/*
	 * Retrieve the message header
	 */
	syscall_get_arguments_deprecated(args, 1, 1, &val);

	mmh_ptr = ((struct mmsghdr *)val) + args->mmsg.index;
#ifdef CONFIG_COMPAT
	if(!args->compat) {
#endif
		if(unlikely(ppm_copy_from_user(&mmh, (const void __user *)mmh_ptr, sizeof(mmh))))
			return PPM_FAILURE_INVALID_USER_MEMORY;

		/* Parameter 1: res (type: PT_ERRNO) */
		res = val_to_ring(args, mmh.msg_len, 0, false, 0);
		CHECK_RES(res);

		/* Parameter 2: fd (type: PT_FD)*/
		res = val_to_ring(args, (int64_t)fd, 0, false, 0);
		CHECK_RES(res);

		/*
		 * data and size
		 */
		iov = (const struct iovec __user *)mmh.msg_hdr.msg_iov;
		iovcnt = mmh.msg_hdr.msg_iovlen;

		res = parse_readv_writev_bufs(args, iov, iovcnt, mmh.msg_len, PRB_FLAG_PUSH_ALL);
#ifdef CONFIG_COMPAT
	} else {
		if(unlikely(ppm_copy_from_user(&compat_mmh,
		                               (const void __user *)compat_ptr((unsigned long)mmh_ptr),
		                               sizeof(compat_mmh))))
			return PPM_FAILURE_INVALID_USER_MEMORY;

		/* Parameter 1: res (type: PT_ERRNO) */
		res = val_to_ring(args, compat_mmh.msg_len, 0, false, 0);
		CHECK_RES(res);

		/* Parameter 2: fd (type: PT_FD)*/
		res = val_to_ring(args, (int64_t)fd, 0, false, 0);
		CHECK_RES(res);

		/*
		 * data and size
		 */
		compat_iov = (const struct compat_iovec __user *)compat_ptr(compat_mmh.msg_hdr.msg_iov);
		iovcnt = compat_mmh.msg_hdr.msg_iovlen;

		res = compat_parse_readv_writev_bufs(args,
		                                     compat_iov,
		                                     iovcnt,
		                                     compat_mmh.msg_len,
		                                     PRB_FLAG_PUSH_ALL);
	}
#endif

	CHECK_RES(res);

	/*
	 * tuple
	 */
	if(retval >= 0) {
		/*
		 * Get the address
		 */
		usrsockaddr = (struct sockaddr __user *)mmh.msg_hdr.msg_name;
		addrlen = mmh.msg_hdr.msg_namelen;

		if(usrsockaddr != NULL && addrlen != 0) {
			/*
			 * Copy the address
			 */
			err = addr_to_kernel(usrsockaddr, addrlen, (struct sockaddr *)&address);
			if(likely(err >= 0)) {
				/*
				 * Convert the fd into socket endpoint information
				 */
				size = fd_to_socktuple(fd,
				                       (struct sockaddr *)&address,
				                       addrlen,
				                       true,
				                       true,
				                       targetbuf,
				                       STR_STORAGE_SIZE);
			}
		}
	}

	/* Copy the endpoint info into the ring */
	res = val_to_ring(args, (uint64_t)(unsigned long)targetbuf, size, false, 0);
	CHECK_RES(res);

	/*
	    msg_control: ancillary data.
	*/
	if(mmh.msg_hdr.msg_control != NULL && mmh.msg_hdr.msg_controllen > 0) {
		res = val_to_ring(args,
		                  (uint64_t)mmh.msg_hdr.msg_control,
		                  (uint32_t)mmh.msg_hdr.msg_controllen,
		                  true,
		                  0);
		CHECK_RES(res);
	} else {
		/* pushing empty data */
		res = push_empty_param(args);
		CHECK_RES(res);
	}

	return add_sentinel(args);
}

int f_sys_creat_e(struct event_filler_arguments *args) {
	unsigned long val;
	unsigned long modes;
	int res;

	/*
	 * name
	 */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	res = val_to_ring(args, val, 0, true, 0);
	CHECK_RES(res);

	/*
	 *  mode
	 */
	syscall_get_arguments_deprecated(args, 1, 1, &modes);
	res = val_to_ring(args, open_modes_to_scap(O_CREAT, modes), 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_creat_x(struct event_filler_arguments *args) {
	unsigned long val;
	unsigned long modes;
	uint32_t dev = 0;
	uint64_t ino = 0;
	int res;
	int64_t retval;
	enum ppm_overlay ol = PPM_NOT_OVERLAY_FS;
	int16_t creat_flags = 0;

	/*
	 * fd
	 */
	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	CHECK_RES(res);

	/*
	 * name
	 */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	res = val_to_ring(args, val, 0, true, 0);
	CHECK_RES(res);
	/*
	 *  mode
	 */
	syscall_get_arguments_deprecated(args, 1, 1, &modes);
	res = val_to_ring(args, open_modes_to_scap(O_CREAT, modes), 0, false, 0);
	CHECK_RES(res);

	get_dev_ino_overlay_from_fd(retval, &dev, &ino, &ol);

	/*
	 *  dev
	 */
	res = val_to_ring(args, dev, 0, false, 0);
	CHECK_RES(res);

	/*
	 *  ino
	 */
	res = val_to_ring(args, ino, 0, false, 0);
	CHECK_RES(res);

	/*
	 * creat_flags
	 */
	if(ol == PPM_OVERLAY_UPPER) {
		creat_flags |= PPM_FD_UPPER_LAYER_CREAT;
	} else if(ol == PPM_OVERLAY_LOWER) {
		creat_flags |= PPM_FD_LOWER_LAYER_CREAT;
	}
	res = val_to_ring(args, creat_flags, 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_pipe_x(struct event_filler_arguments *args) {
	int res = 0;
	int64_t retval = 0;
	unsigned long val = 0;
	int pipefd[2] = {-1, -1};
	uint64_t ino = 0;

	/* Parameter 1: res (type: PT_ERRNO) */
	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	CHECK_RES(res);

	/* Here `val` is a pointer to the vector with the 2 file descriptors. */
	syscall_get_arguments_deprecated(args, 0, 1, &val);

#ifdef CONFIG_COMPAT
	if(!args->compat) {
#endif
		if(unlikely(ppm_copy_from_user(pipefd, (const void __user *)val, sizeof(pipefd)))) {
			pipefd[0] = -1;
			pipefd[1] = -1;
		}
#ifdef CONFIG_COMPAT
	} else {
		if(unlikely(ppm_copy_from_user(pipefd,
		                               (const void __user *)compat_ptr(val),
		                               sizeof(pipefd)))) {
			pipefd[0] = -1;
			pipefd[1] = -1;
		}
	}
#endif

	/* Parameter 2: fd1 (type: PT_FD) */
	res = val_to_ring(args, (int64_t)pipefd[0], 0, false, 0);
	CHECK_RES(res);

	/* Parameter 3: fd2 (type: PT_FD) */
	res = val_to_ring(args, (int64_t)pipefd[1], 0, false, 0);
	CHECK_RES(res);

	/* On success, pipe returns `0` */
	if(retval == 0) {
		get_ino_from_fd(pipefd[0], &ino);
	}

	/* Parameter 4: ino (type: PT_UINT64) */
	res = val_to_ring(args, ino, 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_pipe2_x(struct event_filler_arguments *args) {
	int res = 0;
	int64_t retval = 0;
	unsigned long val = 0;
	int pipefd[2] = {-1, -1};
	uint64_t ino = 0;

	/* Parameter 1: res (type: PT_ERRNO) */
	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	CHECK_RES(res);

	/* Here `val` is a pointer to the vector with the 2 file descriptors. */
	syscall_get_arguments_deprecated(args, 0, 1, &val);

#ifdef CONFIG_COMPAT
	if(!args->compat) {
#endif
		if(unlikely(ppm_copy_from_user(pipefd, (const void __user *)val, sizeof(pipefd)))) {
			pipefd[0] = -1;
			pipefd[1] = -1;
		}
#ifdef CONFIG_COMPAT
	} else {
		if(unlikely(ppm_copy_from_user(pipefd,
		                               (const void __user *)compat_ptr(val),
		                               sizeof(pipefd)))) {
			pipefd[0] = -1;
			pipefd[1] = -1;
		}
	}
#endif

	/* Parameter 2: fd1 (type: PT_FD) */
	res = val_to_ring(args, (int64_t)pipefd[0], 0, false, 0);
	CHECK_RES(res);

	/* Parameter 3: fd2 (type: PT_FD) */
	res = val_to_ring(args, (int64_t)pipefd[1], 0, false, 0);
	CHECK_RES(res);

	/* On success, pipe returns `0` */
	if(retval == 0) {
		get_ino_from_fd(pipefd[0], &ino);
	}

	/* Parameter 4: ino (type: PT_UINT64) */
	res = val_to_ring(args, ino, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 5: flags (type: PT_FLAGS32) */
	syscall_get_arguments_deprecated(args, 1, 1, &val);
	res = val_to_ring(args, pipe2_flags_to_scap((int32_t)val), 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_eventfd_e(struct event_filler_arguments *args) {
	uint64_t initval;
	int res;

	/* Parameter 1: initval (type: PT_UINT64) */
	syscall_get_arguments_deprecated(args, 0, 1, &initval);
	res = val_to_ring(args, initval, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 2: flags (type: PT_UINT32) */
	/* The syscall eventfd has no flags! only `eventfd2` has the `flags` param.
	 * For compatibility with the event definition here we send `0` as flags.
	 */
	res = val_to_ring(args, 0, 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_eventfd_x(struct event_filler_arguments *args) {
	int64_t retval;
	uint64_t initval;
	int res;

	/* Parameter 1: res (type: PT_ERRNO) */
	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 2: initval (type: PT_UINT64) */
	syscall_get_arguments_deprecated(args, 0, 1, &initval);
	res = val_to_ring(args, initval, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 3: flags (type: PT_UINT32) */
	/* The syscall eventfd has no flags! only `eventfd2` has the `flags` param.
	 * For compatibility with the event definition here we send `0` as flags.
	 */
	res = val_to_ring(args, 0, 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_eventfd2_e(struct event_filler_arguments *args) {
	int res = 0;
	unsigned long val = 0;

	/* Parameter 1: initval (type: PT_UINT64) */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	res = val_to_ring(args, val, 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_eventfd2_x(struct event_filler_arguments *args) {
	int res = 0;
	unsigned long val = 0;
	long retval = 0;

	/* Parameter 1: res (type: PT_FD) */
	retval = (long)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 2: flags (type: PT_FLAGS16) */
	syscall_get_arguments_deprecated(args, 1, 1, &val);
	res = val_to_ring(args, eventfd2_flags_to_scap(val), 0, false, 0);
	CHECK_RES(res);

	/* Parameter 3: initval (type: PT_UINT64) */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	res = val_to_ring(args, val, 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_shutdown_e(struct event_filler_arguments *args) {
	int res;
	unsigned long val;
	int64_t fd;
	uint8_t how;

	/* Parameter 1: fd (type: PT_FD) */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	fd = (int64_t)(int32_t)val;
	res = val_to_ring(args, fd, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 2: how (type: PT_ENUMFLAGS8) */
	syscall_get_arguments_deprecated(args, 1, 1, &val);
	how = (uint8_t)val;
	res = val_to_ring(args, (unsigned long)shutdown_how_to_scap(how), 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_shutdown_x(struct event_filler_arguments *args) {
	int64_t retval;
	int res;
	unsigned long val;
	int64_t fd;
	uint8_t how;

	/* Parameter 1: res (type: PT_ERRNO) */
	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 2: fd (type: PT_FD) */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	fd = (int64_t)(int32_t)val;
	res = val_to_ring(args, fd, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 3: how (type: PT_ENUMFLAGS8) */
	syscall_get_arguments_deprecated(args, 1, 1, &val);
	how = (uint8_t)val;
	res = val_to_ring(args, (unsigned long)shutdown_how_to_scap(how), 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_futex_e(struct event_filler_arguments *args) {
	int res;
	unsigned long val;

	/* Parameter 1: addr (type: PT_UINT64) */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	res = val_to_ring(args, val, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 2: op (type: PT_ENUMFLAGS16) */
	syscall_get_arguments_deprecated(args, 1, 1, &val);
	res = val_to_ring(args, (unsigned long)futex_op_to_scap(val), 0, false, 0);
	CHECK_RES(res);

	/* Parameter 3: val (type: PT_UINT64) */
	syscall_get_arguments_deprecated(args, 2, 1, &val);
	res = val_to_ring(args, val, 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_futex_x(struct event_filler_arguments *args) {
	int64_t retval;
	int res;
	unsigned long val;

	/* Parameter 1: res (type: PT_ERRNO) */
	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 2: addr (type: PT_UINT64) */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	res = val_to_ring(args, val, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 3: op (type: PT_ENUMFLAGS16) */
	syscall_get_arguments_deprecated(args, 1, 1, &val);
	res = val_to_ring(args, (unsigned long)futex_op_to_scap(val), 0, false, 0);
	CHECK_RES(res);

	/* Parameter 4: val (type: PT_UINT64) */
	syscall_get_arguments_deprecated(args, 2, 1, &val);
	res = val_to_ring(args, val, 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_lseek_e(struct event_filler_arguments *args) {
	unsigned long val;
	int64_t fd;
	int res;

	/* Parameter 1: fd (type: PT_FD) */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	fd = (int64_t)(int32_t)val;
	res = val_to_ring(args, fd, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 2: offset (type: PT_UINT64) */
	syscall_get_arguments_deprecated(args, 1, 1, &val);
	res = val_to_ring(args, val, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 3: whence (type: PT_ENUMFLAGS8) */
	syscall_get_arguments_deprecated(args, 2, 1, &val);
	res = val_to_ring(args, lseek_whence_to_scap(val), 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_lseek_x(struct event_filler_arguments *args) {
	int64_t retval;
	int res;
	unsigned long val;
	int64_t fd;

	/* Parameter 1: res (type: PT_ERRNO) */
	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 2: fd (type: PT_FD) */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	fd = (int64_t)(int32_t)val;
	res = val_to_ring(args, fd, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 3: offset (type: PT_UINT64) */
	syscall_get_arguments_deprecated(args, 1, 1, &val);
	res = val_to_ring(args, val, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 4: whence (type: PT_ENUMFLAGS8) */
	syscall_get_arguments_deprecated(args, 2, 1, &val);
	res = val_to_ring(args, lseek_whence_to_scap(val), 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_llseek_e(struct event_filler_arguments *args) {
	unsigned long val;
	int res;
	unsigned long oh;
	unsigned long ol;
	uint64_t offset;
	int32_t fd;

	/* Parameter 1: fd (type: PT_FD) */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	fd = (int32_t)val;
	res = val_to_ring(args, (int64_t)fd, 0, false, 0);
	CHECK_RES(res);

	/*
	 * Parameter 2: offset (type: PT_UINT64)
	 * We build it by combining the offset_high and offset_low system call arguments
	 */
	syscall_get_arguments_deprecated(args, 1, 1, &oh);
	syscall_get_arguments_deprecated(args, 2, 1, &ol);
	offset = (((uint64_t)oh) << 32) + ((uint64_t)ol);
	res = val_to_ring(args, offset, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 3: whence (type: PT_ENUMFLAGS8) */
	syscall_get_arguments_deprecated(args, 4, 1, &val);
	res = val_to_ring(args, lseek_whence_to_scap(val), 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_llseek_x(struct event_filler_arguments *args) {
	int64_t retval;
	unsigned long val;
	int res;
	unsigned long oh;
	unsigned long ol;
	uint64_t offset;
	int32_t fd;

	/* Parameter 1: res (type: PT_ERRNO) */
	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 2: fd (type: PT_FD) */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	fd = (int32_t)val;
	res = val_to_ring(args, (int64_t)fd, 0, false, 0);
	CHECK_RES(res);

	/*
	 * Parameter 3: offset (type: PT_UINT64)
	 * We build it by combining the offset_high and offset_low system call arguments
	 */
	syscall_get_arguments_deprecated(args, 1, 1, &oh);
	syscall_get_arguments_deprecated(args, 2, 1, &ol);
	offset = (((uint64_t)oh) << 32) + ((uint64_t)ol);
	res = val_to_ring(args, offset, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 4: whence (type: PT_ENUMFLAGS8) */
	syscall_get_arguments_deprecated(args, 4, 1, &val);
	res = val_to_ring(args, lseek_whence_to_scap(val), 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

static int poll_parse_fds(struct event_filler_arguments *args, bool enter_event) {
	struct pollfd *fds;
	char *targetbuf;
	unsigned long val;
	unsigned long nfds;
	uint32_t j;
	uint32_t pos;
	uint16_t flags;

	/*
	 * fds
	 *
	 * Get the number of fds
	 */
	syscall_get_arguments_deprecated(args, 1, 1, &nfds);

	/*
	 * Check if we have enough space to store both the fd list
	 * from user space and the temporary buffer to serialize to the ring
	 */
	if(unlikely(sizeof(struct pollfd) * nfds + 2 + 10 * nfds > STR_STORAGE_SIZE))
		return PPM_FAILURE_BUFFER_FULL;

	/* Get the fds pointer */
	syscall_get_arguments_deprecated(args, 0, 1, &val);

	fds = (struct pollfd *)args->str_storage;

	/* We don't want to discard the whole event if the pointer is null.
	 * Setting `nfds = 0` we will just push to userspace the number of fds read,
	 * in this case `0`.
	 */
#ifdef CONFIG_COMPAT
	if(!args->compat) {
#endif
		if(unlikely(
		           ppm_copy_from_user(fds, (const void __user *)val, nfds * sizeof(struct pollfd))))
			nfds = 0;
#ifdef CONFIG_COMPAT
	} else {
		if(unlikely(ppm_copy_from_user(fds,
		                               (const void __user *)compat_ptr(val),
		                               nfds * sizeof(struct pollfd))))
			nfds = 0;
	}
#endif

	pos = 2;
	targetbuf = args->str_storage + nfds * sizeof(struct pollfd);

	/* Copy each fd into the temporary buffer */
	for(j = 0; j < nfds; j++) {
		if(enter_event) {
			flags = poll_events_to_scap(fds[j].events);
		} else {
			flags = poll_events_to_scap(fds[j].revents);
		}

		*(int64_t *)(targetbuf + pos) = (int64_t)fds[j].fd;
		*(int16_t *)(targetbuf + pos + 8) = flags;
		pos += 10;
	}

	*(uint16_t *)(targetbuf) = (uint16_t)nfds;

	return val_to_ring(args, (uint64_t)(unsigned long)targetbuf, pos, false, 0);
}

int f_sys_poll_e(struct event_filler_arguments *args) {
	unsigned long val;
	int res;

	/* Parameter 1: fds (type: PT_FDLIST) */
	res = poll_parse_fds(args, true);
	CHECK_RES(res);

	/* Parameter 2: timeout (type: PT_INT64) */
	syscall_get_arguments_deprecated(args, 2, 1, &val);
	res = val_to_ring(args, val, 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_poll_x(struct event_filler_arguments *args) {
	int64_t retval;
	unsigned long val;
	int res;

	/* Parameter 1: ret (type: PT_FD) */
	retval = (int64_t)(long)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 2: fds (type: PT_FDLIST) */
	res = poll_parse_fds(args, false);
	CHECK_RES(res);

	/* Parameter 3: timeout (type: PT_INT64) */
	syscall_get_arguments_deprecated(args, 2, 1, &val);
	res = val_to_ring(args, val, 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

static int timespec_parse(struct event_filler_arguments *args, unsigned long val) {
	uint64_t longtime = 0;
	int cfulen = 0;
	char *targetbuf = args->str_storage;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 18, 0)
	struct __kernel_timespec *tts = (struct __kernel_timespec *)targetbuf;
#else
	struct timespec *tts = (struct timespec *)targetbuf;
#endif

#ifdef CONFIG_COMPAT
	struct compat_timespec *compat_tts = (struct compat_timespec *)targetbuf;
#endif

	/*
	 * interval
	 * We copy the timespec structure and then convert it to a 64bit relative time
	 */
#ifdef CONFIG_COMPAT
	if(!args->compat) {
#endif
		cfulen = (int)ppm_copy_from_user(targetbuf, (void __user *)val, sizeof(*tts));
		if(likely(cfulen == 0)) {
			longtime = ((uint64_t)tts->tv_sec) * 1000000000 + tts->tv_nsec;
		}
#ifdef CONFIG_COMPAT
	} else {
		cfulen = (int)ppm_copy_from_user(targetbuf,
		                                 (void __user *)compat_ptr(val),
		                                 sizeof(struct compat_timespec));
		if(likely(cfulen == 0)) {
			longtime = ((uint64_t)compat_tts->tv_sec) * 1000000000 + compat_tts->tv_nsec;
		}
	}
#endif

	return val_to_ring(args, longtime, 0, false, 0);
}

int f_sys_ppoll_e(struct event_filler_arguments *args) {
	int res;
	unsigned long val;

	/* Parameter 1: fds (type: PT_FDLIST) */
	res = poll_parse_fds(args, true);
	CHECK_RES(res);

	/* Parameter 2: timeout (type: PT_RELTIME) */
	syscall_get_arguments_deprecated(args, 2, 1, &val);
	res = timespec_parse(args, val);
	CHECK_RES(res);

	/* Parameter 3: sigmask (type: PT_SIGSET) */
	syscall_get_arguments_deprecated(args, 3, 1, &val);
	if(val == (unsigned long)NULL || ppm_copy_from_user(&val, (void __user *)val, sizeof(val))) {
		val = 0;
	}
	res = val_to_ring(args, (uint32_t)val, 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_ppoll_x(struct event_filler_arguments *args) {
	int64_t retval;
	int res;
	unsigned long val;

	/* Parameter 1: res (type: PT_ERRNO) */
	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 2: fds (type: PT_FDLIST) */
	res = poll_parse_fds(args, false);
	CHECK_RES(res);

	/* Parameter 3: timeout (type: PT_RELTIME) */
	syscall_get_arguments_deprecated(args, 2, 1, &val);
	res = timespec_parse(args, val);
	CHECK_RES(res);

	/* Parameter 4: sigmask (type: PT_SIGSET) */
	syscall_get_arguments_deprecated(args, 3, 1, &val);
	if(val == (unsigned long)NULL || ppm_copy_from_user(&val, (void __user *)val, sizeof(val))) {
		val = 0;
	}
	res = val_to_ring(args, (uint32_t)val, 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_mount_e(struct event_filler_arguments *args) {
	unsigned long val;
	int res;

	/* Parameter 1: flags (type: PT_FLAGS32) */
	/*
	 * Fix mount flags in arg 3.
	 * See http://lxr.free-electrons.com/source/fs/namespace.c?v=4.2#L2650
	 */
	syscall_get_arguments_deprecated(args, 3, 1, &val);
	if((val & PPM_MS_MGC_MSK) == PPM_MS_MGC_VAL)
		val &= ~PPM_MS_MGC_MSK;
	res = val_to_ring(args, val, 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_mount_x(struct event_filler_arguments *args) {
	int64_t retval;
	unsigned long val;
	int res;

	/* Parameter 1: res (type: PT_ERRNO) */
	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 2: dev (type: PT_CHARBUF) */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	res = val_to_ring(args, val, 0, true, 0);
	CHECK_RES(res);

	/* Parameter 3: dir (type: PT_FSPATH) */
	syscall_get_arguments_deprecated(args, 1, 1, &val);
	res = val_to_ring(args, val, 0, true, 0);
	CHECK_RES(res);

	/* Parameter 4: type (type: PT_CHARBUF) */
	syscall_get_arguments_deprecated(args, 2, 1, &val);
	res = val_to_ring(args, val, 0, true, 0);
	CHECK_RES(res);

	/* Parameter 5: flags (type: PT_FLAGS32) */
	/*
	 * Fix mount flags in arg 3.
	 * See http://lxr.free-electrons.com/source/fs/namespace.c?v=4.2#L2650
	 */
	syscall_get_arguments_deprecated(args, 3, 1, &val);
	if((val & PPM_MS_MGC_MSK) == PPM_MS_MGC_VAL)
		val &= ~PPM_MS_MGC_MSK;
	res = val_to_ring(args, val, 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_openat_e(struct event_filler_arguments *args) {
	unsigned long val;
	unsigned long flags;
	unsigned long modes;
	int32_t fd;
	int res;

	/*
	 * dirfd
	 */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	fd = (int32_t)val;
	if(fd == AT_FDCWD)
		fd = PPM_AT_FDCWD;

	res = val_to_ring(args, (int64_t)fd, 0, false, 0);
	CHECK_RES(res);

	/*
	 * name
	 */
	syscall_get_arguments_deprecated(args, 1, 1, &val);
	res = val_to_ring(args, val, 0, true, 0);
	CHECK_RES(res);
	/*
	 * Flags
	 * Note that we convert them into the ppm portable representation before pushing them to the
	 * ring
	 */
	syscall_get_arguments_deprecated(args, 2, 1, &flags);
	res = val_to_ring(args, open_flags_to_scap(flags), 0, false, 0);
	CHECK_RES(res);

	/*
	 *  mode
	 */
	syscall_get_arguments_deprecated(args, 3, 1, &modes);
	res = val_to_ring(args, open_modes_to_scap(flags, modes), 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_openat_x(struct event_filler_arguments *args) {
	unsigned long val;
	unsigned long flags;
	unsigned long scap_flags;
	unsigned long modes;

	uint32_t dev = 0;
	uint64_t ino = 0;
	int res;
	int32_t fd;
	int64_t retval;
	enum ppm_overlay ol = PPM_NOT_OVERLAY_FS;

	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	CHECK_RES(res);

	/*
	 * dirfd
	 */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	fd = (int32_t)val;
	if(fd == AT_FDCWD)
		fd = PPM_AT_FDCWD;

	res = val_to_ring(args, (int64_t)fd, 0, false, 0);
	CHECK_RES(res);

	/*
	 * name
	 */
	syscall_get_arguments_deprecated(args, 1, 1, &val);
	res = val_to_ring(args, val, 0, true, 0);
	CHECK_RES(res);

	get_dev_ino_overlay_from_fd(retval, &dev, &ino, &ol);
	/*
	 * Flags
	 * Note that we convert them into the ppm portable representation before pushing them to the
	 * ring
	 */
	syscall_get_arguments_deprecated(args, 2, 1, &flags);
	scap_flags = open_flags_to_scap(flags);
	/* update scap flags if file is created */
	get_fd_fmode_created(retval, &scap_flags);
	if(ol == PPM_OVERLAY_UPPER) {
		scap_flags |= PPM_FD_UPPER_LAYER;
	} else if(ol == PPM_OVERLAY_LOWER) {
		scap_flags |= PPM_FD_LOWER_LAYER;
	}
	res = val_to_ring(args, scap_flags, 0, false, 0);
	CHECK_RES(res);
	/*
	 *  mode
	 */
	syscall_get_arguments_deprecated(args, 3, 1, &modes);
	res = val_to_ring(args, open_modes_to_scap(flags, modes), 0, false, 0);
	CHECK_RES(res);

	/*
	 *  dev
	 */
	res = val_to_ring(args, dev, 0, false, 0);
	CHECK_RES(res);
	/*
	 *  ino
	 */
	res = val_to_ring(args, ino, 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_unlinkat_x(struct event_filler_arguments *args) {
	unsigned long val = 0;
	int res = 0;
	long retval = 0;
	int32_t dirfd = 0;

	/* Parameter 1: res (type: PT_ERRNO) */
	retval = syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 2: dirfd (type: PT_FD) */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	dirfd = (int32_t)val;
	if(dirfd == AT_FDCWD) {
		dirfd = PPM_AT_FDCWD;
	}
	res = val_to_ring(args, (int64_t)dirfd, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 3: path (type: PT_FSRELPATH) */
	syscall_get_arguments_deprecated(args, 1, 1, &val);
	res = val_to_ring(args, val, 0, true, 0);
	CHECK_RES(res);

	/* Parameter 4: flags (type: PT_FLAGS32) */
	syscall_get_arguments_deprecated(args, 2, 1, &val);
	res = val_to_ring(args, unlinkat_flags_to_scap((int32_t)val), 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_linkat_x(struct event_filler_arguments *args) {
	unsigned long val;
	unsigned long flags;
	int res;
	int64_t retval;

	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	CHECK_RES(res);

	/*
	 * olddir
	 */
	syscall_get_arguments_deprecated(args, 0, 1, &val);

	if((int)val == AT_FDCWD)
		val = PPM_AT_FDCWD;

	res = val_to_ring(args, val, 0, false, 0);
	CHECK_RES(res);

	/*
	 * oldpath
	 */
	syscall_get_arguments_deprecated(args, 1, 1, &val);
	res = val_to_ring(args, val, 0, true, 0);
	CHECK_RES(res);

	/*
	 * newdir
	 */
	syscall_get_arguments_deprecated(args, 2, 1, &val);

	if((int)val == AT_FDCWD)
		val = PPM_AT_FDCWD;

	res = val_to_ring(args, val, 0, false, 0);
	CHECK_RES(res);

	/*
	 * newpath
	 */
	syscall_get_arguments_deprecated(args, 3, 1, &val);
	res = val_to_ring(args, val, 0, true, 0);
	CHECK_RES(res);

	/*
	 * Flags
	 * Note that we convert them into the ppm portable representation before pushing them to the
	 * ring
	 */
	syscall_get_arguments_deprecated(args, 4, 1, &flags);
	res = val_to_ring(args, linkat_flags_to_scap((int32_t)flags), 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_pread64_e(struct event_filler_arguments *args) {
	unsigned long val;
	unsigned long size;
	int res;
	unsigned long pos64;
	int32_t fd;

	/*
	 * fd
	 */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	fd = (int32_t)val;
	res = val_to_ring(args, (int64_t)fd, 0, false, 0);
	CHECK_RES(res);

	/*
	 * size
	 */
	syscall_get_arguments_deprecated(args, 2, 1, &size);
	res = val_to_ring(args, size, 0, false, 0);
	CHECK_RES(res);

	/*
	 * pos
	 */
#ifndef CAPTURE_64BIT_ARGS_SINGLE_REGISTER
	{
		unsigned long pos0;
		unsigned long pos1;
#if defined CONFIG_X86
		syscall_get_arguments_deprecated(args, 3, 1, &pos0);
		syscall_get_arguments_deprecated(args, 4, 1, &pos1);
#elif defined CONFIG_ARM && CONFIG_AEABI
		syscall_get_arguments_deprecated(args, 4, 1, &pos0);
		syscall_get_arguments_deprecated(args, 5, 1, &pos1);
#else
#error This architecture/abi not yet supported
#endif

		pos64 = merge_64(pos1, pos0);
	}
#else
	syscall_get_arguments_deprecated(args, 3, 1, &pos64);
#endif

	res = val_to_ring(args, pos64, 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_pread64_x(struct event_filler_arguments *args) {
	unsigned long val;
	int res;
	int64_t retval;
	unsigned long pos64;

	// Retrieve the FD. It will be used for dynamic snaplen calculation.
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	args->fd = (int)val;

	/* Parameter 1: res (type: PT_ERRNO) */
	retval = (int64_t)(long)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 2: data (type: PT_BYTEBUF) */
	if(retval > 0) {
		// val now contains the pointer to the buffer
		syscall_get_arguments_deprecated(args, 1, 1, &val);
		args->enforce_snaplen = true;
		res = val_to_ring(args, val, retval, true, 0);
	} else {
		res = push_empty_param(args);
	}
	CHECK_RES(res);

	/* Parameter 3: fd (type: PT_FD) */
	res = val_to_ring(args, (int64_t)args->fd, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 4: size (type: PT_UINT32) */
	syscall_get_arguments_deprecated(args, 2, 1, &val);
	res = val_to_ring(args, val, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 5: pos (type: PT_UINT64) */
#ifndef CAPTURE_64BIT_ARGS_SINGLE_REGISTER
	{
		unsigned long pos0;
		unsigned long pos1;
#if defined CONFIG_X86
		syscall_get_arguments_deprecated(args, 3, 1, &pos0);
		syscall_get_arguments_deprecated(args, 4, 1, &pos1);
#elif defined CONFIG_ARM && CONFIG_AEABI
		syscall_get_arguments_deprecated(args, 4, 1, &pos0);
		syscall_get_arguments_deprecated(args, 5, 1, &pos1);
#else
#error This architecture/abi not yet supported
#endif

		pos64 = merge_64(pos1, pos0);
	}
#else
	syscall_get_arguments_deprecated(args, 3, 1, &pos64);
#endif

	res = val_to_ring(args, pos64, 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_pwrite64_e(struct event_filler_arguments *args) {
	unsigned long val;
	unsigned long size;
	int res;
	unsigned long pos64;
	int32_t fd = 0;

	/*
	 * fd
	 */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	fd = (int32_t)val;
	res = val_to_ring(args, (int64_t)fd, 0, false, 0);
	CHECK_RES(res);

	/*
	 * size
	 */
	syscall_get_arguments_deprecated(args, 2, 1, &size);
	res = val_to_ring(args, size, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 3: pos (type: PT_UINT64) */
#ifndef CAPTURE_64BIT_ARGS_SINGLE_REGISTER
	{
		unsigned long pos0 = 0;
		unsigned long pos1 = 0;
#if defined CONFIG_X86
		syscall_get_arguments_deprecated(args, 3, 1, &pos0);
		syscall_get_arguments_deprecated(args, 4, 1, &pos1);
#elif defined CONFIG_ARM && CONFIG_AEABI
		syscall_get_arguments_deprecated(args, 4, 1, &pos0);
		syscall_get_arguments_deprecated(args, 5, 1, &pos1);
#else
#error This architecture/abi not yet supported
#endif
		pos64 = merge_64(pos1, pos0);
	}
#else
	syscall_get_arguments_deprecated(args, 3, 1, &pos64);
#endif /* CAPTURE_64BIT_ARGS_SINGLE_REGISTER*/

	res = val_to_ring(args, pos64, 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_pwrite64_x(struct event_filler_arguments *args) {
	unsigned long val;
	int res;
	int64_t retval;
	unsigned long bufsize;
	size_t size = 0;
	unsigned long pos64 = 0;

	/*
	 * Retrieve the FD. It will be used for dynamic snaplen calculation.
	 */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	args->fd = (int)val;

	/* Parameter 1: res (type: PT_ERRNO) */
	retval = (int64_t)(long)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 2: data (type: PT_BYTEBUF) */
	/* Get the size from userspace paramater */
	syscall_get_arguments_deprecated(args, 2, 1, &size);
	bufsize = retval > 0 ? retval : size;
	syscall_get_arguments_deprecated(args, 1, 1, &val);
	args->enforce_snaplen = true;
	res = val_to_ring(args, val, bufsize, true, 0);
	CHECK_RES(res);

	/* Parameter 3: fd (type: PT_FD) */
	res = val_to_ring(args, (int64_t)args->fd, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 4: size (type: PT_UINT32) */
	res = val_to_ring(args, (uint32_t)size, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 5: pos (type: PT_UINT64) */
#ifndef CAPTURE_64BIT_ARGS_SINGLE_REGISTER
	{
		unsigned long pos0 = 0;
		unsigned long pos1 = 0;
#if defined CONFIG_X86
		syscall_get_arguments_deprecated(args, 3, 1, &pos0);
		syscall_get_arguments_deprecated(args, 4, 1, &pos1);
#elif defined CONFIG_ARM && CONFIG_AEABI
		syscall_get_arguments_deprecated(args, 4, 1, &pos0);
		syscall_get_arguments_deprecated(args, 5, 1, &pos1);
#else
#error This architecture/abi not yet supported
#endif
		pos64 = merge_64(pos1, pos0);
	}
#else
	syscall_get_arguments_deprecated(args, 3, 1, &pos64);
#endif /* CAPTURE_64BIT_ARGS_SINGLE_REGISTER*/

	res = val_to_ring(args, pos64, 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_preadv_e(struct event_filler_arguments *args) {
	unsigned long val;
	int64_t fd;
	int res;
	unsigned long pos64;

	/* Parameter 1: fd (type: PT_FD) */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	fd = (int64_t)(int32_t)val;
	res = val_to_ring(args, fd, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 2: pos (type: PT_UINT64) */
#ifndef CAPTURE_64BIT_ARGS_SINGLE_REGISTER
	{
		unsigned long pos0;
		unsigned long pos1;
		/*
		 * Note that in preadv and pwritev have NO 64-bit arguments in the
		 * syscall (despite having one in the userspace API), so no alignment
		 * requirements apply here. For an overly-detailed discussion about
		 * this, see https://lwn.net/Articles/311630/
		 */
		syscall_get_arguments_deprecated(args, 3, 1, &pos0);
		syscall_get_arguments_deprecated(args, 4, 1, &pos1);

		pos64 = merge_64(pos1, pos0);
	}
#else
	syscall_get_arguments_deprecated(args, 3, 1, &pos64);
#endif

	res = val_to_ring(args, pos64, 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_preadv_x(struct event_filler_arguments *args) {
	unsigned long val;
	int64_t retval;
	int res;
	unsigned long iovcnt;
	int64_t fd;
	unsigned long pos64;

	/* Parameter 1: res (type: PT_ERRNO) */
	retval = (int64_t)(long)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	CHECK_RES(res);

	if(retval > 0) {
		syscall_get_arguments_deprecated(args, 1, 1, &val);
		syscall_get_arguments_deprecated(args, 2, 1, &iovcnt);

		/* Parameter 2: size (type: PT_UINT32) */
		/* Parameter 3: data (type: PT_BYTEBUF) */
#ifdef CONFIG_COMPAT
		if(unlikely(args->compat)) {
			const struct compat_iovec __user *compat_iov =
			        (const struct compat_iovec __user *)compat_ptr(val);
			res = compat_parse_readv_writev_bufs(args,
			                                     compat_iov,
			                                     iovcnt,
			                                     retval,
			                                     PRB_FLAG_PUSH_ALL);
		} else
#endif
		{
			const struct iovec __user *iov = (const struct iovec __user *)val;
			res = parse_readv_writev_bufs(args, iov, iovcnt, retval, PRB_FLAG_PUSH_ALL);
		}

		CHECK_RES(res);
	} else {
		/* Parameter 2: size (type: PT_UINT32) */
		res = val_to_ring(args, 0, 0, false, 0);
		CHECK_RES(res);

		/* Parameter 3: data (type: PT_BYTEBUF) */
		res = push_empty_param(args);
		CHECK_RES(res);
	}

	/* Parameter 4: fd (type: PT_FD) */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	fd = (int64_t)(int32_t)val;
	res = val_to_ring(args, fd, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 5: pos (type: PT_UINT64) */
#ifndef CAPTURE_64BIT_ARGS_SINGLE_REGISTER
	{
		unsigned long pos0;
		unsigned long pos1;
		/*
		 * Note that in preadv and pwritev have NO 64-bit arguments in the
		 * syscall (despite having one in the userspace API), so no alignment
		 * requirements apply here. For an overly-detailed discussion about
		 * this, see https://lwn.net/Articles/311630/
		 */
		syscall_get_arguments_deprecated(args, 3, 1, &pos0);
		syscall_get_arguments_deprecated(args, 4, 1, &pos1);

		pos64 = merge_64(pos1, pos0);
	}
#else
	syscall_get_arguments_deprecated(args, 3, 1, &pos64);
#endif

	res = val_to_ring(args, pos64, 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_readv_e(struct event_filler_arguments *args) {
	unsigned long val;
	int64_t fd;
	int res;

	/* Parameter 1: fd (type: PT_FD) */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	fd = (int64_t)(int32_t)val;
	res = val_to_ring(args, fd, 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_readv_x(struct event_filler_arguments *args) {
	unsigned long val;
	int64_t retval;
	int res;
	unsigned long iovcnt;
	int64_t fd;

	/* Parameter 1: res (type: PT_ERRNO) */
	retval = (int64_t)(long)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	CHECK_RES(res);

	if(retval > 0) {
		syscall_get_arguments_deprecated(args, 1, 1, &val);
		syscall_get_arguments_deprecated(args, 2, 1, &iovcnt);

		/* Parameter 2: size (type: PT_UINT32) */
		/* Parameter 3: data (type: PT_BYTEBUF) */
#ifdef CONFIG_COMPAT
		if(unlikely(args->compat)) {
			const struct compat_iovec __user *compat_iov =
			        (const struct compat_iovec __user *)compat_ptr(val);
			res = compat_parse_readv_writev_bufs(args,
			                                     compat_iov,
			                                     iovcnt,
			                                     retval,
			                                     PRB_FLAG_PUSH_ALL);
		} else
#endif
		{
			const struct iovec __user *iov = (const struct iovec __user *)val;
			res = parse_readv_writev_bufs(args, iov, iovcnt, retval, PRB_FLAG_PUSH_ALL);
		}

		CHECK_RES(res);
	} else {
		/* Parameter 2: size (type: PT_UINT32) */
		res = val_to_ring(args, 0, 0, false, 0);
		CHECK_RES(res);

		/* Parameter 3: data (type: PT_BYTEBUF) */
		res = push_empty_param(args);
		CHECK_RES(res);
	}

	/* Parameter 4: fd (type: PT_FD) */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	fd = (int64_t)(int32_t)val;
	res = val_to_ring(args, fd, 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_writev_e(struct event_filler_arguments *args) {
	unsigned long val;
	int res;
	int64_t fd;
	unsigned long iov_pointer, iov_cnt;

	/* Parameter 1: fd (type: PT_FD) */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	fd = (int64_t)(int32_t)val;
	res = val_to_ring(args, fd, 0, false, 0);
	CHECK_RES(res);

	/* Get iovecs pointer and count. */
	syscall_get_arguments_deprecated(args, 1, 1, &iov_pointer);
	syscall_get_arguments_deprecated(args, 2, 1, &iov_cnt);

	/* Parameter 2: size (type: PT_UINT32) */
#ifdef CONFIG_COMPAT
	if(unlikely(args->compat)) {
		const struct compat_iovec __user *compat_iov =
		        (const struct compat_iovec __user *)compat_ptr(iov_pointer);
		res = compat_parse_readv_writev_bufs(args,
		                                     compat_iov,
		                                     iov_cnt,
		                                     args->consumer->snaplen,
		                                     PRB_FLAG_PUSH_SIZE | PRB_FLAG_IS_WRITE);
	} else
#endif
	{
		const struct iovec __user *iov = (const struct iovec __user *)iov_pointer;
		res = parse_readv_writev_bufs(args,
		                              iov,
		                              iov_cnt,
		                              args->consumer->snaplen,
		                              PRB_FLAG_PUSH_SIZE | PRB_FLAG_IS_WRITE);
	}

	/* If there was an error we send a size equal to `0`.
	 * We can improve this in the future but at least we don't lose the whole event. */
	if(res == PPM_FAILURE_INVALID_USER_MEMORY) {
		res = val_to_ring(args, 0, 0, true, 0);
	}
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_writev_x(struct event_filler_arguments *args) {
	unsigned long val;
	int res;
	int64_t retval;
	unsigned long iov_pointer, iov_cnt;
	int64_t fd;

	/* Parameter 1: res (type: PT_ERRNO) */
	retval = (int64_t)(long)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	CHECK_RES(res);

	/* Get iovecs pointer and count. */
	syscall_get_arguments_deprecated(args, 1, 1, &iov_pointer);
	syscall_get_arguments_deprecated(args, 2, 1, &iov_cnt);

	/* Parameter 2: data (type: PT_BYTEBUF) */
#ifdef CONFIG_COMPAT
	if(unlikely(args->compat)) {
		const struct compat_iovec __user *compat_iov =
		        (const struct compat_iovec __user *)compat_ptr(iov_pointer);
		res = compat_parse_readv_writev_bufs(args,
		                                     compat_iov,
		                                     iov_cnt,
		                                     args->consumer->snaplen,
		                                     PRB_FLAG_PUSH_DATA | PRB_FLAG_IS_WRITE);
	} else
#endif
	{
		const struct iovec __user *iov = (const struct iovec __user *)iov_pointer;
		res = parse_readv_writev_bufs(args,
		                              iov,
		                              iov_cnt,
		                              args->consumer->snaplen,
		                              PRB_FLAG_PUSH_DATA | PRB_FLAG_IS_WRITE);
	}

	/* If there was an error we send an empty param.
	 * We can improve this in the future but at least we don't lose the whole event. */
	if(res == PPM_FAILURE_INVALID_USER_MEMORY) {
		res = push_empty_param(args);
	}
	CHECK_RES(res);

	/* Parameter 3: fd (type: PT_FD) */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	fd = (int64_t)(int32_t)val;
	res = val_to_ring(args, fd, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 4: size (type: PT_UINT32) */
#ifdef CONFIG_COMPAT
	if(unlikely(args->compat)) {
		const struct compat_iovec __user *compat_iov =
		        (const struct compat_iovec __user *)compat_ptr(iov_pointer);
		res = compat_parse_readv_writev_bufs(args,
		                                     compat_iov,
		                                     iov_cnt,
		                                     args->consumer->snaplen,
		                                     PRB_FLAG_PUSH_SIZE | PRB_FLAG_IS_WRITE);
	} else
#endif
	{
		const struct iovec __user *iov = (const struct iovec __user *)iov_pointer;
		res = parse_readv_writev_bufs(args,
		                              iov,
		                              iov_cnt,
		                              args->consumer->snaplen,
		                              PRB_FLAG_PUSH_SIZE | PRB_FLAG_IS_WRITE);
	}

	/* If there was an error we send a size equal to `0`.
	 * We can improve this in the future but at least we don't lose the whole event. */
	if(res == PPM_FAILURE_INVALID_USER_MEMORY) {
		res = val_to_ring(args, 0, 0, true, 0);
	}
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_pwritev_e(struct event_filler_arguments *args) {
	unsigned long val;
	int res;
	unsigned long pos64;
	int64_t fd;
	unsigned long iov_pointer, iov_cnt;

	/* Parameter 1: fd (type: PT_FD) */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	fd = (int64_t)(int32_t)val;
	res = val_to_ring(args, fd, 0, false, 0);
	CHECK_RES(res);

	/* Get iovecs pointer and count. */
	syscall_get_arguments_deprecated(args, 1, 1, &iov_pointer);
	syscall_get_arguments_deprecated(args, 2, 1, &iov_cnt);

	/* Parameter 2: size (type: PT_UINT32) */
#ifdef CONFIG_COMPAT
	if(unlikely(args->compat)) {
		const struct compat_iovec __user *compat_iov =
		        (const struct compat_iovec __user *)compat_ptr(iov_pointer);
		res = compat_parse_readv_writev_bufs(args,
		                                     compat_iov,
		                                     iov_cnt,
		                                     args->consumer->snaplen,
		                                     PRB_FLAG_PUSH_SIZE | PRB_FLAG_IS_WRITE);
	} else
#endif
	{
		const struct iovec __user *iov = (const struct iovec __user *)iov_pointer;
		res = parse_readv_writev_bufs(args,
		                              iov,
		                              iov_cnt,
		                              args->consumer->snaplen,
		                              PRB_FLAG_PUSH_SIZE | PRB_FLAG_IS_WRITE);
	}

	/* If there was an error we send a size equal to 0.
	 * We can improve this in the future but at least we don't lose the whole event. */
	if(res == PPM_FAILURE_INVALID_USER_MEMORY) {
		res = val_to_ring(args, 0, 0, true, 0);
	}
	CHECK_RES(res);

	/* Parameter 3: pos (type: PT_UINT64) */
#ifndef CAPTURE_64BIT_ARGS_SINGLE_REGISTER
	{
		unsigned long pos0 = 0;
		unsigned long pos1 = 0;
		/*
		 * Note that in preadv and pwritev have NO 64-bit arguments in the
		 * syscall (despite having one in the userspace API), so no alignment
		 * requirements apply here. For an overly-detailed discussion about
		 * this, see https://lwn.net/Articles/311630/
		 */
		syscall_get_arguments_deprecated(args, 3, 1, &pos0);
		syscall_get_arguments_deprecated(args, 4, 1, &pos1);

		pos64 = merge_64(pos1, pos0);
	}
#else
	syscall_get_arguments_deprecated(args, 3, 1, &pos64);
#endif /* CAPTURE_64BIT_ARGS_SINGLE_REGISTER */

	res = val_to_ring(args, pos64, 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_pwritev_x(struct event_filler_arguments *args) {
	unsigned long val;
	int res;
	int64_t retval;
	unsigned long iov_pointer, iov_cnt;
	int64_t fd;
	unsigned long pos64;

	/* Parameter 1: res (type: PT_ERRNO) */
	retval = (int64_t)(long)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	CHECK_RES(res);

	/* Get iovecs pointer and count. */
	syscall_get_arguments_deprecated(args, 1, 1, &iov_pointer);
	syscall_get_arguments_deprecated(args, 2, 1, &iov_cnt);

	/* Parameter 2: data (type: PT_BYTEBUF) */
#ifdef CONFIG_COMPAT
	if(unlikely(args->compat)) {
		const struct compat_iovec __user *compat_iov =
		        (const struct compat_iovec __user *)compat_ptr(iov_pointer);
		res = compat_parse_readv_writev_bufs(args,
		                                     compat_iov,
		                                     iov_cnt,
		                                     args->consumer->snaplen,
		                                     PRB_FLAG_PUSH_DATA | PRB_FLAG_IS_WRITE);
	} else
#endif
	{
		const struct iovec __user *iov = (const struct iovec __user *)iov_pointer;
		res = parse_readv_writev_bufs(args,
		                              iov,
		                              iov_cnt,
		                              args->consumer->snaplen,
		                              PRB_FLAG_PUSH_DATA | PRB_FLAG_IS_WRITE);
	}

	/* If there was an error we send an empty param.
	 * We can improve this in the future but at least we don't lose the whole event. */
	if(res == PPM_FAILURE_INVALID_USER_MEMORY) {
		res = push_empty_param(args);
	}
	CHECK_RES(res);

	/* Parameter 3: fd (type: PT_FD) */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	fd = (int64_t)(int32_t)val;
	res = val_to_ring(args, fd, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 4: size (type: PT_UINT32) */
#ifdef CONFIG_COMPAT
	if(unlikely(args->compat)) {
		const struct compat_iovec __user *compat_iov =
		        (const struct compat_iovec __user *)compat_ptr(iov_pointer);
		res = compat_parse_readv_writev_bufs(args,
		                                     compat_iov,
		                                     iov_cnt,
		                                     args->consumer->snaplen,
		                                     PRB_FLAG_PUSH_SIZE | PRB_FLAG_IS_WRITE);
	} else
#endif
	{
		const struct iovec __user *iov = (const struct iovec __user *)iov_pointer;
		res = parse_readv_writev_bufs(args,
		                              iov,
		                              iov_cnt,
		                              args->consumer->snaplen,
		                              PRB_FLAG_PUSH_SIZE | PRB_FLAG_IS_WRITE);
	}

	/* If there was an error we send a size equal to `0`.
	 * We can improve this in the future but at least we don't lose the whole event. */
	if(res == PPM_FAILURE_INVALID_USER_MEMORY) {
		res = val_to_ring(args, 0, 0, false, 0);
	}
	CHECK_RES(res);

	/* Parameter 5: pos (type: PT_UINT64) */
#ifndef CAPTURE_64BIT_ARGS_SINGLE_REGISTER
	{
		unsigned long pos0 = 0;
		unsigned long pos1 = 0;
		/*
		 * Note that in preadv and pwritev have NO 64-bit arguments in the
		 * syscall (despite having one in the userspace API), so no alignment
		 * requirements apply here. For an overly-detailed discussion about
		 * this, see https://lwn.net/Articles/311630/
		 */
		syscall_get_arguments_deprecated(args, 3, 1, &pos0);
		syscall_get_arguments_deprecated(args, 4, 1, &pos1);

		pos64 = merge_64(pos1, pos0);
	}
#else
	syscall_get_arguments_deprecated(args, 3, 1, &pos64);
#endif /* CAPTURE_64BIT_ARGS_SINGLE_REGISTER */

	res = val_to_ring(args, pos64, 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_nanosleep_e(struct event_filler_arguments *args) {
	unsigned long val;
	int res;

	/* Parameter 1: interval (type: PT_RELTIME) */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	res = timespec_parse(args, val);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_nanosleep_x(struct event_filler_arguments *args) {
	int64_t retval;
	int res;
	unsigned long val;

	/* Parameter 1: res (type: PT_ERRNO) */
	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 2: interval (type: PT_RELTIME) */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	res = timespec_parse(args, val);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_getrlimit_setrlimit_e(struct event_filler_arguments *args) {
	uint8_t ppm_resource;
	unsigned long val;
	int res;

	/* Parameter 1: resource (type: PT_ENUMFLAGS8) */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	ppm_resource = rlimit_resource_to_scap((uint32_t)val);
	res = val_to_ring(args, (uint64_t)ppm_resource, 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_getrlimit_x(struct event_filler_arguments *args) {
	unsigned long val;
	int res;
	int64_t retval;
	struct rlimit rl = {0};
#ifdef CONFIG_COMPAT
	struct compat_rlimit compat_rl = {0};
#endif
	int64_t cur;
	int64_t max;
	uint8_t ppm_resource;

	/* Parameter 1: res (type: PT_ERRNO) */
	retval = (int64_t)(long)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	CHECK_RES(res);

	/*
	 * Copy the user structure and extract cur and max
	 */
	if(retval == 0) {
		syscall_get_arguments_deprecated(args, 1, 1, &val);

#ifdef CONFIG_COMPAT
		if(!args->compat) {
#endif
			if(unlikely(ppm_copy_from_user(&rl, (const void __user *)val, sizeof(struct rlimit)))) {
				cur = 0;
				max = 0;
			} else {
				cur = rl.rlim_cur;
				max = rl.rlim_max;
			}
#ifdef CONFIG_COMPAT
		} else {
			if(unlikely(ppm_copy_from_user(&compat_rl,
			                               (const void __user *)compat_ptr(val),
			                               sizeof(struct compat_rlimit)))) {
				cur = 0;
				max = 0;
			} else {
				cur = compat_rl.rlim_cur;
				max = compat_rl.rlim_max;
			}
		}
#endif
	} else {
		cur = -1;
		max = -1;
	}

	/* Parameter 2: cur (type: PT_INT64) */
	res = val_to_ring(args, cur, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 3: max (type: PT_INT64)*/
	res = val_to_ring(args, max, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 4: resource (type: PT_ENUMFLAGS8) */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	ppm_resource = rlimit_resource_to_scap((uint32_t)val);
	res = val_to_ring(args, (uint64_t)ppm_resource, 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_setrlimit_x(struct event_filler_arguments *args) {
	unsigned long val;
	int res;
	int64_t retval;
#ifdef CONFIG_COMPAT
	struct compat_rlimit compat_rl = {0};
#endif
	int64_t cur;
	int64_t max;
	struct rlimit rl = {0};

	/* Parameter 1: res (type: PT_ERRNO) */
	retval = (int64_t)(long)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	CHECK_RES(res);

	/*
	 * Copy the user structure and extract cur and max
	 */
	syscall_get_arguments_deprecated(args, 1, 1, &val);

#ifdef CONFIG_COMPAT
	if(!args->compat) {
#endif
		ppm_copy_from_user(&rl, (const void __user *)val, sizeof(struct rlimit));
		cur = rl.rlim_cur;
		max = rl.rlim_max;
#ifdef CONFIG_COMPAT
	} else {
		ppm_copy_from_user(&compat_rl,
		                   (const void __user *)compat_ptr(val),
		                   sizeof(struct compat_rlimit));
		cur = compat_rl.rlim_cur;
		max = compat_rl.rlim_max;
	}
#endif

	/* Parameter 2: cur (type: PT_INT64) */
	res = val_to_ring(args, cur, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 3: max (type: PT_INT64) */
	res = val_to_ring(args, max, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 4: resource (type: PT_ENUMFLAGS8) */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	res = val_to_ring(args, rlimit_resource_to_scap((uint32_t)val), 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_prlimit_e(struct event_filler_arguments *args) {
	unsigned long val = 0;
	int res = 0;
	pid_t pid = 0;

	/* Parameter 1: pid (type: PT_PID) */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	pid = (int32_t)val;
	res = val_to_ring(args, (int64_t)pid, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 2: resource (type: PT_ENUMFLAGS8) */
	syscall_get_arguments_deprecated(args, 1, 1, &val);
	res = val_to_ring(args, rlimit_resource_to_scap((uint32_t)val), 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_prlimit_x(struct event_filler_arguments *args) {
	unsigned long val;
	int res;
	int64_t retval;
	struct rlimit rl = {0};
#ifdef CONFIG_COMPAT
	struct compat_rlimit compat_rl = {0};
#endif
	int64_t newcur;
	int64_t newmax;
	int64_t oldcur;
	int64_t oldmax;
	pid_t pid = 0;

	/* Parameter 1: res (type: PT_ERRNO) */
	retval = (int64_t)(long)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	CHECK_RES(res);

	/*
	 * Copy the user structure and extract cur and max
	 */
	syscall_get_arguments_deprecated(args, 2, 1, &val);
#ifdef CONFIG_COMPAT
	if(!args->compat) {
#endif
		ppm_copy_from_user(&rl, (const void __user *)val, sizeof(struct rlimit));
		newcur = rl.rlim_cur;
		newmax = rl.rlim_max;
#ifdef CONFIG_COMPAT
	} else {
		ppm_copy_from_user(&compat_rl, (const void __user *)val, sizeof(struct compat_rlimit));
		newcur = compat_rl.rlim_cur;
		newmax = compat_rl.rlim_max;
	}
#endif

	/* Parameter 2: newcur (type: PT_INT64) */
	res = val_to_ring(args, newcur, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 3: newmax (type: PT_INT64) */
	res = val_to_ring(args, newmax, 0, false, 0);
	CHECK_RES(res);

	if(retval == 0) {
		syscall_get_arguments_deprecated(args, 3, 1, &val);

#ifdef CONFIG_COMPAT
		if(!args->compat) {
#endif
			if(unlikely(ppm_copy_from_user(&rl, (const void __user *)val, sizeof(struct rlimit)))) {
				oldcur = 0;
				oldmax = 0;
			} else {
				oldcur = rl.rlim_cur;
				oldmax = rl.rlim_max;
			}
#ifdef CONFIG_COMPAT
		} else {
			if(unlikely(ppm_copy_from_user(&compat_rl,
			                               (const void __user *)val,
			                               sizeof(struct compat_rlimit)))) {
				oldcur = 0;
				oldmax = 0;
			} else {
				oldcur = compat_rl.rlim_cur;
				oldmax = compat_rl.rlim_max;
			}
		}
#endif
	} else {
		oldcur = -1;
		oldmax = -1;
	}

	/* Parameter 4: oldcur (type: PT_INT64) */
	res = val_to_ring(args, oldcur, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 5: oldmax (type: PT_INT64) */
	res = val_to_ring(args, oldmax, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 6: pid (type: PT_PID) */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	pid = (s32)val;
	res = val_to_ring(args, (s64)pid, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 7: resource (type: PT_ENUMFLAGS8) */
	syscall_get_arguments_deprecated(args, 1, 1, &val);
	res = val_to_ring(args, rlimit_resource_to_scap((uint32_t)val), 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

#ifdef CAPTURE_CONTEXT_SWITCHES

int f_sched_switch_e(struct event_filler_arguments *args) {
	int res;
	long total_vm = 0;
	long total_rss = 0;
	long swap = 0;
	struct mm_struct *mm = NULL;

	if(args->sched_prev == NULL || args->sched_next == NULL) {
		ASSERT(false);
		return -1;
	}

	/*
	 * next
	 */
	res = val_to_ring(args, args->sched_next->pid, 0, false, 0);
	CHECK_RES(res);

	/*
	 * pgft_maj
	 */
	res = val_to_ring(args, args->sched_prev->maj_flt, 0, false, 0);
	CHECK_RES(res);

	/*
	 * pgft_min
	 */
	res = val_to_ring(args, args->sched_prev->min_flt, 0, false, 0);
	CHECK_RES(res);

	mm = args->sched_prev->mm;
	if(mm) {
		total_vm = mm->total_vm << (PAGE_SHIFT - 10);
		total_rss = ppm_get_mm_rss(mm) << (PAGE_SHIFT - 10);
		swap = ppm_get_mm_swap(mm) << (PAGE_SHIFT - 10);
	}

	/*
	 * vm_size
	 */
	res = val_to_ring(args, total_vm, 0, false, 0);
	CHECK_RES(res);

	/*
	 * vm_rss
	 */
	res = val_to_ring(args, total_rss, 0, false, 0);
	CHECK_RES(res);

	/*
	 * vm_swap
	 */
	res = val_to_ring(args, swap, 0, false, 0);
	CHECK_RES(res);

#if 0
	/*
	 * steal
	 */
	steal = cputime64_to_clock_t(kcpustat_this_cpu->cpustat[CPUTIME_STEAL]);
	res = val_to_ring(args, steal, 0, false);
	CHECK_RES(res);
#endif

	return add_sentinel(args);
}
#endif /* CAPTURE_CONTEXT_SWITCHES */

int f_sched_drop(struct event_filler_arguments *args) {
	int res;

	/*
	 * ratio
	 */
	res = val_to_ring(args, args->consumer->sampling_ratio, 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_fcntl_e(struct event_filler_arguments *args) {
	unsigned long val = 0;
	int res = 0;
	int32_t fd = 0;

	/* Parameter 1: fd (type: PT_FD) */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	fd = (int32_t)val;
	res = val_to_ring(args, (int64_t)fd, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 2: cmd (type: PT_ENUMFLAGS8) */
	syscall_get_arguments_deprecated(args, 1, 1, &val);
	res = val_to_ring(args, fcntl_cmd_to_scap(val), 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_fcntl_x(struct event_filler_arguments *args) {
	int64_t retval;
	unsigned long val = 0;
	int res = 0;
	int32_t fd = 0;

	/* Parameter 1: return value */
	retval = (int64_t)(long)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 2: fd (type: PT_FD) */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	fd = (int32_t)val;
	res = val_to_ring(args, (int64_t)fd, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 3: cmd (type: PT_ENUMFLAGS8) */
	syscall_get_arguments_deprecated(args, 1, 1, &val);
	res = val_to_ring(args, fcntl_cmd_to_scap(val), 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

static inline int parse_ptrace_addr(struct event_filler_arguments *args, uint16_t request) {
	unsigned long val;
	uint64_t dst;
	uint8_t idx;

	syscall_get_arguments_deprecated(args, 2, 1, &val);
	switch(request) {
	default:
		idx = PPM_PTRACE_IDX_UINT64;
		dst = (uint64_t)val;
	}

	return val_to_ring(args, dst, 0, false, idx);
}

static inline int parse_ptrace_data(struct event_filler_arguments *args, uint16_t request) {
	unsigned long val;
	unsigned long len;
	uint64_t dst;
	uint8_t idx;

	syscall_get_arguments_deprecated(args, 3, 1, &val);
	switch(request) {
	case PPM_PTRACE_PEEKTEXT:
	case PPM_PTRACE_PEEKDATA:
	case PPM_PTRACE_PEEKUSR:
		idx = PPM_PTRACE_IDX_UINT64;
#ifdef CONFIG_COMPAT
		if(!args->compat) {
#endif
			len = ppm_copy_from_user(&dst, (const void __user *)val, sizeof(long));
#ifdef CONFIG_COMPAT
		} else {
			len = ppm_copy_from_user(&dst,
			                         (const void __user *)compat_ptr(val),
			                         sizeof(compat_long_t));
		}
#endif
		if(unlikely(len != 0))
			return PPM_FAILURE_INVALID_USER_MEMORY;

		break;
	case PPM_PTRACE_CONT:
	case PPM_PTRACE_SINGLESTEP:
	case PPM_PTRACE_DETACH:
	case PPM_PTRACE_SYSCALL:
		idx = PPM_PTRACE_IDX_SIGTYPE;
		dst = (uint64_t)val;
		break;
	case PPM_PTRACE_ATTACH:
	case PPM_PTRACE_TRACEME:
	case PPM_PTRACE_POKETEXT:
	case PPM_PTRACE_POKEDATA:
	case PPM_PTRACE_POKEUSR:
	default:
		idx = PPM_PTRACE_IDX_UINT64;
		dst = (uint64_t)val;
		break;
	}

	return val_to_ring(args, dst, 0, false, idx);
}

int f_sys_ptrace_e(struct event_filler_arguments *args) {
	unsigned long val = 0;
	int res = 0;
	pid_t pid = 0;

	/* Parameter 1: request (type: PT_FLAGS16) */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	res = val_to_ring(args, ptrace_requests_to_scap(val), 0, false, 0);
	CHECK_RES(res);

	/* Parameter 2: pid (type: PT_PID) */
	syscall_get_arguments_deprecated(args, 1, 1, &val);
	pid = (int32_t)val;
	res = val_to_ring(args, (int64_t)pid, 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_ptrace_x(struct event_filler_arguments *args) {
	unsigned long val;
	int64_t retval;
	uint16_t request;
	int res;
	pid_t pid;

	/*
	 * res
	 */
	retval = (int64_t)(long)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	CHECK_RES(res);

	if(retval < 0) {
		res = val_to_ring(args, 0, 0, false, 0);
		CHECK_RES(res);

		res = val_to_ring(args, 0, 0, false, 0);
		CHECK_RES(res);

		/* Parameter 3: request (type: PT_FLAGS16) */
		syscall_get_arguments_deprecated(args, 0, 1, &val);
		res = val_to_ring(args, ptrace_requests_to_scap(val), 0, false, 0);
		CHECK_RES(res);

		/* Parameter 4: pid (type: PT_PID) */
		syscall_get_arguments_deprecated(args, 1, 1, &val);
		pid = (int32_t)val;
		res = val_to_ring(args, (int64_t)pid, 0, false, 0);
		CHECK_RES(res);

		return add_sentinel(args);
	}

	/*
	 * request
	 */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	request = ptrace_requests_to_scap(val);

	res = parse_ptrace_addr(args, request);
	CHECK_RES(res);

	res = parse_ptrace_data(args, request);
	CHECK_RES(res);

	/* Parameter 3: request (type: PT_FLAGS16) */
	res = val_to_ring(args, request, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 4: pid (type: PT_PID) */
	syscall_get_arguments_deprecated(args, 1, 1, &val);
	pid = (int32_t)val;
	res = val_to_ring(args, (int64_t)pid, 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_munmap_x(struct event_filler_arguments *args) {
	int64_t retval;
	int res = 0;
	struct mm_struct *mm = current->mm;
	long total_vm = 0;
	long total_rss = 0;
	long swap = 0;
	unsigned long val;

	/* Parameter 1: ret (type: PT_UINT64) */
	retval = (int64_t)(long)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	CHECK_RES(res);

	if(mm) {
		total_vm = mm->total_vm << (PAGE_SHIFT - 10);
		total_rss = ppm_get_mm_rss(mm) << (PAGE_SHIFT - 10);
		swap = ppm_get_mm_swap(mm) << (PAGE_SHIFT - 10);
	}

	/* Parameter 2: vm_size (type: PT_UINT32) */
	res = val_to_ring(args, total_vm, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 3: vm_rss (type: PT_UINT32) */
	res = val_to_ring(args, total_rss, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 4: vm_swap (type: PT_UINT32) */
	res = val_to_ring(args, swap, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 5: addr (type: PT_UINT64) */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	res = val_to_ring(args, val, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 6: length (type: PT_UINT64) */
	syscall_get_arguments_deprecated(args, 1, 1, &val);
	res = val_to_ring(args, val, 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_mmap_x(struct event_filler_arguments *args) {
	int64_t retval;
	int res = 0;
	struct mm_struct *mm = current->mm;
	long total_vm = 0;
	long total_rss = 0;
	long swap = 0;
	unsigned long val;
	int64_t fd;

	/* Parameter 1: ret (type: PT_UINT64) */
	retval = (int64_t)(long)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	CHECK_RES(res);

	if(mm) {
		total_vm = mm->total_vm << (PAGE_SHIFT - 10);
		total_rss = ppm_get_mm_rss(mm) << (PAGE_SHIFT - 10);
		swap = ppm_get_mm_swap(mm) << (PAGE_SHIFT - 10);
	}

	/* Parameter 2: vm_size (type: PT_UINT32) */
	res = val_to_ring(args, total_vm, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 3: vm_rss (type: PT_UINT32) */
	res = val_to_ring(args, total_rss, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 4: vm_swap (type: PT_UINT32) */
	res = val_to_ring(args, swap, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 5: addr (type: PT_UINT64) */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	res = val_to_ring(args, val, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 6: length (type: PT_UINT64) */
	syscall_get_arguments_deprecated(args, 1, 1, &val);
	res = val_to_ring(args, val, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 7: prot (type: PT_FLAGS32) */
	syscall_get_arguments_deprecated(args, 2, 1, &val);
	res = val_to_ring(args, prot_flags_to_scap(val), 0, false, 0);
	CHECK_RES(res);

	/* Parameter 8: flags (type: PT_FLAGS32) */
	syscall_get_arguments_deprecated(args, 3, 1, &val);
	res = val_to_ring(args, mmap_flags_to_scap(val), 0, false, 0);
	CHECK_RES(res);

	/* Paremeter 9: fd (type: PT_FD) */
	syscall_get_arguments_deprecated(args, 4, 1, &val);
	fd = (int64_t)(int32_t)val;
	res = val_to_ring(args, fd, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 10: offset (type: PT_UINT64) */
	syscall_get_arguments_deprecated(args, 5, 1, &val);
	res = val_to_ring(args, val, 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_mmap2_x(struct event_filler_arguments *args) {
	int64_t retval;
	int res = 0;
	struct mm_struct *mm = current->mm;
	long total_vm = 0;
	long total_rss = 0;
	long swap = 0;
	unsigned long val;
	int64_t fd;

	/* Parameter 1: ret (type: PT_UINT64) */
	retval = (int64_t)(long)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	CHECK_RES(res);

	if(mm) {
		total_vm = mm->total_vm << (PAGE_SHIFT - 10);
		total_rss = ppm_get_mm_rss(mm) << (PAGE_SHIFT - 10);
		swap = ppm_get_mm_swap(mm) << (PAGE_SHIFT - 10);
	}

	/* Parameter 2: vm_size (type: PT_UINT32) */
	res = val_to_ring(args, total_vm, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 3: vm_rss (type: PT_UINT32) */
	res = val_to_ring(args, total_rss, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 4: vm_swap (type: PT_UINT32) */
	res = val_to_ring(args, swap, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 5: addr (type: PT_UINT64) */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	res = val_to_ring(args, val, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 6: length (type: PT_UINT64) */
	syscall_get_arguments_deprecated(args, 1, 1, &val);
	res = val_to_ring(args, val, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 7: prot (type: PT_FLAGS32) */
	syscall_get_arguments_deprecated(args, 2, 1, &val);
	res = val_to_ring(args, prot_flags_to_scap(val), 0, false, 0);
	CHECK_RES(res);

	/* Parameter 8: flags (type: PT_FLAGS32) */
	syscall_get_arguments_deprecated(args, 3, 1, &val);
	res = val_to_ring(args, mmap_flags_to_scap(val), 0, false, 0);
	CHECK_RES(res);

	/* Paremeter 9: fd (type: PT_FD) */
	syscall_get_arguments_deprecated(args, 4, 1, &val);
	fd = (int64_t)(int32_t)val;
	res = val_to_ring(args, fd, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 10: pgoffset (type: PT_UINT64) */
	syscall_get_arguments_deprecated(args, 5, 1, &val);
	res = val_to_ring(args, val, 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_brk_x(struct event_filler_arguments *args) {
	int64_t retval;
	int res = 0;
	struct mm_struct *mm = current->mm;
	long total_vm = 0;
	long total_rss = 0;
	long swap = 0;
	unsigned long addr;

	/* Parameter 1: ret (type: PT_UINT64) */
	retval = (int64_t)(long)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	CHECK_RES(res);

	if(mm) {
		total_vm = mm->total_vm << (PAGE_SHIFT - 10);
		total_rss = ppm_get_mm_rss(mm) << (PAGE_SHIFT - 10);
		swap = ppm_get_mm_swap(mm) << (PAGE_SHIFT - 10);
	}

	/* Parameter 2: vm_size (type: PT_UINT32) */
	res = val_to_ring(args, total_vm, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 3: vm_rss (type: PT_UINT32) */
	res = val_to_ring(args, total_rss, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 4: vm_swap (type: PT_UINT32) */
	res = val_to_ring(args, swap, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 5: addr (type: PT_UINT64) */
	syscall_get_arguments_deprecated(args, 0, 1, &addr);
	res = val_to_ring(args, addr, 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_mmap_e(struct event_filler_arguments *args) {
	unsigned long val;
	int64_t fd;
	int res;

	/* Parameter 1: addr (type: PT_UINT64) */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	res = val_to_ring(args, val, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 2: length (type: PT_UINT64) */
	syscall_get_arguments_deprecated(args, 1, 1, &val);
	res = val_to_ring(args, val, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 3: prot (type: PT_FLAGS32) */
	syscall_get_arguments_deprecated(args, 2, 1, &val);
	res = val_to_ring(args, prot_flags_to_scap(val), 0, false, 0);
	CHECK_RES(res);

	/* Parameter 4: flags (type: PT_FLAGS32) */
	syscall_get_arguments_deprecated(args, 3, 1, &val);
	res = val_to_ring(args, mmap_flags_to_scap(val), 0, false, 0);
	CHECK_RES(res);

	/* Paremeter 5: fd (type: PT_FD) */
	syscall_get_arguments_deprecated(args, 4, 1, &val);
	fd = (int64_t)(int32_t)val;
	res = val_to_ring(args, fd, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 6: offset (type: PT_UINT64) */
	syscall_get_arguments_deprecated(args, 5, 1, &val);
	res = val_to_ring(args, val, 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_mprotect_e(struct event_filler_arguments *args) {
	unsigned long val;
	int res;

	/* Parameter 1: addr (type: PT_UINT64) */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	res = val_to_ring(args, val, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 2: length (type: PT_UINT64) */
	syscall_get_arguments_deprecated(args, 1, 1, &val);
	res = val_to_ring(args, val, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 3: prot (type: PT_FLAGS32) */
	syscall_get_arguments_deprecated(args, 2, 1, &val);
	res = val_to_ring(args, prot_flags_to_scap(val), 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_mprotect_x(struct event_filler_arguments *args) {
	int64_t retval;
	int res;
	unsigned long val;

	/* Parameter 1: res (type: PT_ERRNO) */
	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 2: addr (type: PT_UINT64) */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	res = val_to_ring(args, val, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 3: length (type: PT_UINT64) */
	syscall_get_arguments_deprecated(args, 1, 1, &val);
	res = val_to_ring(args, val, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 4: prot (type: PT_FLAGS32) */
	syscall_get_arguments_deprecated(args, 2, 1, &val);
	res = val_to_ring(args, prot_flags_to_scap(val), 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_renameat_x(struct event_filler_arguments *args) {
	unsigned long val;
	int res;
	int32_t fd;
	int64_t retval;

	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	CHECK_RES(res);

	/*
	 * olddirfd
	 */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	fd = (int32_t)val;
	if(fd == AT_FDCWD)
		fd = PPM_AT_FDCWD;

	res = val_to_ring(args, (int64_t)fd, 0, false, 0);
	CHECK_RES(res);

	/*
	 * oldpath
	 */
	syscall_get_arguments_deprecated(args, 1, 1, &val);
	res = val_to_ring(args, val, 0, true, 0);
	CHECK_RES(res);

	/*
	 * newdirfd
	 */
	syscall_get_arguments_deprecated(args, 2, 1, &val);
	fd = (int32_t)val;
	if(fd == AT_FDCWD)
		fd = PPM_AT_FDCWD;

	res = val_to_ring(args, (int64_t)fd, 0, false, 0);
	CHECK_RES(res);

	/*
	 * newpath
	 */
	syscall_get_arguments_deprecated(args, 3, 1, &val);
	res = val_to_ring(args, val, 0, true, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_renameat2_x(struct event_filler_arguments *args) {
	unsigned long val;
	int res;
	int32_t fd;
	int64_t retval;

	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	CHECK_RES(res);

	/*
	 * olddirfd
	 */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	fd = (int32_t)val;
	if(fd == AT_FDCWD)
		fd = PPM_AT_FDCWD;

	res = val_to_ring(args, (int64_t)fd, 0, false, 0);
	CHECK_RES(res);

	/*
	 * oldpath
	 */
	syscall_get_arguments_deprecated(args, 1, 1, &val);
	res = val_to_ring(args, val, 0, true, 0);
	CHECK_RES(res);

	/*
	 * newdirfd
	 */
	syscall_get_arguments_deprecated(args, 2, 1, &val);
	fd = (int32_t)val;
	if(fd == AT_FDCWD)
		fd = PPM_AT_FDCWD;

	res = val_to_ring(args, (int64_t)fd, 0, false, 0);
	CHECK_RES(res);

	/*
	 * newpath
	 */
	syscall_get_arguments_deprecated(args, 3, 1, &val);
	res = val_to_ring(args, val, 0, true, 0);
	CHECK_RES(res);

	/*
	 * flags
	 */
	syscall_get_arguments_deprecated(args, 4, 1, &val);
	res = val_to_ring(args, val, 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_symlinkat_x(struct event_filler_arguments *args) {
	unsigned long val;
	int res;
	int32_t fd;
	int64_t retval;

	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	CHECK_RES(res);

	/*
	 * oldpath
	 */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	res = val_to_ring(args, val, 0, true, 0);
	CHECK_RES(res);

	/*
	 * newdirfd
	 */
	syscall_get_arguments_deprecated(args, 1, 1, &val);
	fd = (int32_t)val;
	if(fd == AT_FDCWD)
		fd = PPM_AT_FDCWD;

	res = val_to_ring(args, (int64_t)fd, 0, false, 0);
	CHECK_RES(res);

	/*
	 * newpath
	 */
	syscall_get_arguments_deprecated(args, 2, 1, &val);
	res = val_to_ring(args, val, 0, true, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_openat2_e(struct event_filler_arguments *args) {
	unsigned long resolve;
	unsigned long flags;
	unsigned long val;
	unsigned long mode;
	int32_t fd;
	int res;
#ifdef __NR_openat2
	struct open_how how;
#endif

	/*
	 * dirfd
	 */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	fd = (int32_t)val;
	if(fd == AT_FDCWD)
		fd = PPM_AT_FDCWD;

	res = val_to_ring(args, (int64_t)fd, 0, false, 0);
	CHECK_RES(res);

	/*
	 * name
	 */
	syscall_get_arguments_deprecated(args, 1, 1, &val);
	res = val_to_ring(args, val, 0, true, 0);
	CHECK_RES(res);

#ifdef __NR_openat2
	/*
	 * how: we get the data structure, and put its fields in the buffer one by one
	 */
	syscall_get_arguments_deprecated(args, 2, 1, &val);
	res = ppm_copy_from_user(&how, (void *)val, sizeof(struct open_how));
	if(unlikely(res != 0))
		return PPM_FAILURE_INVALID_USER_MEMORY;

	flags = open_flags_to_scap(how.flags);
	mode = open_modes_to_scap(how.flags, how.mode);
	resolve = openat2_resolve_to_scap(how.resolve);
#else
	flags = 0;
	mode = 0;
	resolve = 0;
#endif
	/*
	 * flags (extracted from open_how structure)
	 * Note that we convert them into the ppm portable representation before pushing them to the
	 * ring
	 */
	res = val_to_ring(args, flags, 0, true, 0);
	CHECK_RES(res);

	/*
	 * mode (extracted from open_how structure)
	 * Note that we convert them into the ppm portable representation before pushing them to the
	 * ring
	 */
	res = val_to_ring(args, mode, 0, true, 0);
	CHECK_RES(res);

	/*
	 * resolve (extracted from open_how structure)
	 * Note that we convert them into the ppm portable representation before pushing them to the
	 * ring
	 */
	res = val_to_ring(args, resolve, 0, true, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_openat2_x(struct event_filler_arguments *args) {
	unsigned long resolve;
	unsigned long flags;
	unsigned long val;
	unsigned long mode;
	uint32_t dev = 0;
	uint64_t ino = 0;
	int res;
	int32_t fd;
	int64_t retval;
	enum ppm_overlay ol = PPM_NOT_OVERLAY_FS;
#ifdef __NR_openat2
	struct open_how how;
#endif

	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	CHECK_RES(res);

	/*
	 * dirfd
	 */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	fd = (int32_t)val;
	if(fd == AT_FDCWD)
		fd = PPM_AT_FDCWD;

	res = val_to_ring(args, (int64_t)fd, 0, false, 0);
	CHECK_RES(res);

	/*
	 * name
	 */
	syscall_get_arguments_deprecated(args, 1, 1, &val);
	res = val_to_ring(args, val, 0, true, 0);
	CHECK_RES(res);

#ifdef __NR_openat2
	/*
	 * how: we get the data structure, and put its fields in the buffer one by one
	 */
	syscall_get_arguments_deprecated(args, 2, 1, &val);
	res = ppm_copy_from_user(&how, (void *)val, sizeof(struct open_how));
	if(unlikely(res != 0))
		return PPM_FAILURE_INVALID_USER_MEMORY;

	flags = open_flags_to_scap(how.flags);
	mode = open_modes_to_scap(how.flags, how.mode);
	resolve = openat2_resolve_to_scap(how.resolve);
#else
	flags = 0;
	mode = 0;
	resolve = 0;
#endif

	get_dev_ino_overlay_from_fd(retval, &dev, &ino, &ol);

	/*
	 * flags (extracted from open_how structure)
	 * Note that we convert them into the ppm portable representation before pushing them to the
	 * ring
	 */
	/* update flags if file is created */
	get_fd_fmode_created(retval, &flags);
	if(ol == PPM_OVERLAY_UPPER) {
		flags |= PPM_FD_UPPER_LAYER;
	} else if(ol == PPM_OVERLAY_LOWER) {
		flags |= PPM_FD_LOWER_LAYER;
	}
	res = val_to_ring(args, flags, 0, true, 0);
	CHECK_RES(res);

	/*
	 * mode (extracted from open_how structure)
	 * Note that we convert them into the ppm portable representation before pushing them to the
	 * ring
	 */
	res = val_to_ring(args, mode, 0, true, 0);
	CHECK_RES(res);

	/*
	 * resolve (extracted from open_how structure)
	 * Note that we convert them into the ppm portable representation before pushing them to the
	 * ring
	 */
	res = val_to_ring(args, resolve, 0, true, 0);
	CHECK_RES(res);

	/*
	 *  dev
	 */
	res = val_to_ring(args, dev, 0, false, 0);
	CHECK_RES(res);

	/*
	 *  ino
	 */
	res = val_to_ring(args, ino, 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_copy_file_range_e(struct event_filler_arguments *args) {
	unsigned long val;
	int64_t fdin;
	int res;
	unsigned long offin;
	unsigned long len;

	/* Parameter 1: fdin (type: PT_FD) */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	fdin = (int64_t)(int32_t)val;
	res = val_to_ring(args, fdin, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 2: offin (type: PT_UINT64) */
	syscall_get_arguments_deprecated(args, 1, 1, &offin);
	res = val_to_ring(args, offin, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 3: len (type: PT_UINT64) */
	syscall_get_arguments_deprecated(args, 4, 1, &len);
	res = val_to_ring(args, len, 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_copy_file_range_x(struct event_filler_arguments *args) {
	int64_t retval;
	int res;
	unsigned long val;
	int64_t fdout, fdin;
	unsigned long offout, offin, len;

	/* Parameter 1: res (type: PT_ERRNO) */
	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 2: fdout (type: PT_FD) */
	syscall_get_arguments_deprecated(args, 2, 1, &val);
	fdout = (int64_t)(int32_t)val;
	res = val_to_ring(args, fdout, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 3: offout (type: PT_UINT64) */
	syscall_get_arguments_deprecated(args, 3, 1, &offout);
	res = val_to_ring(args, offout, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 4: fdin (type: PT_FD) */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	fdin = (int64_t)(int32_t)val;
	res = val_to_ring(args, fdin, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 5: offin (type: PT_UINT64) */
	syscall_get_arguments_deprecated(args, 1, 1, &offin);
	res = val_to_ring(args, offin, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 6: len (type: PT_UINT64) */
	syscall_get_arguments_deprecated(args, 4, 1, &len);
	res = val_to_ring(args, len, 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_open_by_handle_at_x(struct event_filler_arguments *args) {
	unsigned long val = 0;
	unsigned long flags = 0;
	int res = 0;
	uint32_t dev = 0;
	uint64_t ino = 0;
	long retval = 0;
	char *pathname = NULL;
	int32_t mountfd = 0;
	enum ppm_overlay ol = PPM_NOT_OVERLAY_FS;

	/* Parameter 1: ret (type: PT_FD) */
	retval = syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 2: mountfd (type: PT_FD) */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	mountfd = (int32_t)val;
	if(mountfd == AT_FDCWD) {
		mountfd = PPM_AT_FDCWD;
	}
	res = val_to_ring(args, (int64_t)mountfd, 0, false, 0);
	CHECK_RES(res);

	get_dev_ino_overlay_from_fd(retval, &dev, &ino, &ol);

	/* Parameter 3: flags (type: PT_FLAGS32) */
	syscall_get_arguments_deprecated(args, 2, 1, &val);
	flags = open_flags_to_scap(val);
	/* update flags if file is created */
	get_fd_fmode_created(retval, &flags);
	if(ol == PPM_OVERLAY_UPPER) {
		flags |= PPM_FD_UPPER_LAYER;
	} else if(ol == PPM_OVERLAY_LOWER) {
		flags |= PPM_FD_LOWER_LAYER;
	}
	res = val_to_ring(args, flags, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 4: path (type: PT_FSPATH) */
	if(retval > 0) {
		/* String storage size is exactly one page.
		 * PAGE_SIZE = 4096 byte like PATH_MAX in unix conventions.
		 */
		char *buf = (char *)args->str_storage;

		struct file *file;
		file = fget(retval);
		if(likely(file)) {
			/* `pathname` will be a pointer inside the buffer `buf`
			 * where the file path effectively starts.
			 */
			pathname = d_path(&file->f_path, buf, PAGE_SIZE);
			fput(file);
		}
	}

	res = val_to_ring(args, (unsigned long)pathname, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 5: dev (type: PT_UINT32) */
	res = val_to_ring(args, dev, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 6: ino (type: PT_UINT64) */
	res = val_to_ring(args, ino, 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_io_uring_setup_x(struct event_filler_arguments *args) {
	int res = 0;
	long retval = 0;
	unsigned long val = 0;

	/* All these params are sent equal to `0` if `__NR_io_uring_setup`
	 * syscall is not defined.
	 */
	uint32_t sq_entries = 0;
	uint32_t cq_entries = 0;
	uint32_t flags = 0;
	uint32_t sq_thread_cpu = 0;
	uint32_t sq_thread_idle = 0;
	uint32_t features = 0;

#ifdef __NR_io_uring_setup
	struct io_uring_params params = {0};
	syscall_get_arguments_deprecated(args, 1, 1, &val);
	res = ppm_copy_from_user(&params, (void *)val, sizeof(struct io_uring_params));
	if(unlikely(res != 0)) {
		memset(&params, 0, sizeof(params));
	}

	sq_entries = params.sq_entries;
	cq_entries = params.cq_entries;
	flags = io_uring_setup_flags_to_scap(params.flags);
	sq_thread_cpu = params.sq_thread_cpu;
	sq_thread_idle = params.sq_thread_idle;

	/* We need this ifdef because `features` field is defined into the
	 * `struct io_uring_params` only if the `IORING_FEAT_SINGLE_MMAP` is
	 * defined.
	 */
#ifdef IORING_FEAT_SINGLE_MMAP
	features = io_uring_setup_feats_to_scap(params.features);
#endif
#endif /* __NR_io_uring_setup */

	/* Parameter 1: res (type: PT_ERRNO) */
	retval = (long)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 2: entries (type: PT_UINT32) */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	res = val_to_ring(args, val, 0, true, 0);
	CHECK_RES(res);

	/* Parameter 3: sq_entries (type: PT_UINT32) */
	res = val_to_ring(args, sq_entries, 0, true, 0);
	CHECK_RES(res);

	/* Parameter 4: cq_entries (type: PT_UINT32) */
	res = val_to_ring(args, cq_entries, 0, true, 0);
	CHECK_RES(res);

	/* Parameter 5: flags (type: PT_FLAGS32) */
	res = val_to_ring(args, flags, 0, true, 0);
	CHECK_RES(res);

	/* Parameter 6: sq_thread_cpu (type: PT_UINT32) */
	res = val_to_ring(args, sq_thread_cpu, 0, true, 0);
	CHECK_RES(res);

	/* Parameter 7: sq_thread_idle (type: PT_UINT32) */
	res = val_to_ring(args, sq_thread_idle, 0, true, 0);
	CHECK_RES(res);

	/* Parameter 8: features (type: PT_FLAGS32) */
	res = val_to_ring(args, features, 0, true, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_io_uring_enter_x(struct event_filler_arguments *args) {
	int res = 0;
	int32_t fd = 0;
	unsigned long val = 0;

	/* Parameter 1: res (type: PT_ERRNO) */
	long retval = (long)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 2: fd (type: PT_FD) */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	fd = (int32_t)val;
	res = val_to_ring(args, (int64_t)fd, 0, true, 0);
	CHECK_RES(res);

	/* Parameter 3: to_submit (type: PT_UINT32) */
	syscall_get_arguments_deprecated(args, 1, 1, &val);
	res = val_to_ring(args, val, 0, true, 0);
	CHECK_RES(res);

	/* Parameter 4: min_complete (type: PT_UINT32) */
	syscall_get_arguments_deprecated(args, 2, 1, &val);
	res = val_to_ring(args, val, 0, true, 0);
	CHECK_RES(res);

	/* Parameter 5: flags (type: PT_FLAGS32) */
	syscall_get_arguments_deprecated(args, 3, 1, &val);
	res = val_to_ring(args, io_uring_enter_flags_to_scap(val), 0, true, 0);
	CHECK_RES(res);

	/* Parameter 6: sig (type: PT_SIGSET) */
	syscall_get_arguments_deprecated(args, 4, 1, &val);
	res = val_to_ring(args, val, 0, true, 0);
	CHECK_RES(res);

	/// TODO: We miss the last parameter `size_t argsz`
	/// we need to implement it in all our drivers

	return add_sentinel(args);
}

int f_sys_io_uring_register_x(struct event_filler_arguments *args) {
	int res = 0;
	unsigned long val = 0;
	int32_t fd = 0;

	/* Parameter 1: res (type: PT_ERRNO) */
	int64_t retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 2: fd (type: PT_FD) */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	fd = (int32_t)val;
	res = val_to_ring(args, (int64_t)fd, 0, true, 0);
	CHECK_RES(res);

	/* Parameter 3: opcode (type: PT_UINT32) */
	syscall_get_arguments_deprecated(args, 1, 1, &val);
	res = val_to_ring(args, io_uring_register_opcodes_to_scap(val), 0, true, 0);
	CHECK_RES(res);

	/* Parameter 4: arg (type: PT_UINT64) */
	syscall_get_arguments_deprecated(args, 2, 1, &val);
	res = val_to_ring(args, val, 0, true, 0);
	CHECK_RES(res);

	/* Parameter 5: nr_args (type: PT_UINT32) */
	syscall_get_arguments_deprecated(args, 3, 1, &val);
	res = val_to_ring(args, val, 0, true, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_timerfd_create_x(struct event_filler_arguments *args) {
	int64_t retval;
	int res;

	/* Parameter 1: res (type: PT_FD) */
	retval = (int64_t)(int32_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 2: clockid (type: PT_UINT8) */
	/* Send `0`. */
	res = val_to_ring(args, 0, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 3: flags (type: PT_UINT8) */
	/* Send `0`. */
	res = val_to_ring(args, 0, 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_inotify_init_e(struct event_filler_arguments *args) {
	/* Parameter 1: flags (type: PT_UINT8) */
	/* We have nothing to extract from the kernel here so we send `0`.
	 * This is done to preserve the `PPME_SYSCALL_INOTIFY_INIT_E` event with 1 param.
	 */
	int res = val_to_ring(args, 0, 0, true, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_inotify_init_x(struct event_filler_arguments *args) {
	int64_t retval;
	int res;

	/* Parameter 1: res (type: PT_FD) */
	retval = (int64_t)(int32_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 2: flags (type: PT_UINT8) */
	/* Send `0` to unify handling with inotify_init1. */
	res = val_to_ring(args, 0, 0, true, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_inotify_init1_x(struct event_filler_arguments *args) {
	int res = 0;
	unsigned long val = 0;

	/* Parameter 1: res (type: PT_ERRNO) */
	int64_t retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 2: flags (type: PT_FLAGS16) */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	res = val_to_ring(args, inotify_init1_flags_to_scap((int32_t)val), 0, true, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_mlock_x(struct event_filler_arguments *args) {
	unsigned long val;

	int64_t retval = (int64_t)syscall_get_return_value(current, args->regs);
	int res = val_to_ring(args, retval, 0, false, 0);
	CHECK_RES(res);
	/*
	 * addr
	 */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	res = val_to_ring(args, val, 0, true, 0);
	CHECK_RES(res);
	/*
	 * len
	 */
	syscall_get_arguments_deprecated(args, 1, 1, &val);
	res = val_to_ring(args, val, 0, true, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_mlock2_x(struct event_filler_arguments *args) {
	unsigned long val;

	int64_t retval = (int64_t)syscall_get_return_value(current, args->regs);
	int res = val_to_ring(args, retval, 0, false, 0);
	CHECK_RES(res);
	/*
	 * addr
	 */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	res = val_to_ring(args, val, 0, true, 0);
	CHECK_RES(res);
	/*
	 * len
	 */
	syscall_get_arguments_deprecated(args, 1, 1, &val);
	res = val_to_ring(args, val, 0, true, 0);
	CHECK_RES(res);
	/*
	 * flags
	 */
	syscall_get_arguments_deprecated(args, 2, 1, &val);
	res = val_to_ring(args, mlock2_flags_to_scap(val), 0, true, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_munlock_x(struct event_filler_arguments *args) {
	unsigned long val;

	int64_t retval = (int64_t)syscall_get_return_value(current, args->regs);
	int res = val_to_ring(args, retval, 0, false, 0);
	CHECK_RES(res);
	/*
	 * addr
	 */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	res = val_to_ring(args, val, 0, true, 0);
	CHECK_RES(res);
	/*
	 * len
	 */
	syscall_get_arguments_deprecated(args, 1, 1, &val);
	res = val_to_ring(args, val, 0, true, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_mlockall_x(struct event_filler_arguments *args) {
	unsigned long val;

	int64_t retval = (int64_t)syscall_get_return_value(current, args->regs);
	int res = val_to_ring(args, retval, 0, false, 0);
	CHECK_RES(res);
	/*
	 * flags
	 */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	res = val_to_ring(args, mlockall_flags_to_scap(val), 0, true, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_munlockall_x(struct event_filler_arguments *args) {
	int64_t retval = (int64_t)syscall_get_return_value(current, args->regs);
	int res = val_to_ring(args, retval, 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_fsconfig_x(struct event_filler_arguments *args) {
	unsigned long res = 0;

	int64_t ret = 0;
	unsigned long val = 0;
	int32_t fd;
	unsigned long cmd = 0;
	unsigned long scap_cmd = 0;
	unsigned long key_pointer = 0;
	unsigned long value_pointer = 0;
	unsigned long aux = 0;

	/* Parameter 1: ret (type: PT_ERRNO) */
	ret = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, ret, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 2: fd (type: PT_FD) */
	/* This is the file-system fd */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	fd = (int32_t)val;
	res = val_to_ring(args, (int64_t)fd, 0, true, 0);
	CHECK_RES(res);

	/* Parameter 3: cmd (type: PT_ENUMFLAGS32) */
	syscall_get_arguments_deprecated(args, 1, 1, &cmd);
	scap_cmd = fsconfig_cmds_to_scap(cmd);
	res = val_to_ring(args, scap_cmd, 0, true, 0);
	CHECK_RES(res);

	/* Parameter 4: key (type: PT_CHARBUF) */
	syscall_get_arguments_deprecated(args, 2, 1, &key_pointer);
	res = val_to_ring(args, key_pointer, 0, true, 0);
	CHECK_RES(res);

	syscall_get_arguments_deprecated(args, 4, 1, &aux);

	if(ret < 0) {
		/* If the syscall fails we push empty params to userspace. */

		/* Parameter 5: value_bytebuf (type: PT_BYTEBUF) */
		res = val_to_ring(args, 0, 0, true, 0);
		CHECK_RES(res);

		/* Parameter 6: value_charbuf (type: PT_CHARBUF) */
		res = val_to_ring(args, 0, 0, true, 0);
		CHECK_RES(res);
	} else {
		syscall_get_arguments_deprecated(args, 3, 1, &value_pointer);

		/* According to the command we need to understand what value we have to push to userspace.
		 */
		/* see https://elixir.bootlin.com/linux/latest/source/fs/fsopen.c#L271 */
		switch(scap_cmd) {
		case PPM_FSCONFIG_SET_FLAG:
		case PPM_FSCONFIG_SET_FD:
		case PPM_FSCONFIG_CMD_CREATE:
		case PPM_FSCONFIG_CMD_RECONFIGURE:
			/* Since `value` is NULL we send two empty params. */

			/* Parameter 5: value_bytebuf (type: PT_BYTEBUF) */
			res = val_to_ring(args, 0, 0, true, 0);
			CHECK_RES(res);

			/* Parameter 6: value_charbuf (type: PT_CHARBUF) */
			res = val_to_ring(args, 0, 0, true, 0);
			CHECK_RES(res);
			break;

		case PPM_FSCONFIG_SET_STRING:
		case PPM_FSCONFIG_SET_PATH:
		case PPM_FSCONFIG_SET_PATH_EMPTY:
			/* `value` is a NUL-terminated string.
			 * Push `value_charbuf` but not `value_bytebuf` (empty).
			 */

			/* Parameter 5: value_bytebuf (type: PT_BYTEBUF) */
			res = val_to_ring(args, 0, 0, true, 0);
			CHECK_RES(res);

			/* Parameter 6: value_charbuf (type: PT_CHARBUF) */
			res = val_to_ring(args, value_pointer, 0, true, 0);
			CHECK_RES(res);
			break;

		case PPM_FSCONFIG_SET_BINARY:
			/* `value` points to a binary blob and `aux` indicates its size.
			 * Push `value_bytebuf` but not `value_charbuf` (empty).
			 */

			/* Parameter 5: value_bytebuf (type: PT_BYTEBUF) */
			res = val_to_ring(args, value_pointer, aux, true, 0);
			CHECK_RES(res);

			/* Parameter 6: value_charbuf (type: PT_CHARBUF) */
			res = val_to_ring(args, 0, 0, true, 0);
			CHECK_RES(res);
			break;

		default:

			/* Parameter 5: value_bytebuf (type: PT_BYTEBUF) */
			res = val_to_ring(args, 0, 0, true, 0);
			CHECK_RES(res);

			/* Parameter 6: value_charbuf (type: PT_CHARBUF) */
			res = val_to_ring(args, 0, 0, true, 0);
			CHECK_RES(res);
			break;
		}
	}

	/* Parameter 7: aux (type: PT_INT32) */
	res = val_to_ring(args, aux, 0, true, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_signalfd_e(struct event_filler_arguments *args) {
	unsigned long val;
	int64_t fd;
	int res;

	/* Parameter 1: fd (type: PT_FD) */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	fd = (int64_t)(int32_t)val;
	res = val_to_ring(args, fd, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 2: mask (type: PT_UINT32) */
	/* Right now we are not interested in the `sigmask`, we can populate it if we need */
	res = val_to_ring(args, 0, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 3: flags (type: PT_UINT8) */
	/* The syscall `signalfd` has no flags! only `signalfd4` has the `flags` param.
	 * For compatibility with the event definition here we send `0` as flags.
	 */
	res = val_to_ring(args, 0, 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_signalfd_x(struct event_filler_arguments *args) {
	int64_t retval;
	int res;
	unsigned long val;
	int64_t fd;

	/* Parameter 1: res (type: PT_FD) */
	retval = (int64_t)(int32_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 2: fd (type: PT_FD) */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	fd = (int64_t)(int32_t)val;
	res = val_to_ring(args, fd, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 3: mask (type: PT_UINT32) */
	/* Right now we are not interested in the `sigmask`, we can populate it if we need */
	res = val_to_ring(args, 0, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 4: flags (type: PT_UINT8) */
	/* The syscall `signalfd` has no flags! only `signalfd4` has the `flags` param.
	 * For compatibility with the event definition here we send `0` as flags.
	 */
	res = val_to_ring(args, 0, 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_signalfd4_e(struct event_filler_arguments *args) {
	unsigned long val;
	int64_t fd;
	int res;

	/* Parameter 1: fd (type: PT_FD) */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	fd = (int64_t)(int32_t)val;
	res = val_to_ring(args, fd, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 2: mask (type: PT_UINT32) */
	/* Right now we are not interested in the `sigmask`, we can populate it if we need */
	res = val_to_ring(args, 0, 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_signalfd4_x(struct event_filler_arguments *args) {
	int64_t retval;
	int res;
	unsigned long val;
	int64_t fd;

	/* Parameter 1: res (type: PT_FD) */
	retval = (int64_t)(int32_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 2: flags (type: PT_FLAGS16) */
	syscall_get_arguments_deprecated(args, 3, 1, &val);
	res = val_to_ring(args, signalfd4_flags_to_scap(val), 0, false, 0);
	CHECK_RES(res);

	/* Parameter 3: fd (type: PT_FD) */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	fd = (int64_t)(int32_t)val;
	res = val_to_ring(args, fd, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 4: mask (type: PT_UINT32) */
	/* Right now we are not interested in the `sigmask`, we can populate it if we need */
	res = val_to_ring(args, 0, 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_kill_x(struct event_filler_arguments *args) {
	int64_t retval;
	int res;
	unsigned long val;
	pid_t pid;
	uint8_t sig;

	/* Parameter 1: res (type: PT_ERRNO) */
	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 2: pid (type: PT_PID) */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	pid = (int32_t)val;
	res = val_to_ring(args, (int64_t)pid, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 3: sig (type: PT_SIGTYPE) */
	syscall_get_arguments_deprecated(args, 1, 1, &val);
	sig = (uint8_t)val;
	res = val_to_ring(args, sig, 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_tkill_x(struct event_filler_arguments *args) {
	int64_t retval;
	int res;
	unsigned long val;
	pid_t tid;
	uint8_t sig;

	/* Parameter 1: res (type: PT_ERRNO) */
	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 2: tid (type: PT_PID) */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	tid = (int32_t)val;
	res = val_to_ring(args, (int64_t)tid, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 3: sig (type: PT_SIGTYPE) */
	syscall_get_arguments_deprecated(args, 1, 1, &val);
	sig = (uint8_t)val;
	res = val_to_ring(args, sig, 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_tgkill_x(struct event_filler_arguments *args) {
	int64_t retval;
	int res;
	unsigned long val;
	pid_t pid, tid;
	uint8_t sig;

	/* Parameter 1: res (type: PT_ERRNO) */
	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 3: pid (type: PT_PID) */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	pid = (int32_t)val;
	res = val_to_ring(args, (int64_t)pid, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 3: tid (type: PT_PID) */
	syscall_get_arguments_deprecated(args, 1, 1, &val);
	tid = (int32_t)val;
	res = val_to_ring(args, (int64_t)tid, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 3: sig (type: PT_SIGTYPE) */
	syscall_get_arguments_deprecated(args, 2, 1, &val);
	sig = (uint8_t)val;
	res = val_to_ring(args, sig, 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_epoll_create_e(struct event_filler_arguments *args) {
	unsigned long size;
	int res;

	/* Parameter 1: size (type: PT_INT32) */
	syscall_get_arguments_deprecated(args, 0, 1, &size);
	res = val_to_ring(args, size, 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_epoll_create_x(struct event_filler_arguments *args) {
	int64_t retval;
	int res;
	unsigned long size;

	/* Parameter 1: res (type: PT_ERRNO) */
	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 2: size (type: PT_INT32) */
	syscall_get_arguments_deprecated(args, 0, 1, &size);
	res = val_to_ring(args, size, 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_epoll_create1_e(struct event_filler_arguments *args) {
	unsigned long flags;
	int res;

	/* Parameter 1: flags (type: PT_FLAGS32) */
	syscall_get_arguments_deprecated(args, 0, 1, &flags);
	res = val_to_ring(args, epoll_create1_flags_to_scap(flags), 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_epoll_create1_x(struct event_filler_arguments *args) {
	int64_t retval;
	int res;
	unsigned long flags;

	/* Parameter 1: res (type: PT_ERRNO) */
	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 2: flags (type: PT_FLAGS32) */
	syscall_get_arguments_deprecated(args, 0, 1, &flags);
	res = val_to_ring(args, epoll_create1_flags_to_scap(flags), 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_epoll_wait_x(struct event_filler_arguments *args) {
	int64_t retval;
	int res;
	unsigned long val;
	int64_t maxevents;

	/* Parameter 1: res (type: PT_ERRNO) */
	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 2: maxevents (type: PT_ERRNO) */
	syscall_get_arguments_deprecated(args, 2, 1, &val);
	maxevents = (int64_t)(int)val;
	res = val_to_ring(args, maxevents, 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_dup_e(struct event_filler_arguments *args) {
	unsigned long val;
	int64_t old_fd;
	int res;

	/* Parameter 1: fd (type: PT_FD) */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	old_fd = (int64_t)(int32_t)val;
	res = val_to_ring(args, old_fd, 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_dup_x(struct event_filler_arguments *args) {
	int64_t retval;
	int res;
	unsigned long val;
	int64_t old_fd;

	/* Parameter 1: res (type: PT_FD) */
	retval = (int64_t)(int32_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 2: oldfd (type: PT_FD) */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	old_fd = (int64_t)(int32_t)val;
	res = val_to_ring(args, old_fd, 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_dup2_e(struct event_filler_arguments *args) {
	unsigned long val;
	int64_t oldfd;
	int res;

	/* Parameter 1: fd (type: PT_FD) */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	oldfd = (int64_t)(int32_t)val;
	res = val_to_ring(args, oldfd, 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_dup2_x(struct event_filler_arguments *args) {
	int64_t retval;
	int res;
	unsigned long val;
	int64_t fd;

	/* Parameter 1: res (type: PT_FD) */
	retval = (int64_t)(int32_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 2: oldfd (type: PT_FD) */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	fd = (int64_t)(int32_t)val;
	res = val_to_ring(args, fd, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 3: newfd (type: PT_FD) */
	syscall_get_arguments_deprecated(args, 1, 1, &val);
	fd = (int64_t)(int32_t)val;
	res = val_to_ring(args, fd, 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_dup3_e(struct event_filler_arguments *args) {
	unsigned long val;
	int64_t fd;
	int res;

	/* Parameter 1: fd (type: PT_FD) */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	fd = (int64_t)(int32_t)val;
	res = val_to_ring(args, fd, 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_dup3_x(struct event_filler_arguments *args) {
	int64_t retval;
	int res;
	unsigned long val;
	int64_t fd;

	/* Parameter 1: res (type: PT_FD) */
	retval = (int64_t)(int32_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 2: oldfd (type: PT_FD) */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	fd = (int64_t)(int32_t)val;
	res = val_to_ring(args, fd, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 3: newfd (type: PT_FD) */
	syscall_get_arguments_deprecated(args, 1, 1, &val);
	fd = (int64_t)(int32_t)val;
	res = val_to_ring(args, fd, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 4: flags (type: PT_FLAGS32) */
	syscall_get_arguments_deprecated(args, 2, 1, &val);
	res = val_to_ring(args, dup3_flags_to_scap((int)val), 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

/* Before kernel version 3.4.0 we dont' have the concept of
 * "sub_reaper", `prctl` wasn't defined so we can simply send -1
 * to userspace. It should be able through its logic to find the correct
 * reaper!
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 4, 0)

static pid_t find_alive_thread(struct task_struct *father) {
	struct task_struct *t = father;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 19, 0)
	while_each_thread(father, t) {
#else  /* Kernel 3.19.0 switched to `for_each_thread` macro */
	for_each_thread(father, t) {
#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(3, 19, 0) */
		/* We add an extra check here for `t != NULL` just to be sure */
		if(t != NULL && (!(t->flags & PF_EXITING)))
			return t->pid;
	}
	return 0;
}

/* When we die, we re-parent all our children, and try to:
 * 1. give them to another thread in our thread group, if such a member exists
 * 2. give it to the first ancestor process which prctl'd itself as a
 *    child_subreaper for its children (like a service manager)
 * 3. give it to the init process (PID 1) in our pid namespace
 */
static pid_t find_new_reaper_pid(struct task_struct *father) {
	struct task_struct *possible_reaper;
	/* This is the namespace level of the thread that is dying, we will
	 * use it to check that the reaper will be always in the same namespace.
	 */
	unsigned int father_ns_level = task_pid(father)->level;
	/* This is the reaper of that namespace */
	struct task_struct *child_ns_reaper = task_active_pid_ns(father)->child_reaper;
	/* Search an alive thread in the same thread group */
	pid_t reaper_pid = find_alive_thread(father);

	/* If `reaper_pid!=0` when we found an alive thread, that's enough */
	if(reaper_pid != 0) {
		return reaper_pid;
	}

	/* There could be a strange case in which the actual thread is the init one
	 * and we have no other threads in the same thread group, so the whole init group is dying.
	 * The kernel will destroy all the processes in that namespace. We send a reaper equal to
	 * `0` in userspace.
	 */
	if(child_ns_reaper == father) {
		return 0;
	}

	/* If there are no sub reapers the reaper is the init process of that namespace */
	if(!father->signal->has_child_subreaper) {
		return child_ns_reaper->pid;
	}

	/* If we fall here it means we have some sub_reapers.
	 * Find the first ->is_child_subreaper ancestor in our pid_ns.
	 * We can't check reaper != child_reaper to ensure we do not
	 * cross the namespaces, the exiting parent could be injected
	 * by setns() + fork().
	 * We check pid->level, this is slightly more efficient than
	 * task_active_pid_ns(reaper) != task_active_pid_ns(father).
	 */
	for(possible_reaper = father->real_parent; task_pid(possible_reaper)->level == father_ns_level;
	    possible_reaper = possible_reaper->real_parent) {
		/* Here we could also check for child_ns_reaper
		 * but the kernel checks against init_task, so we are fine.
		 */
		if(possible_reaper == &init_task) {
			return child_ns_reaper->pid;
		}

		if(!possible_reaper->signal->is_child_subreaper) {
			continue;
		}

		reaper_pid = find_alive_thread(possible_reaper);
		if(reaper_pid != 0) {
			return reaper_pid;
		}
	}

	return child_ns_reaper->pid;
}
#else

static pid_t find_new_reaper_pid(struct task_struct *father) {
	return -1;
}

#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(3, 4, 0) */

int f_sys_procexit_e(struct event_filler_arguments *args) {
	int res;

	pid_t reaper_pid = 0;

	if(args->sched_prev == NULL) {
		ASSERT(false);
		return -1;
	}

	/* Parameter 1: status (type: PT_ERRNO) */
	res = val_to_ring(args, args->sched_prev->exit_code, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 2: ret (type: PT_ERRNO) */
	res = val_to_ring(args, __WEXITSTATUS(args->sched_prev->exit_code), 0, false, 0);
	CHECK_RES(res);

	/* Parameter 3: sig (type: PT_SIGTYPE) */
	/* If signaled -> signum, else 0 */
	if(__WIFSIGNALED(args->sched_prev->exit_code)) {
		res = val_to_ring(args, __WTERMSIG(args->sched_prev->exit_code), 0, false, 0);
	} else {
		res = val_to_ring(args, 0, 0, false, 0);
	}
	CHECK_RES(res);

	/* Parameter 4: core (type: PT_UINT8) */
	res = val_to_ring(args, __WCOREDUMP(args->sched_prev->exit_code) != 0, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 5: reaper_tid (type: PT_PID) */
	/* This is a sort of optimization if this thread has no children in the kernel
	 * we don't need a reaper and we can save some precious cycles.
	 * We send `reaper_pid==0` if the userspace still has some children
	 * it will manage them with its userspace logic.
	 */
	if(!list_empty(&current->children)) {
		/* We have at least one child, so we need a reaper for it */
		reaper_pid = find_new_reaper_pid(current);
	}
	res = val_to_ring(args, (int64_t)reaper_pid, 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_sendfile_e(struct event_filler_arguments *args) {
	unsigned long val;
	int64_t out_fd;
	int64_t in_fd;
	int res;
	off_t offset = 0;

	/* Parameter 1: out_fd (type: PT_FD) */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	out_fd = (int64_t)(int32_t)val;
	res = val_to_ring(args, out_fd, 0, true, 0);
	CHECK_RES(res);

	/* Parameter 2: in_fd (type: PT_FD) */
	syscall_get_arguments_deprecated(args, 1, 1, &val);
	in_fd = (int64_t)(int32_t)val;
	res = val_to_ring(args, in_fd, 0, true, 0);
	CHECK_RES(res);

	/* Parameter 3: offset (type: PT_UINT64) */
	syscall_get_arguments_deprecated(args, 2, 1, &val);

	if(val != 0) {
#ifdef CONFIG_COMPAT
		if(!args->compat) {
#endif
			res = ppm_copy_from_user(&offset, (void *)val, sizeof(off_t));
#ifdef CONFIG_COMPAT
		} else {
			res = ppm_copy_from_user(&offset, (void *)compat_ptr(val), sizeof(compat_off_t));
		}
#endif
		if(unlikely(res))
			val = 0;
		else
			val = offset;
	}

	res = val_to_ring(args, val, 0, true, 0);
	CHECK_RES(res);

	/* Parameter 4: size (type: PT_UINT64) */
	syscall_get_arguments_deprecated(args, 3, 1, &val);
	res = val_to_ring(args, val, 0, true, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_sendfile_x(struct event_filler_arguments *args) {
	int64_t retval;
	int res;
	unsigned long val;
	off_t offset;
	int64_t out_fd;
	int64_t in_fd;

	/* Parameter 1: res (type: PT_ERRNO) */
	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 2: offset (type: PT_UINT64) */
	syscall_get_arguments_deprecated(args, 2, 1, &val);

	if(val != 0) {
#ifdef CONFIG_COMPAT
		if(!args->compat) {
#endif
			res = ppm_copy_from_user(&offset, (void *)val, sizeof(off_t));
#ifdef CONFIG_COMPAT
		} else {
			res = ppm_copy_from_user(&offset, (void *)compat_ptr(val), sizeof(compat_off_t));
		}
#endif
		if(unlikely(res))
			val = 0;
		else
			val = offset;
	}

	res = val_to_ring(args, val, 0, true, 0);
	CHECK_RES(res);

	/* Parameter 3: out_fd (type: PT_FD) */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	out_fd = (int64_t)(int32_t)val;
	res = val_to_ring(args, out_fd, 0, true, 0);
	CHECK_RES(res);

	/* Parameter 4: in_fd (type: PT_FD) */
	syscall_get_arguments_deprecated(args, 1, 1, &val);
	in_fd = (int64_t)(int32_t)val;
	res = val_to_ring(args, in_fd, 0, true, 0);
	CHECK_RES(res);

	/* Parameter 5: size (type: PT_UINT64) */
	syscall_get_arguments_deprecated(args, 3, 1, &val);
	res = val_to_ring(args, val, 0, true, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_quotactl_e(struct event_filler_arguments *args) {
	unsigned long val = 0;
	int res = 0;
	uint32_t id = 0;
	uint8_t quota_fmt = 0;
	uint32_t cmd = 0;
	uint16_t scap_cmd = 0;

	/* Parameter 1: cmd (type: PT_FLAGS16) */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	cmd = (uint32_t)val;
	scap_cmd = quotactl_cmd_to_scap(cmd);
	res = val_to_ring(args, scap_cmd, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 2: type (type: PT_FLAGS8) */
	res = val_to_ring(args, quotactl_type_to_scap(cmd), 0, false, 0);
	CHECK_RES(res);

	/* Parameter 3: id (type: PT_UINT32) */
	syscall_get_arguments_deprecated(args, 2, 1, &val);
	id = (uint32_t)val;
	if((scap_cmd != PPM_Q_GETQUOTA) && (scap_cmd != PPM_Q_SETQUOTA) &&
	   (scap_cmd != PPM_Q_XGETQUOTA) && (scap_cmd != PPM_Q_XSETQLIM)) {
		/* In this case `id` don't represent a `userid` or a `groupid` */
		res = val_to_ring(args, 0, 0, false, 0);
	} else {
		res = val_to_ring(args, id, 0, false, 0);
	}
	CHECK_RES(res);

	/* Parameter 4: quota_fmt (type: PT_FLAGS8) */
	quota_fmt = PPM_QFMT_NOT_USED;
	if(scap_cmd == PPM_Q_QUOTAON) {
		quota_fmt = quotactl_fmt_to_scap(id);
	}
	res = val_to_ring(args, quota_fmt, 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_quotactl_x(struct event_filler_arguments *args) {
	unsigned long val, len;
	int res;
	int64_t retval;
	uint32_t cmd;
	struct if_dqblk dqblk;
	struct if_dqinfo dqinfo;
	uint32_t quota_fmt_out;
	uint16_t scap_cmd;
	uint32_t id;
	uint8_t quota_fmt;

	/* Extract cmd. */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	cmd = (uint32_t)val;
	scap_cmd = quotactl_cmd_to_scap(cmd);

	/* Parameter 1: res (type: PT_ERRNO) */
	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 2: special (type: PT_CHARBUF) */
	syscall_get_arguments_deprecated(args, 1, 1, &val);
	res = val_to_ring(args, val, 0, true, 0);
	CHECK_RES(res);

	/*
	 * get addr
	 */
	syscall_get_arguments_deprecated(args, 3, 1, &val);

	/* Parameter 3: quotafilepath (type: PT_CHARBUF) */
	/* We get `quotafilepath` only for `QUOTAON` command. */
	if(scap_cmd == PPM_Q_QUOTAON)
		res = val_to_ring(args, val, 0, true, 0);
	else
		res = val_to_ring(args, 0, 0, false, 0);

	CHECK_RES(res);

	/*
	 * dqblk fields if present
	 */
	dqblk.dqb_valid = 0;
	if((scap_cmd == PPM_Q_GETQUOTA) || (scap_cmd == PPM_Q_SETQUOTA)) {
		len = ppm_copy_from_user(&dqblk, (void *)val, sizeof(struct if_dqblk));
		if(unlikely(len != 0))
			return PPM_FAILURE_INVALID_USER_MEMORY;
	}
	if(dqblk.dqb_valid & QIF_BLIMITS) {
		/* Parameter 4: dqb_bhardlimit (type: PT_UINT64) */
		res = val_to_ring(args, dqblk.dqb_bhardlimit, 0, false, 0);
		CHECK_RES(res);
		/* Parameter 5: dqb_bsoftlimit (type: PT_UINT64) */
		res = val_to_ring(args, dqblk.dqb_bsoftlimit, 0, false, 0);
		CHECK_RES(res);
	} else {
		/* Parameter 4: dqb_bhardlimit (type: PT_UINT64) */
		res = val_to_ring(args, 0, 0, false, 0);
		CHECK_RES(res);
		/* Parameter 5: dqb_bsoftlimit (type: PT_UINT64) */
		res = val_to_ring(args, 0, 0, false, 0);
		CHECK_RES(res);
	}

	/* Parameter 6: dqb_curspace (type: PT_UINT64) */
	if(dqblk.dqb_valid & QIF_SPACE) {
		res = val_to_ring(args, dqblk.dqb_curspace, 0, false, 0);
		CHECK_RES(res);
	} else {
		res = val_to_ring(args, 0, 0, false, 0);
		CHECK_RES(res);
	}

	if(dqblk.dqb_valid & QIF_ILIMITS) {
		/* Parameter 7: dqb_ihardlimit (type: PT_UINT64) */
		res = val_to_ring(args, dqblk.dqb_ihardlimit, 0, false, 0);
		CHECK_RES(res);
		/* Parameter 8: dqb_isoftlimit (type: PT_UINT64) */
		res = val_to_ring(args, dqblk.dqb_isoftlimit, 0, false, 0);
		CHECK_RES(res);
	} else {
		/* Parameter 7: dqb_ihardlimit (type: PT_UINT64) */
		res = val_to_ring(args, 0, 0, false, 0);
		CHECK_RES(res);
		/* Parameter 8: dqb_isoftlimit (type: PT_UINT64) */
		res = val_to_ring(args, 0, 0, false, 0);
		CHECK_RES(res);
	}

	/* Parameter 9: dqb_btime (type: PT_RELTIME) */
	if(dqblk.dqb_valid & QIF_BTIME) {
		res = val_to_ring(args, dqblk.dqb_btime, 0, false, 0);
		CHECK_RES(res);
	} else {
		res = val_to_ring(args, 0, 0, false, 0);
		CHECK_RES(res);
	}

	/* Parameter 10: dqb_itime (type: PT_RELTIME) */
	if(dqblk.dqb_valid & QIF_ITIME) {
		res = val_to_ring(args, dqblk.dqb_itime, 0, false, 0);
		CHECK_RES(res);
	} else {
		res = val_to_ring(args, 0, 0, false, 0);
		CHECK_RES(res);
	}

	/*
	 * dqinfo fields if present
	 */
	dqinfo.dqi_valid = 0;
	if((scap_cmd == PPM_Q_GETINFO) || (scap_cmd == PPM_Q_SETINFO)) {
		len = ppm_copy_from_user(&dqinfo, (void *)val, sizeof(struct if_dqinfo));
		if(unlikely(len != 0))
			return PPM_FAILURE_INVALID_USER_MEMORY;
	}

	/* Parameter 11: dqi_bgrace (type: PT_RELTIME) */
	if(dqinfo.dqi_valid & IIF_BGRACE) {
		res = val_to_ring(args, dqinfo.dqi_bgrace, 0, false, 0);
		CHECK_RES(res);
	} else {
		res = val_to_ring(args, 0, 0, false, 0);
		CHECK_RES(res);
	}

	/* Parameter 12: dqi_igrace (type: PT_RELTIME) */
	if(dqinfo.dqi_valid & IIF_IGRACE) {
		res = val_to_ring(args, dqinfo.dqi_igrace, 0, false, 0);
		CHECK_RES(res);
	} else {
		res = val_to_ring(args, 0, 0, false, 0);
		CHECK_RES(res);
	}

	/* Parameter 13: dqi_flags (type: PT_FLAGS8) */
	if(dqinfo.dqi_valid & IIF_FLAGS) {
		res = val_to_ring(args, dqinfo.dqi_flags, 0, false, 0);
		CHECK_RES(res);
	} else {
		res = val_to_ring(args, 0, 0, false, 0);
		CHECK_RES(res);
	}

	/* Parameter 14: quota_fmt_out (type: PT_FLAGS8) */
	quota_fmt_out = PPM_QFMT_NOT_USED;
	if(scap_cmd == PPM_Q_GETFMT) {
		len = ppm_copy_from_user(&quota_fmt_out, (void *)val, sizeof(uint32_t));
		if(unlikely(len != 0))
			return PPM_FAILURE_INVALID_USER_MEMORY;
		quota_fmt_out = quotactl_fmt_to_scap(quota_fmt_out);
	}
	res = val_to_ring(args, quota_fmt_out, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 15: cmd (type: PT_FLAGS16) */
	res = val_to_ring(args, scap_cmd, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 16: type (type: PT_FLAGS8) */
	res = val_to_ring(args, quotactl_type_to_scap(cmd), 0, false, 0);
	CHECK_RES(res);

	/* Parameter 17: id (type: PT_UINT32) */
	syscall_get_arguments_deprecated(args, 2, 1, &val);
	id = (uint32_t)val;
	if((scap_cmd != PPM_Q_GETQUOTA) && (scap_cmd != PPM_Q_SETQUOTA) &&
	   (scap_cmd != PPM_Q_XGETQUOTA) && (scap_cmd != PPM_Q_XSETQLIM)) {
		/* In this case `id` don't represent a `userid` or a `groupid` */
		res = val_to_ring(args, 0, 0, false, 0);
	} else {
		res = val_to_ring(args, id, 0, false, 0);
	}
	CHECK_RES(res);

	/* Parameter 18: quota_fmt (type: PT_FLAGS8) */
	quota_fmt = PPM_QFMT_NOT_USED;
	if(scap_cmd == PPM_Q_QUOTAON) {
		quota_fmt = quotactl_fmt_to_scap(id);
	}
	res = val_to_ring(args, quota_fmt, 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_scapevent_e(struct event_filler_arguments *args) {
	int res;

	/*
	 * event_type
	 */
	res = val_to_ring(args, (unsigned long)args->sched_prev, 0, false, 0);
	CHECK_RES(res);

	/*
	 * event_data
	 */
	res = val_to_ring(args, (unsigned long)args->sched_next, 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_getresuid_and_gid_x(struct event_filler_arguments *args) {
	int res;
	unsigned long val, len;
	uint32_t uid;
	int16_t retval;

	/*
	 * return value
	 */
	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	CHECK_RES(res);

	/*
	 * ruid
	 */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
#ifdef CONFIG_COMPAT
	if(!args->compat) {
#endif
		len = ppm_copy_from_user(&uid, (void *)val, sizeof(uint32_t));
#ifdef CONFIG_COMPAT
	} else {
		len = ppm_copy_from_user(&uid, (void *)compat_ptr(val), sizeof(uint32_t));
	}
#endif
	if(unlikely(len != 0))
		return PPM_FAILURE_INVALID_USER_MEMORY;

	res = val_to_ring(args, uid, 0, false, 0);
	CHECK_RES(res);

	/*
	 * euid
	 */
	syscall_get_arguments_deprecated(args, 1, 1, &val);
	len = ppm_copy_from_user(&uid, (void *)val, sizeof(uint32_t));
	if(unlikely(len != 0))
		return PPM_FAILURE_INVALID_USER_MEMORY;

	res = val_to_ring(args, uid, 0, false, 0);
	CHECK_RES(res);

	/*
	 * suid
	 */
	syscall_get_arguments_deprecated(args, 2, 1, &val);
	len = ppm_copy_from_user(&uid, (void *)val, sizeof(uint32_t));
	if(unlikely(len != 0))
		return PPM_FAILURE_INVALID_USER_MEMORY;

	res = val_to_ring(args, uid, 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_flock_e(struct event_filler_arguments *args) {
	unsigned long val;
	int64_t fd;
	int res;
	uint32_t flags;

	/* Parameter 1: fd (type: PT_FD) */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	fd = (int64_t)(int32_t)val;
	res = val_to_ring(args, fd, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 2: operation (type: PT_FLAGS32) */
	syscall_get_arguments_deprecated(args, 1, 1, &val);
	flags = flock_flags_to_scap((int)val);
	res = val_to_ring(args, flags, 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_flock_x(struct event_filler_arguments *args) {
	int64_t retval;
	int res;
	unsigned long val;
	int64_t fd;
	uint32_t flags;

	/* Parameter 1: res (type: PT_ERRNO) */
	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 2: fd (type: PT_FD) */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	fd = (int64_t)(int32_t)val;
	res = val_to_ring(args, fd, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 3: operation (type: PT_FLAGS32) */
	syscall_get_arguments_deprecated(args, 1, 1, &val);
	flags = flock_flags_to_scap((int)val);
	res = val_to_ring(args, flags, 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_ioctl_e(struct event_filler_arguments *args) {
	unsigned long val = 0;
	int res = 0;
	int32_t fd = 0;

	/* Parameter 1: fd (type: PT_FD) */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	fd = (int32_t)val;
	res = val_to_ring(args, (int64_t)fd, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 2: request (type: PT_UINT64) */
	syscall_get_arguments_deprecated(args, 1, 1, &val);
	res = val_to_ring(args, val, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 3: argument (type: PT_UINT64) */
	syscall_get_arguments_deprecated(args, 2, 1, &val);
	res = val_to_ring(args, val, 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_ioctl_x(struct event_filler_arguments *args) {
	int64_t retval;
	unsigned long val = 0;
	int res = 0;
	int32_t fd = 0;

	/* Parameter 1: res (type: PT_ERRNO) */
	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 2: fd (type: PT_FD) */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	fd = (int32_t)val;
	res = val_to_ring(args, (int64_t)fd, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 3: request (type: PT_UINT64) */
	syscall_get_arguments_deprecated(args, 1, 1, &val);
	res = val_to_ring(args, val, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 4: argument (type: PT_UINT64) */
	syscall_get_arguments_deprecated(args, 2, 1, &val);
	res = val_to_ring(args, val, 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_mkdir_e(struct event_filler_arguments *args) {
	unsigned long val = 0;
	int res = 0;

	/* Parameter 1: mode (type: PT_UINT32) */
	syscall_get_arguments_deprecated(args, 1, 1, &val);
	res = val_to_ring(args, val, 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_mkdir_x(struct event_filler_arguments *args) {
	unsigned long val = 0;
	int res = 0;
	long retval = 0;

	/* Parameter 1: res (type: PT_ERRNO) */
	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 2: path (type: PT_FSPATH) */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	res = val_to_ring(args, val, 0, true, 0);
	CHECK_RES(res);

	/* Parameter 3: mode (type: PT_UINT32) */
	syscall_get_arguments_deprecated(args, 1, 1, &val);
	res = val_to_ring(args, val, 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_setns_e(struct event_filler_arguments *args) {
	unsigned long val = 0;
	int res = 0;
	int32_t fd = 0;

	/* Parameter 1: fd (type: PT_FD) */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	fd = (int32_t)val;
	res = val_to_ring(args, (int64_t)fd, 0, true, 0);
	CHECK_RES(res);

	/* Parameter 2: nstype (type: PT_FLAGS32) */
	syscall_get_arguments_deprecated(args, 1, 1, &val);
	res = val_to_ring(args, clone_flags_to_scap((int)val), 0, true, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_setns_x(struct event_filler_arguments *args) {
	unsigned long val = 0;
	int res = 0;
	int32_t fd = 0;
	int64_t retval = 0;

	/* Parameter 1: res (type: PT_ERRNO) */
	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 2: fd (type: PT_FD) */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	fd = (int32_t)val;
	res = val_to_ring(args, (int64_t)fd, 0, true, 0);
	CHECK_RES(res);

	/* Parameter 3: nstype (type: PT_FLAGS32) */
	syscall_get_arguments_deprecated(args, 1, 1, &val);
	res = val_to_ring(args, clone_flags_to_scap((int)val), 0, true, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_setgid_x(struct event_filler_arguments *args) {
	unsigned long val = 0;
	int res = 0;
	uint32_t gid = 0;

	/* Parameter 1: res (type: PT_ERRNO) */
	int64_t retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 2: gid (type: PT_GID) */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	gid = (uint32_t)val;
	res = val_to_ring(args, gid, 0, true, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_setpgid_e(struct event_filler_arguments *args) {
	unsigned long val = 0;
	int res = 0;
	pid_t pid = 0;
	pid_t pgid = 0;

	/* Parameter 1: pid (type: PT_FD) */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	pid = (int32_t)val;
	res = val_to_ring(args, (int64_t)pid, 0, true, 0);
	CHECK_RES(res);

	/* Parameter 2: pgid (type: PT_PID) */
	syscall_get_arguments_deprecated(args, 1, 1, &val);
	pgid = (int32_t)val;
	res = val_to_ring(args, (int64_t)pgid, 0, true, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_setpgid_x(struct event_filler_arguments *args) {
	unsigned long val = 0;
	int res = 0;
	pid_t pid = 0;
	pid_t pgid = 0;

	/* Parameter 1: res (type: PT_ERRNO) */
	int64_t retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 2: pid (type: PT_FD) */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	pid = (int32_t)val;
	res = val_to_ring(args, (int64_t)pid, 0, true, 0);
	CHECK_RES(res);

	/* Parameter 3: pgid (type: PT_PID) */
	syscall_get_arguments_deprecated(args, 1, 1, &val);
	pgid = (int32_t)val;
	res = val_to_ring(args, (int64_t)pgid, 0, true, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_setresgid_x(struct event_filler_arguments *args) {
	unsigned long val = 0;
	int res = 0;
	uint32_t gid = 0;

	/* Parameter 1: res (type: PT_ERRNO) */
	int64_t retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 2: rgid (type: PT_GID) */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	gid = (uint32_t)val;
	res = val_to_ring(args, gid, 0, true, 0);
	CHECK_RES(res);

	/* Parameter 3: egid (type: PT_GID) */
	syscall_get_arguments_deprecated(args, 1, 1, &val);
	gid = (uint32_t)val;
	res = val_to_ring(args, gid, 0, true, 0);
	CHECK_RES(res);

	/* Parameter 4: sgid (type: PT_GID) */
	syscall_get_arguments_deprecated(args, 2, 1, &val);
	gid = (uint32_t)val;
	res = val_to_ring(args, gid, 0, true, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_unshare_e(struct event_filler_arguments *args) {
	unsigned long val;
	int res;
	uint32_t flags;

	/* Parameter 1: flags (type: PT_FLAGS32) */
	/* Parse flags as clone flags as it's a subset of it. */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	flags = clone_flags_to_scap((int)val);
	res = val_to_ring(args, flags, 0, true, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_unshare_x(struct event_filler_arguments *args) {
	int64_t retval;
	int res;
	unsigned long val;
	uint32_t flags;

	/* Parameter 1: res (type: PT_ERRNO) */
	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 2: flags (type: PT_FLAGS32) */
	/* Parse flags as clone flags as it's a subset of it. */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	flags = clone_flags_to_scap((int)val);
	res = val_to_ring(args, flags, 0, true, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

#ifdef CAPTURE_SIGNAL_DELIVERIES
int f_sys_signaldeliver_e(struct event_filler_arguments *args) {
	int res;

	/*
	 * source pid
	 */
	res = val_to_ring(args, args->spid, 0, false, 0);
	CHECK_RES(res);

	/*
	 * destination pid
	 */
	res = val_to_ring(args, args->dpid, 0, false, 0);
	CHECK_RES(res);

	/*
	 * signal number
	 */
	res = val_to_ring(args, args->signo, 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}
#endif

#ifdef CAPTURE_PAGE_FAULTS
int f_sys_pagefault_e(struct event_filler_arguments *args) {
	int res;

	res = val_to_ring(args, args->fault_data.address, 0, false, 0);
	CHECK_RES(res);

	res = val_to_ring(args, args->fault_data.regs->ip, 0, false, 0);
	CHECK_RES(res);

	res = val_to_ring(args, pf_flags_to_scap(args->fault_data.error_code), 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}
#endif

int f_cpu_hotplug_e(struct event_filler_arguments *args) {
	int res;

	/*
	 * cpu
	 */
	res = val_to_ring(args, (uint64_t)args->sched_prev, 0, false, 0);
	CHECK_RES(res);

	/*
	 * action
	 */
	res = val_to_ring(args, (uint64_t)args->sched_next, 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_semop_x(struct event_filler_arguments *args) {
	unsigned long nsops = 0;
	int res = 0;
	long retval = 0;
	struct sembuf *sops_pointer = NULL;
	struct sembuf sops[2] = {0};
	unsigned long val;

	/* Parameter 1: res (type: PT_ERRNO) */
	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 2: nsops (type: PT_UINT32) */
	syscall_get_arguments_deprecated(args, 2, 1, &nsops);
	res = val_to_ring(args, nsops, 0, true, 0);
	CHECK_RES(res);

	/* Extract pointer to the `sembuf` struct */
	syscall_get_arguments_deprecated(args, 1, 1, (unsigned long *)&sops_pointer);

	if(retval != 0 || sops_pointer == 0 || nsops == 0) {
		/* We send all 0 when one of these is true:
		 * - the syscall fails (retval != 0)
		 * - `sops_pointer` is NULL
		 * - `nsops` is 0
		 */
	} else if(nsops == 1) {
		/* If we have just one entry the second will be empty, we don't fill it */
		if(unlikely(ppm_copy_from_user(sops, (void *)sops_pointer, sizeof(struct sembuf)))) {
			memset(&sops, 0, sizeof(sops));
		}
	} else {
		/* If `nsops>1` we read just the first 2 entries. */
		if(unlikely(ppm_copy_from_user(sops, (void *)sops_pointer, 2 * sizeof(struct sembuf)))) {
			memset(&sops, 0, sizeof(sops));
		}
	}

	/* Parameter 3: sem_num_0 (type: PT_UINT16) */
	res = val_to_ring(args, sops[0].sem_num, 0, true, 0);
	CHECK_RES(res);

	/* Parameter 4: sem_op_0 (type: PT_INT16) */
	res = val_to_ring(args, sops[0].sem_op, 0, true, 0);
	CHECK_RES(res);

	/* Parameter 5: sem_flg_0 (type: PT_FLAGS16) */
	res = val_to_ring(args, semop_flags_to_scap(sops[0].sem_flg), 0, true, 0);
	CHECK_RES(res);

	/* Parameter 6: sem_num_1 (type: PT_UINT16) */
	res = val_to_ring(args, sops[1].sem_num, 0, true, 0);
	CHECK_RES(res);

	/* Parameter 7: sem_op_1 (type: PT_INT16) */
	res = val_to_ring(args, sops[1].sem_op, 0, true, 0);
	CHECK_RES(res);

	/* Parameter 8: sem_flg_1 (type: PT_FLAGS16) */
	res = val_to_ring(args, semop_flags_to_scap(sops[1].sem_flg), 0, true, 0);
	CHECK_RES(res);

	/* Parameter 9: semid (type: PT_INT32) */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	res = val_to_ring(args, (int32_t)val, 0, true, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_semget_e(struct event_filler_arguments *args) {
	unsigned long val;
	int res;

	/* Parameter 1: key (type: PT_INT32) */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	res = val_to_ring(args, val, 0, true, 0);
	CHECK_RES(res);

	/* Parameter 2: nsems (type: PT_INT32) */
	syscall_get_arguments_deprecated(args, 1, 1, &val);
	res = val_to_ring(args, val, 0, true, 0);
	CHECK_RES(res);

	/* Parameter 3: semflg (type: PT_FLAGS32) */
	syscall_get_arguments_deprecated(args, 2, 1, &val);
	res = val_to_ring(args, semget_flags_to_scap(val), 0, true, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_semget_x(struct event_filler_arguments *args) {
	int64_t retval;
	unsigned long val;
	int res;

	/* Parameter 1: res (type: PT_ERRNO) */
	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 2: key (type: PT_INT32) */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	res = val_to_ring(args, val, 0, true, 0);
	CHECK_RES(res);

	/* Parameter 3: nsems (type: PT_INT32) */
	syscall_get_arguments_deprecated(args, 1, 1, &val);
	res = val_to_ring(args, val, 0, true, 0);
	CHECK_RES(res);

	/* Parameter 4: semflg (type: PT_FLAGS32) */
	syscall_get_arguments_deprecated(args, 2, 1, &val);
	res = val_to_ring(args, semget_flags_to_scap(val), 0, true, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_semctl_e(struct event_filler_arguments *args) {
	unsigned long val;
	int res;

	/* Parameter 1: semid (type: PT_INT32) */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	res = val_to_ring(args, val, 0, true, 0);
	CHECK_RES(res);

	/* Parameter 2: semnum (type: PT_INT32) */
	syscall_get_arguments_deprecated(args, 1, 1, &val);
	res = val_to_ring(args, val, 0, true, 0);
	CHECK_RES(res);

	/* Parameter 3: cmd (type: PT_FLAGS16) */
	syscall_get_arguments_deprecated(args, 2, 1, &val);
	res = val_to_ring(args, semctl_cmd_to_scap(val), 0, true, 0);
	CHECK_RES(res);

	/* Parameter 4: val (type: PT_INT32) */
	if(val == SETVAL)
		syscall_get_arguments_deprecated(args, 3, 1, &val);
	else
		val = 0;
	res = val_to_ring(args, val, 0, true, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_semctl_x(struct event_filler_arguments *args) {
	int64_t retval;
	int res;
	unsigned long val;

	/* Parameter 1: res (type: PT_ERRNO) */
	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 2: semid (type: PT_INT32) */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	res = val_to_ring(args, val, 0, true, 0);
	CHECK_RES(res);

	/* Parameter 3: semnum (type: PT_INT32) */
	syscall_get_arguments_deprecated(args, 1, 1, &val);
	res = val_to_ring(args, val, 0, true, 0);
	CHECK_RES(res);

	/* Parameter 4: cmd (type: PT_FLAGS16) */
	syscall_get_arguments_deprecated(args, 2, 1, &val);
	res = val_to_ring(args, semctl_cmd_to_scap(val), 0, true, 0);
	CHECK_RES(res);

	/* Parameter 5: val (type: PT_INT32) */
	if(val == SETVAL)
		syscall_get_arguments_deprecated(args, 3, 1, &val);
	else
		val = 0;
	res = val_to_ring(args, val, 0, true, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_access_e(struct event_filler_arguments *args) {
	unsigned long val;
	int res;

	/* Parameter 1: mode (type: PT_UINT32) */
	syscall_get_arguments_deprecated(args, 1, 1, &val);
	res = val_to_ring(args, access_flags_to_scap(val), 0, true, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_access_x(struct event_filler_arguments *args) {
	int64_t retval;
	int res;
	unsigned long val;

	/* Parameter 1: res (type: PT_ERRNO) */
	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 2: name (type: PT_FSPATH) */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	res = val_to_ring(args, val, 0, true, 0);
	CHECK_RES(res);

	/* Parameter 3: mode (type: PT_UINT32) */
	syscall_get_arguments_deprecated(args, 1, 1, &val);
	res = val_to_ring(args, access_flags_to_scap(val), 0, true, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_fchdir_e(struct event_filler_arguments *args) {
	int res = 0;
	int32_t fd = 0;
	unsigned long val = 0;

	/* Parameter 1: fd (type: PT_FD)*/
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	fd = (int32_t)val;
	res = val_to_ring(args, (int64_t)fd, 0, false, 0);
	CHECK_RES(res);
	return add_sentinel(args);
}

int f_sys_fchdir_x(struct event_filler_arguments *args) {
	int64_t res = 0;
	int32_t fd = 0;
	unsigned long val = 0;

	/* Parameter 1: res (type: PT_ERRNO)*/
	res = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, res, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 2: fd (type: PT_FD)*/
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	fd = (int32_t)val;
	res = val_to_ring(args, (int64_t)fd, 0, false, 0);
	CHECK_RES(res);
	return add_sentinel(args);
}

int f_sys_close_e(struct event_filler_arguments *args) {
	unsigned long val = 0;
	int64_t fd;
	int res;

	/* Parameter 1: fd (type: PT_FD) */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	fd = (int64_t)(int32_t)val;
	res = val_to_ring(args, fd, 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_close_x(struct event_filler_arguments *args) {
	int64_t retval = 0;
	int res;
	unsigned long val = 0;
	int64_t fd;

	/* Parameter 1: res (type: PT_ERRNO) */
	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 2: fd (type: PT_FD) */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	fd = (int64_t)(int32_t)val;
	res = val_to_ring(args, fd, 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_socket_x(struct event_filler_arguments *args) {
	int64_t res = 0;
	int64_t retval = 0;
	unsigned long val = 0;
	uint32_t domain;

	/* Parameter 1: fd (type: PT_FD) */
	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 2: domain (type: PT_ENUMFLAGS32) */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	domain = socket_family_to_scap((uint8_t)val);
	res = val_to_ring(args, domain, 0, true, 0);
	CHECK_RES(res);

	/* Parameter 3: type (type: PT_UINT32) */
	syscall_get_arguments_deprecated(args, 1, 1, &val);
	res = val_to_ring(args, val, 0, true, 0);
	CHECK_RES(res);

	/* Parameter 4: proto (type: PT_UINT32) */
	syscall_get_arguments_deprecated(args, 2, 1, &val);
	res = val_to_ring(args, val, 0, true, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_bpf_e(struct event_filler_arguments *args) {
	int res = 0;
	int32_t cmd = 0;
	unsigned long val = 0;
	syscall_get_arguments_deprecated(args, 0, 1, &val);

	/* Parameter 1: cmd (type: PT_ENUMFLAGS32) */
	cmd = (int32_t)val;
	res = val_to_ring(args, (int64_t)cmd, 0, false, 0);
	CHECK_RES(res);
	return add_sentinel(args);
}

int f_sys_bpf_x(struct event_filler_arguments *args) {
	int res = 0;
	int64_t fd = 0;
	unsigned long val = 0;
	int32_t cmd = 0;

	/* Parameter 1: fd (type: PT_DEC) */
	fd = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, fd, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 2: cmd (type: PT_INT64) */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	cmd = (int32_t)bpf_cmd_to_scap(val);
	res = val_to_ring(args, cmd, 0, false, 0);
	CHECK_RES(res);
	return add_sentinel(args);
}

int f_sys_seccomp_x(struct event_filler_arguments *args) {
	int64_t retval;
	int res;
	unsigned long val;
	uint64_t op;
	uint64_t flags;

	/* Parameter 1: res (type: PT_ERRNO) */
	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 2: op (type: PT_UINT64) */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	op = (uint64_t)(uint32_t)val;
	res = val_to_ring(args, op, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 3: flags (type: PT_UINT64) */
	syscall_get_arguments_deprecated(args, 1, 1, &val);
	flags = (uint64_t)val;
	res = val_to_ring(args, flags, 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_mkdirat_x(struct event_filler_arguments *args) {
	unsigned long val = 0;
	int res = 0;
	int64_t retval = 0;
	int32_t dirfd = 0;

	/* Parameter 1: res (type: PT_ERRNO) */
	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 2: dirfd (type: PT_FD) */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	dirfd = (int32_t)val;
	if(dirfd == AT_FDCWD) {
		dirfd = PPM_AT_FDCWD;
	}
	res = val_to_ring(args, (int64_t)dirfd, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 3: path (type: PT_FSRELPATH) */
	syscall_get_arguments_deprecated(args, 1, 1, &val);
	res = val_to_ring(args, val, 0, true, 0);
	CHECK_RES(res);

	/* Parameter 4: mode (type: PT_UINT32) */
	syscall_get_arguments_deprecated(args, 2, 1, &val);
	res = val_to_ring(args, val, 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_fchmodat_x(struct event_filler_arguments *args) {
	unsigned long val = 0;
	int res = 0;
	int64_t retval = 0;
	int32_t dirfd = 0;

	/* Parameter 1: res (type: PT_ERRNO) */
	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 2: dirfd (type: PT_FD) */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	dirfd = (int32_t)val;
	if(dirfd == AT_FDCWD) {
		dirfd = PPM_AT_FDCWD;
	}
	res = val_to_ring(args, (int64_t)dirfd, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 3: filename (type: PT_FSRELPATH) */
	syscall_get_arguments_deprecated(args, 1, 1, &val);
	res = val_to_ring(args, val, 0, true, 0);
	CHECK_RES(res);

	/* Parameter 4: mode (type: PT_MODE) */
	syscall_get_arguments_deprecated(args, 2, 1, &val);
	res = val_to_ring(args, chmod_mode_to_scap(val), 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_chmod_x(struct event_filler_arguments *args) {
	unsigned long val;
	int res;
	int64_t retval;

	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	CHECK_RES(res);

	/*
	 * filename
	 */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	res = val_to_ring(args, val, 0, true, 0);
	CHECK_RES(res);

	/*
	 * mode
	 */
	syscall_get_arguments_deprecated(args, 1, 1, &val);
	res = val_to_ring(args, chmod_mode_to_scap(val), 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_fchmod_x(struct event_filler_arguments *args) {
	unsigned long val = 0;
	int res = 0;
	int64_t retval = 0;
	int32_t fd = 0;

	/* Parameter 1: res (type: PT_ERRNO) */
	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 2: fd (type: PT_FD) */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	fd = (int32_t)val;
	res = val_to_ring(args, (int64_t)fd, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 3: mode (type: PT_MODE) */
	syscall_get_arguments_deprecated(args, 1, 1, &val);
	res = val_to_ring(args, chmod_mode_to_scap(val), 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_chown_x(struct event_filler_arguments *args) {
	unsigned long val;
	int res;
	int64_t retval;

	/* Parameter 1: res (type: PT_ERRNO)*/
	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 2: path (type: PT_FSPATH) */
	syscall_get_arguments_deprecated(args, 0, 1, &val);

	res = val_to_ring(args, val, 0, true, 0);
	CHECK_RES(res);

	/* Parameter 3: uid (type: PT_UINT32) */
	syscall_get_arguments_deprecated(args, 1, 1, &val);

	res = val_to_ring(args, val, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 4: gid (type: PT_UINT32) */
	syscall_get_arguments_deprecated(args, 2, 1, &val);

	res = val_to_ring(args, val, 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_lchown_x(struct event_filler_arguments *args) {
	unsigned long val;
	int res;
	int64_t retval;

	/* Parameter 1: res (type: PT_ERRNO)*/
	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 2: path (type: PT_FSPATH) */
	syscall_get_arguments_deprecated(args, 0, 1, &val);

	res = val_to_ring(args, val, 0, true, 0);
	CHECK_RES(res);

	/* Parameter 3: uid (type: PT_UINT32) */
	syscall_get_arguments_deprecated(args, 1, 1, &val);

	res = val_to_ring(args, val, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 4: gid (type: PT_UINT32) */
	syscall_get_arguments_deprecated(args, 2, 1, &val);

	res = val_to_ring(args, val, 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_fchown_x(struct event_filler_arguments *args) {
	unsigned long val;
	int res;
	int64_t retval;
	int32_t fd;

	/* Parameter 1: res (type: PT_ERRNO)*/
	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 2: fd (type: PT_FD) */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	fd = (int32_t)val;
	res = val_to_ring(args, (int64_t)fd, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 3: uid (type: PT_UINT32) */
	syscall_get_arguments_deprecated(args, 1, 1, &val);

	res = val_to_ring(args, val, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 4: gid (type: PT_UINT32) */
	syscall_get_arguments_deprecated(args, 2, 1, &val);

	res = val_to_ring(args, val, 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_fchownat_x(struct event_filler_arguments *args) {
	unsigned long val;
	int res;
	int64_t retval;
	int32_t fd;

	/* Parameter 1: res (type: PT_ERRNO)*/
	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 2: dirfd (type: PT_FD) */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	fd = (int32_t)val;

	if(fd == AT_FDCWD)
		fd = PPM_AT_FDCWD;

	res = val_to_ring(args, (int64_t)fd, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 3: pathname (type: PT_FSRELPATH) */
	syscall_get_arguments_deprecated(args, 1, 1, &val);

	res = val_to_ring(args, val, 0, true, 0);
	CHECK_RES(res);

	/* Parameter 4: uid (type: PT_UINT32) */
	syscall_get_arguments_deprecated(args, 2, 1, &val);

	res = val_to_ring(args, val, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 5: gid (type: PT_UINT32) */
	syscall_get_arguments_deprecated(args, 3, 1, &val);

	res = val_to_ring(args, val, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 6: flags (type: PT_FLAGS32) */
	syscall_get_arguments_deprecated(args, 4, 1, &val);
	res = val_to_ring(args, fchownat_flags_to_scap(val), 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_capset_x(struct event_filler_arguments *args) {
	unsigned long val;
	int res;
	int64_t retval;
	const struct cred *cred;

	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	CHECK_RES(res);

	cred = get_current_cred();
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 3, 0)
	val = ((uint64_t)cred->cap_inheritable.cap[1] << 32) | cred->cap_inheritable.cap[0];
#else
	val = (uint64_t)cred->cap_inheritable.val;
#endif
	res = val_to_ring(args, capabilities_to_scap(val), 0, false, 0);
	if(unlikely(res != PPM_SUCCESS))
		goto out;

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 3, 0)
	val = ((uint64_t)cred->cap_permitted.cap[1] << 32) | cred->cap_permitted.cap[0];
#else
	val = (uint64_t)cred->cap_permitted.val;
#endif
	res = val_to_ring(args, capabilities_to_scap(val), 0, false, 0);
	if(unlikely(res != PPM_SUCCESS))
		goto out;

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 3, 0)
	val = ((uint64_t)cred->cap_effective.cap[1] << 32) | cred->cap_effective.cap[0];
#else
	val = (uint64_t)cred->cap_effective.val;
#endif
	res = val_to_ring(args, capabilities_to_scap(val), 0, false, 0);
	if(unlikely(res != PPM_SUCCESS))
		goto out;

	put_cred(cred);

	return add_sentinel(args);

out:
	put_cred(cred);
	return res;
}

int f_sys_splice_e(struct event_filler_arguments *args) {
	unsigned long val;
	int64_t fd_in, fd_out;
	int res;

	/* Parameter 1: fd_in (type: PT_FD) */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	fd_in = (int64_t)(int32_t)val;
	res = val_to_ring(args, fd_in, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 2: fd_out (type: PT_FD) */
	syscall_get_arguments_deprecated(args, 2, 1, &val);
	fd_out = (int64_t)(int32_t)val;
	res = val_to_ring(args, fd_out, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 3: size (type: PT_UINT64) */
	syscall_get_arguments_deprecated(args, 4, 1, &val);
	res = val_to_ring(args, val, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 4: flags (type: PT_FLAGS32) */
	syscall_get_arguments_deprecated(args, 5, 1, &val);
	res = val_to_ring(args, splice_flags_to_scap(val), 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_splice_x(struct event_filler_arguments *args) {
	int64_t retval;
	int res;
	unsigned long val;
	int64_t fd_in, fd_out;

	/* Parameter 1: res (type: PT_ERRNO) */
	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 2: fd_in (type: PT_FD) */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	fd_in = (int64_t)(int32_t)val;
	res = val_to_ring(args, fd_in, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 3: fd_out (type: PT_FD) */
	syscall_get_arguments_deprecated(args, 2, 1, &val);
	fd_out = (int64_t)(int32_t)val;
	res = val_to_ring(args, fd_out, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 4: size (type: PT_UINT64) */
	syscall_get_arguments_deprecated(args, 4, 1, &val);
	res = val_to_ring(args, val, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 5: flags (type: PT_FLAGS32) */
	syscall_get_arguments_deprecated(args, 5, 1, &val);
	res = val_to_ring(args, splice_flags_to_scap(val), 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_umount_x(struct event_filler_arguments *args) {
	unsigned long val;
	int res;
	int64_t retval;

	/* Parameter 1: res (type: PT_ERRNO) */
	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 2: name (type: PT_FSPATH) */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	res = val_to_ring(args, val, 0, true, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_umount2_e(struct event_filler_arguments *args) {
	unsigned long val;
	int res;

	/* Parameter 1: flags (type: PT_FLAGS32) */
	syscall_get_arguments_deprecated(args, 1, 1, &val);
	res = val_to_ring(args, umount2_flags_to_scap(val), 0, true, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_umount2_x(struct event_filler_arguments *args) {
	unsigned long val;
	int res;
	int64_t retval;

	/* Parameter 1: res (type: PT_ERRNO) */
	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 2: name (type: PT_FSPATH) */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	res = val_to_ring(args, val, 0, true, 0);
	CHECK_RES(res);

	/* Parameter 3: flags (type: PT_FLAGS32) */
	syscall_get_arguments_deprecated(args, 1, 1, &val);
	res = val_to_ring(args, umount2_flags_to_scap(val), 0, true, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_getcwd_x(struct event_filler_arguments *args) {
	unsigned long val;

	/* Parameter 1: res (type: PT_ERRNO) */
	long retval = syscall_get_return_value(current, args->regs);
	int res = val_to_ring(args, retval, 0, false, 0);
	CHECK_RES(res);

	/* we get the path only in case of success, in case of failure we would read only userspace junk
	 */
	if(retval >= 0) {
		/* Parameter 2: path (type: PT_CHARBUF) */
		syscall_get_arguments_deprecated(args, 0, 1, &val);
		res = val_to_ring(args, val, 0, true, 0);
	} else {
		/* Parameter 2: path (type: PT_CHARBUF) */
		push_empty_param(args);
	}

	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_getdents_e(struct event_filler_arguments *args) {
	unsigned long val;
	int64_t fd;
	int res;

	/* Parameter 1: fd (type: PT_FD) */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	fd = (int64_t)(int32_t)val;
	res = val_to_ring(args, fd, 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_getdents_x(struct event_filler_arguments *args) {
	int64_t retval;
	int res;
	unsigned long val;
	int64_t fd;

	/* Parameter 1: res (type: PT_ERRNO) */
	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 2: fd (type: PT_FD) */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	fd = (int64_t)(int32_t)val;
	res = val_to_ring(args, fd, 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_getdents64_e(struct event_filler_arguments *args) {
	unsigned long val;
	int64_t fd;
	int res;

	/* Parameter 1: fd (type: PT_FD) */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	fd = (int64_t)(int32_t)val;
	res = val_to_ring(args, fd, 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_getdents64_x(struct event_filler_arguments *args) {
	int64_t retval;
	int res;
	unsigned long val;
	int64_t fd;

	/* Parameter 1: res (type: PT_ERRNO) */
	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 2: fd (type: PT_FD) */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	fd = (int64_t)(int32_t)val;
	res = val_to_ring(args, fd, 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

#ifdef CAPTURE_SCHED_PROC_EXEC
int f_sched_prog_exec(struct event_filler_arguments *args) {
	int res = 0;
	struct mm_struct *mm = current->mm;
	int args_len = 0;
	int correctly_read = 0;
	unsigned int exe_len = 0; /* the length of the executable string. */
	int ptid = 0;
	long total_vm = 0;
	long total_rss = 0;
	long swap = 0;
	int available = STR_STORAGE_SIZE;
	long env_len = 0;
	uint32_t tty_nr = 0;
	uint32_t flags = 0;
	bool exe_writable = false;
	enum ppm_overlay exe_layer = PPM_NOT_OVERLAY_FS;
	struct file *exe_file = NULL;
	const struct cred *cred = NULL;
	unsigned long i_ino = 0;
	unsigned long ctime = 0;
	unsigned long mtime = 0;
	uint32_t loginuid = UINT32_MAX;
	uint64_t cap_inheritable = 0;
	uint64_t cap_permitted = 0;
	uint64_t cap_effective = 0;
	uint32_t euid = UINT32_MAX;
	uint32_t egid = UINT32_MAX;
	char *buf = (char *)args->str_storage;
	char *trusted_exepath = NULL;

	/* Parameter 1: res (type: PT_ERRNO) */
	/* Please note: if this filler is called the execve is correctly
	 * performed, so the return value will be always 0.
	 */
	res = val_to_ring(args, 0, 0, false, 0);
	CHECK_RES(res);
	/*
	 * The call always succeed so get `exe`, `args` from the current
	 * process; put one \0-separated exe-args string into
	 * str_storage
	 */
	if(unlikely(!mm)) {
		args->str_storage[0] = 0;
		pr_info("'f_sched_prog_exec' drop, mm=NULL\n");
		return PPM_FAILURE_BUG;
	}

	if(unlikely(!mm->arg_end)) {
		args->str_storage[0] = 0;
		pr_info("'f_sched_prog_exec' drop, mm->arg_end=NULL\n");
		return PPM_FAILURE_BUG;
	}

	/* the combined length of the arguments string + executable string. */
	args_len = mm->arg_end - mm->arg_start;

	if(args_len > STR_STORAGE_SIZE) {
		args_len = STR_STORAGE_SIZE;
	}

	correctly_read =
	        ppm_copy_from_user(args->str_storage, (const void __user *)mm->arg_start, args_len);

	if(args_len && correctly_read == 0) {
		args->str_storage[args_len - 1] = 0;
	} else {
		args_len = 0;
		*args->str_storage = 0;
	}

	exe_len = strnlen(args->str_storage, args_len);
	if(exe_len < args_len) {
		++exe_len;
	}

	/* Parameter 2: exe (type: PT_CHARBUF) */
	res = val_to_ring(args, (uint64_t)(long)args->str_storage, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 3: args (type: PT_CHARBUFARRAY) */
	res = val_to_ring(args,
	                  (int64_t)(long)args->str_storage + exe_len,
	                  args_len - exe_len,
	                  false,
	                  0);
	CHECK_RES(res);

	/* Parameter 4: tid (type: PT_PID) */
	res = val_to_ring(args, (int64_t)current->pid, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 5: pid (type: PT_PID) */
	res = val_to_ring(args, (int64_t)current->tgid, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 6: ptid (type: PT_PID) */
	if(current->real_parent) {
		ptid = current->real_parent->pid;
	}

	res = val_to_ring(args, (int64_t)ptid, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 7: cwd (type: PT_CHARBUF)
	 * cwd, pushed empty to avoid breaking compatibility
	 * with the older event format
	 */
	res = push_empty_param(args);
	CHECK_RES(res);

	/* Parameter 8: fdlimit (type: PT_UINT64) */
	res = val_to_ring(args, (int64_t)rlimit(RLIMIT_NOFILE), 0, false, 0);
	CHECK_RES(res);

	/* Parameter 9: pgft_maj (type: PT_UINT64) */
	res = val_to_ring(args, current->maj_flt, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 10: pgft_min (type: PT_UINT64) */
	res = val_to_ring(args, current->min_flt, 0, false, 0);
	CHECK_RES(res);

	if(mm) {
		total_vm = mm->total_vm << (PAGE_SHIFT - 10);
		total_rss = ppm_get_mm_rss(mm) << (PAGE_SHIFT - 10);
		swap = ppm_get_mm_swap(mm) << (PAGE_SHIFT - 10);
	}

	/* Parameter 11: vm_size (type: PT_UINT32) */
	res = val_to_ring(args, total_vm, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 12: vm_rss (type: PT_UINT32) */
	res = val_to_ring(args, total_rss, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 13: vm_swap (type: PT_UINT32) */
	res = val_to_ring(args, swap, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 14: comm (type: PT_CHARBUF) */
	res = val_to_ring(args, (uint64_t)current->comm, 0, false, 0);
	CHECK_RES(res);

	args->str_storage[0] = 0;
#ifdef CONFIG_CGROUPS
	rcu_read_lock();
#include <linux/cgroup_subsys.h>
cgroups_error:
	rcu_read_unlock();
#endif

	/* Parameter 15: cgroups (type: PT_CHARBUFARRAY) */
	res = val_to_ring(args,
	                  (int64_t)(long)args->str_storage,
	                  STR_STORAGE_SIZE - available,
	                  false,
	                  0);
	CHECK_RES(res);

	env_len = mm->env_end - mm->env_start;
	if(env_len > STR_STORAGE_SIZE) {
		env_len = STR_STORAGE_SIZE;
	}

	correctly_read =
	        ppm_copy_from_user(args->str_storage, (const void __user *)mm->env_start, env_len);

	if(env_len && correctly_read == 0) {
		args->str_storage[env_len - 1] = 0;
	} else {
		env_len = 0;
		*args->str_storage = 0;
	}

	/* Parameter 16: env (type: PT_CHARBUFARRAY) */
	res = val_to_ring(args, (int64_t)(long)args->str_storage, env_len, false, 0);
	CHECK_RES(res);

	/* Parameter 17: tty (type: PT_UINT32) */
	tty_nr = ppm_get_tty();
	res = val_to_ring(args, tty_nr, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 18: vpgid (type: PT_PID) */
	res = val_to_ring(args,
	                  (int64_t)task_pgrp_nr_ns(current, task_active_pid_ns(current)),
	                  0,
	                  false,
	                  0);
	CHECK_RES(res);

	/* Parameter 19: loginuid (type: PT_UID) */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 5, 0)
	loginuid = from_kuid(current_user_ns(), audit_get_loginuid(current));
#else
	loginuid = audit_get_loginuid(current);
#endif
	res = val_to_ring(args, loginuid, 0, false, 0);
	CHECK_RES(res);

	/* `exe_writable`, `exe_upper_layer` and `exe_lower_layer` flag logic */
	exe_file = ppm_get_mm_exe_file(mm);
	if(exe_file != NULL) {
		if(file_inode(exe_file) != NULL) {
			/* Support exe_writable */
#ifdef HAS_FS_MNT_IDMAP
			exe_writable |= (file_permission(exe_file, MAY_WRITE | MAY_NOT_BLOCK) == 0);
			exe_writable |= inode_owner_or_capable(file_mnt_idmap(exe_file), file_inode(exe_file));
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
			exe_writable |= (inode_permission(current_user_ns(),
			                                  file_inode(exe_file),
			                                  MAY_WRITE | MAY_NOT_BLOCK) == 0);
			exe_writable |= inode_owner_or_capable(current_user_ns(), file_inode(exe_file));
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 1, 0)
			exe_writable |=
			        (inode_permission(file_inode(exe_file), MAY_WRITE | MAY_NOT_BLOCK) == 0);
			exe_writable |= inode_owner_or_capable(file_inode(exe_file));
#endif
			/*
			 * Kernels < 3.1.0 doesn't support the exe_writable flags due to the MAY_NOT_BLOCK not
			 * being available. This limitation is related to the fact that this function
			 * (f_sched_prog_exec) is in a RCU critical section: this means that this function (and
			 * its callee) MUST NOT call functions that can yield the processor (e.g.
			 * inode_permission that deep down in its call stack calls a down_read()). This is
			 * addressed after the Kernel 3.1.0 where the MAY_OT_BLOCK flag is introduced and avoids
			 * the processor to being yield.
			 */

			/* Support exe_upper_layer and exe_lower_layer */
			exe_layer = ppm_get_overlay_layer(exe_file);

			/* Support exe_from_memfd */
			flags |= get_exe_from_memfd(exe_file);

			/* Support inode number */
			i_ino = file_inode(exe_file)->i_ino;

			/* Support exe_file ctime
			 * During kernel versions `i_ctime` changed from `struct timespec` to `struct
			 * timespec64` but fields names should be always the same.
			 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
			{
				struct timespec64 inode_ctime;
				inode_ctime = inode_get_ctime(file_inode(exe_file));
				ctime = inode_ctime.tv_sec * (uint64_t)1000000000 + inode_ctime.tv_nsec;
			}
#else
			ctime = file_inode(exe_file)->i_ctime.tv_sec * (uint64_t)1000000000 +
			        file_inode(exe_file)->i_ctime.tv_nsec;
#endif

			/* Support exe_file mtime
			 * During kernel versions `i_mtime` changed from `struct timespec` to `struct
			 * timespec64` but fields names should be always the same.
			 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 7, 0)
			{
				struct timespec64 inode_mtime;
				inode_mtime = inode_get_mtime(file_inode(exe_file));
				mtime = inode_mtime.tv_sec * (uint64_t)1000000000 + inode_mtime.tv_nsec;
			}
#else
			mtime = file_inode(exe_file)->i_mtime.tv_sec * (uint64_t)1000000000 +
			        file_inode(exe_file)->i_mtime.tv_nsec;
#endif
		}
		/* Before free the exefile we catch the resolved path for symlink resolution */
		trusted_exepath = d_path(&exe_file->f_path, buf, PAGE_SIZE);
		fput(exe_file);
	}

	if(exe_writable) {
		flags |= PPM_EXE_WRITABLE;
	}

	if(exe_layer == PPM_OVERLAY_UPPER) {
		flags |= PPM_EXE_UPPER_LAYER;
	} else if(exe_layer == PPM_OVERLAY_LOWER) {
		flags |= PPM_EXE_LOWER_LAYER;
	}

	// write all the additional flags for execve family here...

	/* Parameter 20: flags (type: PT_FLAGS32) */
	res = val_to_ring(args, flags, 0, false, 0);
	CHECK_RES(res);

	/*
	 * capabilities
	 */

	cred = get_current_cred();
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 3, 0)
	cap_inheritable = ((uint64_t)cred->cap_inheritable.cap[1] << 32) | cred->cap_inheritable.cap[0];
	cap_permitted = ((uint64_t)cred->cap_permitted.cap[1] << 32) | cred->cap_permitted.cap[0];
	cap_effective = ((uint64_t)cred->cap_effective.cap[1] << 32) | cred->cap_effective.cap[0];
#else
	cap_inheritable = (uint64_t)cred->cap_inheritable.val;
	cap_permitted = (uint64_t)cred->cap_permitted.val;
	cap_effective = (uint64_t)cred->cap_effective.val;
#endif
	put_cred(cred);

	/* Parameter 21: cap_inheritable (type: PT_UINT64) */
	res = val_to_ring(args, capabilities_to_scap(cap_inheritable), 0, false, 0);
	CHECK_RES(res);

	/* Parameter 22: cap_permitted (type: PT_UINT64) */
	res = val_to_ring(args, capabilities_to_scap(cap_permitted), 0, false, 0);
	CHECK_RES(res);

	/* Parameter 23: cap_effective (type: PT_UINT64) */
	res = val_to_ring(args, capabilities_to_scap(cap_effective), 0, false, 0);
	CHECK_RES(res);

	/*
	 * exe ino fields
	 */

	/* Parameter 24: exe_file ino (type: PT_UINT64) */
	res = val_to_ring(args, i_ino, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 25: exe_file ctime (last status change time, epoch value in nanoseconds) (type:
	 * PT_ABSTIME) */
	res = val_to_ring(args, ctime, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 26: exe_file mtime (last modification time, epoch value in nanoseconds) (type:
	 * PT_ABSTIME) */
	res = val_to_ring(args, mtime, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 27: euid (type: PT_UID) */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 5, 0)
	euid = from_kuid_munged(current_user_ns(), current_euid());
#elif LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 20)
	euid = current_euid();
#else
	euid = current->euid;
#endif
	res = val_to_ring(args, euid, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 28: trusted_exepath (type: PT_FSPATH) */
	res = val_to_ring(args, (unsigned long)trusted_exepath, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 29: pgid (type: PT_PID) */
	res = push_pgid(args);
	CHECK_RES(res);

	/* Parameter 30: egid (type: PT_GID) */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 5, 0)
	egid = from_kgid_munged(current_user_ns(), current_egid());
#elif LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 20)
	egid = current_egid();
#else
	egid = current->egid;
#endif
	res = val_to_ring(args, egid, 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}
#endif

#ifdef CAPTURE_SCHED_PROC_FORK
int f_sched_prog_fork(struct event_filler_arguments *args) {
	int res = 0;
	struct task_struct *child = args->child;
	struct mm_struct *mm = child->mm;
	int args_len = 0;
	int correctly_read = 0;
	unsigned int exe_len = 0; /* the length of the executable string. */
	int ptid = 0;
	long total_vm = 0;
	long total_rss = 0;
	long swap = 0;
	int available = STR_STORAGE_SIZE;
	uint32_t flags = 0;
	uint32_t euid = task_euid(child).val;
	uint32_t egid = child->cred->egid.val;
	struct pid_namespace *pidns = task_active_pid_ns(child);
	uint64_t pidns_init_start_time = 0;

	/* Parameter 1: res (type: PT_ERRNO) */
	/* Please note: here we are in the clone child exit
	 * event, so the return value will be always 0.
	 */
	res = val_to_ring(args, 0, 0, false, 0);
	CHECK_RES(res);

	/*
	 * The call always succeed so get `exe`, `args` from the child
	 * process; put one \0-separated exe-args string into
	 * str_storage
	 */
	if(unlikely(!mm)) {
		args->str_storage[0] = 0;
		pr_info("'f_sched_prog_fork' drop, mm=NULL\n");
		return PPM_FAILURE_BUG;
	}

	if(unlikely(!mm->arg_end)) {
		args->str_storage[0] = 0;
		pr_info("'f_sched_prog_fork' drop, mm->arg_end=NULL\n");
		return PPM_FAILURE_BUG;
	}

	/* the combined length of the arguments string + executable string. */
	args_len = mm->arg_end - mm->arg_start;

	if(args_len > STR_STORAGE_SIZE) {
		args_len = STR_STORAGE_SIZE;
	}

	correctly_read =
	        ppm_copy_from_user(args->str_storage, (const void __user *)mm->arg_start, args_len);

	if(args_len && correctly_read == 0) {
		args->str_storage[args_len - 1] = 0;
	} else {
		args_len = 0;
		*args->str_storage = 0;
	}

	exe_len = strnlen(args->str_storage, args_len);
	// we add the `\0` terminator
	if(exe_len < args_len) {
		++exe_len;
	}

	/* Parameter 2: exe (type: PT_CHARBUF) */
	res = val_to_ring(args, (uint64_t)(long)args->str_storage, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 3: args (type: PT_CHARBUFARRAY) */
	res = val_to_ring(args,
	                  (int64_t)(long)args->str_storage + exe_len,
	                  args_len - exe_len,
	                  false,
	                  0);
	CHECK_RES(res);

	/* Parameter 4: tid (type: PT_PID) */
	res = val_to_ring(args, (int64_t)child->pid, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 5: pid (type: PT_PID) */
	res = val_to_ring(args, (int64_t)child->tgid, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 6: ptid (type: PT_PID) */
	if(child->real_parent) {
		ptid = child->real_parent->pid;
	}

	res = val_to_ring(args, (int64_t)ptid, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 7: cwd (type: PT_CHARBUF)
	 * cwd, pushed empty to avoid breaking compatibility
	 * with the older event format
	 */
	res = push_empty_param(args);
	CHECK_RES(res);

	/* Parameter 8: fdlimit (type: PT_UINT64) */
	res = val_to_ring(args, (int64_t)rlimit(RLIMIT_NOFILE), 0, false, 0);
	CHECK_RES(res);

	/* Parameter 9: pgft_maj (type: PT_UINT64) */
	res = val_to_ring(args, child->maj_flt, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 10: pgft_min (type: PT_UINT64) */
	res = val_to_ring(args, child->min_flt, 0, false, 0);
	CHECK_RES(res);

	if(mm) {
		total_vm = mm->total_vm << (PAGE_SHIFT - 10);
		total_rss = ppm_get_mm_rss(mm) << (PAGE_SHIFT - 10);
		swap = ppm_get_mm_swap(mm) << (PAGE_SHIFT - 10);
	}

	/* Parameter 11: vm_size (type: PT_UINT32) */
	res = val_to_ring(args, total_vm, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 12: vm_rss (type: PT_UINT32) */
	res = val_to_ring(args, total_rss, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 13: vm_swap (type: PT_UINT32) */
	res = val_to_ring(args, swap, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 14: comm (type: PT_CHARBUF) */
	res = val_to_ring(args, (uint64_t)child->comm, 0, false, 0);
	CHECK_RES(res);

	args->str_storage[0] = 0;
#ifdef CONFIG_CGROUPS
	rcu_read_lock();
#include <linux/cgroup_subsys.h>
cgroups_error:
	rcu_read_unlock();
#endif

	/* Parameter 15: cgroups (type: PT_CHARBUFARRAY) */
	res = val_to_ring(args,
	                  (int64_t)(long)args->str_storage,
	                  STR_STORAGE_SIZE - available,
	                  false,
	                  0);
	CHECK_RES(res);

	/* Since Linux 2.5.35, the flags mask must also include
	 * CLONE_SIGHAND if CLONE_THREAD is specified (and note that,
	 * since Linux 2.6.0, CLONE_SIGHAND also requires CLONE_VM to
	 * be included).
	 * Taken from https://man7.org/linux/man-pages/man2/clone.2.html
	 */
	if(child->pid != child->tgid) {
		flags |= PPM_CL_CLONE_THREAD | PPM_CL_CLONE_SIGHAND | PPM_CL_CLONE_VM;
	}

	/* If CLONE_FILES is set, the calling process and the child
	 * process share the same file descriptor table.
	 * Taken from https://man7.org/linux/man-pages/man2/clone.2.html
	 */
	if(child->files == current->files) {
		flags |= PPM_CL_CLONE_FILES;
	}

	/* It's possible to have a process in a PID namespace that
	 * nevertheless has tid == vtid,  so we need to generate this
	 * custom flag `PPM_CL_CHILD_IN_PIDNS`.
	 */
	if(pidns != &init_pid_ns) {
		flags |= PPM_CL_CHILD_IN_PIDNS;
	}

	/* Parameter 16: flags (type: PT_FLAGS32) */
	res = val_to_ring(args, flags, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 17: uid (type: PT_UID) */
	res = val_to_ring(args, euid, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 18: gid (type: PT_UINT32) */
	res = val_to_ring(args, egid, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 19: vtid (type: PT_PID) */
	res = val_to_ring(args, task_pid_nr_ns(child, pidns), 0, false, 0);
	CHECK_RES(res);

	/* Parameter 20: vpid (type: PT_PID) */
	res = val_to_ring(args, task_tgid_nr_ns(child, pidns), 0, false, 0);
	CHECK_RES(res);

	/* Parameter 21: pid_namespace init task start_time monotonic time in ns (type: PT_UINT64) */

	/*
	 * pid_namespace init task start_time monotonic time in ns
	 * the field `start_time` was a `struct timespec` before this
	 * kernel version.
	 * https://elixir.bootlin.com/linux/v3.16/source/include/linux/sched.h#L1370
	 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 17, 0)
	/* Here the father collects this info for the child.
	 * Remember that this is the clone child event.
	 */
	if(pidns && pidns->child_reaper) {
		pidns_init_start_time = pidns->child_reaper->start_time;
	}
	res = val_to_ring(args, pidns_init_start_time, 0, false, 0);
#else
	/* Not relevant in old kernels */
	res = val_to_ring(args, 0, 0, false, 0);
#endif
	CHECK_RES(res);

	return add_sentinel(args);
}
#endif

int f_sys_prctl_x(struct event_filler_arguments *args) {
	int res;
	int retval;
	unsigned long option;
	unsigned long arg2;

	/* Parameter 1: res (type: PT_ERRNO) */
	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	CHECK_RES(res);

	/*
	 * option
	 */
	syscall_get_arguments_deprecated(args, 0, 1, &option);
	option = prctl_options_to_scap(option);
	res = val_to_ring(args, option, 0, false, 0);
	CHECK_RES(res);

	/*
	 * arg2
	 */
	syscall_get_arguments_deprecated(args, 1, 1, &arg2);

	switch(option) {
	case PPM_PR_GET_NAME:
	case PPM_PR_SET_NAME:
		/*
		 * arg2_str
		 */
		res = val_to_ring(args, arg2, 0, true, 0);
		CHECK_RES(res);
		/*
		 * arg2_int
		 */
		res = val_to_ring(args, 0, 0, false, 0);
		CHECK_RES(res);
		break;
	case PPM_PR_GET_CHILD_SUBREAPER: {
		int reaper_attr = 0;
		/* Parameter 3: arg2_str (type: PT_CHARBUF) */
		res = push_empty_param(args);
		CHECK_RES(res);
		/* Parameter 4: arg2_int (type: PT_INT64) */
		if(unlikely(ppm_copy_from_user(&reaper_attr, (void *)arg2, sizeof(reaper_attr)))) {
			reaper_attr = 0;
		}
		res = val_to_ring(args, (int64_t)reaper_attr, 0, false, 0);
		CHECK_RES(res);
	} break;
	case PPM_PR_SET_CHILD_SUBREAPER:
	default:
		/*
		 * arg2_str
		 */
		res = push_empty_param(args);
		CHECK_RES(res);
		/*
		 * arg2_int
		 */
		res = val_to_ring(args, arg2, 0, false, 0);
		CHECK_RES(res);
		break;
	}

	return add_sentinel(args);
}

int f_sys_memfd_create_x(struct event_filler_arguments *args) {
	unsigned long val;
	int res;
	long retval;

	/* Parameter 1: ret (type: PT_FD) */
	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 2: name (type: PT_CHARBUF) */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	res = val_to_ring(args, val, 0, true, 0);
	CHECK_RES(res);

	/* Parameter 3: flags (type: PT_UINT32) */
	syscall_get_arguments_deprecated(args, 1, 1, &val);
	res = val_to_ring(args, memfd_create_flags_to_scap(val), 0, true, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_pidfd_getfd_x(struct event_filler_arguments *args) {
	unsigned long val;
	int res;
	long retval;
	int32_t fd;

	/* Parameter 1: ret (type: PT_FD) */
	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 2: pidfd (type: PT_FD) */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	fd = (int32_t)val;
	res = val_to_ring(args, (int64_t)fd, 0, true, 0);
	CHECK_RES(res);

	/* Parameter 3: targetfd (type: PT_FD) */
	syscall_get_arguments_deprecated(args, 1, 1, &val);
	fd = (int32_t)val;
	res = val_to_ring(args, (int64_t)fd, 0, true, 0);
	CHECK_RES(res);

	/* Parameter 4: flags (type: PT_UINT32) */
	syscall_get_arguments_deprecated(args, 2, 1, &val);
	res = val_to_ring(args, val, 0, true, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_pidfd_open_x(struct event_filler_arguments *args) {
	unsigned long val;
	int res;
	long retval;
	int32_t fd;

	/* Parameter 1: ret (type: PT_FD) */
	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 2: pid (type: PT_PID) */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	fd = (int32_t)val;
	res = val_to_ring(args, (int64_t)fd, 0, true, 0);
	CHECK_RES(res);

	/* Parameter 4: flags (type: PT_FLAGS32) */
	syscall_get_arguments_deprecated(args, 1, 1, &val);
	res = val_to_ring(args, pidfd_open_flags_to_scap(val), 0, true, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_init_module_x(struct event_filler_arguments *args) {
	unsigned long val;
	int res;
	long retval;
	uint64_t len;

	/* Parameter 1: ret (type: PT_ERRNO) */
	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	CHECK_RES(res);

	syscall_get_arguments_deprecated(args, 1, 1, &val);
	len = val;

	/* Parameter 2: img (type: PT_BYTBUF) */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	res = val_to_ring(args, val, len, true, 0);
	CHECK_RES(res);

	/* Parameter 3: length (type: PT_UINT64) */
	res = val_to_ring(args, len, 0, true, 0);
	CHECK_RES(res);

	/* Parameter 2: uargs (type: PT_CHARBUF) */
	syscall_get_arguments_deprecated(args, 2, 1, &val);
	res = val_to_ring(args, val, 0, true, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_finit_module_x(struct event_filler_arguments *args) {
	unsigned long val;
	int res;
	long retval;
	int32_t fd;

	/* Parameter 1: ret (type: PT_ERRNO) */
	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 2: fd (type: PT_FD) */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	fd = (int32_t)val;
	res = val_to_ring(args, (int64_t)fd, 0, true, 0);
	CHECK_RES(res);

	/* Parameter 3: uargs (type: PT_CHARBUF) */
	syscall_get_arguments_deprecated(args, 1, 1, &val);
	res = val_to_ring(args, val, 0, true, 0);
	CHECK_RES(res);

	/* Parameter 4: flags (type: PT_FLAGS32) */
	syscall_get_arguments_deprecated(args, 2, 1, &val);
	res = val_to_ring(args, finit_module_flags_to_scap(val), 0, true, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_mknod_x(struct event_filler_arguments *args) {
	unsigned long val;
	int res;
	long retval;

	/* Parameter 1: ret (type: PT_ERRNO) */
	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 2: path (type: PT_CHARBUF) */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	res = val_to_ring(args, val, 0, true, 0);
	CHECK_RES(res);

	/* Parameter 3: mode (type: PT_MODE) */
	syscall_get_arguments_deprecated(args, 1, 1, &val);
	res = val_to_ring(args, mknod_mode_to_scap(val), 0, false, 0);
	CHECK_RES(res);

	/* Parameter 4: dev (type: PT_UINT32) */
	syscall_get_arguments_deprecated(args, 2, 1, &val);
	res = val_to_ring(args, new_encode_dev(val), 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_mknodat_x(struct event_filler_arguments *args) {
	unsigned long val;
	int res;
	int32_t fd;
	long retval;

	/* Parameter 1: ret (type: PT_ERRNO) */
	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 2: dirfd (type: PT_FD) */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	fd = (int32_t)val;
	if(fd == AT_FDCWD)
		fd = PPM_AT_FDCWD;
	res = val_to_ring(args, (int64_t)fd, 0, true, 0);
	CHECK_RES(res);

	/* Parameter 2: path (type: PT_CHARBUF) */
	syscall_get_arguments_deprecated(args, 1, 1, &val);
	res = val_to_ring(args, val, 0, true, 0);
	CHECK_RES(res);

	/* Parameter 3: mode (type: PT_MODE) */
	syscall_get_arguments_deprecated(args, 2, 1, &val);
	res = val_to_ring(args, mknod_mode_to_scap(val), 0, false, 0);
	CHECK_RES(res);

	/* Parameter 4: dev (type: PT_UINT32) */
	syscall_get_arguments_deprecated(args, 3, 1, &val);
	res = val_to_ring(args, new_encode_dev(val), 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_newfstatat_x(struct event_filler_arguments *args) {
	unsigned long val;
	int res;
	int32_t fd;
	long retval;

	/* Parameter 1: ret (type: PT_ERRNO) */
	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 2: dirfd (type: PT_FD) */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	fd = (int32_t)val;
	if(fd == AT_FDCWD)
		fd = PPM_AT_FDCWD;
	res = val_to_ring(args, (int64_t)fd, 0, true, 0);
	CHECK_RES(res);

	/* Parameter 3: path (type: PT_RELPATH) */
	syscall_get_arguments_deprecated(args, 1, 1, &val);
	res = val_to_ring(args, val, 0, true, 0);
	CHECK_RES(res);

	/* Parameter 4: flags (type: PT_FLAGS32) */
	syscall_get_arguments_deprecated(args, 3, 1, &val);
	res = val_to_ring(args, newfstatat_flags_to_scap(val), 0, true, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_process_vm_readv_x(struct event_filler_arguments *args) {
	unsigned long val;
	long retval;
	int res;
	unsigned long iovcnt;
	int32_t pid;

	/* Parameter 1: ret (type: PT_INT64) */
	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, (int64_t)retval, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 2: pid (type: PT_PID) */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	pid = (int32_t)val;
	res = val_to_ring(args, (int64_t)pid, 0, false, 0);
	CHECK_RES(res);

	if(retval > 0) {
		/* We only get the local iov */
		syscall_get_arguments_deprecated(args, 1, 1, &val);
		syscall_get_arguments_deprecated(args, 2, 1, &iovcnt);

#ifdef CONFIG_COMPAT
		if(unlikely(args->compat)) {
			const struct compat_iovec __user *compat_iov =
			        (const struct compat_iovec __user *)compat_ptr(val);
			res = compat_parse_readv_writev_bufs(args,
			                                     compat_iov,
			                                     iovcnt,
			                                     retval,
			                                     PRB_FLAG_PUSH_DATA);
		} else
#endif
		{
			const struct iovec __user *iov = (const struct iovec __user *)val;
			res = parse_readv_writev_bufs(args, iov, iovcnt, retval, PRB_FLAG_PUSH_DATA);
		}

		CHECK_RES(res);
	} else {
		/* pushing empty data */
		res = push_empty_param(args);
		CHECK_RES(res);
	}

	return add_sentinel(args);
}

int f_sys_process_vm_writev_x(struct event_filler_arguments *args) {
	unsigned long val;
	long retval;
	int res;
	unsigned long iovcnt;
	int32_t pid;

	/* Parameter 1: ret (type: PT_INT64) */
	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, (int64_t)retval, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 2: pid (type: PT_PID) */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	pid = (int32_t)val;
	res = val_to_ring(args, (int64_t)pid, 0, false, 0);
	CHECK_RES(res);

	if(retval > 0) {
		/* We only get the local iov */
		syscall_get_arguments_deprecated(args, 1, 1, &val);
		syscall_get_arguments_deprecated(args, 2, 1, &iovcnt);

#ifdef CONFIG_COMPAT
		if(unlikely(args->compat)) {
			const struct compat_iovec __user *compat_iov =
			        (const struct compat_iovec __user *)compat_ptr(val);
			res = compat_parse_readv_writev_bufs(args,
			                                     compat_iov,
			                                     iovcnt,
			                                     retval,
			                                     PRB_FLAG_PUSH_DATA);
		} else
#endif
		{
			const struct iovec __user *iov = (const struct iovec __user *)val;
			res = parse_readv_writev_bufs(args, iov, iovcnt, retval, PRB_FLAG_PUSH_DATA);
		}

		CHECK_RES(res);
	} else {
		/* pushing empty data */
		res = push_empty_param(args);
		CHECK_RES(res);
	}

	return add_sentinel(args);
}

int f_sys_delete_module_x(struct event_filler_arguments *args) {
	int64_t retval = 0;
	int64_t res = 0;
	uint32_t flags = 0;
	unsigned long val = 0;

	/* Parameter 1: res (type: PT_ERRNO) */
	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, (int64_t)retval, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 2: name (type: PT_CHARBUF) */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	res = val_to_ring(args, val, 0, true, 0);
	CHECK_RES(res);

	/* Parameter 3: flags (type: PT_FLAGS32) */
	syscall_get_arguments_deprecated(args, 1, 1, &val);
	flags = delete_module_flags_to_scap(val);
	res = val_to_ring(args, flags, 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_setuid_x(struct event_filler_arguments *args) {
	int64_t retval = 0;
	int64_t res = 0;
	unsigned long val = 0;
	uint32_t uid;

	/* Parameter 1: res (type: PT_ERRNO) */
	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, (int64_t)retval, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 2: uid (type: PT_UID) */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	uid = (uint32_t)val;
	res = val_to_ring(args, uid, 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}

int f_sys_setresuid_x(struct event_filler_arguments *args) {
	int64_t retval = 0;
	int64_t res = 0;
	unsigned long val = 0;
	uint32_t uid;

	/* Parameter 1: res (type: PT_ERRNO) */
	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, (int64_t)retval, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 2: ruid (type: PT_UID) */
	syscall_get_arguments_deprecated(args, 0, 1, &val);
	uid = (uint32_t)val;
	res = val_to_ring(args, uid, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 3: euid (type: PT_UID) */
	syscall_get_arguments_deprecated(args, 1, 1, &val);
	uid = (uint32_t)val;
	res = val_to_ring(args, uid, 0, false, 0);
	CHECK_RES(res);

	/* Parameter 4: suid (type: PT_UID) */
	syscall_get_arguments_deprecated(args, 2, 1, &val);
	uid = (uint32_t)val;
	res = val_to_ring(args, uid, 0, false, 0);
	CHECK_RES(res);

	return add_sentinel(args);
}
