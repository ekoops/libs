// SPDX-License-Identifier: GPL-2.0-only OR MIT
/*
 * Copyright (C) 2026 The Falco Authors.
 *
 * This file is dual licensed under either the MIT or GPL 2. See MIT.txt
 * or GPL2.txt for full copies of the license.
 */

#include <helpers/interfaces/variable_size_event.h>

SEC("iter.s/task")
int dump_task(struct bpf_iter__task *ctx) {
	struct seq_file *seq = ctx->meta->seq;
	struct task_struct *task = ctx->task;

	if(!task) {
		return 0;
	}

	uint32_t task_flags = 0;
	READ_TASK_FIELD_INTO(&task_flags, task, flags);

	/* We are not interested in kernel threads. */
	if(task_flags & PF_KTHREAD) {
		return 0;
	}

	pid_t pid = extract__task_xid_nr(task, PIDTYPE_PID);

	struct auxiliary_map *auxmap = auxmap_iter__get();
	if(!auxmap) {
		return 0;
	}
	auxmap_iter__preload_event_header(auxmap, pid, PPME_ITER_TASK_X);

	// tgid
	pid_t tgid = extract__task_xid_nr(task, PIDTYPE_TGID);
	auxmap__store_s64_param(auxmap, (int64_t)tgid);

	// ppid
	// Even if we pass PIDTYPE_PGID, the implementation looks at task->parent->pid. So this is what
	// we are searching for.
	pid_t ppid = extract__task_xid_nr(task, PIDTYPE_PGID);
	auxmap__store_s64_param(auxmap, (int64_t)ppid);

	// pgid
	auxmap__store_pgid(auxmap, task);

	// vpgid
	pid_t vpgid = extract__task_xid_vnr(task, PIDTYPE_PGID);
	auxmap__store_s64_param(auxmap, (int64_t)vpgid);

	// sid
	pid_t sid = extract__task_xid_nr(task, PIDTYPE_SID);
	auxmap__store_s64_param(auxmap, (int64_t)sid);

	// comm
	auxmap__store_charbuf_param(auxmap, (unsigned long)task->comm, TASK_COMM_LEN, KERNEL);

	// argv
	unsigned long argv_start_pointer = READ_TASK_FIELD(task, mm, arg_start);
	unsigned long argv_end_pointer = READ_TASK_FIELD(task, mm, arg_end);
	unsigned long total_argv_len = argv_end_pointer - argv_start_pointer;
	auxmap__store_user_task_charbufarray_param(auxmap,
	                                           argv_start_pointer,
	                                           total_argv_len,
	                                           MAX_PROC_ARG_ENV,
	                                           task);

	// exepath
	struct file *exe_file = extract__exe_file_from_task(task);
	if(exe_file) {
		auxmap__store_d_path_approx(auxmap, &exe_file->f_path);
	} else {
		auxmap__store_empty_param(auxmap);
	}

	// flags (exe_writable, exe_upper_layer, exe_lower_layer, exe_upper_layer, exe_from_memfd)
	uint32_t flags = 0;
	struct inode *exe_inode = extract__exe_inode_from_task(task);
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

	// env
	unsigned long env_start_pointer = READ_TASK_FIELD(task, mm, env_start);
	unsigned long env_end_pointer = READ_TASK_FIELD(task, mm, env_end);
	unsigned long total_env_len = env_end_pointer - env_start_pointer;
	auxmap__store_user_task_charbufarray_param(auxmap,
	                                           env_start_pointer,
	                                           total_env_len,
	                                           MAX_PROC_ARG_ENV,
	                                           task);

	// cwd
	struct fs_struct *task_fs = task->fs;
	if(task_fs) {
		auxmap__store_d_path_approx(auxmap, &task_fs->pwd);
	} else {
		auxmap__store_empty_param(auxmap);
	}

	// fdlimit
	unsigned long fdlimit = extract__fdlimit(task);
	auxmap__store_u64_param(auxmap, (uint64_t)fdlimit);

	// TODO(ekoops): implement logic to reliably extract flags.

	// euid
	uint32_t euid = extract__euid(task);
	auxmap__store_u32_param(auxmap, euid);

	// egid
	uint32_t egid = extract__egid(task);
	auxmap__store_u32_param(auxmap, egid);

	// cap_permitted
	uint64_t cap_permitted = extract__capability(task, CAP_PERMITTED);
	auxmap__store_u64_param(auxmap, cap_permitted);

	// cap_effective
	uint64_t cap_effective = extract__capability(task, CAP_EFFECTIVE);
	auxmap__store_u64_param(auxmap, cap_effective);

	// cap_inheritable
	uint64_t cap_inheritable = extract__capability(task, CAP_INHERITABLE);
	auxmap__store_u64_param(auxmap, cap_inheritable);

	// exe_ino_num
	uint64_t ino = extract__ino_from_inode(exe_inode);
	auxmap__store_u64_param(auxmap, ino);

	// exe_ino_ctime
	struct timespec64 time = {0, 0};
	extract__ctime_from_inode(exe_inode, &time);
	auxmap__store_u64_param(auxmap, extract__epoch_ns_from_time(time));

	// exe_ino_mtime
	extract__mtime_from_inode(exe_inode, &time);
	auxmap__store_u64_param(auxmap, extract__epoch_ns_from_time(time));

	// warn: exe_ino_ctime_duration_clone_ts and exe_ino_ctime_duration_pidns_start are currently
	// set to zero in scap_procs.c (not explicitely, they are set to zero by memset) and so there's
	// no need to export from here.

	struct mm_struct *mm = NULL;
	READ_TASK_FIELD_INTO(&mm, task, mm);

	// vm_size
	uint32_t vm_size = extract__vm_size(mm);
	auxmap__store_u32_param(auxmap, vm_size);

	// vm_rss
	uint32_t vm_rss = extract__vm_rss(mm);
	auxmap__store_u32_param(auxmap, vm_rss);

	// vm_swap
	uint32_t vm_swap = extract__vm_swap(mm);
	auxmap__store_u32_param(auxmap, vm_swap);

	// pgft_maj
	unsigned long pgft_maj = extract__pgft_maj(task);
	auxmap__store_u64_param(auxmap, pgft_maj);

	// pgft_min
	unsigned long pgft_min = extract__pgft_min(task);
	auxmap__store_u64_param(auxmap, pgft_min);

	// vtgid
	pid_t vtgid = extract__task_xid_vnr(task, PIDTYPE_TGID);
	auxmap__store_s64_param(auxmap, (int64_t)vtgid);

	// vpid
	pid_t vpid = extract__task_xid_vnr(task, PIDTYPE_PID);
	auxmap__store_s64_param(auxmap, (int64_t)vpid);

	// pidns_init_start_ts
	uint64_t pidns_init_start_ts = extract__task_pidns_start_time(task, PIDTYPE_TGID, 0);
	auxmap__store_u64_param(auxmap, pidns_init_start_ts);

	// cgroups
	auxmap__store_cgroups_param(auxmap, task);

	// root
	if(task_fs) {
		auxmap__store_d_path_approx(auxmap, &task_fs->root);
	} else {
		auxmap__store_empty_param(auxmap);
	}

	// filterd_out and fdlist in scap_threadinfo are internal fields, not relevant in this context.
	// TODO(ekoops): implement support for clone_ts

	// tty
	uint32_t tty = extract__tty(task);
	auxmap__store_u32_param(auxmap, tty);

	// loginuid
	uint32_t loginuid = extract__loginuid(task);
	auxmap__store_u32_param(auxmap, loginuid);

	auxmap__finalize_event_header(auxmap);
	auxmap_iter__submit_event(auxmap, seq);
	return 0;
}

/*static __always_inline int dump_inet_socket_strict(struct seq_file *seq,
                                                 uint32_t pid,
                                                 uint32_t fd,
                                                 struct sock *sk,
                                                 uint16_t sk_type,
                                                 uint16_t sk_proto,
                                                 struct inode *inode) {
    switch(sk_type) {
    case SOCK_STREAM:
        if(sk_proto == IPPROTO_TCP || sk_proto == IPPROTO_IP) {
            return dump_inet_socket(seq, pid, fd, sk, sk_type, sk_proto, inode);
        }
        break;
    case SOCK_DGRAM:
        if(sk_proto == IPPROTO_UDP || sk_proto == IPPROTO_IP) {
            return dump_inet_socket(seq, pid, fd, sk, sk_type, sk_proto, inode);
        }
        break;
    case SOCK_RAW:
        return dump_inet_socket(seq, pid, fd, sk, sk_type, sk_proto, inode);
    }
    return 0;
}

static __always_inline int dump_inet6_socket_strict(struct seq_file *seq,
                                                  uint32_t pid,
                                                  uint32_t fd,
                                                  struct sock *sk,
                                                  uint16_t sk_type,
                                                  uint16_t sk_proto,
                                                  struct inode *inode) {
    switch(sk_type) {
    case SOCK_STREAM:
        if(sk_proto == IPPROTO_TCP || sk_proto == IPPROTO_IP) {
            return dump_inet6_socket(seq, pid, fd, sk, sk_type, sk_proto, inode);
        }
        break;
    case SOCK_DGRAM:
        if(sk_proto == IPPROTO_UDP || sk_proto == IPPROTO_IP) {
            return dump_inet6_socket(seq, pid, fd, sk, sk_type, sk_proto, inode);
        }
        break;
    case SOCK_RAW:
        return dump_inet6_socket(seq, pid, fd, sk, sk_type, sk_proto, inode);
    }
    return 0;
}*/

static __always_inline int dump_inet_socket(struct seq_file *seq,
                                            uint32_t pid,
                                            uint32_t fd,
                                            struct sock *sk,
                                            uint16_t sk_type,
                                            uint16_t sk_proto,
                                            struct inode *inode) {
	uint32_t local_ip = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
	uint16_t local_port = BPF_CORE_READ(sk, __sk_common.skc_num);
	uint32_t remote_ip = BPF_CORE_READ(sk, __sk_common.skc_daddr);
	uint16_t remote_port = ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
	uint64_t ino_num = extract__ino_from_inode(inode);

	struct auxiliary_map *auxmap = auxmap_iter__get();
	if(!auxmap) {
		return 0;
	}

	auxmap_iter__preload_event_header(auxmap, pid, PPME_ITER_TASK_FILE_SOCKET_INET_X);

	auxmap__store_s64_param(auxmap, fd);
	auxmap__store_u16_param(auxmap, sk_type);
	auxmap__store_u16_param(auxmap, sk_proto);
	auxmap__store_u32_param(auxmap, local_ip);
	auxmap__store_u16_param(auxmap, local_port);
	auxmap__store_u32_param(auxmap, remote_ip);
	auxmap__store_u16_param(auxmap, remote_port);
	auxmap__store_u64_param(auxmap, ino_num);

	auxmap__finalize_event_header(auxmap);
	auxmap_iter__submit_event(auxmap, seq);
	return 0;
}

static __always_inline int dump_inet6_socket(struct seq_file *seq,
                                             uint32_t pid,
                                             uint32_t fd,
                                             struct sock *sk,
                                             uint16_t sk_type,
                                             uint16_t sk_proto,
                                             struct inode *inode) {
	struct in6_addr local_ip;
	BPF_CORE_READ_INTO(&local_ip, sk, __sk_common.skc_v6_rcv_saddr);
	uint16_t local_port = BPF_CORE_READ(sk, __sk_common.skc_num);
	struct in6_addr remote_ip;
	BPF_CORE_READ_INTO(&remote_ip, sk, __sk_common.skc_v6_daddr);
	uint32_t remote_port = ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
	uint64_t ino_num = extract__ino_from_inode(inode);

	struct auxiliary_map *auxmap = auxmap_iter__get();
	if(!auxmap) {
		return 0;
	}

	auxmap_iter__preload_event_header(auxmap, pid, PPME_ITER_TASK_FILE_SOCKET_INET6_X);

	auxmap__store_s64_param(auxmap, fd);
	auxmap__store_u16_param(auxmap, sk_type);
	auxmap__store_u16_param(auxmap, sk_proto);
	auxmap__store_ipv6_addr_param(auxmap, (uint32_t *)&local_ip);
	auxmap__store_u16_param(auxmap, local_port);
	auxmap__store_ipv6_addr_param(auxmap, (uint32_t *)&remote_ip);
	auxmap__store_u16_param(auxmap, remote_port);
	auxmap__store_u64_param(auxmap, ino_num);

	auxmap__finalize_event_header(auxmap);
	auxmap_iter__submit_event(auxmap, seq);
	return 0;
}

static __always_inline int dump_unix_socket(struct seq_file *seq,
                                            uint32_t pid,
                                            uint32_t fd,
                                            struct sock *sk,
                                            uint16_t sk_type,
                                            uint16_t sk_proto,
                                            struct inode *inode) {
	struct unix_sock *un_sk = (struct unix_sock *)sk;
	// note: path here is a pointer to a stack-allocated array created by BPF_CORE_READ
	// implementation.
	char *path = BPF_CORE_READ(un_sk, addr, name[0].sun_path);
	int max_path_len = MAX_UNIX_SOCKET_PATH;
	if(path[0] == '\0') {
		// Abstract sockets are identified by a path beginning with a '\0' byte
		// (https://man7.org/linux/man-pages/man7/unix.7.html). Skip it to point to the beginning of
		// the real path.
		path++;
		max_path_len--;
	}
	uint64_t ino_num = extract__ino_from_inode(inode);

	struct auxiliary_map *auxmap = auxmap_iter__get();
	if(!auxmap) {
		return 0;
	}

	auxmap_iter__preload_event_header(auxmap, pid, PPME_ITER_TASK_FILE_SOCKET_UNIX_X);

	auxmap__store_s64_param(auxmap, fd);
	auxmap__store_u16_param(auxmap, sk_type);
	auxmap__store_u16_param(auxmap, sk_proto);
	auxmap__store_u64_param(auxmap, (uint64_t)un_sk);
	auxmap__store_charbuf_param(auxmap, (unsigned long)path, max_path_len, KERNEL);
	auxmap__store_u64_param(auxmap, ino_num);

	auxmap__finalize_event_header(auxmap);
	auxmap_iter__submit_event(auxmap, seq);
	return 0;
}

static int dump_socket(struct seq_file *seq,
                       uint32_t pid,
                       uint32_t fd,
                       struct file *file,
                       struct inode *inode) {
	struct socket *sock = extract__socket_from_file(file);
	if(!sock) {
		return 0;
	}

	struct sock *sk = BPF_CORE_READ(sock, sk);
	if(!sk) {
		return 0;
	}

	uint16_t sk_family = BPF_CORE_READ(sk, __sk_common.skc_family);
	uint16_t sk_type = BPF_CORE_READ(sk, sk_type);
	uint16_t sk_proto = BPF_CORE_READ(sk, sk_protocol);

	switch(sk_family) {
	case AF_INET:
		return dump_inet_socket(seq, pid, fd, sk, sk_type, sk_proto, inode);

	case AF_INET6:
		return dump_inet6_socket(seq, pid, fd, sk, sk_type, sk_proto, inode);

	case AF_UNIX:
		return dump_unix_socket(seq, pid, fd, sk, sk_type, sk_proto, inode);
	}
	return 0;
}

static int dump_pipe(struct seq_file *seq,
                     uint32_t pid,
                     uint32_t fd,
                     struct file *file,
                     struct inode *inode) {
	// Unnamed pipes live in pipefs, while named ones live elsewhere. Check the fs magic to
	// determine the pipe type.
	unsigned long fs_magic = extract__fs_magic_from_inode(inode);
	uint64_t ino_num = extract__ino_from_inode(inode);

	struct auxiliary_map *auxmap = auxmap_iter__get();
	if(!auxmap) {
		return 0;
	}

	auxmap_iter__preload_event_header(auxmap, pid, PPME_ITER_TASK_FILE_PIPE_X);
	auxmap__store_s64_param(auxmap, fd);
	if(fs_magic == PIPEFS_MAGIC) {
		struct dentry *dentry = extract__dentry_from_file(file);
		const unsigned char *name = BPF_CORE_READ(dentry, d_name.name);
		auxmap__store_charbuf_param(auxmap, (unsigned long)name, MAX_PATH, KERNEL);
	} else {
		auxmap__store_d_path_approx(auxmap, &file->f_path);
	}
	auxmap__store_u64_param(auxmap, ino_num);
	auxmap__finalize_event_header(auxmap);
	auxmap_iter__submit_event(auxmap, seq);
	return 0;
}

static int dump_memfd_file(struct seq_file *seq,
                           uint32_t pid,
                           uint32_t fd,
                           struct file *file,
                           struct inode *inode) {
	uint64_t ino_num = extract__ino_from_inode(inode);

	struct auxiliary_map *auxmap = auxmap_iter__get();
	if(!auxmap) {
		return 0;
	}

	auxmap_iter__preload_event_header(auxmap, pid, PPME_ITER_TASK_FILE_MEMFD_X);

	auxmap__store_s64_param(auxmap, fd);
	auxmap__store_d_path_approx(auxmap, &file->f_path);
	auxmap__store_u64_param(auxmap, ino_num);

	auxmap__finalize_event_header(auxmap);
	auxmap_iter__submit_event(auxmap, seq);
	return 0;
}

// The following are DJB2 hashes (i.e.: hash = 5381; foreach c: hash = ((hash << 5) + hash) + c;).
#define HASH_EVENTFD 2801648095UL
#define HASH_EVENTPOLL 4176041839UL
#define HASH_INOTIFY 2246820263UL
#define HASH_SIGNALFD 1850106822UL
#define HASH_TIMERFD 177006678UL
#define HASH_IO_URING 3064336058UL
#define HASH_USERFAULTFD 3763784033UL
#define HASH_PIDFD 211985800UL
#define HASH_BPF_MAP 2216853745UL
#define HASH_BPF_PROG 2221768846UL
#define HASH_BPF_LINK 2216527582UL
#define HASH_PERF_EVENT 3372697669UL
#define HASH_DMABUF 3871439352UL

// This only works for strings shorter than 16 characters (excluding the trailing NUL byte).
static __always_inline uint32_t djb2_hash(const char *str) {
	uint32_t hash = 5381;
#pragma unroll
	for(int i = 0; i < 16; i++) {
		char c = str[i];
		if(c == '\0')
			break;
		hash = ((hash << 5) + hash) + c;
	}
	return hash;
}

static __always_inline enum anon_inode_fd_type classify_anon_inode_file(struct dentry *dentry) {
	const unsigned char *name_ptr = BPF_CORE_READ(dentry, d_name.name);
	if(!name_ptr) {
		return ANON_INODE_FD_TYPE_UNKNOWN;
	}

	char name[32];
	if(bpf_probe_read_kernel_str(name, sizeof(name), name_ptr) < 0) {
		return ANON_INODE_FD_TYPE_UNKNOWN;
	}

	uint32_t hash = djb2_hash(name);
	switch(hash) {
	case HASH_EVENTFD:
		return ANON_INODE_FD_TYPE_EVENTFD;
	case HASH_EVENTPOLL:
		return ANON_INODE_FD_TYPE_EVENTPOLL;
	case HASH_INOTIFY:
		return ANON_INODE_FD_TYPE_INOTIFY;
	case HASH_SIGNALFD:
		return ANON_INODE_FD_TYPE_SIGNALFD;
	case HASH_TIMERFD:
		return ANON_INODE_FD_TYPE_TIMERFD;
	case HASH_IO_URING:
		return ANON_INODE_FD_TYPE_IO_URING;
	case HASH_USERFAULTFD:
		return ANON_INODE_FD_TYPE_USERFAULTFD;
	case HASH_PIDFD:
		return ANON_INODE_FD_TYPE_PIDFD;
	case HASH_BPF_MAP:
		return ANON_INODE_FD_TYPE_BPF_MAP;
	case HASH_BPF_PROG:
		return ANON_INODE_FD_TYPE_BPF_PROG;
	case HASH_BPF_LINK:
		return ANON_INODE_FD_TYPE_BPF_LINK;
	case HASH_PERF_EVENT:
		return ANON_INODE_FD_TYPE_PERF_EVENT;
	case HASH_DMABUF:
		return ANON_INODE_FD_TYPE_DMABUF;
	default:
		return ANON_INODE_FD_TYPE_UNKNOWN;
	}
}

static int dump_anon_inode_file(struct seq_file *seq,
                                uint32_t pid,
                                uint32_t fd,
                                struct file *file,
                                struct inode *inode) {
	struct dentry *dentry = extract__dentry_from_file(file);
	enum anon_inode_fd_type fd_type = classify_anon_inode_file(dentry);
	uint64_t ino_num = extract__ino_from_inode(inode);

	struct auxiliary_map *auxmap = auxmap_iter__get();
	if(!auxmap) {
		return 0;
	}

	auxmap_iter__preload_event_header(auxmap, pid, PPME_ITER_TASK_FILE_ANON_INODE_X);

	auxmap__store_s64_param(auxmap, fd);
	auxmap__store_u8_param(auxmap, fd_type);
	// Push the path just for anon inode files we failed to classify.
	if(fd_type == ANON_INODE_FD_TYPE_UNKNOWN) {
		auxmap__store_d_path_approx(auxmap, &file->f_path);
	} else {
		auxmap__store_empty_param(auxmap);
	}
	auxmap__store_u64_param(auxmap, ino_num);

	auxmap__finalize_event_header(auxmap);
	auxmap_iter__submit_event(auxmap, seq);
	return 0;
}

static int dump_regular_or_device_file(struct seq_file *seq,
                                       uint32_t pid,
                                       uint32_t fd,
                                       struct file *file,
                                       struct inode *inode) {
	unsigned long fs_magic = extract__fs_magic_from_inode(inode);
	if(fs_magic == ANON_INODE_FS_MAGIC) {
		return dump_anon_inode_file(seq, pid, fd, file, inode);
	}

	uint32_t flags = BPF_CORE_READ(file, f_flags);
	uint32_t scap_flags = (uint32_t)open_flags_to_scap(flags);
	struct mount *mnt = extract__mount_from_file(file);
	uint32_t mnt_id = (uint32_t)BPF_CORE_READ(mnt, mnt_id);
	uint64_t ino_num = extract__ino_from_inode(inode);

	struct auxiliary_map *auxmap = auxmap_iter__get();
	if(!auxmap) {
		return 0;
	}

	auxmap_iter__preload_event_header(auxmap, pid, PPME_ITER_TASK_FILE_REGULAR_X);

	auxmap__store_s64_param(auxmap, fd);
	auxmap__store_d_path_approx(auxmap, &file->f_path);
	auxmap__store_u32_param(auxmap, scap_flags);
	auxmap__store_u32_param(auxmap, mnt_id);
	auxmap__store_u64_param(auxmap, ino_num);

	auxmap__finalize_event_header(auxmap);
	auxmap_iter__submit_event(auxmap, seq);
	return 0;
}

static int dump_directory(struct seq_file *seq,
                          uint32_t pid,
                          uint32_t fd,
                          struct file *file,
                          struct inode *inode) {
	uint64_t ino_num = extract__ino_from_inode(inode);

	struct auxiliary_map *auxmap = auxmap_iter__get();
	if(!auxmap) {
		return 0;
	}

	auxmap_iter__preload_event_header(auxmap, pid, PPME_ITER_TASK_FILE_DIRECTORY_X);

	auxmap__store_s64_param(auxmap, fd);
	auxmap__store_d_path_approx(auxmap, &file->f_path);
	auxmap__store_u64_param(auxmap, ino_num);

	auxmap__finalize_event_header(auxmap);
	auxmap_iter__submit_event(auxmap, seq);
	return 0;
}

static __always_inline int dump_unsupported_file(struct seq_file *seq,
                                                 uint32_t pid,
                                                 uint32_t fd,
                                                 struct file *file,
                                                 struct inode *inode,
                                                 umode_t i_mode) {
	bpf_printk("unknown file type: i_mode=%x", i_mode);
	return 0;
}

SEC("iter/task_file")
int dump_task_file(struct bpf_iter__task_file *ctx) {
	struct seq_file *seq = ctx->meta->seq;
	struct task_struct *task = ctx->task;
	struct file *file = ctx->file;
	__u32 fd = ctx->fd;
	if(!task || !file) {
		return 0;
	}

	// We are not interested in this file if the filtering logic is on and it requires dumping a
	// file with a different file descriptor.
	if(dump_task_file_fd_filter >= 0 && fd != (__u32)dump_task_file_fd_filter) {
		return 0;
	}

	uint32_t task_flags = 0;
	READ_TASK_FIELD_INTO(&task_flags, task, flags);

	// We are not interested in kernel threads.
	if(task_flags & PF_KTHREAD) {
		return 0;
	}

	pid_t tgid = extract__task_xid_nr(task, PIDTYPE_TGID);
	pid_t pid = extract__task_xid_nr(task, PIDTYPE_PID);
	if(tgid != pid) {
		return 0;
	}

	struct inode *inode = extract__inode_from_file(file);
	if(!inode) {
		return 0;
	}

	umode_t i_mode = BPF_CORE_READ(inode, i_mode);
	switch(i_mode & S_IFMT) {
	case S_IFIFO:
		return dump_pipe(seq, pid, fd, file, inode);
	case S_IFREG:
		if(extract__exe_from_memfd(file)) {
			return dump_memfd_file(seq, pid, fd, file, inode);
		}
		/* fall through */
	case S_IFBLK:
	case S_IFCHR:
	case S_IFLNK:
		return dump_regular_or_device_file(seq, pid, fd, file, inode);
	case S_IFDIR:
		return dump_directory(seq, pid, fd, file, inode);
	case S_IFSOCK:
		return dump_socket(seq, pid, fd, file, inode);
	default:
		// Paranoid: strive to handle all anon inode files.
		if(extract__fs_magic_from_inode(inode) == ANON_INODE_FS_MAGIC) {
			return dump_anon_inode_file(seq, pid, fd, file, inode);
		}
		/* fall through */
	}
	return dump_unsupported_file(seq, pid, fd, file, inode, i_mode);
}
