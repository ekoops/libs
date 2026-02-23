// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2026 The Falco Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

*/

#include <driver/ppm_events_public.h>
#include <driver/ppm_param_helpers.h>
#include <libscap/scap.h>
#include <libscap/strl.h>
#include <libscap/scap_likely.h>
#include <libscap/strerror.h>

#include <libpman.h>
#include <state.h>
#include <bpf/libbpf.h>
#include <netinet/in.h>

#ifdef BPF_ITERATOR_DEBUG

#if defined(BPF_ITERATOR_DEBUG_RAW) || defined(BPF_ITERATOR_DEBUG_PARSED)

#include <libscap/scap_print.h>

#ifdef BPF_ITERATOR_DEBUG_RAW
#define DEBUG_PRINT_EVENT(evt_ptr) scap_print_event(evt_ptr, PRINT_FULL)
#endif  // BPF_ITERATOR_DEBUG_RAW

#ifdef BPF_ITERATOR_DEBUG_PARSED
#define DEBUG_PRINT_THREADINFO(tinfo_ptr) scap_print_threadinfo(tinfo_ptr)
#define DEBUG_PRINT_FDINFO(fdinfo_ptr) scap_print_fdinfo(fdinfo_ptr)
#endif  // BPF_ITERATOR_DEBUG_PARSED

#endif  // defined(BPF_ITERATOR_DEBUG_RAW) || defined(BPF_ITERATOR_DEBUG_PARSED)

#endif  // BPF_ITERATOR_DEBUG

#ifndef DEBUG_PRINT_EVENT
#define DEBUG_PRINT_EVENT(evt_ptr)
#endif

#ifndef DEBUG_PRINT_THREADINFO
#define DEBUG_PRINT_THREADINFO(tinfo_ptr)
#endif

#ifndef DEBUG_PRINT_FDINFO
#define DEBUG_PRINT_FDINFO(fdinfo_ptr)
#endif

enum parser_selector {
	PAR_SEL_TASK,
	PAR_SEL_TASK_FILE,
};

static bool check_params(const struct ppm_evt_hdr *evt,
                         const scap_const_sized_buffer *decoded_params,
                         const uint32_t params_num,
                         char *error) {
	const struct ppm_event_info *evt_info = &scap_get_event_info_table()[evt->type];
	const uint32_t expected_params_num = evt_info->nparams;
	if(scap_unlikely(params_num < expected_params_num)) {
		return scap_errprintf(
		        error,
		        0,
		        "unexpected number of parameters for event '%s' (%d): expected %d, got %d",
		        evt_info->name,
		        evt->type,
		        expected_params_num,
		        params_num);
	}

	const size_t len_size =
	        evt_info->flags & EF_LARGE_PAYLOAD ? sizeof(uint32_t) : sizeof(uint16_t);

	for(int i = 0; i < expected_params_num; i++) {
		const struct ppm_param_info *param = &evt_info->params[i];
		const size_t actual_param_len = decoded_params[i].size;
		uint32_t min_param_len = 0;
		int res = ppm_param_min_len_from_type(param->type, &min_param_len);
		if(scap_unlikely(res < 0)) {
			return scap_errprintf(error,
			                      0,
			                      "bug: nexpected error while getting the minimum length for "
			                      "parameter %d of type %d in event '%s' (%d): %d",
			                      i,
			                      param->type,
			                      evt_info->name,
			                      evt->type,
			                      res);
		}

		uint32_t max_param_len = 0;
		res = ppm_param_max_len_from_type(param->type, len_size, &max_param_len);
		if(scap_unlikely(res < 0)) {
			return scap_errprintf(error,
			                      0,
			                      "bug: unexpected error while getting the maximum length for "
			                      "parameter %d of type %d in event '%s' (%d): %d",
			                      i,
			                      param->type,
			                      evt_info->name,
			                      evt->type,
			                      res);
		}

		if(scap_unlikely(actual_param_len < min_param_len || actual_param_len > max_param_len)) {
			return scap_errprintf(
			        error,
			        0,
			        "unexpected size for parameter %d of type %d in event '%s' (%d): expected "
			        "range [%u; %u], got %lu",
			        i,
			        param->type,
			        evt_info->name,
			        evt->type,
			        min_param_len,
			        max_param_len,
			        actual_param_len);
		}
	}
	return SCAP_SUCCESS;
}

static void parse_fspath_param(char *dst_buf,
                               const size_t dst_buf_size,
                               const scap_const_sized_buffer *param) {
	if(param->size > 0) {
		strlcpy(dst_buf, param->buf, dst_buf_size);
	} else {
		dst_buf[0] = 0;
	}
}

static void set_tinfo_comm_from_comm_param(scap_threadinfo *tinfo,
                                           const scap_const_sized_buffer *param) {
	parse_fspath_param((char *)&tinfo->comm, sizeof(tinfo->comm), param);
}

static void set_tinfo_exe_and_args_from_argv_param(scap_threadinfo *tinfo,
                                                   const scap_const_sized_buffer *param) {
	const char *buf = param->buf;
	const size_t buf_size = param->size;
	if(buf_size == 0) {
		tinfo->exe[0] = 0;
		tinfo->args[0] = 0;
		tinfo->args_len = 0;
		return;
	}

	const size_t n = strlcpy(tinfo->exe, buf, sizeof(tinfo->exe));
	const size_t argv0_size = n + 1 < buf_size ? n + 1 : buf_size;  // `+ 1` to include '\0'.
	tinfo->args_len = buf_size - argv0_size;
	if(tinfo->args_len > 0) {
		memcpy(tinfo->args, buf + argv0_size, tinfo->args_len);
		tinfo->args[tinfo->args_len - 1] = 0;
	} else {
		tinfo->args[0] = 0;
		tinfo->args_len = 0;
	}
}

static void set_tinfo_exepath_from_exepath_param(scap_threadinfo *tinfo,
                                                 const scap_const_sized_buffer *param) {
	parse_fspath_param((char *)&tinfo->exepath, sizeof(tinfo->exepath), param);
}

static void set_tinfo_flags_from_flags_param(scap_threadinfo *tinfo,
                                             const scap_const_sized_buffer *param) {
	uint32_t flags;
	memcpy(&flags, param->buf, sizeof(flags));
	tinfo->exe_writable = (flags & PPM_EXE_WRITABLE) != 0;
	tinfo->exe_upper_layer = (flags & PPM_EXE_UPPER_LAYER) != 0;
	tinfo->exe_lower_layer = (flags & PPM_EXE_LOWER_LAYER) != 0;
	tinfo->exe_from_memfd = (flags & PPM_EXE_FROM_MEMFD) != 0;
}

static void set_tinfo_env_from_env_param(scap_threadinfo *tinfo,
                                         const scap_const_sized_buffer *param) {
	const char *buf = param->buf;
	const size_t buf_size = param->size;
	if(buf_size == 0) {
		tinfo->env[0] = 0;
		tinfo->env_len = 0;
		return;
	}

	const size_t env_size = buf_size <= sizeof(tinfo->env) ? buf_size : sizeof(tinfo->env);
	memcpy(&tinfo->env, buf, env_size);
	// The following is needed when the actual size is capped to `sizeof(tinfo->env)`.
	tinfo->env[env_size - 1] = 0;
	tinfo->env_len = env_size;
}

static void set_tinfo_cwd_from_cwd_param(scap_threadinfo *tinfo,
                                         const scap_const_sized_buffer *param) {
	parse_fspath_param((char *)&tinfo->cwd, sizeof(tinfo->cwd), param);
}

static void set_tinfo_cgroups_from_cgroups_param(scap_threadinfo *tinfo,
                                                 const scap_const_sized_buffer *param) {
	const char *buf = param->buf;
	const size_t buf_size = param->size;
	struct scap_cgroup_set *cgroups = &tinfo->cgroups;
	if(buf_size == 0) {
		cgroups->path[0] = 0;
		cgroups->len = 0;
		return;
	}

	const size_t cgroups_size =
	        buf_size <= sizeof(cgroups->path) ? buf_size : sizeof(cgroups->path);
	memcpy(&cgroups->path, buf, cgroups_size);
	// The following is needed when the actual size is capped to `sizeof(cgroups->path)`.
	cgroups->path[cgroups_size - 1] = 0;
	cgroups->len = cgroups_size;
}

static void set_tinfo_root_from_root_param(scap_threadinfo *tinfo,
                                           const scap_const_sized_buffer *param) {
	parse_fspath_param((char *)&tinfo->root, sizeof(tinfo->root), param);
}

#define COPY_FROM_PARAM(dst, params, param_index) \
	memcpy(&(dst), (params)[param_index].buf, sizeof(dst))

static void get_evt_pid_tid(const struct ppm_evt_hdr *evt, uint32_t *pid_out, uint32_t *tid_out) {
	const uint64_t tgid_pid = evt->tid;
	*pid_out = (uint32_t)tgid_pid;
	*tid_out = (uint32_t)(tgid_pid >> 32);
}

static void parse_task(const struct ppm_evt_hdr *evt,
                       const scap_const_sized_buffer *decoded_params,
                       const struct fetch_callbacks *callbacks,
                       scap_threadinfo **tinfo_out,
                       const scap_sized_buffer *cb_err_buf) {
	scap_threadinfo tinfo = {};
	uint32_t pid, tid;
	get_evt_pid_tid(evt, &pid, &tid);
	tinfo.tid = (uint64_t)tid;
	tinfo.pid = (uint64_t)pid;
	COPY_FROM_PARAM(tinfo.ptid, decoded_params, 0);                      // ppid
	COPY_FROM_PARAM(tinfo.sid, decoded_params, 3);                       // sid
	COPY_FROM_PARAM(tinfo.vpgid, decoded_params, 2);                     // vpgid
	COPY_FROM_PARAM(tinfo.pgid, decoded_params, 1);                      // pgid
	set_tinfo_comm_from_comm_param(&tinfo, &decoded_params[4]);          // comm
	set_tinfo_exe_and_args_from_argv_param(&tinfo, &decoded_params[5]);  // argv
	set_tinfo_exepath_from_exepath_param(&tinfo, &decoded_params[6]);    // exepath
	set_tinfo_flags_from_flags_param(&tinfo, &decoded_params[7]);        // flags
	set_tinfo_env_from_env_param(&tinfo, &decoded_params[8]);            // env
	set_tinfo_cwd_from_cwd_param(&tinfo, &decoded_params[9]);            // cwd
	COPY_FROM_PARAM(tinfo.fdlimit, decoded_params, 10);                  // fdlimit
	// The following logic is copied from `userspace/libscap/linux/scap_procs.c`, and while it is
	// reliable for `PPM_CL_CLONE_THREAD`, it is not for `PPM_CL_CLONE_FILES`. We should directly
	// take this information in kernel.
	tinfo.flags = tinfo.tid == tinfo.pid ? 0 : PPM_CL_CLONE_THREAD | PPM_CL_CLONE_FILES;
	COPY_FROM_PARAM(tinfo.uid, decoded_params, 11);              // euid
	COPY_FROM_PARAM(tinfo.gid, decoded_params, 12);              // egid
	COPY_FROM_PARAM(tinfo.cap_permitted, decoded_params, 13);    // cap_permitted
	COPY_FROM_PARAM(tinfo.cap_effective, decoded_params, 14);    // cap_effective
	COPY_FROM_PARAM(tinfo.cap_inheritable, decoded_params, 15);  // cap_inheritable
	COPY_FROM_PARAM(tinfo.exe_ino, decoded_params, 16);          // exe_ino_num
	COPY_FROM_PARAM(tinfo.exe_ino_ctime, decoded_params, 17);    // exe_ino_ctime
	COPY_FROM_PARAM(tinfo.exe_ino_mtime, decoded_params, 18);    // exe_ino_mtime
	// `exe_ino_ctime_duration_clone_ts` and `exe_ino_ctime_duration_pidns_start` are implicitely
	// set to 0 in `userspace/libscap/linux/scap_procs.c`. We should take this information in
	// kernel.
	tinfo.exe_ino_ctime_duration_clone_ts = 0;
	tinfo.exe_ino_ctime_duration_pidns_start = 0;
	COPY_FROM_PARAM(tinfo.vmsize_kb, decoded_params, 19);               // vm_size
	COPY_FROM_PARAM(tinfo.vmrss_kb, decoded_params, 20);                // vm_rss
	COPY_FROM_PARAM(tinfo.vmswap_kb, decoded_params, 21);               // vm_swap
	COPY_FROM_PARAM(tinfo.pfmajor, decoded_params, 22);                 // pgft_maj
	COPY_FROM_PARAM(tinfo.pfminor, decoded_params, 23);                 // pgft_min
	COPY_FROM_PARAM(tinfo.vtid, decoded_params, 25);                    // vpid
	COPY_FROM_PARAM(tinfo.vpid, decoded_params, 24);                    // vtgid
	COPY_FROM_PARAM(tinfo.pidns_init_start_ts, decoded_params, 26);     // vtgid
	set_tinfo_cgroups_from_cgroups_param(&tinfo, &decoded_params[27]);  // cgroups
	set_tinfo_root_from_root_param(&tinfo, &decoded_params[28]);
	COPY_FROM_PARAM(tinfo.clone_ts, decoded_params, 29);  // start_time
	COPY_FROM_PARAM(tinfo.tty, decoded_params, 30);       // tty
	COPY_FROM_PARAM(tinfo.loginuid, decoded_params, 31);  // loginuid

	DEBUG_PRINT_THREADINFO(&tinfo);

	const int32_t res = callbacks->proc_entry_cb(callbacks->ctx,
	                                             cb_err_buf->buf,
	                                             (int64_t)tid,
	                                             &tinfo,
	                                             NULL,
	                                             tinfo_out);
	if(scap_unlikely(res != SCAP_SUCCESS)) {
		pman_print_msgf(FALCOSECURITY_LOG_SEV_DEBUG,
		                "process entry callback failed with error code %d for thread (pid: %u, "
		                "tid: %u): %.*s",
		                res,
		                pid,
		                tid,
		                (int)cb_err_buf->size,
		                (char *)cb_err_buf->buf);
	}
}

static uint8_t parse_socket_l4_proto(const uint16_t sk_type, const uint16_t sk_proto) {
	switch(sk_type) {
	case SOCK_STREAM:
		return sk_proto == IPPROTO_TCP || sk_proto == IPPROTO_IP ? SCAP_L4_TCP : SCAP_L4_UNKNOWN;
	case SOCK_DGRAM:
		if(sk_proto == IPPROTO_UDP || sk_proto == IPPROTO_IP) {
			return SCAP_L4_UDP;
		}
		if(sk_proto == IPPROTO_ICMP) {
			return SCAP_L4_ICMP;
		}
		return SCAP_L4_UNKNOWN;
	case SOCK_RAW:
		return SCAP_L4_RAW;
	default:
		return SCAP_L4_UNKNOWN;
	}
}

static void parse_task_file_socket_inet(scap_fdinfo *fdinfo,
                                        const scap_const_sized_buffer *decoded_params) {
	uint16_t sk_type, sk_proto;
	COPY_FROM_PARAM(sk_type, decoded_params, 1);   // sk_type
	COPY_FROM_PARAM(sk_proto, decoded_params, 2);  // sk_proto
	const uint16_t l4_proto = parse_socket_l4_proto(sk_type, sk_proto);

	COPY_FROM_PARAM(fdinfo->fd, decoded_params, 0);   // fd
	COPY_FROM_PARAM(fdinfo->ino, decoded_params, 7);  // ino_num

	uint32_t dip, sip;
	uint16_t sport, dport;
	COPY_FROM_PARAM(sip, decoded_params, 3);    // local_ip
	COPY_FROM_PARAM(sport, decoded_params, 4);  // local_port
	COPY_FROM_PARAM(dip, decoded_params, 5);    // remote_ip
	COPY_FROM_PARAM(dport, decoded_params, 6);  // remote_port

	if(dip != 0) {
		fdinfo->type = SCAP_FD_IPV4_SOCK;
		fdinfo->info.ipv4info.sip = sip;
		fdinfo->info.ipv4info.dip = dip;
		fdinfo->info.ipv4info.sport = sport;
		fdinfo->info.ipv4info.dport = dport;
		fdinfo->info.ipv4info.l4proto = l4_proto;
	} else {
		fdinfo->type = SCAP_FD_IPV4_SERVSOCK;
		fdinfo->info.ipv4serverinfo.ip = sip;
		fdinfo->info.ipv4serverinfo.port = sport;
		fdinfo->info.ipv4serverinfo.l4proto = l4_proto;
	}
}

static bool is_ipv6_unspec_addr(uint32_t ip[4]) {
	return ip[0] == 0 && ip[1] == 0 && ip[2] == 0 && ip[3] == 0;
}

static void parse_task_file_socket_inet6(scap_fdinfo *fdinfo,
                                         const scap_const_sized_buffer *decoded_params) {
	uint16_t sk_type, sk_proto;
	COPY_FROM_PARAM(sk_type, decoded_params, 1);   // sk_type
	COPY_FROM_PARAM(sk_proto, decoded_params, 2);  // sk_proto
	const uint16_t l4_proto = parse_socket_l4_proto(sk_type, sk_proto);

	COPY_FROM_PARAM(fdinfo->fd, decoded_params, 0);   // fd
	COPY_FROM_PARAM(fdinfo->ino, decoded_params, 7);  // ino_num

	uint32_t sip[4], dip[4];
	uint16_t sport, dport;
	COPY_FROM_PARAM(sip, decoded_params, 3);    // local_ip
	COPY_FROM_PARAM(sport, decoded_params, 4);  // local_port
	COPY_FROM_PARAM(dip, decoded_params, 5);    // remote_ip
	COPY_FROM_PARAM(dport, decoded_params, 6);  // remote_port

	if(!is_ipv6_unspec_addr(dip)) {
		fdinfo->type = SCAP_FD_IPV6_SOCK;
		memcpy(&fdinfo->info.ipv6info.sip, sip, sizeof(fdinfo->info.ipv6info.sip));
		memcpy(&fdinfo->info.ipv6info.dip, dip, sizeof(fdinfo->info.ipv6info.dip));
		fdinfo->info.ipv6info.sport = sport;
		fdinfo->info.ipv6info.dport = dport;
		fdinfo->info.ipv6info.l4proto = l4_proto;
	} else {
		fdinfo->type = SCAP_FD_IPV6_SERVSOCK;
		memcpy(fdinfo->info.ipv6serverinfo.ip, sip, sizeof(fdinfo->info.ipv6serverinfo.ip));
		fdinfo->info.ipv6serverinfo.port = sport;
		fdinfo->info.ipv6serverinfo.l4proto = l4_proto;
	}
}

static void parse_task_file_socket_unix(scap_fdinfo *fdinfo,
                                        const scap_const_sized_buffer *decoded_params) {
	fdinfo->type = SCAP_FD_UNIX_SOCK;
	COPY_FROM_PARAM(fdinfo->fd, decoded_params, 0);                            // fd
	COPY_FROM_PARAM(fdinfo->ino, decoded_params, 5);                           // ino_num
	COPY_FROM_PARAM(fdinfo->info.unix_socket_info.source, decoded_params, 3);  // sk_pointer
	fdinfo->info.unix_socket_info.destination = 0;
	parse_fspath_param(fdinfo->info.unix_socket_info.fname,
	                   sizeof(fdinfo->info.unix_socket_info.fname),
	                   &decoded_params[4]);  // sun_path
}

static void parse_task_file_socket_netlink(scap_fdinfo *fdinfo,
                                           const scap_const_sized_buffer *decoded_params) {
	fdinfo->type = SCAP_FD_NETLINK;
	COPY_FROM_PARAM(fdinfo->fd, decoded_params, 0);   // fd
	COPY_FROM_PARAM(fdinfo->ino, decoded_params, 3);  // ino_num
}

static void parse_task_file_pipe(scap_fdinfo *fdinfo,
                                 const scap_const_sized_buffer *decoded_params) {
	fdinfo->type = SCAP_FD_FIFO;
	COPY_FROM_PARAM(fdinfo->fd, decoded_params, 0);   // fd
	COPY_FROM_PARAM(fdinfo->ino, decoded_params, 2);  // ino_num
	parse_fspath_param(fdinfo->info.fname, sizeof(fdinfo->info.fname), &decoded_params[1]);  // path
}

static void parse_task_file_directory(scap_fdinfo *fdinfo,
                                      const scap_const_sized_buffer *decoded_params) {
	fdinfo->type = SCAP_FD_DIRECTORY;
	COPY_FROM_PARAM(fdinfo->fd, decoded_params, 0);   // fd
	COPY_FROM_PARAM(fdinfo->ino, decoded_params, 2);  // ino_num
	parse_fspath_param(fdinfo->info.fname, sizeof(fdinfo->info.fname), &decoded_params[1]);  // path
}

static void parse_task_file_regular(scap_fdinfo *fdinfo,
                                    const scap_const_sized_buffer *decoded_params) {
	fdinfo->type = SCAP_FD_FILE_V2;
	COPY_FROM_PARAM(fdinfo->fd, decoded_params, 0);                           // fd
	COPY_FROM_PARAM(fdinfo->ino, decoded_params, 4);                          // ino_num
	COPY_FROM_PARAM(fdinfo->info.regularinfo.open_flags, decoded_params, 2);  // flags
	parse_fspath_param(fdinfo->info.regularinfo.fname,
	                   sizeof(fdinfo->info.regularinfo.fname),
	                   &decoded_params[1]);                                 // path
	COPY_FROM_PARAM(fdinfo->info.regularinfo.mount_id, decoded_params, 3);  // mnt_id
	// Don't know why, but this is always set to 0 in linux/scap_fds.c.
	fdinfo->info.regularinfo.dev = 0;
}

static enum scap_fd_type parse_anon_inode_fd_type(const uint8_t fd_type) {
	switch(fd_type) {
	case ANON_INODE_FD_TYPE_EVENTFD:
		return SCAP_FD_EVENT;
	case ANON_INODE_FD_TYPE_EVENTPOLL:
		return SCAP_FD_EVENTPOLL;
	case ANON_INODE_FD_TYPE_INOTIFY:
		return SCAP_FD_INOTIFY;
	case ANON_INODE_FD_TYPE_SIGNALFD:
		return SCAP_FD_SIGNALFD;
	case ANON_INODE_FD_TYPE_TIMERFD:
		return SCAP_FD_TIMERFD;
	case ANON_INODE_FD_TYPE_IO_URING:
		return SCAP_FD_IOURING;
	case ANON_INODE_FD_TYPE_USERFAULTFD:
		return SCAP_FD_USERFAULTFD;
	case ANON_INODE_FD_TYPE_PIDFD:
		return SCAP_FD_PIDFD;
	case ANON_INODE_FD_TYPE_BPF_MAP:
	case ANON_INODE_FD_TYPE_BPF_PROG:
	case ANON_INODE_FD_TYPE_BPF_LINK:
	case ANON_INODE_FD_TYPE_BPF_ITER:
		return SCAP_FD_BPF;
	case ANON_INODE_FD_TYPE_PERF_EVENT:
	case ANON_INODE_FD_TYPE_UNKNOWN:
	default:
		return SCAP_FD_UNSUPPORTED;
	}
}

static void parse_task_file_anon_inode(scap_fdinfo *fdinfo,
                                       const scap_const_sized_buffer *decoded_params) {
	COPY_FROM_PARAM(fdinfo->fd, decoded_params, 0);  // fd
	uint8_t fd_type;
	COPY_FROM_PARAM(fd_type, decoded_params, 1);  // fd_type
	fdinfo->type = parse_anon_inode_fd_type(fd_type);
	COPY_FROM_PARAM(fdinfo->ino, decoded_params, 3);  // ino_num
	if(fd_type == ANON_INODE_FD_TYPE_UNKNOWN) {
		parse_fspath_param(fdinfo->info.fname,
		                   sizeof(fdinfo->info.fname),
		                   &decoded_params[2]);  // path
	}
}

static void parse_task_file_memfd(scap_fdinfo *fdinfo,
                                  const scap_const_sized_buffer *decoded_params) {
	fdinfo->type = SCAP_FD_MEMFD;
	COPY_FROM_PARAM(fdinfo->fd, decoded_params, 0);                                          // fd
	parse_fspath_param(fdinfo->info.fname, sizeof(fdinfo->info.fname), &decoded_params[1]);  // path
	COPY_FROM_PARAM(fdinfo->ino, decoded_params, 3);  // ino_num
}

static bool is_task_file_socket_evt(const uint16_t evt_type) {
	switch(evt_type) {
	case PPME_ITER_TASK_FILE_SOCKET_INET_X:
	case PPME_ITER_TASK_FILE_SOCKET_INET6_X:
	case PPME_ITER_TASK_FILE_SOCKET_UNIX_X:
	case PPME_ITER_TASK_FILE_SOCKET_NETLINK_X:
		return true;
	default:
		return false;
	}
}

static void parse_task_file(const struct ppm_evt_hdr *evt,
                            const scap_const_sized_buffer *decoded_params,
                            const struct fetch_callbacks *callbacks,
                            const bool must_fetch_sockets,
                            uint64_t *num_files_added,
                            const scap_sized_buffer *cb_err_buf) {
	uint32_t pid, tid;
	get_evt_pid_tid(evt, &pid, &tid);

	const uint16_t evt_type = evt->type;
	if(!must_fetch_sockets && is_task_file_socket_evt(evt_type)) {
		pman_print_msgf(FALCOSECURITY_LOG_SEV_DEBUG,
		                "received socket event type %d with socket fetching disabled for thread "
		                "(pid: %u, tid: %u)",
		                evt_type,
		                pid,
		                tid);
	}

	scap_fdinfo fdinfo = {};

	switch(evt_type) {
	case PPME_ITER_TASK_FILE_SOCKET_INET_X:
		parse_task_file_socket_inet(&fdinfo, decoded_params);
		break;
	case PPME_ITER_TASK_FILE_SOCKET_INET6_X:
		parse_task_file_socket_inet6(&fdinfo, decoded_params);
		break;
	case PPME_ITER_TASK_FILE_SOCKET_UNIX_X:
		parse_task_file_socket_unix(&fdinfo, decoded_params);
		break;
	case PPME_ITER_TASK_FILE_SOCKET_NETLINK_X:
		parse_task_file_socket_netlink(&fdinfo, decoded_params);
		break;
	case PPME_ITER_TASK_FILE_PIPE_X:
		parse_task_file_pipe(&fdinfo, decoded_params);
		break;
	case PPME_ITER_TASK_FILE_DIRECTORY_X:
		parse_task_file_directory(&fdinfo, decoded_params);
		break;
	case PPME_ITER_TASK_FILE_REGULAR_X:
		parse_task_file_regular(&fdinfo, decoded_params);
		break;
	case PPME_ITER_TASK_FILE_ANON_INODE_X:
		parse_task_file_anon_inode(&fdinfo, decoded_params);
		break;
	case PPME_ITER_TASK_FILE_MEMFD_X:
		parse_task_file_memfd(&fdinfo, decoded_params);
		break;
	default:
		pman_print_msgf(FALCOSECURITY_LOG_SEV_DEBUG,
		                "unknown file event type %d for thread (pid: %u, tid: %u, fd: %ld)",
		                evt_type,
		                pid,
		                tid,
		                fdinfo.fd);
		return;
	}

	DEBUG_PRINT_FDINFO(&fdinfo);

	const int32_t res = callbacks->proc_entry_cb(callbacks->ctx,
	                                             cb_err_buf->buf,
	                                             (int64_t)tid,
	                                             NULL,
	                                             &fdinfo,
	                                             NULL);

	if(scap_unlikely(res != SCAP_SUCCESS)) {
		pman_print_msgf(FALCOSECURITY_LOG_SEV_DEBUG,
		                "process entry callback failed with error code %d for file (pid: %u, "
		                "tid: %u, fd: %ld): %.*s",
		                res,
		                pid,
		                tid,
		                fdinfo.fd,
		                (int)cb_err_buf->size,
		                (char *)cb_err_buf->buf);
	}

	if(num_files_added) {
		(*num_files_added)++;
	}
}

static int32_t parse_iter_evts(const int iter_fd,
                               const enum parser_selector selector,
                               const struct fetch_callbacks *callbacks,
                               scap_threadinfo **tinfo,
                               const bool must_fetch_sockets,
                               uint64_t *num_files_added,
                               char *error) {
	char buff[32 * 1024];
	static_assert(sizeof(buff) >= MAX_ITER_EVENT_SIZE, "buff must accommodate at least one event");
	size_t bytes_in_buff = 0;

	char cb_err[256] = {0};
	const scap_sized_buffer cb_err_buf = {&cb_err, sizeof(cb_err)};

	if(num_files_added) {
		*num_files_added = 0;
	}

	while(true) {
		const ssize_t bytes_read =
		        read(iter_fd, buff + bytes_in_buff, sizeof(buff) - bytes_in_buff);
		if(bytes_read < 0) {
			if(errno == EAGAIN || errno == EINTR) {
				continue;
			}
			return scap_errprintf(error, errno, "failed to read from iter FD %d", iter_fd);
		}
		if(bytes_read == 0) {
			return SCAP_SUCCESS;
		}
		bytes_in_buff += bytes_read;

		char *data_start = buff;
		const char *data_end = buff + bytes_in_buff;

		while(true) {
			const size_t data_len = data_end - data_start;
			if(data_len < sizeof(struct ppm_evt_hdr)) {
				break;
			}

			const struct ppm_evt_hdr *evt = (struct ppm_evt_hdr *)data_start;
			const size_t evt_len = evt->len;
			if(data_len < evt_len) {
				break;
			}

			DEBUG_PRINT_EVENT(evt);

			scap_const_sized_buffer decoded_params[PPM_MAX_EVENT_PARAMS];
			// note: we let `scap_event_decode_params()' believe `decoded_params` is a
			// `scap_sized_buffer` array instead of `scap_const_sized_buffer` one, so that it can
			// write into it.
			const uint32_t params_num =
			        scap_event_decode_params(evt, (scap_sized_buffer *)&decoded_params);
			const int32_t res = check_params(evt, decoded_params, params_num, error);
			if(scap_unlikely(res != SCAP_SUCCESS)) {
				return res;
			}

			cb_err[0] = 0;
			switch(selector) {
			case PAR_SEL_TASK:
				parse_task(evt, decoded_params, callbacks, tinfo, &cb_err_buf);
				break;
			case PAR_SEL_TASK_FILE:
				parse_task_file(evt,
				                decoded_params,
				                callbacks,
				                must_fetch_sockets,
				                num_files_added,
				                &cb_err_buf);
				break;
			default:
				return scap_errprintf(error, 0, "bug: unknown parser selector %d", selector);
			}

			data_start += evt_len;
		}

		const size_t processed_data_len = data_start - buff;
		const size_t buff_unprocessed_data_len = bytes_in_buff - processed_data_len;
		if(buff_unprocessed_data_len > 0 && processed_data_len > 0) {
			memmove(buff, buff + processed_data_len, buff_unprocessed_data_len);
		}

		bytes_in_buff = buff_unprocessed_data_len;

		// Do not allow for unprocessed data with size is bigger than the maximum allowed size for
		// an iterator event.
		if(bytes_in_buff >= MAX_ITER_EVENT_SIZE) {
			return scap_errprintf(
			        error,
			        0,
			        "%lu bytes left on the buffer while the maximum allowed event size is %d bytes",
			        bytes_in_buff,
			        MAX_ITER_EVENT_SIZE);
		}
	}
}

struct prog_info {
	struct bpf_link **link;
	const struct bpf_program *prog;
	const char *name;
	enum parser_selector selector;
};

// todo(ekoops): maybe we can avoid updating the link.
// todo(ekoops): error handling.
static int32_t iter(const struct prog_info *prog_info,
                    const struct fetch_callbacks *callbacks,
                    const int pid_filter,
                    const int tid_filter,
                    scap_threadinfo **tinfo,
                    const bool must_fetch_sockets,
                    uint64_t *num_files_added,
                    char *error) {
	if(pid_filter != 0 && tid_filter != 0) {
		return scap_errprintf(error,
		                      0,
		                      "bug: wrong configuration: pid_filter (%d) and tid_filter (%d) "
		                      "cannot be both non-zero",
		                      pid_filter,
		                      tid_filter);
	}

	// The program must not be already attached.
	if(*prog_info->link) {
		return scap_errprintf(error,
		                      0,
		                      "'%s' program is unexpectedly already attached",
		                      prog_info->name);
	}

	errno = 0;
	int32_t res = SCAP_SUCCESS;
	int iter_fd = -1;

	// Attach the program.
	LIBBPF_OPTS(bpf_iter_attach_opts, opts);
	union bpf_iter_link_info linfo;
	memset(&linfo, 0, sizeof(linfo));
	linfo.task.pid = pid_filter;  // If the pid is set to zero, no filtering logic is applied.
	linfo.task.tid = tid_filter;  // If the tid is set to zero, no filtering logic is applied.
	opts.link_info = &linfo;
	opts.link_info_len = sizeof(linfo);
	*prog_info->link = bpf_program__attach_iter(prog_info->prog, &opts);
	if(!*prog_info->link) {
		res = scap_errprintf(error, errno, "failed to attach the '%s' program", prog_info->name);
		goto cleanup;
	}

	// Create the iter FD.
	iter_fd = bpf_iter_create(bpf_link__fd(*prog_info->link));
	if(iter_fd < 0) {
		res = scap_errprintf(error,
		                     errno,
		                     "failed to create iter FD for '%s' program",
		                     prog_info->name);
		goto cleanup;
	}

	res = parse_iter_evts(iter_fd,
	                      prog_info->selector,
	                      callbacks,
	                      tinfo,
	                      must_fetch_sockets,
	                      num_files_added,
	                      error);

cleanup:
	if(iter_fd != -1 && close(iter_fd) < 0) {
		pman_print_errorf("failed to close iter FD for `%s` program", prog_info->name);
	}
	if(*prog_info->link && bpf_link__destroy(*prog_info->link)) {
		pman_print_errorf("failed to detach the `%s` program", prog_info->name);
	}
	*prog_info->link = NULL;
	return res;
}

static void fill_dump_task_prog_info(struct prog_info *info) {
	info->link = &g_state.skel->links.dump_task;
	info->prog = g_state.skel->progs.dump_task;
	info->name = "dump_task";
	info->selector = PAR_SEL_TASK;
}

static void fill_dump_task_file_prog_info(struct prog_info *info) {
	info->link = &g_state.skel->links.dump_task_file;
	info->prog = g_state.skel->progs.dump_task_file;
	info->name = "dump_task_file";
	info->selector = PAR_SEL_TASK_FILE;
}

int32_t pman_iter_fetch_task(const struct fetch_callbacks *callbacks,
                             const uint32_t tid,
                             scap_threadinfo **tinfo,
                             char *error) {
	if(!g_state.is_tasks_dumping_supported) {
		return SCAP_NOT_SUPPORTED;
	}

	struct prog_info prog_info;
	fill_dump_task_prog_info(&prog_info);
	return iter(&prog_info, callbacks, 0, tid, tinfo, NULL, false, error);
}

int32_t pman_iter_fetch_tasks(const struct fetch_callbacks *callbacks, char *error) {
	if(!g_state.is_tasks_dumping_supported) {
		return SCAP_NOT_SUPPORTED;
	}

	struct prog_info prog_info;
	fill_dump_task_prog_info(&prog_info);
	return iter(&prog_info, callbacks, 0, 0, NULL, NULL, false, error);
}

int32_t pman_iter_fetch_proc_file(const struct fetch_callbacks *callbacks,
                                  const uint32_t pid,
                                  const uint32_t fd,
                                  char *error) {
	if(!g_state.is_task_files_dumping_supported) {
		return SCAP_NOT_SUPPORTED;
	}

	const bool must_fetch_sockets = true;
	g_state.skel->data->dump_task_file__fd_filter = (int64_t)fd;
	g_state.skel->data->dump_task_file__must_dump_sockets = must_fetch_sockets;

	struct prog_info prog_info;
	fill_dump_task_file_prog_info(&prog_info);
	return iter(&prog_info, callbacks, pid, 0, NULL, must_fetch_sockets, NULL, error);
}

int32_t pman_iter_fetch_proc_files(const struct fetch_callbacks *callbacks,
                                   const uint32_t pid,
                                   const bool must_fetch_sockets,
                                   uint64_t *num_files_added,
                                   char *error) {
	if(!g_state.is_task_files_dumping_supported) {
		return SCAP_NOT_SUPPORTED;
	}

	g_state.skel->data->dump_task_file__fd_filter = (int64_t)-1;
	g_state.skel->data->dump_task_file__must_dump_sockets = must_fetch_sockets;

	struct prog_info prog_info;
	fill_dump_task_file_prog_info(&prog_info);
	return iter(&prog_info, callbacks, pid, 0, NULL, must_fetch_sockets, num_files_added, error);
}

int32_t pman_iter_fetch_procs_files(const struct fetch_callbacks *callbacks, char *error) {
	if(!g_state.is_task_files_dumping_supported) {
		return SCAP_NOT_SUPPORTED;
	}

	const bool must_fetch_sockets = true;
	g_state.skel->data->dump_task_file__fd_filter = (int64_t)-1;
	g_state.skel->data->dump_task_file__must_dump_sockets = must_fetch_sockets;

	struct prog_info prog_info;
	fill_dump_task_file_prog_info(&prog_info);
	return iter(&prog_info, callbacks, 0, 0, NULL, must_fetch_sockets, NULL, error);
}
