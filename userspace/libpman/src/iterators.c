#include "driver/ppm_events_public.h"
#include "driver/ppm_param_helpers.h"
#include "libscap/scap.h"
#include "libscap/strl.h"

#include <libpman.h>
#include <state.h>
#include <bpf/libbpf.h>
#include <netinet/in.h>

enum parser_selector {
	PAR_SEL_TASK,
	PAR_SEL_TASK_FILE,
};

#ifndef likely
#define likely(x) __builtin_expect(!!(x), 1)
#endif

#ifndef unlikely
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif

static bool check_params(const struct ppm_evt_hdr *evt,
                         const scap_sized_buffer *decoded_params,
                         const uint32_t params_num) {
	const struct ppm_event_info *evt_info = &scap_get_event_info_table()[evt->type];
	const uint32_t expected_params_num = evt_info->nparams;
	if(unlikely(params_num < expected_params_num)) {
		pman_print_errorf(
		        "unexpected number of parameters for event '%s' (%d): expected %d, got %d",
		        evt_info->name,
		        evt->type,
		        expected_params_num,
		        params_num);
		return -1;
	}

	const size_t len_size =
	        evt_info->flags & EF_LARGE_PAYLOAD ? sizeof(uint32_t) : sizeof(uint16_t);

	for(int i = 0; i < expected_params_num; i++) {
		const struct ppm_param_info *param = &evt_info->params[i];
		const size_t actual_param_len = decoded_params[i].size;
		uint32_t min_param_len = 0;
		int res = ppm_param_min_len_from_type(param->type, &min_param_len);
		if(unlikely(res < 0)) {
			pman_print_errorf(
			        "unexpected error while getting the minimum length for parameter %d of type %d "
			        "in event '%s' (%d): %d",
			        i,
			        param->type,
			        evt_info->name,
			        evt->type,
			        res);
			return -1;
		}
		uint32_t max_param_len = 0;
		res = ppm_param_max_len_from_type(param->type, len_size, &max_param_len);
		if(unlikely(res < 0)) {
			pman_print_errorf(
			        "unexpected error while getting the minimum length for parameter %d of type %d "
			        "in event '%s' (%d): %d",
			        i,
			        param->type,
			        evt_info->name,
			        evt->type,
			        res);
			return -1;
		}
		if(unlikely(actual_param_len < min_param_len || actual_param_len > max_param_len)) {
			pman_print_errorf(
			        "unexpected size for parameter %d of type %d in event '%s' (%d): expected "
			        "range [%u; %u], got %lu",
			        i,
			        param->type,
			        evt_info->name,
			        evt->type,
			        min_param_len,
			        max_param_len,
			        actual_param_len);
			return -1;
		}
	}
	return 0;
}

static void parse_fspath_param(char *dst_buf,
                               const size_t dst_buf_size,
                               const scap_sized_buffer *param) {
	if(param->size > 0) {
		strlcpy(dst_buf, param->buf, dst_buf_size);
	} else {
		dst_buf[0] = 0;
	}
}

static void set_tinfo_comm_from_comm_param(struct scap_threadinfo *tinfo,
                                           const scap_sized_buffer *param) {
	parse_fspath_param((char *)&tinfo->comm, sizeof(tinfo->comm), param);
}

static void set_tinfo_exe_and_args_from_argv_param(struct scap_threadinfo *tinfo,
                                                   const scap_sized_buffer *param) {
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

static void set_tinfo_exepath_from_exepath_param(struct scap_threadinfo *tinfo,
                                                 const scap_sized_buffer *param) {
	parse_fspath_param((char *)&tinfo->exepath, sizeof(tinfo->exepath), param);
}

static void set_tinfo_flags_from_flags_param(struct scap_threadinfo *tinfo,
                                             const struct scap_sized_buffer *param) {
	uint32_t flags;
	memcpy(&flags, param->buf, sizeof(flags));
	tinfo->exe_writable = (flags & PPM_EXE_WRITABLE) != 0;
	tinfo->exe_upper_layer = (flags & PPM_EXE_UPPER_LAYER) != 0;
	tinfo->exe_lower_layer = (flags & PPM_EXE_LOWER_LAYER) != 0;
	tinfo->exe_from_memfd = (flags & PPM_EXE_FROM_MEMFD) != 0;
}

static void set_tinfo_env_from_env_param(struct scap_threadinfo *tinfo,
                                         const struct scap_sized_buffer *param) {
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

static void set_tinfo_cwd_from_cwd_param(struct scap_threadinfo *tinfo,
                                         const struct scap_sized_buffer *param) {
	parse_fspath_param((char *)&tinfo->cwd, sizeof(tinfo->cwd), param);
}

static void set_tinfo_cgroups_from_cgroups_param(struct scap_threadinfo *tinfo,
                                                 const struct scap_sized_buffer *param) {
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

static void set_tinfo_root_from_root_param(struct scap_threadinfo *tinfo,
                                           const struct scap_sized_buffer *param) {
	parse_fspath_param((char *)&tinfo->root, sizeof(tinfo->root), param);
}

static void print_charbuff_array(char *label, char *buf, const size_t buf_size) {
	printf("%s:\n", label);
	const char *buf_end = buf + buf_size;
	while(buf < buf_end) {
		const int written = printf("\t%s", buf);
		putchar('\n');
		buf += written;
	}
}

static void print_threadinfo(struct scap_threadinfo *tinfo) {
	printf(""
	       "tinfo.pid: %lu\n"
	       "tinfo.ptid: %lu\n"
	       "tinfo.sid: %lu\n"
	       "tinfo.vpgid: %lu\n"
	       "tinfo.pgid: %lu\n"
	       "tinfo.comm: %s\n"
	       "tinfo.exe: %s\n"
	       "tinfo.exepath: %s\n"
	       "tinfo.exe_writable: %d\n"
	       "tinfo.exe_upper_layer: %d\n"
	       "tinfo.exe_lower_layer: %d\n"
	       "tinfo.exe_from_memfd: %d\n"
	       "tinfo.args_len: %u\n"
	       "tinfo.env_len: %u\n"
	       "tinfo.cwd: %s\n"
	       "tinfo.fdlimit: %ld\n"
	       "tinfo.flags: %u\n"
	       "tinfo.uid: %u\n"
	       "tinfo.gid: %u\n"
	       "tinfo.cap_permitted: %lu\n"
	       "tinfo.cap_effective: %lu\n"
	       "tinfo.cap_inheritable: %lu\n"
	       "tinfo.exe_ino: %lu\n"
	       "tinfo.exe_ino_ctime: %lu\n"
	       "tinfo.exe_ino_mtime: %lu\n"
	       "tinfo.exe_ino_ctime_duration_clone_ts: %lu\n"
	       "tinfo.exe_ino_ctime_duration_pidns_start: %lu\n"
	       "tinfo.vmsize_kb: %u\n"
	       "tinfo.vmrss_kb: %u\n"
	       "tinfo.vmswap_kb: %u\n"
	       "tinfo.pfmajor: %lu\n"
	       "tinfo.pfminor: %lu\n"
	       "tinfo.vtid: %ld\n"
	       "tinfo.vpid: %ld\n"
	       "tinfo.pidns_init_start_ts: %lu\n"
	       "tinfo.root: %s\n"
	       "tinfo.clone_ts: %lu\n"
	       "tinfo.tty: %u\n"
	       "tinfo.loginuid: %u\n",
	       tinfo->pid,
	       tinfo->ptid,
	       tinfo->sid,
	       tinfo->vpgid,
	       tinfo->pgid,
	       tinfo->comm,
	       tinfo->exe,
	       tinfo->exepath,
	       tinfo->exe_writable,
	       tinfo->exe_upper_layer,
	       tinfo->exe_lower_layer,
	       tinfo->exe_from_memfd,
	       tinfo->args_len,
	       tinfo->env_len,
	       tinfo->cwd,
	       tinfo->fdlimit,
	       tinfo->flags,
	       tinfo->uid,
	       tinfo->gid,
	       tinfo->cap_permitted,
	       tinfo->cap_effective,
	       tinfo->cap_inheritable,
	       tinfo->exe_ino,
	       tinfo->exe_ino_ctime,
	       tinfo->exe_ino_mtime,
	       tinfo->exe_ino_ctime_duration_clone_ts,
	       tinfo->exe_ino_ctime_duration_pidns_start,
	       tinfo->vmsize_kb,
	       tinfo->vmrss_kb,
	       tinfo->vmswap_kb,
	       tinfo->pfmajor,
	       tinfo->pfminor,
	       tinfo->vtid,
	       tinfo->vpid,
	       tinfo->pidns_init_start_ts,
	       tinfo->root,
	       tinfo->clone_ts,
	       tinfo->tty,
	       tinfo->loginuid);
	print_charbuff_array("tinfo.args", tinfo->args, tinfo->args_len);
	print_charbuff_array("tinfo.env", tinfo->env, tinfo->env_len);
	print_charbuff_array("tinfo.cgroups", tinfo->cgroups.path, tinfo->cgroups.len);
}

#define COPY_FROM_PARAM(dst, params, param_index) \
	memcpy(&(dst), (params)[param_index].buf, sizeof(dst))

static int parse_task(const struct ppm_evt_hdr *evt) {
	scap_sized_buffer decoded_params[PPM_MAX_EVENT_PARAMS];
	const uint32_t params_num = scap_event_decode_params(evt, decoded_params);
	if(unlikely(check_params(evt, decoded_params, params_num))) {
		return -1;
	}

	scap_threadinfo tinfo = {};
	tinfo.tid = evt->tid;
	COPY_FROM_PARAM(tinfo.pid, decoded_params, 0);                       // tgid
	COPY_FROM_PARAM(tinfo.ptid, decoded_params, 1);                      // ppid
	COPY_FROM_PARAM(tinfo.sid, decoded_params, 4);                       // sid
	COPY_FROM_PARAM(tinfo.vpgid, decoded_params, 3);                     // vpgid
	COPY_FROM_PARAM(tinfo.pgid, decoded_params, 2);                      // pgid
	set_tinfo_comm_from_comm_param(&tinfo, &decoded_params[5]);          // comm
	set_tinfo_exe_and_args_from_argv_param(&tinfo, &decoded_params[6]);  // argv
	set_tinfo_exepath_from_exepath_param(&tinfo, &decoded_params[7]);    // exepath
	set_tinfo_flags_from_flags_param(&tinfo, &decoded_params[8]);        // flags
	set_tinfo_env_from_env_param(&tinfo, &decoded_params[9]);            // env
	set_tinfo_cwd_from_cwd_param(&tinfo, &decoded_params[10]);           // cwd
	COPY_FROM_PARAM(tinfo.fdlimit, decoded_params, 11);                  // fdlimit
	// The following logic is copied from `userspace/libscap/linux/scap_procs.c`, and while it is
	// reliable for `PPM_CL_CLONE_THREAD`, it is not for `PPM_CL_CLONE_FILES`. We should directly
	// take this information in kernel.
	tinfo.flags = tinfo.tid == tinfo.pid ? 0 : PPM_CL_CLONE_THREAD | PPM_CL_CLONE_FILES;
	COPY_FROM_PARAM(tinfo.uid, decoded_params, 12);              // euid
	COPY_FROM_PARAM(tinfo.gid, decoded_params, 13);              // egid
	COPY_FROM_PARAM(tinfo.cap_permitted, decoded_params, 14);    // cap_permitted
	COPY_FROM_PARAM(tinfo.cap_effective, decoded_params, 15);    // cap_effective
	COPY_FROM_PARAM(tinfo.cap_inheritable, decoded_params, 16);  // cap_inheritable
	COPY_FROM_PARAM(tinfo.exe_ino, decoded_params, 17);          // exe_ino_num
	COPY_FROM_PARAM(tinfo.exe_ino_ctime, decoded_params, 18);    // exe_ino_ctime
	COPY_FROM_PARAM(tinfo.exe_ino_mtime, decoded_params, 19);    // exe_ino_mtime
	// `exe_ino_ctime_duration_clone_ts` and `exe_ino_ctime_duration_pidns_start` are implicitely
	// set to 0 in `userspace/libscap/linux/scap_procs.c`. We should take this information in
	// kernel.
	tinfo.exe_ino_ctime_duration_clone_ts = 0;
	tinfo.exe_ino_ctime_duration_pidns_start = 0;
	COPY_FROM_PARAM(tinfo.vmsize_kb, decoded_params, 20);               // vm_size
	COPY_FROM_PARAM(tinfo.vmrss_kb, decoded_params, 21);                // vm_rss
	COPY_FROM_PARAM(tinfo.vmswap_kb, decoded_params, 22);               // vm_swap
	COPY_FROM_PARAM(tinfo.pfmajor, decoded_params, 23);                 // pgft_maj
	COPY_FROM_PARAM(tinfo.pfminor, decoded_params, 24);                 // pgft_min
	COPY_FROM_PARAM(tinfo.vtid, decoded_params, 26);                    // vpid
	COPY_FROM_PARAM(tinfo.vpid, decoded_params, 25);                    // vtgid
	COPY_FROM_PARAM(tinfo.pidns_init_start_ts, decoded_params, 27);     // vtgid
	set_tinfo_cgroups_from_cgroups_param(&tinfo, &decoded_params[28]);  // cgroups
	set_tinfo_root_from_root_param(&tinfo, &decoded_params[29]);
	// TODO(ekoops): implement support for clone_ts
	tinfo.clone_ts = 0;
	COPY_FROM_PARAM(tinfo.tty, decoded_params, 30);       // tty
	COPY_FROM_PARAM(tinfo.loginuid, decoded_params, 31);  // loginuid
	print_threadinfo(&tinfo);
	return 0;
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

static int parse_task_file_socket_inet(struct ppm_evt_hdr *evt) {
	scap_sized_buffer decoded_params[PPM_MAX_EVENT_PARAMS];
	const uint32_t params_num = scap_event_decode_params(evt, decoded_params);
	if(unlikely(check_params(evt, decoded_params, params_num))) {
		return -1;
	}

	uint16_t sk_type, sk_proto;
	COPY_FROM_PARAM(sk_type, decoded_params, 1);   // sk_type
	COPY_FROM_PARAM(sk_proto, decoded_params, 2);  // sk_proto
	uint16_t l4_proto = parse_socket_l4_proto(sk_type, sk_proto);

	scap_fdinfo fdinfo = {};

	COPY_FROM_PARAM(fdinfo.fd, decoded_params, 0);   // fd
	COPY_FROM_PARAM(fdinfo.ino, decoded_params, 7);  // ino_num

	uint32_t dip, sip;
	uint16_t sport, dport;
	COPY_FROM_PARAM(sip, decoded_params, 3);    // local_ip
	COPY_FROM_PARAM(sport, decoded_params, 4);  // local_port
	COPY_FROM_PARAM(dip, decoded_params, 5);    // remote_ip
	COPY_FROM_PARAM(dport, decoded_params, 6);  // remote_port

	if(dip != 0) {
		fdinfo.type = SCAP_FD_IPV4_SOCK;
		fdinfo.info.ipv4info.sip = sip;
		fdinfo.info.ipv4info.dip = dip;
		fdinfo.info.ipv4info.sport = sport;
		fdinfo.info.ipv4info.dport = dport;
		fdinfo.info.ipv4info.l4proto = l4_proto;
	} else {
		fdinfo.type = SCAP_FD_IPV4_SERVSOCK;
		fdinfo.info.ipv4serverinfo.ip = sip;
		fdinfo.info.ipv4serverinfo.port = sport;
		fdinfo.info.ipv4serverinfo.l4proto = l4_proto;
	}

	scap_print_event(evt, PRINT_FULL);
	return 0;
}

static bool is_ipv6_unspec_addr(uint32_t ip[4]) {
	return ip[0] == 0 && ip[1] == 0 && ip[2] == 0 && ip[3] == 0;
}

static int parse_task_file_socket_inet6(struct ppm_evt_hdr *evt) {
	scap_sized_buffer decoded_params[PPM_MAX_EVENT_PARAMS];
	const uint32_t params_num = scap_event_decode_params(evt, decoded_params);
	if(unlikely(check_params(evt, decoded_params, params_num))) {
		return -1;
	}

	uint16_t sk_type, sk_proto;
	COPY_FROM_PARAM(sk_type, decoded_params, 1);   // sk_type
	COPY_FROM_PARAM(sk_proto, decoded_params, 2);  // sk_proto
	uint16_t l4_proto = parse_socket_l4_proto(sk_type, sk_proto);

	scap_fdinfo fdinfo = {};

	COPY_FROM_PARAM(fdinfo.fd, decoded_params, 0);   // fd
	COPY_FROM_PARAM(fdinfo.ino, decoded_params, 7);  // ino_num

	uint32_t sip[4], dip[4];
	uint16_t sport, dport;
	COPY_FROM_PARAM(sip, decoded_params, 3);    // local_ip
	COPY_FROM_PARAM(sport, decoded_params, 4);  // local_port
	COPY_FROM_PARAM(dip, decoded_params, 5);    // remote_ip
	COPY_FROM_PARAM(dport, decoded_params, 6);  // remote_port

	if(!is_ipv6_unspec_addr(dip)) {
		fdinfo.type = SCAP_FD_IPV6_SOCK;
		memcpy(&fdinfo.info.ipv6info.sip, sip, sizeof(fdinfo.info.ipv6info.sip));
		memcpy(&fdinfo.info.ipv6info.dip, dip, sizeof(fdinfo.info.ipv6info.dip));
		fdinfo.info.ipv6info.sport = sport;
		fdinfo.info.ipv6info.dport = dport;
		fdinfo.info.ipv6info.l4proto = l4_proto;
	} else {
		fdinfo.type = SCAP_FD_IPV6_SERVSOCK;
		memcpy(fdinfo.info.ipv6serverinfo.ip, sip, sizeof(fdinfo.info.ipv6serverinfo.ip));
		fdinfo.info.ipv6serverinfo.port = sport;
		fdinfo.info.ipv6serverinfo.l4proto = l4_proto;
	}

	scap_print_event(evt, PRINT_FULL);
	return 0;
}

static int parse_task_file_socket_unix(struct ppm_evt_hdr *evt) {
	scap_sized_buffer decoded_params[PPM_MAX_EVENT_PARAMS];
	const uint32_t params_num = scap_event_decode_params(evt, decoded_params);
	if(unlikely(check_params(evt, decoded_params, params_num))) {
		return -1;
	}

	scap_fdinfo fdinfo = {};
	fdinfo.type = SCAP_FD_UNIX_SOCK;
	COPY_FROM_PARAM(fdinfo.fd, decoded_params, 0);                            // fd
	COPY_FROM_PARAM(fdinfo.ino, decoded_params, 5);                           // ino_num
	COPY_FROM_PARAM(fdinfo.info.unix_socket_info.source, decoded_params, 3);  // sk_pointer
	fdinfo.info.unix_socket_info.destination = 0;
	parse_fspath_param(fdinfo.info.unix_socket_info.fname,
	                   sizeof(fdinfo.info.unix_socket_info.fname),
	                   &decoded_params[4]);  // sun_path

	scap_print_event(evt, PRINT_FULL);
	return 0;
}

static int parse_task_file_pipe(struct ppm_evt_hdr *evt) {
	scap_sized_buffer decoded_params[PPM_MAX_EVENT_PARAMS];
	const uint32_t params_num = scap_event_decode_params(evt, decoded_params);
	if(unlikely(check_params(evt, decoded_params, params_num))) {
		return -1;
	}

	scap_fdinfo fdinfo = {};
	fdinfo.type = SCAP_FD_FIFO;
	COPY_FROM_PARAM(fdinfo.fd, decoded_params, 0);   // fd
	COPY_FROM_PARAM(fdinfo.ino, decoded_params, 2);  // ino_num
	parse_fspath_param(fdinfo.info.fname, sizeof(fdinfo.info.fname), &decoded_params[1]);  // path

	scap_print_event(evt, PRINT_FULL);
	return 0;
}

static int parse_task_file_directory(struct ppm_evt_hdr *evt) {
	scap_sized_buffer decoded_params[PPM_MAX_EVENT_PARAMS];
	const uint32_t params_num = scap_event_decode_params(evt, decoded_params);
	if(unlikely(check_params(evt, decoded_params, params_num))) {
		return -1;
	}

	scap_fdinfo fdinfo = {};
	fdinfo.type = SCAP_FD_DIRECTORY;
	COPY_FROM_PARAM(fdinfo.fd, decoded_params, 0);   // fd
	COPY_FROM_PARAM(fdinfo.ino, decoded_params, 2);  // ino_num
	parse_fspath_param(fdinfo.info.fname, sizeof(fdinfo.info.fname), &decoded_params[1]);  // path

	scap_print_event(evt, PRINT_FULL);
	return 0;
}

static int parse_task_file_regular(struct ppm_evt_hdr *evt) {
	scap_sized_buffer decoded_params[PPM_MAX_EVENT_PARAMS];
	const uint32_t params_num = scap_event_decode_params(evt, decoded_params);
	if(unlikely(check_params(evt, decoded_params, params_num))) {
		return -1;
	}

	scap_fdinfo fdinfo = {};
	fdinfo.type = SCAP_FD_FILE_V2;
	COPY_FROM_PARAM(fdinfo.fd, decoded_params, 0);                           // fd
	COPY_FROM_PARAM(fdinfo.ino, decoded_params, 4);                          // ino_num
	COPY_FROM_PARAM(fdinfo.info.regularinfo.open_flags, decoded_params, 2);  // flags
	parse_fspath_param(fdinfo.info.regularinfo.fname,
	                   sizeof(fdinfo.info.regularinfo.fname),
	                   &decoded_params[1]);                                // path
	COPY_FROM_PARAM(fdinfo.info.regularinfo.mount_id, decoded_params, 3);  // mnt_id
	// Don't know why, but this is always set to 0 in linux/scap_fds.c.
	fdinfo.info.regularinfo.dev = 0;

	scap_print_event(evt, PRINT_FULL);
	return 0;
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
		return SCAP_FD_BPF;
	case ANON_INODE_FD_TYPE_PERF_EVENT:
	case ANON_INODE_FD_TYPE_DMABUF:
	case ANON_INODE_FD_TYPE_UNKNOWN:
	default:
		return SCAP_FD_UNSUPPORTED;
	}
}

static int parse_task_file_anon_inode(struct ppm_evt_hdr *evt) {
	scap_sized_buffer decoded_params[PPM_MAX_EVENT_PARAMS];
	const uint32_t params_num = scap_event_decode_params(evt, decoded_params);
	if(unlikely(check_params(evt, decoded_params, params_num))) {
		return -1;
	}

	scap_fdinfo fdinfo = {};
	COPY_FROM_PARAM(fdinfo.fd, decoded_params, 0);  // fd
	uint8_t fd_type;
	COPY_FROM_PARAM(fd_type, decoded_params, 1);  // fd_type
	fdinfo.type = parse_anon_inode_fd_type(fd_type);
	COPY_FROM_PARAM(fdinfo.ino, decoded_params, 3);  // ino_num
	if(fd_type == ANON_INODE_FD_TYPE_UNKNOWN) {
		parse_fspath_param(fdinfo.info.fname,
		                   sizeof(fdinfo.info.fname),
		                   &decoded_params[2]);  // path
	}

	scap_print_event(evt, PRINT_FULL);
	return 0;
}

static int parse_task_file_memfd(struct ppm_evt_hdr *evt) {
	scap_sized_buffer decoded_params[PPM_MAX_EVENT_PARAMS];
	const uint32_t params_num = scap_event_decode_params(evt, decoded_params);
	if(unlikely(check_params(evt, decoded_params, params_num))) {
		return -1;
	}

	scap_fdinfo fdinfo = {};
	fdinfo.type = SCAP_FD_MEMFD;
	COPY_FROM_PARAM(fdinfo.fd, decoded_params, 0);                                         // fd
	parse_fspath_param(fdinfo.info.fname, sizeof(fdinfo.info.fname), &decoded_params[1]);  // path
	COPY_FROM_PARAM(fdinfo.ino, decoded_params, 3);  // ino_num

	scap_print_event(evt, PRINT_FULL);
	return 0;
}

static int parse_task_file(struct ppm_evt_hdr *evt) {
	scap_print_event(evt, PRINT_FULL);
	switch(evt->type) {
	case PPME_ITER_TASK_FILE_SOCKET_INET_X:
		return parse_task_file_socket_inet(evt);
	case PPME_ITER_TASK_FILE_SOCKET_INET6_X:
		return parse_task_file_socket_inet6(evt);
	case PPME_ITER_TASK_FILE_SOCKET_UNIX_X:
		return parse_task_file_socket_unix(evt);
	case PPME_ITER_TASK_FILE_PIPE_X:
		return parse_task_file_pipe(evt);
	case PPME_ITER_TASK_FILE_DIRECTORY_X:
		return parse_task_file_directory(evt);
	case PPME_ITER_TASK_FILE_REGULAR_X:
		return parse_task_file_regular(evt);
	case PPME_ITER_TASK_FILE_ANON_INODE_X:
		return parse_task_file_anon_inode(evt);
	case PPME_ITER_TASK_FILE_MEMFD_X:
		return parse_task_file_memfd(evt);
	default:
		return -1;
	}
}

static int parse(const int iter_fd, const enum parser_selector selector) {
	char buff[32 * 1024];
	size_t bytes_in_buff = 0;

	while(true) {
		const ssize_t bytes_read =
		        read(iter_fd, buff + bytes_in_buff, sizeof(buff) - bytes_in_buff);
		if(bytes_read < 0) {
			if(errno == EAGAIN || errno == EINTR) {
				continue;
			}
			return -errno;
		}
		if(bytes_read == 0) {
			return 0;
		}
		bytes_in_buff += bytes_read;

		char *data_start = buff;
		const char *data_end = buff + bytes_in_buff;

		while(true) {
			const size_t data_len = data_end - data_start;
			if(data_len < sizeof(struct ppm_evt_hdr)) {
				break;
			}

			struct ppm_evt_hdr *evt = (struct ppm_evt_hdr *)data_start;
			const size_t evt_len = evt->len;
			if(data_len < evt_len) {
				break;
			}

			int res;
			switch(selector) {
			case PAR_SEL_TASK:
				res = parse_task(evt);
				break;
			case PAR_SEL_TASK_FILE:
				res = parse_task_file(evt);
				break;
			default:
				pman_print_errorf("Unknown parser selector %d", selector);
				return -1;
			}

			if(res) {
				return res;
			}

			data_start += evt_len;
		}

		const size_t processed_data_len = data_start - buff;
		const size_t buff_unprocessed_data_len = bytes_in_buff - processed_data_len;
		if(buff_unprocessed_data_len > 0 && processed_data_len > 0) {
			memmove(buff, buff + processed_data_len, buff_unprocessed_data_len);
		}

		bytes_in_buff = buff_unprocessed_data_len;

		if(bytes_in_buff == sizeof(buff)) {
			// we do not allow for an event to be bigger than the stack-allocated buffer size.
			fprintf(stderr,
			        "event is bigger as the stack-allocated buffer. This should never happen\n");
			return -1;
		}
	}
}

// todo(ekoops): maybe we can avoid updating the link.
// todo(ekoops): error handling.
static int iter(struct bpf_link **link,
                const struct bpf_program *prog,
                char *prog_name,
                const int pid_filter,
                const int tid_filter,
                enum parser_selector selector,
                void *error) {
	errno = 0;
	if(pid_filter != 0 && tid_filter != 0) {
		pman_print_errorf(
		        "Wrong configuration: pid_filter (%d) and tid_filter (%d) cannot be both non-zero",
		        pid_filter,
		        tid_filter);
		return -1;
	}

	/* The program is already attached. */
	if(*link != NULL) {
		pman_print_errorf("'%s' program is unexpectedly already attached", prog_name);
		return -1;
	}

	int err = 0;
	int iter_fd = -1;

	LIBBPF_OPTS(bpf_iter_attach_opts, opts);
	union bpf_iter_link_info linfo;
	memset(&linfo, 0, sizeof(linfo));
	linfo.task.pid = pid_filter; /* If the pid is set to zero, no filtering logic is applied */
	linfo.task.tid = tid_filter; /* If the tid is set to zero, no filtering logic is applied */
	opts.link_info = &linfo;
	opts.link_info_len = sizeof(linfo);

	struct bpf_link *prog_link = bpf_program__attach_iter(prog, &opts);
	if(!prog_link) {
		err = -errno;
		pman_print_errorf("failed to attach the '%s' program", prog_name);
		goto cleanup;
	}
	*link = prog_link;

	iter_fd = bpf_iter_create(bpf_link__fd(prog_link));
	if(iter_fd < 0) {
		err = -1;
		pman_print_errorf("failed to create iterator FD for '%s' program", prog_name);
		goto cleanup;
	}

	printf("'%s' program attached\n", prog_name);

	parse(iter_fd, selector);

cleanup:
	if(iter_fd != -1 && close(iter_fd) < 0) {
		pman_print_errorf("failed to close iterator FD for `%s` program", prog_name);
	}
	if(bpf_link__destroy(prog_link)) {
		pman_print_errorf("failed to detach the `%s` program", prog_name);
	}
	*link = NULL;
	return err;
}

int pman_iter_get_tasks(const int tid_filter, void *error) {
	if(!g_state.is_tasks_dumping_supported) {
		return ENOTSUP;
	}

	return iter(&g_state.skel->links.dump_task,
	            g_state.skel->progs.dump_task,
	            "dump_task",
	            0,
	            tid_filter,
	            PAR_SEL_TASK,
	            error);
}

int pman_iter_get_task_files(const int pid_filter, const int fd_filter, void *error) {
	if(!g_state.is_task_files_dumping_supported) {
		return ENOTSUP;
	}

	g_state.skel->data->dump_task_file_fd_filter = (int64_t)fd_filter;

	return iter(&g_state.skel->links.dump_task_file,
	            g_state.skel->progs.dump_task_file,
	            "dump_task_file",
	            pid_filter,
	            0,
	            PAR_SEL_TASK_FILE,
	            error);
}
