// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2023 The Falco Authors.

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

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/param.h>
#include <dirent.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>

#include <libscap/linux/unixid.h>
#include <libscap/scap.h>
#include <libscap/scap-int.h>
#include <libscap/linux/scap_cgroup.h>
#include <libscap/linux/scap_linux_int.h>
#include <libscap/linux/scap_linux_platform.h>
#include <libscap/strerror.h>
#include <libscap/clock_helpers.h>
#include <libscap/debug_log_helpers.h>

int32_t scap_proc_fill_cwd(char* error, char* procdirname, struct scap_threadinfo* tinfo) {
	int target_res;
	char filename[SCAP_MAX_PATH_SIZE];

	snprintf(filename, sizeof(filename), "%scwd", procdirname);

	target_res = readlink(filename, tinfo->cwd, sizeof(tinfo->cwd) - 1);
	if(target_res <= 0) {
		return scap_errprintf(error, errno, "readlink %s failed", filename);
	}

	tinfo->cwd[target_res] = '\0';
	return SCAP_SUCCESS;
}

int32_t scap_proc_fill_info_from_stats(char* error,
                                       char* procdirname,
                                       struct scap_threadinfo* tinfo) {
	char filename[SCAP_MAX_PATH_SIZE];
	uint32_t pidinfo_nfound = 0;
	uint32_t caps_nfound = 0;
	uint32_t vm_nfound = 0;
	int64_t tmp;
	uint32_t uid;
	uint64_t tgid;
	uint64_t cap_permitted;
	uint64_t cap_effective;
	uint64_t cap_inheritable;
	uint64_t ppid;
	uint64_t vpid;
	uint64_t vtid;
	int64_t sid;
	int64_t pgid;
	int64_t vpgid;
	uint32_t vmsize_kb;
	uint32_t vmrss_kb;
	uint32_t vmswap_kb;
	uint64_t pfmajor;
	uint64_t pfminor;
	uint32_t tty;
	char line[512];
	char tmpc;
	char* s;

	tinfo->uid = (uint32_t)-1;
	tinfo->ptid = (uint32_t)-1LL;
	tinfo->sid = 0;
	tinfo->vpgid = 0;
	tinfo->pgid = -1;
	tinfo->vmsize_kb = 0;
	tinfo->vmrss_kb = 0;
	tinfo->vmswap_kb = 0;
	tinfo->pfmajor = 0;
	tinfo->pfminor = 0;
	tinfo->filtered_out = 0;
	tinfo->tty = 0;

	snprintf(filename, sizeof(filename), "%sstatus", procdirname);

	FILE* f = fopen(filename, "r");
	if(f == NULL) {
		ASSERT(false);
		return scap_errprintf(error, errno, "open status file %s failed", filename);
	}

	while(fgets(line, sizeof(line), f) != NULL) {
		if(strstr(line, "Tgid") == line) {
			pidinfo_nfound++;

			if(sscanf(line, "Tgid: %" PRIu64, &tgid) == 1) {
				tinfo->pid = tgid;
			} else {
				ASSERT(false);
			}
		}
		if(strstr(line, "Uid") == line) {
			pidinfo_nfound++;

			if(sscanf(line, "Uid: %" PRIu64 " %" PRIu32, &tmp, &uid) == 2) {
				tinfo->uid = uid;
			} else {
				ASSERT(false);
			}
		} else if(strstr(line, "Gid") == line) {
			pidinfo_nfound++;

			if(sscanf(line, "Gid: %" PRIu64 " %" PRIu32, &tmp, &uid) == 2) {
				tinfo->gid = uid;
			} else {
				ASSERT(false);
			}
		}
		if(strstr(line, "CapInh") == line) {
			caps_nfound++;

			if(sscanf(line, "CapInh: %" PRIx64, &cap_inheritable) == 1) {
				tinfo->cap_inheritable = cap_inheritable;
			} else {
				ASSERT(false);
			}
		}
		if(strstr(line, "CapPrm") == line) {
			caps_nfound++;

			if(sscanf(line, "CapPrm: %" PRIx64, &cap_permitted) == 1) {
				tinfo->cap_permitted = cap_permitted;
			} else {
				ASSERT(false);
			}
		}
		if(strstr(line, "CapEff") == line) {
			caps_nfound++;

			if(sscanf(line, "CapEff: %" PRIx64, &cap_effective) == 1) {
				tinfo->cap_effective = cap_effective;
			} else {
				ASSERT(false);
			}
		} else if(strstr(line, "PPid") == line) {
			pidinfo_nfound++;

			if(sscanf(line, "PPid: %" PRIu64, &ppid) == 1) {
				tinfo->ptid = ppid;
			} else {
				ASSERT(false);
			}
		} else if(strstr(line, "VmSize:") == line) {
			vm_nfound++;

			if(sscanf(line, "VmSize: %" PRIu32, &vmsize_kb) == 1) {
				tinfo->vmsize_kb = vmsize_kb;
			} else {
				ASSERT(false);
			}
		} else if(strstr(line, "VmRSS:") == line) {
			vm_nfound++;

			if(sscanf(line, "VmRSS: %" PRIu32, &vmrss_kb) == 1) {
				tinfo->vmrss_kb = vmrss_kb;
			} else {
				ASSERT(false);
			}
		} else if(strstr(line, "VmSwap:") == line) {
			vm_nfound++;

			if(sscanf(line, "VmSwap: %" PRIu32, &vmswap_kb) == 1) {
				tinfo->vmswap_kb = vmswap_kb;
			} else {
				ASSERT(false);
			}
		} else if(strstr(line, "NSpid:") == line) {
			pidinfo_nfound++;
			if(sscanf(line, "NSpid: %*u %" PRIu64, &vtid) == 1) {
				tinfo->vtid = vtid;
			} else {
				tinfo->vtid = tinfo->tid;
			}
		} else if(strstr(line, "NSpgid:") == line) {
			pidinfo_nfound++;
			// We are assuming that the second id in the line is the vpgid we are looking for.
			// This is not true in case of nested pid namespaces, but i'm not sure we support them.
			if(sscanf(line, "NSpgid: %" PRIu64 " %" PRIu64, &pgid, &vpgid) == 2) {
				tinfo->vpgid = vpgid;
				tinfo->pgid = pgid;
			}
		} else if(strstr(line, "NStgid:") == line) {
			pidinfo_nfound++;
			if(sscanf(line, "NStgid: %*u %" PRIu64, &vpid) == 1) {
				tinfo->vpid = vpid;
			} else {
				tinfo->vpid = tinfo->pid;
			}
		}

		if(pidinfo_nfound == 7 && caps_nfound == 3 && vm_nfound == 3) {
			break;
		}
	}

	// We must fetch all pidinfo information
	ASSERT(pidinfo_nfound == 7);

	// Capability info may not be found, but it's all or nothing
	ASSERT(caps_nfound == 0 || caps_nfound == 3);

	// VM info may not be found, but it's all or nothing
	ASSERT(vm_nfound == 0 || vm_nfound == 3);

	fclose(f);

	snprintf(filename, sizeof(filename), "%sstat", procdirname);

	f = fopen(filename, "r");
	if(f == NULL) {
		ASSERT(false);
		return scap_errprintf(error, errno, "read stat file %s failed", filename);
	}

	size_t ssres = fread(line, 1, sizeof(line) - 1, f);
	if(ssres == 0) {
		ASSERT(false);
		fclose(f);
		return scap_errprintf(error, errno, "Could not read from stat file %s", filename);
	}
	line[ssres] = 0;

	s = strrchr(line, ')');
	if(s == NULL) {
		ASSERT(false);
		fclose(f);
		return scap_errprintf(error, 0, "Could not find closing bracket in stat file %s", filename);
	}

	//
	// Extract the line content
	//
	if(sscanf(s + 2,
	          "%c %" PRId64 " %" PRId64 " %" PRId64 " %" PRIu32 " %" PRId64 " %" PRId64 " %" PRId64
	          " %" PRId64 " %" PRId64,
	          &tmpc,
	          &tmp,
	          &pgid,
	          &sid,
	          &tty,
	          &tmp,
	          &tmp,
	          &pfminor,
	          &tmp,
	          &pfmajor) != 10) {
		ASSERT(false);
		fclose(f);
		return scap_errprintf(error,
		                      0,
		                      "Could not read expected fields from stat file %s",
		                      filename);
	}

	tinfo->pfmajor = pfmajor;
	tinfo->pfminor = pfminor;
	tinfo->sid = (uint64_t)sid;

	// If we did not find pgid above in /proc/[pid]/status, we use the one from /proc/[pid]/stat
	if(tinfo->pgid == -1) {
		tinfo->pgid = pgid;
	}

	tinfo->tty = tty;

	fclose(f);
	return SCAP_SUCCESS;
}

//
// use prlimit to extract the RLIMIT_NOFILE for the tid. On systems where prlimit
// is not supported, just return -1
//
static int32_t scap_proc_fill_flimit(uint64_t tid, struct scap_threadinfo* tinfo)
#ifdef SYS_prlimit64
{
	struct rlimit rl;

#ifdef __NR_prlimit64
	if(syscall(SYS_prlimit64, tid, RLIMIT_NOFILE, NULL, &rl) == 0) {
		tinfo->fdlimit = rl.rlim_cur;
		return SCAP_SUCCESS;
	}
#endif

	tinfo->fdlimit = -1;
	return SCAP_SUCCESS;
}
#else
{
	tinfo->fdlimit = -1;
	return SCAP_SUCCESS;
}
#endif

int32_t scap_proc_fill_pidns_start_ts(char* error,
                                      struct scap_threadinfo* tinfo,
                                      const char* procdirname) {
	char proc_cmdline_pidns[SCAP_MAX_PATH_SIZE];
	struct stat targetstat = {0};

	// Note: with this implementation, the "container start time" for host
	// processes will not be equal to the boot time but to the time when the
	// host init started.
	snprintf(proc_cmdline_pidns, sizeof(proc_cmdline_pidns), "%sroot/proc/1/cmdline", procdirname);
	if(stat(proc_cmdline_pidns, &targetstat) == 0) {
		tinfo->pidns_init_start_ts =
		        targetstat.st_ctim.tv_sec * SECOND_TO_NS + targetstat.st_ctim.tv_nsec;
		return SCAP_SUCCESS;
	} else {
		tinfo->pidns_init_start_ts = 0;
		return SCAP_FAILURE;
	}
}

static int32_t scap_get_vtid(struct scap_linux_platform* platform, uint64_t tid, int64_t* vtid) {
	if(platform->m_linux_vtable && platform->m_linux_vtable->get_vtid) {
		return platform->m_linux_vtable->get_vtid(platform->m_engine, tid, vtid);
	}

	ASSERT(false);
	return SCAP_FAILURE;
}

static int32_t scap_get_vpid(struct scap_linux_platform* platform, int64_t pid, int64_t* vpid) {
	if(platform->m_linux_vtable && platform->m_linux_vtable->get_vpid) {
		return platform->m_linux_vtable->get_vpid(platform->m_engine, pid, vpid);
	}

	ASSERT(false);
	return SCAP_FAILURE;
}

int32_t scap_proc_fill_root(char* error, struct scap_threadinfo* tinfo, const char* procdirname) {
	char root_path[SCAP_MAX_PATH_SIZE];
	snprintf(root_path, sizeof(root_path), "%sroot", procdirname);
	ssize_t r = readlink(root_path, tinfo->root, sizeof(tinfo->root) - 1);
	if(r > 0) {
		tinfo->root[r] = '\0';
		return SCAP_SUCCESS;
	} else {
		return scap_errprintf(error, errno, "readlink %s failed", root_path);
	}
}

int32_t scap_proc_fill_loginuid(char* error,
                                struct scap_threadinfo* tinfo,
                                const char* procdirname) {
	uint32_t loginuid;
	char loginuid_path[SCAP_MAX_PATH_SIZE];
	char line[512];
	snprintf(loginuid_path, sizeof(loginuid_path), "%sloginuid", procdirname);
	FILE* f = fopen(loginuid_path, "r");
	if(f == NULL) {
		// If Linux kernel is built with CONFIG_AUDIT=n, loginuid management
		// (and associated /proc file) is not implemented.
		// Record default loginuid value of invalid uid in this case.
		tinfo->loginuid = (uint32_t)UINT32_MAX;
		return SCAP_SUCCESS;
	}
	if(fgets(line, sizeof(line), f) == NULL) {
		ASSERT(false);
		fclose(f);
		return scap_errprintf(error, errno, "Could not read loginuid from %s", loginuid_path);
	}

	fclose(f);

	if(sscanf(line, "%" PRIu32, &loginuid) == 1) {
		tinfo->loginuid = loginuid;
		return SCAP_SUCCESS;
	} else {
		ASSERT(false);
		return scap_errprintf(error, 0, "Could not read loginuid from %s", loginuid_path);
	}
}

int32_t scap_proc_fill_exe_ino_ctime_mtime(char* error,
                                           struct scap_threadinfo* tinfo,
                                           const char* procdirname,
                                           const char* exetarget) {
	struct stat targetstat = {0};

	// extract ino field from executable path if it exists
	if(stat(exetarget, &targetstat) == 0) {
		tinfo->exe_ino = targetstat.st_ino;
		tinfo->exe_ino_ctime =
		        targetstat.st_ctim.tv_sec * SECOND_TO_NS + targetstat.st_ctim.tv_nsec;
		tinfo->exe_ino_mtime =
		        targetstat.st_mtim.tv_sec * SECOND_TO_NS + targetstat.st_mtim.tv_nsec;
	}

	return SCAP_SUCCESS;
}

int32_t scap_proc_fill_exe_writable(char* error,
                                    struct scap_threadinfo* tinfo,
                                    uint32_t uid,
                                    uint32_t gid,
                                    const char* procdirname,
                                    const char* exetarget) {
	char proc_exe_path[SCAP_MAX_PATH_SIZE];
	struct stat targetstat;

	snprintf(proc_exe_path, sizeof(proc_exe_path), "%sroot%s", procdirname, exetarget);

	// if the file doesn't exist we can't determine if it was writable, assume false
	if(stat(proc_exe_path, &targetstat) < 0) {
		return SCAP_SUCCESS;
	}

	// if you're the user owning the file you can chmod, so you can effectively write to it
	if(targetstat.st_uid == uid) {
		tinfo->exe_writable = true;
		return SCAP_SUCCESS;
	}

	uid_t orig_uid = geteuid();
	uid_t orig_gid = getegid();

	//
	// In order to check whether the current user can access the file we need to temporarily
	// set the effective uid and gid of our thread to the target ones and then check access,
	// but keep in mind that:
	//  - seteuid()/setegid() libc functions change the euid/egid of the whole process, not just
	//    the current thread
	//  - setfsuid()/setfsgid() operate on threads but cannot be paired with access(),
	//    so we would need to open() the file, but opening executable files in use may result
	//    in "text file busy" errors
	//
	// Therefore we need to directly call the appropriate setresuid syscall that operate on threads,
	// implemented in the thread_seteuid() and thread_setegid() functions.
	//

	if(thread_seteuid(uid) >= 0 && thread_setegid(gid) >= 0) {
		if(faccessat(0, proc_exe_path, W_OK, AT_EACCESS) == 0) {
			tinfo->exe_writable = true;
		}
	}

	int ret;
	if((ret = thread_seteuid(orig_uid)) < 0) {
		return scap_errprintf(error,
		                      -ret,
		                      "Could not restore original euid from %d to %d",
		                      uid,
		                      orig_uid);
	}

	if((ret = thread_setegid(orig_gid)) < 0) {
		return scap_errprintf(error,
		                      -ret,
		                      "Could not restore original egid from %d to %d",
		                      gid,
		                      orig_gid);
	}

	return SCAP_SUCCESS;
}

//
// Add a process to the list by parsing its entry under /proc
//
static int32_t scap_proc_add_from_proc(struct scap_linux_platform* linux_platform,
                                       struct scap_proclist* proclist,
                                       uint32_t tid,
                                       char* procdirname,
                                       struct scap_ns_socket_list** sockets_by_ns,
                                       uint64_t* num_fds_ret,
                                       char* error) {
	char dir_name[256];
	char target_name[SCAP_MAX_PATH_SIZE];
	int target_res;
	char filename[252];
	char line[SCAP_MAX_ENV_SIZE];
	struct scap_threadinfo tinfo = {};
	FILE* f;
	size_t filesize;
	size_t exe_len;
	int32_t res = SCAP_SUCCESS;
	struct stat dirstat;

	memset(&tinfo, 0, sizeof(scap_threadinfo));

	snprintf(dir_name, sizeof(dir_name), "%s/%u/", procdirname, tid);
	snprintf(filename, sizeof(filename), "%sexe", dir_name);

	//
	// Gather the executable full name
	//
	target_res = readlink(
	        filename,
	        target_name,
	        sizeof(target_name) -
	                1);  // Getting the target of the exe, i.e. to which binary it points to

	if(target_res <= 0) {
		//
		// No exe. This either
		//  - a kernel thread (if there is no cmdline). In that case we skip it.
		//  - a process that has been containerized or has some weird thing going on. In that case
		//    we accept it.
		//
		snprintf(filename, sizeof(filename), "%scmdline", dir_name);
		f = fopen(filename, "r");
		if(f == NULL) {
			return scap_errprintf(error, errno, "can't find valid proc dir in %s", dir_name);
		}

		ASSERT(sizeof(line) >= SCAP_MAX_PATH_SIZE);

		if(fgets(line, SCAP_MAX_PATH_SIZE, f) == NULL) {
			fclose(f);
			return scap_errprintf(error, errno, "can't read cmdline file %s", filename);
		} else {
			fclose(f);
		}

		target_name[0] = 0;
	} else {
		// null-terminate target_name (readlink() does not append a null byte)
		target_name[target_res] = 0;
	}

	tinfo.tid = tid;

	tinfo.fdlist = NULL;

	//
	// Gathers the exepath
	//
	snprintf(tinfo.exepath, sizeof(tinfo.exepath), "%s", target_name);

	//
	// Gather the command name
	//
	snprintf(filename, sizeof(filename), "%scomm", dir_name);

	f = fopen(filename, "r");
	if(f == NULL) {
		return scap_errprintf(error, errno, "can't open %s", filename);
	} else {
		ASSERT(sizeof(line) >= SCAP_MAX_PATH_SIZE);

		filesize = fread(line, 1, SCAP_MAX_ARGS_SIZE, f);
		if(filesize > 0) {
			// In case `comm` is greater than `SCAP_MAX_ARGS_SIZE` it could be
			// truncated so we put a `/0` at the end manually.
			line[filesize - 1] = 0;
			snprintf(tinfo.comm, SCAP_MAX_PATH_SIZE, "%s", line);
		} else {
			tinfo.comm[0] = 0;
		}
		fclose(f);
	}

	//
	// Gather the command line
	//
	snprintf(filename, sizeof(filename), "%scmdline", dir_name);

	f = fopen(filename, "r");
	if(f == NULL) {
		return scap_errprintf(error, errno, "can't open cmdline file %s", filename);
	} else {
		ASSERT(sizeof(line) >= SCAP_MAX_ARGS_SIZE);

		filesize = fread(line, 1, SCAP_MAX_ARGS_SIZE, f);
		if(filesize > 0) {
			// In case `args` is greater than `SCAP_MAX_ARGS_SIZE` it could be
			// truncated so we put a `/0` at the end manually.
			line[filesize - 1] = 0;

			// We always count also the terminator so `+1`
			// Please note that this could be exactly `SCAP_MAX_ARGS_SIZE`
			exe_len = strlen(line) + 1;

			snprintf(tinfo.exe, SCAP_MAX_PATH_SIZE, "%s", line);

			// Please note if `exe_len` is `SCAP_MAX_ARGS_SIZE` we will return an empty `args`.
			tinfo.args_len = filesize - exe_len;
			if(tinfo.args_len > 0) {
				memcpy(tinfo.args, line + exe_len, tinfo.args_len);
				tinfo.args[tinfo.args_len - 1] = 0;
			} else {
				tinfo.args_len = 0;
				tinfo.args[0] = 0;
			}
		} else {
			tinfo.args_len = 0;
			tinfo.args[0] = 0;
			tinfo.exe[0] = 0;
		}

		fclose(f);
	}

	//
	// Gather the environment
	//
	snprintf(filename, sizeof(filename), "%senviron", dir_name);

	f = fopen(filename, "r");
	if(f == NULL) {
		return scap_errprintf(error, errno, "can't open environ file %s", filename);
	} else {
		ASSERT(sizeof(line) >= SCAP_MAX_ENV_SIZE);

		filesize = fread(line, 1, SCAP_MAX_ENV_SIZE, f);

		if(filesize > 0) {
			line[filesize - 1] = 0;

			tinfo.env_len = filesize;

			memcpy(tinfo.env, line, tinfo.env_len);
			tinfo.env[SCAP_MAX_ENV_SIZE - 1] = 0;
		} else {
			tinfo.env[0] = 0;
			tinfo.env_len = 0;
		}

		fclose(f);
	}

	//
	// set the current working directory of the process
	//
	if(SCAP_FAILURE == scap_proc_fill_cwd(linux_platform->m_lasterr, dir_name, &tinfo)) {
		return scap_errprintf(error,
		                      0,
		                      "can't fill cwd for %s (%s)",
		                      dir_name,
		                      linux_platform->m_lasterr);
	}

	//
	// extract the user id and ppid from /proc/pid/status
	//
	if(SCAP_FAILURE ==
	   scap_proc_fill_info_from_stats(linux_platform->m_lasterr, dir_name, &tinfo)) {
		return scap_errprintf(error,
		                      0,
		                      "can't fill uid and pid for %s (%s)",
		                      dir_name,
		                      linux_platform->m_lasterr);
	}

	//
	// Set the file limit
	//
	if(SCAP_FAILURE == scap_proc_fill_flimit(tinfo.tid, &tinfo)) {
		return scap_errprintf(error,
		                      0,
		                      "can't fill flimit for %s (%s)",
		                      dir_name,
		                      linux_platform->m_lasterr);
	}

	if(scap_cgroup_get_thread(&linux_platform->m_cgroups,
	                          dir_name,
	                          &tinfo.cgroups,
	                          linux_platform->m_lasterr) == SCAP_FAILURE) {
		return scap_errprintf(error,
		                      0,
		                      "can't fill cgroups for %s (%s)",
		                      dir_name,
		                      linux_platform->m_lasterr);
	}

	if(scap_proc_fill_pidns_start_ts(linux_platform->m_lasterr, &tinfo, dir_name) == SCAP_FAILURE) {
		// ignore errors
		// the thread may not have /proc visible so we shouldn't kill the scan if this fails
	}

	// These values should be read already from /status file, leave these
	// fallback functions for older kernels < 4.1
	if(tinfo.vtid == 0 && scap_get_vtid(linux_platform, tinfo.tid, &tinfo.vtid) == SCAP_FAILURE) {
		tinfo.vtid = tinfo.tid;
	}

	if(tinfo.vpid == 0 && scap_get_vpid(linux_platform, tinfo.tid, &tinfo.vpid) == SCAP_FAILURE) {
		tinfo.vpid = tinfo.pid;
	}

	//
	// set the current root of the process
	//
	if(SCAP_FAILURE == scap_proc_fill_root(linux_platform->m_lasterr, &tinfo, dir_name)) {
		return scap_errprintf(error,
		                      0,
		                      "can't fill root for %s (%s)",
		                      dir_name,
		                      linux_platform->m_lasterr);
	}

	//
	// set the loginuid
	//
	if(SCAP_FAILURE == scap_proc_fill_loginuid(linux_platform->m_lasterr, &tinfo, dir_name)) {
		return scap_errprintf(error,
		                      0,
		                      "can't fill loginuid for %s (%s)",
		                      dir_name,
		                      linux_platform->m_lasterr);
	}

	// Container start time for host processes will be equal to when the
	// host init started
	char proc_cmdline[SCAP_MAX_PATH_SIZE];
	snprintf(proc_cmdline, sizeof(proc_cmdline), "%scmdline", dir_name);
	if(stat(proc_cmdline, &dirstat) == 0) {
		tinfo.clone_ts = dirstat.st_ctim.tv_sec * SECOND_TO_NS + dirstat.st_ctim.tv_nsec;
	}

	// If tid is different from pid, assume this is a thread and that the FDs are shared, and set
	// the corresponding process flags.
	// XXX we should see if the process creation flags are stored somewhere in /proc and handle this
	// properly instead of making assumptions.
	//
	if(tinfo.tid == tinfo.pid) {
		tinfo.flags = 0;
	} else {
		/* Probably we are doing this because `pthread_create` calls `clone()`
		 * with `CLONE_FILES`, but this is just an assumption.
		 * All threads populated by /proc scan will have `fdtable->size()==0`.
		 */
		tinfo.flags = PPM_CL_CLONE_THREAD | PPM_CL_CLONE_FILES;
	}

	if(SCAP_FAILURE == scap_proc_fill_exe_ino_ctime_mtime(linux_platform->m_lasterr,
	                                                      &tinfo,
	                                                      dir_name,
	                                                      target_name)) {
		return scap_errprintf(error,
		                      0,
		                      "can't fill exe writable access for %s (%s)",
		                      dir_name,
		                      linux_platform->m_lasterr);
	}

	if(SCAP_FAILURE == scap_proc_fill_exe_writable(linux_platform->m_lasterr,
	                                               &tinfo,
	                                               tinfo.uid,
	                                               tinfo.gid,
	                                               dir_name,
	                                               target_name)) {
		return scap_errprintf(error,
		                      0,
		                      "can't fill exe writable access for %s (%s)",
		                      dir_name,
		                      linux_platform->m_lasterr);
	}

	scap_threadinfo* new_tinfo = &tinfo;
	//
	// Done. Add the entry to the process table, or fire the notification callback
	//
	proclist->m_callbacks.m_proc_entry_cb(proclist->m_callbacks.m_callback_context,
	                                      error,
	                                      tinfo.tid,
	                                      &tinfo,
	                                      NULL,
	                                      &new_tinfo);

	//
	// Only add fds for processes, not threads
	//
	if(new_tinfo->pid == new_tinfo->tid) {
		res = scap_fd_scan_fd_dir(linux_platform,
		                          proclist,
		                          dir_name,
		                          new_tinfo,
		                          sockets_by_ns,
		                          num_fds_ret,
		                          error);
	}

	return res;
}

static int32_t single_thread_proc_callback(void* context,
                                           char* error,
                                           int64_t tid,
                                           scap_threadinfo* tinfo,
                                           scap_fdinfo* fdinfo,
                                           scap_threadinfo** new_tinfo) {
	scap_threadinfo* out_proc = (scap_threadinfo*)context;

	*out_proc = *tinfo;
	if(new_tinfo) {
		*new_tinfo = out_proc;
	}
	return SCAP_SUCCESS;
}

//
// Read a single thread info from /proc
//
int32_t scap_proc_read_thread(struct scap_linux_platform* linux_platform,
                              char* procdirname,
                              uint64_t tid,
                              struct scap_threadinfo* tinfo,
                              char* error,
                              bool scan_sockets) {
	struct scap_proclist single_thread_proclist;

	init_proclist(&single_thread_proclist,
	              (scap_proc_callbacks){default_refresh_start_end_callback,
	                                    default_refresh_start_end_callback,
	                                    single_thread_proc_callback,
	                                    tinfo});

	struct scap_ns_socket_list* sockets_by_ns = NULL;

	int32_t res;
	char add_error[SCAP_LASTERR_SIZE];

	if(!scan_sockets) {
		sockets_by_ns = (void*)-1;
	}

	res = scap_proc_add_from_proc(linux_platform,
	                              &single_thread_proclist,
	                              tid,
	                              procdirname,
	                              &sockets_by_ns,
	                              NULL,
	                              add_error);
	if(res != SCAP_SUCCESS) {
		scap_errprintf(error,
		               0,
		               "cannot add proc tid = %" PRIu64 ", dirname = %s, error=%s",
		               tid,
		               procdirname,
		               add_error);
	}

	if(sockets_by_ns != NULL && sockets_by_ns != (void*)-1) {
		scap_fd_free_ns_sockets_list(&sockets_by_ns);
	}

	return res;
}

//
// Scan a directory containing multiple processes under /proc
//
static int32_t _scap_proc_scan_proc_dir_impl(struct scap_linux_platform* linux_platform,
                                             struct scap_proclist* proclist,
                                             char* procdirname,
                                             int parenttid,
                                             char* error) {
	DIR* dir_p;
	struct dirent* dir_entry_p;
	scap_threadinfo* tinfo;
	uint64_t tid;
	int32_t res = SCAP_SUCCESS;
	char childdir[SCAP_MAX_PATH_SIZE];

	uint64_t num_procs_processed = 0;
	uint64_t total_num_fds = 0;
	uint64_t last_tid_processed = 0;
	struct scap_ns_socket_list* sockets_by_ns = NULL;

	dir_p = opendir(procdirname);

	if(dir_p == NULL) {
		scap_errprintf(error, errno, "error opening the %s directory", procdirname);
		return SCAP_NOTFOUND;
	}

	// Do timing tracking only if:
	// - this is the top-level call (parenttid == -1)
	// - one or both of the timing parameters is configured to non-zero
	bool do_timing = (parenttid == -1) &&
	                 ((linux_platform->m_proc_scan_timeout_ms != SCAP_PROC_SCAN_TIMEOUT_NONE) ||
	                  (linux_platform->m_proc_scan_log_interval_ms != SCAP_PROC_SCAN_LOG_NONE));
	uint64_t monotonic_ts_context = SCAP_GET_CUR_TS_MS_CONTEXT_INIT;
	uint64_t start_ts_ms = 0;
	uint64_t last_log_ts_ms = 0;
	uint64_t last_proc_ts_ms = 0;
	uint64_t cur_ts_ms = 0;
	uint64_t min_proc_time_ms = UINT64_MAX;
	uint64_t max_proc_time_ms = 0;

	if(do_timing) {
		start_ts_ms = scap_get_monotonic_ts_ms(&monotonic_ts_context);
		last_log_ts_ms = start_ts_ms;
		last_proc_ts_ms = start_ts_ms;
	}

	bool timeout_expired = false;
	while(!timeout_expired) {
		dir_entry_p = readdir(dir_p);
		if(dir_entry_p == NULL) {
			break;
		}

		if(strspn(dir_entry_p->d_name, "0123456789") != strlen(dir_entry_p->d_name)) {
			continue;
		}

		//
		// Gather the process TID, which is the directory name
		//
		tid = atoi(dir_entry_p->d_name);

		//
		// If this is a recursive call for tasks of a parent process,
		// skip the main thread entry
		//
		if(parenttid != -1 && tid == parenttid) {
			continue;
		}

		//
		// This is the initial /proc scan so duplicate threads
		// are an error, or at least unexpected. Check the process
		// list to see if we've encountered this tid already
		//
		HASH_FIND_INT64(proclist->m_proclist, &tid, tinfo);
		if(tinfo != NULL) {
			ASSERT(false);
			res = scap_errprintf(error, 0, "duplicate process %" PRIu64, tid);
			break;
		}

		char add_error[SCAP_LASTERR_SIZE];

		//
		// We have a process that needs to be explored
		//
		uint64_t num_fds_this_proc;
		res = scap_proc_add_from_proc(linux_platform,
		                              proclist,
		                              tid,
		                              procdirname,
		                              &sockets_by_ns,
		                              &num_fds_this_proc,
		                              add_error);
		if(res != SCAP_SUCCESS) {
			//
			// When a /proc lookup fails (while scanning the whole directory,
			// not just while looking up a single tid),
			// we should drop this thread/process completely.
			// We will fill the gap later, when the first event
			// for that process arrives.
			//
			//
			res = SCAP_SUCCESS;
			//
			// Continue because if we failed to read details of pid=1234,
			// it doesn’t say anything about pid=1235
			//
			continue;
		}

		//
		// See if this process includes tasks that need to be added
		// Note the use of recursion will re-enter this function for the childdir.
		//
		if(parenttid == -1 && !linux_platform->m_minimal_scan) {
			snprintf(childdir, sizeof(childdir), "%s/%u/task", procdirname, (int)tid);
			if(_scap_proc_scan_proc_dir_impl(linux_platform, proclist, childdir, tid, error) ==
			   SCAP_FAILURE) {
				res = SCAP_FAILURE;
				break;
			}
		}

		// TID successfully processed.
		last_tid_processed = tid;
		num_procs_processed++;
		total_num_fds += num_fds_this_proc;

		// After successful processing of a process at the top level,
		// perform timing processing if configured.
		if(do_timing) {
			cur_ts_ms = scap_get_monotonic_ts_ms(&monotonic_ts_context);
			uint64_t total_elapsed_time_ms = cur_ts_ms - start_ts_ms;

			uint64_t this_proc_elapsed_time_ms = cur_ts_ms - last_proc_ts_ms;
			last_proc_ts_ms = cur_ts_ms;

			if(this_proc_elapsed_time_ms < min_proc_time_ms) {
				min_proc_time_ms = this_proc_elapsed_time_ms;
			}
			if(this_proc_elapsed_time_ms > max_proc_time_ms) {
				max_proc_time_ms = this_proc_elapsed_time_ms;
			}

			if(linux_platform->m_proc_scan_log_interval_ms != SCAP_PROC_SCAN_LOG_NONE) {
				uint64_t log_elapsed_time_ms = cur_ts_ms - last_log_ts_ms;
				if(log_elapsed_time_ms >= linux_platform->m_proc_scan_log_interval_ms) {
					scap_debug_log(linux_platform,
					               "scap_proc_scan: %ld proc in %ld ms, avg=%ld/min=%ld/max=%ld, "
					               "last pid %ld, num_fds %ld",
					               num_procs_processed,
					               total_elapsed_time_ms,
					               (total_elapsed_time_ms / (uint64_t)num_procs_processed),
					               min_proc_time_ms,
					               max_proc_time_ms,
					               last_tid_processed,
					               total_num_fds);
					last_log_ts_ms = cur_ts_ms;
				}
			}

			if(linux_platform->m_proc_scan_timeout_ms != SCAP_PROC_SCAN_TIMEOUT_NONE) {
				if(total_elapsed_time_ms >= linux_platform->m_proc_scan_timeout_ms) {
					timeout_expired = true;
				}
			}
		}
	}

	if(do_timing) {
		cur_ts_ms = scap_get_monotonic_ts_ms(&monotonic_ts_context);
		uint64_t total_elapsed_time_ms = cur_ts_ms - start_ts_ms;
		uint64_t avg_proc_time_ms =
		        (num_procs_processed != 0) ? (total_elapsed_time_ms / num_procs_processed) : 0;

		if(timeout_expired) {
			scap_debug_log(linux_platform,
			               "scap_proc_scan TIMEOUT (%ld ms): %ld proc in %ld ms, "
			               "avg=%ld/min=%ld/max=%ld, last pid %ld, num_fds %ld",
			               linux_platform->m_proc_scan_timeout_ms,
			               num_procs_processed,
			               total_elapsed_time_ms,
			               avg_proc_time_ms,
			               min_proc_time_ms,
			               max_proc_time_ms,
			               last_tid_processed,
			               total_num_fds);
		} else if((linux_platform->m_proc_scan_log_interval_ms != SCAP_PROC_SCAN_LOG_NONE) &&
		          (num_procs_processed != 0)) {
			scap_debug_log(linux_platform,
			               "scap_proc_scan DONE: %ld proc in %ld ms, avg=%ld/min=%ld/max=%ld, last "
			               "pid %ld, num_fds %ld",
			               num_procs_processed,
			               total_elapsed_time_ms,
			               avg_proc_time_ms,
			               min_proc_time_ms,
			               max_proc_time_ms,
			               last_tid_processed,
			               total_num_fds);
		}
	}

	closedir(dir_p);
	if(sockets_by_ns != NULL && sockets_by_ns != (void*)-1) {
		scap_fd_free_ns_sockets_list(&sockets_by_ns);
	}
	return res;
}

int32_t scap_linux_getpid_global(struct scap_platform* platform, int64_t* pid, char* error) {
	struct scap_linux_platform* linux_platform = (struct scap_linux_platform*)platform;

	if(linux_platform->m_linux_vtable && linux_platform->m_linux_vtable->getpid_global) {
		return linux_platform->m_linux_vtable->getpid_global(linux_platform->m_engine, pid, error);
	}

	char filename[SCAP_MAX_PATH_SIZE];
	char line[512];

	snprintf(filename, sizeof(filename), "%s/proc/self/status", scap_get_host_root());

	FILE* f = fopen(filename, "r");
	if(f == NULL) {
		ASSERT(false);
		return scap_errprintf(error, errno, "can not open status file %s", filename);
	}

	while(fgets(line, sizeof(line), f) != NULL) {
		if(sscanf(line, "Tgid: %" PRId64, pid) == 1) {
			fclose(f);
			return SCAP_SUCCESS;
		}
	}

	fclose(f);
	return scap_errprintf(error, 0, "could not find tgid in status file %s", filename);
}

int32_t scap_linux_proc_get(struct scap_platform* platform,
                            int64_t tid,
                            struct scap_threadinfo* tinfo,
                            bool scan_sockets) {
	struct scap_linux_platform* linux_platform = (struct scap_linux_platform*)platform;

	char filename[SCAP_MAX_PATH_SIZE];
	snprintf(filename, sizeof(filename), "%s/proc", scap_get_host_root());

	return scap_proc_read_thread(linux_platform,
	                             filename,
	                             tid,
	                             tinfo,
	                             linux_platform->m_lasterr,
	                             scan_sockets);
}

bool scap_linux_is_thread_alive(struct scap_platform* platform,
                                int64_t pid,
                                int64_t tid,
                                const char* comm) {
	char charbuf[SCAP_MAX_PATH_SIZE];
	FILE* f;

	snprintf(charbuf,
	         sizeof(charbuf),
	         "%s/proc/%" PRId64 "/task/%" PRId64 "/comm",
	         scap_get_host_root(),
	         pid,
	         tid);

	f = fopen(charbuf, "r");

	if(f != NULL) {
		if(fgets(charbuf, sizeof(charbuf), f) != NULL) {
			if(strncmp(charbuf, comm, strlen(comm)) == 0) {
				fclose(f);
				return true;
			}
		}

		fclose(f);
	} else {
		//
		// If /proc/<pid>/task/<tid>/comm does not exist but /proc/<pid>/task/<tid>/exe does exist,
		// we assume we're on an ancient OS like RHEL5 and we return true. This could generate some
		// false positives on such old distros, and we're going to accept it.
		//
		snprintf(charbuf,
		         sizeof(charbuf),
		         "%s/proc/%" PRId64 "/task/%" PRId64 "/exe",
		         scap_get_host_root(),
		         pid,
		         tid);
		f = fopen(charbuf, "r");
		if(f != NULL) {
			fclose(f);
			return true;
		}
	}

	return false;
}

int32_t scap_linux_refresh_proc_table(struct scap_platform* platform,
                                      struct scap_proclist* proclist) {
	char procdirname[SCAP_MAX_PATH_SIZE];
	struct scap_linux_platform* linux_platform = (struct scap_linux_platform*)platform;

	if(proclist->m_proclist) {
		scap_proc_free_table(proclist);
		proclist->m_proclist = NULL;
	}

	snprintf(procdirname, sizeof(procdirname), "%s/proc", scap_get_host_root());
	scap_cgroup_enable_cache(&linux_platform->m_cgroups);
	proclist->m_callbacks.m_refresh_start_cb(proclist->m_callbacks.m_callback_context);
	int32_t ret = _scap_proc_scan_proc_dir_impl(linux_platform,
	                                            proclist,
	                                            procdirname,
	                                            -1,
	                                            linux_platform->m_lasterr);
	proclist->m_callbacks.m_refresh_end_cb(proclist->m_callbacks.m_callback_context);
	scap_cgroup_clear_cache(&linux_platform->m_cgroups);
	return ret;
}

int32_t scap_linux_get_threadlist(struct scap_platform* platform,
                                  struct ppm_proclist_info** procinfo_p,
                                  char* lasterr) {
	struct scap_linux_platform* linux_platform = (struct scap_linux_platform*)platform;

	if(linux_platform->m_linux_vtable && linux_platform->m_linux_vtable->get_threadlist) {
		return linux_platform->m_linux_vtable->get_threadlist(linux_platform->m_engine,
		                                                      procinfo_p,
		                                                      lasterr);
	}

	DIR* dir_p = NULL;
	FILE* fp = NULL;
	struct dirent* dir_entry_p;
	char procdirname[SCAP_MAX_PATH_SIZE];

	if(*procinfo_p == NULL) {
		if(scap_alloc_proclist_info(procinfo_p, SCAP_DRIVER_PROCINFO_INITIAL_SIZE, lasterr) ==
		   false) {
			return SCAP_FAILURE;
		}
	}

	(*procinfo_p)->n_entries = 0;

	snprintf(procdirname, sizeof(procdirname), "%s/proc", scap_get_host_root());

	dir_p = opendir(procdirname);
	if(dir_p == NULL) {
		scap_errprintf(lasterr, errno, "error opening the %s directory", procdirname);
		goto error;
	}

	while((dir_entry_p = readdir(dir_p)) != NULL) {
		char tasksdirname[SCAP_MAX_PATH_SIZE];
		struct dirent* taskdir_entry_p;
		DIR* taskdir_p;

		if(strspn(dir_entry_p->d_name, "0123456789") != strlen(dir_entry_p->d_name)) {
			continue;
		}

		snprintf(tasksdirname,
		         sizeof(tasksdirname),
		         "%s/%s/task",
		         procdirname,
		         dir_entry_p->d_name);

		taskdir_p = opendir(tasksdirname);
		if(taskdir_p == NULL) {
			scap_errprintf(lasterr, errno, "error opening the %s directory", tasksdirname);
			continue;
		}

		while((taskdir_entry_p = readdir(taskdir_p)) != NULL) {
			char filename[SCAP_MAX_PATH_SIZE];
			unsigned long utime;
			unsigned long stime;
			int tid;

			if(strspn(taskdir_entry_p->d_name, "0123456789") != strlen(taskdir_entry_p->d_name)) {
				continue;
			}

			snprintf(filename,
			         sizeof(filename),
			         "%s/%s/stat",
			         tasksdirname,
			         taskdir_entry_p->d_name);

			fp = fopen(filename, "r");
			if(fp == NULL) {
				continue;
			}

			if(fscanf(fp,
			          "%d %*[^)] %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %lu %lu",
			          &tid,
			          &utime,
			          &stime) != 3) {
				fclose(fp);
				fp = NULL;
				continue;
			}

			if((*procinfo_p)->n_entries == (*procinfo_p)->max_entries) {
				if(!scap_alloc_proclist_info(procinfo_p, (*procinfo_p)->n_entries + 256, lasterr)) {
					goto error;
				}
			}

			(*procinfo_p)->entries[(*procinfo_p)->n_entries].pid = tid;
			(*procinfo_p)->entries[(*procinfo_p)->n_entries].utime = utime;
			(*procinfo_p)->entries[(*procinfo_p)->n_entries].stime = stime;
			++(*procinfo_p)->n_entries;

			fclose(fp);
			fp = NULL;
		}

		closedir(taskdir_p);
		taskdir_p = NULL;
	}

error:
	if(dir_p) {
		closedir(dir_p);
	}

	if(fp) {
		fclose(fp);
	}
	return SCAP_SUCCESS;
}

int32_t scap_linux_get_fdlist(struct scap_platform* platform,
                              struct scap_threadinfo* tinfo,
                              char* lasterr) {
	int res = SCAP_SUCCESS;
	uint64_t num_fds_ret = 0;
	char proc_dir[SCAP_MAX_PATH_SIZE];
	struct scap_ns_socket_list* sockets_by_ns = NULL;
	struct scap_linux_platform* linux_platform = (struct scap_linux_platform*)platform;

	// We collect file descriptors only for the main thread
	snprintf(proc_dir, sizeof(proc_dir), "%s/proc/%lu/", scap_get_host_root(), tinfo->pid);

	res = scap_fd_scan_fd_dir(linux_platform,
	                          &platform->m_proclist,
	                          proc_dir,
	                          tinfo,
	                          &sockets_by_ns,
	                          &num_fds_ret,
	                          lasterr);
	if(sockets_by_ns != NULL && sockets_by_ns != (void*)-1) {
		scap_fd_free_ns_sockets_list(&sockets_by_ns);
	}
	return res;
}

int32_t scap_linux_get_fdinfo(struct scap_platform* platform,
                              struct scap_threadinfo* tinfo,
                              int const fd,
                              char* lasterr) {
	int res = SCAP_SUCCESS;
	char proc_dir[SCAP_MAX_PATH_SIZE];
	struct scap_ns_socket_list* sockets_by_ns = NULL;
	struct scap_linux_platform* linux_platform = (struct scap_linux_platform*)platform;

	// We get file descriptor info from the main thread
	snprintf(proc_dir, sizeof(proc_dir), "%s/proc/%lu/", scap_get_host_root(), tinfo->pid);

	res = scap_fd_get_fdinfo(linux_platform,
	                         &platform->m_proclist,
	                         proc_dir,
	                         tinfo,
	                         fd,
	                         &sockets_by_ns,
	                         lasterr);
	if(sockets_by_ns != NULL && sockets_by_ns != (void*)-1) {
		scap_fd_free_ns_sockets_list(&sockets_by_ns);
	}
	return res;
}
