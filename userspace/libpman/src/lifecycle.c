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

#include "state.h"
#include <driver/feature_gates.h>
#include "events_prog_table.h"
#include "support_probing.h"

int pman_open_probe(struct internal_state *state) {
	state->skel = bpf_probe__open();
	if(!state->skel) {
		log_errorf("failed to open BPF skeleton");
		return errno;
	}
	return 0;
}

static void disable_prog_autoloading(const struct internal_state *state, const char *prog_name) {
	log_msgf(FALCOSECURITY_LOG_SEV_DEBUG, "disabling BPF program '%s'", prog_name);
	struct bpf_program *p = bpf_object__find_program_by_name(state->skel->obj, prog_name);
	if(!p || bpf_program__set_autoload(p, false) < 0) {
		log_errorf("failed to disable prog '%s'", prog_name);
		return;
	}
	log_msgf(FALCOSECURITY_LOG_SEV_DEBUG, "disabled BPF program '%s'", prog_name);
}

// note: this temporarily disables logging.
static bool is_kernel_symbol_available(const char *symbol) {
	// note: `libbpf_find_vmlinux_btf_id()` emits a log line at warning level if the symbol is not
	// available. Temporarily disable it to avoid polluting the log stream.
	const libbpf_print_fn_t old_log_handler = libbpf_set_print(NULL);
	// Actually, 0 corresponds to `BPF_CGROUP_INET_INGRESS`, but use it as "no attach type" value as
	// currently, the kernel reacts by searching for the availability of the requested symbol
	// without adding any prefix to it (that is what we want).
	const int NO_ATTACH_TYPE = 0;
	const bool is_available = libbpf_find_vmlinux_btf_id(symbol, NO_ATTACH_TYPE) >= 0;
	libbpf_set_print(old_log_handler);
	return is_available;
}

#ifdef BPF_ITERATOR_SUPPORT
static void prepare_iter_progs_before_loading(struct internal_state *state) {
	// Disable autoloading for unsupported iterator programs.
	for(int i = 0; i < ITER_PROG_MAX; i++) {
		iter_prog_t *iter_prog = &state->iter_progs_table[i];
		const char *prog_name = iter_prog->name;
		iter_prog->is_supported = iter_support_probing__probe(prog_name) == 0;
		if(!iter_prog->is_supported) {
			log_msgf(FALCOSECURITY_LOG_SEV_DEBUG, "unsupported BPF program '%s'", prog_name);
			disable_prog_autoloading(state, prog_name);
		} else {
			log_msgf(FALCOSECURITY_LOG_SEV_DEBUG, "supported BPF program '%s'", prog_name);
		}
	}
}
#endif

int pman_prepare_progs_before_loading(struct internal_state *state) {
	/*
	 * Probe required features for each bpf program, as requested
	 */
	errno = 0;
	for(int ev = 0; ev < PPM_EVENT_MAX; ev++) {
		// We dropped the support for programs generating enter events, except for the ones managing
		// TOCTOU mitigation (handled separately below).
		if(PPME_IS_ENTER(ev)) {
			continue;
		}
		event_prog_t *progs = state->exit_event_progs_table[ev];
		int idx, chosen_idx = -1;
		for(idx = 0; idx < MAX_FEATURE_CHECKS && progs[idx].name != NULL; idx++) {
			bool should_disable = chosen_idx != -1;
			if(!should_disable) {
				if(progs[idx].feat > 0 &&
				   libbpf_probe_bpf_helper(BPF_PROG_TYPE_RAW_TRACEPOINT, progs[idx].feat, NULL) !=
				           1) {
					log_msgf(FALCOSECURITY_LOG_SEV_DEBUG,
					         "BPF program '%s' did not satisfy required feature [%d]",
					         progs[idx].name,
					         progs[idx].feat);
					// Required feature not present
					should_disable = true;
				} else {
					// We satisfied requested feature
					log_msgf(FALCOSECURITY_LOG_SEV_DEBUG,
					         "BPF program '%s' satisfied required feature [%d]",
					         progs[idx].name,
					         progs[idx].feat);
					chosen_idx = idx;
				}
			}

			// Disable autoloading for all programs except chosen one
			if(should_disable) {
				disable_prog_autoloading(state, progs[idx].name);
			}
		}

		// In case we couldn't find any program satisfying required features, give an error.
		// As of today, this will never happen, but better safe than sorry.
		if(chosen_idx == -1 && progs[0].name != NULL) {
			log_errorf("no program satisfies required features for event %d", ev);
			errno = ENXIO;
			return errno;
		}

		event_prog_t old_prog = progs[0];
		// Always move the selected program to index 0 to be easily accessed by maps.c
		// If no programs are skipped, the following line expands to progs[0] = progs[0];
		progs[0] = progs[chosen_idx];

		// To be able to reload the probe, we need to still reference the old
		// program to set its autoload to false.
		// Ie: in case of:
		// * open()
		// * close()
		// * open()
		progs[chosen_idx] = old_prog;
	}

	// Keep autoloading enabled for all TOCTOU mitigation 64 bit programs.
	// Disable autoloading for unsupported TOCTOU mitigation ia-32 programs.
	for(int i = 0; i < TTM_MAX; i++) {
		const ttm_ia32_prog_t *ia32_progs = state->ttm_progs_table[i].ttm_ia32_progs;
		int chosen_idx = -1;
		for(int j = 0; j < TTM_IA32_PROGS_NUM; j++) {
			const ttm_ia32_prog_t *ia32_prog = &ia32_progs[j];
			bool should_disable = chosen_idx != -1;
			if(!should_disable) {
				if(!is_kernel_symbol_available(ia32_prog->kernel_symbol)) {
					log_msgf(FALCOSECURITY_LOG_SEV_DEBUG,
					         "kernel symbol '%s' (required by BPF program '%s') not available",
					         ia32_prog->kernel_symbol,
					         ia32_prog->name);
					should_disable = true;
				} else {
					// We satisfied requested feature
					log_msgf(FALCOSECURITY_LOG_SEV_DEBUG,
					         "kernel symbol '%s' (required by BPF program '%s') is available",
					         ia32_prog->kernel_symbol,
					         ia32_prog->name);
					chosen_idx = j;
				}
			}
			// Disable autoloading for all programs except chosen one.
			if(should_disable) {
				disable_prog_autoloading(state, ia32_prog->name);
			}
		}
	}

#ifdef BPF_ITERATOR_SUPPORT
	prepare_iter_progs_before_loading(state);
#endif

	return 0;
}

static int bpf_prog_fd_or_default(const struct bpf_program *prog) {
	const int fd = bpf_program__fd(prog);
	if(fd < 0) {
		return -1;
	}
	return fd;
}

static void save_attached_progs(struct internal_state *state) {
	state->attached_progs_fds[0] = bpf_prog_fd_or_default(state->skel->progs.sys_exit);
	state->attached_progs_fds[1] = bpf_prog_fd_or_default(state->skel->progs.sched_proc_exit);
	state->attached_progs_fds[2] = bpf_prog_fd_or_default(state->skel->progs.sched_switch);
	state->attached_progs_fds[3] = bpf_prog_fd_or_default(state->skel->progs.sched_p_exec);
#ifdef CAPTURE_SCHED_PROC_FORK
	state->attached_progs_fds[4] = bpf_prog_fd_or_default(state->skel->progs.sched_p_fork);
#endif
#ifdef CAPTURE_PAGE_FAULTS
	state->attached_progs_fds[5] = bpf_prog_fd_or_default(state->skel->progs.pf_user);
	state->attached_progs_fds[6] = bpf_prog_fd_or_default(state->skel->progs.pf_kernel);
#endif
	state->attached_progs_fds[7] = bpf_prog_fd_or_default(state->skel->progs.signal_deliver);
	state->attached_progs_fds[8] = bpf_prog_fd_or_default(state->skel->progs.connect_e);
	state->attached_progs_fds[9] = bpf_prog_fd_or_default(state->skel->progs.ia32_compat_connect_e);
	state->attached_progs_fds[10] = bpf_prog_fd_or_default(state->skel->progs.ia32_connect_e);
	state->attached_progs_fds[11] = bpf_prog_fd_or_default(state->skel->progs.creat_e);
	state->attached_progs_fds[12] = bpf_prog_fd_or_default(state->skel->progs.ia32_compat_creat_e);
	state->attached_progs_fds[13] = bpf_prog_fd_or_default(state->skel->progs.ia32_creat_e);
	state->attached_progs_fds[14] = bpf_prog_fd_or_default(state->skel->progs.open_e);
	state->attached_progs_fds[15] = bpf_prog_fd_or_default(state->skel->progs.ia32_compat_open_e);
	state->attached_progs_fds[16] = bpf_prog_fd_or_default(state->skel->progs.ia32_open_e);
	state->attached_progs_fds[17] = bpf_prog_fd_or_default(state->skel->progs.openat_e);
	state->attached_progs_fds[18] = bpf_prog_fd_or_default(state->skel->progs.ia32_compat_openat_e);
	state->attached_progs_fds[19] = bpf_prog_fd_or_default(state->skel->progs.ia32_openat_e);
	state->attached_progs_fds[20] = bpf_prog_fd_or_default(state->skel->progs.openat2_e);
	state->attached_progs_fds[21] =
	        bpf_prog_fd_or_default(state->skel->progs.ia32_compat_openat2_e);
	state->attached_progs_fds[22] = bpf_prog_fd_or_default(state->skel->progs.ia32_openat2_e);
#ifdef BPF_ITERATOR_SUPPORT
	state->attached_progs_fds[23] = bpf_prog_fd_or_default(state->skel->progs.dump_task);
	state->attached_progs_fds[24] = bpf_prog_fd_or_default(state->skel->progs.dump_task_file);
#endif
}

int pman_load_probe(struct internal_state *state) {
	if(bpf_probe__load(state->skel)) {
		log_errorf("failed to load BPF object");
		return errno;
	}
	save_attached_progs(state);
	// Programs are loaded so we passed the verifier we can free the 16 MB
	if(state->log_buf) {
		free(state->log_buf);
		state->log_buf = NULL;
		state->log_buf_size = 0;
	}
	return 0;
}

void pman_close_probe(struct internal_state **state) {
	if(!state || !*state) {
		return;
	}

	struct internal_state *s = *state;
	if(s->stats) {
		free(s->stats);
		s->stats = NULL;
	}

	if(s->inner_ringbuf_map_fd != -1) {
		close(s->inner_ringbuf_map_fd);
		s->inner_ringbuf_map_fd = -1;
	}

	for(int i = 0; i < MODERN_BPF_PROG_ATTACHED_MAX; i++) {
		s->attached_progs_fds[i] = -1;
	}

	if(s->cons_pos) {
		free(s->cons_pos);
		s->cons_pos = NULL;
	}

	if(s->prod_pos) {
		free(s->prod_pos);
		s->prod_pos = NULL;
	}

	if(s->skel) {
		bpf_probe__detach(s->skel);
		bpf_probe__destroy(s->skel);
		s->skel = NULL;
	}

	if(s->rb_manager) {
		ring_buffer__free(s->rb_manager);
		s->rb_manager = NULL;
	}

#ifdef BPF_ITERATOR_SUPPORT

	/* BPF iterators section */
	s->is_tasks_dumping_supported = false;
	s->is_task_files_dumping_supported = false;

#endif /* BPF_ITERATOR_SUPPORT */

	*state = NULL;
}
