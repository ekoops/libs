#include "driver/ppm_events_public.h"
#include "libscap/scap.h"

#include <libpman.h>
#include <state.h>
#include <bpf/libbpf.h>

static int parse_data(const int iter_fd) {
	char buff[32 * 1024];
	size_t bytes_in_buff = 0;

	while(true) {
		const ssize_t read_bytes =
		        read(iter_fd, buff + bytes_in_buff, sizeof(buff) - bytes_in_buff);
		if(read_bytes < 0) {
			if(errno == EAGAIN || errno == EINTR) {
				continue;
			}
			return -errno;
		}
		if(read_bytes == 0) {
			return 0;
		}
		bytes_in_buff += read_bytes;

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

			scap_print_event(evt, PRINT_FULL);

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

static int parse_tasks(const int iter_fd) {
	return parse_data(iter_fd);
}
static int parse_files(const int iter_fd) {
	return parse_data(iter_fd);
}

// todo(ekoops): maybe we can avoid updating the link.
// todo(ekoops): error handling.
static int iter(struct bpf_link **link,
                const struct bpf_program *prog,
                char *prog_name,
                int pid_filter,
                int (*parser)(const int),
                void *error) {
	/* The program is already attached. */
	if(*link != NULL) {
		char msg[MAX_ERROR_MESSAGE_LEN];
		snprintf(msg,
		         MAX_ERROR_MESSAGE_LEN,
		         "'%s' program is unexpectedly already attached",
		         prog_name);
		pman_print_error(msg);
		return -1;
	}

	int err = 0;
	int iter_fd = -1;

	LIBBPF_OPTS(bpf_iter_attach_opts, opts);
	union bpf_iter_link_info linfo;
	memset(&linfo, 0, sizeof(linfo));
	linfo.task.pid = pid_filter; /* If the pid is set to zero, no filtering logic is applied */
	opts.link_info = &linfo;
	opts.link_info_len = sizeof(linfo);

	struct bpf_link *prog_link = bpf_program__attach_iter(prog, &opts);
	if(!prog_link) {
		err = -errno;
		char msg[MAX_ERROR_MESSAGE_LEN];
		snprintf(msg, MAX_ERROR_MESSAGE_LEN, "failed to attach the '%s' program", prog_name);
		pman_print_error(msg);
		goto cleanup;
	}
	*link = prog_link;

	iter_fd = bpf_iter_create(bpf_link__fd(prog_link));
	if(iter_fd < 0) {
		err = -1;
		char msg[MAX_ERROR_MESSAGE_LEN];
		snprintf(msg,
		         MAX_ERROR_MESSAGE_LEN,
		         "failed to create iterator FD for '%s' program",
		         prog_name);
		pman_print_error(msg);
		goto cleanup;
	}

	printf("'%s' program attached\n", prog_name);

	parser(iter_fd);

cleanup:
	if(iter_fd != -1 && close(iter_fd) < 0) {
		char msg[MAX_ERROR_MESSAGE_LEN];
		snprintf(msg,
		         MAX_ERROR_MESSAGE_LEN,
		         "failed to close iterator FD for `%s` program",
		         prog_name);
		pman_print_error(msg);
	}
	if(bpf_link__destroy(prog_link)) {
		char msg[MAX_ERROR_MESSAGE_LEN];
		snprintf(msg, MAX_ERROR_MESSAGE_LEN, "failed to detach the `%s` program", prog_name);
		pman_print_error(msg);
	}
	*link = NULL;
	return err;
}

int pman_iter_get_threads(const int pid_filter, void *error) {
	return iter(&g_state.skel->links.dump_task,
	            g_state.skel->progs.dump_task,
	            "dump_task",
	            pid_filter,
	            parse_tasks,
	            error);
}

int pman_iter_get_files(const int pid_filter, void *error) {
	return iter(&g_state.skel->links.dump_task_file,
	            g_state.skel->progs.dump_task_file,
	            "dump_task_file",
	            pid_filter,
	            parse_files,
	            error);
}
