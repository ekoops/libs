/*
Copyright (C) 2021 The Falco Authors.

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

#ifndef _SCAP_BPF_H
#define _SCAP_BPF_H

#include "bpf.h"
#include "../compat/perf_event.h"

struct perf_event_sample {
	struct perf_event_header header;
	uint32_t size;
	char data[];
};

struct perf_lost_sample {
	struct perf_event_header header;
	uint64_t id;
	uint64_t lost;
};

typedef enum kernel_counters_stats {
	N_EVTS = 0,
	N_DROPS_BUFFER_TOTAL,
	N_DROPS_BUFFER_CLONE_FORK_ENTER,
	N_DROPS_BUFFER_CLONE_FORK_EXIT,
	N_DROPS_BUFFER_EXECVE_ENTER,
	N_DROPS_BUFFER_EXECVE_EXIT,
	N_DROPS_BUFFER_CONNECT_ENTER,
	N_DROPS_BUFFER_CONNECT_EXIT,
	N_DROPS_BUFFER_OPEN_ENTER,
	N_DROPS_BUFFER_OPEN_EXIT,
	N_DROPS_BUFFER_DIR_FILE_ENTER,
	N_DROPS_BUFFER_DIR_FILE_EXIT,
	N_DROPS_BUFFER_OTHER_INTEREST_ENTER,
	N_DROPS_BUFFER_OTHER_INTEREST_EXIT,
	N_DROPS_SCRATCH_MAP,
	N_DROPS_PAGE_FAULTS,
	N_DROPS_BUG,
	N_DROPS,
	MAX_KERNEL_COUNTERS_STATS
}kernel_counters_stats;

static const char * const kernel_counters_stats_names[] = {
	[N_EVTS] = "n_evts",
	[N_DROPS_BUFFER_TOTAL] = "n_drops_buffer_total",
	[N_DROPS_BUFFER_CLONE_FORK_ENTER] = "n_drops_buffer_clone_fork_enter",
	[N_DROPS_BUFFER_CLONE_FORK_EXIT] = "n_drops_buffer_clone_fork_exit",
	[N_DROPS_BUFFER_EXECVE_ENTER] = "n_drops_buffer_execve_enter",
	[N_DROPS_BUFFER_EXECVE_EXIT] = "n_drops_buffer_execve_exit",
	[N_DROPS_BUFFER_CONNECT_ENTER] = "n_drops_buffer_connect_enter",
	[N_DROPS_BUFFER_CONNECT_EXIT] = "n_drops_buffer_connect_exit",
	[N_DROPS_BUFFER_OPEN_ENTER] = "n_drops_buffer_open_enter",
	[N_DROPS_BUFFER_OPEN_EXIT] = "n_drops_buffer_open_exit",
	[N_DROPS_BUFFER_DIR_FILE_ENTER] = "n_drops_buffer_dir_file_enter",
	[N_DROPS_BUFFER_DIR_FILE_EXIT] = "n_drops_buffer_dir_file_exit",
	[N_DROPS_BUFFER_OTHER_INTEREST_ENTER] = "n_drops_buffer_other_interest_enter",
	[N_DROPS_BUFFER_OTHER_INTEREST_EXIT] = "n_drops_buffer_other_interest_exit",
	[N_DROPS_SCRATCH_MAP] = "n_drops_scratch_map",
	[N_DROPS_PAGE_FAULTS] = "n_drops_page_faults",
	[N_DROPS_BUG] = "n_drops_bug",
	[N_DROPS] = "n_drops",
};

enum libbpf_stats {
	RUN_CNT = 0,
	RUN_TIME_NS,
	AVG_TIME_NS,
	MAX_LIBBPF_STATS,
};

static const char * const libbpf_stats_names[] = {
	[RUN_CNT] = ".run_cnt", ///< `bpf_prog_info` run_cnt.
	[RUN_TIME_NS] = ".run_time_ns", ///<`bpf_prog_info` run_time_ns.
	[AVG_TIME_NS] = ".avg_time_ns", ///< Average time spent in bpg program, calculation: run_time_ns / run_cnt.
};

/* Return only the raw data of the event skipping the header and the size. */
static inline scap_evt *scap_bpf_evt_from_perf_sample(void *evt)
{
	struct perf_event_sample *perf_evt = (struct perf_event_sample *) evt;
	ASSERT(perf_evt->header.type == PERF_RECORD_SAMPLE);
	return (scap_evt *) perf_evt->data;
}

static inline void scap_bpf_get_buf_pointers(scap_device *dev, uint64_t *phead, uint64_t *ptail, uint64_t *pread_size)
{
	struct perf_event_mmap_page *header;
	uint64_t begin;
	uint64_t end;

	header = (struct perf_event_mmap_page *) dev->m_buffer;

	*phead = header->data_head;
	*ptail = header->data_tail;

	// clang-format off
	asm volatile("" ::: "memory");
	// clang-format on

	begin = *ptail % header->data_size;
	end = *phead % header->data_size;

	if(begin > end)
	{
		*pread_size = header->data_size - begin + end;
	}
	else
	{
		*pread_size = end - begin;
	}
}

static inline int32_t scap_bpf_advance_to_evt(struct scap_device *dev, bool skip_current,
					      char *cur_evt, char **next_evt, uint32_t *len)
{
	void *base;
	void *begin;

	struct perf_event_mmap_page *header = (struct perf_event_mmap_page *) dev->m_buffer;

	base = ((char *) header) + header->data_offset;

	/* if `skip_current` is true it means that we need to increment the position
	 * and this `begin` points to an event that we have already read. If `false`
	 * `begin` points to an event that we still have to read.
	 */
	begin = cur_evt;

	while(*len)
	{
		struct perf_event_header *e = begin;

		ASSERT(*len >= sizeof(*e));
		ASSERT(*len >= e->size);
		if(e->type == PERF_RECORD_SAMPLE)
		{
#ifdef _DEBUG
			struct perf_event_sample *sample = (struct perf_event_sample *) e;
#endif
			ASSERT(*len >= sizeof(*sample));
			ASSERT(*len >= sample->size);
			ASSERT(e->size == sizeof(*e) + sizeof(sample->size) + sample->size);
			ASSERT(((scap_evt *) sample->data)->len <= sample->size);

			if(skip_current)
			{
				skip_current = false;
			}
			else
			{
				*next_evt = (char *) e;
				break;
			}
		}
		else if(e->type != PERF_RECORD_LOST)
		{
			printf("Unknown event type=%d size=%d\n",
			       e->type, e->size);
			ASSERT(false);
		}

		/* Move the pointer inside the block to the next event */
		if(begin + e->size > base + header->data_size)
		{
			begin = begin + e->size - header->data_size;
		}
		else if(begin + e->size == base + header->data_size)
		{
			begin = base;
		}
		else
		{
			begin += e->size;
		}

		/* Decrease the size of the block since we have just read an event */
		*len -= e->size;
	}

	return SCAP_SUCCESS;
}

/* This helper increments the consumer position */
static inline void scap_bpf_advance_tail(struct scap_device *dev)
{
	struct perf_event_mmap_page *header;

	header = (struct perf_event_mmap_page *)dev->m_buffer;

	// clang-format off
	asm volatile("" ::: "memory");
	// clang-format on

	ASSERT(dev->m_lastreadsize > 0);
	/* `header->data_tail` is the consumer position. */
	header->data_tail += dev->m_lastreadsize;
	dev->m_lastreadsize = 0;
}

static inline int32_t scap_bpf_readbuf(struct scap_device *dev, char **buf, uint32_t *len)
{
	struct perf_event_mmap_page *header;
	uint64_t tail;
	uint64_t head;
	uint64_t read_size;
	char *p;

	header = (struct perf_event_mmap_page *) dev->m_buffer;

	ASSERT(dev->m_lastreadsize == 0);
	scap_bpf_get_buf_pointers(dev, &head, &tail, &read_size);

	/* This contains the dimension of the block and it will be used to increment 
	 * the consumer position in `scap_bpf_advance_tail`.
	 */
	dev->m_lastreadsize = read_size;
	/* position of the consumer */
	p = ((char *) header) + header->data_offset + tail % header->data_size;
	*len = read_size;

	return scap_bpf_advance_to_evt(dev, false, p, buf, len);
}

#endif
