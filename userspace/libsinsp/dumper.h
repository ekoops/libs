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

#pragma once

class sinsp;
class sinsp_evt;

#include <libscap/scap_savefile_api.h>

#include <string>

typedef struct scap_dumper scap_dumper_t;

/** @defgroup dump Dumping events to disk
 * Classes to perform miscellaneous functionality
 *  @{
 */

/*!
  \brief A support class to dump events to file in scap format.
*/
class SINSP_PUBLIC sinsp_dumper {
public:
	/*!
	  \brief Constructs the dumper.
	*/
	sinsp_dumper();

	/*!
	  \brief Constructs a dumper that saves to memory instead of disk.
	  Takes the address and the size of a preallocated memory buffer
	  where the data will go.
	*/
	sinsp_dumper(uint8_t* target_memory_buffer, uint64_t target_memory_buffer_size);

	~sinsp_dumper();

	/*!
	  \brief Opens the dump file.

	  \param inspector Pointer to the inspector object that will be the source
	   of the events to save.

	  \param filename The name of the target file.

	  \param compress true to save the trace file in a compressed format.

	  \param threads_from_sinsp If, true the thread and FD tables in the file
	   will be created from the current sinsp's tables instead of reusing the scap
	   ones.

	  \note There's no close() because the file is closed when the dumper is
	   destroyed.
	*/
	void open(sinsp* inspector, const std::string& filename, bool compress);

	void fdopen(sinsp* inspector, int fd, bool compress);

	/*!
	  \brief Closes the dump file.
	*/
	void close();

	/*!
	  \brief Return whether or not the underling scap file has been
	         opened.
	*/
	bool is_open() const;

	/*!
	  \brief Return the number of events dumped so far.
	*/
	bool written_events() const;

	/*!
	  \brief Return the current size of a trace file.

	  \return The current size of the dump file.
	*/
	uint64_t written_bytes() const;

	/*!
	  \brief Flush all pending output into the file.
	*/
	void flush();

	/*!
	  \brief Writes an event to the file.

	  \param evt Pointer to the event to dump.
	*/
	void dump(sinsp_evt* evt);

private:
	scap_dumper_t* m_dumper;
	uint8_t* m_target_memory_buffer;
	uint64_t m_target_memory_buffer_size;
	uint64_t m_nevts;
};

/*@}*/
