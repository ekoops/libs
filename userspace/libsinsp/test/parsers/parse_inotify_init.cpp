
// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2025 The Falco Authors.
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

#include <sinsp_with_test_input.h>

TEST_F(sinsp_with_test_input, INOTIFY_INIT_success) {
	add_default_init_thread();
	open_inspector();

	constexpr int64_t return_value = 60;
	constexpr uint8_t flags = 0;

	const auto evt = add_event_advance_ts(increasing_ts(),
	                                      INIT_TID,
	                                      PPME_SYSCALL_INOTIFY_INIT_X,
	                                      2,
	                                      return_value,
	                                      flags);

	// Check that the returned value is as expected.
	ASSERT_EQ(evt->get_param_by_name("res")->as<int64_t>(), return_value);
	// Check that the flags value is as expected.
	ASSERT_EQ(evt->get_param_by_name("flags")->as<uint8_t>(), flags);

	// Check that fd info associated with the event are as expected.
	auto fdinfo = evt->get_fd_info();
	ASSERT_TRUE(fdinfo);

	// Check that fd info associated with the thread are as expected.
	const auto init_tinfo = m_inspector.m_thread_manager->get_thread_ref(INIT_TID, false).get();
	ASSERT_TRUE(init_tinfo);
	fdinfo = init_tinfo->get_fd(return_value);
	ASSERT_TRUE(fdinfo);
}
