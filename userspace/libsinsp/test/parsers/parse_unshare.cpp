
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

TEST_F(sinsp_with_test_input, UNSHARE_parse) {
	add_default_init_thread();
	open_inspector();

	int64_t return_value = 0;
	uint32_t flags = PPM_CL_CLONE_NEWUSER;
	const auto evt = add_event_advance_ts(increasing_ts(),
	                                      INIT_TID,
	                                      PPME_SYSCALL_UNSHARE_X,
	                                      2,
	                                      return_value,
	                                      flags);

	// Check that the returned value is as expected.
	ASSERT_EQ(evt->get_param_by_name("res")->as<int64_t>(), return_value);

	// Check that the flags value is as expected.
	ASSERT_EQ(evt->get_param_by_name("flags")->as<uint32_t>(), flags);

	// Verify the thread has the entire set of capabilities in its inheritable, permitted and
	// effective set.
	const auto tinfo = m_inspector.m_thread_manager->get_thread_ref(INIT_TID);
	const auto max_caps = sinsp_utils::get_max_caps();
	ASSERT_EQ(tinfo->m_cap_inheritable, max_caps);
	ASSERT_EQ(tinfo->m_cap_permitted, max_caps);
	ASSERT_EQ(tinfo->m_cap_effective, max_caps);
}
