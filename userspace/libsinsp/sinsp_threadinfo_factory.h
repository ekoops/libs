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

#pragma once
#include <libsinsp/sinsp_external_processor.h>
#include <libsinsp/threadinfo.h>

class sinsp;

/*!
  \brief Factory hiding sinsp_threadinfo creation details.
*/
class sinsp_threadinfo_factory {
	sinsp* m_sinsp;
	const sinsp_mode& m_mode;
	const sinsp_network_interfaces& m_network_interfaces;
	const bool& m_hostname_and_port_resolution_enabled;
	const sinsp_fdinfo_factory& m_fdinfo_factory;
	const sinsp_fdtable_factory& m_fdtable_factory;
	const std::shared_ptr<const sinsp_plugin>& m_input_plugin;
	const bool& m_large_envs_enabled;
	const std::shared_ptr<sinsp_thread_manager>* m_thread_manager = nullptr;
	const std::shared_ptr<sinsp_usergroup_manager>& m_usergroup_manager;
	std::set<uint16_t>& m_bound_server_ports;
	const std::shared_ptr<sinsp_filter>& m_filter;

	libsinsp::event_processor* const& m_external_event_processor;
	const std::shared_ptr<libsinsp::state::dynamic_struct::field_infos>&m_thread_manager_dyn_fields,
	        m_fdtable_dyn_fields;

	// TODO(ekoops): `set_thread_manager` has been added in order to avoid circular dependency
	//   during sinsp construction. Currently, sinsp_threadinfo_factory needs a valid reference to
	//   a sinsp_thread_manager, and sinsp_thread_manager needs a valid reference to the
	//   sinsp_threadinfo_factory: providing this setter is a way of untangle the dependency. Remove
	//   this once we figure out a way of removing the circular dependency.
	// The setter must be used after, constructing the factory, via the
	// `sinsp_threadinfo_factory::set_thread_manager_attorney` class (see its definition for more
	// details).
	void set_thread_manager(const std::shared_ptr<sinsp_thread_manager>* thread_manager) {
		m_thread_manager = thread_manager;
	}

	const std::shared_ptr<sinsp_thread_manager>& get_thread_manager() const {
		if(m_thread_manager == nullptr) {
			sinsp_exception{
			        "unexpected null thread manager. It is expected to be set in "
			        "sinsp constructor through sinsp_threadinfo_factory::set_manager_attorney"};
		}
		ASSERT(m_thread_manager != nullptr);
		return *m_thread_manager;
	}

	// `create_unique` is only provided in order to let an external event processor create a
	// threadinfo without tracking all the needed dependencies and, at the same time, avoiding code
	// repetition. The access is granted through the
	// `sinsp_threadinfo_factory::create_unique_attorney` class (see its definition for more
	// details).
	std::unique_ptr<sinsp_threadinfo> create_unique() const {
		return std::make_unique<sinsp_threadinfo>(m_mode,
		                                          m_network_interfaces,
		                                          m_hostname_and_port_resolution_enabled,
		                                          m_fdinfo_factory,
		                                          m_fdtable_factory,
		                                          m_input_plugin,
		                                          m_large_envs_enabled,
		                                          get_thread_manager(),
		                                          m_usergroup_manager,
		                                          m_bound_server_ports,
		                                          m_filter,
		                                          m_thread_manager_dyn_fields);
	}

public:
	/*!
	  \brief This class follows the attorney-client idiom to limit the access to
	  `sinsp_threadinfo_factory::create_unique()` only to `libsinsp::event_processor`.
	*/
	class create_unique_attorney {
		static std::unique_ptr<sinsp_threadinfo> create(sinsp_threadinfo_factory const& factory) {
			return factory.create_unique();
		}
		friend libsinsp::event_processor;
	};

	/*!
	  \brief This class follows the attorney-client idiom to limit the access to
	  `sinsp_threadinfo_factory::set_thread_manager()` only to `sinsp`.
	*/
	class set_thread_manager_attorney {
		static void set(sinsp_threadinfo_factory& factory,
		                const std::shared_ptr<sinsp_thread_manager>* thread_manager) {
			return factory.set_thread_manager(thread_manager);
		}
		friend sinsp;
	};

	sinsp_threadinfo_factory(sinsp* sinsp,
	                         const sinsp_mode& mode,
	                         const sinsp_network_interfaces& network_interfaces,
	                         const bool& hostname_and_port_resolution_enabled,
	                         const sinsp_fdinfo_factory& fdinfo_factory,
	                         const sinsp_fdtable_factory& fdtable_factory,
	                         const std::shared_ptr<const sinsp_plugin>& input_plugin,
	                         const bool& large_envs_enabled,
	                         const std::shared_ptr<sinsp_usergroup_manager>& usergroup_manager,
	                         std::set<uint16_t>& bound_server_ports,
	                         const std::shared_ptr<sinsp_filter>& filter,
	                         libsinsp::event_processor* const& external_event_processor,
	                         const std::shared_ptr<libsinsp::state::dynamic_struct::field_infos>&
	                                 thread_manager_dyn_fields,
	                         const std::shared_ptr<libsinsp::state::dynamic_struct::field_infos>&
	                                 fdtable_dyn_fields):
	        m_sinsp{sinsp},
	        m_mode{mode},
	        m_network_interfaces{network_interfaces},
	        m_hostname_and_port_resolution_enabled{hostname_and_port_resolution_enabled},
	        m_fdinfo_factory{fdinfo_factory},
	        m_fdtable_factory{fdtable_factory},
	        m_input_plugin{input_plugin},
	        m_large_envs_enabled{large_envs_enabled},
	        m_usergroup_manager{usergroup_manager},
	        m_bound_server_ports{bound_server_ports},
	        m_filter{filter},
	        m_external_event_processor{external_event_processor},
	        m_thread_manager_dyn_fields{thread_manager_dyn_fields},
	        m_fdtable_dyn_fields{fdtable_dyn_fields} {}

	std::unique_ptr<sinsp_threadinfo> create() const {
		std::unique_ptr<sinsp_threadinfo> tinfo =
		        m_external_event_processor ? m_external_event_processor->build_threadinfo(m_sinsp)
		                                   : create_unique();
		if(tinfo->dynamic_fields() == nullptr) {
			tinfo->set_dynamic_fields(m_thread_manager_dyn_fields);
		}
		tinfo->get_fdtable().set_dynamic_fields(m_fdtable_dyn_fields);
		return tinfo;
	}

	std::shared_ptr<sinsp_threadinfo> create_shared() const {
		// create_shared is currently used in contexts not handled by any external event processor,
		// nor by any component needing dynamic fields to be initialized: for these reasons, for the
		// moment, it is just a simplified (shared) version of what `create` does.
		return std::make_shared<sinsp_threadinfo>(m_mode,
		                                          m_network_interfaces,
		                                          m_hostname_and_port_resolution_enabled,
		                                          m_fdinfo_factory,
		                                          m_fdtable_factory,
		                                          m_input_plugin,
		                                          m_large_envs_enabled,
		                                          get_thread_manager(),
		                                          m_usergroup_manager,
		                                          m_bound_server_ports,
		                                          m_filter,
		                                          m_thread_manager_dyn_fields);
	}
};
