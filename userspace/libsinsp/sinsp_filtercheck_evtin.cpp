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

#include <libsinsp/sinsp_filtercheck_evtin.h>
#include <libsinsp/sinsp_filtercheck_tracer.h>
#include <libsinsp/sinsp.h>
#include <libsinsp/sinsp_int.h>
#include <libscap/strl.h>

using namespace std;

static inline bool str_match_start(const std::string& val, size_t len, const char* m)
{
	return val.compare(0, len, m) == 0;
}

#define STR_MATCH(s) str_match_start(val, sizeof (s) -1, s)

static const filtercheck_field_info sinsp_filter_check_evtin_fields[] =
{
	{ PT_INT64, EPF_NONE|EPF_DEPRECATED, PF_ID, "evtin.span.id", "In Span ID", "accepts all the events that are between the enter and exit tracers of the spans with the given ID and are generated by the same thread that generated the tracers." },
	{ PT_UINT32, EPF_NONE|EPF_DEPRECATED, PF_DEC, "evtin.span.ntags", "In Span Tag Count", "accepts all the events that are between the enter and exit tracers of the spans with the given number of tags and are generated by the same thread that generated the tracers." },
	{ PT_UINT32, EPF_NONE|EPF_DEPRECATED, PF_DEC, "evtin.span.nargs", "In Span Argument Count", "accepts all the events that are between the enter and exit tracers of the spans with the given number of arguments and are generated by the same thread that generated the tracers." },
	{ PT_CHARBUF, EPF_NONE|EPF_DEPRECATED, PF_NA, "evtin.span.tags", "In Span Tags", "accepts all the events that are between the enter and exit tracers of the spans with the given tags and are generated by the same thread that generated the tracers." },
	{ PT_CHARBUF, EPF_ARG_REQUIRED|EPF_DEPRECATED, PF_NA, "evtin.span.tag", "In Span Tag", "accepts all the events that are between the enter and exit tracers of the spans with the given tag and are generated by the same thread that generated the tracers. See the description of span.tag for information about the syntax accepted by this field." },
	{ PT_CHARBUF, EPF_NONE|EPF_DEPRECATED, PF_NA, "evtin.span.args", "In Span Arguments", "accepts all the events that are between the enter and exit tracers of the spans with the given arguments and are generated by the same thread that generated the tracers." },
	{ PT_CHARBUF, EPF_ARG_REQUIRED|EPF_DEPRECATED, PF_NA, "evtin.span.arg", "In Span Argument", "accepts all the events that are between the enter and exit tracers of the spans with the given argument and are generated by the same thread that generated the tracers. See the description of span.arg for information about the syntax accepted by this field." },
	{ PT_INT64, EPF_NONE|EPF_DEPRECATED, PF_ID, "evtin.span.p.id", "In Parent ID", "same as evtin.span.id, but also accepts events generated by other threads in the same process that produced the span." },
	{ PT_UINT32, EPF_NONE|EPF_DEPRECATED, PF_DEC, "evtin.span.p.ntags", "In Parent Tag Count", "same as evtin.span.ntags, but also accepts events generated by other threads in the same process that produced the span." },
	{ PT_UINT32, EPF_NONE|EPF_DEPRECATED, PF_DEC, "evtin.span.p.nargs", "In Parent Argument Count", "same as evtin.span.nargs, but also accepts events generated by other threads in the same process that produced the span." },
	{ PT_CHARBUF, EPF_NONE|EPF_DEPRECATED, PF_NA, "evtin.span.p.tags", "In Parent Tags", "same as evtin.span.tags, but also accepts events generated by other threads in the same process that produced the span." },
	{ PT_CHARBUF, EPF_ARG_REQUIRED|EPF_DEPRECATED, PF_NA, "evtin.span.p.tag", "In Parent Tag", "same as evtin.span.tag, but also accepts events generated by other threads in the same process that produced the span." },
	{ PT_CHARBUF, EPF_NONE|EPF_DEPRECATED, PF_NA, "evtin.span.p.args", "In Parent Arguments", "same as evtin.span.args, but also accepts events generated by other threads in the same process that produced the span." },
	{ PT_CHARBUF, EPF_ARG_REQUIRED|EPF_DEPRECATED, PF_NA, "evtin.span.p.arg", "In Parent Argument", "same as evtin.span.arg, but also accepts events generated by other threads in the same process that produced the span." },
	{ PT_INT64, EPF_NONE|EPF_DEPRECATED, PF_ID, "evtin.span.s.id", "In Script ID", "same as evtin.span.id, but also accepts events generated by the script that produced the span, i.e. by the processes whose parent PID is the same as the one of the process generating the span." },
	{ PT_UINT32, EPF_NONE|EPF_DEPRECATED, PF_DEC, "evtin.span.s.ntags", "In Script Tag Count", "same as evtin.span.id, but also accepts events generated by the script that produced the span, i.e. by the processes whose parent PID is the same as the one of the process generating the span." },
	{ PT_UINT32, EPF_NONE|EPF_DEPRECATED, PF_DEC, "evtin.span.s.nargs", "In Script Argument Count", "same as evtin.span.id, but also accepts events generated by the script that produced the span, i.e. by the processes whose parent PID is the same as the one of the process generating the span." },
	{ PT_CHARBUF, EPF_NONE|EPF_DEPRECATED, PF_NA, "evtin.span.s.tags", "In Script Tags", "same as evtin.span.id, but also accepts events generated by the script that produced the span, i.e. by the processes whose parent PID is the same as the one of the process generating the span." },
	{ PT_CHARBUF, EPF_ARG_REQUIRED|EPF_DEPRECATED, PF_NA, "evtin.span.s.tag", "In Script Tag", "same as evtin.span.id, but also accepts events generated by the script that produced the span, i.e. by the processes whose parent PID is the same as the one of the process generating the span." },
	{ PT_CHARBUF, EPF_NONE|EPF_DEPRECATED, PF_NA, "evtin.span.s.args", "In Script Arguments", "same as evtin.span.id, but also accepts events generated by the script that produced the span, i.e. by the processes whose parent PID is the same as the one of the process generating the span." },
	{ PT_CHARBUF, EPF_ARG_REQUIRED|EPF_DEPRECATED, PF_NA, "evtin.span.s.arg", "In Script Argument", "same as evtin.span.id, but also accepts events generated by the script that produced the span, i.e. by the processes whose parent PID is the same as the one of the process generating the span." },
	{ PT_INT64, EPF_NONE|EPF_DEPRECATED, PF_ID, "evtin.span.m.id", "In Machine ID", "same as evtin.span.id, but accepts all the events generated on the machine during the span, including other threads and other processes." },
	{ PT_UINT32, EPF_NONE|EPF_DEPRECATED, PF_DEC, "evtin.span.m.ntags", "In Machine Tag Count", "same as evtin.span.id, but accepts all the events generated on the machine during the span, including other threads and other processes." },
	{ PT_UINT32, EPF_NONE|EPF_DEPRECATED, PF_DEC, "evtin.span.m.nargs", "In Machine Argument Count", "same as evtin.span.id, but accepts all the events generated on the machine during the span, including other threads and other processes." },
	{ PT_CHARBUF, EPF_NONE|EPF_DEPRECATED, PF_NA, "evtin.span.m.tags", "In Machine Tags", "same as evtin.span.id, but accepts all the events generated on the machine during the span, including other threads and other processes." },
	{ PT_CHARBUF, EPF_ARG_REQUIRED|EPF_DEPRECATED, PF_NA, "evtin.span.m.tag", "In Machine Tag", "same as evtin.span.id, but accepts all the events generated on the machine during the span, including other threads and other processes." },
	{ PT_CHARBUF, EPF_NONE|EPF_DEPRECATED, PF_NA, "evtin.span.m.args", "In Machine Arguments", "same as evtin.span.id, but accepts all the events generated on the machine during the span, including other threads and other processes." },
	{ PT_CHARBUF, EPF_ARG_REQUIRED|EPF_DEPRECATED, PF_NA, "evtin.span.m.arg", "In Machine Argument", "same as evtin.span.id, but accepts all the events generated on the machine during the span, including other threads and other processes." },
};

sinsp_filter_check_evtin::sinsp_filter_check_evtin()
{
	m_info.m_name = "evtin";
	m_info.m_desc = "Fields used if information about distributed tracing is available.";
	m_info.m_fields = sinsp_filter_check_evtin_fields;
	m_info.m_nfields = sizeof(sinsp_filter_check_evtin_fields) / sizeof(sinsp_filter_check_evtin_fields[0]);
}

int32_t sinsp_filter_check_evtin::extract_arg(string fldname, string val)
{
	uint32_t parsed_len = 0;

	//
	// 'arg' and 'resarg' are handled in a custom way
	//
	if(val[fldname.size()] == '[')
	{
		parsed_len = (uint32_t)val.find(']');
		string numstr = val.substr(fldname.size() + 1, parsed_len - fldname.size() - 1);

		m_argid = sinsp_numparser::parsed32(numstr);

		parsed_len++;
	}
	else if(val[fldname.size()] == '.')
	{
		const ppm_param_info* pi =
			sinsp_utils::find_longest_matching_evt_param(val.substr(fldname.size() + 1));

		if(pi == NULL)
		{
			throw sinsp_exception("unknown event argument " + val.substr(fldname.size() + 1));
		}

		m_argname = pi->name;
		parsed_len = (uint32_t)(fldname.size() + strlen(pi->name) + 1);
		m_argid = -1;
	}
	else
	{
		throw sinsp_exception("filter syntax error: " + val);
	}

	return parsed_len;
}

int32_t sinsp_filter_check_evtin::parse_field_name(const char* str, bool alloc_state, bool needed_for_filtering)
{
	int32_t res;
	string val(str);

	//
	// A couple of fields are handled in a custom way
	//
	if(STR_MATCH("evtin.span.tag") &&
		!STR_MATCH("evtin.span.tags"))
	{
		m_field_id = TYPE_TAG;
		m_field = &m_info.m_fields[m_field_id];

		res = extract_arg("evtin.span.tag", val);
	}
	else if(STR_MATCH("evtin.span.arg") &&
		!STR_MATCH("evtin.span.args"))
	{
		m_field_id = TYPE_ARG;
		m_field = &m_info.m_fields[m_field_id];

		res = extract_arg("evtin.span.arg", val);
	}
	else if(STR_MATCH("evtin.span.p.tag") &&
		!STR_MATCH("evtin.span.p.tags"))
	{
		m_field_id = TYPE_P_TAG;
		m_field = &m_info.m_fields[m_field_id];

		res = extract_arg("evtin.span.p.tag", val);
	}
	else if(STR_MATCH("evtin.span.p.arg") &&
		!STR_MATCH("evtin.span.p.args"))
	{
		m_field_id = TYPE_P_ARG;
		m_field = &m_info.m_fields[m_field_id];

		res = extract_arg("evtin.span.p.arg", val);
	}
	else if(STR_MATCH("evtin.span.s.tag") &&
		!STR_MATCH("evtin.span.s.tags"))
	{
		m_field_id = TYPE_S_TAG;
		m_field = &m_info.m_fields[m_field_id];

		res = extract_arg("evtin.span.s.tag", val);
	}
	else if(STR_MATCH("evtin.span.s.arg") &&
		!STR_MATCH("evtin.span.s.args"))
	{
		m_field_id = TYPE_S_ARG;
		m_field = &m_info.m_fields[m_field_id];

		res = extract_arg("evtin.span.s.arg", val);
	}
	else if(STR_MATCH("evtin.span.m.tag") &&
		!STR_MATCH("evtin.span.m.tags"))
	{
		m_field_id = TYPE_M_TAG;
		m_field = &m_info.m_fields[m_field_id];

		res = extract_arg("evtin.span.m.tag", val);
	}
	else if(STR_MATCH("evtin.span.m.arg") &&
		!STR_MATCH("evtin.span.m.args"))
	{
		m_field_id = TYPE_M_ARG;
		m_field = &m_info.m_fields[m_field_id];

		res = extract_arg("evtin.span.m.arg", val);
	}
	else
	{
		res = sinsp_filter_check::parse_field_name(str, alloc_state, needed_for_filtering);
	}

	return res;
}

sinsp_filter_check* sinsp_filter_check_evtin::allocate_new()
{
	return (sinsp_filter_check*) new sinsp_filter_check_evtin();
}

uint8_t* sinsp_filter_check_evtin::extract(sinsp_evt *evt, OUT uint32_t* len, bool sanitize_strings)
{
	// do nothing: support to tracers has been dropped
	*len = 0;
	return NULL;
}
