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

#include <libscap/scap.h>

void scap_empty_params_set_init(scap_empty_params_set* set, const int n, ...) {
	if(!set) {
		return;
	}
	va_list args;
	va_start(args, n);
	for(int i = 0; i < n; i++) {
		*set |= 1 << va_arg(args, int);
	}
	va_end(args);
}

int scap_empty_params_set_is_set(const scap_empty_params_set* set, const int index) {
	return set && *set & 1 << index;
}
