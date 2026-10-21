/**
 * Copyright 2026 Comcast Cable Communications Management, LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "em_ctrl_hooks.h"
#include <vector>

static std::vector<em_bus_ready_fn_t> g_bus_ready_hooks;

void em_register_bus_ready_hook(em_bus_ready_fn_t fn) { g_bus_ready_hooks.push_back(std::move(fn)); }
void em_fire_bus_ready_hooks(bus_handle_t *h, wifi_bus_desc_t *d) {
    for (auto &fn : g_bus_ready_hooks) fn(h, d);
}