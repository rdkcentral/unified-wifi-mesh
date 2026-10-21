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
#ifndef EM_CTRL_HOOKS_H
#define EM_CTRL_HOOKS_H
#include <functional>
#include "bus.h"

#define DEVICE_WIFI_DATAELEMENTS_RCV_WEI_DATA "Device.WiFi.DataElements.Network.RcvWeiData"

using em_bus_ready_fn_t = std::function<void(bus_handle_t*, wifi_bus_desc_t*)>;

void em_register_bus_ready_hook(em_bus_ready_fn_t fn);
void em_fire_bus_ready_hooks(bus_handle_t*, wifi_bus_desc_t*);
#endif