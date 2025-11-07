/**
 * Copyright 2023 Comcast Cable Communications Management, LLC
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

#ifndef TR_181_H
#define TR_181_H

#include "em_ctrl.h"

#define DEVICE_WIFI_DATAELEMENTS_NETWORK_COLOCATEDAGENTID	"Device.WiFi.DataElements.Network.ColocatedAgentID"
#define DEVICE_WIFI_DATAELEMENTS_NETWORK_CONTROLLERID		"Device.WiFi.DataElements.Network.ControllerID"
//#define DEVICE_WIFI_DATAELEMENTS_NETWORK_SETSSID_CMD "Device.WiFi.DataElements.Network.SetSSID()"
#define DEVICE_WIFI_DATAELEMENTS_NETWORK_SETSSID_CMD		"Device.WiFi.DataElements.Network.SetSSID"
//Orchestrator
#define DEVICE_WIFI_DATAELEMENTS_NETWORK_TOPOLOGY			"Device.WiFi.DataElements.Network.Topology"

typedef struct {
	em_short_string_t ssid;
	bool enable;
	em_short_string_t add_remove_change;
	em_short_string_t passphrase;
	em_short_string_t band;
	em_short_string_t akms_allowed;
	bool advertisement_enabled;
	em_short_string_t mfp_config;
	em_short_string_t mobility_domain;
	em_short_string_t haul_type;
} tr_cmd_setssid;

typedef struct {
    uint32_t id;
    bus_error_t rc;
} bus_resp_get_t;

#endif // TR_181_H
