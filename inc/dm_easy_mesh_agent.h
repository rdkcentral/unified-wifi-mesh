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

#ifndef DM_EM_AGENT_H
#define DM_EM_AGENT_H

#include "em_base.h"
#include "wifi_webconfig.h"
#include "dm_easy_mesh.h"
#include "webconfig_external_proto.h"
#include "bus.h"

class dm_easy_mesh_agent_t : public dm_easy_mesh_t {

public:

    int analyze_dev_init(em_bus_event_t *evt, em_cmd_t *pcmd[]);
    int analyze_sta_list(em_bus_event_t *evt, em_cmd_t *pcmd[]);
    int analyze_autoconfig_renew(em_bus_event_t *evt, em_cmd_t *pcmd[]);

    void translate_onewifi_dml_data(char *);
    void translate_onewifi_sta_data(char *); //translate when we receive the assoc client subdoc
    void translate_onewifi_stats_data(char *);// translate when we receive ap , radio, client stats
	int analyze_onewifi_private_cb(em_bus_event_t *evt, em_cmd_t *pcmd[]);
	int analyze_onewifi_radio_cb(em_bus_event_t *evt, em_cmd_t *pcmd[]);
	int analyze_m2ctrl_configuration(em_bus_event_t *evt, wifi_bus_desc_t *desc,bus_handle_t *bus_hdl);
    int analyze_channel_pref_query(em_bus_event_t *evt, em_cmd_t *pcmd[]);
    int analyze_channel_sel_req(em_bus_event_t *evt, wifi_bus_desc_t *desc,bus_handle_t *bus_hdl);
    int analyze_sta_link_metrics(em_bus_event_t *evt, em_cmd_t *pcmd[]);
    int analyze_btm_request_action_frame(em_bus_event_t *evt, wifi_bus_desc_t *desc,bus_handle_t *bus_hdl);
    int analyze_btm_response_action_frame(em_bus_event_t *evt, em_cmd_t *pcmd[]);
    int analyze_scan_result(em_bus_event_t *evt, em_cmd_t *pcmd[]);
    int analyze_set_policy(em_bus_event_t *evt, wifi_bus_desc_t *desc, bus_handle_t *bus_hdl);
    int analyze_beacon_report(em_bus_event_t *evt, em_cmd_t *pcmd[]);

    static webconfig_error_t webconfig_dummy_apply(webconfig_subdoc_t *doc, webconfig_subdoc_data_t *data);

    dm_easy_mesh_agent_t();
    ~dm_easy_mesh_agent_t();  
};

#endif

