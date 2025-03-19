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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <assert.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>
#include <pthread.h>
#include "em_agent.h"
#include "em_msg.h"
#include "ieee80211.h"
#include "em_cmd_agent.h"
#include "em_orch_agent.h"
#include "util.h"
#include <cjson/cJSON.h>

#include <vector>
#ifdef AL_SAP
#include "al_service_access_point.hpp"
#endif

#define RETRY_SLEEP_INTERVAL_IN_MS 1000
#define SOCKET_PATH "/tmp/ieee1905_tunnel"

em_agent_t g_agent;
const char *global_netid = "OneWifiMesh";
#ifdef AL_SAP
AlServiceAccessPoint* g_sap;
MacAddress g_al_mac_sap;
#endif

void em_agent_t::handle_sta_list(em_bus_event_t *evt)
{
    em_cmd_t *pcmd[EM_MAX_CMD] = {NULL};
    unsigned int num;

    if ((num = m_data_model.analyze_sta_list(evt, pcmd)) == 0) {
        printf("analyze_sta_list failed\n");
    } else if (m_orch->submit_commands(pcmd, num) > 0) {
        printf("analyze_sta_list submit complete\n");
    }
}

void em_agent_t::handle_sta_link_metrics(em_bus_event_t *evt)
{
    em_cmd_t *pcmd[EM_MAX_CMD] = {NULL};
    unsigned int num;

    if (m_orch->is_cmd_type_in_progress(evt->type) == true) {
        printf("analyze_sta_link_metrics in progress\n");
    } else if ((num = m_data_model.analyze_sta_link_metrics(evt, pcmd)) == 0) {
        printf("analyze_sta_link_metrics failed\n");
    }
}

void em_agent_t::handle_ap_cap_query(em_bus_event_t *evt)
{
    em_cmd_t *pcmd[EM_MAX_CMD] = {NULL};
    unsigned int num;

    if (m_orch->is_cmd_type_in_progress(evt->type) == true) {
        m_agent_cmd->send_result(em_cmd_out_status_prev_cmd_in_progress);
    } else if ((num = m_data_model.analyze_ap_cap_query(evt, pcmd)) == 0) {
        m_agent_cmd->send_result(em_cmd_out_status_no_change);
    } else if (m_orch->submit_commands(pcmd, num) > 0) {
        m_agent_cmd->send_result(em_cmd_out_status_success);
    } else {
        m_agent_cmd->send_result(em_cmd_out_status_not_ready);
    }

}

void em_agent_t::handle_radio_config(em_bus_event_t *evt)
{
    em_cmd_t *pcmd[EM_MAX_CMD] = {NULL};
    unsigned int num;

    if (m_orch->is_cmd_type_in_progress(evt->type) == true) {
        m_agent_cmd->send_result(em_cmd_out_status_prev_cmd_in_progress);
    } else if ((num = m_data_model.analyze_radio_config(evt, pcmd)) == 0) {
        m_agent_cmd->send_result(em_cmd_out_status_no_change);
    } else if (m_orch->submit_commands(pcmd, num) > 0) {
        m_agent_cmd->send_result(em_cmd_out_status_success);
    } else {
        m_agent_cmd->send_result(em_cmd_out_status_not_ready);
    }

}

void em_agent_t::handle_vap_config(em_bus_event_t *evt)
{
    em_cmd_t *pcmd[EM_MAX_CMD] = {NULL};
    unsigned int num;

    if (m_orch->is_cmd_type_in_progress(evt->type) == true) {
        m_agent_cmd->send_result(em_cmd_out_status_prev_cmd_in_progress);
    } else if ((num = m_data_model.analyze_vap_config(evt, pcmd)) == 0) {
        m_agent_cmd->send_result(em_cmd_out_status_no_change);
    } else if (m_orch->submit_commands(pcmd, num) > 0) {
        m_agent_cmd->send_result(em_cmd_out_status_success);
    } else {
        m_agent_cmd->send_result(em_cmd_out_status_not_ready);
    }

}

void em_agent_t::handle_dev_init(em_bus_event_t *evt)
{
    em_cmd_t *pcmd[EM_MAX_CMD] = {NULL};
    unsigned int num;

    if (m_orch->is_cmd_type_in_progress(evt->type) == true) {
        m_agent_cmd->send_result(em_cmd_out_status_prev_cmd_in_progress);
    } else if ((num = m_data_model.analyze_dev_init(evt, pcmd)) == 0) {
        m_agent_cmd->send_result(em_cmd_out_status_no_change);
    } else if (m_orch->submit_commands(pcmd, num) > 0) {
        m_agent_cmd->send_result(em_cmd_out_status_success);
    } else {
        m_agent_cmd->send_result(em_cmd_out_status_not_ready);
    }

}

void em_agent_t::handle_channel_pref_query(em_bus_event_t *evt)
{
    em_cmd_t *pcmd[EM_MAX_CMD] = {NULL};
    unsigned int num;

    if (m_orch->is_cmd_type_in_progress(evt->type) == true) {
        m_agent_cmd->send_result(em_cmd_out_status_prev_cmd_in_progress);
    } else if ((num = m_data_model.analyze_channel_pref_query(evt, pcmd)) == 0) {
        printf("%s:%d query send fail \n", __func__, __LINE__);
    } else if (m_orch->submit_commands(pcmd, num) > 0) {
        printf("%s:%d send success \n", __func__, __LINE__);
    }
}

void em_agent_t::handle_channel_sel_req(em_bus_event_t *evt)
{
    unsigned int num;
    wifi_bus_desc_t *desc;
    raw_data_t l_bus_data;

    if((desc = get_bus_descriptor()) == NULL) {
       printf("descriptor is null");
    }

    if (m_orch->is_cmd_type_in_progress(evt->type) == true) {
        m_agent_cmd->send_result(em_cmd_out_status_prev_cmd_in_progress);
    } else if ((num = m_data_model.analyze_channel_sel_req(evt, desc, &m_bus_hdl)) == 0) {
            printf("handle_channel_sel_req complete");
    }
}

void em_agent_t::handle_m2ctrl_configuration(em_bus_event_t *evt)
{
    unsigned int num;
    wifi_bus_desc_t *desc;
    raw_data_t l_bus_data;

    if((desc = get_bus_descriptor()) == NULL) {
       printf("descriptor is null");
    }

    if (m_orch->is_cmd_type_in_progress(evt->type) == true) {
        m_agent_cmd->send_result(em_cmd_out_status_prev_cmd_in_progress);
    } else if ((num = m_data_model.analyze_m2ctrl_configuration(evt, desc, &m_bus_hdl)) == 0) {
	    printf("analyze_onewifi_private_subdoc complete");
    }
}

void em_agent_t::handle_onewifi_private_cb(em_bus_event_t *evt)
{
    em_cmd_t *pcmd[EM_MAX_CMD] = {NULL};
    unsigned int num;
    wifi_bus_desc_t *desc;

    if ((desc = get_bus_descriptor()) == NULL) {
        printf("descriptor is null");
    }

    if (m_orch->is_cmd_type_in_progress(evt->type) == true) {
        m_agent_cmd->send_result(em_cmd_out_status_prev_cmd_in_progress);
    } else if ((num = m_data_model.analyze_onewifi_vap_cb(evt, pcmd)) == 0) {
        printf("analyze_onewifi_vap_cb completed\n");
    } else if (m_orch->submit_commands(pcmd, num) > 0) {
        printf("submitted command for orchestration\n");
    }
}

void em_agent_t::handle_onewifi_radio_cb(em_bus_event_t *evt)
{
    em_cmd_t *pcmd[EM_MAX_CMD] = {NULL};
    unsigned int num;
    wifi_bus_desc_t *desc;

    if ((desc = get_bus_descriptor()) == NULL) {
        printf("descriptor is null");
    }

    if (m_orch->is_cmd_type_in_progress(evt->type) == true) {
        m_agent_cmd->send_result(em_cmd_out_status_prev_cmd_in_progress);
    } else if ((num = m_data_model.analyze_onewifi_radio_cb(evt, pcmd)) == 0) {
        printf("analyze_onewifi_radio_cb completed\n");
    } else if (m_orch->submit_commands(pcmd, num) > 0) {
        printf("submitted command for orchestration\n");
    }
}


void em_agent_t::handle_vendor_public_action_frame(struct ieee80211_mgmt *frame)
{

}

void em_agent_t::handle_public_action_frame(struct ieee80211_mgmt *frame)
{

    switch (frame->u.action.u.vs_public_action.action) {
        case WLAN_PA_VENDOR_SPECIFIC:
            handle_vendor_public_action_frame(frame);
            break;

        default:
            break;

    }

}

void em_agent_t::handle_action_frame(struct ieee80211_mgmt *frame)
{
    switch (frame->u.action.category) {
        case WLAN_ACTION_PUBLIC:
            handle_public_action_frame(frame);
            break;

        default:
            break;

    }
}

void em_agent_t::handle_frame_event(em_frame_event_t *evt)
{
    struct ieee80211_frame *frame;

    frame = (struct ieee80211_frame *)evt->frame;
    assert(IEEE80211_IS_MGMT(frame));

    printf("%s:%d: Received management 'frame event' type %d\n", __func__, __LINE__, frame->i_fc[0] & 0x0f);
    
    // handle action frames only 
    if ((frame->i_fc[0] & 0x0f) == IEEE80211_FC0_SUBTYPE_ACTION) {
        handle_action_frame((struct ieee80211_mgmt *)frame);        
    }
}

void em_agent_t::handle_autoconfig_renew(em_bus_event_t *evt)
{
    em_cmd_t *pcmd[EM_MAX_CMD] = {NULL};
    unsigned int num;

    if (m_orch->is_cmd_type_in_progress(evt->type) == true) {
        printf("handle_autoconfig_renew in progress\n");
    } else if ((num = m_data_model.analyze_autoconfig_renew(evt, pcmd)) == 0) {
        printf("handle_autoconfig_renew cmd creation failed\n");
    } else if (m_orch->submit_commands(pcmd, num) > 0) {
    }

}

void em_agent_t::handle_btm_request_action_frame(em_bus_event_t *evt)
{
    unsigned int num;
    wifi_bus_desc_t *desc;

    if((desc = get_bus_descriptor()) == NULL) {
       printf("descriptor is null");
    }

    if ((num = m_data_model.analyze_btm_request_action_frame(evt, desc, &m_bus_hdl)) == 0) {
	    printf("analyze_btm_request_action_frame failed\n");
    }
}

void em_agent_t::handle_recv_gas_frame(em_bus_event_t *evt)
{
    if (!evt) {
        printf("%s:%d: NULL bus event!\n", __func__, __LINE__);
        return;
    }
    const size_t full_frame_length = evt->data_len;
    const size_t mgmt_hdr_len      = offsetof(struct ieee80211_mgmt, u);
    ieee80211_mgmt *mgmt_frame     = (ieee80211_mgmt *)evt->u.raw_buff;
    mac_addr_str_t dest_mac;
    dm_easy_mesh_t::macbytes_to_string(mgmt_frame->da, dest_mac);
    em_t *dest_node = (em_t *)hash_map_get(g_agent.m_em_map, dest_mac);
    if (!dest_node) {
        printf("%s:%d: no node found for MAC '%s'\n", __func__, __LINE__, dest_mac);
        return;
    }
    auto gas_frame_base = (ec_gas_frame_base_t *)evt->u.raw_buff + mgmt_hdr_len;
    if (!dest_node->m_ec_manager->handle_recv_gas_pub_action_frame(
            gas_frame_base, full_frame_length - mgmt_hdr_len, mgmt_frame->sa)) {
        printf("%s:%d: EC manager failed to handle GAS frame!\n", __func__, __LINE__);
    }
}

void em_agent_t::handle_recv_wfa_action_frame(em_bus_event_t *evt)
{
    size_t frame_len = evt->data_len;

    const size_t mgmt_hdr_len = offsetof(struct ieee80211_mgmt, u);
    const size_t fixed_full_header_len = 
        mgmt_hdr_len +
        // Action category + VS Public Action fixed fields
        sizeof(uint8_t) +  // category field
        sizeof(uint8_t) +  // action field
        sizeof(uint8_t[3]);  // oui field

    if (frame_len <= fixed_full_header_len){
        printf("%s:%d Recieved WFA Action frame is too short! Must have at least the OUI type in the data field\n", __func__, __LINE__);
        return;
    }
    auto mgmt_frame = reinterpret_cast<struct ieee80211_mgmt *>(evt->u.raw_buff);
    auto vs_action_data = mgmt_frame->u.action.u.vs_public_action.variable;
    auto vs_data_len = frame_len - fixed_full_header_len;

    printf("%s:%d: Received WFA action frame: Full Length: %d, VS Action Data Length: %d\n", __func__, __LINE__, frame_len, vs_data_len);

    mac_addr_str_t dest_mac_str;
    dm_easy_mesh_t::macbytes_to_string(mgmt_frame->da, dest_mac_str);

    em_t* dest_radio_node = static_cast<em_t*>(hash_map_get(g_agent.m_em_map, dest_mac_str));
    if (dest_radio_node == NULL) {
        // printf("No radio node found for dest mac %s\n", dest_mac_str);
        return;
    }

    // First byte is the OUI type
    uint8_t oui_type = *vs_action_data;

    size_t full_action_frame_len = frame_len - mgmt_hdr_len;
    auto ec_frame = reinterpret_cast<ec_frame_t*>(evt->u.raw_buff + mgmt_hdr_len);

    switch (oui_type) {
    case DPP_OUI_TYPE:
        dest_radio_node->m_ec_manager->handle_recv_ec_action_frame(ec_frame, full_action_frame_len, mgmt_frame->sa);
        break;
    default:
        break;
    }

}

void em_agent_t::handle_btm_response_action_frame(em_bus_event_t *evt)
{
    em_cmd_t *pcmd[EM_MAX_CMD] = {NULL};
    unsigned int num;

    if (m_orch->is_cmd_type_in_progress(evt->type) == true) {
        printf("analyze_btm_response_action_frame in progress\n");
    } else if ((num = m_data_model.analyze_btm_response_action_frame(evt, pcmd)) == 0) {
        printf("analyze_btm_response_action_frame failed\n");
    } else if (m_orch->submit_commands(pcmd, num) > 0) {
        printf("submitted handle_btm_response_action_frame command for orchestration\n");
    }
}

void em_agent_t::handle_channel_scan_result(em_bus_event_t *evt)
{
    em_cmd_t *pcmd[EM_MAX_CMD] = {NULL};
    unsigned int num;

    if (m_orch->is_cmd_type_in_progress(evt->type) == true) {
        printf("scan results in progress\n");
    } else if ((num = m_data_model.analyze_scan_result(evt, pcmd)) == 0) {
        printf("scan results failed\n");
    } else if (m_orch->submit_commands(pcmd, num) > 0) {
		;
    }
}

void em_agent_t::handle_channel_scan_params(em_bus_event_t *evt)
{
    printf("%s:%d: Scan Parameters received\n", __func__, __LINE__);
#ifdef SCAN_RESULT_TEST
	m_simulator.configure(m_data_model, (em_scan_params_t *)evt->u.raw_buff);
#endif
    unsigned int num;
    wifi_bus_desc_t *desc;

    if((desc = get_bus_descriptor()) == NULL) {
       printf("descriptor is null");
    }

    if ((num = m_data_model.analyze_scan_request(evt, desc, &m_bus_hdl)) == 0) {
	    printf("analyze scan request failed\n");
    }
}

void em_agent_t::handle_set_policy(em_bus_event_t *evt)
{
    em_cmd_t *pcmd[EM_MAX_CMD] = {NULL};
    unsigned int num;
    wifi_bus_desc_t *desc;
    raw_data_t l_bus_data;

    if((desc = get_bus_descriptor()) == NULL) {
       printf("descriptor is null");
    }

    if (m_orch->is_cmd_type_in_progress(evt->type) == true) {
        printf("set policy in progress\n");
    } else if ((num = m_data_model.analyze_set_policy(evt, desc, &m_bus_hdl)) == 0) {
        printf("set policy failed\n");
    }
}

void em_agent_t::handle_beacon_report(em_bus_event_t *evt)
{
    em_cmd_t *pcmd[EM_MAX_CMD] = {NULL};
    unsigned int num;

    if (m_orch->is_cmd_type_in_progress(evt->type) == true) {
        printf("analyze_beacon_report in progress\n");
    } else if ((num = m_data_model.analyze_beacon_report(evt, pcmd)) == 0) {
        printf("analyze_beacon_report failed\n");
    } else if (m_orch->submit_commands(pcmd, num) > 0) {
        printf("submitted beacon report cmd for orch\n");
    }
}

void em_agent_t::handle_bus_event(em_bus_event_t *evt)
{   
    
    switch (evt->type) {
        case em_bus_event_type_dev_init:
            handle_dev_init(evt);
            break;
        case em_bus_event_type_cfg_renew:
            handle_autoconfig_renew(evt);
            break;
        case em_bus_event_type_radio_config:
            handle_radio_config(evt);
            break;

        case em_bus_event_type_vap_config:
            handle_vap_config(evt);
            break;

        case em_bus_event_type_sta_list:
            handle_sta_list(evt);
            break;

        case em_bus_event_type_ap_cap_query:
            handle_ap_cap_query(evt);
            break;

        case em_bus_event_type_m2ctrl_configuration:
            handle_m2ctrl_configuration(evt);
            break;
		
		case em_bus_event_type_onewifi_private_cb:
            handle_onewifi_private_cb(evt);
            break;

		case em_bus_event_type_onewifi_radio_cb:
			handle_onewifi_radio_cb(evt);
			break;

		case em_bus_event_type_channel_pref_query:
			handle_channel_pref_query(evt);
			break;

		case em_bus_event_type_channel_sel_req:
			handle_channel_sel_req(evt);
			break;

        case em_bus_event_type_sta_link_metrics:
            handle_sta_link_metrics(evt);
            break;

        case em_bus_event_type_bss_tm_req:
            handle_btm_request_action_frame(evt);
            break;

        case em_bus_event_type_btm_response:
            handle_btm_response_action_frame(evt);
            break;

		case em_bus_event_type_channel_scan_params:
			handle_channel_scan_params(evt);
			break;

		case em_bus_event_type_scan_result:
			handle_channel_scan_result(evt);
			break;

        case em_bus_event_type_set_policy:
            handle_set_policy(evt);
            break;

        case em_bus_event_type_beacon_report:
            handle_beacon_report(evt);
            break;
        case em_bus_event_type_recv_wfa_action_frame:
            handle_recv_wfa_action_frame(evt);
            break;

        case em_bus_event_type_recv_gas_frame:
            handle_recv_gas_frame(evt);
            break;

        default:
            break;
    }    
}

void em_agent_t::handle_event(em_event_t *evt)
{
    switch(evt->type) {
        case em_event_type_frame:
            handle_frame_event(&evt->u.fevt);
            break;

        case em_event_type_bus:
            handle_bus_event(&evt->u.bevt);
            break;

        default:
            break;
    }

}

void em_agent_t::handle_5s_tick()
{
#ifdef SCAN_RESULT_TEST
	unsigned char *buff = NULL;
	em_cmd_params_t	params;

	if (m_simulator.run(m_data_model) == true) {
		io_process(em_bus_event_type_scan_result, buff, 0, m_simulator.get_cmd_param());	
	}
#endif
}

void em_agent_t::handle_2s_tick()
{

}

void em_agent_t::handle_1s_tick()
{

}

void em_agent_t::handle_500ms_tick()
{
    m_orch->handle_timeout();
}

bool em_agent_t::send_action_frame(uint8_t dest_mac[ETH_ALEN], uint8_t *action_frame, size_t action_frame_len, unsigned int frequency) {

    wifi_bus_desc_t *desc = get_bus_descriptor();
    ASSERT_NOT_NULL(desc, false, "%s:%d descriptor is null\n", __func__, __LINE__);

    // Allocate memory for the action frame parameters, ieee80211 header and action frame body
    action_frame_params_t *act_frame_params = (action_frame_params_t*) calloc(sizeof(action_frame_params_t) + action_frame_len, 1);
    ASSERT_NOT_NULL(act_frame_params, false, "%s:%d calloc failed\n", __func__, __LINE__);

    // Hardcoded to 0 just the same as the other bus calls
    // NOTE: AccessPoint.1 = ap_index 0. One is the data model indexing, one is NL80211/hal indexing
    act_frame_params->ap_index = 0;
    memcpy(act_frame_params->dest_addr, dest_mac, ETH_ALEN);
    act_frame_params->frequency = frequency;
    act_frame_params->frame_len = action_frame_len;
    memcpy(act_frame_params->frame_data, action_frame, action_frame_len);

    raw_data_t raw_act_frame;
    memset(&raw_act_frame, 0, sizeof(raw_data_t));
    raw_act_frame.raw_data.bytes = (uint8_t *)act_frame_params;
    raw_act_frame.raw_data_len = sizeof(action_frame_params_t) + action_frame_len;
    raw_act_frame.data_type = bus_data_type_bytes;

    // Send the action frame
    if (desc->bus_set_fn(&m_bus_hdl, "Device.WiFi.AccessPoint.1.RawFrame.Mgmt.Action.Tx", &raw_act_frame) != 0) {
        printf("%s:%d bus set failed\n", __func__, __LINE__);
        free(act_frame_params);
        return false;
    }

    free(act_frame_params);
    return true;
}


void em_agent_t::input_listener()
{
    wifi_bus_desc_t *desc;
    dm_easy_mesh_t dm;
    raw_data_t data;
    int num_retry = 0;
    bus_error_t bus_error_val;
    char service_name[] = "EasyMesh_service";

    bus_init(&m_bus_hdl);

    if((desc = get_bus_descriptor()) == NULL) {
        printf("%s:%d descriptor is null\n", __func__, __LINE__);
    }

    if (desc->bus_open_fn(&m_bus_hdl, service_name) != 0) {
        printf("%s:%d bus open failed\n",__func__, __LINE__);
        return;
    }

    printf("%s:%d he_bus open success\n", __func__, __LINE__);

    memset(&data, 0, sizeof(raw_data_t));

    while ((bus_error_val = desc->bus_data_get_fn(&m_bus_hdl, WIFI_WEBCONFIG_INIT_DML_DATA, &data)) != bus_error_success) {
        printf("%s:%d bus get failed, error:%d, ", __func__, __LINE__, bus_error_val);
		usleep(RETRY_SLEEP_INTERVAL_IN_MS * 1000);
		num_retry++;
		printf("retrying %d\n", num_retry);

        if (num_retry % 5 == 0) {
            if (access(EM_CFG_FILE, F_OK) != -1) {
                printf("Check that OneWifi is running.\n");
            } else {
                printf("EasymeshCfg.json does not exist. Generate via the unified-wifi-mesh CLI/TUI (if co-located) or by adding the `--interface` flag to the agent (if not)\n");
            }
        }
    }
    printf("%s:%d recv data:\r\n%s\r\n", __func__, __LINE__, (char *)data.raw_data.bytes);

    g_agent.io_process(em_bus_event_type_dev_init, (unsigned char *)data.raw_data.bytes, data.raw_data_len);
    free(data.raw_data.bytes);

    if (desc->bus_event_subs_fn(&m_bus_hdl, WIFI_WEBCONFIG_DOC_DATA_NORTH, (void *)&em_agent_t::onewifi_cb, NULL, 0) != 0) {
        printf("%s:%d bus get failed\n", __func__, __LINE__);
        return;
    }

    if (desc->bus_event_subs_fn(&m_bus_hdl, WIFI_WEBCONFIG_GET_ASSOC, (void *)&em_agent_t::sta_cb, NULL, 0) != 0) {
        printf("%s:%d bus get failed\n", __func__, __LINE__);
        return;
    }

    if (desc->bus_event_subs_fn(&m_bus_hdl, "Device.WiFi.CollectStats.AccessPoint.1.AssociatedDeviceStats", (void *)&em_agent_t::assoc_stats_cb, NULL, 0) != 0) {
        printf("%s:%d bus get failed\n", __func__, __LINE__);
        return;
    }

    if (desc->bus_event_subs_fn(&m_bus_hdl, "Device.WiFi.AccessPoint.1.RawFrame.Mgmt.Action.Rx", (void *)&em_agent_t::mgmt_action_frame_cb, NULL, 0) != 0) {
        printf("%s:%d bus get failed\n", __func__, __LINE__);
        return;
    }

    if (desc->bus_event_subs_fn(&m_bus_hdl, "Device.WiFi.EM.ChannelScanReport", (void *)&em_agent_t::channel_scan_cb, NULL, 0) != 0) {
        printf("%s:%d bus get failed\n", __func__, __LINE__);
        return;
    }

    if (desc->bus_event_subs_fn(&m_bus_hdl, "Device.WiFi.EM.BeaconReport", (void *)&em_agent_t::beacon_report_cb, NULL, 0) != 0) {
        printf("%s:%d bus get failed\n", __func__, __LINE__);
        return;
    }

    io(NULL);
}

int em_agent_t::channel_scan_cb(char *event_name, raw_data_t *data)
{
    cJSON *json, *channel_stats_arr;

    json = cJSON_Parse((const char *)data->raw_data.bytes);
    if (json != NULL) {
        channel_stats_arr = cJSON_GetObjectItem(json, "ChannelScanResponse");
        if ((channel_stats_arr == NULL) && (cJSON_IsObject(channel_stats_arr) == false)) {
            return -1;
        }
        if (cJSON_IsArray(channel_stats_arr) && cJSON_GetArraySize(channel_stats_arr) == 0) {
            return -1;
        }
    }

    g_agent.io_process(em_bus_event_type_scan_result, (unsigned char *)data->raw_data.bytes, data->raw_data_len);

    return 1;
}

int em_agent_t::beacon_report_cb(char *event_name, raw_data_t *data)
{
    //printf("%s:%d Received Frame data for event [%s] and data :\n%s\n", __func__, __LINE__, event_name, data->raw_data.bytes);

    g_agent.io_process(em_bus_event_type_beacon_report, (unsigned char *)data->raw_data.bytes, data->raw_data_len);

    return 0;
}

int em_agent_t::mgmt_action_frame_cb(char *event_name, raw_data_t *data)
{
    struct ieee80211_mgmt *mgmt_frame = (struct ieee80211_mgmt *)data->raw_data.bytes;
    printf("%s:%d Received Frame data for event [%s] and data of len:\n%d\n", __func__, __LINE__, event_name, data->raw_data_len);

   util::print_hex_dump(data->raw_data_len, (uint8_t*)data->raw_data.bytes);

    //printf("Received Frame data for event %s \n", event_name);
    if (mgmt_frame->u.action.u.bss_tm_resp.action == WLAN_WNM_BTM_RESPONSE) {
        g_agent.io_process(em_bus_event_type_btm_response, (unsigned char *)data->raw_data.bytes, data->raw_data_len);

        return 1;
    }

    if (mgmt_frame->u.action.u.vs_public_action.action == WLAN_PA_VENDOR_SPECIFIC) {
        // printf("Received Vendor Specific Public Action Frame\n");
        uint8_t wfa_oui[3] = {0x50, 0x6F, 0x9A};
        if (!memcmp(mgmt_frame->u.action.u.vs_public_action.oui, wfa_oui, sizeof(wfa_oui))){
            // Push WFA action frame back to main thread
            g_agent.io_process(em_bus_event_type_recv_wfa_action_frame, (unsigned char *)data->raw_data.bytes, data->raw_data_len);
        }
    }

    if (mgmt_frame->u.action.u.public_action.action >= WLAN_PA_GAS_INITIAL_REQ &&
        mgmt_frame->u.action.u.public_action.action <= WLAN_PA_GAS_COMEBACK_RESP) {
        printf("%s:%d: GAS frame rx'd\n", __func__, __LINE__);
        g_agent.io_process(em_bus_event_type_recv_gas_frame, (uint8_t *)data->raw_data.bytes,
                           data->raw_data_len);
    }

    return 0;
}

int em_agent_t::assoc_stats_cb(char *event_name, raw_data_t *data)
{
    //printf("%s:%d recv data:\r\n%s\r\n", __func__, __LINE__, (char *)data->raw_data.bytes);
    cJSON *json, *assoc_stats_arr;

    json = cJSON_Parse((const char *)data->raw_data.bytes);
    if (json != NULL) {
        assoc_stats_arr = cJSON_GetObjectItem(json, "AssociatedDeviceStats");
        if ((assoc_stats_arr == NULL) && (cJSON_IsObject(assoc_stats_arr) == false)) {
            return -1;
        }
        if (cJSON_IsArray(assoc_stats_arr) && cJSON_GetArraySize(assoc_stats_arr) == 0) {
            //printf("%s:%d AssociatedDeviceStats is NULL\n", __func__, __LINE__);
            return -1;
        }
    }

    g_agent.io_process(em_bus_event_type_sta_link_metrics, (unsigned char *)data->raw_data.bytes, data->raw_data_len);

    return 1;
}

void em_agent_t::sta_cb(char *event_name, raw_data_t *data)
{
    //printf("%s:%d Recv data from onewifi:\r\n%s\r\n", __func__, __LINE__, (char *)data->raw_data.bytes);
    g_agent.io_process(em_bus_event_type_sta_list, (unsigned char *)data->raw_data.bytes, data->raw_data_len);

}

void em_agent_t::onewifi_cb(char *event_name, raw_data_t *data)
{
	const char *json_data = (char *)data->raw_data.bytes;
	cJSON *json = cJSON_Parse(json_data);

	//printf("%s:%dRecv data from onewifi:\r\n%s\r\n", __func__, __LINE__, (char *)data->raw_data.bytes);

	if (json == NULL) {
		printf("%s:%d Error parsing JSON\n", __func__, __LINE__);
	} else {
		cJSON *subdoc_name = cJSON_GetObjectItemCaseSensitive(json, "SubDocName");
		if (cJSON_IsString(subdoc_name) && (subdoc_name->valuestring != NULL)) {
			if ((strcmp(subdoc_name->valuestring, "private") == 0) || (strcmp(subdoc_name->valuestring, "Vap_5G") == 0) ||
				(strcmp(subdoc_name->valuestring, "Vap_2.4G") == 0)) {
				printf("%s:%d Found SubDocName: private\n", __func__, __LINE__);
				g_agent.io_process(em_bus_event_type_onewifi_private_cb, (unsigned char *)data->raw_data.bytes, data->raw_data_len);

			} else if ((strcmp(subdoc_name->valuestring, "radio") == 0) || (strcmp(subdoc_name->valuestring, "radio_5G") == 0) ||
				(strcmp(subdoc_name->valuestring, "radio_2.4G") == 0)) {
				printf("%s:%d Found SubDocName: radio\n", __func__, __LINE__);
				g_agent.io_process(em_bus_event_type_onewifi_radio_cb, (unsigned char *)data->raw_data.bytes, data->raw_data_len);

			} else {
				printf("%s:%d SubDocName not matching private or radio \n", __func__, __LINE__);
				return;
			}
		} else {
			printf("%s:%d SubDocName not found\n", __func__, __LINE__);
		}

		cJSON_Delete(json);
	}

}

int em_agent_t::data_model_init(const char *data_model_path)
{
    if (data_model_path != NULL) {
        snprintf(m_data_model_path, sizeof(m_data_model_path), "%s", data_model_path);
    } else {
        m_data_model_path[0] = 0;
    }

    if (m_data_model.init() != 0) {
        printf("%s:%d: data model init failed\n", __func__, __LINE__);
        return -1;
    }

    m_agent_cmd = new em_cmd_agent_t();

    return 0;
}

int em_agent_t::orch_init()
{
    m_orch = new em_orch_agent_t(this);
    return 0;
}

em_t *em_agent_t::find_em_for_msg_type(unsigned char *data, unsigned int len, em_t *al_em)
{
    em_raw_hdr_t *hdr;
    em_cmdu_t *cmdu;
    em_interface_t intf;
    em_freq_band_t band;
    dm_easy_mesh_t *dm;
    em_t *em = NULL;
    mac_address_t ruid;
    em_profile_type_t profile;
    mac_addr_str_t mac_str1, mac_str2;
    bssid_t bss_mac;
    mac_address_t client_mac;
    bool found = false;

    assert(len > ((sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t))));
    if (len < ((sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t)))) {
        return NULL;
    }
   
    hdr = (em_raw_hdr_t *)data;

    if (hdr->type != htons(ETH_P_1905)) {
        return NULL;
    }
   
    cmdu = (em_cmdu_t *)(data + sizeof(em_raw_hdr_t));

    switch (htons(cmdu->type)) {
		case em_msg_type_autoconf_resp:
		case em_msg_type_autoconf_renew:
            if (em_msg_t(data + (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t)),
                    len - (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t))).get_freq_band(&band) == false) {
                printf("%s:%d: Could not find frequency band\n", __func__, __LINE__);
                return NULL;
            }

            em = (em_t *)hash_map_get_first(m_em_map);
            while (em != NULL) {
                if (!(em->is_al_interface_em())) {
                    if (em->is_matching_freq_band(&band) == true) {
                        if ((em->get_state() != em_state_agent_autoconfig_renew_pending) && (em->get_state() !=em_state_agent_wsc_m2_pending) && (em->get_state() != em_state_agent_owconfig_pending) ) {
                            found = true;
                            break;
                        } else {
                            printf("%s:%d: Found matching band%d but incorrect em state %d\n", __func__, __LINE__, band, em->get_state());
                        }
                    }
                }   
                em = (em_t *)hash_map_get_next(m_em_map, em);
            }
            if (found == false) {
                printf("%s:%d: Could not find em with matching band%d and expected state \n", __func__, __LINE__, band);
                return NULL;
            }

            break;
        case em_msg_type_chirp_notif:

		case em_msg_type_autoconf_wsc:
			if (em_msg_t(data + (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t)),
                	len - (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t))).get_radio_id(&ruid) == false) {
				return NULL;
			}

			dm_easy_mesh_t::macbytes_to_string(ruid, mac_str1);
        	if ((em = (em_t *)hash_map_get(m_em_map, mac_str1)) != NULL) {
            	printf("%s:%d: Found existing radio:%s\n", __func__, __LINE__, mac_str1);
        	} else {
				return NULL;
			}
			break;

        case em_msg_type_topo_query:
            if (em_msg_t(data + (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t)),
                len - (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t))).get_radio_id(&ruid) == false) {
                printf("%s:%d: Could not find radio_id for em_msg_type_topo_query\n", __func__, __LINE__);
                return NULL;
            }

            dm_easy_mesh_t::macbytes_to_string(ruid, mac_str1);
            if (((em = (em_t *)hash_map_get(m_em_map, mac_str1)) != NULL)  && (em->get_state() == em_state_agent_onewifi_bssconfig_ind)) {
                printf("%s:%d: Received topo query, found existing radio:%s\n", __func__, __LINE__, mac_str1);
            } else {
                printf("%s:%d: Could not find em for em_msg_type_topo_query\n", __func__, __LINE__);
				if (em != NULL) {
					printf("%s:%d em_msg_type_topo_query :em mac=%s is in incorrect state state=%d \n", __func__, __LINE__, mac_str1, em->get_state());
				}
                return NULL;
            }
            break;

        case em_msg_type_channel_pref_query:
            if (em_msg_t(data + (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t)),
                	len - (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t))).get_radio_id(&ruid) == false) {
                printf("%s:%d: Could not find radio_id for em_msg_type_channel_pref_query\n", __func__, __LINE__);
                return NULL;
            }

            dm_easy_mesh_t::macbytes_to_string(ruid, mac_str1);
            if ((em = (em_t *)hash_map_get(m_em_map, mac_str1)) != NULL) {
                printf("%s:%d: Received channel preference query recv, found existing radio:%s\n", __func__, __LINE__, mac_str1);
            } else {
                printf("%s:%d: Could not find em for em_msg_type_channel_pref_query\n", __func__, __LINE__);
                return NULL;
            }
            break;

        case em_msg_type_topo_notif:
            break;
		
        case  em_msg_type_channel_sel_req:
            if (em_msg_t(data + (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t)),
                	len - (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t))).get_radio_id(&ruid) == false) {
                printf("%s:%d: Could not find radio_id for em_msg_type_channel_pref_query\n", __func__, __LINE__);
                return NULL;
            }

            dm_easy_mesh_t::macbytes_to_string(ruid, mac_str1);
            if ((em = (em_t *)hash_map_get(m_em_map, mac_str1)) != NULL) {
                printf("%s:%d: Received em_msg_type_channel_sel_req, found existing radio:%s\n", __func__, __LINE__, mac_str1);
            } else {
                printf("%s:%d: Could not find em for em_msg_type_channel_sel_req\n", __func__, __LINE__);
                return NULL;
            }

            break;

        case em_msg_type_channel_sel_rsp:
            printf("%s:%d: Received em_msg_type_channel_sel_resp\n", __func__, __LINE__);
            break;

        case  em_msg_type_client_cap_query:
            printf("%s:%d: Received client cap query\n", __func__, __LINE__);

            if (em_msg_t(data + (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t)),
                len - (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t))).get_bss_id(&bss_mac) == false) {
                printf("%s:%d: Could not find BSS mac for em_msg_type_client_cap_query\n", __func__, __LINE__);
                return NULL;
            }

            dm_easy_mesh_t::macbytes_to_string(bss_mac, mac_str1);
            if ((em = (em_t *)hash_map_get(m_em_map, mac_str1)) != NULL) {
                printf("%s:%d: Received client cap query, found existing BSS:%s\n", __func__, __LINE__, mac_str1);
            } else {
                printf("%s:%d: Could not find em for em_msg_type_client_cap_query\n", __func__, __LINE__);
                return NULL;
            }
            break;

        case em_msg_type_client_cap_rprt:
            printf("%s:%d: Sending client cap report\n", __func__, __LINE__);
            break;

        case em_msg_type_op_channel_rprt:
            break;

        case em_msg_type_assoc_sta_link_metrics_query:
            printf("\n%s:%d: Rcvd Assoc STA Link Metrics Query\n", __func__, __LINE__);

            em = (em_t *)hash_map_get_first(m_em_map);
            while (em != NULL) {
                if ((em->is_al_interface_em() == false)) {
                    break;
                }
                em = (em_t *)hash_map_get_next(m_em_map, em);
            }
            break;

        case em_msg_type_assoc_sta_link_metrics_rsp:
            printf("%s:%d: Sending Assoc STA Link Metrics response\n", __func__, __LINE__);
            break;

        case em_msg_type_client_steering_req:
            printf("\n%s:%d: Rcvd Client steering request\n", __func__, __LINE__);
            em = (em_t *)hash_map_get_first(m_em_map);
            while (em != NULL) {
                if ((em->is_al_interface_em() == false)) {
                    //printf("%s:%d: Found em\n", __func__, __LINE__);
                    break;
                }
                em = (em_t *)hash_map_get_next(m_em_map, em);
            }
            break;

        case em_msg_type_client_steering_btm_rprt:
            printf("%s:%d: Sending Client BTM REPORT\n", __func__, __LINE__);
            break;

		case em_msg_type_channel_scan_req:
			if (em_msg_t(data + (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t)),
                	len - (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t))).get_radio_id(&ruid) == false) {
				return NULL;
			}

			dm_easy_mesh_t::macbytes_to_string(ruid, mac_str1);
        	if ((em = (em_t *)hash_map_get(m_em_map, mac_str1)) == NULL) {
				return NULL;
			}
			
			break;

        case  em_msg_type_ap_mld_config_req:
            printf("%s:%d: Received em_msg_type_ap_mld_config_req\n", __func__, __LINE__);

            em = (em_t *)hash_map_get_first(m_em_map);
            while (em != NULL) {
                if ((em->is_al_interface_em() == false)) {
                    //printf("%s:%d: Found em\n", __func__, __LINE__);
                    break;
                }
                em = (em_t *)hash_map_get_next(m_em_map, em);
            }

            break;
        
        case em_msg_type_autoconf_search:
        case em_msg_type_topo_resp:
        case em_msg_type_channel_pref_rprt:
        case em_msg_type_1905_ack:
        case em_msg_type_map_policy_config_req:
            printf(" rcvd em_msg_type_map_policy_config_req\n");
        
            em = (em_t *)hash_map_get_first(m_em_map);
            while (em != NULL) {
                if ((em->is_al_interface_em() == false)) {
                    printf(" em found for policy cfg\n");
                    break;
                }
                em = (em_t *)hash_map_get_next(m_em_map, em);
            }
            break;

		case em_msg_type_channel_scan_rprt:
        case em_msg_type_beacon_metrics_rsp:
        case em_msg_type_ap_mld_config_resp:
        case em_msg_type_beacon_metrics_query:
            break;

        default:
            printf("%s:%d: Frame: %d not handled in agent\n", __func__, __LINE__, htons(cmdu->type));
            assert(0);
            break;	
	}

	return em;
}

bool em_agent_t::agent_output(void *data)
{
    // send configuration to OneWifi after translating
    return true;
}

void em_agent_t::io(void *data, bool input)
{
    em_long_string_t result;

    if (input == true) {
        m_agent_cmd->execute(result);
    } else {
        agent_output(data);
    }
}

void em_agent_t::start_complete()
{

}

bool em_agent_t::try_create_default_em_cfg(std::string interface)
{

    std::string em_cfg_file_path = EM_CFG_FILE;

    
    if (access(em_cfg_file_path.c_str(), F_OK) == 0) {
        // EM_CFG_FILE already exists
        printf("%s:%d: EasymeshCfg.json already exists, not overriding.\n", __func__, __LINE__);
        return true;
    }

    printf("%s:%d: Creating default EasymeshCfg.json for interface: %s\n", __func__, __LINE__, interface.c_str());
    mac_address_t if_mac = {0};
    if (dm_easy_mesh_t::mac_address_from_name(interface.c_str(), if_mac) < 0){
        printf("%s:%d: Failed to get MAC address for interface: %s\n", __func__, __LINE__, interface.c_str());
        return false;
    }

    mac_addr_str_t mac_str;
    if (!dm_easy_mesh_t::macbytes_to_string(if_mac, mac_str)){
        printf("%s:%d: Failed to convert MAC address to string\n", __func__, __LINE__);
        return false;
    }
    printf("%s:%d: Interface MAC address: %s\n", __func__, __LINE__, mac_str);

    FILE *fp = fopen(em_cfg_file_path.c_str(), "w");
    if (fp == NULL) {
        printf("%s:%d: Failed to create default EasymeshCfg.json\n", __func__, __LINE__);
        return false;
    }

    cJSON *root = cJSON_CreateObject();
    if (root == NULL) {
        printf("%s:%d: Failed to create root JSON object\n", __func__, __LINE__);
        fclose(fp);
        return false;
    }
    cJSON *al_mac = cJSON_CreateString(mac_str);
    if (al_mac == NULL) {
        printf("%s:%d: Failed to create AL_MAC_ADDR JSON object\n", __func__, __LINE__);
        fclose(fp);
        cJSON_Delete(root);
        return false;
    }
    cJSON *colocated_mode = cJSON_CreateNumber(0);
    if (colocated_mode == NULL) {
        printf("%s:%d: Failed to create Colocated_mode JSON object\n", __func__, __LINE__);
        fclose(fp);
        cJSON_Delete(root);
        return false;
    }

    cJSON_AddItemToObject(root, "AL_MAC_ADDR", al_mac);
    cJSON_AddItemToObject(root, "Colocated_mode", colocated_mode);

    char *json_str = cJSON_Print(root);
    fprintf(fp, "%s", json_str);
    fclose(fp);
    cJSON_Delete(root);

    printf("%s:%d: Created default EasymeshCfg.json for interface: %s\n", __func__, __LINE__, interface.c_str());
    printf("%s\n", json_str);

    free(json_str);

    return true;
}

em_agent_t::em_agent_t()
{

}

em_agent_t::~em_agent_t()
{

}
#ifdef AL_SAP
AlServiceAccessPoint* em_agent_t::al_sap_register()
{
    AlServiceAccessPoint* sap = new AlServiceAccessPoint(SOCKET_PATH);

    AlServiceRegistrationRequest registrationRequest(ServiceOperation::SO_ENABLE, ServiceType::SAP_TUNNEL_CLIENT);
    sap->serviceAccessPointRegistrationRequest(registrationRequest);

    AlServiceRegistrationResponse registrationResponse = sap->serviceAccessPointRegistrationResponse();

    RegistrationResult result = registrationResponse.getResult();
    if (result == RegistrationResult::SUCCESS) {
        g_al_mac_sap = registrationResponse.getAlMacAddressLocal();
        std::cout << "Registration completed with MAC Address: ";
        for (auto byte : g_al_mac_sap) {
            std::cout << std::hex << static_cast<int>(byte) << " ";
        }
        std::cout << std::dec << std::endl;
    } else {
        std::cout << "Registration failed with error: " << (int)result << std::endl;
    }

    return sap;
}
#endif

int main(int argc, const char *argv[])
{

    std::vector<std::string> args;
    // Skip the first argument which is the program name
    for (int i = 1; i < argc; i++) {
        args.push_back(argv[i]);
    }

    if ((args.size() == 1) && (args[0] == "--help" || args[0] == "-h")) {
        printf("Usage: %s [data-model-path] [--interface=iface]\n", argv[0]);
        return 0;
    }

    std::string data_model_path = "";

    bool interface_found = false;

    for (auto arg : args) {
        if (arg.find("--interface=") != std::string::npos && !interface_found) {
            std::string interface = arg.substr(strlen("--interface="));
            if (interface.empty()) {
                printf("Invalid interface name\n");
                return -1;
            }
            if (!g_agent.try_create_default_em_cfg(interface)) {
                printf("Failed to create default EasymeshCfg.json\n");
                return -1;
            }
            interface_found = true;
            continue;
        }
        if (data_model_path.empty()) {
            data_model_path = arg;
            continue;
        }
        printf("Invalid argument: %s\n", arg.c_str());
        return -1;
    }

    if (!data_model_path.empty()) {
        printf("Using data model path: %s\n", data_model_path.c_str());
    }

    if (g_agent.init(data_model_path.empty() ? NULL : data_model_path.c_str()) == 0) {
#ifdef AL_SAP
    g_sap = g_agent.al_sap_register();
#endif
        g_agent.start();
    }

    return 0;
}

