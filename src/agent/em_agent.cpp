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
#include "ec_util.h"
#include "util.h"
#include <cjson/cJSON.h>

#include <string>
#include <vector>
#ifdef AL_SAP
#include "al_service_access_point.h"
#endif

#define RETRY_SLEEP_INTERVAL_IN_MS 1000

#define DATA_SOCKET_PATH "/tmp/al_data_socket"
#define CONTROL_SOCKET_PATH "/tmp/al_control_socket"

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

    if (m_orch->is_cmd_type_in_progress(evt) == true) {
        printf("analyze_sta_link_metrics in progress\n");
    } else if ((num = m_data_model.analyze_sta_link_metrics(evt, pcmd)) == 0) {
        printf("analyze_sta_link_metrics failed\n");
    } else if (m_orch->submit_commands(pcmd, num) > 0) {
        printf("analyze_sta_link_metrics submit complete\n");
    }
}

void em_agent_t::handle_ap_cap_query(em_bus_event_t *evt)
{
    em_cmd_t *pcmd[EM_MAX_CMD] = {NULL};
    unsigned int num;

    if (m_orch->is_cmd_type_in_progress(evt) == true) {
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

    if (m_orch->is_cmd_type_in_progress(evt) == true) {
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

    if (m_orch->is_cmd_type_in_progress(evt) == true) {
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

    if (m_orch->is_cmd_type_in_progress(evt)) {
        m_agent_cmd->send_result(em_cmd_out_status_prev_cmd_in_progress);
        return;
    }
    if ((num = m_data_model.analyze_dev_init(evt, pcmd)) == 0) {
        m_agent_cmd->send_result(em_cmd_out_status_no_change);
        return;
    }
    if (m_orch->submit_commands(pcmd, num) == 0) {
        m_agent_cmd->send_result(em_cmd_out_status_not_ready);
        return;
    }

    if (do_start_dpp_onboarding) {
        try_start_dpp_onboarding();
        // TODO: check if dpp onboarding is successful and manage result
    }
    
    m_agent_cmd->send_result(em_cmd_out_status_success);
}

void em_agent_t::handle_channel_pref_query(em_bus_event_t *evt)
{
    em_cmd_t *pcmd[EM_MAX_CMD] = {NULL};
    unsigned int num;

    if (m_orch->is_cmd_type_in_progress(evt) == true) {
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

    if (m_orch->is_cmd_type_in_progress(evt) == true) {
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

    if (m_orch->is_cmd_type_in_progress(evt) == true) {
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

    if (m_orch->is_cmd_type_in_progress(evt) == true) {
        m_agent_cmd->send_result(em_cmd_out_status_prev_cmd_in_progress);
    } else if ((num = m_data_model.analyze_onewifi_vap_cb(evt, pcmd)) == 0) {
        printf("analyze_onewifi_vap_cb completed\n");
    } else if (m_orch->submit_commands(pcmd, num) > 0) {
        printf("submitted command for orchestration\n");
    }
}

void em_agent_t::handle_onewifi_mesh_sta_cb(em_bus_event_t *evt)
{
    em_cmd_t *pcmd[EM_MAX_CMD] = {NULL};
    unsigned int num;
    wifi_bus_desc_t *desc;

    if ((desc = get_bus_descriptor()) == NULL) {
        printf("descriptor is null");
    }

    if (m_orch->is_cmd_type_in_progress(evt) == true) {
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

    if (m_orch->is_cmd_type_in_progress(evt) == true) {
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

    if (m_orch->is_cmd_type_in_progress(evt) == true) {
	printf("handle_autoconfig_renew in progress\n");
    }  else if ((num = m_data_model.analyze_autoconfig_renew(evt, pcmd)) == 0) {
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

void em_agent_t::handle_recv_assoc_status(em_bus_event_t *event)
{
    if (event == nullptr) {
        em_printfout("NULL event!");
        return;
    }
    rdk_sta_data_t *sta_data = reinterpret_cast<rdk_sta_data_t *>(event->u.raw_buff);

    // Only the `ec_manager_t` (which belongs only to the AL node) needs to get live association status at this time
    em_t *al_node = get_al_node();
    if (al_node == nullptr) {
        em_printfout("AL node is nullptr!");
        return;
    }

    if (!al_node->m_ec_manager->handle_assoc_status(*sta_data)) {
        em_printfout("EC managed failed to handle association status event!");
        return;
    }
}

void em_agent_t::handle_bss_info(em_bus_event_t *event)
{
    if (event == nullptr) {
        em_printfout("NULL event!");
        return;
    }

    const size_t expected_size = sizeof(wifi_bss_info_t);
    unsigned int len = event->data_len;

    if (len % expected_size != 0) {
        em_printfout("Expected event size divisible by %d, got %d, not handling", expected_size, event->data_len);
        return;
    }

    wifi_bss_info_t *bss_info_buff = reinterpret_cast<wifi_bss_info_t *>(event->u.raw_buff);

    em_t *al_node = get_al_node();
    if (al_node == nullptr) {
        em_printfout("AL node is nullptr!");
        return;
    }

    if (len == 0 || bss_info_buff == NULL) {
        // Publish that no scan results contained a CCE IE
        if (!al_node->m_ec_manager->handle_bss_info_event({})) {
            em_printfout("EC manager failed to handle empty scan result!");
        }
        return;
    }

    unsigned int bss_count = static_cast<unsigned int>(len / expected_size);
    std::vector<wifi_bss_info_t> heard_bsses(bss_info_buff, bss_info_buff + bss_count);

    if (!al_node->m_ec_manager->handle_bss_info_event(heard_bsses)) {
        em_printfout("EC manager failed to handle a BSS info event!");
    }
}

void em_agent_t::handle_recv_gas_frame(em_bus_event_t *evt)
{
    if (!evt) {
        printf("%s:%d: NULL bus event!\n", __func__, __LINE__);
        return;
    }
    const size_t full_frame_length = evt->data_len;
    const size_t mgmt_hdr_len = offsetof(struct ieee80211_mgmt, u);
    ieee80211_mgmt *mgmt_frame = (ieee80211_mgmt *)evt->u.raw_buff;

    mac_addr_str_t dest_mac;
    dm_easy_mesh_t::macbytes_to_string(mgmt_frame->da, dest_mac);
    em_t *dest_node = (em_t *)hash_map_get(g_agent.m_em_map, dest_mac);
    if (!dest_node) {
        printf("%s:%d: no node found for MAC '%s'\n", __func__, __LINE__, dest_mac);
        return;
    }

    em_t* al_node = get_al_node();

    auto gas_frame_base = (ec_gas_frame_base_t *)(evt->u.raw_buff + mgmt_hdr_len);

    bool is_wfa_ec_gas = false;

    switch (gas_frame_base->action) {
    case dpp_gas_action_type_t::dpp_gas_initial_req: {
        printf("%s:%d: Received GAS Initial Request\n", __func__, __LINE__);
        ec_gas_initial_request_frame_t *gas_initial_req_frame =
            (ec_gas_initial_request_frame_t *)gas_frame_base;
        uint8_t *ap_proto_id = gas_initial_req_frame->ape_id;
        if (ap_proto_id[0] == 0xDD) {
            // Vendor specific GAS frame
            if (memcmp(ap_proto_id, DPP_GAS_CONFIG_REQ_PROTO_ID,
                       sizeof(DPP_GAS_CONFIG_REQ_PROTO_ID)) == 0) {
                // DPP GAS frame
                is_wfa_ec_gas = true;
            }
        }
        break;
    }
    case dpp_gas_action_type_t::dpp_gas_initial_resp: {
        printf("%s:%d: Received GAS Initial Response\n", __func__, __LINE__);
        ec_gas_initial_response_frame_t *gas_initial_resp_frame =
            (ec_gas_initial_response_frame_t *)gas_frame_base;
        uint8_t *ap_proto_id = gas_initial_resp_frame->ape_id;
        if (ap_proto_id[0] == 0xDD) {
            // Vendor specific GAS frame
            if (memcmp(ap_proto_id, DPP_GAS_CONFIG_REQ_PROTO_ID,
                       sizeof(DPP_GAS_CONFIG_REQ_PROTO_ID)) == 0) {
                // DPP GAS frame
                is_wfa_ec_gas = true;
            }
        }
        break;
    }
    case dpp_gas_action_type_t::dpp_gas_comeback_req: {
        printf("%s:%d: Received GAS Comeback Request\n", __func__, __LINE__);
        is_wfa_ec_gas = true;
        break;
    }
    case dpp_gas_action_type_t::dpp_gas_comeback_resp: {
        printf("%s:%d: Received GAS Comeback Response\n", __func__, __LINE__);
        ec_gas_comeback_response_frame_t *cb_resp_frame = reinterpret_cast<ec_gas_comeback_response_frame_t*>(gas_frame_base);
        if (cb_resp_frame->ape_id[0] == 0xDD && memcmp(cb_resp_frame->ape_id, DPP_GAS_CONFIG_REQ_PROTO_ID, sizeof(DPP_GAS_CONFIG_REQ_PROTO_ID)) == 0) {
            is_wfa_ec_gas = true;
        }
        break;
    }
    default:
        printf("%s:%d: Received unknown GAS action type '0x%x'\n", __func__, __LINE__,
               gas_frame_base->action);
        return;
    }

    if (is_wfa_ec_gas) {
        printf("%s:%d: Received WFA EC GAS frame\n", __func__, __LINE__);
        bool dest_al_same = false;
        if (dest_node != NULL && al_node != NULL) {
            em_printfout("Dest radio node MAC '" MACSTRFMT "', al_node radio MAC '" MACSTRFMT"'\n", MAC2STR(dest_node->get_radio_interface_mac()), MAC2STR(al_node->get_radio_interface_mac()));
            dest_al_same = (memcmp(dest_node->get_radio_interface_mac(), al_node->get_radio_interface_mac(), ETH_ALEN) == 0);
        }
    
        auto ctrl_al = m_data_model.get_controller_interface_mac();
        auto agent_al = m_data_model.get_agent_al_interface_mac();
        bool is_colocated = (memcmp(ctrl_al, agent_al, ETH_ALEN) == 0);
    
        em_printfout("Dest MAC '" MACSTRFMT "', dest_al_same=%d, is_colocated=%d", MAC2STR(dest_node->get_radio_interface_mac()), dest_al_same, is_colocated);
                                
        /*
        If any of the following conditions are satisfied:
            - The destination MAC is the same as the AL node (mac address)
            - The colocated flag is set
        Then the `ec_manager` of the AL node will handle the action frame
        
        We don't ignore it if this co-located since the AL-node will be the same as the controller (eth0) 
        so if we ignore it, no packets will ever get through
        */
        if (dest_al_same || is_colocated) {
            if (!al_node->get_ec_mgr().handle_recv_gas_pub_action_frame(
                gas_frame_base, full_frame_length - mgmt_hdr_len, mgmt_frame->sa)) {
                printf("%s:%d: EC manager failed to handle GAS frame!\n", __func__, __LINE__);
            }
            return;
        }

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
    printf("Dest Mac Str: %s\n", dest_mac_str);
    bool is_bcast = (memcmp(mgmt_frame->da, BROADCAST_MAC_ADDR, ETH_ALEN) == 0);
    if (is_bcast) {
        printf("Received WFA action frame with broadcast destination MAC address\n");
    }
    em_t* dest_radio_node = static_cast<em_t*>(hash_map_get(g_agent.m_em_map, dest_mac_str));
    if (dest_radio_node == NULL &&  !is_bcast) {
        // If the destination MAC is a broadcast address, we don't need to find the node
        em_printfout("No radio node found for dest mac %s\n", dest_mac_str);
        return;
    }

    // First byte is the OUI type
    uint8_t oui_type = *vs_action_data;

    size_t full_action_frame_len = frame_len - mgmt_hdr_len;
    auto ec_frame = reinterpret_cast<ec_frame_t*>(evt->u.raw_buff + mgmt_hdr_len);

    switch (oui_type) {
    case DPP_OUI_TYPE: {
        em_t* al_node = get_al_node();
        bool dest_al_same = false;
        if (dest_radio_node != NULL && al_node != NULL) {
            em_printfout("Dest radio node MAC '" MACSTRFMT "', al_node radio MAC '" MACSTRFMT"'\n", MAC2STR(dest_radio_node->get_radio_interface_mac()), MAC2STR(al_node->get_radio_interface_mac()));
            dest_al_same = (memcmp(dest_radio_node->get_radio_interface_mac(), al_node->get_radio_interface_mac(), ETH_ALEN) == 0);
        }

        auto ctrl_al = m_data_model.get_controller_interface_mac();
        auto agent_al = m_data_model.get_agent_al_interface_mac();
        bool is_colocated = (memcmp(ctrl_al, agent_al, ETH_ALEN) == 0);

        em_printfout("Dest MAC '%s', dest_al_same=%d, is_bcast=%d, is_colocated=%d", dest_mac_str, dest_al_same, is_bcast, is_colocated);

        /*
        If any of the following conditions are satisfied:
            - The destination MAC is a broadcast address
            - The destination MAC is the same as the AL node (mac address)
            - The colocated flag is set
        Then the `ec_manager` of the AL node will handle the action frame
        
        We don't ignore it if this co-located since the AL-node will be the same as the controller (eth0) 
        so if we ignore it, no packets will ever get through
        */

        if (is_bcast || dest_al_same || is_colocated) {
            if (!al_node->get_ec_mgr().handle_recv_ec_action_frame(ec_frame, full_action_frame_len, mgmt_frame->sa)){
                em_printfout("EC manager failed to handle action frame!");
            }
            return;
        }
        em_printfout("Did not find an EM node for action frame!");
    }
    default:
        break;
    }
}

void em_agent_t::handle_btm_response_action_frame(em_bus_event_t *evt)
{
    em_cmd_t *pcmd[EM_MAX_CMD] = {NULL};
    unsigned int num;

    if (m_orch->is_cmd_type_in_progress(evt) == true) {
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

    if ((num = m_data_model.analyze_scan_result(evt, pcmd)) == 0) {
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

    if (!send_scan_request((em_scan_params_t *)&evt->u.raw_buff, true)) {
        printf("send_scan_request failed\n");
        return;
    }
}

bool em_agent_t::send_scan_request(em_scan_params_t* scan_params, bool perform_fresh_scan, bool is_sta_vap){
    unsigned i, j;
    mac_addr_str_t radio_mac_str;
    raw_data_t l_bus_data;
    

    std::string ruid_str = util::mac_to_string(scan_params->ruid);
    em_printfout("Radio: %s Num of Op Classes: %d\n", ruid_str.c_str(), scan_params->num_op_classes);

    channel_scan_request_t scan_data;
    memset(&scan_data, 0, sizeof(channel_scan_request_t));

    scan_data.perform_fresh_scan = perform_fresh_scan;
    scan_data.num_radios = 1;

    memcpy(scan_data.ruid, scan_params->ruid, sizeof(mac_address_t));

    scan_data.num_operating_classes = scan_params->num_op_classes;
    for (i = 0; i < scan_params->num_op_classes; i++) {
        scan_data.operating_classes[i].operating_class = scan_params->op_class[i].op_class;
        scan_data.operating_classes[i].num_channels = scan_params->op_class[i].num_channels;
        printf("Op Class: %d ", scan_params->op_class[i].op_class);
        printf("Channels: ");
        for (j = 0; j < scan_params->op_class[i].num_channels; j++) {
            scan_data.operating_classes[i].channels[j] = scan_params->op_class[i].channels[j];
            printf("%d ", scan_params->op_class[i].channels[j]);
        }
        printf("\n");
    }

    l_bus_data.data_type = bus_data_type_bytes;
    l_bus_data.raw_data.bytes = (void *)&scan_data;
    l_bus_data.raw_data_len = sizeof(channel_scan_request_t);

    wifi_bus_desc_t *desc;

    if((desc = get_bus_descriptor()) == NULL) {
       printf("descriptor is null");
       return false;
    }

    std::string path = (is_sta_vap) ? WIFI_EC_SEND_TRIG_STA_SCAN : WIFI_EM_CHANNEL_SCAN_REQUEST;
    em_printfout("Sending channel scan request to: %s", path.c_str());

    if (desc->bus_set_fn(&m_bus_hdl, path.c_str(), &l_bus_data) != 0) {
        em_printfout("Failed to send channel scan request to bus");
        return false;
    }
    em_printfout("Sent channel scan request to bus\n");
    return true;
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

    if (m_orch->is_cmd_type_in_progress(evt) == true) {
        printf("set policy in progress\n");
    } else if ((num = m_data_model.analyze_set_policy(evt, desc, &m_bus_hdl)) == 0) {
        printf("set policy failed\n");
    }
}

void em_agent_t::handle_beacon_report(em_bus_event_t *evt)
{
    em_cmd_t *pcmd[EM_MAX_CMD] = {NULL};
    unsigned int num = 0;

    if (m_orch->is_cmd_type_in_progress(evt) == true) {
        printf("analyze_beacon_report in progress\n");
    } else if ((num = m_data_model.analyze_beacon_report(evt, pcmd)) == 0) {
        printf("analyze_beacon_report failed\n");
    } else if (m_orch->submit_commands(pcmd, num) > 0) {
        printf("submitted beacon report cmd for orch\n");
    }
}

void em_agent_t::handle_ap_metrics_report(em_bus_event_t *evt)
{
    em_cmd_t *pcmd[EM_MAX_CMD] = {NULL};
    unsigned int num;

    if (m_orch->is_cmd_type_in_progress(evt) == true) {
        printf("analyze_ap_metrics_report in progress\n");
    } else if ((num = m_data_model.analyze_ap_metrics_report(evt, pcmd)) == 0) {
        printf("analyze_ap_metrics_report failed\n");
    } else if (m_orch->submit_commands(pcmd, num) > 0) {
        printf("Submitted AP Metrics report cmd for orch\n");
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
        case em_bus_event_type_onewifi_mesh_sta_cb:
            handle_onewifi_mesh_sta_cb(evt);
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

        case em_bus_event_type_assoc_status:
            handle_recv_assoc_status(evt);
            break;

        case em_bus_event_type_ap_metrics_report:
            handle_ap_metrics_report(evt);
            break;

        case em_bus_event_type_bss_info:
            handle_bss_info(evt);
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

int em_agent_t::refresh_onewifi_subdoc(const char * log_name, const webconfig_subdoc_type_t type)
{
    wifi_bus_desc_t *desc = get_bus_descriptor();
    ASSERT_NOT_NULL(desc, false, "%s:%d descriptor is null\n", __func__, __LINE__);
    
    return m_data_model.refresh_onewifi_subdoc(desc, &m_bus_hdl, log_name, type);
}

bool em_agent_t::send_action_frame(uint8_t dest_mac[ETH_ALEN], uint8_t *action_frame, size_t action_frame_len, unsigned int frequency, unsigned int wait_time_ms) {

    wifi_bus_desc_t *desc = get_bus_descriptor();
    ASSERT_NOT_NULL(desc, false, "%s:%d descriptor is null\n", __func__, __LINE__);

    // Allocate memory for the action frame parameters, ieee80211 header and action frame body
    action_frame_params_t *act_frame_params = (action_frame_params_t*) calloc(sizeof(action_frame_params_t) + action_frame_len, 1);
    ASSERT_NOT_NULL(act_frame_params, false, "%s:%d calloc failed\n", __func__, __LINE__);

    // Hardcoded to 0 just the same as the other bus calls
    // NOTE: AccessPoint.1 = ap_index 0. One is the data model indexing, one is NL80211/hal indexing
    static int test_idx = 0;
    act_frame_params->ap_index = test_idx;
    memcpy(act_frame_params->dest_addr, dest_mac, ETH_ALEN);
    act_frame_params->frequency = frequency;

    //TODO: Disabled until halinterace, rdk-wifi-hal, OneWifi PRs are merged
    act_frame_params->wait_time_ms = wait_time_ms;

    act_frame_params->frame_len = action_frame_len;
    memcpy(act_frame_params->frame_data, action_frame, action_frame_len);

    raw_data_t raw_act_frame;
    memset(&raw_act_frame, 0, sizeof(raw_data_t));
    raw_act_frame.raw_data.bytes = (uint8_t *)act_frame_params;
    raw_act_frame.raw_data_len = sizeof(action_frame_params_t) + action_frame_len;
    raw_act_frame.data_type = bus_data_type_bytes;

    
    char path[100] = {0};
    snprintf(path, sizeof(path), "Device.WiFi.AccessPoint.%d.RawFrame.Mgmt.Action.Tx", test_idx+1);
    
    em_printfout("Sending action frame: VAP Idx (%d), Dest (" MACSTRFMT "), Frequency (%d), Dwell Time (%d)", test_idx, MAC2STR(dest_mac), frequency, wait_time_ms);
    // Send the action frame
    bus_error_t rc;
    if ((rc = desc->bus_set_fn(&m_bus_hdl, path,  &raw_act_frame)) != 0) {
        if (rc == bus_error_destination_not_found) test_idx++;
        if (test_idx > 255) test_idx = 0;
        printf("%s:%d bus set failed (%d)\n", __func__, __LINE__, rc);
        free(act_frame_params);
        return false;
    }

    free(act_frame_params);
    return true;
}

bool em_agent_t::set_disconnected_steady_state()
{
    
    wifi_bus_desc_t *desc = get_bus_descriptor();
    ASSERT_NOT_NULL(desc, false, "%s:%d descriptor is null\n", __func__, __LINE__);

    raw_data_t empty_arg;
    memset(&empty_arg, 0, sizeof(raw_data_t));
    empty_arg.data_type = bus_data_type_none;
    if (desc->bus_set_fn(&m_bus_hdl, WIFI_SET_DISCONN_STEADY_STATE, &empty_arg)== 0) {
        em_printfout("Set Disconnected Steady State succeeded");
        return true;
    }
    em_printfout("Set Disconnected Steady State failed");
    return false;
}

bool em_agent_t::set_disconnected_scan_none_state()
{
    
    wifi_bus_desc_t *desc = get_bus_descriptor();
    ASSERT_NOT_NULL(desc, false, "%s:%d descriptor is null\n", __func__, __LINE__);

    raw_data_t empty_arg;
    memset(&empty_arg, 0, sizeof(raw_data_t));
    empty_arg.data_type = bus_data_type_none;
    if (desc->bus_set_fn(&m_bus_hdl, WIFI_SET_DISCONN_SCAN_NONE_STATE, &empty_arg)== 0) {
        em_printfout("Set Disconnected Scan None succeeded");
        return true;
    }
    em_printfout("Set Disconnected Scan None failed");
    return false;
}

bool em_agent_t::can_onboard_additional_aps()
{
    // XXX: TODO: Real business logic!
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

    if (desc->bus_event_subs_fn(&m_bus_hdl, "Device.WiFi.EM.STALinkMetricsReport", (void *)&em_agent_t::assoc_stats_cb, NULL, 0) != 0) {
        printf("%s:%d bus get failed\n", __func__, __LINE__);
        return;
    }

    if (desc->bus_event_subs_fn(&m_bus_hdl, "Device.WiFi.AccessPoint.1.RawFrame.Mgmt.Action.Rx", (void *)&em_agent_t::mgmt_action_frame_cb, NULL, 0) != 0) {
        printf("%s:%d bus get failed\n", __func__, __LINE__);
        return;
    }

    if (desc->bus_event_subs_fn(&m_bus_hdl, WIFI_EM_CHANNEL_SCAN_REPORT, (void *)&em_agent_t::channel_scan_cb, NULL, 0) != 0) {
        printf("%s:%d bus get failed\n", __func__, __LINE__);
        return;
    }

    if (desc->bus_event_subs_fn(&m_bus_hdl, "Device.WiFi.EM.BeaconReport", (void *)&em_agent_t::beacon_report_cb, NULL, 0) != 0) {
        printf("%s:%d bus get failed\n", __func__, __LINE__);
        return;
    }

    if (desc->bus_event_subs_fn(&m_bus_hdl, "Device.WiFi.EM.AssociationStatus", reinterpret_cast<void *>(&em_agent_t::association_status_cb), nullptr, 0) != 0) {
        em_printfout("Failed to subscribe to 'Device.WiFi.EM.AssociationStatus'");
        return;
    }

    if (desc->bus_event_subs_fn(&m_bus_hdl, "Device.WiFi.EC.BSSInfo", reinterpret_cast<void *>(&em_agent_t::bss_info_cb), nullptr, 0) != 0) {
        em_printfout("Failed to subscribe to 'Device.WiFi.EC.BSSInfo', dynamic DPP channel list for Reconfiguration Announcement is not available");
        // This is fine, not a fatal error
    }

    if (desc->bus_event_subs_fn(&m_bus_hdl, "Device.WiFi.EM.APMetricsReport", (void *)&em_agent_t::ap_metrics_report_cb, NULL, 0) != 0) {
        printf("%s:%d bus get failed\n", __func__, __LINE__);
        return;
    }

    io(NULL);
}

int em_agent_t::bss_info_cb(char *event_name, raw_data_t *data, void *userData)
{
    if (data == nullptr) {
        em_printfout("NULL data from OneWifi callback!");
        return -1;
    }
    g_agent.io_process(em_bus_event_type_bss_info, reinterpret_cast<unsigned char *>(data->raw_data.bytes), data->raw_data_len);
    return 1;
}

int em_agent_t::association_status_cb(char *event_name, raw_data_t *data, void *userData)
{
    if (data == nullptr) {
        em_printfout("NULL data from OneWiFi callback!");
        return -1;
    }
    g_agent.io_process(em_bus_event_type_assoc_status, reinterpret_cast<unsigned char *>(data->raw_data.bytes), data->raw_data_len);
    return 1;
}

int em_agent_t::channel_scan_cb(char *event_name, raw_data_t *data, void *userData)
{
    (void)userData;
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

int em_agent_t::ap_metrics_report_cb(char *event_name, raw_data_t *data, void *userData)
{
    //printf("%s:%d Received Frame data for event [%s] and data :\n%s\n", __func__, __LINE__, event_name, data->raw_data.bytes);
    (void)userData;

    g_agent.io_process(em_bus_event_type_ap_metrics_report, (unsigned char *)data->raw_data.bytes, data->raw_data_len);

    return 0;
}

int em_agent_t::beacon_report_cb(char *event_name, raw_data_t *data, void *userData)
{
    //printf("%s:%d Received Frame data for event [%s] and data :\n%s\n", __func__, __LINE__, event_name, data->raw_data.bytes);
    (void)userData;

    g_agent.io_process(em_bus_event_type_beacon_report, (unsigned char *)data->raw_data.bytes, data->raw_data_len);

    return 0;
}

int em_agent_t::mgmt_action_frame_cb(char *event_name, raw_data_t *data, void *userData)
{
    (void)userData;
    struct ieee80211_mgmt *mgmt_frame = (struct ieee80211_mgmt *)data->raw_data.bytes;
    printf("%s:%d Received Frame data for event [%s] and data of len:\n%d\n", __func__, __LINE__, event_name, data->raw_data_len);

    //util::print_hex_dump(data->raw_data_len, (uint8_t*)data->raw_data.bytes);

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

int em_agent_t::assoc_stats_cb(char *event_name, raw_data_t *data, void *userData)
{
    (void)userData;
    //printf("%s:%d recv data:\r\n%s\r\n", __func__, __LINE__, (char *)data->raw_data.bytes);
    cJSON *json, *assoc_stats_arr;

    json = cJSON_Parse((const char *)data->raw_data.bytes);
    if (json != NULL) {
        cJSON *subdoc_name = cJSON_GetObjectItemCaseSensitive(json, "SubDocName");
        if ((strcmp(subdoc_name->valuestring, "Easymesh STA link metrics") == 0)) {
            printf("%s:%d Found SubDocName: Easymesh STA link metrics\n", __func__, __LINE__);
        } else if ((strcmp(subdoc_name->valuestring, "AssociatedDeviceStats") == 0)) {
            printf("%s:%d Found SubDocName: AssociatedDeviceStats\n", __func__, __LINE__);
            assoc_stats_arr = cJSON_GetObjectItem(json, "AssociatedDeviceStats");
            if ((assoc_stats_arr == NULL) && (cJSON_IsObject(assoc_stats_arr) == false)) {
                return -1;
            }
            if (cJSON_IsArray(assoc_stats_arr) && cJSON_GetArraySize(assoc_stats_arr) == 0) {
                printf("%s:%d AssociatedDeviceStats is NULL\n", __func__, __LINE__);
                return -1;
            }
        }
    }

    g_agent.io_process(em_bus_event_type_sta_link_metrics, (unsigned char *)data->raw_data.bytes, data->raw_data_len);
    cJSON_Delete(json);

    return 1;
}

void em_agent_t::sta_cb(char *event_name, raw_data_t *data, void *userData)
{
    (void)userData;
    //printf("%s:%d Recv data from onewifi:\r\n%s\r\n", __func__, __LINE__, (char *)data->raw_data.bytes);
    g_agent.io_process(em_bus_event_type_sta_list, (unsigned char *)data->raw_data.bytes, data->raw_data_len);

}

void em_agent_t::onewifi_cb(char *event_name, raw_data_t *data, void *userData)
{
        (void)userData;
	const char *json_data = (char *)data->raw_data.bytes;
	cJSON *json = cJSON_Parse(json_data);

	//printf("%s:%dRecv data from onewifi:\r\n%s\r\n", __func__, __LINE__, (char *)data->raw_data.bytes);

	if (json == NULL) {
		printf("%s:%d Error parsing JSON\n", __func__, __LINE__);
        return;
	}
    cJSON *subdoc_name = cJSON_GetObjectItemCaseSensitive(json, "SubDocName");
    if (!cJSON_IsString(subdoc_name) || (subdoc_name->valuestring == NULL)) {
        cJSON_Delete(json);
        return;
    }

    if ((strcmp(subdoc_name->valuestring, "private") == 0) || (strcmp(subdoc_name->valuestring, "Vap_6G") == 0) ||
        (strcmp(subdoc_name->valuestring, "Vap_5G") == 0) || (strcmp(subdoc_name->valuestring, "Vap_2.4G") == 0)) {
        printf("%s:%d Found SubDocName: private\n", __func__, __LINE__);
        g_agent.io_process(em_bus_event_type_onewifi_private_cb, (unsigned char *)data->raw_data.bytes, data->raw_data_len);

    } else if ((strcmp(subdoc_name->valuestring, "radio") == 0) || (strcmp(subdoc_name->valuestring, "radio_6G") == 0) ||
        (strcmp(subdoc_name->valuestring, "radio_5G") == 0) || (strcmp(subdoc_name->valuestring, "radio_2.4G") == 0)) {
        printf("%s:%d Found SubDocName: radio\n", __func__, __LINE__);
        g_agent.io_process(em_bus_event_type_onewifi_radio_cb, (unsigned char *)data->raw_data.bytes, data->raw_data_len);

    } else if ((strcmp(subdoc_name->valuestring, "mesh_sta") == 0) || 
               (strcmp(subdoc_name->valuestring, "mesh backhaul sta") == 0)) {
        printf("%s:%d Found SubDocName: mesh_sta\n", __func__, __LINE__);
        g_agent.io_process(em_bus_event_type_onewifi_mesh_sta_cb, (unsigned char *)data->raw_data.bytes, data->raw_data_len);

    } else {
        printf("%s:%d SubDocName not matching private or radio \n", __func__, __LINE__);
    }

    cJSON_Delete(json);

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
    em_string_t al_mac_str;
    em_bss_info_t *em_bss = NULL;

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
		found = false;
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
	case em_msg_type_autoconf_renew:
		found = false;
		if (em_msg_t(data + (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t)),
				len - (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t))).get_freq_band(&band) == false) {
			printf("%s:%d: Could not find frequency band\n", __func__, __LINE__);
			return NULL;
		}

		if (em_msg_t(data + (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t)),
			len - (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t))).get_al_mac_address(ruid) == false) {
			printf("%s:%d: Could not find radio_id for em_msg_type_topo_query\n", __func__, __LINE__);
			return NULL;
		}
		dm_easy_mesh_t::macbytes_to_string(ruid, al_mac_str);
		strcat(al_mac_str, "_al");
		if ((em = (em_t *)hash_map_get(m_em_map, al_mac_str)) != NULL) {
			printf("%s:%d: Found existing AL MAC:%s\n", __func__, __LINE__, al_mac_str);
		} else {
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
						return NULL;
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
                if (em->is_al_interface_em() == false) {
                        printf("%s:%d: Received channel preference query recv, found existing radio:%s\n", __func__, __LINE__, mac_str1);
                } else {
                        return NULL;
                }
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
                if (em->is_al_interface_em() == false) {
                    printf("%s:%d: Received em_msg_type_channel_sel_req, found existing radio:%s\n", __func__, __LINE__, mac_str1);
                } else {
                    return NULL;
                }
            } else {
                printf("%s:%d: Could not find em for em_msg_type_channel_sel_req\n", __func__, __LINE__);
                return NULL;
            }

            break;

        case em_msg_type_channel_sel_rsp:
            printf("%s:%d: Received em_msg_type_channel_sel_resp\n", __func__, __LINE__);
            break;

        case  em_msg_type_client_cap_query:
            if (em_msg_t(data + (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t)),
                len - (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t))).get_bss_id(&bss_mac) == false) {
                printf("%s:%d: Could not find BSS mac for em_msg_type_client_cap_query\n", __func__, __LINE__);
                return NULL;
            }

            dm_easy_mesh_t::macbytes_to_string(bss_mac, mac_str1);

            em = static_cast<em_t *> (hash_map_get_first(m_em_map));
            while (em != NULL) {
                dm = em->get_data_model();
                em_bss = dm->get_bss_info_with_mac(bss_mac);
                if (memcmp(em_bss->ruid.mac, em->get_radio_interface_mac(), sizeof(bssid_t)) == 0) {
                    printf("%s:%d: Received client cap query: found radio for bss:%s\n", __func__, __LINE__, mac_str1);
                    break;
                }
                em = static_cast<em_t *> (hash_map_get_next(m_em_map, em));
            }
            if(em == NULL){
                dm_easy_mesh_t::macbytes_to_string(bss_mac, mac_str2);
                printf("%s:%d: Received client cap query: Could not find radio:%s of bss:%s\n", __func__, __LINE__, mac_str1, mac_str2);
            }
            break;

        case em_msg_type_client_cap_rprt:
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
            em = (em_t *)hash_map_get_first(m_em_map);
            while (em != NULL) {
                if ((em->is_al_interface_em() == false)) {
                    break;
                }
                em = (em_t *)hash_map_get_next(m_em_map, em);
            }
            break;

		case em_msg_type_channel_scan_rprt:
        case em_msg_type_beacon_metrics_rsp:
        case em_msg_type_ap_mld_config_resp:
        case em_msg_type_beacon_metrics_query:
        case em_msg_type_ap_metrics_rsp:
            break;

        case em_msg_type_proxied_encap_dpp:
        case em_msg_type_direct_encap_dpp:
        case em_msg_type_chirp_notif:
        case em_msg_type_dpp_cce_ind:
            em = al_em;
            break;
        default:
            printf("%s:%d: Frame: %d not handled in agent\n", __func__, __LINE__, htons(cmdu->type));
            em = NULL;
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

bool em_agent_t::try_start_dpp_onboarding()  {
    // Trying to do a cold start, no onboarding at all
    if (!do_start_dpp_onboarding) {
        return false;
    }
    if (m_data_model.get_colocated()){
        printf("%s:%d: Colocated mode is enabled, not starting DPP onboarding\n", __func__, __LINE__);
        return false;
    }

    em_t* al_node = get_al_node();
    ASSERT_NOT_NULL(al_node, false, "%s:%d: al_node is null\n", __func__, __LINE__);

    uint8_t* al_mac = al_node->get_radio_interface_mac();
    ASSERT_NOT_NULL(al_mac, false, "%s:%d: al_mac is null\n", __func__, __LINE__);

    //TODO: Just getting the first op-class info for now since AL is not a Wi-Fi interface
    auto op_chan_data = m_data_model.get_op_class_info(0);
    ASSERT_NOT_NULL(op_chan_data, false, "%s:%d: Could not get current op class/channel from AL radio\n", __func__, __LINE__);

    // Generate new DPP bootstrapping data to ensure correct MAC address is used
    ec_data_t ec_data;
    if (!ec_util::get_dpp_boot_data(&ec_data, al_mac, false, do_regen_dpp_uri, op_chan_data)) {
        printf("%s:%d: Failed to get DPP bootstrapping data\n", __func__, __LINE__);
        return false;
    }
    printf("%s:%d: DPP bootstrapping data generated successfully\n", __func__, __LINE__);

    set_disconnected_steady_state();
    
    if (!al_node->get_ec_mgr().enrollee_start_onboarding(false, &ec_data)){
        printf("%s:%d: DPP onboarding failed to start\n", __func__, __LINE__);
        return false;
    }
    printf("%s:%d: DPP onboarding started successfully\n", __func__, __LINE__);
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
    AlServiceAccessPoint* sap = new AlServiceAccessPoint(DATA_SOCKET_PATH, CONTROL_SOCKET_PATH);

    AlServiceRegistrationRequest registrationRequest(ServiceOperation::SOP_ENABLE, ServiceType::SAP_TUNNEL_CLIENT);
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
        printf("Usage: %s [data-model-path] [--interface=al_mac_iface] [--start-dpp-onboard] [--regen-dpp-uri]\n", argv[0]);
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
        if (arg == "--start-dpp-onboard") {
            g_agent.do_start_dpp_onboarding = true;
            continue;
        }
        if (arg == "--regen-dpp-uri") {
            g_agent.do_regen_dpp_uri = true;
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

