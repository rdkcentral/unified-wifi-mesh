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
#include <strings.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>
#include <signal.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/filter.h>
#include <netinet/ether.h>
#include <netpacket/packet.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <cjson/cJSON.h>
#include "em.h"
#include "em_msg.h"
#include "em_ctrl.h"
#include "em_cmd_ctrl.h"
#include "dm_easy_mesh.h"
#include "em_orch_ctrl.h"
#include "util.h"
#include "wifi_util.h"
#include "em_ext_hooks.h"

#ifdef AL_SAP
#include "al_service_access_point.h"
#endif

em_ctrl_t *em_ctrl_t::s_em_ctrl = NULL;
em_network_topo_t *g_network_topology = NULL;

#ifdef AL_SAP
AlServiceAccessPoint* g_sap;
MacAddress g_al_mac_sap;
#endif

void em_ctrl_t::handle_dm_commit(em_bus_event_t *evt)
{
    em_commit_info_t *info;
    mac_addr_str_t  mac_str;
    dm_easy_mesh_t *dm, new_dm;
    dm_easy_mesh_t *ref_dm;
    dm_network_t *net, *pnet;
    dm_network_ssid_t *net_ssid, *pnet_ssid;

    info = &evt->u.commit;

    dm_easy_mesh_t::macbytes_to_string(info->mac, mac_str);
    dm = m_data_model.get_data_model(info->net_id, info->mac);
    if (dm == NULL) {
        new_dm.init();
        em_printfout("data model mac: %s and info->net_id : %s\n",mac_str, info->net_id);
        memcpy(new_dm.m_device.m_device_info.id.dev_mac, info->mac, sizeof(mac_addr_t));
        memcpy(new_dm.m_device.m_device_info.intf.mac, info->mac, sizeof(mac_addr_t));
        strncpy(new_dm.m_device.m_device_info.id.net_id, info->net_id, strlen(info->net_id) + 1);
        em_printfout("data model dev mac: %s and int.mac: %s\n", util::mac_to_string(new_dm.m_device.m_device_info.id.dev_mac).c_str(),
            util::mac_to_string(new_dm.m_device.m_device_info.intf.mac).c_str());

        if ((net = m_data_model.get_network(info->net_id)) != NULL) {
            em_printfout("net id: %s", net->m_net_info.id);
            pnet = new_dm.get_network();
            *pnet = *net;

            ref_dm = get_data_model(net->m_net_info.id, net->m_net_info.ctrl_id.mac);
            assert(ref_dm != NULL);
            new_dm.set_num_network_ssid(ref_dm->get_num_network_ssid());
            for (unsigned int i = 0; i < ref_dm->get_num_network_ssid(); i++) {
                pnet_ssid = new_dm.get_network_ssid(i);
                net_ssid = ref_dm->get_network_ssid(i);
                *pnet_ssid = *net_ssid;
            }
        }
        em_printfout("data model dev mac: %s and int.mac: %s\n", util::mac_to_string(new_dm.m_device.m_device_info.id.dev_mac).c_str(),
            util::mac_to_string(new_dm.m_device.m_device_info.intf.mac).c_str());
        new_dm.m_device.m_device_info.is_emplus_agent = info->is_emplus_agent;
        new_dm.m_device.set_peer_profile(info->peer_profile);
        new_dm.set_db_cfg_param(db_cfg_type_device_list_update, "");
        m_data_model.set_config(&new_dm);
    } else {
        dm->get_device_info()->is_emplus_agent = info->is_emplus_agent;
        dm->set_db_cfg_param(db_cfg_type_device_list_update, "");
    }
}

// Non-positive analyze_*() result: 0/NO_CHANGE is a no-op, any other negative is an error.
static em_cmd_out_status_t status_for_noncmd(int num)
{
    return (num == 0 || num == EM_PARSE_ERR_NO_CHANGE) ?
        em_cmd_out_status_no_change : em_cmd_out_status_invalid_input;
}

void em_ctrl_t::handle_client_steer(em_bus_event_t *evt)
{
    em_cmd_t *pcmd[EM_MAX_CMD] = {NULL};
    int num;

    if (m_orch->is_cmd_type_in_progress(evt) == true) {
        m_ctrl_cmd->send_result(em_cmd_out_status_prev_cmd_in_progress);
    } else if ((num = m_data_model.analyze_command_steer(evt, pcmd)) <= 0) {
        m_ctrl_cmd->send_result(status_for_noncmd(num));
    } else if (m_orch->submit_commands(pcmd, static_cast<unsigned int> (num)) > 0) {
        m_ctrl_cmd->send_result(em_cmd_out_status_success);
    } else {
        m_ctrl_cmd->send_result(em_cmd_out_status_not_ready);
    }
}

void em_ctrl_t::handle_client_assoc(em_bus_event_t *evt)
{
    em_cmd_t *pcmd[EM_MAX_CMD] = {NULL};
    int num;

    if (m_orch->is_cmd_type_in_progress(evt) == true) {
        m_ctrl_cmd->send_result(em_cmd_out_status_prev_cmd_in_progress);
    } else if ((num = m_data_model.analyze_client_assoc(evt, pcmd)) <= 0) {
        m_ctrl_cmd->send_result(status_for_noncmd(num));
    } else if (m_orch->submit_commands(pcmd, static_cast<unsigned int> (num)) > 0) {
        m_ctrl_cmd->send_result(em_cmd_out_status_success);
    } else {
        m_ctrl_cmd->send_result(em_cmd_out_status_not_ready);
    }
}

void em_ctrl_t::handle_client_disassoc(em_bus_event_t *evt)
{
    em_cmd_t *pcmd[EM_MAX_CMD] = {NULL};
    int num;

    if (m_orch->is_cmd_type_in_progress(evt) == true) {
        m_ctrl_cmd->send_result(em_cmd_out_status_prev_cmd_in_progress);
    } else if ((num = m_data_model.analyze_command_disassoc(evt, pcmd)) <= 0) {
        m_ctrl_cmd->send_result(status_for_noncmd(num));
    } else if (m_orch->submit_commands(pcmd, static_cast<unsigned int> (num)) > 0) {
        m_ctrl_cmd->send_result(em_cmd_out_status_success);
    } else {
        m_ctrl_cmd->send_result(em_cmd_out_status_not_ready);
    }
}

void em_ctrl_t::handle_client_btm(em_bus_event_t *evt)
{
    em_cmd_t *pcmd[EM_MAX_CMD] = {NULL};
    int num;

    if (m_orch->is_cmd_type_in_progress(evt) == true) {
        m_ctrl_cmd->send_result(em_cmd_out_status_prev_cmd_in_progress);
    } else if ((num = m_data_model.analyze_command_btm(evt, pcmd)) <= 0) {
        m_ctrl_cmd->send_result(status_for_noncmd(num));
    } else if (m_orch->submit_commands(pcmd, static_cast<unsigned int> (num)) > 0) {
        m_ctrl_cmd->send_result(em_cmd_out_status_success);
    } else {
        m_ctrl_cmd->send_result(em_cmd_out_status_not_ready);
    }
}

void em_ctrl_t::handle_start_dpp(em_bus_event_t *evt)
{
    em_cmd_t *pcmd[EM_MAX_CMD] = {NULL};
    int num;

    if (m_orch->is_cmd_type_in_progress(evt) == true) {
        m_ctrl_cmd->send_result(em_cmd_out_status_prev_cmd_in_progress);
    } else if ((num = m_data_model.analyze_dpp_start(evt, pcmd)) <= 0) {
        m_ctrl_cmd->send_result(status_for_noncmd(num));
    } else if (m_orch->submit_commands(pcmd, static_cast<unsigned int> (num)) > 0) {
        m_ctrl_cmd->send_result(em_cmd_out_status_success);
    } else {
        m_ctrl_cmd->send_result(em_cmd_out_status_not_ready);
    } 

}

void em_ctrl_t::handle_channel_select(em_bus_event_t *evt)
{
    em_cmd_t *pcmd[EM_MAX_CMD] = {NULL};
    int num;

    if (m_orch->is_cmd_type_in_progress(evt) == true) {
        m_ctrl_cmd->send_result(em_cmd_out_status_prev_cmd_in_progress);
    } else if ((num = m_data_model.analyze_channel_select(evt, pcmd)) <= 0) {
        m_ctrl_cmd->send_result(status_for_noncmd(num));
    } else if (m_orch->submit_commands(pcmd, static_cast<unsigned int> (num)) > 0) {
        m_ctrl_cmd->send_result(em_cmd_out_status_success);
    } else {
        m_ctrl_cmd->send_result(em_cmd_out_status_not_ready);
    }
}

void em_ctrl_t::handle_set_channel_list(em_bus_event_t *evt)
{
    em_cmd_t *pcmd[EM_MAX_CMD] = {NULL};
    int num;

    if (m_orch->is_cmd_type_in_progress(evt) == true) {
        m_ctrl_cmd->send_result(em_cmd_out_status_prev_cmd_in_progress);
    } else if ((num = m_data_model.analyze_set_channel(evt, pcmd)) <= 0) {
        m_ctrl_cmd->send_result(status_for_noncmd(num));
    } else if (m_orch->submit_commands(pcmd, static_cast<unsigned int> (num)) > 0) {
        m_ctrl_cmd->send_result(em_cmd_out_status_success);
    } else {
        m_ctrl_cmd->send_result(em_cmd_out_status_not_ready);
    } 

}

void em_ctrl_t::handle_scan_channel_list(em_bus_event_t *evt)
{
    em_cmd_t *pcmd[EM_MAX_CMD] = {NULL};
    int num;

    if (m_orch->is_cmd_type_in_progress(evt) == true) {
        m_ctrl_cmd->send_result(em_cmd_out_status_prev_cmd_in_progress);
    } else if ((num = m_data_model.analyze_scan_channel(evt, pcmd)) <= 0) {
        m_ctrl_cmd->send_result(status_for_noncmd(num));
    } else if (m_orch->submit_commands(pcmd, static_cast<unsigned int> (num)) > 0) {
        m_ctrl_cmd->send_result(em_cmd_out_status_success);
    } else {
        m_ctrl_cmd->send_result(em_cmd_out_status_not_ready);
    } 

}

void em_ctrl_t::handle_set_policy(em_bus_event_t *evt)
{
    em_cmd_t *pcmd[EM_MAX_CMD] = {NULL};
    int num;

    if (m_orch->is_cmd_type_in_progress(evt) == true) {
        m_ctrl_cmd->send_result(em_cmd_out_status_prev_cmd_in_progress);
    } else if ((num = m_data_model.analyze_set_policy(evt, pcmd)) <= 0) {
        m_ctrl_cmd->send_result(status_for_noncmd(num));
    } else if (m_orch->submit_commands(pcmd, static_cast<unsigned int> (num)) > 0) {
        m_ctrl_cmd->send_result(em_cmd_out_status_success);
    } else {
        m_ctrl_cmd->send_result(em_cmd_out_status_not_ready);
    }
}

void em_ctrl_t::handle_config_renew(em_bus_event_t *evt)
{
    em_cmd_t *pcmd[EM_MAX_CMD] = {NULL};
    int num;
    
    if ((num = m_data_model.analyze_config_renew(evt, pcmd)) > 0) {
        m_orch->submit_commands(pcmd, static_cast<unsigned int> (num));
    }
}

void em_ctrl_t::handle_m2_tx(em_bus_event_t *evt)
{
    em_cmd_t *pcmd[EM_MAX_CMD] = {NULL};
    int num;
    
    if ((num = m_data_model.analyze_m2_tx(evt, pcmd)) > 0) {
        m_orch->submit_commands(pcmd, static_cast<unsigned int> (num));
    }
}

void em_ctrl_t::handle_sta_assoc_event(em_bus_event_t *evt)
{
    em_cmd_t *pcmd[EM_MAX_CMD] = {NULL};
    int num;
    em_bus_event_type_client_assoc_params_t *params;

    params = reinterpret_cast<em_bus_event_type_client_assoc_params_t *> (evt->u.raw_buff);
    record_client_disassoc(params->dev, &params->assoc);

    if ((num = m_data_model.analyze_sta_assoc_event(evt, pcmd)) > 0) {
        m_orch->submit_commands(pcmd, static_cast<unsigned int> (num));
    }
}

void em_ctrl_t::handle_set_radio(em_bus_event_t *evt)
{
    em_cmd_t *pcmd[EM_MAX_CMD] = {NULL};
    int num;

    if (m_orch->is_cmd_type_in_progress(evt) == true) {
        m_ctrl_cmd->send_result(em_cmd_out_status_prev_cmd_in_progress);
    } else if ((num = m_data_model.analyze_set_radio(evt, pcmd)) <= 0) {
        m_ctrl_cmd->send_result(status_for_noncmd(num));
    } else if (m_orch->submit_commands(pcmd, static_cast<unsigned int> (num)) > 0) {
        m_ctrl_cmd->send_result(em_cmd_out_status_success);
    } else {
        m_ctrl_cmd->send_result(em_cmd_out_status_not_ready);
    } 
}

void em_ctrl_t::handle_set_ssid_list(em_bus_event_t *evt)
{
    em_cmd_t *pcmd[EM_MAX_CMD] = {NULL};
    int num, ret;

    if (m_orch->is_cmd_type_in_progress(evt) == true) {
        m_ctrl_cmd->send_result(em_cmd_out_status_prev_cmd_in_progress);
    } else if ((ret = m_data_model.analyze_set_ssid(evt, pcmd)) <= 0) {
        if (ret == EM_PARSE_ERR_NO_CHANGE) {
        	m_ctrl_cmd->send_result(em_cmd_out_status_no_change);
		} else {
        	m_ctrl_cmd->send_result(em_cmd_out_status_invalid_input);
		}
    } else if (m_orch->submit_commands(pcmd, static_cast<unsigned int> (num = ret)) > 0) {
        m_ctrl_cmd->send_result(em_cmd_out_status_success);
    } else {
        m_ctrl_cmd->send_result(em_cmd_out_status_not_ready);
    } 

}

void em_ctrl_t::handle_remove_device(em_bus_event_t *evt)
{
    em_cmd_t *pcmd[EM_MAX_CMD] = {NULL};
    int num;

    if (m_orch->is_cmd_type_in_progress(evt) == true) {
        m_ctrl_cmd->send_result(em_cmd_out_status_prev_cmd_in_progress);
    } else if ((num = m_data_model.analyze_remove_device(evt, pcmd)) <= 0) {
        m_ctrl_cmd->send_result(status_for_noncmd(num));
    } else if (m_orch->submit_commands(pcmd, static_cast<unsigned int> (num)) > 0) {
        m_ctrl_cmd->send_result(em_cmd_out_status_success);
    } else {
        m_ctrl_cmd->send_result(em_cmd_out_status_not_ready);
    } 

}

void em_ctrl_t::handle_get_dev_test(em_bus_event_t *evt)
{
    em_cmd_params_t params = evt->params;
    char *temp = NULL;
    bool teststatus = false;

    if (params.u.args.num_args < 1) {
        m_ctrl_cmd->send_result(em_cmd_out_status_invalid_input);
        return;
    }

    if (m_orch->is_cmd_type_in_progress(evt) == true) {
    }

    if ((temp = strstr(evt->u.subdoc.name, "update")) != NULL) {
	dev_test.encode(&evt->u.subdoc, m_em_map, true, false);
    } else {
	   
           teststatus = m_orch->get_dev_test_status();
	   dev_test.encode(&evt->u.subdoc, m_em_map, false, teststatus);
    }
    evt->data_len = static_cast<unsigned int> (strlen(evt->u.subdoc.buff)) + 1;
    m_ctrl_cmd->copy_bus_event(evt);
    m_ctrl_cmd->send_result(em_cmd_out_status_success);
}

void em_ctrl_t::handle_set_dev_test(em_bus_event_t *evt)
{

    if (m_orch->is_cmd_type_in_progress(evt) == true) {
        m_ctrl_cmd->send_result(em_cmd_out_status_prev_cmd_in_progress);
    } else {
	dev_test.analyze_set_dev_test(evt, m_em_map);
        m_ctrl_cmd->send_result(em_cmd_out_status_success);
    }

}

void em_ctrl_t::handle_get_dm_data(em_bus_event_t *evt)
{           
    em_cmd_params_t params = evt->params;
        
    //em_cmd_t::dump_bus_event(evt);
    if (params.u.args.num_args < 1) {
        m_ctrl_cmd->send_result(em_cmd_out_status_invalid_input);
        return;
    }

    m_data_model.get_config(params.u.args.args[1], &evt->u.subdoc);
	evt->data_len = static_cast<unsigned int> (strlen(evt->u.subdoc.buff)) + 1;
    m_ctrl_cmd->copy_bus_event(evt);
    m_ctrl_cmd->send_result(em_cmd_out_status_success);
}        

void em_ctrl_t::handle_reset(em_bus_event_t *evt)
{
    em_cmd_t *pcmd[EM_MAX_CMD] = {NULL};
    int num = 0;
	
    if (m_orch->is_cmd_type_in_progress(evt) == true) {
        m_ctrl_cmd->send_result(em_cmd_out_status_prev_cmd_in_progress);
    } else if ((num = m_data_model.analyze_reset(evt, pcmd)) <= 0) {
        m_ctrl_cmd->send_result(status_for_noncmd(num));
    } else if (m_orch->submit_commands(pcmd, static_cast<unsigned int> (num)) > 0) {
        m_ctrl_cmd->send_result(em_cmd_out_status_success);
    } else {
        m_ctrl_cmd->send_result(em_cmd_out_status_not_ready);
    }

}

void em_ctrl_t::handle_mld_reconfig(em_bus_event_t *evt)
{
    em_cmd_t *pcmd[EM_MAX_CMD] = {NULL};
    int num;

    if (m_orch->is_cmd_type_in_progress(evt) == true) {
        m_ctrl_cmd->send_result(em_cmd_out_status_prev_cmd_in_progress);
    } else if ((num = m_data_model.analyze_mld_reconfig(pcmd)) <= 0) {
        m_ctrl_cmd->send_result(status_for_noncmd(num));
    } else if (m_orch->submit_commands(pcmd, static_cast<unsigned int> (num)) > 0) {
        m_ctrl_cmd->send_result(em_cmd_out_status_success);
    } else {
        m_ctrl_cmd->send_result(em_cmd_out_status_not_ready);
    }
}

void em_ctrl_t::handle_radio_metrics_req()
{

}

void em_ctrl_t::handle_ap_metrics_req()
{

}

void em_ctrl_t::handle_unassoc_sta_metrics_query(em_bus_event_t *evt)
{
    em_cmd_t *pcmd[EM_MAX_CMD] = {NULL};
    int num;

    if (m_orch->is_cmd_type_in_progress(evt) == true) {
        m_ctrl_cmd->send_result(em_cmd_out_status_prev_cmd_in_progress);
    } else if ((num = m_data_model.analyze_unassoc_sta_metrics_query(evt, pcmd)) <= 0) {
        m_ctrl_cmd->send_result(status_for_noncmd(num));
    } else if (m_orch->submit_commands(pcmd, static_cast<unsigned int> (num)) > 0) {
        m_ctrl_cmd->send_result(em_cmd_out_status_success);
    } else {
        m_ctrl_cmd->send_result(em_cmd_out_status_not_ready);
    }
}

void em_ctrl_t::handle_client_metrics_req()
{
    em_cmd_t *pcmd[EM_MAX_CMD] = {NULL};
    int num;

    if ((num = m_data_model.analyze_sta_link_metrics(pcmd)) > 0) {
        m_orch->submit_commands(pcmd, static_cast<unsigned int> (num));
    }
}

void em_ctrl_t::handle_bsta_cap_req(em_bus_event_t *evt)
{
    em_cmd_t *pcmd[EM_MAX_CMD] = {NULL};
    int num;

    if ((num = m_data_model.analyze_bsta_cap_req(evt, pcmd)) > 0) {
        m_orch->submit_commands(pcmd, static_cast<unsigned int> (num));
    }
}

void em_ctrl_t::handle_link_stats_alarm_report(em_bus_event_t *evt)
{
    em_subdoc_info_t *info = &evt->u.subdoc;
    wifi_bus_desc_t *desc = NULL;
    char *str = NULL;
    raw_data_t raw;

    snprintf(info->name, sizeof(info->name), "alarm_report");

    cJSON *parent = cJSON_CreateObject();
    em_printfout("Getting STAList for alarm report\n");
    m_data_model.get_sta_config(parent, const_cast<char*>(GLOBAL_NET_ID), em_get_sta_list_reason_alarm_report, info->buff);

    //publish to orch
    if((desc = get_bus_descriptor()) == NULL) {
        em_printfout("descriptor is null");
        cJSON_Delete(parent);
        return;
    }

    if (parent == NULL) {
        em_printfout("Failed to create or populate JSON object");
        return;
    }

    str = cJSON_Print(parent);
    em_printfout("Publishing Link Report Json:\n%s",str);

	raw.data_type    = bus_data_type_string;
    raw.raw_data.bytes = reinterpret_cast<unsigned char *> (str);
    raw.raw_data_len = static_cast<unsigned int> (strlen(str));

    if (desc->bus_event_publish_fn(m_data_model.get_bus_hdl(), DEVICE_WIFI_DATAELEMENTS_NETWORK_NODE_LINKSTATS_ALARM, &raw)== 0) {
        em_printfout("Link Stats Alarm published successfull");
    } else {
        em_printfout("Link Stats Alarm publish fail");
    }

    cJSON_free(str);
    cJSON_Delete(parent);
}

/* DisassociationEvent InitiatedBy from the 802.11 reason code. The message does not
 * say which side sent the frame; only the reasons defined for one side are attributed. */
static const char *disassoc_initiated_by(unsigned short reason_code)
{
    switch (reason_code) {
    case 3: /* deauthenticated because sending STA is leaving */
    case 8: /* disassociated because sending STA is leaving BSS */
        return "STA";
    case 4: /* disassociated due to inactivity */
    case 5: /* AP is unable to handle all currently associated STAs */
    case 6: /* class 2 frame received from nonauthenticated STA */
    case 7: /* class 3 frame received from nonassociated STA */
        return "EasyMesh_Agent";
    default:
        return "Unknown";
    }
}

/* Row of a STA on a radio. An MLD client is stored under each affiliated BSSID, so the key
 * built from the AP MLD BSSID of the notification does not match its rows. */
static dm_sta_t *find_sta_row_on_radio(hash_map_t *map, const mac_address_t sta_mac, const mac_address_t radiomac)
{
    dm_sta_t *sta = static_cast<dm_sta_t *>(hash_map_get_first(map));

    while (sta != NULL) {
        if ((memcmp(sta->m_sta_info.id, sta_mac, sizeof(mac_address_t)) == 0) &&
            (memcmp(sta->m_sta_info.radiomac, radiomac, sizeof(mac_address_t)) == 0)) {
            return sta;
        }
        sta = static_cast<dm_sta_t *>(hash_map_get_next(map, sta));
    }

    return NULL;
}

/* Publishes the event and releases the argument list: bus_data_free_fn releases the appended
 * nodes and the values, the head node is ours to free. */
static bool event_publish(wifi_bus_desc_t *desc, bus_handle_t *hdl, const char *event, bus_data_prop_t *args)
{
    raw_data_t raw;
    bool ok;

    memset(&raw, 0, sizeof(raw));
    raw.data_type = bus_data_type_property;
    raw.raw_data.bytes = args;

    ok = (desc->bus_event_publish_fn(hdl, event, &raw) == 0);
    desc->bus_data_free_fn(&raw);
    free(args);
    return ok;
}

void em_ctrl_t::handle_failed_conn_msg(unsigned char *data, unsigned int len)
{
    char *errors[EM_MAX_TLV_MEMBERS] = {0};

    if (em_msg_t(em_msg_type_failed_conn, em_profile_type_3, data, len).validate(errors) == 0) {
        em_printfout("Failed Connection message validation failed");
        return;
    }

    unsigned int hdr_size = static_cast<unsigned int>(sizeof(em_raw_hdr_t)) + static_cast<unsigned int>(sizeof(em_cmdu_t));
    if (len <= hdr_size) {
        em_printfout("Failed Connection message too short");
        return;
    }
    unsigned char *tmp = data + hdr_size;
    unsigned int remaining = len - hdr_size;
    mac_address_t bssid = {0};
    mac_address_t sta_mac = {0};
    unsigned short status_code = 0;
    unsigned short reason_code = 0;
    bool has_bssid = false, has_sta = false, has_status = false;

    while (remaining >= sizeof(em_tlv_t)) {
        em_tlv_t *tlv = reinterpret_cast<em_tlv_t *>(tmp);
        unsigned short tlv_len = ntohs(tlv->len);

        if (tlv->type == em_tlv_type_eom) {
            break;
        }
        if (remaining < sizeof(em_tlv_t) + tlv_len) {
            break;
        }

        switch (tlv->type) {
            case em_tlv_type_bssid:
                memcpy(bssid, tlv->value, sizeof(mac_address_t));
                has_bssid = true;
                break;
            case em_tlv_type_sta_mac_addr:
                memcpy(sta_mac, tlv->value, sizeof(mac_address_t));
                has_sta = true;
                break;
            case em_tlv_type_status_code: {
                em_status_code_t *sc = reinterpret_cast<em_status_code_t *>(tlv->value);
                status_code = ntohs(sc->status_code);
                has_status = true;
                break;
            }
            case em_tlv_type_reason_code: {
                if (tlv_len < sizeof(em_reason_code_t)) {
                    em_printfout("Failed Connection message malformed Reason Code TLV (len=%u)", static_cast<unsigned int>(tlv_len));
                    break;
                }
                em_reason_code_t *rc = reinterpret_cast<em_reason_code_t *>(tlv->value);
                reason_code = ntohs(rc->reason_code);
                break;
            }
            default:
                break;
        }

        tmp += sizeof(em_tlv_t) + tlv_len;
        remaining -= static_cast<unsigned int>(sizeof(em_tlv_t)) + tlv_len;
    }

    if (!has_bssid || !has_sta || !has_status) {
        em_printfout("Failed Connection message missing mandatory TLVs");
        return;
    }

    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    struct tm tm_info;
    gmtime_r(&ts.tv_sec, &tm_info);
    char timestamp[MAX_TIMESTAMP_STRLEN];
    snprintf(timestamp, sizeof(timestamp), "%04d-%02d-%02dT%02d:%02d:%02dZ",
        tm_info.tm_year + 1900, tm_info.tm_mon + 1, tm_info.tm_mday,
        tm_info.tm_hour, tm_info.tm_min, tm_info.tm_sec);

    mac_addr_str_t bssid_str, sta_str;
    dm_easy_mesh_t::macbytes_to_string(bssid, bssid_str);
    dm_easy_mesh_t::macbytes_to_string(sta_mac, sta_str);

    wifi_bus_desc_t *desc = get_bus_descriptor();
    if (desc == NULL) {
        em_printfout("Bus descriptor is null");
        return;
    }

    bus_data_prop_t *args = NULL;
    tr_181_t::tr181_append_string_prop(&args, "BSSID", bssid_str);
    tr_181_t::tr181_append_string_prop(&args, "MACAddress", sta_str);
    tr_181_t::tr181_append_uint32_prop(&args, "StatusCode", status_code);
    tr_181_t::tr181_append_uint32_prop(&args, "ReasonCode", reason_code);
    tr_181_t::tr181_append_string_prop(&args, "TimeStamp", timestamp);

    if (event_publish(desc, m_data_model.get_bus_hdl(), DEVICE_WIFI_DATAELEMENTS_FAILED_CONNECTION, args)) {
        em_printfout("FailedConnectionEvent published: bssid=%s sta=%s status=%u reason=%u",
            bssid_str, sta_str, status_code, reason_code);
    } else {
        em_printfout("FailedConnectionEvent publish failed");
    }
}

void em_ctrl_t::record_client_disassoc(const mac_address_t dev, const em_client_assoc_event_t *assoc)
{
    std::string key = util::mac_to_string(dev) + "@" + util::mac_to_string(assoc->cli_mac_address);
    em_recent_disassoc_t rec;

    std::lock_guard<std::mutex> lock(m_recent_disassoc_lock);
    if (assoc->assoc_event) {
        m_recent_disassoc.erase(key);
        return;
    }

    memset(&rec, 0, sizeof(rec));
    memcpy(rec.bssid, assoc->bssid, sizeof(bssid_t));
    util::monotonic_now(&rec.ts);
    for (auto it = m_recent_disassoc.begin(); it != m_recent_disassoc.end(); ) {
        if (rec.ts.tv_sec - it->second.ts.tv_sec > EM_RECENT_DISASSOC_MAX_AGE_SEC) {
            it = m_recent_disassoc.erase(it);
        } else {
            ++it;
        }
    }
    m_recent_disassoc[key] = rec;
}

bool em_ctrl_t::resolve_client_disassoc(dm_easy_mesh_t *dm, mac_address_t sta_mac, bssid_t bssid, mac_address_t radiomac)
{
    std::string key = util::mac_to_string(dm->get_agent_al_interface_mac()) + "@" + util::mac_to_string(sta_mac);
    struct timespec now;
    bool recorded = false;

    {
        std::lock_guard<std::mutex> lock(m_recent_disassoc_lock);
        auto it = m_recent_disassoc.find(key);
        if (it != m_recent_disassoc.end()) {
            util::monotonic_now(&now);
            if (now.tv_sec - it->second.ts.tv_sec <= EM_RECENT_DISASSOC_MAX_AGE_SEC) {
                memcpy(bssid, it->second.bssid, sizeof(bssid_t));
                recorded = true;
            }
            m_recent_disassoc.erase(it);
        }
    }

    if (recorded) {
        for (unsigned int i = 0; i < dm->get_num_radios(); i++) {
            dm_bss_t *bss = dm->get_bss(dm->get_radio_info(i)->id.ruid, bssid);
            if (bss != NULL) {
                memcpy(radiomac, bss->m_bss_info.ruid.mac, sizeof(mac_address_t));
                return true;
            }
        }
        if (dm->resolve_ap_mld_to_fallback_ruid(bssid, radiomac)) {
            return true;
        }
        em_printfout("Disassociation of sta=%s: no radio for bssid=%s", util::mac_to_string(sta_mac).c_str(),
            util::mac_to_string(bssid).c_str());
        return false;
    }

    for (dm_sta_t *sta = dm->get_first_sta(sta_mac); sta != NULL; sta = dm->get_next_sta(sta_mac, sta)) {
        if (sta->m_sta_info.associated) {
            memcpy(bssid, sta->m_sta_info.bssid, sizeof(bssid_t));
            memcpy(radiomac, sta->m_sta_info.radiomac, sizeof(mac_address_t));
            return true;
        }
    }

    return false;
}

void em_ctrl_t::handle_client_disassoc_stats_msg(unsigned char *data, unsigned int len)
{
    char *errors[EM_MAX_TLV_MEMBERS] = {0};

    if (em_msg_t(em_msg_type_client_disassoc_stats, em_profile_type_3, data, len).validate(errors) == 0) {
        em_printfout("Client Disassociation Stats message validation failed");
        return;
    }

    unsigned int hdr_size = static_cast<unsigned int>(sizeof(em_raw_hdr_t)) + static_cast<unsigned int>(sizeof(em_cmdu_t));
    if (len <= hdr_size) {
        em_printfout("Client Disassociation Stats message too short");
        return;
    }
    em_raw_hdr_t *hdr = reinterpret_cast<em_raw_hdr_t *>(data);
    unsigned char *tmp = data + hdr_size;
    unsigned int remaining = len - hdr_size;
    mac_address_t sta_mac = {0};
    unsigned short reason_code = 0;
    em_assoc_sta_traffic_sts_t stats;
    bool has_sta = false, has_reason = false, has_stats = false;

    memset(&stats, 0, sizeof(stats));

    while (remaining >= sizeof(em_tlv_t)) {
        em_tlv_t *tlv = reinterpret_cast<em_tlv_t *>(tmp);
        unsigned short tlv_len = ntohs(tlv->len);

        if (tlv->type == em_tlv_type_eom) {
            break;
        }
        if (remaining < sizeof(em_tlv_t) + tlv_len) {
            break;
        }

        switch (tlv->type) {
            case em_tlv_type_sta_mac_addr:
                if (tlv_len >= sizeof(mac_address_t)) {
                    memcpy(sta_mac, tlv->value, sizeof(mac_address_t));
                    has_sta = true;
                }
                break;
            case em_tlv_type_reason_code: {
                if (tlv_len < sizeof(em_reason_code_t)) {
                    em_printfout("Client Disassociation Stats malformed Reason Code TLV (len=%u)", static_cast<unsigned int>(tlv_len));
                    break;
                }
                em_reason_code_t *rc = reinterpret_cast<em_reason_code_t *>(tlv->value);
                reason_code = ntohs(rc->reason_code);
                has_reason = true;
                break;
            }
            case em_tlv_type_assoc_sta_traffic_sts:
                if (tlv_len >= sizeof(em_assoc_sta_traffic_sts_t)) {
                    memcpy(&stats, tlv->value, sizeof(stats));
                    has_stats = true;
                }
                break;
            default:
                break;
        }

        tmp += sizeof(em_tlv_t) + tlv_len;
        remaining -= static_cast<unsigned int>(sizeof(em_tlv_t)) + tlv_len;
    }

    if (!has_sta || !has_reason || !has_stats) {
        em_printfout("Client Disassociation Stats message missing mandatory TLVs");
        return;
    }
    if (memcmp(stats.sta_mac_addr, sta_mac, sizeof(mac_address_t)) != 0) {
        em_printfout("Client Disassociation Stats message: STA MAC Address TLV and Associated STA Traffic Stats TLV disagree");
        return;
    }

    /* The data model is updated on the controller thread, like the Topology Notification. */
    em_bus_event_type_client_disassoc_stats_params_t params;
    memset(&params, 0, sizeof(params));
    memcpy(params.dev, hdr->src, sizeof(mac_address_t));
    memcpy(params.stats.sta_mac, sta_mac, sizeof(mac_address_t));
    params.stats.reason_code = reason_code;
    params.stats.bytes_sent = ntohl(stats.bytes_sent);
    params.stats.bytes_recv = ntohl(stats.bytes_recv);
    params.stats.packets_sent = ntohl(stats.packets_sent);
    params.stats.packets_recv = ntohl(stats.packets_recv);
    params.stats.tx_packets_errors = ntohl(stats.tx_packets_errors);
    params.stats.rx_packets_errors = ntohl(stats.rx_packets_errors);
    params.stats.retrans_count = ntohl(stats.retrans_count);
    io_process(em_bus_event_type_client_disassoc_stats, reinterpret_cast<unsigned char *> (&params), sizeof(params));
}

void em_ctrl_t::handle_client_disassoc_stats_event(em_bus_event_t *evt)
{
    em_bus_event_type_client_disassoc_stats_params_t *params =
        reinterpret_cast<em_bus_event_type_client_disassoc_stats_params_t *> (evt->u.raw_buff);
    em_client_disassoc_stats_evt_data_t *stats = &params->stats;
    unsigned short reason_code = stats->reason_code;
    mac_addr_str_t sta_str;
    dm_easy_mesh_t::macbytes_to_string(stats->sta_mac, sta_str);

    dm_easy_mesh_t *dm = get_data_model(GLOBAL_NET_ID, params->dev);
    if (dm == NULL) {
        em_printfout("Client Disassociation Stats: no data model for agent %s", util::mac_to_string(params->dev).c_str());
        return;
    }
    bssid_t bssid;
    mac_address_t radiomac;
    if (!resolve_client_disassoc(dm, stats->sta_mac, bssid, radiomac)) {
        em_printfout("Client Disassociation Stats: no BSS known for sta=%s, DisassociationEvent not published", sta_str);
        return;
    }

    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    struct tm tm_info;
    gmtime_r(&ts.tv_sec, &tm_info);
    char timestamp[MAX_TIMESTAMP_STRLEN];
    snprintf(timestamp, sizeof(timestamp), "%04d-%02d-%02dT%02d:%02d:%02dZ",
        tm_info.tm_year + 1900, tm_info.tm_mon + 1, tm_info.tm_mday,
        tm_info.tm_hour, tm_info.tm_min, tm_info.tm_sec);

    mac_addr_str_t bssid_str;
    dm_easy_mesh_t::macbytes_to_string(bssid, bssid_str);

    /* Mark the station disassociated now, the Topology Notification arrives seconds later. */
    mac_addr_str_t radio_str;
    em_long_string_t sta_key;
    dm_sta_t *assoc_row;
    dm_sta_t *sta_row;

    dm_easy_mesh_t::macbytes_to_string(radiomac, radio_str);
    snprintf(sta_key, sizeof(em_long_string_t), "%s@%s@%s", sta_str, bssid_str, radio_str);

    assoc_row = static_cast<dm_sta_t *>(hash_map_get(dm->m_sta_assoc_map, sta_key));
    if (assoc_row == NULL) {
        assoc_row = find_sta_row_on_radio(dm->m_sta_assoc_map, stats->sta_mac, radiomac);
    }
    if (assoc_row != NULL) {
        assoc_row->m_sta_info.associated = false;
        assoc_row->m_sta_info.frame_body_len = 0;
        memset(assoc_row->m_sta_info.frame_body, 0, sizeof(assoc_row->m_sta_info.frame_body));
    }

    sta_row = static_cast<dm_sta_t *>(hash_map_get(dm->m_sta_map, sta_key));
    if (sta_row == NULL) {
        sta_row = find_sta_row_on_radio(dm->m_sta_map, stats->sta_mac, radiomac);
    }
    if (sta_row != NULL) {
        sta_row->m_sta_info.associated = false;
        sta_row->m_sta_info.frame_body_len = 0;
        memset(sta_row->m_sta_info.frame_body, 0, sizeof(sta_row->m_sta_info.frame_body));
    }
    if ((assoc_row != NULL) || (sta_row != NULL)) {
        /* update_tables() writes m_sta_assoc_map to the DB and drops the rows it wrote */
        dm->set_db_cfg_param(db_cfg_type_sta_list_update, "");
        em_printfout("Client Disassociation Stats: marked sta=%s disassociated, key=%s", sta_str, sta_key);
    }

    /* The last metrics of the station, the radio noise and its operating channel, as the
     * data model reported them before the station left. */
    em_sta_info_t *last = (sta_row != NULL) ? &sta_row->m_sta_info :
                          (assoc_row != NULL) ? &assoc_row->m_sta_info : NULL;
    dm_radio_t *radio = dm->get_radio(radiomac);
    unsigned int op_class = 0, channel = 0;
    for (unsigned int i = 0; i < dm->get_num_op_class(); i++) {
        em_op_class_info_t *oc = dm->get_op_class_info(i);
        if ((oc->id.type == em_op_class_type_current) &&
            (memcmp(oc->id.ruid, radiomac, sizeof(mac_address_t)) == 0)) {
            op_class = oc->op_class;
            channel = oc->channel;
            break;
        }
    }

    wifi_bus_desc_t *desc = get_bus_descriptor();
    if (desc == NULL) {
        em_printfout("Bus descriptor is null");
        return;
    }

    bus_data_prop_t *args = NULL;
    tr_181_t::tr181_append_string_prop(&args, "BSSID", bssid_str);
    tr_181_t::tr181_append_string_prop(&args, "MACAddress", sta_str);
    tr_181_t::tr181_append_uint32_prop(&args, "ReasonCode", reason_code);
    tr_181_t::tr181_append_uint64_prop(&args, "BytesSent", stats->bytes_sent);
    tr_181_t::tr181_append_uint64_prop(&args, "BytesReceived", stats->bytes_recv);
    tr_181_t::tr181_append_uint64_prop(&args, "PacketsSent", stats->packets_sent);
    tr_181_t::tr181_append_uint64_prop(&args, "PacketsReceived", stats->packets_recv);
    tr_181_t::tr181_append_uint32_prop(&args, "ErrorsSent", stats->tx_packets_errors);
    tr_181_t::tr181_append_uint32_prop(&args, "ErrorsReceived", stats->rx_packets_errors);
    tr_181_t::tr181_append_uint32_prop(&args, "RetransCount", stats->retrans_count);
    tr_181_t::tr181_append_string_prop(&args, "TimeStamp", timestamp);
    tr_181_t::tr181_append_uint32_prop(&args, "LastDataDownlinkRate", last ? last->last_dl_rate : 0);
    tr_181_t::tr181_append_uint32_prop(&args, "LastDataUplinkRate", last ? last->last_ul_rate : 0);
    tr_181_t::tr181_append_uint64_prop(&args, "UtilizationReceive", last ? last->util_rx : 0);
    tr_181_t::tr181_append_uint64_prop(&args, "UtilizationTransmit", last ? last->util_tx : 0);
    tr_181_t::tr181_append_uint32_prop(&args, "EstMACDataRateDownlink", last ? last->est_dl_rate : 0);
    tr_181_t::tr181_append_uint32_prop(&args, "EstMACDataRateUplink", last ? last->est_ul_rate : 0);
    tr_181_t::tr181_append_uint32_prop(&args, "SignalStrength", last ? last->rcpi : 0);
    tr_181_t::tr181_append_uint32_prop(&args, "LastConnectTime", last ? last->last_conn_time : 0);
    tr_181_t::tr181_append_uint32_prop(&args, "Noise", radio ? static_cast<uint32_t>(radio->get_radio_info()->noise) : 0);
    tr_181_t::tr181_append_string_prop(&args, "InitiatedBy", disassoc_initiated_by(reason_code));
    tr_181_t::tr181_append_uint32_prop(&args, "OpClass", op_class);
    tr_181_t::tr181_append_uint32_prop(&args, "Channel", channel);

    if (event_publish(desc, m_data_model.get_bus_hdl(), DEVICE_WIFI_DATAELEMENTS_DISASSOCIATION, args)) {
        em_printfout("DisassociationEvent published: bssid=%s sta=%s reason=%u", bssid_str, sta_str, reason_code);
    } else {
        em_printfout("DisassociationEvent publish failed");
    }
}


void em_ctrl_t::handle_beacon_metrics_query(em_bus_event_t *evt)
{
    em_cmd_t *pcmd[EM_MAX_CMD] = {NULL};
    int num;

    if (m_orch->is_cmd_type_in_progress(evt) == true) {
        m_ctrl_cmd->send_result(em_cmd_out_status_prev_cmd_in_progress);
    } else if ((num = m_data_model.analyze_beacon_metrics_query(evt, pcmd)) <= 0) {
        m_ctrl_cmd->send_result(status_for_noncmd(num));
    } else if (m_orch->submit_commands(pcmd, static_cast<unsigned int> (num)) > 0) {
        m_ctrl_cmd->send_result(em_cmd_out_status_success);
    } else {
        m_ctrl_cmd->send_result(em_cmd_out_status_not_ready);
    }
}

void em_ctrl_t::handle_dirty_dm()
{
	m_data_model.handle_dirty_dm();
}

void em_ctrl_t::handle_5s_tick()
{
	//handle_client_metrics_req();
}

void em_ctrl_t::handle_2s_tick()
{

}

void em_ctrl_t::handle_1s_tick()
{

}

void em_ctrl_t::handle_250ms_tick()
{
    handle_dirty_dm();
    m_orch->handle_timeout();
}

void em_ctrl_t::input_listener()
{
    em_long_string_t str;

    // the listener must block on inputs (rbus or pipe or other ipc messages)
    io(str, false);
}

void em_ctrl_t::handle_nb_event(em_nb_event_t *evt)
{
    bus_resp_get_t *resp = static_cast<bus_resp_get_t *> (calloc(1, sizeof(*resp)));
    assert(resp != NULL);
    resp->id = evt->id;

    switch (evt->type) {
        case NB_REQTYPE_GET:
        case NB_REQTYPE_SET: {
            char *name = evt->u.get.name;
            raw_data_t *property = static_cast<raw_data_t *> (evt->u.get.property);
            bus_get_handler_t cb = reinterpret_cast<bus_get_handler_t>(evt->cb);
            /* TODO: sending property only for now */
            resp->rc = cb(name, property, NULL);
        } break;
#if 0
        case NB_REQTYPE_METHOD: {
            const char *method = evt->u.method.method;
            rbusObject_t in = static_cast<rbusObject_t> (evt->u.method.in);
            rbusObject_t out = static_cast<rbusObject_t> (evt->u.method.out);
            rbusMethodAsyncHandle_t async = static_cast<rbusMethodAsyncHandle_t> (evt->u.method.async);
            rbusMethodHandler_t cb = (rbusMethodHandler_t) evt->cb;
            resp->rc = cb(NULL, method, in, out, async);
        } break;
#endif
        default:
            break;
    }

    uintptr_t buf = reinterpret_cast<uintptr_t>(resp);
    ssize_t len = write(m_data_model.m_nb_pipe_wr, &buf, sizeof(buf));
    assert(len == sizeof(buf));
}

void em_ctrl_t::handle_bus_event(em_bus_event_t *evt)
{
    switch (evt->type) {
        case em_bus_event_type_reset:
            handle_reset(evt);
            break;

        case em_bus_event_type_dev_test:
	    handle_get_dev_test(evt);
	    break;

	case em_bus_event_type_set_dev_test:
	    handle_set_dev_test(evt);
	    break;

        case em_bus_event_type_get_network:
        case em_bus_event_type_get_ssid:
        case em_bus_event_type_get_channel:
        case em_bus_event_type_get_device:
        case em_bus_event_type_get_radio:
        case em_bus_event_type_get_bss:
        case em_bus_event_type_get_sta:
        case em_bus_event_type_get_policy:
        case em_bus_event_type_scan_result:
        case em_bus_event_type_get_mld_config:
        case em_bus_event_type_get_reset:
            handle_get_dm_data(evt);
            break;

        case em_bus_event_type_set_radio:
            handle_set_radio(evt);  
            break;

        case em_bus_event_type_set_ssid:
            handle_set_ssid_list(evt);  
            break;

        case em_bus_event_type_remove_device:
            handle_remove_device(evt);
            break;
        
        case em_bus_event_type_set_channel:
            handle_set_channel_list(evt);
            break;

        case em_bus_event_type_channel_select:
            handle_channel_select(evt);
            break;

        case em_bus_event_type_scan_channel:
            handle_scan_channel_list(evt);
            break;

        case em_bus_event_type_set_policy:
            handle_set_policy(evt);
            break;

        case em_bus_event_type_start_dpp:
            handle_start_dpp(evt);  
            break;

        case em_bus_event_type_steer_sta:
            handle_client_steer(evt);   
            break;

        case em_bus_event_type_disassoc_sta:
            handle_client_disassoc(evt);
            break;

        case em_bus_event_type_btm_sta:
            handle_client_btm(evt);
            break;

        case em_bus_event_type_dm_commit:
            handle_dm_commit(evt);
            break;

        case em_bus_event_type_m2_tx:
            handle_m2_tx(evt);
            break;

        case em_bus_event_type_cfg_renew:
			handle_config_renew(evt);
			break;

		case em_bus_event_type_sta_assoc:
			handle_sta_assoc_event(evt);
			break;

        case em_bus_event_type_client_disassoc_stats:
            handle_client_disassoc_stats_event(evt);
            break;

        case em_bus_event_type_mld_reconfig:
			handle_mld_reconfig(evt);
			break;

        case em_bus_event_type_bsta_cap_req:
            handle_bsta_cap_req(evt);
            break;

        case em_bus_event_type_link_quality_report:
           handle_link_stats_alarm_report(evt);
           break;

	case em_bus_event_type_unassoc_sta_query:
           handle_unassoc_sta_metrics_query(evt);
           break;
	
        case em_bus_event_type_beacon_query:
           handle_beacon_metrics_query(evt);
           break;

        case em_bus_event_type_client_assoc_ctrl_req:
           handle_client_assoc(evt);
           break;

        default:
            break;
    }
}

void em_ctrl_t::handle_event(em_event_t *evt)
{
    switch(evt->type) {
        case em_event_type_bus:
            handle_bus_event(&evt->u.bevt);
            break;

        case em_event_type_nb:
            handle_nb_event(&evt->u.nevt);
            break;

        default:
            break;
    }

}

void em_ctrl_t::publish_network_topology()
{
    assert(g_network_topology != NULL);

	wifi_bus_desc_t *desc = NULL;
    cJSON *parent = NULL;
    char *str = NULL;
    raw_data_t raw;
    dm_easy_mesh_ctrl_t *dm_ctrl = NULL;

    if((desc = get_bus_descriptor()) == NULL) {
        printf("%s:%d descriptor is null\n", __func__, __LINE__);
        return;
    }

    parent = cJSON_CreateObject();
    if (parent == NULL) {
        printf("%s:%d cJSON_CreateObject failed\n", __func__, __LINE__);
        return;
    }
    dm_ctrl = reinterpret_cast<dm_easy_mesh_ctrl_t *>(get_data_model(GLOBAL_NET_ID));
    if (dm_ctrl == NULL) {
        printf("%s:%d data model is null\n", __func__, __LINE__);
        cJSON_Delete(parent);
        return;
    }
    dm_ctrl->get_network_config(parent, const_cast<char*>(GLOBAL_NET_ID));

    str = cJSON_Print(parent);
    if (str == NULL) {
        printf("%s:%d cJSON_Print failed\n", __func__, __LINE__);
        cJSON_Delete(parent);
        return;
    }
    em_printfout("    ===============Publish Network Topology Json:\n%s\n===============\n",str);

	raw.data_type    = bus_data_type_string;
    raw.raw_data.bytes = reinterpret_cast<unsigned char *> (str);
    raw.raw_data_len = static_cast<unsigned int> (strlen(str));

    if (desc->bus_event_publish_fn(m_data_model.get_bus_hdl(), const_cast<char*>(DEVICE_WIFI_DATAELEMENTS_NETWORK_TOPOLOGY), &raw)== 0) {
        printf("%s:%d Topology published successfull\n",__func__, __LINE__);
    } else {
        printf("%s:%d Topology publish fail\n",__func__, __LINE__);
    }

    // bus_event_publish_fn copies the payload
    cJSON_Delete(parent);
    cJSON_free(str);

#if 0
    //Test code here
    // if (desc->bus_event_subs_fn(&m_bus_hdl, DEVICE_WIFI_DATAELEMENTS_NETWORK_NODE_CFG_POLICY, (void *)&em_agent_t::onewifi_cb, NULL, 0) != 0) {
    //     printf("%s:%d bus get failed\n", __func__, __LINE__);
    //     return;
    // }
    em_printfout("\n%s:%d TEST_POLICY_CFG start\n", __func__, __LINE__);

    /* Read policy JSON from /nik/orch/policy.json and publish it */
    const char *policy_path = "/nik/orch/policy.json";
    FILE *fp = fopen(policy_path, "rb");
    if (!fp) {
        printf("%s:%d Failed to open %s: %s\n", __func__, __LINE__, policy_path, strerror(errno));
    } else {
        if (fseek(fp, 0, SEEK_END) != 0) {
            printf("%s:%d fseek failed\n", __func__, __LINE__);
            fclose(fp);
        } else {
            long fsize = ftell(fp);
            rewind(fp);
            if (fsize <= 0) {
                printf("%s:%d Empty or invalid file size: %ld\n", __func__, __LINE__, fsize);
                fclose(fp);
            } else {
                char *buf = (char*)malloc((size_t)fsize + 1);
                if (!buf) {
                    printf("%s:%d malloc failed\n", __func__, __LINE__);
                    fclose(fp);
                } else {
                    size_t read = fread(buf, 1, (size_t)fsize, fp);
                    buf[read] = '\0';
                    fclose(fp);

                    printf("%s:%d Read %zu bytes from %s:\n%s\n", __func__, __LINE__, read, policy_path, buf);

                    raw_data_t raw;
                    memset(&raw, 0, sizeof(raw));
                    raw.data_type = bus_data_type_string;
                    raw.raw_data.bytes = reinterpret_cast<unsigned char*>(buf);
                    raw.raw_data_len = static_cast<unsigned int>(read);

                    if (desc->bus_event_publish_fn(m_data_model.get_bus_hdl(), DEVICE_WIFI_DATAELEMENTS_NETWORK_NODE_CFG_POLICY, &raw) == 0) {
                    //if (desc->bus_set_fn(m_data_model.get_bus_hdl(), DEVICE_WIFI_DATAELEMENTS_NETWORK_NODE_CFG_POLICY, &raw) == 0) {
                        printf("%s:%d Policy published successfully\n", __func__, __LINE__);
                    } else {
                        printf("%s:%d Policy publish failed\n", __func__, __LINE__);
                    }

                    free(buf);
                }
            }
        }
    }
#endif
}

int em_ctrl_t::data_model_init(const char *data_model_path)
{
    em_t *em = NULL;
    em_interface_t *intf;
    dm_easy_mesh_t *dm;
    mac_addr_str_t  mac_str;

    m_ctrl_cmd = new em_cmd_ctrl_t();
    if (m_ctrl_cmd->init() != 0) {
        printf("%s:%d: ctrl command init failed\n", __func__, __LINE__);
        return 0;
    }
    
    // Persistence backend is selectable via "--db-type" in the controller
    // arguments, resolved in main() and stashed in m_db_type by
    // set_db_type() before this runs.
    // Defaults to db_client_type_local, preserving existing behavior for
    // invocations that don't pass the flag.
    if (m_data_model.init(data_model_path, this, m_db_type) != 0) {
        printf("%s:%d: data model init failed\n", __func__, __LINE__);
        return -1;
    }

    if (m_db_type == db_client_type_local && !m_data_model.is_initialized()) {
        em_printfout("Local database is unconfigured; controller is available for Reset");
        return 0;
    }

    // Controller device MAC and network ControllerID are set to the AL-SAP MAC when the entry is created.
    intf = m_data_model.get_ctrl_al_interface(const_cast<char*>(GLOBAL_NET_ID));
	if (intf == NULL) {
		printf("%s:%d: data model init failed could not find netid\n", __func__, __LINE__);
		return 0;
	}
    dm_easy_mesh_t::macbytes_to_string(const_cast<unsigned char *> (intf->mac), mac_str);

    if ((dm = get_data_model(GLOBAL_NET_ID, intf->mac)) == NULL) {
        printf("%s:%s:%d: Could not find data model for mac:%s\n", __FILE__, __func__, __LINE__, mac_str);
    } else {
        //printf("%s:%s:%d: Data model found, creating node for mac:%s\n", __FILE__, __func__, __LINE__, mac_str);
            //dm->print_config();

        if ((em = create_node(intf, em_freq_band_unknown, dm, true, em_profile_type_3, em_service_type_ctrl)) == NULL) {
            printf("%s:%d: Could not create and start abstraction layer interface\n", __func__, __LINE__);
        }
    }

    return 0;
}

int em_ctrl_t::orch_init()
{
    m_orch = new em_orch_ctrl_t(this);
    return 0;
}

em_t *em_ctrl_t::find_em_for_msg_type(unsigned char *data, unsigned int len, em_t *al_em)
{
    em_raw_hdr_t *hdr;
    em_cmdu_t *cmdu;
    em_interface_t intf;
    em_freq_band_t band;
    dm_easy_mesh_t *dm;
    em_t *em = NULL;
    mac_address_t ruid, sta_mac;
    bssid_t	bssid;
    em_profile_type_t profile;
    mac_addr_str_t mac_str1 = {0}, mac_str2 = {0};
    unsigned int i = 0;
    em_commit_info_t dm_commit = {};
    em_supported_service_t svc = {};
    uint8_t is_emplus;
    em_tlv_t    *tlv;
    unsigned int tmp_len;
    unsigned int tlv_body_len;
    unsigned int tlv_total_len;
    unsigned int num_ruids;
    em_t *return_em;
    mac_address_t ruids[EM_MAX_RADIO_PER_AGENT];
    em_ap_radio_basic_cap_t *radio_basic_cap;


    assert(len > ((sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t))));
    if (len < ((sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t)))) {
        return NULL;
    }

    hdr = reinterpret_cast<em_raw_hdr_t *> (data);
    
    if (hdr->type != htons(ETH_P_1905)) {
        return NULL;
    }
    
    cmdu = reinterpret_cast<em_cmdu_t *> (data + sizeof(em_raw_hdr_t));

    switch (htons(cmdu->type)) {
        case em_msg_type_autoconf_search:
            if (em_msg_t(data + (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t)), len - static_cast<unsigned int> (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t))).get_freq_band(&band) == false) {
                return NULL;
            }

            if (em_msg_t(data + (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t)), len - static_cast<unsigned int> (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t))).get_al_mac_address(intf.mac) == false) {
                return NULL;
            }

            dm_easy_mesh_t::macbytes_to_string(intf.mac, mac_str1);
            em_printfout("[%s] Received autoconfig search from agent al mac: %s\n", __func__, mac_str1);

            is_emplus = 0;
            if (em_msg_t(data + (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t)), len - static_cast<unsigned int> (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t))).get_supported_service(&svc)) {
                for (i = 0; i < svc.num && i < EM_MAX_SERVICE; i++) {
                    if (svc.service[i] == em_service_type_emplus_agent) {
                        is_emplus = 1;
                        break;
                    }
                }
            }

            if ((dm = get_data_model(GLOBAL_NET_ID, const_cast<const unsigned char *> (intf.mac))) == NULL) {
                if (em_msg_t(data + (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t)), len - static_cast<unsigned int> (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t))).get_profile(&profile) == false) {
                    profile = em_profile_type_1;
                }
                //dm = create_data_model(GLOBAL_NET_ID, const_cast<const em_interface_t *> (&intf), profile);
                memcpy(dm_commit.mac, intf.mac, sizeof(mac_addr_t));
                strncpy(dm_commit.net_id, GLOBAL_NET_ID, sizeof(dm_commit.net_id));
                dm_commit.is_emplus_agent = is_emplus;
                dm_commit.peer_profile = profile;
                io_process(em_bus_event_type_dm_commit, reinterpret_cast<unsigned char *> (&dm_commit), sizeof(em_commit_info_t));
                em_printfout("[%s] Creating data model for mac: %s net: %s emplus: %d\n", __func__, mac_str1, GLOBAL_NET_ID, is_emplus);
            } else {
                dm->get_device_info()->is_emplus_agent = is_emplus;
                dm->set_db_cfg_param(db_cfg_type_device_list_update, "");
                dm_easy_mesh_t::macbytes_to_string(dm->get_agent_al_interface_mac(), mac_str1);
                em_printfout("[%s] Found existing data model for mac: %s net: %s emplus: %d\n", __func__, mac_str1, GLOBAL_NET_ID, is_emplus);
            }
            em = al_em;
            break;

        case em_msg_type_autoconf_wsc:
            if (em_msg_t(data + (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t)),
                	len - static_cast<unsigned int> (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t))).get_radio_id(&ruid) == false) {
                return NULL;
            }

            dm_easy_mesh_t::macbytes_to_string(ruid, mac_str1);
        
            if ((em = static_cast<em_t *> (hash_map_get(m_em_map, mac_str1))) != NULL) {
                printf("%s:%d: Found existing radio:%s\n", __func__, __LINE__, mac_str1);
                if(em->get_state() != em_state_ctrl_wsc_m2_sent)
                    em->set_state(em_state_ctrl_wsc_m1_pending);
                else
                    printf("%s:%d: Autoconf wsc msg sent already. Incorrect state = (%d)\n", __func__, __LINE__, em->get_state());
            } else {
                if ((dm = get_data_model(GLOBAL_NET_ID, const_cast<const unsigned char *> (hdr->src))) == NULL) {
                    printf("%s:%d: Can not find data model\n", __func__, __LINE__);
                    break;
                }

                dm_easy_mesh_t::macbytes_to_string(hdr->src, mac_str1);
                dm_easy_mesh_t::macbytes_to_string(ruid, mac_str2);

                printf("%s:%d: Found data model for mac: %s, creating node for ruid: %s\n", __func__, __LINE__, mac_str1, mac_str2);

                memcpy(intf.mac, ruid, sizeof(mac_address_t));
                if ((em = create_node(&intf, em_freq_band_unknown, dm, false,  dm->get_device()->m_device_info.profile,
                        em_service_type_ctrl)) != NULL) {
                    em->set_state(em_state_ctrl_wsc_m1_pending);
                }
            }

            break;

        case em_msg_type_channel_sel_rsp:
        case em_msg_type_op_channel_rprt:
            if (em_msg_t(data + (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t)),
                    len - static_cast<unsigned int> (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t))).get_radio_id(&ruid) == false) {
                em_printfout("Could not find radio id in msg:0x%04x", htons(cmdu->type));
                return NULL;
            }

            dm_easy_mesh_t::macbytes_to_string(ruid, mac_str1);
            if ((em = static_cast<em_t *> (hash_map_get(m_em_map, mac_str1))) == NULL) {
                em_printfout("Could not find radio:%s", mac_str1);
                return NULL;
            }
            break;

        case em_msg_type_early_ap_cap_rprt:
            tlv = reinterpret_cast<em_tlv_t *>(data + (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t)));
            tmp_len = len - static_cast<unsigned int>(sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));
            num_ruids = 0;
            return_em = NULL;

            while ((tmp_len >= sizeof(em_tlv_t)) && (tlv->type != em_tlv_type_eom)) {
                tlv_body_len = static_cast<unsigned int>(htons(tlv->len));
                tlv_total_len = static_cast<unsigned int>(sizeof(em_tlv_t)) + tlv_body_len;

                if (tlv_total_len > tmp_len) {
                    em_printfout("Early AP Cap Report: malformed TLV length %u exceeds remaining %u",
                        tlv_body_len, tmp_len);
                    return NULL;
                }

                if (tlv->type == em_tlv_type_ap_radio_basic_cap) {
                    if (tlv_body_len < sizeof(em_ap_radio_basic_cap_t)) {
                        em_printfout("Early AP Cap Report: AP Radio Basic Cap TLV too short: %u", tlv_body_len);
                        return NULL;
                    }

                    radio_basic_cap = reinterpret_cast<em_ap_radio_basic_cap_t *>(tlv->value);
                    if (num_ruids < EM_MAX_RADIO_PER_AGENT) {
                        memcpy(ruids[num_ruids], radio_basic_cap->ruid, sizeof(mac_address_t));
                        em_printfout("Early AP Cap Report: Found radio RUID %s", util::mac_to_string(ruids[num_ruids]).c_str());
                        num_ruids++;
                    }
                }
                tmp_len -= tlv_total_len;
                tlv = reinterpret_cast<em_tlv_t *>(reinterpret_cast<unsigned char *>(tlv) + tlv_total_len);
            }

            if (num_ruids == 0) {
                em_printfout("Early AP Cap Report: No radios found in message");
                return NULL;
            }

            if ((dm = get_data_model(GLOBAL_NET_ID, const_cast<const unsigned char *>(hdr->src))) == NULL) {
                em_printfout("Cannot find data model for Early AP Capability Report");
                return NULL;
            }

            em_printfout("Number of radios before processing Early AP Capability Report: %u",
                dm->get_num_radios());
            dm_easy_mesh_t::macbytes_to_string(hdr->src, mac_str2);

            for (i = 0; i < num_ruids; i++) {
                dm_easy_mesh_t::macbytes_to_string(ruids[i], mac_str1);
                em = static_cast<em_t *>(hash_map_get(m_em_map, mac_str1));

                if (em == NULL) {
                    em_printfout("Creating node for missing radio RUID %s from agent %s",
                        mac_str1, mac_str2);
                    memcpy(intf.mac, ruids[i], sizeof(mac_address_t));
                    if ((em = create_node(&intf, em_freq_band_unknown, dm, false,
                                            dm->get_device()->m_device_info.profile,
                                            em_service_type_ctrl)) != NULL) {
                        em->set_state(em_state_ctrl_wsc_m1_pending);
                        return_em = em;
                        em_printfout("Created new em for radio %s", mac_str1);
                    }
                } else if (return_em == NULL) {
                    return_em = em;
                }
            }

            em_printfout("Number of radios after processing Early AP Capability Report: %u",
                dm->get_num_radios());

            em = return_em;
            break;

        case em_msg_type_topo_resp:
        case em_msg_type_ap_cap_rprt:
        case em_msg_type_channel_pref_rprt:
            if ((dm = get_data_model(GLOBAL_NET_ID, const_cast<const unsigned char *>(hdr->src))) == NULL) {
                em_printfout("Cannot find data model for agent AL MAC %s", util::mac_to_string(hdr->src).c_str());
                em = NULL;
                break;
            }
            em = NULL;
            for (i = 0; i < dm->get_num_radios(); i++) {
                dm_easy_mesh_t::macbytes_to_string(dm->get_radio_info(i)->id.ruid, mac_str1);
                em = static_cast<em_t *>(hash_map_get(m_em_map, mac_str1));
                if (em != NULL) {
                    break;
                }
            }
            if (em == NULL) {
                em_printfout("No EM found for agent AL MAC %s", util::mac_to_string(hdr->src).c_str());
            }
            break;

        case em_msg_type_topo_notif:
        case em_msg_type_client_cap_rprt:
        case em_msg_type_ap_metrics_rsp:
        case em_msg_type_failed_conn:
            if (em_msg_t(data + (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t)),
                    len - static_cast<unsigned int> (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t))).get_bss_id(&bssid) == false) {
                em_printfout("Could not find bss id in msg:0x%04x", htons(cmdu->type));
                return NULL;
            }
            em = al_em;
            break;

        case em_msg_type_client_disassoc_stats: {
            mac_address_t sta_mac;

            if (em_msg_t(data + (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t)),
                    len - static_cast<unsigned int> (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t))).get_sta_mac(&sta_mac) == false) {
                em_printfout("Could not find STA MAC in msg:0x%04x", htons(cmdu->type));
                return NULL;
            }
            em = al_em;
            break;
        }

        case em_msg_type_autoconf_resp:
        case em_msg_type_topo_query:
        case em_msg_type_autoconf_renew:
        case em_msg_type_channel_pref_query:
        case em_msg_type_channel_sel_req:
        case em_msg_type_client_cap_query:
        case em_msg_type_assoc_sta_link_metrics_query:
        case em_msg_type_unassoc_sta_link_metrics_query:	    
        case em_msg_type_beacon_metrics_query:
        case em_msg_type_client_steering_req:
        case em_msg_type_client_assoc_ctrl_req:
        case em_msg_type_map_policy_config_req:
        case em_msg_type_channel_scan_req:
        case em_msg_type_ap_mld_config_req:
			break;

		case em_msg_type_channel_scan_rprt:
            if (em_msg_t(data + (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t)),
                	len - static_cast<unsigned int> (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t))).get_radio_id(&ruid) == false) {
                return NULL;
            }

            dm_easy_mesh_t::macbytes_to_string(ruid, mac_str1);

            if ((em = static_cast<em_t *> (hash_map_get(m_em_map, mac_str1))) != NULL) {        
                //printf("%s:%d: Found existing radio:%s\n", __func__, __LINE__, mac_str1);
			}
            break;

        case em_msg_type_assoc_sta_link_metrics_rsp:
            em = static_cast<em_t *> (hash_map_get_first(m_em_map));
            while(em != NULL) {
                if ((em->is_al_interface_em() == false) && (em->has_at_least_one_associated_sta() == true)) {
                    break;
                }
                em = static_cast<em_t *> (hash_map_get_next(m_em_map, em));
            }

            break;

        case em_msg_type_client_steering_btm_rprt:
            em = static_cast<em_t *> (hash_map_get_first(m_em_map));
            while(em != NULL) {
                if ((em->is_al_interface_em() == false) && (em->has_at_least_one_associated_sta() == true)) {
                    break;
                }
                em = static_cast<em_t *> (hash_map_get_next(m_em_map, em));
            }
            break;

        case em_msg_type_ap_mld_config_resp:
        case em_msg_type_1905_ack:
            em_printfout("  -------->>>> 1905_ack rcvdddd");
            em = static_cast<em_t *> (hash_map_get_first(m_em_map));
            while(em != NULL) {
                if ((em->is_al_interface_em() == false)) {
                    break;
                }
                em = static_cast<em_t *> (hash_map_get_next(m_em_map, em));
            }
            em_printfout("1905_ack routing: dispatching to em=%p radio=%s", static_cast<void*>(em),
                em ? util::mac_to_string(em->get_radio_interface_mac()).c_str() : "NULL");
            break;

        case em_msg_type_beacon_metrics_rsp:
            if (em_msg_t(data + (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t)),
                    len - static_cast<unsigned int> (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t))).get_sta_mac(&sta_mac) == false) {
                em_printfout("Could not find sta mac in msg:0x%04x", htons(cmdu->type));
                return NULL;
            }
            em = al_em;
            break;

        case em_msg_type_chirp_notif:
        case em_msg_type_proxied_encap_dpp:
        case em_msg_type_direct_encap_dpp:
        case em_msg_type_dpp_cce_ind:
        case em_msg_type_1905_rekey_req:
        case em_msg_type_1905_encap_eapol:
        case em_msg_type_bss_config_req:
        case em_msg_type_bss_config_res:
	        em = al_em;
	        break;
        case em_msg_type_topo_disc:
            em = NULL;
            break;

        case em_msg_type_bh_sta_cap_query:
        break;

        case em_msg_type_bh_sta_cap_rprt:
            if (em_msg_t(data + (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t)),
                len - static_cast<unsigned int> (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t))).get_radio_id(&ruid) == false) {
                return NULL;
            }

            dm_easy_mesh_t::macbytes_to_string(ruid, mac_str1);
            if ((em = static_cast<em_t *> (hash_map_get(m_em_map, mac_str1))) != NULL) {
                em_printfout("Received bsta report, found em:%s", mac_str1);
            }
            break;

        case em_msg_type_topo_vendor:
            em = static_cast<em_t *> (hash_map_get_first(m_em_map));
            while(em != NULL) {
                if ((em->is_al_interface_em() == false) &&
                    (memcmp(em->get_data_model()->get_agent_al_interface_mac(), hdr->src, sizeof(mac_address_t)) == 0)) {
                    break;
                }
                em = static_cast<em_t *> (hash_map_get_next(m_em_map, em));
            }
            break;

	case em_msg_type_unassoc_sta_link_metrics_rsp:
            em = static_cast<em_t *>(hash_map_get_first(m_em_map));
            while (em != NULL) {
                if ((em->is_al_interface_em() == false) && 
	          (memcmp(em->get_data_model()->get_agent_al_interface_mac(), hdr->src, sizeof(mac_address_t)) == 0)) {
                    break;
                }
                em = static_cast<em_t *>(hash_map_get_next(m_em_map, em));
            }
            break;

        default:
            printf("%s:%d: Frame: 0x%04x not handled in controller\n", __func__, __LINE__, htons(cmdu->type));
            em = NULL;
            break;
    }

    return em;
}

void em_ctrl_t::io(void *data, bool input)
{
    char *str = static_cast<char *> (data);
    m_ctrl_cmd->execute(str);

    m_ctrl_cmd->deinit();
    delete m_ctrl_cmd;
}

void em_ctrl_t::start_complete()
{
	dm_easy_mesh_t *dm;
	wifi_bus_desc_t *desc;
	raw_data_t raw;
	em_interface_t	*intf;
	mac_addr_str_t  al_mac_str;
	em_bus_event_type_cfg_renew_params_t ac_config_raw;
	mac_address_t null_mac = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	int i = 0;
    bus_error_t bus_error_val;
    unsigned int num_elements = 0;

    //Todo: Revisit placement of data elements registration done for orch
    bus_data_element_t dataElements[] = {
        { const_cast<char*>(DEVICE_WIFI_DATAELEMENTS_NETWORK_TOPOLOGY), bus_element_type_method,
            { tr_181_t::get_network_topology, NULL , NULL, NULL, NULL, NULL }, slow_speed, ZERO_TABLE,
            { bus_data_type_string, false, 0, 0, 0, NULL } },
        { const_cast<char*>(DEVICE_WIFI_DATAELEMENTS_NETWORK_NODE_SYNC), bus_element_type_method,
            { tr_181_t::get_node_sync,  tr_181_t::set_node_sync , NULL, NULL, NULL, NULL }, slow_speed, ZERO_TABLE,
            { bus_data_type_string, false, 0, 0, 0, NULL } },
        { const_cast<char*>(DEVICE_WIFI_DATAELEMENTS_NETWORK_NODE_CFG_POLICY), bus_element_type_method,
            { NULL, tr_181_t::policy_config , NULL, NULL, NULL, NULL }, slow_speed, ZERO_TABLE,
            { bus_data_type_string, false, 0, 0, 0, NULL } },
         { const_cast<char*>(DEVICE_WIFI_DATAELEMENTS_NETWORK_NODE_LINKSTATS_ALARM), bus_element_type_method,
            { NULL, NULL , NULL, NULL, NULL, NULL }, slow_speed, ZERO_TABLE,
            { bus_data_type_string, false, 0, 0, 0, NULL } },
        { const_cast<char*>(DEVICE_WIFI_DATAELEMENTS_FAILED_CONNECTION), bus_element_type_event,
            { NULL, NULL , NULL, NULL, NULL, NULL }, slow_speed, ZERO_TABLE,
            { bus_data_type_property, false, 0, 0, 0, NULL } },
        { const_cast<char*>(DEVICE_WIFI_DATAELEMENTS_DISASSOCIATION), bus_element_type_event,
            { NULL, NULL , NULL, NULL, NULL, NULL }, slow_speed, ZERO_TABLE,
            { bus_data_type_property, false, 0, 0, 0, NULL } },
        { const_cast<char*>(DEVICE_WIFI_DATAELEMENTS_NETWORK_SETSSID_CMD), bus_element_type_method,
            { NULL, NULL , NULL, NULL, NULL, tr_181_t::setssid_handler}, slow_speed, ZERO_TABLE,
            { bus_data_type_property, false, 0, 0, 0, NULL } },
        { const_cast<char*>(DE_DEVICE_UNASSOCSTALMQ), bus_element_type_method,
            { NULL, NULL , NULL, NULL, NULL, tr_181_t::unassocstalinkmetricsquery_handler}, slow_speed, ZERO_TABLE,
            { bus_data_type_property, false, 0, 0, 0, NULL } },
        { const_cast<char*>(DE_MAPDEVBH_STEERWIFIBH), bus_element_type_method,
            { NULL, NULL , NULL, NULL, NULL, tr_181_t::steerwifibh_handler}, slow_speed, ZERO_TABLE,
            { bus_data_type_property, false, 0, 0, 0, NULL } },
        { const_cast<char*>(DE_RADIO_CHSCANREQ), bus_element_type_method,
            { NULL, NULL , NULL, NULL, NULL, tr_181_t::channelscan_handler}, slow_speed, ZERO_TABLE,
            { bus_data_type_property, false, 0, 0, 0, NULL } },
        { const_cast<char*>(DE_RADIO_CHSELREQ), bus_element_type_method,
            { NULL, NULL , NULL, NULL, NULL, tr_181_t::channelselect_handler}, slow_speed, ZERO_TABLE,
            { bus_data_type_property, false, 0, 0, 0, NULL } },
        { const_cast<char*>(DE_BSS_CLIENTASSOCCTRL), bus_element_type_method,
            { NULL, NULL , NULL, NULL, NULL, tr_181_t::clientassocctrlrequest_handler}, slow_speed, ZERO_TABLE,
            { bus_data_type_property, false, 0, 0, 0, NULL } },
        { const_cast<char*>(DE_STA_CLIENTSTEER), bus_element_type_method,
            { NULL, NULL , NULL, NULL, NULL, tr_181_t::clientsteer_handler}, slow_speed, ZERO_TABLE,
            { bus_data_type_property, false, 0, 0, 0, NULL } },
        { const_cast<char*>(DE_STA_BEACONMETRICSQ), bus_element_type_method,
            { NULL, NULL , NULL, NULL, NULL, tr_181_t::beaconmetricsquery_handler}, slow_speed, ZERO_TABLE,
            { bus_data_type_property, false, 0, 0, 0, NULL } },
        { const_cast<char*>(DE_STAMAP_DISASSOC), bus_element_type_method,
            { NULL, NULL , NULL, NULL, NULL, tr_181_t::disassociate_handler}, slow_speed, ZERO_TABLE,
            { bus_data_type_property, false, 0, 0, 0, NULL } }
        };

	if (m_data_model.is_initialized() == false) {
		printf("%s:%d: Database not initialized ... needs reset\n", __func__, __LINE__);
		return;
	}

	// build initial network topology
	init_network_topology();

    dm = m_data_model.get_first_dm();
    while (dm != NULL) {
		dm->set_db_cfg_param(db_cfg_type_scan_result_list_delete, "");
		dm->set_db_cfg_param(db_cfg_type_sta_list_delete, "");
		dm->set_db_cfg_param(db_cfg_type_op_class_list_delete, "");
		dm->set_db_cfg_param(db_cfg_type_bss_list_delete, "");
        dm = m_data_model.get_next_dm(dm);
    }
	memcpy(&ac_config_raw.radio, &null_mac, sizeof(mac_address_t));
	io_process(em_bus_event_type_cfg_renew, reinterpret_cast<unsigned char *> (&ac_config_raw), sizeof(em_bus_event_type_cfg_renew_params_t));
	//Initialze cli devtest
	for (i = 0; i < em_dev_test_type_max; i++) {
		dev_test.dev_test_info.num_iteration[i] = 50;
		dev_test.dev_test_info.test_type[i] = static_cast<em_dev_test_type>(i);;
		dev_test.dev_test_info.enabled[i] = 0;
		dev_test.dev_test_info.num_of_iteration_completed[i] = 0;
		dev_test.dev_test_info.test_inprogress[i] = 0;
		dev_test.dev_test_info.test_status[i] = em_dev_test_status_idle;
		dev_test.dev_test_info.haul_type = em_haul_type_iot;
		dev_test.dev_test_info.freq_band = em_freq_band_24;
	}

    if((desc = get_bus_descriptor()) == NULL) {
        printf("%s:%d descriptor is null\n", __func__, __LINE__);
        return;
    }

    num_elements = (sizeof(dataElements) / sizeof(bus_data_element_t));
    bus_error_val = desc->bus_reg_data_element_fn(m_data_model.get_bus_hdl(), dataElements, num_elements);
    if (bus_error_val != bus_error_success) {
        printf("%s:%d bus: bus_regDataElements failed\n", __func__, __LINE__);
        return;
    }

    dm = m_data_model.get_first_dm();
    while (dm != NULL && dm->is_controller() == false) {
        dm = m_data_model.get_next_dm(dm);
    }

    if (dm) {
        intf = dm->get_ctrl_al_interface();
        assert(intf != NULL);

        dm_easy_mesh_t::macbytes_to_string(intf->mac, al_mac_str);
        raw.data_type    = bus_data_type_string;
        raw.raw_data.bytes   = al_mac_str;
        raw.raw_data_len = static_cast<unsigned int> (strlen(al_mac_str));

        if (desc->bus_set_fn(m_data_model.get_bus_hdl(), "Device.WiFi.DataElements.Network.ControllerID", &raw) == 0) {
            em_printfout("Controller ID: %s publish successful.", al_mac_str);
        }
        else {
            em_printfout("Controller ID: %s publish failed.", al_mac_str);
        }
    } else {
            em_printfout("Could not find data model with controller role");
    }

    if (desc->bus_event_subs_fn(m_data_model.get_bus_hdl(), DEVICE_WIFI_DATAELEMENTS_NETWORK_NODE_CFG_POLICY, reinterpret_cast<void *> (&tr_181_t::subs_policy_config), NULL, 0) != 0) {
        em_printfout("bus subscribe failed");
        return;
    }

    em_get_ext_hooks()->on_bus_ready(m_data_model.get_bus_hdl(), desc);
}

em_ctrl_t *em_ctrl_t::get_em_ctrl_instance()
{
    if (s_em_ctrl == nullptr) {
        s_em_ctrl = new em_ctrl_t();
    }
    return s_em_ctrl;
}

em_ctrl_t::em_ctrl_t()
{
    m_db_type = db_client_type_local;
}

em_ctrl_t::~em_ctrl_t()
{
}

#ifdef AL_SAP
AlServiceAccessPoint* em_ctrl_t::al_sap_register(const std::string& data_socket_path, const std::string& control_socket_path)
{
    AlServiceAccessPoint* sap = nullptr;
    try {
        sap = new AlServiceAccessPoint(data_socket_path.c_str(), control_socket_path.c_str());

        AlServiceRegistrationRequest registrationRequest(SAPActivation::SAP_ENABLE, ServiceType::EmController);
        sap->serviceAccessPointRegistrationRequest(registrationRequest);

        AlServiceRegistrationResponse registrationResponse = sap->serviceAccessPointRegistrationResponse();

        RegistrationResult result = registrationResponse.getResult();
        if (result == RegistrationResult::SUCCESS) {
            g_al_mac_sap = registrationResponse.getAlMacAddressLocal();
            uint8_t* al_mac_bytes = g_al_mac_sap.data();
            em_printfout("AL SAP registration successful, AL MAC: %s", util::mac_to_string(al_mac_bytes).c_str());
            m_data_model.set_dev_interface_mac(al_mac_bytes);

            em_interface_t intfs[EM_MAX_INTERFACES];
            unsigned int num_intfs = EM_MAX_INTERFACES;
            if (dm_easy_mesh_t::get_interfaces_list(intfs, &num_intfs) == 0) {
                for (unsigned int i = 0; i < num_intfs; i++) {
                    if (memcmp(intfs[i].mac, al_mac_bytes, sizeof(mac_address_t)) == 0) {
                        m_data_model.set_dev_interface_name(intfs[i].name);
                        m_data_model.get_dev_interface()->media = intfs[i].media;
                        em_printfout("AL interface: %s media: %d", intfs[i].name, intfs[i].media);
                        break;
                    }
                }
            }
        } else {
            em_printfout("Registration failed with error: %d, data socket: %s, control socket: %s",
                         static_cast<int>(result),
                         data_socket_path.c_str(),
                         control_socket_path.c_str());
            delete sap;
            return nullptr;
        }
    }
    catch (const AlServiceException& e) {
        em_printfout("AL SAP registration exception: %s, data socket: %s, control socket: %s",
                     e.what(), data_socket_path.c_str(), control_socket_path.c_str());
        delete sap;
        return nullptr;
    }
    catch (const std::exception& e) {
        em_printfout("Unknown exception: %s during AL SAP registration, data socket: %s, control socket: %s",
                     e.what(), data_socket_path.c_str(), control_socket_path.c_str());
        delete sap;
        return nullptr;
    }

    return sap;
}
#endif


#ifndef TESTING
int main(int argc, const char *argv[])
{
    em_ctrl_t  *em_ctrl = em_ctrl_t::get_em_ctrl_instance();

    if (em_get_ext_hooks()->process_cli_args(&argc, argv) == false) {
        return -1;
    }

    const char *database_path = nullptr;

    // Options and the database path may appear in any order. Unknown options
    // are ignored. To add an option, add one branch below.
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];

        if (arg == "--help" || arg == "-h") {
            printf("Usage: %s [data-model-path] [--db-type=local|cloud|none]\n"
                   "  Defaults to local SQLite persistence. data-model-path is optional;\n"
                   "  if omitted, uses EASYMESH_DB_FILE or the default SQLite database file.\n"
                   "  The path is ignored for cloud and none. Use --db-type=none to disable persistence.\n",
                argv[0]);
            return 0;
        }
        if (arg.find("--db-type=") == 0) {
            std::string value = arg.substr(strlen("--db-type="));
            db_client_type_t type = db_client_t::type_from_string(value.c_str());
            if (value.empty() || (type == db_client_type_local && strcasecmp(value.c_str(), "local") != 0)) {
                em_printfout("Invalid --db-type '%s', using local", value.c_str());
            }
            em_ctrl->set_db_type(type);
            continue;
        }
        if (arg[0] == '-') {
            continue;
        }
        if (database_path == nullptr) {
            database_path = argv[i];
        }
    }

    if (em_ctrl->get_db_type() != db_client_type_local && database_path != nullptr) {
        em_printfout("Ignoring data-model-path '%s', not used with this --db-type", database_path);
        database_path = nullptr;
    }

    em_printf("Database type set to: %d\n", em_ctrl->get_db_type());
    if (em_ctrl->get_db_type() == db_client_type_none) {
        em_printfout("Starting without a database (--db-type=none): nothing will be persisted");
    }

#ifdef AL_SAP
    const char* data_socket_path = "/tmp/al_em_ctrl_data_socket";
    const char* control_socket_path = "/tmp/al_em_ctrl_control_socket";
    g_sap = em_ctrl->al_sap_register(data_socket_path, control_socket_path);
    if (nullptr == g_sap) {
        em_printfout("Error in AL SAP registration, exiting");
        return -1;
    }
#endif

    if (em_ctrl->init(database_path) != 0) {
        return -1;
    }
    em_ctrl->start();
    return 0;
}

#endif // TESTING

extern "C" void wifi_util_print(wifi_log_level_t level, wifi_dbg_type_t module, const char *format, ...)
{

}
