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

    cJSON_Delete(parent);
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

    cJSON *obj = cJSON_CreateObject();
    if (obj == nullptr) {
        em_printfout("Failed to allocate JSON object for FailedConnectionEvent");
        return;
    }

    cJSON_AddStringToObject(obj, "BSSID", bssid_str);
    cJSON_AddStringToObject(obj, "MACAddress", sta_str);
    cJSON_AddNumberToObject(obj, "StatusCode", status_code);
    cJSON_AddNumberToObject(obj, "ReasonCode", reason_code);
    cJSON_AddStringToObject(obj, "TimeStamp", timestamp);

    char *str = cJSON_Print(obj);
    cJSON_Delete(obj);

    if (str == nullptr) {
        em_printfout("Failed to serialize FailedConnectionEvent JSON");
        return;
    }

    wifi_bus_desc_t *desc = get_bus_descriptor();
    if (desc == nullptr) {
        em_printfout("Bus descriptor is null");
        free(str);
        return;
    }

    raw_data_t raw;
    memset(&raw, 0, sizeof(raw));
    raw.data_type = bus_data_type_string;
    raw.raw_data.bytes = reinterpret_cast<unsigned char *>(str);
    raw.raw_data_len = static_cast<unsigned int>(strlen(str));

    if (desc->bus_event_publish_fn(m_data_model.get_bus_hdl(), DEVICE_WIFI_DATAELEMENTS_FAILED_CONNECTION, &raw) == 0) {
        em_printfout("FailedConnectionEvent published: bssid=%s sta=%s status=%u reason=%u",
            bssid_str, sta_str, status_code, reason_code);
    } else {
        em_printfout("FailedConnectionEvent publish failed");
    }

    free(str);
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
        case NB_REQTYPE_GET: {
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
    
    if (m_data_model.init(data_model_path, this) != 0) {
        printf("%s:%d: data model init failed\n", __func__, __LINE__);
        return 0;
    }

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
    mac_address_t ruid;
    bssid_t	bssid;
    dm_bss_t *bss;
    em_profile_type_t profile;
    unsigned int i;
    mac_addr_str_t mac_str1 = {0}, mac_str2 = {0};
    em_commit_info_t dm_commit = {};
    mac_address_t fallback_ruid = {0};
    em_supported_service_t svc = {};
    uint8_t is_emplus;

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
                printf("%s:%d: Could not find bss id in msg:0x%04x\n", __func__, __LINE__, htons(cmdu->type));
                return NULL;
            }

            if ((dm = get_data_model(GLOBAL_NET_ID, const_cast<const unsigned char *> (hdr->src))) == NULL) {
                printf("%s:%d: Can not find data model\n", __func__, __LINE__);
                return NULL;
            }

            if (dm->is_ap_mld_mac(bssid) == false) {
                bss = NULL;
                for (i = 0; i < dm->get_num_radios(); i++) {
                    bss = dm->get_bss(dm->get_radio_info(i)->id.ruid, bssid);
                    if (bss != NULL) {
                        break;
                    }
                }

                if (bss == NULL) {
                    em_printfout("Could not find bss=%s from data model",
                        util::mac_to_string(bssid).c_str());
                    return NULL;
                }

                dm_easy_mesh_t::macbytes_to_string(bss->m_bss_info.ruid.mac, mac_str1);
                if ((em = static_cast<em_t *>(hash_map_get(m_em_map, mac_str1))) == NULL) {
                    em_printfout("Could not find radio:%s", mac_str1);
                    return NULL;
                }
            } else {
                if ((htons(cmdu->type) == em_msg_type_topo_notif) ||
                    (htons(cmdu->type) == em_msg_type_client_cap_rprt)) {
                    if (dm->resolve_ap_mld_to_fallback_ruid(bssid, fallback_ruid)) {
                        dm_easy_mesh_t::macbytes_to_string(fallback_ruid, mac_str1);
                        em = static_cast<em_t *>(hash_map_get(m_em_map, mac_str1));
                        if (em != NULL) {
                            em_printfout("Resolved AP-MLD bssid=%s to radio=%s for msg=0x%04x",
                                util::mac_to_string(bssid).c_str(),
                                util::mac_to_string(fallback_ruid).c_str(),
                                htons(cmdu->type));
                        }
                    }
                    if (em == NULL) {
                        em_printfout("fallback em not found for msg 0x%04x", htons(cmdu->type));
                        return NULL;
                    }
                } else {
                    em_printfout("Could not find bss=%s from data model",
                        util::mac_to_string(bssid).c_str());
                    return NULL;
                }
            }

            break;

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
            em = static_cast<em_t *> (hash_map_get_first(m_em_map));
            while(em != NULL) {
                if ((em->is_al_interface_em() == false)) {
                    break;
                }
                em = static_cast<em_t *> (hash_map_get_next(m_em_map, em));
            }
            break;

        case em_msg_type_beacon_metrics_rsp:
            em = static_cast<em_t *> (hash_map_get_first(m_em_map));
            while(em != NULL) {
                if ((em->is_al_interface_em() == false) && (em->has_at_least_one_associated_sta() == true)) {
                    break;
                }
                em = static_cast<em_t *> (hash_map_get_next(m_em_map, em));
            }
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
                if (em->is_al_interface_em() == false) {
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
            { bus_data_type_string, false, 0, 0, 0, NULL } },
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
        { const_cast<char*>(DE_STA_CLIENTSTEER), bus_element_type_method,
            { NULL, NULL , NULL, NULL, NULL, tr_181_t::clientsteer_handler}, slow_speed, ZERO_TABLE,
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
#ifdef AL_SAP
    const char* data_socket_path = "/tmp/al_em_ctrl_data_socket";
    const char* control_socket_path = "/tmp/al_em_ctrl_control_socket";
    g_sap = em_ctrl->al_sap_register(data_socket_path, control_socket_path);
    if (nullptr == g_sap) {
        em_printfout("Error in AL SAP registration, exiting");
        return -1;
    }
#endif
    if (em_ctrl->init(argv[1]) == 0) {
        em_ctrl->start();
    }
    return 0;
}

#endif // TESTING

extern "C" void wifi_util_print(wifi_log_level_t level, wifi_dbg_type_t module, const char *format, ...)
{

}
