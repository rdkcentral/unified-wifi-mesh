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
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>
#include <pthread.h>
#include <cjson/cJSON.h>
#include "em_cmd.h"

bool em_cmd_t::validate()
{
    if ((m_type == em_cmd_type_none) || (m_type >= em_cmd_type_max)) {
        return false;
    }

    return true;

}

unsigned int em_cmd_t::get_event_data_length()
{
	em_frame_event_t *fevt;
	em_bus_event_t *bevt;
	unsigned int sz = 0;

	switch (m_evt->type) {
		case em_event_type_frame:
			fevt = &m_evt->u.fevt;
			sz = fevt->frame_len;
			break;

		case em_event_type_bus:
			bevt = &m_evt->u.bevt;
			sz = bevt->data_len;
			break;
	}

	return sz;
}

void em_cmd_t::set_event_data_length(unsigned int len)
{
	em_frame_event_t *fevt;
    em_bus_event_t *bevt;
    unsigned int sz = 0;
    
    switch (m_evt->type) {
        case em_event_type_frame:
            fevt = &m_evt->u.fevt;
			fevt->frame_len = len;
            break;
        
        case em_event_type_bus:
            bevt = &m_evt->u.bevt;
			bevt->data_len = len;
            break;
    }
}

void em_cmd_t::copy_bus_event(em_bus_event_t *evt)
{
	em_bus_event_t *bevt;

	m_evt->type = em_event_type_bus;
	bevt = &m_evt->u.bevt;
	memcpy(bevt, evt, sizeof(em_bus_event_t));
	memcpy(bevt->u.subdoc.buff, evt->u.subdoc.buff, evt->data_len);			
}	

void em_cmd_t::copy_frame_event(em_frame_event_t *evt)
{
	em_frame_event_t *fevt;

	m_evt->type = em_event_type_frame;
	fevt = &m_evt->u.fevt;
	memcpy(fevt, evt, sizeof(em_frame_event_t));
	memcpy(fevt->frame, evt->frame, evt->frame_len);			
}	

char *em_cmd_t::status_to_string(em_cmd_out_status_t status, char *str)
{
    cJSON *obj, *res = NULL;
    em_long_string_t status_str;
    em_subdoc_info_t *info;
    em_event_t *evt;
    char *tmp;

    evt = get_event();
    info = &evt->u.bevt.u.subdoc;

    obj = cJSON_CreateObject();

    switch (status) {
        case em_cmd_out_status_success:
            snprintf(status_str, sizeof(status_str), "%s", "Success");
            break;

        case em_cmd_out_status_not_ready:
            snprintf(status_str, sizeof(status_str), "%s", "Error_Not_Ready");
            break;

        case em_cmd_out_status_invalid_input:
            snprintf(status_str, sizeof(status_str), "%s", "Error_Invalid_Input");
            break;

        case em_cmd_out_status_timeout:
            snprintf(status_str, sizeof(status_str), "%s", "Error_Timeout");
            break;

        case em_cmd_out_status_invalid_mac:
            snprintf(status_str, sizeof(status_str), "%s", "Error_Invalid_Mac");
            break;

        case em_cmd_out_status_interface_down:
            snprintf(status_str, sizeof(status_str), "%s", "Error_Interface_Down");
            break;

        case em_cmd_out_status_other:
            snprintf(status_str, sizeof(status_str), "%s", "Error_Other");
            break;

        case em_cmd_out_status_prev_cmd_in_progress:
            snprintf(status_str, sizeof(status_str), "%s", "Error_Prev_Cmd_In_Progress");
            break;

        case em_cmd_out_status_no_change:
            snprintf(status_str, sizeof(status_str), "%s", "Error_No_Config_Change_Detected");
            break;
    }

    cJSON_AddStringToObject(obj, "Status", status_str);
    if (status == em_cmd_out_status_success) {
        res = cJSON_Parse(info->buff);
        if (res != NULL) {
            cJSON_AddItemToObject(obj, "Result", res);
        }
    }

    tmp = cJSON_Print(obj);
    strncpy(str, tmp, strlen(tmp) + 1);
    cJSON_free(tmp);
    cJSON_Delete(obj);

    return str;
}

void em_cmd_t::deinit()
{
    queue_destroy(m_em_candidates);
    m_data_model.deinit();
	//free(m_evt);
}

void em_cmd_t::init(dm_easy_mesh_t *dm)
{
    m_em_candidates = queue_create();
    m_data_model.init();
    m_data_model = *dm;
}

em_cmd_t *em_cmd_t::clone()
{   
    em_cmd_t *out = NULL;
    unsigned int i;
    em_cmd_ctx_t *pctx, ctx;

    out = new em_cmd_t(m_type, m_param, m_data_model);

    out->m_data_model = m_data_model;
    out->set_orch_op_index(m_orch_op_idx);
    out->m_num_orch_desc = m_num_orch_desc;
    for (i = 0; i < m_num_orch_desc; i++) {
        out->m_orch_desc[i].op = m_orch_desc[i].op;
        out->m_orch_desc[i].submit = m_orch_desc[i].submit;
    }

    pctx = m_data_model.get_cmd_ctx();	
    memcpy(&ctx, pctx, sizeof(em_cmd_ctx_t));	
    ctx.arr_index += 1;
    out->m_data_model.set_cmd_ctx(&ctx);
    return out;
}

em_cmd_t *em_cmd_t::clone_for_next()
{
    em_cmd_t *out = NULL;
    unsigned int i;
    em_cmd_ctx_t ctx;

    if (m_orch_op_idx == (m_num_orch_desc - 1)) {
        return NULL;
    }

    out = new em_cmd_t(m_type, m_param, m_data_model);

    out->m_data_model = m_data_model;
    out->set_orch_op_index(m_orch_op_idx + 1);
    out->m_num_orch_desc = m_num_orch_desc;
    for (i = 0; i < m_num_orch_desc; i++) {
        out->m_orch_desc[i].op = m_orch_desc[i].op;
        out->m_orch_desc[i].submit = m_orch_desc[i].submit;
    }

    memset(&ctx, 0, sizeof(em_cmd_ctx_t));
    ctx.type = out->get_orch_op();
    out->m_data_model.set_cmd_ctx(&ctx);

    return out;
}

void em_cmd_t::override_op(unsigned int index, em_orch_desc_t *desc)
{
    em_cmd_ctx_t *ctx;

    m_orch_desc[index].op = desc->op;
    m_orch_desc[index].submit = desc->submit;
    ctx = m_data_model.get_cmd_ctx();
    ctx->type = desc->op;
    m_data_model.set_cmd_ctx(ctx);
}

void em_cmd_t::init()
{
	//m_evt = (em_event_t *)malloc(sizeof(em_event_t) + EM_MAX_EVENT_DATA_LEN);

    switch (m_type) {
        case em_cmd_type_none:
            snprintf(m_name, sizeof(m_name), "%s", "none");
            m_svc = em_service_type_none;
            break;

        case em_cmd_type_reset:
            snprintf(m_name, sizeof(m_name), "%s", "reset");
            m_svc = em_service_type_ctrl;
            break;

        case em_cmd_type_dev_test:
            snprintf(m_name, sizeof(m_name), "%s", "dev_test");
            m_svc = em_service_type_ctrl;
            break;

        case em_cmd_type_get_network:
            snprintf(m_name, sizeof(m_name), "%s", "get_network");
            m_svc = em_service_type_ctrl;
            break;

        case em_cmd_type_get_device:
            strncpy(m_name, "get_device", strlen("get_device") + 1);
            m_svc = em_service_type_ctrl;
            break;

        case em_cmd_type_remove_device:
            strncpy(m_name, "remove_device", strlen("remove_device") + 1);
            m_svc = em_service_type_ctrl;
            break;

        case em_cmd_type_get_radio:
            strncpy(m_name, "get_radio", strlen("get_radio") + 1);
            m_svc = em_service_type_ctrl;
            break;

        case em_cmd_type_set_radio:
            strncpy(m_name, "set_radio", strlen("set_radio") + 1);
            m_svc = em_service_type_ctrl;
            break;

        case em_cmd_type_get_ssid:
            snprintf(m_name, sizeof(m_name), "%s", "get_ssid");
            m_svc = em_service_type_ctrl;
            break;

        case em_cmd_type_set_ssid:
            snprintf(m_name, sizeof(m_name), "%s", "set_ssid");
            m_svc = em_service_type_ctrl;
            break;

        case em_cmd_type_get_channel:
            snprintf(m_name, sizeof(m_name), "%s", "get_channel");
            m_svc = em_service_type_ctrl;
            break;

        case em_cmd_type_set_channel:
            snprintf(m_name, sizeof(m_name), "%s", "set_channel");
            m_svc = em_service_type_ctrl;
            break;

        case em_cmd_type_scan_channel:
            snprintf(m_name, sizeof(m_name), "%s", "scan_channel");
            m_svc = em_service_type_ctrl;
            break;

        case em_cmd_type_scan_result:
            snprintf(m_name, sizeof(m_name), "%s", "scan_result");
            m_svc = em_service_type_ctrl;
            break;

        case em_cmd_type_get_bss:
            snprintf(m_name, sizeof(m_name), "%s", "get_bss");
            m_svc = em_service_type_ctrl;
            break;

        case em_cmd_type_get_sta:
            snprintf(m_name, sizeof(m_name), "%s", "get_sta");
            m_svc = em_service_type_ctrl;
            break;

        case em_cmd_type_steer_sta:
            snprintf(m_name, sizeof(m_name), "%s", "steer_sta");
            m_svc = em_service_type_ctrl;
            break;

        case em_cmd_type_disassoc_sta:
            snprintf(m_name, sizeof(m_name), "%s", "disassoc_sta");
            m_svc = em_service_type_ctrl;
            break;

        case em_cmd_type_btm_sta:
            snprintf(m_name, sizeof(m_name), "%s", "btm_sta");
            m_svc = em_service_type_ctrl;
            break;

        case em_cmd_type_dev_init:
            snprintf(m_name, sizeof(m_name), "%s", "dev_init");
            m_svc = em_service_type_agent;
            break;

        case em_cmd_type_cfg_renew:
            snprintf(m_name, sizeof(m_name), "%s", "cfg_renew");
            m_svc = em_service_type_agent;
            break;

        case em_cmd_type_vap_config:
            snprintf(m_name, sizeof(m_name), "%s", "vap_config");
            m_svc = em_service_type_agent;
            break;

        case em_cmd_type_sta_list:
            snprintf(m_name, sizeof(m_name), "%s", "sta_list");
            m_svc = em_service_type_agent;
            break;

        case em_cmd_type_ap_cap_query:
            snprintf(m_name, sizeof(m_name), "%s", "ap_cap");
            m_svc = em_service_type_agent;
            break;

    	case em_cmd_type_client_cap_query:
	        snprintf(m_name, sizeof(m_name), "%s", "client_cap");
            m_svc = em_service_type_agent;
    	    break;

        case em_cmd_type_start_dpp:
            snprintf(m_name, sizeof(m_name), "%s", "start_dpp");
            m_svc = em_service_type_ctrl;
            break;

        case em_cmd_type_max:
            snprintf(m_name, sizeof(m_name), "%s", "max");
            m_svc = em_service_type_none;
            break;

        case em_cmd_type_topo_sync:
            strncpy(m_name, "topo_sync", strlen("topo_sync") + 1);
            m_svc = em_service_type_ctrl;
            break;

        case em_cmd_type_sta_assoc:
            strncpy(m_name, "sta_assoc", strlen("sta_assoc") + 1);
            m_svc = em_service_type_ctrl;
            break;

        case em_cmd_type_sta_link_metrics:
            strncpy(m_name, "sta_link_metrics", strlen("sta_link_metrics") + 1);
            m_svc = em_service_type_ctrl;
            break;

        case em_cmd_type_sta_steer:
            strncpy(m_name, "sta_steer", strlen("sta_steer") + 1);
            m_svc = em_service_type_ctrl;
            break;

        case em_cmd_type_sta_disassoc:
            strncpy(m_name, "sta_disassoc", strlen("sta_disassoc") + 1);
            m_svc = em_service_type_ctrl;
            break;

        case em_cmd_type_em_config:
            strncpy(m_name, "em_config", strlen("em_config") + 1);
            m_svc = em_service_type_ctrl;
            break;
        
		case em_cmd_type_get_policy:
            strncpy(m_name, "get_policy", strlen("get_policy") + 1);
            m_svc = em_service_type_ctrl;
            break;
		
		case em_cmd_type_set_policy:
            strncpy(m_name, "set_policy", strlen("set_policy") + 1);
            m_svc = em_service_type_ctrl;
            break;
    }
}

const char *em_cmd_t::get_bus_event_type_str(em_bus_event_type_t type)
{
#define BUS_EVENT_TYPE_2S(x) case x: return #x;
    switch (type) { 
    	BUS_EVENT_TYPE_2S(em_bus_event_type_none)
    	BUS_EVENT_TYPE_2S(em_bus_event_type_chirp)
    	BUS_EVENT_TYPE_2S(em_bus_event_type_reset)
    	BUS_EVENT_TYPE_2S(em_bus_event_type_dev_test)
    	BUS_EVENT_TYPE_2S(em_bus_event_type_get_network)
    	BUS_EVENT_TYPE_2S(em_bus_event_type_get_device)
    	BUS_EVENT_TYPE_2S(em_bus_event_type_remove_device)
    	BUS_EVENT_TYPE_2S(em_bus_event_type_get_radio)
    	BUS_EVENT_TYPE_2S(em_bus_event_type_set_radio)
    	BUS_EVENT_TYPE_2S(em_bus_event_type_get_ssid)
    	BUS_EVENT_TYPE_2S(em_bus_event_type_set_ssid)
    	BUS_EVENT_TYPE_2S(em_bus_event_type_get_channel)
    	BUS_EVENT_TYPE_2S(em_bus_event_type_set_channel)
    	BUS_EVENT_TYPE_2S(em_bus_event_type_get_bss)
    	BUS_EVENT_TYPE_2S(em_bus_event_type_get_sta)
    	BUS_EVENT_TYPE_2S(em_bus_event_type_steer_sta)
    	BUS_EVENT_TYPE_2S(em_bus_event_type_disassoc_sta)
    	BUS_EVENT_TYPE_2S(em_bus_event_type_btm_sta)
    	BUS_EVENT_TYPE_2S(em_bus_event_type_start_dpp)
    	BUS_EVENT_TYPE_2S(em_bus_event_type_dev_init)
    	BUS_EVENT_TYPE_2S(em_bus_event_type_cfg_renew)
    	BUS_EVENT_TYPE_2S(em_bus_event_type_radio_config)
    	BUS_EVENT_TYPE_2S(em_bus_event_type_vap_config)
    	BUS_EVENT_TYPE_2S(em_bus_event_type_sta_list)
    	BUS_EVENT_TYPE_2S(em_bus_event_type_listener_stop)
    	BUS_EVENT_TYPE_2S(em_bus_event_type_dm_commit)
    	BUS_EVENT_TYPE_2S(em_bus_event_type_topo_sync)
    	BUS_EVENT_TYPE_2S(em_bus_event_type_get_policy)
    	BUS_EVENT_TYPE_2S(em_bus_event_type_set_policy)
    }
}   

const char *em_cmd_t::get_orch_op_str(dm_orch_type_t type)
{
#define ORCH_TYPE_2S(x) case x: return #x;
    switch (type) {
        ORCH_TYPE_2S(dm_orch_type_none)
        ORCH_TYPE_2S(dm_orch_type_net_insert)
        ORCH_TYPE_2S(dm_orch_type_net_update)
        ORCH_TYPE_2S(dm_orch_type_net_delete)
        ORCH_TYPE_2S(dm_orch_type_al_insert)
        ORCH_TYPE_2S(dm_orch_type_al_update)
        ORCH_TYPE_2S(dm_orch_type_al_delete)
        ORCH_TYPE_2S(dm_orch_type_em_insert)
        ORCH_TYPE_2S(dm_orch_type_em_update)
        ORCH_TYPE_2S(dm_orch_type_em_delete)
        ORCH_TYPE_2S(dm_orch_type_em_test)
        ORCH_TYPE_2S(dm_orch_type_bss_insert)
        ORCH_TYPE_2S(dm_orch_type_bss_update)
        ORCH_TYPE_2S(dm_orch_type_bss_delete)
        ORCH_TYPE_2S(dm_orch_type_ssid_insert)
        ORCH_TYPE_2S(dm_orch_type_ssid_update)
        ORCH_TYPE_2S(dm_orch_type_ssid_delete)
        ORCH_TYPE_2S(dm_orch_type_sta_insert)
        ORCH_TYPE_2S(dm_orch_type_sta_update)
        ORCH_TYPE_2S(dm_orch_type_sta_delete)
        ORCH_TYPE_2S(dm_orch_type_sec_insert)
        ORCH_TYPE_2S(dm_orch_type_sec_update)
        ORCH_TYPE_2S(dm_orch_type_sec_delete)
        ORCH_TYPE_2S(dm_orch_type_cap_insert)
        ORCH_TYPE_2S(dm_orch_type_cap_update)
        ORCH_TYPE_2S(dm_orch_type_cap_delete)
        ORCH_TYPE_2S(dm_orch_type_op_class_insert)
        ORCH_TYPE_2S(dm_orch_type_op_class_update)
        ORCH_TYPE_2S(dm_orch_type_op_class_delete)
        ORCH_TYPE_2S(dm_orch_type_ssid_vid_insert)
        ORCH_TYPE_2S(dm_orch_type_ssid_vid_update)
        ORCH_TYPE_2S(dm_orch_type_ssid_vid_delete)
        ORCH_TYPE_2S(dm_orch_type_dpp_insert)
        ORCH_TYPE_2S(dm_orch_type_dpp_update)
        ORCH_TYPE_2S(dm_orch_type_dpp_delete)
        ORCH_TYPE_2S(dm_orch_type_em_reset)
        ORCH_TYPE_2S(dm_orch_type_db_reset)
        ORCH_TYPE_2S(dm_orch_type_db_cfg)
        ORCH_TYPE_2S(dm_orch_type_db_insert)
        ORCH_TYPE_2S(dm_orch_type_db_update)
        ORCH_TYPE_2S(dm_orch_type_db_delete)
        ORCH_TYPE_2S(dm_orch_type_dm_delete)
        ORCH_TYPE_2S(dm_orch_type_tx_cfg_renew)
        ORCH_TYPE_2S(dm_orch_type_owconfig_req)
        ORCH_TYPE_2S(dm_orch_type_owconfig_cnf)
        ORCH_TYPE_2S(dm_orch_type_ctrl_notify)
        ORCH_TYPE_2S(dm_orch_type_ap_cap_report)
        ORCH_TYPE_2S(dm_orch_type_client_cap_report)
        ORCH_TYPE_2S(dm_orch_type_net_ssid_update)
        ORCH_TYPE_2S(dm_orch_type_topo_sync)
        ORCH_TYPE_2S(dm_orch_type_channel_pref)
        ORCH_TYPE_2S(dm_orch_type_channel_sel)
        ORCH_TYPE_2S(dm_orch_type_channel_cnf)
        ORCH_TYPE_2S(dm_orch_type_channel_sel_resp)
        ORCH_TYPE_2S(dm_orch_type_channel_scan_req)
        ORCH_TYPE_2S(dm_orch_type_channel_scan_res)
        ORCH_TYPE_2S(dm_orch_type_sta_cap)
        ORCH_TYPE_2S(dm_orch_type_sta_link_metrics)
        ORCH_TYPE_2S(dm_orch_type_op_channel_report)
        ORCH_TYPE_2S(dm_orch_type_sta_steer)
        ORCH_TYPE_2S(dm_orch_type_sta_steer_btm_report)
        ORCH_TYPE_2S(dm_orch_type_sta_disassoc)
        ORCH_TYPE_2S(dm_orch_type_policy_cfg)
    }

    return "dm_orch_type_unknown";
}

const char *em_cmd_t::get_cmd_type_str(em_cmd_type_t type)
{
#define CMD_TYPE_2S(x) case x: return #x;
    switch (type) {
        CMD_TYPE_2S(em_cmd_type_none)
        CMD_TYPE_2S(em_cmd_type_reset)
        CMD_TYPE_2S(em_cmd_type_get_network)
        CMD_TYPE_2S(em_cmd_type_get_device)
        CMD_TYPE_2S(em_cmd_type_remove_device)
        CMD_TYPE_2S(em_cmd_type_get_radio)
        CMD_TYPE_2S(em_cmd_type_set_radio)
        CMD_TYPE_2S(em_cmd_type_get_ssid)
        CMD_TYPE_2S(em_cmd_type_set_ssid)
        CMD_TYPE_2S(em_cmd_type_get_channel)
        CMD_TYPE_2S(em_cmd_type_set_channel)
        CMD_TYPE_2S(em_cmd_type_scan_channel)
        CMD_TYPE_2S(em_cmd_type_scan_result)
        CMD_TYPE_2S(em_cmd_type_get_bss)
        CMD_TYPE_2S(em_cmd_type_get_sta)
        CMD_TYPE_2S(em_cmd_type_steer_sta)
        CMD_TYPE_2S(em_cmd_type_disassoc_sta)
        CMD_TYPE_2S(em_cmd_type_btm_sta)
        CMD_TYPE_2S(em_cmd_type_dev_init)
        CMD_TYPE_2S(em_cmd_type_dev_test)
        CMD_TYPE_2S(em_cmd_type_cfg_renew)
        CMD_TYPE_2S(em_cmd_type_vap_config)
        CMD_TYPE_2S(em_cmd_type_sta_list)
        CMD_TYPE_2S(em_cmd_type_start_dpp)
        CMD_TYPE_2S(em_cmd_type_ap_cap_query)
        CMD_TYPE_2S(em_cmd_type_client_cap_query)
        CMD_TYPE_2S(em_cmd_type_topo_sync)
        CMD_TYPE_2S(em_cmd_type_em_config)
        CMD_TYPE_2S(em_cmd_type_sta_assoc)
        CMD_TYPE_2S(em_cmd_type_channel_pref_query)
        CMD_TYPE_2S(em_cmd_type_sta_link_metrics)
        CMD_TYPE_2S(em_cmd_type_sta_steer)
        CMD_TYPE_2S(em_cmd_type_btm_report)
        CMD_TYPE_2S(em_cmd_type_sta_disassoc)
        CMD_TYPE_2S(em_cmd_type_get_policy)
        CMD_TYPE_2S(em_cmd_type_set_policy)
    }

    return "em_cmd_type_unknown";
}

em_cmd_type_t em_cmd_t::bus_2_cmd_type(em_bus_event_type_t etype)
{
    em_cmd_type_t type = em_cmd_type_none;

    switch (etype) {
        case em_bus_event_type_reset:
            type = em_cmd_type_reset;
            break;

        case em_bus_event_type_dev_test:
            type = em_cmd_type_dev_test;
            break;

        case em_bus_event_type_get_network:
            type = em_cmd_type_get_network;
            break;

        case em_bus_event_type_get_device:
            type = em_cmd_type_get_device;
            break;

        case em_bus_event_type_remove_device:
            type = em_cmd_type_remove_device;
            break;

        case em_bus_event_type_get_radio:
            type = em_cmd_type_get_radio;
            break;

        case em_bus_event_type_set_radio:
            type = em_cmd_type_set_radio;
            break;

        case em_bus_event_type_set_ssid:
            type = em_cmd_type_set_ssid;
            break;

        case em_bus_event_type_get_ssid:
            type = em_cmd_type_get_ssid;
            break;

        case em_bus_event_type_set_channel:
            type = em_cmd_type_set_channel;
            break;

        case em_bus_event_type_get_channel:
            type = em_cmd_type_get_channel;
            break;

        case em_bus_event_type_scan_channel:
            type = em_cmd_type_scan_channel;
            break;

        case em_bus_event_type_scan_result:
            type = em_cmd_type_scan_result;
            break;

        case em_bus_event_type_get_bss:
            type = em_cmd_type_get_bss;
            break;

        case em_bus_event_type_get_sta:
            type = em_cmd_type_get_sta;
            break;

        case em_bus_event_type_steer_sta:
            type = em_cmd_type_steer_sta;
            break;

        case em_bus_event_type_disassoc_sta:
            type = em_cmd_type_disassoc_sta;
            break;

        case em_bus_event_type_get_policy:
            type = em_cmd_type_get_policy;
            break;

        case em_bus_event_type_set_policy:
            type = em_cmd_type_set_policy;
            break;

        case em_bus_event_type_btm_sta:
            type = em_cmd_type_btm_sta;
            break;

        case em_bus_event_type_dev_init:
            type = em_cmd_type_dev_init;
            break;

        case em_bus_event_type_cfg_renew:
            type = em_cmd_type_cfg_renew;
            break;			

        case em_bus_event_type_sta_list:
            type = em_cmd_type_sta_list;
            break;

        case em_bus_event_type_ap_cap_query:
            type = em_cmd_type_ap_cap_query;
            break;

	    case em_bus_event_type_client_cap_query:
	        type = em_cmd_type_client_cap_query;
	        break;

        case em_bus_event_type_topo_sync:
            type = em_cmd_type_em_config;
            break;

    }

    return type;
}

em_bus_event_type_t em_cmd_t::cmd_2_bus_event_type(em_cmd_type_t ctype)
{
    em_bus_event_type_t type = em_bus_event_type_none;

    switch (ctype) {
        case em_cmd_type_reset:
            type = em_bus_event_type_reset;
            break;

        case em_cmd_type_dev_test:
            type = em_bus_event_type_dev_test;
            break;

        case em_cmd_type_set_ssid:
            type = em_bus_event_type_set_ssid;;
            break;

        case em_cmd_type_em_config:
            type = em_bus_event_type_topo_sync;;
            break;

        case em_cmd_type_dev_init:
            type = em_bus_event_type_dev_init;
            break;

        case em_cmd_type_cfg_renew:
            type = em_bus_event_type_cfg_renew;
            break;

        case em_cmd_type_sta_list:
            type = em_bus_event_type_sta_list;
            break;
    }

    return type;
}

void em_cmd_t::dump_bus_event(em_bus_event_t *evt)
{
    em_cmd_params_t *params;
    unsigned int i;
    em_subdoc_info_t *info;

    printf("Bus Event\n");
    params = &evt->params;

    switch (evt->type) {
        case em_bus_event_type_get_network:
        case em_bus_event_type_get_device:
        case em_bus_event_type_remove_device:
        case em_bus_event_type_get_radio:
        case em_bus_event_type_get_ssid:
        case em_bus_event_type_get_channel:
        case em_bus_event_type_get_bss:
        case em_bus_event_type_get_sta:
            info = &evt->u.subdoc;
            printf("Name: %s\n", info->name);
            break;
    }

    printf("Type: %s\tNumber of Command Parameters: %d\n", get_bus_event_type_str(evt->type), params->u.args.num_args);
    for (i = 0; i < params->u.args.num_args; i++) {
        printf("Arg[%d]: %s\n", i, params->u.args.args[i]);
    }   
}   

em_cmd_t::em_cmd_t(em_cmd_type_t type, em_cmd_params_t param, dm_easy_mesh_t& dm) : m_evt(NULL)
{
    m_type = type;
    m_db_cfg_type = db_cfg_type_none;
    memcpy(&m_param, &param, sizeof(em_cmd_params_t));
    init(&dm);
    init();
}

em_cmd_t::em_cmd_t(em_cmd_type_t type, em_cmd_params_t param) : m_evt(NULL)
{
    m_type = type;
    m_db_cfg_type = db_cfg_type_none;
    memcpy(&m_param, &param, sizeof(em_cmd_params_t));
    init();
}

em_cmd_t::em_cmd_t() : m_evt(NULL)
{
	m_evt = (em_event_t *)malloc(sizeof(em_event_t) + EM_MAX_EVENT_DATA_LEN);
}

em_cmd_t::~em_cmd_t()
{
	free(m_evt);	
}

