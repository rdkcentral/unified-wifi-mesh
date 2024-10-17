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

em_agent_t g_agent;
const char *global_netid = "OneWifiMesh";

void em_agent_t::handle_sta_list(em_bus_event_t *evt)
{
    em_cmd_t *pcmd[EM_MAX_CMD] = {NULL};
    unsigned int num;

    if (m_orch->is_cmd_type_in_progress(evt->type) == true) {
        m_agent_cmd->send_result(em_cmd_out_status_prev_cmd_in_progress);
    } else if ((num = m_data_model.analyze_sta_list(evt, pcmd)) == 0) {
        m_agent_cmd->send_result(em_cmd_out_status_no_change);
    } else if (m_orch->submit_commands(pcmd, num) > 0) {
        m_agent_cmd->send_result(em_cmd_out_status_success);
    } else {
        m_agent_cmd->send_result(em_cmd_out_status_not_ready);
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


void em_agent_t::handle_client_cap_query(em_bus_event_t *evt)
{
    em_cmd_t *pcmd[EM_MAX_CMD] = {NULL};
    unsigned int num;

    if (m_orch->is_cmd_type_in_progress(evt->type) == true) {
        m_agent_cmd->send_result(em_cmd_out_status_prev_cmd_in_progress);
    } else if ((num = m_data_model.analyze_client_cap_query(evt, pcmd)) == 0) {
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

void em_agent_t::handle_onewifi_private_subdoc(em_bus_event_t *evt)
{
    unsigned int num;
    wifi_bus_desc_t *desc;
    raw_data_t l_bus_data;

    if((desc = get_bus_descriptor()) == NULL) {
       printf("descriptor is null");
    }

    if (m_orch->is_cmd_type_in_progress(evt->type) == true) {
        m_agent_cmd->send_result(em_cmd_out_status_prev_cmd_in_progress);
    } else if ((num = m_data_model.analyze_onewifi_private_subdoc(evt, desc, &m_bus_hdl)) == 0) {
        //m_agent_cmd->send_result(em_cmd_out_status_no_change);
	printf("analyze_onewifi_private_subdoc complete");
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
        m_agent_cmd->send_result(em_cmd_out_status_prev_cmd_in_progress);
    } else if ((num = m_data_model.analyze_autoconfig_renew(evt, pcmd)) == 0) {
        m_agent_cmd->send_result(em_cmd_out_status_no_change);
    } else if (m_orch->submit_commands(pcmd, num) > 0) {
        m_agent_cmd->send_result(em_cmd_out_status_success);
    } else {
        m_agent_cmd->send_result(em_cmd_out_status_not_ready);
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

        case em_bus_event_type_client_cap_query:
	        handle_client_cap_query(evt);
	        break;

        case em_bus_event_type_onewifi_private_subdoc:
			handle_onewifi_private_subdoc(evt);
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

void em_agent_t::handle_timeout()
{
    m_orch->handle_timeout();
}

void em_agent_t::input_listener()
{
    wifi_bus_desc_t *desc;
    dm_easy_mesh_t dm;
    em_event_t evt;
    em_bus_event_t *bevt;
    raw_data_t data;

    bus_init(&m_bus_hdl);

    if((desc = get_bus_descriptor()) == NULL) {
        printf("%s:%d descriptor is null\n", __func__, __LINE__);
    }

    if (desc->bus_open_fn(&m_bus_hdl, "EasyMesh_service") != 0) {
        printf("%s:%d bus open failed\n",__func__, __LINE__);
        return;
    }

    printf("%s:%d he_bus open success\n", __func__, __LINE__);

    memset(&data, 0, sizeof(raw_data_t));

    if (desc->bus_get_fn(&m_bus_hdl, WIFI_WEBCONFIG_INIT_DML_DATA, &data) != 0) {
        printf("%s:%d bus get failed\n", __func__, __LINE__);
        return;
    } else {
        printf("%s:%d recv data:\r\n%s\r\n", __func__, __LINE__, (char *)data.raw_data.bytes);
    }

    bevt = &evt.u.bevt;
    bevt->type = em_bus_event_type_dev_init;
    memcpy(bevt->u.raw_buff, data.raw_data.bytes, data.raw_data_len);

    g_agent.agent_input(&evt);

    printf("%s:%d: Enter\n", __func__, __LINE__);
    if (desc->bus_event_subs_fn(&m_bus_hdl, WIFI_WEBCONFIG_GET_ASSOC, (void *)&em_agent_t::sta_cb, NULL, 0) != 0) {
        printf("%s:%d bus get failed\n", __func__, __LINE__);
        return;
    }
    io(NULL);
}

int em_agent_t::sta_cb(char *event_name, raw_data_t *data)
{
    printf("%s:%d Recv data from onewifi:\r\n%s\r\n", __func__, __LINE__, (char *)data->raw_data.bytes);
    em_event_t evt;
    em_bus_event_t *bevt;

    bevt = &evt.u.bevt;
    bevt->type = em_bus_event_type_sta_list;
    memcpy(bevt->u.raw_buff, data->raw_data.bytes, data->raw_data_len);

    g_agent.agent_input(&evt);

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
    em_radio_id_t ruid;
    em_profile_type_t profile;
    mac_addr_str_t mac_str1, mac_str2;
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
            	if (em->is_matching_freq_band(&band) == true) {
                	found = true;
                	break;
            	}
            	em = (em_t *)hash_map_get_next(m_em_map, em);
        	}  

        	if (found == false) {
            	printf("%s:%d: Could not find em with matching band%d\n", __func__, __LINE__, band);
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
            	em->set_state(em_state_ctrl_wsc_m1_pending);
        	} else {
				return NULL;
			}
			break;

        case em_msg_type_autoconf_search:
        case em_msg_type_topo_query:
            break;

		default:
            printf("%s:%d: Frame: %d not handled in agent\n", __func__, __LINE__, htons(cmdu->type));
            assert(0);
            break;	
	}

	return em;
}

em_agent_t::em_agent_t()
{

}

em_agent_t::~em_agent_t()
{

}

int main(int argc, const char *argv[])
{
    if (g_agent.init(argv[1]) == 0) {
        g_agent.start();
    }

    return 0;
}

