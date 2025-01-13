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
        printf("analyze_sta_list in progress\n");
    } else if ((num = m_data_model.analyze_sta_list(evt, pcmd)) == 0) {
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
    } else if ((num = m_data_model.analyze_onewifi_private_cb(evt, pcmd)) == 0) {
        printf("analyze_onewifi_private_cb completed\n");
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

    if (desc->bus_data_get_fn(&m_bus_hdl, WIFI_WEBCONFIG_INIT_DML_DATA, &data) != 0) {
        printf("%s:%d bus get failed\n", __func__, __LINE__);
        return;
    } else {
        printf("%s:%d recv data:\r\n%s\r\n", __func__, __LINE__, (char *)data.raw_data.bytes);
    }

    g_agent.io_process(em_bus_event_type_dev_init, (unsigned char *)data.raw_data.bytes, data.raw_data_len);

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

    io(NULL);
}

int em_agent_t::mgmt_action_frame_cb(char *event_name, raw_data_t *data)
{
    struct ieee80211_mgmt *btm_frame = (struct ieee80211_mgmt *)data->raw_data.bytes;

    //printf("Received Frame data for event %s \n", event_name);
    if (btm_frame->u.action.u.bss_tm_resp.action == WLAN_WNM_BTM_RESPONSE) {
        g_agent.io_process(em_bus_event_type_btm_response, (unsigned char *)data->raw_data.bytes, data->raw_data_len);

        return 1;
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

int em_agent_t::sta_cb(char *event_name, raw_data_t *data)
{
    //printf("%s:%d Recv data from onewifi:\r\n%s\r\n", __func__, __LINE__, (char *)data->raw_data.bytes);
    g_agent.io_process(em_bus_event_type_sta_list, (unsigned char *)data->raw_data.bytes, data->raw_data_len);

}

int em_agent_t::onewifi_cb(char *event_name, raw_data_t *data)
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
				return 0;
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
    em_radio_id_t ruid;
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
                        }
                    }
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
        case em_msg_type_topo_resp:
        case em_msg_type_topo_query:
            em = (em_t *)hash_map_get_first(m_em_map);

            while (em != NULL) {
                if (!(em->is_al_interface_em())) {
                    if (em->get_state() == em_state_agent_onewifi_bssconfig_ind) {
                        break;
                    }
                }
                em = (em_t *)hash_map_get_next(m_em_map, em);
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
		
        case em_msg_type_channel_pref_rprt:
            printf("%s:%d:Received channel preference report\n",__func__, __LINE__);
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
            printf("%s:%d: Sending Operating Channel report\n", __func__, __LINE__);
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

        case em_msg_type_1905_ack:
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

