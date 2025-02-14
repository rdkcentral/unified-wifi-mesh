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

em_ctrl_t g_ctrl;
const char *global_netid = "OneWifiMesh";


void em_ctrl_t::handle_dm_commit(em_bus_event_t *evt)
{
    em_commit_info_t *info;
    mac_addr_str_t  mac_str;
    dm_easy_mesh_t *dm;

    info = &evt->u.commit;

    dm_easy_mesh_t::macbytes_to_string(info->mac, mac_str);
    dm = m_data_model.get_data_model(info->net_id, info->mac);
    if (dm != NULL) {
        printf("%s:%d: commiting data model mac: %s network: %s \n", __func__, __LINE__, mac_str, info->net_id);
        m_data_model.set_config(dm);
    }
}

void em_ctrl_t::handle_client_steer(em_bus_event_t *evt)
{
    em_cmd_t *pcmd[EM_MAX_CMD] = {NULL};
    unsigned int num;

    if (m_orch->is_cmd_type_in_progress(evt->type) == true) {
        m_ctrl_cmd->send_result(em_cmd_out_status_prev_cmd_in_progress);
    } else if ((num = m_data_model.analyze_command_steer(evt, pcmd)) == 0) {
        m_ctrl_cmd->send_result(em_cmd_out_status_no_change);
    } else if (m_orch->submit_commands(pcmd, num) > 0) {
        m_ctrl_cmd->send_result(em_cmd_out_status_success);
    } else {
        m_ctrl_cmd->send_result(em_cmd_out_status_not_ready);
    }
}

void em_ctrl_t::handle_client_disassoc(em_bus_event_t *evt)
{
    em_cmd_t *pcmd[EM_MAX_CMD] = {NULL};
    unsigned int num;

    if (m_orch->is_cmd_type_in_progress(evt->type) == true) {
        m_ctrl_cmd->send_result(em_cmd_out_status_prev_cmd_in_progress);
    } else if ((num = m_data_model.analyze_command_disassoc(evt, pcmd)) == 0) {
        m_ctrl_cmd->send_result(em_cmd_out_status_no_change);
    } else if (m_orch->submit_commands(pcmd, num) > 0) {
        m_ctrl_cmd->send_result(em_cmd_out_status_success);
    } else {
        m_ctrl_cmd->send_result(em_cmd_out_status_not_ready);
    }
}

void em_ctrl_t::handle_client_btm(em_bus_event_t *evt)
{
    em_cmd_t *pcmd[EM_MAX_CMD] = {NULL};
    unsigned int num;

    if (m_orch->is_cmd_type_in_progress(evt->type) == true) {
        m_ctrl_cmd->send_result(em_cmd_out_status_prev_cmd_in_progress);
    } else if ((num = m_data_model.analyze_command_btm(evt, pcmd)) == 0) {
        m_ctrl_cmd->send_result(em_cmd_out_status_no_change);
    } else if (m_orch->submit_commands(pcmd, num) > 0) {
        m_ctrl_cmd->send_result(em_cmd_out_status_success);
    } else {
        m_ctrl_cmd->send_result(em_cmd_out_status_not_ready);
    }
}

void em_ctrl_t::handle_start_dpp(em_bus_event_t *evt)
{
    em_cmd_t *pcmd[EM_MAX_CMD] = {NULL};
    unsigned int num;

    if (m_orch->is_cmd_type_in_progress(evt->type) == true) {
        m_ctrl_cmd->send_result(em_cmd_out_status_prev_cmd_in_progress);
    } else if ((num = m_data_model.analyze_dpp_start(evt, pcmd)) == 0) {
        m_ctrl_cmd->send_result(em_cmd_out_status_no_change);
    } else if (m_orch->submit_commands(pcmd, num) > 0) {
        m_ctrl_cmd->send_result(em_cmd_out_status_success);
    } else {
        m_ctrl_cmd->send_result(em_cmd_out_status_not_ready);
    } 

}

void em_ctrl_t::handle_set_channel_list(em_bus_event_t *evt)
{
    em_cmd_t *pcmd[EM_MAX_CMD] = {NULL};
    unsigned int num;

    if (m_orch->is_cmd_type_in_progress(evt->type) == true) {
        m_ctrl_cmd->send_result(em_cmd_out_status_prev_cmd_in_progress);
    } else if ((num = m_data_model.analyze_set_channel(evt, pcmd)) == 0) {
        m_ctrl_cmd->send_result(em_cmd_out_status_no_change);
    } else if (m_orch->submit_commands(pcmd, num) > 0) {
        m_ctrl_cmd->send_result(em_cmd_out_status_success);
    } else {
        m_ctrl_cmd->send_result(em_cmd_out_status_not_ready);
    } 

}

void em_ctrl_t::handle_scan_channel_list(em_bus_event_t *evt)
{
    em_cmd_t *pcmd[EM_MAX_CMD] = {NULL};
    unsigned int num;

    if (m_orch->is_cmd_type_in_progress(evt->type) == true) {
        m_ctrl_cmd->send_result(em_cmd_out_status_prev_cmd_in_progress);
    } else if ((num = m_data_model.analyze_scan_channel(evt, pcmd)) == 0) {
        m_ctrl_cmd->send_result(em_cmd_out_status_no_change);
    } else if (m_orch->submit_commands(pcmd, num) > 0) {
        m_ctrl_cmd->send_result(em_cmd_out_status_success);
    } else {
        m_ctrl_cmd->send_result(em_cmd_out_status_not_ready);
    } 

}

void em_ctrl_t::handle_set_policy(em_bus_event_t *evt)
{
    em_cmd_t *pcmd[EM_MAX_CMD] = {NULL};
    unsigned int num;

    if (m_orch->is_cmd_type_in_progress(evt->type) == true) {
        m_ctrl_cmd->send_result(em_cmd_out_status_prev_cmd_in_progress);
    } else if ((num = m_data_model.analyze_set_policy(evt, pcmd)) == 0) {
        m_ctrl_cmd->send_result(em_cmd_out_status_no_change);
    } else if (m_orch->submit_commands(pcmd, num) > 0) {
        m_ctrl_cmd->send_result(em_cmd_out_status_success);
    } else {
        m_ctrl_cmd->send_result(em_cmd_out_status_not_ready);
    } 

}

void em_ctrl_t::handle_config_renew(em_bus_event_t *evt)
{
    em_cmd_t *pcmd[EM_MAX_CMD] = {NULL};
    unsigned int num;
    
    if ((num = m_data_model.analyze_config_renew(evt, pcmd)) > 0) {
        m_orch->submit_commands(pcmd, num);
    }
}

void em_ctrl_t::handle_m2_tx(em_bus_event_t *evt)
{
    em_cmd_t *pcmd[EM_MAX_CMD] = {NULL};
    unsigned int num;
    
    if ((num = m_data_model.analyze_m2_tx(evt, pcmd)) > 0) {
        m_orch->submit_commands(pcmd, num);
    }
}

void em_ctrl_t::handle_sta_assoc_event(em_bus_event_t *evt)
{
    em_cmd_t *pcmd[EM_MAX_CMD] = {NULL};
    unsigned int num;
    
    if ((num = m_data_model.analyze_sta_assoc_event(evt, pcmd)) > 0) {
        m_orch->submit_commands(pcmd, num);
    }
}

void em_ctrl_t::handle_set_radio(em_bus_event_t *evt)
{
    em_cmd_t *pcmd[EM_MAX_CMD] = {NULL};
    unsigned int num;

    if (m_orch->is_cmd_type_in_progress(evt->type) == true) {
        m_ctrl_cmd->send_result(em_cmd_out_status_prev_cmd_in_progress);
    } else if ((num = m_data_model.analyze_set_radio(evt, pcmd)) == 0) {
        m_ctrl_cmd->send_result(em_cmd_out_status_no_change);
    } else if (m_orch->submit_commands(pcmd, num) > 0) {
        m_ctrl_cmd->send_result(em_cmd_out_status_success);
    } else {
        m_ctrl_cmd->send_result(em_cmd_out_status_not_ready);
    } 
}

void em_ctrl_t::handle_set_ssid_list(em_bus_event_t *evt)
{
    em_cmd_t *pcmd[EM_MAX_CMD] = {NULL};
    unsigned int num;
    int ret;

    if (m_orch->is_cmd_type_in_progress(evt->type) == true) {
        m_ctrl_cmd->send_result(em_cmd_out_status_prev_cmd_in_progress);
    } else if ((ret = m_data_model.analyze_set_ssid(evt, pcmd)) <= 0) {
        if (ret == EM_PARSE_ERR_NO_CHANGE) {
        	m_ctrl_cmd->send_result(em_cmd_out_status_no_change);
		} else {
        	m_ctrl_cmd->send_result(em_cmd_out_status_invalid_input);
		}
    } else if (m_orch->submit_commands(pcmd, num = ret) > 0) {
        m_ctrl_cmd->send_result(em_cmd_out_status_success);
    } else {
        m_ctrl_cmd->send_result(em_cmd_out_status_not_ready);
    } 

}

void em_ctrl_t::handle_remove_device(em_bus_event_t *evt)
{
    em_cmd_t *pcmd[EM_MAX_CMD] = {NULL};
    unsigned int num;

    if (m_orch->is_cmd_type_in_progress(evt->type) == true) {
        m_ctrl_cmd->send_result(em_cmd_out_status_prev_cmd_in_progress);
    } else if ((num = m_data_model.analyze_remove_device(evt, pcmd)) == 0) {
        m_ctrl_cmd->send_result(em_cmd_out_status_no_change);
    } else if (m_orch->submit_commands(pcmd, num) > 0) {
        m_ctrl_cmd->send_result(em_cmd_out_status_success);
    } else {
        m_ctrl_cmd->send_result(em_cmd_out_status_not_ready);
    } 

}

void em_ctrl_t::handle_get_dm_data(em_bus_event_t *evt)
{           
    em_cmd_params_t *params = &evt->params;
        
    //em_cmd_t::dump_bus_event(evt);
    if (params->u.args.num_args < 1) {
        m_ctrl_cmd->send_result(em_cmd_out_status_invalid_input);
        return;
    }

    m_data_model.get_config(params->u.args.args[1], &evt->u.subdoc);
	evt->data_len = strlen(evt->u.subdoc.buff) + 1;
    m_ctrl_cmd->copy_bus_event(evt);
    m_ctrl_cmd->send_result(em_cmd_out_status_success);
}        

void em_ctrl_t::handle_dev_test(em_bus_event_t *evt)
{
    em_cmd_t *pcmd[EM_MAX_CMD] = {NULL};
    unsigned int num = 0;

    if (m_orch->is_cmd_type_in_progress(evt->type) == true) {
        m_ctrl_cmd->send_result(em_cmd_out_status_prev_cmd_in_progress);
    } else if ((num = m_data_model.analyze_dev_test(evt, pcmd)) == 0) {
        m_ctrl_cmd->send_result(em_cmd_out_status_no_change);
    } else if (m_orch->submit_commands(pcmd, num) > 0) {
        m_ctrl_cmd->send_result(em_cmd_out_status_success);
    } else {
        m_ctrl_cmd->send_result(em_cmd_out_status_not_ready);
    }
}

void em_ctrl_t::handle_reset(em_bus_event_t *evt)
{
    em_cmd_t *pcmd[EM_MAX_CMD] = {NULL};
    unsigned int num = 0;
	
    if (m_orch->is_cmd_type_in_progress(evt->type) == true) {
        m_ctrl_cmd->send_result(em_cmd_out_status_prev_cmd_in_progress);
    } else if ((num = m_data_model.analyze_reset(evt, pcmd)) == 0) {
        m_ctrl_cmd->send_result(em_cmd_out_status_no_change);
    } else if (m_orch->submit_commands(pcmd, num) > 0) {
        m_ctrl_cmd->send_result(em_cmd_out_status_success);
    } else {
        m_ctrl_cmd->send_result(em_cmd_out_status_not_ready);
    }

}

void em_ctrl_t::handle_mld_reconfig(em_bus_event_t *evt)
{
    em_cmd_t *pcmd[EM_MAX_CMD] = {NULL};
    unsigned int num;

    if (m_orch->is_cmd_type_in_progress(evt->type) == true) {
        m_ctrl_cmd->send_result(em_cmd_out_status_prev_cmd_in_progress);
    } else if ((num = m_data_model.analyze_mld_reconfig(pcmd)) == 0) {
        m_ctrl_cmd->send_result(em_cmd_out_status_no_change);
    } else if (m_orch->submit_commands(pcmd, num) > 0) {
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

void em_ctrl_t::handle_client_metrics_req()
{
    em_cmd_t *pcmd[EM_MAX_CMD] = {NULL};
    unsigned int num;

    if ((num = m_data_model.analyze_sta_link_metrics(pcmd)) > 0) {
        m_orch->submit_commands(pcmd, num);
    }
}

void em_ctrl_t::handle_dirty_dm()
{
	m_data_model.handle_dirty_dm();
}

void em_ctrl_t::handle_5s_tick()
{
	handle_client_metrics_req();
}

void em_ctrl_t::handle_2s_tick()
{

}

void em_ctrl_t::handle_1s_tick()
{

}

void em_ctrl_t::handle_500ms_tick()
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

void em_ctrl_t::handle_bus_event(em_bus_event_t *evt)
{

    switch (evt->type) {
        case em_bus_event_type_reset:
            handle_reset(evt);
            break;

        case em_bus_event_type_dev_test:
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

        default:
            break;
    }

}

int em_ctrl_t::data_model_init(const char *data_model_path)
{
    em_t *em = NULL;
    em_interface_t *intf;
    dm_easy_mesh_t *dm;
    mac_addr_str_t  mac_str;

    m_ctrl_cmd = new em_cmd_ctrl_t();
    m_ctrl_cmd->init();
    
    if (m_data_model.init(data_model_path, this) != 0) {
        printf("%s:%d: data model init failed\n", __func__, __LINE__);
        return 0;
    }

    intf = m_data_model.get_ctrl_al_interface((char *)global_netid);
    dm_easy_mesh_t::macbytes_to_string((unsigned char *)intf->mac, mac_str);

    if ((dm = get_data_model(global_netid, intf->mac)) == NULL) {
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
    em_long_string_t key;
    unsigned int i;
    bool found;
    mac_addr_str_t mac_str1, mac_str2, dev_mac_str, radio_mac_str, bss_mac_str;

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
        case em_msg_type_autoconf_search:
            if (em_msg_t(data + (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t)), len - (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t))).get_freq_band(&band) == false) {
                return NULL;
            }

            if (em_msg_t(data + (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t)), len - (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t))).get_al_mac_address(intf.mac) == false) {
                return NULL;
            }

            dm_easy_mesh_t::macbytes_to_string(intf.mac, mac_str1);
            printf("%s:%d: Received autoconfig search from agenti al mac: %s\n", __func__, __LINE__, mac_str1);
            if ((dm = get_data_model((const char *)global_netid, (const unsigned char *)intf.mac)) == NULL) {
                if (em_msg_t(data + (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t)), len - (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t))).get_profile(&profile) == false) {
                    profile = em_profile_type_1;
                }
                dm = create_data_model((const char *)global_netid, (const em_interface_t *)&intf, profile);
                printf("%s:%d: Created data model for mac: %s net: %s\n", __func__, __LINE__, mac_str1, global_netid);
            } else {
                dm_easy_mesh_t::macbytes_to_string(dm->get_agent_al_interface_mac(), mac_str1);
                printf("%s:%d: Found existing data model for mac: %s net: %s\n", __func__, __LINE__, mac_str1, global_netid);
            }
            em = al_em;
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
                if ((dm = get_data_model((const char *)global_netid, (const unsigned char *)hdr->src)) == NULL) {
                    printf("%s:%d: Can not find data model\n", __func__, __LINE__);
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

        case em_msg_type_topo_resp:
        case em_msg_type_channel_pref_rprt:
        case em_msg_type_channel_sel_rsp:
        case em_msg_type_op_channel_rprt:
            if (em_msg_t(data + (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t)),
                    len - (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t))).get_radio_id(&ruid) == false) {
                printf("%s:%d: Could not find radio id in msg:0x%04x\n", __func__, __LINE__, htons(cmdu->type));
                return NULL;
            }

            dm_easy_mesh_t::macbytes_to_string(ruid, mac_str1);
            if ((em = (em_t *)hash_map_get(m_em_map, mac_str1)) == NULL) {
                printf("%s:%d: Could not find radio:%s\n", __func__, __LINE__, mac_str1);
                return NULL;
            }
            break;

        case em_msg_type_topo_notif:
        case em_msg_type_client_cap_rprt:
            if (em_msg_t(data + (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t)),
                    len - (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t))).get_bss_id(&bssid) == false) {
                printf("%s:%d: Could not find bss id in msg:0x%04x\n", __func__, __LINE__, htons(cmdu->type));
                return NULL;
            }

            if ((dm = get_data_model((const char *)global_netid, (const unsigned char *)hdr->src)) == NULL) {
                printf("%s:%d: Can not find data model\n", __func__, __LINE__);
            }
            for (i = 0; i < dm->get_num_radios(); i++) {
                found = true;
                dm_easy_mesh_t::macbytes_to_string((unsigned char *)dm->get_radio_info(i)->id.dev_mac, dev_mac_str);
                dm_easy_mesh_t::macbytes_to_string((unsigned char *)dm->get_radio_info(i)->id.ruid, radio_mac_str);
                dm_easy_mesh_t::macbytes_to_string(bssid, mac_str1);
    
                snprintf(key, sizeof (em_long_string_t), "%s@%s@%s@%s@", dm->get_radio_info(i)->id.net_id, dev_mac_str, radio_mac_str, mac_str1);

                if ((bss = m_data_model.get_bss(key)) == NULL) {
                    found = false;
                    continue;
                }
                break;
            }

            if (found == false) {
                printf("%s:%d: Could not find bss:%s from data model\n", __func__, __LINE__, mac_str1);
                return NULL;
            }
              
            dm_easy_mesh_t::macbytes_to_string(bss->m_bss_info.ruid.mac, mac_str1);
            if ((em = (em_t *)hash_map_get(m_em_map, mac_str1)) == NULL) {
                printf("%s:%d: Could not find radio:%s\n", __func__, __LINE__, mac_str1);
                return NULL;
            }

            break;

        case em_msg_type_autoconf_resp:
        case em_msg_type_topo_query:
        case em_msg_type_autoconf_renew:
        case em_msg_type_channel_pref_query:
        case em_msg_type_channel_sel_req:
        case em_msg_type_client_cap_query:
        case em_msg_type_assoc_sta_link_metrics_query:
        case em_msg_type_client_steering_req:
        case em_msg_type_client_assoc_ctrl_req:
        case em_msg_type_map_policy_config_req:
        case em_msg_type_channel_scan_req:
        case em_msg_type_ap_mld_config_req:
			break;

		case em_msg_type_channel_scan_rprt:
            if (em_msg_t(data + (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t)),
                	len - (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t))).get_radio_id(&ruid) == false) {
                return NULL;
            }

            dm_easy_mesh_t::macbytes_to_string(ruid, mac_str1);
        
            if ((em = (em_t *)hash_map_get(m_em_map, mac_str1)) != NULL) {
                //printf("%s:%d: Found existing radio:%s\n", __func__, __LINE__, mac_str1);
			}
            break;

        case em_msg_type_assoc_sta_link_metrics_rsp:
            em = (em_t *)hash_map_get_first(m_em_map);
            while(em != NULL) {
                if ((em->is_al_interface_em() == false) && (em->has_at_least_one_associated_sta() == true)) {
                    break;
                }
                em = (em_t *)hash_map_get_next(m_em_map, em);
            }

            break;

        case em_msg_type_client_steering_btm_rprt:
            em = (em_t *)hash_map_get_first(m_em_map);
            while(em != NULL) {
                if ((em->is_al_interface_em() == false) && (em->has_at_least_one_associated_sta() == true)) {
                    break;
                }
                em = (em_t *)hash_map_get_next(m_em_map, em);
            }
            break;

        case em_msg_type_ap_mld_config_resp:
        case em_msg_type_1905_ack:
            em = (em_t *)hash_map_get_first(m_em_map);
            while(em != NULL) {
                if ((em->is_al_interface_em() == false)) {
                    break;
                }
                em = (em_t *)hash_map_get_next(m_em_map, em);
            }
            break;

        default:
            printf("%s:%d: Frame: 0x%04x not handled in controller\n", __func__, __LINE__, htons(cmdu->type));
            assert(0);
            break;
    }

    return em;
}

void em_ctrl_t::io(void *data, bool input)
{
    char *str = (char *)data;
    m_ctrl_cmd->execute(str);
}

void em_ctrl_t::start_complete()
{
	dm_easy_mesh_t *dm;
	wifi_bus_desc_t *desc;
	raw_data_t raw;
	em_interface_t	*intf;
	mac_addr_str_t	al_mac_str;

	if (m_data_model.is_initialized() == false) {
		printf("%s:%d: Database not initialized ... needs reset\n", __func__, __LINE__);
		return;
	}

    bus_init(&m_bus_hdl);
        
    if((desc = get_bus_descriptor()) == NULL) {
        printf("%s:%d descriptor is null\n", __func__, __LINE__);
    }

    if (desc->bus_open_fn(&m_bus_hdl, "EasyMesh_Ctrl_Service") != 0) {
        printf("%s:%d bus open failed\n",__func__, __LINE__);
        return;
    }

	intf = m_data_model.get_ctrl_al_interface((char *)global_netid);
	assert(intf != NULL);

	dm_easy_mesh_t::macbytes_to_string(intf->mac, al_mac_str);
	raw.data_type    = bus_data_type_string;
   	raw.raw_data.bytes   = al_mac_str;
   	raw.raw_data_len = strlen(al_mac_str);

   	if (desc->bus_set_fn(&m_bus_hdl, "Device.WiFi.Ctrl.CollocateAgentID", &raw)== 0) {
       	printf("%s:%d Collocated Agent ID: %s publish successfull\n",__func__, __LINE__, al_mac_str);
   	} else {
       	printf("%s:%d Collocated agent ID: %s publish  fail\n",__func__, __LINE__, al_mac_str);
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

	io_process(em_bus_event_type_cfg_renew, (unsigned char *)NULL, 0);	
}


em_ctrl_t::em_ctrl_t()
{

}

em_ctrl_t::~em_ctrl_t()
{

}

int main(int argc, const char *argv[])
{
    if (g_ctrl.init(argv[1]) == 0) {
        g_ctrl.start();
    }

    return 0;
}

void wifi_util_print(wifi_log_level_t level, wifi_dbg_type_t module, char *format, ...)
{

}
