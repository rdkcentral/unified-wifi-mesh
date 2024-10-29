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

#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>
#include <assert.h>
#include "em_base.h"
#include "em_cmd.h"
#include "em_orch_agent.h"

extern char *global_netid;

void em_orch_agent_t::orch_transient(em_cmd_t *pcmd, em_t *em)
{
    em_cmd_stats_t *stats;
    em_short_string_t key;
    
    snprintf(key, sizeof(em_short_string_t), "%d", pcmd->get_type());

    stats = (em_cmd_stats_t *)hash_map_get(m_cmd_map, key);
    assert(stats != NULL);
    if (stats->time > EM_MAX_CMD_TTL) {
        printf("%s:%d: Canceling comd: %s because time limit exceeded\n", __func__, __LINE__, pcmd->get_cmd_name());
        cancel_command(pcmd->get_type());
        em->set_state(em_state_agent_config_complete);
    }

}

bool em_orch_agent_t::is_em_ready_for_orch_fini(em_cmd_t *pcmd, em_t *em)
{
    switch (pcmd->get_type()) {
        case em_cmd_type_dev_init:
            if (em->get_state() == em_state_agent_owconfig_pending) {
                //m_mgr->io(&pcmd->m_data_model, false);
                return true;				
            }
            break;
        case em_cmd_type_onewifi_cb:
            if (em->get_state() == em_state_agent_topo_synchronized) {
                return true;
            }
            break;
        case em_cmd_type_cfg_renew:
            if (em->get_state() == em_state_agent_owconfig_pending) {
                return true;
            }
            break;
        default:
            if ((em->get_state() == em_state_agent_config_none) || \
                    (em->get_state() == em_state_agent_config_complete)) {
                return true;
            }
            break;
    }

    return false;
}

bool em_orch_agent_t::is_em_ready_for_orch_exec(em_cmd_t *pcmd, em_t *em)
{
    if ((em->get_state() == em_state_agent_config_none) || (em->get_state() == em_state_agent_config_complete)) {
        return true;
    } else if (pcmd->m_type == em_cmd_type_onewifi_cb) {
        return true;
    } else if (pcmd->m_type == em_cmd_type_cfg_renew) {
        return true;
    } else if (pcmd->m_type == em_cmd_type_sta_list) {
        return true;
    }

    return false;
}


void em_orch_agent_t::pre_process_cancel(em_cmd_t *pcmd, em_t *em)
{

}

bool em_orch_agent_t::pre_process_orch_op(em_cmd_t *pcmd)
{
    em_t *em;
    em_cmd_ctx_t *ctx;
    em_interface_t *intf;
    mac_addr_str_t	mac_str;
    dm_easy_mesh_t *dm;
    em_commit_target_t config;

    ctx = pcmd->m_data_model.get_cmd_ctx();

    switch (pcmd->get_orch_op()) {
        case dm_orch_type_al_insert:
            // for device insert, just create the al interface em and return, do not submit command
            printf("%s:%d: calling create node\n", __func__, __LINE__);

            intf = pcmd->get_agent_al_interface();
            if ((dm = m_mgr->get_data_model(global_netid, intf->mac)) == NULL) {
                dm = m_mgr->create_data_model(global_netid, intf->mac);
            }
            config.type = em_commit_target_al;
            //commit basic configuration before orchestrate
            dm->commit_config(pcmd->m_data_model, config);
            em = m_mgr->create_node(intf, pcmd->get_band(), dm, 1, em_profile_type_3, em_service_type_agent);
            if (em != NULL) {
                printf("%s:%d: AL node created\n", __func__, __LINE__);
            }
            break;
        case dm_orch_type_em_insert:
            // for radio insert, create the radio em and then submit command
            intf = pcmd->get_radio_interface(ctx->arr_index);
            if ((dm = m_mgr->get_data_model(global_netid, intf->mac)) == NULL) {
                dm = m_mgr->create_data_model(global_netid, intf->mac);
            }    
            dm_easy_mesh_t::macbytes_to_string(intf->mac, mac_str);
            config.type = em_commit_target_radio;
            snprintf((char *)config.params,sizeof(config.params),(char*)"%s",mac_str);
            dm->commit_config(pcmd->m_data_model, config);
            config.type = em_commit_target_bss;
            dm->commit_config(pcmd->m_data_model, config);
            printf("%s:%d: calling create_node\n", __func__, __LINE__);
            if ((em = m_mgr->create_node(intf, pcmd->get_band(), dm, 0, em_profile_type_3, em_service_type_agent)) == NULL) {
                printf("%s:%d: Failed to create node\n", __func__, __LINE__);
            
            }
            break;
        case dm_orch_type_em_update:
            break;	
        case dm_orch_type_sta_insert:
        case dm_orch_type_sta_update:
        case dm_orch_type_ap_cap_report:
        case dm_orch_type_client_cap_report:
        case dm_orch_type_owconfig_cnf:
        case dm_orch_type_tx_cfg_renew:
            break;
        default:
            break;
    }

    return pcmd->get_orch_submit();
}

unsigned int em_orch_agent_t::build_candidates(em_cmd_t *pcmd)
{
    em_t *em;
    unsigned int count = 0 , num = 0;
    em_cmd_ctx_t *ctx;
    dm_radio_t *radio;
    mac_addr_str_t	src_mac_str, dst_mac_str;
    em_freq_band_t freq_band, em_freq_band;
    int build_autoconf_renew = 0;
    char radio_mac[64] = {0};
    dm_sta_t *sta;
    dm_easy_mesh_t dm;
    hash_map_t **m_sta_assoc_map;

    ctx = pcmd->m_data_model.get_cmd_ctx();
    em = (em_t *)hash_map_get_first(m_mgr->m_em_map);	
    while (em != NULL) {
        switch (pcmd->m_type) {
            case em_cmd_type_dev_init:
                radio = pcmd->m_data_model.get_radio(ctx->arr_index);
                dm_easy_mesh_t::macbytes_to_string(radio->get_radio_interface_mac(), src_mac_str);
                dm_easy_mesh_t::macbytes_to_string(em->get_radio_interface_mac(), dst_mac_str);
                if (em->is_dev_init_candidate(radio->get_radio_interface_mac()) == true) {
                    //printf("%s:%d: Matched source mac: %s and destination mac: %s\n", __func__, __LINE__, 
                    //src_mac_str, dst_mac_str);
                    queue_push(pcmd->m_em_candidates, em);
                    count++;
                }
                break;
            case em_cmd_type_cfg_renew:
                if (memcmp(pcmd->get_data_model()->get_radio(num)->get_radio_info()->id.mac, em->get_radio_interface_mac(), sizeof(mac_address_t)) == 0) {
                    queue_push(pcmd->m_em_candidates, em);
                    count++;
                }
                break;
            case em_cmd_type_sta_list:
                m_sta_assoc_map = pcmd->get_data_model()->get_assoc_sta_map();
                if ((m_sta_assoc_map != NULL) && (*m_sta_assoc_map != NULL)) {
                    sta = (dm_sta_t *)hash_map_get_first(*m_sta_assoc_map);
                    if (sta != NULL) {
                        dm_easy_mesh_t::macbytes_to_string(em->get_radio_interface_mac(), dst_mac_str);
                        printf("%s:%d Sta List build candidate MAC=%s\n", __func__, __LINE__,dst_mac_str);
                        dm_easy_mesh_t::macbytes_to_string(sta->get_sta_info()->radiomac, dst_mac_str);
                        printf("%s:%d Sta List build candidate MAC=%s\n", __func__, __LINE__,dst_mac_str);

                        if(memcmp(em->get_radio_interface_mac(),&sta->get_sta_info()->radiomac,sizeof(mac_address_t)) == 0) {
                            printf("%s:%d Sta List build candidate MAC=%s push to queue\n", __func__, __LINE__,dst_mac_str);
                            queue_push(pcmd->m_em_candidates, em);
                            count++;
                        }
                    }
                }
                break;	
	        case em_cmd_type_ap_cap_query:
                if (!(em->is_al_interface_em())) {
                    dm_easy_mesh_t::macbytes_to_string(em->get_radio_interface_mac(), dst_mac_str);
                    printf("%s:%d Radio CAP report build candidate MAC=%s\n", __func__, __LINE__,dst_mac_str);
                    queue_push(pcmd->m_em_candidates, em);
                    count++;
                }
		        break;
	        case em_cmd_type_client_cap_query:
                if (!(em->is_al_interface_em())) {
                    radio = pcmd->m_data_model.get_radio((unsigned int)0);
		            if (radio == NULL) {
                        printf("%s:%d client cap radio cannot be found.\n", __func__, __LINE__);
                        break;
                    }
                    if (memcmp(radio->get_radio_interface_mac(),em->get_radio_interface_mac(),sizeof(mac_address_t)) == 0) {
                        queue_push(pcmd->m_em_candidates, em);
                        count++;
                        dm_easy_mesh_t::macbytes_to_string(em->get_radio_interface_mac(), dst_mac_str);
                        printf("%s:%d Client CAP report build candidate MAC=%s\n", __func__, __LINE__,dst_mac_str);
                    }
                }
                break;
            case em_cmd_type_onewifi_cb:
                if (memcmp(pcmd->get_data_model()->m_bss[0].m_bss_info.ruid.mac, em->get_radio_interface_mac(), sizeof(mac_address_t)) == 0) {
                    if (em->get_state() == em_state_agent_owconfig_pending) {
                        printf("em candidates created for em_cmd_type_onewifi_cb\n");
                        queue_push(pcmd->m_em_candidates, em);
                        count++;
                    }
                }
                break;
            default:
                break;
        }
        em = (em_t *)hash_map_get_next(m_mgr->m_em_map, em);	
    }

    return count;
}

em_orch_agent_t::em_orch_agent_t(em_mgr_t *mgr)
{
    m_mgr = mgr;
}  
