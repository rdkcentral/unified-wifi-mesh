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
#include <util.h>
#include "em_base.h"
#include "em_cmd.h"
#include "em_orch_agent.h"
#include "em.h"

extern char *global_netid;

void em_orch_agent_t::orch_transient(em_cmd_t *pcmd, em_t *em)
{
    em_cmd_stats_t *stats;
    em_short_string_t key;
    
    snprintf(key, sizeof(em_short_string_t), "%d", pcmd->get_type());

    stats = (em_cmd_stats_t *)hash_map_get(m_cmd_map, key);
    assert(stats != NULL);

    if (pcmd->get_type() == em_cmd_type_dev_init && pcmd->get_agent_al_interface() != NULL) {
        auto agent_int = pcmd->get_agent_al_interface();
        std::string al_mac_key = util::mac_to_string(agent_int->mac) + "_al";
        em_t* al_node = (em_t*)hash_map_get(m_mgr->m_em_map, al_mac_key.c_str());
        if (al_node != NULL && al_node->m_ec_manager && al_node->m_ec_manager->is_enrollee_onboarding()) {
            // If the enrollee is still onboarding, we need to wait for it to finish before timing out
            // Lets reset the timeout
            gettimeofday(&pcmd->m_start_time, NULL);
            stats->time = 0;
        }
    }

    if (stats->time > EM_MAX_CMD_GEN_TTL) {
        printf("%s:%d: Canceling comd: %s because time limit exceeded\n", __func__, __LINE__, pcmd->get_cmd_name());
        cancel_command(pcmd->get_type());
    	if (em->get_state() < em_state_agent_topo_synchronized) {
	    	em->set_state(em_state_agent_unconfigured);
		} else {
	    	em->set_state(em_state_agent_topo_synchronized);
		}
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
		case em_cmd_type_channel_pref_query:
			if (em->get_state() == em_state_agent_channel_selection_pending) {
				return true;
	    	}
	    	break;
        case em_cmd_type_sta_list:
            if (em->get_state() == em_state_agent_configured) {
                return true;
            }
            break;

        case em_cmd_type_sta_link_metrics:
            if (em->get_state() == em_state_agent_configured) {
                return true;
            }
            break;
		
        case em_cmd_type_op_channel_report:
            if (em->get_state() == em_state_agent_configured) {
                return true;
            }
            break;

        case em_cmd_type_btm_report:
            if (em->get_state() == em_state_agent_configured) {
                return true;
            }
            break;

		case em_cmd_type_scan_result:
			if (em->get_state() == em_state_agent_configured) {
                return true;
            }
            break;

        case em_cmd_type_beacon_report:
            if (em->get_state() == em_state_agent_configured) {
                return true;
            }
            break;

        case em_cmd_type_ap_metrics_report:
            if (em->get_state() == em_state_agent_configured) {
                return true;
            }
            break;

        default:
            if ((em->get_state() == em_state_agent_unconfigured) ||
                    (em->get_state() == em_state_agent_configured)) {
                return true;
            }
            break;
    }

    return false;
}

bool em_orch_agent_t::is_em_ready_for_orch_exec(em_cmd_t *pcmd, em_t *em)
{
	if (pcmd->m_type == em_cmd_type_dev_init) {
        return true;
    } else if (pcmd->m_type == em_cmd_type_onewifi_cb) {
        return true;
    } else if (pcmd->m_type == em_cmd_type_cfg_renew) {
        return true;
    } else if ((pcmd->m_type == em_cmd_type_channel_pref_query) && (em->get_state() >= em_state_agent_topo_synchronized)) {
		return true;
    } else if (pcmd->m_type == em_cmd_type_op_channel_report) {
        return true;
    } else if (pcmd->m_type == em_cmd_type_btm_report) {
		if (em->get_state() == em_state_agent_configured) {
			return true;
		}
    } else if (pcmd->m_type == em_cmd_type_sta_list) {
		if ((em->get_state() == em_state_agent_configured) ||
				(em->get_state() >= em_state_agent_topo_synchronized)){
			return true;
		}
    } else if (pcmd->m_type == em_cmd_type_sta_link_metrics) {
		if (em->get_state() == em_state_agent_configured) {
			return true;
		}
    } else if (pcmd->m_type == em_cmd_type_scan_result) {
		if (em->get_state() == em_state_agent_configured) {
			return true;
		}
	} else if (pcmd->m_type == em_cmd_type_beacon_report) {
        if ((em->get_state() == em_state_agent_configured) ||
            ((em->get_state() == em_state_agent_beacon_report_pending))) {
            return true;
        }
    } else if (pcmd->m_type == em_cmd_type_ap_metrics_report) {
        if ((em->get_state() == em_state_agent_configured) ||
            ((em->get_state() == em_state_agent_ap_metrics_pending))) {
            return true;
        }
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
    dm_sta_t *sta;
    em_long_string_t key;
    mac_addr_str_t sta_mac_str, bss_mac_str, radio_mac_str;
    mac_address_t   radio_mac;
    em_freq_band_t band;

    ctx = pcmd->m_data_model.get_cmd_ctx();

    switch (pcmd->get_orch_op()) {
        case dm_orch_type_al_insert:
            // for device insert, just create the al interface em and return, do not submit command
            printf("%s:%d: calling create node\n", __func__, __LINE__);

            intf = pcmd->get_agent_al_interface();
            if ((dm = m_mgr->get_data_model(global_netid, intf->mac)) == NULL) {
                dm = m_mgr->create_data_model(global_netid, intf);
            }
            config.type = em_commit_target_al;
            //commit basic configuration before orchestrate
            dm->commit_config(pcmd->m_data_model, config);
            em = m_mgr->create_node(intf, em_freq_band_unknown, dm, 1, em_profile_type_3, em_service_type_agent);
            if (em != NULL) {
                printf("%s:%d: AL node created\n", __func__, __LINE__);
            }
            break;
        case dm_orch_type_em_insert:
            // for radio insert, create the radio em and then submit command
            for (unsigned int i = 0; i < pcmd->get_data_model()->get_num_radios(); i++) {
                intf = pcmd->get_radio_interface(i);
                if ((dm = m_mgr->get_data_model(global_netid, intf->mac)) == NULL) {
                    dm = m_mgr->create_data_model(global_netid, intf);
                }    
                dm_easy_mesh_t::macbytes_to_string(intf->mac, mac_str);
                config.type = em_commit_target_radio;
                snprintf((char *)config.params,sizeof(config.params),(char*)"%s",mac_str);
                dm->commit_config(pcmd->m_data_model, config);
                config.type = em_commit_target_bss;
                dm->commit_config(pcmd->m_data_model, config);
                band =  pcmd->get_radio(i)->get_radio_info()->band;
                printf("%s:%d: calling create_node band=%d\n", __func__, __LINE__, band);
                if ((em = m_mgr->create_node(intf, band, dm, 0, em_profile_type_3, em_service_type_agent)) == NULL) {
                    printf("%s:%d: Failed to create node\n", __func__, __LINE__);
            
                }
            }
            break;
        case dm_orch_type_em_update:
            break;
        case dm_orch_type_sta_aggregate:
            intf = pcmd->get_radio_interface(ctx->arr_index);
            if ((dm = m_mgr->get_data_model(global_netid, intf->mac)) == NULL) {
                dm = m_mgr->create_data_model(global_netid, intf);
            }

            sta = (dm_sta_t *)hash_map_get_first(pcmd->get_data_model()->m_sta_assoc_map);
            while(sta != NULL) {
                dm_easy_mesh_t::macbytes_to_string(sta->m_sta_info.id, sta_mac_str);
                dm_easy_mesh_t::macbytes_to_string(sta->m_sta_info.bssid, bss_mac_str);
                dm_easy_mesh_t::macbytes_to_string(sta->m_sta_info.radiomac, radio_mac_str);
                snprintf(key, sizeof(em_long_string_t), "%s@%s@%s", sta_mac_str, bss_mac_str, radio_mac_str);

                em_sta_info_t *em_sta = dm->get_sta_info(sta->get_sta_info()->id, sta->get_sta_info()->bssid, sta->get_sta_info()->radiomac, em_target_sta_map_consolidated);
                if (em_sta != NULL) {
                    printf("Consolidated Map, sta exists; updating with key: %s\n", key);
                    memcpy(em_sta, sta->get_sta_info(), sizeof(em_sta_info_t));
                } else {
                    printf("Consolidated map new addition with key: %s\n", key);
                    hash_map_put(dm->m_sta_map, strdup(key), new dm_sta_t(*sta));
                }

                sta = (dm_sta_t *)hash_map_get_next(pcmd->get_data_model()->m_sta_assoc_map, sta);
            }

            sta = (dm_sta_t *)hash_map_get_first(pcmd->get_data_model()->m_sta_dassoc_map);
            while(sta != NULL) {
                dm_easy_mesh_t::macbytes_to_string(sta->m_sta_info.id, sta_mac_str);
                dm_easy_mesh_t::macbytes_to_string(sta->m_sta_info.bssid, bss_mac_str);
                dm_easy_mesh_t::macbytes_to_string(sta->m_sta_info.radiomac, radio_mac_str);
                snprintf(key, sizeof(em_long_string_t), "%s@%s@%s", sta_mac_str, bss_mac_str, radio_mac_str);

                em_sta_info_t *em_sta = dm->get_sta_info(sta->get_sta_info()->id, sta->get_sta_info()->bssid, sta->get_sta_info()->radiomac, em_target_sta_map_consolidated);
                sta = (dm_sta_t *)hash_map_get_next(pcmd->get_data_model()->m_sta_dassoc_map, sta);
                if (em_sta != NULL) {
                    printf("Consolidated Map removed with key: %s\n", key);
                    dm_sta_t *tmp = sta;
                    tmp = (dm_sta_t *)hash_map_remove(dm->m_sta_map, key);
                    delete tmp;
                }
            }
            break;
        case dm_orch_type_sta_insert:
        case dm_orch_type_sta_update:
        case dm_orch_type_ap_cap_report:
        case dm_orch_type_client_cap_report:
        case dm_orch_type_owconfig_cnf:
        case dm_orch_type_tx_cfg_renew:
        case dm_orch_type_channel_pref:
        case dm_orch_type_op_channel_report:
        case dm_orch_type_beacon_report:
            break;

        case dm_orch_type_sta_link_metrics:
            intf = pcmd->get_radio_interface(ctx->arr_index);
            if ((dm = m_mgr->get_data_model(global_netid, intf->mac)) == NULL) {
                dm = m_mgr->create_data_model(global_netid, intf);
            }

            sta = (dm_sta_t *)hash_map_get_first(pcmd->get_data_model()->m_sta_assoc_map);
            while(sta != NULL) {
                em_sta_info_t *em_sta = dm->get_sta_info(sta->get_sta_info()->id, sta->get_sta_info()->bssid, sta->get_sta_info()->radiomac, em_target_sta_map_consolidated);
                if (em_sta != NULL) {
                    memcpy(em_sta, &sta->m_sta_info, sizeof(em_sta_info_t));
                }
                sta = (dm_sta_t *)hash_map_get_next(pcmd->get_data_model()->m_sta_assoc_map, sta);
            }
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
    dm_easy_mesh_t dm;
    mac_address_t	radio_mac, mac1, mac2;
    dm_sta_t *sta;

    ctx = pcmd->m_data_model.get_cmd_ctx();
	pthread_mutex_lock(&m_mgr->m_mutex);
    em = (em_t *)hash_map_get_first(m_mgr->m_em_map);	
    while (em != NULL) {
        switch (pcmd->m_type) {
            case em_cmd_type_dev_init:
                radio = pcmd->m_data_model.get_radio(ctx->arr_index);
                dm_easy_mesh_t::macbytes_to_string(radio->get_radio_interface_mac(), src_mac_str);
                dm_easy_mesh_t::macbytes_to_string(em->get_radio_interface_mac(), dst_mac_str);
				if (!(em->is_al_interface_em())) {
					//printf("%s:%d: Matched source mac: %s and destination mac: %s\n", __func__, __LINE__, 
					//src_mac_str, dst_mac_str);
					queue_push(pcmd->m_em_candidates, em);
					count++;
				}
				break;
            case em_cmd_type_cfg_renew:
		dm_easy_mesh_t::macbytes_to_string(pcmd->get_data_model()->get_radio(num)->get_radio_info()->intf.mac, src_mac_str);
                if ((memcmp(pcmd->get_data_model()->get_radio(num)->get_radio_info()->intf.mac, em->get_radio_interface_mac(), sizeof(mac_address_t)) == 0) && (!(em->is_al_interface_em()))) {
		    printf("%s:%d Renew %s added\n", __func__, __LINE__,src_mac_str);
                    queue_push(pcmd->m_em_candidates, em);
                    count++;
                }
                break;
            case em_cmd_type_sta_list:
                dm_easy_mesh_t::string_to_macbytes(pcmd->m_param.u.args.args[0], radio_mac);
                if (memcmp(radio_mac, em->get_radio_interface_mac(), sizeof(mac_address_t)) != 0) {
                    break;
                }

                printf("%s:%d pcmd radio mac=%s\n", __func__, __LINE__, pcmd->m_param.u.args.args[0]);
                if ((hash_map_count(pcmd->get_data_model()->m_sta_assoc_map) != 0) || (hash_map_count(pcmd->get_data_model()->m_sta_dassoc_map) != 0)) {
                    queue_push(pcmd->m_em_candidates, em);
                    count++;
                }
                break;

            case em_cmd_type_sta_link_metrics:
                if ((em->is_al_interface_em() == false) && \
                    (em->has_at_least_one_associated_sta() == true)) {
                    queue_push(pcmd->m_em_candidates, em);
                    count++;
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
				if (!(em->is_al_interface_em())) {
                    if (memcmp(pcmd->get_data_model()->get_bss(0)->get_bss_info()->ruid.mac, em->get_radio_interface_mac(), sizeof(mac_address_t)) == 0) {
                        if (em->get_state() == em_state_agent_owconfig_pending) {
                        	printf("em candidates created for em_cmd_type_onewifi_cb\n");
                        	queue_push(pcmd->m_em_candidates, em);
                        	count++;
						}
                    }
                }
                break;
			case em_cmd_type_channel_pref_query:
				if (!(em->is_al_interface_em())) {
					radio = pcmd->m_data_model.get_radio((unsigned int)0);
					if (radio == NULL) {
						printf("%s:%d em_cmd_type_channel_pref_query radio cannot be found.\n", __func__, __LINE__);
						break;
					}

					if ((memcmp(radio->get_radio_interface_mac(),em->get_radio_interface_mac(),sizeof(mac_address_t)) == 0)
							&& (em->get_state() >= em_state_agent_topo_synchronized)
							&& (em->get_state() < em_state_agent_configured)) {
						queue_push(pcmd->m_em_candidates, em);
						count++;
						dm_easy_mesh_t::macbytes_to_string(em->get_radio_interface_mac(), dst_mac_str);
						printf("%s:%d em_cmd_type_channel_pref_query build candidate MAC=%s\n", __func__, __LINE__,dst_mac_str);
					}
				}
				break;
            case em_cmd_type_op_channel_report:
                if (!(em->is_al_interface_em())) {
                    radio = pcmd->m_data_model.get_radio((unsigned int)0);
                    if (radio == NULL) {
                        printf("%s:%d channel sel radio cannot be found.\n", __func__, __LINE__);
                        break;
                    }
                    if ((memcmp(radio->get_radio_interface_mac(),em->get_radio_interface_mac(),sizeof(mac_address_t)) == 0) && (em->get_state() == em_state_agent_channel_select_configuration_pending)) {
                        queue_push(pcmd->m_em_candidates, em);
                        count++;
                        dm_easy_mesh_t::macbytes_to_string(em->get_radio_interface_mac(), dst_mac_str);
                        printf("%s:%d Operating Channel Report build candidate MAC=%s\n", __func__, __LINE__,dst_mac_str);
                    }
                }
                break;

            case em_cmd_type_btm_report:
                if (!(em->is_al_interface_em())) {
                    sta = em->get_data_model()->find_sta(pcmd->m_param.u.btm_report_params.sta_mac, pcmd->m_param.u.btm_report_params.source);
                    if (sta != NULL) {
                        dm_easy_mesh_t::macbytes_to_string(pcmd->m_param.u.btm_report_params.sta_mac, src_mac_str);
                        printf("%s:%d BTM report build candidate sta mac=%s\n", __func__, __LINE__, src_mac_str);
                        queue_push(pcmd->m_em_candidates, em);
                        count++;
                    }
                }
                break;

			case em_cmd_type_scan_result:
				if (!(em->is_al_interface_em())) {
					if (memcmp(em->get_radio_interface_mac(), pcmd->m_param.u.scan_params.ruid, sizeof(mac_address_t)) == 0) {
                        queue_push(pcmd->m_em_candidates, em);
                        count++;
					}
				}
				break;

            case em_cmd_type_beacon_report:
                dm_easy_mesh_t::string_to_macbytes(pcmd->m_param.u.args.args[0], mac1);
                dm_easy_mesh_t::string_to_macbytes(pcmd->m_param.u.args.args[1], mac2);

                sta = em->find_sta(mac1, mac2);
                if (sta != NULL) {
                    queue_push(pcmd->m_em_candidates, em);
                    printf("%s:%d Beacon report build candidate pushed\n", __func__, __LINE__);
                    count++;
                }
                break;

            case em_cmd_type_ap_metrics_report:
                if (memcmp(pcmd->m_param.u.ap_metrics_params.ruid,
                    em->get_radio_interface_mac(), sizeof(mac_address_t)) == 0) {
                    queue_push(pcmd->m_em_candidates, em);
                    count++;
                }
                break;

			default:
                break;
        }
        em = (em_t *)hash_map_get_next(m_mgr->m_em_map, em);	
    }
	pthread_mutex_unlock(&m_mgr->m_mutex);
    return count;
}

em_orch_agent_t::em_orch_agent_t(em_mgr_t *mgr)
{
    m_mgr = mgr;
}  
