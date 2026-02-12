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
#include <vector>
#include "em_base.h"
#include "em_cmd.h"
#include "em_cmd_exec.h"
#include "em_configuration.h"
#include "em_orch_ctrl.h"
#include "em_cmd_ctrl.h"

void em_orch_ctrl_t::orch_transient(em_cmd_t *pcmd, em_t *em)
{
    em_cmd_stats_t *stats;
    em_short_string_t key;

    snprintf(key, sizeof(em_short_string_t), "%d", pcmd->get_type());

    stats = static_cast<em_cmd_stats_t *>(hash_map_get(m_cmd_map, key));
    assert(stats != NULL);
	
	//printf("%s:%d: Orchestration:%s(%s) state:%s, time in transient:%d\n", __func__, __LINE__, 
		//em_cmd_t::get_orch_op_str(pcmd->get_orch_op()), em_cmd_t::get_cmd_type_str(pcmd->m_type), 
		//em_t::state_2_str(em->get_state()), stats->time);
	
	switch (pcmd->m_type) {

        case em_cmd_type_em_config:
        {
            dm_easy_mesh_t *dm = em->get_data_model();
            std::vector<em_t *> all_em_radios;
            em->get_mgr()->get_all_em_for_al_mac(dm->get_agent_al_interface_mac(), all_em_radios);
            // Special handling for Topology Sync command.
            if (pcmd->get_orch_op() == dm_orch_type_topo_sync && em->get_state() == em_state_ctrl_topo_sync_pending) {
                if (all_em_radios.empty()) return;
                unsigned int base_time = EM_MAX_CMD_GEN_TTL + EM_MAX_CMD_EXT_TTL;

                // Check if any radio has SSID mismatch within this AL set.
                bool ssid_mismatch_present = std::any_of(all_em_radios.begin(), all_em_radios.end(), [](em_t *radio) {
                    return radio->get_ssid_mismatch();
                });

                // Cancel command if time exceeded and no ssid mismatch
                if (stats->time > base_time && !ssid_mismatch_present) {
                    em_printfout("Canceling cmd: %s because time limit exceeded with no SSID mismatch",pcmd->get_cmd_name());
                    // Reset the mismatch and topo_query_last sent values before sending topo query
                    dm->set_ssid_mismatch_check_time(0);
                    dm->set_last_topo_query_sent_time(0);
                    cancel_command(pcmd->get_type(), all_em_radios);
                    return;
                }

                // Handle SSID mismatch scenario.
                if (ssid_mismatch_present) {
                    // Start timer on first detection
                    if (!dm->get_ssid_mismatch_check_time()) {
                        // ssid_mismatch_check_time records the time when the mismatch was first detected
                        dm->set_ssid_mismatch_check_time(stats->time);
                        em_printfout("SSID mismatch detected, starting %ds timer at time: %ds",EM_SSID_MISMATCH_TTL, stats->time);
                    }

                    // Transition to misconfigured if mismatch persists
                    // EM_SSID_MISMATCH_TTL (120) is used as the timeout threshold
                    if ((stats->time - (dm->get_ssid_mismatch_check_time())) > EM_SSID_MISMATCH_TTL) {
                        //If 120s have passed since ssid mismatch detected, cancel the command and transition to misconfigured state
                        em_printfout("%ds since SSID mismatch detected - canceling (SSID mismatch recovery failed)", EM_SSID_MISMATCH_TTL);
                        for (em_t *radio : all_em_radios) {
                            radio->set_ssid_mismatch(false);
                        }
                        //Reset the mismatch and topo_query_last sent values
                        dm->set_ssid_mismatch_check_time(0);
                        dm->set_last_topo_query_sent_time(0);
                        cancel_command(pcmd->get_type(), all_em_radios);

                        // Notify all radios by sending an Autoconfig Renew on each radio interface
                        em_printfout("SSID Mismatch recovery failed, sending Autoconfig Renew on all radios and transitioning to misconfigured state");
                        for (em_t *radio : all_em_radios) {
                            em_configuration_t *cfg = static_cast<em_configuration_t *>(radio);
                            // Move radio to misconfigured before issuing renew to resync config
                            radio->set_state(em_state_ctrl_misconfigured);
                            if (cfg->send_autoconfig_renew_msg() < 0) {
                                em_printfout("Autoconfig Renew send failed for radio:%s", util::mac_to_string(radio->get_radio_interface_mac()).c_str());
                            }
                        }
                        return;
                    }

                    // Send Topology Query every query_interval seconds
                    //EM_MAX_CMD_GEN_TTL(10s) is used as the query interval
                    if (!dm->get_last_topo_query_sent_time() ||
                       (stats->time - (dm->get_last_topo_query_sent_time())) >= EM_MAX_CMD_GEN_TTL) {
                        // Resend Topology Query every 10s if SSID mismatch is still present
                        for (em_t *radio : all_em_radios) {
                            if (radio->get_state() != em_state_ctrl_topo_sync_pending) {
                                radio->set_state(em_state_ctrl_topo_sync_pending);
                            }
                        }
                        em_printfout("Re-sent Topology Query due to SSID mismatch at time: %ds",stats->time);
                        static_cast<em_configuration_t*>(all_em_radios.front())->send_topology_query_msg();
                        // Update last query time
                        dm->set_last_topo_query_sent_time(stats->time);
                    }
                }
            } else if (stats->time > (EM_MAX_CMD_GEN_TTL + EM_MAX_CMD_EXT_TTL)) {
                em_printfout("Canceling cmd: %s because time limit exceeded",pcmd->get_cmd_name());
                // Reset the mismatch and topo_query_last sent values before canceling
                dm->set_ssid_mismatch_check_time(0);
                dm->set_last_topo_query_sent_time(0);
                cancel_command(pcmd->get_type());
            }
            break;
        }

        default:
        if (stats->time > EM_MAX_CMD_GEN_TTL)
        {
            em_printfout("Canceling cmd: %s because time limit exceeded",pcmd->get_cmd_name());
            cancel_command(pcmd->get_type());
        }
        break;
    }
}

bool em_orch_ctrl_t::is_em_ready_for_orch_fini(em_cmd_t *pcmd, em_t *em)
{
    // if the command is SetSSID and 5 renews have been sent transition to fini
    switch (pcmd->m_type) {
        case em_cmd_type_set_ssid:
        case em_cmd_type_cfg_renew:
		case em_cmd_type_set_radio:
            if (em->get_renew_tx_count() >= EM_MAX_RENEW_TX_THRESH) {
                em->set_renew_tx_count(0);
                printf("%s:%d: Maximum renew tx threshold crossed, transitioning to fini\n", __func__, __LINE__);
                return true;
            } else if (em->get_state() == em_state_ctrl_wsc_m2_sent) {
                return true;
			}
            break;

        case em_cmd_type_em_config:
            if (em->get_state() == em_state_ctrl_configured) {
                em->set_topo_query_tx_count(0);
                em->set_channel_pref_query_tx_count(0);
				em->set_channel_sel_req_tx_count(0);
                return true;
            } else if (em->get_state() == em_state_ctrl_ap_cap_report_received) {
                return true;
            } else if (em->get_state() == em_state_ctrl_topo_synchronized) {
                return true;
            } else if (em->get_state() == em_state_ctrl_channel_queried) {
                return true;
            } else if (em->get_state() == em_state_ctrl_channel_selected) {
                return true;
            } else if (em->get_state() == em_state_ctrl_configured) {
                return true;
            }
			//printf("%s:%d: em not ready orchestration:%s(%s) because of incorrect state, state:%s\n", __func__, __LINE__,
                    //em_cmd_t::get_orch_op_str(pcmd->get_orch_op()), em_cmd_t::get_cmd_type_str(pcmd->m_type), 
					//em_t::state_2_str(em->get_state()));
            break;
        
        case em_cmd_type_set_channel:
	    if (em->get_state() == em_state_ctrl_channel_selected) {
                return true;
            } else if (em->get_state() == em_state_ctrl_configured) {
		return true;
            }
	    break;
        case em_cmd_type_scan_channel:
            if (em->get_state() == em_state_ctrl_configured) {                               
                return true;
            }
            break;

        case em_cmd_type_sta_assoc:
            if (em->get_cap_query_tx_count() >= EM_MAX_CAP_QUERY_TX_THRESH) {
                em->set_cap_query_tx_count(0);
                em_printfout("Maximum renew tx threshold crossed, transitioning to fini");
                em->set_state(em_state_ctrl_configured);
                return true;
            } else if (em->get_state() == em_state_ctrl_sta_cap_confirmed) {
                em->set_state(em_state_ctrl_configured);
                return true;
            } else if (em->get_state() == em_state_ctrl_configured) {
                return true;
            }
            break;

        case em_cmd_type_sta_link_metrics:
            if (em->get_state() == em_state_ctrl_configured) {
                return true;
            }
            break;
        case em_cmd_type_sta_steer:
            if (em->get_client_steering_req_tx_count() >= EM_MAX_CLIENT_STEER_REQ_TX_THRESH
                || (em->get_state() == em_state_ctrl_steer_btm_req_ack_rcvd)) {
                em->set_client_steering_req_tx_count(0);
                em->set_state(em_state_ctrl_configured);
                printf("%s:%d: Maximum client steering req threshold crossed, transitioning to fini\n", __func__, __LINE__);
                return true;
            } else if (em->get_state() == em_state_ctrl_configured) {
                return true;
            }
            break;

        case em_cmd_type_sta_disassoc:
            if (em->get_client_assoc_ctrl_req_tx_count() >= EM_MAX_CLIENT_ASSOC_CTRL_REQ_TX_THRESH) {
                em->set_client_assoc_ctrl_req_tx_count(0);
                em->set_state(em_state_ctrl_configured);
                printf("%s:%d: Maximum client assoc control req threshold crossed, transitioning to fini\n", __func__, __LINE__);
                return true;
            } else if (em->get_state() == em_state_ctrl_configured) {
                return true;
            }

            break;

		case em_cmd_type_set_policy:
            if (em->get_state() == em_state_ctrl_configured) {
                return true;
            }
			break;

        case em_cmd_type_mld_reconfig:
            if (em->get_state() == em_state_ctrl_ap_mld_configured) {
                em->set_state(em_state_ctrl_configured);
                return true;
            }

			break;
        case em_cmd_type_start_dpp:
            return true;

        case em_cmd_type_bsta_cap:
            if (em->get_state() == em_state_ctrl_configured) {
                return true;
            }
            break;

        default:
            break;
    }

    return false;
}

bool em_orch_ctrl_t::is_em_ready_for_orch_exec(em_cmd_t *pcmd, em_t *em)
{
    switch (pcmd->m_type) {
        case em_cmd_type_set_ssid:
        case em_cmd_type_set_radio:
        case em_cmd_type_mld_reconfig:
        case em_cmd_type_start_dpp:
            return true;

        case em_cmd_type_em_config:
        case em_cmd_type_cfg_renew:
            if (em->get_state() == em_state_ctrl_unconfigured) {
				return true;
            } else if (em->get_state() == em_state_ctrl_wsc_m2_sent) {
                return true;
            } else if (em->get_state() == em_state_ctrl_ap_cap_report_received){
                return true;
            } else if (em->get_state() == em_state_ctrl_topo_synchronized) {
                return true;
            } else if (em->get_state() == em_state_ctrl_channel_queried) {
                return true;
            } else if (em->get_state() == em_state_ctrl_channel_selected) {
                return true;
            } else if (em->get_state() == em_state_ctrl_configured) {
                return true;
            } else if (em->get_state() == em_state_ctrl_misconfigured) {
                return true;
            }
            break;

        case em_cmd_type_sta_assoc:
            if (em->get_state() >= em_state_ctrl_topo_synchronized) {
                return true;
            }
            break;

	case em_cmd_type_set_channel:
	   if (em->get_state() == em_state_ctrl_configured) {
                return true;
            } else if (em->get_state() == em_state_ctrl_misconfigured) {
                return true;
            } else if( em->get_state() == em_state_ctrl_channel_selected) {
		return true;
	    }
	break;
        case em_cmd_type_sta_steer:
        case em_cmd_type_sta_disassoc:
        case em_cmd_type_sta_link_metrics:
        case em_cmd_type_scan_channel:
        case em_cmd_type_set_policy:
        case em_cmd_type_bsta_cap:
            if (em->get_state() == em_state_ctrl_configured) {
                return true;
            }
            break;
        default:
            break;
    }
    return false;
}

void em_orch_ctrl_t::pre_process_cancel(em_cmd_t *pcmd, em_t *em)
{
	em_event_t  ev;
    em_bus_event_t *bev;
    em_bus_event_type_cfg_renew_params_t    *raw;
	em_ctrl_t *ctrl = static_cast<em_ctrl_t *>(m_mgr);
	em_cmd_ctrl_t *cmd_ctrl = ctrl->get_ctrl_cmd();

	switch (pcmd->get_type()) {
		case em_cmd_type_em_config:
           	em->set_state(em_state_ctrl_misconfigured);
            em->set_topo_query_tx_count(0);
            em->set_channel_pref_query_tx_count(0);
            em->set_cap_query_tx_count(0);
			// send cfg renew so that controller can orchestrate renew
			ev.type = em_event_type_bus;
    		bev = &ev.u.bevt;
    		bev->type = em_bus_event_type_cfg_renew;
            raw = reinterpret_cast<em_bus_event_type_cfg_renew_params_t *>(bev->u.raw_buff);
    		memcpy(raw->radio, em->get_radio_interface_mac(), sizeof(mac_address_t));
            cmd_ctrl->send_cmd(em_service_type_ctrl, reinterpret_cast<unsigned char *>(&ev), sizeof(em_event_t));
			break;
		
		case em_cmd_type_cfg_renew:
           	em->set_state(em_state_ctrl_misconfigured);
            em->set_renew_tx_count(0);
			break;

        default:
            break;
	}
}

bool em_orch_ctrl_t::pre_process_orch_op(em_cmd_t *pcmd)
{
    em_t *em;
    em_ctrl_t *ctrl = static_cast<em_ctrl_t *>(m_mgr);
    dm_easy_mesh_ctrl_t *dm_ctrl = reinterpret_cast<dm_easy_mesh_ctrl_t *>(ctrl->get_data_model(GLOBAL_NET_ID));
    dm_easy_mesh_t *dm = &pcmd->m_data_model;
    dm_easy_mesh_t *mgr_dm;
    mac_addr_str_t	mac_str;
    em_commit_target_t config;
	mac_address_t radio_mac, dev_mac;
	em_2xlong_string_t criteria;

    //printf("%s:%d: Orchestration operation: %s\n", __func__, __LINE__, em_cmd_t::get_orch_op_str(pcmd->get_orch_op()));
    switch (pcmd->get_orch_op()) {
        case dm_orch_type_db_reset:
            dm_ctrl->reset_config();
            break;	

        case dm_orch_type_em_reset:
            m_mgr->delete_nodes();
            break;

        case dm_orch_type_em_delete:
			em = dm->get_em();
            m_mgr->delete_node(em->get_radio_interface());
            break;
        
        case dm_orch_type_db_cfg:
            dm_ctrl->set_config(dm);
            dm_ctrl->set_initialized();
            break;

        case dm_orch_type_al_insert:
            mgr_dm = m_mgr->get_data_model(GLOBAL_NET_ID, pcmd->get_al_interface_mac());
            if (mgr_dm == NULL) {
                break;
            }
			dm_easy_mesh_t::macbytes_to_string(pcmd->get_al_interface_mac(), mac_str);	
			//printf("%s:%d: DM of net_id: %s, AL MAC: %s Manager dm: %p\n", __func__, __LINE__, GLOBAL_NET_ID, mac_str, mgr_dm);
            
            // for device insert, just create the al interface em and return, do not submit command
            em = m_mgr->create_node(pcmd->get_ctrl_al_interface(), em_freq_band_unknown, mgr_dm, true, em_profile_type_3, em_service_type_ctrl);
            if (em != NULL) {
                config.type = em_commit_target_em;
                // since this does not have to go through orchestration of M1 M2, commit the data model
                em->get_data_model()->commit_config(pcmd->m_data_model, config);
            }
            break;

        case dm_orch_type_tx_cfg_renew:
            break;

        case dm_orch_type_db_delete:
			dm->set_db_cfg_param(db_cfg_type_device_list_delete, "");
			dm->set_db_cfg_param(db_cfg_type_radio_list_delete, "");
			dm->set_db_cfg_param(db_cfg_type_bss_list_delete, "");
			dm->set_db_cfg_param(db_cfg_type_op_class_list_delete, "");
            m_mgr->update_tables(dm);
			break;

		case dm_orch_type_dm_delete:
			printf("%s:%d: Deleting data model\n", __func__, __LINE__);
			m_mgr->delete_data_model((dm->get_device())->m_device_info.id.net_id, (dm->get_device())->m_device_info.id.dev_mac);
			break;

		case dm_orch_type_dm_delete_all:
			printf("%s:%d: Deleting all data models\n", __func__, __LINE__);
			m_mgr->delete_all_data_models();
			break;

		case dm_orch_type_em_update:
        case dm_orch_type_em_test:
        case dm_orch_type_sta_cap:
        case dm_orch_type_sta_link_metrics:
        case dm_orch_type_mld_reconfig:
            break;  

        case dm_orch_type_net_ssid_update:
            m_mgr->load_net_ssid_table();
            break;  

		case dm_orch_type_bss_delete:
			if (pcmd->get_type() != em_cmd_type_em_config) {
				break;
			}
			if (pcmd->m_param.u.args.num_args != 2) {
				break;
			}	
			dm_easy_mesh_t::string_to_macbytes(pcmd->m_param.u.args.args[0], radio_mac);
			dm_easy_mesh_t::string_to_macbytes(pcmd->m_param.u.args.args[1], dev_mac);
			
			mgr_dm = m_mgr->get_data_model(GLOBAL_NET_ID, dev_mac);
            if (mgr_dm == NULL) {
                break;
            }		
			snprintf(criteria, sizeof(em_2xlong_string_t), "radio=%s", pcmd->m_param.u.args.args[0]);
			mgr_dm->set_db_cfg_param(db_cfg_type_bss_list_delete, criteria);
			break;

        case dm_orch_type_topo_update:
            if (pcmd->get_type() == em_cmd_type_em_config) {
                break;
            }
            m_mgr->update_network_topology();
            break;

        case dm_orch_type_topo_publish:
        case dm_orch_type_bsta_cap_query:
			break;

        default:
            break;
    }

    return pcmd->get_orch_submit();
}

unsigned int em_orch_ctrl_t::build_candidates(em_cmd_t *pcmd)
{
    em_t *em;
    dm_easy_mesh_t *dm;
    mac_address_t	bss_mac, rad_mac;
    unsigned int count = 0, i;
    mac_addr_str_t mac_str;
    em_disassoc_params_t *disassoc_param;
    dm_sta_t *sta;
	mac_address_t null_mac = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    if (pcmd->m_type == em_cmd_type_em_config) {
        em = static_cast<em_t *>(hash_map_get(m_mgr->m_em_map, pcmd->m_param.u.args.args[0]));
        if (em != NULL) {
            queue_push(pcmd->m_em_candidates, em);
            count++;
        }
        return count;
    }

	pthread_mutex_lock(&m_mgr->m_mutex);
    em = static_cast<em_t *>(hash_map_get_first(m_mgr->m_em_map));
    while (em != NULL) {
        switch (pcmd->m_type) {
            case em_cmd_type_set_ssid:
		if (em->is_al_interface_em() == false) {
			dm_easy_mesh_t::macbytes_to_string(em->get_radio_interface_mac(), mac_str);
			printf("%s:%d Set SSID : %s push to queue \n", __func__, __LINE__,mac_str);
			queue_push(pcmd->m_em_candidates, em);
			count++;
                }
                break;

            case em_cmd_type_dev_test:
                if (em->is_dev_test_candidate()) {
                    queue_push(pcmd->m_em_candidates, em);
                    count++;
                }
                break;

            case em_cmd_type_reset:
                if (em->is_tx_cfg_renew_candidate()) {
                    queue_push(pcmd->m_em_candidates, em);
                    count++;
                }
                break;

            case em_cmd_type_cfg_renew:
		dm = pcmd->get_data_model();
		dm_easy_mesh_t::string_to_macbytes(pcmd->m_param.u.args.args[0], dm->m_radio[0].m_radio_info.intf.mac);
		// check if the radio is null mac
		if ((memcmp(null_mac, dm->m_radio[0].m_radio_info.intf.mac, sizeof(mac_address_t)) == 0) &&  (em->is_al_interface_em() == false)) {
			printf("%s:%d push to queue since null mac \n", __func__, __LINE__);	
			queue_push(pcmd->m_em_candidates, em);
                	count++;
		} else if ((memcmp(em->get_radio_interface_mac(), dm->m_radio[0].m_radio_info.intf.mac, sizeof(mac_address_t)) == 0) && (em->is_al_interface_em() == false)) {
			dm_easy_mesh_t::macbytes_to_string(em->get_radio_interface_mac(), mac_str);
			printf("%s:%d Auto config renew %s push to queue since mac matches\n", __func__, __LINE__,mac_str);
			queue_push(pcmd->m_em_candidates, em);
			count++;
                }
                break;

            case em_cmd_type_sta_assoc:
                dm = em->get_data_model();
                dm_easy_mesh_t::string_to_macbytes(pcmd->m_param.u.args.args[1], bss_mac);
                //printf("%s:%d:BSS for this STA %s is %s\n", __func__, __LINE__, pcmd->m_param.u.args.args[2], pcmd->m_param.u.args.args[1]);
                for (i = 0; i < dm->m_num_bss; i++) {
                    if ((memcmp(dm->m_bss[i].m_bss_info.bssid.mac, bss_mac, sizeof(mac_address_t)) == 0) &&
                        (em->is_al_interface_em() == false)) {
                        queue_push(pcmd->m_em_candidates, em);
                        count++;
                        //printf("%s:%d:Found em this STA, candidate count: %d\n", __func__, __LINE__, count);
                        break;
                    }
                }
                break;

            case em_cmd_type_sta_link_metrics:
                if ((em->is_al_interface_em() == false) && (em->get_state() == em_state_ctrl_configured)  && 
                        (em->has_at_least_one_associated_sta() == true)) {
                    queue_push(pcmd->m_em_candidates, em);
                    count++;
                }
                break;
            
            case em_cmd_type_set_channel:
				if (em->is_al_interface_em() == false) {
					for(i = 0; i < pcmd->m_param.u.args.num_args; i++) {
						if(atoi(pcmd->m_param.u.args.args[i]) == em->get_band()) {
							dm_easy_mesh_t::macbytes_to_string(em->get_radio_interface_mac(), mac_str);
							printf("%s:%d Set Channel : %s push to queue \n", __func__, __LINE__,mac_str);
							queue_push(pcmd->m_em_candidates, em);
							count++;
							break;
						}
					}
                }
                break;
            case em_cmd_type_scan_channel:
                if (em->is_al_interface_em() == false) {
                    queue_push(pcmd->m_em_candidates, em);
                    count++;
                }
                break;

            case em_cmd_type_sta_steer:
                if (em->find_sta(pcmd->m_param.u.steer_params.sta_mac, pcmd->m_param.u.steer_params.source) != NULL) {
                    queue_push(pcmd->m_em_candidates, em);
                    count++;
                }
                break;

            case em_cmd_type_sta_disassoc:
                dm = pcmd->get_data_model();
                for (i = 0; i < pcmd->m_param.u.disassoc_params.num; i++) {
                    disassoc_param = &pcmd->m_param.u.disassoc_params.params[i];
                    if ((sta = em->find_sta(disassoc_param->sta_mac, disassoc_param->bssid)) != NULL) {
                        queue_push(pcmd->m_em_candidates, em);
                        count++;
                    }
                }
                break;

			case em_cmd_type_set_policy:
                dm = pcmd->get_data_model();
                //need a radio from a device to send, no need to push all ems
                if (memcmp(em->get_radio_interface_mac(), dm->m_radio[0].m_radio_info.intf.mac, sizeof(mac_address_t)) == 0) {
                    dm_easy_mesh_t::macbytes_to_string(em->get_radio_interface_mac(), mac_str);
                    em_printfout("em: %s pushed for command: em_cmd_type_set_policy\n", mac_str);
                    queue_push(pcmd->m_em_candidates, em);
                    count++;
                    break;
                }
                break;

			case em_cmd_type_set_radio:
				dm = pcmd->get_data_model();
				for (i = 0; i < dm->get_num_radios(); i++) {
					if (memcmp(em->get_radio_interface_mac(), dm->m_radio[i].m_radio_info.intf.mac, sizeof(mac_address_t)) == 0) {
						dm_easy_mesh_t::macbytes_to_string(em->get_radio_interface_mac(), mac_str);
						//printf("%s:%d: em: %s pushed for command: em_cmd_type_set_policy\n", __func__, __LINE__, mac_str);
                        queue_push(pcmd->m_em_candidates, em);
                        count++;
						break;
					}
				}
				break;

            case em_cmd_type_mld_reconfig:
                if (em->is_al_interface_em()) {
                    queue_push(pcmd->m_em_candidates, em);
                    count++;
                }
                break;
            case em_cmd_type_start_dpp:
                if (em->is_al_interface_em()) {
                    // TODO: Add additional checks for provisioning state or more if needed 
                    queue_push(pcmd->m_em_candidates, em);
                    count++;
                }
                break;

            case em_cmd_type_bsta_cap:
                dm_easy_mesh_t::string_to_macbytes(pcmd->m_param.u.args.args[0], rad_mac);
                //search this radio em of for this agent al device to filter the em
                dm = em->get_data_model();
                if ((memcmp(em->get_radio_interface_mac(), rad_mac, sizeof(mac_address_t)) == 0))
                {
                    queue_push(pcmd->m_em_candidates, em);
                    count++;
                    em_printfout("BSTA CAP count: %d; push to queue for em radio: %s\n", count, util::mac_to_string(em->get_radio_interface_mac()).c_str());
                    break;
                }
                break;

            default:
                break;
        }			
        em = static_cast<em_t *>(hash_map_get_next(m_mgr->m_em_map, em));
    }
	pthread_mutex_unlock(&m_mgr->m_mutex);

    return count;
}

em_orch_ctrl_t::em_orch_ctrl_t(em_mgr_t *mgr)
{
    m_mgr = mgr;
}
