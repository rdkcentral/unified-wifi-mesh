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

// True when the controller's AL MAC is a local interface, i.e. this is the co-located agent,
// which reaches the controller without a bSTA and so needs no extra time after a reconfig
static bool is_colocated_with_ctrl(dm_easy_mesh_t *dm)
{
    unsigned char *ctrl_mac = dm->get_ctrl_al_interface_mac();
    em_interface_name_t if_name;

    return (ctrl_mac != NULL) &&
            (dm_easy_mesh_t::name_from_mac_address(reinterpret_cast<const mac_address_t*>(ctrl_mac), if_name) == 0);
}

void em_orch_agent_t::orch_transient(em_cmd_t *pcmd, em_t *em)
{
    em_cmd_stats_t *stats;
    em_short_string_t key;
    
    snprintf(key, sizeof(em_short_string_t), "%d", pcmd->get_type());

    stats = static_cast <em_cmd_stats_t *> (hash_map_get(m_cmd_map, key));
    assert(stats != NULL);

    if (pcmd->get_type() == em_cmd_type_dev_init && pcmd->get_agent_al_interface() != NULL) {
        auto agent_int = pcmd->get_agent_al_interface();
        std::string al_mac_key = util::mac_to_string(agent_int->mac) + "_al";
        em_t* al_node = static_cast <em_t*> (hash_map_get(m_mgr->m_em_map, al_mac_key.c_str()));
        if (al_node != NULL && al_node->m_ec_manager && al_node->get_is_dpp_onboarding()) {
            // If the enrollee is still onboarding, we need to wait for it to finish before timing out
            // Lets reset the timeout
            pcmd->set_start_time();
            stats->time = 0;
        }
    }

    if (stats->time > EM_MAX_CMD_GEN_TTL) {
        // For cfg_renew on a non-colocated agent (extender): after M8 backhaul
        // reconfig the bSTA disconnects and reconnects with new credentials.
        // While disconnected the radio cycles through unconfigured →
        // autoconfig_rsp_pending → wsc_m2_pending.  Allow extra time for the
        // bSTA to come back up before canceling.
        if (pcmd->get_type() == em_cmd_type_cfg_renew &&
            em->get_state() < em_state_agent_topo_synchronized) {
            dm_easy_mesh_t *dm = em->get_data_model();
            // Only once an M8 arrived in this renew, i.e. during a backhaul reconfig
            if ((dm != NULL) && dm->m_bsta_reconnect_pending && !is_colocated_with_ctrl(dm) &&
                    (stats->time <= EM_SSID_MISMATCH_TTL)) {
                return; // keep sending autoconfig_search
            }
        }
         // For dev_init on a non-colocated agent (extender): after cfg_renew
        // completes, the "dml" subdoc triggers dev_init while the bSTA is still
        // reconnecting to the new SSID.  Allow extended time for the bSTA to
        // come back up so autoconfig_search can reach the controller.
        if (pcmd->get_type() == em_cmd_type_dev_init &&
            em->get_state() < em_state_agent_topo_synchronized) {
            dm_easy_mesh_t *dm = em->get_data_model();
            // Only for the re-onboarding after a backhaul reconfig ("dml" -> dev_init window open)
            if ((dm != NULL) && dm->bh_reconfig_window_open() && !is_colocated_with_ctrl(dm) &&
                    (stats->time <= EM_SSID_MISMATCH_TTL)) {
                return; // keep sending autoconfig_search until bSTA reconnects
            }
        }
        em_printfout("Canceling cmd: %s because time limit exceeded\n", pcmd->get_cmd_name());
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
            if ((em->get_state() == em_state_agent_owconfig_pending) ||
                // An extension that intercepts M2 moves to wsc_m2_processed or straight on to topo_synchronized/configured
                (em->get_state() == em_state_agent_wsc_m2_processed) ||
                (em->get_state() >= em_state_agent_topo_synchronized)) {
                //m_mgr->io(&pcmd->m_data_model, false);
                return true;				
            }
            break;
        case em_cmd_type_onewifi_cb:
            // orch_execute leaves a state at or past topo_synchronized as it is
            if (em->get_state() >= em_state_agent_topo_synchronized) {
                return true;
            }
            break;
        case em_cmd_type_cfg_renew:
            if ((em->get_state() == em_state_agent_owconfig_pending) ||
                // An extension that intercepts M2 moves to wsc_m2_processed or straight on to topo_synchronized/configured
                (em->get_state() == em_state_agent_wsc_m2_processed) ||
                (em->get_state() >= em_state_agent_topo_synchronized)) {
                // The em thread queues the M2 configuration before moving on; wait until the agent
                // thread applied it, so on_cmd_fini sees the bSTA credentials of every M8
                dm_easy_mesh_t *dm = em->get_data_model();
                return (dm == NULL) || (__atomic_load_n(&dm->m_m2ctrl_pending, __ATOMIC_ACQUIRE) == 0);
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
            if (em->get_state() == em_state_beacon_report_complete) {
                return true;
            }
            break;

        case em_cmd_type_get_link_quality_report:
            if (em->get_state() == em_state_agent_configured) {
                return true;
            }
            break;

        case em_cmd_type_unassoc_sta_result:
            if (em->get_state() == em_state_agent_configured) {
                return true;
            }
            break;

        case em_cmd_type_vendor_data:
            if (pcmd->processed == true) {
                return true;
            }
            break;

        default:
            if ((em->get_state() == em_state_agent_unconfigured) ||
                    (em->get_state() == em_state_agent_configured) ||
                    (em->get_state() == em_state_agent_1905_unconfigured)) {
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
    } else if (pcmd->m_type == em_cmd_type_ap_cap_query) {
        return true;
    } else if ((pcmd->m_type == em_cmd_type_channel_pref_query) && (em->get_state() >= em_state_agent_ap_cap_report)) {
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
        if ((em->get_state() == em_state_beacon_report_pending) ||
            (em->get_state() == em_state_agent_configured) ||
            (em->get_state() >= em_state_agent_topo_synchronized)) {
            return true;
        }
    } else if (pcmd->m_type == em_cmd_type_get_link_quality_report) {
        if ((em->get_state() >= em_state_agent_topo_synchronized) ||
            ((em->get_state() == em_state_agent_link_quality_report_pending))) {
            return true;
        }
    } else if (pcmd->m_type == em_cmd_type_unassoc_sta_result) {
        if ((em->get_state() == em_state_agent_configured) ||
            ((em->get_state() ==em_state_agent_unassoc_sta_metrics_report_pending))) {
            return true;
        }
    } else if (pcmd->m_type == em_cmd_type_vendor_data) {
        if ((em->get_state() == em_state_agent_configured) ||
            (em->get_state() >= em_state_agent_topo_synchronized)){
            return true;
        }
    }

    return false;
}


void em_orch_agent_t::on_cmd_fini(em_cmd_t *pcmd)
{
    em_t *first_em = static_cast<em_t *>(queue_peek(pcmd->m_em_candidates, 0));
    dm_easy_mesh_t *dm = (first_em != NULL) ? first_em->get_data_model() : NULL;

    if (dm == NULL) {
        return;
    }

    // When cfg_renew completes on agent, handle bSTA reconnect if pending.
    // Push mesh STA subdoc to trigger bSTA reconnection with new credentials.
    // After bSTA reconnects, OneWifi fires dev_init which triggers
    // normal reonboarding through orchestration.
    // A cancelled renew (e.g. one radio's M2 never came) ends here too: the bSTAs still get the
    // credentials the M8s delivered, or the agent keeps the old ones once its parent switches.
    // A renew cancelled while an M2's AP configuration is still held (retried, or not handled yet)
    // keeps the bSTA push back: em_agent_t makes it due once that M2 is done.
    if (pcmd->m_type == em_cmd_type_cfg_renew) {
        dm->m_cfg_renew_in_progress = false;
        if ((__atomic_load_n(&dm->m_m2ctrl_pending, __ATOMIC_ACQUIRE) == 0) &&
                dm->prepare_bsta_reconnect()) {
            // A failed push (or no manager to push with) stays pending and is retried
            bool pushed = (first_em->get_mgr() != NULL) &&
                (first_em->get_mgr()->refresh_onewifi_subdoc("MESH STA CONFIG",
                    webconfig_subdoc_type_mesh_backhaul_sta) == 1);
            dm->bsta_reconnect_push_result(pushed);
        }
    }
    // The re-onboarding after a backhaul reconfig is done (M2 received); close the "dml" ->
    // dev_init window so a later "dml" push does not restart onboarding on a healthy agent.
    // A dev_init that ended without onboarding (cancel/timeout) keeps the window open, so
    // a late bSTA reconnect can still trigger the re-onboarding.
    if (pcmd->m_type == em_cmd_type_dev_init) {
        if ((first_em->get_state() == em_state_agent_owconfig_pending) ||
                (first_em->get_state() == em_state_agent_wsc_m2_processed) ||
                (first_em->get_state() >= em_state_agent_topo_synchronized)) {
            dm->m_bh_reconfig_time = 0;
        }
    }
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
    em_freq_band_t band;

    ctx = pcmd->m_data_model.get_cmd_ctx();

    switch (pcmd->get_orch_op()) {
        case dm_orch_type_al_insert:
            // for device insert, just create the al interface em and return, do not submit command
            printf("%s:%d: calling create node\n", __func__, __LINE__);

            intf = pcmd->get_agent_al_interface();
            if ((dm = m_mgr->get_data_model(GLOBAL_NET_ID, intf->mac)) == NULL) {
                dm = m_mgr->create_data_model(GLOBAL_NET_ID, intf);
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
                if ((dm = m_mgr->get_data_model(GLOBAL_NET_ID, intf->mac)) == NULL) {
                    dm = m_mgr->create_data_model(GLOBAL_NET_ID, intf);
                }    
                dm_easy_mesh_t::macbytes_to_string(intf->mac, mac_str);
                config.type = em_commit_target_radio;
                snprintf(reinterpret_cast<char*>(&config.params[0]), sizeof(config.params), "%s", mac_str);
                dm->commit_config(pcmd->m_data_model, config);
                config.type = em_commit_target_bss;
                dm->commit_config(pcmd->m_data_model, config);
                band =  pcmd->get_radio(i)->get_radio_info()->band;
                em_printfout("calling create_node band=%d", band);
                if ((em = m_mgr->create_node(intf, band, dm, 0, em_profile_type_3, em_service_type_agent)) == NULL) {
                    em_printfout("Failed to create node");
                }
            }
            break;
        case dm_orch_type_em_update:
            break;
        case dm_orch_type_sta_aggregate:
            intf = pcmd->get_radio_interface(ctx->arr_index);
            if ((dm = m_mgr->get_data_model(GLOBAL_NET_ID, intf->mac)) == NULL) {
                dm = m_mgr->create_data_model(GLOBAL_NET_ID, intf);
            }
            dm->merge_assoc_sta_updates(*pcmd->get_data_model());
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
        case dm_orch_type_vendor_data:
            break;

        case dm_orch_type_sta_link_metrics:
            intf = pcmd->get_radio_interface(ctx->arr_index);
            if ((dm = m_mgr->get_data_model(GLOBAL_NET_ID, intf->mac)) == NULL) {
                dm = m_mgr->create_data_model(GLOBAL_NET_ID, intf);
            }
            dm->merge_sta_link_metrics(*pcmd->get_data_model());
            break;

        default:
            break;
    }

    return pcmd->get_orch_submit();
}

unsigned int em_orch_agent_t::build_candidates(em_cmd_t *pcmd)
{
    em_t *em;
    unsigned int count = 0;
    em_cmd_ctx_t *ctx;
    dm_radio_t *radio;
    mac_addr_str_t	src_mac_str, dst_mac_str;
    dm_easy_mesh_t dm;
    mac_address_t	radio_mac, mac1, mac2;
    dm_sta_t *sta;

    ctx = pcmd->m_data_model.get_cmd_ctx();
	pthread_mutex_lock(&m_mgr->m_mutex);
    em = static_cast<em_t *> (hash_map_get_first(m_mgr->m_em_map));
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
                if (!(em->is_al_interface_em())) {
                    dm_easy_mesh_t::macbytes_to_string(em->get_radio_interface_mac(), src_mac_str);
                    printf("%s:%d Renew %s added\n", __func__, __LINE__, src_mac_str);
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
                    dm_easy_mesh_t::macbytes_to_string(em->get_radio_interface_mac(), dst_mac_str);
                    printf("%s:%d Radio CAP report build candidate MAC=%s\n", __func__, __LINE__,dst_mac_str);
                    queue_push(pcmd->m_em_candidates, em);
                    count++;
		        break;
	        case em_cmd_type_client_cap_query:
                if (!(em->is_al_interface_em())) {
                    radio = pcmd->m_data_model.get_radio(static_cast<unsigned int> (0));
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
                            em_printfout("em candidates created for em_cmd_type_onewifi_cb");
                        	queue_push(pcmd->m_em_candidates, em);
                        	count++;
						}
                    }
                }
                break;
			case em_cmd_type_channel_pref_query:
				if ((em->is_al_interface_em())) {
					if ((em->get_state() >= em_state_agent_ap_cap_report)
							&& (em->get_state() < em_state_agent_configured)) {
						queue_push(pcmd->m_em_candidates, em);
						count++;
						dm_easy_mesh_t::macbytes_to_string(em->get_al_interface_mac(), dst_mac_str);
						printf("%s:%d em_cmd_type_channel_pref_query build candidate MAC=%s\n", __func__, __LINE__,dst_mac_str);
					}
				}
				break;
            case em_cmd_type_op_channel_report:
                if (!(em->is_al_interface_em())) {
                    radio = pcmd->m_data_model.get_radio(static_cast<unsigned int> (0));
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
                    em_printfout("Beacon report build candidate pushed");
                    count++;
                }
                break;

            case em_cmd_type_get_link_quality_report:
                if ((em->is_al_interface_em() == true)) {
                    queue_push(pcmd->m_em_candidates, em);
                    count++;
                }
                break;

            case em_cmd_type_unassoc_sta_result:
                // Unassociated STA metrics response is processed only once.
                // Select the first non-AL EM instance as the candidate and
                // avoid queuing additional EMs for the same response.		
                if (!(em->is_al_interface_em()) && (count == 0)) {
                    queue_push(pcmd->m_em_candidates, em);
                    count++;
                }
                break;

            case em_cmd_type_vendor_data:
                // Vendor data is sent once via the first non-AL EM.
                if (!(em->is_al_interface_em()) && (count == 0)) {
                    queue_push(pcmd->m_em_candidates, em);
                    count++;
                }
                break;

            default:
                break;
        }
        em = static_cast<em_t *> (hash_map_get_next(m_mgr->m_em_map, em));	
    }
	pthread_mutex_unlock(&m_mgr->m_mutex);
    return count;
}

em_orch_agent_t::em_orch_agent_t(em_mgr_t *mgr)
{
    m_mgr = mgr;
}  
