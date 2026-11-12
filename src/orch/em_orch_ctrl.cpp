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
#include <set>
#include <vector>
#include "em_base.h"
#include "em_cmd.h"
#include "em_cmd_exec.h"
#include "em_configuration.h"
#include "em_orch_ctrl.h"
#include "em_cmd_client_assoc_ctrl_req.h"
#include "em_cmd_ctrl.h"
#include "em_network_topo.h"

extern em_network_topo_t *g_network_topology;

// The ACL replay waits for the agent's other radios to settle (so it does not run while a VAP may
// still be recreated), but not for longer than this, which stays below the em_config TTL (GEN+EXT)
#define EM_ACL_CFG_MAX_WAIT_SECS 20

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
                    em_printfout("Canceling cmd: %s because time limit exceeded.",pcmd->get_cmd_name());
                    // Reset the mismatch and topo_query_last sent values before sending topo query
                    dm->set_ssid_mismatch_check_time(0);
                    dm->set_last_topo_query_sent_time(0);
                    cancel_command(pcmd->get_type(), all_em_radios);
                    /* Escalate like the SSID-mismatch path so a stuck agent redoes WSC;
                     * the renew tx budget re-arms at the threshold, keeping this bounded. */
                    em_printfout("Topology sync did not complete within TTL, sending Autoconfig Renew on all radios and transitioning to misconfigured state");
                    for (em_t *radio : all_em_radios) {
                        em_configuration_t *cfg = static_cast<em_configuration_t *>(radio);
                        radio->set_state(em_state_ctrl_misconfigured);
                        if (cfg->send_autoconfig_renew_msg() < 0) {
                            em_printfout("Autoconfig Renew send failed for radio:%s", util::mac_to_string(radio->get_radio_interface_mac()).c_str());
                        }
                    }
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
                em_printfout("Canceling cmd: %s for agent %s because time limit exceeded",
                    pcmd->get_cmd_name(),
                    util::mac_to_string(dm->get_agent_al_interface_mac()).c_str());
                // Reset the mismatch and topo_query_last sent values before canceling
                dm->set_ssid_mismatch_check_time(0);
                dm->set_last_topo_query_sent_time(0);
                // Cancel only this agent's radios, not all em_config commands
                cancel_command(pcmd->get_type(), all_em_radios);
            }
            break;
        }

        case em_cmd_type_set_bh_cfg:
            if (stats->time > (EM_MAX_CMD_GEN_TTL + EM_MAX_CMD_EXT_TTL)) {
                cancel_command(pcmd->get_type());
            }
            break;

        default:
        if (stats->time > EM_MAX_CMD_GEN_TTL)
        {
            em_printfout("Canceling cmd: %s because time limit exceeded (stats->time=%u)",pcmd->get_cmd_name(), stats->time);
            cancel_command(pcmd->get_type());
        }
        break;
    }
}

// A set_bh_cfg radio that got no M2 kept its old configuration: put back the state the phase found
static void restore_state_after_bh_cfg(em_t *em)
{
    if ((em->get_state() == em_state_ctrl_misconfigured) ||
             (em->get_state() == em_state_ctrl_wsc_m1_pending)) {
        em->set_state(em->m_state_before_bh_cfg);
    }
}

// True when this radio hosts a backhaul AP BSS, i.e. child agents' bSTAs connect through it
static bool em_hosts_backhaul_ap(em_t *em)
{
    dm_easy_mesh_t *dm = em->get_data_model();

    for (unsigned int i = 0; (dm != NULL) && (i < dm->get_num_bss()); i++) {
        em_bss_info_t *bss = dm->get_bss_info(i);
        if ((bss != NULL) && (bss->id.haul_type == em_haul_type_backhaul) && (bss->vap_mode == em_vap_mode_ap) &&
                (memcmp(bss->ruid.mac, em->get_radio_interface_mac(), sizeof(mac_address_t)) == 0)) {
            return true;
        }
    }
    return false;
}

void em_orch_ctrl_t::undo_refused_acl(em_cmd_t *pcmd, em_t *em)
{
    em_ctrl_t *ctrl = static_cast<em_ctrl_t *>(m_mgr);
    dm_easy_mesh_ctrl_t *dm_ctrl = ctrl->get_dm_ctrl();
    em_cmd_client_assoc_ctrl_req_t *cacr = static_cast<em_cmd_client_assoc_ctrl_req_t *> (pcmd);
    em_cmd_client_assoc_params_t *assoc = &pcmd->m_param.u.client_assoc_params;
    mac_address_t refused[MAX_STA_LIST];
    em_acl_undo_t restore;
    em_bss_info_t persist_info;
    bool persist = false;
    unsigned int num, i, j;

    num = em->take_cacr_refused(refused);
    if ((num == 0) || !cacr->m_acl_undo_valid) {
        return;
    }

    // Only the refused STAs go back to their previous state; the agent applied the others
    memset(&restore, 0, sizeof(restore));
    for (i = 0; i < cacr->m_acl_undo.count; i++) {
        for (j = 0; j < num; j++) {
            if (memcmp(cacr->m_acl_undo.sta[i].mac, refused[j], sizeof(mac_address_t)) == 0) {
                restore.sta[restore.count++] = cacr->m_acl_undo.sta[i];
                break;
            }
        }
    }
    if (restore.count == 0) {
        return;
    }
    dm_ctrl->acl_restore(cacr->m_acl_bss_key, &restore);

    pthread_mutex_lock(&m_mgr->m_mutex);
    dm_bss_t *bss = em->find_bss(assoc->bssid);
    if ((bss != NULL) && (bss->m_bss_info.vap_mode == em_vap_mode_ap)) {
        memcpy(&persist_info, &bss->m_bss_info, sizeof(persist_info));
        persist = true;
    }
    pthread_mutex_unlock(&m_mgr->m_mutex);

    em_printfout("Client Association Control: agent refused %u STA(s) on BSS %s, previous ACL kept for them",
        restore.count, cacr->m_acl_bss_key);
    if (persist && (dm_ctrl->persist_bss_acl(&persist_info, cacr->m_acl_bss_key) != 0)) {
        em_printfout("Failed to persist the ACL of BSS %s after the refusal", cacr->m_acl_bss_key);
    }
}

bool em_orch_ctrl_t::is_em_ready_for_orch_fini(em_cmd_t *pcmd, em_t *em)
{
    em_state_t state = em->get_state();

    switch (pcmd->m_type) {
        // if the command is SetSSID and 5 renews have been sent transition to fini
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
   
        case em_cmd_type_set_bh_cfg:
            if (em->get_state() == em_state_ctrl_wsc_m2_sent) {
                // The M2 (with the M8) went out. The agent sends no confirmation beyond its M1, so
                // this is where the agent counts as reconfigured and its parent may switch next:
                // once one M2 delivered the M8 and every radio hosting a backhaul AP has its M2
                // (its children reconnect through those). Marked here, not at destroy time: a
                // co-located or wired agent moves on into em_config once this command ends.
                dm_easy_mesh_t *agent_dm = em->get_data_model();
                if (agent_dm == NULL) {
                    return true;
                }
                if (em_hosts_backhaul_ap(em) && (agent_dm->m_bh_reconfig_bh_radios_left != 0)) {
                    agent_dm->m_bh_reconfig_bh_radios_left--;
                }
                em_network_topo_t *topo = (g_network_topology != NULL) ?
                        g_network_topology->find_topology(agent_dm) : NULL;
                if ((topo != NULL) && (agent_dm->m_bh_reconfig_bh_radios_left == 0)) {
                    topo->set_bh_processed(true);
                }
                return true;
            } else if (em->get_renew_tx_count() >= EM_MAX_RENEW_TX_THRESH) {
                em->set_renew_tx_count(0);
                restore_state_after_bh_cfg(em);
                // Not marked processed: counted as a failed try when the command ends (on_cmd_fini)
                return true;
            }
            break;

        case em_cmd_type_em_config:
            if (pcmd->get_orch_op() == dm_orch_type_acl_cfg) {
                if ((state == em_state_ctrl_acl_cfg_configured) ||
                        (state == em_state_ctrl_acl_cfg_failed)) {
                    // ACL step is the last em_config op; hand the radio back to the normal
                    // configured state so other commands (steer, disassoc, ...) can run.
                    em->set_state(em_state_ctrl_configured);
                    return true;
                }
                return false;
            }
                if (state == em_state_ctrl_configured) {
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
            } else if (em->get_state() == em_state_ctrl_wsc_m2_sent) {
                // A second M1/M2 exchange on 2.4GHz regresses the per band state machine back to em_state_ctrl_m2_sent,
                // so the controller never reaches/maintains the topo_synch_pending.
                // Because of thisTopology Query is never sent.
                // Added changes to move state machine to topo_sync_pending if it brought
                // back to m2_sent
                em->set_state(em_state_ctrl_topo_sync_pending);
                return false;
            }
			//printf("%s:%d: em not ready orchestration:%s(%s) because of incorrect state, state:%s\n", __func__, __LINE__,
                    //em_cmd_t::get_orch_op_str(pcmd->get_orch_op()), em_cmd_t::get_cmd_type_str(pcmd->m_type), 
					//em_t::state_2_str(em->get_state()));
            break;
        
        case em_cmd_type_set_channel:
            if (state == em_state_ctrl_configured) {
                return true;
            }
	    break;
        case em_cmd_type_scan_channel:
            if (state == em_state_ctrl_configured) {
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
            } else if (em->get_state() == em_state_ctrl_topo_synchronized) {
                return true;
            } else if (state == em_state_ctrl_configured) {
                return true;
            }
            break;

        case em_cmd_type_sta_link_metrics:
            if (state == em_state_ctrl_configured) {
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
            } else if (state == em_state_ctrl_configured) {
                return true;
            }
            break;

        case em_cmd_type_client_assoc_ctrl_req:
            if (state == em_state_ctrl_configured) {
                undo_refused_acl(pcmd, em);
                return true;
            }
            break;

        case em_cmd_type_sta_disassoc:
            if (em->get_client_assoc_ctrl_req_tx_count() >= EM_MAX_CLIENT_ASSOC_CTRL_REQ_TX_THRESH) {
                em->set_client_assoc_ctrl_req_tx_count(0);
                em->set_state(em_state_ctrl_configured);
                printf("%s:%d: Maximum client assoc control req threshold crossed, transitioning to fini\n", __func__, __LINE__);
                return true;
            } else if (state == em_state_ctrl_configured) {
                return true;
            }

            break;

		case em_cmd_type_set_policy:
        if (state == em_state_ctrl_configured) {
                // Commit policies from the command DM to the live data model and DB
                dm_easy_mesh_t *cmd_dm = pcmd->get_data_model();
                dm_easy_mesh_t *live_dm = em->get_data_model();
                if (cmd_dm != NULL && live_dm != NULL) {
                    for (dm_policy_t *pol = cmd_dm->m_policy_map ? static_cast<dm_policy_t *>(hash_map_get_first(cmd_dm->m_policy_map)) : NULL;
                         pol != NULL;
                         pol = static_cast<dm_policy_t *>(hash_map_get_next(cmd_dm->m_policy_map, pol))) {
                        em_printfout("orch set_policy: committing policy type=%d to live_dm", pol->m_policy.id.type);
                        live_dm->set_policy(*pol);
                    }
                    // Trigger DB write
                    cmd_dm->set_db_cfg_param(db_cfg_type_policy_list_update, "");
                    m_mgr->update_tables(cmd_dm);
                }
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
            // The report handler puts back the state bsta_cap found (configured, or an em_config step)
            if (state != em_state_ctrl_bsta_cap_pending) {
                return true;
            }
            break;

	case em_cmd_type_unassoc_sta_query:
    if (state == em_state_ctrl_configured) {
                return true;
            }
            break;

        case em_cmd_type_beacon_query:
            if (em->get_state() == em_state_beacon_report_complete) {
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
    em_state_t em_state = em->get_state();

    switch (pcmd->m_type) {
        case em_cmd_type_set_ssid:
        case em_cmd_type_set_bh_cfg:
        case em_cmd_type_set_radio:
        case em_cmd_type_mld_reconfig:
        case em_cmd_type_start_dpp:
            return true;

        case em_cmd_type_em_config:
            if (pcmd->get_orch_op() == dm_orch_type_acl_cfg) {
                dm_easy_mesh_t *dm = em->get_data_model();
                if (dm == NULL) {
                    return false;
                }

                std::vector<em_t *> em_radios;
                m_mgr->get_all_em_for_al_mac(dm->get_agent_al_interface_mac(), em_radios);
                if (em_radios.empty()) {
                    return false;
                }

                // The replay is per radio (only this radio's BSSes). Wait for the other radios so
                // it does not run while one of them may still recreate VAPs, but do not wait for a
                // misconfigured radio (it gets no further in this em_config), and cap the wait so
                // one stuck radio cannot hold back the whitelist of the others.
                struct timeval now;
                util::monotonic_now(&now);
                bool waited_enough = ((now.tv_sec - pcmd->m_start_time.tv_sec) >= EM_ACL_CFG_MAX_WAIT_SECS);
                for (em_t *radio : em_radios) {
                    em_state_t radio_state = radio->get_state();
                    if (em_t::is_ctrl_configured_or_acl(radio_state) ||
                            (radio_state == em_state_ctrl_misconfigured)) {
                        continue;
                    }
                    if (waited_enough == false) {
                        return false;
                    }
                }

                return em_t::is_ctrl_configured_or_acl(em_state);
            }
                [[fallthrough]];

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
            } else if (em_state == em_state_ctrl_configured) {
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

	case em_cmd_type_scan_channel:
		return em_state == em_state_ctrl_configured;

	case em_cmd_type_set_channel:
    if (em_state == em_state_ctrl_configured) {
                return true;
            } else if (em->get_state() == em_state_ctrl_misconfigured) {
                return true;
            } else if( em->get_state() == em_state_ctrl_channel_selected) {
		return true;
	    }
	break;
    case em_cmd_type_bsta_cap:
        return (em_state == em_state_ctrl_topo_synchronized) ||
            (em_state == em_state_ctrl_ap_cap_report_received) ||
            (em_state == em_state_ctrl_channel_queried) ||
            (em_state == em_state_ctrl_channel_selected) ||
            (em_state == em_state_ctrl_misconfigured) ||
            (em_state == em_state_ctrl_configured);
        case em_cmd_type_sta_steer:
        case em_cmd_type_sta_disassoc:
        case em_cmd_type_sta_link_metrics:
        case em_cmd_type_set_policy:
	case em_cmd_type_unassoc_sta_query:
        case em_cmd_type_client_assoc_ctrl_req:
            if (em_state == em_state_ctrl_configured) {
                return true;
            }
            break;
        case em_cmd_type_beacon_query:
            if (em->get_state() >= em_state_ctrl_topo_synchronized) {
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

        case em_cmd_type_set_channel:
            em_printfout("Cancel received for Set Channel command, transitioning to configured state radio: %s",
                util::mac_to_string(em->get_radio_interface_mac()).c_str());
            em->set_state(em_state_ctrl_configured);
            // Reset the count of active channel selection requests
            // Currently this counter is not used, reset for future use of this counter
            em->set_channel_sel_req_tx_count(0);
            break;

        case em_cmd_type_set_policy:
            em_printfout("Cancel received for Set Policy command, transitioning to configured state radio: %s",
                util::mac_to_string(em->get_radio_interface_mac()).c_str());
            em->set_state(em_state_ctrl_configured);
            break;

        case em_cmd_type_beacon_query:
            em_printfout("Cancel received for Beacon Metrics Query command, transitioning to configured state radio: %s",
                util::mac_to_string(em->get_radio_interface_mac()).c_str());
            em->set_state(em_state_ctrl_configured);
            break;

        case em_cmd_type_set_bh_cfg:
            em->set_renew_tx_count(0);
            restore_state_after_bh_cfg(em);
            break;

        case em_cmd_type_bsta_cap:
            // No report came: put back the state bsta_cap found, so an interrupted em_config goes on
            if (em->get_state() == em_state_ctrl_bsta_cap_pending) {
                em->set_state(em->m_state_before_bsta_cap);
            }
            break;

        default:
            break;
	}
}

void em_orch_ctrl_t::on_cmd_fini(em_cmd_t *pcmd)
{
    std::set<em_network_topo_t *> failed;
    em_t *em;

    if ((pcmd->m_type != em_cmd_type_set_bh_cfg) || (g_network_topology == NULL)) {
        return;
    }

    // An agent whose M2 went out was marked processed in is_em_ready_for_orch_fini(). One still
    // unprocessed here hit the renew limit or the timeout: count one failed try per agent. It stays
    // a candidate for the next phase while its parent still has the old credentials.
    for (int j = static_cast<int>(queue_count(pcmd->m_em_candidates)) - 1; j >= 0; j--) {
        em = static_cast<em_t *>(queue_peek(pcmd->m_em_candidates, static_cast<unsigned int>(j)));
        em_network_topo_t *topo = g_network_topology->find_topology(em->get_data_model());
        if ((topo != NULL) && (topo->is_bh_processed() == false)) {
            failed.insert(topo);
        }
    }
    for (em_network_topo_t *topo : failed) {
        topo->note_bh_reconfig_failure();
    }

    // Next phase: the nodes whose children are all done now
    g_network_topology->send_bh_reconfig_event();
}

bool em_orch_ctrl_t::pre_process_orch_op(em_cmd_t *pcmd)
{
    em_t *em;
    em_ctrl_t *ctrl = static_cast<em_ctrl_t *>(m_mgr);
    dm_easy_mesh_ctrl_t *dm_ctrl = ctrl->get_dm_ctrl();
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
        {
            // Every radio: an em left behind would point at the data model freed next. An offline
            // agent after a controller restart has none, and its dm has no em set.
            std::vector<em_t *> em_radios;
            m_mgr->get_all_em_for_al_mac(dm->get_device()->get_dev_interface_mac(), em_radios);
            for (em_t *radio_em : em_radios) {
                m_mgr->delete_node(radio_em->get_radio_interface());
            }
            break;
        }
        
        case dm_orch_type_db_cfg:
            dm_ctrl->set_config(dm);
            dm_ctrl->set_initialized();
            // The flag stays set when the write failed. Agents would get the old credentials over
            // a walk that makes each one re-onboard, so report it instead of starting one.
            if ((pcmd->m_type == em_cmd_type_set_bh_cfg) &&
                    dm->db_cfg_type_is_set(db_cfg_type_network_ssid_list_update)) {
                em_printfout("SetBhCfg: storing the new backhaul credentials failed");
                return false;
            }
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
			// The topology node points at this data model, and reconfig walks use it
			if (g_network_topology != NULL) {
				dm_easy_mesh_t *live_dm = dm_ctrl->get_data_model((dm->get_device())->m_device_info.id.net_id,
						(dm->get_device())->m_device_info.id.dev_mac);
				if (live_dm != NULL) {
					g_network_topology->remove(live_dm, NULL, NULL);
				}
			}
			m_mgr->delete_data_model((dm->get_device())->m_device_info.id.net_id, (dm->get_device())->m_device_info.id.dev_mac);
			break;

		case dm_orch_type_dm_delete_all:
			printf("%s:%d: Deleting all data models\n", __func__, __LINE__);
			if (g_network_topology != NULL) {
				for (dm_easy_mesh_t *each = dm_ctrl->get_first_dm(); each != NULL; each = dm_ctrl->get_next_dm(each)) {
					if (each->is_controller() == false) {
						g_network_topology->remove(each, NULL, NULL);
					}
				}
			}
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

        case dm_orch_type_policy_cfg:
        {
            // Update dev_dm flat array so the next SET comparison sees the updated
            // baseline and doesn't re-detect the same change as new.
            dm_easy_mesh_t *dev_dm = m_mgr->get_data_model(GLOBAL_NET_ID, dm->m_device.m_device_info.intf.mac);
            if (dev_dm != nullptr) {
                for (dm_policy_t *pol = dm->m_policy_map ? static_cast<dm_policy_t *>(hash_map_get_first(dm->m_policy_map)) : NULL;
                     pol != NULL;
                     pol = static_cast<dm_policy_t *>(hash_map_get_next(dm->m_policy_map, pol))) {
                    dev_dm->set_policy(*pol);
                }
            }
            break;
        }

        case dm_orch_type_topo_publish:
        case dm_orch_type_bsta_cap_query:
        case dm_orch_type_beacon_query:
        case dm_orch_type_acl_cfg:
			break;

        case dm_orch_type_client_assoc:
        {
            // Persist the ACL carried by the CACR so it survives a controller/agent reboot
            em_cmd_client_assoc_params_t *assoc = &pcmd->m_param.u.client_assoc_params;
            em_2xlong_string_t bss_key;
            em_bss_info_t persist_info;
            em_acl_undo_t undo;
            unsigned char prev_mode = 0;
            unsigned short prev_validity = 0;
            bool persist = false;
            bool bss_found = false;
            bool stored = true;

            pthread_mutex_lock(&m_mgr->m_mutex);
            em = static_cast<em_t *>(hash_map_get_first(m_mgr->m_em_map));
            while (em != NULL) {
                dm_bss_t *bss = (em->is_al_interface_em() == false) ? em->find_bss(assoc->bssid) : NULL;
                if ((bss != NULL) && (bss->m_bss_info.vap_mode == em_vap_mode_ap)) {
                    bss_found = true;
                    prev_mode = bss->m_bss_info.acl_filter_mode;
                    prev_validity = bss->m_bss_info.acl_validity_period;
                    // All or nothing (e.g. a full 256-entry list): on failure the ACL is unchanged
                    if (dm_ctrl->acl_apply_cacr(&bss->m_bss_info, assoc, bss_key, sizeof(bss_key), &undo) != 0) {
                        em_printfout("Failed to update ACL state for BSS %s", bss_key);
                        stored = false;
                        break;
                    }

                    // Copied under the lock: em threads may rewrite this BSS meanwhile
                    memcpy(&persist_info, &bss->m_bss_info, sizeof(persist_info));
                    persist = true;
                    break;
                }
                em = static_cast<em_t *>(hash_map_get_next(m_mgr->m_em_map, em));
            }
            pthread_mutex_unlock(&m_mgr->m_mutex);

            // DB I/O outside the em-map lock, so 1905 handling is not held up behind SQLite. Only
            // this BSS's row changes, so only it is written (from the copy taken under the lock).
            if (persist && (dm_ctrl->persist_bss_acl(&persist_info, bss_key) != 0)) {
                em_printfout("Failed to persist ACL state for BSS %s", bss_key);
                // Not stored, so not kept: the replay at onboarding must match what the agent has
                dm_ctrl->acl_restore(bss_key, &undo);
                pthread_mutex_lock(&m_mgr->m_mutex);
                for (em = static_cast<em_t *>(hash_map_get_first(m_mgr->m_em_map)); em != NULL;
                        em = static_cast<em_t *>(hash_map_get_next(m_mgr->m_em_map, em))) {
                    dm_bss_t *bss = (em->is_al_interface_em() == false) ? em->find_bss(assoc->bssid) : NULL;
                    if ((bss != NULL) && (bss->m_bss_info.vap_mode == em_vap_mode_ap)) {
                        bss->m_bss_info.acl_filter_mode = prev_mode;
                        bss->m_bss_info.acl_validity_period = prev_validity;
                        break;
                    }
                }
                pthread_mutex_unlock(&m_mgr->m_mutex);
                stored = false;
            } else if (persist) {
                // Stored before the agent answers: kept so the STAs its ACK refuses are put back
                em_cmd_client_assoc_ctrl_req_t *cacr = static_cast<em_cmd_client_assoc_ctrl_req_t *> (pcmd);
                memcpy(&cacr->m_acl_undo, &undo, sizeof(undo));
                snprintf(cacr->m_acl_bss_key, sizeof(cacr->m_acl_bss_key), "%s", bss_key);
                cacr->m_acl_undo_valid = true;
            }

            // No em hosts this BSS, so the agent is offline and this command has no candidate. The
            // change is still stored, or the replay would undo it when the agent returns.
            if (!bss_found) {
                if (dm_ctrl->acl_apply_offline(assoc) != 0) {
                    stored = false;
                } else {
                    // Applied at the agent's next onboarding: a success, though nothing is sent
                    m_acl_stored_offline++;
                }
            }

            // A change the controller could not store must not reach the agent: it would be lost
            // at the next replay. Not submitting reports the failure to the requester.
            if (!stored) {
                em_printfout("Client Association Control not sent: the ACL change for " MACSTRFMT
                    " could not be stored", MAC2STR(assoc->bssid));
                return false;
            }
            break;
        }

        default:
            break;
    }

    return pcmd->get_orch_submit();
}

unsigned int em_orch_ctrl_t::build_candidates(em_cmd_t *pcmd)
{
    em_t *em;
    dm_easy_mesh_t *dm;
    mac_address_t   rad_mac, dev_mac;
    unsigned int count = 0, i;
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

    if (pcmd->m_type == em_cmd_type_set_policy) {
        dm = pcmd->get_data_model();
        std::vector<em_t *> em_radios;
        m_mgr->get_all_em_for_al_mac(dm->get_agent_al_interface_mac(), em_radios);
        if (!em_radios.empty()) {
            em_printfout("Set Policy: %s pushed to queue", util::mac_to_string(em_radios.front()->get_radio_interface_mac()).c_str());
            queue_push(pcmd->m_em_candidates, em_radios.front());
            count++;
        }
        return count;
    }

    // set_bh_cfg: agents whose backhaul state was taken in this phase (once per agent, not per radio)
    std::set<dm_easy_mesh_t *> bh_agents;

    if ((pcmd->m_type == em_cmd_type_set_bh_cfg) && (g_network_topology != NULL)) {
        g_network_topology->mark_bh_leaves_processed();
    }

    pthread_mutex_lock(&m_mgr->m_mutex);
    em = static_cast<em_t *>(hash_map_get_first(m_mgr->m_em_map));
    while (em != NULL) {
        switch (pcmd->m_type) {
            case em_cmd_type_set_ssid:
                if (em->is_al_interface_em() == false) {
                    //mac_addr_str_t mac_str;
                    //dm_easy_mesh_t::macbytes_to_string(em->get_radio_interface_mac(), mac_str);
                    //em_printfout("Set SSID: %s push to queue", mac_str);
                    queue_push(pcmd->m_em_candidates, em);
                    count++;
                }
                break;

            case em_cmd_type_set_bh_cfg:
                if (em->is_al_interface_em() == false && g_network_topology != NULL) {
                    em_network_topo_t *topo = g_network_topology->find_topology(em->get_data_model());
                    if (topo != NULL && topo->is_bh_reconfig_candidate()) {
                        // topo != NULL, so the radio has a data model
                        dm_easy_mesh_t *agent_dm = em->get_data_model();
                        if (bh_agents.insert(agent_dm).second) {
                            // A bSTA with an upstream BSSID means a wireless backhaul: the agent
                            // drops it and re-onboards after the M8. A wired one does not, and
                            // still gets em_config. An agent already found wireless stays so in a
                            // later phase, as its bSTA may be down by then.
                            em_bss_info_t *bsta = agent_dm->get_bsta_bss_info();
                            agent_dm->set_bh_reconfig_reonboards(agent_dm->is_bh_reconfig_reonboards() ||
                                    ((bsta != NULL) && (memcmp(bsta->bssid.mac, ZERO_MAC_ADDR, sizeof(mac_address_t)) != 0)));
                            agent_dm->m_bh_reconfig_bh_radios_left = 0;
                        }
                        if (em_hosts_backhaul_ap(em)) {
                            agent_dm->m_bh_reconfig_bh_radios_left++;
                        }
                        queue_push(pcmd->m_em_candidates, em);
                        count++;
                    }
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
                if ((memcmp(null_mac, dm->m_radio[0].m_radio_info.intf.mac, sizeof(mac_address_t)) == 0) &&
                    (em->is_al_interface_em() == false)) {
                    //em_printfout("Push to queue since null mac");	
                    queue_push(pcmd->m_em_candidates, em);
                    count++;
                } else if ((memcmp(em->get_radio_interface_mac(), dm->m_radio[0].m_radio_info.intf.mac, sizeof(mac_address_t)) == 0) &&
                    (em->is_al_interface_em() == false)) {
                    //mac_addr_str_t mac_str;
                    //dm_easy_mesh_t::macbytes_to_string(em->get_radio_interface_mac(), mac_str);
                    //em_printfout("Auto config renew %s push to queue since mac matches", mac_str);
                    queue_push(pcmd->m_em_candidates, em);
                    count++;
                }
                break;

            case em_cmd_type_sta_assoc:
                dm = em->get_data_model();
                dm_easy_mesh_t::string_to_macbytes(pcmd->m_param.u.args.args[0], dev_mac);
                if ((em->is_al_interface_em() == false) &&
                    (memcmp(dm->get_agent_al_interface_mac(), dev_mac, sizeof(mac_address_t)) == 0) &&
                    (count == 0)) {
                    em_printfout("sta_assoc: using radio %s for dev %s orch_op: %s",
                        util::mac_to_string(em->get_radio_interface_mac()).c_str(),
                        pcmd->m_param.u.args.args[0],
                        em_cmd_t::get_orch_op_str(pcmd->get_orch_op()));
                    queue_push(pcmd->m_em_candidates, em);
                    count++;
                }
                break;

            case em_cmd_type_sta_link_metrics:
                if ((em->is_al_interface_em() == false) &&
                    (em->get_state() == em_state_ctrl_configured) &&
                    (em->has_at_least_one_associated_sta() == true)) {
                    queue_push(pcmd->m_em_candidates, em);
                    count++;
                }
                break;
            case em_cmd_type_set_channel:
                if ((em->is_al_interface_em() == false) && (!pcmd->m_param.u.args.num_args)) {
                    dm = pcmd->get_data_model();
                    if (memcmp(em->get_radio_interface_mac(), dm->m_radio[0].m_radio_info.intf.mac, sizeof(mac_address_t)) == 0) {
                        queue_push(pcmd->m_em_candidates, em);
                        count++;
                    }
                } else if (em->is_al_interface_em() == false) {
                    for (i = 0; i < pcmd->m_param.u.args.num_args; i++) {
                        if (atoi(pcmd->m_param.u.args.args[i]) == em->get_band()) {
                            //mac_addr_str_t mac_str;
                            //dm_easy_mesh_t::macbytes_to_string(em->get_radio_interface_mac(), mac_str);
                            //em_printfout("Set Channel: %s push to queue", mac_str);
                            queue_push(pcmd->m_em_candidates, em);
                            count++;
                            break;
                        }
                    }
                }
                break;

            case em_cmd_type_scan_channel:
                dm = pcmd->get_data_model();
                if (em->is_al_interface_em() == false) {
                    if (memcmp(em->get_radio_interface_mac(), dm->m_radio[0].m_radio_info.intf.mac, sizeof(mac_address_t)) == 0) {
                        //mac_addr_str_t mac_str;
                        //dm_easy_mesh_t::macbytes_to_string(em->get_radio_interface_mac(), mac_str);
                        //em_printfout("Channel Scan: %s pushed to queue", mac_str);
                        queue_push(pcmd->m_em_candidates, em);
                        count++;
                    }
                }
                break;

            case em_cmd_type_sta_steer:
                if (em->find_sta(pcmd->m_param.u.steer_params.sta_mac, pcmd->m_param.u.steer_params.source) != NULL) {
                    queue_push(pcmd->m_em_candidates, em);
                    count++;
                }
                break;

            case em_cmd_type_client_assoc_ctrl_req:
                if (em->is_al_interface_em() == false) {
                    em_cmd_client_assoc_params_t *assoc = &pcmd->m_param.u.client_assoc_params;
                    mac_addr_str_t em_mac_str;
                    dm_easy_mesh_t::macbytes_to_string(em->get_radio_interface_mac(), em_mac_str);

                    dm_bss_t *bss = em->find_bss(assoc->bssid);
                    if (bss == NULL || bss->m_bss_info.vap_mode != em_vap_mode_ap) {
                        em_printfout("Skipping radio %s (BSSID not AP on this EM)\n", em_mac_str);
                        break;
                    }
                    em_printfout("Pushing radio %s as candidate for client assoc ctrl\n", em_mac_str);
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
                // handled before the loop
                break;

            case em_cmd_type_set_radio:
                dm = pcmd->get_data_model();
                for (i = 0; i < dm->get_num_radios(); i++) {
                    if (memcmp(em->get_radio_interface_mac(), dm->m_radio[i].m_radio_info.intf.mac, sizeof(mac_address_t)) == 0) {
                        //mac_addr_str_t mac_str;
                        //dm_easy_mesh_t::macbytes_to_string(em->get_radio_interface_mac(), mac_str);
                        //em_printfout("Set Radio: %s pushed to queue", mac_str);
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
                if ((memcmp(em->get_radio_interface_mac(), rad_mac, sizeof(mac_address_t)) == 0)) {
                    queue_push(pcmd->m_em_candidates, em);
                    count++;
                    em_printfout("BSTA CAP count: %d; push to queue for em radio: %s", count, util::mac_to_string(em->get_radio_interface_mac()).c_str());
                    break;
                }
                break;
            case em_cmd_type_unassoc_sta_query:
                if (count == 0 && memcmp(em->get_data_model()->get_agent_al_interface_mac(),
                    pcmd->m_param.u.unassoc_sta_query_params.al_mac, sizeof(mac_address_t)) == 0) {
                    queue_push(pcmd->m_em_candidates, em);
                    count++;
                }
                break;

            case em_cmd_type_beacon_query:
                // An MLD/multi-link STA can have a dm_sta_t record on more than one
                // radio; cap to the first match (mirroring em_cmd_type_unassoc_sta_query
                // above) so the query is only sent/completed once instead of on every
                // affiliated link's radio.
                if (count == 0 && em->find_sta(pcmd->m_param.u.beacon_metrics_params.sta_mac_addr) != NULL) {
                    queue_push(pcmd->m_em_candidates, em);
                    count++;
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
