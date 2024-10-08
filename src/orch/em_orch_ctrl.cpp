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
#include "em_orch_ctrl.h"

extern char *global_netid;

void em_orch_ctrl_t::orch_transient(em_cmd_t *pcmd, em_t *em)
{
    em_cmd_stats_t *stats;
    em_short_string_t key;

    snprintf(key, sizeof(em_short_string_t), "%d", pcmd->get_type());

    stats = (em_cmd_stats_t *)hash_map_get(m_cmd_map, key);
    assert(stats != NULL);
    if (stats->time > EM_MAX_CMD_TTL) {
        printf("%s:%d: Canceling comd: %s because time limit exceeded\n", __func__, __LINE__, pcmd->get_cmd_name());
        cancel_command(pcmd->get_type());
    }   

}

bool em_orch_ctrl_t::is_em_ready_for_orch_fini(em_cmd_t *pcmd, em_t *em)
{
    // if the command is SetSSID and 5 renews have been sent transition to fini

    switch (pcmd->m_type) {
        case em_cmd_type_set_ssid:
            if (em->get_renew_tx_count() >= EM_MAX_RENEW_TX_THRESH) {
                em->set_state(em_state_ctrl_idle);
                em->set_renew_tx_count(0);
                printf("%s:%d: Maximum renew tx threshold crossed, transitioning to fini\n", __func__, __LINE__);
                return true;
            }
            break;

        case em_cmd_type_topo_sync:
            if (em->get_topo_query_tx_count() >= EM_MAX_TOPO_QUERY_TX_THRESH) {
                em->set_state(em_state_ctrl_idle);
                em->set_topo_query_tx_count(0);
                printf("%s:%d: Maximum topo sync tx threshold crossed, transitioning to fini\n", __func__, __LINE__);
                return true;
            }
            break;
    }

    return false;
}

bool em_orch_ctrl_t::is_em_ready_for_orch_exec(em_cmd_t *pcmd, em_t *em)
{
    if ((em->get_state() == em_state_ctrl_none) || (em->get_state() == em_state_ctrl_idle)) {
        return true;
    } else if (pcmd->m_type == em_cmd_type_set_ssid) {
        return true;
    } else if (pcmd->m_type == em_cmd_type_topo_sync) {
        return true;
    }
    return false;
}

bool em_orch_ctrl_t::pre_process_orch_op(em_cmd_t *pcmd)
{
    em_t *em;
    em_ctrl_t *ctrl = (em_ctrl_t *)m_mgr;
    dm_easy_mesh_ctrl_t *dm_ctrl = (dm_easy_mesh_ctrl_t *)ctrl->get_data_model(global_netid);
    dm_easy_mesh_t *dm = &pcmd->m_data_model;
    dm_easy_mesh_t *mgr_dm;
    mac_addr_str_t	mac_str;

    printf("%s:%d: Orchestration operation: %s\n", __func__, __LINE__, em_cmd_t::get_orch_op_str(pcmd->get_orch_op()));
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
            mgr_dm = m_mgr->get_data_model(global_netid, pcmd->get_al_interface_mac());
            if (mgr_dm == NULL) {
                break;
            }
			dm_easy_mesh_t::macbytes_to_string(pcmd->get_al_interface_mac(), mac_str);	
			//printf("%s:%d: DM of net_id: %s, AL MAC: %s Manager dm: %p\n", __func__, __LINE__, global_netid, mac_str, mgr_dm);
            
            // for device insert, just create the al interface em and return, do not submit command
            em = m_mgr->create_node(pcmd->get_ctrl_al_interface(), em_freq_band_unknown, mgr_dm, true, em_profile_type_3, em_service_type_ctrl);
            if (em != NULL) {
                // since this does not have to go through orchestration of M1 M2, commit the data model
                em->get_data_model()->commit_config(pcmd->m_data_model, em_commit_target_em);
            }
            break;

        case dm_orch_type_tx_cfg_renew:
            break;

        case dm_orch_type_db_delete:
			dm->set_db_cfg_type(db_cfg_type_device_list_delete|db_cfg_type_radio_list_delete|db_cfg_type_bss_list_delete|db_cfg_type_op_class_list_delete|db_cfg_type_op_class_list_delete);
            m_mgr->update_tables(dm);
			break;

		case dm_orch_type_dm_delete:
			printf("%s:%d: Deleting data model\n", __func__, __LINE__);
			m_mgr->delete_data_model((dm->get_device())->m_device_info.net_id, (dm->get_device())->m_device_info.id.mac);
			break;

		case dm_orch_type_dm_delete_all:
			printf("%s:%d: Deleting all data models\n", __func__, __LINE__);
			m_mgr->delete_all_data_models();
			break;

		case dm_orch_type_em_update:
            break;  

		case dm_orch_type_net_ssid_update:
			m_mgr->load_net_ssid_table();
            break;  

        /*case dm_orch_type_topology_response:
            mgr_dm = m_mgr->get_data_model(global_netid, pcmd->get_al_interface_mac());
            em = mgr_dm->get_em();
			em->test_topology_response_msg();	
            submit = false;
			break;*/

        default:
            break;
    }

    return pcmd->get_orch_submit();
}

unsigned int em_orch_ctrl_t::build_candidates(em_cmd_t *pcmd)
{
    em_t *em;
    unsigned int count = 0, i;

    if (pcmd->m_type == em_cmd_type_topo_sync) {
        em = (em_t *)hash_map_get(m_mgr->m_em_map, pcmd->m_param.args[0]);
        if (em != NULL) {
            queue_push(pcmd->m_em_candidates, em);
            count++;
        }

        return count;
    }

    em = (em_t *)hash_map_get_first(m_mgr->m_em_map);	
    while (em != NULL) {
        switch (pcmd->m_type) {
            case em_cmd_type_set_ssid:
                for (i = 0; i < pcmd->get_num_network_ssid(); i++) {
                    if (em->is_set_ssid_candidate(pcmd->get_network_ssid(i))) {
                        queue_push(pcmd->m_em_candidates, em);
                        count++;
                    }
                }
                break;

            case em_cmd_type_start_dpp:
                if (em->is_start_dpp_candidate(pcmd->get_dpp())) {
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

            default:
                break;
        }			
        em = (em_t *)hash_map_get_next(m_mgr->m_em_map, em);	
    }

    return count;
}

em_orch_ctrl_t::em_orch_ctrl_t(em_mgr_t *mgr)
{
    m_mgr = mgr;
}
