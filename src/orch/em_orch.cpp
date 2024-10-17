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
#include "em_orch.h"
#include "util.h"

unsigned int em_orch_t::submit_commands(em_cmd_t *pcmd[], unsigned int num)
{
    unsigned int i,j;	
    unsigned int submitted = 0;
    bool submit = true;
    em_t *em;

    for (i = 0; i < num; i++) {
        if ((submit = pre_process_orch_op(pcmd[i])) == false) {
            // complete the command
            destroy_command(pcmd[i]);	
            submit = true;
            continue;
        } else {
            submitted += submit_command(pcmd[i]);
        }
    }	

    //printf("%s:%d: Submitted commands count:%d\n", __func__, __LINE__, submitted);

    return submitted;
}

void em_orch_t::update_stats(em_cmd_t *pcmd)
{
    struct timeval  time_now;
    em_cmd_stats_t *stats;
    unsigned int time = 0;
    em_short_string_t key;

    snprintf(key, sizeof(em_short_string_t), "%d", pcmd->get_type());

    gettimeofday(&time_now, NULL);
    stats = (em_cmd_stats_t *)hash_map_get(m_cmd_map, key);
    assert(stats != NULL);
    time = time_now.tv_sec - pcmd->m_start_time.tv_sec;
    if (stats->time < time) {
        stats->time = time;
    }

    //printf("%s:%d: Cmd execution time spent: %d senconds\n", __func__, __LINE__, stats->time);
}

void em_orch_t::pop_stats(em_cmd_t *pcmd)
{
    em_short_string_t key;
    em_cmd_stats_t *stats;

    snprintf(key, sizeof(em_short_string_t), "%d", pcmd->get_type());
    stats = (em_cmd_stats_t *)hash_map_get(m_cmd_map, key);
    if (stats == NULL) {
        return;
    }


    stats->count--;
    if (stats->count == 0) {
        hash_map_remove(m_cmd_map, key);
        free(stats);
    }
}

void em_orch_t::push_stats(em_cmd_t *pcmd)
{
    em_short_string_t key;
    em_cmd_stats_t *stats;

    snprintf(key, sizeof(em_short_string_t), "%d", pcmd->get_type());
    stats = (em_cmd_stats_t *)hash_map_get(m_cmd_map, key);
    if (stats == NULL) {
        stats = (em_cmd_stats_t *)malloc(sizeof(em_cmd_stats_t));
        memset(stats, 0, sizeof(em_cmd_stats_t));
        stats->type = pcmd->get_type();
        hash_map_put(m_cmd_map, strdup(key), stats);
    }	

    stats->count++;
}

bool em_orch_t::submit_command(em_cmd_t *pcmd)
{
    bool submitted = false;

    // build em candidates in cmd;
    if (build_candidates(pcmd) == 0) {
        // if there are no candidates, complete the command
        destroy_command(pcmd);
    } else {
        queue_push(m_pending, pcmd);
        push_stats(pcmd);
        submitted = true;
    }

    return submitted;
}

void em_orch_t::destroy_command(em_cmd_t *pcmd)
{
    unsigned int count;

    // remove candidates from queue
    while (count = queue_count(pcmd->m_em_candidates)) {
        queue_remove(pcmd->m_em_candidates, count - 1);
    }	

    pcmd->deinit();

    delete pcmd;
}

void em_orch_t::cancel_command(em_cmd_type_t type) 
{
    signed int i, j;
    em_cmd_t *pcmd;
    em_t *em;
    mac_addr_str_t	mac_str;

    // first go through the pending queue and remove the commnands
    for (i = queue_count(m_pending) - 1; i >= 0; i--) {
        pcmd = (em_cmd_t *)queue_peek(m_pending, i); 
        if (pcmd->m_type == type) {
            for (j = queue_count(pcmd->m_em_candidates) - 1; j >= 0; j--) {
                queue_remove(pcmd->m_em_candidates, j);
            }

            queue_remove(m_pending, i);
            pop_stats(pcmd);
            destroy_command(pcmd);
        }   
    } 
    // go though active queue and finish the commands
    for (i = queue_count(m_active) - 1; i >= 0; i--) {
        pcmd = (em_cmd_t *)queue_peek(m_active, i);
        if (pcmd->m_type == type) {
            for (j = queue_count(pcmd->m_em_candidates) - 1; j >= 0; j--) {
                em = (em_t *)queue_peek(pcmd->m_em_candidates, j);
                dm_easy_mesh_t::macbytes_to_string(em->get_radio_interface_mac(), mac_str);
                printf("%s:%d: Setting em:%s State set to cancel\n", __func__, __LINE__, mac_str);
                pre_process_cancel(pcmd, em);
                em->set_orch_state(em_orch_state_cancel);
            }
        }
    }
}

bool em_orch_t::orchestrate(em_cmd_t *pcmd, em_t *em)
{
    bool done = false;
    em_orch_state_t orch_state;
    mac_addr_str_t	mac_str;

    orch_state = em->get_orch_state();

    dm_easy_mesh_t::macbytes_to_string(em->get_radio_interface_mac(), mac_str);

    if (orch_state == em_orch_state_pending) {
        if (is_em_ready_for_orch_exec(pcmd, em) == true) {
            // ask em to execute the command
            printf("%s:%d: Start executing cmd:%s, Orchestartion:%s\n", __func__, __LINE__, 
				em_cmd_t::get_cmd_type_str(pcmd->m_type), em_cmd_t::get_orch_op_str(pcmd->get_orch_op()));
            pcmd->set_start_time();
            em->orch_execute(pcmd);
        } else {
            printf("%s:%d: skipping em orchestration because of incorrect state, state: %d\n", __func__, __LINE__, em->get_state());
        }

    } else if (orch_state == em_orch_state_progress) {
        if (is_em_ready_for_orch_fini(pcmd, em) == true) {
            em->set_orch_state(em_orch_state_fini);
        } else {
            update_stats(pcmd);
            orch_transient(pcmd, em);
        }

    } else if (orch_state == em_orch_state_fini) {
        printf("%s:%d: em:%s Detected in fini state\n", __func__, __LINE__, mac_str);
        done = true;
    }

    return done;
}

bool em_orch_t::eligible_for_active(em_cmd_t *pcmd)
{
    signed int i;
    bool eligible = true;
    em_t *em;

    for (i = queue_count(pcmd->m_em_candidates) - 1; i >= 0; i--) {
        em = (em_t *)queue_peek(pcmd->m_em_candidates, i);
        if (em->get_orch_state() != em_orch_state_idle) {
            eligible = false;
            break;
        }
    }

    return eligible;
}

bool em_orch_t::is_cmd_type_in_progress(em_bus_event_type_t etype)
{
    em_cmd_stats_t *stats;
    em_short_string_t key;
    em_cmd_type_t	type;

    type = em_cmd_t::bus_2_cmd_type(etype);	

    snprintf(key, sizeof(em_short_string_t), "%d", type);

    if ((stats = (em_cmd_stats_t *)hash_map_get(m_cmd_map, key)) != NULL) {
        printf("%s:%d: Command of type: %d actively executing\n", __func__, __LINE__, type);
        return true;
    }

    return false;
}

void em_orch_t::handle_timeout()
{
    em_cmd_t *pcmd;
    em_t *em;
    signed int i, j; 
    unsigned int cnt;
    bool eligible_to_move = false;
    bool ret = true;

    // go through pending queue and check if the commands can be moved to active
    for (i = queue_count(m_pending) - 1; i >= 0; i--) {
        pcmd = (em_cmd_t *)queue_peek(m_pending, i);
        if (eligible_for_active(pcmd) == true) {
            queue_remove(m_pending, i);
            //printf("%s:%d: Cmd: %s Orch Type: %s eligible for active\n", __func__, __LINE__, 
                    //pcmd->get_cmd_name(), em_cmd_t::get_orch_op_str(pcmd->get_orch_op()));
            eligible_to_move = true;
            break;			
        }
    }	

    if (eligible_to_move == true) {
        for (i = queue_count(pcmd->m_em_candidates) - 1; i >= 0; i--) {
            em = (em_t *)queue_peek(pcmd->m_em_candidates, i);
            em->set_orch_state(em_orch_state_pending);
        }

        queue_push(m_active, pcmd);
    } else {
        if ((cnt = queue_count(m_pending))) {
            pcmd = (em_cmd_t *)queue_peek(m_pending, cnt - 1);
            //printf("%s:%d:%d Command in pending but not eligible for active\n", __func__, __LINE__, cnt);
        }
    }


    // go through active queue and check command states
    for (i = queue_count(m_active) - 1; i >= 0; i--) {
        pcmd = (em_cmd_t *)queue_peek(m_active, i);
        for (j = queue_count(pcmd->m_em_candidates) - 1; j >= 0; j--) {
            em = (em_t *)queue_peek(pcmd->m_em_candidates, j);
            ret &= orchestrate(pcmd, em);
        }

        if (ret == true) {
            // means the command is in fini sate 
            printf("%s:%d: Removing and destroying Command type: %s Orchestration: %s because command is in fini state\n", 
                    __func__, __LINE__, pcmd->get_cmd_name(), em_cmd_t::get_orch_op_str(pcmd->get_orch_op()));
            queue_remove(m_active, i);
            pop_stats(pcmd);
            for (j = queue_count(pcmd->m_em_candidates) - 1; j >= 0; j--) {
                em = (em_t *)queue_peek(pcmd->m_em_candidates, j);
                em->set_orch_state(em_orch_state_idle);
            }
            destroy_command(pcmd);
            em->set_state(em_state_agent_config_complete);
            break;
        }

    }

}

em_orch_t::em_orch_t()
{
    m_pending = queue_create();
    m_active = queue_create();
    m_cmd_map = hash_map_create();
}

em_orch_t::~em_orch_t()
{

}
