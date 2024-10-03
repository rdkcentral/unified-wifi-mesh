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
#include "em_ctrl.h"
#include "em_cmd_ctrl.h"
#include "dm_easy_mesh.h"
#include "em_orch_ctrl.h"

em_ctrl_t g_ctrl;
const char *global_netid = "Private";


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
    } else if ((num = m_data_model.analyze_client_steer(evt, pcmd)) == 0) {
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
    } else if ((num = m_data_model.analyze_network_ssid_list(evt, pcmd)) == 0) {
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

    if (m_orch->is_cmd_type_in_progress(evt->type) == true) {
        m_ctrl_cmd->send_result(em_cmd_out_status_prev_cmd_in_progress);
    } else if ((num = m_data_model.analyze_network_ssid_list(evt, pcmd)) == 0) {
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
    if (params->num_args < 1) {
        m_ctrl_cmd->send_result(em_cmd_out_status_invalid_input);
        return;
    }       
            
    m_data_model.get_config(params->args[1], &evt->u.subdoc);
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

void em_ctrl_t::handle_topology_req()
{
    em_t *em;

    em = em = (em_t *)hash_map_get_first(m_em_map);
    while (em != NULL) {
        if (em->is_al_interface_em() == false) {
            em->send_topology_query_msg();
        }
        em = em = (em_t *)hash_map_get_next(m_em_map, em);
    }
}

void em_ctrl_t::handle_radio_metrics_req()
{
    em_cmd_t *pcmd[EM_MAX_CMD] = {NULL};
    unsigned int num = 0;

    if ((num = m_data_model.analyze_radio_metrics_req(pcmd)) != 0) {
        if (m_orch->submit_commands(pcmd, num) == 0) {
            printf("%s:%d: Radio metrics request not submitted\n", __func__, __LINE__);
        }
    } else {
        //printf("%s:%d: Radio metrics request command not created\n", __func__, __LINE__);
    }
}

void em_ctrl_t::handle_ap_metrics_req()
{
    em_cmd_t *pcmd[EM_MAX_CMD] = {NULL};
    unsigned int num = 0;

    if ((num = m_data_model.analyze_ap_metrics_req(pcmd)) != 0) {
        if (m_orch->submit_commands(pcmd, num) == 0) {
            printf("%s:%d: AP metrics request not submitted\n", __func__, __LINE__);
        }
    } else {
        //printf("%s:%d: AP metrics request command not created\n", __func__, __LINE__);
    }
}

void em_ctrl_t::handle_client_metrics_req()
{
    em_cmd_t *pcmd[EM_MAX_CMD] = {NULL};
    unsigned int num = 0;

    if ((num = m_data_model.analyze_client_metrics_req(pcmd)) != 0) {
        if (m_orch->submit_commands(pcmd, num) == 0) {
            printf("%s:%d: Client metrics request not submitted\n", __func__, __LINE__);
        }
    } else {
        //printf("%s:%d: Client metrics request command not created\n", __func__, __LINE__);
    }
}

void em_ctrl_t::handle_timeout()
{
    handle_dirty_dm();
    handle_5s_timeout();
    m_orch->handle_timeout();
}

void em_ctrl_t::handle_dirty_dm()
{
	m_data_model.handle_dirty_dm();
}

void em_ctrl_t::handle_5s_timeout()
{
    char buffer[30];
    struct timeval tv;
    time_t curtime;

    m_tick_demultiplex++;
    if ((m_tick_demultiplex % EM_METRICS_REQ_MULT) != 0) {
        return;
    }
    gettimeofday(&tv, NULL);
    curtime = tv.tv_sec;

    //strftime(buffer,30,"%m-%d-%Y  %T.",localtime(&curtime));
    //printf("%s:%d: %s%ld\n", __func__, __LINE__, buffer, tv.tv_usec);
    handle_topology_req();
    handle_radio_metrics_req();
    handle_ap_metrics_req();
    handle_client_metrics_req();
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
            handle_dev_test(evt);
            break;

        case em_bus_event_type_get_network:
        case em_bus_event_type_get_ssid:
        case em_bus_event_type_get_channel:
        case em_bus_event_type_get_bss:
        case em_bus_event_type_get_sta:
            handle_get_dm_data(evt);
            break;

        case em_bus_event_type_set_ssid:
            handle_set_ssid_list(evt);  
            break;

        case em_bus_event_type_set_channel:
            handle_set_channel_list(evt);
            break;

        case em_bus_event_type_start_dpp:
            handle_start_dpp(evt);  
            break;

        case em_bus_event_type_client_steer:
            handle_client_steer(evt);   
            break;

        case em_bus_event_type_dm_commit:
            handle_dm_commit(evt);
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
    
    if (m_data_model.init(data_model_path) != 0) {
        printf("%s:%d: data model init failed\n", __func__, __LINE__);
        return 0;
    }

    intf = m_data_model.get_ctrl_al_interface((char *)global_netid);
    dm_easy_mesh_t::macbytes_to_string((unsigned char *)intf->mac, mac_str);

    if ((dm = get_data_model(global_netid, intf->mac)) == NULL) {
        printf("%s:%s:%d: Could not find data model for mac:%s\n", __FILE__, __func__, __LINE__, mac_str);
    } else {
        printf("%s:%s:%d: Data model found, creating node for mac:%s\n", __FILE__, __func__, __LINE__, mac_str);
        dm->print_config();

        if ((em = create_node(intf, dm, true, em_profile_type_3, em_service_type_ctrl)) == NULL) {
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

em_ctrl_t::em_ctrl_t()
{
    m_tick_demultiplex = 0;
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

