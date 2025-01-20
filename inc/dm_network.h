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

#ifndef DM_NETWORK_H
#define DM_NETWORK_H

#include "em_base.h"

class dm_network_t {
public:
    em_network_info_t   m_net_info;

public:
    int init();
    em_network_info_t *get_network_info() { return &m_net_info; }
    
    int decode(const cJSON *obj, void *parent_id);
    void encode(cJSON *obj, bool summary = false);

    char *get_network_id() { return m_net_info.id; }

    em_interface_t *get_controller_interface() { return &m_net_info.ctrl_id; }
    unsigned char *get_controller_interface_mac() { return m_net_info.ctrl_id.mac; }

    em_interface_t *get_colocated_agent_interface() { return &m_net_info.colocated_agent_id; }
    unsigned char *get_colocated_agent_interface_mac() { return m_net_info.colocated_agent_id.mac; }
    char *get_colocated_agent_interface_name() { return m_net_info.colocated_agent_id.name; }
    void set_colocated_agent_interface_mac(unsigned char *mac) { memcpy(m_net_info.colocated_agent_id.mac, mac, sizeof(mac_address_t)); }
    void set_colocated_agent_interface_name(char *name) { snprintf(m_net_info.colocated_agent_id.name, sizeof(m_net_info.colocated_agent_id.name), "%s", name); }

    bool operator == (const dm_network_t& obj);
    //void operator = (const dm_network_t& obj) { memcpy(&m_net_info, &obj.m_net_info, sizeof(em_network_info_t)); }
    void operator = (const dm_network_t& obj);

    dm_network_t(em_network_info_t *net);
    dm_network_t(const dm_network_t& net);
    dm_network_t();
    ~dm_network_t();    
};

#endif
