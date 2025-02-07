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

#ifndef DM_DEVICE_H
#define DM_DEVICE_H

#include "em_base.h"

class dm_device_t {
public:
    em_device_info_t    m_device_info;

public:
    int init() { memset(&m_device_info, 0, sizeof(em_device_info_t)); return 0; }
    em_device_info_t *get_device_info() { return &m_device_info; }
	
    int decode(const cJSON *obj, void *parent_id);
    void encode(cJSON *obj, bool summary = false);

    em_interface_t *get_dev_interface() { return &m_device_info.intf; }
    unsigned char *get_dev_interface_mac() { return m_device_info.intf.mac; }
    char *get_dev_interface_name() { return m_device_info.intf.name; }
    void set_dev_interface_mac(unsigned char *mac) { memcpy(m_device_info.intf.mac, mac, sizeof(mac_address_t)); }
    void set_dev_interface_name(char *name) { strncpy(m_device_info.intf.name, name, strlen(name) + 1); }
	
    em_interface_t *get_al_interface() { return &m_device_info.backhaul_alid; }
    unsigned char *get_al_interface_mac() { return m_device_info.backhaul_alid.mac; }
    char *get_al_interface_name() { return m_device_info.backhaul_alid.name; }

    char *get_manufacturer() { return m_device_info.manufacturer; }
    char *get_manufacturer_model() { return m_device_info.manufacturer_model; }
    char *get_software_version() { return m_device_info.software_ver; }
    char *get_serial_number() { return m_device_info.serial_number; }
    char *get_primary_device_type() { return m_device_info.primary_device_type; }
	
    void set_manufacturer(char *manufacturer) { snprintf(m_device_info.manufacturer, sizeof(m_device_info.manufacturer), "%s", manufacturer); }
    void set_manufacturer_model(char *model) { snprintf(m_device_info.manufacturer_model, sizeof(m_device_info.manufacturer_model), "%s", model); }
    void set_software_version(char *version) { snprintf(m_device_info.software_ver, sizeof(m_device_info.software_ver), "%s", version); }
    void set_serial_number(char *serial) { snprintf(m_device_info.serial_number, sizeof(m_device_info.serial_number), "%s", serial); }
    void set_primary_device_type(char *type) { snprintf(m_device_info.primary_device_type, sizeof(m_device_info.primary_device_type), "%s", type); }
    bool operator == (const dm_device_t& obj);
    void operator = (const dm_device_t& obj);
    //void operator = (const dm_device_t& obj) { memcpy(&m_device_info, &obj.m_device_info, sizeof(em_device_info_t)); }
    dm_orch_type_t get_dm_orch_type(const dm_device_t& device);

    static int parse_device_id_from_key(const char *key, em_device_id_t *id);
    int update_easymesh_json_cfg(bool colocated_mode);

    dm_device_t(em_device_info_t *dev);
    dm_device_t(const dm_device_t& dev);
    dm_device_t();
    ~dm_device_t();
};

#endif
