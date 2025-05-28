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
#include "em_ctrl.h"
#include "tr_181.h"

extern em_ctrl_t g_ctrl;
extern char *global_netid;
bus_error_t em_ctrl_t::get_device_wifi_dataelements_network_colocated_agentid (char *event_name, raw_data_t *p_data, bus_user_data_t *user_data)
{
	em_interface_t  *intf;
	mac_addr_str_t  al_mac_str;
	int len = 0;
	intf = g_ctrl.m_data_model.get_ctrl_al_interface(const_cast<char *> (global_netid));
	
        dm_easy_mesh_t::macbytes_to_string(intf->mac, al_mac_str);
        p_data->data_type    = bus_data_type_string;
	len = strlen(al_mac_str);
	p_data->raw_data.bytes = malloc(len);
	if (p_data->raw_data.bytes == NULL) {
		printf("%s:%d memory allocation is failed:%d\r\n",__func__,__LINE__, len);
		return bus_error_out_of_resources;
	}
	snprintf((char*)p_data->raw_data.bytes, len, "%s", al_mac_str);
	p_data->raw_data_len = len;
	return bus_error_success;
}

bus_error_t em_ctrl_t::get_device_wifi_dataelements_network_controllerid (char *event_name, raw_data_t *p_data, bus_user_data_t *user_data)
{
        em_interface_t  *intf;
	int len = 0;
        mac_addr_str_t  ctrl_mac;

	dm_easy_mesh_t::macbytes_to_string(g_ctrl.m_data_model.get_network_info()->ctrl_id.mac, ctrl_mac);
	len = strlen(ctrl_mac);
        p_data->data_type = bus_data_type_string;
        p_data->raw_data.bytes = malloc(len);
        if (p_data->raw_data.bytes == NULL) {
                printf("%s:%d memory allocation is failed:%d\r\n",__func__,__LINE__, len);
                return bus_error_out_of_resources;
        }
	snprintf((char*)p_data->raw_data.bytes, len, "%s", ctrl_mac);
        p_data->raw_data_len = len;
        printf("%s:%d descriptor value=%s %d\n", __func__, __LINE__, (char *)p_data->raw_data.bytes, p_data->raw_data_len);
	return bus_error_success;
}

