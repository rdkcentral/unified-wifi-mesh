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
#include <ctype.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>
#include <signal.h>
#include <unistd.h>
#include <math.h>
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
#include <sys/types.h>
#include <ifaddrs.h>
#include "dm_easy_mesh.h"
#include "em_cmd_dev_init.h"
#include <cjson/cJSON.h>
#include "em_cmd_sta_list.h"
#include "em_cmd_ap_cap.h"
#include "em_cmd_autoconfig_renew.h"
#include "em_cmd_client_cap.h"

dm_easy_mesh_t dm_easy_mesh_t::operator =(dm_easy_mesh_t const& obj)
{
    dm_sta_t *sta;

    memcpy(&this->m_device, &obj.m_device, sizeof(dm_device_t));
    memcpy(&this->m_network, &obj.m_network, sizeof(dm_network_t));
    memcpy(&this->m_ieee_1905_security, &obj.m_ieee_1905_security, sizeof(dm_ieee_1905_security_t));
    
    this->m_num_radios = obj.m_num_radios;
    for (unsigned int i = 0; i < obj.m_num_radios; i++) {
        memcpy(&this->m_radio[i], &obj.m_radio[i], sizeof(dm_radio_t));
    }

    this->m_num_bss = obj.m_num_bss;
    for (unsigned int i = 0; i < EM_MAX_BSSS; i++) {
        memcpy(&this->m_bss[i], &obj.m_bss[i], sizeof(dm_bss_t));
    }
    memcpy(&this->m_dpp, &obj.m_dpp, sizeof(dm_dpp_t));

    this->m_num_opclass = obj.m_num_opclass;
    for (unsigned int i = 0; i < EM_MAX_OPCLASS; i++) {
        memcpy(&this->m_op_class[i], &obj.m_op_class[i], sizeof(dm_op_class_t));
    }

    this->m_num_net_ssids = obj.m_num_net_ssids;
    for (unsigned int i = 0; i < EM_MAX_NET_SSIDS; i++) {
        memcpy(&this->m_network_ssid[i], &obj.m_network_ssid[i], sizeof(dm_network_ssid_t));
    }

    this->m_db_cfg_type = obj.m_db_cfg_type;

    hash_map_t **dst_m_sta_assoc_map = (hash_map_t** ) this->get_assoc_sta_map();
    hash_map_t **dst_m_sta_dassoc_map = (hash_map_t** ) this->get_dassoc_sta_map();
    hash_map_t **dst_m_sta_map = (hash_map_t** ) this->get_sta_map();

    *dst_m_sta_assoc_map = hash_map_create();
    *dst_m_sta_dassoc_map = hash_map_create();
    *dst_m_sta_map = hash_map_create();

    hash_map_t **m_sta_map = (hash_map_t** ) &obj.m_sta_map;
    if((m_sta_map != NULL) && (*m_sta_map != NULL)) {
        sta = (dm_sta_t *)hash_map_get_first(*m_sta_map);
        while (sta != NULL) {
            hash_map_put(*dst_m_sta_map,strdup(sta->get_sta_info()->m_sta_key),sta);
            sta = (dm_sta_t *)hash_map_get_next(*m_sta_map, sta);
            }
    }

    hash_map_t **m_sta_assoc_map = (hash_map_t** ) &obj.m_sta_assoc_map;
    if((m_sta_assoc_map != NULL) && (*m_sta_assoc_map != NULL)) {
        sta = (dm_sta_t *)hash_map_get_first(*m_sta_assoc_map);
        while (sta != NULL) {
	    hash_map_put(*dst_m_sta_assoc_map,strdup(sta->get_sta_info()->m_sta_key),sta);
            sta = (dm_sta_t *)hash_map_get_next(*m_sta_assoc_map, sta);
            }
    }

    hash_map_t **m_sta_dassoc_map = (hash_map_t** ) &obj.m_sta_dassoc_map;

    if((m_sta_dassoc_map != NULL) && (*m_sta_dassoc_map != NULL)) {
        sta = (dm_sta_t *)hash_map_get_first(*m_sta_dassoc_map);
        while (sta != NULL) {
            hash_map_put(*dst_m_sta_dassoc_map,strdup(sta->get_sta_info()->m_sta_key),sta);
            sta = (dm_sta_t *)hash_map_get_next(*m_sta_dassoc_map, sta);
            }
    }

    this->m_em = obj.m_em;
    return *this;
}

int dm_easy_mesh_t::commit_config(dm_easy_mesh_t& dm, em_commit_target_t target)
{
    unsigned int i;
    int j = 0;
    dm_radio_t *radio;
    mac_address_t mac;
    dm_sta_t *sta;
    mac_addr_str_t mac_str;

    if ( target.type == em_commit_target_sta_hash_map ) {
        hash_map_t **m_sta_assoc_map = (hash_map_t **)dm.get_assoc_sta_map();
        hash_map_t **em_m_sta_map = get_sta_map();

        if ((m_sta_assoc_map != NULL) && (*m_sta_assoc_map != NULL)) {
            sta = (dm_sta_t *)hash_map_get_first(*m_sta_assoc_map);
            while (sta != NULL) {
                // update the em
                if ((em_m_sta_map != NULL) && (*em_m_sta_map != NULL)) {
                    hash_map_put(*em_m_sta_map,strdup(sta->get_sta_info()->m_sta_key),sta);
                    printf("%s:%d: node with key:%s updated\n", __func__, \
                                 __LINE__,sta->get_sta_info()->m_sta_key);
                    sta = (dm_sta_t *)hash_map_get_next(*m_sta_assoc_map, sta);
                    continue;
                } else {
                    *em_m_sta_map = hash_map_create();
                    hash_map_put(*em_m_sta_map,strdup(sta->get_sta_info()->m_sta_key),sta);
                    printf("%s:%d: New node created with key:%s \n", __func__,\
                             __LINE__,sta->get_sta_info()->m_sta_key);
                    sta = (dm_sta_t *)hash_map_get_next(*m_sta_assoc_map, sta);
                    continue;
                }
                sta = (dm_sta_t *)hash_map_get_next(*m_sta_assoc_map, sta);
            }
        }
        hash_map_t **m_sta_dassoc_map = (hash_map_t **)dm.get_dassoc_sta_map();
        if ((m_sta_dassoc_map != NULL) && (*m_sta_dassoc_map != NULL) && \
             (em_m_sta_map != NULL) && (*em_m_sta_map != NULL )) {
             sta = (dm_sta_t *)hash_map_get_first(*m_sta_dassoc_map);
             while (sta != NULL) {
                hash_map_remove(*em_m_sta_map,sta->get_sta_info()->m_sta_key);
                printf("%s:%d: node with key:%s removed\n", __func__,\
                                 __LINE__,sta->get_sta_info()->m_sta_key);
                sta = (dm_sta_t *)hash_map_get_next(*m_sta_dassoc_map, sta);
            }
        }
    } else if( target.type == em_commit_target_al) {
        m_network = dm.m_network;
        m_device = dm.m_device;
    } else if (target.type == em_commit_target_radio) {
        string_to_macbytes((char *)target.params,mac);
        radio = dm.get_radio(mac);
        if (radio != NULL) {
            for (i = 0;i < m_num_radios; i++) {
                if (memcmp(radio->get_radio_info()->id.mac, get_radio(i)->get_radio_info()->id.mac, sizeof(mac_address_t)) == 0) {
                    m_radio[i] = *(radio);
                    printf("%s:%d Radio %s configuration updated \n", __func__, __LINE__,target.params);
                    break;
                }
            }
            if (i == m_num_radios) { //New Radio
                m_radio[m_num_radios] = *(radio);
                m_num_radios = m_num_radios + 1;
                printf("%s:%d New Radio %s configuration created no of radios=%d\n", __func__, __LINE__,target.params,m_num_radios);
            }
        }
    } else if (target.type == em_commit_target_bss) {
        printf("%s:%d Commit radio=%s\n", __func__, __LINE__,target.params);
        string_to_macbytes((char *)target.params,mac);
        for (i = 0; i < dm.m_num_bss; i++) {
            for (j = 0; j < m_num_bss; j++) {

                if ((memcmp(mac, dm.get_bss(i)->get_bss_info()->ruid.mac, sizeof(mac_address_t)) == 0) &&
                    (memcmp(get_bss(j)->get_bss_info()->bssid.mac, dm.get_bss(i)->get_bss_info()->bssid.mac, sizeof(mac_address_t)) == 0)){
                        m_bss[j] = dm.m_bss[i];
                        macbytes_to_string(dm.get_bss(i)->get_bss_info()->bssid.mac,mac_str);
                        printf("%s:%d BSS %s configuration updated \n", __func__, __LINE__,mac_str);
                        break;
                }
            }
            if (j == m_num_bss) { //New bss Configuration
                m_bss[m_num_bss] = dm.m_bss[i];
                m_num_bss = m_num_bss + 1;
                macbytes_to_string(dm.get_bss(i)->get_bss_info()->bssid.mac,mac_str);
                printf("%s:%d New BSS %s configuration updated  no of bss=%d\n", __func__, __LINE__,mac_str,m_num_bss);
            }
        }
    }
    return 0;
}

int dm_easy_mesh_t::commit_config(em_tlv_type_t tlv, unsigned char *data, unsigned int len, bssid_t id, em_commit_target_t target)
{
	return 0;
}

int dm_easy_mesh_t::commit_bss_config(dm_easy_mesh_t& dm, unsigned int vap_index)
{
    int i = 0;
    if (vap_index >= EM_MAX_BSS_PER_RADIO) {
        printf("%s:%d Invalid index vap_index=%d\n", __func__, __LINE__,vap_index);
        return false;
    }
    for (i = 0; i < m_num_bss; i++) {
           if (memcmp(get_bss(i)->get_bss_info()->ruid.mac, dm.get_bss(vap_index)->get_bss_info()->ruid.mac, sizeof(mac_address_t)) == 0) {
               if (memcmp(get_bss(i)->get_bss_info()->bssid.mac, dm.get_bss(vap_index)->get_bss_info()->bssid.mac, sizeof(mac_address_t)) == 0) {
                   m_bss[i] = dm.m_bss[vap_index];
                    return true;
               }
           }
       }
    return false;
}

int dm_easy_mesh_t::commit_config(em_attrib_id_t attrib, unsigned char *data, unsigned int len, bssid_t id, em_commit_target_t target)
{
    return 0;
}

int dm_easy_mesh_t::commit_config(em_cmd_t  *cmd)
{
    switch (cmd->m_type) {
        case em_cmd_type_set_ssid:
            //To be Implemented
            break;
        case em_cmd_type_start_dpp:
            //To be Implemented
            break;
        case em_cmd_type_dev_init: {
                switch (cmd->get_orch_op()) {
                    case dm_orch_type_al_insert:
                        m_device = cmd->m_data_model.m_device;
                        break;
                    case dm_orch_type_em_insert:
                        m_radio[m_num_radios] = cmd->m_data_model.m_radio[0];
                        m_num_radios++;

                        break;
                }
            }
            break;
        default:
            break;
    }
    return 0;
}

int dm_easy_mesh_t::analyze_radio_config(em_bus_event_t *evt, em_cmd_t *pcmd[])
{
	int num = 0;
	
	printf("%s:%d: Enter\n", __func__, __LINE__);

	return num;
}

int dm_easy_mesh_t::analyze_vap_config(em_bus_event_t *evt, em_cmd_t *pcmd[])
{
	int num = 0;

	printf("%s:%d: Enter\n", __func__, __LINE__);
	return num;
}

int dm_easy_mesh_t::analyze_autoconfig_renew(em_bus_event_t *evt, em_cmd_t *pcmd[])
{
    dm_easy_mesh_t  dm;
    em_orch_desc_t desc;
    em_subdoc_info_t *subdoc;

    printf("%s:%d: Enter\n", __func__, __LINE__);

    subdoc = &evt->u.subdoc;

    if (dm.decode_config(subdoc, "Renew") == -1) {
        printf("%s:%d: Failed to decode\n", __func__, __LINE__);
        return 0;
    }
    
    desc.op = dm_orch_type_em_update;
    desc.submit = true;

    pcmd[0] = new em_cmd_autoconfig_renew_t(evt->params,dm);
    pcmd[0]->set_rd_freq_band(0);
    pcmd[0]->override_op(0, &desc);

    return 1;
}

int dm_easy_mesh_t::analyze_ap_cap_query(em_bus_event_t *evt, em_cmd_t *pcmd[])
{
    dm_easy_mesh_t  dm;
    em_orch_desc_t desc;
    em_subdoc_info_t *subdoc;
    subdoc = &evt->u.subdoc;

    desc.op = dm_orch_type_ap_cap_report;
    desc.submit = true;    

    dm.decode_ap_cap_config(subdoc, "CapReport");
    pcmd[0] = new em_cmd_ap_cap_report_t(evt->params,dm);
    pcmd[0]->override_op(0, &desc);

    return 1;
}

int dm_easy_mesh_t::analyze_client_cap_query(em_bus_event_t *evt, em_cmd_t *pcmd[])
{
    dm_easy_mesh_t  dm;
    em_orch_desc_t desc;
    em_subdoc_info_t *subdoc;
    
    desc.op = dm_orch_type_client_cap_report;
	desc.submit = true;

    subdoc = &evt->u.subdoc;
    mac_addr_str_t client_mac,radio_str_mac;
    dm_sta_t *sta = new dm_sta_t();;
    hash_map_t **m_sta_assoc_map = (hash_map_t **)dm.get_assoc_sta_map();
    mac_address_t cap_mac,radio_mac;
    *m_sta_assoc_map = hash_map_create();

    dm.decode_client_cap_config(subdoc, "ClientCapReport", client_mac, radio_str_mac);
    string_to_macbytes(client_mac,cap_mac);
    printf("%s:%d:ClientCapReport msg id %d", __func__, __LINE__,dm.msg_id);
    printf("%s:%d: clientmac %s", __func__, __LINE__,client_mac);
    printf("%s:%d: Radiomac %s\n", __func__, __LINE__,radio_str_mac);
    string_to_macbytes(radio_str_mac,radio_mac);
    memcpy(sta->get_sta_info()->id,&cap_mac,sizeof(mac_address_t));
    //memcpy(sta->get_sta_info()->bssid,&bss_mac,sizeof(mac_address_t)); TODO once cache is available
    hash_map_put(*m_sta_assoc_map,strdup(client_mac),sta);
    memcpy(dm.m_radio[0].get_radio_info()->id.mac,&radio_mac,sizeof(mac_address_t));
    dm.m_num_radios = 1;
    mac_addr_str_t mac_str;dm_easy_mesh_t::macbytes_to_string(dm.m_radio[0].get_radio_info()->id.mac,mac_str);
    pcmd[0] = new em_cmd_client_cap_report_t(evt->params,dm);
    pcmd[0]->override_op(0, &desc);
    return 1;
}

int dm_easy_mesh_t::analyze_sta_list(em_bus_event_t *evt, em_cmd_t *pcmd[])
{
    dm_easy_mesh_t  dm;
    em_orch_desc_t desc;
    em_subdoc_info_t *subdoc;

    printf("%s:%d: Enter\n", __func__, __LINE__);

    subdoc = &evt->u.subdoc;
    if (dm.decode_sta_config(subdoc, 0) == -1) {
        printf("%s:%d: Failed to decode\n", __func__, __LINE__);
        return 0;
    }
    
    desc.op = dm_orch_type_sta_update;
	desc.submit = true;

    pcmd[0] =  new em_cmd_sta_list_t(evt->params,dm);
    pcmd[0]->override_op(0, &desc);

    return 1;

}

int dm_easy_mesh_t::analyze_dev_init(em_bus_event_t *evt, em_cmd_t *pcmd[])
{
    return 0;
}

int dm_easy_mesh_t::encode_config(em_subdoc_info_t *subdoc, const char *str)
{
	em_long_string_t key;

	if (strncmp(str, "Reset", strlen("Reset")) == 0) {
    	snprintf(key, sizeof(em_long_string_t), "wfa-dataelements:%s", str);
		return encode_config_reset(subdoc, key);
	} else if (strncmp(str, "Test", strlen("Test")) == 0) {
        snprintf(key, sizeof(em_long_string_t), "wfa-dataelements:%s", str);
        return encode_config_test(subdoc, key);
    } else if (strncmp(str, "dm_cache", strlen("dm_cache")) == 0) {
        snprintf(key, sizeof(em_long_string_t), "wfa-dataelements:%s", str);
        return encode_config_test(subdoc, key);
    }

	return -1;

}

int dm_easy_mesh_t::encode_config_reset(em_subdoc_info_t *subdoc, const char *key)
{
    cJSON *parent_obj, *net_obj, *ssid_obj, *ssid_arr_objs;
	char *formatted_json;
	unsigned int i;

    if ((parent_obj = cJSON_CreateObject()) == NULL) {
        printf("%s:%d: Could not create parent object\n", __func__, __LINE__);
        return -1;
    }
    if ((net_obj = cJSON_CreateObject()) == NULL) {
        printf("%s:%d: Could not create net object\n", __func__, __LINE__);
        cJSON_Delete(parent_obj);
        return -1;
    }
    if (cJSON_AddItemToObject(parent_obj, key, net_obj) == false) {
        printf("%s:%d: Could not create net object\n", __func__, __LINE__);
        cJSON_Delete(parent_obj);
        return -1;
    }
    m_network.encode(net_obj);
    if ((ssid_arr_objs = cJSON_CreateArray()) == NULL) {
        printf("%s:%d: Could not create NetworkSSIDList array object\n", __func__, __LINE__);
        cJSON_Delete(parent_obj);
        return -1;
    }
    if (cJSON_AddItemToObject(net_obj, "NetworkSSIDList", ssid_arr_objs) == false) {
        printf("%s:%d: Could not create net object\n", __func__, __LINE__);
        cJSON_Delete(parent_obj);
        return -1;
    }

	for (i = 0; i < m_num_net_ssids; i++) {
		if ((ssid_obj = cJSON_CreateObject()) == NULL) {	
        	printf("%s:%d: Could not create ssid object\n", __func__, __LINE__);
        	cJSON_Delete(parent_obj);
        	return -1;
		}
			
		m_network_ssid[i].encode(ssid_obj);
        if (cJSON_AddItemToArray(ssid_arr_objs, ssid_obj) == false) {
            cJSON_Delete(parent_obj);
            printf("%s:%d: Could not create net object\n", __func__, __LINE__);
            return -1;
        }
	}
	
	formatted_json = cJSON_Print(parent_obj);
    printf("%s:%d: %s\n", __func__, __LINE__, formatted_json);
    snprintf(subdoc->buff,sizeof(em_subdoc_data_buff_t),"%s",cJSON_Print(parent_obj));
    cJSON_Delete(parent_obj);
    return 0;
}

int dm_easy_mesh_t::encode_config_op_class_array(cJSON *arr_obj, em_op_class_type_t type, unsigned char *mac)
{
	unsigned int i;
	cJSON *op_obj;
	mac_addr_str_t	mac_str;
	
	dm_easy_mesh_t::macbytes_to_string(mac, mac_str);

	for (i = 0; i < m_num_opclass; i++) {
		if ((memcmp(m_op_class[i].m_op_class_info.id.ruid, mac, sizeof(mac_address_t)) != 0) ||
					(m_op_class[i].m_op_class_info.id.type != type)) {
			continue;
		}
		if ((op_obj = cJSON_CreateObject()) == NULL) {
        	printf("%s:%d: Could not create op object\n", __func__, __LINE__);
            return -1;
		}

		m_op_class[i].encode(op_obj);
        if (cJSON_AddItemToArray(arr_obj, op_obj) == false) {
            printf("%s:%d: Could not create net object\n", __func__, __LINE__);
            return -1;
        }
	}

	return 0;
}

int dm_easy_mesh_t::encode_config_test(em_subdoc_info_t *subdoc, const char *key)
{
    cJSON *parent_obj, *net_obj, *dev_arr_objs,  *dev_obj, *radio_arr_objs, *radio_obj;
	cJSON *cap_obj, *op_arr_objs, *op_obj, *bss_obj, *bss_arr_objs;
	char *formatted_json;
	unsigned int i, j, num_op_classes = 0, num_bss = 0;
	em_op_class_id_t id;

    if ((parent_obj = cJSON_CreateObject()) == NULL) {
        printf("%s:%d: Could not create parent object\n", __func__, __LINE__);
        return -1;
    }
    if ((net_obj = cJSON_CreateObject()) == NULL) {
        printf("%s:%d: Could not create net object\n", __func__, __LINE__);
        cJSON_Delete(parent_obj);
        return -1;
    }
    if (cJSON_AddItemToObject(parent_obj, key, net_obj) == false) {
        printf("%s:%d: Could not create net object\n", __func__, __LINE__);
        cJSON_Delete(parent_obj);
        return -1;
    }
    
    m_network.encode(net_obj);

	if ((dev_arr_objs = cJSON_CreateArray()) == NULL) {
        printf("%s:%d: Could not create dev array object\n", __func__, __LINE__);
        cJSON_Delete(parent_obj);
        return -1;
    }
    if (cJSON_AddItemToObject(net_obj, "DeviceList", dev_arr_objs) == false) {
        printf("%s:%d: Could not create net object\n", __func__, __LINE__);
        cJSON_Delete(parent_obj);
        return -1;
    }
    if ((dev_obj = cJSON_CreateObject()) == NULL) {
        printf("%s:%d: Could not create dev object\n", __func__, __LINE__);
        cJSON_Delete(parent_obj);
        return -1;
    }
    m_device.encode(dev_obj);
    if (cJSON_AddItemToArray(dev_arr_objs, dev_obj) == false) {
        cJSON_Delete(parent_obj);
        printf("%s:%d: Could not create net object\n", __func__, __LINE__);
        return -1;
    }
    
    if ((radio_arr_objs = cJSON_CreateArray()) == NULL) {
        printf("%s:%d: Could not create dev array object\n", __func__, __LINE__);
        cJSON_Delete(parent_obj);
        return -1;
    }
    if (cJSON_AddItemToObject(dev_obj, "RadioList", radio_arr_objs) == false) {
        printf("%s:%d: Could not create Radio object\n", __func__, __LINE__);
        cJSON_Delete(parent_obj);
        return -1;
    }

    for (i = 0; i < m_num_radios; i++) {
        if ((radio_obj = cJSON_CreateObject()) == NULL) {
            printf("%s:%d: Could not create dev object\n", __func__, __LINE__);
            cJSON_Delete(parent_obj);
            return -1;
        }
        m_radio[i].encode(radio_obj);
        if (cJSON_AddItemToArray(radio_arr_objs, radio_obj) == false) {
            cJSON_Delete(parent_obj);
            printf("%s:%d: Could not create net object\n", __func__, __LINE__);
            return -1;
        }

        if ((op_arr_objs = cJSON_CreateArray()) == NULL) {
            printf("%s:%d: Could not create op array object\n", __func__, __LINE__);
            cJSON_Delete(parent_obj);
            return -1;
        }
        if (cJSON_AddItemToObject(radio_obj, "CurrentOperatingClasses", op_arr_objs) == false) {
            printf("%s:%d: Could not create op object\n", __func__, __LINE__);
            cJSON_Delete(parent_obj);
            return -1;
        }

        if (encode_config_op_class_array(op_arr_objs, em_op_class_type_current, m_radio[i].m_radio_info.id.mac) != 0) {
            printf("%s:%d: CurrentOperatingClasses Encoding failed \n", __func__, __LINE__);
            cJSON_Delete(parent_obj);
            return -1;
		}         

        if ((bss_arr_objs = cJSON_CreateArray()) == NULL) {
            printf("%s:%d: Could not create bss array object\n", __func__, __LINE__);
            cJSON_Delete(parent_obj);
            return -1;
        }
		if (cJSON_AddItemToObject(radio_obj, "BSSList", bss_arr_objs) == false) {
            printf("%s:%d: Could not create Radio object\n", __func__, __LINE__);
            cJSON_Delete(parent_obj);
            return -1;
        }
        //printf("%s:%d: VAP object num of bss=%d\n", __func__, __LINE__,m_num_bss);

        for (j = 0; j < m_num_bss; j++) {
			if (memcmp(m_bss[j].m_bss_info.ruid.mac, m_radio[i].m_radio_info.id.mac, sizeof(mac_address_t)) != 0) {
				continue;
			}

            if ((bss_obj = cJSON_CreateObject()) == NULL) {
                printf("%s:%d: Could not create net object\n", __func__, __LINE__);
                cJSON_Delete(parent_obj);
                return -1;
            }
            m_bss[j].encode(bss_obj);
            if (cJSON_AddItemToArray(bss_arr_objs, bss_obj) == false) {
                if (cJSON_AddItemToArray(bss_arr_objs, bss_obj) == false) {
                    printf("%s:%d: Could not create net object\n", __func__, __LINE__);
                    cJSON_Delete(parent_obj);
                    return -1;
                }

            }
        }

    // Capabilities
    	if ((cap_obj = cJSON_CreateObject()) == NULL) {
        	printf("%s:%d: Could not create capability object\n", __func__, __LINE__);
        	cJSON_Delete(parent_obj);
        	return -1;
    	}

		if (cJSON_AddItemToObject(radio_obj, "Capabilities", cap_obj) == false) {
            printf("%s:%d: Could not add capability object\n", __func__, __LINE__);
            cJSON_Delete(parent_obj);
            return -1;
        }  

		if ((op_arr_objs = cJSON_CreateArray()) == NULL) {
            printf("%s:%d: Could not create op array object\n", __func__, __LINE__);
            cJSON_Delete(parent_obj);
            return -1;
        }

        if (cJSON_AddItemToObject(cap_obj, "OperatingClasses", op_arr_objs) == false) {
            printf("%s:%d: Could not create op object\n", __func__, __LINE__);
            cJSON_Delete(parent_obj);
            return -1;
        }

        if (encode_config_op_class_array(op_arr_objs, em_op_class_type_capability, m_radio[i].m_radio_info.id.mac) != 0) {
            printf("%s:%d: CurrentOperatingClasses Encoding failed \n", __func__, __LINE__);
            cJSON_Delete(parent_obj);
            return -1;
        }
    }

	// CACStatus
   	if ((cap_obj = cJSON_CreateObject()) == NULL) {
       	printf("%s:%d: Could not create capability object\n", __func__, __LINE__);
       	cJSON_Delete(parent_obj);
       	return -1;
   	}

	if (cJSON_AddItemToObject(dev_obj, "CACStatus", cap_obj) == false) {
		printf("%s:%d: Could not add cac status object\n", __func__, __LINE__);
        cJSON_Delete(parent_obj);
        return -1;
    }  

	if ((op_arr_objs = cJSON_CreateArray()) == NULL) {
        printf("%s:%d: Could not create op array object\n", __func__, __LINE__);
        cJSON_Delete(parent_obj);
        return -1;
    }

    if (cJSON_AddItemToObject(cap_obj, "AvailableChannelList", op_arr_objs) == false) {
       	printf("%s:%d: Could not create op object\n", __func__, __LINE__);
        cJSON_Delete(parent_obj);
       	return -1;
	}

  	if (encode_config_op_class_array(op_arr_objs, em_op_class_type_cac_available, m_device.m_device_info.id.mac) != 0) {
        printf("%s:%d: AvailableChannelList Encoding failed \n", __func__, __LINE__);
        cJSON_Delete(parent_obj);
        return -1;
    }

	if ((op_arr_objs = cJSON_CreateArray()) == NULL) {
        printf("%s:%d: Could not create op array object\n", __func__, __LINE__);
        cJSON_Delete(parent_obj);
        return -1;
    }

    if (cJSON_AddItemToObject(cap_obj, "NonOccupancyChannelList", op_arr_objs) == false) {
       	printf("%s:%d: Could not create op object\n", __func__, __LINE__);
        cJSON_Delete(parent_obj);
       	return -1;
	}

  	if (encode_config_op_class_array(op_arr_objs, em_op_class_type_cac_non_occ, m_device.m_device_info.id.mac) != 0) {
        printf("%s:%d: NonOccupancyChannelList Encoding failed \n", __func__, __LINE__);
        cJSON_Delete(parent_obj);
        return -1;
    }

	if ((op_arr_objs = cJSON_CreateArray()) == NULL) {
        printf("%s:%d: Could not create op array object\n", __func__, __LINE__);
        cJSON_Delete(parent_obj);
        return -1;
    }

    if (cJSON_AddItemToObject(cap_obj, "ActiveChannelList", op_arr_objs) == false) {
       	printf("%s:%d: Could not create op object\n", __func__, __LINE__);
        cJSON_Delete(parent_obj);
       	return -1;
	}

  	if (encode_config_op_class_array(op_arr_objs, em_op_class_type_cac_active, m_device.m_device_info.id.mac) != 0) {
        printf("%s:%d: ActiveChannelList Encoding failed \n", __func__, __LINE__);
        cJSON_Delete(parent_obj);
        return -1;
    }

	formatted_json = cJSON_Print(parent_obj);
    printf("%s:%d: %s\n", __func__, __LINE__, formatted_json);
    snprintf(subdoc->buff,sizeof(em_subdoc_data_buff_t),"%s",cJSON_Print(parent_obj));
    cJSON_Delete(parent_obj);
    return 0;
}


unsigned int dm_easy_mesh_t::decode_num_devices(em_subdoc_info_t *subdoc)
{
    cJSON *parent_obj, *net_obj, *dev_arr_objs;
    unsigned int size;

    if ((parent_obj = cJSON_Parse(subdoc->buff)) == NULL) {
        printf("%s:%d: Failed to initialize device data model\n", __func__, __LINE__);
        return -1;
    }

    if (((net_obj = cJSON_GetObjectItem(parent_obj, "wfa-dataelements:Network")) == NULL) && 
			((net_obj = cJSON_GetObjectItem(parent_obj, "wfa-dataelements:Init")) == NULL) &&
			((net_obj = cJSON_GetObjectItem(parent_obj, "wfa-dataelements:StaList")) == NULL)) {	    
        cJSON_Delete(parent_obj);
        printf("%s:%d: wfa-dataelements:Network not present\n", __func__, __LINE__);
        return -1;
    }

    m_network.decode(net_obj, NULL);
    if ((dev_arr_objs = cJSON_GetObjectItem(net_obj, "DeviceList")) == NULL) {
        cJSON_Delete(parent_obj);
        printf("%s:%d: DeviceList not present\n", __func__, __LINE__);
        return -1;
    }
   
    size = cJSON_GetArraySize(dev_arr_objs);
    cJSON_Delete(parent_obj);

    return size;

}


int dm_easy_mesh_t::decode_config(em_subdoc_info_t *subdoc, const char *str, unsigned int index, unsigned int *num)
{
	em_long_string_t key;

	if (strncmp(str, "Reset", strlen("Reset")) == 0) {
    	snprintf(key, sizeof(em_long_string_t), "wfa-dataelements:%s", str);
		return decode_config_reset(subdoc, key);
	} else if (strncmp(str, "SetSSID", strlen("SetSSID")) == 0) {
        snprintf(key, sizeof(em_long_string_t), "wfa-dataelements:%s", str);
        return decode_config_set_ssid(subdoc, key);
    } else if (strncmp(str, "SetAnticipatedChannelPreference", strlen("SetAnticipatedChannelPreference")) == 0) {
        snprintf(key, sizeof(em_long_string_t), "wfa-dataelements:%s", str);
        return decode_config_set_channel(subdoc, key, index, num);
    } else if (strncmp(str, "Test", strlen("Test")) == 0) {
        snprintf(key, sizeof(em_long_string_t), "wfa-dataelements:%s", str);
        return decode_config_test(subdoc, key); 
	} else if (strncmp(str, "dm_cache", strlen("dm_cache")) == 0) {
         snprintf(key, sizeof(em_long_string_t), "wfa-dataelements:%s", str);
         return decode_config_test(subdoc, key);
    }

	return -1;
}

int dm_easy_mesh_t::decode_config_reset(em_subdoc_info_t *subdoc, const char *key)
{
    cJSON *parent_obj, *net_obj, *tmp, *ssid_obj, *ssid_arr_obj;
    unsigned int i;

    //printf("%s\n", subdoc->buff);
    if ((parent_obj = cJSON_Parse(subdoc->buff)) == NULL) {
        printf("%s:%d: Failed to initialize device data model\n", __func__, __LINE__);
        return -1;
    }

    if ((net_obj = cJSON_GetObjectItem(parent_obj, key)) == NULL) {
        cJSON_Delete(parent_obj);
        return -1;
    }

    m_network.decode(net_obj, NULL);
	
	if ((ssid_arr_obj = cJSON_GetObjectItem(net_obj, "NetworkSSIDList")) == NULL) {
        cJSON_Delete(parent_obj);
        printf("%s:%d: NetworkSSID List not present\n", __func__, __LINE__);
        return -1;
    }

	m_num_net_ssids = cJSON_GetArraySize(ssid_arr_obj);
    if (m_num_net_ssids == 0) {
        cJSON_Delete(parent_obj);
        printf("%s:%d: NetworkSSIDList has no memebers not present\n", __func__, __LINE__);
        return -1;
    }

	for (i = 0; i < m_num_net_ssids; i++) {
        if((ssid_obj = cJSON_GetArrayItem(ssid_arr_obj, i)) == NULL) {
            cJSON_Delete(parent_obj);
            printf("%s:%d: NetworkSSIDList has no members present\n", __func__, __LINE__);
            return -1;
        }
			
        m_network_ssid[i].decode(ssid_obj, m_network.m_net_info.id);
	}

    cJSON_Delete(parent_obj);
    //printf("%s:%d: End\n", __func__, __LINE__);
    return 0;
}

int dm_easy_mesh_t::decode_config_set_channel(em_subdoc_info_t *subdoc, const char *key, unsigned int index, unsigned int *num)
{
    cJSON *parent_obj, *net_obj, *net_obj_id, *dev_arr_obj, *dev_obj; 
	cJSON *anticipated_arr_obj, *anticipated_obj, *channel_arr_obj, *channel_obj;
    unsigned int i, j, arr_size;
    char *dev_id, *net_id;
    int ret = 0;
    int haul_bit_mask = 0;

    parent_obj = cJSON_Parse(subdoc->buff);
    if (parent_obj == NULL) {
        printf("%s:%d: Failed to parse: %s\n", __func__, __LINE__, subdoc->buff);
        return EM_PARSE_ERR_GEN;
    }

    if ((net_obj = cJSON_GetObjectItem(parent_obj, key)) == NULL) {
        printf("%s:%d: Failed to parse: %s\n", __func__, __LINE__, subdoc->buff);
        cJSON_Delete(parent_obj);
        return EM_PARSE_ERR_GEN;
    }

    if ((net_obj = cJSON_GetObjectItem(net_obj, "Network")) == NULL) {
        printf("%s:%d: Failed to parse: %s\n", __func__, __LINE__, subdoc->buff);
        cJSON_Delete(parent_obj);
        return EM_PARSE_ERR_GEN;
    }

    if ((net_obj_id = cJSON_GetObjectItem(net_obj, "ID")) == NULL) {
        printf("%s:%d: Network ID not present\n", __func__, __LINE__);
        cJSON_Delete(parent_obj);
        return EM_PARSE_ERR_NET_ID;
    }

    if ((net_id = cJSON_GetStringValue(net_obj_id)) == NULL) {
        printf("%s:%d: Network ID not present\n", __func__, __LINE__);
        cJSON_Delete(parent_obj);
        return EM_PARSE_ERR_NET_ID;
    }


    dev_arr_obj = cJSON_GetObjectItem(net_obj, "DeviceList");
    if (dev_arr_obj == NULL) {
        printf("%s:%d: DeviceList not present\n", __func__, __LINE__);
        cJSON_Delete(parent_obj);
        return EM_PARSE_ERR_CONFIG;
    }

	arr_size = cJSON_GetArraySize(dev_arr_obj);
	*num = arr_size;

	if (index >= arr_size) {
		printf("%s:%d: Passed index: %d greater than array size: %d\n", __func__, __LINE__, index, arr_size);
    	cJSON_Delete(parent_obj);
    	//printf("%s:%d: End\n", __func__, __LINE__);
    	return 0;
	}

	if	((dev_obj = cJSON_GetArrayItem(dev_arr_obj, index)) == NULL) {
		cJSON_Delete(parent_obj);
        printf("%s:%d: DeviceList has no members present\n", __func__, __LINE__);
        return -1;
	}	

	dev_id = cJSON_GetStringValue(cJSON_GetObjectItem(dev_obj, "ID"));
	dm_easy_mesh_t::string_to_macbytes(dev_id, m_device.m_device_info.id.mac);
	strncpy(m_device.m_device_info.net_id, net_id, strlen(net_id) + 1);

	if ((anticipated_arr_obj = cJSON_GetObjectItem(dev_obj, "AnticipatedChannelPreference")) == NULL) {
		cJSON_Delete(parent_obj);
        printf("%s:%d: AnticipatedChannelPreference not present\n", __func__, __LINE__);
        return -1;

	}	

	m_num_opclass = 0;
	arr_size = cJSON_GetArraySize(anticipated_arr_obj);
	for (i = 0; i < arr_size; i++) {
		if ((anticipated_obj = cJSON_GetArrayItem(anticipated_arr_obj, i)) == NULL) {
			cJSON_Delete(parent_obj);
        	printf("%s:%d: AnticipatedChannelPreference not present\n", __func__, __LINE__);
        	return -1;
    	}

		memset(&m_op_class[m_num_opclass].m_op_class_info, 0, sizeof(em_op_class_info_t));   

		m_op_class[m_num_opclass].m_op_class_info.id.type = em_op_class_type_preference;
		dm_easy_mesh_t::string_to_macbytes(dev_id, m_op_class[m_num_opclass].m_op_class_info.id.ruid);
		m_op_class[m_num_opclass].m_op_class_info.id.index = i;
		m_op_class[m_num_opclass].m_op_class_info.op_class = cJSON_GetNumberValue(cJSON_GetObjectItem(anticipated_obj, "Class"));

		if ((channel_arr_obj = cJSON_GetObjectItem(anticipated_obj, "ChannelList")) == NULL) {
			cJSON_Delete(parent_obj);
        	printf("%s:%d: AnticipatedChannelPreference not present\n", __func__, __LINE__);
        	return -1;
		}

		m_op_class[m_num_opclass].m_op_class_info.num_anticipated_channels = 0;

		for (j = 0; j < cJSON_GetArraySize(channel_arr_obj); j++) {
			m_op_class[m_num_opclass].m_op_class_info.anticipated_channel[m_op_class[m_num_opclass].m_op_class_info.num_anticipated_channels] = cJSON_GetNumberValue(cJSON_GetArrayItem(channel_arr_obj, j));
			m_op_class[m_num_opclass].m_op_class_info.num_anticipated_channels++;
		}	

		m_num_opclass++;
	}	
	
    cJSON_Delete(parent_obj);
    //printf("%s:%d: End\n", __func__, __LINE__);
    return 0;
}

int dm_easy_mesh_t::decode_config_set_ssid(em_subdoc_info_t *subdoc, const char *key)
{
	cJSON *parent_obj, *net_obj, *net_obj_id, *netssid_list_obj;
	unsigned int i, arr_size;
	char *parent;
	int ret = 0;
	int haul_bit_mask = 0;

    parent_obj = cJSON_Parse(subdoc->buff);
    if (parent_obj == NULL) {
        printf("%s:%d: Failed to parse: %s\n", __func__, __LINE__, subdoc->buff);
        return EM_PARSE_ERR_GEN;
    }

    if ((net_obj = cJSON_GetObjectItem(parent_obj, key)) == NULL) {
        printf("%s:%d: Failed to parse: %s\n", __func__, __LINE__, subdoc->buff);
        cJSON_Delete(parent_obj);
        return EM_PARSE_ERR_GEN;
    }

	if ((net_obj_id = cJSON_GetObjectItem(net_obj, "ID")) == NULL) {
        printf("%s:%d: Network ID not present\n", __func__, __LINE__);
        cJSON_Delete(parent_obj);
		return EM_PARSE_ERR_NET_ID;
	}

	if ((parent = cJSON_GetStringValue(net_obj_id)) == NULL) {
        printf("%s:%d: Network ID not present\n", __func__, __LINE__);
        cJSON_Delete(parent_obj);
		return EM_PARSE_ERR_NET_ID;
	}

    netssid_list_obj = cJSON_GetObjectItem(net_obj, "NetworkSSIDList");
    if (netssid_list_obj == NULL) {
        printf("%s:%d: NetworkSSIDList not present\n", __func__, __LINE__);
        cJSON_Delete(parent_obj);
        return EM_PARSE_ERR_CONFIG;
    }

	arr_size = cJSON_GetArraySize(netssid_list_obj);
	if (arr_size != EM_MAX_NET_SSIDS) {
		printf("%s:%d: Invalid configuration: %s\n", __func__, __LINE__, key);
        cJSON_Delete(parent_obj);
        return EM_PARSE_ERR_CONFIG;
	}

	for (i = 0; i < arr_size; i++) {
		m_network_ssid[i].decode(cJSON_GetArrayItem(netssid_list_obj, i), parent);
	}

	m_num_net_ssids = arr_size;

    cJSON_free(parent_obj);
	
	// now validate
	for (i = 0; i < arr_size; i++) {
		if (m_network_ssid[i].m_network_ssid_info.num_hauls != 1) {
			printf("%s:%d: Invalid haul configuration\n", __func__, __LINE__);
			return EM_PARSE_ERR_CONFIG;
		}

		haul_bit_mask |= (1 << m_network_ssid[i].m_network_ssid_info.haul_type[0]);

	}

	if (haul_bit_mask != (pow(2, (double)em_haul_type_max) - 1)) {
		printf("%s:%d: Invalid haul configuration, bit mask: %x\n", __func__, __LINE__, haul_bit_mask);
		return EM_PARSE_ERR_CONFIG;
	}


	return ret;
}

int dm_easy_mesh_t::decode_config_op_class_array(cJSON *arr_obj, em_op_class_type_t type, unsigned char *mac)
{
	cJSON *op_obj;
	unsigned int num_objs, i;
	mac_addr_str_t	mac_str;
	em_long_string_t key;

	num_objs = cJSON_GetArraySize(arr_obj);
	//printf("%s:%d: Operating Classes for type: %d are: %d\n", __func__, __LINE__, type, num_objs);

	for (i = 0; i < num_objs; i++) {
		if ((op_obj = cJSON_GetArrayItem(arr_obj, i)) == NULL) {
			printf("%s:%d: Type: %d has no memebers\n", __func__, __LINE__, type);
			return -1;
		}

		dm_easy_mesh_t::macbytes_to_string(mac, mac_str);
		snprintf(key, sizeof(em_long_string_t), "%s@%d@%d", mac_str, type, i);

		//printf("%s:%d: Data at m_op_class[%d]\n", __func__, __LINE__, i + m_num_opclass);
		m_op_class[i + m_num_opclass].decode(op_obj, key);
	}

	m_num_opclass += num_objs;

	return 0;
}

void dm_easy_mesh_t::update_cac_status_id(mac_address_t al_mac)
{
	unsigned int i;
	mac_addr_str_t	mac_str;
	em_long_string_t	key;

	for (i = 0; i < m_num_opclass; i++) {
		if (m_op_class[i].m_op_class_info.id.type > em_op_class_type_capability) {
			memcpy(m_op_class[i].m_op_class_info.id.ruid, al_mac, sizeof(mac_address_t));
		}
	}

    for (i = 0; i < m_num_opclass; i++) {
        dm_easy_mesh_t::macbytes_to_string(m_op_class[i].m_op_class_info.id.ruid, mac_str);
        snprintf(key, sizeof(em_long_string_t), "%s@%d@%d", mac_str,
                m_op_class[i].m_op_class_info.id.type, m_op_class[i].m_op_class_info.id.index);
        printf("%s:%d: ID: %s: OpClass: %d Channel: %d\n", __func__, __LINE__,
                key, m_op_class[i].m_op_class_info.op_class, m_op_class[i].m_op_class_info.channel);
    }
}

int dm_easy_mesh_t::decode_config_test(em_subdoc_info_t *subdoc, const char *key)
{
    cJSON *parent_obj, *net_obj, *dev_arr_objs,  *dev_obj, *radio_arr_objs, *radio_obj , *cap_obj;
	cJSON *op_arr_objs, *op_obj, *cac_status_obj;
    cJSON *bss_arr_objs,*bss_obj, *tmp;
    unsigned int size, i, j, num_objs;
	mac_addr_str_t mac_str;
	em_long_string_t parent_key;

    if ((parent_obj = cJSON_Parse(subdoc->buff)) == NULL) {
        printf("%s:%d: Failed to initialize device data model\n", __func__, __LINE__);
        return -1;
    }

    if ((net_obj = cJSON_GetObjectItem(parent_obj, key)) == NULL) {
        cJSON_Delete(parent_obj);
        return -1;
    }

    m_network.decode(net_obj, NULL);

    if ((dev_arr_objs = cJSON_GetObjectItem(net_obj, "DeviceList")) == NULL) {
        cJSON_Delete(parent_obj);
        printf("%s:%d: DeviceList not present\n", __func__, __LINE__);
        return -1;
    }

    size = cJSON_GetArraySize(dev_arr_objs);
    if (size == 0) {
        cJSON_Delete(parent_obj);
        printf("%s:%d: DeviceList has no memebers not present\n", __func__, __LINE__);
        return -1;
    }

    if ((dev_obj = cJSON_GetArrayItem(dev_arr_objs, 0)) != NULL) {
        m_device.decode(dev_obj, m_network.get_network_id());
    }

    if ((radio_arr_objs = cJSON_GetObjectItem(dev_obj, "RadioList")) == NULL) {
        cJSON_Delete(parent_obj);
        printf("%s:%d: RadioList not present\n", __func__, __LINE__);
        return -1;

    }

    m_num_radios = cJSON_GetArraySize(radio_arr_objs);
    if (m_num_radios == 0) {
        cJSON_Delete(parent_obj);
        printf("%s:%d: RadioList has no memebers not present\n", __func__, __LINE__);
        return -1;
    }
    for (i = 0; i < m_num_radios; i++) {
        if((radio_obj = cJSON_GetArrayItem(radio_arr_objs, i)) == NULL) {
            cJSON_Delete(parent_obj);
            printf("%s:%d: RadioList has no members present\n", __func__, __LINE__);
            return -1;
        }
			
		dm_easy_mesh_t::macbytes_to_string(m_device.get_dev_interface_mac(), mac_str);	
		snprintf(parent_key, sizeof(parent_key), "%s@%s", mac_str, m_device.m_device_info.net_id);

        m_radio[i].decode(radio_obj, parent_key);

        if ((op_arr_objs = cJSON_GetObjectItem(radio_obj, "CurrentOperatingClasses")) == NULL) {
            cJSON_Delete(parent_obj);
            printf("%s:%d: CurrentOperatingClasses not present\n", __func__, __LINE__);
            return -1;
        }

        if (decode_config_op_class_array(op_arr_objs, em_op_class_type_current, m_radio[i].m_radio_info.id.mac) != 0) {
            cJSON_Delete(parent_obj);
            printf("%s:%d: CurrentOperatingClasses decode failed\n", __func__, __LINE__);
            return -1;
		}

		// Capabilities
		if ((cap_obj = cJSON_GetObjectItem(radio_obj, "Capabilities")) == NULL) {
            cJSON_Delete(parent_obj);
            printf("%s:%d: Capabilities not present\n", __func__, __LINE__);
            return -1;
        }

		if ((op_arr_objs = cJSON_GetObjectItem(cap_obj, "OperatingClasses")) == NULL) {
            cJSON_Delete(parent_obj);
            printf("%s:%d: OperatingClasses not present\n", __func__, __LINE__);
            return -1;
		}

		if (decode_config_op_class_array(op_arr_objs, em_op_class_type_capability, m_radio[i].m_radio_info.id.mac) != 0) {
            cJSON_Delete(parent_obj);
            printf("%s:%d: OperatingClasses decode failed\n", __func__, __LINE__);
            return -1;
		}

        if ((bss_arr_objs = cJSON_GetObjectItem(radio_obj, "BSSList")) == NULL) {
            cJSON_Delete(parent_obj);
            printf("%s:%d: BssList not present\n", __func__, __LINE__);
            return -1;
        }

        num_objs = cJSON_GetArraySize(bss_arr_objs);
        
		for (j = 0; j < num_objs; j++) {

            if((bss_obj = cJSON_GetArrayItem(bss_arr_objs, j)) == NULL) {
                cJSON_Delete(parent_obj);
                printf("%s:%d: BSSObj member read failed \n", __func__, __LINE__);
                return -1;
            }

            if ((tmp = cJSON_GetObjectItem(bss_obj, "BSSID")) == NULL) {
                cJSON_Delete(parent_obj);
                printf("%s:%d: BSSID not found\n", __func__, __LINE__);
                return -1;
            }
			printf("%s:%d: BSSID: %s\n", __func__, __LINE__, cJSON_GetStringValue(tmp));
			dm_easy_mesh_t::macbytes_to_string(m_radio[i].m_radio_info.id.mac, mac_str);
            m_bss[j + m_num_bss].decode(bss_obj, mac_str);
        }

		m_num_bss += num_objs;

    }
    
    if ((cac_status_obj = cJSON_GetObjectItem(dev_obj, "CACStatus")) == NULL) {
        cJSON_Delete(parent_obj);
        printf("%s:%d: CACStatus not present\n", __func__, __LINE__);
        return -1;

    }

	if ((op_arr_objs = cJSON_GetObjectItem(cac_status_obj, "AvailableChannelList")) == NULL) {
        cJSON_Delete(parent_obj);
        printf("%s:%d: AvailableChannelList not present\n", __func__, __LINE__);
        return -1;
	}	
		
	if (decode_config_op_class_array(op_arr_objs, em_op_class_type_cac_available, m_device.m_device_info.id.mac) != 0) {
        cJSON_Delete(parent_obj);
        printf("%s:%d: AvailableChannelList decode failed\n", __func__, __LINE__);
        return -1;
	}
        
	if ((op_arr_objs = cJSON_GetObjectItem(cac_status_obj, "NonOccupancyChannelList")) == NULL) {
        cJSON_Delete(parent_obj);
        printf("%s:%d: NonOccupancyChannelList not present\n", __func__, __LINE__);
        return -1;
	}	

	if (decode_config_op_class_array(op_arr_objs, em_op_class_type_cac_non_occ, m_device.m_device_info.id.mac) != 0) {
        cJSON_Delete(parent_obj);
        printf("%s:%d: NonOccupancyChannelList decode failed\n", __func__, __LINE__);
        return -1;
	}
        
	if ((op_arr_objs = cJSON_GetObjectItem(cac_status_obj, "ActiveChannelList")) == NULL) {
        cJSON_Delete(parent_obj);
        printf("%s:%d: ActiveChannelList not present\n", __func__, __LINE__);
        return -1;
	}	

	if (decode_config_op_class_array(op_arr_objs, em_op_class_type_cac_active, m_device.m_device_info.id.mac) != 0) {
        cJSON_Delete(parent_obj);
        printf("%s:%d: ActiveChannelList decode failed\n", __func__, __LINE__);
        return -1;
	}

    cJSON_Delete(parent_obj);
    //printf("%s:%d: End\n", __func__, __LINE__);
    return 0;
}

int dm_easy_mesh_t::decode_sta_config(em_subdoc_info_t *subdoc, unsigned int dev_idx)
{
        cJSON *parent_obj, *net_obj, *dev_arr_objs,  *dev_obj, *radio_arr_objs, *radio_obj, *tmp, *bss_arr_objs, *bss_obj;
        cJSON *dev_arr_bss_objs, *dev_arr_sta_objs, *sta_obj;
        unsigned int size, i = 0,j = 0, k = 0, sta = 0, m_num_sta = 0;
        mac_addr_str_t  mac_str;
        mac_address_t mac_add;
        dm_sta_t *sta_list ;
        char sta_list_key[64];
        m_sta_assoc_map = hash_map_create();
        m_sta_dassoc_map = hash_map_create();
        m_sta_map = hash_map_create();

        if ((parent_obj = cJSON_Parse(subdoc->buff)) == NULL) {
                printf("%s:%d: Failed to initialize device data model\n", __func__, __LINE__);
                return -1;
        }

        if ((net_obj = cJSON_GetObjectItem(parent_obj, "wfa-dataelements:StaList")) == NULL) {
                cJSON_Delete(parent_obj);
                printf("%s:%d: wfa-dataelements:StaList not present\n", __func__, __LINE__);
                return -1;
        }

        m_network.decode(net_obj, NULL);
        if ((dev_arr_objs = cJSON_GetObjectItem(net_obj, "DeviceList")) == NULL) {
                cJSON_Delete(parent_obj);
                printf("%s:%d: DeviceList not present\n", __func__, __LINE__);
                return -1;
        }

        size = cJSON_GetArraySize(dev_arr_objs);
        if (size == 0) {
                cJSON_Delete(parent_obj);
                printf("%s:%d: DeviceList has no memebers not present\n", __func__, __LINE__);
                return -1;
        }

        if ((dev_obj = cJSON_GetArrayItem(dev_arr_objs, dev_idx)) != NULL) {
                m_device.decode(dev_obj, m_network.get_network_id());
        }

        if ((radio_arr_objs = cJSON_GetObjectItem(dev_obj, "RadioList")) == NULL) {
                cJSON_Delete(parent_obj);
                printf("%s:%d: RadioList not present\n", __func__, __LINE__);
                return -1;

        }

        m_num_radios = cJSON_GetArraySize(radio_arr_objs);
        if (m_num_radios == 0) {
                cJSON_Delete(parent_obj);
                printf("%s:%d: RadioList has no memebers not present\n", __func__, __LINE__);
                return -1;
        }

        for (i =0; i < m_num_radios; i++) {
            if((radio_obj = cJSON_GetArrayItem(radio_arr_objs, i)) == NULL) {
                cJSON_Delete(parent_obj);
                printf("%s:%d: RadioList has no members present\n", __func__, __LINE__);
                return -1;
            }
            m_radio[i].decode(radio_obj, m_device.get_dev_interface_mac());
            if ((dev_arr_bss_objs = cJSON_GetObjectItem(radio_obj, "BSSList")) == NULL) {
                cJSON_Delete(parent_obj);
                printf("%s:%d: BSSList has no members present\n", __func__, __LINE__);
                return -1;
            }

            m_num_bss = cJSON_GetArraySize(dev_arr_bss_objs);

            if (m_num_bss == 0) {
                cJSON_Delete(parent_obj);
                printf("%s:%d: Bss has no memebers not present\n", __func__, __LINE__);
                return -1;
            }

            for (j = 0;j < m_num_bss; j++) {

                if((bss_obj = cJSON_GetArrayItem(dev_arr_bss_objs, j)) == NULL) {
                    cJSON_Delete(parent_obj);
                    printf("%s:%d: BSSObj member read failed \n", __func__, __LINE__);
                    return -1;
                }

                if ((tmp = cJSON_GetObjectItem(bss_obj, "BSSID")) == NULL) {
                    cJSON_Delete(parent_obj);
                    printf("%s:%d: BSSID not found\n", __func__, __LINE__);
                    return -1;
                }
                snprintf(mac_str, sizeof(mac_str), "%s", cJSON_GetStringValue(tmp));
                dm_easy_mesh_t::string_to_macbytes(mac_str, mac_add);
                if ((dev_arr_sta_objs = cJSON_GetObjectItem(bss_obj, "STAList")) != NULL) {
                    m_num_sta = cJSON_GetArraySize(dev_arr_sta_objs);
                    if (m_num_sta == 0) {
                        cJSON_Delete(parent_obj);
                        printf("%s:%d: STAList has no memebers not present\n", __func__, __LINE__);
                        return -1;
                    }


                        for (k = 0;k < m_num_sta; k++) {
                            if((sta_obj = cJSON_GetArrayItem(dev_arr_sta_objs, k)) != NULL) {
                                sta_list = new dm_sta_t();
                                sta_list->decode(sta_obj, mac_add);

                                memset(sta_list_key,0,sizeof(sta_list_key));
                                dm_easy_mesh_t::macbytes_to_string(m_radio[i].get_radio_interface_mac(),mac_str);
                                snprintf(sta_list_key + strlen(sta_list_key), sizeof(sta_list_key) - strlen(sta_list_key), "%s-", mac_str);
                                dm_easy_mesh_t::macbytes_to_string(mac_add,mac_str);

                                snprintf(sta_list_key + strlen(sta_list_key), sizeof(sta_list_key) - strlen(sta_list_key), "%s-", mac_str);
                                if ((tmp = cJSON_GetObjectItem(sta_obj, "MACAddress")) == NULL) {
                                    cJSON_Delete(parent_obj);
                                    printf("%s:%d: STA ID not found\n", __func__, __LINE__);
                                    return -1;
                                }
                                snprintf(mac_str, sizeof(mac_str), "%s", cJSON_GetStringValue(tmp));
                                snprintf(sta_list_key + strlen(sta_list_key), sizeof(sta_list_key) - strlen(sta_list_key), "%s", mac_str);
                                snprintf(sta_list->get_sta_info()->m_sta_key, sizeof(sta_list->get_sta_info()->m_sta_key), "%s", sta_list_key);
                                printf("%s:%d: Add key=%s\n", __func__, __LINE__,sta_list_key);
                                hash_map_put(m_sta_assoc_map,strdup(sta_list->get_sta_info()->m_sta_key),sta_list);
                				hash_map_put(m_sta_map,strdup(sta_list->get_sta_info()->m_sta_key),sta_list);
                                memset(sta_list_key,0,sizeof(sta_list_key));
                                sta++;
                        }
                    }
                }

                if ((dev_arr_sta_objs = cJSON_GetObjectItem(bss_obj, "UnassociatedStaList")) != NULL) {
                    m_num_sta = cJSON_GetArraySize(dev_arr_sta_objs);
                    if (m_num_sta == 0) {
                        cJSON_Delete(parent_obj);
                        printf("%s:%d: STAList has no memebers not present\n", __func__, __LINE__);
                        return -1;
                    }

                        for (k = 0;k < m_num_sta; k++) {
                            if((sta_obj = cJSON_GetArrayItem(dev_arr_sta_objs, k)) != NULL) {
                                sta_list = new dm_sta_t();
                                sta_list->decode(sta_obj, mac_add);

                                memset(sta_list_key,0,sizeof(sta_list_key));
                                dm_easy_mesh_t::macbytes_to_string(m_radio[i].get_radio_interface_mac(),mac_str);
                                snprintf(sta_list_key + strlen(sta_list_key), sizeof(sta_list_key) - strlen(sta_list_key), "%s-", mac_str);
                                dm_easy_mesh_t::macbytes_to_string(mac_add,mac_str);
                                snprintf(sta_list_key + strlen(sta_list_key), sizeof(sta_list_key) - strlen(sta_list_key), "%s-", mac_str);
                                if ((tmp = cJSON_GetObjectItem(sta_obj, "MACAddress")) == NULL) {
                                    cJSON_Delete(parent_obj);
                                    printf("%s:%d: STA ID not found\n", __func__, __LINE__);
                                    return -1;
                                }
                                snprintf(mac_str, sizeof(mac_str), "%s", cJSON_GetStringValue(tmp));
                				
                                snprintf(sta_list_key + strlen(sta_list_key), sizeof(sta_list_key) - strlen(sta_list_key), "%s", mac_str);
                                snprintf(sta_list->get_sta_info()->m_sta_key, sizeof(sta_list->get_sta_info()->m_sta_key), "%s", sta_list_key);
                                printf("%s:%d: Remove key=%s\n", __func__, __LINE__,sta_list_key);
                                hash_map_put(m_sta_dassoc_map,strdup(sta_list->get_sta_info()->m_sta_key),sta_list);

                                memset(sta_list_key,0,sizeof(sta_list_key));
                                sta++;
                        }
                    }
                }
            }

        }
        printf("%s:%d: Update for %d clients \n", __func__, __LINE__,sta);
        cJSON_Delete(parent_obj);

    return 0;
}

int dm_easy_mesh_t::decode_ap_cap_config(em_subdoc_info_t *subdoc, const char *str)
{
    cJSON *parent_obj, *net_obj, *dev_arr_objs, *dev_obj;
    unsigned int size, i,num_objs;
    em_long_string_t parent_key;
    cJSON *id, *cltmac;

    printf("%s:%d: test Received Subdoc\n", __func__, __LINE__);
    printf("%s\n", subdoc->buff);

    snprintf(parent_key, sizeof(em_long_string_t), "wfa-dataelements:%s", str);

    if ((parent_obj = cJSON_Parse(subdoc->buff)) == NULL) {
        printf("%s:%d: Failed to initialize device data model\n", __func__, __LINE__);
        return -1;
    }
    if ((net_obj = cJSON_GetObjectItem(parent_obj, parent_key)) == NULL) {
        cJSON_Delete(parent_obj);
        printf("%s:%d: wfa-dataelements:%s not present\n", __func__, __LINE__, str);
        return -1;
    }
    if ((dev_arr_objs = cJSON_GetObjectItem(net_obj, "DeviceList")) == NULL) {
        cJSON_Delete(parent_obj);
        printf("%s:%d: DeviceList not present\n", __func__, __LINE__);
        return -1;
    }
    if (size == 0) {
        cJSON_Delete(parent_obj);
        printf("%s:%d: DeviceList has no memebers not present\n", __func__, __LINE__);
        return -1;
    }
    if ((dev_obj = cJSON_GetArrayItem(dev_arr_objs, 0)) != NULL) {
        id = cJSON_GetObjectItem(dev_obj, "MsgID");
	if ( id == NULL) {
            printf("%s:%d: cannot find msg id\n", __func__, __LINE__);
        }
        if (id != NULL)
             msg_id = id->valuedouble;
        printf("%s:%d: msg id %d\n", __func__, __LINE__,msg_id);
    }
    return 0;
}

int dm_easy_mesh_t::decode_client_cap_config(em_subdoc_info_t *subdoc, const char *str, char *clientmac, char *radiomac)
{
    cJSON *parent_obj, *net_obj, *dev_arr_objs, *dev_obj;
    unsigned int size, i,num_opclass;
    em_long_string_t parent_key;
    cJSON *id, *cltmac, *rmac;
	
    printf("%s:%d: test Received Subdoc\n", __func__, __LINE__);
    printf("%s\n", subdoc->buff);

    snprintf(parent_key, sizeof(em_long_string_t), "wfa-dataelements:%s", str);

    if ((parent_obj = cJSON_Parse(subdoc->buff)) == NULL) {
        printf("%s:%d: Failed to initialize device data model\n", __func__, __LINE__);
        return -1;
     }
     if ((net_obj = cJSON_GetObjectItem(parent_obj, parent_key)) == NULL) {
         cJSON_Delete(parent_obj);
	 printf("%s:%d: wfa-dataelements:%s not present\n", __func__, __LINE__, str);
	 return -1;
     }
	
     if ((dev_arr_objs = cJSON_GetObjectItem(net_obj, "DeviceList")) == NULL) {
        cJSON_Delete(parent_obj);
        printf("%s:%d: DeviceList not present\n", __func__, __LINE__);
	return -1;
    }
    if (size == 0) {
        cJSON_Delete(parent_obj);
        printf("%s:%d: DeviceList has no memebers not present\n", __func__, __LINE__);
        return -1;
    }
    if ((dev_obj = cJSON_GetArrayItem(dev_arr_objs, 0)) != NULL) {
        id = cJSON_GetObjectItem(dev_obj, "MsgID");
        cltmac = cJSON_GetObjectItem(dev_obj, "ClientMac");
	rmac = cJSON_GetObjectItem(dev_obj, "RadioMac");
        if (( id == NULL) || (cltmac == NULL)) {
           printf("%s:%d: cannot find msg id\n", __func__, __LINE__);
        }
        if (id != NULL)
	msg_id = id->valuedouble;
        if (cltmac != NULL) {
            snprintf((char *) clientmac, sizeof(clientmac), "%s", cJSON_GetStringValue(cltmac));
        }
        if (rmac != NULL) {
	        snprintf((char *) radiomac, sizeof(radiomac), "%s", cJSON_GetStringValue(rmac));
        }
	//printf("%s:%d: msg id %d rmac=%s\n", __func__, __LINE__,msg_id,radiomac);

    }
    return 0;
}


void dm_easy_mesh_t::deinit()
{
	hash_map_destroy(m_sta_map);
}


int dm_easy_mesh_t::init()
{
    unsigned int i;
	m_network.init();
    m_device.init();
	m_ieee_1905_security.init();
    
    for (i = 0; i < EM_MAX_BANDS; i++) {
        m_radio[i].init();
    }
    for (i = 0; i < EM_MAX_NET_SSIDS; i++) {
	    m_network_ssid[i].init();
    }
	m_sta_map = hash_map_create();
    m_sta_assoc_map = hash_map_create();
    m_sta_dassoc_map = hash_map_create();
	
    return 0;
}

void dm_easy_mesh_t::print_hex_dump(unsigned int length, unsigned char *buffer)
{
    int i;
    unsigned char buff[512] = {};
    const unsigned char * pc = (const unsigned char *)buffer;

    if ((pc == NULL) || (length <= 0)) {
        printf ("buffer NULL or BAD LENGTH = %d :\n", length);
        return;
    }

    for (i = 0; i < length; i++) {
        if ((i % 16) == 0) {
            if (i != 0)
                printf ("  %s\n", buff);
            printf ("  %04x ", i);
        }

        printf (" %02x", pc[i]);

        if (!isprint(pc[i]))
            buff[i % 16] = '.';
        else
            buff[i % 16] = pc[i];
        buff[(i % 16) + 1] = '\0';
    }

    while ((i % 16) != 0) {
        printf ("   ");
        i++;
    }

    printf ("  %s\n", buff);
}

char *dm_easy_mesh_t::macbytes_to_string(mac_address_t mac, char* string)
{
    if( mac != NULL) {
        sprintf((char *)string, "%02x:%02x:%02x:%02x:%02x:%02x",
            mac[0] & 0xff,
            mac[1] & 0xff,
            mac[2] & 0xff,
            mac[3] & 0xff,
            mac[4] & 0xff,
            mac[5] & 0xff);
    }
    return (char *)string;
}

void dm_easy_mesh_t::string_to_macbytes(char *key, mac_address_t bmac)
{
    unsigned int mac[6];
    if(strlen(key) > MIN_MAC_LEN)
        sscanf(key, "%02x:%02x:%02x:%02x:%02x:%02x",
                &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
    else
        sscanf(key, "%02x%02x%02x%02x%02x%02x",
                &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
    bmac[0] = mac[0]; bmac[1] = mac[1]; bmac[2] = mac[2];
    bmac[3] = mac[3]; bmac[4] = mac[4]; bmac[5] = mac[5];

}

void dm_easy_mesh_t::securitymode_to_str(unsigned short mode, char *sec_mode_str, int len)
{
    if (mode == EM_AUTH_OPEN)
        snprintf(sec_mode_str, len, "%s", "OPEN");
    else if (mode == EM_AUTH_WPAPSK)
        snprintf(sec_mode_str, len, "%s", "WEP_64");
    else if (mode == EM_AUTH_SHARED)
        snprintf(sec_mode_str, len, "%s", "WEP_128");
    else if (mode == EM_AUTH_SAE)
        snprintf(sec_mode_str, len, "%s", "WPA-WPA2-Personal"); //TODO Need to check what SAE
    else if (mode == EM_AUTH_WPA2PSK)
        snprintf(sec_mode_str, len, "%s", "WPA-Personal");
    else if (mode == EM_AUTH_WPA2)
        snprintf(sec_mode_str, len, "%s", "WPA2-Personal");
    else if (mode == EM_AUTH_WPA2PSK)
        snprintf(sec_mode_str, len, "%s", "WPA-WPA2-Personal");
}

void dm_easy_mesh_t::str_to_securitymode(unsigned short *mode, char *sec_mode_str, int len)
{
    if (strncmp(sec_mode_str,"OPEN", len) == 0)
        *mode = EM_AUTH_OPEN;
    else if (strncmp(sec_mode_str,"WEP_64", len) == 0)
        *mode = EM_AUTH_WPAPSK;
    else if (strncmp(sec_mode_str,"WEP_128", len) == 0)
        *mode = EM_AUTH_SHARED;
    else if (strncmp(sec_mode_str,"WPA-WPA2-Personal", len) == 0)
        *mode = EM_AUTH_WPA2PSK;
    else if (strncmp(sec_mode_str,"WPA-Personal", len) == 0)
        *mode = EM_AUTH_WPA;
    else if (strncmp(sec_mode_str,"WPA2-Personal", len) == 0)
        *mode = EM_AUTH_WPA2;
    else if (strncmp(sec_mode_str,"WPA-WPA2-Personal",len) == 0) 
        *mode = EM_AUTH_SAE;
}

int dm_easy_mesh_t::mac_address_from_name(const char *ifname, mac_address_t mac)
{
    int sock;
    struct ifreq ifr;

    if ((sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP)) < 0) {
        printf("%s:%d: Failed to create socket\n", __func__, __LINE__);
        return -1;
    }

    memset(&ifr, 0, sizeof(struct ifreq));
    ifr.ifr_addr.sa_family = AF_INET;
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", ifname);
    if (ioctl(sock, SIOCGIFHWADDR, &ifr) != 0) {
        close(sock);
        printf("%s:%d: ioctl failed to get hardware address for interface:%s\n", __func__, __LINE__, ifname);
        return -1;
    }

    memcpy(mac, (unsigned char *)ifr.ifr_hwaddr.sa_data, sizeof(mac_address_t));

    close(sock);

    return 0;
}

int dm_easy_mesh_t::name_from_mac_address(const mac_address_t *mac, char *ifname)
{
    struct ifaddrs *ifaddr = NULL, *tmp = NULL;
    struct sockaddr *addr;
    struct sockaddr_ll *ll_addr;
    bool found = false;

    if (getifaddrs(&ifaddr) != 0) {
        printf("%s:%d: Failed to get interfae information\n", __func__, __LINE__);
        return -1;
    }

    tmp = ifaddr;
    while (tmp != NULL) {
        addr = tmp->ifa_addr;
        ll_addr = (struct sockaddr_ll*)tmp->ifa_addr;
        if ((addr != NULL) && (addr->sa_family == AF_PACKET) && (memcmp(ll_addr->sll_addr, mac, sizeof(mac_address_t)) == 0)) {
            snprintf(ifname, sizeof(ifname), "%s", tmp->ifa_name);
            found = true;
            break;
        }

        tmp = tmp->ifa_next;
    }

    freeifaddrs(ifaddr);

    return (found == true) ? 0:-1;
}

rdk_wifi_radio_t *dm_easy_mesh_t::get_radio_data(em_interface_t *interface)
{
	unsigned int i;
	rdk_wifi_radio_t *radio;

	for (i = 0; i < m_wifi_data.u.decoded.num_radios; i++) {
		radio = &m_wifi_data.u.decoded.radios[i];

		if (strncmp(radio->name, interface->name, strlen(radio->name)) == 0) {
			return radio;
		}
			
	}

	return NULL;
}

dm_radio_t *dm_easy_mesh_t::get_radio(unsigned int index)
{

	return &m_radio[index];
}

dm_radio_t *dm_easy_mesh_t::get_radio(mac_address_t mac)
{
    int i = 0;
    for (i = 0; i < m_num_radios; i++) {
        if (memcmp(m_radio[i].m_radio_info.id.mac, mac, sizeof(mac_address_t)) == 0) {
            return &m_radio[i];
        }
    }
    return NULL;
}

dm_radio_cap_t *dm_easy_mesh_t::get_radio_cap(mac_address_t mac)
{
    int i = 0;
    for (i = 0; i < m_num_radios; i++) {
        if (memcmp(m_radio_cap[i].m_radio_cap_info.ruid.mac, mac, sizeof(mac_address_t)) == 0) {
            return &m_radio_cap[i];
        }
    }
    return NULL;
}

dm_radio_t *dm_easy_mesh_t::find_matching_radio(dm_radio_t *radio)
{
    int i = 0;
    for (i = 0; i < m_num_radios; i++) {
        if (memcmp(m_radio[i].m_radio_info.id.mac, radio->m_radio_info.id.mac, sizeof(mac_address_t)) == 0) {
            return &m_radio[i];
        }
    }
    return NULL;
}

dm_op_class_t *dm_easy_mesh_t::get_curr_op_class(unsigned int index)
{
        return &m_op_class[index];
}

dm_device_t *dm_easy_mesh_t::find_matching_device(dm_device_t *dev)
{
    int i = 0;
        if (memcmp(m_device.m_device_info.id.mac, dev->m_device_info.id.mac, sizeof(mac_address_t)) == 0) {
            return &m_device;
        }
    return NULL;
}

void dm_easy_mesh_t::print_config()
{
    unsigned int i;
    mac_addr_str_t  ctrl_mac, ctrl_al_mac, agent_al_mac, radio_mac, mac_str;

    dm_easy_mesh_t::macbytes_to_string(get_controller_interface_mac(), ctrl_mac);
    dm_easy_mesh_t::macbytes_to_string(get_ctrl_al_interface_mac(), ctrl_al_mac);
    dm_easy_mesh_t::macbytes_to_string(get_agent_al_interface_mac(), agent_al_mac);
	printf("%s:%d:Network:%s\n", __func__, __LINE__, m_network.m_net_info.id);
    printf("%s:%d:Controller MAC:%s\tController AL MAC:%s\tAgent AL MAC:%s\n", __func__, __LINE__,
            ctrl_mac, ctrl_al_mac, agent_al_mac);
    printf("%s:%d:Manufacturer:%s\tManufacturere Model:%s\tSoftwareVersion:%s\n", __func__, __LINE__,
            get_manufacturer(), get_manufacturer_model(), get_software_version());

    for (i = 0; i < m_num_net_ssids; i++) {
        printf("%s:%d:Data Model SSID[%d]: %s\n", __func__, __LINE__, i, m_network_ssid[i].m_network_ssid_info.ssid);
    }

    for (i = 0; i < m_num_opclass; i++) {
        dm_easy_mesh_t::macbytes_to_string(m_op_class[i].m_op_class_info.id.ruid, radio_mac);
        printf("%s:%d: OpClass[%d] id.ruid: %s id.type: %d id.index: %d\n", __func__, __LINE__, i, radio_mac, m_op_class[i].m_op_class_info.id.type, m_op_class[i].m_op_class_info.id.index);
    }

    printf("%s:%d:No of BSS=%d No of Radios=%d \n", __func__, __LINE__, m_num_bss, m_num_radios);
    for (i = 0; i < m_num_bss; i++) {
        dm_easy_mesh_t::macbytes_to_string(get_bss(i)->get_bss_info()->ruid.mac, mac_str);
        printf("%s:%d:Radio Mac : %s ", __func__, __LINE__, mac_str);
        dm_easy_mesh_t::macbytes_to_string(get_bss(i)->get_bss_info()->bssid.mac, mac_str);
        printf("BSSID : %s\n", mac_str);
    }

    for (i = 0;i < m_num_radios; i++) {
        dm_easy_mesh_t::macbytes_to_string(m_radio[i].get_radio_info()->id.mac, mac_str);
        printf("%s:%d:Radio Mac: %s \n", __func__, __LINE__, mac_str);
    }
}


bool dm_easy_mesh_t::operator==(dm_easy_mesh_t const& obj)
{
    int ret = 0;
    ret += (memcmp(&this->m_device,&obj.m_device,sizeof(dm_device_t)) != 0);
    ret += (memcmp(&this->m_network,&obj.m_network,sizeof(dm_network_t)) != 0);
    ret += (memcmp(&this->m_ieee_1905_security,&obj.m_ieee_1905_security,sizeof(dm_ieee_1905_security_t)) != 0);
    for (unsigned int i = 0; i < m_num_radios; i++) {
        ret += memcmp(&this->m_radio, &obj.m_radio, sizeof(dm_radio_t));
    }
    ret += this->m_num_radios == obj.m_num_radios;
    ret += this->m_num_opclass == obj.m_num_opclass;
    for (unsigned int i = 0; i < EM_MAX_BSSS; i++) {
        ret += memcmp(&this->m_bss[i], &obj.m_bss[i], sizeof(dm_bss_t));
    }
    ret += (memcmp(&this->m_dpp,&obj.m_dpp,sizeof(dm_dpp_t)) != 0);
    for (unsigned int i = 0; i < EM_MAX_OPCLASS; i++) {
        ret += (memcmp(&this->m_op_class[i], &obj.m_op_class, sizeof(dm_op_class_t)) != 0);
    }
    ret += (memcmp(&this->m_network_ssid,&obj.m_network_ssid,sizeof(dm_network_ssid_t)) != 0);

    if (ret > 0)
        return false;
    else
        return true;
}

void dm_easy_mesh_t::create_autoconfig_renew_json_cmd(char* src_mac_addr, char* agent_al_mac, em_freq_band_t freq_band, char* autoconfig_renew_json)
{
    cJSON *root, *renew, *device_list, *radio_list, *current_operating_classes, *class_item;
    int op_class = em_freq_band_24;
    root = cJSON_CreateObject();
    renew = cJSON_CreateObject();
    device_list = cJSON_CreateArray();
    radio_list = cJSON_CreateArray();
    current_operating_classes = cJSON_CreateArray();
    class_item = cJSON_CreateObject();
    cJSON_AddStringToObject(renew, "ID", "OneWifiMesh");
    cJSON_AddNumberToObject(renew, "NumberOfDevices", 1);
    cJSON_AddStringToObject(renew, "TimeStamp", "2019-02-11T06:23:43.743847-08:00");
    cJSON_AddStringToObject(renew, "ControllerID", src_mac_addr);
    switch (freq_band) {
        case em_freq_band_24:
            op_class = EM_MIN_OP_CLASS_24;
            break;
        case em_freq_band_5:
            op_class =  EM_MIN_OP_CLASS_5;
            break;
        case em_freq_band_60:
            op_class = EM_MIN_OP_CLASS_6;
            break;
        default:
            break;
    }
    cJSON_AddNumberToObject(class_item, "Class", op_class);
    cJSON_AddItemToArray(current_operating_classes, class_item);
    cJSON *radio = cJSON_CreateObject();
    cJSON_AddItemToArray(radio_list, radio);
    cJSON_AddItemToObject(radio, "CurrentOperatingClasses", current_operating_classes);
    cJSON *device = cJSON_CreateObject();
    cJSON_AddStringToObject(device, "ID", agent_al_mac);
    cJSON_AddItemToObject(device, "RadioList", radio_list);
    cJSON_AddItemToArray(device_list, device);
    cJSON_AddItemToObject(renew, "DeviceList", device_list);
    cJSON_AddItemToObject(root, "wfa-dataelements:Renew", renew);
    char* tmp = cJSON_Print(root);
    snprintf(autoconfig_renew_json, sizeof(autoconfig_renew_json), "%s", tmp);
    cJSON_Delete(root);
}

void dm_easy_mesh_t::create_ap_cap_query_json_cmd(char* src_mac_addr, char* agent_al_mac, char* ap_query_json, short msg_id)
{
    cJSON *root, *query_info, *device_list;
    root = cJSON_CreateObject();
    query_info = cJSON_CreateObject();
    device_list = cJSON_CreateArray();
    cJSON_AddStringToObject(query_info, "ID", "OneWifiMesh");
    cJSON_AddNumberToObject(query_info, "NumberOfDevices", 1);
    cJSON_AddStringToObject(query_info, "TimeStamp", "2019-02-11T06:23:43.743847-08:00");
    cJSON_AddStringToObject(query_info, "ControllerID", src_mac_addr);
    cJSON_AddNumberToObject(query_info, "MsgID", msg_id);
    cJSON *device = cJSON_CreateObject();
    cJSON_AddStringToObject(device, "ID", agent_al_mac);
    cJSON_AddItemToArray(device_list, device);
    cJSON_AddItemToObject(query_info, "DeviceList", device_list);
    cJSON_AddItemToObject(root, "wfa-dataelements:Radiocap", query_info);
    char* tmp = cJSON_Print(root);
    snprintf(ap_query_json, sizeof(ap_query_json), "%s", tmp);
    cJSON_Delete(root);
}

void dm_easy_mesh_t::create_client_cap_query_json_cmd(char* src_mac_addr, char* agent_al_mac, char* ap_query_json, short msg_id, char *mac)
{
    cJSON *root, *query_info, *device_list;
    root = cJSON_CreateObject();
    query_info = cJSON_CreateObject();
    device_list = cJSON_CreateArray();
    cJSON_AddStringToObject(query_info, "ID", "OneWifiMesh");
    cJSON_AddNumberToObject(query_info, "NumberOfDevices", 1);
    cJSON_AddStringToObject(query_info, "TimeStamp", "2019-02-11T06:23:43.743847-08:00");
    cJSON_AddStringToObject(query_info, "ControllerID", src_mac_addr);
    cJSON_AddNumberToObject(query_info, "MsgID", msg_id);
    cJSON_AddStringToObject(query_info, "ClientMac", mac);
    cJSON *device = cJSON_CreateObject();
    cJSON_AddStringToObject(device, "ID", agent_al_mac);
    cJSON_AddItemToArray(device_list, device);
    cJSON_AddItemToObject(query_info, "DeviceList", device_list);
    cJSON_AddItemToObject(root, "wfa-dataelements:Clientcap", query_info);
    char* tmp = cJSON_Print(root);
    snprintf(ap_query_json, sizeof(ap_query_json), "%s", tmp);
    cJSON_Delete(root);
}

em_network_ssid_info_t *dm_easy_mesh_t::get_network_ssid_info_by_haul_type(em_haul_type_t haul_type)
{
    em_network_ssid_info_t *info;
    unsigned int i, j;
    bool found = false;

    for (i = 0; i < m_num_net_ssids; i++) {
        info = &m_network_ssid[i].m_network_ssid_info;
        //printf("%s:%d: ssid: %s, Number of Hauls: %d Haul Type: %s\n", __func__, __LINE__, info->ssid, info->num_hauls, info->haul_type[0]);
        for (j = 0; j < info->num_hauls; j++) {
            if (info->haul_type[j] == haul_type) {
                found = true;
                break;
            }
        }
        if (found == true) {
            break;
        }
    }

    return (found == true) ? info:NULL;
}

em_sta_info_t *dm_easy_mesh_t::get_first_sta_info()
{
	dm_sta_t *sta = NULL;

	//sta = (dm_sta_t *)hash_map_get_first(m_sta_map);
	sta = (dm_sta_t *)hash_map_get_first(m_sta_assoc_map);
    if (sta != NULL) {
		return &sta->m_sta_info;
	}

	return NULL;
}

em_sta_info_t *dm_easy_mesh_t::get_next_sta_info(em_sta_info_t *info)
{
	dm_sta_t *sta = NULL;
	bool return_next = false;

	//sta = (dm_sta_t *)hash_map_get_first(m_sta_map);
    sta = (dm_sta_t *)hash_map_get_first(m_sta_assoc_map);
	while (sta != NULL) {
		if (return_next == true) {
			break;
		}
		if (info == &sta->m_sta_info) {
			return_next = true;
		}
		//sta = (dm_sta_t *)hash_map_get_next(m_sta_map, sta);
	    sta = (dm_sta_t *)hash_map_get_next(m_sta_assoc_map, sta);
    }

	if (return_next == true) {
		return &sta->m_sta_info;
	}

	return NULL;
}

em_sta_info_t *dm_easy_mesh_t::get_sta_info(unsigned char *mac)
{
	mac_addr_str_t mac_str;
	dm_sta_t *sta = NULL;

	dm_easy_mesh_t::macbytes_to_string(mac, mac_str);
	//sta = (dm_sta_t *)hash_map_get(m_sta_map, mac_str);
    sta = (dm_sta_t *)hash_map_get(m_sta_assoc_map, mac_str);
	if (sta != NULL) {
		return &sta->m_sta_info;
	}	

	return NULL;
}

/*void dm_easy_mesh_t::put_sta_info(em_sta_info_t *sta_info)
{
	mac_addr_str_t mac_str;

	dm_easy_mesh_t::macbytes_to_string(sta_info->id, mac_str);
	if (get_sta_info(sta_info->id) != NULL) {
		hash_map_put(m_sta_map, strdup(mac_str), new dm_sta_t(sta_info));	
	}	
}
*/

void dm_easy_mesh_t::put_sta_info(em_sta_info_t *sta_info)
{
    printf("---put_sta_info dm map addr: %p\n", m_sta_assoc_map);
    mac_addr_str_t s_mac_str, d_mac_str;
    em_sta_info_t *em_sta;
    em_sta = get_sta_info(sta_info->id);
    if(em_sta != NULL)
    {
        dm_easy_mesh_t::macbytes_to_string(sta_info->id, s_mac_str);
        dm_easy_mesh_t::macbytes_to_string(em_sta->id, d_mac_str);
        if(strcmp(s_mac_str, d_mac_str) != 0)
        {
            return;
        }
    }
    if(sta_info == NULL)
    {
        printf("sta info in put map null\n");
    }
//  hash_map_put(m_sta_map, strdup(s_mac_str), new dm_sta_t(sta_info));
    int ret = hash_map_put(m_sta_assoc_map, strdup(s_mac_str), new dm_sta_t(sta_info));
    printf("---put_sta_info ret %d\n", ret);
}

dm_easy_mesh_t::dm_easy_mesh_t(const dm_network_t& net)
{
    memcpy(&m_device.m_device_info.id, &net.m_net_info.ctrl_id, sizeof(em_interface_t));
    memcpy(&m_device.m_device_info.backhaul_alid, &net.m_net_info.ctrl_id, sizeof(em_interface_t));
    memcpy(&m_device.m_device_info.backhaul_mac, &net.m_net_info.ctrl_id, sizeof(em_interface_t));

    name_from_mac_address(&m_device.m_device_info.id.mac, m_device.m_device_info.id.name);  
    name_from_mac_address(&m_device.m_device_info.backhaul_alid.mac, m_device.m_device_info.backhaul_alid.name);    
    name_from_mac_address(&m_device.m_device_info.backhaul_mac.mac, m_device.m_device_info.backhaul_mac.name);  
}

dm_easy_mesh_t::dm_easy_mesh_t()
{
    m_num_radios = 0;
	m_num_opclass = 0;
	m_num_bss = 0;
	m_db_cfg_type = db_cfg_type_none;
    m_colocated = false;
}

dm_easy_mesh_t::~dm_easy_mesh_t()
{

}


