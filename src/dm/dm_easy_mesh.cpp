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
#include "em_cmd_client_cap.h"

dm_easy_mesh_t dm_easy_mesh_t::operator =(dm_easy_mesh_t const& obj)
{
    dm_sta_t *sta;
    em_long_string_t key;
    mac_addr_str_t radio_mac_str, bss_mac_str, sta_mac_str;

    memcpy(&m_device, &obj.m_device, sizeof(dm_device_t));
    memcpy(&m_network, &obj.m_network, sizeof(dm_network_t));
    memcpy(&m_ieee_1905_security, &obj.m_ieee_1905_security, sizeof(dm_ieee_1905_security_t));

	if (m_num_radios >= EM_MAX_BANDS) {
		m_num_radios = 0;
	}
    this->m_num_radios = obj.m_num_radios;
    for (unsigned int i = 0; i < obj.m_num_radios; i++) {
        memcpy(&m_radio[i], &obj.m_radio[i], sizeof(dm_radio_t));
    }

    this->m_num_bss = obj.m_num_bss;
    for (unsigned int i = 0; i < EM_MAX_BSSS; i++) {
        memcpy(&m_bss[i], &obj.m_bss[i], sizeof(dm_bss_t));
    }
    memcpy(&m_dpp, &obj.m_dpp, sizeof(dm_dpp_t));

    m_num_opclass = obj.m_num_opclass;
    for (unsigned int i = 0; i < EM_MAX_OPCLASS; i++) {
        memcpy(&m_op_class[i], &obj.m_op_class[i], sizeof(dm_op_class_t));
    }

    this->m_num_net_ssids = obj.m_num_net_ssids;
    for (unsigned int i = 0; i < EM_MAX_NET_SSIDS; i++) {
        memcpy(&m_network_ssid[i], &obj.m_network_ssid[i], sizeof(dm_network_ssid_t));
    }

    memcpy(&m_db_cfg_param, &obj.m_db_cfg_param, sizeof(em_db_cfg_param_t));

    m_num_policy = obj.m_num_policy;
    for (unsigned int i = 0; i < EM_MAX_POLICIES; i++) {
        memcpy(&m_policy[i], &obj.m_policy[i], sizeof(dm_policy_t));
    }

    sta = (dm_sta_t *)hash_map_get_first(obj.m_sta_map);
    while (sta != NULL) {
        dm_easy_mesh_t::macbytes_to_string(sta->m_sta_info.id, sta_mac_str);
        dm_easy_mesh_t::macbytes_to_string(sta->m_sta_info.bssid, bss_mac_str);
        dm_easy_mesh_t::macbytes_to_string(sta->m_sta_info.radiomac, radio_mac_str);
        snprintf(key, sizeof(em_long_string_t), "%s@%s@%s", sta_mac_str, bss_mac_str, radio_mac_str);
        hash_map_put(m_sta_map, strdup(key), new dm_sta_t(*sta));
        sta = (dm_sta_t *)hash_map_get_next(obj.m_sta_map, sta);
    }

    m_em = obj.m_em;

    return *this;
}

int dm_easy_mesh_t::commit_config(dm_easy_mesh_t& dm, em_commit_target_t target)
{
    unsigned int i, found = 0;
    int j = 0;
    dm_radio_t *radio;
    mac_address_t mac;
    dm_sta_t *sta;
    mac_addr_str_t mac_str;

    if (target.type == em_commit_target_sta_hash_map ) {
    } else if (target.type == em_commit_target_al) {
        m_network = dm.m_network;
        m_device = dm.m_device;
    } else if (target.type == em_commit_target_radio) {
        string_to_macbytes((char *)target.params,mac);
        radio = dm.get_radio(mac);
        if (radio != NULL) {
            for (i = 0;i < m_num_radios; i++) {
                if (memcmp(radio->get_radio_info()->intf.mac, get_radio(i)->get_radio_info()->intf.mac, sizeof(mac_address_t)) == 0) {
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
			//Commit op class
			for (i = 0; i<dm.m_num_opclass; i++) {
				if (memcmp(radio->get_radio_info()->intf.mac, dm.m_op_class[i].m_op_class_info.id.ruid, sizeof(mac_address_t)) == 0) {
					found = 0;
					for (j = 0; j<m_num_opclass;j++) {
						if ((dm.m_op_class[i].m_op_class_info.op_class == m_op_class[j].m_op_class_info.op_class) &&
							(dm.m_op_class[i].m_op_class_info.id.type == m_op_class[j].m_op_class_info.id.type)) {
							m_op_class[j].m_op_class_info = dm.m_op_class[i].m_op_class_info;
							printf("%s:%d op class=%d  already exist so updated \n", __func__, __LINE__,
								dm.m_op_class[i].m_op_class_info.op_class);
							found++;
							break;
						} else if ((dm.m_op_class[i].m_op_class_info.id.type == m_op_class[j].m_op_class_info.id.type) && 
							(dm.m_op_class[i].m_op_class_info.id.type == 1) &&
							(memcmp(dm.m_op_class[i].m_op_class_info.id.ruid, m_op_class[j].m_op_class_info.id.ruid, sizeof(mac_address_t)) == 0)) {
							m_op_class[j].m_op_class_info = dm.m_op_class[i].m_op_class_info;
							printf("%s:%d op class=%d  already exist so updated  ID = 1\n", 
								__func__, __LINE__,dm.m_op_class[i].m_op_class_info.op_class);
                           	found++;
                           	break;
						}
					}
					if (found == 0) {
						//New Op class
						printf("%s:%d New op class=%d commiting it \n", __func__, __LINE__,dm.m_op_class[i].m_op_class_info.op_class);
						m_op_class[m_num_opclass].m_op_class_info = dm.m_op_class[i].m_op_class_info;
						m_num_opclass++;
					}
				}
        	}
		}	
    } else if (target.type == em_commit_target_bss) {
        printf("%s:%d Commit radio=%s\n", __func__, __LINE__,target.params);
        string_to_macbytes((char *)target.params,mac);
		for (i = 0; i < dm.m_num_bss; i++) {
			if (memcmp(mac, dm.get_bss(i)->get_bss_info()->ruid.mac, sizeof(mac_address_t)) == 0) {
				for (j = 0; j < m_num_bss; j++) {
					if ((memcmp(get_bss(j)->get_bss_info()->bssid.mac, dm.get_bss(i)->get_bss_info()->bssid.mac, sizeof(mac_address_t)) == 0)){
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
					printf("%s:%d New BSS %s configuration updated  no of bss=%d vapname=%s\n", __func__, __LINE__,mac_str,m_num_bss, dm.get_bss(i)->get_bss_info()->bssid.name);
				}
			}
		}
	}
    return false;
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
            printf("COMMIT DPP\n");
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
                    default:
                        printf("%s:%d: unhandled case %d\n", __func__, __LINE__, cmd->get_orch_op());
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

int analyze_client_cap_query(em_bus_event_t *evt, em_cmd_t *pcmd[])
{
    return 0;
}

int dm_easy_mesh_t::analyze_sta_list(em_bus_event_t *evt, em_cmd_t *pcmd[])
{
    return 0;
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
    cJSON *parent_obj, *net_obj, *interfaces_obj, *interface_obj, *interface_arr_obj, *ssid_obj, *ssid_arr_objs;
	char *formatted_json;
	mac_addr_str_t	mac_str;
	em_long_string_t	interface_str;
	const char *preference[] = {"First Preference", "Second Preference", "Third Preference", "Fourth Preference", "Fifth Preference"};
	unsigned int i, preference_arraysz = sizeof(preference)/sizeof(*preference);

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

	if ((interfaces_obj = cJSON_AddObjectToObject(net_obj, "Interfaces")) == NULL) {
		printf("%s:%d: Could not create interface object\n", __func__, __LINE__);
        return -1;
	}

	if ((interface_arr_obj = cJSON_AddArrayToObject(interfaces_obj, "List")) == NULL) {
        printf("%s:%d: Could not create interface array object\n", __func__, __LINE__);
        return -1;
    }

	for (i = 0; i < m_num_interfaces && i < preference_arraysz; i++) {
		interface_obj = cJSON_CreateObject();
		cJSON_AddItemToArray(interface_arr_obj, interface_obj);
		dm_easy_mesh_t::macbytes_to_string(m_interfaces[i].mac, mac_str);
		snprintf(interface_str, sizeof(em_long_string_t), "%s (%s)", mac_str, m_interfaces[i].name);
		cJSON_AddStringToObject(interface_obj, preference[i], interface_str);
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

    //printf("%s:%d: %s\n", __func__, __LINE__, formatted_json);
    snprintf(subdoc->buff, EM_IO_BUFF_SZ, "%s", formatted_json);
    cJSON_free(formatted_json);
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

        if (encode_config_op_class_array(op_arr_objs, em_op_class_type_current, m_radio[i].m_radio_info.intf.mac) != 0) {
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
			if (memcmp(m_bss[j].m_bss_info.ruid.mac, m_radio[i].m_radio_info.intf.mac, sizeof(mac_address_t)) != 0) {
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

        if (encode_config_op_class_array(op_arr_objs, em_op_class_type_capability, m_radio[i].m_radio_info.intf.mac) != 0) {
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

  	if (encode_config_op_class_array(op_arr_objs, em_op_class_type_cac_available, m_device.m_device_info.intf.mac) != 0) {
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

  	if (encode_config_op_class_array(op_arr_objs, em_op_class_type_cac_non_occ, m_device.m_device_info.intf.mac) != 0) {
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

  	if (encode_config_op_class_array(op_arr_objs, em_op_class_type_cac_active, m_device.m_device_info.intf.mac) != 0) {
        printf("%s:%d: ActiveChannelList Encoding failed \n", __func__, __LINE__);
        cJSON_Delete(parent_obj);
        return -1;
    }

	formatted_json = cJSON_Print(parent_obj);
    snprintf(subdoc->buff, EM_IO_BUFF_SZ, "%s", formatted_json);
    cJSON_free(formatted_json);

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
    } else if (strncmp(str, "ChannelScanRequest", strlen("ChannelScanRequest")) == 0) {
        snprintf(key, sizeof(em_long_string_t), "wfa-dataelements:%s", str);
        return decode_config_set_channel(subdoc, key, index, num);
    } else if (strncmp(str, "SetPolicy", strlen("SetPolicy")) == 0) {
        snprintf(key, sizeof(em_long_string_t), "wfa-dataelements:%s", str);
        return decode_config_set_policy(subdoc, key, index, num);
    } else if (strncmp(str, "RadioEnable", strlen("RadioEnable")) == 0) {
        snprintf(key, sizeof(em_long_string_t), "wfa-dataelements:%s", str);
        return decode_config_set_radio(subdoc, key, index, num);
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
    cJSON *parent_obj, *net_obj, *ssid_obj, *ssid_arr_obj, *interfaces_obj, *preference_list_obj, *preference_obj, *obj;
    unsigned int i;
	unsigned int num_interfaces = EM_MAX_INTERFACES;

	get_interfaces_list(m_interfaces, &num_interfaces);
	m_num_interfaces = num_interfaces;

    //printf("%s\n", subdoc->buff);
    if ((parent_obj = cJSON_Parse(subdoc->buff)) == NULL) {
        printf("%s:%d: Failed to initialize device data model\n", __func__, __LINE__);
        return -1;
    }

    if ((net_obj = cJSON_GetObjectItem(parent_obj, key)) == NULL) {
        cJSON_Delete(parent_obj);
        return -1;
    }

	if ((interfaces_obj = cJSON_GetObjectItem(net_obj, "Interfaces")) == NULL) {
        cJSON_Delete(parent_obj);
        return -1;
	}

	if ((preference_list_obj = cJSON_GetObjectItem(interfaces_obj, "Preference")) != NULL) {
		for (i = 0; i < cJSON_GetArraySize(preference_list_obj); i++) {
			preference_obj = cJSON_GetArrayItem(preference_list_obj, i);

			if ((obj = cJSON_GetObjectItem(preference_obj, "rpi")) != NULL) {
				strncpy(m_preference[m_num_preferences].platform, "rpi", strlen("rpi") + 1);
				if (strncmp(cJSON_GetStringValue(obj), "eth", strlen("eth")) == 0) {
					m_preference[m_num_preferences].media = em_media_type_ieee8023ab;
				} else if (strncmp(cJSON_GetStringValue(obj), "wlan", strlen("wlan")) == 0) {
					m_preference[m_num_preferences].media = em_media_type_ieee80211b_24;
				}
				m_num_preferences++;
			} 

			if ((obj = cJSON_GetObjectItem(preference_obj, "sim")) != NULL) {
				strncpy(m_preference[m_num_preferences].platform, "sim", strlen("sim") + 1);
				if (strncmp(cJSON_GetStringValue(obj), "ens", strlen("ens")) == 0) {
					m_preference[m_num_preferences].media = em_media_type_ieee8023ab;
				}
				m_num_preferences++;
			}

			if ((obj = cJSON_GetObjectItem(preference_obj, "bpi")) != NULL) {
                                strncpy(m_preference[m_num_preferences].platform, "bpi", strlen("bpi") + 1);
                                if (strncmp(cJSON_GetStringValue(obj), "erouter", strlen("erouter")) == 0) {
                                        m_preference[m_num_preferences].media = em_media_type_ieee8023ab;
                                }
                                m_num_preferences++;
                        }
		}
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
	m_num_radios = 0;
    cJSON_Delete(parent_obj);
    //printf("%s:%d: End\n", __func__, __LINE__);
    return 0;
}

int dm_easy_mesh_t::decode_config_set_radio(em_subdoc_info_t *subdoc, const char *key, unsigned int index, unsigned int *num)
{
    cJSON *parent_obj, *net_obj, *net_obj_id, *dev_arr_obj, *dev_obj, *dev_obj_id;
	cJSON *radio_obj, *radio_arr_obj;
    unsigned int num_devices = 0, i;
    char *dev_mac_str, *net_id;
    em_long_string_t parent;

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

    strncpy(m_network.m_net_info.id, net_id, strlen(net_id) + 1);

    if ((dev_arr_obj = cJSON_GetObjectItem(net_obj, "DeviceList")) == NULL) {
        printf("%s:%d: Failed to parse: %s\n", __func__, __LINE__, subdoc->buff);
        cJSON_Delete(parent_obj);
        return EM_PARSE_ERR_GEN;
    }

    num_devices = cJSON_GetArraySize(dev_arr_obj);
    *num = num_devices;

    // check if the index passed is within range
    if (index >= num_devices) {
        printf("%s:%d: Invalid input index: %d\n", __func__, __LINE__, index);
        cJSON_Delete(parent_obj);
        return EM_PARSE_ERR_GEN;
    }

    if ((dev_obj = cJSON_GetArrayItem(dev_arr_obj, index)) == NULL) {
        printf("%s:%d: Invalid input index: %d\n", __func__, __LINE__, index);
        cJSON_Delete(parent_obj);
        return EM_PARSE_ERR_GEN;
    }

    if ((dev_obj_id = cJSON_GetObjectItem(dev_obj, "ID")) == NULL) {
        printf("%s:%d: Failed to parse: %s\n", __func__, __LINE__, subdoc->buff);
        cJSON_Delete(parent_obj);
        return EM_PARSE_ERR_GEN;
    }

    if ((dev_mac_str = cJSON_GetStringValue(dev_obj_id)) == NULL) {
        printf("%s:%d: Dev Obj ID not present\n", __func__, __LINE__);
        cJSON_Delete(parent_obj);
        return EM_PARSE_ERR_NET_ID;
    }

    dm_easy_mesh_t::string_to_macbytes(dev_mac_str, m_device.m_device_info.intf.mac);

	if ((radio_arr_obj = cJSON_GetObjectItem(dev_obj, "RadioList")) == NULL) {
       	printf("%s:%d: Failed to parse: %s\n", __func__, __LINE__, subdoc->buff);
       	cJSON_Delete(parent_obj);
       	return EM_PARSE_ERR_GEN;
   	}

	for (i = 0; i < cJSON_GetArraySize(radio_arr_obj); i++) {
		if ((radio_obj = cJSON_GetArrayItem(radio_arr_obj, i)) == NULL) {
       		printf("%s:%d: Failed to parse: %s\n", __func__, __LINE__, subdoc->buff);
       		cJSON_Delete(parent_obj);
       		return EM_PARSE_ERR_GEN;
		}
		
		snprintf(parent, sizeof(em_long_string_t), "%s@%s", dev_mac_str, net_id);	
		m_radio[m_num_radios].decode(radio_obj, parent);
		m_num_radios++;
			
	}
    return 0;
}

int dm_easy_mesh_t::decode_config_set_policy(em_subdoc_info_t *subdoc, const char *key, unsigned int index, unsigned int *num)
{
	cJSON *parent_obj, *net_obj, *net_obj_id, *dev_arr_obj, *dev_obj, *dev_obj_id, *policy_obj; 
	cJSON *ap_metrics_obj, *scan_obj, *radio_metrics_arr_obj, *radio_steer_arr_obj, *local_steer_obj, *btm_steer_obj;
	cJSON *backhaul_obj, *radio_id_obj, *radio_metrics_obj, *radio_steer_obj;
	unsigned int num_devices = 0, i;
	char *dev_mac_str, *net_id;
	em_long_string_t parent;

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

	strncpy(m_network.m_net_info.id, net_id, strlen(net_id) + 1);

    if ((dev_arr_obj = cJSON_GetObjectItem(net_obj, "DeviceList")) == NULL) {
        printf("%s:%d: Failed to parse: %s\n", __func__, __LINE__, subdoc->buff);
        cJSON_Delete(parent_obj);
        return EM_PARSE_ERR_GEN;
    }

	num_devices = cJSON_GetArraySize(dev_arr_obj);
	*num = num_devices;

	// check if the index passed is within range
	if (index >= num_devices) {
        printf("%s:%d: Invalid input index: %d\n", __func__, __LINE__, index);
        cJSON_Delete(parent_obj);
        return EM_PARSE_ERR_GEN;
	}

	if ((dev_obj = cJSON_GetArrayItem(dev_arr_obj, index)) == NULL) {
        printf("%s:%d: Invalid input index: %d\n", __func__, __LINE__, index);
        cJSON_Delete(parent_obj);
        return EM_PARSE_ERR_GEN;
	}

	if ((dev_obj_id = cJSON_GetObjectItem(dev_obj, "ID")) == NULL) {
        printf("%s:%d: Failed to parse: %s\n", __func__, __LINE__, subdoc->buff);
        cJSON_Delete(parent_obj);
        return EM_PARSE_ERR_GEN;
    }

	if ((dev_mac_str = cJSON_GetStringValue(dev_obj_id)) == NULL) {
        printf("%s:%d: Dev Obj ID not present\n", __func__, __LINE__);
        cJSON_Delete(parent_obj);
        return EM_PARSE_ERR_NET_ID;
	}

	dm_easy_mesh_t::string_to_macbytes(dev_mac_str, m_device.m_device_info.intf.mac);

	if ((policy_obj = cJSON_GetObjectItem(dev_obj, "Policy")) == NULL) {
        printf("%s:%d: Failed to parse: %s\n", __func__, __LINE__, subdoc->buff);
        cJSON_Delete(parent_obj);
        return EM_PARSE_ERR_GEN;
    }

	if ((ap_metrics_obj = cJSON_GetObjectItem(policy_obj, "AP Metrics Reporting Policy")) != NULL) {
		snprintf(parent, sizeof(em_long_string_t), "%s@%s@00:00:00:00:00:00@%d", net_id, dev_mac_str,
					em_policy_id_type_ap_metrics_rep);
		m_policy[m_num_policy].decode(ap_metrics_obj, parent, em_policy_id_type_ap_metrics_rep);
		m_num_policy++;
    }

	if ((local_steer_obj = cJSON_GetObjectItem(policy_obj, "Local Steering Disallowed Policy")) != NULL) {
		snprintf(parent, sizeof(em_long_string_t), "%s@%s@00:00:00:00:00:00@%d", net_id, dev_mac_str,
					em_policy_id_type_steering_local);
		m_policy[m_num_policy].decode(local_steer_obj, parent, em_policy_id_type_steering_local);
		m_num_policy++;
    }

	if ((btm_steer_obj = cJSON_GetObjectItem(policy_obj, "BTM Steering Disallowed Policy")) != NULL) {
		snprintf(parent, sizeof(em_long_string_t), "%s@%s@00:00:00:00:00:00@%d", net_id, dev_mac_str,
					em_policy_id_type_steering_btm);
		m_policy[m_num_policy].decode(btm_steer_obj, parent, em_policy_id_type_steering_btm);
		m_num_policy++;
    }

	if ((backhaul_obj = cJSON_GetObjectItem(policy_obj, "Backhaul BSS Configuration Policy")) != NULL) {
		snprintf(parent, sizeof(em_long_string_t), "%s@%s@00:00:00:00:00:00@%d", net_id, dev_mac_str,
					em_policy_id_type_backhaul_bss_config);
		m_policy[m_num_policy].decode(backhaul_obj, parent, em_policy_id_type_backhaul_bss_config);
		m_num_policy++;
    }

	if ((scan_obj = cJSON_GetObjectItem(policy_obj, "Channel Scan Reporting Policy")) != NULL) {
		snprintf(parent, sizeof(em_long_string_t), "%s@%s@00:00:00:00:00:00@%d", net_id, dev_mac_str,
					em_policy_id_type_channel_scan);
		m_policy[m_num_policy].decode(scan_obj, parent, em_policy_id_type_channel_scan);
		m_num_policy++;
    }

	if ((radio_metrics_arr_obj = cJSON_GetObjectItem(policy_obj, "Radio Specific Metrics Policy")) != NULL) {
		for (i = 0; i < cJSON_GetArraySize(radio_metrics_arr_obj); i++) {
			radio_metrics_obj = cJSON_GetArrayItem(radio_metrics_arr_obj, i);
			radio_id_obj = cJSON_GetObjectItem(radio_metrics_obj, "ID");
			snprintf(parent, sizeof(em_long_string_t), "%s@%s@%s@%d", net_id, dev_mac_str, cJSON_GetStringValue(radio_id_obj),
						em_policy_id_type_radio_metrics_rep);
			m_policy[m_num_policy].decode(radio_metrics_obj, parent, em_policy_id_type_radio_metrics_rep);
			m_num_policy++;
		}
    }


	if ((radio_steer_arr_obj = cJSON_GetObjectItem(policy_obj, "Radio Steering Parameters")) != NULL) {
		for (i = 0; i < cJSON_GetArraySize(radio_steer_arr_obj); i++) {
			radio_steer_obj = cJSON_GetArrayItem(radio_steer_arr_obj, i);
			radio_id_obj = cJSON_GetObjectItem(radio_steer_obj, "ID");
			snprintf(parent, sizeof(em_long_string_t), "%s@%s@%s@%d", net_id, dev_mac_str, cJSON_GetStringValue(radio_id_obj),
						em_policy_id_type_steering_param);
			m_policy[m_num_policy].decode(radio_steer_obj, parent, em_policy_id_type_steering_param);
			m_num_policy++;
		}
    }


	return 0;
}

int dm_easy_mesh_t::decode_config_set_channel(em_subdoc_info_t *subdoc, const char *key, unsigned int index, unsigned int *num)
{
    cJSON *parent_obj, *net_obj, *net_obj_id; 
	cJSON *target_arr_obj, *target_obj, *channel_arr_obj, *channel_obj;
    unsigned int i, j, arr_size;
    char *net_id;
    int ret = 0;
    int haul_bit_mask = 0;
	em_long_string_t	target_key;	
	em_op_class_type_t	type = em_op_class_type_none;

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

	if (strncmp(key, "wfa-dataelements:SetAnticipatedChannelPreference", strlen("wfa-dataelements:SetAnticipatedChannelPreference")) == 0) {
		snprintf(target_key, sizeof(em_long_string_t), "AnticipatedChannelPreference");
		type = em_op_class_type_anticipated;
	} else if (strncmp(key, "wfa-dataelements:ChannelScanRequest", strlen("wfa-dataelements:ChannelScanRequest")) == 0) {
		snprintf(target_key, sizeof(em_long_string_t), "ChannelScanParameters");
		type = em_op_class_type_scan_param;
	}

	if ((target_arr_obj = cJSON_GetObjectItem(net_obj, target_key)) == NULL) {
		cJSON_Delete(parent_obj);
        printf("%s:%d: %s not present\n", __func__, __LINE__, target_key);
        return -1;

	}	

	m_num_opclass = 0;
	arr_size = cJSON_GetArraySize(target_arr_obj);
	for (i = 0; i < arr_size; i++) {
		if ((target_obj = cJSON_GetArrayItem(target_arr_obj, i)) == NULL) {
			cJSON_Delete(parent_obj);
        	printf("%s:%d: %s not present\n", __func__, __LINE__, target_key);
        	return -1;
    	}

		memset(&m_op_class[m_num_opclass].m_op_class_info, 0, sizeof(em_op_class_info_t));   

		m_op_class[m_num_opclass].m_op_class_info.id.type = type;
		m_op_class[m_num_opclass].m_op_class_info.op_class = cJSON_GetNumberValue(cJSON_GetObjectItem(target_obj, "Class"));
		m_op_class[m_num_opclass].m_op_class_info.id.op_class = m_op_class[m_num_opclass].m_op_class_info.op_class;

		if ((channel_arr_obj = cJSON_GetObjectItem(target_obj, "ChannelList")) == NULL) {
			cJSON_Delete(parent_obj);
        	printf("%s:%d: %s not present\n", __func__, __LINE__, target_key);
        	return -1;
		}

		m_op_class[m_num_opclass].m_op_class_info.num_channels = 0;

		for (j = 0; j < cJSON_GetArraySize(channel_arr_obj); j++) {
			m_op_class[m_num_opclass].m_op_class_info.channels[m_op_class[m_num_opclass].m_op_class_info.num_channels] = cJSON_GetNumberValue(cJSON_GetArrayItem(channel_arr_obj, j));
			m_op_class[m_num_opclass].m_op_class_info.num_channels++;
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
                m_op_class[i].m_op_class_info.id.type, m_op_class[i].m_op_class_info.id.op_class);
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
		snprintf(parent_key, sizeof(parent_key), "%s@%s", m_device.m_device_info.id.net_id, mac_str);

        m_radio[i].decode(radio_obj, parent_key);

        if ((op_arr_objs = cJSON_GetObjectItem(radio_obj, "CurrentOperatingClasses")) == NULL) {
            cJSON_Delete(parent_obj);
            printf("%s:%d: CurrentOperatingClasses not present\n", __func__, __LINE__);
            return -1;
        }

        if (decode_config_op_class_array(op_arr_objs, em_op_class_type_current, m_radio[i].m_radio_info.intf.mac) != 0) {
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

		if (decode_config_op_class_array(op_arr_objs, em_op_class_type_capability, m_radio[i].m_radio_info.intf.mac) != 0) {
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
			dm_easy_mesh_t::macbytes_to_string(m_radio[i].m_radio_info.intf.mac, mac_str);
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
		
	if (decode_config_op_class_array(op_arr_objs, em_op_class_type_cac_available, m_device.m_device_info.intf.mac) != 0) {
        cJSON_Delete(parent_obj);
        printf("%s:%d: AvailableChannelList decode failed\n", __func__, __LINE__);
        return -1;
	}
        
	if ((op_arr_objs = cJSON_GetObjectItem(cac_status_obj, "NonOccupancyChannelList")) == NULL) {
        cJSON_Delete(parent_obj);
        printf("%s:%d: NonOccupancyChannelList not present\n", __func__, __LINE__);
        return -1;
	}	

	if (decode_config_op_class_array(op_arr_objs, em_op_class_type_cac_non_occ, m_device.m_device_info.intf.mac) != 0) {
        cJSON_Delete(parent_obj);
        printf("%s:%d: NonOccupancyChannelList decode failed\n", __func__, __LINE__);
        return -1;
	}
        
	if ((op_arr_objs = cJSON_GetObjectItem(cac_status_obj, "ActiveChannelList")) == NULL) {
        cJSON_Delete(parent_obj);
        printf("%s:%d: ActiveChannelList not present\n", __func__, __LINE__);
        return -1;
	}	

	if (decode_config_op_class_array(op_arr_objs, em_op_class_type_cac_active, m_device.m_device_info.intf.mac) != 0) {
        cJSON_Delete(parent_obj);
        printf("%s:%d: ActiveChannelList decode failed\n", __func__, __LINE__);
        return -1;
	}

    cJSON_Delete(parent_obj);
    //printf("%s:%d: End\n", __func__, __LINE__);
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


char *dm_easy_mesh_t::hex(unsigned int in_len, unsigned char *in, unsigned int out_len, char *out)
{
    unsigned int i;
    unsigned char tmp;

    if (out_len < 2*in_len + 1) {
        return NULL;
    }

    memset(out, 0, out_len);

    for (i = 0; i < in_len; i++) {
        tmp = in[i] >> 4;
        if (tmp < 0xa) {
            out[2*i] = tmp + 0x30;
        } else {
            out[2*i] = tmp - 0xa + 0x61;
        }

        tmp = in[i] & 0xf;
        if (tmp < 0xa) {
            out[2*i + 1] = tmp + 0x30;
        } else {
            out[2*i + 1] = tmp - 0xa + 0x61;
        }
    }

    return out;
}

unsigned char *dm_easy_mesh_t::unhex(unsigned int in_len, char *in, unsigned int out_len, unsigned char *out)
{
    unsigned int i;
    unsigned char tmp1, tmp2;

    if (out_len < in_len/2) {
        return NULL;
    }

    for (i = 0; i < in_len/2; i++) {
        if (in[2*i] <= '9') {
            tmp1 = (unsigned char)in[2*i] - 0x30;
        } else {
            tmp1 = (unsigned char)in[2*i] - 0x61 + 0xa;
        }

        tmp1 = tmp1 << 4;

        if (in[2*i + 1] <= '9') {
            tmp2 = (unsigned char)in[2*i + 1] - 0x30;
        } else {
            tmp2 = (unsigned char)in[2*i + 1] - 0x61 + 0xa;
        }

        tmp2 &= 0xf;

        out[i] = tmp1 | tmp2;
    }

    return out;
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
    else if (mode == EM_AUTH_SAE_AKM8)
        snprintf(sec_mode_str, len, "%s", "WPA-WPA3-Personal_AKM8"); //TODO Need to check what SAE_AKM8
    else if (mode == EM_AUTH_DPP_AKM)
        snprintf(sec_mode_str, len, "%s", "WPA-WPA3-Personal_DPP"); //TODO Need to check what DPP
    else if (mode == EM_AUTH_SAE_AKM24)
        snprintf(sec_mode_str, len, "%s", "WPA-WPA3-Personal_AKM24"); //TODO Need to check what SAE_AKM24
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
    else if (strncmp(sec_mode_str,"WPA-WPA3-Personal",len) == 0) 
        *mode = EM_AUTH_SAE_AKM8;
    else if (strncmp(sec_mode_str,"WPA-WPA3-Personal_DPP",len) == 0) 
        *mode = EM_AUTH_DPP_AKM;
    else if (strncmp(sec_mode_str,"WPA-WPA3-Personal_AKM24",len) == 0) 
        *mode = EM_AUTH_SAE_AKM24;
}

em_interface_t *dm_easy_mesh_t::get_prioritized_interface(const char *platform)
{
	bool swap = false;
	em_interface_t intf;
	unsigned int i;
	bool found_match = false;

	for (i = 0; i < m_num_preferences; i++) {
		if (strncmp(platform, m_preference[i].platform, strlen(platform)) == 0) {
			found_match = true;
			break;
		}
	}	

	if (found_match == false) {
		return NULL;
	}

	found_match = false;

	if (m_preference[i].media == em_media_type_ieee8023ab) {
		for (i = 0; i < m_num_interfaces; i++) {
			if ((strstr(m_interfaces[i].name, "eth") != NULL) || (strstr(m_interfaces[i].name, "ens") != NULL) || (strstr(m_interfaces[i].name, "erouter") != NULL)) {
				found_match = true;
				break;
			}
		}
	} else if (m_preference[i].media == em_media_type_ieee80211b_24) {
		for (i = 0; i < m_num_interfaces; i++) {
			if (strstr(m_interfaces[i].name, "wlan") != NULL) {
				found_match = true;
				break;
			}
		}

	}

	if (found_match == false) {
		return NULL;
	}

	return &m_interfaces[i];	
}

int dm_easy_mesh_t::get_interfaces_list(em_interface_t interfaces[], unsigned int *num_interfaces)
{
    struct ifaddrs *ifaddr = NULL, *tmp = NULL;
    struct sockaddr *addr;
	struct sockaddr_ll *ll_addr;	
	unsigned int num = 0;
	mac_address_t null_mac = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    if (getifaddrs(&ifaddr) != 0) {
        printf("%s:%d: Failed to get interfae information\n", __func__, __LINE__);
        return -1;
    }

    tmp = ifaddr;
    while (tmp != NULL) {
        addr = tmp->ifa_addr;
		ll_addr = (struct sockaddr_ll*)tmp->ifa_addr;
        if ((addr != NULL) && (addr->sa_family == AF_PACKET) && 
				(strncmp(tmp->ifa_name, "lo", strlen("lo")) != 0) && (strncmp(tmp->ifa_name, "brlan", strlen("brlan")) != 0) &&
				(memcmp(ll_addr->sll_addr, null_mac, sizeof(mac_address_t)) != 0)) {
            strncpy(interfaces[num].name, tmp->ifa_name, strlen(tmp->ifa_name) + 1);
			if (strstr(tmp->ifa_name, "eth") != NULL) {
				interfaces[num].media = em_media_type_ieee8023ab;
			} else if (strstr(tmp->ifa_name, "erouter") != NULL) {
                                interfaces[num].media = em_media_type_ieee8023ab;	
			} else if (strstr(tmp->ifa_name, "ens") != NULL) {
				interfaces[num].media = em_media_type_ieee8023ab;
			} else if (strstr(tmp->ifa_name, "wlan") != NULL) {
				interfaces[num].media = em_media_type_ieee80211b_24;
			}
			memcpy(interfaces[num].mac, ll_addr->sll_addr, sizeof(mac_address_t));	
			num++;
			if (num >= *num_interfaces) {
				break;
			}
        }

        tmp = tmp->ifa_next;
    }

    freeifaddrs(ifaddr);

	*num_interfaces = num;

    return 0;
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

	if ( m_wifi_data == NULL )
        {
              printf("%s:%d: m_wifi_data is not initialized \n",__func__,__LINE__);
              return NULL;
        }

	for (i = 0; i < m_wifi_data->u.decoded.num_radios; i++) {
		radio = &m_wifi_data->u.decoded.radios[i];

		if (strncmp(radio->name, interface->name, strlen(radio->name)) == 0) {
			return radio;
		}
			
	}

	return NULL;
}

dm_radio_t *dm_easy_mesh_t::get_radio(unsigned int index)
{
	if (index < EM_MAX_BANDS) {
		return &m_radio[index];
	} else {
		return NULL;
	}
}

dm_radio_t *dm_easy_mesh_t::get_radio(mac_address_t mac)
{
    int i = 0;
    for (i = 0; i < m_num_radios; i++) {
        if (memcmp(m_radio[i].m_radio_info.intf.mac, mac, sizeof(mac_address_t)) == 0) {
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
        if (memcmp(m_radio[i].m_radio_info.intf.mac, radio->m_radio_info.intf.mac, sizeof(mac_address_t)) == 0) {
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

    if (memcmp(m_device.m_device_info.intf.mac, dev->m_device_info.intf.mac, sizeof(mac_address_t)) == 0) {
        return &m_device;
    }

    return NULL;
}

void dm_easy_mesh_t::print_config()
{
    unsigned int i;
    mac_addr_str_t  ctrl_mac, ctrl_al_mac, agent_al_mac, radio_mac, mac_str;
    int transmit_power_limit;

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
        //printf("%s:%d: OpClass[%d] id.ruid: %s id.type: %d id.index: %d Channel : %d Op_class : %d num_channel : %d Max tx_p : %d\n\n", 
		//		__func__, __LINE__, i, radio_mac, m_op_class[i].m_op_class_info.id.type, 
		//		m_op_class[i].m_op_class_info.id.op_class, m_op_class[i].m_op_class_info.channel, 
		//		m_op_class[i].m_op_class_info.op_class, m_op_class[i].m_op_class_info.num_channels, m_op_class[i].m_op_class_info.max_tx_power);
    }

    printf("%s:%d:No of BSS=%d No of Radios=%d \n", __func__, __LINE__, m_num_bss, m_num_radios);
    for (i = 0; i < m_num_bss; i++) {
        dm_easy_mesh_t::macbytes_to_string(get_bss(i)->get_bss_info()->ruid.mac, mac_str);
        printf("%s:%d:Radio Mac : %s ", __func__, __LINE__, mac_str);
        dm_easy_mesh_t::macbytes_to_string(get_bss(i)->get_bss_info()->bssid.mac, mac_str);
        printf("BSSID : %s\n", mac_str);
    }

    for (i = 0;i < m_num_radios; i++) {
        dm_easy_mesh_t::macbytes_to_string(m_radio[i].get_radio_info()->intf.mac, mac_str);
        transmit_power_limit = m_radio[i].get_radio_info()->transmit_power_limit;
        printf("%s:%d:Radio Mac: %s \n", __func__, __LINE__, mac_str);
        printf("%s:%d:Radio Band: %d \n", __func__, __LINE__, m_radio[i].get_radio_info()->band);
        printf("%s:%d:TransmitPowerLimit: %d \n", __func__, __LINE__, transmit_power_limit);
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

em_e4_table_t dm_easy_mesh_t::m_e4_table[] = {
	{ 81, em_freq_band_24, 25, 11, {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11} },
	{ 83, em_freq_band_24, 40, 9, {1, 2, 3, 4, 5, 6, 7, 8, 9} },
	{ 84, em_freq_band_24, 40, 7, {5, 6, 7, 8, 9, 10, 11} },
	{ 115, em_freq_band_5, 20, 4, {36, 40, 44, 48} },
	{ 116, em_freq_band_5, 40, 2, {36, 44} },
	{ 117, em_freq_band_5, 40, 2, {40, 48} },
	{ 118, em_freq_band_5, 20, 4, {52, 56, 60, 64} }
};

// Function to get frequency band by operating class
em_freq_band_t  dm_easy_mesh_t::get_freq_band_by_op_class(int op_class)
{
	int i = 0;
	for (i = 0; i < sizeof(m_e4_table) / sizeof(m_e4_table[0]); ++i) {
		if (m_e4_table[i].op_class == op_class) {
			return m_e4_table[i].band;
		}
	}
    
	return em_freq_band_unknown; // Return invalid if op_class not found
}

em_bss_info_t *dm_easy_mesh_t::get_bss_info_with_mac(mac_address_t mac)
{
	unsigned int i = 0;

	for (i = 0; i < m_num_bss; i++) {
		if (memcmp(m_bss[i].m_bss_info.bssid.mac, mac, sizeof(mac_address_t)) == 0) {
			return &m_bss[i].m_bss_info;
		}
	}
	return NULL;
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

dm_bss_t *dm_easy_mesh_t::get_bss(mac_address_t radio_mac, mac_address_t bss_mac)
{
    unsigned int i;
    dm_bss_t *bss;

    for (i = 0; i < m_num_bss; i++) {
        bss = &m_bss[i];
        if ((memcmp(bss->m_bss_info.bssid.mac, bss_mac, sizeof(mac_address_t)) == 0) &&
                (memcmp(bss->m_bss_info.ruid.mac, radio_mac, sizeof(mac_address_t)) == 0)) {
			return &m_bss[i];
        }
    }

    return NULL;
}

em_sta_info_t *dm_easy_mesh_t::get_first_sta_info(em_target_sta_map_t target)
{
    hash_map_t *map;
    dm_sta_t *sta = NULL;
    const char  *map_str;
    bool match_found = false;

    if (target == em_target_sta_map_assoc) {
        map = m_sta_assoc_map;
        map_str = "Assoc Map";
    } else if (target == em_target_sta_map_disassoc) {
        map = m_sta_dassoc_map;
        map_str = "Disssoc Map";
    } else {
        map = m_sta_map;
        map_str = "Consolidated Map";
    }

    sta = (dm_sta_t *)hash_map_get_first(map);
    if (sta == NULL) {
        return NULL;
    }

    return &sta->m_sta_info;
}

em_sta_info_t *dm_easy_mesh_t::get_next_sta_info(em_sta_info_t *info, em_target_sta_map_t target)
{
    hash_map_t *map;
    dm_sta_t *sta = NULL;
    const char  *map_str;
    bool match_found = false;

    if (target == em_target_sta_map_assoc) {
        map = m_sta_assoc_map;
        map_str = "Assoc Map";
    } else if (target == em_target_sta_map_disassoc) {
        map = m_sta_dassoc_map;
        map_str = "Disssoc Map";
    } else {
        map = m_sta_map;
        map_str = "Consolidated Map";
    }

    sta = (dm_sta_t *)hash_map_get_first(map);
    while ((sta != NULL) && (match_found == false)) {
        if (&sta->m_sta_info == info) {
            match_found = true;
        }

        sta = (dm_sta_t *)hash_map_get_next(map, sta);
    }

    if (match_found == false) {
        return NULL;
    }

    if (sta == NULL) {
        return NULL;
    }

    return &sta->m_sta_info;
}

bool dm_easy_mesh_t::has_at_least_one_associated_sta()
{
    dm_sta_t *sta;

    sta = (dm_sta_t *)hash_map_get_first(m_sta_map);
    while (sta != NULL) {
        if (sta->m_sta_info.associated == true) {
            return true;
        }
        sta = (dm_sta_t *)hash_map_get_next(m_sta_map, sta);
    }

    return false;
}

dm_sta_t *dm_easy_mesh_t::find_sta(mac_address_t sta_mac, bssid_t bssid)
{
    dm_sta_t *sta;

    sta = (dm_sta_t *)hash_map_get_first(m_sta_map);
    while (sta != NULL) {
        if ((memcmp(sta->m_sta_info.id, sta_mac, sizeof(mac_address_t)) == 0) &&
                        (memcmp(sta->m_sta_info.bssid, bssid, sizeof(mac_address_t)) == 0)) {
            return sta;
        }
        sta = (dm_sta_t *)hash_map_get_next(m_sta_map, sta);
    }

    return NULL;
}

dm_sta_t *dm_easy_mesh_t::get_first_sta(mac_address_t sta_mac)
{
    dm_sta_t *sta;

    sta = (dm_sta_t *)hash_map_get_first(m_sta_map);
    while (sta != NULL) {
        if (memcmp(sta->m_sta_info.id, sta_mac, sizeof(mac_address_t)) == 0) {
            return sta;
        }
        sta = (dm_sta_t *)hash_map_get_next(m_sta_map, sta);
    }

    return NULL;
}

dm_sta_t *dm_easy_mesh_t::get_next_sta(mac_address_t sta_mac, dm_sta_t *psta)
{
    dm_sta_t *sta;
    bool return_next = false;

    sta = (dm_sta_t *)hash_map_get_first(m_sta_map);
    while (sta != NULL) {
        if ((return_next == true) && (memcmp(sta->m_sta_info.id, sta_mac, sizeof(mac_address_t)) == 0)) {
            return sta;
        }
        if (sta == psta) {
            return_next = true;
        }
        sta = (dm_sta_t *)hash_map_get_next(m_sta_map, sta);
    }

    return NULL;
}

em_sta_info_t *dm_easy_mesh_t::get_sta_info(mac_address_t sta_mac, bssid_t bssid, mac_address_t ruid, em_target_sta_map_t target)
{
    hash_map_t *map;
    dm_sta_t *sta = NULL;
    const char	*map_str;
    mac_addr_str_t radio_str, bss_str, sta_str;
    em_long_string_t key;

    if (target == em_target_sta_map_assoc) {
        map = m_sta_assoc_map;
        map_str = "Assoc Map";
    } else if (target == em_target_sta_map_disassoc) {
        map = m_sta_dassoc_map;
        map_str = "Disssoc Map";
    } else {
        map = m_sta_map;
        map_str = "Consolidated Map";
    }

    dm_easy_mesh_t::macbytes_to_string(sta_mac, sta_str);
    dm_easy_mesh_t::macbytes_to_string(bssid, bss_str);
    dm_easy_mesh_t::macbytes_to_string(ruid, radio_str);

    snprintf(key, sizeof(em_long_string_t), "%s@%s@%s", sta_str, bss_str, radio_str);
    printf("\n%s:%d: key=%s\n", __func__, __LINE__,key);
    sta = (dm_sta_t *)hash_map_get(map, key);
    if (sta == NULL) {
        printf("%s:%d: sta: %s not found in %s\n", __func__, __LINE__, sta_str, map_str);
        return NULL;
    }

    return &sta->m_sta_info;
}

void dm_easy_mesh_t::put_sta_info(em_sta_info_t *sta_info, em_target_sta_map_t target)
{
    hash_map_t *map;
    dm_sta_t *sta;
    const char	*map_str;
    mac_addr_str_t radio_str, bss_str, sta_str;
    em_long_string_t key;

    if (target == em_target_sta_map_assoc) {
        map = m_sta_assoc_map;
        map_str = "Assoc Map";
    } else if (target == em_target_sta_map_disassoc) {
        map = m_sta_dassoc_map;
        map_str = "Disssoc Map";
    } else {
        map = m_sta_map;
        map_str = "Consolidated Map";
    }

    dm_easy_mesh_t::macbytes_to_string(sta_info->id, sta_str);
    if (get_sta_info(sta_info->id, sta_info->bssid, sta_info->radiomac, target) != NULL) {
        printf("%s:%d: sta: %s already exists in %s\n", __func__, __LINE__, sta_str, map_str);
        return;
    }

    dm_easy_mesh_t::macbytes_to_string(sta_info->bssid, bss_str);
    dm_easy_mesh_t::macbytes_to_string(sta_info->radiomac, radio_str);

    snprintf(key, sizeof(em_long_string_t), "%s@%s@%s", sta_str, bss_str, radio_str);
    printf("\n%s:%d: key=%s\n", __func__, __LINE__,key);

    hash_map_put(map, strdup(key), new dm_sta_t(sta_info));
}

int dm_easy_mesh_t::get_num_bss_for_associated_sta(mac_address_t sta_mac)
{
    dm_sta_t *sta;
    unsigned int num_bssids = 0;

    sta = (dm_sta_t *)hash_map_get_first(m_sta_map);
    while (sta != NULL) {
        if (memcmp(sta->m_sta_info.id, sta_mac, sizeof(mac_address_t)) == 0) {
            num_bssids++;
        }
        sta = (dm_sta_t *)hash_map_get_next(m_sta_map, sta);
    }

    return num_bssids;
}

void dm_easy_mesh_t::clone_hash_maps(dm_easy_mesh_t& obj)
{
    mac_addr_str_t  sta_mac_str, bss_mac_str, radio_mac_str;
    dm_sta_t *sta;
    em_long_string_t key;

    sta = (dm_sta_t *)hash_map_get_first(m_sta_map);
    while (sta != NULL) {
        macbytes_to_string(sta->m_sta_info.id, sta_mac_str);
        macbytes_to_string(sta->m_sta_info.bssid, bss_mac_str);
        macbytes_to_string(sta->m_sta_info.radiomac, radio_mac_str);
        snprintf(key, sizeof(em_long_string_t), "%s@%s@%s", sta_mac_str, bss_mac_str, radio_mac_str);
        hash_map_put(obj.m_sta_map, strdup(key),sta);
        sta = (dm_sta_t *)hash_map_get_next(m_sta_map, sta);
    }

    sta = (dm_sta_t *)hash_map_get_first(m_sta_assoc_map);
    while (sta != NULL) {
        macbytes_to_string(sta->m_sta_info.id, sta_mac_str);
        macbytes_to_string(sta->m_sta_info.bssid, bss_mac_str);
        macbytes_to_string(sta->m_sta_info.radiomac, radio_mac_str);
        snprintf(key, sizeof(em_long_string_t), "%s@%s@%s", sta_mac_str, bss_mac_str, radio_mac_str);
        hash_map_put(obj.m_sta_assoc_map, strdup(key),sta);
        sta = (dm_sta_t *)hash_map_get_next(m_sta_assoc_map, sta);
    }

    sta = (dm_sta_t *)hash_map_get_first(m_sta_dassoc_map);
    while (sta != NULL) {
        macbytes_to_string(sta->m_sta_info.id, sta_mac_str);
        macbytes_to_string(sta->m_sta_info.bssid, bss_mac_str);
        macbytes_to_string(sta->m_sta_info.radiomac, radio_mac_str);
        snprintf(key, sizeof(em_long_string_t), "%s@%s@%s", sta_mac_str, bss_mac_str, radio_mac_str);
        hash_map_put(obj.m_sta_dassoc_map, strdup(key),sta);
        sta = (dm_sta_t *)hash_map_get_next(m_sta_dassoc_map, sta);
    }
}

void dm_easy_mesh_t::deinit()
{
    dm_sta_t *sta = NULL;
    dm_sta_t *tmp_sta = NULL;
	dm_scan_result_t	*res = NULL;
	dm_scan_result_t	*tmp_res = NULL;
    em_long_string_t key;
    mac_addr_str_t dev_mac_str, radio_mac_str, bss_mac_str, sta_mac_str, scanner_mac_str;

    //destroy elements of m_scan_result_map
	res = (dm_scan_result_t *)hash_map_get_first(m_scan_result_map);
	while (res != NULL) {
		tmp_res = res;
        res = (dm_scan_result_t *)hash_map_get_next(m_scan_result_map, res);
	
		dm_easy_mesh_t::macbytes_to_string(tmp_res->m_scan_result.id.dev_mac, dev_mac_str);
		dm_easy_mesh_t::macbytes_to_string(tmp_res->m_scan_result.id.scanner_mac, scanner_mac_str);

		snprintf(key, sizeof(em_long_string_t), "%s@%s@%s@%d@%d@%d", res->m_scan_result.id.net_id, dev_mac_str, scanner_mac_str, 
					tmp_res->m_scan_result.id.op_class, tmp_res->m_scan_result.id.channel, tmp_res->m_scan_result.id.scanner_type);
		hash_map_remove(m_scan_result_map, key);
	}

	hash_map_destroy(m_scan_result_map);	

    //destroy elements of m_sta_map
    sta = (dm_sta_t *)hash_map_get_first(m_sta_map);
    while (sta != NULL) {
        tmp_sta = sta;
        sta = (dm_sta_t *)hash_map_get_next(m_sta_map, sta);

        dm_easy_mesh_t::macbytes_to_string(tmp_sta->m_sta_info.id, sta_mac_str);
        dm_easy_mesh_t::macbytes_to_string(tmp_sta->m_sta_info.bssid, bss_mac_str);
        dm_easy_mesh_t::macbytes_to_string(tmp_sta->m_sta_info.radiomac, radio_mac_str);
        snprintf(key, sizeof(em_long_string_t), "%s@%s@%s", sta_mac_str, bss_mac_str, radio_mac_str);

        hash_map_remove(m_sta_map, key);
    }
    hash_map_destroy(m_sta_map);
    sta = NULL;

    sta = (dm_sta_t *)hash_map_get_first(m_sta_assoc_map);
    while (sta != NULL)
    {
        tmp_sta = sta;
        sta = (dm_sta_t *)hash_map_get_next(m_sta_assoc_map, sta);
        dm_easy_mesh_t::macbytes_to_string(tmp_sta->m_sta_info.id, sta_mac_str);
        dm_easy_mesh_t::macbytes_to_string(tmp_sta->m_sta_info.bssid, bss_mac_str);
        dm_easy_mesh_t::macbytes_to_string(tmp_sta->m_sta_info.radiomac, radio_mac_str);
        snprintf(key, sizeof(em_long_string_t), "%s@%s@%s", sta_mac_str, bss_mac_str, radio_mac_str);

        hash_map_remove(m_sta_assoc_map, key);
    }
	hash_map_destroy(m_sta_assoc_map);
    sta = NULL;

    sta = (dm_sta_t *)hash_map_get_first(m_sta_dassoc_map);
    while (sta != NULL)
    {
        tmp_sta = sta;
        sta = (dm_sta_t *)hash_map_get_next(m_sta_dassoc_map, sta);

        dm_easy_mesh_t::macbytes_to_string(tmp_sta->m_sta_info.id, sta_mac_str);
        dm_easy_mesh_t::macbytes_to_string(tmp_sta->m_sta_info.bssid, bss_mac_str);
        dm_easy_mesh_t::macbytes_to_string(tmp_sta->m_sta_info.radiomac, radio_mac_str);
        snprintf(key, sizeof(em_long_string_t), "%s@%s@%s", sta_mac_str, bss_mac_str, radio_mac_str);

        hash_map_remove(m_sta_dassoc_map, key);
    }
	hash_map_destroy(m_sta_dassoc_map);
	if (m_wifi_data != NULL)
		free(m_wifi_data);

}

void dm_easy_mesh_t::set_policy(dm_policy_t policy)
{
	unsigned int i = 0;
	dm_policy_t *ppolicy;
	bool found_match = false;

	for (i = 0; i < m_num_policy; i++) {
		ppolicy = &m_policy[i];
		if ((strncmp(policy.m_policy.id.net_id, ppolicy->m_policy.id.net_id, strlen(policy.m_policy.id.net_id) == 0)) &&
				(memcmp(policy.m_policy.id.dev_mac, ppolicy->m_policy.id.dev_mac, sizeof(mac_address_t)) == 0) &&
				(memcmp(policy.m_policy.id.radio_mac, ppolicy->m_policy.id.radio_mac, sizeof(mac_address_t)) == 0) && 
				(policy.m_policy.id.type == ppolicy->m_policy.id.type)) {
			found_match = true;
			break;
		}
	}	

	memcpy(&m_policy[i].m_policy, &policy.m_policy, sizeof(em_policy_t));
	memcpy(m_policy[i].m_policy.id.dev_mac, m_device.m_device_info.intf.mac, sizeof(mac_address_t));
	if (found_match == false) {
		m_num_policy++;
	}	
}

void dm_easy_mesh_t::set_channels_list(dm_op_class_t op_class[], unsigned int num)
{
	unsigned int i, j;
	bool match_found = false;
	dm_op_class_t *oclass, *poclass;
	mac_address_t null_mac = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

	for (i = 0; i < num; i++) {
		oclass = &op_class[i];
		// first check if the op class types have the right ruid
		if (((oclass->m_op_class_info.id.type == em_op_class_type_anticipated) || 
				((oclass->m_op_class_info.id.type == em_op_class_type_scan_param))) && 
				(memcmp(oclass->m_op_class_info.id.ruid, null_mac, sizeof(mac_address_t)) == 0)) {
			memcpy(oclass->m_op_class_info.id.ruid, m_device.m_device_info.intf.mac, sizeof(mac_address_t));
		}

		for (j = 0; j < m_num_opclass; j++) {
			poclass = &m_op_class[j];

			if ((memcmp(oclass->m_op_class_info.id.ruid, poclass->m_op_class_info.id.ruid, sizeof(mac_address_t)) == 0) &&
					(oclass->m_op_class_info.id.type == poclass->m_op_class_info.id.type) &&
					(oclass->m_op_class_info.id.op_class == poclass->m_op_class_info.id.op_class)) {
				match_found = true;
				break;
			}
		}

		if (match_found == true) {
			match_found = false;
		} else {
			poclass = &m_op_class[m_num_opclass];
			m_num_opclass++;
		}
			
		memcpy(&poclass->m_op_class_info, &oclass->m_op_class_info, sizeof(em_op_class_info_t));
	}
}

void dm_easy_mesh_t::print_op_class_list(dm_easy_mesh_t *dm)
{
	unsigned int i;
	mac_addr_str_t mac_str;

	printf("\n\n");
	for (i = 0; i < dm->m_num_opclass; i++) {
		dm_easy_mesh_t::macbytes_to_string(dm->m_op_class[i].m_op_class_info.id.ruid, mac_str);	
		printf("%s:%d: Index: %d\tMAC: %s\tType: %d\tOp Class:%d\tClass: %d\tChannel:%d\n", __func__, __LINE__, i, mac_str, 
						dm->m_op_class[i].m_op_class_info.id.type, dm->m_op_class[i].m_op_class_info.id.op_class,
						dm->m_op_class[i].m_op_class_info.op_class, dm->m_op_class[i].m_op_class_info.channels[0]);

	}
	printf("\n\n");
}

void dm_easy_mesh_t::remove_bss_by_index(unsigned int index)
{
	unsigned int i;
    
    if (index >= m_num_bss) {
        printf("%s:%d: Invalid Index: %d\n", __func__, __LINE__, index);
        return;
    }
    
    for (i = index; i < m_num_bss - 1; i++) {
		m_bss[i] = m_bss[i + 1];
    }
    
    m_num_bss--;
}

dm_bss_t *dm_easy_mesh_t::find_matching_bss(em_bss_id_t *id)
{
	unsigned int i;
	dm_bss_t *bss;

	for (i = 0; i < m_num_bss; i++) {
		bss = &m_bss[i];

		if ((strncmp(bss->m_bss_info.id.net_id, id->net_id, strlen(id->net_id)) == 0) &&
				(memcmp(bss->m_bss_info.id.dev_mac, id->dev_mac, sizeof(mac_address_t)) == 0) &&
				(memcmp(bss->m_bss_info.id.ruid, id->ruid, sizeof(mac_address_t)) == 0) &&
			    (memcmp(bss->m_bss_info.id.bssid, id->bssid, sizeof(mac_address_t)) == 0) &&
                (memcmp(&(bss->m_bss_info.id.haul_type), &(id->haul_type), sizeof(em_haul_type_t)) == 0)) {
            return bss;
		}
	}	

	return NULL;
}

dm_scan_result_t *dm_easy_mesh_t::create_new_scan_result(em_scan_result_id_t *id)
{
	dm_scan_result_t *res, scan_result;
	em_long_string_t key;
	mac_addr_str_t  dev_mac_str, scanner_mac_str;

	memcpy(&scan_result.m_scan_result.id, id, sizeof(em_scan_result_id_t));

	res = new dm_scan_result_t(scan_result);

    dm_easy_mesh_t::macbytes_to_string(id->dev_mac, dev_mac_str);
    dm_easy_mesh_t::macbytes_to_string(id->scanner_mac, scanner_mac_str);

	snprintf(key, sizeof(em_long_string_t), "%s@%s@%s@%d@%d@%d", res->m_scan_result.id.net_id, dev_mac_str, scanner_mac_str,
                    res->m_scan_result.id.op_class, res->m_scan_result.id.channel, res->m_scan_result.id.scanner_type);

	hash_map_put(m_scan_result_map, strdup(key), res);

	return res;
}

dm_scan_result_t *dm_easy_mesh_t::get_scan_result(unsigned int index)
{
	dm_scan_result_t *res;
	unsigned int i = 0;

	res = (dm_scan_result_t *)hash_map_get_first(m_scan_result_map);
	while (res != NULL) {
		if (i == index) {
			return res;
		}
		i++;
		res = (dm_scan_result_t *)hash_map_get_next(m_scan_result_map, res);
	}

	return NULL;
}

dm_scan_result_t *dm_easy_mesh_t::find_matching_scan_result(em_scan_result_id_t *id)
{
    int index;
    unsigned int i;
    dm_scan_result_t *res;

	res = (dm_scan_result_t *)hash_map_get_first(m_scan_result_map);
	while (res != NULL) {
        if ((strncmp(res->m_scan_result.id.net_id, id->net_id, strlen(id->net_id)) == 0) &&
                (memcmp(res->m_scan_result.id.dev_mac, id->dev_mac, sizeof(mac_address_t)) == 0) &&
                (memcmp(res->m_scan_result.id.scanner_mac, id->scanner_mac, sizeof(mac_address_t)) == 0) &&
                (res->m_scan_result.id.op_class == id->op_class) &&
                (res->m_scan_result.id.channel == id->channel) &&
                (res->m_scan_result.id.scanner_type == id->scanner_type)) {
            return res;
        }

		res = (dm_scan_result_t *)hash_map_get_next(m_scan_result_map, res);
	}    

    return NULL;
}

void dm_easy_mesh_t::update_scan_results(em_scan_result_t *scan_result)
{
    const char *netid = "OneWifiMesh";
    mac_addr_str_t mac_str, radio_str;

    em_scan_result_id_t *id = &scan_result->id;

    strncpy(id->net_id, netid, strlen(netid) + 1);
	memcpy(id->dev_mac, get_agent_al_interface_mac(), sizeof(mac_address_t));
	memcpy(id->scanner_mac, get_radio_by_ref(0).get_radio_interface_mac(), sizeof(mac_address_t));
    id->scanner_type = em_scanner_type_radio;

    dm_scan_result_t *res = find_matching_scan_result(id);

    if (res) {
        *res->get_scan_result() = *scan_result;
    } else {
        printf("%s:%d creating new scan result\n", __func__, __LINE__);
        res = create_new_scan_result(id);
        *res->get_scan_result() = *scan_result;
    }
}

void dm_easy_mesh_t::reset_db_cfg_type(db_cfg_type_t type) 
{
    unsigned int num = type;
    unsigned int index = 0;

    while (num % 2 == 0) {
        num /= 2;
        index++;
    }

    if (num != 1) {
        return;
    }
    strncpy(m_db_cfg_param.db_cfg_criteria[num], "", strlen(""));
    m_db_cfg_param.db_cfg_type &= ~type; 
}   

void dm_easy_mesh_t::set_db_cfg_param(db_cfg_type_t cfg_type, char *criteria)
{
	unsigned int num = cfg_type;
	unsigned int index = 0;

	while (num % 2 == 0) {
		num /= 2;
		index++;
	}

	if (num != 1) {
		return;
	}

	m_db_cfg_param.db_cfg_type |= cfg_type;
	strncpy(m_db_cfg_param.db_cfg_criteria[index], criteria, strlen(criteria));
}

char *dm_easy_mesh_t::db_cfg_type_get_criteria(db_cfg_type_t cfg_type)
{
	unsigned int num = 0;
	unsigned int type = (unsigned int)cfg_type;

	while (type != 1) {
		type = type >> 1;
		num++;
	}

	return m_db_cfg_param.db_cfg_criteria[num];
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

    m_scan_result_map = hash_map_create();
    m_sta_map = hash_map_create();
    m_sta_assoc_map = hash_map_create();
    m_sta_dassoc_map = hash_map_create();
    m_wifi_data = (webconfig_subdoc_data_t*)malloc(sizeof(webconfig_subdoc_data_t));
	memset(&m_db_cfg_param, 0, sizeof(em_db_cfg_param_t));
    return 0;
}

void dm_easy_mesh_t::reset()
{
	m_num_preferences = 0;
	m_num_interfaces = 0;
    m_num_radios = 0;
	m_num_opclass = 0;
	m_num_policy = 0;
	m_num_bss = 0;
    m_num_ap_mld = 0;
	m_db_cfg_param.db_cfg_type = db_cfg_type_none;
    m_colocated = false;

	memset(&m_network.m_net_info, 0, sizeof(em_network_info_t));
	memset(&m_device.m_device_info, 0, sizeof(em_device_info_t));
	memset(&m_db_cfg_param, 0, sizeof(em_db_cfg_param_t));
}

dm_easy_mesh_t::dm_easy_mesh_t(const dm_network_t& net)
{
    memcpy(&m_device.m_device_info.id, &net.m_net_info.ctrl_id, sizeof(em_interface_t));
    memcpy(&m_device.m_device_info.backhaul_alid, &net.m_net_info.ctrl_id, sizeof(em_interface_t));
    memcpy(&m_device.m_device_info.backhaul_mac, &net.m_net_info.ctrl_id, sizeof(em_interface_t));

    name_from_mac_address(&m_device.m_device_info.intf.mac, m_device.m_device_info.intf.name);  
    name_from_mac_address(&m_device.m_device_info.backhaul_alid.mac, m_device.m_device_info.backhaul_alid.name);    
    name_from_mac_address(&m_device.m_device_info.backhaul_mac.mac, m_device.m_device_info.backhaul_mac.name);  
}

dm_easy_mesh_t::dm_easy_mesh_t()
{
	m_num_preferences = 0;
	m_num_interfaces = 0;
    m_num_radios = 0;
	m_num_opclass = 0;
	m_num_policy = 0;
	m_num_bss = 0;
    m_num_ap_mld = 0;
        m_num_net_ssids = 0;
	m_db_cfg_param.db_cfg_type = db_cfg_type_none;
    m_colocated = false;
}

dm_easy_mesh_t::~dm_easy_mesh_t()
{

}


