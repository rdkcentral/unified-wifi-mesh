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
#include "dm_easy_mesh_ctrl.h"
#include "dm_easy_mesh.h"
#include <cjson/cJSON.h>
#include "em_cmd_reset.h"
#include "em_cmd_dev_test.h"

extern char *global_netid;

int dm_easy_mesh_ctrl_t::analyze_radio_metrics_req(em_cmd_t *cmd[])
{
    return 0;
}

int dm_easy_mesh_ctrl_t::analyze_ap_metrics_req(em_cmd_t *cmd[])
{
    return 0;
}

int dm_easy_mesh_ctrl_t::analyze_client_metrics_req(em_cmd_t *cmd[])
{
    return 0;
}

int dm_easy_mesh_ctrl_t::analyze_dev_test(em_bus_event_t *evt, em_cmd_t *pcmd[])
{
    unsigned int num = 0;
    em_subdoc_info_t *subdoc;
    dm_easy_mesh_t  dm;
    em_cmd_t *tmp;

    subdoc = &evt->u.subdoc;

    dm.decode_config(subdoc, "Test");
    dm.print_config();

    pcmd[num] = new em_cmd_dev_test_t(evt->params, dm);
    tmp = pcmd[num];
    num++;

    while ((pcmd[num] = tmp->clone_for_next()) != NULL) {
		tmp = pcmd[num];
		num++;
    }
    printf("%s:%d: Number of commands:%d\n", __func__, __LINE__, num);

    return num;

}

int dm_easy_mesh_ctrl_t::analyze_reset(em_bus_event_t *evt, em_cmd_t *pcmd[])
{
    unsigned int num = 0;
    em_subdoc_info_t *subdoc;
    dm_easy_mesh_t  dm;
    em_cmd_t *tmp;

    subdoc = &evt->u.subdoc;

    dm.decode_config(subdoc, "Reset");
    dm.print_config();

    pcmd[num] = new em_cmd_reset_t(evt->params, dm);
    tmp = pcmd[num];
    num++;

    while ((pcmd[num] = tmp->clone_for_next()) != NULL) {
		tmp = pcmd[num];
		num++;
    }
    printf("%s:%d: Number of commands:%d\n", __func__, __LINE__, num);

    return num;

}


int dm_easy_mesh_ctrl_t::analyze_client_steer(em_bus_event_t *evt, em_cmd_t *cmd[])
{
    cJSON *obj, *steer_obj;
    unsigned int num = 0;
    em_subdoc_info_t *subdoc;

    subdoc = &evt->u.subdoc;

    obj = cJSON_Parse(subdoc->buff);
    if (obj == NULL) {
        printf("%s:%d: Failed to parse: %s\n", __func__, __LINE__, subdoc->buff);
        return 0;
    }

    steer_obj = cJSON_GetObjectItem(obj, "ClientSteer");
    if (steer_obj == NULL) {
        printf("%s:%d: Failed to parse: %s\n", __func__, __LINE__, subdoc->buff);
        return 0;
    }

    num = dm_sta_list_t::analyze_config(steer_obj, NULL, cmd, &evt->params);

    cJSON_free(obj);

    return num;
}

int dm_easy_mesh_ctrl_t::analyze_dpp_start(em_bus_event_t *evt, em_cmd_t *cmd[])
{
    cJSON *obj, *dpp_obj;
    unsigned int num = 0;
    em_subdoc_info_t *subdoc;

    subdoc = &evt->u.subdoc;

    obj = cJSON_Parse(subdoc->buff);
    if (obj == NULL) {
        printf("%s:%d: Failed to parse: %s\n", __func__, __LINE__, subdoc->buff);
        return 0;
    }

    dpp_obj = cJSON_GetObjectItem(obj, "URI");
    if (dpp_obj == NULL) {
        printf("%s:%d: Failed to parse: %s\n", __func__, __LINE__, subdoc->buff);
        return 0;
    }

    //num = m_dpp.analyze_config(dpp_obj, NULL, cmd, &evt->params);
    cJSON_free(obj);

    return num;
}

int dm_easy_mesh_ctrl_t::analyze_network_ssid_list(em_bus_event_t *evt, em_cmd_t *cmd[])
{
    cJSON *obj, *netssid_list_obj;
    unsigned int num = 0;
    em_subdoc_info_t *subdoc;

    subdoc = &evt->u.subdoc;

    obj = cJSON_Parse(subdoc->buff);
    if (obj == NULL) {
        printf("%s:%d: Failed to parse: %s\n", __func__, __LINE__, subdoc->buff);
        return 0;
    }

    netssid_list_obj = cJSON_GetObjectItem(obj, "NetworkSSIDList");
    if (netssid_list_obj == NULL) {
        printf("%s:%d: Failed to parse: %s\n", __func__, __LINE__, subdoc->buff);
        return 0;
    }

    num = dm_network_ssid_list_t::analyze_config(netssid_list_obj, (void *)global_netid, cmd, &evt->params);
    cJSON_free(obj);

    return num;
}

int dm_easy_mesh_ctrl_t::set_op_class_list(cJSON *op_class_list_obj, mac_address_t *radio_mac)
{
    dm_op_class_list_t::set_config(m_db_client, op_class_list_obj, radio_mac);
    return 0;
}

int dm_easy_mesh_ctrl_t::set_radio_cap_list(cJSON *radio_cap_list_obj, mac_address_t *radio_mac)
{
    dm_radio_cap_list_t::set_config(m_db_client, radio_cap_list_obj, radio_mac);
    return 0;
}

int dm_easy_mesh_ctrl_t::set_bss_list(cJSON *bss_list_obj, mac_address_t *radio_mac)
{
    dm_bss_list_t::set_config(m_db_client, bss_list_obj, radio_mac);
    return 0;
}

int dm_easy_mesh_ctrl_t::set_radio_list(cJSON *radio_list_obj, mac_address_t *dev_mac)
{
    unsigned int i, num;
    cJSON *obj, *radio_obj, *bss_list_obj, *op_class_list_obj, *radio_cap_list_obj;
    mac_address_t radio_mac;

    dm_radio_list_t::set_config(m_db_client, radio_list_obj, dev_mac);

    num = cJSON_GetArraySize(radio_list_obj);
    printf("%s:%d: Number of devices: %d\n", __func__, __LINE__, num);
    for (i = 0; i < num; i++) {
        if ((radio_obj = cJSON_GetArrayItem(radio_list_obj, i)) != NULL) {

            obj = cJSON_GetObjectItem(radio_obj, "ID");
            dm_easy_mesh_t::string_to_macbytes(cJSON_GetStringValue(obj), radio_mac);
            printf("%s:%d: BSSList for radio[%d]: %s\n", __func__, __LINE__, i, cJSON_GetStringValue(obj));

            if ((bss_list_obj = cJSON_GetObjectItem(radio_obj, "BSSList")) != NULL) {
                set_bss_list(bss_list_obj, &radio_mac);
            }

            if ((op_class_list_obj = cJSON_GetObjectItem(radio_obj, "CurrentOperatingClasses")) != NULL) {
                set_op_class_list(op_class_list_obj, &radio_mac);
            }

            if ((radio_cap_list_obj = cJSON_GetObjectItem(radio_obj, "Capabilities")) != NULL) {
                set_radio_cap_list(radio_cap_list_obj, &radio_mac);
            }

        }
    }

    return 0;
}

int dm_easy_mesh_ctrl_t::set_device_list(cJSON *dev_list_obj)
{
    unsigned int i, num;
    cJSON *obj, *dev_obj, *radio_list_obj;
    mac_address_t dev_mac;

    dm_device_list_t::set_config(m_db_client, dev_list_obj, (void *)global_netid);

    num = cJSON_GetArraySize(dev_list_obj);
    printf("%s:%d: Number of devices: %d\n", __func__, __LINE__, num);
    for (i = 0; i < num; i++) {
        if (((dev_obj = cJSON_GetArrayItem(dev_list_obj, i)) != NULL) &&
           ((radio_list_obj = cJSON_GetObjectItem(dev_obj, "RadioList")) != NULL)) {
            obj = cJSON_GetObjectItem(dev_obj, "ID");
            dm_easy_mesh_t::string_to_macbytes(cJSON_GetStringValue(obj), dev_mac);
            printf("%s:%d: RadioList for device[%d]: %s\n", __func__, __LINE__, i, cJSON_GetStringValue(obj));
            set_radio_list(radio_list_obj, &dev_mac);
        }
    }

    return 0;
}

int dm_easy_mesh_ctrl_t::reset_config()
{
    
    dm_network_list_t::delete_list();
    dm_device_list_t::delete_list();
    dm_radio_list_t::delete_list();
    dm_network_ssid_list_t::delete_list();
    //dm_ieee_1905_security_list_t::delete_list();
    //dm_radio_cap_list_t::delete_list();
    dm_op_class_list_t::delete_list();
    dm_bss_list_t::delete_list();
    dm_sta_list_t::delete_list();
    
    dm_network_list_t::delete_table(m_db_client);
    dm_device_list_t::delete_table(m_db_client);
    dm_radio_list_t::delete_table(m_db_client);    
    dm_network_ssid_list_t::delete_table(m_db_client);   
    //dm_ieee_1905_security_list_t::delete_table(m_db_client);
    //dm_radio_cap_list_t::delete_table(m_db_client);
    dm_op_class_list_t::delete_table(m_db_client);
    dm_bss_list_t::delete_table(m_db_client);
    dm_sta_list_t::delete_table(m_db_client);

    dm_network_list_t::load_table(m_db_client);
    dm_device_list_t::load_table(m_db_client);
    dm_radio_list_t::load_table(m_db_client);    
    dm_network_ssid_list_t::load_table(m_db_client);    
    //dm_ieee_1905_security_list_t::load_table(m_db_client);
    //dm_radio_cap_list_t::load_table(m_db_client);
    dm_op_class_list_t::load_table(m_db_client);
    dm_bss_list_t::load_table(m_db_client);
    dm_sta_list_t::load_table(m_db_client);

    return 0;
}

int dm_easy_mesh_ctrl_t::get_bss_config(cJSON *parent, char *key)
{
    cJSON *net_obj, *dev_list_obj, *dev_obj, *radio_list_obj, *radio_obj, *bss_list_obj;
    unsigned int i, j;
    char *tmp;

    net_obj = cJSON_AddObjectToObject(parent, "Network");
    dm_network_list_t::get_config(net_obj, key, true);

    dev_list_obj = cJSON_AddArrayToObject(net_obj, "DeviceList");
    dm_device_list_t::get_config(dev_list_obj, key, true);

    for (i = 0; i < cJSON_GetArraySize(dev_list_obj); i++) {
        dev_obj = cJSON_GetArrayItem(dev_list_obj, i);
        radio_list_obj = cJSON_AddArrayToObject(dev_obj, "RadioList");
        dm_radio_list_t::get_config(radio_list_obj, cJSON_GetStringValue(cJSON_GetObjectItem(dev_obj, "ID")), true);
        for (j = 0; j < cJSON_GetArraySize(radio_list_obj); j++) {
            radio_obj = cJSON_GetArrayItem(radio_list_obj, j);
            tmp = cJSON_GetStringValue(cJSON_GetObjectItem(radio_obj, "ID"));
            bss_list_obj = cJSON_AddArrayToObject(radio_obj, "BSSList");
            dm_bss_list_t::get_config(bss_list_obj, tmp);
        }
    }

    return 0;
}

int dm_easy_mesh_ctrl_t::get_sta_config(cJSON *parent, char *key)
{

    return 0;
}

int dm_easy_mesh_ctrl_t::get_network_ssid_config(cJSON *parent, char *key)
{
    cJSON *netssid_list_obj;

    netssid_list_obj = cJSON_AddArrayToObject(parent, "NetworkSSIDList");
    dm_network_ssid_list_t::get_config(netssid_list_obj, key);
	
    return 0;
}

int dm_easy_mesh_ctrl_t::get_channel_config(cJSON *parent, char *key)
{
    cJSON *net_obj, *dev_list_obj, *dev_obj, *radio_list_obj, *radio_obj, *op_class_list_obj;
    unsigned int i, j;
    char *tmp;
    em_long_string_t op_key;
		
    net_obj = cJSON_AddObjectToObject(parent, "Network");
    dm_network_list_t::get_config(net_obj, key, true);

    dev_list_obj = cJSON_AddArrayToObject(net_obj, "DeviceList");
    dm_device_list_t::get_config(dev_list_obj, key, true);

    for (i = 0; i < cJSON_GetArraySize(dev_list_obj); i++) {	
        dev_obj = cJSON_GetArrayItem(dev_list_obj, i);
	radio_list_obj = cJSON_AddArrayToObject(dev_obj, "RadioList");
	dm_radio_list_t::get_config(radio_list_obj, cJSON_GetStringValue(cJSON_GetObjectItem(dev_obj, "ID")), true);
	for (j = 0; j < cJSON_GetArraySize(radio_list_obj); j++) {
	    radio_obj = cJSON_GetArrayItem(radio_list_obj, j);
	    tmp = cJSON_GetStringValue(cJSON_GetObjectItem(radio_obj, "ID"));
	    op_class_list_obj = cJSON_AddArrayToObject(radio_obj, "CurrentOperatingClasses");
	    snprintf(op_key, sizeof(op_key), "%s@%d@&d", tmp, em_op_class_type_current, 0);
	    dm_op_class_list_t::get_config(op_class_list_obj, op_key);
	}
    }

    return 0;
}

int dm_easy_mesh_ctrl_t::get_network_config(cJSON *parent, char *key)
{
    cJSON *net_obj, *dev_list_obj, *netssid_list_obj, *radio_list_obj;
    cJSON *obj, *dev_obj;
    unsigned int i, num;
    mac_address_t dev_mac;
		
    net_obj = cJSON_AddObjectToObject(parent, "Network");
    dm_network_list_t::get_config(net_obj, key);

    dev_list_obj = cJSON_AddArrayToObject(net_obj, "DeviceList");
    dm_device_list_t::get_config(dev_list_obj, key);

    netssid_list_obj = cJSON_AddArrayToObject(net_obj, "NetworkSSIDList");
    dm_network_ssid_list_t::get_config(netssid_list_obj, key);

#ifdef FIX_B
    num = cJSON_GetArraySize(dev_list_obj);
    for (i = 0; i < num; i++) {
	if (((dev_obj = cJSON_GetArrayItem(dev_list_obj, i)) != NULL) &&
			((obj = cJSON_GetObjectItem(dev_obj, "ID")) != NULL)) {
	    radio_list_obj = cJSON_AddArrayToObject(dev_obj, "RadioList");
	    dm_easy_mesh_t::string_to_macbytes(cJSON_GetStringValue(obj), dev_mac);
	    dm_radio_list_t::get_config(radio_list_obj, &dev_mac);
	}
    }
#endif // FIX_B
}

int dm_easy_mesh_ctrl_t::get_config(em_long_string_t net_id, em_subdoc_info_t *subdoc)
{
    cJSON *parent;
    char *tmp;

    parent = cJSON_CreateObject();

    if (strncmp(subdoc->name, "Network", strlen(subdoc->name)) == 0) {
		get_network_config(parent, net_id); 
    } else if (strncmp(subdoc->name, "NetworkSSIDList", strlen(subdoc->name)) == 0) {
		get_network_ssid_config(parent, net_id); 
	} else if (strncmp(subdoc->name, "ChannelList", strlen(subdoc->name)) == 0) {
		get_channel_config(parent, net_id); 
	} else if (strncmp(subdoc->name, "BSSList", strlen(subdoc->name)) == 0) {
		get_bss_config(parent, net_id); 
	} else if (strncmp(subdoc->name, "STAList", strlen(subdoc->name)) == 0) {
		get_sta_config(parent, net_id); 
	}

    tmp = cJSON_Print(parent);
    printf("%s:%d: Subdoc: %s\n", __func__, __LINE__, tmp);
    strncpy(subdoc->buff, tmp, strlen(tmp) + 1);
    cJSON_free(parent);
}

int dm_easy_mesh_ctrl_t::copy_config(dm_easy_mesh_t *dm, em_long_string_t net_id)
{
    dm_network_t *network;

    network = m_data_model_list.get_network(net_id);
    if (network == NULL) {
        printf("%s%%d: Network with id:%d not found\n", __func__, __LINE__, net_id);
        return -1;
    }

    dm->set_network(*network);

    return 0;
}

int dm_easy_mesh_ctrl_t::set_config(dm_easy_mesh_t *dm)
{
    return update_tables(dm);
}

dm_easy_mesh_t *dm_easy_mesh_ctrl_t::create_data_model(const char *net_id, const unsigned char *al_mac, em_profile_type_t profile)
{
    
    return m_data_model_list.create_data_model(net_id, al_mac, profile);
}

void dm_easy_mesh_ctrl_t::handle_dirty_dm()
{
    dm_easy_mesh_t *dm;

    dm = m_data_model_list.get_first_dm();
    while (dm != NULL) {
	if (dm->get_db_cfg_type()) {
	    set_config(dm);		
	}
	dm = m_data_model_list.get_next_dm(dm);
    }
}

dm_easy_mesh_t  *dm_easy_mesh_ctrl_t::get_data_model(const char *net_id, const unsigned char *al_mac) 
{
    if (al_mac == NULL) {
        return (dm_easy_mesh_t *)this;
    } else {
        return m_data_model_list.get_data_model(net_id, al_mac);
    }
}

void dm_easy_mesh_ctrl_t::init_tables()
{
    dm_network_list_t::init();
    dm_device_list_t::init();
    dm_network_ssid_list_t::init();
    dm_ieee_1905_security_list_t::init();
    dm_radio_cap_list_t::init();
    dm_radio_list_t::init();
    dm_op_class_list_t::init();
    dm_bss_list_t::init();
    dm_sta_list_t::init();
}

int dm_easy_mesh_ctrl_t::load_tables()
{
    dm_orch_type_t type = dm_orch_type_none;
    
    if (dm_network_list_t::load_table(m_db_client) != 0) {
        type = dm_orch_type_net_update;
    } else if (dm_device_list_t::load_table(m_db_client) != 0) {
        type = dm_orch_type_dev_update;
    } else if (dm_radio_list_t::load_table(m_db_client) != 0) {
        type = dm_orch_type_rd_update;
    } else if (dm_network_ssid_list_t::load_table(m_db_client) != 0) {
		type = dm_orch_type_ssid_update;
    } else if (dm_op_class_list_t::load_table(m_db_client) != 0) {
		type = dm_orch_type_op_class_update;
	} else if (dm_bss_list_t::load_table(m_db_client) != 0) {
		type = dm_orch_type_bss_update;
	} else if (dm_sta_list_t::load_table(m_db_client) != 0) {
		type = dm_orch_type_sta_update;
/*
	} else if (dm_ieee_1905_security_list_t::load_table(m_db_client) != 0) {
		type = dm_orch_type_1905_security_update;
	} else if (dm_radio_cap_list_t::load_table(m_db_client) != 0) {
		type = dm_orch_type_cap_update;
*/
    }

    if (type == dm_orch_type_none) {
        set_initialized();
    }

    return type;
}

int dm_easy_mesh_ctrl_t::update_tables(dm_easy_mesh_t *dm)
{
    dm_orch_type_t type = dm_orch_type_none;
    dm_device_t device;
    dm_radio_t radio;
    dm_op_class_t op_class;
	dm_bss_t bss;
    mac_addr_str_t	mac_str;
    unsigned int i;
    em_long_string_t	parent;

    printf("%s:%d: db config type: %d\n", __func__, __LINE__, dm->get_db_cfg_type());

    if ((dm->get_db_cfg_type() & db_cfg_type_network_list) && dm_network_list_t::set_config(m_db_client, dm->get_network_by_ref(), global_netid) != 0) {
        type = dm_orch_type_net_update;
    }
    if ((dm->get_db_cfg_type() & db_cfg_type_device_list) && dm_device_list_t::set_config(m_db_client, dm->get_device_by_ref(), global_netid) != 0) {
        type = dm_orch_type_dev_update;
    }

    if (dm->get_db_cfg_type() & db_cfg_type_radio_list) {
        device = dm->get_device_by_ref();
        dm_easy_mesh_t::macbytes_to_string((unsigned char *)device.m_device_info.id.mac, mac_str);
        for (i = 0; i < dm->get_num_radios(); i++) {
            snprintf(parent, sizeof(em_long_string_t), "%s@%s", mac_str, device.m_device_info.net_id);
            radio = dm->get_radio_by_ref(i);
            if (dm_radio_list_t::set_config(m_db_client, radio, parent) != 0) {
                type = dm_orch_type_rd_update; 
            }
        }
    }

    if (dm->get_db_cfg_type() & db_cfg_type_bss_list) {
		for (i = 0; i < dm->get_num_bss(); i++) {
			bss = dm->get_bss_by_ref(i);
   			if (dm_bss_list_t::set_config(m_db_client, dm->get_bss_by_ref(i), parent) != 0) {
        		type = dm_orch_type_bss_update;
			}
		}
	}

    if (dm->get_db_cfg_type() & db_cfg_type_op_class_list) {
		for (i = 0; i < dm->get_num_op_class(); i++) {
			op_class = dm->get_op_class_by_ref(i);
			dm_easy_mesh_t::macbytes_to_string(op_class.m_op_class_info.id.ruid, mac_str);
			printf("%s:%d: Op Class[%d] ruid: %s type: %d index: %d\n", __func__, __LINE__, i,
				mac_str, op_class.m_op_class_info.id.type, op_class.m_op_class_info.id.index);
			snprintf(parent, sizeof(em_long_string_t), "%s@%d@%d", mac_str, op_class.m_op_class_info.id.type, op_class.m_op_class_info.id.index);
   			if (dm_op_class_list_t::set_config(m_db_client, dm->get_op_class_by_ref(i), parent) != 0) {
        		type = dm_orch_type_rd_update;
			}
		}
	}

    if (dm->get_db_cfg_type() & db_cfg_type_network_ssid_list) {
        for (i = 0; i < dm->get_num_network_ssid(); i++) {
            snprintf(parent, sizeof(em_string_t), "%s@%d", global_netid, i);
            if (dm_network_ssid_list_t::set_config(m_db_client, dm->get_network_ssid_by_ref(i), parent) != 0) {
                type = dm_orch_type_ssid_update;
            }
        }
    }

    return type;
}

int dm_easy_mesh_ctrl_t::init(const char *data_model_path)
{
    dm_device_t *dev;
    void *res;
    int rc;

    m_data_model_list.init();
    init_tables();

    if (m_db_client.init(data_model_path) != 0) {
        printf("%s:%d db init failed\n", __func__, __LINE__);
        return -1;
    }

    if ((rc = load_tables()) != 0) {
        printf("%s:%d: Load operation failed, err: %s\n", __func__, __LINE__, em_cmd_t::get_orch_op_str((dm_orch_type_t)rc));
        return -1;
    }
    return 0;
}

dm_easy_mesh_ctrl_t::dm_easy_mesh_ctrl_t()
{
    m_initialized = false;
}

dm_easy_mesh_ctrl_t::~dm_easy_mesh_ctrl_t()
{

}

