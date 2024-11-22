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
#include <unordered_map>
#include <string>
#include "em_cmd_dev_init.h"
#include "dm_easy_mesh_agent.h"
#include <cjson/cJSON.h>
#include "em_cmd_sta_list.h"
#include "em_cmd_onewifi_cb.h"
#include "em_cmd_cfg_renew.h"
#include "em_cmd_channel_pref_query.h"
#include "em_cmd_op_channel_report.h"

int dm_easy_mesh_agent_t::analyze_dev_init(em_bus_event_t *evt, em_cmd_t *pcmd[])
{
    unsigned int index = 0;
    unsigned int num = 0, i, j = 0, num_radios = 0;
    em_orch_desc_t desc;
    dm_easy_mesh_agent_t  dm;
    dm_device_t *dev, *tgt_dev;
    dm_radio_t *rd, *tgt_rd;
    em_cmd_t *tmp;
    dm.translate_onewifi_dml_data((char *)evt->u.raw_buff);

    dm.print_config();
    num_radios = dm.get_num_radios();
    //TODO: Check for multiple radios
    pcmd[num] = new em_cmd_dev_init_t(evt->params, dm);
    tmp = pcmd[num];
    num++;

    while ((pcmd[num] = tmp->clone_for_next()) != NULL) {
        tmp = pcmd[num];
        num++;
    }
    return num;

}

int dm_easy_mesh_agent_t::analyze_sta_list(em_bus_event_t *evt, em_cmd_t *pcmd[])
{
    unsigned int num = 0, i = 0, num_radios = 0;
    dm_easy_mesh_agent_t  dm;
    dm_sta_t *sta = NULL;
    em_cmd_t *tmp = NULL;
    em_sta_info_t *em_sta = NULL;
    em_long_string_t key;
    mac_addr_str_t radio_str;
    em_cmd_params_t *evt_param = NULL;
    mac_addr_str_t  sta_mac_str, bss_mac_str, radio_mac_str;

    num_radios = get_num_radios();
    dm.init();

    evt_param = &evt->params;

    num_radios = m_num_radios;
    for (unsigned int i = 0; i < m_num_radios; i++) {
        memcpy(&dm.m_radio[i], &m_radio[i], sizeof(dm_radio_t));
    }

    dm.m_num_bss = m_num_bss;
    for (unsigned int i = 0; i < EM_MAX_BSSS; i++) {
        memcpy(&dm.m_bss[i], &m_bss[i], sizeof(dm_bss_t));
    }

    dm.translate_onewifi_stats_data((char *)evt->u.raw_buff);

    for ( i = 0; i < num_radios; i++) {
        evt_param->u.args.num_args = 1;
        dm_easy_mesh_t::macbytes_to_string(get_radio_by_ref(i).get_radio_interface_mac(), radio_str);
        strncpy(evt_param->u.args.args[0], radio_str, strlen(radio_str) + 1);

        pcmd[num] = new em_cmd_sta_list_t(evt->params, dm);

        sta = (dm_sta_t *)hash_map_get_first(dm.m_sta_assoc_map);
        while(sta != NULL) {
            em_sta = sta->get_sta_info();
            if (memcmp(sta->get_sta_info()->radiomac, get_radio_by_ref(i).get_radio_interface_mac(), sizeof(mac_address_t)) != 0) {
                sta = (dm_sta_t *)hash_map_get_next(dm.m_sta_assoc_map, sta);
                continue;
            }

            dm_easy_mesh_t::macbytes_to_string(sta->m_sta_info.id, sta_mac_str);
            dm_easy_mesh_t::macbytes_to_string(sta->m_sta_info.bssid, bss_mac_str);
            dm_easy_mesh_t::macbytes_to_string(sta->m_sta_info.radiomac, radio_mac_str);
            snprintf(key, sizeof(em_long_string_t), "%s@%s@%s", sta_mac_str, bss_mac_str, radio_mac_str);
            printf("Key in assoc map: %s\n", key);
            hash_map_put(pcmd[num]->m_data_model.m_sta_assoc_map, strdup(key), new dm_sta_t(*sta));
            sta = (dm_sta_t *)hash_map_get_next(dm.m_sta_assoc_map, sta);
        }

        sta = (dm_sta_t *)hash_map_get_first(dm.m_sta_dassoc_map);
        while(sta != NULL) {
            em_sta = sta->get_sta_info();

            if (memcmp(sta->get_sta_info()->radiomac, get_radio_by_ref(i).get_radio_interface_mac(), sizeof(mac_address_t)) != 0) {
                sta = (dm_sta_t *)hash_map_get_next(dm.m_sta_dassoc_map, sta);
                continue;
             }

            dm_easy_mesh_t::macbytes_to_string(sta->m_sta_info.id, sta_mac_str);
            dm_easy_mesh_t::macbytes_to_string(sta->m_sta_info.bssid, bss_mac_str);
            dm_easy_mesh_t::macbytes_to_string(sta->m_sta_info.radiomac, radio_mac_str);
            snprintf(key, sizeof(em_long_string_t), "%s@%s@%s", sta_mac_str, bss_mac_str, radio_mac_str);
            printf("Key in Dassoc map: %s\n", key);
            hash_map_put(pcmd[num]->m_data_model.m_sta_dassoc_map, strdup(key), new dm_sta_t(*sta));
            sta = (dm_sta_t *)hash_map_get_next(dm.m_sta_dassoc_map, sta);
        }

        tmp = pcmd[num];
        num++;

        while ((pcmd[num] = tmp->clone_for_next()) != NULL) {
            dm.clone_hash_maps(*pcmd[num]->get_data_model());
            tmp = pcmd[num];
            num++;
        }
    }

    return num;
}

int dm_easy_mesh_agent_t::analyze_autoconfig_renew(em_bus_event_t *evt, em_cmd_t *pcmd[])
{
    em_bus_event_type_cfg_renew_params_t *raw;
    em_event_t bus;
    dm_easy_mesh_agent_t  dm = *this;
    int num = 0;
    em_cmd_t *tmp;

    raw = (em_bus_event_type_cfg_renew_params_t *)evt->u.raw_buff;
    memcpy(dm.get_controller_interface_mac(), raw->ctrl_src, sizeof(mac_address_t));

    pcmd[num] = new em_cmd_cfg_renew_t(em_service_type_agent, evt->params, dm);
    tmp = pcmd[num];
    num++;

    while ((pcmd[num] = tmp->clone_for_next()) != NULL) {
        tmp = pcmd[num];
        num++;
    }
    return num;
}

void dm_easy_mesh_agent_t::translate_onewifi_dml_data (char *str)
{           
    webconfig_t config;
    webconfig_external_easymesh_t ext;
    webconfig_subdoc_type_t type;
    int num_radios,num_op,num_bss;
    unsigned int i = 0;
                
    webconfig_proto_easymesh_init(&ext, this, NULL, get_num_radios, set_num_radios, 
            get_num_op_class, set_num_op_class, get_num_bss, set_num_bss,
            get_device_info, get_network_info, get_radio_info, get_ieee_1905_security_info, get_bss_info, get_op_class_info, get_first_sta_info, get_next_sta_info, get_sta_info, put_sta_info);
    
    config.initializer = webconfig_initializer_onewifi;
    config.apply_data =  webconfig_dummy_apply;
                
    if (webconfig_init(&config) != webconfig_error_none) {
        printf( "[%s]:%d Init WiFi Web Config  fail\n",__func__,__LINE__);
        return ;
                
    }           
                
    if ((webconfig_easymesh_decode(&config, str, &ext, &type)) == webconfig_error_none) {
        printf("%s:%d Dev-Init decode success\n",__func__, __LINE__);
    } else {       
        printf("%s:%d Dev-Init decode fail\n",__func__, __LINE__);
    }       
        
}

int dm_easy_mesh_agent_t::analyze_m2ctrl_configuration(em_bus_event_t *evt, wifi_bus_desc_t *desc,bus_handle_t *bus_hdl)
{
    em_event_t bus;
    webconfig_external_easymesh_t dev_data;
    webconfig_subdoc_type_t type = webconfig_subdoc_type_private;
    webconfig_apply_data_t temp;
    webconfig_t config;
    static char *webconfig_easymesh_raw_data_ptr;
    dm_easy_mesh_agent_t  dm;
    raw_data_t l_bus_data;
    unsigned int index = 0;
    m2ctrl_vapconfig *vapconfig;
    m2ctrl_vapconfig m2ctrl;

    vapconfig = (m2ctrl_vapconfig *)evt->u.raw_buff;
    memcpy(m2ctrl.ssid, vapconfig->ssid, sizeof(m2ctrl.ssid));
    m2ctrl.authtype = vapconfig->authtype;
    memcpy(m2ctrl.password, vapconfig->password, sizeof(m2ctrl.password));
    m2ctrl.enable = vapconfig->enable;
    printf("%s:%d New configuration SSID=%s Security mode=%d  passphrase=%s \n",__func__,__LINE__,m2ctrl.ssid,m2ctrl.authtype,m2ctrl.password);

    webconfig_proto_easymesh_init(&dev_data, &dm, &m2ctrl, get_num_radios, set_num_radios,
                                get_num_op_class, set_num_op_class, get_num_bss, set_num_bss,
                                get_device_info, get_network_info, get_radio_info, get_ieee_1905_security_info, get_bss_info, get_op_class_info,
                                get_first_sta_info, get_next_sta_info, get_sta_info, put_sta_info);

    config.initializer = webconfig_initializer_onewifi;
    config.apply_data =  webconfig_dummy_apply;

    if (webconfig_init(&config) != webconfig_error_none) {
        printf( "[%s]:%d Init WiFi Web Config  fail\n",__func__,__LINE__);
        return 0;
    }

    if ((webconfig_easymesh_encode(&config, &dev_data, type, &webconfig_easymesh_raw_data_ptr )) == webconfig_error_none) {
        printf("%s:%d Private subdoc encode success %s\n",__func__, __LINE__,webconfig_easymesh_raw_data_ptr);
    } else {
        printf("%s:%d Private subdoc encode fail\n",__func__, __LINE__);
        return 0;
    }
    memset(&l_bus_data, 0, sizeof(raw_data_t));

    l_bus_data.data_type    = bus_data_type_string;
    l_bus_data.raw_data.bytes   = webconfig_easymesh_raw_data_ptr;
    l_bus_data.raw_data_len = strlen(webconfig_easymesh_raw_data_ptr);

    if (desc->bus_set_fn(bus_hdl, "Device.WiFi.WebConfig.Data.Subdoc.South", &l_bus_data)== 0) {
        printf("%s:%d private subdoc send successfull\n",__func__, __LINE__);
    }
    else {
        printf("%s:%d private subdoc send fail\n",__func__, __LINE__);
        return -1;
    }
    return 1;
}    

int dm_easy_mesh_agent_t::analyze_onewifi_private_cb(em_bus_event_t *evt, em_cmd_t *pcmd[])
{
    webconfig_t config;
    webconfig_external_easymesh_t ext;
    webconfig_subdoc_type_t type;
    int num = 0;
    unsigned int i = 0, j = 0;
    dm_easy_mesh_agent_t  dm;
    em_cmd_t *tmp;
    webconfig_proto_easymesh_init(&ext, &dm, NULL, get_num_radios, set_num_radios,
            get_num_op_class, set_num_op_class, get_num_bss, set_num_bss,
            get_device_info, get_network_info, get_radio_info, get_ieee_1905_security_info, get_bss_info, get_op_class_info, get_first_sta_info, get_next_sta_info, get_sta_info, put_sta_info);
    config.initializer = webconfig_initializer_onewifi;
    config.apply_data =  webconfig_dummy_apply;
    if (webconfig_init(&config) != webconfig_error_none) {
        printf( "[%s]:%d Init WiFi Web Config  fail\n",__func__,__LINE__);
        return 0;
    }

    if ((webconfig_easymesh_decode(&config, (char *)evt->u.raw_buff, &ext, &type)) == webconfig_error_none) {
        printf("%s:%d Private subdoc decode success\n",__func__, __LINE__);
    } else {
        printf("%s:%d Private subdoc decode fail\n",__func__, __LINE__);
    }

    for (i = 0; i < m_num_bss; i++) {
        for (j = 0; j < dm.m_num_bss; j++) {
           if (memcmp(get_bss(i)->get_bss_info()->ruid.mac, dm.get_bss(j)->get_bss_info()->ruid.mac, sizeof(mac_address_t)) == 0) {
               if (memcmp(get_bss(i)->get_bss_info()->bssid.mac, dm.get_bss(j)->get_bss_info()->bssid.mac, sizeof(mac_address_t)) == 0) {
                   commit_bss_config(dm, j);
               }
           }
       }
    }

    pcmd[num] = new em_cmd_ow_cb_t(evt->params, dm);
    tmp = pcmd[num];
    num++;

    while ((pcmd[num] = tmp->clone_for_next()) != NULL) {
        tmp = pcmd[num];
        num++;
    }
    return num;
}

int dm_easy_mesh_agent_t::analyze_onewifi_radio_cb(em_bus_event_t *evt, em_cmd_t *pcmd[])
{
    webconfig_t config;
    webconfig_external_easymesh_t ext;
    webconfig_subdoc_type_t type;
    int num = 0;
    mac_addr_str_t  mac_str;
    unsigned int i = 0, j = 0;
    dm_easy_mesh_agent_t  dm;
    em_cmd_t *tmp;
    em_commit_target_t cm_config;

    webconfig_proto_easymesh_init(&ext, &dm, NULL, get_num_radios, set_num_radios,
            get_num_op_class, set_num_op_class, get_num_bss, set_num_bss,
            get_device_info, get_network_info, get_radio_info, get_ieee_1905_security_info, get_bss_info, get_op_class_info, get_first_sta_info, get_next_sta_info, get_sta_info, put_sta_info);

    config.initializer = webconfig_initializer_onewifi;
    config.apply_data =  webconfig_dummy_apply;
    if (webconfig_init(&config) != webconfig_error_none) {
        printf( "[%s]:%d Init WiFi Web Config  fail\n",__func__,__LINE__);
        return 0;
    }

    if ((webconfig_easymesh_decode(&config, (char *)evt->u.raw_buff, &ext, &type)) == webconfig_error_none) {
        printf("%s:%d Radio subdoc decode success\n",__func__, __LINE__);
    } else {
        printf("%s:%d Radio subdoc decode fail\n",__func__, __LINE__);
    }
    for (i = 0; i < m_num_radios; i++) {
        for (j = 0; j < dm.m_num_radios; j++) {
            if (memcmp(get_radio(i)->get_radio_info()->id.mac, dm.get_radio(j)->get_radio_info()->id.mac, sizeof(mac_address_t)) == 0) {
                dm_easy_mesh_t::macbytes_to_string(get_radio(i)->get_radio_info()->id.mac, mac_str);
                cm_config.type = em_commit_target_radio;
                snprintf((char *)cm_config.params,sizeof(cm_config.params),(char*)"%s",mac_str);
                commit_config(dm, cm_config);
            }
        }
    }
    pcmd[num] = new em_cmd_op_channel_report_t(evt->params, dm);
    tmp = pcmd[num];
    num++;

    while ((pcmd[num] = tmp->clone_for_next()) != NULL) {
        tmp = pcmd[num];
        num++;
    }
    return num;

}

        
void dm_easy_mesh_agent_t::translate_onewifi_sta_data(char *str)
{               
                
}               
                    
void dm_easy_mesh_agent_t::translate_onewifi_stats_data(char *str)
{
    printf("%s:%d: Enter\n", __func__, __LINE__);

    webconfig_t config;
    webconfig_external_easymesh_t extdata = {0};
    webconfig_subdoc_type_t type = webconfig_subdoc_type_associated_clients;

    webconfig_proto_easymesh_init(&extdata, this, NULL, get_num_radios, set_num_radios,
            get_num_op_class, set_num_op_class, get_num_bss, set_num_bss,
            get_device_info, get_network_info, get_radio_info, get_ieee_1905_security_info, get_bss_info, get_op_class_info,
			get_first_sta_info, get_next_sta_info, get_sta_info, put_sta_info);

    config.initializer = webconfig_initializer_onewifi;
    config.apply_data =  webconfig_dummy_apply;

    if (webconfig_init(&config) != webconfig_error_none) {
        printf( "[%s]:%d Init WiFi Web Config  fail\n",__func__,__LINE__);
        return ;

    }

    if ((webconfig_easymesh_decode(&config, str, &extdata, &type)) == webconfig_error_none) {
        printf("%s:%d Assoc clients decode success\n",__func__, __LINE__);
    } else {
        printf("%s:%d Assoc clients decode fail\n",__func__, __LINE__);
    }
}

int dm_easy_mesh_agent_t::analyze_channel_pref_query(em_bus_event_t *evt, em_cmd_t *pcmd[])
{
    int num = 0;
    dm_easy_mesh_agent_t  dm;
    em_radio_info_t *radio;
    em_bus_event_type_channel_pref_query_params_t *params;
    
    params = (em_bus_event_type_channel_pref_query_params_t *)evt->u.raw_buff;
    dm.set_num_radios(1);
    radio = dm.get_radio_info(0);
    if (radio != NULL) {
        memcpy(&radio->id.mac, &params->mac, sizeof(mac_address_t));
    }
    dm.set_msg_id(params->msg_id);
    dm.print_config();
    pcmd[num] = new em_cmd_channel_pref_query_t(em_service_type_agent, evt->params, dm);
    num++;

    return num;
}

int dm_easy_mesh_agent_t::analyze_channel_sel_req(em_bus_event_t *evt, wifi_bus_desc_t *desc,bus_handle_t *bus_hdl)
{
	em_event_t bus;
	webconfig_external_easymesh_t dev_data;
	webconfig_subdoc_type_t type = webconfig_subdoc_type_radio;
	webconfig_apply_data_t temp;
	webconfig_t config;
	static char *webconfig_easymesh_raw_data_ptr;
	dm_easy_mesh_agent_t  dm = *this;
	raw_data_t l_bus_data;
	unsigned int index = 0, i = 0, noofopclass = 0, j = 0;
	mac_addr_str_t mac_str;
	op_class_channel_sel *channel_sel;
	em_op_class_info_t *dm_op_class;

	channel_sel = (op_class_channel_sel*) evt->u.raw_buff;
	printf("%s:%d No of opclass=%d\n", __func__, __LINE__,channel_sel->num);

	noofopclass = dm.get_num_op_class();
	//TODO Select the right op class and number and configure
	for (i = 0; i < noofopclass; i++) {
		dm_op_class = dm.get_op_class_info(i);
		if ((memcmp(dm_op_class->id.ruid, &channel_sel->op_class_info[0].id.ruid, sizeof(mac_address_t)) == 0) && 
			(dm_op_class->id.type == channel_sel->op_class_info[0].id.type)) {
			dm_op_class->channel =  channel_sel->op_class_info[0].anticipated_channel[0];
			dm_op_class->op_class = channel_sel->op_class_info[0].op_class;
		break;
		}
	}
	if (i == noofopclass) {
		dm_op_class = dm.get_op_class_info(i);
		memcpy(dm_op_class, &channel_sel->op_class_info[i], sizeof(em_op_class_info_t));
		dm_op_class->channel = channel_sel->op_class_info[0].anticipated_channel[0];
		dm_op_class->op_class = channel_sel->op_class_info[0].op_class;
		noofopclass++;
	}
	dm.set_num_op_class(noofopclass);
	dm.print_config();

    webconfig_proto_easymesh_init(&dev_data, &dm, NULL, get_num_radios, set_num_radios,
			get_num_op_class, set_num_op_class, get_num_bss, set_num_bss,
			get_device_info, get_network_info, get_radio_info, get_ieee_1905_security_info, get_bss_info, get_op_class_info, 
			get_first_sta_info, get_next_sta_info, get_sta_info, put_sta_info);

	config.initializer = webconfig_initializer_onewifi;
	config.apply_data =	 webconfig_dummy_apply;

	if (webconfig_init(&config) != webconfig_error_none) {
		printf( "[%s]:%d Init WiFi Web Config  fail\n",__func__,__LINE__);
		return 0;
	}

	if ((webconfig_easymesh_encode(&config, &dev_data, type, &webconfig_easymesh_raw_data_ptr )) == webconfig_error_none) {
		printf("%s:%d Radio subdoc encode success %s\n",__func__, __LINE__,webconfig_easymesh_raw_data_ptr);
	} else {
		printf("%s:%d Radio subdoc encode fail\n",__func__, __LINE__);
		return 0;
	}
	memset(&l_bus_data, 0, sizeof(raw_data_t));

	l_bus_data.data_type	= bus_data_type_string;
	l_bus_data.raw_data.bytes	= webconfig_easymesh_raw_data_ptr;
	l_bus_data.raw_data_len = strlen(webconfig_easymesh_raw_data_ptr);

	if (desc->bus_set_fn(bus_hdl, "Device.WiFi.WebConfig.Data.Subdoc.South", &l_bus_data)== 0) {
		printf("%s:%d Radio subdoc send successfull\n",__func__, __LINE__);
	}
	else {
		printf("%s:%d Radio subdoc send fail\n",__func__, __LINE__);
		return -1;
	}

	return 1;
}

webconfig_error_t dm_easy_mesh_agent_t::webconfig_dummy_apply(webconfig_subdoc_t *doc, webconfig_subdoc_data_t *data)
{       
    return webconfig_error_none;
}   

dm_easy_mesh_agent_t::dm_easy_mesh_agent_t()
{

}

dm_easy_mesh_agent_t::~dm_easy_mesh_agent_t()
{

}
