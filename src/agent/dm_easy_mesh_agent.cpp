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
#include "ieee80211.h"
#include "em_cmd_sta_list.h"
#include "em_cmd_onewifi_cb.h"
#include "em_cmd_cfg_renew.h"
#include "em_cmd_channel_pref_query.h"
#include "em_cmd_op_channel_report.h"
#include "em_cmd_btm_report.h"

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
            if (memcmp(sta->get_sta_info()->radiomac, get_radio_by_ref(i).get_radio_interface_mac(), sizeof(mac_address_t)) != 0) {
                sta = (dm_sta_t *)hash_map_get_next(dm.m_sta_assoc_map, sta);
                continue;
            }

            dm_easy_mesh_t::macbytes_to_string(sta->m_sta_info.id, sta_mac_str);
            dm_easy_mesh_t::macbytes_to_string(sta->m_sta_info.bssid, bss_mac_str);
            dm_easy_mesh_t::macbytes_to_string(sta->m_sta_info.radiomac, radio_mac_str);
            snprintf(key, sizeof(em_long_string_t), "%s@%s@%s", sta_mac_str, bss_mac_str, radio_mac_str);
            hash_map_put(pcmd[num]->m_data_model.m_sta_assoc_map, strdup(key), new dm_sta_t(*sta));
            sta = (dm_sta_t *)hash_map_get_next(dm.m_sta_assoc_map, sta);
        }

        sta = (dm_sta_t *)hash_map_get_first(dm.m_sta_dassoc_map);
        while(sta != NULL) {
            if (memcmp(sta->get_sta_info()->radiomac, get_radio_by_ref(i).get_radio_interface_mac(), sizeof(mac_address_t)) != 0) {
                sta = (dm_sta_t *)hash_map_get_next(dm.m_sta_dassoc_map, sta);
                continue;
             }

            dm_easy_mesh_t::macbytes_to_string(sta->m_sta_info.id, sta_mac_str);
            dm_easy_mesh_t::macbytes_to_string(sta->m_sta_info.bssid, bss_mac_str);
            dm_easy_mesh_t::macbytes_to_string(sta->m_sta_info.radiomac, radio_mac_str);
            snprintf(key, sizeof(em_long_string_t), "%s@%s@%s", sta_mac_str, bss_mac_str, radio_mac_str);
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
    unsigned int index = 0;
    em_cmd_t *tmp;

    raw = (em_bus_event_type_cfg_renew_params_t *)evt->u.raw_buff;
    memcpy(dm.get_controller_interface_mac(), raw->ctrl_src, sizeof(mac_address_t));
    memcpy(dm.get_radio(index)->get_radio_info()->id.mac,raw->radio, sizeof(mac_address_t));
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
            get_device_info, get_network_info, get_radio_info, get_ieee_1905_security_info, get_bss_info, get_op_class_info, 
			get_first_sta_info, get_next_sta_info, get_sta_info, put_sta_info, get_bss_info_with_mac);
    
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
    webconfig_subdoc_type_t type;
    webconfig_apply_data_t temp;
    webconfig_t config;
    static char *webconfig_easymesh_raw_data_ptr;
    dm_easy_mesh_agent_t  dm = *this;
    raw_data_t l_bus_data;
    unsigned int index = 0;
    m2ctrl_vapconfig *vapconfig;
    m2ctrl_vapconfig m2ctrl;
	em_freq_band_t freq_band;
	mac_addr_str_t mac_str;

    vapconfig = (m2ctrl_vapconfig *)evt->u.raw_buff;
	freq_band = vapconfig->freq;
	if (freq_band == em_freq_band_24) {
		type = webconfig_subdoc_type_vap_24G;
	} else if (vapconfig->freq == em_freq_band_5) {
		type = webconfig_subdoc_type_vap_5G;
	} else {
		type = webconfig_subdoc_type_vap_6G;
	}
    memcpy(m2ctrl.ssid, vapconfig->ssid, sizeof(m2ctrl.ssid));
    m2ctrl.authtype = vapconfig->authtype;
    memcpy(m2ctrl.password, vapconfig->password, sizeof(m2ctrl.password));
    m2ctrl.enable = vapconfig->enable;
	memcpy(m2ctrl.mac, vapconfig->mac, sizeof(mac_address_t));
	printf("%s:%d New configuration SSID=%s Security mode=%d  passphrase=%s radiomac=%s\n",
		__func__,__LINE__, m2ctrl.ssid, m2ctrl.authtype, m2ctrl.password, mac_str);

    webconfig_proto_easymesh_init(&dev_data, &dm, &m2ctrl, get_num_radios, set_num_radios,
                                get_num_op_class, set_num_op_class, get_num_bss, set_num_bss,
                                get_device_info, get_network_info, get_radio_info, get_ieee_1905_security_info, get_bss_info, get_op_class_info,
                                get_first_sta_info, get_next_sta_info, get_sta_info, put_sta_info, get_bss_info_with_mac);

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
    unsigned int i = 0, j = 0, index = 0;
    dm_easy_mesh_agent_t  dm;
    em_cmd_t *tmp;
	mac_addr_str_t mac_str;
	em_commit_target_t cm_config;
    webconfig_proto_easymesh_init(&ext, &dm, NULL, get_num_radios, set_num_radios,
            get_num_op_class, set_num_op_class, get_num_bss, set_num_bss,
            get_device_info, get_network_info, get_radio_info, get_ieee_1905_security_info, get_bss_info, 
			get_op_class_info, get_first_sta_info, get_next_sta_info, get_sta_info, put_sta_info, get_bss_info_with_mac);
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

	dm_easy_mesh_t::macbytes_to_string(dm.get_bss(index)->get_bss_info()->ruid.mac, mac_str);
	snprintf((char *)cm_config.params,sizeof(cm_config.params),(char*)"%s",mac_str);
	cm_config.type = em_commit_target_bss;
	commit_config(dm, cm_config);
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
    unsigned int i = 0, j = 0, index = 0;
    dm_easy_mesh_agent_t  dm;
    em_cmd_t *tmp;
    em_commit_target_t cm_config;

    webconfig_proto_easymesh_init(&ext, &dm, NULL, get_num_radios, set_num_radios,
            get_num_op_class, set_num_op_class, get_num_bss, set_num_bss,
            get_device_info, get_network_info, get_radio_info, get_ieee_1905_security_info, get_bss_info, get_op_class_info, 
			get_first_sta_info, get_next_sta_info, get_sta_info, put_sta_info, get_bss_info_with_mac);

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

	dm_easy_mesh_t::macbytes_to_string(dm.get_radio(index)->get_radio_info()->id.mac, mac_str);
	cm_config.type = em_commit_target_radio;
	snprintf((char *)cm_config.params,sizeof(cm_config.params),(char*)"%s",mac_str);
	commit_config(dm, cm_config);
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
			get_first_sta_info, get_next_sta_info, get_sta_info, put_sta_info, get_bss_info_with_mac);

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
    pcmd[num] = new em_cmd_channel_pref_query_t(em_service_type_agent, evt->params, dm);
    num++;

    return num;
}

int dm_easy_mesh_agent_t::analyze_channel_sel_req(em_bus_event_t *evt, wifi_bus_desc_t *desc,bus_handle_t *bus_hdl)
{
	em_event_t bus;
	webconfig_external_easymesh_t dev_data;
	webconfig_subdoc_type_t type;
	webconfig_apply_data_t temp;
	webconfig_t config;
	static char *webconfig_easymesh_raw_data_ptr;
	dm_easy_mesh_agent_t  dm = *this;
	raw_data_t l_bus_data;
	unsigned int index = 0, i = 0, noofopclass = 0, j = 0, k = 0, l = 0;
	mac_addr_str_t mac_str;
	op_class_channel_sel *channel_sel;
	em_op_class_info_t *dm_op_class;
	em_tx_power_limit_t	*tx_power_limit;
	em_spatial_reuse_req_t *spatial_reuse_req;
    em_eht_operations_t *eht_ops;

	channel_sel = (op_class_channel_sel*) evt->u.raw_buff;
	printf("%s:%d No of opclass=%d tx=%d\n", __func__, __LINE__,channel_sel->num, channel_sel->tx_power);
	tx_power_limit = (em_tx_power_limit_t*) &channel_sel->tx_power;
	spatial_reuse_req = (em_spatial_reuse_req_t*) &channel_sel->spatial_reuse_req;
    eht_ops = (em_eht_operations_t*) &channel_sel->eht_ops;

	noofopclass = dm.get_num_op_class();

	if (channel_sel->freq_band == em_freq_band_24) {
		type = webconfig_subdoc_type_radio_24G;
	} else if (channel_sel->freq_band == em_freq_band_5) {
		type = webconfig_subdoc_type_radio_5G;
	} else {
		type = webconfig_subdoc_type_radio_6G;
	}

	//TODO Select the right op class and number and configure
	for (i = 0; i < noofopclass; i++) {
		dm_op_class = dm.get_op_class_info(i);
		if ((memcmp(&dm_op_class->id.ruid, &channel_sel->op_class_info[0].id.ruid, sizeof(mac_address_t)) == 0) && 
			(dm_op_class->id.type == channel_sel->op_class_info[0].id.type)) {
			dm_op_class->channel =  channel_sel->op_class_info[0].channels[0];
			dm_op_class->op_class = channel_sel->op_class_info[0].op_class;
		break;
		}
	}
	if (i == noofopclass) {
		dm_op_class = dm.get_op_class_info(i);
		memcpy(dm_op_class, &channel_sel->op_class_info[i], sizeof(em_op_class_info_t));
		dm_op_class->channel = channel_sel->op_class_info[0].channels[0];
		dm_op_class->op_class = channel_sel->op_class_info[0].op_class;
		noofopclass++;
	}
	dm.set_num_op_class(noofopclass);
    
	if(tx_power_limit->tx_power_eirp != 0) {
		dm_radio_t* radio = dm.get_radio(tx_power_limit->ruid);
		em_radio_info_t* radio_info = radio->get_radio_info();
		radio_info->transmit_power_limit = tx_power_limit->tx_power_eirp;
	}

    dm_radio_t* radio = dm.get_radio(spatial_reuse_req->ruid);
    em_radio_info_t* radio_info = radio->get_radio_info();
    radio_info->bss_color = spatial_reuse_req->bss_color;
    radio_info->hesiga_spatial_reuse_value15_allowed = spatial_reuse_req->hesiga_spatial_reuse_value15_allowed;
    radio_info->srg_information_valid = spatial_reuse_req->srg_info_valid;
    radio_info->non_srg_offset_valid = spatial_reuse_req->non_srg_offset_valid;
    radio_info->psr_disallowed = spatial_reuse_req->psr_disallowed;
    radio_info->non_srg_obsspd_max_offset = spatial_reuse_req->non_srg_obsspd_max_offset;
    radio_info->srg_obsspd_min_offset = spatial_reuse_req->srg_obsspd_min_offset;
    radio_info->srg_obsspd_max_offset = spatial_reuse_req->srg_obsspd_max_offset;
    memcpy(radio_info->srg_bss_color_bitmap, spatial_reuse_req->srg_bss_color_bitmap, sizeof(radio_info->srg_bss_color_bitmap));
    memcpy(radio_info->srg_partial_bssid_bitmap, spatial_reuse_req->srg_partial_bssid_bitmap, sizeof(radio_info->srg_partial_bssid_bitmap));   

#ifdef REL_6_FEATURE
    bool found_radio = false;
    bool found_bss = false;
    for (i = 0; i < eht_ops->radios_num; i++) {
        for (j = 0; j < dm.get_num_radios(); j++) {
            if (memcmp(eht_ops->radios[i].ruid, dm.m_radio[j].m_radio_info.id.mac, sizeof(mac_address_t)) == 0) {
                found_radio = true;
                break;
            }
            if (found_radio == false) {
                // do not update anything and retrun error
                return -1;
            }
        }
        found_radio = false;

        for(k = 0; k < eht_ops->radios[i].bss_num; k++) {
            for(l = 0; l < dm.get_num_bss(); l++) {
                if (memcmp(eht_ops->radios[i].bss, dm.m_bss[j].m_bss_info.bssid.mac, sizeof(mac_address_t)) == 0) {
                    found_bss = true;
                    break;
                }
                if (found_bss == false) {
                    // do not update anything and retrun error
                    return -1;
                }
            }
            found_bss = false;
            memcpy(&dm.m_bss[j].get_bss_info()->eht_ops, &eht_ops->radios[i].bss[k], sizeof(em_eht_operations_bss_t));
        }
    }
#endif 
    webconfig_proto_easymesh_init(&dev_data, &dm, NULL, get_num_radios, set_num_radios,
			get_num_op_class, set_num_op_class, get_num_bss, set_num_bss,
			get_device_info, get_network_info, get_radio_info, get_ieee_1905_security_info, get_bss_info, get_op_class_info, 
			get_first_sta_info, get_next_sta_info, get_sta_info, put_sta_info, get_bss_info_with_mac);

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

int dm_easy_mesh_agent_t::analyze_sta_link_metrics(em_bus_event_t *evt, em_cmd_t *pcmd[])
{
    dm_sta_t *sta = NULL;
    em_cmd_t *tmp = NULL;
    em_sta_info_t *em_sta = NULL;
    em_long_string_t key;
    mac_addr_str_t radio_str;
    em_cmd_params_t *evt_param = NULL;
    mac_addr_str_t  sta_mac_str, bss_mac_str, radio_mac_str;

    webconfig_t config;
    webconfig_external_easymesh_t extdata = {0};
    webconfig_subdoc_type_t type = webconfig_subdoc_type_assocdev_stats;

    webconfig_proto_easymesh_init(&extdata, this, NULL, get_num_radios, set_num_radios,
            get_num_op_class, set_num_op_class, get_num_bss, set_num_bss,
            get_device_info, get_network_info, get_radio_info, get_ieee_1905_security_info, get_bss_info, get_op_class_info,
			get_first_sta_info, get_next_sta_info, get_sta_info, put_sta_info, get_bss_info_with_mac);

    config.initializer = webconfig_initializer_onewifi;
    config.apply_data =  webconfig_dummy_apply;

    if (webconfig_init(&config) != webconfig_error_none) {
        printf( "[%s]:%d Init WiFi Web Config  fail\n",__func__,__LINE__);
        return 0;
    }

    if ((webconfig_easymesh_decode(&config, (char *)evt->u.raw_buff, &extdata, &type)) == webconfig_error_none) {
        printf("%s:%d assoc sta Link metrics decode success\n",__func__, __LINE__);
    } else {
        printf("%s:%d assoc sta link metrics decode fail\n",__func__, __LINE__);
    }

    return 1;
}

int dm_easy_mesh_agent_t::analyze_btm_request_action_frame(em_bus_event_t *evt, wifi_bus_desc_t *desc, bus_handle_t *bus_hdl)
{
    struct ieee80211_mgmt *ieeeframe;
    action_frame_params_t *aframe;
    raw_data_t l_bus_data;
    int len = 0;
    mac_addr_str_t mac_str;
    em_steering_req_t *steer_req = (em_steering_req_t *)&evt->u.raw_buff;

    len = sizeof(ieeeframe->u.action.category) + sizeof(ieeeframe->u.action.u.bss_tm_req) \
        + sizeof(em_80211_neighbor_report_t);
    aframe = (action_frame_params_t *)malloc(sizeof(action_frame_params_t) + len);
    // Point ieeeframe to aframe->frame_data
    ieeeframe = (struct ieee80211_mgmt *)aframe->frame_data;

    //convert steering req to 802.11 bss tm req
    ieeeframe->u.action.category = WLAN_ACTION_WNM;
    ieeeframe->u.action.u.bss_tm_req.action = WLAN_ACTION_HT;
    ieeeframe->u.action.u.bss_tm_req.dialog_token = 1;

    em_80211_btm_req_reqmode_t req_mode;
    req_mode.pref_candidate_list_inc = 0;
    req_mode.btm_abridged = steer_req->btm_abridged;
    req_mode.btm_disassoc_imminent = steer_req->btm_dissoc_imminent;
    //todo: check what is this
    req_mode.bss_termination_inc = steer_req->btm_dissoc_timer;
    //todo: check what is this
    req_mode.ess_disassoc_imminent = steer_req->btm_dissoc_imminent;

    ieeeframe->u.action.u.bss_tm_req.req_mode = *(uint8_t *)&req_mode;
    memcpy(&ieeeframe->u.action.u.bss_tm_req.disassoc_timer, &steer_req->btm_dissoc_timer, sizeof(steer_req->btm_dissoc_timer));
    //todo: check this
    ieeeframe->u.action.u.bss_tm_req.validity_interval = 0;

    // Copy the variable part
    em_80211_btm_req_var_t *bss_list = (em_80211_btm_req_var_t *)&ieeeframe->u.action.u.bss_tm_req.variable;
    bss_list->bss_transition_cand_list[0].elem_id = 52;
    bss_list->bss_transition_cand_list[0].length = 13;
    memcpy(bss_list->bss_transition_cand_list[0].bssid, steer_req->target_bssids, sizeof(bssid_t));
    //todo: capabilities mapping tbd
    bss_list->bss_transition_cand_list[0].bssid_info = 0;
        bss_list->bss_transition_cand_list[0].op_class = steer_req->target_bss_op_class;
    bss_list->bss_transition_cand_list[0].channel_num = steer_req->target_bss_channel_num;
    //todo: check how to get this
    bss_list->bss_transition_cand_list[0].phy_type = 0;

    dm_easy_mesh_t::macbytes_to_string(steer_req->sta_mac_addr, mac_str);
    printf("%s:%d STA MAC for BTM request %s\n", __func__, __LINE__, mac_str);
    memcpy(aframe->dest_addr, steer_req->sta_mac_addr, sizeof(mac_addr_t));
    aframe->frequency = 2412;
    aframe->ap_index = 0;
    //here sendng only the btm_req union to onewifi as header is dealt internally
    aframe->frame_len = len;
    memcpy(aframe->frame_data, &ieeeframe->u.action, len);

    l_bus_data.data_type = bus_data_type_bytes;
    l_bus_data.raw_data.bytes = (void *)aframe;
    l_bus_data.raw_data_len = len + sizeof(action_frame_params_t);

    if (desc->bus_set_fn(bus_hdl, "Device.WiFi.AccessPoint.1.RawFrame.Mgmt.Action.Tx", &l_bus_data)== 0) {
        printf("%s:%d Frame subdoc send successfull\n",__func__, __LINE__);
    }
    else {
        printf("%s:%d Frame subdoc send fail\n",__func__, __LINE__);
        return -1;
    }

    return 1;
}

int dm_easy_mesh_agent_t::analyze_btm_response_action_frame(em_bus_event_t *evt, em_cmd_t *pcmd[])
{
    //TODO: if callback would give for multiple entries or one by one
    dm_easy_mesh_agent_t  dm;
    em_cmd_t *tmp;
    em_cmd_params_t *evt_param;
    int num = 0;
    em_steering_btm_rprt_t btm;
    mac_addr_str_t mac_str;
    struct ieee80211_mgmt *btm_frame = (struct ieee80211_mgmt *)&evt->u.raw_buff;

    em_cmd_btm_report_params_t  btm_report_param;
    memcpy(btm_report_param.source, btm_frame->bssid, sizeof(mac_addr_t));
    memcpy(btm_report_param.sta_mac, btm_frame->sa, sizeof(mac_addr_t));
    btm_report_param.status_code = btm_frame->u.action.u.bss_tm_resp.status_code;
    memcpy(btm_report_param.target, &btm_frame->u.action.u.bss_tm_resp.variable, sizeof(mac_addr_t));

    pcmd[num] = new em_cmd_btm_report_t(btm_report_param);
    tmp = pcmd[num];
    num++;

    while ((pcmd[num] = tmp->clone_for_next()) != NULL) {
        tmp = pcmd[num];
        num++;
    }

    return num;
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
