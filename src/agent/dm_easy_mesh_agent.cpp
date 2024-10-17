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

int dm_easy_mesh_agent_t::analyze_dev_init(em_bus_event_t *evt, em_cmd_t *pcmd[])
{
    unsigned int index = 0;
    unsigned int num = 0, i, j = 0, num_radios = 0;
    em_orch_desc_t desc;
    dm_easy_mesh_agent_t  dm;
    dm_device_t *dev, *tgt_dev;
    dm_radio_t *rd, *tgt_rd;
    em_cmd_t *tmp;
    printf("%s:%d: Enter\n", __func__, __LINE__);
    dm.translate_onewifi_dml_data(evt->u.raw_buff);

    num_radios = dm.get_num_radios();
    printf("%s:%d: Number of radios: %d\n", __func__, __LINE__, num_radios);
    dev = dm.get_device();
    tgt_dev = find_matching_device(dev);
    if (tgt_dev != NULL) {
        desc.op = dm_orch_type_em_update;
    } else {
        desc.op = dm_orch_type_al_insert;
    }

    pcmd[num] = new em_cmd_dev_init_t(evt->params,dm);
    //pcmd[num]->init(&dm);
    pcmd[num]->override_op(pcmd[num]->get_orch_op_index(), &desc);
    printf("%s:%d: Orch op :%s\n", __func__, __LINE__, em_cmd_t::get_orch_op_str(pcmd[num]->get_orch_op()));
    tmp = pcmd[num];
    num++;

    while ((pcmd[num] = tmp->clone_for_next()) != NULL) {
        //pcmd[num]->init(&dm);
        if (pcmd[num]->get_orch_op() == dm_orch_type_em_insert) {
            i = 0;
            do {
                rd = dm.get_radio(i);
                tgt_rd = find_matching_radio(rd);
                if (tgt_rd != NULL) {
                    desc.op = dm_orch_type_em_update;
                } else {
                    desc.op = dm_orch_type_em_insert;
                }
                index = pcmd[num]->m_data_model.get_cmd_ctx()->arr_index;
                pcmd[num]->m_data_model.m_radio[index] = dm.m_radio[i];

                pcmd[num]->override_op(pcmd[num]->get_orch_op_index(), &desc);
                printf("%s:%d: Orch op :%s\n", __func__, __LINE__, em_cmd_t::get_orch_op_str(pcmd[num]->get_orch_op()));
                pcmd[num]->set_rd_freq_band(j);
                j++;
                tmp = pcmd[num]; i++; num++;
                if (i < num_radios) {
                    pcmd[num] = tmp->clone();
                   //pcmd[num]->init(&dm);
                }
            } while (i < num_radios);
        } else if ((pcmd[num]->get_orch_op() == dm_orch_type_owconfig_req) || (pcmd[num]->get_orch_op() == dm_orch_type_owconfig_cnf)) {
            i = 0;
            do {
                //printf("%s:%d: Orch op :%s\n", __func__, __LINE__, em_cmd_t::get_orch_op_str(pcmd[num]->get_orch_op()));
                tmp = pcmd[num]; i++; num++;
                if (i < num_radios) {
                    pcmd[num] = tmp->clone();
                }
            } while (i < num_radios);
        } else {
            printf("%s:%d: Orch op :%s\n", __func__, __LINE__, em_cmd_t::get_orch_op_str(pcmd[num]->get_orch_op()));
            tmp = pcmd[num];
            num++;
        }
    }

    return num;
}

int dm_easy_mesh_agent_t::analyze_sta_list(em_bus_event_t *evt, em_cmd_t *pcmd[])
{
    unsigned int index = 0;
    unsigned int num = 0, i, j = 0, num_radios = 0;
    em_orch_desc_t desc;
    dm_device_t *dev, *tgt_dev;
    dm_radio_t *rd, *tgt_rd;
    em_cmd_t *tmp;

    printf("%s:%d: -------Enterstr=%s\n", __func__, __LINE__,evt->u.raw_buff);

    translate_onewifi_stats_data(evt->u.raw_buff);

#if 0
    desc.op = dm_orch_type_sta_update;
    //pcmd[0] =  new em_cmd_sta_list_t(evt->params,dm);
    pcmd[0] =  new em_cmd_sta_list_t(evt->params,*this);
    pcmd[0]->override_op(0, &desc);
#endif
    desc.op = dm_orch_type_sta_update;

    dm_easy_mesh_agent_t  *dm = this;
    dm_easy_mesh_agent_t* dm_pcmd = new dm_easy_mesh_agent_t[2];

    hash_map_t **ptr_sta_map = dm->get_assoc_sta_map();
    //put hash_map for dm_pcmd from this object
    mac_address_t radio_macaddr, temp_rmacaddr;
    dm_sta_t *get_sta = NULL;
    //dm_sta_t *pcmd_get_sta = NULL;

    std::unordered_map<std::string, int> mac_to_index_map; // To map MAC addresses to pcmd instances and their indices
    int count = 0;
    
    if ((ptr_sta_map != NULL) && (*ptr_sta_map != NULL)) {

        get_sta = (dm_sta_t *)hash_map_get_first(*ptr_sta_map);

        while (get_sta != NULL) {
             printf("\n\nWhile: Index>>>>>>>>>>>> %d\n", count);
            dm_sta_t put_sta;// = NULL;// = *get_sta;

            memcpy(&temp_rmacaddr, put_sta.get_sta_info()->radiomac, 6);

    	    memcpy(&radio_macaddr, get_sta->get_sta_info()->radiomac, sizeof(mac_address_t));

            std::string mac_str(reinterpret_cast<char*>(&radio_macaddr), sizeof(mac_address_t));
            if ((mac_to_index_map.find(mac_str) == mac_to_index_map.end()) == true)
            {
                //returned true, means its a new rmac and was not processed earlier
                //so use a new dm object, as in new hash_map.
                mac_addr_str_t dst_mac_str;
                dm_easy_mesh_t::macbytes_to_string(radio_macaddr, dst_mac_str);
                printf("%s:%d radio_macaddr MAC=%s\n", __func__, __LINE__,dst_mac_str);
                dm_easy_mesh_t::macbytes_to_string(temp_rmacaddr, dst_mac_str);
                printf("%s:%d &temp_rmacaddr MAC=%s\n", __func__, __LINE__,dst_mac_str);
                if (memcmp(&radio_macaddr, &temp_rmacaddr, sizeof(mac_address_t)) == 0) {
                    index = index + 1;
                    mac_to_index_map[mac_str] = index; // Map the MAC address to the index
                    count = mac_to_index_map[mac_str];
                    //printf("if-if case\n");
                } else {
                    //printf("if-else case\n");
                    mac_to_index_map[mac_str] = index; // Map the MAC address to the index
                    //index = index +1;
                    count = mac_to_index_map[mac_str];
                }
                hash_map_t **put_hm = dm_pcmd[count].get_assoc_sta_map();
                if(*put_hm == NULL)
                {

                    *put_hm = hash_map_create();
                }
                //printf("WHILE: put_hm %p and **put_hm %p\n", *put_hm, **put_hm);
                em_sta_info_t *em_sta;
                em_sta = get_sta->get_sta_info();
                hash_map_put(*put_hm, strdup(put_sta.get_sta_info()->m_sta_key), new dm_sta_t(em_sta));
            }
            else
            {
                printf("Else-case: new mac found\n");
                // Use the existing index for this MAC address
                // since it already has an index, get the index based on rmac to push to same hash_map
                count = mac_to_index_map[mac_str];
                hash_map_t **put_hm = dm_pcmd[count].get_assoc_sta_map();
                if(*put_hm == NULL)
                {

                    *put_hm = hash_map_create();
                }
                //printf("WHILE: put_hm %p and **put_hm %p\n", *put_hm, **put_hm);
                em_sta_info_t *em_sta;
                em_sta = get_sta->get_sta_info();
                hash_map_put(*put_hm, strdup(put_sta.get_sta_info()->m_sta_key), new dm_sta_t(em_sta));
            }

            //printf(">>>>>> for putS-ta obj signal_strength %d\n", put_sta.m_sta_info.signal_strength);
            mac_addr_str_t  rad_str_mac;
            macbytes_to_string(radio_macaddr, rad_str_mac);
            //printf(">>>>>> radio mac %s and count %d\n", rad_str_mac, count);

            get_sta = (dm_sta_t *)hash_map_get_next(*ptr_sta_map, get_sta);
        }
        printf("DM objects created\n");
    }

    //pcmd cmd create code
    //printf("\nPut now , index val %d and count val %d\n", index, count);
    for(int i = 0; i <= count; i++)
    {
        hash_map_t **test_map = dm_pcmd[i].get_assoc_sta_map();
        //push all in a loop now for the number of indexes
        //printf("create cmd\n");
        pcmd[i] = new em_cmd_sta_list_t(evt->params, dm_pcmd[i]);
        pcmd[i]->override_op(0, &desc);
        printf("Pushed to PCMD for index %d\n",i );
    }

    return 1;
}

void dm_easy_mesh_agent_t::translate_onewifi_dml_data (char *str)
{           
    webconfig_t config;
    webconfig_external_easymesh_t ext;
    webconfig_subdoc_type_t type;
    int num_radios,num_op,num_bss;
    unsigned int i = 0;
                
    webconfig_proto_easymesh_init(&ext, this, get_num_radios, set_num_radios, 
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
    
int dm_easy_mesh_agent_t::analyze_onewifi_private_subdoc(em_bus_event_t *evt, wifi_bus_desc_t *desc,bus_handle_t *bus_hdl)
{
    dm_orch_type_t op;
    em_subdoc_info_t *subdoc;
    unsigned int num_radios;
    subdoc = &evt->u.subdoc;
    em_event_t bus;
    webconfig_external_easymesh_t dev_data;
    webconfig_subdoc_type_t type = webconfig_subdoc_type_private;
    webconfig_apply_data_t temp;
    webconfig_t config;
    static char *webconfig_easymesh_raw_data_ptr;
    dm_easy_mesh_agent_t  dm;
    raw_data_t l_bus_data;
    unsigned int index = 0;
    raw_data_t data;

    printf("%s:%d: Enter\n", __func__, __LINE__);
    if ( dm.decode_config(subdoc, "dm_cache") == -1) {
        printf("%s:%d: Failed to decode\n", __func__, __LINE__);
        return 0;
    }
    num_radios = dm.get_num_radios();
    printf("%s:%d: Number of radios: %d\n", __func__, __LINE__, num_radios);
    memset(&data, 0, sizeof(raw_data_t));

    webconfig_proto_easymesh_init(&dev_data, &dm, get_num_radios, set_num_radios, 
				get_num_op_class, set_num_op_class, get_num_bss, set_num_bss,
				get_device_info, get_network_info, get_radio_info, get_ieee_1905_security_info, get_bss_info, get_op_class_info,
				get_first_sta_info, get_next_sta_info, get_sta_info, put_sta_info);

    config.initializer = webconfig_initializer_onewifi;
    config.apply_data =  webconfig_dummy_apply;

    if (webconfig_init(&config) != webconfig_error_none) {
        printf( "[%s]:%d Init WiFi Web Config  fail\n",__func__,__LINE__);
        return 0;
    }

    printf("%s:%d New configuration SSID=%s Security mode=%d  passphrase=%s \n",__func__,__LINE__,
	    dm.get_bss(index)->get_bss_info()->ssid,dm.get_bss(index)->get_bss_info()->sec_mode,dm.get_bss(index)->get_bss_info()->passphrase);

    if ((webconfig_easymesh_encode(&config, &dev_data, type, &webconfig_easymesh_raw_data_ptr )) == webconfig_error_none) {
        printf("%s:%d Private subdoc encode success %s\n",__func__, __LINE__,webconfig_easymesh_raw_data_ptr);
    } else {
        printf("%s:%d Private subdoc encode fail\n",__func__, __LINE__);
        return 0;
    }
    memset(&l_bus_data, 0, sizeof(raw_data_t));

    l_bus_data.data_type    = bus_data_type_bytes;
    l_bus_data.raw_data.bytes   = webconfig_easymesh_raw_data_ptr;
    l_bus_data.raw_data_len = strlen(webconfig_easymesh_raw_data_ptr);
    if (desc->bus_set_fn(bus_hdl, "Device.WiFi.WebConfig.Data.Subdoc.South", &l_bus_data)== 0) {
	printf("%s:%d private subdoc send successfull\n",__func__, __LINE__);
	printf("%s:%d Before commit config SSID=%s Security mode=%d  passphrase=%s \n",__func__,__LINE__,
		get_bss(index)->get_bss_info()->ssid,get_bss(index)->get_bss_info()->sec_mode,get_bss(index)->get_bss_info()->passphrase);
        commit_config(dm,index,index);//Private vap will always be first index
	printf("%s:%d After commit SSID=%s Security mode=%d  passphrase=%s \n",__func__,__LINE__,get_bss(index)->get_bss_info()->ssid,
		get_bss(index)->get_bss_info()->sec_mode,get_bss(index)->get_bss_info()->passphrase);
    }
    else {
	printf("%s:%d private subdoc send fail\n",__func__, __LINE__);
	return -1;
    }
    return 1;
}
        
void dm_easy_mesh_agent_t::translate_onewifi_sta_data(char *str)
{               
                
}               
                    
void dm_easy_mesh_agent_t::translate_onewifi_stats_data(char *str)
{
    printf("---------translate_onewifi_stats_data %s\n",str);

    webconfig_t config;
    webconfig_external_easymesh_t extdata = {0};
    webconfig_subdoc_type_t type;
    //declare dm = this;

    webconfig_proto_easymesh_init(&extdata, this, get_num_radios, set_num_radios, 
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
        printf("%s:%d Dev-Init decode success\n",__func__, __LINE__);
    } else {
        printf("%s:%d Dev-Init decode fail\n",__func__, __LINE__);
    }
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
