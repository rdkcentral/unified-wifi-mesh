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
#include <openssl/rand.h>
#include <assert.h>
#include "em_configuration.h"
#include "em_msg.h"
#include "dm_easy_mesh.h"
#include "em_cmd.h"
#include "util.h"
#include "em_crypto.h"
#include "em.h"
#include "em_cmd_exec.h"

// Initialize the static member variables
unsigned short em_configuration_t::msg_id = 0;

/* Extract N bytes (ignore endianess) */
static inline void _EnB(uint8_t **packet_ppointer, void *memory_pointer, uint32_t n)
{
    memcpy(memory_pointer, *packet_ppointer, n);
    (*packet_ppointer) += n;
}

void print_errors_array(char** errors)
{
    for (int i = 0; i < EM_MAX_TLV_MEMBERS; i++) {
        if (errors[i] != NULL) {
            printf("Failed TLV [%d]: %s\n",(i+1),errors[i]);
        }
    }
}
short em_configuration_t::create_ap_radio_basic_cap(unsigned char *buff)
{
    short len = 0;
    em_ap_radio_basic_cap_t *cap = (em_ap_radio_basic_cap_t *)buff;
    memcpy(&cap->ruid, get_radio_interface_mac(), sizeof(mac_address_t));
    len += sizeof(mac_address_t);

    em_interface_t* radio_interface = get_radio_interface();
    rdk_wifi_radio_t* radio_data = get_current_cmd()->get_radio_data(radio_interface);
    if (radio_data != NULL)
        cap->num_bss = radio_data->vaps.num_vaps;
    cap->num_bss = 1;

    len += 1;
    cap->op_class_num= 1;
    len += 1;

    cap->op_classes[0].op_class = get_current_cmd()->get_rd_op_class();
    len += 1;
    cap->op_classes[0].channels.num = 1;
    len += 1;
    cap->op_classes[0].channels.channel[0] = get_current_cmd()->get_rd_channel();
    len += 2;


    return len;
}       

short em_configuration_t::create_client_notify_msg(unsigned char *buff)
{
    short len = 0;
    em_tlv_client_assoc_t *client_info = (em_tlv_client_assoc_t*) buff;
    dm_sta_t *sta;

    hash_map_t **m_sta_assoc_map = get_current_cmd()->get_data_model()->get_assoc_sta_map();

    if ((m_sta_assoc_map != NULL) && (*m_sta_assoc_map != NULL)) {
        sta = (dm_sta_t *)hash_map_get_first(*m_sta_assoc_map);
        if (sta != NULL) {
            memcpy(&client_info->cli_mac_address,&sta->get_sta_info()->id,sizeof(client_info->cli_mac_address));
            len += sizeof(client_info->cli_mac_address);
            memcpy(&client_info->bssid,&sta->get_sta_info()->bssid,sizeof(client_info->bssid));
            len += sizeof(client_info->bssid);
            client_info->assoc_event = 1;
            len+= 1;
            hash_map_remove(*m_sta_assoc_map,sta->get_sta_info()->m_sta_key);
            return len;
        }
    }

    hash_map_t **m_sta_dassoc_map = (hash_map_t**)get_current_cmd()->get_data_model()->get_dassoc_sta_map();

    if ((m_sta_dassoc_map != NULL) && (*m_sta_dassoc_map != NULL)) {
        sta = (dm_sta_t *)hash_map_get_first(*m_sta_dassoc_map);
        if (sta != NULL) {
            memcpy(&client_info->cli_mac_address,&sta->get_sta_info()->id,sizeof(client_info->cli_mac_address));
            len += sizeof(client_info->cli_mac_address);
            memcpy(&client_info->bssid,&sta->get_sta_info()->bssid,sizeof(client_info->bssid));
            len += sizeof(client_info->bssid);
            client_info->assoc_event = 0;
            len+= 1;
            hash_map_remove(*m_sta_dassoc_map,sta->get_sta_info()->m_sta_key);
            return len;
        }
    }
    return len;
}

void em_configuration_t::handle_state_topology_notify()
{
    unsigned char buff[MAX_EM_BUFF_SZ];
    unsigned int sz;
    char* Errors[EM_MAX_TLV_MEMBERS];
    hash_map_t **m_sta_assoc_map = get_current_cmd()->get_data_model()->get_assoc_sta_map();
    hash_map_t **m_sta_dassoc_map = (hash_map_t**)get_current_cmd()->get_data_model()->get_dassoc_sta_map();

    int count = hash_map_count(*m_sta_assoc_map);
    count += hash_map_count(*m_sta_dassoc_map);

    printf("%s:%d Topology notify Client Count=%d\n", __func__, __LINE__,count);
    while (count != 0) {
        sz = create_topology_notify_msg(buff);


        printf("%s:%d: Creation of topology notify size=%d successful\n", __func__, __LINE__,sz);
        // em_msg_t validateObj(em_msg_type_topo_notif,em_profile_type_3,buff,sz);//TODO

        //    if (validateObj.validate(Errors)) //TODO
        if (1) {
            if (send_frame(buff, sz)  < 0) {
                printf("%s:%d: failed, err:%d\n", __func__, __LINE__, errno);
                return;
            }
            printf("%s:%d: Topology notify send successful\n", __func__, __LINE__);
        }
        count = hash_map_count(*m_sta_assoc_map);
        count += hash_map_count(*m_sta_dassoc_map);
        printf("%s:%d Topology notify Client Count=%d\n", __func__, __LINE__,count);
        sz = 0;
        memset(buff,0,MAX_EM_BUFF_SZ);
    }
    set_state(em_state_agent_config_complete);
}


int em_configuration_t::create_topology_notify_msg(unsigned char *buff)
{
    unsigned short  msg_id = em_msg_type_topo_notif;
    int len = 0;
    int sz = 0;
    em_cmdu_t *cmdu;
    em_tlv_t *tlv;
    unsigned char *tmp = buff;
    unsigned short type = htons(ETH_P_1905);
    mac_address_t   multi_addr = {0x01, 0x80, 0xc2, 0x00, 0x00, 0x13};

    memcpy(tmp, (unsigned char *)multi_addr, sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += sizeof(mac_address_t);

    memcpy(tmp, get_current_cmd()->get_al_interface_mac(), sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += sizeof(mac_address_t);

    memcpy(tmp, (unsigned char *)&type, sizeof(unsigned short));
    tmp += sizeof(unsigned short);
    len += sizeof(unsigned short);

    cmdu = (em_cmdu_t *)tmp;

    memset(tmp, 0, sizeof(em_cmdu_t));
    cmdu->type = htons(msg_id);
    cmdu->id = htons(msg_id);
    cmdu->last_frag_ind = 1;
    cmdu->relay_ind = 1;

    tmp += sizeof(em_cmdu_t);
    len += sizeof(em_cmdu_t);

    // AL MAC Address type TLV
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_al_mac_address;
    tlv->len = htons(sizeof(mac_address_t));
    memcpy(tlv->value,get_current_cmd()->get_al_interface_mac(), sizeof(mac_address_t));

    tmp += (sizeof (em_tlv_t) + sizeof(mac_address_t));
    len += (sizeof (em_tlv_t) + sizeof(mac_address_t));

    // Client Association Event  17.2.20
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_client_assoc_event;
    sz = create_client_notify_msg(tlv->value);
    tlv->len =  htons(sz);

    tmp += (sizeof(em_tlv_t) + sz);
    len += (sizeof(em_tlv_t) + sz);

    // End of message
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += (sizeof (em_tlv_t));

    printf("%s:%d Create topology notification msg successfull\n", __func__, __LINE__);
    return len;
}

short em_configuration_t::create_traffic_separation_policy(unsigned char *buff)
{
    short len = 8;
    return len;
}

short em_configuration_t::create_m2_msg(unsigned char *buff)
{
    data_elem_attr_t *attr;
    short len = 0;
    unsigned char band;
    unsigned short size;
    unsigned char *tmp;
    tmp = buff;
    
    // version
    attr = (data_elem_attr_t *)tmp;
    attr->id = htons(attr_id_version);
    size = 1;
    attr->len = htons(size);
    attr->val[0] = 0x10;
    len += (sizeof(data_elem_attr_t) + size);
    tmp += (sizeof(data_elem_attr_t) + size);
    // message type
    attr = (data_elem_attr_t *)tmp;
    attr->id = htons(attr_id_msg_type);
    size = 1;
    attr->len = htons(size);
    attr->val[0] = em_wsc_msg_type_m2;
    
    len += (sizeof(data_elem_attr_t) + size);
    tmp += (sizeof(data_elem_attr_t) + size);
    // enrollee nonce
    attr = (data_elem_attr_t *)tmp;
    attr->id = htons(attr_id_enrollee_nonce);
    size = sizeof(em_nonce_t);
    attr->len = htons(size);
    get_e_nonce(attr->val);
    
    len += (sizeof(data_elem_attr_t) + size);
    tmp += (sizeof(data_elem_attr_t) + size);
    // registrar nonce
    attr = (data_elem_attr_t *)tmp;
    attr->id = htons(attr_id_registrar_nonce);
    size = sizeof(em_nonce_t);
    attr->len = htons(size);
    get_r_nonce(attr->val);
    len += (sizeof(data_elem_attr_t) + size);
    tmp += (sizeof(data_elem_attr_t) + size);
    // uuid-r
    attr = (data_elem_attr_t *)tmp;
    attr->id = htons(attr_id_uuid_r);
    size = sizeof(uuid_t);
    attr->len = htons(size);
    get_r_uuid(attr->val);
    
    len += (sizeof(data_elem_attr_t) + size);
    tmp += (sizeof(data_elem_attr_t) + size);
    // registrar public key 
    attr = (data_elem_attr_t *)tmp;
    attr->id = htons(attr_id_public_key);
    size = get_r_public_len();
    attr->len = htons(size);
    memcpy(attr->val, get_r_public(), size);
    len += (sizeof(data_elem_attr_t) + size);
    tmp += (sizeof(data_elem_attr_t) + size);
    // auth type flags  
    attr = (data_elem_attr_t *)tmp;
    attr->id = htons(attr_id_auth_type_flags);
    size = sizeof(unsigned short);
    attr->len = htons(size);
    //memcpy(attr->val, &get_device_info()->sec_1905.auth_flags, size);
    
    len += (sizeof(data_elem_attr_t) + size);
    tmp += (sizeof(data_elem_attr_t) + size);
    // encryption type flags
    attr = (data_elem_attr_t *)tmp;
    attr->id = htons(attr_id_encryption_type_flags);
    size = sizeof(unsigned short);
    attr->len = htons(size);
    //memcpy(attr->val, &get_device_info()->sec_1905.encr_flags, size);
    
    len += (sizeof(data_elem_attr_t) + size);
    tmp += (sizeof(data_elem_attr_t) + size);
    // connection type flags    
    attr = (data_elem_attr_t *)tmp;
    attr->id = htons(attr_id_conn_type_flags);
    size = sizeof(unsigned short);
    attr->len = htons(size);
    //memcpy(attr->val, &get_device_info()->sec_1905.conn_flags, size);
    
    len += (sizeof(data_elem_attr_t) + size);
    tmp += (sizeof(data_elem_attr_t) + size);
    // config methods   
    attr = (data_elem_attr_t *)tmp;
    attr->id = htons(attr_id_cfg_methods);
    size = sizeof(unsigned short);
    attr->len = htons(size);
    //memcpy(attr->val, &get_device_info()->sec_1905.cfg_methods, size);
    
    len += (sizeof(data_elem_attr_t) + size);
    tmp += (sizeof(data_elem_attr_t) + size);
    
    // manufacturer 
    attr = (data_elem_attr_t *)tmp;
    attr->id = htons(attr_id_manufacturer);
    size = sizeof(em_long_string_t);;
    attr->len = htons(size);
    memcpy(attr->val, get_manufacturer(), size);
    
    len += (sizeof(data_elem_attr_t) + size);
    tmp += (sizeof(data_elem_attr_t) + size);
    // model name
    attr = (data_elem_attr_t *)tmp;
    attr->id = htons(attr_id_model_name);
    size = sizeof(em_small_string_t);
    attr->len = htons(size);
    memcpy(attr->val, get_manufacturer_model(), size);    
    len += (sizeof(data_elem_attr_t) + size);
    tmp += (sizeof(data_elem_attr_t) + size);
    // model_num
    attr = (data_elem_attr_t *)tmp;
    attr->id = htons(attr_id_model_number);
    size = sizeof(em_small_string_t);
    attr->len = htons(size);
    memcpy(attr->val, get_manufacturer_model(), size);
    
    len += (sizeof(data_elem_attr_t) + size);
    tmp += (sizeof(data_elem_attr_t) + size);
    // serial number    
    attr = (data_elem_attr_t *)tmp;
    attr->id = htons(attr_id_serial_num);
    size = sizeof(em_short_string_t);
    attr->len = htons(size);
    memcpy(attr->val, get_serial_number(), size);    
    len += (sizeof(data_elem_attr_t) + size);
    tmp += (sizeof(data_elem_attr_t) + size);
    // primary device type
    attr = (data_elem_attr_t *)tmp;
    attr->id = htons(attr_id_primary_device_type);
    size = sizeof(em_short_string_t);
    attr->len = htons(size);
    memcpy(attr->val, get_primary_device_type(), size);
    
    len += (sizeof(data_elem_attr_t) + size);
    tmp += (sizeof(data_elem_attr_t) + size);
    // device name
    attr = (data_elem_attr_t *)tmp;
    attr->id = htons(attr_id_device_name);
    size = sizeof(em_short_string_t);
    attr->len = htons(size);
    memcpy(attr->val, get_manufacturer_model(), size);
    
    len += (sizeof(data_elem_attr_t) + size);
    tmp += (sizeof(data_elem_attr_t) + size);
    // rf bands
    attr = (data_elem_attr_t *)tmp;
    attr->id = htons(attr_id_rf_bands);
    size = 1;
    attr->len = htons(size);
    memcpy(attr->val, &band, size);
    
    len += (sizeof(data_elem_attr_t) + size);
    tmp += (sizeof(data_elem_attr_t) + size);
    // association state
    attr = (data_elem_attr_t *)tmp;
    attr->id = htons(attr_id_assoc_state);
    size = sizeof(unsigned short);
    attr->len = htons(size);
    memcpy(attr->val, &band, sizeof(attr->val));
    
    len += (sizeof(data_elem_attr_t) + size);
    tmp += (sizeof(data_elem_attr_t) + size);
    // config error
    attr = (data_elem_attr_t *)tmp;
    attr->id = htons(attr_id_cfg_error);
    size = sizeof(unsigned short);
    attr->len = htons(size);
    memcpy(attr->val, &band, sizeof(attr->val));
    
    len += (sizeof(data_elem_attr_t) + size);
    tmp += (sizeof(data_elem_attr_t) + size);
    // device password id
    attr = (data_elem_attr_t *)tmp;
    attr->id = htons(attr_id_device_password_id);
    size = sizeof(unsigned short);
    attr->len = htons(size);
    memcpy(attr->val, &band, sizeof(attr->val));
    
    len += (sizeof(data_elem_attr_t) + size);
    tmp += (sizeof(data_elem_attr_t) + size);
    // os version   
    attr = (data_elem_attr_t *)tmp;
    attr->id = htons(attr_id_os_version);
    size = sizeof(unsigned short);
    attr->len = htons(size);
    memcpy(attr->val, &band, sizeof(attr->val));
    
    len += (sizeof(data_elem_attr_t) + size);
    tmp += (sizeof(data_elem_attr_t) + size);
    // encrypted settings
    attr = (data_elem_attr_t *)tmp;
    attr->id = htons(attr_id_encrypted_settings);
    size = create_encrypted_settings(attr->val);
    attr->len = htons(size);
    
    len += (sizeof(data_elem_attr_t) + size);
    tmp += (sizeof(data_elem_attr_t) + size);
    m_m2_length = len;
    memcpy(m_m2_msg, buff, m_m2_length);
    // authenticator
    attr = (data_elem_attr_t *)tmp;
    attr->id = htons(attr_id_authenticator);
    size = create_authenticator(attr->val);
    attr->len = htons(size);
    
    len += (sizeof(data_elem_attr_t) + size);
    tmp += (sizeof(data_elem_attr_t) + size);
    return len;
}

short em_configuration_t::create_m1_msg(unsigned char *buff)
{
    data_elem_attr_t *attr;
    short len = 0;
    unsigned char band;
    unsigned short size;
    unsigned char *tmp;

    tmp = buff;

    // version
    attr = (data_elem_attr_t *)tmp;
    attr->id = htons(attr_id_version);
    size = 1;
    attr->len = htons(size);
    attr->val[0] = 0x11;

    len += (sizeof(data_elem_attr_t) + size);
    tmp += (sizeof(data_elem_attr_t) + size);

    // message type
    attr = (data_elem_attr_t *)tmp;
    attr->id = htons(attr_id_msg_type);
    size = 1;
    attr->len = htons(size);
    attr->val[0] = em_wsc_msg_type_m1;

    len += (sizeof(data_elem_attr_t) + size);
    tmp += (sizeof(data_elem_attr_t) + size);

    // uuid-e
    attr = (data_elem_attr_t *)tmp;
    attr->id = htons(attr_id_uuid_e);
    size = sizeof(uuid_t);
    attr->len = htons(size);
    get_e_uuid(attr->val);
    
    len += (sizeof(data_elem_attr_t) + size);
    tmp += (sizeof(data_elem_attr_t) + size);

    // mac address
    attr = (data_elem_attr_t *)tmp;
    attr->id = htons(attr_id_mac_address);
    size = sizeof(mac_address_t);
    attr->len = htons(size);
    memcpy(attr->val, get_radio_interface_mac(), size);

    len += (sizeof(data_elem_attr_t) + size);
    tmp += (sizeof(data_elem_attr_t) + size);


    attr = (data_elem_attr_t *)tmp;
    attr->id = htons(attr_id_enrollee_nonce);
    size = sizeof(em_nonce_t);
    attr->len = htons(size);
    get_e_nonce(attr->val);
    
    len += (sizeof(data_elem_attr_t) + size);
    tmp += (sizeof(data_elem_attr_t) + size);

    // enrollee public key
    attr = (data_elem_attr_t *)tmp;
    attr->id = htons(attr_id_public_key);
    size = get_e_public_len();
    attr->len = htons(size);
    memcpy(attr->val, get_e_public(), size);
    
    len += (sizeof(data_elem_attr_t) + size);
    tmp += (sizeof(data_elem_attr_t) + size);

    // auth type flags  
    attr = (data_elem_attr_t *)tmp;
    attr->id = htons(attr_id_auth_type_flags);
    size = sizeof(unsigned short);
    attr->len = htons(size);
    memcpy(attr->val, &get_device_info()->sec_1905.auth_flags, size);
    
    len += (sizeof(data_elem_attr_t) + size);
    tmp += (sizeof(data_elem_attr_t) + size);

    // encryption type flags
    attr = (data_elem_attr_t *)tmp;
    attr->id = htons(attr_id_encryption_type_flags);
    size = sizeof(unsigned short);
    attr->len = htons(size);
    memcpy(attr->val, &get_device_info()->sec_1905.encr_flags, size);

    len += (sizeof(data_elem_attr_t) + size);
    tmp += (sizeof(data_elem_attr_t) + size);

    // connection type flags    
    attr = (data_elem_attr_t *)tmp;
    attr->id = htons(attr_id_conn_type_flags);
    size = sizeof(unsigned short);
    attr->len = htons(size);
    memcpy(attr->val, &get_device_info()->sec_1905.conn_flags, size);

    len += (sizeof(data_elem_attr_t) + size);
    tmp += (sizeof(data_elem_attr_t) + size);

    // config methods   
    attr = (data_elem_attr_t *)tmp;
    attr->id = htons(attr_id_cfg_methods);
    size = sizeof(unsigned short);
    attr->len = htons(size);
    memcpy(attr->val, &get_device_info()->sec_1905.cfg_methods, size);

    len += (sizeof(data_elem_attr_t) + size);
    tmp += (sizeof(data_elem_attr_t) + size);

    // Wi-Fi Simple Configuration state 
    attr = (data_elem_attr_t *)tmp;
    attr->id = htons(attr_id_wifi_wsc_state);
    size = 1;
    attr->len = htons(size);
    attr->val[0] = 0;

    len += (sizeof(data_elem_attr_t) + size);
    tmp += (sizeof(data_elem_attr_t) + size);

    // manufacturer 
    attr = (data_elem_attr_t *)tmp;
    attr->id = htons(attr_id_manufacturer);
    size = sizeof(em_long_string_t);
    attr->len = htons(size);
    memcpy(attr->val, get_current_cmd()->get_manufacturer(), size);

    len += (sizeof(data_elem_attr_t) + size);
    tmp += (sizeof(data_elem_attr_t) + size);

    // model name
    attr = (data_elem_attr_t *)tmp;
    attr->id = htons(attr_id_model_name);
    size = sizeof(em_short_string_t);
    attr->len = htons(size);
    memcpy(attr->val, get_current_cmd()->get_manufacturer_model(), size);

    len += (sizeof(data_elem_attr_t) + size);
    tmp += (sizeof(data_elem_attr_t) + size);

    // model_num
    attr = (data_elem_attr_t *)tmp;
    attr->id = htons(attr_id_model_number);
    size = sizeof(em_short_string_t);
    attr->len = htons(size);
    memcpy(attr->val, get_current_cmd()->get_manufacturer_model(), size);

    len += (sizeof(data_elem_attr_t) + size);
    tmp += (sizeof(data_elem_attr_t) + size);

    // serial number    
    attr = (data_elem_attr_t *)tmp;
    attr->id = htons(attr_id_serial_num);
    size = sizeof(em_short_string_t);
    attr->len = htons(size);
    memcpy(attr->val, get_current_cmd()->get_serial_number(), size);

    len += (sizeof(data_elem_attr_t) + size);
    tmp += (sizeof(data_elem_attr_t) + size);

    // primary device type
    attr = (data_elem_attr_t *)tmp;
    attr->id = htons(attr_id_primary_device_type);
    size = sizeof(em_short_string_t);
    attr->len = htons(size);
    memcpy(attr->val, get_current_cmd()->get_primary_device_type(), size);

    len += (sizeof(data_elem_attr_t) + size);
    tmp += (sizeof(data_elem_attr_t) + size);

    // device name
    attr = (data_elem_attr_t *)tmp;
    attr->id = htons(attr_id_device_name);
    size = sizeof(em_short_string_t);
    attr->len = htons(size);
    memcpy(attr->val, get_current_cmd()->get_manufacturer_model(), size);

    len += (sizeof(data_elem_attr_t) + size);
    tmp += (sizeof(data_elem_attr_t) + size);

    // rf bands
    attr = (data_elem_attr_t *)tmp;
    attr->id = htons(attr_id_rf_bands);
    size = 1;
    attr->len = htons(size);
    memcpy(attr->val, &band, size);

    len += (sizeof(data_elem_attr_t) + size);
    tmp += (sizeof(data_elem_attr_t) + size);

    // association state
    attr = (data_elem_attr_t *)tmp;
    attr->id = htons(attr_id_assoc_state);
    size = sizeof(unsigned short);
    attr->len = htons(size);
    memcpy(attr->val, &band, sizeof(attr->val));

    len += (sizeof(data_elem_attr_t) + size);
    tmp += (sizeof(data_elem_attr_t) + size);

    // device password id
    attr = (data_elem_attr_t *)tmp;
    attr->id = htons(attr_id_device_password_id);
    size = sizeof(unsigned short);
    attr->len = htons(size);
    memcpy(attr->val, &band, sizeof(attr->val));

    len += (sizeof(data_elem_attr_t) + size);
    tmp += (sizeof(data_elem_attr_t) + size);

    // config error
    attr = (data_elem_attr_t *)tmp;
    attr->id = htons(attr_id_cfg_error);
    size = sizeof(unsigned short);
    attr->len = htons(size);
    memcpy(attr->val, &band, sizeof(attr->val));

    len += (sizeof(data_elem_attr_t) + size);
    tmp += (sizeof(data_elem_attr_t) + size);

    // os version   
    attr = (data_elem_attr_t *)tmp;
    attr->id = htons(attr_id_os_version);
    size = sizeof(unsigned short);
    attr->len = htons(size);
    memcpy(attr->val, &band, sizeof(attr->val));

    len += (sizeof(data_elem_attr_t) + size);
    tmp += (sizeof(data_elem_attr_t) + size);


    return len;
}

int em_configuration_t::compute_keys(unsigned char *remote_pub, unsigned short pub_len, unsigned char *local_priv, unsigned short priv_len)
{
    unsigned char *secret;
    unsigned short secret_len;
    unsigned char  *addr[3];
    unsigned int length[3];
    unsigned char  dhkey[SHA256_MAC_LEN];
    unsigned char  kdk  [SHA256_MAC_LEN];
    unsigned char keys[WPS_AUTHKEY_LEN + WPS_KEYWRAPKEY_LEN + WPS_EMSK_LEN];
    char str[] = "Wi-Fi Easy and Secure Key Derivation";

    // first compute keys
    if (compute_secret(&secret, &secret_len, remote_pub, pub_len, local_priv, priv_len) != 1) {
        printf("%s:%d: Shared secret computation failed\n", __func__, __LINE__);
        return -1;
    }

    printf("%s:%d: Secret Key:\n", __func__, __LINE__);
    dm_easy_mesh_t::print_hex_dump(secret_len, secret);

    addr[0] = secret;
    length[0] = secret_len;

    if (compute_digest(1, addr, length, dhkey) != 1) {
        free(secret);
        printf("%s:%d: Hash key computation failed\n", __func__, __LINE__);
        return -1;
    }

    addr[0] = get_e_nonce();
    addr[1] = get_e_mac();
    addr[2] = get_r_nonce();
    length[0] = sizeof(em_nonce_t);
    length[1] = sizeof(mac_address_t);
    length[2] = sizeof(em_nonce_t);

    printf("%s:%d: e-nonce:\n", __func__, __LINE__);
    dm_easy_mesh_t::print_hex_dump(length[0], addr[0]);
    
    printf("%s:%d: e-mac:\n", __func__, __LINE__);
    dm_easy_mesh_t::print_hex_dump(length[1], addr[1]);
    
    printf("%s:%d: r-nonce:\n", __func__, __LINE__);
    dm_easy_mesh_t::print_hex_dump(length[2], addr[2]);
    
    if (compute_kdk(dhkey, SHA256_MAC_LEN, 3, addr, length, kdk) != 1) {
        free(secret);
        printf("%s:%d: kdk computation failed\n", __func__, __LINE__);
        return -1;
    }

    printf("%s:%d: kdk:\n", __func__, __LINE__);
    dm_easy_mesh_t::print_hex_dump(SHA256_MAC_LEN, kdk);
    if (derive_key(kdk, NULL, 0, str, keys, sizeof(keys)) != 1) {
        free(secret);
        printf("%s:%d: key derivation failed\n", __func__, __LINE__);
        return -1;
    }

    memcpy(m_auth_key, keys, WPS_AUTHKEY_LEN);
    memcpy(m_key_wrap_key, keys + WPS_AUTHKEY_LEN, WPS_KEYWRAPKEY_LEN);
    memcpy(m_emsk, keys + WPS_AUTHKEY_LEN + WPS_KEYWRAPKEY_LEN, WPS_EMSK_LEN);

    printf("%s:%d: Encrypt/Decrypt Key:\n", __func__, __LINE__);
    dm_easy_mesh_t::print_hex_dump(WPS_EMSK_LEN, m_emsk);

    return 1;
}

int em_configuration_t::create_autoconfig_wsc_m2_msg(unsigned char *buff)
{
    unsigned short  msg_id = em_msg_type_autoconf_wsc;
    int len = 0;
    em_cmdu_t *cmdu;
    em_tlv_t *tlv;
    em_8021q_settings_t *q_settings;
    unsigned char *tmp = buff;
    unsigned short sz = 0;
    unsigned short type = htons(ETH_P_1905);

    // first compute keys
    if (compute_keys(get_e_public(), get_e_public_len(), get_r_private(), get_r_private_len()) != 1) {
        printf("%s:%d: Keys computation failed\n", __func__, __LINE__);
        return -1;
    }

    memcpy(tmp, (unsigned char *)get_peer_mac(), sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += sizeof(mac_address_t);
    
    memcpy(tmp, get_al_interface_mac(), sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += sizeof(mac_address_t);

    memcpy(tmp, (unsigned char *)&type, sizeof(unsigned short));
    tmp += sizeof(unsigned short);
    len += sizeof(unsigned short);

    cmdu = (em_cmdu_t *)tmp;

    memset(tmp, 0, sizeof(em_cmdu_t));
    cmdu->type = htons(msg_id);
    cmdu->id = htons(msg_id);
    cmdu->last_frag_ind = 1;

    tmp += sizeof(em_cmdu_t);
    len += sizeof(em_cmdu_t);

    // One AP Radio Identifier tlv 17.2.3
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_radio_id;
    memcpy(tlv->value, get_radio_interface_mac(), sizeof(mac_address_t));
    tlv->len = htons(sizeof(mac_address_t));
    
    tmp += (sizeof(em_tlv_t) + sizeof(mac_address_t));
    len += (sizeof(em_tlv_t) + sizeof(mac_address_t));

    // One wsc tlv containing M2
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_wsc;
    sz = create_m2_msg(tlv->value);
    tlv->len = htons(sz);

    tmp += (sizeof(em_tlv_t) + sz);
    len += (sizeof(em_tlv_t) + sz);

    // default 8022.1q settings tlv 17.2.49
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_dflt_8021q_settings;
    tlv->len = htons(sizeof(em_8021q_settings_t));

    q_settings = (em_8021q_settings_t *)tlv->value; 

    tmp += (sizeof(em_tlv_t) + sizeof(em_8021q_settings_t));
    len += (sizeof(em_tlv_t) + sizeof(em_8021q_settings_t));

    // traffic separation policy tlv 17.2.50 
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_traffic_separation_policy;
    sz = create_traffic_separation_policy(tlv->value);
    tlv->len = htons(sz);

    tmp += (sizeof(em_tlv_t) + sz);
    len += (sizeof(em_tlv_t) + sz);


    // End of message
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += (sizeof (em_tlv_t));

    return len;

}

int em_configuration_t::create_autoconfig_wsc_m1_msg(unsigned char *buff)
{
    unsigned short  msg_id = em_msg_type_autoconf_wsc;
    int len = 0;
    em_cmdu_t *cmdu;
    em_tlv_t *tlv;
    em_profile_2_ap_cap_t *profile_2_cap;
    em_ap_radio_advanced_cap_t  *advanced_cap;
    unsigned char *tmp = buff;
    unsigned short sz = 0;
    unsigned short type = htons(ETH_P_1905);

    memcpy(tmp, (unsigned char *)get_peer_mac(), sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += sizeof(mac_address_t);

    memcpy(tmp, get_current_cmd()->get_al_interface_mac(), sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += sizeof(mac_address_t);

    memcpy(tmp, (unsigned char *)&type, sizeof(unsigned short));
    tmp += sizeof(unsigned short);
    len += sizeof(unsigned short);

    cmdu = (em_cmdu_t *)tmp;

    memset(tmp, 0, sizeof(em_cmdu_t));
    cmdu->type = htons(msg_id);
    cmdu->id = htons(msg_id);
    cmdu->last_frag_ind = 1;

    tmp += sizeof(em_cmdu_t);
    len += sizeof(em_cmdu_t);

    // AP radio basic capabilities 17.2.7
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_ap_radio_basic_cap;
    sz = create_ap_radio_basic_cap(tlv->value);
    tlv->len = htons(sz);

    tmp += (sizeof(em_tlv_t) + sz);
    len += (sizeof(em_tlv_t) + sz);

    // One wsc tlv containing M1
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_wsc;
    sz = create_m1_msg(tlv->value);
    tlv->len = htons(sz);

    tmp += (sizeof(em_tlv_t) + sz);
    len += (sizeof(em_tlv_t) + sz);

    m_m1_length = sz;
    memcpy(m_m1_msg, (unsigned char *)tlv->value, m_m1_length);
    
    // One profile 2 AP capability tlv 17.2.48
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_profile_2_ap_cap;
    tlv->len = htons(sizeof(em_profile_2_ap_cap_t));

    profile_2_cap = (em_profile_2_ap_cap_t *)tlv->value;    

    tmp += (sizeof(em_tlv_t) + sizeof(em_profile_2_ap_cap_t));
    len += (sizeof(em_tlv_t) + sizeof(em_profile_2_ap_cap_t));

    // One AP radio advanced capability tlv 17.2.52
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_ap_radio_advanced_cap;
    tlv->len = htons(sizeof(em_ap_radio_advanced_cap_t));

    advanced_cap = (em_ap_radio_advanced_cap_t *)tlv->value;    

    tmp += (sizeof(em_tlv_t) + sizeof(em_ap_radio_advanced_cap_t));
    len += (sizeof(em_tlv_t) + sizeof(em_ap_radio_advanced_cap_t));

    // End of message
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += (sizeof (em_tlv_t));

    return len;
}

int em_configuration_t::create_autoconfig_resp_msg(unsigned char *buff)
{
    unsigned short  msg_id = em_msg_type_autoconf_resp;
    int len = 0;
    em_cmdu_t *cmdu;
    em_tlv_t *tlv;
    em_dpp_chirp_value_t    chirp;
    em_enum_type_t profile;
    em_ctrl_cap_t   ctrl_cap;
    unsigned char *tmp = buff;
    unsigned short type = htons(ETH_P_1905);
    em_service_type_t   service_type = get_service_type();
    unsigned char registrar = 0;

    memcpy(tmp, (unsigned char *)get_peer_mac(), sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += sizeof(mac_address_t);

    memcpy(tmp, (unsigned char *)get_al_interface_mac(), sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += sizeof(mac_address_t);

    memcpy(tmp, (unsigned char *)&type, sizeof(unsigned short));
    tmp += sizeof(unsigned short);
    len += sizeof(unsigned short);

    cmdu = (em_cmdu_t *)tmp;

    memset(tmp, 0, sizeof(em_cmdu_t));
    cmdu->type = htons(msg_id);
    cmdu->id = em_configuration_t::msg_id;
    em_configuration_t::msg_id++;
    cmdu->last_frag_ind = 1;
    cmdu->relay_ind = 1;

    tmp += sizeof(em_cmdu_t);
    len += sizeof(em_cmdu_t);

    //6-24—SupportedRole TLV
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_supported_role;
    tlv->len = htons(sizeof(unsigned char));
    memcpy(&tlv->value, &registrar, sizeof(unsigned char));

    tmp += (sizeof (em_tlv_t) + 1);
    len += (sizeof (em_tlv_t) + 1);

    //6-25—supported freq_band TLV
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_supported_freq_band;
    tlv->len = htons(sizeof(unsigned char));
    memcpy(&tlv->value, &m_peer_band, sizeof(unsigned char));

    tmp += (sizeof (em_tlv_t) + 1);
    len += (sizeof (em_tlv_t) + 1);

    // supported service tlv 17.2.1
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_supported_service;
    tlv->len = htons(sizeof(em_enum_type_t) + 1);
    tlv->value[0] = 1;
    memcpy(&tlv->value[1], &service_type, sizeof(em_enum_type_t));

    tmp += (sizeof(em_tlv_t) + sizeof(em_enum_type_t) + 1);
    len += (sizeof(em_tlv_t) + sizeof(em_enum_type_t) + 1);

    // 1905 layer security capability tlv 17.2.67
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_1905_layer_security_cap;
    tlv->len = htons(sizeof(em_ieee_1905_security_cap_t));
    memcpy(tlv->value, get_ieee_1905_security_cap(), sizeof(em_ieee_1905_security_cap_t));

    tmp += (sizeof(em_tlv_t) + sizeof(em_ieee_1905_security_cap_t));
    len += (sizeof(em_tlv_t) + sizeof(em_ieee_1905_security_cap_t));

    // One multiAP profile tlv 17.2.47
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_profile;
    tlv->len = htons(sizeof(em_enum_type_t));
    profile = em_profile_type_3;
    memcpy(tlv->value, &profile, sizeof(em_enum_type_t));

    tmp += (sizeof(em_tlv_t) + sizeof(em_enum_type_t));
    len += (sizeof(em_tlv_t) + sizeof(em_enum_type_t));

    // One controller capability tlv 17.2.94
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_ctrl_cap;
    tlv->len = htons(sizeof(em_ctrl_cap_t));
    memset(&ctrl_cap, 0, sizeof(em_ctrl_cap_t));;
    memcpy(tlv->value, &ctrl_cap, sizeof(em_ctrl_cap_t));

    tmp += (sizeof(em_tlv_t) + sizeof(em_ctrl_cap_t));
    len += (sizeof(em_tlv_t) + sizeof(em_ctrl_cap_t));

    // End of message
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += (sizeof (em_tlv_t));

    return len;

}

int em_configuration_t::create_autoconfig_search_msg(unsigned char *buff)
{
    unsigned short  msg_id = em_msg_type_autoconf_search;
    int len = 0, num_errors;
    em_cmdu_t *cmdu;
    em_tlv_t *tlv;
    em_enum_type_t searched, profile;
    em_dpp_chirp_value_t    chirp;
    unsigned char *tmp = buff;
    unsigned short type = htons(ETH_P_1905);
    mac_address_t   multi_addr = {0x01, 0x80, 0xc2, 0x00, 0x00, 0x13};
    char *errors[EM_MAX_TLV_MEMBERS];
    em_service_type_t service_type = get_service_type();
    unsigned char config_freq = 0;
    unsigned char registrar = 0;
    em_freq_band_t freq_band;

    memcpy(tmp, (unsigned char *)multi_addr, sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += sizeof(mac_address_t);

    memcpy(tmp, get_current_cmd()->get_al_interface_mac(), sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += sizeof(mac_address_t);

    memcpy(tmp, (unsigned char *)&type, sizeof(unsigned short));
    tmp += sizeof(unsigned short);
    len += sizeof(unsigned short);

    cmdu = (em_cmdu_t *)tmp;

    memset(tmp, 0, sizeof(em_cmdu_t));
    cmdu->type = htons(msg_id);
    cmdu->id = em_configuration_t::msg_id;
    em_configuration_t::msg_id++;
    cmdu->last_frag_ind = 1;
    cmdu->relay_ind = 1;

    tmp += sizeof(em_cmdu_t);
    len += sizeof(em_cmdu_t);

    // AL MAC Address type TLV
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_al_mac_address;
    tlv->len = htons(sizeof(mac_address_t));
    memcpy(tlv->value,get_current_cmd()->get_al_interface_mac(), sizeof(mac_address_t));

    tmp += (sizeof (em_tlv_t) + sizeof(mac_address_t));
    len += (sizeof (em_tlv_t) + sizeof(mac_address_t));

    //6-22—SearchedRole TLV
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_searched_role;
    tlv->len = htons(sizeof(unsigned char));
    memcpy(&tlv->value, &registrar, sizeof(unsigned char));

    tmp += (sizeof (em_tlv_t) + 1);
    len += (sizeof (em_tlv_t) + 1);

    //6-23—autoconf_freq_band TLV
    freq_band = get_current_cmd()->get_rd_freq_band();
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_autoconf_freq_band;
    tlv->len = htons(sizeof(unsigned char));
    memcpy(&tlv->value, &freq_band, sizeof(unsigned char));
 
    tmp += (sizeof (em_tlv_t) + 1);
    len += (sizeof (em_tlv_t) + 1);

    // supported service 17.2.1
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_supported_service;
    tlv->len = htons(sizeof(em_enum_type_t) + 1);
    tlv->value[0] = 1;
    memcpy(&tlv->value[1], &service_type, sizeof(em_enum_type_t));

    tmp += (sizeof(em_tlv_t) + sizeof(em_enum_type_t) + 1);
    len += (sizeof(em_tlv_t) + sizeof(em_enum_type_t) + 1);

    // searched service 17.2.2
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_searched_service;
    tlv->len = htons(sizeof(em_enum_type_t) + 1);
    tlv->value[0] = 1;
    searched = em_service_type_ctrl;
    memcpy(&tlv->value[1], &searched, sizeof(em_enum_type_t));

    tmp += (sizeof(em_tlv_t) + sizeof(em_enum_type_t) + 1);
    len += (sizeof(em_tlv_t) + sizeof(em_enum_type_t) + 1);

    // One multiAP profile tlv 17.2.47
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_profile;
    tlv->len = htons(sizeof(em_enum_type_t));
    profile = em_profile_type_3;
    memcpy(tlv->value, &profile, sizeof(em_enum_type_t));

    tmp += (sizeof(em_tlv_t) + sizeof(em_enum_type_t));
    len += (sizeof(em_tlv_t) + sizeof(em_enum_type_t));
    

    // End of message
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += (sizeof (em_tlv_t));

    return len;

}

int em_configuration_t::handle_wsc_m2(unsigned char *buff, unsigned int len)
{
    data_elem_attr_t    *attr;
    int tmp_len, ret = 0;
    unsigned short id;

    printf("%s:%d: Parsing m1 message, len: %d\n", __func__, __LINE__, len);

    m_m2_length = len - 12;
    memcpy(m_m2_msg, buff, m_m2_length);
    
    attr = (data_elem_attr_t *)buff; tmp_len = len;

    while (tmp_len > 0) {

        id = htons(attr->id);

        if (id == attr_id_version) {
        } else if (id == attr_id_msg_type) {
            if (attr->val[0] != em_wsc_msg_type_m2) {
                return -1;
            }
        } else if (id == attr_id_registrar_nonce) {
            set_r_nonce(attr->val, htons(attr->len));
        } else if (id == attr_id_public_key) {
            set_r_public(attr->val, htons(attr->len));
        } else if (id == attr_id_encrypted_settings) {
            memcpy(m_m2_encrypted_settings, attr->val, htons(attr->len));
            m_m2_encrypted_settings_len = htons(attr->len);
        } else if (id == attr_id_authenticator) {
            memcpy(m_m2_authenticator, attr->val, htons(attr->len));
        }

        tmp_len -= (sizeof(data_elem_attr_t) + htons(attr->len));
        attr = (data_elem_attr_t *)((unsigned char *)attr + sizeof(data_elem_attr_t) + htons(attr->len));
    }

    return ret;

}

int em_configuration_t::handle_wsc_m1(unsigned char *buff, unsigned int len)
{
    data_elem_attr_t    *attr;
    int tmp_len, ret = 0;
    unsigned short id;
    em_device_info_t    dev_info;
    mac_addr_str_t mac_str;

    m_m1_length = len;
    memcpy(m_m1_msg, buff, m_m1_length);
    
    attr = (data_elem_attr_t *)buff; tmp_len = len;

    while (tmp_len > 0) {

        id = htons(attr->id);
        if (id == attr_id_version) {
        } else if (id == attr_id_msg_type) {
            if (attr->val[0] != em_wsc_msg_type_m1) {
                return -1;
            }
        } else if (id == attr_id_uuid_e) {
            set_e_uuid(attr->val, htons(attr->len));
            printf("%s:%d: enrollee uuid length:%d\n", __func__, __LINE__, htons(attr->len));
        } else if (id == attr_id_mac_address) {
            set_e_mac(attr->val);
            dm_easy_mesh_t::macbytes_to_string(attr->val, mac_str);
            printf("%s:%d: enrollee mac address:%s\n", __func__, __LINE__, mac_str);
        } else if (id == attr_id_enrollee_nonce) {
            set_e_nonce(attr->val, htons(attr->len));
            printf("%s:%d: enrollee nonce length:%d\n", __func__, __LINE__, htons(attr->len));
        } else if (id == attr_id_public_key) {
            set_e_public(attr->val, htons(attr->len));
            printf("%s:%d: enrollee public key length:%d\n", __func__, __LINE__, htons(attr->len));
        } else if (id == attr_id_auth_type_flags) {
        } else if (id == attr_id_encryption_type_flags) {
        } else if (id == attr_id_conn_type_flags) {
        } else if (id == attr_id_cfg_methods) {
        } else if (id == attr_id_wifi_wsc_state) {
        } else if (id == attr_id_manufacturer) {
            memcpy(dev_info.manufacturer, attr->val, htons(attr->len));
            set_manufacturer(dev_info.manufacturer);
            printf("%s:%d: Manufacturer:%s\n", __func__, __LINE__, dev_info.manufacturer);
        } else if (id == attr_id_model_name) {
            memcpy(dev_info.manufacturer_model, attr->val, htons(attr->len));
            set_manufacturer_model(dev_info.manufacturer_model);
            printf("%s:%d: Manufacturer Model:%s\n", __func__, __LINE__, dev_info.manufacturer_model);
        } else if (id == attr_id_model_number) {
        } else if (id == attr_id_serial_num) {
            memcpy(dev_info.serial_number, attr->val, htons(attr->len));
            set_serial_number(dev_info.serial_number);
            printf("%s:%d: Manufacturer:%s\n", __func__, __LINE__, dev_info.serial_number);
        } else if (id == attr_id_primary_device_type) {
        } else if (id == attr_id_device_name) {
        } else if (id == attr_id_rf_bands) {
        } else if (id == attr_id_assoc_state) {
        } else if (id == attr_id_device_password_id) {
        } else if (id == attr_id_cfg_error) {
        } else if (id == attr_id_os_version) {
        }

        tmp_len -= (sizeof(data_elem_attr_t) + htons(attr->len));
        attr = (data_elem_attr_t *)((unsigned char *)attr + sizeof(data_elem_attr_t) + htons(attr->len));
    }

    return ret;

}

int em_configuration_t::handle_autoconfig_wsc_m2(unsigned char *buff, unsigned int len)
{

    em_tlv_t *tlv;
    int tmp_len, ret = 0;
    unsigned char msg[MAX_EM_BUFF_SZ];
    unsigned int sz;
    char *errors[EM_MAX_TLV_MEMBERS] = {0};
    bool found_wsc = false;
    unsigned char *secret;
    unsigned short secret_len;
    unsigned char hash[SHA256_MAC_LEN];

    if (em_msg_t(em_msg_type_autoconf_wsc, m_peer_profile, buff, len).validate(errors) == 0) {
        printf("%s:%d: received wsc m2 msg failed validation\n", __func__, __LINE__);
        print_errors_array(errors);

        return -1;
    }
   
    tlv =  (em_tlv_t *)(buff + sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));
    tmp_len = len - (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));

    while ((tlv->type != em_tlv_type_eom) && (tmp_len > 0)) {
        if (tlv->type != em_tlv_type_wsc) {
            tmp_len -= (sizeof(em_tlv_t) + htons(tlv->len));
            tlv = (em_tlv_t *)((unsigned char *)tlv + sizeof(em_tlv_t) + htons(tlv->len));

            continue;

        } else {
            found_wsc = true;
            break; 
        }
    }

    if (found_wsc == false) {
        printf("%s:%d: Could not find wcs, failing mesaage\n", __func__, __LINE__);
        return -1;
    }
            
    //Storing m2 address and length in static variable;

    set_e_mac(get_radio_interface_mac());
    handle_wsc_m2(tlv->value, htons(tlv->len));

    // first compute keys
    if (compute_keys(get_r_public(), get_r_public_len(), get_e_private(), get_e_private_len()) != 1) {
        printf("%s:%d: Keys computation failed\n", __func__, __LINE__);
        return -1;
    }

    if (create_authenticator(hash) == -1) {
        printf("%s:%d: Authenticator create failed\n", __func__, __LINE__);
        return -1;
    } else {
        printf("%s:%d: Authenticator verification succeeded\n", __func__, __LINE__);
    }

    if (memcmp(m_m2_authenticator, hash, AUTHENTICATOR_LEN) != 0) {
        printf("%s:%d: Authenticator validation failed\n", __func__, __LINE__);
        //return -1;
    }

    if (handle_encrypted_settings() == -1) {
        printf("%s:%d: Error in decrypting settings\n", __func__, __LINE__);
        return -1;
    }

    return 0;
}

int em_configuration_t::handle_encrypted_settings()
{
    data_elem_attr_t    *attr;
    int tmp_len, ret = 0;
    unsigned short id;
    char ssid[32] = {0};
    char pass[64] = {0};
    mac_addr_str_t mac_str;
    unsigned char *plain;
    unsigned short plain_len;

    plain = m_m2_encrypted_settings + AES_BLOCK_SIZE;
    plain_len = m_m2_encrypted_settings_len - AES_BLOCK_SIZE;
    
    // first decrypt the encrypted data

    attr = (data_elem_attr_t *)plain;
    tmp_len = plain_len;

    while (tmp_len > 0) {

        id = htons(attr->id);

        if (id == attr_id_ssid) {
            memcpy(ssid, attr->val, htons(attr->len));
            printf("%s:%d: ssid attrib: %s\n", __func__, __LINE__, ssid);
        } else if (id == attr_id_auth_type) {
            printf("%s:%d: auth type attrib\n", __func__, __LINE__);
        } else if (id == attr_id_encryption_type) {
            printf("%s:%d: encr type attrib\n", __func__, __LINE__);
        } else if (id == attr_id_network_key) {
            memcpy(pass, attr->val, htons(attr->len));
            printf("%s:%d: network key attrib: %s\n", __func__, __LINE__, pass);
        } else if (id == attr_id_mac_address) {
            dm_easy_mesh_t::macbytes_to_string(attr->val, mac_str);
            printf("%s:%d: mac address attrib: %s\n", __func__, __LINE__, mac_str);
        } else if (id == attr_id_key_wrap_authenticator) {
            printf("%s:%d: key wrap auth attrib\n", __func__, __LINE__);
        }

        tmp_len -= (sizeof(data_elem_attr_t) + htons(attr->len));
        attr = (data_elem_attr_t *)((unsigned char *)attr + sizeof(data_elem_attr_t) + htons(attr->len));
    }

    return ret;


    return 0;
}

unsigned int em_configuration_t::create_encrypted_settings(unsigned char *buff)
{
    data_elem_attr_t *attr;
    short len = 0;
    unsigned char *tmp;
    unsigned int size = 0;
    const char *test_ssid = "test-ssid-settings";
    const char *net_key = "test-password-settings";
    unsigned short auth_type = 0x0020;

    tmp = buff + AES_BLOCK_SIZE;
    len = AES_BLOCK_SIZE;

    // ssid
    attr = (data_elem_attr_t *)tmp;
    attr->id = htons(attr_id_ssid);
    size = strlen(test_ssid) + 1;
    attr->len = htons(size);
    snprintf((char *)attr->val, size, "%s", test_ssid);

    len += (sizeof(data_elem_attr_t) + size);
    tmp += (sizeof(data_elem_attr_t) + size);

    // auth type
    attr = (data_elem_attr_t *)tmp;
    attr->id = htons(attr_id_auth_type);
    size = sizeof(auth_type);
    attr->len = htons(size);
    memcpy((char *)attr->val, (unsigned char *)&auth_type, size);

    len += (sizeof(data_elem_attr_t) + size);
    tmp += (sizeof(data_elem_attr_t) + size);

    // network key 
    attr = (data_elem_attr_t *)tmp;
    attr->id = htons(attr_id_network_key);
    size = strlen(net_key) + 1;
    attr->len = htons(size);
    snprintf((char *)attr->val,size,"%s", net_key);

    len += (sizeof(data_elem_attr_t) + size);
    tmp += (sizeof(data_elem_attr_t) + size);

    // mac adress
    attr = (data_elem_attr_t *)tmp;
    attr->id = htons(attr_id_mac_address);
    size = sizeof(mac_address_t);
    attr->len = htons(size);
    memcpy((char *)attr->val, (unsigned char *)get_radio_interface_mac(), size);

    len += (sizeof(data_elem_attr_t) + size);
    tmp += (sizeof(data_elem_attr_t) + size);

    // key wrap
    attr = (data_elem_attr_t *)tmp;
    attr->id = htons(attr_id_key_wrap_authenticator);
    size = 32;
    attr->len = htons(size);
    //mwmcpy((char *)attr->val, (unsigned char *)&auth_type, size);

    len += (sizeof(data_elem_attr_t) + size);
    tmp += (sizeof(data_elem_attr_t) + size);

    return len;
}

unsigned int em_configuration_t::create_authenticator(unsigned char *buff)
{
    unsigned char *addr[2];
    unsigned int length[2];
    unsigned char hash[SHA256_MAC_LEN];

    addr[0] = m_m1_msg;
    addr[1] = m_m2_msg;
    length[0] = m_m1_length;
    length[1] = m_m2_length;

    //printf( "%s:%d m1 addr:%s::length:%d,\n", __func__, __LINE__, addr[0], length[0]);
    //dm_easy_mesh_t::print_hex_dump(length[0], addr[0]);
    //printf( "%s:%d m2 addr:%s::length:%d,\n", __func__, __LINE__, addr[1], length[1]);
    //dm_easy_mesh_t::print_hex_dump(length[1], addr[1]);

    if (get_crypto()->platform_hmac_SHA256(m_auth_key, WPS_AUTHKEY_LEN, 2, addr, length, hash) != 1) {
        printf("%s:%d: Authenticator create failed\n", __func__, __LINE__);
        return -1;
    }
    memcpy(buff, hash, AUTHENTICATOR_LEN);

    return AUTHENTICATOR_LEN;
}

em_wsc_msg_type_t em_configuration_t::get_wsc_msg_type(unsigned char *buff, unsigned int len)
{
    em_tlv_t    *tlv;
    data_elem_attr_t    *attr;
    int tmp_len_tlvs, tmp_len_attribs;

    tlv = (em_tlv_t *)buff; tmp_len_tlvs = len;

    while ((tlv->type != em_tlv_type_eom) && (tmp_len_tlvs > 0)) {
        if (tlv->type == em_tlv_type_wsc) {
            tmp_len_attribs = tlv->len;
            attr = (data_elem_attr_t *)tlv->value;

            while (tmp_len_attribs > 0) {

                if (htons(attr->id) == attr_id_msg_type) {
                    return (em_wsc_msg_type_t)(attr->val[0]);
                }

                tmp_len_attribs -= (sizeof(data_elem_attr_t) + htons(attr->len));
                attr = (data_elem_attr_t *)((unsigned char *)attr + sizeof(data_elem_attr_t) + htons(attr->len));
            }
        }

        tmp_len_tlvs -= (sizeof(em_tlv_t) + htons(tlv->len));
        tlv = (em_tlv_t *)((unsigned char *)tlv + sizeof(em_tlv_t) + htons(tlv->len));

    }

    return em_wsc_msg_type_none;
}

int em_configuration_t::handle_autoconfig_wsc_m1(unsigned char *buff, unsigned int len)
{
    unsigned char msg[MAX_EM_BUFF_SZ];
    unsigned int sz;
    char *errors[EM_MAX_TLV_MEMBERS] = {0};
    mac_addr_str_t  mac_str;
    em_tlv_t    *tlv;
    int tlv_len;

    dm_easy_mesh_t::macbytes_to_string(get_radio_interface_mac(), mac_str);

    if (em_msg_t(em_msg_type_autoconf_wsc, m_peer_profile, buff, len).validate(errors) == 0) {
        printf("%s:%d: received autoconfig wsc m1 msg failed validation\n", __func__, __LINE__);
        print_errors_array(errors);

        return -1;
    }

    tlv = (em_tlv_t *)(buff + sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t)); 
    tlv_len = len - (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));

    while ((tlv->type != em_tlv_type_eom) && (len > 0)) {
        if (tlv->type == em_tlv_type_ap_radio_basic_cap) {
        } else if (tlv->type == em_tlv_type_wsc) {
            handle_wsc_m1(tlv->value, htons(tlv->len));
        } else if (tlv->type == em_tlv_type_profile_2_ap_cap) {
        } else if (tlv->type == em_tlv_type_ap_radio_advanced_cap) {
        }

        tlv_len -= (sizeof(em_tlv_t) + htons(tlv->len));
        tlv = (em_tlv_t *)((unsigned char *)tlv + sizeof(em_tlv_t) + htons(tlv->len));
    }

    sz = create_autoconfig_wsc_m2_msg(msg);

    if (em_msg_t(em_msg_type_autoconf_wsc, em_profile_type_3, msg, sz).validate(errors) == 0) {
        printf("Autoconfig wsc m2 msg failed validation in tnx end\n");
        print_errors_array(errors);

        return -1;
    }

    if (send_frame(msg, sz)  < 0) {
        printf("%s:%d: autoconfig wsc m2 send failed, error:%d\n", __func__, __LINE__, errno);
        return -1;
    }

    return 0;
}

int em_configuration_t::handle_autoconfig_resp(unsigned char *buff, unsigned int len)
{
    unsigned char msg[MAX_EM_BUFF_SZ];
    unsigned int sz;
    char *errors[EM_MAX_TLV_MEMBERS] = {0};

    if (em_msg_t(buff + (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t)),
                len - (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t))).get_profile_type(&m_peer_profile) == false) {
        printf("%s:%d: Could not get peer profile type\n", __func__, __LINE__);
        return -1;
    }

    if (em_msg_t(em_msg_type_autoconf_resp, m_peer_profile, buff, len).validate(errors) == 0) {
        printf("received autoconfig resp msg failed validation\n");
        print_errors_array(errors);

        return -1;
    }
    printf("Received resp and validated...creating M1 msg\n");
    sz = create_autoconfig_wsc_m1_msg(msg);

    if (em_msg_t(em_msg_type_autoconf_wsc, em_profile_type_3, msg, sz).validate(errors) == 0) {
        printf("autoconfig wsc m1 validation failed\n");
        print_errors_array(errors);

        return -1;
    }

    if (send_frame(msg, sz)  < 0) {
        printf("%s:%d: autoconfig wsc m1 send failed, error:%d\n", __func__, __LINE__, errno);

        return -1;
    }
    printf("%s:%d: autoconfig wsc m1 send success\n", __func__, __LINE__);
    set_state(em_state_agent_wsc_m2_pending);

    return 0;   
}

int em_configuration_t::handle_autoconfig_search(unsigned char *buff, unsigned int len)
{
    unsigned char msg[MAX_EM_BUFF_SZ];
    unsigned int sz = 0;
    char *errors[EM_MAX_TLV_MEMBERS] = {0};
    
    if (em_msg_t(buff + (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t)),
                len - (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t))).get_profile_type(&m_peer_profile) == false) {
        printf("%s:%d: Could not get peer profile type\n", __func__, __LINE__);
        return -1;
    }


    if (em_msg_t(em_msg_type_autoconf_search, em_profile_type_3, buff, len).validate(errors) == 0) {
        printf("received autoconfig search msg failed validation\n");
        print_errors_array(errors);

        return -1;
    }
    
    sz = create_autoconfig_resp_msg(msg);
    if (em_msg_t(em_msg_type_autoconf_resp, em_profile_type_3, msg, sz).validate(errors) == 0) {
        printf("%s:%d: autoconfig rsp validation failed\n", __func__, __LINE__);
        print_errors_array(errors);

        //return -1;
    }

    if (send_frame(msg, sz)  < 0) {
        printf("%s:%d: autoconfig rsp send failed, error:%d\n", __func__, __LINE__, errno);

        return -1;
    }
    printf("%s:%d: autoconfig rsp send success\n", __func__, __LINE__);
    set_state(em_state_agent_wsc_m1_pending);

    return 0;

}

int em_configuration_t::handle_autoconfig_renew(unsigned char *buff, unsigned int len)
{
    em_tlv_t *tlv;
    em_raw_hdr_t *hdr;
    int tmp_len, ret = 0;
    char autoconfig_renew_json[EM_SUBDOC_BUFF_SZ];
    mac_addr_str_t  src_mac_str, agent_al_mac;
    char* errors[EM_MAX_TLV_MEMBERS];
    em_bus_event_t *bevt;
    em_subdoc_info_t *info;
    em_event_t evt;
    em_service_type_t to_svc;
    em_long_string_t res;
    em_freq_band_t band;

    if (em_msg_t(em_msg_type_autoconf_renew, em_profile_type_2, buff, len).validate(errors) == 0) {

        printf("autoconfig renew validation failed\n");
        print_errors_array(errors);
        return -1;

    }

    hdr = (em_raw_hdr_t *)buff;
    if (em_msg_t(buff + (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t)),
        len - (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t))).get_freq_band(&band) == true) {
        printf("autoconfig renew frequency band = %d\n",band);

    }

    evt.type = em_event_type_bus;
    bevt = &evt.u.bevt;
    to_svc = em_service_type_agent;
    bevt->type = em_bus_event_type_cfg_renew;
    info = &bevt->u.subdoc;
    dm_easy_mesh_t::macbytes_to_string(hdr->src, src_mac_str);
    printf("autoconfig renew src mac = %s\n",src_mac_str);

    dm_easy_mesh_t::macbytes_to_string(get_al_interface_mac(), agent_al_mac);

    dm_easy_mesh_t::create_autoconfig_renew_json_cmd(src_mac_str, agent_al_mac, band, autoconfig_renew_json);

    to_svc = em_service_type_agent;
    info->sz = strlen(autoconfig_renew_json);
    snprintf(info->buff,sizeof(info->buff),"%s",autoconfig_renew_json);
    em_cmd_exec_t::send_cmd(to_svc, (unsigned char *)&evt, sizeof(em_event_t), res, sizeof(em_long_string_t));
    return 0;

}

void em_configuration_t::process_msg(unsigned char *data, unsigned int len)
{
    em_raw_hdr_t *hdr;
    em_cmdu_t *cmdu;
    unsigned char *tlvs;
    unsigned int tlvs_len;

    hdr = (em_raw_hdr_t *)data;
    cmdu = (em_cmdu_t *)(data + sizeof(em_raw_hdr_t));
            
    tlvs = data + sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t);
    tlvs_len = len - (sizeof(em_raw_hdr_t) - sizeof(em_cmdu_t));

    switch (htons(cmdu->type)) {
        case em_msg_type_autoconf_search:
            if (get_service_type() == em_service_type_ctrl) {
                set_peer_mac(hdr->src);
                handle_autoconfig_search(data, len);

            } else if (get_service_type() == em_service_type_agent) {
                printf("%s:%d: received em_msg_type_autoconf_search message in agent ... dropping\n", __func__, __LINE__);
            }

            break;

        case em_msg_type_autoconf_resp:
            if ((get_service_type() == em_service_type_agent) && (get_state() == em_state_agent_autoconfig_rsp_pending)) {
                set_peer_mac(hdr->src);
                handle_autoconfig_resp(data, len);
            }
            break;

        case em_msg_type_autoconf_wsc:
            if ((get_wsc_msg_type(tlvs, tlvs_len) == em_wsc_msg_type_m2) &&
                    (get_service_type() == em_service_type_agent) && (get_state() == em_state_agent_wsc_m2_pending)) {
                handle_autoconfig_wsc_m2(data, len);              
            } else if ((get_wsc_msg_type(tlvs, tlvs_len) == em_wsc_msg_type_m1) &&
                    (get_service_type() == em_service_type_ctrl) && (get_state() == em_state_agent_wsc_m1_pending))  {
                handle_autoconfig_wsc_m1(data, len);
            }

            break;

    case em_msg_type_autoconf_renew:
                handle_autoconfig_renew(data, len);
                break;

        default:
            break;
    }
}

void em_configuration_t::handle_state_config_none()
{
    unsigned char buff[MAX_EM_BUFF_SZ];
    unsigned int sz;
    char* errors[EM_MAX_TLV_MEMBERS] = {0};

    sz = create_autoconfig_search_msg(buff);
    if (em_msg_t(em_msg_type_autoconf_search, em_profile_type_3, buff, sz).validate(errors) == 0) {
        printf("Autoconfig_search validation failed\n");
        print_errors_array(errors);

        return;
    }

    if (send_frame(buff, sz, true)  < 0) {
        printf("%s:%d: failed, err:%d\n", __func__, __LINE__, errno);
        return;
    }

    printf("%s:%d: autoconfig_search send successful\n", __func__, __LINE__);
    set_state(em_state_agent_autoconfig_rsp_pending);

    return;

}

void em_configuration_t::handle_state_autoconfig_renew()
{
    unsigned char msg[MAX_EM_BUFF_SZ];
    unsigned int sz;
    char *errors[EM_MAX_TLV_MEMBERS] = {0};

    sz = create_autoconfig_wsc_m1_msg(msg);

    if (em_msg_t(em_msg_type_autoconf_wsc, em_profile_type_3, msg, sz).validate(errors) == 0) {
        printf("autoconfig wsc m1 validation failed\n");
        print_errors_array(errors);
        return ;
    }

    if (send_frame(msg, sz)  < 0) {
        printf("%s:%d: autoconfig wsc m1 send failed, error:%d\n", __func__, __LINE__, errno);
        return ;
    }
    printf("%s:%d: autoconfig wsc m1 send success\n", __func__, __LINE__);
    set_state(em_state_agent_wsc_m2_pending);

    return ;
}

void em_configuration_t::handle_state_autoconfig_rsp_pending()
{
    assert(get_service_type() == em_service_type_agent);
    handle_state_config_none();
}

void em_configuration_t::handle_state_wsc_m1_pending()
{
    assert(get_service_type() == em_service_type_ctrl);
}

void em_configuration_t::handle_state_wsc_m2_pending()
{
    assert(get_service_type() == em_service_type_agent);
}

void em_configuration_t::process_agent_state()
{
    switch (get_state()) {
        case em_state_agent_config_none:
            handle_state_config_none();
            break;

        case em_state_agent_autoconfig_rsp_pending:
            handle_state_autoconfig_rsp_pending();
            break;

        case em_state_agent_wsc_m1_pending:
            handle_state_wsc_m1_pending();
            break;

        case em_state_agent_wsc_m2_pending:
            handle_state_wsc_m2_pending();
            break;

        case em_state_agent_topology_notify:
            handle_state_topology_notify();
            break;

        case em_state_agent_autoconfig_renew_pending:
            handle_state_autoconfig_renew();
            break;

        default:
            break;
    }
}

void em_configuration_t::process_ctrl_state()
{

}

em_configuration_t::em_configuration_t()
{

}

em_configuration_t::~em_configuration_t()
{

}

