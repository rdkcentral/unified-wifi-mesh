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

unsigned short em_configuration_t::create_client_assoc_event_tlv(unsigned char *buff, mac_address_t sta, bssid_t bssid, bool assoc)
{
    unsigned short len = 0;
    unsigned char *tmp;
    unsigned char joined = (assoc == true)?0x80:0x00;
    bool found_assoc_sta_mld = false;
    unsigned int i;

    tmp = buff;

    dm_easy_mesh_t *dm = get_data_model();

    for (i = 0; i < dm->get_num_assoc_sta_mld(); i++) {
        em_assoc_sta_mld_info_t& assoc_sta_mld_info = dm->m_assoc_sta_mld[i].m_assoc_sta_mld_info;
        if (memcmp(assoc_sta_mld_info.mac_addr, sta, sizeof(mac_address_t) == 0)) {
            found_assoc_sta_mld = true;
            memcpy(tmp, assoc_sta_mld_info.mac_addr, sizeof(mac_address_t));
            memcpy(tmp + sizeof(mac_address_t), assoc_sta_mld_info.ap_mld_mac_addr, sizeof(mac_address_t));
        }
    }

    if (!found_assoc_sta_mld) {
        memcpy(tmp, sta, sizeof(mac_address_t));
        memcpy(tmp + sizeof(mac_address_t), bssid, sizeof(bssid_t));
    }
    memcpy(tmp + 2*sizeof(mac_address_t), &joined, sizeof(unsigned char));

    len = 2*sizeof(mac_address_t) + sizeof(unsigned char);

    return len;
}

int em_configuration_t::send_topology_notification_by_client(mac_address_t sta, bssid_t bssid, bool assoc)
{
    unsigned short  msg_id = em_msg_type_topo_notif;
    char *errors[EM_MAX_TLV_MEMBERS] = {0};
    unsigned int len = 0;
    unsigned short sz;
    em_cmdu_t *cmdu;
    em_tlv_t *tlv;
    unsigned char buff[MAX_EM_BUFF_SZ];
    unsigned char *tmp = buff;
    unsigned short type = htons(ETH_P_1905);
    mac_address_t   multi_addr = {0x01, 0x80, 0xc2, 0x00, 0x00, 0x13};
    unsigned char joined = (assoc == true)?0x80:0x00;
    dm_easy_mesh_t *dm;

    dm = get_data_model();

    memcpy(tmp, reinterpret_cast<unsigned char *> (multi_addr), sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += static_cast<unsigned int> (sizeof(mac_address_t));

    memcpy(tmp, dm->get_agent_al_interface_mac(), sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += static_cast<unsigned int> (sizeof(mac_address_t));

    memcpy(tmp, reinterpret_cast<unsigned char *> (&type), sizeof(unsigned short));
    tmp += sizeof(unsigned short);
    len += static_cast<unsigned int> (sizeof(unsigned short));

    cmdu = reinterpret_cast<em_cmdu_t *> (tmp);

    memset(tmp, 0, sizeof(em_cmdu_t));
    cmdu->type = htons(msg_id);
    cmdu->id = htons(msg_id);
    cmdu->last_frag_ind = 1;
    cmdu->relay_ind = 1;

    tmp += sizeof(em_cmdu_t);
    len += static_cast<unsigned int> (sizeof(em_cmdu_t));

    // AL MAC Address type TLV
    tlv = reinterpret_cast<em_tlv_t *> (tmp);
    tlv->type = em_tlv_type_al_mac_address;
    tlv->len = htons(sizeof(mac_address_t));
    memcpy(tlv->value, get_al_interface_mac(), sizeof(mac_address_t));

    tmp += (sizeof (em_tlv_t) + sizeof(mac_address_t));
    len += static_cast<unsigned int> (sizeof (em_tlv_t) + sizeof(mac_address_t));

    // Client Association Event  17.2.20
    tlv = reinterpret_cast<em_tlv_t *> (tmp);
    tlv->type = em_tlv_type_client_assoc_event;
    sz = create_client_assoc_event_tlv(tlv->value, sta, bssid, joined);
    tlv->len =  htons(sz);

    tmp += (sizeof(em_tlv_t) + sz);
    len += static_cast<unsigned int> (sizeof(em_tlv_t) + sz);

    // End of message
    tlv = reinterpret_cast<em_tlv_t *> (tmp);
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += static_cast<unsigned int> (sizeof (em_tlv_t));

    printf("%s:%d Create topology notification msg successfull\n", __func__, __LINE__);

    if (em_msg_t(em_msg_type_topo_notif, em_profile_type_3, buff, len).validate(errors) == 0) {
        printf("Topology notification msg validation failed\n");

        return -1;
    }

    if (send_frame(buff, len)  < 0) {
        printf("%s:%d: Topology notification send failed, error:%d\n", __func__, __LINE__, errno);
        return -1;
    }

    printf("%s:%d: Topology notification Send Successful\n", __func__, __LINE__);

    return static_cast<int> (len);
}

void em_configuration_t::handle_state_topology_notify()
{
    dm_easy_mesh_t *dm;
    dm_sta_t *sta;

    dm = get_current_cmd()->get_data_model();

    sta = static_cast<dm_sta_t *>(hash_map_get_first(dm->m_sta_assoc_map));
    while (sta != NULL) {
        send_topology_notification_by_client(sta->m_sta_info.id, sta->m_sta_info.bssid, true);
        sta = static_cast<dm_sta_t *> (hash_map_get_next(dm->m_sta_assoc_map, sta));
    }

    sta = static_cast<dm_sta_t *> (hash_map_get_first(dm->m_sta_dassoc_map));
    while (sta != NULL) {
        send_topology_notification_by_client(sta->m_sta_info.id, sta->m_sta_info.bssid, false);
        sta = static_cast<dm_sta_t *> (hash_map_get_next(dm->m_sta_dassoc_map, sta));
    }
    set_state(em_state_agent_configured);
}

int em_configuration_t::send_autoconfig_renew_msg()
{
    unsigned char buff[MAX_EM_BUFF_SZ];
    char *errors[EM_MAX_TLV_MEMBERS] = {0};
    unsigned short  msg_id = em_msg_type_autoconf_renew;
    unsigned int len = 0;
    em_cmdu_t *cmdu;
    em_tlv_t *tlv;
    unsigned char *tmp = buff;
    unsigned short type = htons(ETH_P_1905);
    dm_easy_mesh_t *dm;
    unsigned char registrar = 0;
    em_freq_band_t freq_band;
    mac_addr_str_t mac_str;
    dm = get_data_model();

    memcpy(tmp, dm->get_agent_al_interface_mac(), sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += static_cast<unsigned int> (sizeof(mac_address_t));

    memcpy(tmp, dm->get_ctrl_al_interface_mac(), sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += static_cast<unsigned int> (sizeof(mac_address_t));

    memcpy(tmp, reinterpret_cast<unsigned char *> (&type), sizeof(unsigned short));
    tmp += sizeof(unsigned short);
    len += static_cast<unsigned int> (sizeof(unsigned short));

    cmdu = reinterpret_cast<em_cmdu_t *> (tmp);

    memset(tmp, 0, sizeof(em_cmdu_t));
    cmdu->type = htons(msg_id);
    cmdu->id = htons(msg_id);
    cmdu->last_frag_ind = 1;
    cmdu->relay_ind = 0;

    tmp += sizeof(em_cmdu_t);
    len += static_cast<unsigned int> (sizeof(em_cmdu_t));

    // AL MAC Address type TLV
    tlv = reinterpret_cast<em_tlv_t *> (tmp);
    tlv->type = em_tlv_type_al_mac_address;
    tlv->len = htons(sizeof(mac_address_t));
    memcpy(tlv->value, dm->get_agent_al_interface_mac(), sizeof(mac_address_t));

    tmp += (sizeof (em_tlv_t) + sizeof(mac_address_t));
    len += static_cast<unsigned int> (sizeof (em_tlv_t) + sizeof(mac_address_t));

    //6-24—SupportedRole TLV
    tlv = reinterpret_cast<em_tlv_t *> (tmp);
    tlv->type = em_tlv_type_supported_role;
    tlv->len = htons(sizeof(unsigned char));
    memcpy(&tlv->value, &registrar, sizeof(unsigned char));

    tmp += (sizeof (em_tlv_t) + 1);
    len += static_cast<unsigned int> (sizeof (em_tlv_t) + 1);

    //6-25—supported freq_band TLV
    tlv = reinterpret_cast<em_tlv_t *> (tmp);
    tlv->type = em_tlv_type_supported_freq_band;
    tlv->len = htons(sizeof(unsigned char));
    freq_band = static_cast<em_freq_band_t> (get_band());
    memcpy(&tlv->value, &freq_band, sizeof(unsigned char));

    tmp += (sizeof (em_tlv_t) + 1);
    len += static_cast<unsigned int> (sizeof (em_tlv_t) + 1);

    // End of message
    tlv = reinterpret_cast<em_tlv_t *> (tmp);
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += static_cast<unsigned int> (sizeof (em_tlv_t));
    
    if (em_msg_t(em_msg_type_autoconf_renew, em_profile_type_3, buff, len).validate(errors) == 0) {
        printf("Autoconfig Renew msg validation failed\n");

        return -1;
    }

    if (send_frame(buff, len)  < 0) {
        printf("%s:%d: Autoconfig Renew send failed, error:%d\n", __func__, __LINE__, errno);
        return -1;
    }

    m_renew_tx_cnt++;
    dm_easy_mesh_t::macbytes_to_string (get_radio_interface_mac(), mac_str);
    printf("%s:%d: AutoConfig Renew (%d) Send Successful for %s freq band=%d\n", __func__, __LINE__, m_renew_tx_cnt, mac_str, get_band());

    return static_cast<int> (len);
}

int em_configuration_t::send_topology_query_msg()
{
    unsigned char buff[MAX_EM_BUFF_SZ];
    char *errors[EM_MAX_TLV_MEMBERS] = {0};
    unsigned short  msg_id = em_msg_type_topo_query;
    unsigned int len = 0;
    em_cmdu_t *cmdu;
    em_tlv_t *tlv;
	em_enum_type_t profile;	
    unsigned char *tmp = buff;
    unsigned short type = htons(ETH_P_1905);
	dm_easy_mesh_t *dm;

	dm = get_data_model();

    memcpy(tmp, dm->get_agent_al_interface_mac(), sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += static_cast<unsigned int> (sizeof(mac_address_t));

    memcpy(tmp, dm->get_ctrl_al_interface_mac(), sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += static_cast<unsigned int> (sizeof(mac_address_t));

    memcpy(tmp, reinterpret_cast<unsigned char *> (&type), sizeof(unsigned short));
    tmp += sizeof(unsigned short);
    len += static_cast<unsigned int> (sizeof(unsigned short));

    cmdu = reinterpret_cast<em_cmdu_t *> (tmp);

    memset(tmp, 0, sizeof(em_cmdu_t));
    cmdu->type = htons(msg_id);
    cmdu->id = htons(msg_id);
    cmdu->last_frag_ind = 1;
    cmdu->relay_ind = 0;

    tmp += sizeof(em_cmdu_t);
    len += static_cast<unsigned int> (sizeof(em_cmdu_t));

    // One AP Radio Identifier tlv 17.2.3
    tlv = reinterpret_cast<em_tlv_t *> (tmp);
    tlv->type = em_tlv_type_radio_id;
    memcpy(tlv->value, get_radio_interface_mac(), sizeof(mac_address_t));
    tlv->len = htons(sizeof(mac_address_t));

    tmp += (sizeof(em_tlv_t) + sizeof(mac_address_t));
    len += static_cast<unsigned int> (sizeof(em_tlv_t) + sizeof(mac_address_t));

    // One multiAP profile tlv 17.2.47
    tlv = reinterpret_cast<em_tlv_t *> (tmp);
    tlv->type = em_tlv_type_profile;
    tlv->len = htons(sizeof(em_enum_type_t));
    profile = em_profile_type_3;
    memcpy(tlv->value, &profile, sizeof(em_enum_type_t));

    tmp += (sizeof(em_tlv_t) + sizeof(em_enum_type_t));
    len += static_cast<unsigned int> (sizeof(em_tlv_t) + sizeof(em_enum_type_t));

    // End of message
    tlv = reinterpret_cast<em_tlv_t *> (tmp);
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += static_cast<unsigned int> (sizeof (em_tlv_t));

    if (em_msg_t(em_msg_type_topo_query, em_profile_type_3, buff, len).validate(errors) == 0) {
        printf("Topology Query msg failed validation in tnx end\n");
        return -1;
    }

    if (send_frame(buff, len)  < 0) {
        printf("%s:%d: Topology Query send failed, error:%d\n", __func__, __LINE__, errno);
        return -1;
    }

    m_topo_query_tx_cnt++;
    printf("%s:%d: Topology Query (%d) Send Successful\n", __func__, __LINE__, m_topo_query_tx_cnt);

	return static_cast<int> (len);
}

int em_configuration_t::create_operational_bss_tlv(unsigned char *buff)
{
    em_tlv_t *tlv;
    unsigned char *tmp = buff;
    em_ap_op_bss_t  *ap;
    em_ap_op_bss_radio_t    *radio;
    em_ap_operational_bss_t *bss;
    dm_easy_mesh_t  *dm;
    unsigned int i, j, all_bss_len = 0;
    unsigned short tlv_len = 0;

    dm = get_data_model();

    tlv = reinterpret_cast<em_tlv_t *> (tmp);
    tlv->type = em_tlv_type_operational_bss;
    tlv_len = sizeof(em_ap_op_bss_t);
    printf("first tlv_len in em_configuration_t::create_operational_bss_tlv = %d\n",tlv_len);

    ap = reinterpret_cast<em_ap_op_bss_t *> (tlv->value);
    assert(ap->radios_num == dm->get_num_radios());
    ap->radios_num = static_cast<unsigned char> (dm->get_num_radios());
    radio = ap->radios;
	for (i = 0; i < dm->get_num_radios(); i++) {
		memcpy(radio->ruid, dm->get_radio_by_ref(i).get_radio_interface_mac(), sizeof(mac_address_t));
    	radio->bss_num = 0;
    	bss = radio->bss;
    	all_bss_len = 0;
    	for (j = 0; j < dm->get_num_bss(); j++) {
        	if (memcmp(dm->m_bss[j].m_bss_info.ruid.mac, get_radio_interface_mac(), sizeof(mac_address_t)) != 0) {
            	continue;
        	}
        	radio->bss_num++;
        	memcpy(bss->bssid, dm->m_bss[j].m_bss_info.bssid.mac, sizeof(mac_address_t));
            strncpy(bss->ssid, dm->m_bss[j].m_bss_info.ssid, sizeof(ssid_t));
        	bss->ssid_len = static_cast<unsigned char> (strlen(dm->m_bss[j].m_bss_info.ssid) + 1);
        	all_bss_len += static_cast<unsigned int> (sizeof(em_ap_operational_bss_t) + bss->ssid_len);
        	bss = reinterpret_cast<em_ap_operational_bss_t *>(reinterpret_cast<unsigned char *> (bss) + sizeof(em_ap_operational_bss_t) + bss->ssid_len);
		}
    	radio = reinterpret_cast<em_ap_op_bss_radio_t *>(reinterpret_cast<unsigned char *> (radio) + sizeof(em_ap_op_bss_radio_t) + all_bss_len);
    	tlv_len += static_cast<short unsigned int> (sizeof(em_ap_op_bss_radio_t) + all_bss_len);
	}

    tlv->len = htons(tlv_len);
    print_ap_operational_bss_tlv(tlv->value, tlv->len);

    return tlv_len;
}

int em_configuration_t::create_operational_bss_tlv_topology(unsigned char *buff)
{
	em_tlv_t *tlv;
	unsigned char *tmp = buff;
	em_ap_op_bss_t	*ap;
	em_ap_op_bss_radio_t	*radio;
	em_ap_operational_bss_t *bss;
	dm_easy_mesh_t	*dm;
	unsigned int i, j, all_bss_len = 0;
	unsigned short tlv_len = 0;

	dm = get_data_model();

	tlv = reinterpret_cast<em_tlv_t *> (tmp);
	tlv->type = em_tlv_type_operational_bss;
	tlv_len = sizeof(em_ap_op_bss_t);
	printf("first tlv_len in em_configuration_t::create_operational_bss_tlv = %d\n",tlv_len);

	ap = reinterpret_cast<em_ap_op_bss_t *> (tlv->value);
	ap->radios_num = 1;  //Hard-Coding since topology response is per radio
	radio = ap->radios;
	for (i = 0; i < dm->get_num_radios(); i++) {
		if (memcmp(dm->get_radio_by_ref(i).get_radio_interface_mac(), get_radio_interface_mac(), sizeof(mac_address_t)) == 0) {
			memcpy(radio->ruid, dm->get_radio_by_ref(i).get_radio_interface_mac(), sizeof(mac_address_t));
			radio->bss_num = 0;
			bss = radio->bss;
			all_bss_len = 0;
			for (j = 0; j < dm->get_num_bss(); j++) {
				if (memcmp(dm->m_bss[j].m_bss_info.ruid.mac, get_radio_interface_mac(), sizeof(mac_address_t)) != 0) {
					continue;
				}
				radio->bss_num++;
				memcpy(bss->bssid, dm->m_bss[j].m_bss_info.bssid.mac, sizeof(mac_address_t));
				strncpy(bss->ssid, dm->m_bss[j].m_bss_info.ssid, sizeof(ssid_t));
				bss->ssid_len = static_cast<unsigned char> (strlen(dm->m_bss[j].m_bss_info.ssid) + 1);
				all_bss_len += static_cast<unsigned int> (sizeof(em_ap_operational_bss_t) + bss->ssid_len);
				bss = reinterpret_cast<em_ap_operational_bss_t *>(reinterpret_cast<unsigned char *> (bss) + sizeof(em_ap_operational_bss_t) + bss->ssid_len);
			}
			radio = reinterpret_cast<em_ap_op_bss_radio_t *>(reinterpret_cast<unsigned char *> (radio) + sizeof(em_ap_op_bss_radio_t) + all_bss_len);
			tlv_len += static_cast<short unsigned int> (sizeof(em_ap_op_bss_radio_t) + all_bss_len);
		}
	}

	tlv->len = htons(tlv_len);
	print_ap_operational_bss_tlv(tlv->value, tlv->len);

	return tlv_len;
}

int em_configuration_t::create_bss_config_rprt_tlv(unsigned char *buff)
{
    em_tlv_t *tlv;
    unsigned char *tmp = buff;
    em_bss_config_rprt_t    *rprt;
    em_radio_rprt_t    *rd_rprt;
    em_bss_rprt_t *bss_rprt;
    dm_easy_mesh_t  *dm;
    unsigned int i, j;
    unsigned int bss_rprt_len = 0;
    unsigned short tlv_len = 0;

    dm = get_data_model();

    tlv = reinterpret_cast<em_tlv_t *> (tmp);
    tlv->type = em_tlv_type_bss_conf_rep;

    rprt = reinterpret_cast<em_bss_config_rprt_t *> (tlv->value);
    rprt->num_radios = static_cast<unsigned char> (dm->get_num_radios());

    tlv_len = sizeof(em_bss_config_rprt_t);

    rd_rprt = rprt->radio_rprt;
	
	for (i = 0; i < dm->get_num_radios(); i++) {
    	memcpy(rd_rprt->ruid, dm->get_radio_by_ref(i).get_radio_interface_mac(), sizeof(mac_address_t));
    	rd_rprt->num_bss = 0;
    	bss_rprt = rd_rprt->bss_rprt;

    	for (j = 0; j < dm->get_num_bss(); j++) {
        	if (memcmp(rd_rprt->ruid, dm->m_bss[j].m_bss_info.ruid.mac, sizeof(mac_address_t)) != 0) {
            	continue;
        	}
        	bss_rprt_len += sizeof(em_bss_rprt_t);
        	memcpy(bss_rprt->bssid, dm->m_bss[j].m_bss_info.bssid.mac, sizeof(bssid_t));
        	bss_rprt->ssid_len = static_cast<unsigned char> (strlen(dm->m_bss[j].m_bss_info.ssid) + 1);
            strncpy(bss_rprt->ssid, dm->m_bss[j].m_bss_info.ssid, sizeof(ssid_t));
	
    	    bss_rprt_len += bss_rprt->ssid_len;

        	bss_rprt = reinterpret_cast<em_bss_rprt_t *> (reinterpret_cast<unsigned char *> (bss_rprt) + sizeof(em_bss_rprt_t) + strlen(dm->m_bss[j].m_bss_info.ssid) + 1);

        	rd_rprt->num_bss++;
    	}

    	rd_rprt = reinterpret_cast<em_radio_rprt_t *>(reinterpret_cast<unsigned char *> (rd_rprt) + sizeof(em_radio_rprt_t) + bss_rprt_len);
    	tlv_len += static_cast<short unsigned int> (sizeof(em_radio_rprt_t) + bss_rprt_len);
    	bss_rprt_len = 0;
	}

    tlv->len = htons(tlv_len);
    //print_bss_configuration_report_tlv(tlv->value, tlv->len);

    return tlv_len;
}

int em_configuration_t::create_device_info_type_tlv(unsigned char *buff)
{
    em_tlv_t *tlv;
    unsigned char *tmp = buff;
    em_device_info_type_t *dev_info;
    em_local_interface_t *local_intf;
    dm_easy_mesh_t  *dm;
    unsigned int i, j, no_of_bss = 0;
    unsigned short tlv_len = 0;

    dm = get_data_model();

    tlv = reinterpret_cast<em_tlv_t *> (tmp);
    tlv->type = em_tlv_type_device_info;
    dev_info = reinterpret_cast<em_device_info_type_t *> (tlv->value);

    memcpy(dev_info->al_mac_addr, dm->get_agent_al_interface_mac(), sizeof(mac_address_t));
    dev_info->local_interface_num = static_cast<unsigned char> (dm->get_num_bss());
    local_intf = dev_info->local_interface;
    tlv_len = sizeof(em_device_info_type_t);
	for (i = 0; i < dm->get_num_radios(); i++) {
    	for (j = 0; j < dm->get_num_bss(); j++) {
			if (memcmp(dm->m_bss[j].m_bss_info.ruid.mac, dm->get_radio_by_ref(i).get_radio_interface_mac(), sizeof(mac_address_t)) != 0) {
				continue;
            }
			no_of_bss++;
			memcpy(local_intf->mac_addr, dm->m_bss[i].m_bss_info.bssid.mac, sizeof(mac_address_t));
			// fill test data
			fill_media_data(&dm->m_radio[i].m_radio_info.media_data);
			memcpy(&local_intf->media_data, &dm->m_radio[i].m_radio_info.media_data, sizeof(em_media_spec_data_t));

			local_intf = reinterpret_cast<em_local_interface_t *>(reinterpret_cast<unsigned char *> (local_intf) + sizeof(em_local_interface_t));
			tlv_len = tlv_len + sizeof(em_local_interface_t);
		}
	}

	dev_info->local_interface_num = static_cast<unsigned char> (no_of_bss);
    tlv->len = htons(tlv_len);

    return tlv_len;
}

int em_configuration_t::create_ap_mld_config_tlv(unsigned char *buff)
{
    em_tlv_t *tlv;
    unsigned char *tmp = buff;
    em_ap_mld_config_t *ap_mld_conf;
    em_ap_mld_t *ap_mld;
    em_ap_mld_ssids_t *ap_mld_ssids;
    em_affiliated_ap_mld_t *affiliated_ap_mld;
    dm_easy_mesh_t  *dm;
    unsigned int i, j;
    unsigned short ap_mld_len = 0;
    unsigned short affiliated_ap_len = 0;
    unsigned short tlv_len = 0;

    dm = get_data_model();

    tlv = reinterpret_cast<em_tlv_t *> (tmp);
    tlv->type = em_tlv_type_ap_mld_config;

    ap_mld_conf = reinterpret_cast<em_ap_mld_config_t *> (tlv->value);
    ap_mld_conf->num_ap_mld = static_cast<unsigned char> (dm->get_num_ap_mld());

    tlv_len = static_cast<short unsigned int> (sizeof(em_ap_mld_config_t));

    ap_mld = ap_mld_conf->ap_mld;

    //dm->set_num_ap_mld(1);
    //dm->m_ap_mld[0].m_ap_mld_info.num_affiliated_ap = 1;
    //memcpy(dm->m_ap_mld[0].m_ap_mld_info.affiliated_ap[0].ruid.mac, get_radio_interface_mac(), sizeof(mac_address_t));

    for (i = 0; i < dm->get_num_ap_mld(); i++) {
        em_ap_mld_info_t& ap_mld_info = dm->m_ap_mld[i].m_ap_mld_info;
        ap_mld->ap_mld_mac_addr_valid = ap_mld_info.mac_addr_valid;

        ap_mld_ssids = ap_mld->ssids;
        ap_mld_ssids->ssid_len = static_cast<unsigned char> (strlen(ap_mld_info.ssid) + 1);
        strncpy(ap_mld_ssids->ssid, ap_mld_info.ssid, ap_mld_ssids->ssid_len);

        memcpy(ap_mld->ap_mld_mac_addr, ap_mld_info.mac_addr, sizeof(mac_address_t));
        ap_mld->str = ap_mld_info.str;
        ap_mld->nstr = ap_mld_info.nstr;
        ap_mld->emlsr = ap_mld_info.emlsr;
        ap_mld->emlmr = ap_mld_info.emlmr;

        ap_mld->num_affiliated_ap = ap_mld_info.num_affiliated_ap;
        affiliated_ap_mld = ap_mld->affiliated_ap_mld;

        for (j = 0; j < ap_mld->num_affiliated_ap; j++) {
            em_affiliated_ap_info_t& affiliated_ap_info = dm->m_ap_mld[i].m_ap_mld_info.affiliated_ap[j];
            affiliated_ap_mld->affiliated_mac_addr_valid = affiliated_ap_info.mac_addr_valid;
            affiliated_ap_mld->link_id_valid = affiliated_ap_info.link_id_valid;
            memcpy(affiliated_ap_mld->ruid, affiliated_ap_info.ruid.mac, sizeof(mac_address_t));
            mac_addr_t temp_mac;
            memcpy(temp_mac, affiliated_ap_info.mac_addr, sizeof(mac_addr_t));
            memcpy(affiliated_ap_mld->affiliated_mac_addr, temp_mac, sizeof(mac_addr_t));
            memcpy(&affiliated_ap_mld->link_id, &affiliated_ap_info.link_id, sizeof(unsigned char));

            affiliated_ap_mld = reinterpret_cast<em_affiliated_ap_mld_t *> (reinterpret_cast<unsigned char *> (affiliated_ap_mld) + sizeof(em_affiliated_ap_mld_t));
            affiliated_ap_len += static_cast<short unsigned int> (sizeof(em_affiliated_ap_mld_t));
        }

        ap_mld = reinterpret_cast<em_ap_mld_t *>(reinterpret_cast<unsigned char *> (ap_mld) + sizeof(em_ap_mld_t) + ap_mld_ssids->ssid_len + affiliated_ap_len);
        ap_mld_len += static_cast<short unsigned int> (sizeof(em_ap_mld_t) + ap_mld_ssids->ssid_len + affiliated_ap_len);
    }

    tlv_len += ap_mld_len;
    tlv->len = htons(tlv_len);

    return tlv_len;
}

int em_configuration_t::create_bsta_mld_config_tlv(unsigned char *buff)
{
    em_tlv_t *tlv;
    unsigned char *tmp = buff;
    em_bsta_mld_config_t *bsta_mld_conf;
    em_bsta_mld_t *bsta_mld;
    em_affiliated_bsta_mld_t *affiliated_bsta_mld;
    dm_easy_mesh_t  *dm;
    unsigned int i;
    unsigned short bsta_mld_len = 0;
    unsigned short affiliated_bsta_len = 0;
    unsigned short tlv_len = 0;

    dm = get_data_model();

    tlv = reinterpret_cast<em_tlv_t *>(tmp);
    tlv->type = em_tlv_type_bsta_mld_config;

    bsta_mld_conf = reinterpret_cast<em_bsta_mld_config_t *> (tlv->value);
    bsta_mld_conf->num_bsta_mld = static_cast<unsigned char> (dm->get_num_bsta_mld());

    tlv_len = sizeof(em_bsta_mld_config_t);

    bsta_mld = bsta_mld_conf->bsta_mld;

    for (i = 0; i < dm->get_num_bsta_mld(); i++) {
        em_bsta_mld_info_t& bsta_mld_info = dm->m_bsta_mld[i].m_bsta_mld_info;
        bsta_mld->bsta_mld_mac_addr_valid = bsta_mld_info.mac_addr_valid;
        bsta_mld->ap_mld_mac_addr_valid = bsta_mld_info.ap_mld_mac_addr_valid;
        memcpy(bsta_mld->bsta_mld_mac_addr, bsta_mld_info.mac_addr, sizeof(mac_address_t));
        memcpy(bsta_mld->ap_mld_mac_addr, bsta_mld_info.ap_mld_mac_addr, sizeof(mac_address_t));
        bsta_mld->str = bsta_mld_info.str;
        bsta_mld->nstr = bsta_mld_info.nstr;
        bsta_mld->emlsr = bsta_mld_info.emlsr;
        bsta_mld->emlmr = bsta_mld_info.emlmr;

        bsta_mld->num_affiliated_bsta = bsta_mld_info.num_affiliated_bsta;
        affiliated_bsta_mld = bsta_mld->affiliated_bsta_mld;

        for (i = 0; i < bsta_mld->num_affiliated_bsta; i++) {
            em_affiliated_bsta_info_t& affiliated_bsta_info = bsta_mld_info.affiliated_bsta[i];
            affiliated_bsta_mld->affiliated_bsta_mac_addr_valid = affiliated_bsta_info.mac_addr_valid;
            memcpy(affiliated_bsta_mld->ruid, affiliated_bsta_info.ruid.mac, sizeof(mac_address_t));
            memcpy(affiliated_bsta_mld->affiliated_bsta_mac_addr, affiliated_bsta_info.mac_addr, sizeof(mac_address_t));

            affiliated_bsta_mld = reinterpret_cast<em_affiliated_bsta_mld_t *>(reinterpret_cast<unsigned char *> (affiliated_bsta_mld) + sizeof(em_affiliated_bsta_mld_t));
            affiliated_bsta_len += static_cast<short unsigned int> (sizeof(em_affiliated_bsta_mld_t));
        }

        bsta_mld = reinterpret_cast<em_bsta_mld_t *>(reinterpret_cast<unsigned char *> (bsta_mld) + sizeof(em_bsta_mld_t) + affiliated_bsta_len);
        bsta_mld_len += static_cast<short unsigned int> (sizeof(em_bsta_mld_t) + affiliated_bsta_len);
    }

    tlv_len += bsta_mld_len;
    tlv->len = htons(tlv_len);

    return tlv_len;
}

int em_configuration_t::create_assoc_sta_mld_config_report_tlv(unsigned char *buff)
{
    em_tlv_t *tlv;
    unsigned char *tmp = buff;
    em_assoc_sta_mld_config_report_t *assoc_sta_mld_conf_report;
    em_assoc_sta_mld_t *assoc_sta_mld;
    em_affiliated_sta_mld_t *affiliated_sta_mld;
    dm_easy_mesh_t  *dm;
    unsigned int i;
    unsigned short assoc_sta_mld_len = 0;
    unsigned short affiliated_sta_len = 0;
    unsigned short tlv_len = 0;

    dm = get_data_model();

    tlv = reinterpret_cast<em_tlv_t *> (tmp);
    tlv->type = em_tlv_type_assoc_sta_mld_conf_rep;

    assoc_sta_mld_conf_report = reinterpret_cast<em_assoc_sta_mld_config_report_t *> (tlv->value);
    assoc_sta_mld_conf_report->num_assoc_sta_mld = static_cast<unsigned char> (dm->get_num_assoc_sta_mld());

    tlv_len = sizeof(em_assoc_sta_mld_config_report_t);

    assoc_sta_mld = assoc_sta_mld_conf_report->assoc_sta_mld;

    for (i = 0; i < dm->get_num_assoc_sta_mld(); i++) {
        em_assoc_sta_mld_info_t& assoc_sta_mld_info = dm->m_assoc_sta_mld[i].m_assoc_sta_mld_info;
        memcpy(assoc_sta_mld->sta_mld_mac_addr, assoc_sta_mld_info.mac_addr, sizeof(mac_address_t));
        memcpy(assoc_sta_mld->ap_mld_mac_addr, assoc_sta_mld_info.ap_mld_mac_addr, sizeof(mac_address_t));
        assoc_sta_mld->str = assoc_sta_mld_info.str;
        assoc_sta_mld->nstr = assoc_sta_mld_info.nstr;
        assoc_sta_mld->emlsr = assoc_sta_mld_info.emlsr;
        assoc_sta_mld->emlmr = assoc_sta_mld_info.emlmr;

        assoc_sta_mld->num_affiliated_sta = assoc_sta_mld_info.num_affiliated_sta;
        affiliated_sta_mld = assoc_sta_mld->affiliated_sta_mld;

        for (i = 0; i < assoc_sta_mld->num_affiliated_sta; i++) {
            em_affiliated_sta_info_t& affiliated_sta_info = assoc_sta_mld_info.affiliated_sta[i];
            memcpy(affiliated_sta_mld->bssid, affiliated_sta_info.bssid, sizeof(mac_address_t));
            memcpy(affiliated_sta_mld->affiliated_sta_mac_addr, affiliated_sta_info.mac_addr, sizeof(mac_address_t));

            affiliated_sta_mld = reinterpret_cast<em_affiliated_sta_mld_t *>(reinterpret_cast<unsigned char *> (affiliated_sta_mld) + sizeof(em_affiliated_sta_mld_t));
            affiliated_sta_len += static_cast<short unsigned int> (sizeof(em_affiliated_sta_mld_t));
        }

        assoc_sta_mld = reinterpret_cast<em_assoc_sta_mld_t *>(reinterpret_cast<unsigned char *> (assoc_sta_mld) + sizeof(em_assoc_sta_mld_t) + affiliated_sta_len);
        assoc_sta_mld_len += static_cast<short unsigned int> (sizeof(em_assoc_sta_mld_t) + affiliated_sta_len);
    }

    tlv_len += assoc_sta_mld_len;
    tlv->len = htons(tlv_len);

    return tlv_len;
}

int em_configuration_t::create_vendor_operational_bss_tlv(unsigned char *buff)
{
	em_tlv_t *tlv;
	unsigned char *tmp = buff;
	em_ap_vendor_op_bss_radio_t *radio;
	em_ap_vendor_operational_bss_t *bss;
	em_ap_vendor_op_bss_t *ap;
	dm_easy_mesh_t	*dm;
	unsigned int i, j, all_bss_len = 0;
	unsigned short tlv_len = 0;

	dm = get_data_model();

	tlv = reinterpret_cast<em_tlv_t *> (tmp);
	tlv->type = em_tlv_type_vendor_operational_bss;
	//tlv_len = sizeof(em_ap_vendor_op_bss_radio_t);
	printf("first tlv_len in em_configuration_t::create_custom_operational_bss_tlv = %d\n",tlv_len);
	ap = reinterpret_cast<em_ap_vendor_op_bss_t *> (tlv->value);
	ap->radios_num = 1;
	radio = ap->radios;
	for (i = 0; i < dm->get_num_radios(); i++) {
		if (memcmp(dm->get_radio_by_ref(i).get_radio_interface_mac(), get_radio_interface_mac(), sizeof(mac_address_t)) == 0) {
			memcpy(radio->ruid, dm->get_radio_by_ref(i).get_radio_interface_mac(), sizeof(mac_address_t));
			radio->bss_num = 0;
			bss = radio->bss;
			for (j = 0; j < dm->get_num_bss(); j++) {
					if (memcmp(dm->m_bss[j].m_bss_info.ruid.mac, get_radio_interface_mac(), sizeof(mac_address_t)) != 0) {
						continue;
					}
					radio->bss_num++;
					memcpy(bss->bssid, dm->m_bss[j].m_bss_info.bssid.mac, sizeof(mac_address_t));
					bss->haultype = static_cast<short unsigned int> (dm->m_bss[j].m_bss_info.id.haul_type);
					bss = reinterpret_cast<em_ap_vendor_operational_bss_t *> (reinterpret_cast<unsigned char *> (bss) + sizeof(em_ap_vendor_operational_bss_t));
					all_bss_len += sizeof(em_ap_vendor_operational_bss_t);
			}
			radio = reinterpret_cast<em_ap_vendor_op_bss_radio_t *>(reinterpret_cast<unsigned char *> (radio) + sizeof(em_ap_vendor_op_bss_radio_t) + all_bss_len);
			tlv_len += static_cast<short unsigned int> (sizeof(em_ap_vendor_op_bss_radio_t) + all_bss_len);
			all_bss_len = 0;
		}
	}
	tlv->len = htons(tlv_len);
	print_ap_vendor_operational_bss_tlv(tlv->value, tlv->len);
	return tlv_len;
}

void em_configuration_t::print_ap_vendor_operational_bss_tlv(unsigned char *value, unsigned int len)
{
	mac_addr_str_t	rd_mac_str, bss_mac_str;
	em_ap_vendor_op_bss_radio_t		   *radio;
	em_ap_vendor_operational_bss_t *bss;
	em_ap_vendor_op_bss_t *ap;
	unsigned int i, j, all_bss_len = 0;

	ap = reinterpret_cast<em_ap_vendor_op_bss_t *> (value);
	radio = ap->radios;
	printf("%s:%d Number of radios: %d\n", __func__, __LINE__, ap->radios_num);
	for (i = 0; i < ap->radios_num; i++) {
		dm_easy_mesh_t::macbytes_to_string(radio->ruid, rd_mac_str);
		printf("%s:%d: Radio: %s\n", __func__, __LINE__, rd_mac_str);
		bss = radio->bss;
		printf("%s:%d Number of bss: %d\n", __func__, __LINE__, radio->bss_num);
		for (j = 0; j < radio->bss_num; j++) {
			dm_easy_mesh_t::macbytes_to_string(bss->bssid, bss_mac_str);
			printf("%s:%d: BSSID=%s	 haul type=%d\n", __func__, __LINE__, bss_mac_str, bss->haultype);
			bss = reinterpret_cast<em_ap_vendor_operational_bss_t *> (reinterpret_cast<unsigned char *> (bss) + sizeof(em_ap_vendor_operational_bss_t));
			all_bss_len += sizeof(em_ap_vendor_operational_bss_t);
		}
		radio = reinterpret_cast<em_ap_vendor_op_bss_radio_t *> (reinterpret_cast<unsigned char *> (radio) + sizeof(em_ap_vendor_op_bss_radio_t) + all_bss_len);
		all_bss_len = 0;
	}
}

void em_configuration_t::handle_ap_vendor_operational_bss(unsigned char *value, unsigned int len)
{
	mac_addr_str_t	rd_mac_str, bss_mac_str;
	em_ap_vendor_op_bss_radio_t		   *radio;
	em_ap_vendor_operational_bss_t *bss;
	em_ap_vendor_op_bss_t *ap;
	unsigned int i, j, all_bss_len = 0;
	dm_bss_t *dm_bss;
	dm_easy_mesh_t  *dm;
	dm = get_data_model();
	ap = reinterpret_cast<em_ap_vendor_op_bss_t *> (value);
	radio = ap->radios;
	printf("%s:%d Number of radios: %d\n", __func__, __LINE__, ap->radios_num);
	for (i = 0; i < ap->radios_num; i++) {
		dm_easy_mesh_t::macbytes_to_string(radio->ruid, rd_mac_str);
		printf("%s:%d: Radio: %s\n", __func__, __LINE__, rd_mac_str);
		bss = radio->bss;
		printf("%s:%d Number of bss: %d\n", __func__, __LINE__, radio->bss_num);
		for (j = 0; j < radio->bss_num; j++) {
			dm_easy_mesh_t::macbytes_to_string(bss->bssid, bss_mac_str);
			printf("%s:%d: BSSID=%s	 haul type=%d\n", __func__, __LINE__, bss_mac_str, bss->haultype);
			dm_bss = dm->get_bss(radio->ruid, bss->bssid);
			if (dm_bss == NULL) {
				dm_bss = &dm->m_bss[dm->m_num_bss];
				dm->set_num_bss(dm->get_num_bss() + 1);
			}
			// fill up id first
			strncpy(dm_bss->m_bss_info.id.net_id, dm->m_device.m_device_info.id.net_id, sizeof(em_long_string_t));
			memcpy(dm_bss->m_bss_info.id.dev_mac, dm->m_device.m_device_info.intf.mac, sizeof(mac_address_t));
			memcpy(dm_bss->m_bss_info.id.ruid, radio->ruid, sizeof(mac_address_t));
			memcpy(dm_bss->m_bss_info.id.bssid, bss->bssid, sizeof(mac_address_t));
			memcpy(dm_bss->m_bss_info.ruid.mac, radio->ruid, sizeof(mac_address_t));
			memcpy(dm_bss->m_bss_info.bssid.mac, bss->bssid, sizeof(mac_address_t));
			dm_bss->m_bss_info.id.haul_type = static_cast<em_haul_type_t> (bss->haultype);
			bss = reinterpret_cast<em_ap_vendor_operational_bss_t *>(reinterpret_cast<unsigned char *> (bss) + sizeof(em_ap_vendor_operational_bss_t));
			all_bss_len += sizeof(em_ap_vendor_operational_bss_t);
		}

		radio = reinterpret_cast<em_ap_vendor_op_bss_radio_t *>(reinterpret_cast<unsigned char *> (radio) + sizeof(em_ap_vendor_op_bss_radio_t) + all_bss_len);
		all_bss_len = 0;
	}
}

int em_configuration_t::create_tid_to_link_map_policy_tlv(unsigned char *buff)
{
    em_tlv_t *tlv;
    unsigned char *tmp = buff;
    em_tid_to_link_map_policy_t *tid_to_link_map_policy;
    em_tid_to_link_mapping_t *tid_to_link_mapping;
    dm_easy_mesh_t  *dm;
    unsigned int i;
    unsigned short tid_to_link_map_len = 0;
    unsigned short tlv_len = 0;

    dm = get_data_model();

    tlv = reinterpret_cast<em_tlv_t *> (tmp);
    tlv->type = em_tlv_type_tid_to_link_map_policy;

    tid_to_link_map_policy = reinterpret_cast<em_tid_to_link_map_policy_t *> (tlv->value);
    tlv_len = sizeof(em_tid_to_link_map_policy_t);

    em_tid_to_link_info_t& tid_to_link_info = dm->m_tid_to_link.m_tid_to_link_info;
    tid_to_link_map_policy->is_bsta_config = tid_to_link_info.is_bsta_config;
    memcpy(tid_to_link_map_policy->mld_mac_addr, tid_to_link_info.mld_mac_addr, sizeof(mac_address_t));
    tid_to_link_map_policy->tid_to_link_map_negotiation = tid_to_link_info.tid_to_link_map_neg;

    tid_to_link_map_policy->num_mapping = tid_to_link_info.num_mapping;
    tid_to_link_mapping = tid_to_link_map_policy->tid_to_link_mapping;

    for (i = 0; i < tid_to_link_map_policy->num_mapping; i++) {
        em_tid_to_link_map_info_t& tid_to_link_map_info = tid_to_link_info.tid_to_link_mapping[i];
        tid_to_link_mapping->add_remove = tid_to_link_map_info.add_remove;
        memcpy(tid_to_link_mapping->sta_mld_mac_addr, tid_to_link_map_info.sta_mld_mac_addr, sizeof(mac_address_t));
        tid_to_link_mapping->direction = tid_to_link_map_info.direction;
        tid_to_link_mapping->default_link_mapping = tid_to_link_map_info.default_link_map;
        tid_to_link_mapping->map_switch_time_present = tid_to_link_map_info.map_switch_time_present;
        tid_to_link_mapping->link_map_size = tid_to_link_map_info.link_map_size;
        tid_to_link_mapping->link_map_presence_ind = tid_to_link_map_info.link_map_presence_ind;
        memcpy(tid_to_link_mapping->expected_duration, tid_to_link_map_info.expected_dur, 3 * sizeof(unsigned char));
        //TODO: tid_to_link_map

        tid_to_link_mapping = reinterpret_cast<em_tid_to_link_mapping_t *> (reinterpret_cast<unsigned char *> (tid_to_link_mapping) + sizeof(em_tid_to_link_mapping_t));
        tid_to_link_map_len += sizeof(em_tid_to_link_mapping_t);
    }

    tlv_len += tid_to_link_map_len;
    tlv->len = htons(tlv_len);

    return tlv_len;
}

int em_configuration_t::send_topology_response_msg(unsigned char *dst)
{
    unsigned char buff[MAX_EM_BUFF_SZ];
    char *errors[EM_MAX_TLV_MEMBERS] = {0};
    unsigned short  msg_id = em_msg_type_topo_resp;
    unsigned int len = 0;
    em_cmdu_t *cmdu;
    em_tlv_t *tlv;
    unsigned short tlv_len;
    unsigned char *tmp = buff;
    unsigned short type = htons(ETH_P_1905);
    em_service_type_t   service_type = get_service_type();
    dm_easy_mesh_t  *dm;
    em_enum_type_t profile;

    em_raw_hdr_t *hdr = reinterpret_cast<em_raw_hdr_t *> (dst);

    dm = get_data_model();
    printf("%s:%d: Testing topo, number of radios: %d, bss: %d\n", __func__, __LINE__,
                        dm->get_num_radios(), dm->get_num_bss());

    memcpy(tmp, reinterpret_cast<unsigned char *> (hdr->src), sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += static_cast<unsigned int> (sizeof(mac_address_t));

    memcpy(tmp, dm->get_agent_al_interface_mac(), sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += static_cast<unsigned int> (sizeof(mac_address_t));

    memcpy(tmp, reinterpret_cast<unsigned char *> (&type), sizeof(unsigned short));
    tmp += sizeof(unsigned short);
    len += static_cast<unsigned int> (sizeof(unsigned short));

    cmdu = reinterpret_cast<em_cmdu_t *> (tmp);
    memset(tmp, 0, sizeof(em_cmdu_t));
    cmdu->type = htons(msg_id);
    cmdu->id = htons(msg_id);
    cmdu->last_frag_ind = 1;
    cmdu->relay_ind = 0;

    tmp += sizeof(em_cmdu_t);
    len += static_cast<unsigned int> (sizeof(em_cmdu_t));

    // Device Info type TLV 1905.1 6.4.5
    tlv_len = static_cast<short unsigned int> (create_device_info_type_tlv(tmp));

    tmp += (sizeof (em_tlv_t) + tlv_len);
    len += static_cast<unsigned int> (sizeof (em_tlv_t) + tlv_len);

    // supported service tlv 17.2.1
    tlv = reinterpret_cast<em_tlv_t *> (tmp);
    tlv->type = em_tlv_type_supported_service;
    tlv->len = htons(sizeof(em_enum_type_t) + 1);
    tlv->value[0] = 1;
    memcpy(&tlv->value[1], &service_type, sizeof(em_enum_type_t));

    tmp += (sizeof(em_tlv_t) + sizeof(em_enum_type_t) + 1);
    len += static_cast<unsigned int> (sizeof(em_tlv_t) + sizeof(em_enum_type_t) + 1);

    // One AP Radio Identifier tlv 17.2.3
    tlv = reinterpret_cast<em_tlv_t *> (tmp);
    tlv->type = em_tlv_type_radio_id;
    memcpy(tlv->value, get_radio_interface_mac(), sizeof(mac_address_t));
    tlv->len = htons(sizeof(mac_address_t));

    tmp += (sizeof(em_tlv_t) + sizeof(mac_address_t));
    len += static_cast<unsigned int> (sizeof(em_tlv_t) + sizeof(mac_address_t));

    // AP operational BSS
    tlv_len = static_cast<short unsigned int> (create_operational_bss_tlv_topology(tmp));

    tmp += (sizeof(em_tlv_t) + tlv_len);
    len += static_cast<unsigned int> (sizeof(em_tlv_t) + tlv_len);

    // One multiAP profile tlv 17.2.47
    tlv = reinterpret_cast<em_tlv_t *> (tmp);
    tlv->type = em_tlv_type_profile;
    tlv->len = htons(sizeof(em_enum_type_t));
    profile = em_profile_type_3;
    memcpy(tlv->value, &profile, sizeof(em_enum_type_t));

    tmp += (sizeof(em_tlv_t) + sizeof(em_enum_type_t));
    len += static_cast<unsigned int> (sizeof(em_tlv_t) + sizeof(em_enum_type_t));

    // One BSS Configuration Report 17.2.75
    tlv_len = static_cast<short unsigned int> (create_bss_config_rprt_tlv(tmp));

    tmp += (sizeof(em_tlv_t) + tlv_len);
    len += static_cast<unsigned int> (sizeof(em_tlv_t) + tlv_len);

    // One AP MLD Configuration TLV
    tlv_len = static_cast<short unsigned int> (create_ap_mld_config_tlv(tmp));

    tmp += (sizeof(em_tlv_t) + tlv_len);
    len += static_cast<unsigned int> (sizeof(em_tlv_t) + tlv_len);

    // One Backhaul STA MLD Configuration TLV
    tlv_len = static_cast<short unsigned int> (create_bsta_mld_config_tlv(tmp));

    tmp += (sizeof(em_tlv_t) + tlv_len);
    len += static_cast<unsigned int> (sizeof(em_tlv_t) + tlv_len);

    // One Associated STA MLD Configuration Report TLV
    tlv_len = static_cast<short unsigned int> (create_assoc_sta_mld_config_report_tlv(tmp));

    tmp += (sizeof(em_tlv_t) + tlv_len);
    len += static_cast<unsigned int> (sizeof(em_tlv_t) + tlv_len);

    // One TID-to-Link Mapping Policy TLV
    tlv_len = static_cast<short unsigned int> (create_tid_to_link_map_policy_tlv(tmp));

    tmp += (sizeof(em_tlv_t) + tlv_len);
    len += static_cast<unsigned int> (sizeof(em_tlv_t) + tlv_len);

	// AP vendor operational BSS
	tlv_len = static_cast<short unsigned int> (create_vendor_operational_bss_tlv(tmp));
	tmp += (sizeof(em_tlv_t) + tlv_len);
	len += static_cast<unsigned int> (sizeof(em_tlv_t) + tlv_len);

    // End of message
    tlv = reinterpret_cast<em_tlv_t *> (tmp);
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += static_cast<unsigned int> (sizeof (em_tlv_t));

    // Validate the frame
    if (em_msg_t(em_msg_type_topo_resp, em_profile_type_3, buff, len).validate(errors) == 0) {
        printf("Topology Response msg failed validation in tnx end\n");

        return -1;
    }

    printf("%s:%d: Testing topo, frame length: %d\n", __func__, __LINE__, len);
    if (send_frame(buff, len)  < 0) {
        printf("%s:%d: Topology Response send failed, error:%d\n", __func__, __LINE__, errno);
        return -1;
    }
    printf("setting state to em_state_agent_topo_synchronized\n");
    set_state(em_state_agent_topo_synchronized);
    return static_cast<int> (len);
}

unsigned short em_configuration_t::create_eht_operations_tlv(unsigned char *buff)
{
    unsigned short len = 0;
    unsigned int i = 0, j = 0;
    unsigned char *tmp = buff;
    dm_easy_mesh_t  *dm;
    em_eht_operations_bss_t  *eht_ops_bss;

    dm = get_data_model();

    unsigned char num_radios = static_cast<unsigned char> (dm->get_num_radios());
    unsigned char num_bss;

    memcpy(tmp, &num_radios, sizeof(unsigned char));
    tmp += sizeof(unsigned char);
    len += sizeof(unsigned char);

    for (i = 0; i < num_radios; i++) {
        memcpy(tmp, dm->get_radio_by_ref(i).get_radio_interface_mac(), sizeof(mac_address_t));
        tmp += sizeof(mac_address_t);
        len += sizeof(mac_address_t);

        num_bss = static_cast<unsigned char> (dm->get_num_bss());

        memcpy(tmp, &num_bss, sizeof(unsigned char));
        tmp += sizeof(unsigned char);
        len += sizeof(unsigned char);


        for (j = 0; j < dm->get_num_bss(); j++) {
        	if (memcmp(dm->m_bss[j].m_bss_info.ruid.mac, dm->get_radio_by_ref(i).get_radio_interface_mac(), sizeof(mac_address_t)) != 0) {
            	continue;
        	}

            memcpy(tmp, dm->m_bss[j].m_bss_info.bssid.mac, sizeof(mac_address_t));
            tmp += sizeof(mac_address_t);
            len += sizeof(mac_address_t);

            eht_ops_bss = &dm->m_bss[j].m_bss_info.eht_ops;
            memcpy(tmp, eht_ops_bss, sizeof(em_eht_operations_bss_t));
            tmp += sizeof(em_eht_operations_bss_t);
            len += sizeof(em_eht_operations_bss_t);
        }
    }

    return len;
}

int em_configuration_t::send_ap_mld_config_req_msg()
{
    unsigned char buff[MAX_EM_BUFF_SZ];
    char *errors[EM_MAX_TLV_MEMBERS] = {0};
    unsigned short  msg_id = em_msg_type_ap_mld_config_req;
    unsigned int len = 0;
    em_cmdu_t *cmdu;
    em_tlv_t *tlv;
    unsigned short tlv_len;
    unsigned char *tmp = buff;
    unsigned short type = htons(ETH_P_1905);
	dm_easy_mesh_t *dm;

	dm = get_data_model();

    memcpy(tmp, dm->get_agent_al_interface_mac(), sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += static_cast<unsigned int> (sizeof(mac_address_t));

    memcpy(tmp, dm->get_ctrl_al_interface_mac(), sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += static_cast<unsigned int> (sizeof(mac_address_t));

    memcpy(tmp, reinterpret_cast<unsigned char *> (&type), sizeof(unsigned short));
    tmp += sizeof(unsigned short);
    len += static_cast<unsigned int> (sizeof(unsigned short));

    cmdu = reinterpret_cast<em_cmdu_t *> (tmp);

    memset(tmp, 0, sizeof(em_cmdu_t));
    cmdu->type = htons(msg_id);
    cmdu->id = htons(msg_id);
    cmdu->last_frag_ind = 1;
    cmdu->relay_ind = 0;

    tmp += sizeof(em_cmdu_t);
    len += static_cast<unsigned int> (sizeof(em_cmdu_t));

    // One AP MLD Configuration TLV
    tlv_len = static_cast<short unsigned int> (create_ap_mld_config_tlv(tmp));

    tmp += (sizeof(em_tlv_t) + tlv_len);
    len += static_cast<unsigned int> (sizeof(em_tlv_t) + tlv_len);

    // AP EHT Operations 17.2.103
    tlv = reinterpret_cast<em_tlv_t *> (tmp);
    tlv->type = em_tlv_eht_operations;
    tlv_len = create_eht_operations_tlv(tlv->value);
    tlv->len = htons(tlv_len);

    tmp += (sizeof(em_tlv_t) + tlv_len);
    len += static_cast<unsigned int> (sizeof(em_tlv_t) + tlv_len);

    // End of message
    tlv = reinterpret_cast<em_tlv_t *> (tmp);
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += static_cast<unsigned int> (sizeof (em_tlv_t));
    if (em_msg_t(em_msg_type_ap_mld_config_req, em_profile_type_3, buff, len).validate(errors) == 0) {
        printf("AP MLD config msg failed validation in tnx end\n");
        return -1;
    }

    if (send_frame(buff, len)  < 0) {
        printf("%s:%d: AP MLD config request send failed, error:%d\n", __func__, __LINE__, errno);
        return -1;
    }

    printf("%s:%d: AP MLD config request Send Successful\n", __func__, __LINE__);

    set_state(em_state_ctrl_ap_mld_configured);

	return static_cast<int> (len);
}

int em_configuration_t::send_1905_ack_message(mac_addr_t sta_mac)
{
    unsigned char buff[MAX_EM_BUFF_SZ];
    char *errors[EM_MAX_TLV_MEMBERS] = {0};
    unsigned short  msg_type = em_msg_type_1905_ack;
    unsigned int len = 0;
    em_cmdu_t *cmdu;
    em_tlv_t *tlv;
    unsigned char *tmp = buff;
    unsigned short sz = 0;
    unsigned short type = htons(ETH_P_1905);
    unsigned short msg_id = em_msg_type_1905_ack;
    dm_easy_mesh_t *dm = get_data_model();

    memcpy(tmp, dm->get_ctrl_al_interface_mac(), sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += static_cast<unsigned int> (sizeof(mac_address_t));

    memcpy(tmp, dm->get_agent_al_interface_mac(), sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += static_cast<unsigned int> (sizeof(mac_address_t));

    memcpy(tmp, reinterpret_cast<unsigned char *> (&type), sizeof(unsigned short));
    tmp += sizeof(unsigned short);
    len += static_cast<unsigned int> (sizeof(unsigned short));

    cmdu = reinterpret_cast<em_cmdu_t *> (tmp);

    memset(tmp, 0, sizeof(em_cmdu_t));
    cmdu->type = htons(msg_type);
    cmdu->id = htons(msg_id);
    cmdu->last_frag_ind = 1;

    tmp += sizeof(em_cmdu_t);
    len += static_cast<unsigned int> (sizeof(em_cmdu_t));

    //17.2.36 Error Code TLV format
    tlv = reinterpret_cast<em_tlv_t *> (tmp);
    tlv->type = em_tlv_type_error_code;
    sz = create_error_code_tlv(tlv->value, 0, sta_mac);
    tlv->len = htons(sz);

    tmp += (sizeof(em_tlv_t) + sz);
    len += static_cast<unsigned int> (sizeof(em_tlv_t) + sz);

    // End of message
    tlv = reinterpret_cast<em_tlv_t *> (tmp);
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += static_cast<unsigned int> (sizeof (em_tlv_t));

    if (em_msg_t(em_msg_type_1905_ack, em_profile_type_3, buff, len).validate(errors) == 0) {
        printf("%s:%d: 1905 ACK validation failed\n", __func__, __LINE__);
        return 0;
    }

    if (send_frame(buff, len)  < 0) {
        printf("%s:%d: 1905 ACK send failed, error:%d\n", __func__, __LINE__, errno);
        return 0;
    }
    printf("%s:%d: 1905 ACK send success\n", __func__, __LINE__);

    return static_cast<int> (len);
}

int em_configuration_t::send_ap_mld_config_resp_msg(unsigned char *dst)
{
    unsigned char buff[MAX_EM_BUFF_SZ];
    char *errors[EM_MAX_TLV_MEMBERS] = {0};
    unsigned short  msg_id = em_msg_type_ap_mld_config_resp;
    unsigned int len = 0;
    em_cmdu_t *cmdu;
    em_tlv_t *tlv;
    unsigned short tlv_len;
    unsigned char *tmp = buff;
    unsigned short type = htons(ETH_P_1905);
	dm_easy_mesh_t *dm;

	dm = get_data_model();

    memcpy(tmp, dm->get_ctrl_al_interface_mac(), sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += static_cast<unsigned int> (sizeof(mac_address_t));

    memcpy(tmp, dm->get_agent_al_interface_mac(), sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += static_cast<unsigned int> (sizeof(mac_address_t));

    memcpy(tmp, reinterpret_cast<unsigned char *> (&type), sizeof(unsigned short));
    tmp += sizeof(unsigned short);
    len += static_cast<unsigned int> (sizeof(unsigned short));

    cmdu = reinterpret_cast<em_cmdu_t *> (tmp);

    memset(tmp, 0, sizeof(em_cmdu_t));
    cmdu->type = htons(msg_id);
    cmdu->id = htons(msg_id);
    cmdu->last_frag_ind = 1;
    cmdu->relay_ind = 0;

    tmp += sizeof(em_cmdu_t);
    len += static_cast<unsigned int> (sizeof(em_cmdu_t));

    // One AP MLD Configuration TLV
    tlv_len = static_cast<short unsigned int> (create_ap_mld_config_tlv(tmp));

    tmp += (sizeof(em_tlv_t) + tlv_len);
    len += static_cast<unsigned int> (sizeof(em_tlv_t) + tlv_len);

    // AP EHT Operations 17.2.103
    tlv = reinterpret_cast<em_tlv_t *> (tmp);
    tlv->type = em_tlv_eht_operations;
    tlv_len = create_eht_operations_tlv(tlv->value);
    tlv->len = htons(tlv_len);

    tmp += (sizeof(em_tlv_t) + tlv_len);
    len += static_cast<unsigned int> (sizeof(em_tlv_t) + tlv_len);

    // End of message
    tlv = reinterpret_cast<em_tlv_t *> (tmp);
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += static_cast<unsigned int> (sizeof (em_tlv_t));
    if (em_msg_t(em_msg_type_ap_mld_config_resp, em_profile_type_3, buff, len).validate(errors) == 0) {
        printf("AP MLD config response failed validation in tnx end\n");
        return -1;
    }

    if (send_frame(buff, len)  < 0) {
        printf("%s:%d: AP MLD config response send failed, error:%d\n", __func__, __LINE__, errno);
        return -1;
    }

    printf("%s:%d: AP MLD config response Send Successful\n", __func__, __LINE__);

	return static_cast<int> (len);
}

int em_configuration_t::send_bsta_mld_config_req_msg(unsigned char *buff)
{
    return create_bsta_mld_config_tlv(buff);
}

int em_configuration_t::send_bsta_mld_config_resp_msg(unsigned char *buff)
{
    return create_bsta_mld_config_tlv(buff);
}

void em_configuration_t::print_bss_configuration_report_tlv(unsigned char *value, unsigned int len)
{
	mac_addr_str_t	rd_mac_str, bss_mac_str;
	em_bss_config_rprt_t *rprt;
	em_radio_rprt_t *rd_rprt;
	em_bss_rprt_t *bss_rprt;
	unsigned int i, j;
	unsigned int all_bss_len = 0;

	rprt = reinterpret_cast<em_bss_config_rprt_t *> (value);
	rd_rprt = rprt->radio_rprt;

	printf("%s:%d: Number of radios: %d\n", __func__, __LINE__, rprt->num_radios);
	for (i = 0; i < rprt->num_radios; i++) {
		dm_easy_mesh_t::macbytes_to_string(rd_rprt->ruid, rd_mac_str);
		printf("%s:%d: Radio: %s Number of BSS: %d\n", __func__, __LINE__, rd_mac_str, rd_rprt->num_bss);
		bss_rprt = rd_rprt->bss_rprt;
		for (j = 0; j < rd_rprt->num_bss; j++) {
			dm_easy_mesh_t::macbytes_to_string(bss_rprt->bssid, bss_mac_str);
			printf("%s:%d: BSSID: %s SSID: %s\n", __func__, __LINE__, bss_mac_str, bss_rprt->ssid);
			
			all_bss_len = all_bss_len + static_cast<unsigned int> (sizeof(em_bss_rprt_t) + strlen(bss_rprt->ssid) + 1);
			bss_rprt = reinterpret_cast<em_bss_rprt_t *> (reinterpret_cast<unsigned char *> (bss_rprt) + sizeof(em_bss_rprt_t) + strlen(bss_rprt->ssid) + 1);
		}
		rd_rprt = reinterpret_cast<em_radio_rprt_t *> (reinterpret_cast<unsigned char *> (rd_rprt) + sizeof(em_radio_rprt_t) + all_bss_len);
		all_bss_len = 0;
		
	}		
}

void em_configuration_t::print_ap_operational_bss_tlv(unsigned char *value, unsigned int len)
{
	mac_addr_str_t	rd_mac_str, bss_mac_str;
	em_ap_op_bss_t	*ap;
	em_ap_op_bss_radio_t	*radio;
	em_ap_operational_bss_t	*bss;
	unsigned int i, j, all_bss_len = 0;
	
	ap = reinterpret_cast<em_ap_op_bss_t *> (value);
	radio = ap->radios;
	printf("%s:%d Number of radios: %d\n", __func__, __LINE__, ap->radios_num);
	for (i = 0; i < ap->radios_num; i++) {
		dm_easy_mesh_t::macbytes_to_string(radio->ruid, rd_mac_str);
		printf("%s:%d: Radio: %s\n", __func__, __LINE__, rd_mac_str);
		bss = radio->bss;
		all_bss_len = 0;
		printf("%s:%d Number of bss: %d\n", __func__, __LINE__, radio->bss_num);
		for (j = 0; j < radio->bss_num; j++) {
			dm_easy_mesh_t::macbytes_to_string(bss->bssid, bss_mac_str);
			printf("%s:%d: BSS:%s SSID:%s, SSID Length: %d\n", __func__, __LINE__, bss_mac_str, bss->ssid, bss->ssid_len);

			all_bss_len += static_cast<unsigned int> (sizeof(em_ap_operational_bss_t) + bss->ssid_len);
			//printf("%s:%d: All BSS Len: %d\n", __func__, __LINE__, all_bss_len);
			bss = reinterpret_cast<em_ap_operational_bss_t *> (reinterpret_cast<unsigned char *> (bss) + sizeof(em_ap_operational_bss_t) + bss->ssid_len);
		}		

		radio = reinterpret_cast<em_ap_op_bss_radio_t *> (reinterpret_cast<unsigned char *> (radio) + sizeof(em_ap_op_bss_radio_t) + all_bss_len);
	}
}

int em_configuration_t::handle_bss_configuration_report(unsigned char *buff, unsigned int len)
{
	return 0;
}

int em_configuration_t::handle_bsta_mld_config_req(unsigned char *buff, unsigned int len)
{
    // TODO: 
    // - send 1905 Ack message
    // - apply ml requested (real/dummy data are needed for actual ml structure)
    send_bsta_mld_config_resp_msg(buff);
	return 0;
}

int em_configuration_t::handle_ap_operational_bss(unsigned char *buff, unsigned int len)
{
	dm_easy_mesh_t	*dm;
	em_ap_op_bss_t	*ap;
	em_ap_op_bss_radio_t	*radio;
	em_ap_operational_bss_t	*bss;
	dm_bss_t *dm_bss;
	bool found_radio = false, updated_at_least_one_bss = false;;
	unsigned int i, j;
	unsigned int all_bss_len = 0;
	mac_addr_str_t radio_mac_str;
	char time_date[EM_DATE_TIME_BUFF_SZ];

	dm = get_data_model();
            
    // first verify that dm has all the radios
    ap = reinterpret_cast<em_ap_op_bss_t *> (buff);
    radio = const_cast<em_ap_op_bss_radio_t *> (ap->radios);

	util::get_date_time_rfc3399(time_date, sizeof(time_date));

    for (i = 0; i < ap->radios_num; i++) {
		dm_easy_mesh_t::macbytes_to_string(radio->ruid, radio_mac_str);
        for (j = 0; j < dm->get_num_radios(); j++) {
            if (memcmp(radio->ruid, dm->m_radio[j].m_radio_info.intf.mac, sizeof(mac_address_t)) == 0) {
                found_radio = true;
                break;
            }
        }

        if (found_radio == false) {
            // do not update anything and retrun error
			printf("%s:%d; Could not find radio: %s in data model\n", __func__, __LINE__, radio_mac_str);
            return -1;
        }

        found_radio = false;
        bss = radio->bss;
        all_bss_len = 0;
        for (j = 0; j < radio->bss_num; j++) {
            dm_bss = dm->get_bss(radio->ruid, bss->bssid);
		
			if (dm_bss == NULL) {
				dm_bss = &dm->m_bss[dm->m_num_bss];

				// fill up id first
				strncpy(dm_bss->m_bss_info.id.net_id, dm->m_device.m_device_info.id.net_id, sizeof(em_long_string_t));
				memcpy(dm_bss->m_bss_info.id.dev_mac, dm->m_device.m_device_info.intf.mac, sizeof(mac_address_t));
				memcpy(dm_bss->m_bss_info.id.ruid, radio->ruid, sizeof(mac_address_t));
				memcpy(dm_bss->m_bss_info.id.bssid, bss->bssid, sizeof(mac_address_t));
	
                memcpy(dm_bss->m_bss_info.bssid.mac, bss->bssid, sizeof(mac_address_t));
                memcpy(dm_bss->m_bss_info.ruid.mac, radio->ruid, sizeof(mac_address_t));
                dm->set_num_bss(dm->get_num_bss() + 1);
			}
            strncpy(dm_bss->m_bss_info.ssid, bss->ssid, bss->ssid_len);
			dm_bss->m_bss_info.enabled = true;
			strncpy(dm_bss->m_bss_info.timestamp, time_date, sizeof(em_long_string_t));

			updated_at_least_one_bss = true;
			
			all_bss_len += static_cast<unsigned int> (sizeof(em_ap_operational_bss_t) + bss->ssid_len);
			bss = reinterpret_cast<em_ap_operational_bss_t *> (reinterpret_cast<unsigned char *> (bss) + sizeof(em_ap_operational_bss_t) + bss->ssid_len);
        }

        radio = reinterpret_cast<em_ap_op_bss_radio_t *> (reinterpret_cast<unsigned char *> (radio) + sizeof(em_ap_op_bss_radio_t) + all_bss_len);

    }

	if (updated_at_least_one_bss == true) {
		dm->set_db_cfg_param(db_cfg_type_bss_list_update, "");
	}

	return 0;

}

int em_configuration_t::handle_topology_notification(unsigned char *buff, unsigned int len)
{
    em_tlv_t *tlv;
    unsigned int tmp_len;
    mac_address_t dev_mac;
    mac_addr_str_t sta_mac_str, bssid_str, radio_mac_str;
    em_long_string_t    key;
    dm_easy_mesh_t  *dm;
    bool found_dev_mac = false;
    dm_sta_t *sta;
    em_client_assoc_event_t *assoc_evt_tlv;
    em_sta_info_t sta_info;
    em_bus_event_type_client_assoc_params_t    raw;
    char *errors[EM_MAX_TLV_MEMBERS] = {0};
    bool eligible_to_req_cap = false;

    dm = get_data_model();
	
	if (em_msg_t(em_msg_type_topo_notif, m_peer_profile, buff, len).validate(errors) == 0) {
        printf("%s:%d: topology response msg validation failed\n", __func__, __LINE__);
            
        //return -1;
    }       
        
    tlv =  reinterpret_cast<em_tlv_t *> (buff + sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));
    tmp_len = len - static_cast<unsigned int> (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));
        
    while ((tlv->type != em_tlv_type_eom) && (tmp_len > 0)) {
        if (tlv->type == em_tlv_type_al_mac_address) {
			memcpy(dev_mac, tlv->value, sizeof(mac_address_t));
			found_dev_mac = true;
			break;
        }
            
		tmp_len -= static_cast<unsigned int> (sizeof(em_tlv_t) + htons(tlv->len));
		tlv = reinterpret_cast<em_tlv_t *> (reinterpret_cast<unsigned char *> (tlv) + sizeof(em_tlv_t) + htons(tlv->len));
    }

	if (found_dev_mac == false) {
		printf("%s:%d: Could not find device al mac address\n", __func__, __LINE__);
		return -1;
	}

    while ((tlv->type != em_tlv_type_eom) && (tmp_len > 0)) {
        if (tlv->type == em_tlv_type_client_assoc_event) {
            assoc_evt_tlv = reinterpret_cast<em_client_assoc_event_t *> (tlv->value);
            dm_easy_mesh_t::macbytes_to_string(assoc_evt_tlv->cli_mac_address, sta_mac_str);
            dm_easy_mesh_t::macbytes_to_string(assoc_evt_tlv->bssid, bssid_str);
            dm_easy_mesh_t::macbytes_to_string(get_radio_interface_mac(), radio_mac_str);
            snprintf(key, sizeof(em_long_string_t), "%s@%s@%s", sta_mac_str, bssid_str, radio_mac_str);

            //printf("%s:%d: Client Device:%s %s\n", __func__, __LINE__, sta_mac_str,
                    //(assoc_evt_tlv->assoc_event == 1)?"associated":"disassociated");

            if ((sta = static_cast<dm_sta_t *> (hash_map_get(dm->m_sta_map, key))) == NULL) {
                eligible_to_req_cap = true;
            } else {
                sta = static_cast<dm_sta_t *> (hash_map_get(dm->m_sta_map, key));
                // During an association if map data has empty frame for an existing entry, request cap report to update Frame body
                if ((assoc_evt_tlv->assoc_event == true)) {
                    eligible_to_req_cap = true;
                    //In case ctrl is in em_state_ctrl_sta_link_metrics_pending state bcause of previous assoc state
                    set_state(em_state_ctrl_configured);
                }
            }

            // if associated for first time, orchestrate a client capability query/response
            if(eligible_to_req_cap == true) {
                memcpy(raw.dev, dev_mac, sizeof(mac_address_t));
                memcpy(reinterpret_cast<unsigned char *> (&raw.assoc), reinterpret_cast<unsigned char *> (assoc_evt_tlv), sizeof(em_client_assoc_event_t));

				get_mgr()->io_process(em_bus_event_type_sta_assoc, reinterpret_cast<unsigned char *> (&raw), sizeof(em_bus_event_type_client_assoc_params_t));

            } else {
                memset(&sta_info, 0, sizeof(em_sta_info_t));
                memcpy(sta_info.id, assoc_evt_tlv->cli_mac_address, sizeof(mac_address_t));
                memcpy(sta_info.bssid, assoc_evt_tlv->bssid, sizeof(mac_address_t));
                memcpy(sta_info.radiomac, get_radio_interface_mac(), sizeof(mac_address_t));
                sta_info.associated = assoc_evt_tlv->assoc_event;

                hash_map_put(dm->m_sta_assoc_map, strdup(key), new dm_sta_t(&sta_info));

                dm->set_db_cfg_param(db_cfg_type_sta_list_update, "");
            }
            break;
        }
            
		tmp_len -= static_cast<unsigned int> (sizeof(em_tlv_t) + htons(tlv->len));
		tlv = reinterpret_cast<em_tlv_t *> (reinterpret_cast<unsigned char *> (tlv) + sizeof(em_tlv_t) + htons(tlv->len));
    }

	return 0;
}

int em_configuration_t::handle_topology_response(unsigned char *buff, unsigned int len)
{
    em_tlv_t *tlv;
    unsigned int tmp_len;
    int ret = 0;
    char *errors[EM_MAX_TLV_MEMBERS] = {0};
    bool found_op_bss = false;
    bool found_profile = false;
    bool found_bss_config_rprt = false;
    em_profile_type_t profile = em_profile_type_reserved;
	dm_easy_mesh_t *dm;
    
	dm = get_data_model();

    tlv =  reinterpret_cast<em_tlv_t *> (buff + sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));
    tmp_len = len - static_cast<unsigned int> (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));
        
    while ((tlv->type != em_tlv_type_eom) && (tmp_len > 0)) {
        if (tlv->type != em_tlv_type_profile) {
            tmp_len -= static_cast<unsigned int> (sizeof(em_tlv_t) + htons(tlv->len));
            tlv = reinterpret_cast<em_tlv_t *> (reinterpret_cast<unsigned char *> (tlv) + sizeof(em_tlv_t) + htons(tlv->len));

            continue;

        } else {
            found_profile = true;
			memcpy(&profile, tlv->value, ntohs(tlv->len));
            break; 
        }
    }

	if (found_profile == false) {
		printf("%s:%d: Could not find profile in topo reponse message, dropping\n", __func__, __LINE__);
		return -1;
	}

	m_peer_profile = profile;
    
	if (em_msg_t(em_msg_type_topo_resp, m_peer_profile, buff, len).validate(errors) == 0) {
        printf("%s:%d: topology response msg validation failed\n", __func__, __LINE__);
            
        //return -1;
    }       
        
    tlv =  reinterpret_cast<em_tlv_t *> (buff + sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));
    tmp_len = len - static_cast<unsigned int> (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));

	while ((tlv->type != em_tlv_type_eom) && (tmp_len > 0)) {
		if (tlv->type != em_tlv_type_vendor_operational_bss) {
			tmp_len -= static_cast<unsigned int> (sizeof(em_tlv_t) + htons(tlv->len));
			tlv = reinterpret_cast<em_tlv_t *> (reinterpret_cast<unsigned char *> (tlv) + sizeof(em_tlv_t) + htons(tlv->len));
			continue;
		} else {
			handle_ap_vendor_operational_bss(tlv->value, tlv->len);
			break;
		}
	}
	tlv =  reinterpret_cast<em_tlv_t *> (buff + sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));
	tmp_len = len - static_cast<unsigned int> (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t)); 
    while ((tlv->type != em_tlv_type_eom) && (tmp_len > 0)) {
        if (tlv->type != em_tlv_type_operational_bss) {
            tmp_len -= static_cast<unsigned int> (sizeof(em_tlv_t) + htons(tlv->len));
            tlv = reinterpret_cast<em_tlv_t *> (reinterpret_cast<unsigned char *> (tlv) + sizeof(em_tlv_t) + htons(tlv->len));

            continue;

        } else {
            found_op_bss = true;
            break;
        }
    }

    if (found_op_bss == false) {
        printf("%s:%d: Could not find operational bss, failing mesaage\n", __func__, __LINE__);
        return -1;
    }

	if (handle_ap_operational_bss(tlv->value, tlv->len) != 0) {
		printf("%s:%d: Operational BSS handling failed\n", __func__, __LINE__);
		return -1;
	}

    while ((tlv->type != em_tlv_type_eom) && (tmp_len > 0)) {
        if (tlv->type != em_tlv_type_bss_conf_rep) {
            tmp_len -= static_cast<unsigned int> (sizeof(em_tlv_t) + htons(tlv->len));
            tlv = reinterpret_cast <em_tlv_t *> (reinterpret_cast<unsigned char *> (tlv) + sizeof(em_tlv_t) + htons(tlv->len));

            continue;

        } else {
            found_bss_config_rprt = true;
            break;
        }
    }

    if (found_bss_config_rprt == false) {
        printf("%s:%d: Could not find bss configuration report, failing mesaage\n", __func__, __LINE__);
        return -1;
    }

	if (handle_bss_configuration_report(tlv->value, tlv->len) != 0) {
		printf("%s:%d: BSS Configuration Report handling failed\n", __func__, __LINE__);
		return -1;
	}


	dm->set_db_cfg_param(db_cfg_type_policy_list_update, "");
	return ret;
}

int em_configuration_t::handle_ack_msg(unsigned char *buff, unsigned int len)
{
    set_state(em_state_ctrl_ap_mld_req_ack_rcvd);
    return 0;
}

int em_configuration_t::handle_ap_mld_config_tlv(unsigned char *buff, unsigned int len)
{
    em_ap_mld_config_t *ap_mld_conf = reinterpret_cast<em_ap_mld_config_t *> (buff);
    em_ap_mld_t *ap_mld;
    em_ap_mld_ssids_t *ap_mld_ssids;
    em_affiliated_ap_mld_t *affiliated_ap_mld;
    dm_easy_mesh_t  *dm;
    unsigned int i, j;
    unsigned short ap_mld_len = 0;
    unsigned short affiliated_ap_len = 0;

    dm = get_data_model();

    dm->set_num_ap_mld(ap_mld_conf->num_ap_mld);

    ap_mld = ap_mld_conf->ap_mld;

    for (i = 0; i < ap_mld_conf->num_ap_mld; i++) {
        em_ap_mld_info_t* ap_mld_info = &dm->m_ap_mld[i].m_ap_mld_info;
        ap_mld_info->mac_addr_valid = ap_mld->ap_mld_mac_addr_valid;

        ap_mld_ssids = ap_mld->ssids;
        strncpy(ap_mld_info->ssid, ap_mld_ssids->ssid, ap_mld_ssids->ssid_len);

        memcpy(ap_mld_info->mac_addr, ap_mld->ap_mld_mac_addr, sizeof(mac_address_t));
        ap_mld_info->str = ap_mld->str;
        ap_mld_info->nstr = ap_mld->nstr;
        ap_mld_info->emlsr = ap_mld->emlsr;
        ap_mld_info->emlmr = ap_mld->emlmr;

        ap_mld_info->num_affiliated_ap = ap_mld->num_affiliated_ap;
        affiliated_ap_mld = ap_mld->affiliated_ap_mld;

        for (j = 0; j < ap_mld->num_affiliated_ap; j++) {
            em_affiliated_ap_info_t* affiliated_ap_info = &dm->m_ap_mld[i].m_ap_mld_info.affiliated_ap[j];
            affiliated_ap_info->mac_addr_valid = affiliated_ap_mld->affiliated_mac_addr_valid;
            affiliated_ap_info->link_id_valid = affiliated_ap_mld->link_id_valid;
            memcpy(affiliated_ap_info->ruid.mac, affiliated_ap_mld->ruid, sizeof(mac_address_t));
            mac_addr_t temp_mac;
            memcpy(temp_mac, affiliated_ap_mld->affiliated_mac_addr, sizeof(mac_addr_t));
            memcpy(affiliated_ap_info->mac_addr, temp_mac, sizeof(mac_address_t));
            memcpy(&affiliated_ap_info->link_id, &affiliated_ap_mld->link_id, sizeof(unsigned char));

            affiliated_ap_mld = reinterpret_cast<em_affiliated_ap_mld_t *> (reinterpret_cast<unsigned char *> (affiliated_ap_mld) + sizeof(em_affiliated_ap_mld_t));
            affiliated_ap_len += sizeof(em_affiliated_ap_mld_t);
        }

        ap_mld = reinterpret_cast<em_ap_mld_t *> (reinterpret_cast<unsigned char *> (ap_mld) + sizeof(em_ap_mld_t) + ap_mld_ssids->ssid_len + affiliated_ap_len);
        ap_mld_len += static_cast<short unsigned int> (sizeof(em_ap_mld_t) + ap_mld_ssids->ssid_len + affiliated_ap_len);
    }

    return 0;
}

int em_configuration_t::handle_eht_operations_tlv(unsigned char *buff)
{
    short len = 0;
    unsigned int i = 0, j = 0, k = 0, l = 0;
    unsigned char *tmp = buff;

    unsigned char num_radios;
    unsigned char num_bss = 0;

    em_eht_operations_t eht_ops;

    dm_easy_mesh_t *dm;

    dm = get_data_model();

    memcpy(&num_radios, tmp, sizeof(unsigned char));
    eht_ops.radios_num = num_radios;
    tmp += sizeof(unsigned char);
    len += static_cast<short> (sizeof(unsigned char));

    for (i = 0; i < num_radios; i++) {
        memcpy(&eht_ops.radios[i].ruid, tmp, sizeof(mac_address_t));
        tmp += sizeof(mac_address_t);
        len += static_cast<short> (sizeof(mac_address_t));

        memcpy(&num_bss, tmp, sizeof(unsigned char));
        eht_ops.radios[i].bss_num = num_bss;
        tmp += sizeof(unsigned char);
        len += static_cast<short> (sizeof(unsigned char));

        for(j = 0; j < num_bss; j++) {
            memcpy(&eht_ops.radios[i].bss[j], tmp, sizeof(em_eht_operations_bss_t));
            tmp += sizeof(em_eht_operations_bss_t);
            len += static_cast<short> (sizeof(em_eht_operations_bss_t));
        }
    }

    bool found_radio = false;
    bool found_bss = false;
    for (i = 0; i < eht_ops.radios_num; i++) {
        for (j = 0; j < dm->get_num_radios(); j++) {
            if (memcmp(eht_ops.radios[i].ruid, dm->m_radio[j].m_radio_info.id.dev_mac, sizeof(mac_address_t)) == 0) {
                found_radio = true;
                break;
            }
            if (found_radio == false) {
                // do not update anything and retrun error
                return -1;
            }
        }
        found_radio = false;

        for(k = 0; k < eht_ops.radios[i].bss_num; k++) {
            for(l = 0; l < dm->get_num_bss(); l++) {
                if (memcmp(eht_ops.radios[i].bss, dm->m_bss[j].m_bss_info.bssid.mac, sizeof(mac_address_t)) == 0) {
                    found_bss = true;
                    break;
                }
                if (found_bss == false) {
                    // do not update anything and retrun error
                    return -1;
                }
            }
            found_bss = false;
            memcpy(&dm->m_bss[j].get_bss_info()->eht_ops, &eht_ops.radios[i].bss[k], sizeof(em_eht_operations_bss_t));
        }
    }

    return 0;
}

int em_configuration_t::handle_ap_mld_config_req(unsigned char *buff, unsigned int len)
{
    em_tlv_t    *tlv;
    unsigned int tlv_len;

    tlv = reinterpret_cast<em_tlv_t *> (buff + sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));
    tlv_len = len - static_cast<unsigned int> (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));

    while ((tlv->type != em_tlv_type_eom) && (len > 0)) {
        if (tlv->type == em_tlv_type_ap_mld_config) {
            handle_ap_mld_config_tlv(tlv->value, sizeof(em_ap_mld_config_t));
        }
        if (tlv->type == em_tlv_eht_operations) {
            handle_eht_operations_tlv(tlv->value);
            break;
        }

        tlv_len -= static_cast<unsigned int> (sizeof(em_tlv_t) + htons(tlv->len));
        tlv = reinterpret_cast<em_tlv_t *> (reinterpret_cast<unsigned char *> (tlv) + sizeof(em_tlv_t) + htons(tlv->len));
    }

	printf("%s:%d Received AP MLD configuration request\n",__func__, __LINE__);

    send_1905_ack_message(0);

    return 0;
}

int em_configuration_t::handle_ap_mld_config_resp(unsigned char *buff, unsigned int len)
{
    printf("%s:%d Received AP MLD configuration response\n",__func__, __LINE__);
    return 0;
}

unsigned short em_configuration_t::create_traffic_separation_policy(unsigned char *buff)
{
    unsigned short len = 0;
    unsigned int i;
    em_traffic_sep_policy_t *policy;
    em_traffic_sep_policy_ssid_t *policy_ssid;
    dm_easy_mesh_t *dm = get_data_model();

    policy = reinterpret_cast<em_traffic_sep_policy_t *> (buff);
    policy->ssids_num = static_cast<unsigned char> (dm->m_num_net_ssids);
    policy_ssid = policy->ssids;

    len += static_cast<unsigned short int> (sizeof(em_traffic_sep_policy_t));

    for (i = 0; i < dm->m_num_net_ssids; i++) {
        policy_ssid->ssid_len = static_cast<unsigned char> (strlen(dm->m_network_ssid[i].m_network_ssid_info.ssid) + 1);
        strncpy(policy_ssid->ssid, dm->m_network_ssid[i].m_network_ssid_info.ssid, policy_ssid->ssid_len);
        len = len + static_cast<unsigned short int> (sizeof(em_traffic_sep_policy_ssid_t) + policy_ssid->ssid_len + sizeof(unsigned short));
        policy_ssid = reinterpret_cast<em_traffic_sep_policy_ssid_t *>(reinterpret_cast<unsigned char *>(policy_ssid) + sizeof(em_traffic_sep_policy_ssid_t) + policy_ssid->ssid_len + sizeof(unsigned short));
        //printf("%s:%d: SSID: %s SSID Len: %d\n", __func__, __LINE__, 
        //    dm->m_network_ssid[i].m_network_ssid_info.ssid, strlen(dm->m_network_ssid[i].m_network_ssid_info.ssid));
    }

	//printf("%s:%d: Length: %d\n", __func__, __LINE__, len);
    return len;
}

unsigned short em_configuration_t::create_m2_msg(unsigned char *buff, em_haul_type_t haul_type)
{
    data_elem_attr_t *attr;
    unsigned short size, len = 0;
    unsigned char *tmp;
    tmp = buff;
    em_freq_band_t rf_band;
	char *str;
 
    // version
    attr = reinterpret_cast<data_elem_attr_t *> (tmp);
    attr->id = htons(attr_id_version);
    size = 1;
    attr->len = htons(size);
    attr->val[0] = 0x10;
    len += static_cast<unsigned short int> (sizeof(data_elem_attr_t) + size);
    tmp += (sizeof(data_elem_attr_t) + size);
    // message type
    attr = reinterpret_cast<data_elem_attr_t *> (tmp);
    attr->id = htons(attr_id_msg_type);
    size = 1;
    attr->len = htons(size);
    attr->val[0] = em_wsc_msg_type_m2;
    
    len += static_cast<unsigned short int> (sizeof(data_elem_attr_t) + size);
    tmp += (sizeof(data_elem_attr_t) + size);
    // enrollee nonce
    attr = reinterpret_cast<data_elem_attr_t *> (tmp);
    attr->id = htons(attr_id_enrollee_nonce);
    size = sizeof(em_nonce_t);
    attr->len = htons(size);
    get_e_nonce(attr->val);
    
    len += static_cast<unsigned short int> (sizeof(data_elem_attr_t) + size);
    tmp += (sizeof(data_elem_attr_t) + size);
    // registrar nonce
    attr = reinterpret_cast<data_elem_attr_t *> (tmp);
    attr->id = htons(attr_id_registrar_nonce);
    size = sizeof(em_nonce_t);
    attr->len = htons(size);
    get_r_nonce(attr->val);
    len += static_cast<unsigned short int> (sizeof(data_elem_attr_t) + size);
    tmp += (sizeof(data_elem_attr_t) + size);
    // uuid-r
    attr = reinterpret_cast<data_elem_attr_t *> (tmp);
    attr->id = htons(attr_id_uuid_r);
    size = sizeof(uuid_t);
    attr->len = htons(size);
    get_r_uuid(attr->val);
    
    len += static_cast<unsigned short int> (sizeof(data_elem_attr_t) + size);
    tmp += (sizeof(data_elem_attr_t) + size);
    // registrar public key 
    attr = reinterpret_cast<data_elem_attr_t *> (tmp);
    attr->id = htons(attr_id_public_key);
    size = static_cast<short unsigned int> (get_r_public_len());
    attr->len = htons(size);
    memcpy(attr->val, get_r_public(), size);
    len += static_cast<unsigned short int> (sizeof(data_elem_attr_t) + size);
    tmp += (sizeof(data_elem_attr_t) + size);
    // auth type flags  
    attr = reinterpret_cast<data_elem_attr_t *> (tmp);
    attr->id = htons(attr_id_auth_type_flags);
    size = sizeof(unsigned short);
    attr->len = htons(size);
    //memcpy(attr->val, &get_device_info()->sec_1905.auth_flags, size);
    
    len += static_cast<unsigned short int> (sizeof(data_elem_attr_t) + size);
    tmp += (sizeof(data_elem_attr_t) + size);
    // encryption type flags
    attr = reinterpret_cast<data_elem_attr_t *> (tmp);
    attr->id = htons(attr_id_encryption_type_flags);
    size = sizeof(unsigned short);
    attr->len = htons(size);
    //memcpy(attr->val, &get_device_info()->sec_1905.encr_flags, size);
    
    len += static_cast<unsigned short int> (sizeof(data_elem_attr_t) + size);
    tmp += (sizeof(data_elem_attr_t) + size);
    // connection type flags    
    attr = reinterpret_cast<data_elem_attr_t *> (tmp);
    attr->id = htons(attr_id_conn_type_flags);
    size = sizeof(unsigned short);
    attr->len = htons(size);
    //memcpy(attr->val, &get_device_info()->sec_1905.conn_flags, size);
    
    len += static_cast<unsigned short int> (sizeof(data_elem_attr_t) + size);
    tmp += (sizeof(data_elem_attr_t) + size);
    // config methods   
    attr = reinterpret_cast<data_elem_attr_t *> (tmp);
    attr->id = htons(attr_id_cfg_methods);
    size = sizeof(unsigned short);
    attr->len = htons(size);
    //memcpy(attr->val, &get_device_info()->sec_1905.cfg_methods, size);
    
    len += static_cast<unsigned short int> (sizeof(data_elem_attr_t) + size);
    tmp += (sizeof(data_elem_attr_t) + size);
    
    // manufacturer 
    attr = reinterpret_cast<data_elem_attr_t *> (tmp);
    attr->id = htons(attr_id_manufacturer);
	str = get_manufacturer();
    size = static_cast<short unsigned int> (strlen(str));
    attr->len = htons(size);
    memcpy(attr->val, str, size);
    
    len += static_cast<unsigned short int> (sizeof(data_elem_attr_t) + size);
    tmp += (sizeof(data_elem_attr_t) + size);

    // model name
    attr = reinterpret_cast<data_elem_attr_t *> (tmp);
    attr->id = htons(attr_id_model_name);
	str = get_manufacturer_model();
    size = static_cast<short unsigned int> (strlen(str));
    attr->len = htons(size);
    memcpy(attr->val, str, size);

    len += static_cast<unsigned short int> (sizeof(data_elem_attr_t) + size);
    tmp += (sizeof(data_elem_attr_t) + size);

    // model_num
    attr = reinterpret_cast<data_elem_attr_t *> (tmp);
    attr->id = htons(attr_id_model_number);
	str = get_manufacturer_model();
    size = static_cast<short unsigned int> (strlen(str));
    attr->len = htons(size);
    memcpy(attr->val, str, size);
    
    len += static_cast<unsigned short int> (sizeof(data_elem_attr_t) + size);
    tmp += (sizeof(data_elem_attr_t) + size);

    // serial number    
    attr = reinterpret_cast<data_elem_attr_t *> (tmp);
    attr->id = htons(attr_id_serial_num);
	str = get_serial_number();
    size = static_cast<short unsigned int> (strlen(str));
    attr->len = htons(size);
    memcpy(attr->val, str, size);    

    len += static_cast<unsigned short int> (sizeof(data_elem_attr_t) + size);
    tmp += (sizeof(data_elem_attr_t) + size);

    // primary device type
    attr = reinterpret_cast<data_elem_attr_t *> (tmp);
    attr->id = htons(attr_id_primary_device_type);
    size = sizeof(em_short_string_t);
    attr->len = htons(size);
    memcpy(attr->val, get_primary_device_type(), size);
    
    len += static_cast<unsigned short int> (sizeof(data_elem_attr_t) + size);
    tmp += (sizeof(data_elem_attr_t) + size);

    // device name
    attr = reinterpret_cast<data_elem_attr_t *> (tmp);
    attr->id = htons(attr_id_device_name);
	str = get_manufacturer_model();
    size = static_cast<short unsigned int> (strlen(str));
    attr->len = htons(size);
    memcpy(attr->val, str, size);
    
    len += static_cast<unsigned short int> (sizeof(data_elem_attr_t) + size);
    tmp += (sizeof(data_elem_attr_t) + size);
    
	// rf bands Table 6.1.3 - RF Band
    attr = reinterpret_cast<data_elem_attr_t *> (tmp);
    attr->id = htons(attr_id_rf_bands);
    size = 1;
    attr->len = htons(size);
    rf_band = static_cast<em_freq_band_t> (1 << get_band());
    memcpy(attr->val, &rf_band, size);
 
    len += static_cast<unsigned short int> (sizeof(data_elem_attr_t) + size);
    tmp += (sizeof(data_elem_attr_t) + size);

    // association state
    attr = reinterpret_cast<data_elem_attr_t *> (tmp);
    attr->id = htons(attr_id_assoc_state);
    size = sizeof(unsigned short);
    attr->len = htons(size);
    memcpy(attr->val, &rf_band, sizeof(attr->val));
    
    len += static_cast<unsigned short int> (sizeof(data_elem_attr_t) + size);
    tmp += (sizeof(data_elem_attr_t) + size);

    // config error
    attr = reinterpret_cast<data_elem_attr_t *> (tmp);
    attr->id = htons(attr_id_cfg_error);
    size = sizeof(unsigned short);
    attr->len = htons(size);
    memcpy(attr->val, &rf_band, sizeof(attr->val));
    
    len += static_cast<unsigned short int> (sizeof(data_elem_attr_t) + size);
    tmp += (sizeof(data_elem_attr_t) + size);

    // device password id
    attr = reinterpret_cast<data_elem_attr_t *> (tmp);
    attr->id = htons(attr_id_device_password_id);
    size = sizeof(unsigned short);
    attr->len = htons(size);
    memcpy(attr->val, &rf_band, sizeof(attr->val));
    
    len += static_cast<unsigned short int> (sizeof(data_elem_attr_t) + size);
    tmp += (sizeof(data_elem_attr_t) + size);
    // os version   
    attr = reinterpret_cast<data_elem_attr_t *> (tmp);
    attr->id = htons(attr_id_os_version);
    size = sizeof(unsigned short);
    attr->len = htons(size);
    memcpy(attr->val, &rf_band, sizeof(attr->val));
    
    len += static_cast<unsigned short int> (sizeof(data_elem_attr_t) + size);
    tmp += (sizeof(data_elem_attr_t) + size);
    // encrypted settings
    attr = reinterpret_cast<data_elem_attr_t *> (tmp);
    attr->id = htons(attr_id_encrypted_settings);
    size = static_cast<short unsigned int> (create_encrypted_settings(attr->val, haul_type));
    attr->len = htons(size);
    
    len += static_cast<unsigned short int> (sizeof(data_elem_attr_t) + size);
    tmp += (sizeof(data_elem_attr_t) + size);
    m_m2_length = len;
    memcpy(m_m2_msg, buff, m_m2_length);
    // authenticator
    attr = reinterpret_cast<data_elem_attr_t *> (tmp);
    attr->id = htons(attr_id_authenticator);
    size = static_cast<short unsigned int> (create_authenticator(attr->val));
    attr->len = htons(size);
    
    len += static_cast<unsigned short int> (sizeof(data_elem_attr_t) + size);
    tmp += (sizeof(data_elem_attr_t) + size);
    return len;
}

unsigned short em_configuration_t::create_m1_msg(unsigned char *buff)
{
    data_elem_attr_t *attr;
    unsigned short size, len = 0;
    unsigned char *tmp;
    em_freq_band_t rf_band;
	char *str;

    tmp = buff;

    // version
    attr = reinterpret_cast<data_elem_attr_t *> (tmp);
    attr->id = htons(attr_id_version);
    size = 1;
    attr->len = htons(size);
    attr->val[0] = 0x11;

    len += static_cast<unsigned short int> (sizeof(data_elem_attr_t) + size);
    tmp += (sizeof(data_elem_attr_t) + size);

    // message type
    attr = reinterpret_cast<data_elem_attr_t *> (tmp);
    attr->id = htons(attr_id_msg_type);
    size = 1;
    attr->len = htons(size);
    attr->val[0] = em_wsc_msg_type_m1;

    len += static_cast<unsigned short int> (sizeof(data_elem_attr_t) + size);
    tmp += (sizeof(data_elem_attr_t) + size);

    // uuid-e
    attr = reinterpret_cast<data_elem_attr_t *> (tmp);
    attr->id = htons(attr_id_uuid_e);
    size = sizeof(uuid_t);
    attr->len = htons(size);
    get_e_uuid(attr->val);
    
    len += static_cast<unsigned short int> (sizeof(data_elem_attr_t) + size);
    tmp += (sizeof(data_elem_attr_t) + size);

    // mac address
    attr = reinterpret_cast<data_elem_attr_t *> (tmp);
    attr->id = htons(attr_id_mac_address);
    size = sizeof(mac_address_t);
    attr->len = htons(size);
    memcpy(attr->val, get_radio_interface_mac(), size);

    len += static_cast<unsigned short int> (sizeof(data_elem_attr_t) + size);
    tmp += (sizeof(data_elem_attr_t) + size);

    //enrollee nonce
    attr = reinterpret_cast<data_elem_attr_t *> (tmp);
    attr->id = htons(attr_id_enrollee_nonce);
    size = sizeof(em_nonce_t);
    attr->len = htons(size);
    get_e_nonce(attr->val);
    
    len += static_cast<unsigned short int> (sizeof(data_elem_attr_t) + size);
    tmp += (sizeof(data_elem_attr_t) + size);

    // enrollee public key
    attr = reinterpret_cast<data_elem_attr_t *> (tmp);
    attr->id = htons(attr_id_public_key);
    size = static_cast<short unsigned int> (get_e_public_len());
    attr->len = htons(size);
    memcpy(attr->val, get_e_public(), size);
    
    len += static_cast<unsigned short int> (sizeof(data_elem_attr_t) + size);
    tmp += (sizeof(data_elem_attr_t) + size);

    // auth type flags  
    attr = reinterpret_cast<data_elem_attr_t *> (tmp);
    attr->id = htons(attr_id_auth_type_flags);
    size = sizeof(unsigned short);
    attr->len = htons(size);
    memcpy(attr->val, &get_device_info()->sec_1905.auth_flags, size);
    
    len += static_cast<unsigned short int> (sizeof(data_elem_attr_t) + size);
    tmp += (sizeof(data_elem_attr_t) + size);

    // encryption type flags
    attr = reinterpret_cast<data_elem_attr_t *> (tmp);
    attr->id = htons(attr_id_encryption_type_flags);
    size = sizeof(unsigned short);
    attr->len = htons(size);
    memcpy(attr->val, &get_device_info()->sec_1905.encr_flags, size);

    len += static_cast<unsigned short int> (sizeof(data_elem_attr_t) + size);
    tmp += (sizeof(data_elem_attr_t) + size);

    // connection type flags    
    attr = reinterpret_cast<data_elem_attr_t *> (tmp);
    attr->id = htons(attr_id_conn_type_flags);
    size = sizeof(unsigned short);
    attr->len = htons(size);
    memcpy(attr->val, &get_device_info()->sec_1905.conn_flags, size);

    len += static_cast<unsigned short int> (sizeof(data_elem_attr_t) + size);
    tmp += (sizeof(data_elem_attr_t) + size);

    // config methods   
    attr = reinterpret_cast<data_elem_attr_t *> (tmp);
    attr->id = htons(attr_id_cfg_methods);
    size = sizeof(unsigned short);
    attr->len = htons(size);
    memcpy(attr->val, &get_device_info()->sec_1905.cfg_methods, size);

    len += static_cast<unsigned short int> (sizeof(data_elem_attr_t) + size);
    tmp += (sizeof(data_elem_attr_t) + size);

    // Wi-Fi Simple Configuration state 
    attr = reinterpret_cast<data_elem_attr_t *> (tmp);
    attr->id = htons(attr_id_wifi_wsc_state);
    size = 1;
    attr->len = htons(size);
    attr->val[0] = 0;

    len += static_cast<unsigned short int> (sizeof(data_elem_attr_t) + size);
    tmp += (sizeof(data_elem_attr_t) + size);

    // manufacturer 
    attr = reinterpret_cast<data_elem_attr_t *> (tmp);
    attr->id = htons(attr_id_manufacturer);
	str = get_current_cmd()->get_manufacturer();
    size = static_cast<short unsigned int> (strlen(str));
    attr->len = htons(size);
    memcpy(attr->val, str, size);

    len += static_cast<unsigned short int> (sizeof(data_elem_attr_t) + size);
    tmp += (sizeof(data_elem_attr_t) + size);

    // model name
    attr = reinterpret_cast<data_elem_attr_t *> (tmp);
    attr->id = htons(attr_id_model_name);
	str = get_current_cmd()->get_manufacturer_model();
    size = static_cast<short unsigned int> (strlen(str));
    attr->len = htons(size);
    memcpy(attr->val, str, size);

    len += static_cast<unsigned short int> (sizeof(data_elem_attr_t) + size);
    tmp += (sizeof(data_elem_attr_t) + size);

    // model_num
    attr = reinterpret_cast<data_elem_attr_t *> (tmp);
    attr->id = htons(attr_id_model_number);
	str = get_current_cmd()->get_manufacturer_model();
    size = static_cast<short unsigned int> (strlen(str));
    attr->len = htons(size);
    memcpy(attr->val, str, size);

    len += static_cast<unsigned short int> (sizeof(data_elem_attr_t) + size);
    tmp += (sizeof(data_elem_attr_t) + size);

    // serial number    
    attr = reinterpret_cast<data_elem_attr_t *> (tmp);
    attr->id = htons(attr_id_serial_num);
	str = get_current_cmd()->get_serial_number();
    size = static_cast<short unsigned int> (strlen(str));
    attr->len = htons(size);
    memcpy(attr->val, str, size);

    len += static_cast<unsigned short int> (sizeof(data_elem_attr_t) + size);
    tmp += (sizeof(data_elem_attr_t) + size);

    // primary device type
    attr = reinterpret_cast<data_elem_attr_t *> (tmp);
    attr->id = htons(attr_id_primary_device_type);
    size = sizeof(em_short_string_t);
    attr->len = htons(size);
    memcpy(attr->val, get_current_cmd()->get_primary_device_type(), size);

    len += static_cast<unsigned short int> (sizeof(data_elem_attr_t) + size);
    tmp += (sizeof(data_elem_attr_t) + size);

    // device name
    attr = reinterpret_cast<data_elem_attr_t *> (tmp);
    attr->id = htons(attr_id_device_name);
	str = get_current_cmd()->get_manufacturer_model();
    size = static_cast<short unsigned int> (strlen(str));
    attr->len = htons(size);
    memcpy(attr->val, str, size);

    len += static_cast<unsigned short int> (sizeof(data_elem_attr_t) + size);
    tmp += (sizeof(data_elem_attr_t) + size);

    // rf bands Table 6.1.3 - RF Band
    attr = reinterpret_cast<data_elem_attr_t *> (tmp);
    attr->id = htons(attr_id_rf_bands);
    size = 1;
    attr->len = htons(size);
    rf_band = static_cast<em_freq_band_t> (1 << get_band());
    memcpy(attr->val, &rf_band, size);

    len += static_cast<unsigned short int> (sizeof(data_elem_attr_t) + size);
    tmp += (sizeof(data_elem_attr_t) + size);

    // association state
    attr = reinterpret_cast<data_elem_attr_t *> (tmp);
    attr->id = htons(attr_id_assoc_state);
    size = sizeof(unsigned short);
    attr->len = htons(size);
    memcpy(attr->val, &rf_band, sizeof(attr->val));

    len += static_cast<unsigned short int> (sizeof(data_elem_attr_t) + size);
    tmp += (sizeof(data_elem_attr_t) + size);

    // device password id
    attr = reinterpret_cast<data_elem_attr_t *> (tmp);
    attr->id = htons(attr_id_device_password_id);
    size = sizeof(unsigned short);
    attr->len = htons(size);
    memcpy(attr->val, &rf_band, sizeof(attr->val));

    len += static_cast<unsigned short int> (sizeof(data_elem_attr_t) + size);
    tmp += (sizeof(data_elem_attr_t) + size);

    // config error
    attr = reinterpret_cast<data_elem_attr_t *> (tmp);
    attr->id = htons(attr_id_cfg_error);
    size = sizeof(unsigned short);
    attr->len = htons(size);
    memcpy(attr->val, &rf_band, sizeof(attr->val));

    len += static_cast<unsigned short int> (sizeof(data_elem_attr_t) + size);
    tmp += (sizeof(data_elem_attr_t) + size);

    // os version   
    attr = reinterpret_cast<data_elem_attr_t *> (tmp);
    attr->id = htons(attr_id_os_version);
    size = sizeof(unsigned short);
    attr->len = htons(size);
    memcpy(attr->val, &rf_band, sizeof(attr->val));

    len += static_cast<unsigned short int> (sizeof(data_elem_attr_t) + size);
    tmp += (sizeof(data_elem_attr_t) + size);


    return len;
}

unsigned short em_configuration_t::create_error_code_tlv(unsigned char *buff, int val, mac_addr_t sta_mac)
{
    unsigned short len = 0;
    unsigned char *tmp = buff;

    //em_cmd_t *pcmd = get_current_cmd();
    //em_cmd_btm_report_params_t *btm_param = &pcmd->m_param.u.btm_report_params;

    memcpy(tmp, &val, sizeof(unsigned char));
    tmp += sizeof(unsigned char);
    len += static_cast<unsigned short int> (sizeof(unsigned char));

    if(sta_mac != NULL) {
        memcpy(tmp, sta_mac, sizeof(mac_address_t));
    } else {
        memset(tmp, 0, sizeof(mac_address_t));
    }
    
    tmp += sizeof(mac_address_t);
    len += static_cast<unsigned short int> (sizeof(mac_address_t));

    return len;
}

int em_configuration_t::compute_keys(unsigned char *remote_pub, unsigned short pub_len, unsigned char *local_priv, unsigned short priv_len)
{
    unsigned char *secret;
    unsigned short secret_len;
    unsigned char  *addr[3];
    size_t length[3];
    unsigned char  dhkey[SHA256_MAC_LEN];
    unsigned char  kdk  [SHA256_MAC_LEN];
    unsigned char keys[WPS_AUTHKEY_LEN + WPS_KEYWRAPKEY_LEN + WPS_EMSK_LEN];
    char str[] = "Wi-Fi Easy and Secure Key Derivation";

    // first compute keys
    if (compute_secret(&secret, &secret_len, remote_pub, pub_len, local_priv, priv_len) != 1) {
        printf("%s:%d: Shared secret computation failed\n", __func__, __LINE__);
        return -1;
    }

    //printf("%s:%d: Secret Key:\n", __func__, __LINE__);
    //util::print_hex_dump(secret_len, secret);

    addr[0] = secret;
    length[0] = static_cast<size_t> (secret_len);

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

    //printf("%s:%d: e-nonce:\n", __func__, __LINE__);
    //util::print_hex_dump(length[0], addr[0]);
    
    //printf("%s:%d: e-mac:\n", __func__, __LINE__);
    //util::print_hex_dump(length[1], addr[1]);
    
    //printf("%s:%d: r-nonce:\n", __func__, __LINE__);
    //util::print_hex_dump(length[2], addr[2]);
    
    if (compute_kdk(dhkey, SHA256_MAC_LEN, 3, addr, length, kdk) != 1) {
        free(secret);
        printf("%s:%d: kdk computation failed\n", __func__, __LINE__);
        return -1;
    }

    //printf("%s:%d: kdk:\n", __func__, __LINE__);
    //util::print_hex_dump(SHA256_MAC_LEN, kdk);
    if (derive_key(kdk, NULL, 0, str, keys, sizeof(keys)) != 1) {
        free(secret);
        printf("%s:%d: key derivation failed\n", __func__, __LINE__);
        return -1;
    }

    memcpy(m_auth_key, keys, WPS_AUTHKEY_LEN);
    memcpy(m_key_wrap_key, keys + WPS_AUTHKEY_LEN, WPS_KEYWRAPKEY_LEN);
    memcpy(m_emsk, keys + WPS_AUTHKEY_LEN + WPS_KEYWRAPKEY_LEN, WPS_EMSK_LEN);

    //printf("%s:%d: Encrypt/Decrypt Key:\n", __func__, __LINE__);
    //util::print_hex_dump(WPS_EMSK_LEN, m_emsk);

    return 1;
}

int em_configuration_t::create_autoconfig_wsc_m2_msg(unsigned char *buff, em_haul_type_t haul_type[], unsigned int num_hauls)
{
    unsigned short  msg_id = em_msg_type_autoconf_wsc;
    int len = 0;
    unsigned int i;
    em_cmdu_t *cmdu;
    em_tlv_t *tlv;
    unsigned char *tmp = buff;
    unsigned short sz = 0;
    unsigned short type = htons(ETH_P_1905);
	dm_radio_t *radio, *pradio;

	radio = get_radio_from_dm();
	pradio = get_radio_from_dm(true);

    // first compute keys
    if (compute_keys(get_e_public(), static_cast<short unsigned int> (get_e_public_len()), get_r_private(), static_cast<short unsigned int> (get_r_private_len())) != 1) {
        printf("%s:%d: Keys computation failed\n", __func__, __LINE__);
        return -1;
    }

    memcpy(tmp, const_cast<unsigned char *> (get_peer_mac()), sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += static_cast<int> (sizeof(mac_address_t));
    
    memcpy(tmp, get_al_interface_mac(), sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += static_cast<int> (sizeof(mac_address_t));

    memcpy(tmp, reinterpret_cast<unsigned char *> (&type), sizeof(unsigned short));
    tmp += sizeof(unsigned short);
    len += static_cast<int> (sizeof(unsigned short));

    cmdu = reinterpret_cast<em_cmdu_t *> (tmp);

    memset(tmp, 0, sizeof(em_cmdu_t));
    cmdu->type = htons(msg_id);
    cmdu->id = htons(msg_id);
    cmdu->last_frag_ind = 1;

    tmp += sizeof(em_cmdu_t);
    len += static_cast<int> (sizeof(em_cmdu_t));

    // One AP Radio Identifier tlv 17.2.3
    tlv = reinterpret_cast<em_tlv_t *> (tmp);
    tlv->type = em_tlv_type_radio_id;
    memcpy(tlv->value, get_radio_interface_mac(), sizeof(mac_address_t));
    tlv->len = htons(sizeof(mac_address_t));
    
    tmp += (sizeof(em_tlv_t) + sizeof(mac_address_t));
    len += static_cast<int> (sizeof(em_tlv_t) + sizeof(mac_address_t));

	// RDK proprietary tlv for radio enable/disable
	tlv = reinterpret_cast<em_tlv_t *> (tmp);
    tlv->type = em_tlv_type_rdk_radio_enable;
	
	if (pradio != NULL) {
    	memcpy(tlv->value, &pradio->m_radio_info.enabled, sizeof(unsigned char));
		radio->m_radio_info.enabled = pradio->m_radio_info.enabled;
	} else {
    	memcpy(tlv->value, &radio->m_radio_info.enabled, sizeof(unsigned char));
	}

    tlv->len = htons(sizeof(unsigned char));
    
    tmp += (sizeof(em_tlv_t) + sizeof(unsigned char));
    len += static_cast<int> (sizeof(em_tlv_t) + sizeof(unsigned char));

    // As many wsc tlv containing M2 as number of BSS
    for (i = 0; i < num_hauls; i++) {
        tlv = reinterpret_cast<em_tlv_t *> (tmp);
        tlv->type = em_tlv_type_wsc;
        sz = create_m2_msg(tlv->value, haul_type[i]);
        tlv->len = htons(sz);

        tmp += (sizeof(em_tlv_t) + sz);
        len += static_cast<int> (sizeof(em_tlv_t) + sz);
    }

    // default 8022.1q settings tlv 17.2.49
    tlv = reinterpret_cast<em_tlv_t *> (tmp);
    tlv->type = em_tlv_type_dflt_8021q_settings;
    tlv->len = htons(sizeof(em_8021q_settings_t));

    tmp += (sizeof(em_tlv_t) + sizeof(em_8021q_settings_t));
    len += static_cast<int> (sizeof(em_tlv_t) + sizeof(em_8021q_settings_t));

    // traffic separation policy tlv 17.2.50 
    tlv = reinterpret_cast<em_tlv_t *> (tmp);
    tlv->type = em_tlv_type_traffic_separation_policy;
    sz = static_cast<short unsigned int> (create_traffic_separation_policy(tlv->value));
    tlv->len = htons(sz);

    tmp += (sizeof(em_tlv_t) + sz);
    len += static_cast<int> (sizeof(em_tlv_t) + sz);

    // ap mld tlv 17.2.96
    tlv =reinterpret_cast<em_tlv_t *> (tmp);
    tlv->type = em_tlv_type_ap_mld_config;
    sz = static_cast<short unsigned int> (create_ap_mld_config_tlv(tlv->value));
    tlv->len = htons(sz);

    tmp += (sizeof(em_tlv_t) + sz);
    len += static_cast<int> (sizeof(em_tlv_t) + sz);

    // End of message
    tlv = reinterpret_cast<em_tlv_t *> (tmp);
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += static_cast<int> (sizeof (em_tlv_t));

    return len;

}

int em_configuration_t::create_autoconfig_wsc_m1_msg(unsigned char *buff, unsigned char *dst)
{
    unsigned short  msg_id = em_msg_type_autoconf_wsc;
    int len = 0;
    em_cmdu_t *cmdu;
    em_tlv_t *tlv;
    unsigned char *tmp = buff;
    unsigned short sz = 0;
    unsigned short type = htons(ETH_P_1905);

    memcpy(tmp, const_cast<unsigned char *> (dst), sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += static_cast<int> (sizeof(mac_address_t));

    memcpy(tmp, get_current_cmd()->get_al_interface_mac(), sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += static_cast<int> (sizeof(mac_address_t));

    memcpy(tmp, reinterpret_cast<unsigned char *> (&type), sizeof(unsigned short));
    tmp += sizeof(unsigned short);
    len += static_cast<int> (sizeof(unsigned short));

    cmdu = reinterpret_cast<em_cmdu_t *> (tmp);

    memset(tmp, 0, sizeof(em_cmdu_t));
    cmdu->type = htons(msg_id);
    cmdu->id = htons(msg_id);
    cmdu->last_frag_ind = 1;

    tmp += sizeof(em_cmdu_t);
    len += static_cast<int> (sizeof(em_cmdu_t));

    // AP radio basic capabilities 17.2.7
    tlv = reinterpret_cast<em_tlv_t *>(tmp);
    tlv->type = em_tlv_type_ap_radio_basic_cap;
    sz = static_cast<short unsigned int> (create_ap_radio_basic_cap(tlv->value));
    tlv->len = htons(sz);

    tmp += (sizeof(em_tlv_t) + sz);
    len += static_cast<int> (sizeof(em_tlv_t) + sz);

    // One wsc tlv containing M1
    tlv = reinterpret_cast<em_tlv_t *>(tmp);
    tlv->type = em_tlv_type_wsc;
    sz = static_cast<short unsigned int> (create_m1_msg(tlv->value));
    tlv->len = htons(sz);

    tmp += (sizeof(em_tlv_t) + sz);
    len += static_cast<int> (sizeof(em_tlv_t) + sz);

    m_m1_length = sz;
    memcpy(m_m1_msg, const_cast<unsigned char *> (tlv->value), m_m1_length);
    
    // One profile 2 AP capability tlv 17.2.48
    tlv = reinterpret_cast<em_tlv_t *> (tmp);
    tlv->type = em_tlv_type_profile_2_ap_cap;
    tlv->len = htons(sizeof(em_profile_2_ap_cap_t));

    tmp += (sizeof(em_tlv_t) + sizeof(em_profile_2_ap_cap_t));
    len += static_cast<int> (sizeof(em_tlv_t) + sizeof(em_profile_2_ap_cap_t)); 

    // One AP radio advanced capability tlv 17.2.52
    tlv = reinterpret_cast<em_tlv_t *> (tmp);
    tlv->type = em_tlv_type_ap_radio_advanced_cap;
    tlv->len = htons(sizeof(em_ap_radio_advanced_cap_t));

    tmp += (sizeof(em_tlv_t) + sizeof(em_ap_radio_advanced_cap_t));
    len += static_cast<int> (sizeof(em_tlv_t) + sizeof(em_ap_radio_advanced_cap_t));

    // End of message
    tlv = reinterpret_cast<em_tlv_t *> (tmp);
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += static_cast<int> (sizeof(em_tlv_t));

    return len;
}

int em_configuration_t::create_autoconfig_resp_msg(unsigned char *buff, em_freq_band_t band, unsigned char *dst)
{
    unsigned short  msg_id = em_msg_type_autoconf_resp;
    int len = 0;
    em_cmdu_t *cmdu;
    em_tlv_t *tlv;
    em_enum_type_t profile;
    em_ctrl_cap_t   ctrl_cap;
    unsigned char *tmp = buff;
    unsigned short type = htons(ETH_P_1905);
    em_service_type_t   service_type = get_service_type();
    unsigned char registrar = 0;

    memcpy(tmp, const_cast<unsigned char *>(dst), sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += static_cast<int> (sizeof(mac_address_t));

    memcpy(tmp, const_cast<unsigned char *> (get_al_interface_mac()), sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += static_cast<int> (sizeof(mac_address_t));

    memcpy(tmp, reinterpret_cast<unsigned char *> (&type), sizeof(unsigned short));
    tmp += sizeof(unsigned short);
    len += static_cast<int> (sizeof(unsigned short));

    cmdu = reinterpret_cast<em_cmdu_t *> (tmp);

    memset(tmp, 0, sizeof(em_cmdu_t));
    cmdu->type = htons(msg_id);
    cmdu->id = em_configuration_t::msg_id;
    em_configuration_t::msg_id++;
    cmdu->last_frag_ind = 1;
    cmdu->relay_ind = 1;

    tmp += sizeof(em_cmdu_t);
    len += static_cast<int> (sizeof(em_cmdu_t));

    //6-24—SupportedRole TLV
    tlv = reinterpret_cast<em_tlv_t *> (tmp);
    tlv->type = em_tlv_type_supported_role;
    tlv->len = htons(sizeof(unsigned char));
    memcpy(&tlv->value, &registrar, sizeof(unsigned char));

    tmp += (sizeof (em_tlv_t) + 1);
    len += static_cast<int> (sizeof (em_tlv_t) + 1);

    //6-25—supported freq_band TLV
    tlv = reinterpret_cast<em_tlv_t *> (tmp);
    tlv->type = em_tlv_type_supported_freq_band;
    tlv->len = htons(sizeof(unsigned char));
    memcpy(&tlv->value, &band, sizeof(unsigned char));

    tmp += (sizeof (em_tlv_t) + 1);
    len += static_cast<int> (sizeof (em_tlv_t) + 1);

    // supported service tlv 17.2.1
    tlv = reinterpret_cast<em_tlv_t *> (tmp);
    tlv->type = em_tlv_type_supported_service;
    tlv->len = htons(sizeof(em_enum_type_t) + 1);
    tlv->value[0] = 1;
    memcpy(&tlv->value[1], &service_type, sizeof(em_enum_type_t));

    tmp += (sizeof(em_tlv_t) + sizeof(em_enum_type_t) + 1);
    len += static_cast<int> (sizeof(em_tlv_t) + sizeof(em_enum_type_t) + 1);

    // 1905 layer security capability tlv 17.2.67
    tlv = reinterpret_cast<em_tlv_t *> (tmp);
    tlv->type = em_tlv_type_1905_layer_security_cap;
    tlv->len = htons(sizeof(em_ieee_1905_security_cap_t));
    memcpy(tlv->value, get_ieee_1905_security_cap(), sizeof(em_ieee_1905_security_cap_t));

    tmp += (sizeof(em_tlv_t) + sizeof(em_ieee_1905_security_cap_t));
    len += static_cast<int> (sizeof(em_tlv_t) + sizeof(em_ieee_1905_security_cap_t));

    // One multiAP profile tlv 17.2.47
    tlv = reinterpret_cast<em_tlv_t *> (tmp);
    tlv->type = em_tlv_type_profile;
    tlv->len = htons(sizeof(em_enum_type_t));
    profile = em_profile_type_3;
    memcpy(tlv->value, &profile, sizeof(em_enum_type_t));

    tmp += (sizeof(em_tlv_t) + sizeof(em_enum_type_t));
    len += static_cast<int> (sizeof(em_tlv_t) + sizeof(em_enum_type_t));

    // One controller capability tlv 17.2.94
    tlv = reinterpret_cast<em_tlv_t *> (tmp);
    tlv->type = em_tlv_type_ctrl_cap;
    tlv->len = htons(sizeof(em_ctrl_cap_t));
    memset(&ctrl_cap, 0, sizeof(em_ctrl_cap_t));;
    memcpy(tlv->value, &ctrl_cap, sizeof(em_ctrl_cap_t));

    tmp += (sizeof(em_tlv_t) + sizeof(em_ctrl_cap_t));
    len += static_cast<int> (sizeof(em_tlv_t) + sizeof(em_ctrl_cap_t));

    // End of message
    tlv = reinterpret_cast<em_tlv_t *> (tmp);
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += static_cast<int> (sizeof (em_tlv_t));

    return len;

}

int em_configuration_t::create_autoconfig_search_msg(unsigned char *buff)
{
    unsigned short  msg_id = em_msg_type_autoconf_search;
    int len = 0;
    em_cmdu_t *cmdu;
    em_tlv_t *tlv;
    em_enum_type_t searched, profile;
    unsigned char *tmp = buff;
    unsigned short type = htons(ETH_P_1905);
    mac_address_t   multi_addr = {0x01, 0x80, 0xc2, 0x00, 0x00, 0x13};
    em_service_type_t service_type = get_service_type();
    unsigned char registrar = 0;
    em_freq_band_t freq_band;

    memcpy(tmp, const_cast<unsigned char *> (multi_addr), sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += static_cast<int> (sizeof(mac_address_t));

    memcpy(tmp, get_current_cmd()->get_al_interface_mac(), sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += static_cast<int> (sizeof(mac_address_t));

    memcpy(tmp, reinterpret_cast<unsigned char *> (&type), sizeof(unsigned short));
    tmp += sizeof(unsigned short);
    len += static_cast<int> (sizeof(unsigned short));

    cmdu = reinterpret_cast<em_cmdu_t *> (tmp);

    memset(tmp, 0, sizeof(em_cmdu_t));
    cmdu->type = htons(msg_id);
    cmdu->id = em_configuration_t::msg_id;
    em_configuration_t::msg_id++;
    cmdu->last_frag_ind = 1;
    cmdu->relay_ind = 1;

    tmp += sizeof(em_cmdu_t);
    len += static_cast<int> (sizeof(em_cmdu_t));

    // AL MAC Address type TLV
    tlv = reinterpret_cast<em_tlv_t *> (tmp);
    tlv->type = em_tlv_type_al_mac_address;
    tlv->len = htons(sizeof(mac_address_t));
    memcpy(tlv->value,get_current_cmd()->get_al_interface_mac(), sizeof(mac_address_t));

    tmp += (sizeof (em_tlv_t) + sizeof(mac_address_t));
    len += static_cast<int> (sizeof (em_tlv_t) + sizeof(mac_address_t));

    //6-22—SearchedRole TLV
    tlv = reinterpret_cast<em_tlv_t *> (tmp);
    tlv->type = em_tlv_type_searched_role;
    tlv->len = htons(sizeof(unsigned char));
    memcpy(&tlv->value, &registrar, sizeof(unsigned char));

    tmp += (sizeof (em_tlv_t) + 1);
    len += static_cast<int> (sizeof (em_tlv_t) + 1);

    //6-23—autoconf_freq_band TLV
    freq_band = get_band();
    tlv = reinterpret_cast<em_tlv_t *> (tmp);
    tlv->type = em_tlv_type_autoconf_freq_band;
    tlv->len = htons(sizeof(unsigned char));
    memcpy(&tlv->value, &freq_band, sizeof(unsigned char));
 
    tmp += (sizeof (em_tlv_t) + 1);
    len += static_cast<int> (sizeof (em_tlv_t) + 1);

    // supported service 17.2.1
    tlv = reinterpret_cast<em_tlv_t *> (tmp);
    tlv->type = em_tlv_type_supported_service;
    tlv->len = htons(sizeof(em_enum_type_t) + 1);
    tlv->value[0] = 1;
    memcpy(&tlv->value[1], &service_type, sizeof(em_enum_type_t));

    tmp += (sizeof(em_tlv_t) + sizeof(em_enum_type_t) + 1);
    len += static_cast<int> (sizeof(em_tlv_t) + sizeof(em_enum_type_t) + 1);

    // searched service 17.2.2
    tlv = reinterpret_cast<em_tlv_t *> (tmp);
    tlv->type = em_tlv_type_searched_service;
    tlv->len = htons(sizeof(em_enum_type_t) + 1);
    tlv->value[0] = 1;
    searched = em_service_type_ctrl;
    memcpy(&tlv->value[1], &searched, sizeof(em_enum_type_t));

    tmp += (sizeof(em_tlv_t) + sizeof(em_enum_type_t) + 1);
    len += static_cast<int> (sizeof(em_tlv_t) + sizeof(em_enum_type_t) + 1);

    // One multiAP profile tlv 17.2.47
    tlv = reinterpret_cast<em_tlv_t *> (tmp);
    tlv->type = em_tlv_type_profile;
    tlv->len = htons(sizeof(em_enum_type_t));
    profile = em_profile_type_3;
    memcpy(tlv->value, &profile, sizeof(em_enum_type_t));

    tmp += (sizeof(em_tlv_t) + sizeof(em_enum_type_t));
    len += static_cast<int> (sizeof(em_tlv_t) + sizeof(em_enum_type_t));
    

    // End of message
    tlv = reinterpret_cast<em_tlv_t *> (tmp);
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += static_cast<int> (sizeof (em_tlv_t));

    return len;

}

int em_configuration_t::handle_wsc_m2(unsigned char *buff, unsigned int len)
{
    data_elem_attr_t    *attr;
    int ret = 0;
    unsigned int tmp_len;
    unsigned short id;

    printf("%s:%d: Parsing m1 message, len: %d\n", __func__, __LINE__, len);

    m_m2_length = len - 12;
    memcpy(m_m2_msg, buff, m_m2_length);
    
    attr = reinterpret_cast<data_elem_attr_t *> (buff); tmp_len = len;

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
            m_m2_encrypted_settings_len = sizeof(m_m2_encrypted_settings); //work around
        } else if (id == attr_id_authenticator) {
            memcpy(m_m2_authenticator, attr->val, htons(attr->len));
        }

        tmp_len -= static_cast<unsigned int> (sizeof(data_elem_attr_t) + htons(attr->len));
        attr = reinterpret_cast<data_elem_attr_t *>(reinterpret_cast<unsigned char *> (attr) + sizeof(data_elem_attr_t) + htons(attr->len));
    }

    return ret;

}

int em_configuration_t::handle_wsc_m1(unsigned char *buff, unsigned int len)
{
    data_elem_attr_t    *attr;
    int ret = 0;
    unsigned int tmp_len;
    unsigned short id;
    mac_addr_str_t mac_str;
    em_device_info_t    dev_info;
    dm_easy_mesh_t *dm;
    em_freq_band_t  band;
    dm_radio_t *radio;
    unsigned int found = 0, i  = 0;

	dm = get_data_model();
	memset(&dev_info, 0, sizeof(em_device_info_t));

	for (i = 0; i < dm->m_num_radios; i++) {
		radio = dm->get_radio(i);
		if (memcmp(radio->get_radio_interface_mac(), get_radio_interface_mac(), sizeof(mac_address_t)) != 0) {
			continue;
		}
		found++;
		break;
	}

	if (found == 0) {
		printf("%s:%d Failed to find the radio\n", __func__, __LINE__);
		return -1;
	}
    m_m1_length = len;
    memcpy(m_m1_msg, buff, m_m1_length);
    
    attr = reinterpret_cast<data_elem_attr_t *> (buff); tmp_len = len;

    while (tmp_len > 0) {

        id = htons(attr->id);
        if (id == attr_id_version) {
        } else if (id == attr_id_msg_type) {
            if (attr->val[0] != em_wsc_msg_type_m1) {
                return -1;
            }
        } else if (id == attr_id_uuid_e) {
            set_e_uuid(attr->val, htons(attr->len));
            //printf("%s:%d: enrollee uuid length:%d\n", __func__, __LINE__, htons(attr->len));
        } else if (id == attr_id_mac_address) {
            set_e_mac(attr->val);
            dm_easy_mesh_t::macbytes_to_string(attr->val, mac_str);
            //printf("%s:%d: enrollee mac address:%s\n", __func__, __LINE__, mac_str);
        } else if (id == attr_id_enrollee_nonce) {
            set_e_nonce(attr->val, htons(attr->len));
            //printf("%s:%d: enrollee nonce length:%d\n", __func__, __LINE__, htons(attr->len));
        } else if (id == attr_id_public_key) {
            set_e_public(attr->val, htons(attr->len));
            //printf("%s:%d: enrollee public key length:%d\n", __func__, __LINE__, htons(attr->len));
        } else if (id == attr_id_auth_type_flags) {
        } else if (id == attr_id_encryption_type_flags) {
        } else if (id == attr_id_conn_type_flags) {
        } else if (id == attr_id_cfg_methods) {
        } else if (id == attr_id_wifi_wsc_state) {
        } else if (id == attr_id_manufacturer) {
            memcpy(dev_info.manufacturer, attr->val, htons(attr->len));
            set_manufacturer(dev_info.manufacturer);
            //printf("%s:%d: Manufacturer:%s\n", __func__, __LINE__, dev_info.manufacturer);
            dm->set_db_cfg_param(db_cfg_type_device_list_update, "");
        } else if (id == attr_id_model_name) {
            memcpy(dev_info.manufacturer_model, attr->val, htons(attr->len));
            set_manufacturer_model(dev_info.manufacturer_model);
            dm->set_db_cfg_param(db_cfg_type_device_list_update, "");
            //printf("%s:%d: Manufacturer Model:%s\n", __func__, __LINE__, dev_info.manufacturer_model);
        } else if (id == attr_id_model_number) {
        } else if (id == attr_id_serial_num) {
            memcpy(dev_info.serial_number, attr->val, htons(attr->len));
            set_serial_number(dev_info.serial_number);
            //printf("%s:%d: Manufacturer:%s\n", __func__, __LINE__, dev_info.serial_number);
            dm->set_db_cfg_param(db_cfg_type_device_list_update, "");
        } else if (id == attr_id_primary_device_type) {
        } else if (id == attr_id_device_name) {
        } else if (id == attr_id_rf_bands) {
			band = static_cast<em_freq_band_t> (attr->val[0] >> 1);
			printf("%s:%d Freq band = %d \n", __func__, __LINE__,band);
			set_band(band);
			radio->get_radio_info()->band = band;
			dm->set_db_cfg_param(db_cfg_type_radio_list_update, "");
        } else if (id == attr_id_assoc_state) {
        } else if (id == attr_id_device_password_id) {
        } else if (id == attr_id_cfg_error) {
        } else if (id == attr_id_os_version) {
        }

        tmp_len -= static_cast<unsigned int> (sizeof(data_elem_attr_t) + htons(attr->len));
        attr = reinterpret_cast<data_elem_attr_t *> (reinterpret_cast<unsigned char *> (attr) + sizeof(data_elem_attr_t) + htons(attr->len));
    }

    return ret;

}

int em_configuration_t::handle_autoconfig_wsc_m2(unsigned char *buff, unsigned int len)
{
    em_tlv_t *tlv;
    int tmp_len;
    char *errors[EM_MAX_TLV_MEMBERS] = {0};
    bool found_wsc = false;
    unsigned char hash[SHA256_MAC_LEN];
    dm_easy_mesh_t *dm;
    dm_network_t network;
    em_raw_hdr_t *hdr = reinterpret_cast<em_raw_hdr_t *> (buff);

    if (em_msg_t(em_msg_type_autoconf_wsc, m_peer_profile, buff, len).validate(errors) == 0) {
        printf("%s:%d: received wsc m2 msg failed validation\n", __func__, __LINE__);

        return -1;
    }
   
    tlv =  reinterpret_cast<em_tlv_t *> (buff + sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));
    tmp_len = static_cast<int> (len - (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t)));

    while ((tlv->type != em_tlv_type_eom) && (tmp_len > 0)) {
        if (tlv->type != em_tlv_type_wsc) {
            tmp_len -= static_cast<int> (sizeof(em_tlv_t) + htons(tlv->len));
            tlv = reinterpret_cast<em_tlv_t *> (reinterpret_cast<unsigned char *> (tlv) + sizeof(em_tlv_t) + htons(tlv->len));

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
    if (compute_keys(get_r_public(), static_cast<short unsigned int> (get_r_public_len()), get_e_private(), static_cast<short unsigned int> (get_e_private_len())) != 1) {
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

    dm = get_data_model();
    //Commit controller mac address
    if ((dm != NULL) && (hdr != NULL)) {
        memcpy(&network.m_net_info.ctrl_id.mac, &hdr->src, sizeof(mac_address_t));
        dm->set_network(network);
    }
    return 0;
}

int em_configuration_t::handle_encrypted_settings()
{
    data_elem_attr_t    *attr;
    int tmp_len, ret = 0;
    unsigned short id;
    char pass[64] = {0};
    mac_addr_str_t mac_str;
    unsigned char *plain;
    unsigned short plain_len;
    unsigned short auth_type;
    int index = -1;
    m2ctrl_radioconfig radioconfig;
    plain = m_m2_encrypted_settings + AES_BLOCK_SIZE;
    plain_len = static_cast<short unsigned int> (m_m2_encrypted_settings_len - AES_BLOCK_SIZE);
    radioconfig.noofbssconfig = 0;

    // first decrypt the encrypted m2 data

    if (em_crypto_t::platform_aes_128_cbc_decrypt(m_key_wrap_key, m_m2_encrypted_settings, plain, plain_len) != 1) {
        printf("%s:%d: platform decrypt failed\n", __func__, __LINE__);
        return 0;
    }

    attr = reinterpret_cast<data_elem_attr_t *> (plain);
    tmp_len = plain_len;
    radioconfig.freq = get_band();

    while (tmp_len > 0) {

        id = htons(attr->id);
        if (id == attr_id_no_of_haul_type) {
            radioconfig.noofbssconfig	 = attr->val[0];
            printf("%s:%d: noofbss configuration recv=%d\n", __func__, __LINE__,radioconfig.noofbssconfig);
        } else if (id == attr_id_haul_type) {
            index++;
            radioconfig.haultype[index] = static_cast<em_haul_type_t> (attr->val[0]);
        } else if (id == attr_id_ssid) {
        //If controller does not support no of haultype parameter
            if (index == -1) {
                index = 0;
            }
            memcpy(radioconfig.ssid[index], attr->val, sizeof(radioconfig.ssid[index]));
            radioconfig.enable[index] = true;
            printf("%s:%d: ssid attrib: %s\n", __func__, __LINE__, radioconfig.ssid[index]);
            memcpy(radioconfig.radio_mac[index], get_radio_interface_mac(), sizeof(mac_address_t));
        } else if (id == attr_id_auth_type) {
            memcpy(reinterpret_cast<char *> (&auth_type), reinterpret_cast<unsigned char *> (attr->val), htons(attr->len));
            radioconfig.authtype[index] = static_cast<unsigned int>(auth_type);
        } else if (id == attr_id_encryption_type) {
            printf("%s:%d: encr type attrib\n", __func__, __LINE__);
        } else if (id == attr_id_network_key) {
            memcpy(pass, attr->val, htons(attr->len));
            memcpy(radioconfig.password[index], attr->val, htons(attr->len));
            printf("%s:%d: network key attrib: %s\n", __func__, __LINE__, pass);
        } else if (id == attr_id_mac_address) {
            dm_easy_mesh_t::macbytes_to_string(attr->val, mac_str);
            printf("%s:%d: mac address attrib: %s\n", __func__, __LINE__, mac_str);
            memcpy(radioconfig.radio_mac[index], attr->val, sizeof(mac_address_t));
        } else if (id == attr_id_key_wrap_authenticator) {
            printf("%s:%d: key wrap auth attrib\n", __func__, __LINE__);
            radioconfig.key_wrap_authenticator[index] = attr->val[0];
        }
        tmp_len -= static_cast<int> (sizeof(data_elem_attr_t) + htons(attr->len));
        attr = reinterpret_cast<data_elem_attr_t *> (reinterpret_cast<unsigned char *>(attr) + sizeof(data_elem_attr_t) + htons(attr->len));
    }

    get_mgr()->io_process(em_bus_event_type_m2ctrl_configuration, reinterpret_cast<unsigned char *> (&radioconfig), sizeof(radioconfig));
    set_state(em_state_agent_owconfig_pending);
    if (get_service_type() == em_service_type_agent) {
        get_ec_mgr().upgrade_to_onboarded_proxy_agent();
    }
    return ret;
}

int em_configuration_t::create_encrypted_settings(unsigned char *buff, em_haul_type_t haul_type)
{
	data_elem_attr_t *attr;
	short len = 0;
	unsigned char *tmp;
	unsigned int size = 0, cipher_len, plain_len;
	unsigned char iv[AES_BLOCK_SIZE];
	unsigned char plain[MAX_EM_BUFF_SZ];
	unsigned short auth_type = 0x0010;
	em_network_ssid_info_t *net_ssid_info;
	em_haul_type_t haultype_precedence[em_haul_type_max] = {em_haul_type_fronthaul, em_haul_type_backhaul, em_haul_type_iot, em_haul_type_configurator, em_haul_type_hotspot};
	memset(plain, 0, MAX_EM_BUFF_SZ);
	tmp = plain;
	len = 0;

	dm_easy_mesh_t *dm = get_data_model();
	unsigned int no_of_haultype = 0, radio_exists, i;
	dm_radio_t * radio = NULL;
	bool is_colocated = dm->get_colocated();

	for (i = 0; i < dm->get_num_radios(); i++) {
		radio = dm->get_radio(i);
		if (memcmp(radio->m_radio_info.id.ruid, get_radio_interface_mac(), sizeof(mac_address_t)) == 0) {
			radio_exists = true;
			break;
		}
	}
	if (radio_exists == false) {
		printf("%s:%d: Radio does not exist, getting radio at index: %d\n", __func__, __LINE__, dm->get_num_radios());
		no_of_haultype = 1;
	} else {
		no_of_haultype = radio->m_radio_info.number_of_bss;
		if (no_of_haultype >= em_haul_type_max) {
			no_of_haultype = em_haul_type_max ;
		}
	}

	if (get_band() == 2) {
		auth_type = 0x0200;
	}

	printf("%s:%d No of haultype=%d radio no of bss=%d \n", __func__, __LINE__,no_of_haultype, radio->m_radio_info.number_of_bss);

	// haultype
	attr = reinterpret_cast<data_elem_attr_t *> (tmp);
	attr->id = htons(attr_id_no_of_haul_type);
	size = 1;
	attr->len = htons(static_cast<short unsigned int> (size));
	memcpy(reinterpret_cast<char *> (attr->val), reinterpret_cast<unsigned char *> (&no_of_haultype), sizeof(no_of_haultype));

	len += static_cast<short> (sizeof(data_elem_attr_t) + size);
	tmp += (sizeof(data_elem_attr_t) + size);
	for (i = 0; i < no_of_haultype; i++) {
		if(is_colocated && no_of_haultype == 1 && (memcmp(get_radio_interface_mac(), dm->get_agent_al_interface_mac(), ETH_ALEN) == 0)) {
			printf("\n%s:%d: Colocated and Single BSS. Configuring em_haul_type_backhaul \n", __func__, __LINE__);
			haul_type = em_haul_type_backhaul;
		} else {
			haul_type = static_cast<em_haul_type_t> (haultype_precedence[i]);
		}
		if ((net_ssid_info = get_network_ssid_info_by_haul_type(haul_type)) == NULL) {
			printf("%s:%d: Could not find network ssid information for haul type %d\n", __func__, __LINE__, haul_type);
			continue;
		}
		printf("%s:%d: ssid: %s, passphrase: %s\n", __func__, __LINE__, net_ssid_info->ssid, net_ssid_info->pass_phrase);
	
		// haultype
		attr = reinterpret_cast<data_elem_attr_t *> (tmp);
		attr->id = htons(attr_id_haul_type);
		size = sizeof(em_haul_type_t);
		attr->len = htons(static_cast<short unsigned int> (size));
		attr->val[0] = haul_type;

		len += static_cast<short> (sizeof(data_elem_attr_t) + size);
		tmp += (sizeof(data_elem_attr_t) + size);

		// ssid
		attr = reinterpret_cast<data_elem_attr_t *> (tmp);
		attr->id = htons(attr_id_ssid);
		size = static_cast<unsigned int> (strlen(net_ssid_info->ssid) + 1);
		attr->len = htons(static_cast<short unsigned int> (size));
		snprintf(reinterpret_cast<char *> (attr->val), size, "%s", net_ssid_info->ssid);

		len += static_cast<short> (sizeof(data_elem_attr_t) + size);
		tmp += (sizeof(data_elem_attr_t) + size);

		// auth type
		attr = reinterpret_cast<data_elem_attr_t *> (tmp);
		attr->id = htons(attr_id_auth_type);
		size = sizeof(auth_type);
		attr->len = htons(static_cast<short unsigned int> (size));
		memcpy(reinterpret_cast<char *> (attr->val), reinterpret_cast<unsigned char *> (&auth_type), size);

		len += static_cast<short> (sizeof(data_elem_attr_t) + size);
		tmp += (sizeof(data_elem_attr_t) + size);

		// network key
		attr = reinterpret_cast<data_elem_attr_t *> (tmp);
		attr->id = htons(attr_id_network_key);
		size = static_cast<unsigned int> (strlen(net_ssid_info->pass_phrase) + 1);
		attr->len = htons(static_cast<short unsigned int> (size));
		snprintf(reinterpret_cast<char *> (attr->val), size, "%s", net_ssid_info->pass_phrase);

		len += static_cast<short> (sizeof(data_elem_attr_t) + size);
		tmp += (sizeof(data_elem_attr_t) + size);

		// mac adress
		attr = reinterpret_cast<data_elem_attr_t *> (tmp);
		attr->id = htons(attr_id_mac_address);
		size = sizeof(mac_address_t);
		attr->len = htons(static_cast<short unsigned int> (size));
		memcpy(reinterpret_cast<char *> (attr->val), const_cast<unsigned char *> (get_radio_interface_mac()), size);

		len += static_cast<short> (sizeof(data_elem_attr_t) + size);
		tmp += (sizeof(data_elem_attr_t) + size);

		// key wrap
		attr = reinterpret_cast<data_elem_attr_t *> (tmp);
		attr->id = htons(attr_id_key_wrap_authenticator);
		size = 32;
		attr->len = htons(static_cast<short unsigned int> (size));

		len += static_cast<short> (sizeof(data_elem_attr_t) + size);
		tmp += (sizeof(data_elem_attr_t) + size);

	}

	if (em_crypto_t::generate_iv(iv, AES_BLOCK_SIZE) != 1) {
		printf("%s:%d: iv generate failed\n", __func__, __LINE__);
		return 0;
	}

	memcpy(buff, iv, AES_BLOCK_SIZE);

	plain_len = static_cast<unsigned int> (len + (AES_BLOCK_SIZE - len%AES_BLOCK_SIZE));

	// encrypt the m2 data
	if (em_crypto_t::platform_aes_128_cbc_encrypt(m_key_wrap_key, iv, plain, plain_len, buff + AES_BLOCK_SIZE, &cipher_len) != 1) {
		printf("%s:%d: platform encrypt failed\n", __func__, __LINE__);
		return 0;
	}

	return static_cast<int> (cipher_len) + AES_BLOCK_SIZE;
}

int em_configuration_t::create_authenticator(unsigned char *buff)
{
    unsigned char *addr[2];
    size_t length[2];
    unsigned char hash[SHA256_MAC_LEN];

    addr[0] = m_m1_msg;
    addr[1] = m_m2_msg;
    length[0] = m_m1_length;
    length[1] = m_m2_length;

    //printf( "%s:%d m1 addr:%s::length:%d,\n", __func__, __LINE__, addr[0], length[0]);
    //util::print_hex_dump(length[0], addr[0]);
    //printf( "%s:%d m2 addr:%s::length:%d,\n", __func__, __LINE__, addr[1], length[1]);
    //util::print_hex_dump(length[1], addr[1]);

    if (em_crypto_t::platform_hmac_SHA256(m_auth_key, WPS_AUTHKEY_LEN, 2, addr, length, hash) != 1) {
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
    unsigned int tmp_len_tlvs, tmp_len_attribs;

    tlv = reinterpret_cast<em_tlv_t *> (buff); tmp_len_tlvs = len;

    while ((tlv->type != em_tlv_type_eom) && (tmp_len_tlvs > 0)) {
        if (tlv->type == em_tlv_type_wsc) {
            tmp_len_attribs = tlv->len;
            attr = reinterpret_cast<data_elem_attr_t *> (tlv->value);

            while (tmp_len_attribs > 0) {

                if (htons(attr->id) == attr_id_msg_type) {
                    return static_cast<em_wsc_msg_type_t> (attr->val[0]);
                }

                tmp_len_attribs -=  static_cast<unsigned int> (sizeof(data_elem_attr_t) + htons(attr->len));
                attr = reinterpret_cast<data_elem_attr_t *> (reinterpret_cast<unsigned char *> (attr) + sizeof(data_elem_attr_t) + htons(attr->len));
            }
        }

        tmp_len_tlvs -= static_cast<unsigned int> (sizeof(em_tlv_t) + htons(tlv->len));
        tlv = reinterpret_cast<em_tlv_t *> (reinterpret_cast<unsigned char *> (tlv) + sizeof(em_tlv_t) + htons(tlv->len));

    }

    return em_wsc_msg_type_none;
}

int em_configuration_t::handle_ap_radio_advanced_cap(unsigned char *buff, unsigned int len)
{
    //dm_easy_mesh_t *dm;
    //dm = get_data_model();

    return 0;
}

int em_configuration_t::handle_ap_radio_basic_cap(unsigned char *buff, unsigned int len)
{
	dm_radio_t * radio;
	mac_address_t	ruid;
	unsigned int i, j;
	em_radio_info_t *radio_info;
	bool radio_exists = false;
	bool op_class_exists = false;
	mac_addr_str_t mac_str;
	em_ap_radio_basic_cap_t		*radio_basic_cap = reinterpret_cast<em_ap_radio_basic_cap_t *> (buff);
	em_op_class_t *basic_cap_op_class;
	em_op_class_info_t	op_class_info;
	dm_op_class_t *op_class_obj;

	dm_easy_mesh_t *dm = get_data_model();

	memcpy(ruid, radio_basic_cap->ruid, sizeof(mac_address_t));
	dm_easy_mesh_t::macbytes_to_string(ruid, mac_str);
	for (i = 0; i < dm->get_num_radios(); i++) {
		radio = dm->get_radio(i);
		if (memcmp(radio->m_radio_info.intf.mac, ruid, sizeof(mac_address_t)) == 0) {
			radio_exists = true;
			break;
		}
	}
	if (radio_exists == false) {
		printf("%s:%d: Radio does not exist, getting radio at index: %d\n", __func__, __LINE__, dm->get_num_radios());
		radio = dm->get_radio(dm->get_num_radios());
		memset(&radio->m_radio_info, 0, sizeof(em_radio_info_t));	
		dm->set_num_radios(dm->get_num_radios() + 1);
	}

	radio_info = &radio->m_radio_info;
	memcpy(radio_info->intf.mac, ruid, sizeof(mac_address_t));
	radio_info->enabled = true;
	radio_info->number_of_bss = radio_basic_cap->num_bss;
	dm->set_db_cfg_param(db_cfg_type_radio_list_update, "");

	basic_cap_op_class = radio_basic_cap->op_classes;
	if (basic_cap_op_class != NULL) {
		for (i = 0; i < radio_basic_cap->op_class_num; i++) {
			memset(&op_class_info, 0, sizeof(em_op_class_info_t));
			memcpy(op_class_info.id.ruid, ruid, sizeof(mac_address_t));
			op_class_info.id.type = em_op_class_type_capability;
			op_class_info.op_class = static_cast<unsigned int> (basic_cap_op_class->op_class);
			op_class_info.id.op_class = op_class_info.op_class;
			op_class_info.max_tx_power = static_cast<int> (basic_cap_op_class->max_tx_eirp);
			op_class_info.num_channels = static_cast<unsigned int> (basic_cap_op_class->num);
			for (j = 0; j < op_class_info.num_channels; j++) {
				op_class_info.channels[j] = static_cast<unsigned int> (basic_cap_op_class->channels.channel[j]);
			}
			basic_cap_op_class = reinterpret_cast<em_op_class_t *>(reinterpret_cast<unsigned char *> (basic_cap_op_class) + sizeof(em_op_class_t) + op_class_info.num_channels);
 			op_class_obj = &dm->m_op_class[0];
			op_class_obj = &dm->m_op_class[0];
			// now check if the op_class already exists
			for (j = 0; j < dm->get_num_op_class(); j++) {
				op_class_obj = &dm->m_op_class[j];
				if (*op_class_obj == dm_op_class_t(&op_class_info)) {
					op_class_exists = true;
					break;
				}
			}

			if (op_class_exists == true) {
				op_class_exists = false;
			} else {
				op_class_obj = &dm->m_op_class[dm->get_num_op_class()];
				dm->set_num_op_class(dm->get_num_op_class() + 1);
			}
			memcpy(&op_class_obj->m_op_class_info, &op_class_info, sizeof(em_op_class_info_t));
			dm->set_db_cfg_param(db_cfg_type_op_class_list_update, "");
		}
	} else {
		printf("%s:%d basic_cap_op_class is NULL \n", __func__, __LINE__);
	}

	return 0;
}

int em_configuration_t::handle_autoconfig_wsc_m1(unsigned char *buff, unsigned int len)
{
    unsigned char msg[MAX_EM_BUFF_SZ*EM_MAX_BANDS];
    unsigned int sz;
    char *errors[EM_MAX_TLV_MEMBERS] = {0};
    mac_addr_str_t  mac_str;
    em_tlv_t    *tlv;
    unsigned int tlv_len;
    em_bus_event_type_m2_tx_params_t   raw;
    em_haul_type_t haul_type[1];


    dm_easy_mesh_t::macbytes_to_string(get_peer_mac(), mac_str);
    printf("%s:%d: Device AL MAC: %s\n", __func__, __LINE__, mac_str);

    if (em_msg_t(em_msg_type_autoconf_wsc, em_profile_type_3, buff, len).validate(errors) == 0) {
        printf("%s:%d: received autoconfig wsc m1 msg failed validation\n", __func__, __LINE__);

        //return -1;
    }

    tlv = reinterpret_cast<em_tlv_t *>(buff + sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t)); 
    tlv_len = len - static_cast<unsigned int> (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));

    while ((tlv->type != em_tlv_type_eom) && (len > 0)) {
        if (tlv->type == em_tlv_type_ap_radio_basic_cap) {
            handle_ap_radio_basic_cap(tlv->value, htons(tlv->len));
        } else if (tlv->type == em_tlv_type_wsc) {
            handle_wsc_m1(tlv->value, htons(tlv->len));
        } else if (tlv->type == em_tlv_type_profile_2_ap_cap) {
        } else if (tlv->type == em_tlv_type_ap_radio_advanced_cap) {
            handle_ap_radio_advanced_cap(tlv->value, htons(tlv->len));
        }

        tlv_len -= static_cast<unsigned int> (sizeof(em_tlv_t) + htons(tlv->len));
        tlv = reinterpret_cast<em_tlv_t *> (reinterpret_cast<unsigned char *> (tlv) + sizeof(em_tlv_t) + htons(tlv->len));
    }

    haul_type[0] = em_haul_type_fronthaul;
    sz = static_cast<unsigned int> (create_autoconfig_wsc_m2_msg(msg, haul_type, 1));

    if (em_msg_t(em_msg_type_autoconf_wsc, em_profile_type_3, msg, sz).validate(errors) == 0) {
        printf("Autoconfig wsc m2 msg failed validation in tnx end\n");

        return -1;
    }

    if (send_frame(msg, sz)  < 0) {
        printf("%s:%d: autoconfig wsc m2 send failed, error:%d\n", __func__, __LINE__, errno);
        return -1;
    }
	set_state(em_state_ctrl_wsc_m2_sent);
	printf("%s:%d: autoconfig wsc m2 send\n", __func__, __LINE__);
    memcpy(raw.al, const_cast<unsigned char *> (get_peer_mac()), sizeof(mac_address_t));
    memcpy(raw.radio, get_radio_interface_mac(), sizeof(mac_address_t));

	get_mgr()->io_process(em_bus_event_type_m2_tx, reinterpret_cast<unsigned char *> (&raw), sizeof(em_bus_event_type_m2_tx_params_t));


    return 0;
}

int em_configuration_t::handle_autoconfig_resp(unsigned char *buff, unsigned int len)
{
    unsigned char msg[MAX_EM_BUFF_SZ];
    unsigned int sz;
    char *errors[EM_MAX_TLV_MEMBERS] = {0};
    em_raw_hdr_t *hdr = reinterpret_cast<em_raw_hdr_t *> (buff);

    if (em_msg_t(buff + (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t)),
                len - static_cast<unsigned int>(sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t))).get_profile_type(&m_peer_profile) == false) {
        printf("%s:%d: Could not get peer profile type\n", __func__, __LINE__);
        return -1;
    }

    if (em_msg_t(em_msg_type_autoconf_resp, m_peer_profile, buff, len).validate(errors) == 0) {
        printf("received autoconfig resp msg failed validation\n");

        return -1;
    }
    printf("Received resp and validated...creating M1 msg\n");
    sz = static_cast<unsigned int> (create_autoconfig_wsc_m1_msg(msg, hdr->src));

    if (em_msg_t(em_msg_type_autoconf_wsc, em_profile_type_3, msg, sz).validate(errors) == 0) {
        printf("autoconfig wsc m1 validation failed\n");

        return -1;
    }

    if (send_frame(msg, sz)  < 0) {
        printf("%s:%d: autoconfig wsc m1 send failed, error:%d\n", __func__, __LINE__, errno);

        return -1;
    }
    em_printf("autoconfig wsc m1 send successful");
    printf("%s:%d: autoconfig wsc m1 send success\n", __func__, __LINE__);
    set_state(em_state_agent_wsc_m2_pending);

    return 0;   
}

int em_configuration_t::handle_autoconfig_search(unsigned char *buff, unsigned int len)
{
    unsigned char msg[MAX_EM_BUFF_SZ];
    unsigned int sz = 0;
    char *errors[EM_MAX_TLV_MEMBERS] = {0};

    em_freq_band_t  band;
    mac_address_t al_mac;

    if (em_msg_t(em_msg_type_autoconf_search, em_profile_type_3, buff, len).validate(errors) == 0) {
        printf("received autoconfig search msg failed validation\n");
    
        return -1;
    }
    if (em_msg_t(buff + (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t)),
               len - static_cast<unsigned int> (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t))).get_profile_type(&m_peer_profile) == false) { 
        printf("%s:%d: Could not get peer profile type\n", __func__, __LINE__);
    } else {
        m_peer_profile = em_profile_type_1;
    }

    if (em_msg_t(buff + (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t)), len - static_cast<unsigned int> (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t))).get_freq_band(&band) == false) {
        printf("%s:%d: Could not get freq band\n", __func__, __LINE__);
        return -1;
    }

    if (em_msg_t(buff + (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t)), len - static_cast<unsigned int> (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t))).get_al_mac_address(al_mac) == false) {
        printf("%s:%d: Could not get al mac address\n", __func__, __LINE__);
        return -1;
    }
    
    sz = static_cast<unsigned int> (create_autoconfig_resp_msg(msg, band, al_mac));
    if (em_msg_t(em_msg_type_autoconf_resp, em_profile_type_3, msg, sz).validate(errors) == 0) {
        printf("%s:%d: autoconfig rsp validation failed\n", __func__, __LINE__);

        //return -1;
    }

    if (send_frame(msg, sz)  < 0) {
        printf("%s:%d: autoconfig rsp send failed, error:%d\n", __func__, __LINE__, errno);

        return -1;
    }
    printf("%s:%d: autoconfig rsp send success\n", __func__, __LINE__);
    set_state(em_state_ctrl_wsc_m1_pending);

    return 0;

}

int em_configuration_t::handle_autoconfig_renew(unsigned char *buff, unsigned int len)
{
    em_raw_hdr_t *hdr;
    char* errors[EM_MAX_TLV_MEMBERS];
    em_bus_event_type_cfg_renew_params_t raw;

    if (em_msg_t(em_msg_type_autoconf_renew, em_profile_type_2, buff, len).validate(errors) == 0) {

        printf("autoconfig renew validation failed\n");
        return -1;

    }

    hdr = reinterpret_cast<em_raw_hdr_t *> (buff);

    memcpy(raw.radio, get_radio_interface_mac(), sizeof(mac_address_t));
    memcpy(raw.ctrl_src, hdr->src, sizeof(mac_address_t));
    
	get_mgr()->io_process(em_bus_event_type_cfg_renew, reinterpret_cast<unsigned char *> (&raw), sizeof(em_bus_event_type_cfg_renew_params_t));

    return 0;
}

void em_configuration_t::process_msg(unsigned char *data, unsigned int len)
{
    em_cmdu_t *cmdu;
    unsigned char *tlvs;
    unsigned int tlvs_len;

    cmdu = reinterpret_cast<em_cmdu_t *>(data + sizeof(em_raw_hdr_t));
            
    tlvs = data + sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t);
    tlvs_len = len - static_cast<unsigned int> (sizeof(em_raw_hdr_t) - sizeof(em_cmdu_t));

    switch (htons(cmdu->type)) {
        case em_msg_type_autoconf_search:
            if (get_service_type() == em_service_type_ctrl) {
                handle_autoconfig_search(data, len);

            } else if (get_service_type() == em_service_type_agent) {
                printf("%s:%d: received em_msg_type_autoconf_search message in agent ... dropping\n", __func__, __LINE__);
            }

            break;

        case em_msg_type_autoconf_resp:
            if ((get_service_type() == em_service_type_agent) && (get_state() == em_state_agent_autoconfig_rsp_pending)) {
                handle_autoconfig_resp(data, len);
            }
            break;

        case em_msg_type_autoconf_wsc:
            if ((get_wsc_msg_type(tlvs, tlvs_len) == em_wsc_msg_type_m2) &&
                    (get_service_type() == em_service_type_agent) && (get_state() == em_state_agent_wsc_m2_pending)) {
                handle_autoconfig_wsc_m2(data, len);              
            } else if ((get_wsc_msg_type(tlvs, tlvs_len) == em_wsc_msg_type_m1) &&
                    (get_service_type() == em_service_type_ctrl) && (get_state() == em_state_ctrl_wsc_m1_pending))  {
                handle_autoconfig_wsc_m1(data, len);
            }

            break;

        case em_msg_type_autoconf_renew:
            if (get_service_type() == em_service_type_agent) {
                handle_autoconfig_renew(data, len);
            }
            break;

        case em_msg_type_topo_query:
            if ((get_service_type() == em_service_type_agent) && (get_state() == em_state_agent_onewifi_bssconfig_ind)) {
                send_topology_response_msg(data);
            }
			break;

        case em_msg_type_topo_resp:
            if ((get_service_type() == em_service_type_ctrl) && (get_state() == em_state_ctrl_topo_sync_pending)) {
			    if (handle_topology_response(data, len) == 0) {
					set_state(em_state_ctrl_topo_synchronized);
				} else {
					printf("%s:%d em_msg_type_topo_resp handle failed \n", __func__, __LINE__);
				}
				
            }			
            break;

        case em_msg_type_topo_notif:
            if ((get_service_type() == em_service_type_ctrl) && (get_state() >= em_state_ctrl_topo_synchronized)) {
                handle_topology_notification(data, len);
            }
            break;
        
        case em_msg_type_ap_mld_config_req:
            if ((get_service_type() == em_service_type_agent)) {
                handle_ap_mld_config_req(data, len);
                send_ap_mld_config_resp_msg(data);
            }
            break;
        
        case em_msg_type_bsta_mld_config_req:
            if ((get_service_type() == em_service_type_ctrl) && (get_state() == em_state_ctrl_bsta_mld_config_pending)) {
                handle_bsta_mld_config_req(data, len);
            }
            break;
            
        case em_msg_type_ap_mld_config_resp:
            if ((get_service_type() == em_service_type_ctrl)) {
                handle_ap_mld_config_resp(data, len);
            }
            break;

        case em_msg_type_1905_ack:
            handle_ack_msg(data, len);

        default:
            break;
    }
}

void em_configuration_t::handle_state_config_none()
{
    bool is_dpp_onboarding = get_ec_mgr().is_enrollee_onboarding();
    if (is_dpp_onboarding) {
        // Enrollee is in onboarding state, so we should not send autoconfig search message
        return;
    }

    unsigned char buff[MAX_EM_BUFF_SZ];
    unsigned int sz;
    char* errors[EM_MAX_TLV_MEMBERS] = {0};

    sz = static_cast<unsigned int> (create_autoconfig_search_msg(buff));
    if (em_msg_t(em_msg_type_autoconf_search, em_profile_type_3, buff, sz).validate(errors) == 0) {
        printf("Autoconfig_search validation failed\n");

        return;
    }

    if (send_frame(buff, sz, true)  < 0) {
        printf("%s:%d: failed, err:%d\n", __func__, __LINE__, errno);
        return;
    }
    em_printf("autoconfig_search send successful");
    printf("%s:%d: autoconfig_search send successful\n", __func__, __LINE__);
    set_state(em_state_agent_autoconfig_rsp_pending);

    return;

}

void em_configuration_t::handle_state_autoconfig_renew()
{
    unsigned char msg[MAX_EM_BUFF_SZ];
    unsigned int sz;
    char *errors[EM_MAX_TLV_MEMBERS] = {0};
    mac_address_t ctrl_src;


    memcpy(ctrl_src, get_current_cmd()->get_data_model()->get_controller_interface_mac(), sizeof(mac_address_t));
    sz = static_cast<unsigned int> (create_autoconfig_wsc_m1_msg(msg, ctrl_src));

    if (em_msg_t(em_msg_type_autoconf_wsc, em_profile_type_3, msg, sz).validate(errors) == 0) {
        printf("autoconfig wsc m1 validation failed\n");
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

void em_configuration_t::fill_media_data(em_media_spec_data_t *spec)
{
    spec->media_type = EM_MEDIA_WIFI_80211b_2_4;
    spec->media_spec_size = 10;
}

void em_configuration_t::process_agent_state()
{
    switch (get_state()) {
        case em_state_agent_unconfigured:
            handle_state_config_none();
            break;

        case em_state_agent_autoconfig_rsp_pending:
            handle_state_autoconfig_rsp_pending();
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
    switch (get_state()) {
        case em_state_ctrl_misconfigured:
            send_autoconfig_renew_msg();
            break;

        case em_state_ctrl_topo_sync_pending:
            send_topology_query_msg();
            break;

        case em_state_ctrl_ap_mld_config_pending:
            send_ap_mld_config_req_msg();
            break;
        default:
            printf("%s:%d: unhandled case %s\n", __func__, __LINE__, em_t::state_2_str(get_state()));
            break;
    }

}

em_configuration_t::em_configuration_t()
{
    m_renew_tx_cnt = 0;
    m_topo_query_tx_cnt = 0;
}

em_configuration_t::~em_configuration_t()
{

}

