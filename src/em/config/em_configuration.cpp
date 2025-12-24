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
#include <string>
#include <vector>
#include <algorithm>
#include "em_configuration.h"
#include "em_msg.h"
#include "dm_easy_mesh.h"
#include "em_cmd.h"
#include "util.h"
#include "em_crypto.h"
#include "em.h"
#include "em_cmd_exec.h"
#include "cjson_util.h"
#include "ec_ctrl_configurator.h"

#include "wifi_util.h"

// Initialize the static member variables
unsigned short em_configuration_t::msg_id = 0;
// OUI value of Comcast
static const unsigned char em_vendor_oui[EM_VENDOR_OUI_SIZE] = {0xd8, 0x9c, 0x8e};

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
    unsigned short  msg_type = em_msg_type_topo_notif;
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
    cmdu->type = htons(msg_type);
    cmdu->id = htons(get_mgr()->get_next_msg_id());
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

    printf("%s:%d Create topology notification msg successful, len:%d\n", __func__, __LINE__, len);

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
    unsigned short  msg_type = em_msg_type_autoconf_renew;
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
    cmdu->type = htons(msg_type);
    cmdu->id = htons(get_mgr()->get_next_msg_id());
    cmdu->last_frag_ind = 1;
    cmdu->relay_ind = 1;

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

    dm_easy_mesh_t::macbytes_to_string (get_radio_interface_mac(), mac_str);
    if (send_frame(buff, len)  < 0) {
        printf("%s:%d: Autoconfig Renew send failed, error:%d for %s\n", __func__, __LINE__, errno, mac_str);
        return -1;
    }

    m_renew_tx_cnt++;
    printf("%s:%d: AutoConfig Renew (%d) Send Successful for %s freq band=%d\n", __func__, __LINE__, m_renew_tx_cnt, mac_str, get_band());

    return static_cast<int> (len);
}

int em_configuration_t::send_topology_query_msg()
{
    unsigned char buff[MAX_EM_BUFF_SZ];
    char *errors[EM_MAX_TLV_MEMBERS] = {0};
    unsigned short  msg_type = em_msg_type_topo_query;
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
    cmdu->type = htons(msg_type);
    cmdu->id = htons(get_mgr()->get_next_msg_id());
    cmdu->last_frag_ind = 1;
    cmdu->relay_ind = 0;

    tmp += sizeof(em_cmdu_t);
    len += static_cast<unsigned int> (sizeof(em_cmdu_t));

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
    em_printfout("Topology Query (%d) Sent for radio:%s", m_topo_query_tx_cnt, util::mac_to_string(get_radio_interface_mac()).c_str());

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
	unsigned int radio_index, bss_index, all_bss_len = 0;
	unsigned short tlv_len = 0;

	dm = get_data_model();

	tlv = reinterpret_cast<em_tlv_t *> (tmp);
	tlv->type = em_tlv_type_operational_bss;
	tlv_len = sizeof(em_ap_op_bss_t);
	printf("first tlv_len in em_configuration_t::create_operational_bss_tlv = %d\n",tlv_len);

	ap = reinterpret_cast<em_ap_op_bss_t *> (tlv->value);
	ap->radios_num = dm->get_num_radios();
	radio = ap->radios;
	for (radio_index = 0; radio_index < dm->get_num_radios(); radio_index++) {
        memcpy(radio->ruid, dm->get_radio_by_ref(radio_index).get_radio_interface_mac(), sizeof(mac_address_t));
        radio->bss_num = 0;
        bss = radio->bss;
        all_bss_len = 0;
        for (bss_index = 0; bss_index < dm->get_num_bss(); bss_index++) {
            if (memcmp(dm->m_bss[bss_index].m_bss_info.ruid.mac, radio->ruid, sizeof(mac_address_t)) != 0) {
                continue;
            }
            radio->bss_num++;
            memcpy(bss->bssid, dm->m_bss[bss_index].m_bss_info.bssid.mac, sizeof(mac_address_t));
            strncpy(bss->ssid, dm->m_bss[bss_index].m_bss_info.ssid, sizeof(ssid_t));
            bss->ssid_len = static_cast<unsigned char>(strlen(dm->m_bss[bss_index].m_bss_info.ssid) + 1);
            all_bss_len += static_cast<unsigned int>(sizeof(em_ap_operational_bss_t) + bss->ssid_len);
            bss = reinterpret_cast<em_ap_operational_bss_t *>(reinterpret_cast<unsigned char *>(bss) + sizeof(em_ap_operational_bss_t) + bss->ssid_len);
        }
        radio = reinterpret_cast<em_ap_op_bss_radio_t *>(reinterpret_cast<unsigned char *>(radio) + sizeof(em_ap_op_bss_radio_t) + all_bss_len);
        tlv_len += static_cast<short unsigned int>(sizeof(em_ap_op_bss_radio_t) + all_bss_len);
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

    return sizeof(em_tlv_t) + tlv_len;
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
			if (dm->m_bss[j].m_bss_info.vap_mode == em_vap_mode_ap) {
				memcpy(local_intf->mac_addr, dm->m_bss[j].m_bss_info.bssid.mac, sizeof(mac_address_t));
			} else {
				memcpy(local_intf->mac_addr, dm->m_bss[j].m_bss_info.sta_mac, sizeof(mac_address_t));
			}
			// fill test data
			fill_media_data(&local_intf->media_data, &dm->m_bss[j]);

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
    em_ap_mld_config_t *ap_mld_conf;
    em_ap_mld_t *ap_mld;
    em_affiliated_ap_mld_t *affiliated_ap_mld;
    dm_easy_mesh_t  *dm;
    unsigned int i, j;
    unsigned short ap_mld_len = 0;
    unsigned short affiliated_ap_len = 0;
    unsigned short tlv_len = 0;

    dm = get_data_model();

    ap_mld_conf = reinterpret_cast<em_ap_mld_config_t *> (buff);
    memset(ap_mld_conf, 0, sizeof(em_ap_mld_config_t));

    tlv_len = static_cast<short unsigned int> (sizeof(em_ap_mld_config_t));

    ap_mld = ap_mld_conf->ap_mld;
    memset(ap_mld, 0, sizeof(em_ap_mld_t));

    ap_mld_conf->num_ap_mld = static_cast<unsigned char> (dm->get_num_ap_mld());

    for (i = 0; i < dm->get_num_ap_mld(); i++) {
        em_ap_mld_info_t& ap_mld_info = dm->m_ap_mld[i].m_ap_mld_info;
        ap_mld->ap_mld_mac_addr_valid = ap_mld_info.mac_addr_valid;

        ap_mld->ssid_len = static_cast<unsigned char>(sizeof(ssid_t));
        strncpy(ap_mld->ssid, ap_mld_info.ssid, ap_mld->ssid_len);

        memcpy(ap_mld->ap_mld_mac_addr, ap_mld_info.mac_addr, sizeof(mac_address_t));
        ap_mld->str = ap_mld_info.str;
        ap_mld->nstr = ap_mld_info.nstr;
        ap_mld->emlsr = ap_mld_info.emlsr;
        ap_mld->emlmr = ap_mld_info.emlmr;

        ap_mld->num_affiliated_ap = ap_mld_info.num_affiliated_ap;
        affiliated_ap_mld = ap_mld->affiliated_ap_mld;
        affiliated_ap_len = 0;

        for (j = 0; j < ap_mld->num_affiliated_ap; j++) {
            em_affiliated_ap_info_t& affiliated_ap_info = dm->m_ap_mld[i].m_ap_mld_info.affiliated_ap[j];
            memset(affiliated_ap_mld, 0, sizeof(em_affiliated_ap_mld_t));
            affiliated_ap_mld->affiliated_mac_addr_valid = affiliated_ap_info.mac_addr_valid;
            affiliated_ap_mld->link_id_valid = affiliated_ap_info.link_id_valid;
            memcpy(affiliated_ap_mld->ruid, affiliated_ap_info.ruid.mac, sizeof(mac_address_t));
            memcpy(affiliated_ap_mld->affiliated_mac_addr, affiliated_ap_info.mac_addr, sizeof(mac_address_t));
            memcpy(&affiliated_ap_mld->link_id, &affiliated_ap_info.link_id, sizeof(unsigned char));

            affiliated_ap_mld = reinterpret_cast<em_affiliated_ap_mld_t *> (reinterpret_cast<unsigned char *> (affiliated_ap_mld) + sizeof(em_affiliated_ap_mld_t));
            affiliated_ap_len += static_cast<short unsigned int> (sizeof(em_affiliated_ap_mld_t));
        }

        ap_mld = reinterpret_cast<em_ap_mld_t *>(reinterpret_cast<unsigned char *> (ap_mld) + sizeof(em_ap_mld_t) + affiliated_ap_len);
        ap_mld_len += static_cast<short unsigned int> (sizeof(em_ap_mld_t) + affiliated_ap_len);
    }

    tlv_len += ap_mld_len;

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

    return sizeof(em_tlv_t) + tlv_len;
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
	unsigned int radio_index, bss_index, all_bss_len = 0;
	unsigned short tlv_len = 0;

	dm = get_data_model();

	tlv = reinterpret_cast<em_tlv_t *> (tmp);
	tlv->type = em_tlv_type_vendor_operational_bss;
	printf("first tlv_len in em_configuration_t::create_custom_operational_bss_tlv = %d\n",tlv_len);
	ap = reinterpret_cast<em_ap_vendor_op_bss_t *> (tlv->value);
	ap->radios_num = dm->get_num_radios();
	radio = ap->radios;
    for (radio_index = 0; radio_index < dm->get_num_radios(); radio_index++) {
        memcpy(radio->ruid, dm->get_radio_by_ref(radio_index).get_radio_interface_mac(), sizeof(mac_address_t));
        radio->bss_num = 0;
        bss = radio->bss;
        for (bss_index = 0; bss_index < dm->get_num_bss(); bss_index++) {
            if (memcmp(dm->m_bss[bss_index].m_bss_info.ruid.mac, radio->ruid, sizeof(mac_address_t)) != 0) {
                continue;
            }
            radio->bss_num++;
            memcpy(bss->bssid, dm->m_bss[bss_index].m_bss_info.bssid.mac, sizeof(mac_address_t));
            bss->haultype = static_cast<short unsigned int>(dm->m_bss[bss_index].m_bss_info.id.haul_type);
            bss->vap_mode = static_cast<short unsigned int>(dm->m_bss[bss_index].m_bss_info.vap_mode);
            bss = reinterpret_cast<em_ap_vendor_operational_bss_t *>(reinterpret_cast<unsigned char *>(bss) + sizeof(em_ap_vendor_operational_bss_t));
            all_bss_len += sizeof(em_ap_vendor_operational_bss_t);
        }
        radio = reinterpret_cast<em_ap_vendor_op_bss_radio_t *>(reinterpret_cast<unsigned char *>(radio) + sizeof(em_ap_vendor_op_bss_radio_t) + all_bss_len);
        tlv_len += static_cast<short unsigned int>(sizeof(em_ap_vendor_op_bss_radio_t) + all_bss_len);
        all_bss_len = 0;
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
	em_printfout("Number of radios: %d", ap->radios_num);
	for (i = 0; i < ap->radios_num; i++) {
		dm_easy_mesh_t::macbytes_to_string(radio->ruid, rd_mac_str);
		em_printfout("Radio: %s", rd_mac_str);
		bss = radio->bss;
		em_printfout("Number of bss: %d", radio->bss_num);
		for (j = 0; j < radio->bss_num; j++) {
			dm_easy_mesh_t::macbytes_to_string(bss->bssid, bss_mac_str);
			em_printfout("BSSID=%s haul type=%d vap_mode:%d", bss_mac_str, bss->haultype, bss->vap_mode);
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
	em_printfout("Number of radios: %d", ap->radios_num);
	for (i = 0; i < ap->radios_num; i++) {
		dm_easy_mesh_t::macbytes_to_string(radio->ruid, rd_mac_str);
		em_printfout("Radio: %s", rd_mac_str);
		bss = radio->bss;
		em_printfout("Number of bss: %d", radio->bss_num);
		for (j = 0; j < radio->bss_num; j++) {
			dm_easy_mesh_t::macbytes_to_string(bss->bssid, bss_mac_str);
			em_printfout("BSSID=%s haul type=%d vap_mode:%d", bss_mac_str, bss->haultype, bss->vap_mode);
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
			dm_bss->m_bss_info.vap_mode = static_cast<em_vap_mode_t> (bss->vap_mode);

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

int em_configuration_t::send_topology_response_msg(unsigned char *dst, unsigned short msg_id)
{
    unsigned char buff[MAX_EM_BUFF_SZ];
    char *errors[EM_MAX_TLV_MEMBERS] = {0};
    unsigned short  msg_type = em_msg_type_topo_resp;
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
    printf("%s:%d: Number of radios: %d, bss: %d\n", __func__, __LINE__,
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
    cmdu->type = htons(msg_type);
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

    tmp += tlv_len;
    len += static_cast<unsigned int> (tlv_len);

    // Zero or One Backhaul STA Radio capabilities, 17.2.65 Backhaul STA Radio Capabilities TLV
    tlv = reinterpret_cast<em_tlv_t *> (tmp);
    tlv_len = static_cast<short unsigned int> (create_bsta_radio_cap_tlv(tlv->value));
    if (tlv_len != 0) {
        tlv->type = em_tlv_type_bh_sta_radio_cap;
        tlv->len = htons(tlv_len);
        tmp += sizeof(em_tlv_t) + tlv_len;
        len += static_cast<unsigned int> (sizeof(em_tlv_t) + tlv_len);
    } else {
        // No Backhaul STA Radio capabilities
        em_printfout("No Backhaul STA Radio capabilities", __func__, __LINE__);
    }

    // One AP MLD Configuration TLV
    tlv = reinterpret_cast<em_tlv_t *> (tmp);
    tlv->type = em_tlv_type_ap_mld_config;
    tlv_len = static_cast<short unsigned int> (create_ap_mld_config_tlv(tlv->value));
    tlv->len = htons(tlv_len);

    tmp += sizeof(em_tlv_t) + tlv_len;
    len += static_cast<unsigned int> (sizeof(em_tlv_t) + tlv_len);

    // One Backhaul STA MLD Configuration TLV
    tlv_len = static_cast<short unsigned int> (create_bsta_mld_config_tlv(tmp));

    tmp += tlv_len;
    len += static_cast<unsigned int> (tlv_len);

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

    em_printfout("frame length: %d", len);
    if (send_frame(buff, len)  < 0) {
        printf("%s:%d: Topology Response send failed, error:%d\n", __func__, __LINE__, errno);
        return -1;
    }
    printf("setting state to em_state_agent_topo_synchronized\n");
    set_state(em_state_agent_topo_synchronized);
    return static_cast<int> (len);
}

int em_configuration_t::send_ap_mld_config_req_msg()
{
    unsigned char buff[MAX_EM_BUFF_SZ];
    char *errors[EM_MAX_TLV_MEMBERS] = {0};
    unsigned short  msg_type = em_msg_type_ap_mld_config_req;
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
    cmdu->type = htons(msg_type);
    cmdu->id = htons(get_mgr()->get_next_msg_id());
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

int em_configuration_t::send_1905_ack_message(mac_addr_t sta_mac, unsigned short msg_id)
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

int em_configuration_t::send_ap_mld_config_resp_msg(unsigned char *dst, unsigned short msg_id)
{
    unsigned char buff[MAX_EM_BUFF_SZ];
    char *errors[EM_MAX_TLV_MEMBERS] = {0};
    unsigned short  msg_type = em_msg_type_ap_mld_config_resp;
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
    cmdu->type = htons(msg_type);
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
    return 0;
}

int em_configuration_t::send_bsta_mld_config_resp_msg(unsigned char *buff)
{
    return 0;
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

int em_configuration_t::handle_bsta_radio_cap(unsigned char *buff, unsigned int len)
{
    dm_easy_mesh_t *dm = get_data_model();
    em_bh_sta_radio_cap_t *bsta_radio_cap = reinterpret_cast<em_bh_sta_radio_cap_t*>(buff);
    bool is_colocated = dm->get_colocated();

    em_printfout("Backhaul STA Radio Capabilities received, sta mac: %s for radio: %s, mac present: %d",
        util::mac_to_string(bsta_radio_cap->bsta_addr).c_str(),
        util::mac_to_string(bsta_radio_cap->ruid).c_str(), bsta_radio_cap->bsta_mac_present);

    //find device based on this radio
    em_device_info_t *dev = dm->get_device_info();
    if (dev == NULL) {
        em_printfout("Could not find device in data model");
        return -1;
    }

    //memcpy(dm->m_device.m_device_info.backhaul_sta, bsta_radio_cap->bsta_addr, sizeof(mac_address_t));
    //also update the bss with the sta mac
    for (unsigned int i = 0; i < dm->get_num_bss(); i++) {
        if ( (memcmp(dm->m_bss[i].m_bss_info.ruid.mac, bsta_radio_cap->ruid, sizeof(mac_address_t)) == 0) &&
                (dm->m_bss[i].m_bss_info.vap_mode == em_vap_mode_sta) ) {
            memcpy(dm->m_bss[i].m_bss_info.sta_mac, bsta_radio_cap->bsta_addr, sizeof(mac_address_t));
            em_printfout("Topo Response: BSS updated with backhaul sta mac: %s for radio: %s",
                util::mac_to_string(bsta_radio_cap->bsta_addr).c_str(),
                util::mac_to_string(bsta_radio_cap->ruid).c_str());
            break;
        }
    }

    em_printfout("is_colocated val: %d for device id: %s, ctrl al_interface mac: %s \
        , ctrl interface mac: %s", is_colocated, util::mac_to_string(dev->id.dev_mac).c_str(),
        util::mac_to_string(dm->get_ctrl_al_interface_mac()).c_str(),
        util::mac_to_string(dm->get_controller_interface_mac()).c_str());

    mac_addr_str_t rad_mac_str;
    dm_easy_mesh_t::macbytes_to_string(bsta_radio_cap->ruid, rad_mac_str);

    get_mgr()->io_process(em_bus_event_type_bsta_cap_req, reinterpret_cast<unsigned char *> (&rad_mac_str), sizeof(mac_addr_str_t));
    em_printfout("IO process for bcap query submitted with rad mac: %s", rad_mac_str);

    em_printfout("Update BSTA Cap for Device id: %s",
        util::mac_to_string(dev->id.dev_mac).c_str());

    memcpy(dm->m_device.m_device_info.backhaul_sta, bsta_radio_cap->bsta_addr, sizeof(mac_address_t));
    dm->set_db_cfg_param(db_cfg_type_device_list_update, "");

    return 0;
}

int em_configuration_t::handle_ap_operational_bss(unsigned char *buff, unsigned int len)
{
	dm_easy_mesh_t	*dm;
	em_ap_op_bss_t	*ap;
	em_ap_op_bss_radio_t	*radio;
	em_ap_operational_bss_t	*bss;
	dm_bss_t *dm_bss;
	bool updated_at_least_one_bss = false;;
	unsigned int i, j;
	unsigned int all_bss_len = 0;
	char time_date[EM_DATE_TIME_BUFF_SZ];

	dm = get_data_model();
            
    // first verify that dm has all the radios
    ap = reinterpret_cast<em_ap_op_bss_t *> (buff);
    radio = const_cast<em_ap_op_bss_radio_t *> (ap->radios);

	util::get_date_time_rfc3399(time_date, sizeof(time_date));

    for (i = 0; i < ap->radios_num; i++) {
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
    em_client_assoc_event_t *assoc_evt_tlv;
    em_sta_info_t sta_info;
    em_bus_event_type_client_assoc_params_t    raw;
    char *errors[EM_MAX_TLV_MEMBERS] = {0};

	dm = get_data_model();
	em_printfout("Topology Notification received, length: %d", len);

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

            //em_printfout("Client Device:%s %s to BSSID: %s\n", sta_mac_str,
            //        (assoc_evt_tlv->assoc_event == 1)?"associated":"disassociated", bssid_str);
            if ((assoc_evt_tlv->assoc_event == false)) {
                //if disassoc, update db with thi sta_info info
                memset(&sta_info, 0, sizeof(em_sta_info_t));
                memcpy(sta_info.id, assoc_evt_tlv->cli_mac_address, sizeof(mac_address_t));
                memcpy(sta_info.bssid, assoc_evt_tlv->bssid, sizeof(mac_address_t));
                memcpy(sta_info.radiomac, get_radio_interface_mac(), sizeof(mac_address_t));
                sta_info.associated = assoc_evt_tlv->assoc_event;

                hash_map_put(dm->m_sta_assoc_map, strdup(key), new dm_sta_t(&sta_info));

                dm->set_db_cfg_param(db_cfg_type_sta_list_update, "");
                //em_printfout("Client updated to db: %s", key);
            }
            memcpy(raw.dev, dev_mac, sizeof(mac_address_t));
            memcpy(reinterpret_cast<unsigned char *> (&raw.assoc), reinterpret_cast<unsigned char *> (assoc_evt_tlv), sizeof(em_client_assoc_event_t));
            get_mgr()->io_process(em_bus_event_type_sta_assoc, reinterpret_cast<unsigned char *> (&raw), sizeof(em_bus_event_type_client_assoc_params_t));
            break;
        }
            
		tmp_len -= static_cast<unsigned int> (sizeof(em_tlv_t) + htons(tlv->len));
		tlv = reinterpret_cast<em_tlv_t *> (reinterpret_cast<unsigned char *> (tlv) + sizeof(em_tlv_t) + htons(tlv->len));
    }
    set_state(em_state_ctrl_configured);

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
    em_raw_hdr_t *hdr = reinterpret_cast<em_raw_hdr_t *>(buff);
    uint8_t *src_al_mac = hdr->src;
    em_interface_name_t name;
    
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

    while ((tlv->type != em_tlv_type_eom) && (tmp_len > 0)) {
        if (tlv->type != em_tlv_type_bh_sta_radio_cap) {
            tmp_len -= static_cast<unsigned int> (sizeof(em_tlv_t) + htons(tlv->len));
            tlv = reinterpret_cast <em_tlv_t *> (reinterpret_cast<unsigned char *> (tlv) + sizeof(em_tlv_t) + htons(tlv->len));
            continue;
        } else {
            handle_bsta_radio_cap(tlv->value, tlv->len);
            break;
        }
    }


    bool found_ap_mld = false;
    while ((tlv->type != em_tlv_type_eom) && (tmp_len > 0)) {
        if (tlv->type != em_tlv_type_ap_mld_config) {
            tmp_len -= static_cast<unsigned int> (sizeof(em_tlv_t) + htons(tlv->len));
            tlv = reinterpret_cast<em_tlv_t *> (reinterpret_cast<unsigned char *> (tlv) + sizeof(em_tlv_t) + htons(tlv->len));

            continue;

        } else {
            found_ap_mld = true;
            break;
       }
    }

    if (found_ap_mld == true) {
        em_printfout("Found AP MLD details in topology response message");
        handle_ap_mld_config_tlv(tlv->value, htons(tlv->len));
    }
    em_printfout("No of AP MLDs: %d", dm->m_num_ap_mld);

    em_printfout("Src al mac: " MACSTRFMT, MAC2STR(src_al_mac));

    if (dm_easy_mesh_t::name_from_mac_address(reinterpret_cast<const mac_address_t*>(src_al_mac), name) == 0) {
        em_printfout("MAC address exists on this device.");
        memset(dm->m_device.m_device_info.backhaul_alid.mac, 0, sizeof(mac_address_t));
    } else {
        em_printfout("MAC address not found on any interface.");
        memcpy(dm->m_device.m_device_info.backhaul_alid.mac, dm->get_ctrl_al_interface_mac(), sizeof(mac_address_t));
    }

    em_printfout("updated dm dev_info's colocated: %d backhaul_mac: %s and backhaul_alid: %s", dm->get_colocated(),
        util::mac_to_string(dm->m_device.m_device_info.backhaul_mac.mac).c_str(),
        util::mac_to_string(dm->m_device.m_device_info.backhaul_alid.mac).c_str());

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
    em_affiliated_ap_mld_t *affiliated_ap_mld;
    dm_easy_mesh_t  *dm;
    unsigned int i, j;
    unsigned short ap_mld_len = 0;
    unsigned short affiliated_ap_len = 0;
    dm_bss_t *dm_bss;

    dm = get_data_model();

    if(ap_mld_conf->num_ap_mld == 0) {
        em_printfout("Zero AP MLD data");
        return 0;
    }
    dm->set_num_ap_mld(ap_mld_conf->num_ap_mld);

    em_printfout("No of AP MLDs: %d", ap_mld_conf->num_ap_mld);
    ap_mld = ap_mld_conf->ap_mld;

    for (i = 0; i < ap_mld_conf->num_ap_mld; i++) {
        em_ap_mld_info_t* ap_mld_info = &dm->m_ap_mld[i].m_ap_mld_info;
        if (ap_mld_info == NULL) {
           em_printfout("NULL pointer detected in ap_mld_info");
           return 0;
        }

        ap_mld_info->mac_addr_valid = ap_mld->ap_mld_mac_addr_valid;
        strncpy(ap_mld_info->ssid, ap_mld->ssid, ap_mld->ssid_len);

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
            memcpy(affiliated_ap_info->mac_addr, affiliated_ap_mld->affiliated_mac_addr, sizeof(mac_address_t));
            memcpy(&affiliated_ap_info->link_id, &affiliated_ap_mld->link_id, sizeof(unsigned char));

            affiliated_ap_mld = reinterpret_cast<em_affiliated_ap_mld_t *> (reinterpret_cast<unsigned char *> (affiliated_ap_mld) + sizeof(em_affiliated_ap_mld_t));
            affiliated_ap_len += sizeof(em_affiliated_ap_mld_t);

            dm_bss = dm->get_bss(affiliated_ap_info->ruid.mac, affiliated_ap_info->mac_addr);
            if (dm_bss != NULL) {
                memcpy(dm_bss->m_bss_info.mld_mac, ap_mld_info->mac_addr , sizeof(mac_address_t));
            }

        }

        ap_mld = reinterpret_cast<em_ap_mld_t *> (reinterpret_cast<unsigned char *> (ap_mld) + sizeof(em_ap_mld_t) + affiliated_ap_len);
        ap_mld_len += static_cast<short unsigned int> (sizeof(em_ap_mld_t) + affiliated_ap_len);
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
    
    if (num_radios > EM_MAX_RADIO_PER_AGENT) {
        em_printfout("Invalid num_radios=%d, max allowed=%d", num_radios, EM_MAX_RADIO_PER_AGENT);
        return -1;
    }
    
    eht_ops.radios_num = num_radios;
    tmp += sizeof(unsigned char);
    len += static_cast<short> (sizeof(unsigned char));

    for (i = 0; i < num_radios; i++) {
        memcpy(&eht_ops.radios[i].ruid, tmp, sizeof(mac_address_t));
        tmp += sizeof(mac_address_t);
        len += static_cast<short> (sizeof(mac_address_t));

        memcpy(&num_bss, tmp, sizeof(unsigned char));
        
        if (num_bss > EM_MAX_BSS_PER_RADIO) {
            em_printfout("Invalid num_bss=%d for radio %d, max allowed=%d", num_bss, i, EM_MAX_BSS_PER_RADIO);
            return -1;
        }
        
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
                if (memcmp(eht_ops.radios[i].bss[k].bssid, dm->m_bss[l].m_bss_info.bssid.mac, sizeof(mac_address_t)) == 0) {
                    found_bss = true;
                    break;
                }
                if (found_bss == false) {
                    // do not update anything and retrun error
                    return -1;
                }
            }
            found_bss = false;
            memcpy(&dm->m_bss[l].get_bss_info()->eht_ops, &eht_ops.radios[i].bss[k], sizeof(em_eht_operations_bss_t));
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
    em_cmdu_t *cmdu = reinterpret_cast<em_cmdu_t *> (buff + sizeof(em_raw_hdr_t));

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

    send_1905_ack_message(0, ntohs(cmdu->id));

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
    dm_easy_mesh_t *dm = get_data_model();
    dm_policy_t *policy;
    unsigned char *tmp = buff;
    bool found_match = false;

    for (i = 0; i < dm->get_num_policy(); i++) {
        policy = &dm->m_policy[i];
        if (policy->m_policy.id.type == em_policy_id_type_traffic_separation) {
            found_match = true;
            break;
        }
    }
    if (found_match == false) {
        em_printfout("Found Match False ");
        return 0;
    }

    unsigned char ssids_num = static_cast<unsigned char>(policy->m_policy.traffic_separ.num_ssids);
    *tmp = ssids_num;
    tmp += sizeof(unsigned char);
    len += sizeof(unsigned char);

    for (i = 0; i < policy->m_policy.traffic_separ.num_ssids; i++) {
        auto &info = policy->m_policy.traffic_separ.ssid_info[i];

        std::vector<unsigned char> ssid_bytes(info.ssid, info.ssid + strlen(info.ssid));
        unsigned char ssid_len = static_cast<unsigned char>(ssid_bytes.size());

        *tmp = ssid_len;
        tmp += sizeof(unsigned char);
        len += sizeof(unsigned char);

        memcpy(tmp, ssid_bytes.data(), ssid_len);
        tmp += ssid_len;
        len += ssid_len;

        unsigned short vlan_n = htons(info.vlan_id);
        memcpy(tmp, &vlan_n, sizeof(vlan_n));
        tmp += sizeof(unsigned short);
        len += sizeof(unsigned short);
	em_printfout(" TRAFFIC SEPARATION SSID='%.*s' Len=%u, VLAN=%u ",ssid_len,ssid_bytes.data(), ssid_len, info.vlan_id);
    }
    em_printfout("Length: %d ", len);
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
    size = EM_CONN_TYPE_FLAGS_LEN;
    attr->len = htons(size);
    memset(attr->val, 0, size);
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
    size = EM_PRIMARY_DEV_TYPE_LEN;
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
    size = EM_OS_VERSION_LEN;
    attr->len = htons(size);
    memset(attr->val, 0, size);
    //memcpy(attr->val, &rf_band, sizeof(attr->val));
    
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

typedef enum
{
    wifi_security_mode_wps_none = 0x0001, /**< No security. */
    wifi_security_mode_wps_wpa_personal = 0x0002, /**< WPA Personal. */
    wifi_security_mode_wps_shared = 0x0004, /**< Shared. */
    wifi_security_mode_wps_wpa_enterprise = 0x0008, /**< WPA Enterprise. */
    wifi_security_mode_wps_wpa2_enterprise = 0x0010, /**< WPA2 Enterprise. */
    wifi_security_mode_wps_wpa2_personal = 0x0020, /**< WPA2 Personal. */
    wifi_security_mode_wps_sae_m8 = 0x0040, /**< SAE with AKM8. */
    wifi_security_mode_wps_dpp = 0x0080, /**< DPP AKM. */
    wifi_security_mode_wps_sae_24 = 0x0100, /**< SAE with AKM24. */
} wifi_security_modes_wps_t;

struct security_mapping_table_t {
    std::vector<std::string> keys;
    uint16_t mode;
};

static const std::vector<security_mapping_table_t> wps_security_map = {
    { { "wpa-psk" },                  wifi_security_mode_wps_wpa_personal },
    { { "wpa2-psk" },                 wifi_security_mode_wps_wpa2_personal },
    { { "wpa2-eap" },                 wifi_security_mode_wps_wpa2_enterprise },
    { { "sae" },                      wifi_security_mode_wps_sae_24 }, // WPA 3 - Personal
    { { "wpa-eap" },                  wifi_security_mode_wps_wpa_enterprise },
    { { "wpa-eap", "wpa2-eap" },      wifi_security_mode_wps_wpa2_enterprise },
    { { "wpa2-psk", "sae" },          wifi_security_mode_wps_wpa2_personal | wifi_security_mode_wps_sae_m8 },
    { { "wpa-psk", "wpa2-psk" },      wifi_security_mode_wps_wpa2_personal },
    { { "wpa2-psk", "sae", "rsno" },  wifi_security_mode_wps_wpa2_personal | wifi_security_mode_wps_sae_m8 },
    { { "dpp" },                      wifi_security_mode_wps_dpp }
};

static const std::vector<security_mapping_table_t> ow_security_map = {
    { { "wpa-psk" },                  wifi_security_mode_wps_wpa_personal },
    { { "wpa2-psk" },                 wifi_security_mode_wpa2_personal },
    { { "wpa2-eap" },                 wifi_security_mode_wpa2_enterprise },
    { { "sae" },                      wifi_security_mode_wpa3_personal },
    { { "aes" },                      wifi_security_mode_wpa3_enterprise },
    { { "enhanced-open" },                      wifi_security_mode_enhanced_open },
    { { "wpa-eap" },                  wifi_security_mode_wpa_enterprise },
    { { "wpa-eap", "wpa2-eap" },      wifi_security_mode_wpa_wpa2_enterprise },
    { { "wpa2-psk", "sae" },          wifi_security_mode_wpa3_transition },
    { { "wpa-psk", "wpa2-psk" },      wifi_security_mode_wpa_wpa2_personal },
    { { "wpa2-psk", "sae", "rsno" },  wifi_security_mode_wpa3_compatibility }
};

std::optional<wifi_security_modes_t> ow_akm_strings_to_security_mode(const std::vector<std::string>& input_keys) {
    for (const auto& mapping : ow_security_map) {
        if (mapping.keys.size() != input_keys.size()) {
            continue;
        }
        
        // Check if sets are equal (order doesn't matter)
        auto sorted_mapping_keys = mapping.keys;
        auto sorted_input_keys = input_keys;
        std::sort(sorted_mapping_keys.begin(), sorted_mapping_keys.end());
        std::sort(sorted_input_keys.begin(), sorted_input_keys.end());
        
        if (sorted_mapping_keys == sorted_input_keys) {
            return static_cast<wifi_security_modes_t>(mapping.mode);
        }
    }
    return std::nullopt;
}

uint16_t convert_akm_strings_to_wps_authtype(const em_short_string_t akm_array[], size_t akm_count)
{
    if (akm_count == 0 || akm_array == nullptr) {
        return 0; // No AKM strings provided
    }
    
    // Both `akm_array` and `wps_security_map` keys are expected to have few elements so 
    // the actual complexity of this nested loop is not a concern.
    for (const auto& entry : wps_security_map) {
        // All AKMs in akm_array must be present in entry key
        // This assumes they are in order
        if (entry.keys.size() != akm_count) {
            continue;
        }
        size_t matching_akm_count = 0;
        for (size_t i = 0; i < akm_count; ++i) {
            if (strcmp(entry.keys[i].c_str(), akm_array[i]) == 0) {
                matching_akm_count++;
            }
        }
        if (matching_akm_count == akm_count) {
            return entry.mode;
        }
    }
    
    return 0;
}

uint16_t convert_akm_strings_to_wps_authtype(std::vector<std::string> akm_strings)

{
    em_short_string_t akms_array[akm_strings.size()];
    memset(akms_array, 0, sizeof(em_short_string_t)*akm_strings.size());
    for (size_t i = 0; i < akm_strings.size(); i++) {
        strncpy(akms_array[i], akm_strings[i].c_str(), sizeof(em_short_string_t)-1);
    }
    return convert_akm_strings_to_wps_authtype(akms_array, akm_strings.size());
}

std::vector<std::string> convert_wps_authtype_to_akm_strings(uint16_t authtype)
{
    std::set<std::string> result;
    
    // First try exact match for efficiency (handles common single combinations)
    for (const auto& entry : wps_security_map) {
        if (authtype == entry.mode) {
            for (const auto& key : entry.keys) {
                result.insert(key);
            }
            return std::vector<std::string>(result.begin(), result.end());
        }
    }
    
    // If no exact match, decompose into individual flags and collect all corresponding AKMs
    uint16_t remaining_flags = authtype;
    
    // Process each entry in wps_security_map to see if its mode is a subset of authtype
    for (const auto& entry : wps_security_map) {
        if (entry.mode != 0 && (remaining_flags & entry.mode) == entry.mode) {
            // This entry's mode is fully contained in authtype
            for (const auto& key : entry.keys) {
                result.insert(key);
            }
            // Remove these flags from remaining_flags to avoid double-counting
            remaining_flags &= ~entry.mode;
        }
    }
    
    return std::vector<std::string>(result.begin(), result.end());
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

    // Add fronthaul and backhaul AKMs of all BSSs on a radio to
    // a set (to prevent duplicates)
    uint16_t auth_flags = 0;
/*
    dm_easy_mesh_t *dm = get_current_cmd()->get_data_model();
    for (unsigned int i = 0; i < dm->get_num_bss(); i++) {
        em_bss_info_t *bss_info = dm->get_bss_info(i);
        if (bss_info == NULL) continue;

        uint16_t fh_auth_flags = convert_akm_strings_to_wps_authtype(bss_info->fronthaul_akm, bss_info->num_fronthaul_akms);
        if (fh_auth_flags == 0) {
            em_printfout("Warning: Could not map fronthaul AKM strings to WPS auth type for BSS %s", bss_info->ssid);
            printf("Fronthaul AKM strings (%d):", bss_info->num_fronthaul_akms);
            for (int i = 0; i < bss_info->num_fronthaul_akms; i++) {
                printf(" %s", bss_info->fronthaul_akm[i]);
            }
            printf("\n");
        }

        uint16_t bh_auth_flags = convert_akm_strings_to_wps_authtype(bss_info->backhaul_akm, bss_info->num_backhaul_akms);
        if (bh_auth_flags == 0) {
            em_printfout("Warning: Could not map backhaul AKM strings to WPS auth type for BSS %s", bss_info->ssid);
            printf("Backhaul AKM strings (%d):", bss_info->num_backhaul_akms);
            for (int i = 0; i < bss_info->num_backhaul_akms; i++) {
                printf(" %s", bss_info->backhaul_akm[i]);
            }
            printf("\n");
        }
        auth_flags |= (fh_auth_flags | bh_auth_flags);
    }
*/
    em_printfout("WPS Auth Flags: 0x%04x", auth_flags);
    auth_flags = htons(auth_flags);

    attr = reinterpret_cast<data_elem_attr_t *> (tmp);
    attr->id = htons(attr_id_auth_type_flags);
    size = sizeof(auth_flags);
    attr->len = htons(size);
    memcpy(attr->val, &auth_flags, size);
    
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
    size = EM_CONN_TYPE_FLAGS_LEN;
    attr->len = htons(size);
    memset(attr->val, 0, size);
    //memcpy(attr->val, &get_device_info()->sec_1905.conn_flags, size);

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
    size = EM_PRIMARY_DEV_TYPE_LEN;
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
    size = EM_OS_VERSION_LEN;
    attr->len = htons(size);
    memset(attr->val, 0, size);
    //memcpy(attr->val, &rf_band, sizeof(attr->val));

    len += static_cast<unsigned short int> (sizeof(data_elem_attr_t) + size);
    tmp += (sizeof(data_elem_attr_t) + size);


    return len;
}

bool em_configuration_t::send_bss_config_req_msg(uint8_t dest_al_mac[ETH_ALEN])
{
    uint8_t buff[UINT16_MAX] = {0};
    int msg_len = create_bss_config_req_msg(buff, dest_al_mac);
    EM_ASSERT_MSG_TRUE(msg_len > 0, false, "Failed to create BSS Config Request message");

    if (send_frame(buff, static_cast<unsigned int>(msg_len)) < 0) {
        em_printfout("Failed to send BSS Config Request message\n");
        return false;
    }
    return true;
}

int em_configuration_t::create_bss_config_req_msg(uint8_t *buff, uint8_t dest_al_mac[ETH_ALEN])
{
    unsigned int len = 0;
    uint8_t tlv_buff[4096] = {0};
    em_service_type_t service_type = get_service_type();
    em_profile_type_t profile_type = get_profile_type();
    int tlv_size = 0;

    uint8_t* tmp = em_msg_t::add_1905_header(buff, &len, dest_al_mac, get_al_interface_mac(), em_msg_type_bss_config_req,
                        get_mgr()->get_next_msg_id());

    // 5.3.8 Fronthaul BSS and Backhaul BSS configuration
    // If an Enrollee Multi-AP Agent has established a PMK and PTK with the Controller at 1905-layer using the procedures
    // described in section 5.3.7, it shall request configuration for its fronthaul BSSs and backhaul BSSs by sending a BSS
    // Configuration Request message to the Controller. The BSS Configuration Request message shall include at least

    // TODO: Commented out TLVs are commented out because of DM SEGFAULTs, likely because this is operating on the wrong `em_t`. Revisit...

    //  One Multi-AP Profile TLV.
    tmp = em_msg_t::add_tlv(tmp, &len, em_tlv_type_profile, reinterpret_cast<uint8_t *> (&profile_type), sizeof(em_profile_type_t));

    //  One SupportedService TLV.
    // 1 service type followed by the service type value
    uint8_t service_type_buff[2] = {1, service_type};
    tmp = em_msg_t::add_tlv(tmp, &len, em_tlv_type_supported_service, service_type_buff, sizeof(service_type_buff));

    // Zero or One Backhaul STA Radio Capabilities TLV.
    tlv_size = create_bsta_radio_cap_tlv(tlv_buff); // Data
    if (tlv_size) {
        tmp = em_msg_t::add_tlv(tmp, &len, em_tlv_type_bh_sta_radio_cap, tlv_buff, static_cast<unsigned int> (tlv_size));
    }

    // One AP capability TLV 
    // tlv_size = create_ap_cap_tlv(tlv_buff); //Data
    // tmp = em_msg_t::add_tlv(tmp, &len, em_tlv_type_ap_cap, tlv_buff, static_cast<unsigned int> (tlv_size));

    // // One AP Radio Basic Capabilities TLV for each of the supported radios of the Multi-AP Agent.
    // tlv_size = create_ap_radio_basic_cap(tlv_buff); // Data
    // tmp = em_msg_t::add_tlv(tmp, &len, em_tlv_type_ap_radio_basic_cap, tlv_buff, static_cast<unsigned int> (tlv_size));

    //  One AKM Suite Capabilities TLV
    tlv_size = create_akm_suite_cap_tlv(tlv_buff); // Data
    tmp = em_msg_t::add_tlv(tmp, &len, em_tlv_type_akm_suite, tlv_buff, static_cast<unsigned int> (tlv_size));

    //  One Profile-2 AP Capability TLV.
    // tlv_size = create_prof_2_tlv(tlv_buff); // Data
    // tmp = em_msg_t::add_tlv(tmp, &len, em_tlv_type_profile_2_ap_cap, tlv_buff, static_cast<unsigned int> (tlv_size));

    //  One BSS Configuration Request TLV with DPP attribute(s) for all supported radios of the Multi-AP Agent.
    tlv_size = create_bss_conf_req_tlv(tlv_buff); // Data
    EM_ASSERT_MSG_TRUE(tlv_size > 0, -1, "Failed to create BSS Configuration Request TLV");
    tmp = em_msg_t::add_tlv(tmp, &len, em_tlv_type_bss_conf_req, tlv_buff, static_cast<unsigned int> (tlv_size));

    //  One AP HT Capabilities TLV for each radio that is capable of HT (Wi-Fi 4) operation.
    // tlv_size = create_ht_tlv(tlv_buff); // Data
    // tmp = em_msg_t::add_tlv(tmp, &len, em_tlv_type_ht_cap, tlv_buff, static_cast<unsigned int> (tlv_size));

    // //  One AP VHT Capabilities TLV for each radio that is capable of VHT (Wi-Fi 5) operation.
    // tlv_size = create_vht_tlv(tlv_buff); // Data
    // tmp = em_msg_t::add_tlv(tmp, &len, em_tlv_type_vht_cap, tlv_buff, static_cast<unsigned int> (tlv_size));

    // // NOTE: this CMDU is extended in R6 with additional TLVs for Wi-Fi 6/6E and Wi-Fi 7 capabilities.
    // //  One AP Wi-Fi 6 Capabilities TLV for each radio that is capable of HE (Wi-Fi 6) operation
    // tlv_size = create_wifi6_tlv(tlv_buff); // Data
    // tmp = em_msg_t::add_tlv(tmp, &len, em_tlv_type_ap_wifi6_cap, tlv_buff, static_cast<unsigned int> (tlv_size));

    //  One AP Radio Advanced Capabilities TLV for each of the supported radios of the Multi-AP Agent
    tlv_size = create_ap_radio_advanced_cap_tlv(tlv_buff); // Data
    tmp = em_msg_t::add_tlv(tmp, &len, em_tlv_type_ap_radio_advanced_cap, tlv_buff, static_cast<unsigned int> (tlv_size));

    //  If the Agent supports EHT (Wi-Fi 7) operation, one Wi-Fi 7 Agent Capabilities TLV.
    // tlv_size = create_wifi7_tlv(tlv_buff); // Data
    // tmp = em_msg_t::add_tlv(tmp, &len, em_tlv_type_wifi7_agent_cap, tlv_buff, static_cast<unsigned int> (tlv_size));

    //  Zero or one EHT Operations TLV (see section 17.2.103)
    tlv_size = create_eht_operations_tlv(tlv_buff); // Data
    tmp = em_msg_t::add_tlv(tmp, &len, em_tlv_eht_operations, tlv_buff, static_cast<unsigned int> (tlv_size));

    // End of message
    tmp = em_msg_t::add_eom_tlv(tmp, &len);

    return static_cast<int> (len);
}

int em_configuration_t::create_bss_config_rsp_msg(uint8_t *buff, uint8_t dest_al_mac[ETH_ALEN], SSL_KEY* enrollee_nak, unsigned short msg_id)
{

    unsigned int len = 0;
    uint8_t tlv_buff[UINT16_MAX] = {0};
    int tlv_size = 0;

    memset(tlv_buff, 0, sizeof(tlv_buff));

    uint8_t *tmp = em_msg_t::add_1905_header(buff, &len, dest_al_mac, get_al_interface_mac(), em_msg_type_bss_config_rsp, msg_id);

    // One or more BSS config response tlv 17.2.85

    /* EasyMesh 5.3.8 Fronthaul BSS and Backhaul BSS configuration
    
    If a Multi-AP Controller receives a BSS Configuration Request message, it shall respond within one second with a BSS Configuration Response message including one or more BSS Configuration Response TLV(s), 
    each TLV containing one DPP Configuration Object with DPP Configuration Object attributes for the fronthaul BSS(s) and backhaul BSS(s) to be configured on the Enrollee Multi-AP Agent.
        
        - Each TLV has one DPP Configuration Object but there will be multiple TLVs in the BSS Configuration Response message.
    */
   
    em_mgr_t *em_mgr = get_mgr();
    EM_ASSERT_NOT_NULL(em_mgr, -1, "EM Manager is NULL, cannot create Agent List TLV");
    dm_easy_mesh_t *dm = em_mgr->get_first_dm();
    EM_ASSERT_NOT_NULL(dm, -1, "First DM is NULL, cannot create Agent List TLV");

    // Each DM in the list contains BSSs, not the current `get_data_model()` dm. 
    int dbg_dm_idx = 0;
    while (dm != NULL) {
        em_printfout("Creating BSS Config Response TLV for DM index: %d, Num BSS: %d", dbg_dm_idx++, dm->get_num_bss());
        for (unsigned int i = 0; i < dm->get_num_bss(); i++) {
            em_bss_info_t *bss_info = dm->get_bss_info(i);
            if (bss_info == nullptr) continue;
            em_printfout("-------------------------------------------------");
            std::string bssid_str = util::mac_to_string(bss_info->id.bssid);
            
            if (bss_info->id.haul_type == em_haul_type_max) {
                em_printfout("Skipping BSS ID: %s, haul type is max", bssid_str.c_str());
                continue;
            }

            if (bss_info->vap_mode == em_vap_mode_sta) {
                em_printfout("Skipping BSS (with RUID): %s, vap mode is STA", util::mac_to_string(bss_info->ruid.mac).c_str());
                continue;
            }
            
            em_printfout("Creating BSS Config Response TLV for BSS ID: %s", bssid_str.c_str());

            auto radio = dm->get_radio(bss_info->ruid.mac);
            if (!radio) continue;
            if (!radio->m_radio_info.enabled || !bss_info->enabled) {
                em_printfout("Skipping BSS ID: %s, radio or BSS is not enabled", bssid_str.c_str());
                continue;
            }

            tlv_size = create_bss_conf_resp_tlv(tlv_buff, bss_info, dest_al_mac, dm, enrollee_nak); // Data
            if (tlv_size < 0) {
                em_printfout("Failed to create BSS config response TLV for BSS ID: %s", bssid_str.c_str());
                continue;
            }
            em_printfout("BSS Config Response TLV created for BSS ID: %s, TLV size: %d", bssid_str.c_str(), tlv_size);
            tmp = em_msg_t::add_tlv(tmp, &len, em_tlv_type_bss_conf_rsp, tlv_buff, static_cast<unsigned int> (tlv_size));
        }
        em_printfout("-------------------------------------------------");
        dm = em_mgr->get_next_dm(dm);
    }

    // Zero or One default 802.1Q settings tlv 17.2.49
    // Default 802.1Q settings TLV as used in Auto-Configuration right now
    memset(tlv_buff, 0, sizeof(em_8021q_settings_t));
    tmp = em_msg_t::add_tlv(tmp, &len, em_tlv_type_dflt_8021q_settings, tlv_buff, sizeof(em_8021q_settings_t));

    // Zero or One traffic separation policy tlv 17.2.50
    tlv_size = create_traffic_separation_policy(tlv_buff); // Data
    tmp = em_msg_t::add_tlv(tmp, &len, em_tlv_type_traffic_separation_policy, tlv_buff, static_cast<unsigned int> (tlv_size));

    // Zero or one Agent AP MLD Configuration TLV (see section 17.2.96)
    tlv_size = create_ap_mld_config_tlv(tlv_buff); // TLV
    tmp = em_msg_t::add_buff_element(tmp, &len, tlv_buff, static_cast<unsigned int> (tlv_size));

    // Zero or one Backhaul STA MLD Configuration TLV (see section 17.2.97)
    tlv_size = create_bsta_mld_config_tlv(tlv_buff); // TLV
    tmp = em_msg_t::add_buff_element(tmp, &len, tlv_buff, static_cast<unsigned int> (tlv_size));

    //Zero or one EHT Operations TLV (see section 17.2.103)
    tlv_size = create_eht_operations_tlv(tlv_buff); // Data
    tmp = em_msg_t::add_tlv(tmp, &len, em_tlv_eht_operations, tlv_buff, static_cast<unsigned int> (tlv_size));

    // End of message
    tmp = em_msg_t::add_eom_tlv(tmp, &len);

    return static_cast<int> (len);

}

int em_configuration_t::create_bss_config_res_msg(uint8_t *buff, uint8_t dest_al_mac[ETH_ALEN], unsigned short msg_id)
{
    unsigned int len = 0;
    uint8_t *tmp = buff;

    uint8_t tlv_buff[UINT16_MAX] = {0};
    int tlv_size = 0;

    tmp = em_msg_t::add_1905_header(tmp, &len, dest_al_mac, get_al_interface_mac(), em_msg_type_bss_config_res, msg_id);

    // One BSS Configuration Report TLV 17.2.75
    tlv_size = create_bss_config_rprt_tlv(tlv_buff); // TLV
    EM_ASSERT_MSG_TRUE(tlv_size > 0, -1, "Failed to create BSS Configuration Report TLV");
    tmp = em_msg_t::add_buff_element(tmp, &len, tlv_buff, static_cast<unsigned int> (tlv_size));

    // Zero or one Agent AP MLD Configuration TLV (see section 17.2.96)
    tlv_size = create_ap_mld_config_tlv(tlv_buff); // TLV
    if (tlv_size > 0) {
        tmp = em_msg_t::add_buff_element(tmp, &len, tlv_buff, static_cast<unsigned int> (tlv_size));
    }
    // Zero or one Backhaul STA MLD Configuration TLV (see section 17.2.97)
    tlv_size = create_bsta_mld_config_tlv(tlv_buff); // TLV
    if (tlv_size > 0) {
        tmp = em_msg_t::add_buff_element(tmp, &len, tlv_buff, static_cast<unsigned int> (tlv_size));
    }

    // Zero or one EHT Operations TLV (see section 17.2.103)
    tlv_size = create_eht_operations_tlv(tlv_buff); // Data
    if (tlv_size > 0) {
        tmp = em_msg_t::add_tlv(tmp, &len, em_tlv_eht_operations, tlv_buff, static_cast<unsigned int> (tlv_size));
    }

    // End of message
    tmp = em_msg_t::add_eom_tlv(tmp, &len);

    return static_cast<int> (len);

}

int em_configuration_t::create_agent_list_msg(uint8_t *buff, uint8_t dest_al_mac[ETH_ALEN])
{

    unsigned int len = 0;
    uint8_t *tmp = buff;
    uint8_t tlv_buff[UINT16_MAX] = {0};
    int tlv_size = 0;

    tmp = em_msg_t::add_1905_header(tmp, &len, dest_al_mac, get_al_interface_mac(), em_msg_type_agent_list,
                        get_mgr()->get_next_msg_id());

    // One Agent List TLV 17.2.77
    tlv_size = create_agent_list_tlv(tlv_buff); // Data
    EM_ASSERT_MSG_TRUE(tlv_size > 0, -1, "Failed to create Agent List TLV");
    tmp = em_msg_t::add_tlv(tmp, &len, em_tlv_type_agent_list, tlv_buff, static_cast<unsigned int> (tlv_size));

    // End of message
    tmp = em_msg_t::add_eom_tlv(tmp, &len);

    return static_cast<int> (len);
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

int em_configuration_t::create_bsta_radio_cap_tlv(uint8_t *buff)
{
    ASSERT_NOT_NULL(buff, -1, "%s:%d: Buffer is null\n", __func__, __LINE__);
    dm_easy_mesh_t *dm = get_data_model();
    ASSERT_NOT_NULL(dm, -1, "%s:%d: Data model is null\n", __func__, __LINE__);

    int len = 0;
    em_interface_name_t name;
    em_bh_sta_radio_cap_t *bsta_radio_cap = reinterpret_cast<em_bh_sta_radio_cap_t*>(buff);

    for (unsigned int j = 0; j < dm->get_num_bss(); j++) {
        auto* bss_info = dm->get_bss_info(j);
        if (!bss_info) continue;

        em_printfout("BSSID %s, vap_mode:%d, vap name: %s, haul type: %d",
            util::mac_to_string(bss_info->bssid.mac).c_str(), bss_info->vap_mode, bss_info->bssid.name,  bss_info->id.haul_type);

        if (bss_info->id.haul_type != em_haul_type_backhaul ||
            bss_info->vap_mode != em_vap_mode_sta) {
            continue;
        }
        memcpy(bsta_radio_cap->ruid, bss_info->ruid.mac, sizeof(mac_address_t));
        len = static_cast <int> (sizeof(mac_address_t) + sizeof(uint8_t)); // RUID + MAC present flag
        if (dm_easy_mesh_t::name_from_mac_address((reinterpret_cast<const mac_address_t*>(dm->get_ctl_mac())), name) == 0) {
            em_printfout("MAC address exists on this device.");
            memset(bsta_radio_cap->bsta_addr, 0, sizeof(mac_address_t));
        } else {
            em_printfout("MAC address not found on any interface.");
            memcpy(bsta_radio_cap->bsta_addr, bss_info->sta_mac, sizeof(mac_address_t));
        }
        bsta_radio_cap->bsta_mac_present = 1;
        len += static_cast <int> (sizeof(mac_address_t)); // BSTA MAC
        break;
    }
    if (len) {
        em_printfout("Backhaul STA Radio Capabilities TLV: BSTA: %s of rad: %s",
            util::mac_to_string(bsta_radio_cap->bsta_addr).c_str(),
            util::mac_to_string(bsta_radio_cap->ruid).c_str());
    }
    return len;
}

int em_configuration_t::create_akm_suite_cap_tlv(uint8_t *buff)
{
    ASSERT_NOT_NULL(buff, -1, "%s:%d: Buffer is null\n", __func__, __LINE__);
    dm_easy_mesh_t *dm = get_data_model();
    ASSERT_NOT_NULL(dm, -1, "%s:%d: Data model is null\n", __func__, __LINE__);

    em_akm_suite_info_t *akm_suite_info = reinterpret_cast<em_akm_suite_info_t *>(buff);

    std::set<std::string> fh_akms;
    std::set<std::string> bh_akms;

    for (unsigned int i = 0; i < dm->get_num_bss(); i++) {
        em_bss_info_t *bss_info = dm->get_bss_info(i);
        if (bss_info == NULL) continue;

        for (int i = 0; i < bss_info->num_fronthaul_akms; i++) {
            fh_akms.insert(bss_info->fronthaul_akm[i]);
        }
        for (int i = 0; i < bss_info->num_backhaul_akms; i++) {
            bh_akms.insert(bss_info->backhaul_akm[i]);
        }
    }

    std::vector<std::string> fh_akms_vec(fh_akms.begin(), fh_akms.end());
    std::vector<std::string> bh_akms_vec(bh_akms.begin(), bh_akms.end());

    size_t tlv_size = sizeof(uint8_t) + sizeof(uint8_t); // Size of the `Num_BackAKM` and `Num_FrontAKM` fields
    tlv_size += (sizeof(em_fh_akm_suite_t) * fh_akms_vec.size()); // Size of fronthaul AKM suites
    tlv_size += (sizeof(em_bh_akm_suite_t) * bh_akms_vec.size()); // Size of backhaul AKM suites

    memset(buff, 0, tlv_size);

    em_bh_akm_suite_info_t *bh_akm_suite_info = &akm_suite_info->bh_akm_suites;
    em_fh_akm_suite_info_t *fh_akm_suite_info = &akm_suite_info->fh_akm_suites;
    
    bh_akm_suite_info->count = static_cast<uint8_t>(bh_akms_vec.size());
    fh_akm_suite_info->count = static_cast<uint8_t>(fh_akms_vec.size());

    em_bh_akm_suite_t *bh_akm_suite = bh_akm_suite_info->suites;
    // Copy backhaul AKMs
    for (size_t i = 0; i < bh_akms_vec.size(); i++) {
        if (bh_akms_vec[i].empty()) continue;
        std::vector<uint8_t> bh_akm_bytes = util::akm_to_bytes(bh_akms_vec[i]);
        if (bh_akm_bytes.size() != 4) {
            em_printfout("Warning: Could not map backhaul AKM string '%s' to AKM suite bytes, skipping", bh_akms_vec[i].c_str());
            continue;
        }
        // OUI is first 3 bytes, suite type is last byte
        memcpy(bh_akm_suite[i].oui, bh_akm_bytes.data(), 3);
        bh_akm_suite[i].akm_suite_type = bh_akm_bytes[3];
    }

    em_fh_akm_suite_t *fh_akm_suite = fh_akm_suite_info->suites;

    // Copy fronthaul AKMs
    for (size_t i = 0; i < fh_akms_vec.size(); i++) {
        if (fh_akms_vec[i].empty()) continue;
        std::vector<uint8_t> fh_akm_bytes = util::akm_to_bytes(fh_akms_vec[i]);
        if (fh_akm_bytes.size() != 4) {
            em_printfout("Warning: Could not map fronthaul AKM string '%s' to AKM suite bytes, skipping", fh_akms_vec[i].c_str());
            continue;
        }
        // OUI is first 3 bytes, suite type is last byte
        memcpy(fh_akm_suite[i].oui, fh_akm_bytes.data(), 3);
        fh_akm_suite[i].akm_suite_type = fh_akm_bytes[3];
    }

    return static_cast<int>(tlv_size);
}

int em_configuration_t::create_bss_conf_req_tlv(uint8_t *buff)
{
    ASSERT_NOT_NULL(buff, -1, "%s:%d: Buffer is null\n", __func__, __LINE__);
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "netRole", "mapAgent");
    cJSON_AddStringToObject(root, "wi-fi_tech", "map");
    std::string hostname;
    {
        constexpr size_t hostname_size = 256;
        char hostname_buffer[hostname_size];
        if (gethostname(hostname_buffer, hostname_size) == 0) {
            hostname = std::string(hostname_buffer);
        } else {
            em_printfout("Failed to get hostname: %s", strerror(errno));
            hostname = "EasyMeshAgentEnrollee";
        }
    }
    cJSON_AddStringToObject(root, "name", hostname.c_str());

    std::string dpp_config_req_obj_str = cjson_utils::stringify(root);
    cJSON_Delete(root);

    ec_connection_context_t* conn_ctx = get_ec_mgr().get_al_conn_ctx(NULL);
    ec_persistent_sec_ctx_t* sec_ctx = get_ec_mgr().get_sec_ctx();

    EM_ASSERT_NOT_NULL(conn_ctx, -1, "Connection context is NULL, cannot create BSS Configuration Request TLV");
    EM_ASSERT_NOT_NULL(sec_ctx, -1, "Security context is NULL, cannot create BSS Configuration Request TLV");

    uint16_t nak_len = static_cast<uint16_t>(BN_num_bytes(conn_ctx->prime) * 2);
    scoped_ec_point public_nak(em_crypto_t::get_pub_key_point(sec_ctx->net_access_key));
    EM_ASSERT_NOT_NULL(public_nak, -1, "Public NAK is NULL, cannot create BSS Configuration Request TLV");
    
    scoped_ec_group group(em_crypto_t::get_key_group(sec_ctx->net_access_key));
    EM_ASSERT_NOT_NULL(group.get(), -1,"Failed to get elliptic curve group from network access key");

    scoped_buff encoded_nak(ec_crypto::encode_ec_point(group.get(), public_nak.get()));
    EM_ASSERT_NOT_NULL(encoded_nak.get(), -1, "Failed to encode public NAK to buffer");

    uint16_t tls_group_id = ec_crypto::get_tls_group_id_from_ec_group(group.get());
    EM_ASSERT_MSG_TRUE(tls_group_id != UINT16_MAX, -1, "Failed to get TLS group ID from EC group");

    size_t attribs_len = 0;
    uint8_t* attribs = NULL;
    attribs = ec_util::add_attrib(attribs, &attribs_len, ec_attrib_id_dpp_config_req_obj, dpp_config_req_obj_str);
    attribs = ec_util::add_attrib(attribs, &attribs_len, ec_attrib_id_init_proto_key, nak_len, encoded_nak.get());
    attribs = ec_util::add_attrib(attribs, &attribs_len, ec_attrib_id_finite_cyclic_group, SWAP_LITTLE_ENDIAN(tls_group_id));

    memcpy(buff, attribs, attribs_len);
    free(attribs); 

    return static_cast<int>(attribs_len);
}

int em_configuration_t::create_agent_list_tlv(uint8_t *buff) {


    em_mgr_t *em_mgr = get_mgr();
    EM_ASSERT_NOT_NULL(em_mgr, -1, "EM Manager is NULL, cannot create Agent List TLV");
    dm_easy_mesh_t *dm = em_mgr->get_first_dm();
    EM_ASSERT_NOT_NULL(dm, -1, "First DM is NULL, cannot create Agent List TLV");

    /* EasyMesh 17.2.77
    - Num_Agents: 
        - MAC Address
        - Multi-AP Profile
        - Security
    */

    em_agent_list_t *agent_list = reinterpret_cast<em_agent_list_t *>(buff);
    agent_list->num_agents = 0;

    uint8_t* agent_obj_buff = buff + sizeof(em_agent_list_t);

    size_t tlv_size = sizeof(em_agent_list_t);

    while (dm != NULL) {
        // 
        em_agent_list_agent_t *agent_obj = reinterpret_cast<em_agent_list_agent_t *>(agent_obj_buff);
        memset(agent_obj, 0, sizeof(em_agent_list_agent_t));

        em_profile_type_t profile = dm->get_device()->m_device_info.profile;
        uint8_t* al_mac = dm->get_agent_al_interface_mac();

        // Double check that all of these values are actually correct given that stuff can be set weird in UWM
        memcpy(agent_obj->agent_mac, al_mac, ETH_ALEN);
        agent_obj->multi_ap_profile = static_cast<uint8_t>(profile);
        agent_obj->security = 0x01; // ALl UWM agents support 1905-layer security

        agent_list->num_agents++;

        agent_obj_buff += sizeof(em_agent_list_agent_t);
        tlv_size += sizeof(em_agent_list_agent_t);
        dm = em_mgr->get_next_dm(dm);
    }

    return static_cast<int>(tlv_size);
}


int em_configuration_t::create_bss_conf_resp_tlv(uint8_t *buff, em_bss_info_t *bss_info, uint8_t dest_al_mac[ETH_ALEN], dm_easy_mesh_t *dm, SSL_KEY* enrollee_nak)
{

    EM_ASSERT_NOT_NULL(buff, -1, "Buffer is NULL, cannot create BSS Configuration Response TLV");
    EM_ASSERT_NOT_NULL(bss_info, -1, "BSS info is NULL, cannot create BSS Configuration Response TLV");

    /* EasyMesh 5.3.8 Fronthaul BSS and Backhaul BSS configuration
    
    If a Multi-AP Controller receives a BSS Configuration Request message, it shall respond within one second with a BSS Configuration Response message including one or more BSS Configuration Response TLV(s), 
    each TLV containing one DPP Configuration Object with DPP Configuration Object attributes for the fronthaul BSS(s) and backhaul BSS(s) to be configured on the Enrollee Multi-AP Agent.
        
        - Each TLV has one DPP Configuration Object but there will be multiple TLVs in the BSS Configuration Response message.
    */

    std::string bssid_mac = util::mac_to_string(bss_info->bssid.mac);

    ec_manager_t &ec_mgr = get_ec_mgr();
    ec_persistent_sec_ctx_t* sec_ctx = ec_mgr.get_sec_ctx();
    EM_ASSERT_NOT_NULL(sec_ctx, -1, "Security context is NULL, cannot create BSS Configuration Response objects");

    // false for is_sta_response, false for tear_down_bss
    scoped_cjson bss_config_obj(create_bss_dpp_response_obj(bss_info, false, false, dm));

    EM_ASSERT_NOT_NULL(bss_config_obj.get(), -1, "Failed to create BSS DPP Configuration Object for BSS ID: %s", bssid_mac.c_str());

    bool is_backhaul = bss_info->id.haul_type == em_haul_type_backhaul;

    /*
    The DPP connector created here is used for station onboarding to the BSS.
    */
    dpp_config_obj_type_e dpp_conf_obj_type = dpp_config_obj_type_e::dpp_config_obj_none;
    if (is_backhaul) {
        dpp_conf_obj_type = dpp_config_obj_type_e::dpp_config_obj_backhaul_bss;
    } else {
        // Assume all other haul types are fronthaul
        dpp_conf_obj_type = dpp_config_obj_type_e::dpp_config_obj_fbss_ap;
    }

    // finalize_dpp_config_obj modifies the object in-place and returns the same pointer
    // Use release() to transfer ownership and avoid double-free
    scoped_cjson final_config_obj(ec_ctrl_configurator_t::finalize_dpp_config_obj(bss_config_obj.release(), dpp_conf_obj_type, sec_ctx, enrollee_nak));

    // DEBUG
    em_printfout("Created BSS DPP Configuration Object for BSSID: %s, haul type: %s",
                 bssid_mac.c_str(),
                 is_backhaul ? "Backhaul" : "Fronthaul");
    em_printfout("%s", cjson_utils::stringify(final_config_obj.get(), false).c_str());

    std::string json_string = cjson_utils::stringify(final_config_obj.get(), true);

    EM_ASSERT_MSG_TRUE(json_string.length() > 0, -1, "Failed to stringify BSS DPP Configuration Object for BSS ID: %s", bssid_mac.c_str());

    memcpy(buff, json_string.c_str(), json_string.length());

    return static_cast<int>(json_string.length());
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

int em_configuration_t::create_autoconfig_wsc_m2_msg(unsigned char *buff, unsigned short msg_id)
{
    unsigned short  msg_type = em_msg_type_autoconf_wsc;
    int len = 0;
    unsigned int i, num_hauls = em_haul_type_max;
    em_cmdu_t *cmdu;
    em_tlv_t *tlv;
    unsigned char *tmp = buff;
    unsigned short sz = 0;
    unsigned short type = htons(ETH_P_1905);
    dm_radio_t *radio;

    radio = get_radio_from_dm();

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
    cmdu->type = htons(msg_type);
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

    // Add as many wsc tlv in M2 as number of BSS associated with this radio
    if (radio && radio->m_radio_info.number_of_bss < num_hauls) {
        num_hauls = radio->m_radio_info.number_of_bss;
        em_printfout("Adjusting number of hauls to: %d", num_hauls);
    } else if (!radio) {
        em_printfout("Radio is NULL for WSC haul type TLV creation");
        num_hauls = 0;
    }

    for (i = 0; i < num_hauls; i++) {
        tlv = reinterpret_cast<em_tlv_t *> (tmp);
        tlv->type = em_tlv_type_wsc;
        sz = create_m2_msg(tlv->value, static_cast<em_haul_type_t> (i));
        if (sz == 0) {
            em_printfout("Not adding haul_type: %d as size returned is 0", i);
            continue;
        }
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
    unsigned short  msg_type = em_msg_type_autoconf_wsc;
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
    cmdu->type = htons(msg_type);
    cmdu->id = htons(get_mgr()->get_next_msg_id());
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

int em_configuration_t::create_autoconfig_resp_msg(unsigned char* buff, em_freq_band_t band, unsigned char* dst, unsigned short msg_id, em_dpp_chirp_value_t* chirp, size_t hash_len)
{
    unsigned short  msg_type = em_msg_type_autoconf_resp;
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
    cmdu->type = htons(msg_type);
    cmdu->id = htons(msg_id);
    cmdu->last_frag_ind = 1;
    cmdu->relay_ind = 0;

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

    // Zero or one DPP Chirp Value TLV (see section 17.2.83).
    if (chirp) {
        tlv = reinterpret_cast<em_tlv_t *> (tmp);
        tlv->type = em_tlv_type_dpp_chirp_value;
        tlv->len = htons(static_cast<unsigned short int>(sizeof(em_dpp_chirp_value_t) + hash_len));
        memcpy(tlv->value, chirp, sizeof(em_dpp_chirp_value_t) + hash_len);

        tmp += (sizeof(em_tlv_t) + sizeof(em_dpp_chirp_value_t) + hash_len);
        len += static_cast<int> (sizeof(em_tlv_t) + sizeof(em_dpp_chirp_value_t) + hash_len);
    }

    // End of message
    tlv = reinterpret_cast<em_tlv_t *> (tmp);
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += static_cast<int> (sizeof (em_tlv_t));

    return len;

}

bool em_configuration_t::send_autoconf_search_resp_ext_chirp(em_dpp_chirp_value_t *chirp, size_t len, uint8_t dest_mac[ETH_ALEN], unsigned short msg_id)
{
    uint8_t buff[4096] = {0};
    int msg_len = create_autoconfig_resp_msg(buff, get_band(), dest_mac, msg_id, chirp, len);
    if (msg_len < 0) {
        em_printfout("Failed to create Autoconf Search Response (extended)");
        return false;
    }

    if (send_frame(buff, static_cast<unsigned int>(msg_len)) < 0) {
        em_printfout("Failed to send Autoconf Search Response (extended)");
        return false;
    }
    em_printfout("Sent Autoconf Search Response (extended)");
    return true;
}

bool em_configuration_t::send_autoconf_search_ext_chirp(em_dpp_chirp_value_t *chirp, size_t hash_len)
{
    unsigned char buff[4096] = {0};
    int len = 0;

    len = create_autoconfig_search_msg(buff, chirp, hash_len);
    if (len < 0) {
        em_printfout("Failed to create autoconf search ext chirp msg");
        return false;
    }

    // Send the message
    if (send_frame(buff, static_cast<unsigned int>(len)) < 0) {
        em_printfout("Failed to send autoconf search ext chirp msg");
        return false;
    }
    em_printfout("Sent Autoconf Search (extended chirp)");
    return true;
}

int em_configuration_t::create_autoconfig_search_msg(unsigned char *buff, em_dpp_chirp_value_t *chirp, size_t hash_len)
{
    unsigned int len = 0;
    uint8_t *tmp = buff;
    mac_address_t multi_addr = {0x01, 0x80, 0xc2, 0x00, 0x00, 0x13};

    tmp = em_msg_t::add_1905_header(tmp, &len, multi_addr, get_al_interface_mac(), em_msg_type_autoconf_search,
                        get_mgr()->get_next_msg_id());

    // One 1905.1 AL MAC address type TLV (table 6-8)
    tmp = em_msg_t::add_tlv(tmp, &len, em_tlv_type_al_mac_address, get_al_interface_mac(), sizeof(mac_address_t));

    // One SearchedRole TLV (see Table 6-22)
    // Registrar == 0x00, 0x01 - 0xFF reserved
    uint8_t role = 0;
    tmp = em_msg_t::add_tlv(tmp, &len, em_tlv_type_searched_role, &role, sizeof(role));

    // One AutoconfigFreqBand TLV (see Table 6-23)
    uint8_t band = static_cast<uint8_t>(get_band());
    tmp = em_msg_t::add_tlv(tmp, &len, em_tlv_type_autoconf_freq_band,
                        &band, sizeof(band));

    // Extended fields
    // Zero or one SupportedService TLV (see section 17.2.1).
    uint8_t service[2] = {1, get_service_type()};
    tmp = em_msg_t::add_tlv(tmp, &len, em_tlv_type_supported_service, service, sizeof(service));

    // Zero or one SearchedService TLV (see section 17.2.2).
    // 0x00: Controller, 0x01 - 0xFF reserved
    uint8_t searched_service[2] = {1, em_service_type_ctrl};
    tmp = em_msg_t::add_tlv(tmp, &len, em_tlv_type_searched_service, searched_service, sizeof(searched_service));

    // One Multi-AP Profile TLV (see section 17.2.47).
    uint8_t profile = static_cast<uint8_t>(get_profile_type());
    tmp = em_msg_t::add_tlv(tmp, &len, em_tlv_type_profile, &profile, sizeof(profile));

    // Zero or One DPP Chirp TLV (section 17.2.83)
    if (chirp) {
        tmp = em_msg_t::add_tlv(tmp, &len, em_tlv_type_dpp_chirp_value, reinterpret_cast<uint8_t*>(chirp), static_cast<unsigned int>(sizeof(em_dpp_chirp_value_t) + hash_len));
    }

    // OEM
    tmp = em_msg_t::add_eom_tlv(tmp, &len);
    return static_cast<int>(len);
}

int em_configuration_t::handle_wsc_m2(unsigned char *buff, unsigned int len, unsigned int index)
{
    data_elem_attr_t    *attr;
    int ret = 0;
    unsigned int tmp_len;
    unsigned short id;

    em_printfout("Parsing m2 message, index: %d, len: %d", index, len);

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
            memcpy(&m_m2_encrypted_settings[index][0], attr->val, htons(attr->len));
            m_m2_encrypted_settings_len[index] = htons(attr->len);
            //em_printfout("Copied encrypted setting[%d] len:%d", index, htons(attr->len));
        } else if (id == attr_id_authenticator) {
            memcpy(m_m2_authenticator[index], attr->val, htons(attr->len));
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
            uint16_t auth_flags = 0;
            memcpy(&auth_flags, attr->val, sizeof(uint16_t));
            auth_flags = ntohs(auth_flags);
            std::vector<std::string> akms = convert_wps_authtype_to_akm_strings(auth_flags);
            em_printfout("Recieved AKMs: (0x%04x)", auth_flags);
            for (auto &akm : akms) {
                printf(" %s", akm.c_str());
            }
            printf("\n");
            if (akms.size() > 0) {
                for (unsigned int i = 0; i < radio->get_radio_info()->number_of_bss; i++) {
                    em_bss_info_t* bss_info = dm->get_bss_info(i);
                    if (bss_info != NULL) {
                        bss_info->num_fronthaul_akms = static_cast<uint8_t>(akms.size());
                        bss_info->num_backhaul_akms = static_cast<uint8_t>(akms.size());
                        em_printfout("BSS %u, Set %zu FH AKMs, Set %zu BH AKMs", i, akms.size(), akms.size());
                        for (size_t i = 0; i < akms.size(); i++){
                            snprintf(bss_info->fronthaul_akm[i], sizeof(em_short_string_t), "%s", akms[i].c_str());
                            snprintf(bss_info->backhaul_akm[i], sizeof(em_short_string_t), "%s", akms[i].c_str());
                        }
                    }
                }
			    dm->set_db_cfg_param(db_cfg_type_bss_list_update, "");
            }
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
            if( dm->get_colocated() == false )
            {
                memcpy(dm->m_device.m_device_info.backhaul_alid.mac, dm->get_ctrl_al_interface_mac(), sizeof(mac_address_t));
            }

            em_printfout("Updated dm dev_info's backhaul_mac: %s and backhaul_alid: %s",
                util::mac_to_string(dm->m_device.m_device_info.backhaul_mac.mac).c_str(),
                util::mac_to_string(dm->m_device.m_device_info.backhaul_alid.mac).c_str());

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
    unsigned int wsc_tlv_count = 0;
    char *errors[EM_MAX_TLV_MEMBERS] = {0};
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
        if (tlv->type == em_tlv_type_ap_mld_config) {
            em_printfout("Found AP MLD details in message");
            handle_ap_mld_config_tlv(tlv->value, htons(tlv->len));
        } else if (tlv->type == em_tlv_type_wsc) {
            em_printfout("Handle wsc TLV, count: %d", wsc_tlv_count);
            //Storing m2 address and length in static variable;
            set_e_mac(get_radio_interface_mac());
            handle_wsc_m2(tlv->value, htons(tlv->len), wsc_tlv_count);

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

            if (memcmp(m_m2_authenticator[wsc_tlv_count], hash, AUTHENTICATOR_LEN) != 0) {
                printf("%s:%d: Authenticator validation failed\n", __func__, __LINE__);
                //return -1;
            }
            wsc_tlv_count++;
        }
        tmp_len -= static_cast<int> (sizeof(em_tlv_t) + htons(tlv->len));
        tlv = reinterpret_cast<em_tlv_t *> (reinterpret_cast<unsigned char *> (tlv) + sizeof(em_tlv_t) + htons(tlv->len));
    }

    if (wsc_tlv_count == 0) {
        em_printfout("Could not find wsc, failing message");
        return -1;
    }

    if (handle_encrypted_settings(wsc_tlv_count) == -1) {
        em_printfout("Error in decrypting settings wsc_tlv_count:%d", wsc_tlv_count);
        return -1;
    }

    dm = get_data_model();
    //Commit controller mac address
    if ((dm != NULL) && (hdr != NULL)) {
        memcpy(&network.m_net_info.ctrl_id.mac, &hdr->src, sizeof(mac_address_t));
        dm->set_network(network);
        em_t* al_node = get_mgr()->get_al_node();
        if (al_node != NULL) {
            get_ec_mgr().upgrade_to_onboarded_proxy_agent(hdr->src);
#ifdef ENABLE_COLOCATED_1905_SECURE
            if (al_node->get_peer_1905_security_status(hdr->src) == peer_1905_security_status::PEER_1905_SECURITY_NOT_STARTED) {
                al_node->set_peer_1905_security_status(hdr->src, peer_1905_security_status::PEER_1905_SECURITY_IN_PROGRESS);
                get_ec_mgr().start_secure_1905_layer(hdr->src);
            }
#endif
        }
    }
    return 0;
}

int em_configuration_t::handle_encrypted_settings(unsigned int wsc_tlv_count)
{
    data_elem_attr_t    *attr;
    int tmp_len, ret = 0;
    unsigned short id;
    char pass[64] = {0};
    unsigned char *plain;
    unsigned short plain_len;
    unsigned short auth_type;
    m2ctrl_radioconfig radioconfig;

    memset(&radioconfig, 0, sizeof(m2ctrl_radioconfig));
    radioconfig.noofbssconfig = 0;

    em_printfout("Total wsc_tlv_count:%d for radio:%s", wsc_tlv_count, util::mac_to_string(get_radio_interface_mac()).c_str());
    for(unsigned int wsc_index = 0;((wsc_index < wsc_tlv_count) && (wsc_index < EM_MAX_BSS_PER_RADIO)); wsc_index++) {
        plain = static_cast<unsigned char *> (m_m2_encrypted_settings[wsc_index]) + AES_BLOCK_SIZE;
        plain_len = static_cast<short unsigned int> (m_m2_encrypted_settings_len[wsc_index]) - AES_BLOCK_SIZE;
        em_printfout("##handle_encrypted_settings wsc_index:%d plain_len: %d", wsc_index, plain_len);

        // first decrypt the encrypted m2 data
        if ((plain_len = em_crypto_t::platform_aes_128_cbc_decrypt(m_key_wrap_key, &m_m2_encrypted_settings[wsc_index][0], plain, plain_len)) == 0) {
            em_printfout("Platform decrypt failed for wsc_tlv:%d", wsc_index);
            return 0;
        }

        attr = reinterpret_cast<data_elem_attr_t *> (plain);
        tmp_len = plain_len;

        // Set the haultype to the wsc index by default
        if (wsc_index >= em_haul_type_max) {
            em_printfout("wsc_index:%d exceeds max haul types:%d, not proceeding further", wsc_index, em_haul_type_max);
            return 0;
        }
        radioconfig.haultype[wsc_index] = static_cast<em_haul_type_t> (wsc_index);
        while (tmp_len > 0) {
            id = htons(attr->id);
            if (id == attr_id_vendor_ext) {
                // Handle only em_vendor_oui
                unsigned short attr_len = htons(attr->len);
                if ((attr_len > EM_VENDOR_OUI_SIZE) && (memcmp(attr->val, em_vendor_oui, EM_VENDOR_OUI_SIZE) == 0)) {
                    unsigned char vendor_attr_id = attr->val[EM_VENDOR_OUI_SIZE];
                    if (vendor_attr_id == vendor_ext_attr_id_haul_type) {
                        radioconfig.haultype[wsc_index] = static_cast<em_haul_type_t> (attr->val[EM_VENDOR_OUI_SIZE + 1]);
                        em_printfout("##vendor_ext haul_type attrib[%d]: %d", wsc_index, radioconfig.haultype[wsc_index]);
                    }
                }
            } else if (id == attr_id_ssid) {
                //If controller does not support no of haultype parameter
                memcpy(radioconfig.ssid[wsc_index], attr->val, sizeof(radioconfig.ssid[wsc_index]));
                radioconfig.enable[wsc_index] = true;
                em_printfout("##ssid attrib[%d]: %s", wsc_index, radioconfig.ssid[wsc_index]);
                memcpy(radioconfig.radio_mac[wsc_index], get_radio_interface_mac(), sizeof(mac_address_t));
            } else if (id == attr_id_auth_type) {
                memcpy(reinterpret_cast<char *> (&auth_type), reinterpret_cast<unsigned char *> (attr->val), htons(attr->len));
                radioconfig.authtype[wsc_index] = static_cast<unsigned int>(auth_type);
                em_printfout("##authtype[%d]: %x", wsc_index, radioconfig.authtype[wsc_index]);
            } else if (id == attr_id_encryption_type) {
                em_printfout("##encr type attrib for wsc_index:%d", wsc_index);
            } else if (id == attr_id_network_key) {
                memcpy(pass, attr->val, htons(attr->len));
                memcpy(radioconfig.password[wsc_index], attr->val, htons(attr->len));
                em_printfout("##network key[%d]: %s", wsc_index, pass);
            } else if (id == attr_id_mac_address) {
                memcpy(radioconfig.radio_mac[wsc_index], attr->val, sizeof(mac_address_t));
                em_printfout("##mac address[%d]: %s", wsc_index, util::mac_to_string(radioconfig.radio_mac[wsc_index]).c_str());
            } else if (id == attr_id_key_wrap_authenticator) {
                radioconfig.key_wrap_authenticator[wsc_index] = attr->val[0];
                em_printfout("##key wrap auth[%d]: %u", wsc_index, radioconfig.key_wrap_authenticator[wsc_index]);
            }
            tmp_len -= static_cast<int> (sizeof(data_elem_attr_t) + htons(attr->len));
            attr = reinterpret_cast<data_elem_attr_t *> (reinterpret_cast<unsigned char *>(attr) + sizeof(data_elem_attr_t) + htons(attr->len));
        }
        radioconfig.noofbssconfig++;
    }

    em_printfout("##num bss configuration=%d", radioconfig.noofbssconfig);
    for (unsigned int i = 0; i < radioconfig.noofbssconfig; i++){
        radioconfig.freq[i] = get_band();
    }
    get_mgr()->io_process(em_bus_event_type_m2ctrl_configuration, reinterpret_cast<unsigned char *> (&radioconfig), sizeof(radioconfig));
    set_state(em_state_agent_owconfig_pending);
    return ret;
}

int em_configuration_t::handle_bss_config_req_msg(uint8_t *buff, unsigned int len, uint8_t src_al_mac[ETH_ALEN]) {
    // Controller

    /* EasyMesh 5.3.8 
    If a Multi-AP Controller receives a BSS Configuration Request message, it shall respond within one second with a BSS
    Configuration Response message including one or more BSS Configuration Response TLV(s), each TLV containing one
    DPP Configuration Object with DPP Configuration Object attributes for the fronthaul BSS(s) and backhaul BSS(s) to be
    configured on the Enrollee Multi-AP Agent.
    */

    // Despite the amount of TLVs in the BSS Configuration Request message, we only need to respond with a BSS Configuration Response message

    em_printfout("Received BSS Configuration Request message from '" MACSTRFMT "'", MAC2STR(src_al_mac));

    //TODO:  Update DM
    em_tlv_t *tlv_buff = reinterpret_cast<em_tlv_t *>(buff + sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));
    unsigned int tlv_buff_len = static_cast<unsigned int>(len - (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t)));

    em_tlv_t *tlv = em_msg_t::get_first_tlv(tlv_buff, tlv_buff_len);
    EM_ASSERT_NOT_NULL(tlv, -1, "Failed to get first TLV from BSS Configuration Request message");

    /* EasyMesh 17.1.53
    • One Multi-AP Profile TLV.
    • One SupportedService TLV.
    • If the Agent supports a Backhaul STA, one Backhaul STA Radio Capabilities TLV.
    • One AP Capability TLV
    • One AP Radio Basic Capabilities TLV for each of the supported radios of the Multi-AP Agent.
    • One AKM Suite Capabilities TLV.
    • One Profile-2 AP Capability TLV.
    • One BSS Configuration Request TLV with DPP attribute(s) for all supported radios of the Multi-AP Agent.
    • One AP HT Capabilities TLV for each radio that is capable of HT (Wi-Fi 4) operation.
    • One AP VHT Capabilities TLV for each radio that is capable of VHT (Wi-Fi 5) operation.
    • One AP HE Capabilities TLV for each radio that is capable of HE (Wi-Fi 6) operation.
    • One AP Wi-Fi 6 Capabilities TLV for each radio that is capable of HE (Wi-Fi 6) operation.
    • One AP Radio Advanced Capabilities TLV for each of the supported radios of the Multi-AP Agent.
    • If the Agent supports EHT (Wi-Fi 7) operation, one Wi-Fi 7 Agent Capabilities TLV.
    • Zero or one EHT Operations TLV (see section 17.2.103)
    */

    em_profile_type_t profile = em_profile_type_reserved;
    em_service_type_t service_type = em_service_type_none;

    scoped_ssl_key enrollee_nak(nullptr); // Network Access Key

    while (tlv != NULL) {

        if (tlv->type == em_tlv_type_eom || tlv->len == 0) {
            break; // End of message or empty TLV
        }

        switch (tlv->type) {
            case em_tlv_type_profile:
                em_printfout("Processing Multi-AP Profile TLV");
                memcpy(&profile, tlv->value, ntohs(tlv->len));
                break;
            case em_tlv_type_supported_service:
                em_printfout("Processing Supported Service TLV");
                memcpy(&service_type, &tlv->value[1], sizeof(em_service_type_t));
                break;
            case em_tlv_type_bh_sta_radio_cap:
                 // Not handled by UWM right now? 
                 em_printfout("Processing Backhaul STA Radio Capabilities TLV - Not handled");
                break;
            case em_tlv_type_ap_cap:
                 // Not handled by UWM right now?
                 em_printfout("Processing AP Capabilities TLV - Not handled");
                break;
            case em_tlv_type_ap_radio_basic_cap:
                em_printfout("Processing AP Radio Basic Capabilities TLV");
                handle_ap_radio_basic_cap(tlv->value, htons(tlv->len));
                break;
            case em_tlv_type_akm_suite:
                 // Not handled by UWM right now?
                em_printfout("Processing AKM Suite Capabilities TLV");
                // TODO: HANDLE AKM Suite Capabilities TLV
                util::print_hex_dump(ntohs(tlv->len), tlv->value);
                break;
            case em_tlv_type_profile_2_ap_cap:
                // Not handled by UWM right now?
                em_printfout("Processing Profile-2 AP Capabilities TLV - Not handled");
                break;
            case em_tlv_type_bss_conf_req: {
                em_printfout("Processing BSS Configuration Request TLV");
                SSL_KEY* nak = handle_bss_config_req_tlv(tlv);
                enrollee_nak.reset(nak);
                EM_ASSERT_NOT_NULL(enrollee_nak.get(), -1, "Failed to handle BSS Configuration Request TLV, Enrollee Network Access Key is NULL");
                break;
            }
            case em_tlv_type_ht_cap:
                em_printfout("Processing HT Capabilities TLV - Not handled");
                // Not handled by UWM right now?
                break;
            case em_tlv_type_vht_cap:
                em_printfout("Processing VHT Capabilities TLV - Not handled");
                // Not handled by UWM right now?
                break;
            case em_tlv_type_he_cap:
                em_printfout("Processing HE Capabilities TLV - Not handled");
                // Not handled by UWM right now?
                break;
            case em_tlv_type_ap_wifi6_cap:
                em_printfout("Processing Wi-Fi 6 Capabilities TLV - Not handled");
                // Not handled by UWM right now?
                break;
            case em_tlv_type_ap_radio_advanced_cap:
                em_printfout("Processing AP Radio Advanced Capabilities TLV");
                handle_ap_radio_advanced_cap(tlv->value, htons(tlv->len));
                break;
            case em_tlv_type_wifi7_agent_cap:
                em_printfout("Processing Wi-Fi 7 Agent Capabilities TLV - Not handled");
                // Not handled by UWM right now?
                break;
            case em_tlv_eht_operations:
                em_printfout("Processing EHT Operations TLV");
                handle_eht_operations_tlv(tlv->value);
                break;
            default:
                em_printfout("Unknown TLV type %d in BSS Configuration Request message", tlv->type);
                break;
        } 

        tlv = em_msg_t::get_next_tlv(tlv, tlv_buff, tlv_buff_len);
    }

    EM_ASSERT_NOT_NULL(enrollee_nak.get(), -1, "Enrollee Network Access Key was not recieved, cannot continue with BSS Configuration Response");


    uint8_t frame[UINT16_MAX] = {0};
    em_cmdu_t *cmdu = reinterpret_cast<em_cmdu_t *> (buff + sizeof(em_raw_hdr_t));

    int frame_len = create_bss_config_rsp_msg(frame, src_al_mac, enrollee_nak.get(), ntohs(cmdu->id));
    EM_ASSERT_MSG_TRUE(frame_len > 0, -1, "Failed to create BSS Configuration Response message");

    // Send the BSS Configuration Response message
    int ret = send_frame(frame, static_cast<unsigned int>(frame_len), src_al_mac);
    EM_ASSERT_MSG_TRUE(ret == 0, -1, "Failed to send BSS Configuration Response message to '" MACSTRFMT "'", MAC2STR(src_al_mac));

    em_printfout("Sent BSS Configuration Response message to '" MACSTRFMT "'", MAC2STR(src_al_mac));

    return 0;
}


SSL_KEY* em_configuration_t::handle_bss_config_req_tlv(em_tlv_t* tlv) {

    EM_ASSERT_NOT_NULL(tlv, NULL, "BSS Configuration Request TLV is NULL");
    
    em_printfout("Processing BSS Configuration Request TLV with DPP Configuration Object");

    uint8_t* attribs = tlv->value;
    size_t attribs_len = static_cast<size_t>(ntohs(tlv->len));

    /* NOTE
    Passing the Enrollee NAK and the finite cyclic group are not strictly inside the spec however there really is no spec compliant method 
    to get the enrollee NAK (for generating the following connector) without this. You can store the enrollee NAK but you also don't _really_ know which
    enrollee NAK corresponds to your newly onboarded device since you previously communicated via phy MAC addresses, and now you communicate via AL MACs.
    Since Wi-Fi DPP onboarding uses regular Auto-configuration and not Auto-conf + chirp, you also can't do a lookup by hash to find which AL MAC corresponds 
    you are **now** communicating on corresponds to your previous phy MAC. Either way these methods are not how DPP is intended to be set up and onboarding is intended to
    be done.

    This is a flaw in the spec that hopefully can be resolved soon. 

    The good news is that the use of attributes in this way is supported by the spec already. For example in EasyMesh 5.3.2:
    
    >The DPP Configuration Request object is a JSON (JavaScript Object Notation) encoded data structure as defined in [22], that is transmitted as a DPP attribute (see 8.1 in [18])
    >in the DPP Configuration Request frame (see 8.3.2 in [18]) and BSS Configuration Request TLV (see 17.2.84).

    This means that the BSS Configuration Request TLV (and later on the "BSS Configuration Response TLV") is intended to have EasyConnect Attributes inside it. So the addition
    of these two attributes to the existing attributes buffer is not outside of the realm of posibilities.
    */

    // This TLV contains DPP Configuration Request Object which does not appear to have any specific use with generating a response 
    // `ec_attrib_id_dpp_config_req_obj` does not seem to do anything here

    auto group_attrib = ec_util::get_attrib(attribs, attribs_len, ec_attrib_id_finite_cyclic_group);
    EM_ASSERT_OPT_HAS_VALUE(group_attrib, NULL, "BSS Configuration Request TLV does not contain finite cyclic group attribute");
    uint16_t fc_tls_group_id = SWAP_LITTLE_ENDIAN(*reinterpret_cast<uint16_t*>(group_attrib->data));
    int fc_nid = ec_crypto::get_nid_from_tls_group_id(fc_tls_group_id);
    EM_ASSERT_MSG_TRUE(fc_nid != NID_undef, NULL, "Received finite cyclic group is not a supported TLS Group ID: %d", fc_tls_group_id);

    scoped_ec_group group(EC_GROUP_new_by_curve_name(fc_nid));
    EM_ASSERT_NOT_NULL(group.get(), NULL, "Failed to create EC Group from TLS Group ID: %d", fc_tls_group_id);
    
    auto nak_attrib = ec_util::get_attrib(attribs, attribs_len, ec_attrib_id_init_proto_key);
    EM_ASSERT_OPT_HAS_VALUE(nak_attrib, NULL, "BSS Configuration Request TLV does not contain Enrollee protocol key attribute");

    scoped_ec_point enrollee_public_nak(ec_crypto::decode_ec_point(group.get(), nak_attrib->data));
    EM_ASSERT_NOT_NULL(enrollee_public_nak, NULL, "Failed to decode Enrollee protocol key from BSS Configuration Request TLV");

    return em_crypto_t::bundle_ec_key(group.get(), enrollee_public_nak.get());
}

int em_configuration_t::handle_bss_config_rsp_tlv(em_tlv_t* tlv, m2ctrl_radioconfig& radioconfig, size_t bss_count) {
    // Agent

    EM_ASSERT_NOT_NULL(tlv, -1, "BSS Configuration Response TLV is NULL");

    dm_easy_mesh_t *dm = get_data_model();
    EM_ASSERT_NOT_NULL(dm, -1, "Data model is NULL");


    std::string dpp_config_obj(reinterpret_cast<char*>(tlv->value));
    EM_ASSERT_MSG_TRUE(dpp_config_obj.length() > 0, -1, "DPP Configuration Object in BSS Configuration Response TLV is empty");
    scoped_cjson dpp_config_json(cJSON_ParseWithLength(dpp_config_obj.data(), dpp_config_obj.length()));

    EM_ASSERT_NOT_NULL(dpp_config_json.get(), -1, "Failed to parse DPP Configuration Object from BSS Configuration Response TLV");
    EM_ASSERT_MSG_TRUE(cJSON_IsObject(dpp_config_json.get()), -1, "DPP Configuration Object in BSS Configuration Response TLV is not a JSON object");


    cJSON* wifi_tech_json = cJSON_GetObjectItemCaseSensitive(dpp_config_json.get(), "wi-fi_tech");
    EM_ASSERT_NOT_NULL(wifi_tech_json, -1, "Failed to get 'wi-fi_tech' from DPP Configuration Object in BSS Configuration Response TLV");
    EM_ASSERT_MSG_TRUE(cJSON_IsString(wifi_tech_json), -1, "'wi-fi_tech' in DPP Configuration Object is not a string");

    std::string wifi_tech(cJSON_GetStringValue(wifi_tech_json));
    EM_ASSERT_MSG_TRUE(!wifi_tech.empty(), -1, "'wi-fi_tech' in DPP Configuration Object is empty");

    // Determine haul type based on 'wi-fi_tech' according to EasyMesh 5.3.8
    em_haul_type_t haul_type = em_haul_type_max;
    if (wifi_tech == "map") {
        haul_type = em_haul_type_backhaul;
    }
    if (wifi_tech == "inframap") {
        haul_type = em_haul_type_fronthaul;
    }

    EM_ASSERT_MSG_TRUE(haul_type != em_haul_type_max, -1, "Invalid 'wi-fi_tech' value in DPP Configuration Object: %s", wifi_tech.c_str());


    cJSON* discovery_obj = cJSON_GetObjectItem(dpp_config_json.get(), "discovery");
    EM_ASSERT_NOT_NULL(discovery_obj, -1, "Failed to get 'discovery' from DPP Configuration Object in BSS Configuration Response TLV");
    EM_ASSERT_MSG_TRUE(cJSON_IsObject(discovery_obj), -1, "'discovery' in DPP Configuration Object is not a JSON object");

    cJSON* ssid_obj = cJSON_GetObjectItemCaseSensitive(discovery_obj, "SSID");
    cJSON* bssid_obj = cJSON_GetObjectItemCaseSensitive(discovery_obj, "BSSID");
    cJSON* ruid_obj = cJSON_GetObjectItemCaseSensitive(discovery_obj, "RUID");

    // RUID must always be present and SSID can be "null" but always present so not NULL/nullptr
    EM_ASSERT_NOT_NULL(ssid_obj, -1, "Failed to get 'SSID' from 'discovery' in DPP Configuration Object in BSS Configuration Response TLV");
    EM_ASSERT_NOT_NULL(ruid_obj, -1, "Failed to get 'RUID' from 'discovery' in DPP Configuration Object in BSS Configuration Response TLV");


    EM_ASSERT_MSG_TRUE(cJSON_IsString(ruid_obj), -1, "'RUID' in 'discovery' is not a string");
    std::string ruid = cJSON_GetStringValue(ruid_obj);

    std::vector<uint8_t> ruid_mac = util::macstr_to_vector(ruid, "");

    // Begin setting bss configuration in data model

    // Get frequency from RDK freq band attribute if present
    cJSON* rdk_freq_obj = cJSON_GetObjectItemCaseSensitive(dpp_config_json.get(), "XRDK_BSS_Frequency");
    em_freq_band_t freq_band = em_freq_band_unknown;
    if (cJSON_IsNumber(rdk_freq_obj)) {
        int freq = rdk_freq_obj->valueint;
        if (freq >= 0 && freq < em_freq_band_unknown) {
            freq_band = static_cast<em_freq_band_t>(freq);
        }
    }
    if (freq_band == em_freq_band_unknown) {
        em_printfout("RDK frequency band attribute not present or invalid!");
    }
    radioconfig.freq[bss_count] = freq_band;

    if (cJSON_IsNull(ssid_obj)) {


        // "inframap"
        if (haul_type == em_haul_type_fronthaul && bssid_obj == NULL){
            /*
            If a Multi-AP Controller does not want to configure any BSS on a radio of a Multi-AP Agent, it shall include a BSS
            Configuration Response TLV in the BSS Configuration Response message and shall set the parameters in the DPP
            Configuration Object fields of the BSS Configuration Response TLV described in Table 6 as follows:
            • DPP Configuration Object
                ▪ wi-fi_tech = "inframap"
            • Discovery Object
                ▪ SSID: NULL
                ▪ Radio Unique Identifier of the radio
            */
            em_printfout("Received BSS Configuration Response TLV with 'SSID' as NULL for haul type 'inframap', not configuring radio %s", ruid.c_str());
            return -1;
        }
        // "inframap" or "map"
        if (bssid_obj != NULL) {
            /*
            If a Multi-AP Controller wants to tear down an existing BSS on a radio of a Multi-AP Agent, it shall include a BSS
            Configuration Response TLV in the BSS Configuration Response message and shall set the parameters in the DPP
            Configuration Object fields of the BSS Configuration Response TLV described in Table 6 as follows:
            • DPP Configuration Object
                ▪ wi-fi_tech = "inframap" or "map"
            • Discovery Object
                ▪ SSID: NULL
                ▪ Radio Unique Identifier of the radio
                ▪ BSSID
            */

            std::string bssid = cJSON_GetStringValue(bssid_obj);
            std::vector <uint8_t> bssid_mac = util::macstr_to_vector(bssid, "");
            std::string bssid_formatted = util::mac_to_string(bssid_mac.data());
           
            em_printfout("Received BSS Configuration Response TLV with 'SSID' as NULL, \"tearing down\" (disabling) BSS on radio %s with BSSID %s", 
                         ruid.c_str(), bssid_formatted);

            dm_bss_t* bss = dm->get_bss(ruid_mac.data(), bssid_mac.data());
            EM_ASSERT_NOT_NULL(bss, -1, "Failed to get BSS with RUID %s and BSSID %s", ruid.c_str(), bssid_formatted);
            
            // Disable BSS
            bss->m_bss_info.enabled = false;
            radioconfig.enable[bss_count] = false;
            return 0;
        }
        
        // SSID is NULL but not within spec paths, undefined error
        em_printfout("Received Invalid BSS Configuration Response TLV with 'SSID' as NULL. Failing...");
        return -1;
    }

    // Traditional configuration
    EM_ASSERT_NOT_NULL(bssid_obj, -1, "Failed to get 'BSSID' from 'discovery' in DPP Configuration Object in BSS Configuration Response TLV");

    std::string ssid = cJSON_GetStringValue(ssid_obj);
    EM_ASSERT_MSG_TRUE(!ssid.empty(), -1, "'SSID' in 'discovery' is empty");

    std::string bssid = cJSON_GetStringValue(bssid_obj);
    std::vector <uint8_t> bssid_mac = util::macstr_to_vector(bssid, "");
    std::string bssid_formatted = util::mac_to_string(bssid_mac.data());

    // em_network_ssid_info_t* ssid_info = dm->get_network_ssid_info_by_haul_type(haul_type);
    
    // // You're kind of out of luck here. The implementation of UWM assumes that the SSID info is always available for the haul type
    // // Even if BSS infos are not. 1905 Topology Responses creates BSS infos, OneWifi configurations (/nvram/InterfaceMap) which is hardcoded on the router
    // // creates DM SSID infos. Auto-config will return whatever SSIDs are on the DM which then updates OneWifi SSIDs, which then, when the 1905 topology response
    // // occurs, will create the BSS infos with those SSIDs. The SSIDs are not being created in UWM code (besides database sync) so I am not doing that here...
    // EM_ASSERT_NOT_NULL(ssid_info, -1, "Failed to get SSID info for haul type %d", haul_type);

    em_printfout("Received BSS Configuration Response TLV with SSID '%s', BSSID '%s' and haul type %d", ssid.c_str(), bssid_formatted.c_str(), haul_type);

    radioconfig.haultype[bss_count] = haul_type;
    memcpy(radioconfig.ssid[bss_count], ssid.c_str(), sizeof(radioconfig.ssid[bss_count]));
    memcpy(radioconfig.radio_mac[bss_count], bssid_mac.data(), sizeof(mac_address_t));
    radioconfig.enable[bss_count] = true;


    cJSON* cred_obj = cJSON_GetObjectItemCaseSensitive(dpp_config_json.get(), "cred");
    EM_ASSERT_NOT_NULL(cred_obj, -1, "Failed to get 'cred' from DPP Configuration Object in BSS Configuration Response TLV");
    EM_ASSERT_MSG_TRUE(cJSON_IsObject(cred_obj), -1, "'cred' in DPP Configuration Object is not a JSON object");


    cJSON* dpp_connector_obj = cJSON_GetObjectItemCaseSensitive(cred_obj, "signedConnector");
    EM_ASSERT_NOT_NULL(dpp_connector_obj, -1, "Failed to get 'signedConnector' from 'cred' in DPP Configuration Object in BSS Configuration Response TLV");
    EM_ASSERT_MSG_TRUE(cJSON_IsString(dpp_connector_obj), -1, "'signedConnector' in 'cred' is not a string");

    std::string dpp_connector = cJSON_GetStringValue(dpp_connector_obj);

    cJSON* csign_obj = cJSON_GetObjectItemCaseSensitive(cred_obj, "csign");
    EM_ASSERT_NOT_NULL(csign_obj, -1, "Failed to get 'csign' from 'cred' in DPP Configuration Object in BSS Configuration Response TLV");
    EM_ASSERT_MSG_TRUE(cJSON_IsObject(csign_obj), -1, "'csign' is not an object");


    cJSON* akm_str = cJSON_GetObjectItemCaseSensitive(cred_obj, "akm");
    EM_ASSERT_NOT_NULL(akm_str, -1, "Failed to get 'akm' from 'cred' in DPP Configuration Object in BSS Configuration Response TLV");
    EM_ASSERT_MSG_TRUE(cJSON_IsString(akm_str), -1, "'akm' in 'cred' in DPP Configuration Object is not a string");
    std::string akm = cJSON_GetStringValue(akm_str);

    cJSON* pass_str = cJSON_GetObjectItemCaseSensitive(cred_obj, "pass");
    EM_ASSERT_NOT_NULL(pass_str, -1, "Failed to get 'pass' from 'cred' in DPP Configuration Object in BSS Configuration Response TLV");
    EM_ASSERT_MSG_TRUE(cJSON_IsString(pass_str), -1, "'pass' in 'cred' in DPP Configuration Object is not a string");
    std::string pass = cJSON_GetStringValue(pass_str);

    /*
    Theoretically, the main point of this is to set a DPP Connector for STAs to join via non-EasyMesh DPP rather than using a PSK.
    While I am setting the DPP Connector here, I am also setting the PSK since OneWifi currently doesn't do anything with the DPP Connector
    and the PSK is needed.
    */
    

    // The AKM recieved "should" be valid, but it's not because the controller doesn't recieved information from the BSSes.
    // Since this information is initialized by OneWifi, we're just going to use it here, like how they do in other areas...
   
    std::vector<std::string> akm_ouis = util::split_by_delim(akm, '+');
    std::vector<std::string> ow_akm_strs;
    for (const auto& akm_oui : akm_ouis) {
        std::string akm_str = util::oui_to_akm(akm_oui);
        if (akm_str.empty()) {
            em_printfout("Received invalid AKM OUI in BSS Configuration Response TLV: %s", akm_oui.c_str());
            continue;
        }
        ow_akm_strs.push_back(akm_str);
    }
    EM_ASSERT_MSG_TRUE(!ow_akm_strs.empty(), -1, "No valid AKM OUIs received in BSS Configuration Response TLV");

    auto auth_type = ow_akm_strings_to_security_mode(ow_akm_strs);
    EM_ASSERT_OPT_HAS_VALUE(auth_type, -1, "Failed to convert AKM OUIs to auth type");

    em_printfout("Security Mode: %04x, AKMS: ", *auth_type);
    for (const auto& str : ow_akm_strs) {
        printf("\t- %s\n", str.c_str());
    }

    radioconfig.authtype[bss_count] = static_cast<unsigned int>(*auth_type);
    memcpy(radioconfig.password[bss_count], pass.c_str(), sizeof(radioconfig.password[bss_count]));

    auto [csign_group, csign_pub] = ec_crypto::decode_jwk(csign_obj);
    if (csign_group == NULL || csign_pub == NULL) {
        em_printfout("Failed to decode C-sign key");
        if (csign_group) EC_GROUP_free(csign_group);
        if (csign_pub) EC_POINT_free(csign_pub);
        return -1;
    }

    scoped_ssl_key csign_key(em_crypto_t::bundle_ec_key(csign_group, csign_pub));
    EM_ASSERT_NOT_NULL(csign_key.get(), -1, "Failed to bundle C-sign key");

    // Validate the DPP Connector
    auto parts = ec_crypto::split_decode_connector(dpp_connector.c_str(), csign_key.get());
    EM_ASSERT_OPT_HAS_VALUE(parts, -1, "Failed to decode or verify DPP Connector: %s", dpp_connector.c_str());

    if (dpp_connector.length() > sizeof(radioconfig.dpp_connector[bss_count])){
        em_printfout("Recieved DPP Connector is larger than can fit in buffer, ignoring it");
    } else {
        memcpy(radioconfig.dpp_connector[bss_count], dpp_connector.c_str(), sizeof(radioconfig.dpp_connector[bss_count]));
    }

    return 0;
}

int em_configuration_t::handle_bss_config_rsp_msg(uint8_t *buff, unsigned int len, uint8_t src_al_mac[ETH_ALEN]) {
    // Agent

    /*
    If an Enrollee Multi-AP Agent receives a BSS Configuration Response message from the
    Multi-AP Controller, it shall configure its fronthaul BSS(s) and backhaul BSS(s) accordingly and send a BSS Configuration
    Result message to the Multi-AP Controller.
    */

    // TODO: Update DM to configure fronthaul and backhaul BSSs

    /* EasyMesh 17.1.54
    • One or more BSS Configuration Response TLV (see section 17.2.85) [Profile-3].
    • Zero or one Default 802.1Q Settings TLV (see section 17.2.49).
    • Zero or one Traffic Separation Policy TLV (see section 17.2.50).
    • Zero or one Agent AP MLD Configuration TLV (see section 17.2.96)
    • Zero or one Backhaul STA MLD Configuration TLV (see section 17.2.97)
    • Zero or one EHT Operations TLV (see section 17.2.103)
    */

    em_tlv_t *tlv_buff = reinterpret_cast<em_tlv_t *>(buff + sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));
    unsigned int tlv_buff_len = static_cast<unsigned int>(len - (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t)));

    em_printfout("Received BSS Configuration Response message from '" MACSTRFMT "'", MAC2STR(src_al_mac));

    em_tlv_t *tlv = em_msg_t::get_first_tlv(tlv_buff, tlv_buff_len);
    EM_ASSERT_NOT_NULL(tlv, -1, "Failed to get first TLV from BSS Configuration Response message");

    std::string bss_dpp_connector = "";
    m2ctrl_radioconfig radioconfig;

    unsigned int bss_count = 0;

    while (tlv != NULL) {

        if (tlv->type == em_tlv_type_eom || tlv->len == 0) {
            break; // End of message or empty TLV
        }

        switch (tlv->type) {
            case em_tlv_type_bss_conf_rsp: {
                // Process BSS Configuration Response TLV
                // Can be more than one for each BSS a classical DPP connector should be assigned to
                if (handle_bss_config_rsp_tlv(tlv, radioconfig, static_cast<size_t>(bss_count))) return -1;
                bss_count++;
                break;
            }
            case em_tlv_type_dflt_8021q_settings:
                // Not handled by UWM right now?
                break;
            case em_tlv_type_traffic_separation_policy:
                // Not handled by UWM right now?
                break;
            case em_tlv_type_ap_mld_config:
                handle_ap_mld_config_tlv(tlv->value, htons(tlv->len));
                break;
            case em_tlv_type_bsta_mld_config:
                handle_bsta_mld_config_req(tlv->value, htons(tlv->len));
                break;
            case em_tlv_eht_operations:
                handle_eht_operations_tlv(tlv->value);
                break;
            default:
                em_printfout("Unknown TLV type %d in BSS Configuration Response message", tlv->type);
                break;
        } 

        tlv = em_msg_t::get_next_tlv(tlv, tlv_buff, tlv_buff_len);
    }

    uint8_t frame[MAX_EM_BUFF_SZ] = {0};
    em_cmdu_t *cmdu = reinterpret_cast<em_cmdu_t *> (buff + sizeof(em_raw_hdr_t));

    int frame_len = create_bss_config_res_msg(frame, src_al_mac, ntohs(cmdu->id));
    EM_ASSERT_MSG_TRUE(frame_len > 0, -1, "Failed to create BSS Configuration Response message");

    // Send the BSS Configuration Result message
    int ret = send_frame(frame, static_cast<unsigned int>(frame_len), src_al_mac);
    EM_ASSERT_MSG_TRUE(ret == 0, -1, "Failed to send BSS Configuration Result message to '" MACSTRFMT "'", MAC2STR(src_al_mac));
    em_printfout("Sent BSS Configuration Result message to '" MACSTRFMT "'", MAC2STR(src_al_mac));

    radioconfig.noofbssconfig = bss_count;

    hash_map_t* em_map = get_mgr()->m_em_map;
    em_t* em = static_cast<em_t *>(hash_map_get_first(em_map));
    dm_network_t network;
    dm_easy_mesh_t* dm = NULL;

    // Organize the configurations by frequency band
    m2ctrl_radioconfig band_radioconfigs[em_freq_band_unknown];
    memset(band_radioconfigs, 0, sizeof(band_radioconfigs));

    for (unsigned int i = 0; i < radioconfig.noofbssconfig; i++) {
        m2ctrl_radioconfig* band_config = &band_radioconfigs[radioconfig.freq[i]];
        unsigned int idx = band_config->noofbssconfig;

        band_config->haultype[idx] = radioconfig.haultype[i];
        memcpy(band_config->ssid[idx], radioconfig.ssid[i], sizeof(radioconfig.ssid[i]));
        memcpy(band_config->password[idx], radioconfig.password[i], sizeof(radioconfig.password[i]));
        band_config->authtype[idx] = radioconfig.authtype[i];
        memcpy(band_config->radio_mac[idx], radioconfig.radio_mac[i], sizeof(radioconfig.radio_mac[i]));
        memcpy(band_config->bssid_mac[idx], radioconfig.bssid_mac[i], sizeof(radioconfig.bssid_mac[i]));
        memcpy(band_config->dpp_connector[idx], radioconfig.dpp_connector[i], sizeof(radioconfig.dpp_connector[i]));
        band_config->key_wrap_authenticator[idx] = radioconfig.key_wrap_authenticator[i];
        band_config->enable[idx] = radioconfig.enable[i];
        band_config->freq[idx] = radioconfig.freq[i];
        band_config->noofbssconfig++;
    }

    // DEBUG: Print the radio configuration
    em_printfout("Radio Config: ");
    for (em_freq_band_t band = em_freq_band_24; band < em_freq_band_unknown; band = static_cast<em_freq_band_t>(band + 1)) {
        m2ctrl_radioconfig& config = band_radioconfigs[band];
        printf("\tFrequency Band: %d\n", band);
        if (config.noofbssconfig == 0) {
            printf("\t\tNo BSS configurations\n");
            continue;
        }
        for (unsigned int i = 0; i < config.noofbssconfig; i++) {
            printf("\t\tBSS %u:\n", i);
            bool is_enabled = config.enable[i];
            printf("\t\t\tEnabled: %s\n", is_enabled ? "true" : "false");
            if (!is_enabled) continue;
            printf("\t\t\tHaul Type: %d\n", config.haultype[i]);
            printf("\t\t\tSSID: %s\n", config.ssid[i]);
            printf("\t\t\tPassword: %s\n", config.password[i]);
            printf("\t\t\tAuth Type: %u\n", config.authtype[i]);
            printf("\t\t\tRadio MAC: " MACSTRFMT "\n", MAC2STR(config.radio_mac[i]));
            printf("\t\t\tBSSID (expected empty): " MACSTRFMT "\n", MAC2STR(config.bssid_mac[i]));
            printf("\t\t\tDPP Connector: %s\n", config.dpp_connector[i]);
            printf("\t\t\tKey Wrap Authenticator (expected 0): %d\n", config.key_wrap_authenticator[i]);
        }
    }

    // For all the nodes, commit the configuration
    while (em != NULL) {
        // Skip AL EM
        if (em->is_al_interface_em()){
            em->set_is_dpp_onboarding(false);
            em = static_cast<em_t *>(hash_map_get_next(em_map, reinterpret_cast<void *>(em)));
            continue;
        }

        m2ctrl_radioconfig* band_radioconfig = &band_radioconfigs[em->get_band()];
        if (band_radioconfig == NULL) {
            em_printfout("No radio configuration for band %d, skipping configuration for node '" MACSTRFMT "'", em->get_band(), MAC2STR(em->get_radio_interface_mac()));
            em = static_cast<em_t *>(hash_map_get_next(em_map, reinterpret_cast<void *>(em)));
            continue;
        }
        
        //Commit controller mac address
        if ((dm = em->get_data_model()) != NULL) {
            memcpy(&network.m_net_info.ctrl_id.mac, src_al_mac, sizeof(mac_address_t));
            dm->set_network(network);
        }
        em->set_is_dpp_onboarding(false);
        if (band_radioconfig->noofbssconfig == 0) {
            em_printfout("No BSS configurations for band %d, skipping configuration for node '" MACSTRFMT "'", band_radioconfig->freq[0], MAC2STR(em->get_radio_interface_mac()));
            em = static_cast<em_t *>(hash_map_get_next(em_map, reinterpret_cast<void *>(em)));
            continue;
        }
        em_printfout("Committing radio configuration to node '" MACSTRFMT "' on band %d with %d BSS configurations", 
                     MAC2STR(em->get_radio_interface_mac()), band_radioconfig->freq[0], band_radioconfig->noofbssconfig);
        em->get_mgr()->io_process(em_bus_event_type_m2ctrl_configuration, reinterpret_cast<unsigned char *> (band_radioconfig), sizeof(m2ctrl_radioconfig));
        em->set_state(em_state_agent_owconfig_pending);

        em = static_cast<em_t *>(hash_map_get_next(em_map, reinterpret_cast<void *>(em)));
    }


    return 0;
}

int em_configuration_t::handle_bss_config_res_msg(uint8_t *buff, unsigned int len, uint8_t src_al_mac[ETH_ALEN]) {
    // Controller

    /*
    If the Multi-AP Controller receives a BSS Configuration Result message, it shall:
        • send an Agent List message to the newly onboarded Enrollee Multi-AP Agent and all the other existing Multi-AP
        Agents
        • include the Agent List TLV with the list of all the Multi-AP Agents that are part of the Multi-AP network (including the
        newly enrolled Multi-AP Agent itself)
        • set the Multi-AP Profile field in the Agent List TLV to the value of the Multi-AP Profile field of the Multi-AP Profile TLV
        received from each Multi-AP Agent (If the Multi-AP Profile field is not received, set to Profile-1)
        • set the Security field in the Agent List TLV to 1905 Security enabled for all Multi-AP Profile-3 devices onboarded with
        DPP Onboarding, and set the Security field to 1905 Security not enabled otherwise
    */

    /* EasyMesh 17.1.55
    • One BSS Configuration Report TLV (see section 17.2.75) [Profile-3].
    • Zero or one Agent AP MLD Configuration TLV (see section 17.2.96)
    • Zero or one Backhaul STA MLD Configuration TLV (see section 17.2.97)
    • Zero or one EHT Operations TLV (see section 17.2.103)
    */

    em_tlv_t *tlv_buff = reinterpret_cast<em_tlv_t *>(buff + sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));
    unsigned int tlv_buff_len = static_cast<unsigned int>(len - (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t)));

    em_printfout("Received BSS Configuration Result message from '" MACSTRFMT "'", MAC2STR(src_al_mac));

    em_tlv_t *tlv = em_msg_t::get_first_tlv(tlv_buff, tlv_buff_len);
    EM_ASSERT_NOT_NULL(tlv, -1, "Failed to get first TLV from BSS Configuration Result message");

    while (tlv != NULL) {

        if (tlv->type == em_tlv_type_eom || tlv->len == 0) {
            break; // End of message or empty TLV
        }

        switch (tlv->type) {
            case em_tlv_type_bss_conf_rep:
                // Process BSS Configuration Report TLV
                handle_bss_configuration_report(tlv->value, htons(tlv->len));
                break;
            case em_tlv_type_ap_mld_config:
                handle_ap_mld_config_tlv(tlv->value, htons(tlv->len));
                break;
            case em_tlv_type_bsta_mld_config:
                // Not handled by UWM right now?
                break;
            case em_tlv_eht_operations:
                handle_eht_operations_tlv(tlv->value);
                break;
            default:
                em_printfout("Unknown TLV type %d in BSS Configuration Result message", tlv->type);
                break;
        } 

        tlv = em_msg_t::get_next_tlv(tlv, tlv_buff, tlv_buff_len);
    }

    uint8_t frame[MAX_EM_BUFF_SZ] = {0};

    int frame_len = create_agent_list_msg(frame, src_al_mac);
    EM_ASSERT_MSG_TRUE(frame_len > 0, -1, "Failed to create Agent List message");

    // Send the Agent List message
    int ret = send_frame(frame, static_cast<unsigned int>(frame_len), src_al_mac);
    EM_ASSERT_MSG_TRUE(ret == 0, -1, "Failed to send Agent List message to '" MACSTRFMT "'", MAC2STR(src_al_mac));
    em_printfout("Sent Agent List message to '" MACSTRFMT "'", MAC2STR(src_al_mac));

    // Set to WSC M2 Sent state, which can be used to kick off the rest
    em_bus_event_type_m2_tx_params_t   raw;

    set_state(em_state_ctrl_wsc_m2_sent);
    memcpy(raw.al, src_al_mac, sizeof(mac_address_t));
    memcpy(raw.radio, get_radio_interface_mac(), sizeof(mac_address_t));

	get_mgr()->io_process(em_bus_event_type_m2_tx, reinterpret_cast<unsigned char *> (&raw), sizeof(em_bus_event_type_m2_tx_params_t));

    return 0;
}

int em_configuration_t::handle_agent_list_msg(uint8_t *buff, unsigned int len, uint8_t src_al_mac[ETH_ALEN]) {
    // Agent

    em_tlv_t *tlv_buff = reinterpret_cast<em_tlv_t *>(buff + sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));
    unsigned int tlv_buff_len = static_cast<unsigned int>(len - (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t)));

    em_printfout("Received Agent List message from '" MACSTRFMT "'", MAC2STR(src_al_mac));

    em_tlv_t *tlv = em_msg_t::get_tlv(tlv_buff, tlv_buff_len, em_tlv_type_agent_list);
    EM_ASSERT_NOT_NULL(tlv, -1, "Failed to get Agent List TLV from Agent List message");


    em_agent_list_t* agent_list_tlv = reinterpret_cast<em_agent_list_t *>(tlv->value);

    em_agent_list_agent_t* agent_list = reinterpret_cast<em_agent_list_agent_t *>(agent_list_tlv->agents);
    for (size_t i = 0; i < agent_list_tlv->num_agents; i++) {

        em_agent_list_agent_t* agent = &agent_list[i];

        em_printfout("Agent %zu: MAC: " MACSTRFMT ", Profile: %d, Security: %s", i + 1, MAC2STR(agent->agent_mac), agent->multi_ap_profile,
                     agent->security ? "Enabled" : "Not Enabled");

        // TODO: DM? I don't think so?
        // This message is recieved on the agent side so theres no DM agent list to update here, just the DM for this agent
    }

    dm_network_t network;
    dm_easy_mesh_t *dm = get_data_model();
    //Commit controller mac address and upgrade to onboarded proxy agent
    if ((dm != NULL)) {
        memcpy(&network.m_net_info.ctrl_id.mac, src_al_mac, sizeof(mac_address_t));
        dm->set_network(network);
        if (get_mgr()->get_al_node() != NULL) {
            get_ec_mgr().upgrade_to_onboarded_proxy_agent(src_al_mac);
            set_is_dpp_onboarding(false);
            get_mgr()->get_al_node()->set_is_dpp_onboarding(false); // Just in case
        }
    }
    return 0;
}

int em_configuration_t::create_encrypted_settings(unsigned char *buff, em_haul_type_t haul_type)
{
    data_elem_attr_t *attr;
    short len = 0;
    unsigned char *tmp;
    unsigned int size = 0, cipher_len, plain_len;
    unsigned char iv[AES_BLOCK_SIZE];
    unsigned char plain[MAX_EM_BUFF_SZ];
    unsigned short auth_type = 0x0200; // WPA3-Personal
    unsigned char hash[SHA256_MAC_LEN];
    unsigned char *keywrap_data_addr[1];
    size_t keywrap_data_length[1];
    em_network_ssid_info_t *net_ssid_info;
    memset(plain, 0, MAX_EM_BUFF_SZ);
    tmp = plain;
    len = 0;

    dm_easy_mesh_t *dm = get_data_model();
    unsigned int no_of_haultype = 0, radio_exists, i;
    dm_radio_t * radio = NULL;

    for (i = 0; i < dm->get_num_radios(); i++) {
        radio = dm->get_radio(i);
        if (memcmp(radio->m_radio_info.id.ruid, get_radio_interface_mac(), sizeof(mac_address_t)) == 0) {
            radio_exists = true;
            break;
        }
    }
    if (radio_exists == false) {
        em_printfout("Radio does not exist, return len as 0.");
        return len;
    }
    em_printfout("radio:%s haul_type=%d radio no of bss=%d",
        util::mac_to_string(get_radio_interface_mac()).c_str(), haul_type, radio->m_radio_info.number_of_bss);

    if ((net_ssid_info = get_network_ssid_info_by_haul_type(haul_type)) == NULL) {
        em_printfout("Could not find network ssid information for haul type %d", haul_type);
        return 0;
    }
    em_printfout("ssid: %s, passphrase: %s", net_ssid_info->ssid, net_ssid_info->pass_phrase);

    // Add vendor extension for haul type
    attr = reinterpret_cast<data_elem_attr_t *> (tmp);
    attr->id = htons(attr_id_vendor_ext);
    size = EM_VENDOR_OUI_SIZE + sizeof(vendor_ext_attr_id_t) + sizeof(em_haul_type_t);
    attr->len = htons(static_cast<short unsigned int> (size));
    memcpy(reinterpret_cast<char *> (attr->val), em_vendor_oui, EM_VENDOR_OUI_SIZE);
    attr->val[EM_VENDOR_OUI_SIZE] = static_cast<unsigned char> (vendor_ext_attr_id_haul_type);
    attr->val[EM_VENDOR_OUI_SIZE + 1] = static_cast<unsigned char> (haul_type);

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

    // mac address
    attr = reinterpret_cast<data_elem_attr_t *> (tmp);
    attr->id = htons(attr_id_mac_address);
    size = sizeof(mac_address_t);
    attr->len = htons(static_cast<short unsigned int> (size));
    memcpy(reinterpret_cast<char *> (attr->val), const_cast<unsigned char *> (get_radio_interface_mac()), size);

    len += static_cast<short> (sizeof(data_elem_attr_t) + size);
    tmp += (sizeof(data_elem_attr_t) + size);

    // key wrap
    keywrap_data_addr[0] = plain;
    keywrap_data_length[0] = static_cast<size_t> (len);
    if (em_crypto_t::platform_hmac_SHA256(m_auth_key, WPS_AUTHKEY_LEN, 1, keywrap_data_addr, keywrap_data_length, hash) != 1) {
	    printf("%s:%d: Authenticator create failed\n", __func__, __LINE__);
	    return 0;
    }
    attr = reinterpret_cast<data_elem_attr_t *> (tmp);
    attr->id = htons(attr_id_key_wrap_authenticator);
    size = EM_KEY_WRAP_TLV_LEN;
    attr->len = htons(static_cast<short unsigned int> (size));
    memcpy(reinterpret_cast<char *> (attr->val), const_cast<unsigned char *> (hash), EM_KEY_WRAP_TLV_LEN);

    len += static_cast<short> (sizeof(data_elem_attr_t) + size);
    tmp += (sizeof(data_elem_attr_t) + size);

    if (em_crypto_t::generate_iv(iv, AES_BLOCK_SIZE) != 1) {
	    printf("%s:%d: iv generate failed\n", __func__, __LINE__);
	    return 0;
    }

    memcpy(buff, iv, AES_BLOCK_SIZE);

    plain_len = static_cast<unsigned int> (len);

    // encrypt the m2 data
    if (em_crypto_t::platform_aes_128_cbc_encrypt(m_key_wrap_key, iv, plain, plain_len, buff + AES_BLOCK_SIZE, &cipher_len) != 1) {
	    printf("%s:%d: platform encrypt failed\n", __func__, __LINE__);
	    return 0;
    }

    em_printfout("Encrypted for radio:%s haul_type:%d length:%u plain_len:%u",
        util::mac_to_string(get_radio_interface_mac()).c_str(), haul_type, cipher_len + AES_BLOCK_SIZE, plain_len);
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
    unsigned char msg[MAX_EM_BUFF_SZ*em_haul_type_max];
    unsigned int sz;
    char *errors[EM_MAX_TLV_MEMBERS] = {0};
    mac_addr_str_t  mac_str;
    em_tlv_t    *tlv;
    unsigned int tlv_len;
    em_bus_event_type_m2_tx_params_t   raw;


    dm_easy_mesh_t::macbytes_to_string(get_peer_mac(), mac_str);
    printf("%s:%d: Device AL MAC: %s\n", __func__, __LINE__, mac_str);

    if (em_msg_t(em_msg_type_autoconf_wsc, em_profile_type_3, buff, len).validate(errors) == 0) {
        printf("%s:%d: received autoconfig wsc m1 msg failed validation\n", __func__, __LINE__);

        //return -1;
    }

    tlv = reinterpret_cast<em_tlv_t *>(buff + sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t)); 
    tlv_len = len - static_cast<unsigned int> (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));
    em_cmdu_t *cmdu = reinterpret_cast<em_cmdu_t *> (buff + sizeof(em_raw_hdr_t));

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

    sz = static_cast<unsigned int> (create_autoconfig_wsc_m2_msg(msg, ntohs(cmdu->id)));

    if (em_msg_t(em_msg_type_autoconf_wsc, em_profile_type_3, msg, sz).validate(errors) == 0) {
        printf("Autoconfig wsc m2 msg failed validation in tnx end\n");

        return -1;
    }

    if (send_frame(msg, sz)  < 0) {
        printf("%s:%d: autoconfig wsc m2 send failed, error:%d\n", __func__, __LINE__, errno);
        return -1;
    }
	set_state(em_state_ctrl_wsc_m2_sent);
	printf("%s:%d: autoconfig wsc m2 send, len:%d\n", __func__, __LINE__, sz);
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

    em_printfout("Received autoconfig resp from " MACSTRFMT, MAC2STR(hdr->src));

    if (em_msg_t(buff + (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t)),
                len - static_cast<unsigned int>(sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t))).get_profile_type(&m_peer_profile) == false) {
        printf("%s:%d: Could not get peer profile type\n", __func__, __LINE__);
        return -1;
    }

    if (em_msg_t(em_msg_type_autoconf_resp, m_peer_profile, buff, len).validate(errors) == 0) {
        printf("received autoconfig resp msg failed validation\n");

        return -1;
    }

    // If this contains a DPP Chirp TLV, forward to EC manager for handling.
    em_tlv_t *dpp_chirp_tlv = em_msg_t(buff + sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t), len - static_cast<unsigned int> (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t))).get_tlv(em_tlv_type_dpp_chirp_value);
    if (dpp_chirp_tlv) {
        em_printfout("Found DPP Chirp in Autoconfig Response, forwarding to EC");
        return get_ec_mgr().handle_autoconf_resp_chirp(reinterpret_cast<em_dpp_chirp_value_t*>(dpp_chirp_tlv->value), SWAP_LITTLE_ENDIAN(dpp_chirp_tlv->len), hdr->src);
    }

    if (get_is_dpp_onboarding()) {
        // If DPP onboarding is enabled, we end here and start securing the 1905 layer
        set_state(em_state_agent_1905_securing); // Set state to avoid follow-on autoconf messages
        ec_manager_t &ec_mgr = get_ec_mgr();
        em_printfout("DPP Onboarding - starting 1905 security with controller " MACSTRFMT, MAC2STR(hdr->src));
        // Set peer AL MAC to controller AL MAC
        memcpy(ec_mgr.get_al_conn_ctx(NULL)->peer_al_mac, hdr->src, sizeof(mac_address_t));
        return get_ec_mgr().start_secure_1905_layer(hdr->src) ? 0 : -1;
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
    em_printfout("autoconfig wsc m1 send success, len:%d", sz);
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

    ec_manager_t &ec_mgr = get_ec_mgr();

    // Autoconf Search (extended) optionally contains a DPP chirp
    // If we find a chirp, forward to the EC manager for handling
    em_tlv_t *dpp_chirp_tlv = em_msg_t(buff + sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t), len - static_cast<unsigned int> (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t))).get_tlv(em_tlv_type_dpp_chirp_value);
    em_cmdu_t *cmdu = reinterpret_cast<em_cmdu_t *> (buff + sizeof(em_raw_hdr_t));
    if (dpp_chirp_tlv) {
        em_printfout("Found DPP Chirp in Autoconfig Search (extended), forwarding to EC");
        return ec_mgr.handle_autoconf_chirp(reinterpret_cast<em_dpp_chirp_value_t*>(dpp_chirp_tlv->value), SWAP_LITTLE_ENDIAN(dpp_chirp_tlv->len), al_mac, ntohs(cmdu->id));
    }
    
    sz = static_cast<unsigned int> (create_autoconfig_resp_msg(msg, band, al_mac, ntohs(cmdu->id)));
    if (em_msg_t(em_msg_type_autoconf_resp, em_profile_type_3, msg, sz).validate(errors) == 0) {
        printf("%s:%d: autoconfig rsp validation failed\n", __func__, __LINE__);

        //return -1;
    }

    if (send_frame(msg, sz)  < 0) {
        printf("%s:%d: autoconfig rsp send failed, error:%d\n", __func__, __LINE__, errno);

        return -1;
    }
    printf("%s:%d: autoconfig rsp send success\n", __func__, __LINE__);

    if (!get_is_dpp_onboarding()) {
        set_state(em_state_ctrl_wsc_m1_pending);
    }

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
    unsigned char *tlvs;
    unsigned int tlvs_len;

    em_cmdu_t *cmdu = reinterpret_cast<em_cmdu_t *>(data + sizeof(em_raw_hdr_t));
            
    tlvs = data + sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t);
    tlvs_len = len - static_cast<unsigned int> (sizeof(em_raw_hdr_t) - sizeof(em_cmdu_t));

    em_raw_hdr_t *hdr = reinterpret_cast<em_raw_hdr_t *>(data);
    uint8_t *src_al_mac = hdr->src;

    switch (htons(cmdu->type)) {
        case em_msg_type_autoconf_search:
            if (get_service_type() == em_service_type_ctrl) {
                handle_autoconfig_search(data, len);

            } else if (get_service_type() == em_service_type_agent) {
                printf("%s:%d: received em_msg_type_autoconf_search message in agent ... dropping\n", __func__, __LINE__);
            }

            break;

        case em_msg_type_autoconf_resp:
            if (((get_service_type() == em_service_type_agent &&
                    get_state() == em_state_agent_autoconfig_rsp_pending) ||
                (get_service_type() == em_service_type_agent && get_is_dpp_onboarding())) && get_state() != em_state_agent_1905_securing) {
                handle_autoconfig_resp(data, len);
            }
            break;

        case em_msg_type_autoconf_wsc:
            if ((get_wsc_msg_type(tlvs, tlvs_len) == em_wsc_msg_type_m2) &&
                    (get_service_type() == em_service_type_agent) && (get_state() == em_state_agent_wsc_m2_pending)) {
                        printf("%s:%d: received wsc_m2 len:%d\n", __func__, __LINE__, len);
                        handle_autoconfig_wsc_m2(data, len);
            } else if ((get_wsc_msg_type(tlvs, tlvs_len) == em_wsc_msg_type_m1) &&
                    (get_service_type() == em_service_type_ctrl) && (get_state() == em_state_ctrl_wsc_m1_pending))  {
                        printf("%s:%d: received wsc_m1 len:%d\n", __func__, __LINE__, len);
                        handle_autoconfig_wsc_m1(data, len);
            }

            break;

        case em_msg_type_autoconf_renew:
            if (get_service_type() == em_service_type_agent) {
                handle_autoconfig_renew(data, len);
            }
            break;

        case em_msg_type_topo_query:
            {
                int len = 0;
                std::vector<em_t*> em_radios;
                get_mgr()->get_all_em_for_al_mac(hdr->dst, em_radios);
                for (auto &em : em_radios) {
                    if ((em->get_service_type() == em_service_type_agent) && (em->get_state() < em_state_agent_ap_cap_report)) {
                        em_printfout("radio %s is not configured, ignoring", util::mac_to_string(em->get_radio_interface_mac()).c_str());
                        em_radios.clear();
                        return;
                    }
                }
                em_printfout("All radios are configured for al_mac:%s, sending topology response", util::mac_to_string(hdr->dst).c_str());
                len = send_topology_response_msg(data, ntohs(cmdu->id));
                if(len) {
                    for(auto &em : em_radios) {
                            em->set_state(em_state_agent_topo_synchronized);
                    }
                    em_printfout("Sent topology response message, set state to em_state_agent_topo_synchronized");
                }
                em_radios.clear();
            }
			break;

        case em_msg_type_topo_resp:
            if ((get_service_type() == em_service_type_ctrl) && (get_state() == em_state_ctrl_topo_sync_pending)){
                if (handle_topology_response(data, len) == 0) {
                    set_state(em_state_ctrl_topo_synchronized);
                    std::vector<em_t *> em_radios;
                    dm_easy_mesh_t *dm = get_data_model();
                    em_printfout("Topology response handled successfully by em radio:%s agent al_mac:%s src_mac:%s",
                        util::mac_to_string(get_radio_interface_mac()).c_str(), util::mac_to_string(dm->get_agent_al_interface_mac()).c_str(),
                        util::mac_to_string(hdr->src).c_str());
                    get_mgr()->get_all_em_for_al_mac(hdr->src, em_radios);
                    for (auto &em : em_radios) {
                        em->set_state(em_state_ctrl_topo_synchronized);
                        printf("%s:%d em_msg_type_topo_resp handle success, state: %s\n", __func__, __LINE__, em_t::state_2_str(em->get_state()));
                    }
                    em_radios.clear();
                    // update network topology here
                    get_mgr()->update_network_topology();
                    dm->set_topo_state(true);
                    dm->set_db_cfg_param(db_cfg_type_device_list_update, "");
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
                em_cmdu_t *cmdu = reinterpret_cast<em_cmdu_t *> (data + sizeof(em_raw_hdr_t));
                send_ap_mld_config_resp_msg(data, ntohs(cmdu->id));
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
            break;
        case em_msg_type_bss_config_req:
            if ((get_service_type() == em_service_type_ctrl)) {
                handle_bss_config_req_msg(data, len, src_al_mac);
            }
            break;
        case em_msg_type_bss_config_rsp:
            if ((get_service_type() == em_service_type_agent)){
                handle_bss_config_rsp_msg(data, len, src_al_mac);
            }
            break;
        case em_msg_type_bss_config_res:
            if ((get_service_type() == em_service_type_ctrl)) {
                handle_bss_config_res_msg(data, len, src_al_mac);
            }
            break;
        case em_msg_type_agent_list:
            if ((get_service_type() == em_service_type_agent)){
                handle_agent_list_msg(data, len, src_al_mac);
            }
            break;
        default:
            break;
    }
}

void em_configuration_t::handle_state_config_none()
{
    if (get_is_dpp_onboarding()) {
        // Enrollee is in onboarding state, so we should not send autoconfig search message
        em_t* al_node = get_mgr()->get_al_node();
        if (al_node == NULL) {
            return;
        }
        // TODO: Currently ethernet DPP never sets `m_is_onboarding` to false so this will work as expected.
        // but it should at some point so that needs to be addressed
        if (al_node->m_ec_manager->is_enrollee_onboarding()){
            // If the enrollee is DPP onboarding, we should not send autoconfig search
            return;
        }
        // Enrollee is not actively onboarding via EasyConnect DPP so we should procede with autoconfig search
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

void em_configuration_t::fill_media_data(em_media_spec_data_t *spec, dm_bss_t *bss)
{
    em_bss_info_t *bss_info = bss->get_bss_info();
    dm_easy_mesh_t  *dm = get_data_model();
    dm_radio_t      *radio;

    //update the media_type to 11ax
    spec->media_type = EM_MEDIA_WIFI_80211ax_6;
    spec->media_spec_size = 10;
    /* Update the media specific information here which includes
       1. role : AP or STA
       2. Band: 1 - 20Mhz, 2 - 40Mhz, 3 - 80Mhz, 4 - 160Mhz
    */
    if (bss_info->vap_mode == em_vap_mode_ap) {
        memcpy(spec->network_memb, bss_info->bssid.mac, sizeof(mac_address_t));
        spec->role = EM_MEDIA_WIFI_ROLE_AP;
    } else {
        memcpy(spec->network_memb, bss_info->sta_mac, sizeof(mac_address_t));
        spec->role = EM_MEDIA_WIFI_ROLE_STA;
    }
    radio = dm->get_radio(bss_info->ruid.mac);
    switch (radio->get_radio_info()->band) {
        case em_freq_band_24:
            spec->band = 0x01;
            break;

        case em_freq_band_5:
            spec->band = 0x03;
            break;

        case em_freq_band_60:
            spec->band = 0x04;
            break;

        default:
            spec->band = 0x01;
            break;
    }
    spec->center_freq_index_1 = 0;
    spec->center_freq_index_2 = 0;
}

void em_configuration_t::process_agent_state()
{
    switch (get_state()) {
        case em_state_agent_unconfigured:
        case em_state_agent_1905_unconfigured:
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
    dm_easy_mesh_t *dm = get_data_model();

    switch (get_state()) {
        case em_state_ctrl_misconfigured:
            send_autoconfig_renew_msg();
            break;

        case em_state_ctrl_topo_sync_pending:
            {
                std::vector<em_t *> em_radios;
                dm_easy_mesh_t *dm = get_data_model();
                get_mgr()->get_all_em_for_al_mac(dm->get_agent_al_interface_mac(), em_radios);
                for (auto &em : em_radios) {
                    if (em->get_state() != em_state_ctrl_topo_sync_pending) {
                        em_printfout("radio %s is not in topo sync pending state, ignoring",
                            util::mac_to_string(em->get_radio_interface_mac()).c_str());
                        em_radios.clear();
                        return;
                    }
                }
                // If all radios are in topo sync pending state, send topo query on one of them, 
                // ignore sending topo query on other radios
                if (this == em_radios.front()){
                    em_printfout("Sending the Topology query message to agent al_mac:%s on radio: %s",
                        util::mac_to_string(dm->get_agent_al_interface_mac()).c_str(),
                        util::mac_to_string(get_radio_interface_mac()).c_str());
                    em_t *al_em = get_mgr()->get_al_node();
                    al_em->set_state(em_state_ctrl_topo_sync_pending);
                    send_topology_query_msg();
                }
                em_radios.clear();
            }
            break;

        case em_state_ctrl_ap_mld_config_pending:
            send_ap_mld_config_req_msg();
            break;

        case em_state_ctrl_topo_publish_pending:
            if (dm->get_topo_state() == true) {
                em_printfout("Topology has changed for device: %s", util::mac_to_string(dm->get_agent_al_interface_mac()).c_str());
                dm->set_topo_state(false);
                get_mgr()->publish_network_topology();
            }
            set_state(em_state_ctrl_configured);
            break;

        default:
            em_printfout("unhandled state:%s in config state machine.", em_t::state_2_str(get_state()));
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


