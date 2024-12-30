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

short em_configuration_t::create_client_assoc_event_tlv(unsigned char *buff, mac_address_t sta, bssid_t bssid, bool assoc)
{
    short len = 0;
    unsigned char *tmp;
    unsigned char joined = (assoc == true)?0x80:0x00;

    tmp = buff;
    memcpy(tmp, sta, sizeof(mac_address_t));
    memcpy(tmp + sizeof(mac_address_t), bssid, sizeof(bssid_t));
    memcpy(tmp + 2*sizeof(mac_address_t), &joined, sizeof(unsigned char));

    len = 2*sizeof(mac_address_t) + sizeof(unsigned char);

    return len;
}

int em_configuration_t::send_topology_notification_by_client(mac_address_t sta, bssid_t bssid, bool assoc)
{
    unsigned short  msg_id = em_msg_type_topo_notif;
    char *errors[EM_MAX_TLV_MEMBERS] = {0};
    int len = 0;
    short sz;
    em_cmdu_t *cmdu;
    em_tlv_t *tlv;
    unsigned char buff[MAX_EM_BUFF_SZ];
    unsigned char *tmp = buff;
    unsigned short type = htons(ETH_P_1905);
    mac_address_t   multi_addr = {0x01, 0x80, 0xc2, 0x00, 0x00, 0x13};
    unsigned char joined = (assoc == true)?0x80:0x00;
    dm_easy_mesh_t *dm;

    dm = get_data_model();

    memcpy(tmp, (unsigned char *)multi_addr, sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += sizeof(mac_address_t);

    memcpy(tmp, dm->get_agent_al_interface_mac(), sizeof(mac_address_t));
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
    memcpy(tlv->value, get_al_interface_mac(), sizeof(mac_address_t));

    tmp += (sizeof (em_tlv_t) + sizeof(mac_address_t));
    len += (sizeof (em_tlv_t) + sizeof(mac_address_t));

    // Client Association Event  17.2.20
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_client_assoc_event;
    sz = create_client_assoc_event_tlv(tlv->value, sta, bssid, joined);
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

    if (em_msg_t(em_msg_type_topo_notif, em_profile_type_3, buff, len).validate(errors) == 0) {
        printf("Topology notification msg validation failed\n");

        return -1;
    }

    if (send_frame(buff, len)  < 0) {
        printf("%s:%d: Topology notification send failed, error:%d\n", __func__, __LINE__, errno);
        return -1;
    }

    printf("%s:%d: Topology notification Send Successful\n", __func__, __LINE__);

    return len;
}

void em_configuration_t::handle_state_topology_notify()
{
    dm_easy_mesh_t *dm;
    dm_sta_t *sta;

    dm = get_current_cmd()->get_data_model();

    sta = (dm_sta_t *)hash_map_get_first(dm->m_sta_assoc_map);
    while (sta != NULL) {
        send_topology_notification_by_client(sta->m_sta_info.id, sta->m_sta_info.bssid, true);
        sta = (dm_sta_t *)hash_map_get_next(dm->m_sta_assoc_map, sta);
    }

    sta = (dm_sta_t *)hash_map_get_first(dm->m_sta_dassoc_map);
    while (sta != NULL) {
        send_topology_notification_by_client(sta->m_sta_info.id, sta->m_sta_info.bssid, false);
        sta = (dm_sta_t *)hash_map_get_next(dm->m_sta_dassoc_map, sta);
    }
    set_state(em_state_agent_configured);
}

int em_configuration_t::send_autoconfig_renew_msg()
{
    unsigned char buff[MAX_EM_BUFF_SZ];
    char *errors[EM_MAX_TLV_MEMBERS] = {0};
    unsigned short  msg_id = em_msg_type_autoconf_renew;
    int len = 0;
    em_cmdu_t *cmdu;
    em_tlv_t *tlv;
    em_enum_type_t profile;
    unsigned char *tmp = buff;
    unsigned short type = htons(ETH_P_1905);
    dm_easy_mesh_t *dm;
    unsigned char registrar = 0;
    em_freq_band_t freq_band;

    dm = get_data_model();

    memcpy(tmp, dm->get_agent_al_interface_mac(), sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += sizeof(mac_address_t);

    memcpy(tmp, dm->get_ctrl_al_interface_mac(), sizeof(mac_address_t));
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
    cmdu->relay_ind = 0;

    tmp += sizeof(em_cmdu_t);
    len += sizeof(em_cmdu_t);

    // AL MAC Address type TLV
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_al_mac_address;
    tlv->len = htons(sizeof(mac_address_t));
    memcpy(tlv->value,get_current_cmd()->get_al_interface_mac(), sizeof(mac_address_t));

    tmp += (sizeof (em_tlv_t) + sizeof(mac_address_t));
    len += (sizeof (em_tlv_t) + sizeof(mac_address_t));

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
    freq_band = (em_freq_band_t)(get_band() >> 1);
    memcpy(&tlv->value, &freq_band, sizeof(unsigned char));

    tmp += (sizeof (em_tlv_t) + 1);
    len += (sizeof (em_tlv_t) + 1);

    // End of message
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += (sizeof (em_tlv_t));
    
    if (em_msg_t(em_msg_type_autoconf_renew, em_profile_type_3, buff, len).validate(errors) == 0) {
        printf("Autoconfig Renew msg validation failed\n");

        return -1;
    }

    if (send_frame(buff, len)  < 0) {
        printf("%s:%d: Autoconfig Renew send failed, error:%d\n", __func__, __LINE__, errno);
        return -1;
    }

    m_renew_tx_cnt++;
    printf("%s:%d: AutoConfig Renew (%d) Send Successful\n", __func__, __LINE__, m_renew_tx_cnt);

    return len;
}

int em_configuration_t::send_topology_query_msg()
{
    unsigned char buff[MAX_EM_BUFF_SZ];
    char *errors[EM_MAX_TLV_MEMBERS] = {0};
    unsigned short  msg_id = em_msg_type_topo_query;
    int len = 0;
    em_cmdu_t *cmdu;
    em_tlv_t *tlv;
	em_enum_type_t profile;	
    unsigned char *tmp = buff;
    unsigned short type = htons(ETH_P_1905);
	dm_easy_mesh_t *dm;

	dm = get_data_model();

    memcpy(tmp, dm->get_agent_al_interface_mac(), sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += sizeof(mac_address_t);

    memcpy(tmp, dm->get_ctrl_al_interface_mac(), sizeof(mac_address_t));
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
    cmdu->relay_ind = 0;

    tmp += sizeof(em_cmdu_t);
    len += sizeof(em_cmdu_t);

    // One AP Radio Identifier tlv 17.2.3
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_radio_id;
    memcpy(tlv->value, get_radio_interface_mac(), sizeof(mac_address_t));
    tlv->len = htons(sizeof(mac_address_t));

    tmp += (sizeof(em_tlv_t) + sizeof(mac_address_t));
    len += (sizeof(em_tlv_t) + sizeof(mac_address_t));

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

	return len;
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

    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_operational_bss;
    tlv_len = sizeof(em_ap_op_bss_t);
    printf("first tlv_len in em_configuration_t::create_operational_bss_tlv = %d\n",tlv_len);

    ap = (em_ap_op_bss_t *)tlv->value;
    ap->radios_num = dm->get_num_radios();
    radio = ap->radios;
	for (i = 0; i < dm->get_num_radios(); i++) {
		memcpy(radio->ruid, dm->get_radio_by_ref(i).get_radio_interface_mac(), sizeof(mac_address_t));
    	radio->bss_num = 0;
    	bss = radio->bss;
    	all_bss_len = 0;
    	for (j = 0; j < dm->get_num_bss(); j++) {
        	if (memcmp(dm->m_bss[j].m_bss_info.ruid.mac, dm->get_radio_by_ref(i).get_radio_interface_mac(), sizeof(mac_address_t)) != 0) {
            	continue;
        	}
        	radio->bss_num++;
        	memcpy(bss->bssid, dm->m_bss[j].m_bss_info.bssid.mac, sizeof(mac_address_t));
        	strncpy(bss->ssid, dm->m_bss[j].m_bss_info.ssid, strlen(dm->m_bss[j].m_bss_info.ssid) + 1);
        	printf("bss->ssid=%s\n",bss->ssid);
        	bss->ssid_len = strlen(dm->m_bss[j].m_bss_info.ssid) + 1;
        	all_bss_len += sizeof(em_ap_operational_bss_t) + bss->ssid_len;
        	bss = (em_ap_operational_bss_t *)((unsigned char *)bss + sizeof(em_ap_operational_bss_t) + bss->ssid_len);
    	}
    	radio = (em_ap_op_bss_radio_t *)((unsigned char *)radio + sizeof(em_ap_op_bss_radio_t) + all_bss_len);
    	tlv_len += sizeof(em_ap_op_bss_radio_t) + all_bss_len;
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

    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_bss_conf_rep;

    rprt = (em_bss_config_rprt_t *)tlv->value;
    rprt->num_radios = dm->get_num_radios();

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
        	bss_rprt->ssid_len = strlen(dm->m_bss[j].m_bss_info.ssid) + 1;
        	strncpy(bss_rprt->ssid, dm->m_bss[j].m_bss_info.ssid, strlen(dm->m_bss[j].m_bss_info.ssid) + 1);
	
    	    bss_rprt_len += bss_rprt->ssid_len;

        	bss_rprt = (em_bss_rprt_t *)((unsigned char *)bss_rprt + sizeof(em_bss_rprt_t) + strlen(dm->m_bss[j].m_bss_info.ssid) + 1);

        	rd_rprt->num_bss++;
    	}

    	rd_rprt = (em_radio_rprt_t *)((unsigned char *)rd_rprt + sizeof(em_radio_rprt_t) + bss_rprt_len);
    	tlv_len += sizeof(em_radio_rprt_t) + bss_rprt_len;
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

    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_device_info;
    dev_info = (em_device_info_type_t *)tlv->value;

    memcpy(dev_info->al_mac_addr, dm->get_agent_al_interface_mac(), sizeof(mac_address_t));
    dev_info->local_interface_num = dm->get_num_bss();
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
			fill_media_data(&dm->m_radio[j].m_radio_info.media_data);
			memcpy(&local_intf->media_data, &dm->m_radio[j].m_radio_info.media_data, sizeof(em_media_spec_data_t));

			local_intf = (em_local_interface_t *)((unsigned char *)local_intf + sizeof(em_local_interface_t));
			tlv_len = tlv_len + sizeof(em_local_interface_t);
		}
	}

	dev_info->local_interface_num = no_of_bss;
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

    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_ap_mld_config;

    ap_mld_conf = (em_ap_mld_config_t *)tlv->value;
    ap_mld_conf->num_ap_mld = dm->get_num_ap_mld();

    tlv_len = sizeof(em_ap_mld_config_t);

    ap_mld = ap_mld_conf->ap_mld;

    for (i = 0; i < dm->get_num_ap_mld(); i++) {
        em_ap_mld_info_t& ap_mld_info = dm->m_ap_mld[i].m_ap_mld_info;
        ap_mld->ap_mld_mac_addr_valid = ap_mld_info.mac_addr_valid;

        ap_mld_ssids = ap_mld->ssids;
        ap_mld_ssids->ssid_len = strlen(ap_mld_info.ssid) + 1;
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
            memcpy(affiliated_ap_mld->affiliated_mac_addr, affiliated_ap_info.mac_addr, sizeof(mac_address_t));
            memcpy(&affiliated_ap_mld->link_id, &affiliated_ap_info.link_id, sizeof(unsigned char));

            affiliated_ap_mld = (em_affiliated_ap_mld_t *)((unsigned char *)affiliated_ap_mld + sizeof(em_affiliated_ap_mld_t));
            affiliated_ap_len += sizeof(em_affiliated_ap_mld_t);
        }

        ap_mld = (em_ap_mld_t *)((unsigned char *)ap_mld + sizeof(em_ap_mld_t) + ap_mld_ssids->ssid_len + affiliated_ap_len);
        ap_mld_len += sizeof(em_ap_mld_t) + ap_mld_ssids->ssid_len + affiliated_ap_len;
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
    em_affiliated_bsta_mld_t *affiliated_bsta_mld;
    dm_easy_mesh_t  *dm;
    unsigned int i;
    unsigned short affiliated_bsta_len = 0;
    unsigned short tlv_len = 0;

    dm = get_data_model();

    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_bsta_mld_config;

    bsta_mld_conf = (em_bsta_mld_config_t *)tlv->value;
    tlv_len = sizeof(em_bsta_mld_config_t);

    em_bsta_mld_info_t& bsta_mld_info = dm->m_bsta_mld.m_bsta_mld_info;
    bsta_mld_conf->bsta_mld_mac_addr_valid = bsta_mld_info.mac_addr_valid;
    bsta_mld_conf->ap_mld_mac_addr_valid = bsta_mld_info.ap_mld_mac_addr_valid;
    memcpy(bsta_mld_conf->bsta_mld_mac_addr, bsta_mld_info.mac_addr, sizeof(mac_address_t));
    memcpy(bsta_mld_conf->ap_mld_mac_addr, bsta_mld_info.ap_mld_mac_addr, sizeof(mac_address_t));
    bsta_mld_conf->str = bsta_mld_info.str;
    bsta_mld_conf->nstr = bsta_mld_info.nstr;
    bsta_mld_conf->emlsr = bsta_mld_info.emlsr;
    bsta_mld_conf->emlmr = bsta_mld_info.emlmr;

    bsta_mld_conf->num_affiliated_bsta = bsta_mld_info.num_affiliated_bsta;
    affiliated_bsta_mld = bsta_mld_conf->affiliated_bsta_mld;

    for (i = 0; i < bsta_mld_conf->num_affiliated_bsta; i++) {
        em_affiliated_bsta_info_t& affiliated_bsta_info = bsta_mld_info.affiliated_bsta[i];
        affiliated_bsta_mld->affiliated_bsta_mac_addr_valid = affiliated_bsta_info.mac_addr_valid;
        memcpy(affiliated_bsta_mld->ruid, affiliated_bsta_info.ruid.mac, sizeof(mac_address_t));
        memcpy(affiliated_bsta_mld->affiliated_bsta_mac_addr, affiliated_bsta_info.mac_addr, sizeof(mac_address_t));

        affiliated_bsta_mld = (em_affiliated_bsta_mld_t *)((unsigned char *)affiliated_bsta_mld + sizeof(em_affiliated_bsta_mld_t));
        affiliated_bsta_len += sizeof(em_affiliated_bsta_mld_t);
    }

    tlv_len += affiliated_bsta_len;
    tlv->len = htons(tlv_len);

    return tlv_len;
}

int em_configuration_t::create_assoc_sta_mld_config_report_tlv(unsigned char *buff)
{
    em_tlv_t *tlv;
    unsigned char *tmp = buff;
    em_assoc_sta_mld_config_report_t *assoc_sta_mld_conf_report;
    em_affiliated_sta_mld_t *affiliated_sta_mld;
    dm_easy_mesh_t  *dm;
    unsigned int i;
    unsigned short affiliated_sta_len = 0;
    unsigned short tlv_len = 0;

    dm = get_data_model();

    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_assoc_sta_mld_conf_rep;

    assoc_sta_mld_conf_report = (em_assoc_sta_mld_config_report_t *)tlv->value;
    tlv_len = sizeof(em_assoc_sta_mld_config_report_t);

    em_assoc_sta_mld_info_t& assoc_sta_mld_info = dm->m_assoc_sta_mld.m_assoc_sta_mld_info;
    memcpy(assoc_sta_mld_conf_report->sta_mld_mac_addr, assoc_sta_mld_info.mac_addr, sizeof(mac_address_t));
    memcpy(assoc_sta_mld_conf_report->ap_mld_mac_addr, assoc_sta_mld_info.ap_mld_mac_addr, sizeof(mac_address_t));
    assoc_sta_mld_conf_report->str = assoc_sta_mld_info.str;
    assoc_sta_mld_conf_report->nstr = assoc_sta_mld_info.nstr;
    assoc_sta_mld_conf_report->emlsr = assoc_sta_mld_info.emlsr;
    assoc_sta_mld_conf_report->emlmr = assoc_sta_mld_info.emlmr;

    assoc_sta_mld_conf_report->num_affiliated_sta = assoc_sta_mld_info.num_affiliated_sta;
    affiliated_sta_mld = assoc_sta_mld_conf_report->affiliated_sta_mld;

    for (i = 0; i < assoc_sta_mld_conf_report->num_affiliated_sta; i++) {
        em_affiliated_sta_info_t& affiliated_sta_info = assoc_sta_mld_info.affiliated_sta[i];
        memcpy(affiliated_sta_mld->bssid, affiliated_sta_info.bssid, sizeof(mac_address_t));
        memcpy(affiliated_sta_mld->affiliated_sta_mac_addr, affiliated_sta_info.mac_addr, sizeof(mac_address_t));

        affiliated_sta_mld = (em_affiliated_sta_mld_t *)((unsigned char *)affiliated_sta_mld + sizeof(em_affiliated_sta_mld_t));
        affiliated_sta_len += sizeof(em_affiliated_sta_mld_t);
    }

    tlv_len += affiliated_sta_len;
    tlv->len = htons(tlv_len);

    return tlv_len;
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

    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_tid_to_link_map_policy;

    tid_to_link_map_policy = (em_tid_to_link_map_policy_t *)tlv->value;
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

        tid_to_link_mapping = (em_tid_to_link_mapping_t *)((unsigned char *)tid_to_link_mapping + sizeof(em_tid_to_link_mapping_t));
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
    int len = 0;
    em_cmdu_t *cmdu;
    em_tlv_t *tlv;
    unsigned short tlv_len;
    unsigned char *tmp = buff;
    unsigned short type = htons(ETH_P_1905);
    em_service_type_t   service_type = get_service_type();
    dm_easy_mesh_t  *dm;
    em_enum_type_t profile;

    em_raw_hdr_t *hdr = (em_raw_hdr_t *)dst;

    dm = get_data_model();
    printf("%s:%d: Testing topo, number of radios: %d, bss: %d\n", __func__, __LINE__,
                        dm->get_num_radios(), dm->get_num_bss());

    memcpy(tmp, (unsigned char *)hdr->src, sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += sizeof(mac_address_t);

    memcpy(tmp, dm->get_agent_al_interface_mac(), sizeof(mac_address_t));
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
    cmdu->relay_ind = 0;

    tmp += sizeof(em_cmdu_t);
    len += sizeof(em_cmdu_t);

    // Device Info type TLV 1905.1 6.4.5
    tlv_len = create_device_info_type_tlv(tmp);

    tmp += (sizeof (em_tlv_t) + tlv_len);
    len += (sizeof (em_tlv_t) + tlv_len);

    // supported service tlv 17.2.1
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_supported_service;
    tlv->len = htons(sizeof(em_enum_type_t) + 1);
    tlv->value[0] = 1;
    memcpy(&tlv->value[1], &service_type, sizeof(em_enum_type_t));

    tmp += (sizeof(em_tlv_t) + sizeof(em_enum_type_t) + 1);
    len += (sizeof(em_tlv_t) + sizeof(em_enum_type_t) + 1);

    // One AP Radio Identifier tlv 17.2.3
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_radio_id;
    memcpy(tlv->value, get_radio_interface_mac(), sizeof(mac_address_t));
    tlv->len = htons(sizeof(mac_address_t));

    tmp += (sizeof(em_tlv_t) + sizeof(mac_address_t));
    len += (sizeof(em_tlv_t) + sizeof(mac_address_t));

    // AP operational BSS
    tlv_len = create_operational_bss_tlv(tmp);

    tmp += (sizeof(em_tlv_t) + tlv_len);
    len += (sizeof(em_tlv_t) + tlv_len);

    // One multiAP profile tlv 17.2.47
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_profile;
    tlv->len = htons(sizeof(em_enum_type_t));
    profile = em_profile_type_3;
    memcpy(tlv->value, &profile, sizeof(em_enum_type_t));

    tmp += (sizeof(em_tlv_t) + sizeof(em_enum_type_t));
    len += (sizeof(em_tlv_t) + sizeof(em_enum_type_t));

    // One BSS Configuration Report 17.2.75
    tlv_len = create_bss_config_rprt_tlv(tmp);

    tmp += (sizeof(em_tlv_t) + tlv_len);
    len += (sizeof(em_tlv_t) + tlv_len);

    // One AP MLD Configuration TLV
    tlv_len = create_ap_mld_config_tlv(tmp);

    tmp += (sizeof(em_tlv_t) + tlv_len);
    len += (sizeof(em_tlv_t) + tlv_len);

    // One Backhaul STA MLD Configuration TLV
    tlv_len = create_bsta_mld_config_tlv(tmp);

    tmp += (sizeof(em_tlv_t) + tlv_len);
    len += (sizeof(em_tlv_t) + tlv_len);

    // One Associated STA MLD Configuration Report TLV
    tlv_len = create_assoc_sta_mld_config_report_tlv(tmp);

    tmp += (sizeof(em_tlv_t) + tlv_len);
    len += (sizeof(em_tlv_t) + tlv_len);

    // One TID-to-Link Mapping Policy TLV
    tlv_len = create_tid_to_link_map_policy_tlv(tmp);

    tmp += (sizeof(em_tlv_t) + tlv_len);
    len += (sizeof(em_tlv_t) + tlv_len);

    // End of message
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += (sizeof (em_tlv_t));

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
    return len;
}

int em_configuration_t::send_ap_mld_config_req_msg(unsigned char *buff)
{
    int tlv_len = create_ap_mld_config_tlv(buff);
    em_radio_cap_info_t* cap_info = get_data_model()->get_radio_cap(get_radio_interface_mac())->get_radio_cap_info();
    em_eht_operations_t *eht_ops = (em_eht_operations_t *)buff;

    if ((eht_ops == NULL) || (cap_info == NULL)) {
        printf("%s:%d No data Found\n", __func__, __LINE__);
        return 0;
    }
    memcpy(&eht_ops,&cap_info->eht_ops,sizeof(em_eht_operations_t));
    tlv_len += sizeof(em_eht_operations_t);
    return tlv_len;
}

int em_configuration_t::send_ap_mld_config_resp_msg(unsigned char *buff)
{
    int tlv_len = create_ap_mld_config_tlv(buff);
    em_radio_cap_info_t* cap_info = get_data_model()->get_radio_cap(get_radio_interface_mac())->get_radio_cap_info();
    em_eht_operations_t *eht_ops = (em_eht_operations_t *)buff;

    if ((eht_ops == NULL) || (cap_info == NULL)) {
        printf("%s:%d No data Found\n", __func__, __LINE__);
        return 0;
    }
    memcpy(&eht_ops,&cap_info->eht_ops,sizeof(em_eht_operations_t));
    tlv_len += sizeof(em_eht_operations_t);
    return tlv_len;
}

void em_configuration_t::print_bss_configuration_report_tlv(unsigned char *value, unsigned int len)
{
	mac_addr_str_t	rd_mac_str, bss_mac_str;
	em_bss_config_rprt_t *rprt;
	em_radio_rprt_t *rd_rprt;
	em_bss_rprt_t *bss_rprt;
	unsigned int i, j;
	unsigned int all_bss_len = 0;

	rprt = (em_bss_config_rprt_t *)value;
	rd_rprt = rprt->radio_rprt;

	printf("%s:%d: Number of radios: %d\n", __func__, __LINE__, rprt->num_radios);
	for (i = 0; i < rprt->num_radios; i++) {
		dm_easy_mesh_t::macbytes_to_string(rd_rprt->ruid, rd_mac_str);
		printf("%s:%d: Radio: %s Number of BSS: %d\n", __func__, __LINE__, rd_mac_str, rd_rprt->num_bss);
		bss_rprt = rd_rprt->bss_rprt;
		for (j = 0; j < rd_rprt->num_bss; j++) {
			dm_easy_mesh_t::macbytes_to_string(bss_rprt->bssid, bss_mac_str);
			printf("%s:%d: BSSID: %s SSID: %s\n", __func__, __LINE__, bss_mac_str, bss_rprt->ssid);
			
			all_bss_len = all_bss_len + sizeof(em_bss_rprt_t) + strlen(bss_rprt->ssid) + 1;
			bss_rprt = (em_bss_rprt_t *)((unsigned char *)bss_rprt + sizeof(em_bss_rprt_t) + strlen(bss_rprt->ssid) + 1);
		}
		rd_rprt = (em_radio_rprt_t *)((unsigned char *)rd_rprt + sizeof(em_radio_rprt_t) + all_bss_len);
		all_bss_len = 0;
		
	}		
}

void em_configuration_t::print_ap_operational_bss_tlv(unsigned char *value, unsigned int len)
{
	mac_addr_str_t	rd_mac_str, bss_mac_str;
	em_ap_op_bss_t	*ap;
	em_ap_op_bss_radio_t	*radio;
	em_ap_operational_bss_t	*bss;
	unsigned char * tmp = value;
	unsigned int i, j, all_bss_len = 0, ap_op_bss_tlv_len = 0;
	
	ap = (em_ap_op_bss_t *)value;
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

			all_bss_len += sizeof(em_ap_operational_bss_t) + bss->ssid_len;
			//printf("%s:%d: All BSS Len: %d\n", __func__, __LINE__, all_bss_len);
			bss = (em_ap_operational_bss_t *)((unsigned char *)bss + sizeof(em_ap_operational_bss_t) + bss->ssid_len);
		}		

		radio = (em_ap_op_bss_radio_t *)((unsigned char *)radio + sizeof(em_ap_op_bss_radio_t) + all_bss_len);
	}
}

int em_configuration_t::handle_bss_configuration_report(unsigned char *buff, unsigned int len)
{
	return 0;
}

int em_configuration_t::handle_ap_operational_bss(unsigned char *buff, unsigned int len)
{
	dm_easy_mesh_t	*dm;
	em_ap_op_bss_t	*ap;
	em_ap_op_bss_radio_t	*radio;
	em_ap_operational_bss_t	*bss;
	dm_bss_t *dm_bss;
	unsigned int db_cfg_type;
	bool found_radio = false, new_bss;
	unsigned int i, j;
	unsigned int all_bss_len = 0;

	dm = get_data_model();
            
    // first verify that dm has all the radios
    ap = (em_ap_op_bss_t *)buff;
    assert(ap->radios_num == dm->get_num_radios());
    radio = (em_ap_op_bss_radio_t *)ap->radios;

    for (i = 0; i < ap->radios_num; i++) {
        for (j = 0; j < dm->get_num_radios(); j++) {
            if (memcmp(radio->ruid, dm->m_radio[j].m_radio_info.id.mac, sizeof(mac_address_t)) == 0) {
                found_radio = true;
                break;
            }
        }

        if (found_radio == false) {
            // do not update anything and retrun error
            return -1;
        }

        db_cfg_type = dm->get_db_cfg_type();

        found_radio = false;
        bss = radio->bss;
        all_bss_len = 0;
        for (j = 0; j < radio->bss_num; j++) {
            dm->set_db_cfg_type(db_cfg_type | db_cfg_type_bss_list_update);
            dm_bss = dm->get_bss_index(radio->ruid, bss->bssid, &new_bss);
            strncpy(dm_bss->m_bss_info.ssid, bss->ssid, bss->ssid_len);
            if (new_bss == true) {
                memcpy(dm_bss->m_bss_info.bssid.mac, bss->bssid, sizeof(mac_address_t));
                memcpy(dm_bss->m_bss_info.ruid.mac, radio->ruid, sizeof(mac_address_t));
                dm->set_num_bss(dm->get_num_bss() + 1);
            }
			all_bss_len += sizeof(em_ap_operational_bss_t) + bss->ssid_len;
            bss += sizeof(em_ap_operational_bss_t) + bss->ssid_len;
        }

        radio = (em_ap_op_bss_radio_t *)((unsigned char *)radio + sizeof(em_ap_op_bss_radio_t) + all_bss_len);

    }

	return 0;

}

int em_configuration_t::handle_topology_notification(unsigned char *buff, unsigned int len)
{
    em_tlv_t *tlv;
    int tmp_len, ret = 0;
    mac_address_t dev_mac;
    mac_addr_str_t sta_mac_str, bssid_str, radio_mac_str;
    em_long_string_t    key;
    dm_easy_mesh_t  *dm;
    unsigned int db_cfg_type;
    bool found_dev_mac = false;
    dm_sta_t *sta;
    em_client_assoc_event_t *assoc_evt_tlv;
    em_sta_info_t sta_info;
    em_event_t  ev;
    em_bus_event_t *bev;
    em_bus_event_type_client_assoc_params_t    *raw;
    char *errors[EM_MAX_TLV_MEMBERS] = {0};
    bool eligible_to_req_cap = false;

    dm = get_data_model();
	
	if (em_msg_t(em_msg_type_topo_notif, m_peer_profile, buff, len).validate(errors) == 0) {
        printf("%s:%d: topology response msg validation failed\n", __func__, __LINE__);
            
        //return -1;
    }       
        
    tlv =  (em_tlv_t *)(buff + sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));
    tmp_len = len - (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));
        
    while ((tlv->type != em_tlv_type_eom) && (tmp_len > 0)) {
        if (tlv->type == em_tlv_type_al_mac_address) {
			memcpy(dev_mac, tlv->value, sizeof(mac_address_t));
			found_dev_mac = true;
			break;
        }
            
		tmp_len -= (sizeof(em_tlv_t) + htons(tlv->len));
		tlv = (em_tlv_t *)((unsigned char *)tlv + sizeof(em_tlv_t) + htons(tlv->len));
    }

	if (found_dev_mac == false) {
		printf("%s:%d: Could not find device al mac address\n", __func__, __LINE__);
		return -1;
	}

    while ((tlv->type != em_tlv_type_eom) && (tmp_len > 0)) {
        if (tlv->type == em_tlv_type_client_assoc_event) {
            assoc_evt_tlv = (em_client_assoc_event_t *)tlv->value;
            dm_easy_mesh_t::macbytes_to_string(assoc_evt_tlv->cli_mac_address, sta_mac_str);
            dm_easy_mesh_t::macbytes_to_string(assoc_evt_tlv->bssid, bssid_str);
            dm_easy_mesh_t::macbytes_to_string(get_radio_interface_mac(), radio_mac_str);
            snprintf(key, sizeof(em_long_string_t), "%s@%s@%s", sta_mac_str, bssid_str, radio_mac_str);

            //printf("%s:%d: Client Device:%s %s\n", __func__, __LINE__, sta_mac_str,
                    //(assoc_evt_tlv->assoc_event == 1)?"associated":"disassociated");

            if ((sta = (dm_sta_t *)hash_map_get(dm->m_sta_map, key)) == NULL) {
                eligible_to_req_cap = true;
            } else {
                sta = (dm_sta_t *)hash_map_get(dm->m_sta_map, key);
                // During an association if map data has empty frame for an existing entry, request cap report to update Frame body
                if ((assoc_evt_tlv->assoc_event == true)) {
                    eligible_to_req_cap = true;
                }
            }

            // if associated for first time, orchestrate a client capability query/response
            if(eligible_to_req_cap == true) {
                ev.type = em_event_type_bus;
                bev = &ev.u.bevt;
                bev->type = em_bus_event_type_sta_assoc;
                raw = (em_bus_event_type_client_assoc_params_t *)bev->u.raw_buff;
                memcpy(raw->dev, dev_mac, sizeof(mac_address_t));
                memcpy((unsigned char *)&raw->assoc, (unsigned char *)assoc_evt_tlv, sizeof(em_client_assoc_event_t));

                em_cmd_exec_t::send_cmd(em_service_type_ctrl, (unsigned char *)&ev, sizeof(em_event_t));
            } else {
                memset(&sta_info, 0, sizeof(em_sta_info_t));
                memcpy(sta_info.id, assoc_evt_tlv->cli_mac_address, sizeof(mac_address_t));
                memcpy(sta_info.bssid, assoc_evt_tlv->bssid, sizeof(mac_address_t));
                memcpy(sta_info.radiomac, get_radio_interface_mac(), sizeof(mac_address_t));
                sta_info.associated = assoc_evt_tlv->assoc_event;

                hash_map_put(dm->m_sta_assoc_map, strdup(key), new dm_sta_t(&sta_info));

                db_cfg_type = dm->get_db_cfg_type();
                dm->set_db_cfg_type(db_cfg_type | db_cfg_type_sta_list_update);
            }
            break;
        }
            
		tmp_len -= (sizeof(em_tlv_t) + htons(tlv->len));
		tlv = (em_tlv_t *)((unsigned char *)tlv + sizeof(em_tlv_t) + htons(tlv->len));
    }

	return 0;
}

int em_configuration_t::handle_topology_response(unsigned char *buff, unsigned int len)
{
    em_tlv_t *tlv;
    int tmp_len, ret = 0;
    unsigned int sz, i, j;
    char *errors[EM_MAX_TLV_MEMBERS] = {0};
    bool found_op_bss = false;
    bool found_profile = false;
    bool found_bss_config_rprt = false;
    em_profile_type_t profile;
	dm_easy_mesh_t *dm;
	unsigned int db_cfg_type;
    
	dm = get_data_model();
    db_cfg_type = dm->get_db_cfg_type();

    tlv =  (em_tlv_t *)(buff + sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));
    tmp_len = len - (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));
        
    while ((tlv->type != em_tlv_type_eom) && (tmp_len > 0)) {
        if (tlv->type != em_tlv_type_profile) {
            tmp_len -= (sizeof(em_tlv_t) + htons(tlv->len));
            tlv = (em_tlv_t *)((unsigned char *)tlv + sizeof(em_tlv_t) + htons(tlv->len));

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
        
    tlv =  (em_tlv_t *)(buff + sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));
    tmp_len = len - (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));
        
    while ((tlv->type != em_tlv_type_eom) && (tmp_len > 0)) {
        if (tlv->type != em_tlv_type_operational_bss) {
            tmp_len -= (sizeof(em_tlv_t) + htons(tlv->len));
            tlv = (em_tlv_t *)((unsigned char *)tlv + sizeof(em_tlv_t) + htons(tlv->len));

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
            tmp_len -= (sizeof(em_tlv_t) + htons(tlv->len));
            tlv = (em_tlv_t *)((unsigned char *)tlv + sizeof(em_tlv_t) + htons(tlv->len));

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

	dm->set_db_cfg_type(db_cfg_type | db_cfg_type_policy_list_update);

	return ret;
}


short em_configuration_t::create_traffic_separation_policy(unsigned char *buff)
{
    short len = 0;
    unsigned int i;
    em_traffic_sep_policy_t *policy;
    em_traffic_sep_policy_ssid_t *policy_ssid;
    dm_easy_mesh_t *dm = get_data_model();

    policy = (em_traffic_sep_policy_t *)buff;
    policy->ssids_num = dm->m_num_net_ssids;
    policy_ssid = policy->ssids;

    len += sizeof(em_traffic_sep_policy_t);

    for (i = 0; i < dm->m_num_net_ssids; i++) {

        policy_ssid->ssid_len = strlen(dm->m_network_ssid[i].m_network_ssid_info.ssid) + 1;
        strncpy(policy_ssid->ssid, dm->m_network_ssid[i].m_network_ssid_info.ssid, policy_ssid->ssid_len);
        len = len + (sizeof(em_traffic_sep_policy_ssid_t) + policy_ssid->ssid_len + sizeof(unsigned short));
        policy_ssid = (em_traffic_sep_policy_ssid_t *)((unsigned char *)policy_ssid + sizeof(em_traffic_sep_policy_ssid_t) + policy_ssid->ssid_len + sizeof(unsigned short));
        //printf("%s:%d: SSID: %s SSID Len: %d\n", __func__, __LINE__, 
        //    dm->m_network_ssid[i].m_network_ssid_info.ssid, strlen(dm->m_network_ssid[i].m_network_ssid_info.ssid));
    }

    //printf("%s:%d: Length: %d\n", __func__, __LINE__, len);
    return len;
}

short em_configuration_t::create_m2_msg(unsigned char *buff, em_haul_type_t haul_type)
{
    data_elem_attr_t *attr;
    short len = 0;
    unsigned short size;
    unsigned char *tmp;
    tmp = buff;
    em_freq_band_t rf_band;
 
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
    rf_band = get_band();
    memcpy(attr->val, &rf_band, size);
 
    len += (sizeof(data_elem_attr_t) + size);
    tmp += (sizeof(data_elem_attr_t) + size);
    // association state
    attr = (data_elem_attr_t *)tmp;
    attr->id = htons(attr_id_assoc_state);
    size = sizeof(unsigned short);
    attr->len = htons(size);
    memcpy(attr->val, &rf_band, sizeof(attr->val));
    
    len += (sizeof(data_elem_attr_t) + size);
    tmp += (sizeof(data_elem_attr_t) + size);
    // config error
    attr = (data_elem_attr_t *)tmp;
    attr->id = htons(attr_id_cfg_error);
    size = sizeof(unsigned short);
    attr->len = htons(size);
    memcpy(attr->val, &rf_band, sizeof(attr->val));
    
    len += (sizeof(data_elem_attr_t) + size);
    tmp += (sizeof(data_elem_attr_t) + size);
    // device password id
    attr = (data_elem_attr_t *)tmp;
    attr->id = htons(attr_id_device_password_id);
    size = sizeof(unsigned short);
    attr->len = htons(size);
    memcpy(attr->val, &rf_band, sizeof(attr->val));
    
    len += (sizeof(data_elem_attr_t) + size);
    tmp += (sizeof(data_elem_attr_t) + size);
    // os version   
    attr = (data_elem_attr_t *)tmp;
    attr->id = htons(attr_id_os_version);
    size = sizeof(unsigned short);
    attr->len = htons(size);
    memcpy(attr->val, &rf_band, sizeof(attr->val));
    
    len += (sizeof(data_elem_attr_t) + size);
    tmp += (sizeof(data_elem_attr_t) + size);
    // encrypted settings
    attr = (data_elem_attr_t *)tmp;
    attr->id = htons(attr_id_encrypted_settings);
    size = create_encrypted_settings(attr->val, haul_type);
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
    unsigned short size;
    unsigned char *tmp;
    em_freq_band_t rf_band;

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
    rf_band = (em_freq_band_t)(1 << get_band());
    memcpy(attr->val, &rf_band, size);

    len += (sizeof(data_elem_attr_t) + size);
    tmp += (sizeof(data_elem_attr_t) + size);

    // association state
    attr = (data_elem_attr_t *)tmp;
    attr->id = htons(attr_id_assoc_state);
    size = sizeof(unsigned short);
    attr->len = htons(size);
    memcpy(attr->val, &rf_band, sizeof(attr->val));

    len += (sizeof(data_elem_attr_t) + size);
    tmp += (sizeof(data_elem_attr_t) + size);

    // device password id
    attr = (data_elem_attr_t *)tmp;
    attr->id = htons(attr_id_device_password_id);
    size = sizeof(unsigned short);
    attr->len = htons(size);
    memcpy(attr->val, &rf_band, sizeof(attr->val));

    len += (sizeof(data_elem_attr_t) + size);
    tmp += (sizeof(data_elem_attr_t) + size);

    // config error
    attr = (data_elem_attr_t *)tmp;
    attr->id = htons(attr_id_cfg_error);
    size = sizeof(unsigned short);
    attr->len = htons(size);
    memcpy(attr->val, &rf_band, sizeof(attr->val));

    len += (sizeof(data_elem_attr_t) + size);
    tmp += (sizeof(data_elem_attr_t) + size);

    // os version   
    attr = (data_elem_attr_t *)tmp;
    attr->id = htons(attr_id_os_version);
    size = sizeof(unsigned short);
    attr->len = htons(size);
    memcpy(attr->val, &rf_band, sizeof(attr->val));

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

    //printf("%s:%d: Secret Key:\n", __func__, __LINE__);
    //dm_easy_mesh_t::print_hex_dump(secret_len, secret);

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

    //printf("%s:%d: e-nonce:\n", __func__, __LINE__);
    //dm_easy_mesh_t::print_hex_dump(length[0], addr[0]);
    
    //printf("%s:%d: e-mac:\n", __func__, __LINE__);
    //dm_easy_mesh_t::print_hex_dump(length[1], addr[1]);
    
    //printf("%s:%d: r-nonce:\n", __func__, __LINE__);
    //dm_easy_mesh_t::print_hex_dump(length[2], addr[2]);
    
    if (compute_kdk(dhkey, SHA256_MAC_LEN, 3, addr, length, kdk) != 1) {
        free(secret);
        printf("%s:%d: kdk computation failed\n", __func__, __LINE__);
        return -1;
    }

    //printf("%s:%d: kdk:\n", __func__, __LINE__);
    //dm_easy_mesh_t::print_hex_dump(SHA256_MAC_LEN, kdk);
    if (derive_key(kdk, NULL, 0, str, keys, sizeof(keys)) != 1) {
        free(secret);
        printf("%s:%d: key derivation failed\n", __func__, __LINE__);
        return -1;
    }

    memcpy(m_auth_key, keys, WPS_AUTHKEY_LEN);
    memcpy(m_key_wrap_key, keys + WPS_AUTHKEY_LEN, WPS_KEYWRAPKEY_LEN);
    memcpy(m_emsk, keys + WPS_AUTHKEY_LEN + WPS_KEYWRAPKEY_LEN, WPS_EMSK_LEN);

    //printf("%s:%d: Encrypt/Decrypt Key:\n", __func__, __LINE__);
    //dm_easy_mesh_t::print_hex_dump(WPS_EMSK_LEN, m_emsk);

    return 1;
}

int em_configuration_t::create_autoconfig_wsc_m2_msg(unsigned char *buff, em_haul_type_t haul_type[], unsigned int num_hauls)
{
    unsigned short  msg_id = em_msg_type_autoconf_wsc;
    int len = 0, i;
    em_cmdu_t *cmdu;
    em_tlv_t *tlv;
    em_8021q_settings_t *q_settings;
    unsigned char *tmp = buff;
    unsigned short sz = 0;
    unsigned short type = htons(ETH_P_1905);
	dm_radio_t *radio, *pradio;

	radio = get_radio_from_dm();
	pradio = get_radio_from_dm(true);

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

	// RDK proprietary tlv for radio enable/disable
	tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_rdk_radio_enable;
	
	if (pradio != NULL) {
    	memcpy(tlv->value, &pradio->m_radio_info.enabled, sizeof(unsigned char));
		radio->m_radio_info.enabled = pradio->m_radio_info.enabled;
	} else {
    	memcpy(tlv->value, &radio->m_radio_info.enabled, sizeof(unsigned char));
	}

    tlv->len = htons(sizeof(unsigned char));
    
    tmp += (sizeof(em_tlv_t) + sizeof(unsigned char));
    len += (sizeof(em_tlv_t) + sizeof(unsigned char));

    // As many wsc tlv containing M2 as number of BSS
    for (i = 0; i < num_hauls; i++) {
        tlv = (em_tlv_t *)tmp;
        tlv->type = em_tlv_type_wsc;
        sz = create_m2_msg(tlv->value, haul_type[i]);
        tlv->len = htons(sz);

        tmp += (sizeof(em_tlv_t) + sz);
        len += (sizeof(em_tlv_t) + sz);
    }

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

int em_configuration_t::create_autoconfig_wsc_m1_msg(unsigned char *buff, unsigned char *dst)
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

    memcpy(tmp, (unsigned char *)dst, sizeof(mac_address_t));
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

int em_configuration_t::create_autoconfig_resp_msg(unsigned char *buff, em_freq_band_t band, unsigned char *dst)
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

    memcpy(tmp, (unsigned char *)dst, sizeof(mac_address_t));
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
    memcpy(&tlv->value, &band, sizeof(unsigned char));

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
    freq_band = get_band();
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
            m_m2_encrypted_settings_len = sizeof(m_m2_encrypted_settings); //work around
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
    mac_addr_str_t mac_str;
    em_device_info_t    dev_info;
    dm_easy_mesh_t *dm;
    unsigned int db_cfg_type;

    dm = get_data_model();
    db_cfg_type = dm->get_db_cfg_type();
    
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
            dm->set_db_cfg_type(db_cfg_type | db_cfg_type_device_list_update);
        } else if (id == attr_id_model_name) {
            memcpy(dev_info.manufacturer_model, attr->val, htons(attr->len));
            set_manufacturer_model(dev_info.manufacturer_model);
            dm->set_db_cfg_type(db_cfg_type | db_cfg_type_device_list_update);
            //printf("%s:%d: Manufacturer Model:%s\n", __func__, __LINE__, dev_info.manufacturer_model);
        } else if (id == attr_id_model_number) {
        } else if (id == attr_id_serial_num) {
            memcpy(dev_info.serial_number, attr->val, htons(attr->len));
            set_serial_number(dev_info.serial_number);
            //printf("%s:%d: Manufacturer:%s\n", __func__, __LINE__, dev_info.serial_number);
            dm->set_db_cfg_type(db_cfg_type | db_cfg_type_device_list_update);
        } else if (id == attr_id_primary_device_type) {
        } else if (id == attr_id_device_name) {
        } else if (id == attr_id_rf_bands) {
            set_band((em_freq_band_t)attr->val[0]);
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
    dm_easy_mesh_t *dm;
    dm_network_t network;
    em_raw_hdr_t *hdr = (em_raw_hdr_t *)buff;

    if (em_msg_t(em_msg_type_autoconf_wsc, m_peer_profile, buff, len).validate(errors) == 0) {
        printf("%s:%d: received wsc m2 msg failed validation\n", __func__, __LINE__);

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
    char ssid[32] = {0};
    char pass[64] = {0};
    mac_addr_str_t mac_str;
    unsigned char *plain;
    unsigned short plain_len;
    unsigned short authtype;
    unsigned int index = 0;
    m2ctrl_vapconfig *vapconfig;
    em_event_t  ev;
    em_bus_event_t *bev;
    plain = m_m2_encrypted_settings + AES_BLOCK_SIZE;
    plain_len = m_m2_encrypted_settings_len - AES_BLOCK_SIZE;
    //ev = (em_event_t *)malloc(sizeof(em_event_t));
    memset(&ev,0,sizeof(em_event_t));
    // first decrypt the encrypted m2 data

    if (em_crypto_t::platform_aes_128_cbc_decrypt(m_key_wrap_key, m_m2_encrypted_settings, plain, plain_len) != 1) {
        printf("%s:%d: platform decrypt failed\n", __func__, __LINE__);
        return 0;
    }

    ev.type = em_event_type_bus;
    bev = &ev.u.bevt;
    bev->type = em_bus_event_type_m2ctrl_configuration;
    vapconfig = (m2ctrl_vapconfig *)&bev->u.raw_buff;
    attr = (data_elem_attr_t *)plain;
    tmp_len = plain_len;
	memcpy(vapconfig->mac, get_radio_interface_mac(), sizeof(mac_address_t));
    vapconfig->freq = get_band();

    while (tmp_len > 0) {

        id = htons(attr->id);

        if (id == attr_id_ssid) {
            memcpy(ssid, attr->val, htons(attr->len));
            memcpy(vapconfig->ssid, attr->val, htons(attr->len));
            vapconfig->enable = true;
            printf("%s:%d: ssid attrib: %s\n", __func__, __LINE__, ssid);
        } else if (id == attr_id_auth_type) {
            printf("%s:%d: auth type attrib\n", __func__, __LINE__);
            authtype = attr->val[0];
            vapconfig->authtype = attr->val[0];
        } else if (id == attr_id_encryption_type) {
            printf("%s:%d: encr type attrib\n", __func__, __LINE__);
        } else if (id == attr_id_network_key) {
            memcpy(pass, attr->val, htons(attr->len));
            memcpy(vapconfig->password, attr->val, htons(attr->len));
            printf("%s:%d: network key attrib: %s\n", __func__, __LINE__, pass);
        } else if (id == attr_id_mac_address) {
            dm_easy_mesh_t::macbytes_to_string(attr->val, mac_str);
            printf("%s:%d: mac address attrib: %s\n", __func__, __LINE__, mac_str);
            memcpy(vapconfig->mac, attr->val, sizeof(mac_address_t));
        } else if (id == attr_id_key_wrap_authenticator) {
            printf("%s:%d: key wrap auth attrib\n", __func__, __LINE__);
            vapconfig->key_wrap_authenticator = attr->val[0];
        }

        tmp_len -= (sizeof(data_elem_attr_t) + htons(attr->len));
        attr = (data_elem_attr_t *)((unsigned char *)attr + sizeof(data_elem_attr_t) + htons(attr->len));
    }

    printf("%s:%d Recived new config ssid=%s mode=%d pass=%s \n", __func__, __LINE__,vapconfig->ssid,vapconfig->authtype,vapconfig->password);
    em_cmd_exec_t::send_cmd(em_service_type_agent, (unsigned char *)&ev, sizeof(em_event_t));
    set_state(em_state_agent_owconfig_pending);
    return ret;
}

unsigned int em_configuration_t::create_encrypted_settings(unsigned char *buff, em_haul_type_t haul_type)
{
    data_elem_attr_t *attr;
    short len = 0;
    unsigned char *tmp;
    unsigned int size = 0, cipher_len, plain_len;
    unsigned char iv[AES_BLOCK_SIZE];
    unsigned char plain[MAX_EM_BUFF_SZ];
    unsigned short auth_type = 0x0010;
    em_network_ssid_info_t *net_ssid_info;


    if ((net_ssid_info = get_network_ssid_info_by_haul_type(haul_type)) == NULL) {
        printf("%s:%d: Could not find network ssid information for haul type\n", __func__, __LINE__);
        return -1;
    }
    printf("%s:%d: ssid: %s, passphrase: %s\n", __func__, __LINE__, net_ssid_info->ssid, net_ssid_info->pass_phrase);

    memset(plain, 0, MAX_EM_BUFF_SZ);
    tmp = plain;
    len = 0;

    // ssid
    attr = (data_elem_attr_t *)tmp;
    attr->id = htons(attr_id_ssid);
    size = strlen(net_ssid_info->ssid) + 1;
    attr->len = htons(size);
    snprintf((char *)attr->val, size, "%s", net_ssid_info->ssid);

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
    size = strlen(net_ssid_info->pass_phrase) + 1;
    attr->len = htons(size);
    snprintf((char *)attr->val, size, "%s", net_ssid_info->pass_phrase);

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

    if (em_crypto_t::generate_iv(iv, AES_BLOCK_SIZE) != 1) {
        printf("%s:%d: iv generate failed\n", __func__, __LINE__);
        return 0;
    }

    memcpy(buff, iv, AES_BLOCK_SIZE);

    plain_len = len + (AES_BLOCK_SIZE - len%AES_BLOCK_SIZE);
    
    // encrypt the m2 data
    if (em_crypto_t::platform_aes_128_cbc_encrypt(m_key_wrap_key, iv, plain, plain_len, buff + AES_BLOCK_SIZE, &cipher_len) != 1) {
        printf("%s:%d: platform encrypt failed\n", __func__, __LINE__);
        return 0;
    }

    return cipher_len + AES_BLOCK_SIZE;
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

int em_configuration_t::handle_ap_radio_advanced_cap(unsigned char *buff, unsigned int len)
{
    dm_easy_mesh_t *dm;
    dm = get_data_model();

    return 0;
}
int em_configuration_t::handle_ap_radio_basic_cap(unsigned char *buff, unsigned int len)
{
	dm_radio_t * radio;
	em_radio_id_t	ruid;
	unsigned int i, j;
	em_radio_info_t *radio_info;
	bool radio_exists = false;
	bool op_class_exists = false;
	mac_addr_str_t mac_str;
	em_ap_radio_basic_cap_t		*radio_basic_cap = (em_ap_radio_basic_cap_t *)buff;
	em_op_class_t *basic_cap_op_class;
	em_op_class_info_t	op_class_info;
	dm_op_class_t *op_class_obj;
	unsigned int db_cfg_type;

	dm_easy_mesh_t *dm = get_data_model();

	memcpy(ruid, radio_basic_cap->ruid, sizeof(em_radio_id_t));
	dm_easy_mesh_t::macbytes_to_string(ruid, mac_str);
	for (i = 0; i < dm->get_num_radios(); i++) {
		radio = dm->get_radio(i);
		if (memcmp(radio->m_radio_info.id.mac, ruid, sizeof(mac_address_t)) == 0) {
			radio_exists = true;
			break;
		}
	}
	if (radio_exists == false) {
		printf("%s:%d: Radio does not exist, getting radio at index: %d\n", __func__, __LINE__, dm->get_num_radios());
		radio = dm->get_radio(dm->get_num_radios());
		dm->set_num_radios(dm->get_num_radios() + 1);
	}

	radio_info = &radio->m_radio_info;
	memcpy(radio_info->id.mac, ruid, sizeof(mac_address_t));
	radio_info->enabled = true;
	radio_info->number_of_bss = radio_basic_cap->num_bss;
	db_cfg_type = dm->get_db_cfg_type();
	dm->set_db_cfg_type(db_cfg_type | db_cfg_type_radio_list_update);

	basic_cap_op_class = radio_basic_cap->op_classes;
	if (basic_cap_op_class != NULL) {
		for (i = 0; i < radio_basic_cap->op_class_num; i++) {
			memset(&op_class_info, 0, sizeof(em_op_class_info_t));
			memcpy(op_class_info.id.ruid, ruid, sizeof(mac_address_t));
			op_class_info.id.type = em_op_class_type_capability;
			op_class_info.op_class = (unsigned int)basic_cap_op_class->op_class;
			op_class_info.id.op_class = op_class_info.op_class;
			op_class_info.max_tx_power = (int)basic_cap_op_class->max_tx_eirp;
			op_class_info.num_channels = (unsigned int)basic_cap_op_class->num;
			for (j = 0; j < op_class_info.num_channels; j++) {
				op_class_info.channels[j] = (unsigned int )basic_cap_op_class->channels.channel[j];
			}
			basic_cap_op_class = (em_op_class_t *)((unsigned char *)basic_cap_op_class + sizeof(em_op_class_t) + op_class_info.num_channels);
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
			db_cfg_type = dm->get_db_cfg_type();
			dm->set_db_cfg_type(db_cfg_type | db_cfg_type_op_class_list_update);
		}
	} else {
		printf("%s:%d basic_cap_op_class is NULL \n", __func__, __LINE__);
	}

	return 0;
}

int em_configuration_t::handle_autoconfig_wsc_m1(unsigned char *buff, unsigned int len)
{
    unsigned char msg[MAX_EM_BUFF_SZ];
    unsigned int sz;
    char *errors[EM_MAX_TLV_MEMBERS] = {0};
    mac_addr_str_t  mac_str;
    em_tlv_t    *tlv;
    int tlv_len;
    //dm_easy_mesh_t *dm;
    //dm_device_t *dev;
    em_event_t  ev;
    em_bus_event_t *bev;
    em_bus_event_type_m2_tx_params_t    *raw;
    em_haul_type_t haul_type[1];

    //dm = get_data_model();
    dm_easy_mesh_t::macbytes_to_string(get_peer_mac(), mac_str);
    printf("%s:%d: Device AL MAC: %s\n", __func__, __LINE__, mac_str);

    if (em_msg_t(em_msg_type_autoconf_wsc, m_peer_profile, buff, len).validate(errors) == 0) {
        printf("%s:%d: received autoconfig wsc m1 msg failed validation\n", __func__, __LINE__);

        //return -1;
    }

    tlv = (em_tlv_t *)(buff + sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t)); 
    tlv_len = len - (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));

    while ((tlv->type != em_tlv_type_eom) && (len > 0)) {
        if (tlv->type == em_tlv_type_ap_radio_basic_cap) {
            handle_ap_radio_basic_cap(tlv->value, htons(tlv->len));
        } else if (tlv->type == em_tlv_type_wsc) {
            handle_wsc_m1(tlv->value, htons(tlv->len));
        } else if (tlv->type == em_tlv_type_profile_2_ap_cap) {
        } else if (tlv->type == em_tlv_type_ap_radio_advanced_cap) {
            handle_ap_radio_advanced_cap(tlv->value, htons(tlv->len));
        }

        tlv_len -= (sizeof(em_tlv_t) + htons(tlv->len));
        tlv = (em_tlv_t *)((unsigned char *)tlv + sizeof(em_tlv_t) + htons(tlv->len));
    }

    haul_type[0] = em_haul_type_fronthaul;
    sz = create_autoconfig_wsc_m2_msg(msg, haul_type, 1);

    if (em_msg_t(em_msg_type_autoconf_wsc, em_profile_type_3, msg, sz).validate(errors) == 0) {
        printf("Autoconfig wsc m2 msg failed validation in tnx end\n");

        return -1;
    }

    if (send_frame(msg, sz)  < 0) {
        printf("%s:%d: autoconfig wsc m2 send failed, error:%d\n", __func__, __LINE__, errno);
        return -1;
    }

    ev.type = em_event_type_bus;
    bev = &ev.u.bevt;
    bev->type = em_bus_event_type_m2_tx;
    raw = (em_bus_event_type_m2_tx_params_t *)bev->u.raw_buff;
    memcpy(raw->al, (unsigned char *)get_peer_mac(), sizeof(mac_address_t));
    memcpy(raw->radio, get_radio_interface_mac(), sizeof(mac_address_t));

    em_cmd_exec_t::send_cmd(em_service_type_ctrl, (unsigned char *)&ev, sizeof(em_event_t));
    set_state(em_state_ctrl_wsc_m2_sent);

    return 0;
}

int em_configuration_t::handle_autoconfig_resp(unsigned char *buff, unsigned int len)
{
    unsigned char msg[MAX_EM_BUFF_SZ];
    unsigned int sz;
    char *errors[EM_MAX_TLV_MEMBERS] = {0};
    em_raw_hdr_t *hdr = (em_raw_hdr_t *)buff;

    if (em_msg_t(buff + (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t)),
                len - (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t))).get_profile_type(&m_peer_profile) == false) {
        printf("%s:%d: Could not get peer profile type\n", __func__, __LINE__);
        return -1;
    }

    if (em_msg_t(em_msg_type_autoconf_resp, m_peer_profile, buff, len).validate(errors) == 0) {
        printf("received autoconfig resp msg failed validation\n");

        return -1;
    }
    printf("Received resp and validated...creating M1 msg\n");
    sz = create_autoconfig_wsc_m1_msg(msg, hdr->src);

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

    em_device_info_t *dev_info;
    em_freq_band_t  band;
    mac_address_t al_mac;

    if (em_msg_t(em_msg_type_autoconf_search, em_profile_type_3, buff, len).validate(errors) == 0) {
        printf("received autoconfig search msg failed validation\n");
    
        return -1;
    }
    if (em_msg_t(buff + (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t)),
                len - (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t))).get_profile_type(&m_peer_profile) == false) {
        printf("%s:%d: Could not get peer profile type\n", __func__, __LINE__);
    } else {
        m_peer_profile = em_profile_type_1;
    }

    if (em_msg_t(buff + (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t)), len - (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t))).get_freq_band(&band) == false) {
        printf("%s:%d: Could not get peer profile type\n", __func__, __LINE__);
        return -1;
    }

    if (em_msg_t(buff + (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t)), len - (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t))).get_al_mac_address(al_mac) == false) {
        printf("%s:%d: Could not get peer profile type\n", __func__, __LINE__);
        return -1;
    }
    
    sz = create_autoconfig_resp_msg(msg, band, al_mac);
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
    em_tlv_t *tlv;
    em_raw_hdr_t *hdr;
    char* errors[EM_MAX_TLV_MEMBERS];
    em_bus_event_t *bevt;
    em_event_t evt;
    em_bus_event_type_cfg_renew_params_t *raw;

    if (em_msg_t(em_msg_type_autoconf_renew, em_profile_type_2, buff, len).validate(errors) == 0) {

        printf("autoconfig renew validation failed\n");
        return -1;

    }

    hdr = (em_raw_hdr_t *)buff;

    evt.type = em_event_type_bus;
    bevt = &evt.u.bevt;
    bevt->type = em_bus_event_type_cfg_renew;
    raw = (em_bus_event_type_cfg_renew_params_t *)bevt->u.raw_buff;
    memcpy(raw->radio, get_radio_interface_mac(), sizeof(mac_address_t));
    memcpy(raw->ctrl_src, hdr->src, sizeof(mac_address_t));
    em_cmd_exec_t::send_cmd(em_service_type_agent, (unsigned char *)&evt, sizeof(em_event_t));

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
            if ((get_service_type() == em_service_type_ctrl) && (get_state() == em_state_ctrl_ap_mld_config_pending)) {
                send_ap_mld_config_req_msg(data);
            }
            break;

        case em_msg_type_ap_mld_config_resp:
            if ((get_service_type() == em_service_type_ctrl) && (get_state() == em_state_ctrl_ap_mld_configured)) {
                send_ap_mld_config_resp_msg(data);
            }
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
    sz = create_autoconfig_wsc_m1_msg(msg, ctrl_src);

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

        case em_state_ctrl_wsc_m1_pending:
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
    switch (get_state()) {
        case em_state_ctrl_misconfigured:
            send_autoconfig_renew_msg();
            break;

        case em_state_ctrl_topo_sync_pending:
            send_topology_query_msg();
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

