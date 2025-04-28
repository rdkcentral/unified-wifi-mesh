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
#include <signal.h>
#include <unistd.h>
#include <stdexcept>
#include <arpa/inet.h>
#include "em_msg.h"
//#include "util.h"
#include "em_configuration.h"

bool em_msg_t::get_tlv(em_tlv_t *itlv)
{
    em_tlv_t    *tlv;
    unsigned int len;

    tlv = reinterpret_cast<em_tlv_t *> (m_buff); len = m_len;
    while ((tlv->type != em_tlv_type_eom) && (len > 0)) {
        if (tlv->type == itlv->type) {
            memcpy(itlv->value, tlv->value, htons(tlv->len));
            return true;
        }
        len -= static_cast<unsigned int> (sizeof(em_tlv_t) + htons(tlv->len));
        tlv = reinterpret_cast<em_tlv_t *> (reinterpret_cast<unsigned char *> (tlv) + sizeof(em_tlv_t) + htons(tlv->len));
    }

    return false;
}

bool em_msg_t::get_client_mac_info(mac_address_t *mac)
{
    em_tlv_t    *tlv;
    unsigned int len;
    em_client_info_t *cltinfo;

    tlv = reinterpret_cast<em_tlv_t *> (m_buff); len = m_len;
    while ((tlv->type != em_tlv_type_eom) && (len > 0)) {
        if (tlv->type == em_tlv_type_client_info) {
            cltinfo = reinterpret_cast<em_client_info_t *> (tlv->value);
            memcpy(mac, &cltinfo->client_mac_addr, sizeof(mac_address_t));
            return true;
        }
    }
    return false;
}

bool em_msg_t::get_al_mac_address(unsigned char *mac)
{
    em_tlv_t    *tlv;
    unsigned int len;

    tlv = reinterpret_cast<em_tlv_t *> (m_buff); len = m_len;
    while ((tlv->type != em_tlv_type_eom) && (len > 0)) {
        if (tlv->type == em_tlv_type_al_mac_address) {
            memcpy(mac, tlv->value, htons(tlv->len));
            return true;
        }
        len -= static_cast<unsigned int> (sizeof(em_tlv_t) + htons(tlv->len));
        tlv = reinterpret_cast<em_tlv_t *> (reinterpret_cast<unsigned char *> (tlv) + sizeof(em_tlv_t) + htons(tlv->len));
    }

    return false;
}

bool em_msg_t::get_profile(em_profile_type_t *profile)
{
    em_tlv_t    *tlv;
    unsigned int len;

    tlv = reinterpret_cast<em_tlv_t *> (m_buff); len = m_len;
    while ((tlv->type != em_tlv_type_eom) && (len > 0)) {
        if (tlv->type == em_tlv_type_profile) {
            memcpy(profile, tlv->value, htons(tlv->len));
            return true;
        }

        len -= static_cast<unsigned int> (sizeof(em_tlv_t) + htons(tlv->len));
        tlv = reinterpret_cast<em_tlv_t *> (reinterpret_cast<unsigned char *> (tlv) + sizeof(em_tlv_t) + htons(tlv->len));
    }

    return false;
}

bool em_msg_t::get_bss_id(mac_address_t *mac)
{
    em_tlv_t    *tlv;
    unsigned int len;

    tlv = reinterpret_cast<em_tlv_t *> (m_buff); len = m_len;
    while ((tlv->type != em_tlv_type_eom) && (len > 0)) {
        if (tlv->type == em_tlv_type_client_info) {
            memcpy(mac, tlv->value, sizeof(mac_address_t));
            return true;
        } else if (tlv->type == em_tlv_type_client_assoc_event) {
            memcpy(mac, tlv->value + sizeof(mac_address_t), sizeof(mac_address_t));
            return true;
        } else if (tlv->type == em_tlv_type_client_info) {
            memcpy(mac, tlv->value + sizeof(mac_address_t), sizeof(mac_address_t));
            return true;
        }

        len -= static_cast<unsigned int> (sizeof(em_tlv_t) + htons(tlv->len));
        tlv = reinterpret_cast<em_tlv_t *> (reinterpret_cast<unsigned char *> (tlv) + sizeof(em_tlv_t) + htons(tlv->len));
    }

    return false;
}

bool em_msg_t::get_radio_id(mac_address_t *mac)
{
    em_tlv_t    *tlv;
    unsigned int len;
	unsigned int num_radios = 0;
    em_ap_radio_basic_cap_t *rd_basic_cap;
    em_ap_radio_advanced_cap_t  *rd_adv_cap;
    em_ap_ht_cap_t *rd_ht_cap;
    em_ap_vht_cap_t *rd_vht_cap;
    em_ap_he_cap_t *rd_he_cap;
    em_ap_op_bss_t  *ap;
    
	em_ap_op_bss_radio_t    *radio;

    tlv = reinterpret_cast<em_tlv_t *> (m_buff); len = m_len;
    while ((tlv->type != em_tlv_type_eom) && (len > 0)) {
        if (tlv->type == em_tlv_type_radio_id) {
            memcpy(mac, tlv->value, sizeof(mac_address_t));
            return true;    
        } else if (tlv->type == em_tlv_type_ap_radio_basic_cap) {
            rd_basic_cap = reinterpret_cast<em_ap_radio_basic_cap_t *> (tlv->value);
            memcpy(mac, &rd_basic_cap->ruid, sizeof(mac_address_t));
            return true;    
        } else if (tlv->type == em_tlv_type_ap_radio_advanced_cap) {
            rd_adv_cap = reinterpret_cast<em_ap_radio_advanced_cap_t *> (tlv->value);
            memcpy(mac, &rd_adv_cap->ruid, sizeof(mac_address_t));
            return true;    

        } else if (tlv->type == em_tlv_type_ht_cap) {
            rd_ht_cap = reinterpret_cast<em_ap_ht_cap_t *> (tlv->value);
            memcpy(mac, &rd_ht_cap->ruid, sizeof(mac_address_t));
            return true;
        } else if (tlv->type == em_tlv_type_vht_cap) {
            rd_vht_cap = reinterpret_cast<em_ap_vht_cap_t *>(tlv->value);
            memcpy(mac, &rd_vht_cap->ruid, sizeof(mac_address_t));
            return true;
        } else if (tlv->type == em_tlv_type_he_cap) {
            rd_he_cap = reinterpret_cast<em_ap_he_cap_t *> (tlv->value);
            memcpy(mac, &rd_he_cap->ruid, sizeof(mac_address_t));
            return true;
        } else if (tlv->type == em_tlv_type_operational_bss) {
			ap = reinterpret_cast<em_ap_op_bss_t *> (tlv->value);
			if (ap->radios_num >= 1) {
				radio = ap->radios;
				memcpy(mac, &radio->ruid, sizeof(mac_address_t));
				return true;	
			} 
        } else if (tlv->type == em_tlv_type_channel_pref) {
			memcpy(mac, tlv->value, sizeof(mac_address_t));
			return true;	
		} else if (tlv->type == em_tlv_type_channel_sel_resp) {
			memcpy(mac, tlv->value, sizeof(mac_address_t));
			return true;
		} else if (tlv->type == em_tlv_type_op_channel_report) {
			memcpy(mac, tlv->value, sizeof(mac_address_t));
			return true;
		} else if (tlv->type == em_tlv_type_channel_scan_req) {
			memcpy(&num_radios, tlv->value + sizeof(unsigned char), sizeof(unsigned char));
			if (num_radios != 0) {
				memcpy(mac, tlv->value + 2*sizeof(unsigned char), sizeof(mac_address_t));
				return true;
			} else {
				return false;
			}
		} else if (tlv->type == em_tlv_type_channel_scan_rslt) {
			memcpy(mac, tlv->value, sizeof(mac_address_t));
            return true;
		}

        len -= static_cast<unsigned int> (sizeof(em_tlv_t) + htons(tlv->len));
        tlv = reinterpret_cast<em_tlv_t *> (reinterpret_cast<unsigned char *> (tlv) + sizeof(em_tlv_t) + htons(tlv->len));
    }

    return false;
}

bool em_msg_t::get_freq_band(em_freq_band_t *band)
{
    em_tlv_t    *tlv;
    unsigned int len;

    tlv = reinterpret_cast<em_tlv_t *> (m_buff); len = m_len;
    while ((tlv->type != em_tlv_type_eom) && (len > 0)) {
        if ((tlv->type == em_tlv_type_supported_freq_band) || (tlv->type == em_tlv_type_autoconf_freq_band)) {
            memcpy(reinterpret_cast<unsigned char *> (band), tlv->value, sizeof(unsigned char));
            return true;
        }
        len -= static_cast<unsigned int> (sizeof(em_tlv_t) + htons(tlv->len));
        tlv = reinterpret_cast<em_tlv_t *> (reinterpret_cast<unsigned char *> (tlv) + sizeof(em_tlv_t) + htons(tlv->len));
    }

    return false;

}

bool em_msg_t::get_profile_type(em_profile_type_t *profile)
{
    em_tlv_t    *tlv;
    unsigned int len;

    *profile = em_profile_type_reserved;
    tlv = reinterpret_cast<em_tlv_t *> (m_buff); len = m_len;
    while ((tlv->type != em_tlv_type_eom) && (len > 0)) {
        if (tlv->type == em_tlv_type_profile) {
            memcpy(reinterpret_cast<unsigned char *> (profile), tlv->value, htons(tlv->len));
            return true;
        }
        len -= static_cast<unsigned int> (sizeof(em_tlv_t) + htons(tlv->len));
        tlv = reinterpret_cast<em_tlv_t *> (reinterpret_cast<unsigned char *> (tlv) + sizeof(em_tlv_t) + htons(tlv->len));
    }

    return false;
}

em_tlv_t *em_msg_t::get_tlv(em_tlv_type_t type)
{
    em_tlv_t    *tlv;
    unsigned int len;

    tlv = reinterpret_cast<em_tlv_t *> (m_buff); len = m_len;
    while ((tlv->type != em_tlv_type_eom) && (len > 0)) {
        if (tlv->type == type) {
            return tlv; 
        }
        len -= static_cast<unsigned int> (sizeof(em_tlv_t) + ntohs(tlv->len));
        tlv = reinterpret_cast<em_tlv_t *> (reinterpret_cast<unsigned char *> (tlv) + sizeof(em_tlv_t) + ntohs(tlv->len));
    }

    return NULL;
}

unsigned char* em_msg_t::add_buff_element(unsigned char *buff, unsigned int *len, unsigned char *element, unsigned int element_len)
{
    memcpy(buff, element, element_len);
    *len += element_len;
    return buff + element_len;
}

unsigned char* em_msg_t::add_tlv(unsigned char *buff, unsigned int *len, em_tlv_type_t tlv_type, 
                                            unsigned char *value, unsigned int value_len)
{
    em_tlv_t* tlv = reinterpret_cast<em_tlv_t *> (buff);
    tlv->type = tlv_type;
    tlv->len = (htons(static_cast<short unsigned int>(value_len)));
    if (value_len > 0) {
        memcpy(tlv->value, value, value_len);
    }

    *len += static_cast<unsigned int> (sizeof(em_tlv_t) + value_len);
    return buff + (sizeof(em_tlv_t) + value_len);
    
}
unsigned char* em_msg_t::add_1905_header(unsigned char *buff, unsigned int *len, mac_addr_t dst, mac_addr_t src, em_msg_type_t msg_type)
{

    uint16_t type = htons(ETH_P_1905);
    uint16_t  msg_id = msg_type;

    unsigned char* tmp = buff;
    tmp = em_msg_t::add_buff_element(tmp, len, reinterpret_cast<uint8_t *>(dst), sizeof(mac_address_t));
    tmp = em_msg_t::add_buff_element(tmp, len, reinterpret_cast<uint8_t *>(src), sizeof(mac_address_t));
    tmp = em_msg_t::add_buff_element(tmp, len, reinterpret_cast<uint8_t *> (&type), sizeof(uint16_t));

    em_cmdu_t cmdu = {
        .ver = 0,
        .reserved = 0,
        .type = htons(msg_id),
        .id = htons(msg_id),
        .frag_id = 0,
        .reserved_field = 0,
        .relay_ind = 0,
        .last_frag_ind = 1
    };

    return em_msg_t::add_buff_element(tmp, len, reinterpret_cast<uint8_t *> (&cmdu), sizeof(em_cmdu_t));
}
unsigned int em_msg_t::validate(char *errors[])
{
    em_tlv_t *tlv;
    unsigned int i, len;
    bool validation = true;

    for (i = 0; i < m_num_tlv; i++) {
        tlv =  reinterpret_cast<em_tlv_t *> (m_buff + sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));
        len = m_len - static_cast<unsigned int> (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));

        while ((tlv->type != em_tlv_type_eom) && (len > 0)) {
            if (tlv->type == m_tlv_member[i].m_type) {
                m_tlv_member[i].m_present = true;
                break;
            }
            len -= static_cast<unsigned int> (sizeof(em_tlv_t) + htons(tlv->len));
            tlv = reinterpret_cast<em_tlv_t *> ((reinterpret_cast<unsigned char *>(tlv) + sizeof(em_tlv_t) + htons(tlv->len)));
        }

        if ((m_tlv_member[i].m_requirement == mandatory) &&((m_tlv_member[i].m_present == false)||((sizeof(em_tlv_t) + htons(tlv->len)) < static_cast<size_t> (m_tlv_member[i].m_tlv_length)))) {
            strncpy(m_errors[m_num_errors], m_tlv_member[i].m_spec, sizeof(m_errors[m_num_errors]) - 1);
            m_errors[m_num_errors][sizeof(m_errors[m_num_errors]) - 1] = '\0';
            m_num_errors++;
            errors[m_num_errors - 1] = m_errors[m_num_errors - 1];
            validation = false;
            if (m_tlv_member[i].m_present == false) { 
                //printf("%s:%d; TLV not present\n", __func__, __LINE__);
            }   

            if (((sizeof(em_tlv_t) + htons(tlv->len)) < static_cast<size_t> (m_tlv_member[i].m_tlv_length))) {
                //printf("%s:%d; TLV type: 0x%04x Length: %d, length validation error\n", __func__, __LINE__, tlv->type, htons(tlv->len));
            }
        }

        if ((m_tlv_member[i].m_requirement == bad) && (m_tlv_member[i].m_present == true)) {
            strncpy(m_errors[m_num_errors], m_tlv_member[i].m_spec, sizeof(m_errors[m_num_errors]) - 1);
            m_errors[m_num_errors][sizeof(m_errors[m_num_errors]) - 1] = '\0';
            m_num_errors++;
            errors[m_num_errors - 1] = m_errors[m_num_errors - 1];
            //printf("%s:%d; TLV type: 0x%04x Length: %d, presence validation error, profile: %d\n", __func__, __LINE__, 
            //tlv->type, htons(tlv->len), m_profile);
            validation = false;
        }
    }

    if (validation == false) {
        for (i = 0; i < EM_MAX_TLV_MEMBERS; i++) {
            if (errors[i] != NULL) {
                printf("Failed TLV [%d]: %s\n",(i+1),errors[i]);
            }
        }
    }

    return validation;
}


void em_msg_t::autoconfig_search()
{
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_al_mac_address, mandatory, "table 6-8 of IEEE-1905-1", 9);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_searched_role, mandatory, "table 6-22 of IEEE-1905-1", 4);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_autoconf_freq_band, mandatory, "table 6-23 of IEEE-1905-1", 4);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_supported_service, optional, "17.2.1 of Wi-Fi Easy Mesh 5.0", 5);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_searched_service, optional, "17.2.2 of Wi-Fi Easy Mesh 5.0", 5);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_profile, (m_profile > em_profile_type_1) ? mandatory:bad, "17.2.47 of Wi-Fi Easy Mesh 5.0", 4);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_dpp_chirp_value, (m_profile > em_profile_type_2) ? optional:bad, "17.2.83 of Wi-Fi Easy Mesh 5.0", 4); 
}

void em_msg_t::autoconfig_resp()
{
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_supported_role, mandatory, "table 6-24 of IEEE-1905-1", 4);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_supported_freq_band, mandatory, "table 6-25 of IEEE-1905-1", 4);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_1905_layer_security_cap, (m_profile > em_profile_type_2) ? mandatory:bad, "17.2.67 of Wi-Fi Easy Mesh 5.0", 6);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_supported_service, optional, "17.2.1 of Wi-Fi Easy Mesh 5.0", 5);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_profile, (m_profile > em_profile_type_1) ? mandatory:bad, "17.2.47 of Wi-Fi Easy Mesh 5.0", 4);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_dpp_chirp_value, (m_profile > em_profile_type_2) ? optional:bad, "17.2.83 of Wi-Fi Easy Mesh 5.0", 4);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_ctrl_cap, optional, "17.2.94 of Wi-Fi Easy Mesh 5.0", 3);

}
void em_msg_t::autoconfig_wsc_m1() //M1 from MAP Agent
{
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_ap_radio_basic_cap, mandatory, "17.2.7 of Wi-Fi Easy Mesh 5.0", 2);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_wsc, mandatory, "table 8 of WSC v2.0.7", 264);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_profile_2_ap_cap, (m_profile > em_profile_type_1) ? mandatory:bad, "17.2.48 of Wi-Fi Easy Mesh 5.0", 2);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_ap_radio_advanced_cap, (m_profile > em_profile_type_1) ? mandatory:bad, "17.2.52 of Wi-Fi Easy Mesh 5.0", 2);


}

void em_msg_t::autoconfig_wsc_m2() //M2 from MAP Controller
{
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_radio_id, mandatory, "17.2.3 of Wi-Fi Easy Mesh 5.0", 4);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_wsc, mandatory, "table 9 of WSC v2.0.7", 264);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_dflt_8021q_settings, (m_profile > em_profile_type_1) ? optional:bad, "17.2.49 of Wi-Fi Easy Mesh 5.0", 2);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_traffic_separation_policy, (m_profile > em_profile_type_1) ? optional:bad, "17.2.50 of Wi-Fi Easy Mesh 5.0", 2);

}

void em_msg_t::topo_disc()
{
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_al_mac_address, mandatory, "table 6-8 of IEEE-1905-1", 9);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_mac_address, mandatory, "table 6-9 of IEEE-1905-1", 9);

}

void em_msg_t::topo_notif()
{
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_al_mac_address, mandatory, "table 6-8 of IEEE-1905-1", 9);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_client_assoc_event, optional, "17.2.20 of Wi-Fi Easy Mesh 5.0", 15); 

}

void em_msg_t::topo_query()
{
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_profile, (m_profile > em_profile_type_1) ? mandatory:bad, "17.2.47 of Wi-Fi Easy Mesh 5.0", 4); 

}

void em_msg_t::topo_resp()
{
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_device_info, mandatory, "table 6-10 of IEEE-1905-1", 19); 
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_operational_bss, mandatory, "17.2.4 of Wi-Fi Easy Mesh 5.0", 18);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_supported_service, optional, "17.2.1 of Wi-Fi Easy Mesh 5.0", 5);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_associated_clients, optional, "17.2.5 of Wi-Fi Easy Mesh 5.0", 20);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_profile, (m_profile > em_profile_type_1) ? mandatory:bad, "17.2.47 of Wi-Fi Easy Mesh 5.0", 4);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_bss_conf_rep, (m_profile > em_profile_type_2) ? mandatory:bad, "17.2.75 of Wi-Fi Easy Mesh 5.0", 17);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_ap_mld_config, optional, "17.2.96 of Wi-Fi Easy Mesh 6.0", 64);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_bsta_mld_config, optional, "17.2.97 of Wi-Fi Easy Mesh 6.0", 64);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_assoc_sta_mld_conf_rep, optional, "17.2.98 of Wi-Fi Easy Mesh 6.0", 64);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_tid_to_link_map_policy, optional, "17.2.97 of Wi-Fi Easy Mesh 6.0", 64);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_device_bridging_cap, optional, "table 6-11 of IEEE-1905-1", 11);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_non1905_neigh_list, optional, "table 6-14 of IEEE-1905-1", 15);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_1905_neigh_list, optional, "table 6-15 of IEEE-1905-1", 15);
}


void em_msg_t::topo_vendor()
{
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_vendor_specific, mandatory, "table 6-7 of IEEE-1905-1", 6); 
}

void em_msg_t::link_metric_query()
{
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_link_metric, mandatory, "table 6-16 of IEEE-1905-1", 11);

}

void em_msg_t::link_metric_resp()
{
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_transmitter_link_metric, optional, "table 6-17 of IEEE-1905-1", 15);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_receiver_link_metric, optional, "table 6-19 of IEEE-1905-1", 15);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_link_metric_result_code, optional, "table 6-21 of IEEE-1905-1", 4);
}

void em_msg_t::autoconfig_renew()
{
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_al_mac_address, mandatory, "table 6-8 of IEEE-1905-1", 9);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_supported_role, mandatory, "table 6-24 of IEEE-1905-1", 4);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_supported_freq_band, mandatory, "table 6-25 of IEEE-1905-1", 4);
}
void em_msg_t::ap_cap_query()
{
    //No TLVs are required in this message
}

void em_msg_t::ap_cap_rprt()
{
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_ap_cap, mandatory, "17.2.6 of Wi-Fi Easy Mesh 5.0", 3);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_ap_radio_basic_cap, mandatory, "17.2.7 of Wi-Fi Easy Mesh 5.0", 15);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_ht_cap, optional, "17.2.8 of Wi-Fi Easy Mesh 5.0", 9);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_vht_cap, optional, "17.2.9 of Wi-Fi Easy Mesh 5.0", 13);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_he_cap, optional, "17.2.10 of Wi-Fi Easy Mesh 5.0", 10);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_ap_wifi6_cap, (m_profile > em_profile_type_2) ? optional:bad, "17.2.72 of Wi-Fi Easy Mesh 5.0", 24);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_channel_scan_cap, (m_profile > em_profile_type_1) ? mandatory:bad, "17.2.38 of Wi-Fi Easy Mesh 5.0", 17);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_1905_layer_security_cap, (m_profile > em_profile_type_2) ? mandatory:bad, "17.2.67 of Wi-Fi Easy Mesh 5.0", 6);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_cac_cap, (m_profile > em_profile_type_1) ? mandatory:bad, "17.2.46 of Wi-Fi Easy Mesh 5.0", 21);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_profile_2_ap_cap, (m_profile > em_profile_type_1) ? mandatory:bad, "17.2.48 of Wi-Fi Easy Mesh 5.0", 6); 
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_metric_cltn_interval, (m_profile > em_profile_type_1) ? mandatory:bad, "17.2.59 of Wi-Fi Easy Mesh 5.0", 7);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_device_inventory, (m_profile > em_profile_type_2) ? mandatory:bad, "17.2.76 of Wi-Fi Easy Mesh 5.0", 270); 
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_ap_radio_advanced_cap, optional, "17.2.52 of Wi-Fi Easy Mesh 5.0", 9);
}

void em_msg_t::policy_config_req()
{
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_steering_policy, optional, "17.2.11 of Wi-Fi Easy Mesh 5.0", 27);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_metric_reporting_policy, optional, "17.2.12 of Wi-Fi Easy Mesh 5.0", 13);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_dflt_8021q_settings, (m_profile > em_profile_type_1) ? optional:bad, "17.2.49 of Wi-Fi Easy Mesh 5.0", 5); 
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_traffic_separation_policy, (m_profile > em_profile_type_1) ? optional:bad, "17.2.50 of Wi-Fi Easy Mesh 5.0", 7);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_channel_scan_rprt_policy, (m_profile > em_profile_type_1) ? optional:bad, "17.2.37 of Wi-Fi Easy Mesh 5.0", 3);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_unsucc_assoc_policy, (m_profile > em_profile_type_1) ? optional:bad, "17.2.58 of Wi-Fi Easy Mesh 5.0", 7);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_backhaul_bss_conf, (m_profile > em_profile_type_1) ? optional:bad, "17.2.66 of Wi-Fi Easy Mesh 5.0", 9); 
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_qos_mgmt_policy, optional, "17.2.92 of Wi-Fi Easy Mesh 5.0", 37);
}

void em_msg_t::channel_pref_query()
{
    //No TLVs are required in this message
}

void em_msg_t::channel_pref_rprt()
{
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_channel_pref, optional, "17.2.13 of Wi-Fi Easy Mesh 5.0", 12);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_radio_op_restriction, optional, "17.2.14 of Wi-Fi Easy Mesh 5.0", 14);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_cac_cmpltn_rprt, (m_profile > em_profile_type_1) ? optional:bad, "17.2.44 of Wi-Fi Easy Mesh 5.0", 16);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_cac_sts_rprt, (m_profile > em_profile_type_1) ? mandatory:bad, "17.2.45 of Wi-Fi Easy Mesh 5.0", 19);
}

void em_msg_t::channel_sel_req()
{
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_channel_pref, optional, "17.2.13 of Wi-Fi Easy Mesh 5.0", 12);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_tx_power, optional, "17.2.15 of Wi-Fi Easy Mesh 5.0", 10);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_spatial_reuse_req, optional, "17.2.89 of Wi-Fi Easy Mesh 5.0", 9);
}

void em_msg_t::channel_sel_rsp()
{
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_channel_sel_resp, mandatory, "17.2.16 of Wi-Fi Easy Mesh 5.0", 10);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_spatial_reuse_cfg_rsp, optional, "17.2.91 of Wi-Fi Easy Mesh 5.0", 10);
}
void em_msg_t::op_channel_rprt()
{
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_op_channel_report, mandatory, "17.2.17 of Wi-Fi Easy Mesh 5.0", 13);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_spatial_reuse_rep, optional, "17.2.90 of Wi-Fi Easy Mesh 5.0", 38);
}
void em_msg_t::client_cap_query()
{
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_client_info, mandatory, "17.2.18 of Wi-Fi Easy Mesh 5.0", 15);
}


void em_msg_t::client_steering_req()
{
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_steering_request, (m_profile > em_profile_type_1) ? optional:bad, "17.2.29 of Wi-Fi Easy Mesh 5.0", 15); 
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_profile2_steering_request, (m_profile > em_profile_type_1) ? optional:bad, "17.2.57 of Wi-Fi Easy Mesh 5.0", 15); 

}


void em_msg_t::client_steering_btm_rprt()
{
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_steering_btm_rprt, mandatory, "17.2.30 of Wi-Fi Easy Mesh 5.0", 16);
}

void em_msg_t::client_assoc_ctrl_req()
{
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_client_assoc_ctrl_req, mandatory, "17.2.31 of Wi-Fi Easy Mesh 5.0", 19);
}


void em_msg_t::steering_complete()
{
    // No TLVs are required in this message.
}

void em_msg_t::higher_layer_data()
{
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_higher_layer_data, mandatory, "17.2.34 of Wi-Fi Easy Mesh 5.0", 4);
}

void em_msg_t::bh_steering_req()
{
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_bh_steering_req, mandatory, "17.2.32 of Wi-Fi Easy Mesh 5.0", 17);
}

void em_msg_t::bh_steering_rsp()
{
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_error_code, optional, "17.2.36 of Wi-Fi Easy Mesh 5.0", 10);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_bh_steering_rsp, optional, "17.2.33 of Wi-Fi Easy Mesh 5.0", 15);
}

void em_msg_t::client_cap_rprt()
{
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_client_info, mandatory, "17.2.18 of Wi-Fi Easy Mesh 5.0", 15);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_client_cap_report, mandatory, "17.2.19 of Wi-Fi Easy Mesh 5.0", 4);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_error_code, optional, "17.2.36 of Wi-Fi Easy Mesh 5.0", 10);
}

void em_msg_t::ap_metrics_query()
{
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_ap_metrics_query, mandatory, "17.2.21 of Wi-Fi Easy Mesh 5.0", 10);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_radio_id, (m_profile > em_profile_type_1) ? optional:bad, "17.2.3 of Wi-Fi Easy Mesh 5.0", 9);
}

void em_msg_t::ap_metrics_rsp()
{
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_ap_metrics, mandatory, "17.2.22 of Wi-Fi Easy Mesh 5.0", 24);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_ap_ext_metric, (m_profile > em_profile_type_1) ? mandatory:bad, "17.2.61 of Wi-Fi Easy Mesh 5.0", 33);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_radio_metric, (m_profile > em_profile_type_1) ? optional:bad, "17.2.60 of Wi-Fi Easy Mesh 5.0", 13);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_assoc_sta_traffic_sts, optional, "17.2.35 of Wi-Fi Easy Mesh 5.0", 37);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_assoc_sta_link_metric, optional, "17.2.24 of Wi-Fi Easy Mesh 5.0", 29);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_assoc_sta_ext_link_metric, (m_profile > em_profile_type_1) ? optional:bad, "17.2.62 of Wi-Fi Easy Mesh 5.0", 32);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_assoc_wifi6_sta_rprt, (m_profile > em_profile_type_2) ? optional:bad, "17.2.73 of Wi-Fi Easy Mesh 5.0", 12);
}

void em_msg_t::sta_link_metrics_query()
{
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_sta_mac_addr, mandatory, "17.2.23 of Wi-Fi Easy Mesh 5.0", 9);
}

void em_msg_t::sta_link_metrics_rsp()
{
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_assoc_sta_link_metric, mandatory, "17.2.24 of Wi-Fi Easy Mesh 5.0", 29);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_error_code, optional, "17.2.36 of Wi-Fi Easy Mesh 5.0", 10);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_assoc_sta_ext_link_metric, (m_profile > em_profile_type_1) ? mandatory:bad, "17.2.62 of Wi-Fi Easy Mesh 5.0", 32);
}

void em_msg_t::unassoc_sta_link_metrics_query()
{
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_unassoc_sta_link_metric_query, mandatory, "17.2.25 of Wi-Fi Easy Mesh 5.0", 13);
}
void em_msg_t::unassoc_sta_link_metrics_rsp()
{
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_unassoc_sta_link_metric_rsp, mandatory, "17.2.26 of Wi-Fi Easy Mesh 5.0", 11);
}

void em_msg_t::beacon_metrics_query()
{
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_bcon_metric_query, mandatory, "17.2.27 of Wi-Fi Easy Mesh 5.0", 23);

}
void em_msg_t::beacon_metrics_rsp()
{
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_bcon_metric_rsp, mandatory, "17.2.28 of Wi-Fi Easy Mesh 5.0", 11);
}


void em_msg_t::combined_infra_metrics()
{
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_ap_metrics, mandatory, "17.2.22 of Wi-Fi Easy Mesh 5.0", 24);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_transmitter_link_metric, mandatory, "section 6.4.11 of IEEE-1905-1", 50);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_transmitter_link_metric, mandatory, "section 6.4.11 of IEEE-1905-1", 50);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_receiver_link_metric, mandatory, "section 6.4.12 of IEEE-1905-1", 38);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_receiver_link_metric, mandatory, "section 6.4.12 of IEEE-1905-1", 38);
}

void em_msg_t::channel_scan_req()
{
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_channel_scan_req, mandatory, "17.2.39 of Wi-Fi Easy Mesh 5.0", 13);

}

void em_msg_t::qos_mgmt_notif()
{
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_qos_mgmt_desc, mandatory, "17.2.93 of Wi-Fi Easy Mesh 5.0", 17);       
}

void em_msg_t::anticipated_channel_usage_rprt()
{
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_channel_usage, mandatory, "17.2.88 of Wi-Fi Easy Mesh 5.0", 41);       
}

void em_msg_t::anticipated_channel_pref()
{
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_anticipated_channel_pref, mandatory, "17.2.87 of Wi-Fi Easy Mesh 5.0", 8);       
}


void em_msg_t::agent_list()
{
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_agent_list, (m_profile > em_profile_type_2) ? mandatory:bad, "17.2.77 of Wi-Fi Easy Mesh 5.0", 12);       
}

void em_msg_t::failed_conn()
{
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_bssid, (m_profile > em_profile_type_2) ? mandatory:bad, "17.2.74 of Wi-Fi Easy Mesh 5.0", 9);       
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_sta_mac_addr, mandatory, "17.2.23 of Wi-Fi Easy Mesh 5.0", 9);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_status_code, mandatory, "17.2.63 of Wi-Fi Easy Mesh 5.0", 5);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_reason_code, optional, "17.2.64 of Wi-Fi Easy Mesh 5.0", 5);
}

void em_msg_t::dpp_bootstrap_uri_notif()
{
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_dpp_bootstrap_uri_notification, (m_profile > em_profile_type_2) ? mandatory:bad, "17.2.81 of Wi-Fi Easy Mesh 5.0", 21);       
}

void em_msg_t::i1905_encap_eapol()
{
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_1905_encap_eapol, (m_profile > em_profile_type_2) ? mandatory:bad, "17.2.80 of Wi-Fi Easy Mesh 5.0", 3);       
}

void em_msg_t::chirp_notif()
{
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_dpp_chirp_value, (m_profile > em_profile_type_2) ? mandatory:bad, "17.2.83 of Wi-Fi Easy Mesh 5.0", 4);       
}


void em_msg_t::bss_config_res()
{
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_bss_conf_rep, (m_profile > em_profile_type_2) ? mandatory:bad, "17.2.75 of Wi-Fi Easy Mesh 5.0", 17);       
}


void em_msg_t::bss_config_rsp()
{
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_bss_conf_rsp, (m_profile > em_profile_type_2) ? mandatory:bad, "17.2.85 of Wi-Fi Easy Mesh 5.0", 3);     
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_dflt_8021q_settings, optional, "17.2.49 of Wi-Fi Easy Mesh 5.0", 5); 
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_traffic_separation_policy, optional, "17.2.50 of Wi-Fi Easy Mesh 5.0", 7);  
}


void em_msg_t::bss_config_req()
{
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_profile, (m_profile > em_profile_type_2) ? mandatory:bad, "17.2.47 of Wi-Fi Easy Mesh 5.0", 4);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_supported_service, mandatory, "17.2.1 of Wi-Fi Easy Mesh 5.0", 5);      
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_ap_radio_basic_cap, mandatory, "17.2.7 of Wi-Fi Easy Mesh 5.0", 15);       
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_profile_2_ap_cap, mandatory, "17.2.48 of Wi-Fi Easy Mesh 5.0", 7);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_ap_radio_advanced_cap, mandatory, "17.2.52 of Wi-Fi Easy Mesh 5.0", 10);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_bss_conf_req, (m_profile > em_profile_type_2) ? mandatory:bad, "17.2.84 of Wi-Fi Easy Mesh 5.0", 3);     
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_akm_suite, (m_profile > em_profile_type_2) ? mandatory:bad, "17.2.78 of Wi-Fi Easy Mesh 5.0", 5);   
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_bh_sta_radio_cap, optional, "17.2.65 of Wi-Fi Easy Mesh 5.0", 15);  
}

void em_msg_t::channel_scan_rprt()
{
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_timestamp, mandatory, "17.2.41 of Wi-Fi Easy Mesh 5.0", 4);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_channel_scan_rslt, mandatory, "17.2.40 of Wi-Fi Easy Mesh 5.0", 32);
}
void em_msg_t::dpp_cce_ind()
{
    m_tlv_member[m_num_tlv++] = em_tlv_member_t( em_tlv_type_dpp_cce_indication, (m_profile > em_profile_type_2) ? mandatory:bad, "17.2.82 of Wi-Fi Easy Mesh 5.0", 4);
}
void em_msg_t::i1905_rekey_req()
{
    //No TLVs are required in this message.

}
void em_msg_t::i1905_decrypt_fail()
{
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_al_mac_address, (m_profile > em_profile_type_2) ? mandatory:bad, "table 6.4.3 of IEEE 1905.1", 9);
}
void em_msg_t::cac_term()
{
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_cac_term, mandatory, "17.2.43 of Wi-Fi Easy Mesh 5.0", 4);// actual 12
}
void em_msg_t::client_disassoc_stats()
{
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_sta_mac_addr, mandatory, "17.2.23 of Wi-Fi Easy Mesh 5.0", 9);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_reason_code, mandatory, "17.2.64 of Wi-Fi Easy Mesh 5.0", 5);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_assoc_sta_traffic_sts, mandatory, "17.2.35 of Wi-Fi Easy Mesh 5.0", 37);
}
void em_msg_t::svc_prio_req()
{
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_svc_prio_rule, (m_profile > em_profile_type_2) ? optional:bad, "17.2.70 of Wi-Fi Easy Mesh 5.0", 9);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_dscp_map_tbl, (m_profile > em_profile_type_2) ? optional:bad, "17.2.71 of Wi-Fi Easy Mesh 5.0", 67);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_qos_mgmt_desc, optional, "17.2.93 of Wi-Fi Easy Mesh 5.0", 17);
}
void em_msg_t::err_rsp()
{
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_profile_2_error_code, mandatory, "17.2.51 of Wi-Fi Easy Mesh 5.0", 4);
}
void em_msg_t::assoc_status_notif()
{
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_assoc_sts_notif, mandatory, "17.2.53 of Wi-Fi Easy Mesh 5.0", 11);
}
void em_msg_t::tunneled()
{
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_src_info, mandatory, "17.2.54 of Wi-Fi Easy Mesh 5.0", 9);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_tunneled_msg_type, mandatory, "17.2.55 of Wi-Fi Easy Mesh 5.0", 4);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_tunneled, mandatory, "17.2.56 of Wi-Fi Easy Mesh 5.0", 3);
}
void em_msg_t::bh_sta_cap_query()
{
    //No TLVs are required in this message
}
void em_msg_t::bh_sta_cap_rprt()
{
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_bh_sta_radio_cap, optional, "17.2.65 of Wi-Fi Easy Mesh 5.0", 15);
}
void em_msg_t::proxied_encap_dpp()
{
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_1905_encap_dpp, (m_profile > em_profile_type_2) ? mandatory:bad, "17.2.79 of Wi-Fi Easy Mesh 5.0", 12);
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_dpp_chirp_value, (m_profile > em_profile_type_2) ? optional:bad, "17.2.83 of Wi-Fi Easy Mesh 5.0", 4);
}
void em_msg_t::direct_encap_dpp()
{
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_dpp_msg, (m_profile > em_profile_type_2) ? mandatory:bad, "17.2.86 of Wi-Fi Easy Mesh 5.0", 3);
}
void em_msg_t::reconfig_trigger()
{
    //No TLVs are required in this message
}

void em_msg_t::cac_req()
{
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_cac_req, mandatory, "17.2.42 of Wi-Fi Easy Mesh 5.0", 12);
}

void em_msg_t::ap_mld_config_req()
{
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_ap_mld_config, mandatory, "17.2.96 of Wi-Fi Easy Mesh 6.0", 4);
}

void em_msg_t::ap_mld_config_rsp()
{
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_ap_mld_config, mandatory, "17.2.96 of Wi-Fi Easy Mesh 6.0", 4);
}

void em_msg_t::i1905_ack()
{
    m_tlv_member[m_num_tlv++] = em_tlv_member_t(em_tlv_type_error_code, optional, "17.2.36 of Wi-Fi Easy Mesh 5.0", 10);
}


em_msg_t::em_msg_t(em_msg_type_t type, em_profile_type_t profile, unsigned char *tlvs, unsigned int len)
{
    m_type = type;
    m_profile = profile;
    m_num_tlv = 0;
    m_buff  = tlvs;
    m_len = len;
    m_num_errors = 0;   

    switch (type) {
        case em_msg_type_autoconf_search:
            autoconfig_search();
            break;
        case em_msg_type_autoconf_resp:
            autoconfig_resp();
            break;

        case em_msg_type_autoconf_wsc:
            tlvs = tlvs + sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t);
            len = static_cast<unsigned int>(len - (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t)));
            if(em_configuration_t::get_wsc_msg_type(tlvs,len) == em_wsc_msg_type_m1) {
                autoconfig_wsc_m1();
            } else if (em_configuration_t::get_wsc_msg_type(tlvs, len) == em_wsc_msg_type_m2) {
                autoconfig_wsc_m2();
            }

            break;

        case em_msg_type_topo_disc:
            topo_disc();

            break;

        case em_msg_type_topo_notif:
            topo_notif();
            break;

        case em_msg_type_topo_query:
            topo_query();
            break;

        case em_msg_type_topo_resp:
            topo_resp();
            break;

        case em_msg_type_topo_vendor:
            topo_vendor();
            break;

        case em_msg_type_link_metric_query:
            link_metric_query();

            break;

        case em_msg_type_link_metric_resp:
            link_metric_resp();

            break;

        case em_msg_type_autoconf_renew:
            autoconfig_renew();
            break;

        case em_msg_type_ap_cap_query:
            ap_cap_query();
            break;

        case em_msg_type_ap_cap_rprt:
            ap_cap_rprt();
            break;

        case em_msg_type_map_policy_config_req:
            policy_config_req();
            break;

        case em_msg_type_channel_pref_query:
            channel_pref_query();
            break;

        case em_msg_type_channel_pref_rprt:
            channel_pref_rprt();
            break;

        case em_msg_type_channel_sel_req:
            channel_sel_req();
            break;

        case em_msg_type_channel_sel_rsp:
            channel_sel_rsp();
            break;

        case em_msg_type_op_channel_rprt:
            op_channel_rprt();
            break;

        case em_msg_type_client_cap_query:
            client_cap_query();
            break;

        case em_msg_type_client_steering_req:
            client_steering_req();
            break;

        case em_msg_type_client_steering_btm_rprt:
            client_steering_btm_rprt();
            break;


        case em_msg_type_client_assoc_ctrl_req:
            client_assoc_ctrl_req();
            break;

        case em_msg_type_steering_complete:
            steering_complete();
            break;


        case em_msg_type_higher_layer_data:
            higher_layer_data();
            break;


        case em_msg_type_bh_steering_req:
            bh_steering_req();
            break;


        case em_msg_type_bh_steering_rsp:
            bh_steering_rsp();
            break;


        case em_msg_type_client_cap_rprt:
            client_cap_rprt();
            break;

        case em_msg_type_ap_metrics_query:
            ap_metrics_query();
            break;

        case em_msg_type_ap_metrics_rsp:
            ap_metrics_rsp();
            break;

        case em_msg_type_assoc_sta_link_metrics_query:
            sta_link_metrics_query();
            break;

        case em_msg_type_assoc_sta_link_metrics_rsp:
            sta_link_metrics_rsp();
            break;

        case em_msg_type_unassoc_sta_link_metrics_query:
            unassoc_sta_link_metrics_query();
            break;

        case em_msg_type_unassoc_sta_link_metrics_rsp:
            unassoc_sta_link_metrics_rsp();
            break;

        case em_msg_type_beacon_metrics_query:
            beacon_metrics_query();
            break;

        case em_msg_type_beacon_metrics_rsp:
            beacon_metrics_rsp();
            break;

        case em_msg_type_combined_infra_metrics:
            combined_infra_metrics();
            break;


        case em_msg_type_channel_scan_req:
            channel_scan_req();
            break;


        case em_msg_type_qos_mgmt_notif:
            qos_mgmt_notif();
            break;

        case em_msg_type_anticipated_channel_usage_rprt:
            anticipated_channel_usage_rprt();
            break;

        case em_msg_type_anticipated_channel_pref:
            anticipated_channel_pref();
            break;

        case em_msg_type_agent_list:
            agent_list();
            break;

        case em_msg_type_failed_conn:
            failed_conn();
            break;

        case em_msg_type_dpp_bootstrap_uri_notif:
            dpp_bootstrap_uri_notif();
            break;

        case em_msg_type_1905_encap_eapol:
            i1905_encap_eapol();
            break;

        case em_msg_type_chirp_notif:
            chirp_notif();
            break;

        case em_msg_type_bss_config_res:
            bss_config_res();
            break;


        case em_msg_type_bss_config_rsp:
            bss_config_rsp();
            break;

        case em_msg_type_bss_config_req:
            bss_config_req();
            break;


        case em_msg_type_channel_scan_rprt:
            channel_scan_rprt();
            break;

        case em_msg_type_dpp_cce_ind:
            dpp_cce_ind();
            break;

        case em_msg_type_1905_rekey_req:
            i1905_rekey_req();
            break;

        case em_msg_type_1905_decrypt_fail:
            i1905_decrypt_fail();
            break;

        case em_msg_type_cac_term:
            cac_term();
            break;

        case em_msg_type_client_disassoc_stats:
            client_disassoc_stats();
            break;

        case em_msg_type_svc_prio_req:
            svc_prio_req();
            break;

        case em_msg_type_err_rsp:
            err_rsp();
            break;

        case em_msg_type_assoc_status_notif:
            assoc_status_notif();
            break;

        case em_msg_type_tunneled:
            tunneled();
            break;

        case em_msg_type_bh_sta_cap_query:
            bh_sta_cap_query();
            break;

        case em_msg_type_bh_sta_cap_rprt:
            bh_sta_cap_rprt();
            break;

        case em_msg_type_proxied_encap_dpp:
            proxied_encap_dpp();
            break;

        case em_msg_type_direct_encap_dpp:
            direct_encap_dpp();
            break;

        case em_msg_type_reconfig_trigger:
            reconfig_trigger();
            break;

        case em_msg_type_cac_req:
            cac_req();
            break;

        case em_msg_type_ap_mld_config_req:
            ap_mld_config_req();
            break;
        
        case em_msg_type_ap_mld_config_resp:
            ap_mld_config_rsp();
            break;

        case em_msg_type_1905_ack:
            i1905_ack();
            break;

        default: 
            printf("\ninvalid message type\n");
            break;
    }
}

void em_msg_t::set_m1(unsigned char *tlvs, unsigned int len)
{
    m_buff  = tlvs;
    m_len = len;
}

em_msg_t::em_msg_t(unsigned char *tlvs, unsigned int len)
{
    m_buff  = tlvs;
    m_len = len;
}
em_msg_t::~em_msg_t()
{

}

