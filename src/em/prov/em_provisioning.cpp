/**
 * Copyright 2025 Comcast Cable Communications Management, LLC
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
#include "em.h"
#include "em_cmd.h"
#include "em_msg.h"
#include "cjson/cJSON.h"
#include "util.h"
#include "ec_util.h"
#include "cjson_util.h"

int em_provisioning_t::create_cce_ind_msg(uint8_t *buff, bool enable)
{
    uint16_t  msg_id = em_msg_type_dpp_cce_ind;
    unsigned int len = 0;
    em_cmdu_t *cmdu;
    em_tlv_t *tlv;
    uint8_t *tmp = buff;
    uint8_t cce_enable = 0;
    uint16_t type = htons(ETH_P_1905);

    memcpy(tmp, reinterpret_cast<uint8_t *> (get_peer_mac()), sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += static_cast<unsigned int> (sizeof(mac_address_t));

    memcpy(tmp, get_al_interface_mac(), sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += static_cast<unsigned int> (sizeof(mac_address_t));

    memcpy(tmp, reinterpret_cast<uint8_t *> (&type), sizeof(uint16_t));
    tmp += sizeof(uint16_t);
    len += static_cast<unsigned int> (sizeof(uint16_t));

    cmdu = reinterpret_cast<em_cmdu_t *> (tmp);

    memset(tmp, 0, sizeof(em_cmdu_t));
    cmdu->type = htons(msg_id);
    cmdu->id = htons(msg_id);
    cmdu->last_frag_ind = 1;

    tmp += sizeof(em_cmdu_t);
    len += static_cast<unsigned int> (sizeof(em_cmdu_t));

    // One DPP CCE Indication tlv 17.2.82
    tlv = reinterpret_cast<em_tlv_t *> (tmp);
    tlv->type = em_tlv_type_dpp_cce_indication;
    cce_enable = (enable ? 1 : 0); 
    memcpy(tlv->value, &cce_enable, sizeof(uint8_t));
    tlv->len = htons(sizeof(uint16_t));

    tmp += (sizeof(em_tlv_t) + sizeof(uint16_t));
    len += static_cast<unsigned int> (sizeof(em_tlv_t) + sizeof(uint16_t));

    // End of message
    tlv = reinterpret_cast<em_tlv_t *> (tmp);
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += static_cast<unsigned int> (sizeof (em_tlv_t));

    return static_cast<int> (len);
}

int em_provisioning_t::send_prox_encap_dpp_msg(em_encap_dpp_t* encap_dpp_tlv, size_t encap_dpp_len, em_dpp_chirp_value_t *chirp, size_t chirp_len)
{
    if (encap_dpp_len == 0 || encap_dpp_tlv == NULL) {
        em_printfout("Encap DPP TLV is empty");
        return -1;
    }

    // Make sure there is enough room for the TLV, the 1905 layer will deal with fragmentation.
    uint8_t buff[MAX_EM_BUFF_SZ+encap_dpp_len];
    unsigned int len = 0;
    uint8_t *tmp = buff;

    tmp = em_msg_t::add_1905_header(tmp, &len, const_cast<uint8_t *> (get_peer_mac()), get_al_interface_mac(), em_msg_type_proxied_encap_dpp);

    // One 1905 Encap DPP TLV 17.2.79
    tmp = em_msg_t::add_tlv(tmp, &len, em_tlv_type_1905_encap_dpp, reinterpret_cast<uint8_t *> (encap_dpp_tlv), static_cast<unsigned int> (encap_dpp_len));

    // Zero or One DPP Chirp value tlv 17.2.83
    if (chirp != NULL && chirp_len > 0) {
        tmp = em_msg_t::add_tlv(tmp, &len, em_tlv_type_dpp_chirp_value, reinterpret_cast<uint8_t *> (chirp), static_cast<unsigned int> (chirp_len));
    }


    tmp = em_msg_t::add_eom_tlv(tmp, &len);

    char *errors[EM_MAX_TLV_MEMBERS] = {0};

    if (em_msg_t(em_msg_type_proxied_encap_dpp, em_profile_type_3, buff, len).validate(errors) == 0) {
        em_printfout("Proxied Encap DPP msg failed validation in tnx end");
        //return -1;
    }

    {
        em_raw_hdr_t *hdr = reinterpret_cast<em_raw_hdr_t *>(buff);
        em_printfout("Sending Proxied Encap DPP msg from '" MACSTRFMT "' to '" MACSTRFMT "'\n", MAC2STR(hdr->src), MAC2STR(hdr->dst));
    }

    em_printfout("Sending Proxied Encap DPP msg of length %d", len);
    if (send_frame(buff, len)  < 0) {
        em_printfout("Proxied Encap DPP msg failed");
        perror("send_frame");
        return -1;
    }

    return static_cast<int> (len);
}

int em_provisioning_t::send_direct_encap_dpp_msg(uint8_t* dpp_frame, size_t dpp_frame_len, uint8_t dest_al_mac[ETH_ALEN])
{
    if (dpp_frame_len == 0 || dpp_frame == NULL) {
        em_printfout("Direct DPP Frame is empty");
        return -1;
    }

    // Make sure there is enough room for the TLV, the 1905 layer will deal with fragmentation.
    uint8_t buff[MAX_EM_BUFF_SZ+dpp_frame_len];
    unsigned int len = 0;
    uint8_t *tmp = buff;

    tmp = em_msg_t::add_1905_header(tmp, &len, dest_al_mac, get_al_interface_mac(), em_msg_type_direct_encap_dpp);

    // One 1905 Encap DPP TLV 17.2.86
    tmp = em_msg_t::add_tlv(tmp, &len, em_tlv_type_dpp_msg, dpp_frame, static_cast<unsigned int> (dpp_frame_len));

    tmp = em_msg_t::add_eom_tlv(tmp, &len);

    char *errors[EM_MAX_TLV_MEMBERS] = {0};

    if (em_msg_t(em_msg_type_direct_encap_dpp, em_profile_type_3, buff, len).validate(errors) == 0) {
        em_printfout("Direct Encap DPP msg failed validation in tnx end");
        //return -1;
    }

    {
        em_raw_hdr_t *hdr = reinterpret_cast<em_raw_hdr_t *>(buff);
        em_printfout("Sending Direct Encap DPP msg from '" MACSTRFMT "' to '" MACSTRFMT "'\n", MAC2STR(hdr->src), MAC2STR(hdr->dst));
    }

    em_printfout("Sending Direct Encap DPP msg of length %d", len);
    if (send_frame(buff, len)  < 0) {
        em_printfout("Direct Encap DPP msg failed");
        perror("send_frame");
        return -1;
    }

    return static_cast<int> (len);
}

int em_provisioning_t::send_1905_eapol_encap_msg(uint8_t* eapol_frame, size_t eapol_frame_len, uint8_t dest_al_mac[ETH_ALEN])
{
    if (eapol_frame_len == 0 || eapol_frame == NULL) {
        em_printfout("Direct DPP Frame is empty");
        return -1;
    }
    if (dest_al_mac == NULL) {
        em_printfout("Destination AL MAC address is NULL");
        return -1;
    }

    // Make sure there is enough room for the TLV, the 1905 layer will deal with fragmentation.
    uint8_t buff[MAX_EM_BUFF_SZ+eapol_frame_len];
    unsigned int len = 0;
    uint8_t *tmp = buff;

    tmp = em_msg_t::add_1905_header(tmp, &len, dest_al_mac, get_al_interface_mac(), em_msg_type_1905_encap_eapol);

    // One 1905 Encap DPP TLV 17.2.86
    tmp = em_msg_t::add_tlv(tmp, &len, em_tlv_type_1905_encap_eapol, eapol_frame, static_cast<unsigned int> (eapol_frame_len));

    tmp = em_msg_t::add_eom_tlv(tmp, &len);

    char *errors[EM_MAX_TLV_MEMBERS] = {0};

    if (em_msg_t(em_msg_type_1905_encap_eapol, em_profile_type_3, buff, len).validate(errors) == 0) {
        em_printfout("EAPOL Encap DPP msg failed validation in tnx end");
        //return -1;
    }

    {
        em_raw_hdr_t *hdr = reinterpret_cast<em_raw_hdr_t *>(buff);
        em_printfout("Sending EAPOL Encap DPP msg from '" MACSTRFMT "' to '" MACSTRFMT "'\n", MAC2STR(hdr->src), MAC2STR(hdr->dst));
    }

    em_printfout("Sending EAPOL Encap DPP msg of length %d", len);
    if (send_frame(buff, len)  < 0) {
        em_printfout("EAPOL Encap DPP msg failed");
        perror("send_frame");
        return -1;
    }

    return static_cast<int> (len);
}

int em_provisioning_t::send_1905_rekey_msg(uint8_t dest_al_mac[ETH_ALEN])
{
    if (dest_al_mac == NULL) {
        em_printfout("Destination AL MAC address is NULL");
        return -1;
    }

    // Make sure there is enough room for the TLV, the 1905 layer will deal with fragmentation.
    uint8_t buff[MAX_EM_BUFF_SZ];
    unsigned int len = 0;
    uint8_t *tmp = buff;

    tmp = em_msg_t::add_1905_header(tmp, &len, dest_al_mac, get_al_interface_mac(), em_msg_type_1905_rekey_req);
    // No TLVs
    tmp = em_msg_t::add_eom_tlv(tmp, &len);

    char *errors[EM_MAX_TLV_MEMBERS] = {0};

    if (em_msg_t(em_msg_type_1905_rekey_req, em_profile_type_3, buff, len).validate(errors) == 0) {
        em_printfout("1905 Rekey msg failed validation in tnx end");
        //return -1;
    }

    {
        em_raw_hdr_t *hdr = reinterpret_cast<em_raw_hdr_t *>(buff);
        em_printfout("Sending 1905 Rekey msg from '" MACSTRFMT "' to '" MACSTRFMT "'\n", MAC2STR(hdr->src), MAC2STR(hdr->dst));
    }

    em_printfout("Sending 1905 Rekey msg of length %d", len);
    if (send_frame(buff, len)  < 0) {
        em_printfout("1905 Rekey msg failed");
        perror("send_frame");
        return -1;
    }

    return static_cast<int> (len);
}

int em_provisioning_t::send_chirp_notif_msg(em_dpp_chirp_value_t *chirp, size_t chirp_len)
{

    if (chirp_len == 0 || chirp == NULL) {
        printf("Chirp value is empty\n");
        return -1;
    }

    uint8_t buff[MAX_EM_BUFF_SZ];
    unsigned int len = 0;
    uint8_t *tmp = buff;

    //dm_easy_mesh_t *dm = get_data_model();

    // NOTE: `get_ctrl_al_interface_mac` is really only for co-located so `get_peer_mac` does not work.

    //TODO: Decide on addressing.
    mac_addr_str_t peer_mac_str = {0}, al_mac_str = {0};
    dm_easy_mesh_t::macbytes_to_string(get_peer_mac(), peer_mac_str);
    dm_easy_mesh_t::macbytes_to_string(get_al_interface_mac(), al_mac_str);
    
    tmp = em_msg_t::add_1905_header(tmp, &len, get_peer_mac(), get_al_interface_mac(), em_msg_type_chirp_notif);

    // One DPP Chirp value tlv 17.2.83
    tmp = em_msg_t::add_tlv(tmp, &len, em_tlv_type_dpp_chirp_value, reinterpret_cast<uint8_t *> (chirp), static_cast<unsigned int> (chirp_len));

    tmp = em_msg_t::add_eom_tlv(tmp, &len);

    char *errors[EM_MAX_TLV_MEMBERS] = {0};

    if (em_msg_t(em_msg_type_chirp_notif, em_profile_type_3, buff, len).validate(errors) == 0) {
        printf("Channel Selection Request msg failed validation in tnx end\n");
        //return -1;
    }

    em_printfout("Sending CHIRP NOTIFICATION");
    if (send_frame(buff, len)  < 0) {
        em_printfout("Channel Selection Request msg failed, error:%d", errno);
        return -1;
    }

    // TODO: If needed, likely not
	//set_state(em_state_ctrl_configured);

    return static_cast<int> (len);

}

int em_provisioning_t::create_bss_conf_req_tlv(uint8_t *buff)
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

    cJSON *bsta_info = create_enrollee_bsta_list(nullptr);
    if (!bsta_info) {
        em_printfout("Failed to create enrollee BSTA list");
        cJSON_Delete(root);
        return -1;
    }
    cJSON_AddItemToObject(root, "bSTAList", bsta_info);
    std::string dpp_config_req_obj_str = cjson_utils::stringify(root);
    cJSON_Delete(root);

    em_bss_conf_req_t *bss_conf_req = reinterpret_cast<em_bss_conf_req_t *>(buff);
    memcpy(bss_conf_req->dpp_config_req_obj, dpp_config_req_obj_str.c_str(), dpp_config_req_obj_str.size());

    return static_cast<int>(dpp_config_req_obj_str.size());
}

int em_provisioning_t::create_bsta_radio_cap_tlv(uint8_t *buff)
{
    ASSERT_NOT_NULL(buff, -1, "%s:%d: Buffer is null\n", __func__, __LINE__);
    dm_easy_mesh_t *dm = get_data_model();
    ASSERT_NOT_NULL(dm, -1, "%s:%d: Data model is null\n", __func__, __LINE__);

    int len = sizeof(em_bh_sta_radio_cap_t);
    em_bh_sta_radio_cap_t *bsta_radio_cap = reinterpret_cast<em_bh_sta_radio_cap_t*>(buff);

    for (unsigned int i = 0; i < dm->get_num_bss(); i++) {
        auto* bss_info = dm->get_bss_info(i);
        if (!bss_info) continue;
        if (bss_info->id.haul_type != em_haul_type_backhaul) continue;
        memcpy(bsta_radio_cap->bsta_addr, bss_info->bssid.mac, sizeof(mac_address_t));
        memcpy(bsta_radio_cap->ruid, bss_info->id.ruid, sizeof(mac_address_t));
        bsta_radio_cap->bsta_mac_present = 1;
        break;
    }

    return len;
}

int em_provisioning_t::create_akm_suite_cap_tlv(uint8_t *buff)
{
    ASSERT_NOT_NULL(buff, -1, "%s:%d: Buffer is null\n", __func__, __LINE__);
    dm_easy_mesh_t *dm = get_data_model();
    ASSERT_NOT_NULL(dm, -1, "%s:%d: Data model is null\n", __func__, __LINE__);

    // TODO: AKM suites are not populated in the data model.

    // Complete this TLV (EasyMesh 12.2.78) when this data is dynamically available.

    return 0;
}

int em_provisioning_t::create_bss_config_req_msg(uint8_t *buff)
{
    em_msg_type_t msg_id = em_msg_type_bss_config_req;
    unsigned int len = 0;
    uint8_t tlv_buff[4096] = {0};
    uint8_t *tmp = buff;
    em_service_type_t service_type = get_service_type();
    em_profile_type_t profile_type = get_profile_type();
    int tlv_size = 0;

    tmp = em_msg_t::add_1905_header(tmp, &len, const_cast<uint8_t *> (get_peer_mac()), get_al_interface_mac(), msg_id);

    // 5.3.8 Fronthaul BSS and Backhaul BSS configuration
    // If an Enrollee Multi-AP Agent has established a PMK and PTK with the Controller at 1905-layer using the procedures
    // described in section 5.3.7, it shall request configuration for its fronthaul BSSs and backhaul BSSs by sending a BSS
    // Configuration Request message to the Controller. The BSS Configuration Request message shall include at least

    //  One Multi-AP Profile TLV.
    tmp = em_msg_t::add_tlv(tmp, &len, em_tlv_type_profile, reinterpret_cast<uint8_t *> (&profile_type), sizeof(em_profile_type_t));

    //  One SupportedService TLV.
    // 1 service type followed by the service type value
    uint8_t service_type_buff[2] = {1, service_type};
    tmp = em_msg_t::add_tlv(tmp, &len, em_tlv_type_supported_service, service_type_buff, sizeof(service_type_buff));

    // One Backhaul STA Radio Capabilities TLV.
    tlv_size = create_bsta_radio_cap_tlv(tlv_buff);
    tmp = em_msg_t::add_tlv(tmp, &len, em_tlv_type_bh_sta_radio_cap, tlv_buff, static_cast<unsigned int> (tlv_size));

    // One AP capability TLV
    tlv_size = create_ap_cap_tlv(tlv_buff);
    tmp = em_msg_t::add_tlv(tmp, &len, em_tlv_type_ap_cap, tlv_buff, static_cast<unsigned int> (tlv_size));

    // One AP Radio Basic Capabilities TLV for each of the supported radios of the Multi-AP Agent.
    tlv_size = create_ap_radio_basic_cap(tlv_buff);
    tmp = em_msg_t::add_tlv(tmp, &len, em_tlv_type_ap_radio_basic_cap, tlv_buff, static_cast<unsigned int> (tlv_size));

    //  One AKM Suite Capabilities TLV
    tlv_size = create_akm_suite_cap_tlv(tlv_buff);
    tmp = em_msg_t::add_tlv(tmp, &len, em_tlv_type_akm_suite, tlv_buff, static_cast<unsigned int> (tlv_size));

    //  One Profile-2 AP Capability TLV.
    tlv_size = create_prof_2_tlv(tlv_buff);
    tmp = em_msg_t::add_tlv(tmp, &len, em_tlv_type_profile_2_ap_cap, tlv_buff, static_cast<unsigned int> (tlv_size));

    //  One BSS Configuration Request TLV with DPP attribute(s) for all supported radios of the Multi-AP Agent.
    tlv_size = create_bss_conf_req_tlv(tlv_buff);
    tmp = em_msg_t::add_tlv(tmp, &len, em_tlv_type_bss_conf_req, tlv_buff, static_cast<unsigned int> (tlv_size));

    //  One AP HT Capabilities TLV for each radio that is capable of HT (Wi-Fi 4) operation.
    tlv_size = create_ht_tlv(tlv_buff);
    tmp = em_msg_t::add_tlv(tmp, &len, em_tlv_type_ht_cap, tlv_buff, static_cast<unsigned int> (tlv_size));

    //  One AP VHT Capabilities TLV for each radio that is capable of VHT (Wi-Fi 5) operation.
    tlv_size = create_vht_tlv(tlv_buff);
    tmp = em_msg_t::add_tlv(tmp, &len, em_tlv_type_vht_cap, tlv_buff, static_cast<unsigned int> (tlv_size));

    // NOTE: this CMDU is extended in R6 with additional TLVs for Wi-Fi 6/6E and Wi-Fi 7 capabilities.
    //  One AP Wi-Fi 6 Capabilities TLV for each radio that is capable of HE (Wi-Fi 6) operation
    tlv_size = create_wifi6_tlv(tlv_buff);
    tmp = em_msg_t::add_tlv(tmp, &len, em_tlv_type_ap_wifi6_cap, tlv_buff, static_cast<unsigned int> (tlv_size));

    //  One AP Radio Advanced Capabilities TLV for each of the supported radios of the Multi-AP Agent
    tlv_size = create_ap_radio_advanced_cap_tlv(tlv_buff);
    tmp = em_msg_t::add_tlv(tmp, &len, em_tlv_type_ap_radio_advanced_cap, tlv_buff, static_cast<unsigned int> (tlv_size));

    //  If the Agent supports EHT (Wi-Fi 7) operation, one Wi-Fi 7 Agent Capabilities TLV.
    tlv_size = create_wifi7_tlv(tlv_buff);
    tmp = em_msg_t::add_tlv(tmp, &len, em_tlv_type_wifi7_agent_cap, tlv_buff, static_cast<unsigned int> (tlv_size));

    //  Zero or one EHT Operations TLV (see section 17.2.103)
    tlv_size = create_eht_operations_tlv(tlv_buff);
    tmp = em_msg_t::add_tlv(tmp, &len, em_tlv_eht_operations, tlv_buff, static_cast<unsigned int> (tlv_size));

    // End of message
    tmp = em_msg_t::add_eom_tlv(tmp, &len);

    return static_cast<int> (len);
}

int em_provisioning_t::create_bss_config_rsp_msg(uint8_t *buff)
{
    uint16_t  msg_id = em_msg_type_bss_config_rsp;
    unsigned int len = 0;
    em_cmdu_t *cmdu;
    em_tlv_t *tlv;
    uint8_t *tmp = buff;
    uint16_t type = htons(ETH_P_1905);

    memcpy(tmp, reinterpret_cast<uint8_t *> (get_peer_mac()), sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += static_cast<unsigned int> (sizeof(mac_address_t));

    memcpy(tmp, get_current_cmd()->get_al_interface_mac(), sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += static_cast<unsigned int> (sizeof(mac_address_t));

    memcpy(tmp, reinterpret_cast<uint8_t *> (&type), sizeof(uint16_t));
    tmp += sizeof(uint16_t);
    len += static_cast<unsigned int> (sizeof(uint16_t));

    cmdu = reinterpret_cast<em_cmdu_t *> (tmp);

    memset(tmp, 0, sizeof(em_cmdu_t));
    cmdu->type = htons(msg_id);
    cmdu->id = htons(msg_id);
    cmdu->last_frag_ind = 1;

    tmp += sizeof(em_cmdu_t);
    len += static_cast<unsigned int> (sizeof(em_cmdu_t));

    // One or more BSS config response tlv 17.2.85
    // Zero or One deafult 802,1Q settings tlv 17.2.49
    // Zero or One traffic separation policy tlv 17.2.50

    // End of message
    tlv = reinterpret_cast<em_tlv_t *> (tmp);
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += static_cast<unsigned int> (sizeof (em_tlv_t));

    return static_cast<int> (len);

}

int em_provisioning_t::create_bss_config_res_msg(uint8_t *buff)
{
    uint16_t  msg_id = em_msg_type_bss_config_res;
    unsigned int len = 0;
    em_cmdu_t *cmdu;
    em_tlv_t *tlv;
    uint8_t *tmp = buff;
    uint16_t type = htons(ETH_P_1905);

    memcpy(tmp, reinterpret_cast<uint8_t *> (get_peer_mac()), sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += static_cast<unsigned int> (sizeof(mac_address_t));

    memcpy(tmp, get_current_cmd()->get_al_interface_mac(), sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += static_cast<unsigned int> (sizeof(mac_address_t));

    memcpy(tmp, reinterpret_cast<uint8_t *> (&type), sizeof(uint16_t)); 
    tmp += sizeof(uint16_t);
    len += static_cast<unsigned int> (sizeof(uint16_t));

    cmdu = reinterpret_cast<em_cmdu_t *> (tmp);

    memset(tmp, 0, sizeof(em_cmdu_t));
    cmdu->type = htons(msg_id);
    cmdu->id = htons(msg_id);
    cmdu->last_frag_ind = 1;

    tmp += sizeof(em_cmdu_t);
    len += static_cast<unsigned int> (sizeof(em_cmdu_t));

    // One BSS configuration report tlv 17.2.75
    tlv = reinterpret_cast<em_tlv_t *> (tmp);
    tlv->type = em_tlv_type_dpp_chirp_value;


    // End of message
    tlv = reinterpret_cast<em_tlv_t *> (tmp);
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += static_cast<unsigned int> (sizeof (em_tlv_t));

    return static_cast<int> (len);

}

int em_provisioning_t::create_dpp_direct_encap_msg(uint8_t *buff, uint8_t *frame, uint16_t frame_len)
{
    uint16_t  msg_id = em_msg_type_direct_encap_dpp;
    unsigned int len = 0;
    em_cmdu_t *cmdu;
    em_tlv_t *tlv;
    uint8_t *tmp = buff;
    uint16_t type = htons(ETH_P_1905);

    memcpy(tmp, reinterpret_cast<uint8_t *> (get_peer_mac()), sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += static_cast<unsigned int> (sizeof(mac_address_t));

    memcpy(tmp, get_current_cmd()->get_al_interface_mac(), sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += static_cast<unsigned int> (sizeof(mac_address_t));

    memcpy(tmp, reinterpret_cast<uint8_t *> (&type), sizeof(uint16_t));
    tmp += sizeof(uint16_t);
    len += static_cast<unsigned int> (sizeof(uint16_t));

    cmdu = reinterpret_cast<em_cmdu_t *> (tmp);

    memset(tmp, 0, sizeof(em_cmdu_t));
    cmdu->type = htons(msg_id);
    cmdu->id = htons(msg_id);
    cmdu->last_frag_ind = 1;

    tmp += sizeof(em_cmdu_t);
    len += static_cast<unsigned int> (sizeof(em_cmdu_t));

    // One DPP Message tlv 17.2.86
    tlv = reinterpret_cast<em_tlv_t *> (tmp);
    tlv->type = em_tlv_type_dpp_msg;
    tlv->len = htons(frame_len);
    memcpy(tlv->value, frame, frame_len);

    tmp += (sizeof(em_tlv_t) + frame_len);
    len += static_cast<unsigned int> (sizeof(em_tlv_t) + frame_len);

    // End of message
    tlv = reinterpret_cast<em_tlv_t *> (tmp);
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += static_cast<unsigned int> (sizeof (em_tlv_t));

    return static_cast<int> (len);
}

int em_provisioning_t::handle_1905_rekey_msg(uint8_t *buff, unsigned int len){
    // No TLVs, just a notification to rekey the 1905 layer.
    EM_ASSERT_NOT_NULL(m_ec_manager, -1, "EC Manager is NULL, cannot handle 1905 Rekey message");
    if (!m_ec_manager->rekey_1905_layer_ptk()){
        em_printfout("Failed to rekey 1905 layer PTK");
        return -1;
    }
    em_printfout("Successfully rekeyed 1905 layer PTK");
    return 0;
}

int em_provisioning_t::handle_1905_encap_eapol_msg(uint8_t *buff, unsigned int len){

    EM_ASSERT_NOT_NULL(m_ec_manager, -1, "EC Manager is NULL, cannot handle 1905 Encap EAPOL message");
    EM_ASSERT_NOT_NULL(buff, -1, "Buffer is NULL, cannot handle 1905 Encap EAPOL message");

    em_raw_hdr_t *hdr = reinterpret_cast<em_raw_hdr_t *>(buff);
    
    uint8_t *src_mac = hdr->src;

    em_tlv_t    *tlv = reinterpret_cast<em_tlv_t *> (buff + sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));
    unsigned int tlv_len = len - static_cast<unsigned int> (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));

    uint8_t *eapol_frame = NULL;
    uint16_t eapol_frame_len = 0;

    while ((tlv->type != em_tlv_type_eom) && (tlv_len > 0)) {

        if (tlv->type == em_tlv_type_1905_encap_eapol) {
            eapol_frame = tlv->value;
            eapol_frame_len = ntohs(tlv->len);
        }

        tlv_len -= static_cast<unsigned int> (sizeof(em_tlv_t) + ntohs(tlv->len));
        tlv = reinterpret_cast<em_tlv_t *>(reinterpret_cast<uint8_t *> (tlv) + sizeof(em_tlv_t) + ntohs(tlv->len));
    }

    if (eapol_frame == NULL || eapol_frame_len == 0) {
        em_printfout("Received a 1905 EAPOL Encap message but did not contain EAPOL frame!");
        return -1;
    }

    if (!m_ec_manager->process_1905_eapol_encap_msg(buff, len, src_mac)){
        em_printfout("Failed to handle 1905 EAPOL Encap message");
        return -1;
    }
    em_printfout("Successfully handled 1905 EAPOL Encap message");
    return 0;
}


int em_provisioning_t::handle_cce_ind_msg(uint8_t *buff, unsigned int len)
{
    em_tlv_t *tlv = reinterpret_cast<em_tlv_t *> (buff + sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));

    bool enable = false;
    bool valid_tlv = false;

    while ((tlv->type != em_tlv_type_eom)) {
        if (tlv->type == em_tlv_type_dpp_cce_indication) {
            em_cce_indication_t *cce_ind_tlv = reinterpret_cast<em_cce_indication_t *>(tlv->value);
            enable = static_cast<bool>(cce_ind_tlv->advertise_cce);
            valid_tlv = true;
            break;
        }
        tlv = reinterpret_cast<em_tlv_t *>(reinterpret_cast<uint8_t *> (tlv) + sizeof(em_tlv_t) + ntohs(tlv->len));
    }

    if (!valid_tlv) {
        em_printfout("Received a DPP CCE Indication Message but did not contain DPP CCE Indication TLV!");
        return -1;
    }

    bool cce_toggled = m_ec_manager->pa_cfg_toggle_cce(enable);
    if (!cce_toggled) {
        em_printfout("Could not toggle CCE to %d", static_cast<int>(enable));
        return -1;
    }

    em_printfout("Successfully %s CCE in Beacons and Probe Responses", (enable == true ? "enabled" : "disabled"));
    return 0;
}

void em_provisioning_t::process_msg(uint8_t *data, unsigned int len)
{
    em_cmdu_t *cmdu;

    cmdu = reinterpret_cast<em_cmdu_t *> (data + sizeof(em_raw_hdr_t));

    switch (htons(cmdu->type)) {
        case em_msg_type_dpp_cce_ind:
            handle_cce_ind_msg(data, len);
            break;

        case em_msg_type_proxied_encap_dpp:
            handle_proxy_encap_dpp(data, len);
            break;

        case em_msg_type_direct_encap_dpp:
            handle_direct_encap_dpp(data, len);
            break;

        case em_msg_type_reconfig_trigger:
            break;

        case em_msg_type_bss_config_req:
            break;

        case em_msg_type_bss_config_rsp:
            break;

        case em_msg_type_bss_config_res:
            break;

        case em_msg_type_chirp_notif:
            handle_dpp_chirp_notif(data, len);
            break;

        case em_msg_type_dpp_bootstrap_uri_notif:
            break;
        case em_msg_type_1905_rekey_req:
            handle_1905_rekey_msg(data, len);
            break;
        case em_msg_type_1905_encap_eapol:
            handle_1905_encap_eapol_msg(data, len);
            break;
        default:
            em_printfout("unhandled message type %u", htons(cmdu->type));
            break;
    }
}

int em_provisioning_t::handle_dpp_chirp_notif(uint8_t *buff, unsigned int len)
{
    em_tlv_t    *tlv;
    unsigned int tlv_len;

    tlv = reinterpret_cast<em_tlv_t *> (buff + sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));
    tlv_len = len - static_cast<unsigned int> (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));

    while ((tlv->type != em_tlv_type_eom) && (len > 0)) {
        // Can be one or more
        if (tlv->type == em_tlv_type_dpp_chirp_value) {
            // Parse out dest STA mac address and hash value then validate against the hash in the 
            // ec_session dpp uri info public key. 
            // Then construct an Auth request frame and send back in an Encap message
            em_dpp_chirp_value_t* chirp_tlv = reinterpret_cast<em_dpp_chirp_value_t*> (tlv->value);

            if (!m_ec_manager->process_chirp_notification(chirp_tlv, ntohs(tlv->len))){
                //TODO: Fail
                em_printfout("Failed to process chirp notification");
            }
        }

        tlv_len -= static_cast<unsigned int> (sizeof(em_tlv_t) + ntohs(tlv->len));
        tlv = reinterpret_cast<em_tlv_t *> (reinterpret_cast<uint8_t *> (tlv) + sizeof(em_tlv_t) + ntohs(tlv->len));
    }

	return 0;
}

int em_provisioning_t::handle_proxy_encap_dpp(uint8_t *buff, unsigned int len)
{
    em_tlv_t    *tlv;
    unsigned int tlv_len;

    tlv = reinterpret_cast<em_tlv_t *> (buff + sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));
    tlv_len = len - static_cast<unsigned int> (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));

    uint16_t encap_tlv_len = 0, chirp_tlv_len = 0;
    em_encap_dpp_t* encap_tlv = NULL;
    em_dpp_chirp_value_t* chirp_tlv = NULL;

    while ((tlv->type != em_tlv_type_eom) && (tlv_len > 0)) {

        if (tlv->type == em_tlv_type_1905_encap_dpp) {
            // Parse out dest STA mac address and hash value then validate against the hash in the 
            // ec_session dpp uri info public key. 
            // Then construct an Auth request frame and send back in an Encap message
            encap_tlv = reinterpret_cast<em_encap_dpp_t*> (tlv->value);
            encap_tlv_len = ntohs(tlv->len);
        }

        // Optional: Can be 0 or 1
        if (tlv->type == em_tlv_type_dpp_chirp_value) {
            chirp_tlv = reinterpret_cast<em_dpp_chirp_value_t*> (tlv->value);
            chirp_tlv_len = ntohs(tlv->len);
        }

        tlv_len -= static_cast<unsigned int> (sizeof(em_tlv_t) + ntohs(tlv->len));
        tlv = reinterpret_cast<em_tlv_t *>(reinterpret_cast<uint8_t *> (tlv) + sizeof(em_tlv_t) + ntohs(tlv->len));
    }

    if (m_ec_manager->process_proxy_encap_dpp_msg(encap_tlv, encap_tlv_len, chirp_tlv, chirp_tlv_len) != 0){
        //TODO: Fail
        return -1;
    }

	return 0;
}

int em_provisioning_t::handle_direct_encap_dpp(uint8_t *buff, unsigned int len)
{
    em_tlv_t    *tlv;
    unsigned int tlv_len;

    tlv = reinterpret_cast<em_tlv_t *> (buff + sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));
    tlv_len = len - static_cast<unsigned int> (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));

    uint16_t direct_frame_len = 0;
    uint8_t* direct_frame = NULL;

    while ((tlv->type != em_tlv_type_eom) && (tlv_len > 0)) {

        if (tlv->type == em_tlv_type_dpp_msg) {
            // Direct Encap DPP TLV value **is** the encapsulated frame
            direct_frame = tlv->value;
            direct_frame_len = ntohs(tlv->len);
        }

        tlv_len -= static_cast<unsigned int> (sizeof(em_tlv_t) + ntohs(tlv->len));
        tlv = reinterpret_cast<em_tlv_t *>(reinterpret_cast<uint8_t *> (tlv) + sizeof(em_tlv_t) + ntohs(tlv->len));
    }

    if (direct_frame == NULL || direct_frame_len == 0) {
        em_printfout("Received Invalid Direct Encap DPP TLV!");
        return -1;
    }

    em_raw_hdr_t *hdr = reinterpret_cast<em_raw_hdr_t *>(buff);
    uint8_t *src_mac = hdr->src;
    em_printfout("Received Direct Encap DPP msg from '" MACSTRFMT "' of length %d", MAC2STR(src_mac), direct_frame_len);

    if (m_ec_manager->process_direct_encap_dpp_msg(direct_frame, direct_frame_len, src_mac) != 0){
        //TODO: Fail
        return -1;
    }

	return 0;
}

cJSON *em_provisioning_t::create_enrollee_bsta_list(ec_connection_context_t *conn_ctx)
{
    dm_easy_mesh_t *dm = get_data_model();
    if (dm == nullptr) {
        em_printfout("Could not get data model handle!");
        return nullptr;
    }

    std::string channelList;
    scoped_cjson bsta_list_obj(cJSON_CreateObject());
    EM_ASSERT_NOT_NULL(bsta_list_obj.get(), nullptr, "Failed to allocate for bSTAList object!");

    scoped_cjson b_sta_list_arr(cJSON_CreateArray());
    EM_ASSERT_NOT_NULL(b_sta_list_arr.get(), nullptr, "Failed to allocate for bSTAList array!");

    if (!cJSON_AddStringToObject(bsta_list_obj.get(), "netRole", "mapBackhaulSta")) {
        em_printfout("Could not add netRole to bSTAList object!");
        return nullptr;
    }

    // XXX: TODO: akm is hard-coded. Should come from em_akm_suite_info_t or equivalent, but
    // not currently populated anywhere in the data model.
    std::string akms[2] = {"psk", "dpp"};
    std::string akm_suites = {};
    for (size_t i = 0; i < std::size(akms); i++) {
        akm_suites += util::akm_to_oui(akms[i]);
        if (!akm_suites.empty() && i < std::size(akms) - 1) akm_suites += "+";
    }

    if (!cJSON_AddStringToObject(bsta_list_obj.get(), "akm", akm_suites.c_str())) {
        em_printfout("Could not add AKM to bSTAList object!");
        return nullptr;
    }

    if (!cJSON_AddNumberToObject(bsta_list_obj.get(), "bSTA_Maximum_Links", 1)) {
        em_printfout("Could not add bSTA_Maximum_Links to bSTAList object!");
        return nullptr;
    }

    if (!cJSON_AddItemToArray(b_sta_list_arr.get(), bsta_list_obj.get())) {
        em_printfout("Could not add bSTAList object to bSTAList array!");
        return nullptr;
    }

    scoped_cjson radio_list_arr(cJSON_AddArrayToObject(bsta_list_obj.get(), "RadioList"));
    EM_ASSERT_NOT_NULL(radio_list_arr.get(), nullptr, "Could not add RadioList array to bSTAList object!");

    for (unsigned int i = 0; i < dm->get_num_bss(); i++) {
        em_bss_info_t *bss_info = dm->get_bss_info(i);
        if (!bss_info) {
            continue;
        }
        // Skip if not backhaul
        if (bss_info->id.haul_type != em_haul_type_backhaul) {
            continue;
        }

        scoped_cjson radioListObj(cJSON_CreateObject());
        EM_ASSERT_NOT_NULL(radioListObj.get(), nullptr, "Failed to create RadioList object!");

        uint8_t* ruid = bss_info->ruid.mac;
        if (!cJSON_AddStringToObject(
                radioListObj.get(), "RUID",
                util::mac_to_string(ruid, "").c_str())) {
            em_printfout("Could not add RUID to RadioList object!");
            return nullptr;
        }

        std::string radio_channel_list;
        for (unsigned int j = 0; j < dm->get_num_op_class(); j++) {
            dm_op_class_t *opclass = dm->get_op_class(j);
            if (opclass == nullptr) {
                continue;
            }

            if (memcmp(ruid, opclass->m_op_class_info.id.ruid, ETH_ALEN) == 0) {
                em_printfout("Found opclass %d for radio '" MACSTRFMT "'", opclass->m_op_class_info.op_class, MAC2STR(ruid));
                radio_channel_list += std::to_string(opclass->m_op_class_info.op_class) + "/" +
                                      std::to_string(opclass->m_op_class_info.channel);
                if (j != dm->get_num_op_class() - 1)
                    radio_channel_list += ",";
            }
        }
        channelList += radio_channel_list;

        if (!cJSON_AddStringToObject(radioListObj.get(), "RadioChannelList",
                                     radio_channel_list.c_str())) {
            printf("%s:%d: Could not add RadioChannelList to RadioList object!\n", __func__,
                   __LINE__);
            return nullptr;
        }

        if (!cJSON_AddItemToArray(radio_list_arr.get(), radioListObj.get())) {
            printf("%s:%d: Could not add RadioList object to RadioList array!\n", __func__,
                   __LINE__);
            return nullptr;
        }
    }

    if (!cJSON_AddStringToObject(bsta_list_obj.get(), "channelList", channelList.c_str())) {
        em_printfout("Could not add channelList to bSTAList object!");
        return nullptr;
    }
    return b_sta_list_arr.get();
}

cJSON *em_provisioning_t::create_fbss_response_obj(ec_connection_context_t *conn_ctx)
{
    dm_easy_mesh_t *dm = get_data_model();
    ASSERT_NOT_NULL(dm, nullptr, "%s:%d: Failed to get data model handle.\n", __func__, __LINE__);

    scoped_cjson fbss_configuration_object(cJSON_CreateObject());
    ASSERT_NOT_NULL(fbss_configuration_object, nullptr, "%s:%d: Could not create fBSS Configuration Object\n", __func__, __LINE__);

    if (!cJSON_AddStringToObject(fbss_configuration_object.get(), "wi-fi_tech", "map")) {
        em_printfout("Failed to add \"wi-fi_tech\" to Configuration Object");
        return nullptr;
    }

    scoped_cjson discovery_object(cJSON_CreateObject());
    ASSERT_NOT_NULL(discovery_object.get(), nullptr, "%s:%d: Could not create Discovery Object for DPP Configuration Object\n", __func__, __LINE__);

    const em_network_ssid_info_t* network_ssid_info = dm->get_network_ssid_info_by_haul_type(em_haul_type_fronthaul);
    EM_ASSERT_NOT_NULL(network_ssid_info, nullptr, "Could not get network SSID info for fronthaul BSS");

    if (!cJSON_AddStringToObject(discovery_object.get(), "SSID", network_ssid_info->ssid)) {
        em_printfout("Could not add \"SSID\" to fBSS Configuration Object");
        return nullptr;
    }

    for (unsigned int i = 0; i < dm->get_num_bss(); i++) {
        const dm_bss_t *bss = dm->get_bss(i);
        if (!bss) continue;
        if (bss->m_bss_info.id.haul_type == em_haul_type_fronthaul && strncmp(bss->m_bss_info.ssid, network_ssid_info->ssid, strlen(network_ssid_info->ssid)) == 0) {
            em_printfout("Found fronthaul BSS! '%s'", bss->m_bss_info.ssid);
            if (!cJSON_AddStringToObject(discovery_object.get(), "BSSID", util::mac_to_string(bss->m_bss_info.bssid.mac, "").c_str())) {
                em_printfout("Failed to add \"BSSID\" to fBSS Configuration Object");
                return nullptr;
            }
            if (!cJSON_AddStringToObject(discovery_object.get(), "RUID", util::mac_to_string(bss->m_bss_info.ruid.mac, "").c_str())) {
                em_printfout("Failed to add \"RUID\" to fBSS Configuration Object");
                return nullptr;
            }
        }
    }

    scoped_cjson credential_object(cJSON_CreateObject());
    if (credential_object == nullptr) {
        em_printfout("Failed to create credential object for DPP Configuration object.");
        return nullptr;
    }

    std::string akm_suites = {};
    bool needs_psk_hex = false;
    for (unsigned int i = 0; i < network_ssid_info->num_akms; i++) {
        if (!akm_suites.empty()) akm_suites += "+";
        akm_suites += util::akm_to_oui(network_ssid_info->akm[i]);

    }
    // "psk_hex" is a conditional field,
    // present only if PSK or AKM or SAE is a selected AKM
    const auto check_needs_psk_hex = [](std::string akm) -> bool {
        // psk || sae
        return akm == util::akm_to_oui("psk")
        || akm == util::akm_to_oui("sae");
    };

    std::vector<std::string> akms = util::split_by_delim(akm_suites, '+');
    for (const auto& akm : akms) {
        if (check_needs_psk_hex(akm)) needs_psk_hex = true;
    }

    if (!cJSON_AddStringToObject(credential_object.get(), "akm", akm_suites.c_str())) {
        em_printfout("Failed to add \"akm\" to bSTA DPP Configuration Object");
        return nullptr;
    }

    if (needs_psk_hex) {
        std::vector<uint8_t> psk = ec_crypto::gen_psk(std::string(network_ssid_info->pass_phrase), std::string(network_ssid_info->ssid));
        if (psk.empty()) {
            em_printfout("Failed to generate PSK");
            return nullptr;
        }

        cJSON_AddStringToObject(credential_object.get(), "psk_hex", em_crypto_t::hash_to_hex_string(psk).c_str());
    }

    if (!cJSON_AddStringToObject(credential_object.get(), "pass", network_ssid_info->pass_phrase)) {
        em_printfout("Failed to add \"pass\" to bSTA DPP Configuration Object");
        return nullptr;
    }

    if (!cJSON_AddItemToObject(fbss_configuration_object.get(), "discovery", discovery_object.get())) {
        em_printfout("Failed to add \"discovery\" to bSTA DPP Configuration Object");
        return nullptr;
    }

    if (!cJSON_AddItemToObject(fbss_configuration_object.get(), "cred", credential_object.get())) {
        em_printfout("Failed to add \"cred\" to bSTA DPP Configuration Object");
        return nullptr;
    }

    return fbss_configuration_object.get();
}

cJSON *em_provisioning_t::create_configurator_bsta_response_obj(ec_connection_context_t *conn_ctx)
{
    dm_easy_mesh_t *dm = get_data_model();
    ASSERT_NOT_NULL(dm, nullptr, "%s:%d: Failed to get data model handle.\n", __func__, __LINE__);

    scoped_cjson bsta_configuration_object(cJSON_CreateObject());
    ASSERT_NOT_NULL(bsta_configuration_object.get(), nullptr, "%s:%d: Could not create bSTA Configuration Object\n", __func__, __LINE__);

    if (!cJSON_AddStringToObject(bsta_configuration_object.get(), "wi-fi_tech", "map")) {
        em_printfout("Failed to add \"wi-fi_tech\" to Configuration Object");
    }

    scoped_cjson discovery_object(cJSON_CreateObject());
    EM_ASSERT_NOT_NULL(discovery_object.get(), nullptr, "Failed to create Discovery Object for DPP Configuration Object");

    const em_network_ssid_info_t* network_ssid_info = dm->get_network_ssid_info_by_haul_type(em_haul_type_backhaul);
    ASSERT_NOT_NULL(network_ssid_info, nullptr, "%s:%d: No backhaul BSS found, cannot create bSTA Configuration Object\n", __func__, __LINE__);
    if (!cJSON_AddStringToObject(discovery_object.get(), "SSID", network_ssid_info->ssid)) {
        em_printfout("Could not add \"SSID\" to bSTA Configuration Object");
        return nullptr;
    }
    // Find "BSSID" and "RUID" since not contained in `em_network_ssid_info_t`
    // XXX: Note: R5 only - R6 introduces MLDs.
    for (unsigned int i = 0; i < dm->get_num_bss(); i++) {
        const dm_bss_t *bss = dm->get_bss(i);
        if (!bss) continue;
        if (bss->m_bss_info.id.haul_type == em_haul_type_backhaul && strncmp(bss->m_bss_info.ssid, network_ssid_info->ssid, strlen(network_ssid_info->ssid)) == 0) {
            em_printfout("Found backhaul mesh! '%s'", bss->m_bss_info.ssid);
            if (!cJSON_AddStringToObject(discovery_object.get(), "BSSID", util::mac_to_string(bss->m_bss_info.bssid.mac, "").c_str())) {
                em_printfout("Failed to add \"BSSID\" to bSTA Configuration Object");
                return nullptr;
            }
            if (!cJSON_AddStringToObject(discovery_object.get(), "RUID", util::mac_to_string(bss->m_bss_info.ruid.mac, "").c_str())) {
                em_printfout("Failed to add \"RUID\" to bSTA Configuration Object");
                return nullptr;
            }
        }
    }

    scoped_cjson credential_object(cJSON_CreateObject());

    EM_ASSERT_NOT_NULL(credential_object.get(), nullptr, "Failed to create Credential object for DPP Configuration Object");

    std::string akm_suites = {};
    bool needs_psk_hex = false;
    for (unsigned int i = 0; i < network_ssid_info->num_akms; i++) {
        if (!akm_suites.empty()) akm_suites += "+";
        akm_suites += util::akm_to_oui(network_ssid_info->akm[i]);

    }
    // "psk_hex" is a conditional field,
    // present only if PSK or AKM or SAE is a selected AKM
    const auto check_needs_psk_hex = [](std::string akm) -> bool {
        // psk || sae
        return akm == util::akm_to_oui("psk")
        || akm == util::akm_to_oui("sae");
    };

    std::vector<std::string> akms = util::split_by_delim(akm_suites, '+');
    for (const auto& akm : akms) {
        if (check_needs_psk_hex(akm)) needs_psk_hex = true;
    }

    if (!cJSON_AddStringToObject(credential_object.get(), "akm", akm_suites.c_str())) {
        em_printfout("Failed to add \"akm\" to bSTA DPP Configuration Object");
        return nullptr;
    }

    if (needs_psk_hex) {
        std::vector<uint8_t> psk = ec_crypto::gen_psk(std::string(network_ssid_info->pass_phrase), std::string(network_ssid_info->ssid));
        if (psk.empty()) {
            em_printfout("Failed to generate PSK");
            return nullptr;
        }

        cJSON_AddStringToObject(credential_object.get(), "psk_hex", em_crypto_t::hash_to_hex_string(psk).c_str());
    }

    if (!cJSON_AddStringToObject(credential_object.get(), "pass", network_ssid_info->pass_phrase)) {
        em_printfout("Failed to add \"pass\" to bSTA DPP Configuration Object");
        return nullptr;
    }

    if (!cJSON_AddItemToObject(bsta_configuration_object.get(), "discovery", discovery_object.get())) {
        em_printfout("Failed to add \"discovery\" to bSTA DPP Configuration Object");
        return nullptr;
    }

    if (!cJSON_AddItemToObject(bsta_configuration_object.get(), "cred", credential_object.get())) {
        em_printfout("Failed to add \"cred\" to bSTA DPP Configuration Object");
        return nullptr;
    }
    return bsta_configuration_object.get();
}

cJSON *em_provisioning_t::create_ieee1905_response_obj(ec_connection_context_t *conn_ctx)
{
    scoped_cjson dpp_configuration_object(cJSON_CreateObject());
    ASSERT_NOT_NULL(dpp_configuration_object, nullptr, "%s:%d: Failed to create 1905 DPP Configuration Object.\n", __func__, __LINE__);

    if (!cJSON_AddStringToObject(dpp_configuration_object.get(), "wi-fi_tech", "dpp")) {
        em_printfout("Failed to add \"wi-fi_tech\" to 1905 DPP Configuration Object.");
        return nullptr;
    }

    if (!cJSON_AddNumberToObject(dpp_configuration_object.get(), "dfCounterThreshold", 42)) {
        em_printfout("Failed to add \"dfCounterThreshold\" to 1905 DPP Configuration Object.");
        return nullptr;
    }

    scoped_cjson credential_object(cJSON_CreateObject());
    if (!credential_object) {
        em_printfout("Failed to create Credential object for 1905 DPP Configuration Object.");
        return nullptr;
    }
    if (!cJSON_AddStringToObject(credential_object.get(), "akm", util::akm_to_oui("dpp").c_str())) {
        em_printfout("Failed to add \"akm\" to 1905 DPP Configuration Object.");
        return nullptr;
    }

    cJSON_AddItemToObject(dpp_configuration_object.get(), "cred", credential_object.get());

    return dpp_configuration_object.get();
}

void em_provisioning_t::handle_state_prov_none()
{
    em_printfout("Waiting for CCE indication interface: %s", const_cast<char *> (get_radio_interface_name()));
}

void em_provisioning_t::handle_state_prov()
{

    assert(get_service_type() == em_service_type_ctrl);
}

void em_provisioning_t::handle_state_auth_req_pending()
{
    assert(get_service_type() == em_service_type_agent);
}

void em_provisioning_t::handle_state_auth_rsp_pending()
{
    assert(get_service_type() == em_service_type_ctrl);
}

void em_provisioning_t::handle_state_auth_cnf_pending()
{
    assert(get_service_type() == em_service_type_agent);
}

void em_provisioning_t::handle_state_config_req_pending()
{
    assert(get_service_type() == em_service_type_ctrl);
}

void em_provisioning_t::handle_state_config_rsp_pending()
{
    assert(get_service_type() == em_service_type_agent);
}

void em_provisioning_t::handle_state_config_res_pending()
{
    assert(get_service_type() == em_service_type_ctrl);
}

void em_provisioning_t::process_agent_state()
{
    switch (get_state()) {
/* To be implemented
		case em_state_agent_prov_none:
            handle_state_prov_none();
            break;

        case em_state_agent_prov:
            handle_state_prov();
            break;

        case em_state_agent_auth_req_pending:
            handle_state_auth_req_pending();
            break;

        case em_state_agent_auth_rsp_pending:
            handle_state_auth_rsp_pending();
            break;

        case em_state_agent_auth_cnf_pending:
            handle_state_auth_cnf_pending();
            break;

        case em_state_agent_config_req_pending:
            handle_state_config_req_pending();
            break;

        case em_state_agent_config_rsp_pending:
            handle_state_config_rsp_pending();
            break;

        case em_state_agent_config_res_pending:
            handle_state_config_res_pending();
            break;
*/
        default:
            break; 
    }
}

void em_provisioning_t::process_ctrl_state()
{

}

em_provisioning_t::em_provisioning_t()
{
}

em_provisioning_t::~em_provisioning_t()
{

}

