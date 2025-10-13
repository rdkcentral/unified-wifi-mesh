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
#include "em_provisioning.h"
#include "ec_ctrl_configurator.h"

int em_provisioning_t::create_cce_ind_msg(uint8_t *buff, bool enable)
{
    unsigned int len = 0;

    /*
    ...it shall send a DPP CCE Indication message containing one DPP CCE Indication TLV 
    with the Advertise CCE field set to one and send it to one or more Multi-AP Agents 
    that indicate support for DPP Onboarding
    */
    mac_address_t   multi_addr = {0x01, 0x80, 0xc2, 0x00, 0x00, 0x13};

    uint8_t* tmp = em_msg_t::add_1905_header(buff, &len, multi_addr, get_al_interface_mac(), em_msg_type_dpp_cce_ind,
                        get_mgr()->get_next_msg_id());

    // One DPP CCE Indication tlv 17.2.82
    uint8_t cce_enable = (enable ? 1 : 0); 
    tmp = em_msg_t::add_tlv(tmp, &len, em_tlv_type_dpp_cce_indication, &cce_enable, sizeof(uint8_t));


    tmp = em_msg_t::add_eom_tlv(tmp, &len); 

    return static_cast<int> (len);
}

int em_provisioning_t::send_prox_encap_dpp_msg(em_encap_dpp_t* encap_dpp_tlv, size_t encap_dpp_len, em_dpp_chirp_value_t *chirp, size_t chirp_len, uint8_t dest_al_mac[ETH_ALEN])
{
    if (encap_dpp_len == 0 || encap_dpp_tlv == NULL) {
        em_printfout("Encap DPP TLV is empty");
        return -1;
    }

    if (dest_al_mac == NULL) {
        em_printfout("Destination AL MAC address is NULL");
        return -1;
    }

    if (memcmp(dest_al_mac, ZERO_MAC_ADDR, ETH_ALEN) == 0) {
        em_printfout("Destination AL MAC address is zero");
        return -1;
    }

    // Make sure there is enough room for the TLV, the 1905 layer will deal with fragmentation.
    uint8_t buff[MAX_EM_BUFF_SZ+encap_dpp_len];
    unsigned int len = 0;
    uint8_t *tmp = buff;

    tmp = em_msg_t::add_1905_header(tmp, &len, dest_al_mac, get_al_interface_mac(), em_msg_type_proxied_encap_dpp,
                        get_mgr()->get_next_msg_id());

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
        em_printfout("Sending Proxied Encap DPP msg from '" MACSTRFMT "' to '" MACSTRFMT "'", MAC2STR(hdr->src), MAC2STR(hdr->dst));
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

    if (dest_al_mac == NULL) {
        em_printfout("Destination AL MAC address is NULL");
        return -1;
    }
    if (memcmp(dest_al_mac, ZERO_MAC_ADDR, ETH_ALEN) == 0) {
        em_printfout("Destination AL MAC address is zero");
        return -1;
    }

    // Make sure there is enough room for the TLV, the 1905 layer will deal with fragmentation.
    uint8_t buff[MAX_EM_BUFF_SZ+dpp_frame_len];
    unsigned int len = 0;
    uint8_t *tmp = buff;

    tmp = em_msg_t::add_1905_header(tmp, &len, dest_al_mac, get_al_interface_mac(), em_msg_type_direct_encap_dpp,
                        get_mgr()->get_next_msg_id());

    // One 1905 Encap DPP TLV 17.2.86
    tmp = em_msg_t::add_tlv(tmp, &len, em_tlv_type_dpp_msg, dpp_frame, static_cast<unsigned int> (dpp_frame_len));

    tmp = em_msg_t::add_eom_tlv(tmp, &len);

    char *errors[EM_MAX_TLV_MEMBERS] = {0};

    if (em_msg_t(em_msg_type_direct_encap_dpp, em_profile_type_3, buff, len).validate(errors) == 0) {
        em_printfout("Direct Encap DPP msg failed validation in tnx end");
        //return -1;
    }

    em_raw_hdr_t *hdr = reinterpret_cast<em_raw_hdr_t *>(buff);
    em_printfout("Sending Direct Encap DPP msg from '" MACSTRFMT "' to '" MACSTRFMT "' of length %d", MAC2STR(hdr->src), MAC2STR(hdr->dst), len);

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
    if (memcmp(dest_al_mac, ZERO_MAC_ADDR, ETH_ALEN) == 0) {
        em_printfout("Destination AL MAC address is zero");
        return -1;
    }

    // Make sure there is enough room for the TLV, the 1905 layer will deal with fragmentation.
    uint8_t buff[MAX_EM_BUFF_SZ+eapol_frame_len];
    unsigned int len = 0;
    uint8_t *tmp = buff;

    tmp = em_msg_t::add_1905_header(tmp, &len, dest_al_mac, get_al_interface_mac(), em_msg_type_1905_encap_eapol,
                        get_mgr()->get_next_msg_id());

    // One 1905 Encap DPP TLV 17.2.86
    tmp = em_msg_t::add_tlv(tmp, &len, em_tlv_type_1905_encap_eapol, eapol_frame, static_cast<unsigned int> (eapol_frame_len));

    tmp = em_msg_t::add_eom_tlv(tmp, &len);

    char *errors[EM_MAX_TLV_MEMBERS] = {0};

    if (em_msg_t(em_msg_type_1905_encap_eapol, em_profile_type_3, buff, len).validate(errors) == 0) {
        em_printfout("EAPOL Encap DPP msg failed validation in tnx end");
        //return -1;
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
    if (memcmp(dest_al_mac, ZERO_MAC_ADDR, ETH_ALEN) == 0) {
        em_printfout("Destination AL MAC address is zero");
        return -1;
    }

    // Make sure there is enough room for the TLV, the 1905 layer will deal with fragmentation.
    uint8_t buff[MAX_EM_BUFF_SZ];
    unsigned int len = 0;
    uint8_t *tmp = buff;

    tmp = em_msg_t::add_1905_header(tmp, &len, dest_al_mac, get_al_interface_mac(), em_msg_type_1905_rekey_req,
                        get_mgr()->get_next_msg_id());
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

int em_provisioning_t::send_chirp_notif_msg(em_dpp_chirp_value_t *chirp, size_t chirp_len, uint8_t dest_al_mac[ETH_ALEN])
{

    if (chirp_len == 0 || chirp == NULL) {
        printf("Chirp value is empty\n");
        return -1;
    }

    if (dest_al_mac == NULL) {
        printf("Destination AL MAC address is NULL\n");
        return -1;
    }

    if (memcmp(dest_al_mac, ZERO_MAC_ADDR, ETH_ALEN) == 0) {
        printf("Destination AL MAC address is zero\n");
        return -1;
    }


    uint8_t buff[MAX_EM_BUFF_SZ];
    unsigned int len = 0;
    uint8_t *tmp = buff;

    tmp = em_msg_t::add_1905_header(tmp, &len, dest_al_mac, get_al_interface_mac(), em_msg_type_chirp_notif,
                        get_mgr()->get_next_msg_id());

    // One DPP Chirp value tlv 17.2.83
    tmp = em_msg_t::add_tlv(tmp, &len, em_tlv_type_dpp_chirp_value, reinterpret_cast<uint8_t *> (chirp), static_cast<unsigned int> (chirp_len));

    tmp = em_msg_t::add_eom_tlv(tmp, &len);

    char *errors[EM_MAX_TLV_MEMBERS] = {0};

    if (em_msg_t(em_msg_type_chirp_notif, em_profile_type_3, buff, len).validate(errors) == 0) {
        em_printfout("Chirp Notification msg failed validation in tnx end");
        //return -1;
    }

    em_printfout("Sending CHIRP NOTIFICATION to '" MACSTRFMT "' from '" MACSTRFMT "'",
                 MAC2STR(dest_al_mac), MAC2STR(get_al_interface_mac()));
    if (send_frame(buff, len)  < 0) {
        em_printfout("Chirp Notification msg failed, error:%d", errno);
        return -1;
    }

    return static_cast<int> (len);

}

int em_provisioning_t::create_dpp_direct_encap_msg(uint8_t *buff, uint8_t *frame, uint16_t frame_len)
{
    uint16_t  msg_type = em_msg_type_direct_encap_dpp;
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
    cmdu->type = htons(msg_type);
    cmdu->id = htons(get_mgr()->get_next_msg_id());
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

int em_provisioning_t::handle_1905_encap_eapol_msg(uint8_t *buff, unsigned int len, uint8_t src_al_mac[ETH_ALEN]){

    EM_ASSERT_NOT_NULL(m_ec_manager, -1, "EC Manager is NULL, cannot handle 1905 Encap EAPOL message");
    EM_ASSERT_NOT_NULL(buff, -1, "Buffer is NULL, cannot handle 1905 Encap EAPOL message");

    em_tlv_t    *tlv = reinterpret_cast<em_tlv_t *> (buff + sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));
    unsigned int tlv_len = len - static_cast<unsigned int> (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));

    em_tlv_t* eapol_tlv = em_msg_t::get_tlv(tlv, tlv_len, em_tlv_type_1905_encap_eapol);
    EM_ASSERT_NOT_NULL(eapol_tlv, -1, "EAPOL Encap TLV not found in 1905 Encap EAPOL message");

    uint16_t eapol_frame_len = ntohs(eapol_tlv->len);
    if (eapol_frame_len == 0) {
        em_printfout("Received a 1905 EAPOL Encap message but did not contain EAPOL frame!");
        return -1;
    }

    if (!m_ec_manager->process_1905_eapol_encap_msg(eapol_tlv->value, eapol_frame_len, src_al_mac)){
        em_printfout("Failed to handle 1905 EAPOL Encap message");
        return -1;
    }
    return 0;
}


int em_provisioning_t::handle_cce_ind_msg(uint8_t *buff, unsigned int len)
{
    em_tlv_t *tlv = reinterpret_cast<em_tlv_t *> (buff + sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));
    unsigned int tlvs_len = len - static_cast<unsigned int> (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));
    
    em_tlv_t* cce_ind_tlv = em_msg_t::get_tlv(tlv, tlvs_len, em_tlv_type_dpp_cce_indication);
    EM_ASSERT_NOT_NULL(cce_ind_tlv, -1, "DPP CCE Indication TLV not found in CCE Indication message");
    EM_ASSERT_NOT_NULL(cce_ind_tlv->value, -1, "DPP CCE Indication TLV value is NULL in CCE Indication message");

    em_cce_indication_t* cce_indication = reinterpret_cast<em_cce_indication_t*>(cce_ind_tlv->value);

    bool do_enable_cce = (cce_indication->advertise_cce == 1);

    if (!do_enable_cce) {
        em_printfout("Received a DPP CCE Indication Message but did not contain DPP CCE Indication TLV!");
        return -1;
    }

    bool cce_toggled = m_ec_manager->pa_cfg_toggle_cce(do_enable_cce);
    if (!cce_toggled) {
        em_printfout("Could not toggle CCE to %d", static_cast<int>(do_enable_cce));
        return -1;
    }

    em_printfout("Successfully %s CCE in Beacons and Probe Responses", (do_enable_cce ? "enabled" : "disabled"));
    return 0;
}

void em_provisioning_t::process_msg(uint8_t *data, unsigned int len)
{
    em_cmdu_t *cmdu = reinterpret_cast<em_cmdu_t *> (data + sizeof(em_raw_hdr_t));

    em_raw_hdr_t *hdr = reinterpret_cast<em_raw_hdr_t *>(data);
    uint8_t *src_al_mac = hdr->src;

    switch (htons(cmdu->type)) {
        case em_msg_type_dpp_cce_ind:
            handle_cce_ind_msg(data, len);
            break;

        case em_msg_type_proxied_encap_dpp:
            handle_proxy_encap_dpp(data, len, src_al_mac);
            break;

        case em_msg_type_direct_encap_dpp:
            handle_direct_encap_dpp(data, len, src_al_mac);
            break;

        case em_msg_type_reconfig_trigger:
            break;

        case em_msg_type_chirp_notif:
            handle_dpp_chirp_notif(data, len, src_al_mac);
            break;
        case em_msg_type_dpp_bootstrap_uri_notif:
            break;
        case em_msg_type_1905_rekey_req:
            handle_1905_rekey_msg(data, len);
            break;
        case em_msg_type_1905_encap_eapol:
            handle_1905_encap_eapol_msg(data, len, src_al_mac);
            break;
        default:
            em_printfout("unhandled message type %u", htons(cmdu->type));
            break;
    }
}

int em_provisioning_t::handle_dpp_chirp_notif(uint8_t *buff, unsigned int len, uint8_t src_al_mac[ETH_ALEN])
{
    em_tlv_t    *tlv = reinterpret_cast<em_tlv_t *> (buff + sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));
    unsigned int tlv_len = len - static_cast<unsigned int> (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));

    em_tlv_t* chirp_tlv = em_msg_t::get_tlv(tlv, tlv_len, em_tlv_type_dpp_chirp_value);
    EM_ASSERT_NOT_NULL(chirp_tlv, -1, "DPP Chirp Value TLV not found in DPP Chirp Notification message");
    EM_ASSERT_NOT_NULL(chirp_tlv->value, -1, "DPP Chirp Value TLV value is NULL in DPP Chirp Notification message");
    em_dpp_chirp_value_t* chirp = reinterpret_cast<em_dpp_chirp_value_t*> (tlv->value);

    if (!m_ec_manager->process_chirp_notification(chirp, SWAP_LITTLE_ENDIAN(tlv->len), src_al_mac)) {
        em_printfout("Failed to process chirp notification");
        return -1;
    }
    set_is_dpp_onboarding(true);

    return 0;
}

int em_provisioning_t::handle_proxy_encap_dpp(uint8_t *buff, unsigned int len, uint8_t src_al_mac[ETH_ALEN])
{
    em_tlv_t    *tlv;
    unsigned int tlv_len;

    tlv = reinterpret_cast<em_tlv_t *> (buff + sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));
    tlv_len = len - static_cast<unsigned int> (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));

    // em_encap_dpp_t* encap_tlv = NULL;
    // em_dpp_chirp_value_t* chirp_tlv = NULL;

    em_tlv_t* encap_tlv = em_msg_t::get_tlv(tlv, tlv_len, em_tlv_type_1905_encap_dpp);
    em_tlv_t* chirp_tlv = em_msg_t::get_tlv(tlv, tlv_len, em_tlv_type_dpp_chirp_value);
    EM_ASSERT_NOT_NULL(encap_tlv, -1, "1905 Encap DPP TLV not found in Proxy Encap DPP message");

    em_encap_dpp_t* encap = reinterpret_cast<em_encap_dpp_t*> (encap_tlv->value);
    uint16_t encap_tlv_len = ntohs(encap_tlv->len);

    em_dpp_chirp_value_t* chirp = NULL;
    uint16_t chirp_tlv_len = 0;

    if (chirp_tlv != nullptr) {
        chirp = reinterpret_cast<em_dpp_chirp_value_t*> (chirp_tlv->value);
        chirp_tlv_len = ntohs(chirp_tlv->len);
    }

    if (m_ec_manager->process_proxy_encap_dpp_msg(encap, encap_tlv_len, chirp, chirp_tlv_len, src_al_mac) != 0){
        //TODO: Fail
        return -1;
    }

	return 0;
}

int em_provisioning_t::handle_direct_encap_dpp(uint8_t *buff, unsigned int len, uint8_t src_al_mac[ETH_ALEN])
{
    em_tlv_t    *tlv;
    unsigned int tlv_len;

    tlv = reinterpret_cast<em_tlv_t *> (buff + sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));
    tlv_len = len - static_cast<unsigned int> (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));

    em_printfout("Received Direct Encap DPP message of length %d", len);

    em_tlv_t* direct_tlv = em_msg_t::get_tlv(tlv, tlv_len, em_tlv_type_dpp_msg);
    EM_ASSERT_NOT_NULL(direct_tlv, -1, "Direct Encap DPP TLV not found in Direct Encap DPP message");

    uint16_t direct_frame_len = ntohs(direct_tlv->len);
    EM_ASSERT_MSG_TRUE(direct_frame_len > 0, -1, "Direct Encap DPP TLV length is zero in Direct Encap DPP message");

    if (m_ec_manager->process_direct_encap_dpp_msg(direct_tlv->value, direct_frame_len, src_al_mac) != 0){
        //TODO: Fail
        return -1;
    }

	return 0;
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

