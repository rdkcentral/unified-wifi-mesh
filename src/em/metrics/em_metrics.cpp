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
#include "em_metrics.h"
#include "em_msg.h"
#include "dm_easy_mesh.h"
#include "em_cmd.h"
#include "util.h"
#include "em.h"
#include "em_cmd_exec.h"

int em_metrics_t::handle_assoc_sta_link_metrics_tlv(unsigned char *buff)
{
    em_assoc_sta_link_metrics_t	*sta_metrics;
    em_assoc_link_metrics_t *metrics;
    dm_sta_t *sta;
    unsigned int i;
    dm_easy_mesh_t  *dm;

    dm = get_data_model();

    sta_metrics = (em_assoc_sta_link_metrics_t *)buff;

    for (i = 0; i < sta_metrics->num_bssids; i++) {
        metrics	= &sta_metrics->assoc_link_metrics[i];
        sta = dm->find_sta(sta_metrics->sta_mac, metrics->bssid);
        if (sta == NULL) {
            continue;
        }

        sta->m_sta_info.est_dl_rate = metrics->est_mac_data_rate_dl;
        sta->m_sta_info.est_ul_rate = metrics->est_mac_data_rate_ul;
        sta->m_sta_info.rcpi = metrics->rcpi;
    }

    return 0;
}

int em_metrics_t::handle_assoc_sta_ext_link_metrics_tlv(unsigned char *buff)
{
    em_assoc_sta_ext_link_metrics_t	*sta_metrics;
    em_assoc_ext_link_metrics_t *metrics;
    dm_sta_t *sta;
    unsigned int i;
    dm_easy_mesh_t  *dm;

    dm = get_data_model();

    sta_metrics = (em_assoc_sta_ext_link_metrics_t *)buff;

    for (i = 0; i < sta_metrics->num_bssids; i++) {
        metrics	= &sta_metrics->assoc_ext_link_metrics[i];
        sta = dm->find_sta(sta_metrics->sta_mac, metrics->bssid);
        if (sta == NULL) {
            continue;
        }

        sta->m_sta_info.last_dl_rate = metrics->last_data_dl_rate;
        sta->m_sta_info.last_ul_rate = metrics->last_data_ul_rate;
        sta->m_sta_info.util_rx = metrics->util_receive;
        sta->m_sta_info.util_tx = metrics->util_transmit;
    }

    return 0;
}

int em_metrics_t::handle_assoc_sta_vendor_link_metrics_tlv(unsigned char *buff)
{
    em_assoc_sta_vendor_link_metrics_t *sta_metrics;
    em_assoc_vendor_link_metrics_t *metrics;
    dm_sta_t *sta;
    unsigned int i;
    dm_easy_mesh_t  *dm;

    dm = get_data_model();

    sta_metrics = (em_assoc_sta_vendor_link_metrics_t *)buff;

    for (i = 0; i < sta_metrics->num_bssids; i++) {
        metrics = &sta_metrics->assoc_vendor_link_metrics[i];
        sta = dm->find_sta(sta_metrics->sta_mac, metrics->bssid);
        if (sta == NULL) {
            continue;
        }

        sta->m_sta_info.pkts_rx = metrics->packets_received;
        sta->m_sta_info.pkts_tx = metrics->packets_sent;
        sta->m_sta_info.bytes_rx = metrics->bytes_received;
        sta->m_sta_info.bytes_tx = metrics->bytes_sent;
    }

    return 0;
}


int em_metrics_t::handle_associated_sta_link_metrics_query(unsigned char *buff, unsigned int len)
{
    mac_address_t sta;
    em_cmdu_t *cmdu;
    em_tlv_t *tlv;
    char *errors[EM_MAX_TLV_MEMBERS] = {0};
    em_raw_hdr_t *hdr = (em_raw_hdr_t *)buff;

    if (em_msg_t(em_msg_type_assoc_sta_link_metrics_query, em_profile_type_3, buff, len).validate(errors) == 0) {
        printf("%s:%d:Assoc STA Link Metrics query message validation failed\n");
        return -1;
    }

    cmdu = (em_cmdu_t *)(buff + sizeof(em_raw_hdr_t));
    tlv = (em_tlv_t *)(buff + sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));

    memcpy(sta, tlv->value, sizeof(mac_address_t));

    send_associated_link_metrics_response(sta);
    set_state(em_state_agent_configured);

    return 0;
}

int em_metrics_t::handle_associated_sta_link_metrics_resp(unsigned char *buff, unsigned int len)
{
    em_tlv_t *tlv;
    int tmp_len, ret = 0;
    mac_address_t 	sta_mac;
    dm_easy_mesh_t  *dm;
    char *errors[EM_MAX_TLV_MEMBERS] = {0};
    mac_addr_str_t sta_mac_str, bssid_str, radio_mac_str;
    em_long_string_t	key;
    em_sta_info_t sta_info;

    dm = get_data_model();

    if (em_msg_t(em_msg_type_assoc_sta_link_metrics_rsp, get_profile_type(), buff, len).validate(errors) == 0) {
        printf("%s:%d: associated sta link metrics response msg validation failed\n", __func__, __LINE__);
        //return -1;
    }

    tlv =  (em_tlv_t *)(buff + sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));
    tmp_len = len - (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));

    while ((tlv->type != em_tlv_type_eom) && (tmp_len > 0)) {
        if (tlv->type == em_tlv_type_assoc_sta_link_metric) {
            handle_assoc_sta_link_metrics_tlv(tlv->value);
        }
        tmp_len -= (sizeof(em_tlv_t) + htons(tlv->len));
        tlv = (em_tlv_t *)((unsigned char *)tlv + sizeof(em_tlv_t) + htons(tlv->len));
    }

    tlv =  (em_tlv_t *)(buff + sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));
    tmp_len = len - (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));

    while ((tlv->type != em_tlv_type_eom) && (tmp_len > 0)) {
        if (tlv->type == em_tlv_type_error_code) {
            if (tlv->value[0] == 0x01) {
                memcpy(sta_mac, &tlv->value[1], sizeof(mac_address_t));
            } else if (tlv->value[0] == 0x02) {
                memcpy(sta_mac, &tlv->value[1], sizeof(mac_address_t));
            }
            break;
        }

        tmp_len -= (sizeof(em_tlv_t) + htons(tlv->len));
        tlv = (em_tlv_t *)((unsigned char *)tlv + sizeof(em_tlv_t) + htons(tlv->len));
    }

    tlv =  (em_tlv_t *)(buff + sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));
    tmp_len = len - (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));

    while ((tlv->type != em_tlv_type_eom) && (tmp_len > 0)) {
        if (tlv->type == em_tlv_type_assoc_sta_ext_link_metric) {
            handle_assoc_sta_ext_link_metrics_tlv(tlv->value);
        }

        tmp_len -= (sizeof(em_tlv_t) + htons(tlv->len));
        tlv = (em_tlv_t *)((unsigned char *)tlv + sizeof(em_tlv_t) + htons(tlv->len));
    }

    tlv =  (em_tlv_t *)(buff + sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));
    tmp_len = len - (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));

    while ((tlv->type != em_tlv_type_eom) && (tmp_len > 0)) {
        if (tlv->type == em_tlv_type_vendor_sta_metrics) {
            handle_assoc_sta_vendor_link_metrics_tlv(tlv->value);
        }

        tmp_len -= (sizeof(em_tlv_t) + htons(tlv->len));
        tlv = (em_tlv_t *)((unsigned char *)tlv + sizeof(em_tlv_t) + htons(tlv->len));
    }
    dm->set_db_cfg_param(db_cfg_type_sta_metrics_update, "");
    set_state(em_state_ctrl_configured);

    return 0;
}

int em_metrics_t::send_associated_sta_link_metrics_msg(mac_address_t sta_mac)
{
    unsigned char buff[MAX_EM_BUFF_SZ];
    char *errors[EM_MAX_TLV_MEMBERS] = {0};
    unsigned short  msg_id = em_msg_type_assoc_sta_link_metrics_query;
    int len = 0;
    em_cmdu_t *cmdu;
    em_tlv_t *tlv;
    dm_easy_mesh_t *dm;
    unsigned char *tmp = buff;
    unsigned short type = htons(ETH_P_1905);

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

    // One STA MAC Address Type TLV (see section 17.2.23).
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_sta_mac_addr;
    memcpy(tlv->value, sta_mac, sizeof(mac_address_t));
    tlv->len = htons(sizeof(mac_address_t));

    tmp += (sizeof (em_tlv_t) + sizeof(mac_address_t));
    len += (sizeof (em_tlv_t) + sizeof(mac_address_t));

    // End of message
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += (sizeof (em_tlv_t));

    if (em_msg_t(em_msg_type_assoc_sta_link_metrics_query, em_profile_type_3, buff, len).validate(errors) == 0) {
        printf("Associated STA Link Metrics Query msg validation failed\n");
        return -1;
    }

    if (send_frame(buff, len)  < 0) {
        printf("%s:%d: Associated STA Link Metrics Query send failed, error:%d\n", __func__, __LINE__, errno);
        return -1;
    }

    printf("%s:%d: Associated STA Link Metrics Query send success\n", __func__, __LINE__);
    return len;
}

void em_metrics_t::send_all_associated_sta_link_metrics_msg()
{
    dm_easy_mesh_t *dm;
    dm_sta_t *sta;

    dm = get_data_model();
    sta = (dm_sta_t *)hash_map_get_first(dm->m_sta_map);
    while (sta != NULL) {
        if (sta->m_sta_info.associated == true) {
            send_associated_sta_link_metrics_msg(sta->m_sta_info.id);
        }
        sta = (dm_sta_t *)hash_map_get_next(dm->m_sta_map, sta);
    }
}

int em_metrics_t::send_associated_link_metrics_response(mac_address_t sta_mac)
{
    unsigned char buff[MAX_EM_BUFF_SZ];
    char *errors[EM_MAX_TLV_MEMBERS] = {0};
    unsigned short  msg_type = em_msg_type_assoc_sta_link_metrics_rsp;
    int len = 0;
    em_cmdu_t *cmdu;
    em_tlv_t *tlv;
    unsigned char *tmp = buff;
    unsigned short sz = 0;
    unsigned short type = htons(ETH_P_1905);
    dm_easy_mesh_t *dm = get_data_model();
    mac_addr_str_t mac_str;
    bool sta_found = false;
    dm_sta_t *sta;

    sta = (dm_sta_t *)hash_map_get_first(dm->m_sta_map);
    while(sta != NULL) {
        if (memcmp(sta->m_sta_info.id, sta_mac, sizeof(mac_address_t)) == 0) {
            sta_found = true;
            break;
        }
        sta = (dm_sta_t *)hash_map_get_next(dm->m_sta_map, sta);
    }

    if (sta == NULL) {
        //TODO: Have to fix Failed TLV while sending empty frame with error code
        return -1;
    }

    short msg_id = em_msg_type_assoc_sta_link_metrics_rsp;

    dm_easy_mesh_t::macbytes_to_string(sta_mac, mac_str);

    memcpy(tmp, dm->get_ctrl_al_interface_mac(), sizeof(mac_address_t));
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
    cmdu->type = htons(msg_type);
    cmdu->id = htons(msg_id);
    cmdu->last_frag_ind = 1;

    tmp += sizeof(em_cmdu_t);
    len += sizeof(em_cmdu_t);

    //Assoc sta link metrics 17.2.24
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_assoc_sta_link_metric;
    sz = create_assoc_sta_link_metrics_tlv(tlv->value, sta_mac, sta);
    tlv->len =  htons(sz);

    tmp += (sizeof(em_tlv_t) + sz);
    len += (sizeof(em_tlv_t) + sz);

    //Error code  TLV 17.2.36
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_error_code;
    sz = create_error_code_tlv(tlv->value, sta_mac, sta_found);
    tlv->len = htons(sz);

    tmp += (sizeof(em_tlv_t) + sz);
    len += (sizeof(em_tlv_t) + sz);

    //assoc ext link metrics 17.2.62
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_assoc_sta_ext_link_metric;
    sz = create_assoc_ext_sta_link_metrics_tlv(tlv->value, sta_mac, sta);
    tlv->len = htons(sz);

    tmp += (sizeof(em_tlv_t) + sz);
    len += (sizeof(em_tlv_t) + sz);

    //assoc vendor link metrics
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_vendor_sta_metrics;
    sz = create_assoc_vendor_sta_link_metrics_tlv(tlv->value, sta_mac, sta);
    tlv->len = htons(sz);

    tmp += (sizeof(em_tlv_t) + sz);
    len += (sizeof(em_tlv_t) + sz);

    // End of message
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += (sizeof (em_tlv_t));

    if (em_msg_t(em_msg_type_assoc_sta_link_metrics_rsp, em_profile_type_3, buff, len).validate(errors) == 0) {
        printf("%s:%d: Associated STA Link Metrics validation failed for %s\n", __func__, __LINE__, mac_str);
        return -1;
    }

    if (send_frame(buff, len)  < 0) {
        printf("%s:%d: Associated STA Link Metrics  send failed, error:%d\n", __func__, __LINE__, errno);
        return -1;
    }
    printf("%s:%d: Associated STA Link Metrics for sta %s sent successfully\n", __func__, __LINE__, mac_str);

    return len;
}

short em_metrics_t::create_assoc_sta_link_metrics_tlv(unsigned char *buff, mac_address_t sta_mac, const dm_sta_t *const sta)
{
    //TODO: Cleanup hard-coded data
    short len = 0;
    dm_easy_mesh_t *dm;
    int num_bssids = 0;
    em_assoc_sta_link_metrics_t *assoc_sta_metrics = (em_assoc_sta_link_metrics_t*) buff;
    em_assoc_link_metrics_t *metrics;

    dm = get_data_model();
    num_bssids = dm->get_num_bss_for_associated_sta(sta_mac);

    if (sta == NULL) {
        memcpy(&assoc_sta_metrics->sta_mac, &sta_mac, sizeof(assoc_sta_metrics->sta_mac));
        len += sizeof(assoc_sta_metrics->sta_mac);

        assoc_sta_metrics->num_bssids = 0;
        len += sizeof(assoc_sta_metrics->num_bssids);
        return len;
    }
    else {
        metrics	= &assoc_sta_metrics->assoc_link_metrics[0];
        if ((memcmp(sta->m_sta_info.id, sta_mac, sizeof(mac_address_t)) == 0)) {
            memcpy(&assoc_sta_metrics->sta_mac, &sta->m_sta_info.id, sizeof(assoc_sta_metrics->sta_mac));
            len += sizeof(assoc_sta_metrics->sta_mac);

            assoc_sta_metrics->num_bssids = num_bssids;
            len += sizeof(assoc_sta_metrics->num_bssids);

            memcpy(&metrics->bssid, &sta->m_sta_info.bssid, sizeof(metrics->bssid));
            len += sizeof(metrics->bssid);

            metrics->time_delta_ms = 10;//TODO: Pending proper update
            len += sizeof(metrics->time_delta_ms);

            metrics->est_mac_data_rate_dl = sta->m_sta_info.last_dl_rate;
            len += sizeof(metrics->est_mac_data_rate_dl);

            metrics->est_mac_data_rate_ul = sta->m_sta_info.last_ul_rate;
            len += sizeof(metrics->est_mac_data_rate_ul);

            metrics->rcpi = 1;//TODO: Pending proper update
            len += sizeof(metrics->rcpi);
        }
    }
    return len;
}

short em_metrics_t::create_assoc_ext_sta_link_metrics_tlv(unsigned char *buff, mac_address_t sta_mac, const dm_sta_t *const sta)
{
    //TODO: Cleanup hard-coded data
    short len = 0;
    dm_easy_mesh_t *dm;
    int num_bssids = 0;
    em_assoc_sta_ext_link_metrics_t *assoc_sta_metrics = (em_assoc_sta_ext_link_metrics_t*) buff;
    em_assoc_ext_link_metrics_t *metrics;

    dm = get_data_model();
    num_bssids = dm->get_num_bss_for_associated_sta(sta_mac);

    if (sta == NULL) {
        memcpy(&assoc_sta_metrics->sta_mac, &sta_mac, sizeof(assoc_sta_metrics->sta_mac));
        len += sizeof(assoc_sta_metrics->sta_mac);

        assoc_sta_metrics->num_bssids = 0;
        len += sizeof(assoc_sta_metrics->num_bssids);
        return len;
    }
    else {
        metrics	= &assoc_sta_metrics->assoc_ext_link_metrics[0];
        if ((memcmp(sta->m_sta_info.id, sta_mac, sizeof(mac_address_t)) == 0)) {
            memcpy(assoc_sta_metrics->sta_mac, sta->m_sta_info.id, sizeof(assoc_sta_metrics->sta_mac));
            len += sizeof(assoc_sta_metrics->sta_mac);

            assoc_sta_metrics->num_bssids = dm->get_num_bss_for_associated_sta(sta_mac);
            len += sizeof(assoc_sta_metrics->num_bssids);

            memcpy(metrics->bssid, sta->m_sta_info.bssid, sizeof(metrics->bssid));
            len += sizeof(metrics->bssid);

            metrics->last_data_dl_rate = sta->m_sta_info.last_dl_rate;
            len += sizeof(metrics->last_data_dl_rate);

            metrics->last_data_ul_rate = sta->m_sta_info.last_ul_rate;
            len += sizeof(metrics->last_data_ul_rate);

            metrics->util_receive = sta->m_sta_info.util_rx;
            len += sizeof(metrics->util_receive);

            metrics->util_transmit = sta->m_sta_info.util_tx;
            len += sizeof(metrics->util_transmit);
        }
    }
    return len;
}

short em_metrics_t::create_assoc_vendor_sta_link_metrics_tlv(unsigned char *buff, mac_address_t sta_mac, const dm_sta_t *const sta)
{
    short len = 0;
    dm_easy_mesh_t *dm;
    int num_bssids = 0;
    em_assoc_sta_vendor_link_metrics_t *assoc_sta_metrics = (em_assoc_sta_vendor_link_metrics_t*) buff;
    em_assoc_vendor_link_metrics_t *metrics;

    dm = get_data_model();
    num_bssids = dm->get_num_bss_for_associated_sta(sta_mac);

    if (sta == NULL) {
        memcpy(&assoc_sta_metrics->sta_mac, &sta_mac, sizeof(assoc_sta_metrics->sta_mac));
        len += sizeof(assoc_sta_metrics->sta_mac);

        assoc_sta_metrics->num_bssids = 0;
        len += sizeof(assoc_sta_metrics->num_bssids);
        return len;
    }
    else {
        metrics = &assoc_sta_metrics->assoc_vendor_link_metrics[0];
        if ((memcmp(sta->m_sta_info.id, sta_mac, sizeof(mac_address_t)) == 0)) {
            memcpy(assoc_sta_metrics->sta_mac, sta->m_sta_info.id, sizeof(assoc_sta_metrics->sta_mac));
            len += sizeof(assoc_sta_metrics->sta_mac);

            assoc_sta_metrics->num_bssids = dm->get_num_bss_for_associated_sta(sta_mac);
            len += sizeof(assoc_sta_metrics->num_bssids);

            memcpy(metrics->bssid, sta->m_sta_info.bssid, sizeof(metrics->bssid));
            len += sizeof(metrics->bssid);

            metrics->packets_received = sta->m_sta_info.pkts_rx;
            len += sizeof(metrics->packets_received);

            metrics->packets_sent = sta->m_sta_info.pkts_tx;
            len += sizeof(metrics->packets_sent);

            metrics->bytes_received = sta->m_sta_info.bytes_rx;
            len += sizeof(metrics->bytes_received);

            metrics->bytes_sent = sta->m_sta_info.bytes_tx;
            len += sizeof(metrics->bytes_sent);
        }
    }
    return len;
}

short em_metrics_t::create_error_code_tlv(unsigned char *buff, mac_address_t sta, bool sta_found)
{
    short len = 0;
    unsigned char *tmp = buff;
    unsigned char reason = 0;

    /* if(sta_found == false)
    {
        reason = 0x02;
    } */

    memcpy(tmp, &reason, sizeof(unsigned char));
    tmp += sizeof(unsigned char);
    len += sizeof(unsigned char);

    memcpy(tmp, sta, sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += sizeof(mac_address_t);

    return len;
}

void em_metrics_t::process_msg(unsigned char *data, unsigned int len)
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
        case em_msg_type_assoc_sta_link_metrics_rsp:
            handle_associated_sta_link_metrics_resp(data, len);
            break;

        case em_msg_type_assoc_sta_link_metrics_query:
            handle_associated_sta_link_metrics_query(data, len);
            break;

        default:
            break;
    }
}

void em_metrics_t::process_ctrl_state()
{
    switch (get_state()) {
        case em_state_ctrl_sta_link_metrics_pending:
            send_all_associated_sta_link_metrics_msg();
            break;
    }
}

em_metrics_t::em_metrics_t()
{

}

em_metrics_t::~em_metrics_t()
{

}
