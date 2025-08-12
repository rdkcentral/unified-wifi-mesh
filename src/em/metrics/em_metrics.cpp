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

    sta_metrics = reinterpret_cast<em_assoc_sta_link_metrics_t *> (buff);

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

    sta_metrics = reinterpret_cast<em_assoc_sta_ext_link_metrics_t *> (buff);

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
    //em_assoc_vendor_link_metrics_t *metrics;
    dm_sta_t *sta = NULL;
    //unsigned int i;
    dm_easy_mesh_t  *dm;

    dm = get_data_model();

    sta_metrics = reinterpret_cast<em_assoc_sta_vendor_link_metrics_t *> (buff);
    /* for (i = 0; i < sta_metrics->num_bssids; i++) {
        metrics = &sta_metrics->assoc_vendor_link_metrics[i];
        sta = dm->find_sta(sta_metrics->sta_mac, sta_metrics->bssid);
        if (sta == NULL) {
            continue;
        }

        sta->m_sta_info.pkts_rx = metrics->packets_received;
        sta->m_sta_info.pkts_tx = metrics->packets_sent;
        sta->m_sta_info.bytes_rx = metrics->bytes_received;
        sta->m_sta_info.bytes_tx = metrics->bytes_sent;
    } */

    sta = dm->find_sta(sta_metrics->sta_mac, sta_metrics->bssid);
    if (sta != NULL) {
        strncpy(sta->m_sta_info.sta_client_type, sta_metrics->sta_client_type, sizeof(sta->m_sta_info.sta_client_type));
    }

    return 0;
}

int em_metrics_t::handle_associated_sta_link_metrics_query(unsigned char *buff, unsigned int len)
{
    mac_address_t sta;
    em_tlv_t *tlv;
    char *errors[EM_MAX_TLV_MEMBERS] = {0};

    if (em_msg_t(em_msg_type_assoc_sta_link_metrics_query, em_profile_type_3, buff, len).validate(errors) == 0) {
        printf("%s:%d:Assoc STA Link Metrics query message validation failed\n",__func__,__LINE__);
        return -1;
    }

    tlv = reinterpret_cast<em_tlv_t *> (buff + sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));

    memcpy(sta, tlv->value, sizeof(mac_address_t));

    send_associated_link_metrics_response(sta);
    set_state(em_state_agent_configured);

    return 0;
}

int em_metrics_t::handle_associated_sta_link_metrics_resp(unsigned char *buff, unsigned int len)
{
    em_tlv_t *tlv, *tlv_start;
    size_t tmp_len, base_len;
    mac_address_t 	sta_mac;
    dm_easy_mesh_t  *dm;
    char *errors[EM_MAX_TLV_MEMBERS] = {0};

    dm = get_data_model();

    if (em_msg_t(em_msg_type_assoc_sta_link_metrics_rsp, get_profile_type(), buff, len).validate(errors) == 0) {
        printf("%s:%d: associated sta link metrics response msg validation failed\n", __func__, __LINE__);
        //return -1;
    }

    tlv_start =  reinterpret_cast<em_tlv_t *> (buff + sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));
    base_len = static_cast<size_t> (len) - (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));

	tlv = tlv_start;
	tmp_len = base_len;

    while ((tlv->type != em_tlv_type_eom) && (tmp_len > 0)) {
        if (tlv->type == em_tlv_type_assoc_sta_link_metric) {
            handle_assoc_sta_link_metrics_tlv(tlv->value);
        }
        tmp_len -= (sizeof(em_tlv_t) + static_cast<size_t> (htons(tlv->len)));
        tlv = reinterpret_cast<em_tlv_t *> (reinterpret_cast<unsigned char *> (tlv) + sizeof(em_tlv_t) + htons(tlv->len));
    }

    tlv = tlv_start;
    tmp_len = base_len;

    while ((tlv->type != em_tlv_type_eom) && (tmp_len > 0)) {
        if (tlv->type == em_tlv_type_error_code) {
            if (tlv->value[0] == 0x01) {
                memcpy(sta_mac, &tlv->value[1], sizeof(mac_address_t));
            } else if (tlv->value[0] == 0x02) {
                memcpy(sta_mac, &tlv->value[1], sizeof(mac_address_t));
            }
            break;
        }

        tmp_len -= (sizeof(em_tlv_t) + static_cast<size_t> (htons(tlv->len)));
        tlv = reinterpret_cast<em_tlv_t *> (reinterpret_cast<unsigned char *> (tlv) + sizeof(em_tlv_t) + htons(tlv->len));
    }

    tlv = tlv_start;
    tmp_len = base_len;

    while ((tlv->type != em_tlv_type_eom) && (tmp_len > 0)) {
        if (tlv->type == em_tlv_type_assoc_sta_ext_link_metric) {
            handle_assoc_sta_ext_link_metrics_tlv(tlv->value);
        }

        tmp_len -= (sizeof(em_tlv_t) + static_cast<size_t> (htons(tlv->len)));
        tlv = reinterpret_cast<em_tlv_t *> (reinterpret_cast<unsigned char *> (tlv) + sizeof(em_tlv_t) + htons(tlv->len));
    }

    tlv = tlv_start;
    tmp_len = base_len;

    while ((tlv->type != em_tlv_type_eom) && (tmp_len > 0)) {
        if (tlv->type == em_tlv_type_vendor_sta_metrics) {
            handle_assoc_sta_vendor_link_metrics_tlv(tlv->value);
        }

        tmp_len -= (sizeof(em_tlv_t) + static_cast<size_t> (htons(tlv->len)));
        tlv = reinterpret_cast<em_tlv_t *> (reinterpret_cast<unsigned char *> (tlv) + sizeof(em_tlv_t) + htons(tlv->len));
    }
    dm->set_db_cfg_param(db_cfg_type_sta_metrics_update, "");
    set_state(em_state_ctrl_configured);

    return 0;
}

int em_metrics_t::handle_beacon_metrics_query(unsigned char *buff, unsigned int len)
{
    mac_address_t sta;
    em_tlv_t *tlv;
    char *errors[EM_MAX_TLV_MEMBERS] = {0};

    if (em_msg_t(em_msg_type_beacon_metrics_query, em_profile_type_2, buff, len).validate(errors) == 0) {
        printf("%s:%d:Beacon Metrics query message validation failed\n",__func__,__LINE__);
        return -1;
    }

    tlv = reinterpret_cast<em_tlv_t *> (buff + sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));

    em_beacon_metrics_query_t *beacon_metrics = reinterpret_cast<em_beacon_metrics_query_t*> (tlv->value);
    printf("\n\n    STA MAC Address: %02x:%02x:%02x:%02x:%02x:%02x\n",
        beacon_metrics->sta_mac_addr[0], beacon_metrics->sta_mac_addr[1], beacon_metrics->sta_mac_addr[2],
        beacon_metrics->sta_mac_addr[3], beacon_metrics->sta_mac_addr[4], beacon_metrics->sta_mac_addr[5]);
    printf("   Operating Class: %u\n", beacon_metrics->op_class);
    printf("   Channel Number: %u\n", beacon_metrics->channel_num);
    printf("   BSSID: %02x:%02x:%02x:%02x:%02x:%02x\n",
        beacon_metrics->bssid[0], beacon_metrics->bssid[1], beacon_metrics->bssid[2],
        beacon_metrics->bssid[3], beacon_metrics->bssid[4], beacon_metrics->bssid[5]);
    printf("   Reporting Detail: %u\n", beacon_metrics->rprt_detail);
    printf("   SSID Length: %u\n", beacon_metrics->ssid_len);
    printf("\n\n");


    memcpy(sta, tlv->value, sizeof(mac_address_t));

    return 0;
}

int em_metrics_t::handle_beacon_metrics_response(unsigned char *buff, unsigned int len)
{
    em_tlv_t *tlv;
    char *errors[EM_MAX_TLV_MEMBERS] = {0};
    unsigned int tmp_len = 0;
    dm_sta_t *sta;
    em_beacon_metrics_resp_t *response = NULL;
    dm_easy_mesh_t  *dm;
    unsigned int report_len = 0;

    dm = get_data_model();

    if (em_msg_t(em_msg_type_beacon_metrics_rsp, em_profile_type_2, buff, len).validate(errors) == 0) {
        printf("%s:%d: Beacon Metrics Response message validation failed\n",__func__,__LINE__);
        return -1;
    }

    tlv = reinterpret_cast<em_tlv_t *> (buff + sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));
    tmp_len = len - static_cast<unsigned int> (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));
    while ((tlv->type != em_tlv_type_eom) && (tmp_len > 0)) {
        if (tlv->type == em_tlv_type_bcon_metric_rsp) {
            report_len = ntohs(tlv->len) - 8;
            response = reinterpret_cast<em_beacon_metrics_resp_t *> (tlv->value);
            break;
        }
        tmp_len -= static_cast<unsigned int> (sizeof(em_tlv_t) + static_cast<size_t> (htons(tlv->len)));
        tlv = reinterpret_cast<em_tlv_t *> (reinterpret_cast<unsigned char *> (tlv) + sizeof(em_tlv_t) + htons(tlv->len));
    }

    sta = dm->get_first_sta(response->sta_mac_addr);
    while (sta != NULL) {
        if (memcmp(sta->m_sta_info.id, response->sta_mac_addr, sizeof(mac_address_t)) == 0) {
            break;
        }
        sta = dm->get_next_sta(response->sta_mac_addr, sta);
    }

    if(sta == NULL)
    {
        printf("%s:%d: sta not found\n", __func__, __LINE__);
        return -1;
    }

    sta->m_sta_info.num_beacon_meas_report = response->meas_rprt_count;
    sta->m_sta_info.beacon_report_len = report_len;
    memcpy(sta->m_sta_info.beacon_report_elem, response->meas_reports, static_cast<size_t> (report_len));

    printf("%s:%d Beacon Metrics Response rcvd\n", __func__, __LINE__);
    printf("%s:%d No of reports %d\n", __func__, __LINE__, sta->m_sta_info.num_beacon_meas_report);
    printf("%s:%d Report len %d\n", __func__, __LINE__, sta->m_sta_info.beacon_report_len);

    //get_data_model()->set_db_cfg_param(db_cfg_type_sta_list_update, "");

    //send_ack(sta);

    return 0;
}

int em_metrics_t::handle_ap_metrics_tlv(unsigned char *buff, bssid_t get_bssid)
{
    em_ap_metric_t *ap_metrics = reinterpret_cast<em_ap_metric_t *> (buff);
    em_bss_info_t *bss = get_data_model()->get_bss_info_with_mac(ap_metrics->bssid);
    mac_addr_str_t bss_str;

    memcpy(get_bssid, ap_metrics->bssid, sizeof(mac_addr_t));
    if (bss != NULL) {
        bss->numberofsta = htons(ap_metrics->num_sta);
        dm_easy_mesh_t::macbytes_to_string(ap_metrics->bssid, bss_str);
        printf("%s:%d Num of stas associated to BSS[%s] is: %d\n", __func__, __LINE__, bss_str, bss->numberofsta);
    } else {
        dm_easy_mesh_t::macbytes_to_string(ap_metrics->bssid, bss_str);
        printf("%s:%d BSS not found: %s\n", __func__, __LINE__, bss_str);
    }

    return 0;
}

int em_metrics_t::handle_assoc_sta_traffic_stats(unsigned char *buff, bssid_t bssid)
{
    em_assoc_sta_traffic_stats_t	*sta_metrics;
    dm_sta_t *sta;
    dm_easy_mesh_t  *dm;
    mac_addr_str_t sta_str;

    dm = get_data_model();
    sta_metrics = reinterpret_cast<em_assoc_sta_traffic_stats_t *> (buff);

    dm_easy_mesh_t::macbytes_to_string(sta_metrics->sta_mac, sta_str);
    sta = dm->find_sta(sta_metrics->sta_mac, bssid);
    if (sta == NULL) {
        printf("%s:%d: sta not found: %s\n", __func__, __LINE__, sta_str);
        return -1;
    }

    sta->m_sta_info.bytes_tx        = sta_metrics->tx_bytes;
    sta->m_sta_info.bytes_rx        = sta_metrics->rx_bytes;
    sta->m_sta_info.pkts_tx         = sta_metrics->tx_pkts;
    sta->m_sta_info.pkts_rx         = sta_metrics->rx_pkts;
    sta->m_sta_info.errors_tx       = sta_metrics->tx_pkt_errors;
    sta->m_sta_info.errors_rx       = sta_metrics->rx_pkt_errors;
    sta->m_sta_info.retrans_count   = sta_metrics->retx_cnt;

    return 0;
}


int em_metrics_t::handle_ap_metrics_response(unsigned char *buff, unsigned int len)
{
    em_tlv_t *tlv, *tlv_start;
    size_t tmp_len, base_len;
    dm_easy_mesh_t  *dm;
    char *errors[EM_MAX_TLV_MEMBERS] = {0};
    bssid_t bssid;

    dm = get_data_model();

    if (em_msg_t(em_msg_type_ap_metrics_rsp, get_profile_type(), buff, len).validate(errors) == 0) {
        printf("%s:%d: AP Metrics metrics response msg validation failed\n", __func__, __LINE__);
        return -1;
    }

    tlv_start =  reinterpret_cast<em_tlv_t *> (buff + sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));
    base_len = static_cast<size_t> (len) - (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));

    tlv = tlv_start;
    tmp_len = base_len;

    while ((tlv->type != em_tlv_type_eom) && (tmp_len > 0)) {
        if (tlv->type == em_tlv_type_ap_metrics) {
            handle_ap_metrics_tlv(tlv->value, bssid);
        }
        tmp_len -= static_cast<unsigned int> (sizeof(em_tlv_t) + static_cast<size_t> (htons(tlv->len)));
        tlv = reinterpret_cast<em_tlv_t *> (reinterpret_cast<unsigned char *> (tlv) + sizeof(em_tlv_t) + htons(tlv->len));
    }

    tlv = tlv_start;
    tmp_len = base_len;

    while ((tlv->type != em_tlv_type_eom) && (tmp_len > 0)) {
        if (tlv->type == em_tlv_type_ap_ext_metric) {
        }
        tmp_len -= (sizeof(em_tlv_t) + static_cast<size_t> (htons(tlv->len)));
        tlv = reinterpret_cast<em_tlv_t *> (reinterpret_cast<unsigned char *> (tlv) + sizeof(em_tlv_t) + htons(tlv->len));
    }

    tlv = tlv_start;
    tmp_len = base_len;

    while ((tlv->type != em_tlv_type_eom) && (tmp_len > 0)) {
        if (tlv->type == em_tlv_type_radio_metric) {
        }
        tmp_len -= (sizeof(em_tlv_t) + static_cast<size_t> (htons(tlv->len)));
        tlv = reinterpret_cast<em_tlv_t *> (reinterpret_cast<unsigned char *> (tlv) + sizeof(em_tlv_t) + htons(tlv->len));
    }

    tlv = tlv_start;
    tmp_len = base_len;

    while ((tlv->type != em_tlv_type_eom) && (tmp_len > 0)) {
        if (tlv->type == em_tlv_type_assoc_sta_traffic_sts) {
            handle_assoc_sta_traffic_stats(tlv->value, bssid);
        }
        tmp_len -= (sizeof(em_tlv_t) + static_cast<size_t> (htons(tlv->len)));
        tlv = reinterpret_cast<em_tlv_t *> (reinterpret_cast<unsigned char *> (tlv) + sizeof(em_tlv_t) + htons(tlv->len));
    }

    tlv = tlv_start;
    tmp_len = base_len;

    while ((tlv->type != em_tlv_type_eom) && (tmp_len > 0)) {
        if (tlv->type == em_tlv_type_assoc_sta_link_metric) {
            handle_assoc_sta_link_metrics_tlv(tlv->value);
        }
        tmp_len -= (sizeof(em_tlv_t) + static_cast<size_t> (htons(tlv->len)));
        tlv = reinterpret_cast<em_tlv_t *> (reinterpret_cast<unsigned char *> (tlv) + sizeof(em_tlv_t) + htons(tlv->len));
    }

    tlv = tlv_start;
    tmp_len = base_len;

    while ((tlv->type != em_tlv_type_eom) && (tmp_len > 0)) {
        if (tlv->type == em_tlv_type_assoc_sta_ext_link_metric) {
            handle_assoc_sta_ext_link_metrics_tlv(tlv->value);
        }
        tmp_len -= (sizeof(em_tlv_t) + static_cast<size_t> (htons(tlv->len)));
        tlv = reinterpret_cast<em_tlv_t *> (reinterpret_cast<unsigned char *> (tlv) + sizeof(em_tlv_t) + htons(tlv->len));
    }

    tlv = tlv_start;
    tmp_len = base_len;

    while ((tlv->type != em_tlv_type_eom) && (tmp_len > 0)) {
        if (tlv->type == em_tlv_type_assoc_wifi6_sta_rprt) {
        }
        tmp_len -= (sizeof(em_tlv_t) + static_cast<size_t> (htons(tlv->len)));
        tlv = reinterpret_cast<em_tlv_t *> (reinterpret_cast<unsigned char *> (tlv) + sizeof(em_tlv_t) + htons(tlv->len));
    }

    tlv = tlv_start;
    tmp_len = base_len;

    while ((tlv->type != em_tlv_type_eom) && (tmp_len > 0)) {
        if (tlv->type == em_tlv_type_vendor_sta_metrics) {
            handle_assoc_sta_vendor_link_metrics_tlv(tlv->value);
        }
        tmp_len -= (sizeof(em_tlv_t) + static_cast<size_t> (htons(tlv->len)));
        tlv = reinterpret_cast<em_tlv_t *> (reinterpret_cast<unsigned char *> (tlv) + sizeof(em_tlv_t) + htons(tlv->len));
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
    size_t len = 0;
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

    memcpy(tmp, reinterpret_cast<unsigned char *> (&type), sizeof(unsigned short));
    tmp += sizeof(unsigned short);
    len += sizeof(unsigned short);

    cmdu = reinterpret_cast<em_cmdu_t *> (tmp);

    memset(tmp, 0, sizeof(em_cmdu_t));
    cmdu->type = htons(msg_id);
    cmdu->id = htons(msg_id);
    cmdu->last_frag_ind = 1;
    cmdu->relay_ind = 0;

    tmp += sizeof(em_cmdu_t);
    len += sizeof(em_cmdu_t);

    // One STA MAC Address Type TLV (see section 17.2.23).
    tlv = reinterpret_cast<em_tlv_t *> (tmp);
    tlv->type = em_tlv_type_sta_mac_addr;
    memcpy(tlv->value, sta_mac, sizeof(mac_address_t));
    tlv->len = htons(sizeof(mac_address_t));

    tmp += (sizeof (em_tlv_t) + sizeof(mac_address_t));
    len += (sizeof (em_tlv_t) + sizeof(mac_address_t));

    // End of message
    tlv = reinterpret_cast<em_tlv_t *> (tmp);
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof(em_tlv_t));
    len += (sizeof(em_tlv_t));

    if (em_msg_t(em_msg_type_assoc_sta_link_metrics_query, em_profile_type_3, buff, static_cast<unsigned int> (len)).validate(errors) == 0) {
        printf("Associated STA Link Metrics Query msg validation failed\n");
        return -1;
    }

    if (send_frame(buff, static_cast<unsigned int> (len))  < 0) {
        printf("%s:%d: Associated STA Link Metrics Query send failed, error:%d\n", __func__, __LINE__, errno);
        return -1;
    }

    printf("%s:%d: Associated STA Link Metrics Query send success\n", __func__, __LINE__);
    return static_cast<int> (len);
}

void em_metrics_t::send_all_associated_sta_link_metrics_msg()
{
    dm_easy_mesh_t *dm;
    dm_sta_t *sta;

    dm = get_data_model();
    sta = static_cast<dm_sta_t *> (hash_map_get_first(dm->m_sta_map));
    while (sta != NULL) {
        if (sta->m_sta_info.associated == true) {
            send_associated_sta_link_metrics_msg(sta->m_sta_info.id);
        }
        sta = static_cast<dm_sta_t *> (hash_map_get_next(dm->m_sta_map, sta));
    }
}

void em_metrics_t::send_associated_sta_link_metrics_resp_msg()
{
    dm_easy_mesh_t *dm;
    dm_sta_t *sta;

    dm = get_current_cmd()->get_data_model();
    sta = static_cast<dm_sta_t *> (hash_map_get_first(dm->m_sta_assoc_map));
    while (sta != NULL) {
        send_associated_link_metrics_response(sta->m_sta_info.id);
        sta = static_cast<dm_sta_t *> (hash_map_get_next(dm->m_sta_assoc_map, sta));
    }
    set_state(em_state_agent_configured);
}

int em_metrics_t::send_associated_link_metrics_response(mac_address_t sta_mac)
{
    unsigned char buff[MAX_EM_BUFF_SZ];
    char *errors[EM_MAX_TLV_MEMBERS] = {0};
    unsigned short  msg_type = em_msg_type_assoc_sta_link_metrics_rsp;
    size_t len = 0;
    em_cmdu_t *cmdu;
    em_tlv_t *tlv;
    unsigned char *tmp = buff;
    short sz = 0;
    unsigned short type = htons(ETH_P_1905);
    dm_easy_mesh_t *dm = get_data_model();
    mac_addr_str_t mac_str;
    bool sta_found = false;
    dm_sta_t *sta;

    sta = reinterpret_cast<dm_sta_t *> (hash_map_get_first(dm->m_sta_map));
    while(sta != NULL) {
        if (memcmp(sta->m_sta_info.id, sta_mac, sizeof(mac_address_t)) == 0) {
            sta_found = true;
            break;
        }
        sta = reinterpret_cast<dm_sta_t *> (hash_map_get_next(dm->m_sta_map, sta));
    }

    if (sta == NULL) {
        //TODO: Have to fix Failed TLV while sending empty frame with error code
        return -1;
    }

    short msg_id = em_msg_type_assoc_sta_link_metrics_rsp;

    dm_easy_mesh_t::macbytes_to_string(sta_mac, mac_str);

    memcpy(tmp, dm->get_ctl_mac(), sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += sizeof(mac_address_t);

    memcpy(tmp, dm->get_agent_al_interface_mac(), sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += sizeof(mac_address_t);

    memcpy(tmp, reinterpret_cast<unsigned char *> (&type), sizeof(unsigned short));
    tmp += sizeof(unsigned short);
    len += sizeof(unsigned short);

    cmdu = reinterpret_cast<em_cmdu_t *> (tmp);

    memset(tmp, 0, sizeof(em_cmdu_t));
    cmdu->type = htons(msg_type);
    cmdu->id = htons(static_cast<uint16_t> (msg_id));
    cmdu->last_frag_ind = 1;

    tmp += sizeof(em_cmdu_t);
    len += sizeof(em_cmdu_t);

    //Assoc sta link metrics 17.2.24
    tlv = reinterpret_cast<em_tlv_t *> (tmp);
    tlv->type = em_tlv_type_assoc_sta_link_metric;
    sz = create_assoc_sta_link_metrics_tlv(tlv->value, sta_mac, sta);
    tlv->len = htons(static_cast<short unsigned int> (sz));

    tmp += (sizeof(em_tlv_t) + static_cast<size_t> (sz));
    len += (sizeof(em_tlv_t) + static_cast<size_t> (sz));

    //Error code  TLV 17.2.36
    tlv = reinterpret_cast<em_tlv_t *> (tmp);
    tlv->type = em_tlv_type_error_code;
    sz = create_error_code_tlv(tlv->value, sta_mac, sta_found);
    tlv->len = htons(static_cast<short unsigned int> (sz));

    tmp += (sizeof(em_tlv_t) + static_cast<size_t> (sz));
    len += (sizeof(em_tlv_t) + static_cast<size_t> (sz));

    //assoc ext link metrics 17.2.62
    tlv = reinterpret_cast<em_tlv_t *> (tmp);
    tlv->type = em_tlv_type_assoc_sta_ext_link_metric;
    sz = create_assoc_ext_sta_link_metrics_tlv(tlv->value, sta_mac, sta);
    tlv->len = htons(static_cast<short unsigned int> (sz));

    tmp += (sizeof(em_tlv_t) + static_cast<size_t> (sz));
    len += (sizeof(em_tlv_t) + static_cast<size_t> (sz));

    //assoc vendor link metrics
    tlv = reinterpret_cast<em_tlv_t *> (tmp);
    tlv->type = em_tlv_type_vendor_sta_metrics;
    sz = create_assoc_vendor_sta_link_metrics_tlv(tlv->value, sta_mac, sta);
    tlv->len = htons(static_cast<short unsigned int> (sz));

    tmp += (sizeof(em_tlv_t) + static_cast<size_t> (sz));
    len += (sizeof(em_tlv_t) + static_cast<size_t> (sz));

    // End of message
    tlv = reinterpret_cast<em_tlv_t *> (tmp);
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += (sizeof (em_tlv_t));

    if (em_msg_t(em_msg_type_assoc_sta_link_metrics_rsp, em_profile_type_3, buff, static_cast<unsigned int> (len)).validate(errors) == 0) {
        printf("%s:%d: Associated STA Link Metrics validation failed for %s\n", __func__, __LINE__, mac_str);
        return -1;
    }

    if (send_frame(buff, static_cast<unsigned int> (len))  < 0) {
        printf("%s:%d: Associated STA Link Metrics  send failed, error:%d\n", __func__, __LINE__, errno);
        return -1;
    }
    printf("%s:%d: Associated STA Link Metrics for sta %s sent successfully\n", __func__, __LINE__, mac_str);

    return static_cast<int> (len);
}

short em_metrics_t::send_beacon_metrics_query(mac_address_t sta_mac, bssid_t bssid)
{
    unsigned char buff[MAX_EM_BUFF_SZ];
    char *errors[EM_MAX_TLV_MEMBERS] = {0};
    unsigned short  msg_id = em_msg_type_beacon_metrics_query;
    short sz = 0;
	size_t len = 0;
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

    memcpy(tmp, reinterpret_cast<unsigned char *> (&type), sizeof(unsigned short));
    tmp += sizeof(unsigned short);
    len += sizeof(unsigned short);

    cmdu = reinterpret_cast<em_cmdu_t *> (tmp);

    memset(tmp, 0, sizeof(em_cmdu_t));
    cmdu->type = htons(msg_id);
    cmdu->id = htons(msg_id);
    cmdu->last_frag_ind = 1;
    cmdu->relay_ind = 0;

    tmp += sizeof(em_cmdu_t);
    len += sizeof(em_cmdu_t);

    //Beacon Metrics Query TLV (see section 17.2.27).
    tlv = reinterpret_cast<em_tlv_t *> (tmp);
    tlv->type = em_tlv_type_bcon_metric_query;
    sz = create_beacon_metrics_query_tlv(tlv->value, sta_mac, bssid);
    tlv->len = htons(static_cast<short unsigned int> (sz));

    tmp += (sizeof (em_tlv_t) + static_cast<size_t> (sz));
    len += (sizeof (em_tlv_t) + static_cast<size_t> (sz));

    // End of message
    tlv = reinterpret_cast<em_tlv_t *> (tmp);
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += (sizeof (em_tlv_t));

    if (em_msg_t(em_msg_type_beacon_metrics_query, em_profile_type_2, buff, static_cast<unsigned int> (len)).validate(errors) == 0) {
        printf("Beacon Metrics Query msg validation failed\n");
        return -1;
    }

    if (send_frame(buff, static_cast<unsigned int> (len))  < 0) {
        printf("%s:%d: Beacon Metrics Query send failed, error:%d\n", __func__, __LINE__, errno);
        return -1;
    }

    printf("%s:%d: Beacon Metrics Query send success\n", __func__, __LINE__);
    return static_cast<short> (len);
}

int em_metrics_t::send_beacon_metrics_response()
{
    unsigned char buff[MAX_EM_BUFF_SZ];
    char *errors[EM_MAX_TLV_MEMBERS] = {0};
    unsigned short  msg_type = em_msg_type_beacon_metrics_rsp;
    size_t len = 0;
    em_cmdu_t *cmdu;
    em_tlv_t *tlv;
    unsigned char *tmp = buff;
    short sz = 0;
    unsigned short type = htons(ETH_P_1905);
    dm_easy_mesh_t *dm = get_data_model();
    mac_addr_str_t mac_str;
    bool sta_found = false;
    dm_sta_t *sta;

    sta = reinterpret_cast<dm_sta_t *> (hash_map_get_first(get_current_cmd()->get_data_model()->m_sta_map));

    short msg_id = em_msg_type_beacon_metrics_rsp;

    memcpy(tmp, dm->get_ctl_mac(), sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += sizeof(mac_address_t);

    memcpy(tmp, dm->get_agent_al_interface_mac(), sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += sizeof(mac_address_t);

    memcpy(tmp, reinterpret_cast<unsigned char *> (&type), sizeof(unsigned short));
    tmp += sizeof(unsigned short);
    len += sizeof(unsigned short);

    cmdu = reinterpret_cast<em_cmdu_t *> (tmp);

    memset(tmp, 0, sizeof(em_cmdu_t));
    cmdu->type = htons(msg_type);
    cmdu->id = htons(static_cast<uint16_t> (msg_id));
    cmdu->last_frag_ind = 1;

    tmp += sizeof(em_cmdu_t);
    len += sizeof(em_cmdu_t);

    //Beacon Metrics Response 17.1.23
    tlv = reinterpret_cast<em_tlv_t *> (tmp);
    tlv->type = em_tlv_type_bcon_metric_rsp;
    sz = create_beacon_metrics_response_tlv(tlv->value);
    tlv->len =  htons(static_cast<short unsigned int> (sz));

    tmp += (sizeof(em_tlv_t) + static_cast<size_t> (sz));
    len += (sizeof(em_tlv_t) + static_cast<size_t> (sz));

    //Error code  TLV 17.2.36
    tlv = reinterpret_cast<em_tlv_t *> (tmp);
    tlv->type = em_tlv_type_error_code;
    sz = create_error_code_tlv(tlv->value, sta->m_sta_info.id, sta_found);
    tlv->len = htons(static_cast<short unsigned int> (sz));

    tmp += (sizeof(em_tlv_t) + static_cast<size_t> (sz));
    len += (sizeof(em_tlv_t) + static_cast<size_t> (sz));

    // End of message
    tlv = reinterpret_cast<em_tlv_t *> (tmp);
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof(em_tlv_t));
    len += (sizeof(em_tlv_t));

    if (em_msg_t(em_msg_type_beacon_metrics_rsp, em_profile_type_2, buff, static_cast<unsigned int> (len)).validate(errors) == 0) {
        printf("%s:%d: Beacon Metrics Response validation failed for %s\n", __func__, __LINE__, mac_str);
        return -1;
    }

    if (send_frame(buff, static_cast<unsigned int> (len))  < 0) {
        printf("%s:%d: Beacon Metrics Response send failed, error:%d\n", __func__, __LINE__, errno);
        return -1;
    }

    printf("%s:%d: Beacon Metrics Response send success\n", __func__, __LINE__);

    return static_cast<int> (len);
}

int em_metrics_t::send_ap_metrics_response()
{
    unsigned char buff[MAX_EM_BUFF_SZ] = {0};
    char *errors[EM_MAX_TLV_MEMBERS] = {0};
    unsigned short  msg_type = em_msg_type_ap_metrics_rsp;
    size_t len = 0;
    em_cmdu_t *cmdu;
    em_tlv_t *tlv;
    unsigned char *tmp = buff;
    short sz = 0;
    unsigned short type = htons(ETH_P_1905);
    dm_easy_mesh_t *dm = get_data_model();
    mac_addr_str_t mac_str;
    dm_sta_t *sta;
    short msg_id = em_msg_type_ap_metrics_rsp;
    int bss_index = 0;

    memcpy(tmp, dm->get_ctl_mac(), sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += sizeof(mac_address_t);

    memcpy(tmp, dm->get_agent_al_interface_mac(), sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += sizeof(mac_address_t);

    memcpy(tmp, reinterpret_cast<unsigned char *> (&type), sizeof(unsigned short));
    tmp += sizeof(unsigned short);
    len += sizeof(unsigned short);

    cmdu = reinterpret_cast<em_cmdu_t *> (tmp);

    memset(tmp, 0, sizeof(em_cmdu_t));
    cmdu->type = htons(msg_type);
    cmdu->id = htons(static_cast<uint16_t> (msg_id));
    cmdu->last_frag_ind = 1;

    tmp += sizeof(em_cmdu_t);
    len += sizeof(em_cmdu_t);

    //AP Metrics Response 17.1.17
    //AP Metrics TLV (17.2.22)
    for (bss_index = 0; bss_index < static_cast<int>(dm->m_num_bss); bss_index++) {
        if (memcmp(dm->m_bss[bss_index].m_bss_info.ruid.mac,
            get_current_cmd()->get_param()->u.ap_metrics_params.ruid, sizeof(mac_addr_t)) != 0) {
            continue;
        }

        tlv = reinterpret_cast<em_tlv_t *> (tmp);
        tlv->type = em_tlv_type_ap_metrics;
        sz = create_ap_metrics_tlv(tlv->value, dm->m_bss[bss_index]);
        tlv->len =  htons(static_cast<unsigned short> (sz));

        tmp += (sizeof(em_tlv_t) + static_cast<size_t> (sz));
        len += (sizeof(em_tlv_t) + static_cast<size_t> (sz));

        //AP Extended Metrics TLV (17.2.61)
        tlv = reinterpret_cast<em_tlv_t *> (tmp);
        tlv->type = em_tlv_type_ap_ext_metric;
        sz = create_ap_ext_metrics_tlv(tlv->value, dm->m_bss[bss_index]);
        tlv->len =  htons(static_cast<unsigned short> (sz));

        tmp += (sizeof(em_tlv_t) + static_cast<size_t> (sz));
        len += (sizeof(em_tlv_t) + static_cast<size_t> (sz));

        //Radio Metrics TLV (17.2.60)
        tlv = reinterpret_cast<em_tlv_t *> (tmp);
        tlv->type = em_tlv_type_radio_metric;
        sz = create_radio_metrics_tlv(tlv->value);
        tlv->len =  htons(static_cast<unsigned short> (sz));

        tmp += (sizeof(em_tlv_t) + static_cast<size_t> (sz));
        len += (sizeof(em_tlv_t) + static_cast<size_t> (sz));

        //now search if this sta is associated to this
        sta = reinterpret_cast<dm_sta_t *> (hash_map_get_first(dm->m_sta_map));
        while(sta != NULL) {
            if (memcmp(sta->get_sta_info()->bssid, dm->m_bss[bss_index].m_bss_info.bssid.mac, sizeof(mac_address_t)) != 0) {
                sta = static_cast<dm_sta_t *>(hash_map_get_next(dm->m_sta_map, sta));
                continue;
            }
            //Associated STA Traffic Stats TLV (17.2.35)
            tlv = reinterpret_cast<em_tlv_t *> (tmp);
            tlv->type = em_tlv_type_assoc_sta_traffic_sts;
            sz = create_assoc_sta_traffic_stats_tlv(tlv->value, sta);
            tlv->len =  htons(static_cast<unsigned short> (sz));

            tmp += (sizeof(em_tlv_t) + static_cast<size_t> (sz));
            len += (sizeof(em_tlv_t) + static_cast<size_t> (sz));

            //Associated STA Link Metrics TLV (17.2.24).
            tlv = reinterpret_cast<em_tlv_t *> (tmp);
            tlv->type = em_tlv_type_assoc_sta_link_metric;
            sz = create_assoc_sta_link_metrics_tlv(tlv->value, sta->m_sta_info.id, sta);
            tlv->len =  htons(static_cast<unsigned short> (sz));

            tmp += (sizeof(em_tlv_t) + static_cast<size_t> (sz));
            len += (sizeof(em_tlv_t) + static_cast<size_t> (sz));

            //Associated STA Extended Link Metrics TLV (17.2.62)
            tlv = reinterpret_cast<em_tlv_t *> (tmp);
            tlv->type = em_tlv_type_assoc_sta_ext_link_metric;
            sz = create_assoc_ext_sta_link_metrics_tlv(tlv->value, sta->m_sta_info.id, sta);
            tlv->len =  htons(static_cast<unsigned short> (sz));

            tmp += (sizeof(em_tlv_t) + static_cast<size_t> (sz));
            len += (sizeof(em_tlv_t) + static_cast<size_t> (sz));

            //Associated Wi-Fi 6 STA Status Report TLV (17.2.73)
            //Profile-3 msg, hence failing even though optional
            tlv = reinterpret_cast<em_tlv_t *> (tmp);
            tlv->type = em_tlv_type_assoc_wifi6_sta_rprt;
            sz = create_assoc_wifi6_sta_sta_report_tlv(tlv->value, sta);
            tlv->len =  htons(static_cast<unsigned short> (sz));

            tmp += (sizeof(em_tlv_t) + static_cast<size_t> (sz));
            len += (sizeof(em_tlv_t) + static_cast<size_t> (sz));

            //assoc vendor link metrics
            tlv = reinterpret_cast<em_tlv_t *> (tmp);
            tlv->type = em_tlv_type_vendor_sta_metrics;
            sz = create_assoc_vendor_sta_link_metrics_tlv(tlv->value, sta->m_sta_info.id, sta);
            tlv->len = htons(static_cast<short unsigned int> (sz));

            tmp += (sizeof(em_tlv_t) + static_cast<size_t> (sz));
            len += (sizeof(em_tlv_t) + static_cast<size_t> (sz));

            sta = reinterpret_cast<dm_sta_t *> (hash_map_get_next(dm->m_sta_map, sta));
        }
    }

    // End of message
    tlv = reinterpret_cast<em_tlv_t *> (tmp);
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof(em_tlv_t));
    len += (sizeof(em_tlv_t));

    if (em_msg_t(em_msg_type_ap_metrics_rsp, em_profile_type_2, buff, static_cast<unsigned int> (len)).validate(errors) == 0) {
        printf("%s:%d: AP Metrics Response validation failed for %s\n", __func__, __LINE__, mac_str);
        //return -1;
    }

    if (send_frame(buff, static_cast<unsigned int> (len))  < 0) {
        printf("%s:%d: AP Metrics Response send failed, error:%d\n", __func__, __LINE__, errno);
        return -1;
    }

    printf("%s:%d: AP Metrics Response send success\n", __func__, __LINE__);

    set_state(em_state_agent_configured);

    return static_cast<int> (len);
}

short em_metrics_t::create_assoc_sta_link_metrics_tlv(unsigned char *buff, mac_address_t sta_mac, const dm_sta_t *const sta)
{
    size_t len = 0;
    dm_easy_mesh_t *dm;
    int num_bssids = 0;
    em_assoc_sta_link_metrics_t *assoc_sta_metrics = reinterpret_cast<em_assoc_sta_link_metrics_t*> (buff);
    em_assoc_link_metrics_t *metrics;

    dm = get_data_model();
    num_bssids = dm->get_num_bss_for_associated_sta(sta_mac);

    if (sta == NULL) {
        memcpy(&assoc_sta_metrics->sta_mac, &sta_mac, sizeof(assoc_sta_metrics->sta_mac));
        len += sizeof(assoc_sta_metrics->sta_mac);

        assoc_sta_metrics->num_bssids = 0;
        len += sizeof(assoc_sta_metrics->num_bssids);
        return static_cast<short> (len);
    }
    else {
        metrics	= &assoc_sta_metrics->assoc_link_metrics[0];
        if ((memcmp(sta->m_sta_info.id, sta_mac, sizeof(mac_address_t)) == 0)) {
            memcpy(&assoc_sta_metrics->sta_mac, &sta->m_sta_info.id, sizeof(assoc_sta_metrics->sta_mac));
            len += sizeof(assoc_sta_metrics->sta_mac);

            assoc_sta_metrics->num_bssids = static_cast<unsigned char> (num_bssids);
            len += sizeof(assoc_sta_metrics->num_bssids);

            memcpy(&metrics->bssid, &sta->m_sta_info.bssid, sizeof(metrics->bssid));
            len += sizeof(metrics->bssid);

            metrics->time_delta_ms = 10;//TODO: Pending proper update
            len += sizeof(metrics->time_delta_ms);

            metrics->est_mac_data_rate_dl = sta->m_sta_info.est_dl_rate;
            len += sizeof(metrics->est_mac_data_rate_dl);

            metrics->est_mac_data_rate_ul = sta->m_sta_info.est_ul_rate;
            len += sizeof(metrics->est_mac_data_rate_ul);

            metrics->rcpi = sta->m_sta_info.rcpi;
            len += sizeof(metrics->rcpi);
        }
    }
    return static_cast<short> (len);
}

short em_metrics_t::create_assoc_ext_sta_link_metrics_tlv(unsigned char *buff, mac_address_t sta_mac, const dm_sta_t *const sta)
{
    size_t len = 0;
    dm_easy_mesh_t *dm;
    em_assoc_sta_ext_link_metrics_t *assoc_sta_metrics = reinterpret_cast<em_assoc_sta_ext_link_metrics_t*> (buff);
    em_assoc_ext_link_metrics_t *metrics;

    dm = get_data_model();

    if (sta == NULL) {
        memcpy(&assoc_sta_metrics->sta_mac, &sta_mac, sizeof(assoc_sta_metrics->sta_mac));
        len += sizeof(assoc_sta_metrics->sta_mac);

        assoc_sta_metrics->num_bssids = 0;
        len += sizeof(assoc_sta_metrics->num_bssids);
        return static_cast<short> (len);
    }
    else {
        metrics	= &assoc_sta_metrics->assoc_ext_link_metrics[0];
        if ((memcmp(sta->m_sta_info.id, sta_mac, sizeof(mac_address_t)) == 0)) {
            memcpy(assoc_sta_metrics->sta_mac, sta->m_sta_info.id, sizeof(assoc_sta_metrics->sta_mac));
            len += sizeof(assoc_sta_metrics->sta_mac);

            assoc_sta_metrics->num_bssids = static_cast<unsigned char> (dm->get_num_bss_for_associated_sta(sta_mac));
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
    return static_cast<short> (len);
}

short em_metrics_t::create_assoc_vendor_sta_link_metrics_tlv(unsigned char *buff, mac_address_t sta_mac, const dm_sta_t *const sta)
{
    size_t len = 0;
    em_assoc_sta_vendor_link_metrics_t *assoc_sta_metrics = reinterpret_cast<em_assoc_sta_vendor_link_metrics_t*> (buff);
    //em_assoc_vendor_link_metrics_t *metrics;

    if (sta == NULL) {
        memcpy(&assoc_sta_metrics->sta_mac, &sta_mac, sizeof(assoc_sta_metrics->sta_mac));
        len += sizeof(assoc_sta_metrics->sta_mac);

        /*assoc_sta_metrics->num_bssids = 0;
        len += sizeof(assoc_sta_metrics->num_bssids);*/
        return static_cast<short> (len);
    }
    else {
        //metrics = &assoc_sta_metrics->assoc_vendor_link_metrics[0];
        if ((memcmp(sta->m_sta_info.id, sta_mac, sizeof(mac_address_t)) == 0)) {
            memcpy(assoc_sta_metrics->sta_mac, sta->m_sta_info.id, sizeof(assoc_sta_metrics->sta_mac));
            len += sizeof(assoc_sta_metrics->sta_mac);

            memcpy(&assoc_sta_metrics->bssid, sta->m_sta_info.bssid, sizeof(bssid_t));
            len += sizeof(bssid_t);

            strncpy(assoc_sta_metrics->sta_client_type, sta->m_sta_info.sta_client_type, sizeof(assoc_sta_metrics->sta_client_type));
            len += sizeof(assoc_sta_metrics->sta_client_type);

            /*assoc_sta_metrics->num_bssids = static_cast<unsigned char> (dm->get_num_bss_for_associated_sta(sta_mac));
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
            len += sizeof(metrics->bytes_sent);*/
        }
    }
    return static_cast<short> (len);
}

short em_metrics_t::create_beacon_metrics_query_tlv(unsigned char *buff, mac_address_t sta_mac, bssid_t bssid)
{
    size_t len = 0;
    dm_easy_mesh_t *dm;
    ssid_t ssid;
    dm_sta_t *sta;
    unsigned int j;
    unsigned char ap_channel_list[] = {1, 6, 11};
    
	dm = get_data_model();

    sta = reinterpret_cast<dm_sta_t *> (hash_map_get_first(dm->m_sta_map));
    while(sta != NULL) {
        if (memcmp(sta->m_sta_info.id, sta_mac, sizeof(mac_address_t)) == 0) {
            break;
        }
        sta = reinterpret_cast<dm_sta_t *> (hash_map_get_next(dm->m_sta_map, sta));
    }

    for (j = 0; j < dm->get_num_bss(); j++) {
        if (memcmp(&dm->m_bss[j].m_bss_info.bssid, sta->m_sta_info.bssid, sizeof(bssid_t)) != 0) {
            snprintf(ssid, sizeof(ssid_t), "%s", dm->m_bss[j].m_bss_info.ssid);
            break;
        }
    }


    em_beacon_metrics_query_t *beacon_metrics = reinterpret_cast<em_beacon_metrics_query_t*> (buff);

    if (sta == NULL) {

    }
    else {

        memcpy(beacon_metrics->sta_mac_addr, sta_mac, sizeof(mac_addr_t));
        len += sizeof(beacon_metrics->sta_mac_addr);

        beacon_metrics->op_class = 10;
        len += sizeof(beacon_metrics->op_class);

        beacon_metrics->channel_num = 6;
        len += sizeof(beacon_metrics->channel_num);

        memcpy(beacon_metrics->bssid, bssid, sizeof(bssid_t));
        len += sizeof(beacon_metrics->bssid);

        beacon_metrics-> rprt_detail = 1;
        len += sizeof(beacon_metrics-> rprt_detail);

        beacon_metrics->ssid_len = sizeof(ssid);
        len += sizeof(beacon_metrics->ssid_len);

        memcpy(beacon_metrics->ssid, ssid, sizeof(ssid));
        len += sizeof(ssid);

        beacon_metrics->num_ap_channel_rprt = 2;
        len += sizeof(beacon_metrics->num_ap_channel_rprt);

        em_beacon_ap_channel_rprt_t *ap_chann_rprt;// = buff + len;

        for (int i = 0; i < beacon_metrics->num_ap_channel_rprt; i++) {
            ap_chann_rprt = reinterpret_cast<em_beacon_ap_channel_rprt_t *> (buff + len);
            ap_chann_rprt->ap_channel_rprt_len = 4;
            len += sizeof(ap_chann_rprt->ap_channel_rprt_len);

            ap_chann_rprt->ap_channel_op_class = 10;
            len += sizeof(ap_chann_rprt->ap_channel_op_class);

            for(int j = 0; j < ap_chann_rprt->ap_channel_rprt_len - 1; j++) {
                ap_chann_rprt->ap_channel_list[j] = ap_channel_list[j];
                len += sizeof(unsigned char);
            }
        }
    }

    // Print the filled data
    printf("STA MAC Address: %02x:%02x:%02x:%02x:%02x:%02x\n",
           beacon_metrics->sta_mac_addr[0], beacon_metrics->sta_mac_addr[1], beacon_metrics->sta_mac_addr[2],
           beacon_metrics->sta_mac_addr[3], beacon_metrics->sta_mac_addr[4], beacon_metrics->sta_mac_addr[5]);
    printf("Operating Class: %u\n", beacon_metrics->op_class);
    printf("Channel Number: %u\n", beacon_metrics->channel_num);
    mac_addr_str_t mac_str;
    dm_easy_mesh_t::macbytes_to_string(beacon_metrics->bssid, mac_str);
    printf("BSSID: %s\n", mac_str);
    printf("Reporting Detail: %u\n", beacon_metrics->rprt_detail);
    printf("SSID Length: %u\n", beacon_metrics->ssid_len);
    printf("SSID: %s\n", beacon_metrics->ssid);
    printf("Number of AP Channel Reports: %u\n", beacon_metrics->num_ap_channel_rprt);

    return static_cast<short> (len);
}

short em_metrics_t::create_beacon_metrics_response_tlv(unsigned char *buff)
{
    size_t len = 0;
    dm_easy_mesh_t *dm;
    em_beacon_metrics_resp_t *response = reinterpret_cast<em_beacon_metrics_resp_t *> (buff);

    dm = get_current_cmd()->get_data_model();
    dm_sta_t *sta;
    sta = reinterpret_cast<dm_sta_t *> (hash_map_get_first(dm->m_sta_map));
    if (sta != NULL) {
        memcpy(response->sta_mac_addr, sta->m_sta_info.id, sizeof(mac_addr_t));
        len += sizeof(response->sta_mac_addr);

        response->reserved = 0;
        len += sizeof(response->reserved);

        response->meas_rprt_count = static_cast<unsigned char> (sta->m_sta_info.num_beacon_meas_report);
        len += sizeof(response->meas_rprt_count);

        memcpy(response->meas_reports, sta->m_sta_info.beacon_report_elem, sta->m_sta_info.beacon_report_len);
        len += sta->m_sta_info.beacon_report_len;
    }

    return static_cast<short> (len);
}

short em_metrics_t::create_ap_metrics_tlv(unsigned char *buff, dm_bss_t &dm_bss)
{
    size_t len = 0;
    mac_addr_str_t rad_str, bss_str;
    em_ap_metric_t *ap_metrics = reinterpret_cast<em_ap_metric_t *> (buff);

    dm_easy_mesh_t::macbytes_to_string(dm_bss.m_bss_info.ruid.mac, rad_str);
    if (memcmp(dm_bss.m_bss_info.ruid.mac, 
        get_current_cmd()->get_param()->u.ap_metrics_params.ruid, sizeof(mac_addr_t)) == 0) {
        dm_easy_mesh_t::macbytes_to_string(dm_bss.m_bss_info.bssid.mac, bss_str);
        printf("%s:%d Creating ap response for bssid: %s\n", __func__, __LINE__, bss_str);

        memcpy(ap_metrics->bssid, dm_bss.m_bss_info.bssid.mac, sizeof(mac_address_t));
        len += static_cast<size_t> (sizeof(mac_address_t));

        ap_metrics->channel_util = static_cast<unsigned char>(dm_bss.m_bss_info.numberofsta);
        len += static_cast<size_t> (sizeof(unsigned char));

        ap_metrics->num_sta = htons(static_cast<uint16_t>(dm_bss.m_bss_info.numberofsta));
        len += static_cast<size_t> (sizeof(unsigned short));

        ap_metrics->est_service_params_BE_bit = 1;
        len += static_cast<size_t> (sizeof(unsigned char));

        for(int i = 0; i < static_cast<int>(sizeof(ap_metrics->est_service_params_BE)); i++) {
            ap_metrics->est_service_params_BE[i] = 0;
            len += static_cast<size_t> (sizeof(unsigned char));
        }
    }

    return static_cast<short> (len);
}

short em_metrics_t::create_ap_ext_metrics_tlv(unsigned char *buff, dm_bss_t &dm_bss)
{
    size_t len = 0;
    mac_addr_str_t rad_str;
    em_ap_ext_metric_t *ap_ext_metrics = reinterpret_cast<em_ap_ext_metric_t *> (buff);

    dm_easy_mesh_t::macbytes_to_string(dm_bss.m_bss_info.ruid.mac, rad_str);
    if (memcmp(dm_bss.m_bss_info.ruid.mac,
        get_current_cmd()->get_param()->u.ap_metrics_params.ruid, sizeof(mac_addr_t)) == 0) {
        memcpy(ap_ext_metrics->bssid, dm_bss.m_bss_info.bssid.mac, sizeof(mac_address_t));
    }

    len = static_cast<size_t> (sizeof(em_ap_ext_metric_t));

    return static_cast<short> (len);
}

short em_metrics_t::create_radio_metrics_tlv(unsigned char *buff)
{
    size_t len = 0;
    dm_easy_mesh_t *dm = get_data_model();
    em_radio_metric_t *radio_metric = reinterpret_cast<em_radio_metric_t *> (buff);
    dm_radio_t *radio = NULL;

    radio = dm->get_radio(get_current_cmd()->get_param()->u.ap_metrics_params.ruid);
    memcpy(radio_metric->ruid, radio->get_radio_info()->intf.mac, sizeof(mac_address_t));

    len = static_cast<size_t> (sizeof(em_radio_metric_t));

    return static_cast<short> (len);
}

short em_metrics_t::create_assoc_sta_traffic_stats_tlv(unsigned char *buff, const dm_sta_t *const sta)
{
    size_t len = 0;
    em_assoc_sta_traffic_sts_t *response = reinterpret_cast<em_assoc_sta_traffic_sts_t *> (buff);

    if (sta != NULL) {
        memcpy(response->sta_mac_addr, sta->m_sta_info.id, sizeof(mac_addr_t));
        len += sizeof(response->sta_mac_addr);

        response->bytes_sent = sta->m_sta_info.bytes_tx;
        len += sizeof(response->bytes_sent);

        response->bytes_recv = sta->m_sta_info.bytes_rx;
        len += sizeof(response->bytes_recv);

        response->packets_sent = sta->m_sta_info.pkts_tx;
        len += sizeof(response->packets_sent);

        response->packets_recv = sta->m_sta_info.pkts_rx;
        len += sizeof(response->packets_recv);

        response->tx_packets_errors = sta->m_sta_info.errors_tx;
        len += sizeof(response->tx_packets_errors);

        response->rx_packets_errors = sta->m_sta_info.errors_rx;
        len += sizeof(response->rx_packets_errors);

        response->retrans_count = sta->m_sta_info.retrans_count;
        len += sizeof(response->retrans_count);
    }

    return static_cast<short> (len);
}

short em_metrics_t::create_assoc_wifi6_sta_sta_report_tlv(unsigned char *buff, const dm_sta_t *const sta)
{
    size_t len = 0;

    len = static_cast<size_t> (sizeof(em_assoc_wifi6_sta_sts_t));

    return static_cast<short> (len);
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
    len += static_cast<short> (sizeof(unsigned char));

    memcpy(tmp, sta, sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += static_cast<short> (sizeof(mac_address_t));

    return len;
}

void em_metrics_t::process_msg(unsigned char *data, unsigned int len)
{
    em_cmdu_t *cmdu;
    cmdu = reinterpret_cast<em_cmdu_t *> (data + sizeof(em_raw_hdr_t));

    switch (htons(cmdu->type)) {
        case em_msg_type_assoc_sta_link_metrics_rsp:
            handle_associated_sta_link_metrics_resp(data, len);
            break;

        case em_msg_type_assoc_sta_link_metrics_query:
            handle_associated_sta_link_metrics_query(data, len);
            break;

        case em_msg_type_beacon_metrics_query:
            handle_beacon_metrics_query(data, len);
            break;

        case em_msg_type_beacon_metrics_rsp:
            handle_beacon_metrics_response(data, len);
            break;

        case em_msg_type_ap_metrics_rsp:
            handle_ap_metrics_response(data, len);
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
        default:
            printf("%s:%d: unhandled case %s\n", __func__, __LINE__, em_t::state_2_str(get_state()));
            break;
    }
}

void em_metrics_t::process_agent_state()
{
    switch (get_state()) {
        case em_state_agent_sta_link_metrics_pending:
            send_associated_sta_link_metrics_resp_msg();
            break;

        case em_state_agent_beacon_report_pending:
            send_beacon_metrics_response();
            break;

        case em_state_agent_ap_metrics_pending:
            send_ap_metrics_response();
            break;

        default:
            break;
    }
}

em_metrics_t::em_metrics_t()
{

}

em_metrics_t::~em_metrics_t()
{

}
