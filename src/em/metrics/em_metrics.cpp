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
#include <algorithm>
#include "em_metrics.h"
#include "em_msg.h"
#include "dm_easy_mesh.h"
#include "em_cmd.h"
#include "util.h"
#include "em.h"
#include "em_cmd_exec.h"

static     const unsigned char em_vendor_oui[EM_VENDOR_OUI_SIZE] = {0xd8, 0x9c, 0x8e};

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

        // RCPI-based beacon query trigger: if STA supports 802.11k beacon measurement
        // and its RCPI is below the configured steering threshold, request a beacon report.
        if (sta->m_sta_info.rcpi == 0 || !sta->m_sta_info.associated) {
            continue;
        }
        // Skip only if rm_cap is explicitly present and shows no beacon measurement support.
        // If rm_cap is empty (e.g. MLD clients where IE parsing may miss it), allow the query —
        // the agent will send the request and we'll find out from the response.
        if (sta->m_sta_info.rm_cap[0] != '\0' &&
            !sta_supports_beacon_measurement(sta->m_sta_info.rm_cap)) {
            continue;
        }
        // Find the radio this BSS belongs to and check its RCPI threshold
        dm_radio_t *radio = NULL;
        for (unsigned int b = 0; b < dm->get_num_bss(); b++) {
            if (memcmp(dm->m_bss[b].m_bss_info.bssid.mac, metrics->bssid, sizeof(mac_address_t)) == 0) {
                radio = dm->get_radio(dm->m_bss[b].m_bss_info.id.ruid);
                break;
            }
        }
        if (radio != NULL) {
            em_radio_info_t *radio_info = radio->get_radio_info();
            unsigned int threshold = (radio_info != NULL) ? radio_info->rcpi_steering_threshold : 0;
            if (threshold > 0 && sta->m_sta_info.rcpi < static_cast<unsigned char>(threshold)) {
                em_printfout("STA %s RCPI=%u below threshold=%u, triggering beacon query",
                    util::mac_to_string(sta->m_sta_info.id).c_str(),
                    sta->m_sta_info.rcpi, threshold);
                send_beacon_metrics_query(sta->m_sta_info.id, sta->m_sta_info.bssid);
            }
        }
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

int em_metrics_t::handle_assoc_sta_vendor_link_metrics_tlv(unsigned char *buff, unsigned int len)
{
    em_vendor_specific_t *vendor_metrics = reinterpret_cast<em_vendor_specific_t *> (buff);
    em_vendor_data_t *vendor_data = vendor_metrics->data;
    em_assoc_sta_vendor_link_metrics_t *sta_metrics;
    dm_sta_t *sta = NULL;
    dm_easy_mesh_t  *dm;

    dm = get_data_model();
    sta_metrics = reinterpret_cast<em_assoc_sta_vendor_link_metrics_t *> (vendor_data->vendor_data);

    sta = dm->find_sta(sta_metrics->sta_mac, sta_metrics->bssid);
    if (sta != NULL && len >= sizeof(em_assoc_sta_vendor_link_metrics_t)) {
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
    em_cmdu_t *cmdu = reinterpret_cast<em_cmdu_t *> (buff + sizeof(em_raw_hdr_t));

    send_associated_link_metrics_response(sta, ntohs(cmdu->id));
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
        if (tlv->type == em_tlv_type_vendor_specific) {
            handle_assoc_sta_vendor_link_metrics_tlv(tlv->value, ntohs(tlv->len));
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
    em_tlv_t *tlv;
    char *errors[EM_MAX_TLV_MEMBERS] = {0};
    size_t sz = 0;

    if (em_msg_t(em_msg_type_beacon_metrics_query, em_profile_type_2, buff, len).validate(errors) == 0) {
        em_printfout("Beacon Metrics query message validation failed");
        return -1;
    }

    tlv = reinterpret_cast<em_tlv_t *> (buff + sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));

    unsigned char *tmp = reinterpret_cast<unsigned char*> (&tlv->value);

    em_beacon_metrics_query_t *beacon_metrics = reinterpret_cast<em_beacon_metrics_query_t*> (tlv->value);
    em_printfout("    STA MAC Address: %s", util::mac_to_string(beacon_metrics->sta_mac_addr).c_str());
    em_printfout("   Operating Class: %u", beacon_metrics->op_class);
    em_printfout("   Channel Number: %u", beacon_metrics->channel_num);
    em_printfout("   BSSID: %s", util::mac_to_string(beacon_metrics->bssid).c_str());
    em_printfout("   Reporting Detail: %u", beacon_metrics->rprt_detail);
    em_printfout("   SSID Length: %u", beacon_metrics->ssid_len);
    em_printfout("   SSID: %.*s", beacon_metrics->ssid_len, beacon_metrics->ssid);
    em_printfout("\n\n");

    //todo: need to copy after parsing len,
    em_beacon_metrics_query_t query_params;
    memcpy(query_params.sta_mac_addr, beacon_metrics->sta_mac_addr, sizeof(mac_address_t));
    sz += sizeof(mac_address_t);

    query_params.op_class = beacon_metrics->op_class;
    sz += sizeof(unsigned char);
    query_params.channel_num = beacon_metrics->channel_num;
    sz += sizeof(unsigned char);
    memcpy(query_params.bssid, beacon_metrics->bssid, sizeof(mac_address_t));
    sz += sizeof(mac_address_t);

    query_params.rprt_detail = beacon_metrics->rprt_detail;
    sz += sizeof(unsigned char);
    query_params.ssid_len = beacon_metrics->ssid_len;
    sz += sizeof(unsigned char);
    memcpy(query_params.ssid, beacon_metrics->ssid, beacon_metrics->ssid_len);
    sz += beacon_metrics->ssid_len;
    query_params.num_ap_channel_rprt = *(tmp + sz);
    sz += sizeof(unsigned char);
    for (unsigned int i = 0; i < query_params.num_ap_channel_rprt; i++) {
        query_params.ap_channel_rprt[i].ap_channel_rprt_len = *(tmp + sz);
        sz += sizeof(unsigned char);
        query_params.ap_channel_rprt[i].ap_channel_op_class = *(tmp + sz);
        sz += sizeof(unsigned char);

        for(int j = 0; j < query_params.ap_channel_rprt[i].ap_channel_rprt_len - 1; j++) {
            query_params.ap_channel_rprt[i].ap_channel_list[j] = *(tmp + sz);
            sz += sizeof(unsigned char);
        }
    }
    em_beacon_element_list_t *element_list = reinterpret_cast<em_beacon_element_list_t*> (tmp + sz);
    query_params.element_list.num_element_id = element_list->num_element_id;
    for (int i = 0; i < element_list->num_element_id; i++) {
        query_params.element_list.element_list[i] = element_list->element_list[i];
    }

    // Extract message ID for the ACK
    em_cmdu_t *cmdu = reinterpret_cast<em_cmdu_t *>(buff + sizeof(em_raw_hdr_t));
    unsigned short msg_id = ntohs(cmdu->id);

    // Check if the STA is associated with any BSS on this agent
    dm_easy_mesh_t *dm = get_data_model();
    dm_sta_t *sta = dm->get_first_sta(beacon_metrics->sta_mac_addr);
    if (sta == NULL) {
        em_printfout("STA %s not associated, sending error ACK (reason 0x02)",
            util::mac_to_string(beacon_metrics->sta_mac_addr).c_str());
        send_beacon_metrics_query_ack(beacon_metrics->sta_mac_addr, msg_id, 0x02);
        return -1;
    }

    // STA is associated — send ACK before forwarding the request to OneWifi
    send_beacon_metrics_query_ack(beacon_metrics->sta_mac_addr, msg_id, 0);

    get_mgr()->io_process(em_bus_event_type_beacon_query, reinterpret_cast<unsigned char *>(&query_params), sizeof(em_beacon_metrics_query_t));

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
            report_len = static_cast<unsigned int>(ntohs(tlv->len) - 8);
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

    // Send 1905 ACK back to the agent
    em_cmdu_t *cmdu = reinterpret_cast<em_cmdu_t *>(buff + sizeof(em_raw_hdr_t));
    send_beacon_metrics_ack(ntohs(cmdu->id));

    //get_data_model()->set_db_cfg_param(db_cfg_type_sta_list_update, "");

    return 0;
}

int em_metrics_t::send_beacon_metrics_ack(unsigned short msg_id)
{
    unsigned char buff[MAX_EM_BUFF_SZ] = {0};
    char *errors[EM_MAX_TLV_MEMBERS] = {0};
    unsigned int len = 0;
    em_cmdu_t *cmdu;
    em_tlv_t *tlv;
    unsigned char *tmp = buff;
    unsigned short type = htons(ETH_P_1905);
    dm_easy_mesh_t *dm = get_data_model();

    // dst = agent, src = controller
    memcpy(tmp, dm->get_agent_al_interface_mac(), sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += sizeof(mac_address_t);

    memcpy(tmp, dm->get_ctrl_al_interface_mac(), sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += sizeof(mac_address_t);

    memcpy(tmp, reinterpret_cast<unsigned char *>(&type), sizeof(unsigned short));
    tmp += sizeof(unsigned short);
    len += sizeof(unsigned short);

    cmdu = reinterpret_cast<em_cmdu_t *>(tmp);
    memset(tmp, 0, sizeof(em_cmdu_t));
    cmdu->type = htons(em_msg_type_1905_ack);
    cmdu->id   = htons(msg_id);
    cmdu->last_frag_ind = 1;
    tmp += sizeof(em_cmdu_t);
    len += sizeof(em_cmdu_t);

    tlv = reinterpret_cast<em_tlv_t *>(tmp);
    tlv->type = em_tlv_type_eom;
    tlv->len  = 0;
    tmp += sizeof(em_tlv_t);
    len += sizeof(em_tlv_t);

    if (em_msg_t(em_msg_type_1905_ack, em_profile_type_2, buff, len).validate(errors) == 0) {
        em_printfout("Beacon Metrics ACK validation failed");
        return -1;
    }

    if (send_frame(buff, len) < 0) {
        em_printfout("Beacon Metrics ACK send failed, error:%d", errno);
        return -1;
    }

    em_printfout("Beacon Metrics ACK sent for msg_id=%u", msg_id);
    return static_cast<int>(len);
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

    dm = get_data_model();
    sta_metrics = reinterpret_cast<em_assoc_sta_traffic_stats_t *> (buff);

    sta = dm->find_sta(sta_metrics->sta_mac, bssid);
    if (sta == NULL) {
        em_printfout("sta not found: %s for bssid: %s", util::mac_to_string(sta_metrics->sta_mac).c_str(),
            util::mac_to_string(bssid).c_str());
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

int em_metrics_t::handle_link_stats_alarm_rprt_tlv(unsigned char *buff, size_t len)
{
    em_link_report_t *link_report;
    dm_sta_t *sta;
    dm_easy_mesh_t  *dm;
    mac_addr_str_t sta_str;
    unsigned char *tmp = buff;
    size_t alarm_offset = 0;

    dm = get_data_model();

    em_vendor_specific_t *vendor_data = reinterpret_cast<em_vendor_specific_t *> (tmp);
    em_printfout("vendor_data->num count [%d]", vendor_data->num);

    em_vendor_data_t *vendor_data_ptr = vendor_data->data;
    em_printfout("vendor_data->attri [%d]", vendor_data_ptr->attr_id);

    if (vendor_data_ptr->attr_id != vendor_ext_attr_id_link_report) {
        return 0;
    }

    tmp += sizeof(vendor_data->num) + EM_VENDOR_OUI_SIZE + sizeof(vendor_data_ptr->attr_id);
    len -= static_cast<unsigned int>( sizeof(vendor_data->num) + EM_VENDOR_OUI_SIZE ) + sizeof(vendor_data_ptr->attr_id);

    link_report = reinterpret_cast<em_link_report_t *> (tmp);

    while (link_report != NULL && len > 0) {
        alarm_offset = offsetof(em_link_report_t, alarm_sample);

        if (len < alarm_offset) {
            em_printfout("Invalid alarm report length");
            break;
        }
        em_printfout("length : %d", len);

        dm_easy_mesh_t::macbytes_to_string(link_report->sta_mac, sta_str);
        sta = dm->get_first_sta(link_report->sta_mac);
        while (sta != NULL) {
            if (memcmp(sta->m_sta_info.id, link_report->sta_mac, sizeof(mac_address_t)) == 0) {
                break;
            }
            sta = dm->get_next_sta(link_report->sta_mac, sta);
        }

        if(sta == NULL)
        {
            em_printfout("sta[%s] not found", sta_str);
            //todo: handle this case, shouldnot return, should goto next after incrementing
            return -1;
        }

        em_printfout("sta mac : %s", sta_str);
        memcpy(sta->m_sta_info.link_stats_report.reporting_timestamp, link_report->reporting_timestamp, 31);
        sta->m_sta_info.link_stats_report.reporting_timestamp[31] = '\0';
        sta->m_sta_info.link_stats_report.link_quality_threshold = link_report->link_quality_threshold;
        sta->m_sta_info.link_stats_report.alarm_triggered = link_report->alarm_triggered;

        em_printfout("\t\t===>>> Link Stats Alarm Report rcvd for STA [%s] <<<===", sta_str);
        em_printfout("\t\tReporting Timestamp: %s", sta->m_sta_info.link_stats_report.reporting_timestamp);
        em_printfout("\t\tLink Quality Threshold: %.2f", sta->m_sta_info.link_stats_report.link_quality_threshold);
        em_printfout("\t\tAlarm Triggered: %s", sta->m_sta_info.link_stats_report.alarm_triggered ? "True" : "False");

        sta->m_sta_info.link_stats_report.sample_count = link_report->sample_count;
        em_printfout("    Number of Samples: %d", sta->m_sta_info.link_stats_report.sample_count);

        for (int i = 0; i < link_report->sample_count; i++) {
            memcpy(&sta->m_sta_info.link_stats_report.alarm_sample[i],
                &link_report->alarm_sample[i],
                sizeof(em_alarm_samples_t));

            em_printfout("\t\treporting_time: %s", sta->m_sta_info.link_stats_report.alarm_sample[i].reporting_time);
            em_printfout("\t\tLink Quality score: %.2f", sta->m_sta_info.link_stats_report.alarm_sample[i].link_quality_score);
            em_printfout("\t\tSNR: %f dB", sta->m_sta_info.link_stats_report.alarm_sample[i].snr);
            em_printfout("\t\tPER Rate: %f ", sta->m_sta_info.link_stats_report.alarm_sample[i].per);
            em_printfout("\t\tPHY Rate: %f ", sta->m_sta_info.link_stats_report.alarm_sample[i].phy);
        }

        tmp += alarm_offset + (static_cast<size_t>(link_report->sample_count) * sizeof(em_alarm_samples_t));
        len -= alarm_offset + (static_cast<size_t>(link_report->sample_count) * sizeof(em_alarm_samples_t));

        link_report = reinterpret_cast<em_link_report_t *> (tmp);
    }

    //form json and send to cli/orchestrator
    get_mgr()->io_process(em_bus_event_type_link_quality_report, reinterpret_cast<char *>(dm->get_device_info()->id.dev_mac), sizeof(mac_address_t));

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
            //todo: bug fix to find sta
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
        if (tlv->type == em_tlv_type_vendor_specific) {
            handle_assoc_sta_vendor_link_metrics_tlv(tlv->value, ntohs(tlv->len));
        }
        tmp_len -= (sizeof(em_tlv_t) + static_cast<size_t> (htons(tlv->len)));
        tlv = reinterpret_cast<em_tlv_t *> (reinterpret_cast<unsigned char *> (tlv) + sizeof(em_tlv_t) + htons(tlv->len));
    }

    dm->set_db_cfg_param(db_cfg_type_sta_metrics_update, "");

    return 0;
}

int em_metrics_t::handle_vendor_msg(unsigned char *buff, unsigned int len)
{
    em_tlv_t *tlv, *tlv_start;
    size_t tmp_len, base_len;
    char *errors[EM_MAX_TLV_MEMBERS] = {0};

    if (em_msg_t(em_msg_type_topo_vendor, get_profile_type(), buff, len).validate(errors) == 0) {
        printf("%s:%d: Vendor msg validation failed\n", __func__, __LINE__);
        return -1;
    }

    tlv_start =  reinterpret_cast<em_tlv_t *> (buff + sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));
    base_len = static_cast<size_t> (len) - (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));

    tlv = tlv_start;
    tmp_len = base_len;

    while ((tlv->type != em_tlv_type_eom) && (tmp_len > 0)) {
        if (tlv->type == em_tlv_type_vendor_specific) {
            handle_link_stats_alarm_rprt_tlv(tlv->value, ntohs(tlv->len));
        }
        tmp_len -= (sizeof(em_tlv_t) + static_cast<size_t> (htons(tlv->len)));
        tlv = reinterpret_cast<em_tlv_t *> (reinterpret_cast<unsigned char *> (tlv) + sizeof(em_tlv_t) + htons(tlv->len));
    }

    return 0;
}

int em_metrics_t::send_associated_sta_link_metrics_msg(mac_address_t sta_mac)
{
    unsigned char buff[MAX_EM_BUFF_SZ];
    char *errors[EM_MAX_TLV_MEMBERS] = {0};
    unsigned short  msg_type = em_msg_type_assoc_sta_link_metrics_query;
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
    cmdu->type = htons(msg_type);
    cmdu->id = htons(get_mgr()->get_next_msg_id());
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
        send_associated_link_metrics_response(sta->m_sta_info.id, dm->get_msg_id());
        sta = static_cast<dm_sta_t *> (hash_map_get_next(dm->m_sta_assoc_map, sta));
    }
    set_state(em_state_agent_configured);
}

int em_metrics_t::send_associated_link_metrics_response(mac_address_t sta_mac, unsigned short msg_id)
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
    cmdu->id = htons(msg_id);
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
    tlv->type = em_tlv_type_vendor_specific;
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
    unsigned short  msg_type = em_msg_type_beacon_metrics_query;
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
    cmdu->type = htons(msg_type);
    cmdu->id = htons(get_mgr()->get_next_msg_id());
    cmdu->last_frag_ind = 1;
    cmdu->relay_ind = 0;

    tmp += sizeof(em_cmdu_t);
    len += sizeof(em_cmdu_t);

    //Beacon Metrics Query TLV (see section 17.2.27).
    tlv = reinterpret_cast<em_tlv_t *> (tmp);
    tlv->type = em_tlv_type_bcon_metric_query;
    sz = create_beacon_metrics_query_tlv(tlv->value, sta_mac, bssid);
    if (sz < 0) {
        em_printfout("Failed to create beacon metrics query tlv for sta:%s and bssid:%s", util::mac_to_string(sta_mac).c_str(), util::mac_to_string(bssid).c_str());
        return -1;
    }
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
        em_printfout("Beacon Metrics Query msg validation failed");
        return -1;
    }

    if (send_frame(buff, static_cast<unsigned int> (len))  < 0) {
        em_printfout("Beacon Metrics Query send failed, error:%d", errno);
        return -1;
    }

    em_printfout("Beacon Metrics Query send success for sta:%s", util::mac_to_string(sta_mac).c_str());
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
    if (sta == NULL) {
        printf("%s:%d: No STA in beacon report data model, cannot send response\n", __func__, __LINE__);
        set_state(em_state_agent_configured);
        return -1;
    }

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
    //TBD: MID should be same as beacon metrics query msg id
    cmdu->id = htons(get_mgr()->get_next_msg_id());
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

int em_metrics_t::send_link_quality_report()
{
    unsigned char buff[MAX_EM_BUFF_SZ] = {0};
    char *errors[EM_MAX_TLV_MEMBERS] = {0};
    unsigned short  msg_type = em_msg_type_topo_vendor;
    size_t len = 0;
    em_cmdu_t *cmdu;
    em_tlv_t *tlv;
    unsigned char *tmp = buff;
    short sz = 0;
    unsigned short type = htons(ETH_P_1905);
    dm_easy_mesh_t *dm = get_data_model();
    mac_addr_str_t mac_str;

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
    cmdu->id = htons(get_mgr()->get_next_msg_id());
    cmdu->last_frag_ind = 1;

    tmp += sizeof(em_cmdu_t);
    len += sizeof(em_cmdu_t);

    //Add Link Stats alarm tlv
    tlv = reinterpret_cast<em_tlv_t *> (tmp);
    tlv->type = em_tlv_type_vendor_specific;

    //todo: add type id for future usage
    sz = create_link_stats_alarm_tlv(tlv->value);
    tlv->len = htons(static_cast<unsigned short> (sz));
    tmp += (sizeof(em_tlv_t) + static_cast<size_t> (sz));
    len += (sizeof(em_tlv_t) + static_cast<size_t> (sz));

    // End of message
    tlv = reinterpret_cast<em_tlv_t *> (tmp);
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof(em_tlv_t));
    len += (sizeof(em_tlv_t));

    if (em_msg_t(em_msg_type_topo_vendor, em_profile_type_2, buff, static_cast<unsigned int> (len)).validate(errors) == 0) {
        em_printfout("Link Stats msg validation failed for %s", mac_str);
        //return -1;
    }

    if (send_frame(buff, static_cast<unsigned int> (len))  < 0) {
        em_printfout("Link Stats msg send failed, error:%d", errno);
        return -1;
    }

    em_printfout("Link Stats msg send success");

    set_state(em_state_agent_configured);

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
    dm_sta_t *sta;
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
    cmdu->id = htons(get_mgr()->get_next_msg_id());
    cmdu->last_frag_ind = 1;

    tmp += sizeof(em_cmdu_t);
    len += sizeof(em_cmdu_t);

    //AP Metrics Response 17.1.17
    //AP Metrics TLV (17.2.22)
    for (bss_index = 0; bss_index < static_cast<int>(dm->m_num_bss); bss_index++) {

        if(dm->m_bss[bss_index].get_bss_info()->vap_mode != em_vap_mode_ap) {
            em_printfout("Vap mode is not ap, skipping");
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
            tlv->type = em_tlv_type_vendor_specific;
            sz = create_assoc_vendor_sta_link_metrics_tlv(tlv->value, sta->m_sta_info.id, sta);
            tlv->len = htons(static_cast<short unsigned int> (sz));

            tmp += (sizeof(em_tlv_t) + static_cast<size_t> (sz));
            len += (sizeof(em_tlv_t) + static_cast<size_t> (sz));

            sta = reinterpret_cast<dm_sta_t *> (hash_map_get_next(dm->m_sta_map, sta));
        }
    }

    for (int i = 0; i < get_current_cmd()->get_param()->u.ap_metrics_params.num_radios; i++) {
        //Radio Metrics TLV (17.2.60)
        tlv = reinterpret_cast<em_tlv_t *> (tmp);
        tlv->type = em_tlv_type_radio_metric;
        sz = create_radio_metrics_tlv(tlv->value, i);
        if (sz == 0) {
            em_printfout("create_radio_metrics_tlv size equals to zero\n");
            continue;
        }
        tlv->len =  htons(static_cast<unsigned short> (sz));

        tmp += (sizeof(em_tlv_t) + static_cast<size_t> (sz));
        len += (sizeof(em_tlv_t) + static_cast<size_t> (sz));
    }

    // End of message
    tlv = reinterpret_cast<em_tlv_t *> (tmp);
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof(em_tlv_t));
    len += (sizeof(em_tlv_t));

    if (em_msg_t(em_msg_type_ap_metrics_rsp, em_profile_type_2, buff, static_cast<unsigned int> (len)).validate(errors) == 0) {
        em_printfout("AP Metrics Response validation failed for agent:%s, still sending",
            util::mac_to_string(dm->get_agent_al_interface_mac()).c_str());
        //return -1;
    }

    if (send_frame(buff, static_cast<unsigned int> (len))  < 0) {
        em_printfout("AP Metrics Response send failed, error:%d\n", errno);
        return -1;
    }

    em_printfout("AP Metrics Response sent for %u BSSs, %d Radios", dm->m_num_bss, get_current_cmd()->get_param()->u.ap_metrics_params.num_radios);

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

            metrics->time_delta_ms = htonl(sta->m_sta_info.delta_ms);
            len += sizeof(metrics->time_delta_ms);

            metrics->est_mac_data_rate_dl = htonl(sta->m_sta_info.est_dl_rate);
            len += sizeof(metrics->est_mac_data_rate_dl);

            metrics->est_mac_data_rate_ul = htonl(sta->m_sta_info.est_ul_rate);
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

            metrics->last_data_dl_rate = htonl(sta->m_sta_info.last_dl_rate);
            len += sizeof(metrics->last_data_dl_rate);

            metrics->last_data_ul_rate = htonl(sta->m_sta_info.last_ul_rate);
            len += sizeof(metrics->last_data_ul_rate);

            metrics->util_receive = htonl(sta->m_sta_info.util_rx);
            len += sizeof(metrics->util_receive);

            metrics->util_transmit = htonl(sta->m_sta_info.util_tx);
            len += sizeof(metrics->util_transmit);
        }
    }
    return static_cast<short> (len);
}

short em_metrics_t::create_assoc_vendor_sta_link_metrics_tlv(unsigned char *buff, mac_address_t sta_mac, const dm_sta_t *const sta)
{
    size_t len = 0;
    em_assoc_sta_vendor_link_metrics_t *assoc_sta_metrics = NULL;
    em_vendor_specific_t *vendor_metrics = reinterpret_cast<em_vendor_specific_t *> (buff);
    em_vendor_data_t *vendor_data = vendor_metrics->data;

    assoc_sta_metrics = reinterpret_cast<em_assoc_sta_vendor_link_metrics_t *> (vendor_data->vendor_data);

    memcpy(vendor_metrics->vendor_oui, em_vendor_oui, sizeof(vendor_metrics->vendor_oui));
    len += sizeof(vendor_metrics->vendor_oui);

    vendor_metrics->num = 1;
    len += sizeof(vendor_metrics->num);

    vendor_data->attr_id = vendor_ext_attr_id_client_type;
    len += sizeof(vendor_data->attr_id);

    if (sta == NULL) {
        memcpy(&assoc_sta_metrics->sta_mac, &sta_mac, sizeof(assoc_sta_metrics->sta_mac));
        len += sizeof(assoc_sta_metrics->sta_mac);

        /*assoc_sta_metrics->num_bssids = 0;
        len += sizeof(assoc_sta_metrics->num_bssids);*/
        return static_cast<short> (len);
    }
    else {
        if ((memcmp(sta->m_sta_info.id, sta_mac, sizeof(mac_address_t)) == 0)) {
            memcpy(assoc_sta_metrics->sta_mac, sta->m_sta_info.id, sizeof(assoc_sta_metrics->sta_mac));
            len += sizeof(assoc_sta_metrics->sta_mac);

            memcpy(&assoc_sta_metrics->bssid, sta->m_sta_info.bssid, sizeof(bssid_t));
            len += sizeof(bssid_t);

            strncpy(assoc_sta_metrics->sta_client_type, sta->m_sta_info.sta_client_type, sizeof(assoc_sta_metrics->sta_client_type));
            len += sizeof(assoc_sta_metrics->sta_client_type);
        }
    }
    return static_cast<short> (len);
}

short em_metrics_t::create_beacon_metrics_query_tlv(unsigned char *buff, mac_address_t sta_mac, bssid_t bssid)
{
    size_t len = 0;
    dm_easy_mesh_t *dm;
    ssid_t ssid = {0};
    dm_sta_t *sta;
    unsigned int j;
    bool ssid_found = false;
    unsigned int radio_op_class = 128; // default fallback: 5GHz VHT80
    
	dm = get_data_model();

    sta = reinterpret_cast<dm_sta_t *> (hash_map_get_first(dm->m_sta_map));
    while(sta != NULL) {
        if (memcmp(sta->m_sta_info.id, sta_mac, sizeof(mac_address_t)) == 0) {
            break;
        }
        sta = reinterpret_cast<dm_sta_t *> (hash_map_get_next(dm->m_sta_map, sta));
    }

    if (sta == NULL) {
        em_printfout("STA not found for mac:%s", util::mac_to_string(sta_mac).c_str());
        return -1;
    }

    em_printfout("BSS lookup: sta_mac:%s sta->bssid:%s bssid_param:%s num_bss:%u",
        util::mac_to_string(sta_mac).c_str(),
        util::mac_to_string(sta->m_sta_info.bssid).c_str(),
        util::mac_to_string(bssid).c_str(),
        dm->get_num_bss());

    // Try bssid parameter first (from em_sta->bssid), then fall back to sta->m_sta_info.bssid
    for (j = 0; j < dm->get_num_bss(); j++) {
        em_printfout("  BSS[%u] bssid:%s ssid:%s", j,
            util::mac_to_string(dm->m_bss[j].m_bss_info.bssid.mac).c_str(),
            dm->m_bss[j].m_bss_info.ssid);
        if (memcmp(dm->m_bss[j].m_bss_info.bssid.mac, bssid, sizeof(bssid_t)) == 0) {
            snprintf(ssid, sizeof(ssid_t), "%s", dm->m_bss[j].m_bss_info.ssid);
            ssid_found = true;
            em_printfout("BSS found via bssid param: ssid:%s", ssid);
            break;
        }
    }

    if (!ssid_found) {
        // Fallback: try sta->m_sta_info.bssid
        for (j = 0; j < dm->get_num_bss(); j++) {
            if (memcmp(dm->m_bss[j].m_bss_info.bssid.mac, sta->m_sta_info.bssid, sizeof(bssid_t)) == 0) {
                snprintf(ssid, sizeof(ssid_t), "%s", dm->m_bss[j].m_bss_info.ssid);
                ssid_found = true;
                em_printfout("BSS found via sta->bssid fallback: ssid:%s", ssid);
                break;
            }
        }
    }

    if (!ssid_found) {
        em_printfout("BSS not found for bssid_param:%s sta->bssid:%s, cannot populate SSID",
            util::mac_to_string(bssid).c_str(),
            util::mac_to_string(sta->m_sta_info.bssid).c_str());
        return -1;
    }

    // Derive op_class from the radio the serving BSS is on (index j holds the found BSS)
    {
        em_op_class_info_t *oci = dm->get_opclass_info_for_bss(dm->m_bss[j].m_bss_info.id.ruid);
        if (oci != nullptr) {
            radio_op_class = oci->op_class;
            em_printfout("Derived radio op_class %u from BSS ruid:%s",
                radio_op_class, util::mac_to_string(dm->m_bss[j].m_bss_info.id.ruid).c_str());
        } else {
            em_printfout("Could not get op_class from BSS ruid, using default %u", radio_op_class);
        }
    }

    em_beacon_metrics_query_t *beacon_metrics = reinterpret_cast<em_beacon_metrics_query_t*> (buff);

    memcpy(beacon_metrics->sta_mac_addr, sta_mac, sizeof(mac_addr_t));
    len += sizeof(beacon_metrics->sta_mac_addr);

    // Map any wide-band op_class to its 20 MHz primary-channel equivalent using
    // the e4 table, so get_channel_list_by_op_class() returns actual primary
    // channel numbers rather than VHT/HE centre frequencies.
    unsigned int scan_op_class = static_cast<unsigned int>(
        dm_easy_mesh_t::get_primary_channel_op_class(static_cast<int>(radio_op_class)));
    em_printfout("Using scan_op_class %u (derived from radio_op_class %u) for channel list",
        scan_op_class, radio_op_class);

    beacon_metrics->op_class = static_cast<unsigned char>(scan_op_class);
    len += sizeof(beacon_metrics->op_class);

    beacon_metrics->channel_num = 255; // 255 = wildcard, use AP Channel Report IE
    len += sizeof(beacon_metrics->channel_num);

    // Keep real BSSID so agent can resolve ap_index; OW will override to wildcard after lookup
    memcpy(beacon_metrics->bssid, bssid, sizeof(bssid_t));
    len += sizeof(beacon_metrics->bssid);

    beacon_metrics->rprt_detail = 1;
    len += sizeof(beacon_metrics->rprt_detail);

    beacon_metrics->ssid_len = strlen(ssid);
    len += sizeof(beacon_metrics->ssid_len);

    memcpy(beacon_metrics->ssid, ssid, beacon_metrics->ssid_len);
    len += beacon_metrics->ssid_len;

    // Write num_ap_channel_rprt at wire position (variable-length SSID means we can't use struct member)
    // Use 20 MHz scan_op_class to get actual primary channel numbers.
    std::vector<int> ch_vec = dm_easy_mesh_t::get_channel_list_by_op_class(static_cast<int>(scan_op_class));
    em_printfout("Channel list for op_class %u: %zu entries", scan_op_class, ch_vec.size());
    for (int ch : ch_vec) {
        em_printfout("  raw channel: %d", ch);
    }

    // Remove any zero entries — channel 0 is invalid and some STAs reject the request.
    size_t before_erase = ch_vec.size();
    ch_vec.erase(std::remove(ch_vec.begin(), ch_vec.end(), 0), ch_vec.end());
    if (ch_vec.size() != before_erase) {
        em_printfout("Removed %zu zero/invalid channel entries", before_erase - ch_vec.size());
    }

    // Chunk the channel list across multiple AP Channel Report entries.
    // Each entry holds at most EM_MAX_CHANNELS_IN_LIST channels.
    // Up to EM_MAX_AP_CHANNEL_RPRT_ENTRIES report entries, giving full coverage
    // of all op classes including 6 GHz op_class 131 (59 channels).
    const size_t max_ch_per_rprt = EM_MAX_CHANNELS_IN_LIST;
    const size_t max_rprts       = EM_MAX_NEIGHBORS;

    uint8_t num_rprts;
    if (ch_vec.empty()) {
        // No valid channels: omit the channel report IE; STA will treat channel=255
        // as "all supported channels".
        em_printfout("No valid channels for scan_op_class %u, omitting AP Channel Report", scan_op_class);
        num_rprts = 0;
        *(buff + len) = num_rprts;
        len += sizeof(uint8_t);
    } else {
        // Calculate how many report entries are needed
        size_t total_ch  = std::min(ch_vec.size(), max_ch_per_rprt * max_rprts);
        num_rprts = static_cast<uint8_t>((total_ch + max_ch_per_rprt - 1) / max_ch_per_rprt);
        *(buff + len) = num_rprts;
        len += sizeof(uint8_t);

        size_t ch_idx = 0;
        for (uint8_t r = 0; r < num_rprts; r++) {
            size_t chunk = std::min(max_ch_per_rprt, total_ch - ch_idx);
            uint8_t rprt_len = static_cast<uint8_t>(1 + chunk); // 1 for op_class byte
            *(buff + len) = rprt_len;
            len += sizeof(uint8_t);

            *(buff + len) = static_cast<uint8_t>(scan_op_class);
            len += sizeof(uint8_t);

            em_printfout("AP Channel Report[%u]: op_class=%u num_channels=%zu", r, scan_op_class, chunk);
            for (size_t c = 0; c < chunk; c++, ch_idx++) {
                em_printfout("  channel: %d", ch_vec[ch_idx]);
                *(buff + len) = static_cast<uint8_t>(ch_vec[ch_idx]);
                len += sizeof(uint8_t);
            }
        }
    }

    // Print the filled data
    em_printfout("STA MAC Address: %s", util::mac_to_string(beacon_metrics->sta_mac_addr).c_str());
    em_printfout("Operating Class: %u", beacon_metrics->op_class);
    em_printfout("Channel Number: %u", beacon_metrics->channel_num);
    em_printfout("BSSID: %s", util::mac_to_string(beacon_metrics->bssid).c_str());
    em_printfout("Reporting Detail: %u", beacon_metrics->rprt_detail);
    em_printfout("SSID Length: %u", beacon_metrics->ssid_len);
    em_printfout("SSID: %.*s", beacon_metrics->ssid_len, beacon_metrics->ssid);
    em_printfout("Number of AP Channel Reports: %u", num_rprts);

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
    em_ap_metric_t *ap_metrics = reinterpret_cast<em_ap_metric_t *> (buff);
    int i = 0;

 
    for(i = 0; i < get_current_cmd()->get_param()->u.ap_metrics_params.num_radios; i++) {
        if (memcmp(dm_bss.m_bss_info.ruid.mac,
            get_current_cmd()->get_param()->u.ap_metrics_params.ruid[i], sizeof(mac_addr_t)) == 0) {
            break;
        }
    }
    if (i < get_current_cmd()->get_param()->u.ap_metrics_params.num_radios) {

        memcpy(ap_metrics->bssid, dm_bss.m_bss_info.bssid.mac, sizeof(mac_address_t));
        len += static_cast<size_t> (sizeof(mac_address_t));

        ap_metrics->channel_util = static_cast<unsigned char>(dm_bss.m_bss_info.channel_util);
        len += static_cast<size_t> (sizeof(unsigned char));

        ap_metrics->num_sta = htons(static_cast<uint16_t>(dm_bss.m_bss_info.numberofsta));
        len += static_cast<size_t> (sizeof(unsigned short));

        ap_metrics->est_service_params_BE_bit = 1;
        ap_metrics->est_service_params_BK_bit = (dm_bss.m_bss_info.inc_esp_ac_bk) ? 1 : 0;
        ap_metrics->est_service_params_VO_bit = (dm_bss.m_bss_info.inc_esp_ac_vo) ? 1 : 0;
        ap_metrics->est_service_params_VI_bit = (dm_bss.m_bss_info.inc_esp_ac_vi) ? 1 : 0;
        len += static_cast<size_t> (sizeof(unsigned char));

        if (dm_bss.m_bss_info.inc_esp_ac_be) {
            memcpy(ap_metrics->est_service_params_BE, dm_bss.m_bss_info.est_svc_params_be, sizeof(ap_metrics->est_service_params_BE));
        }
        len += static_cast<size_t> (sizeof(ap_metrics->est_service_params_BE));

        uint8_t *p = buff + len;
        if(dm_bss.m_bss_info.inc_esp_ac_bk)
        {
            memcpy(p, dm_bss.m_bss_info.est_svc_params_bk, EM_ESP_AC_PARAMS_LEN);
            p += EM_ESP_AC_PARAMS_LEN;
            len += EM_ESP_AC_PARAMS_LEN;
        }

        if(dm_bss.m_bss_info.inc_esp_ac_vo)
        {
            memcpy(p, dm_bss.m_bss_info.est_svc_params_vo, EM_ESP_AC_PARAMS_LEN);
            p += EM_ESP_AC_PARAMS_LEN;
            len += EM_ESP_AC_PARAMS_LEN;
        }

        if(dm_bss.m_bss_info.inc_esp_ac_vi)
        {
            memcpy(p, dm_bss.m_bss_info.est_svc_params_vi, EM_ESP_AC_PARAMS_LEN);
            p += EM_ESP_AC_PARAMS_LEN;
            len += EM_ESP_AC_PARAMS_LEN;
        }
    }
    return static_cast<short> (len);
}

short em_metrics_t::create_ap_ext_metrics_tlv(unsigned char *buff, dm_bss_t &dm_bss)
{
    size_t len = 0;
    em_ap_ext_metric_t *ap_ext_metrics = reinterpret_cast<em_ap_ext_metric_t *> (buff);
    int i = 0;
    uint32_t bytes;

    for(i = 0; i < get_current_cmd()->get_param()->u.ap_metrics_params.num_radios; i++) {
        if (memcmp(dm_bss.m_bss_info.ruid.mac,
            get_current_cmd()->get_param()->u.ap_metrics_params.ruid[i], sizeof(mac_addr_t)) == 0) {
            break;
        }
    }

    if (i < get_current_cmd()->get_param()->u.ap_metrics_params.num_radios) {
        memcpy(ap_ext_metrics->bssid, dm_bss.m_bss_info.bssid.mac, sizeof(mac_address_t));

        bytes = htonl(dm_bss.m_bss_info.unicast_bytes_sent);
        memcpy(ap_ext_metrics->uni_bytes_sent, &bytes, sizeof(bytes));

        bytes = htonl(dm_bss.m_bss_info.unicast_bytes_rcvd);
        memcpy(ap_ext_metrics->uni_bytes_recv, &bytes, sizeof(bytes));

        bytes = htonl(dm_bss.m_bss_info.multicast_bytes_sent);
        memcpy(ap_ext_metrics->multi_bytes_sent, &bytes, sizeof(bytes));

        bytes = htonl(dm_bss.m_bss_info.multicast_bytes_rcvd);
        memcpy(ap_ext_metrics->multi_bytes_recv, &bytes, sizeof(bytes));

        bytes = htonl(dm_bss.m_bss_info.broadcast_bytes_sent);
        memcpy(ap_ext_metrics->bcast_bytes_sent, &bytes, sizeof(bytes));

        bytes = htonl(dm_bss.m_bss_info.broadcast_bytes_rcvd);
        memcpy(ap_ext_metrics->bcast_bytes_recv, &bytes, sizeof(bytes));
    }

    len = static_cast<size_t> (sizeof(em_ap_ext_metric_t));

    return static_cast<short> (len);
}

short em_metrics_t::create_radio_metrics_tlv(unsigned char *buff, int index)
{
    size_t len = 0;
    dm_easy_mesh_t *dm = get_data_model();
    em_radio_metric_t *radio_metric = reinterpret_cast<em_radio_metric_t *> (buff);
    dm_radio_t *radio = NULL;
    em_radio_info_t *em_radio_info = NULL;
    radio = dm->get_radio(get_current_cmd()->get_param()->u.ap_metrics_params.ruid[index]);

    if (radio != NULL) {
        em_radio_info = radio->get_radio_info();
        if (em_radio_info != NULL) {
            memcpy(radio_metric->ruid, em_radio_info->intf.mac, sizeof(mac_address_t));
            radio_metric->noise = static_cast<unsigned char>(em_radio_info->noise);
            radio_metric->transmit = static_cast<unsigned char>(em_radio_info->transmit);
            radio_metric->rece_self = static_cast<unsigned char>(em_radio_info->receive_self);
            radio_metric->rece_other = static_cast<unsigned char>(em_radio_info->receive_other);
            len = static_cast<size_t> (sizeof(em_radio_metric_t));
        }
    }

    return static_cast<short> (len);
}

short em_metrics_t::create_assoc_sta_traffic_stats_tlv(unsigned char *buff, const dm_sta_t *const sta)
{
    size_t len = 0;
    em_assoc_sta_traffic_sts_t *response = reinterpret_cast<em_assoc_sta_traffic_sts_t *> (buff);

    if (sta != NULL) {
        memcpy(response->sta_mac_addr, sta->m_sta_info.id, sizeof(mac_addr_t));
        len += sizeof(response->sta_mac_addr);

        response->bytes_sent = htonl(sta->m_sta_info.bytes_tx);
        len += sizeof(response->bytes_sent);

        response->bytes_recv = htonl(sta->m_sta_info.bytes_rx);
        len += sizeof(response->bytes_recv);

        response->packets_sent = htonl(sta->m_sta_info.pkts_tx);
        len += sizeof(response->packets_sent);

        response->packets_recv = htonl(sta->m_sta_info.pkts_rx);
        len += sizeof(response->packets_recv);

        response->tx_packets_errors = htonl(sta->m_sta_info.errors_tx);
        len += sizeof(response->tx_packets_errors);

        response->rx_packets_errors = htonl(sta->m_sta_info.errors_rx);
        len += sizeof(response->rx_packets_errors);

        response->retrans_count = htonl(sta->m_sta_info.retrans_count);
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

short em_metrics_t::create_link_stats_alarm_tlv(unsigned char *buff)
{
    size_t len = 0;
    em_link_report_t *link_stats;
    unsigned char *tmp = buff;
    dm_sta_t *sta;
    dm_easy_mesh_t  *dm = get_current_cmd()->get_data_model();
    size_t alarm_offset = offsetof(em_link_report_t, alarm_sample);
    size_t record_len = 0;

    em_vendor_specific_t *vendor_data = reinterpret_cast<em_vendor_specific_t *> (buff);
    memcpy(reinterpret_cast<char *> (vendor_data->vendor_oui), em_vendor_oui, EM_VENDOR_OUI_SIZE);

    vendor_data->num = 1;

    tmp += sizeof(vendor_data->num) + EM_VENDOR_OUI_SIZE;
    len += sizeof(vendor_data->num) + EM_VENDOR_OUI_SIZE;

    em_vendor_data_t *data = vendor_data->data;

    data->attr_id = static_cast<unsigned char> (vendor_ext_attr_id_link_report);
    len += sizeof(data->attr_id);
    tmp += sizeof(data->attr_id);

    sta = static_cast<dm_sta_t *> (hash_map_get_first(dm->m_sta_map));
    while (sta != NULL) {
        link_stats = reinterpret_cast<em_link_report_t *>(tmp);
        memcpy(link_stats->sta_mac, sta->m_sta_info.id, sizeof(mac_address_t));
        strncpy(reinterpret_cast<char*>(link_stats->reporting_timestamp),
            reinterpret_cast<const char*>(sta->m_sta_info.link_stats_report.reporting_timestamp), 32);

        link_stats->link_quality_threshold = sta->m_sta_info.link_stats_report.link_quality_threshold;
        link_stats->alarm_triggered = sta->m_sta_info.link_stats_report.alarm_triggered;
        link_stats->sample_count = sta->m_sta_info.link_stats_report.sample_count;

        em_printfout("   sta mac : %s", util::mac_to_string(link_stats->sta_mac).c_str());
        em_printfout("   reporting_timestamp : %s", link_stats->reporting_timestamp);
        em_printfout("   link_quality_threshold : %.2f", link_stats->link_quality_threshold);
        em_printfout("   alarm_triggered : %d", link_stats->alarm_triggered);
        em_printfout("create_link_stats_alarm_tlv: sample_count=%d", link_stats->sample_count);

        for (int j = 0; j < link_stats->sample_count; j++) {
            link_stats->alarm_sample[j].link_quality_score = sta->m_sta_info.link_stats_report.alarm_sample[j].link_quality_score;
            strncpy(reinterpret_cast<char*>(link_stats->alarm_sample[j].reporting_time),
                reinterpret_cast<const char*>(sta->m_sta_info.link_stats_report.alarm_sample[j].reporting_time), 32);
            link_stats->alarm_sample[j].snr = sta->m_sta_info.link_stats_report.alarm_sample[j].snr;
            link_stats->alarm_sample[j].per = sta->m_sta_info.link_stats_report.alarm_sample[j].per;
            link_stats->alarm_sample[j].phy = sta->m_sta_info.link_stats_report.alarm_sample[j].phy;

            em_printfout("   Sample %d:", j + 1);
            em_printfout("       link_quality_score : %.2f", link_stats->alarm_sample[j].link_quality_score);
            em_printfout("       reporting_time : %s", link_stats->alarm_sample[j].reporting_time);
            em_printfout("       snr : %f", link_stats->alarm_sample[j].snr);
            em_printfout("       per : %f", link_stats->alarm_sample[j].per);
            em_printfout("       phy : %f", link_stats->alarm_sample[j].phy);
        }

        record_len = alarm_offset + (static_cast<size_t>(link_stats->sample_count) * sizeof(em_alarm_samples_t));
        len += record_len;
        tmp += record_len;
        em_printfout("framed report len: %d", len);
        sta = static_cast<dm_sta_t *> (hash_map_get_next(dm->m_sta_map, sta));
    }

    em_printfout("create_link_stats_alarm_tlv done of len: %d", len);

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
    em_cmdu_t *cmdu = reinterpret_cast<em_cmdu_t *> (data + sizeof(em_raw_hdr_t));

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
        case em_msg_type_topo_vendor:
            handle_vendor_msg(data, len);
            break;

        case em_msg_type_client_cap_rprt:
        {
            // Extract the specific STA from the Client Info TLV so we only
            // send one beacon query for the STA that just joined.
            em_tlv_t *cap_tlv = reinterpret_cast<em_tlv_t *>(data + sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));
            unsigned int cap_len = len - static_cast<unsigned int>(sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));
            mac_address_t join_sta_mac = {0};
            bssid_t       join_bssid   = {0};
            bool found_sta = false;
            while ((cap_tlv->type != em_tlv_type_eom) && (cap_len > 0)) {
                if (cap_tlv->type == em_tlv_type_client_info) {
                    // em_client_info_t layout: bssid[6] then client_mac[6]
                    memcpy(join_bssid,   cap_tlv->value,                    sizeof(bssid_t));
                    memcpy(join_sta_mac, cap_tlv->value + sizeof(bssid_t),  sizeof(mac_address_t));
                    found_sta = true;
                    break;
                }
                cap_len -= static_cast<unsigned int>(sizeof(em_tlv_t) + htons(cap_tlv->len));
                cap_tlv  = reinterpret_cast<em_tlv_t *>(reinterpret_cast<unsigned char *>(cap_tlv) + sizeof(em_tlv_t) + htons(cap_tlv->len));
            }
            if (found_sta) {
                em_printfout("cap report: sending beacon query for sta:%s bssid:%s",
                    util::mac_to_string(join_sta_mac).c_str(),
                    util::mac_to_string(join_bssid).c_str());
                send_beacon_metrics_query(join_sta_mac, join_bssid);
            } else {
                em_printfout("cap report: could not find Client Info TLV, skipping beacon query");
            }

            // Previous implementation: send beacon query for all associated STAs.
            // Kept for reference.
            // em_sta_info_t *em_sta = get_data_model()->get_first_sta_info(em_target_sta_map_assoc);
            // while (em_sta != NULL) {
            //     if (!sta_supports_beacon_measurement(em_sta->rm_cap)) {
            //         em_printfout("cap report: STA %s has no 802.11k beacon meas capability, skipping query",
            //             util::mac_to_string(em_sta->id).c_str());
            //     } else {
            //         em_printfout("cap report: sending beacon query for sta:%s bssid:%s",
            //             util::mac_to_string(em_sta->id).c_str(),
            //             util::mac_to_string(em_sta->bssid).c_str());
            //         send_beacon_metrics_query(em_sta->id, em_sta->bssid);
            //     }
            //     em_sta = get_data_model()->get_next_sta_info(em_sta, em_target_sta_map_assoc);
            // }
            break;
        }

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

        case em_state_agent_link_quality_report_pending:
            send_link_quality_report();
            break;

        default:
            break;
    }
}

void em_metrics_t::process_agent_state(em_cmd_event_type_t type)
{
    switch (type) {
        case em_cmd_event_type_ap_metrics_report:
            send_ap_metrics_response();
            break;

        default:
            break;
    }
}

int em_metrics_t::send_beacon_metrics_query_ack(mac_address_t sta_mac, unsigned short msg_id, unsigned char reason)
{
    unsigned char buff[MAX_EM_BUFF_SZ] = {0};
    char *errors[EM_MAX_TLV_MEMBERS] = {0};
    unsigned int len = 0;
    em_cmdu_t *cmdu;
    em_tlv_t *tlv;
    unsigned char *tmp = buff;
    unsigned short type = htons(ETH_P_1905);
    dm_easy_mesh_t *dm = get_data_model();

    // dst = controller, src = agent
    memcpy(tmp, dm->get_ctrl_al_interface_mac(), sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += sizeof(mac_address_t);

    memcpy(tmp, dm->get_agent_al_interface_mac(), sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += sizeof(mac_address_t);

    memcpy(tmp, reinterpret_cast<unsigned char *>(&type), sizeof(unsigned short));
    tmp += sizeof(unsigned short);
    len += sizeof(unsigned short);

    cmdu = reinterpret_cast<em_cmdu_t *>(tmp);
    memset(tmp, 0, sizeof(em_cmdu_t));
    cmdu->type = htons(em_msg_type_1905_ack);
    cmdu->id   = htons(msg_id);
    cmdu->last_frag_ind = 1;
    tmp += sizeof(em_cmdu_t);
    len += sizeof(em_cmdu_t);

    if (reason != 0) {
        // 17.2.36 Error Code TLV
        tlv = reinterpret_cast<em_tlv_t *>(tmp);
        tlv->type = em_tlv_type_error_code;
        unsigned char *ec = tlv->value;
        *ec = reason;
        ec += sizeof(unsigned char);
        memcpy(ec, sta_mac, sizeof(mac_address_t));
        ec += sizeof(mac_address_t);
        tlv->len = htons(static_cast<unsigned short>(sizeof(unsigned char) + sizeof(mac_address_t)));
        tmp += sizeof(em_tlv_t) + sizeof(unsigned char) + sizeof(mac_address_t);
        len += sizeof(em_tlv_t) + sizeof(unsigned char) + sizeof(mac_address_t);
    }

    tlv = reinterpret_cast<em_tlv_t *>(tmp);
    tlv->type = em_tlv_type_eom;
    tlv->len  = 0;
    tmp += sizeof(em_tlv_t);
    len += sizeof(em_tlv_t);

    if (em_msg_t(em_msg_type_1905_ack, em_profile_type_2, buff, len).validate(errors) == 0) {
        em_printfout("Beacon Metrics Query ACK validation failed");
        return -1;
    }

    if (send_frame(buff, len) < 0) {
        em_printfout("Beacon Metrics Query ACK send failed, error:%d", errno);
        return -1;
    }

    em_printfout("Beacon Metrics Query ACK sent for msg_id=%u reason=%u", msg_id, reason);
    return static_cast<int>(len);
}

bool em_metrics_t::sta_supports_beacon_measurement(const char *rm_cap)
{
    // rm_cap is stored as a compact hex string by dm_easy_mesh_t::hex().
    // e.g. tag value {0x71, 0x00, ...} → "7100..."
    // IEEE 802.11-2020 Table 9-157 (RM Enabled Capabilities, Octet 1):
    //   bit 4 = Beacon Passive measurement
    //   bit 5 = Beacon Active measurement
    //   bit 6 = Beacon Table measurement
    // Mask 0x70 covers all three.
    if (rm_cap == nullptr || rm_cap[0] == '\0') {
        return false;
    }
    unsigned int byte0 = 0;
    if (sscanf(rm_cap, "%02x", &byte0) != 1) {
        return false;
    }
    return (byte0 & 0x70) != 0;
}

em_metrics_t::em_metrics_t()
{

}

em_metrics_t::~em_metrics_t()
{

}
