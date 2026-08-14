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
#include "dm_easy_mesh_agent.h"
#include "em_cmd_unassoc_sta_query.h"

static     const unsigned char em_vendor_oui[EM_VENDOR_OUI_SIZE] = {0xd8, 0x9c, 0x8e};

int em_metrics_t::handle_assoc_sta_link_metrics_tlv(unsigned char *buff,
                                                    unsigned int tlv_len)
{
    em_assoc_sta_link_metrics_t *sta_metrics;
    em_assoc_link_metrics_t *metrics;
    dm_sta_t *sta;
    unsigned int i;
    dm_easy_mesh_t *dm;

    if (buff == NULL || tlv_len == 0 || tlv_len < 7) {
        return -1;
    }

    dm = get_data_model();

    sta_metrics = reinterpret_cast<em_assoc_sta_link_metrics_t *>(buff);

    unsigned int k = sta_metrics->num_bssids;
    unsigned int expected_len = 7 + (k * sizeof(em_assoc_link_metrics_t));

    if (tlv_len != expected_len) {
        return -1;
    }

    for (i = 0; i < sta_metrics->num_bssids; i++) {
        metrics = &sta_metrics->assoc_link_metrics[i];
        sta = dm->find_sta(sta_metrics->sta_mac, metrics->bssid);
        if (sta == NULL) {
            continue;
        }

        sta->m_sta_info.est_dl_rate = ntohl(metrics->est_mac_data_rate_dl);
        sta->m_sta_info.est_ul_rate = ntohl(metrics->est_mac_data_rate_ul);
        sta->m_sta_info.rcpi = metrics->rcpi;

        // RCPI-based beacon query trigger: if STA supports 802.11k beacon measurement
        // and its RCPI is below the configured steering threshold, request a beacon report.
        if (sta->m_sta_info.rcpi == 0 || !sta->m_sta_info.associated) {
            continue;
        }

        if (sta->supports_beacon_measurement() == false) {
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

int em_metrics_t::handle_assoc_sta_ext_link_metrics_tlv(unsigned char *buff, unsigned int tlv_len)
{
    em_assoc_sta_ext_link_metrics_t	*sta_metrics;
    em_assoc_ext_link_metrics_t *metrics;
    dm_sta_t *sta;
    unsigned int i;
    dm_easy_mesh_t  *dm;

    if (buff == NULL || tlv_len == 0 || tlv_len < 7) {
            printf("Invalid input: null buffer or invalid tlv_len=%u\n", tlv_len);
            return -1;
    }

    dm = get_data_model();

    sta_metrics = reinterpret_cast<em_assoc_sta_ext_link_metrics_t *> (buff);

    unsigned int k = sta_metrics->num_bssids;
    unsigned int expected_len = offsetof(em_assoc_sta_ext_link_metrics_t, assoc_ext_link_metrics) + (k * sizeof(em_assoc_ext_link_metrics_t));

    if (tlv_len != expected_len) {
            return -1;
    }

    for (i = 0; i < sta_metrics->num_bssids; i++) {
        metrics	= &sta_metrics->assoc_ext_link_metrics[i];
        sta = dm->find_sta(sta_metrics->sta_mac, metrics->bssid);
        if (sta == NULL) {
            continue;
        }

        sta->m_sta_info.last_dl_rate = ntohl(metrics->last_data_dl_rate);
        sta->m_sta_info.last_ul_rate = ntohl(metrics->last_data_ul_rate);
        sta->m_sta_info.util_rx = ntohl(metrics->util_receive);
        sta->m_sta_info.util_tx = ntohl(metrics->util_transmit);
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
            uint16_t tlv_len = ntohs(tlv->len);
            handle_assoc_sta_link_metrics_tlv(tlv->value, tlv_len);
        }
        tmp_len -= (sizeof(em_tlv_t) + static_cast<size_t> (ntohs(tlv->len)));
        tlv = reinterpret_cast<em_tlv_t *> (reinterpret_cast<unsigned char *> (tlv) + sizeof(em_tlv_t) + ntohs(tlv->len));
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

        tmp_len -= (sizeof(em_tlv_t) + static_cast<size_t> (ntohs(tlv->len)));
        tlv = reinterpret_cast<em_tlv_t *> (reinterpret_cast<unsigned char *> (tlv) + sizeof(em_tlv_t) + ntohs(tlv->len));
    }

    tlv = tlv_start;
    tmp_len = base_len;

    while ((tlv->type != em_tlv_type_eom) && (tmp_len > 0)) {
        if (tlv->type == em_tlv_type_assoc_sta_ext_link_metric) {
            handle_assoc_sta_ext_link_metrics_tlv(tlv->value, ntohs(tlv->len));
        }

        tmp_len -= (sizeof(em_tlv_t) + static_cast<size_t> (ntohs(tlv->len)));
        tlv = reinterpret_cast<em_tlv_t *> (reinterpret_cast<unsigned char *> (tlv) + sizeof(em_tlv_t) + ntohs(tlv->len));
    }

    tlv = tlv_start;
    tmp_len = base_len;

    while ((tlv->type != em_tlv_type_eom) && (tmp_len > 0)) {
        if (tlv->type == em_tlv_type_vendor_specific) {
            handle_assoc_sta_vendor_link_metrics_tlv(tlv->value, ntohs(tlv->len));
        }

        tmp_len -= (sizeof(em_tlv_t) + static_cast<size_t> (ntohs(tlv->len)));
        tlv = reinterpret_cast<em_tlv_t *> (reinterpret_cast<unsigned char *> (tlv) + sizeof(em_tlv_t) + ntohs(tlv->len));
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

    em_printfout(" Rcvd Beacon Metrics Query");

    tlv = reinterpret_cast<em_tlv_t *> (buff + sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));

    unsigned char *tmp = tlv->value;

    const unsigned int tlv_payload_len = ntohs(tlv->len);
    const unsigned int max_ssid_len = sizeof(em_beacon_metrics_query_t{}.ssid);
    const unsigned int max_ap_channel_rprt = sizeof(em_beacon_metrics_query_t{}.ap_channel_rprt) /
        sizeof(em_beacon_metrics_query_t{}.ap_channel_rprt[0]);
    const unsigned int max_channels_in_list = sizeof(em_beacon_metrics_query_t{}.ap_channel_rprt[0].ap_channel_list) /
        sizeof(em_beacon_metrics_query_t{}.ap_channel_rprt[0].ap_channel_list[0]);
    const unsigned int max_element_ids = sizeof(em_beacon_metrics_query_t{}.element_list.element_list) /
        sizeof(em_beacon_metrics_query_t{}.element_list.element_list[0]);
    const unsigned int min_fixed_len = sizeof(mac_address_t) + sizeof(unsigned char) + sizeof(unsigned char) +
        sizeof(mac_address_t) + sizeof(unsigned char) + sizeof(unsigned char);

    if (tlv_payload_len < min_fixed_len) {
        em_printfout("Malformed Beacon Metrics Query TLV: payload too short (%u)", tlv_payload_len);
        return -1;
    }

    em_beacon_metrics_query_t query_params = {};
    memcpy(query_params.sta_mac_addr, tmp + sz, sizeof(mac_address_t));
    sz += sizeof(mac_address_t);

    query_params.op_class = *(tmp + sz);
    sz += sizeof(unsigned char);
    query_params.channel_num = *(tmp + sz);
    sz += sizeof(unsigned char);
    memcpy(query_params.bssid, tmp + sz, sizeof(mac_address_t));
    sz += sizeof(mac_address_t);

    query_params.rprt_detail = *(tmp + sz);
    sz += sizeof(unsigned char);

    unsigned int ssid_len = *(tmp + sz);
    sz += sizeof(unsigned char);
    if (sz + ssid_len > tlv_payload_len) {
        em_printfout("Malformed Beacon Metrics Query TLV: ssid_len %u exceeds payload %u",
            ssid_len, tlv_payload_len);
        return -1;
    }
    query_params.ssid_len = (ssid_len > max_ssid_len) ? max_ssid_len : ssid_len;
    if (query_params.ssid_len > 0) {
        memcpy(query_params.ssid, tmp + sz, query_params.ssid_len);
    }
    sz += ssid_len;

    if (sz + sizeof(unsigned char) > tlv_payload_len) {
        em_printfout("Malformed Beacon Metrics Query TLV: missing AP Channel Report count");
        return -1;
    }

    unsigned int num_ap_channel_rprt = *(tmp + sz);
    sz += sizeof(unsigned char);
    query_params.num_ap_channel_rprt = (num_ap_channel_rprt > max_ap_channel_rprt) ?
        max_ap_channel_rprt : num_ap_channel_rprt;

    for (unsigned int i = 0; i < num_ap_channel_rprt; i++) {
        unsigned int ap_channel_rprt_len;
        unsigned int num_channels;

        if (sz + sizeof(unsigned char) > tlv_payload_len) {
            em_printfout("Malformed Beacon Metrics Query TLV: missing AP Channel Report length");
            return -1;
        }

        ap_channel_rprt_len = *(tmp + sz);
        sz += sizeof(unsigned char);
        if (ap_channel_rprt_len < 1) {
            em_printfout("Malformed Beacon Metrics Query TLV: invalid AP Channel Report length %u",
                ap_channel_rprt_len);
            return -1;
        }
        if (sz + ap_channel_rprt_len > tlv_payload_len) {
            em_printfout("Malformed Beacon Metrics Query TLV: AP Channel Report overruns payload");
            return -1;
        }

        num_channels = ap_channel_rprt_len - 1;
        if (i < query_params.num_ap_channel_rprt) {
            query_params.ap_channel_rprt[i].ap_channel_rprt_len =
                (ap_channel_rprt_len > (max_channels_in_list + 1)) ?
                (max_channels_in_list + 1) : ap_channel_rprt_len;
            query_params.ap_channel_rprt[i].ap_channel_op_class = *(tmp + sz);
        }
        sz += sizeof(unsigned char);

        for (unsigned int j = 0; j < num_channels; j++) {
            if (i < query_params.num_ap_channel_rprt && j < max_channels_in_list) {
                query_params.ap_channel_rprt[i].ap_channel_list[j] = *(tmp + sz);
            }
            sz += sizeof(unsigned char);
        }
    }

    if (sz < tlv_payload_len) {
        unsigned int num_element_id = *(tmp + sz);
        sz += sizeof(unsigned char);
        if (sz + num_element_id > tlv_payload_len) {
            em_printfout("Malformed Beacon Metrics Query TLV: element list overruns payload");
            return -1;
        }
        query_params.element_list.num_element_id = (num_element_id > max_element_ids) ?
            max_element_ids : num_element_id;
        for (unsigned int i = 0; i < num_element_id; i++) {
            if (i < query_params.element_list.num_element_id) {
                query_params.element_list.element_list[i] = *(tmp + sz);
            }
            sz += sizeof(unsigned char);
        }
    }

    em_printfout("   STA MAC Address: %s", util::mac_to_string(query_params.sta_mac_addr).c_str());
    em_printfout("   Operating Class: %u", query_params.op_class);
    em_printfout("   Channel Number: %u", query_params.channel_num);
    em_printfout("   BSSID: %s", util::mac_to_string(query_params.bssid).c_str());
    em_printfout("   Reporting Detail: %u", query_params.rprt_detail);
    em_printfout("   SSID Length: %u", query_params.ssid_len);
    em_printfout("   SSID: %.*s", query_params.ssid_len, query_params.ssid);


    // Extract message ID for the ACK
    em_cmdu_t *cmdu = reinterpret_cast<em_cmdu_t *>(buff + sizeof(em_raw_hdr_t));
    unsigned short msg_id = ntohs(cmdu->id);
    em_printfout("   msg_id: %u", msg_id);

    // Check if the STA is associated with any BSS on this agent
    dm_easy_mesh_t *dm = get_data_model();
    dm_sta_t *sta = dm->get_first_sta(query_params.sta_mac_addr);
    if (sta == NULL) {
        em_printfout("STA %s not associated, sending error ACK (reason 0x02)",
            util::mac_to_string(query_params.sta_mac_addr).c_str());
        send_beacon_metrics_query_ack(query_params.sta_mac_addr, msg_id, 0x02);
        return -1;
    }

    // STA is associated — send ACK before forwarding the request to OneWifi
    send_beacon_metrics_query_ack(query_params.sta_mac_addr, msg_id, 0);

    get_mgr()->io_process(em_bus_event_type_beacon_query, reinterpret_cast<unsigned char *>(&query_params), sizeof(em_beacon_metrics_query_t));

    return 0;
}

int em_metrics_t::handle_unassoc_sta_link_metrics_tlv(unsigned char *buff, unsigned int tlv_len)
{
    dm_easy_mesh_t *dm = get_data_model();

    unsigned short pos = 0;
    mac_addr_str_t mac_str;

    if (tlv_len < 2) {
        em_printfout("%s:%d Invalid TLV length=%u\n", __func__, __LINE__, tlv_len);
        return -1;
    }

    unsigned char op_class = buff[pos++];
    unsigned char num_sta  = buff[pos++];

    for (unsigned int i = 0; i < num_sta; i++)
    {
        if (pos + sizeof(em_unassoc_sta_metric_t) > tlv_len) {
            em_printfout("%s:%d Malformed Unassoc STA Link Metrics TLV: num_sta=%u parsed=%u tlv_len=%u\n", __func__, __LINE__, num_sta, i,tlv_len);
            return -1;
        }
        em_unassoc_sta_metric_t *metric = reinterpret_cast<em_unassoc_sta_metric_t *>(buff + pos);

        unsigned int idx = dm->m_num_unassoc_sta_metrics;

        if (idx >= EM_MAX_UNASSOC_STA)
        {
            em_printfout("%s:%d Max STA limit reached",__func__, __LINE__);
            break;
        }

        memcpy(dm->m_unassoc_sta_metrics[idx].sta_mac, metric->sta_mac,sizeof(mac_address_t));
        dm->m_unassoc_sta_metrics[idx].channel = metric->channel;
        dm->m_unassoc_sta_metrics[idx].op_class = op_class;
        dm->m_unassoc_sta_metrics[idx].rcpi = metric->rcpi;
        dm->m_unassoc_sta_metrics[idx].time_delta = ntohl(metric->time_delta);
        dm_easy_mesh_t::macbytes_to_string(metric->sta_mac, mac_str);

        dm->m_num_unassoc_sta_metrics++;

        pos += sizeof(em_unassoc_sta_metric_t);
    }
    return 0;
}

int em_metrics_t::handle_unassoc_sta_link_metrics_rsp(unsigned char *buff, unsigned int len)
{
    em_tlv_t *tlv;
    unsigned int tmp_len = 0;
    unsigned int tlv_len = 0;
    char *errors[EM_MAX_TLV_MEMBERS] = {0};

    if (m_unassoc_in_progress) {
        return -1;
    }

    m_unassoc_in_progress = true;

    if (em_msg_t(em_msg_type_unassoc_sta_link_metrics_rsp, get_profile_type(), buff, len).validate(errors) == 0) {
        em_printfout("Unassoc STA Link Metrics Response validation failed");
        m_unassoc_in_progress = false;
        return -1;
    }

    dm_easy_mesh_t *dm = get_data_model();

    memset(dm->m_unassoc_sta_metrics, 0, sizeof(dm->m_unassoc_sta_metrics));
    dm->m_num_unassoc_sta_metrics = 0;

    tlv = reinterpret_cast<em_tlv_t *>(buff + sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));

    tmp_len = len - static_cast<unsigned int>(sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));

    while (tmp_len >= sizeof(em_tlv_t)) {
        if (tlv->type == em_tlv_type_eom) {
            break;
        }

        tlv_len = static_cast<unsigned int>(ntohs(tlv->len));

        if ((sizeof(em_tlv_t) + tlv_len) > tmp_len) {
            em_printfout("Malformed TLV detected in Unassoc STA Link Metrics Response");
            break;
        }
    
        if (tlv->type == em_tlv_type_unassoc_sta_link_metric_rsp) {
            if (handle_unassoc_sta_link_metrics_tlv(tlv->value, tlv_len) < 0) {
                em_printfout("%s:%d Failed to parse Unassoc STA Link Metrics TLV\n", __func__, __LINE__);
                m_unassoc_in_progress = false;
                return -1;
            }
        }
        tmp_len -= static_cast<unsigned int>(sizeof(em_tlv_t)) + tlv_len;
        tlv = reinterpret_cast<em_tlv_t *>(reinterpret_cast<unsigned char *>(tlv) + sizeof(em_tlv_t) + tlv_len);
    }

    m_unassoc_in_progress = false;
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
        em_printfout("Beacon Metrics Response message validation failed on controller");
        return -1;
    }

    if (len < sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t)) {
        em_printfout("Frame shorter than the 1905 headers");
        return -1;
    }

    tlv = reinterpret_cast<em_tlv_t *> (buff + sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));
    tmp_len = len - static_cast<unsigned int> (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));
    while ((tmp_len >= sizeof(em_tlv_t)) && (tlv->type != em_tlv_type_eom)) {
        /* Stop before a TLV that runs past the received bytes; tmp_len would underflow. */
        size_t tlv_total = sizeof(em_tlv_t) + static_cast<size_t> (ntohs(tlv->len));
        if (tmp_len < tlv_total) {
            em_printfout("Truncated beacon metrics TLV, stopping");
            break;
        }
        if (tlv->type == em_tlv_type_bcon_metric_rsp) {
            if (ntohs(tlv->len) < 8) {
                em_printfout("Beacon metrics TLV too short");
                return -1;
            }
            report_len = static_cast<unsigned int>(ntohs(tlv->len) - 8);
            if (report_len > sizeof(em_sta_info_t::beacon_report_elem)) {
                report_len = sizeof(em_sta_info_t::beacon_report_elem);
            }
            response = reinterpret_cast<em_beacon_metrics_resp_t *> (tlv->value);
            break;
        }
        tmp_len -= static_cast<unsigned int> (tlv_total);
        tlv = reinterpret_cast<em_tlv_t *> (reinterpret_cast<unsigned char *> (tlv) + tlv_total);
    }

    if (response == NULL) {
        em_printfout("Beacon Metrics Response: no beacon metrics response TLV found");
        return -1;
    }

    // Raw 802.11 Measurement Report IE layout (beacon type):
    //   [0]=elem-id [1]=length [2]=token [3]=report-mode [4]=report-type
    //   [5]=op-class [6]=channel [7..14]=start-time [15..16]=duration
    //   [17]=frame-info [18]=RCPI [19]=RSNI [20..25]=BSSID
    static constexpr unsigned int BSSID_OFFSET_IN_BEACON_RPT_IE = 20;
    static constexpr unsigned int MIN_BEACON_RPT_IE_LEN = 26; // through BSSID
    if (response->meas_rprt_count > 0 &&
            report_len >= MIN_BEACON_RPT_IE_LEN) {
        const unsigned char *first_ie = response->meas_reports;
        mac_address_t null_bssid = {};
        if (memcmp(first_ie + BSSID_OFFSET_IN_BEACON_RPT_IE, null_bssid, sizeof(mac_address_t)) == 0) {
            em_printfout("Beacon Metrics Response: null BSSID in report, discarding stub measurement for sta:%s",
                util::mac_to_string(response->sta_mac_addr).c_str());
            return 0;
        }
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
        em_printfout("Beacon Metrics Response: sta not found in controller data model");
        return -1;
    }

    sta->m_sta_info.num_beacon_meas_report = response->meas_rprt_count;
    sta->m_sta_info.beacon_report_len = report_len;
    memcpy(sta->m_sta_info.beacon_report_elem, response->meas_reports, static_cast<size_t> (report_len));

    // Clear the timestamp so new queries can be sent immediately after a response
    sta->m_sta_info.beacon_query_sent_time = 0;

    em_printfout("Beacon Metrics Response rcvd for sta:%s reports:%u len:%u",
        util::mac_to_string(sta->m_sta_info.id).c_str(),
        sta->m_sta_info.num_beacon_meas_report, sta->m_sta_info.beacon_report_len);

    // Send 1905 ACK back to the agent
    em_cmdu_t *cmdu = reinterpret_cast<em_cmdu_t *>(buff + sizeof(em_raw_hdr_t));
    send_beacon_metrics_ack(ntohs(cmdu->id));

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
        em_printfout("Beacon Metrics response ACK send failed, error:%d", errno);
        return -1;
    }

    em_printfout("Beacon Metrics response ACK sent for msg_id=%u", msg_id);
    return static_cast<int>(len);
}

int em_metrics_t::handle_ap_metrics_tlv(unsigned char *buff, unsigned int tlv_len, bssid_t get_bssid)
{
    em_ap_metric_t *ap_metrics;
    em_bss_info_t *bss;
    mac_addr_str_t bss_str;
    mac_address_t zero_bssid = {0};

    if (buff == NULL || tlv_len < sizeof(em_ap_metric_t)) {
        return -1;
    }

    ap_metrics = reinterpret_cast<em_ap_metric_t *> (buff);

    /* Unconfigured VAP: its zeroed utilization would clobber the radio's real value. */
    if (memcmp(ap_metrics->bssid, zero_bssid, sizeof(mac_address_t)) == 0) {
        return 0;
    }

    bss = get_data_model()->get_bss_info_with_mac(ap_metrics->bssid);

    memcpy(get_bssid, ap_metrics->bssid, sizeof(mac_addr_t));
    if (bss != NULL) {
        bss->numberofsta = htons(ap_metrics->num_sta);
        bss->channel_util = ap_metrics->channel_util;
        /* ruid.mac holds the owning radio's interface MAC, which get_radio() matches. */
        dm_radio_t *radio = get_data_model()->get_radio(bss->ruid.mac);
        if (radio != NULL) {
            radio->m_radio_info.utilization = ap_metrics->channel_util;
        }
        dm_easy_mesh_t::macbytes_to_string(ap_metrics->bssid, bss_str);
    } else {
        dm_easy_mesh_t::macbytes_to_string(ap_metrics->bssid, bss_str);
        em_printfout("Error: BSS not found: %s", bss_str);
    }

    return 0;
}

int em_metrics_t::handle_ap_ext_metrics_tlv(unsigned char *buff, unsigned int tlv_len)
{
    em_ap_ext_metric_t *ap_ext_metrics;
    em_bss_info_t *bss;
    mac_addr_str_t bss_str;
    uint32_t bytes;

    if (buff == NULL || tlv_len < sizeof(em_ap_ext_metric_t)) {
        return -1;
    }

    ap_ext_metrics = reinterpret_cast<em_ap_ext_metric_t *> (buff);
    bss = get_data_model()->get_bss_info_with_mac(ap_ext_metrics->bssid);
    if (bss == NULL) {
        dm_easy_mesh_t::macbytes_to_string(ap_ext_metrics->bssid, bss_str);
        em_printfout("Error: BSS not found: %s", bss_str);
        return -1;
    }

    memcpy(&bytes, ap_ext_metrics->uni_bytes_sent, sizeof(bytes));
    bss->unicast_bytes_sent = ntohl(bytes);
    memcpy(&bytes, ap_ext_metrics->uni_bytes_recv, sizeof(bytes));
    bss->unicast_bytes_rcvd = ntohl(bytes);
    memcpy(&bytes, ap_ext_metrics->multi_bytes_sent, sizeof(bytes));
    bss->multicast_bytes_sent = ntohl(bytes);
    memcpy(&bytes, ap_ext_metrics->multi_bytes_recv, sizeof(bytes));
    bss->multicast_bytes_rcvd = ntohl(bytes);
    memcpy(&bytes, ap_ext_metrics->bcast_bytes_sent, sizeof(bytes));
    bss->broadcast_bytes_sent = ntohl(bytes);
    memcpy(&bytes, ap_ext_metrics->bcast_bytes_recv, sizeof(bytes));
    bss->broadcast_bytes_rcvd = ntohl(bytes);

    return 0;
}

int em_metrics_t::handle_radio_metrics_tlv(unsigned char *buff, unsigned int tlv_len)
{
    em_radio_metric_t *radio_metrics;
    dm_radio_t *radio;
    mac_addr_str_t radio_str;

    if (buff == NULL || tlv_len < sizeof(em_radio_metric_t)) {
        return -1;
    }

    radio_metrics = reinterpret_cast<em_radio_metric_t *> (buff);
    radio = get_data_model()->get_radio(radio_metrics->ruid);
    if (radio == NULL) {
        dm_easy_mesh_t::macbytes_to_string(radio_metrics->ruid, radio_str);
        em_printfout("Error: Radio not found: %s", radio_str);
        return -1;
    }

    radio->m_radio_info.noise = radio_metrics->noise;
    radio->m_radio_info.transmit = radio_metrics->transmit;
    radio->m_radio_info.receive_self = radio_metrics->rece_self;
    radio->m_radio_info.receive_other = radio_metrics->rece_other;

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
        em_printfout("Error: sta not found: %s for bssid: %s", util::mac_to_string(sta_metrics->sta_mac).c_str(),
            util::mac_to_string(bssid).c_str());
        return -1;
    }

    sta->m_sta_info.bytes_tx        = ntohl(sta_metrics->tx_bytes);
    sta->m_sta_info.bytes_rx        = ntohl(sta_metrics->rx_bytes);
    sta->m_sta_info.pkts_tx         = ntohl(sta_metrics->tx_pkts);
    sta->m_sta_info.pkts_rx         = ntohl(sta_metrics->rx_pkts);
    sta->m_sta_info.errors_tx       = ntohl(sta_metrics->tx_pkt_errors);
    sta->m_sta_info.errors_rx       = ntohl(sta_metrics->rx_pkt_errors);
    sta->m_sta_info.retrans_count   = ntohl(sta_metrics->retx_cnt);

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

        /* sample_count is wire data: reject counts past the array or the received bytes. */
        if (link_report->sample_count < 0 ||
            static_cast<size_t>(link_report->sample_count) > EM_MAX_SAMPLES_PER_LINK_REPORT ||
            len < alarm_offset + static_cast<size_t>(link_report->sample_count) * sizeof(em_alarm_samples_t)) {
            em_printfout("Invalid alarm sample_count %d (len %zu)", link_report->sample_count, len);
            break;
        }

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
    bssid_t bssid = {};

    dm = get_data_model();

    if (em_msg_t(em_msg_type_ap_metrics_rsp, get_profile_type(), buff, len).validate(errors) == 0) {
        printf("%s:%d: AP Metrics metrics response msg validation failed\n", __func__, __LINE__);
        return -1;
    }

    if (len < sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t)) {
        em_printfout("Frame shorter than the 1905 headers");
        return -1;
    }

    tlv_start =  reinterpret_cast<em_tlv_t *> (buff + sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));
    base_len = static_cast<size_t> (len) - (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));

    // Single-pass loop: maintain running BSSID context so per-STA TLVs can be associated with the correct BSS
    tlv = tlv_start;
    tmp_len = base_len;

    while ((tmp_len >= sizeof(em_tlv_t)) && (tlv->type != em_tlv_type_eom)) {
        /* Stop before a TLV that runs past the received bytes; tmp_len would underflow. */
        size_t tlv_total = sizeof(em_tlv_t) + static_cast<size_t> (ntohs(tlv->len));
        if (tmp_len < tlv_total) {
            em_printfout("Truncated AP metrics TLV, stopping");
            break;
        }
        switch (tlv->type) {
            case em_tlv_type_ap_metrics:
                // Update current BSSID context; subsequent per-STA TLVs use this value.
                if (handle_ap_metrics_tlv(tlv->value, ntohs(tlv->len), bssid) != 0) {
                    em_printfout("ap_metrics_tlv failed, skipping TLV");
                }
                break;
            case em_tlv_type_ap_ext_metric:
                if (handle_ap_ext_metrics_tlv(tlv->value, ntohs(tlv->len)) != 0) {
                    em_printfout("ap_ext_metrics_tlv failed, skipping TLV");
                }
                break;
            case em_tlv_type_radio_metric:
                if (handle_radio_metrics_tlv(tlv->value, ntohs(tlv->len)) != 0) {
                    em_printfout("radio_metrics_tlv failed, skipping TLV");
                }
                break;
            case em_tlv_type_assoc_sta_traffic_sts:
                if (handle_assoc_sta_traffic_stats(tlv->value, bssid) != 0) {
                    em_printfout("assoc_sta_traffic_stats failed, skipping TLV");
                }
                break;
            case em_tlv_type_assoc_sta_link_metric:
                if (handle_assoc_sta_link_metrics_tlv(tlv->value, ntohs(tlv->len)) != 0) {
                    em_printfout("assoc_sta_link_metrics_tlv failed, skipping TLV");
                }
                break;
            case em_tlv_type_assoc_sta_ext_link_metric:
                if (handle_assoc_sta_ext_link_metrics_tlv(tlv->value, ntohs(tlv->len)) != 0) {
                    em_printfout("assoc_sta_ext_link_metrics_tlv failed, skipping TLV");
                }
                break;
            case em_tlv_type_assoc_wifi6_sta_rprt:
                /* future implementation */
                break;
            case em_tlv_type_vendor_specific:
                if (handle_assoc_sta_vendor_link_metrics_tlv(tlv->value, ntohs(tlv->len)) != 0) {
                    em_printfout("assoc_sta_vendor_link_metrics_tlv failed, skipping TLV");
                }
                break;
            default:
                break;
        }
        tmp_len -= tlv_total;
        tlv = reinterpret_cast<em_tlv_t *> (reinterpret_cast<unsigned char *> (tlv) + tlv_total);
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
        tmp_len -= (sizeof(em_tlv_t) + static_cast<size_t> (ntohs(tlv->len)));
        tlv = reinterpret_cast<em_tlv_t *> (reinterpret_cast<unsigned char *> (tlv) + sizeof(em_tlv_t) + ntohs(tlv->len));
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
    sz = create_error_code_tlv(tlv->value, sta_mac, sta_found, false);
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

short em_metrics_t::send_single_beacon_metrics_query(mac_address_t sta_mac, bssid_t bssid)
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
    em_cmd_t *cmd = get_current_cmd();
    bool ack_gated_retry = (cmd != NULL && cmd->get_data_model() != NULL &&
        cmd->supports_retry_state());

    // For assoc/beacon_report commands: retry once per second until ACK is received for the tracked MID.
    static constexpr time_t BEACON_QUERY_RETRY_SECS = 1;
    static constexpr time_t BEACON_QUERY_TIMEOUT_SECS = 10;

    time_t now = time(NULL);
    if (ack_gated_retry == TRUE) {
        time_t last_tx = cmd->get_query_tx_time();
        int elapsed = now - last_tx;
        if (last_tx != 0 && elapsed < BEACON_QUERY_RETRY_SECS) {
            // em_printfout("Beacon Metrics Query retry window active for sta:%s (sent %lds ago), skipping.......",
            //     util::mac_to_string(sta_mac).c_str(),
            // static_cast<long>(elapsed));
            return 0;
        }
    } else {
        dm_sta_t *dm_sta = dm->find_sta(sta_mac, bssid);
        if (dm_sta != NULL && dm_sta->m_sta_info.beacon_query_sent_time != 0) {
            if ((now - dm_sta->m_sta_info.beacon_query_sent_time) < BEACON_QUERY_TIMEOUT_SECS) {
                // em_printfout("Beacon Metrics Query retry window active for sta:%s (sent %lds ago), skipping.......",
                // util::mac_to_string(sta_mac).c_str(),
                // static_cast<long>(now - dm_sta->m_sta_info.beacon_query_sent_time));
            return 0;
            }
        }
    }

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
    unsigned short tracked_msg_id = 0;
    if (ack_gated_retry) {
        tracked_msg_id = cmd->get_data_model()->get_msg_id();
    }
    unsigned short query_msg_id = (tracked_msg_id != 0) ? tracked_msg_id : get_mgr()->get_next_msg_id();
    // em_printfout("  MID=%u for sta:%s", query_msg_id, util::mac_to_string(sta_mac).c_str());

    cmdu->id = htons(query_msg_id);
    cmdu->last_frag_ind = 1;
    cmdu->relay_ind = 0;

    tmp += sizeof(em_cmdu_t);
    len += sizeof(em_cmdu_t);

    //Beacon Metrics Query TLV (see section 17.2.27).
    tlv = reinterpret_cast<em_tlv_t *> (tmp);
    tlv->type = em_tlv_type_bcon_metric_query;
    // When the controller is forwarding a received beacon query, use its cmd params directly.
    if (get_state() == em_state_beacon_report_pending && cmd != NULL) {
        em_cmd_beacon_metrics_param_t *params = &cmd->get_param()->u.beacon_metrics_params;
        sz = create_beacon_metrics_query_tlv(tlv->value, params->sta_mac_addr, params->bssid);
    } else {
        sz = create_beacon_metrics_query_tlv(tlv->value, sta_mac, bssid);
    }
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

    // Track outstanding query MID in the current command DM for ACK correlation.
    if (ack_gated_retry && tracked_msg_id == 0) {
        cmd->get_data_model()->set_msg_id(query_msg_id);
    }

    if (ack_gated_retry) {
        cmd->set_query_tx_time(now);
    }

    em_printfout("Beacon Metrics Query send success for sta:%s", util::mac_to_string(sta_mac).c_str());

    // For non command-local
    if (!ack_gated_retry) {
        dm_sta_t *sta_sent = dm->find_sta(sta_mac, bssid);
        if (sta_sent != NULL) {
            sta_sent->m_sta_info.beacon_query_sent_time = now;
        }
    }

    return static_cast<short> (len);
}

short em_metrics_t::send_beacon_metrics_query(mac_address_t sta_mac, bssid_t bssid)
{
    dm_easy_mesh_t *dm = get_data_model();
    em_assoc_sta_mld_info_t *mld_info = NULL;

    if (dm == NULL) {
        return 0;
    }

    //check if mlo, then trigger multiple query based on links
    if (dm->is_sta_mld(sta_mac) == true) {
        // Resolve whether this STA belongs to an MLD client.
        for (unsigned int mld = 0; mld < dm->get_num_assoc_sta_mld(); mld++) {
            em_assoc_sta_mld_info_t &assoc_sta_mld_info = dm->m_assoc_sta_mld[mld].m_assoc_sta_mld_info;
            if (memcmp(assoc_sta_mld_info.mac_addr, sta_mac, sizeof(mac_address_t)) == 0) {
                mld_info = &assoc_sta_mld_info;
                //mld info found
                break;
            }
        }
        if (mld_info == NULL) {
            em_printfout("No MLD info found for STA: %s", util::mac_to_string(sta_mac).c_str());
            return -1;
        }
        for (int i = 0; i < mld_info->num_affiliated_sta; i++) {
            em_printfout("For sta %s, bssid is %s and link_addr is %s", util::mac_to_string(mld_info->mac_addr).c_str(),
                util::mac_to_string(mld_info->affiliated_sta[i].bssid).c_str(), util::mac_to_string(mld_info->affiliated_sta[i].link_addr).c_str());
            em_printfout("Sending %d beacon metrics query for affiliated STA: %s", i, util::mac_to_string(mld_info->mac_addr).c_str());

            send_single_beacon_metrics_query(sta_mac, mld_info->affiliated_sta[i].bssid);
        }
    } else {
        em_printfout("Sending beacon metrics query for STA: %s", util::mac_to_string(sta_mac).c_str());
        send_single_beacon_metrics_query(sta_mac, bssid);
    }

    return 0;
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
    bool sta_found = false;
    dm_sta_t *sta;

    sta = reinterpret_cast<dm_sta_t *> (hash_map_get_first(get_current_cmd()->get_data_model()->m_sta_map));
    if (sta == NULL) {
        em_printfout("No STA in beacon report data model, cannot send response");
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
    sz = create_error_code_tlv(tlv->value, sta->m_sta_info.id, sta_found, false);
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
        em_printfout("Beacon Metrics Response validation failed");
        return -1;
    }

    if (send_frame(buff, static_cast<unsigned int> (len))  < 0) {
        em_printfout("Beacon Metrics Response send failed, error:%d", errno);
        return -1;
    }

    em_printfout("Beacon Metrics Response send success for sta:%s reports:%u",
        util::mac_to_string(sta->m_sta_info.id).c_str(), sta->m_sta_info.num_beacon_meas_report);

    set_state(em_state_beacon_report_complete);
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

        mac_address_t zero_bssid = {0};
        if (memcmp(dm->m_bss[bss_index].get_bss_info()->bssid.mac, zero_bssid, sizeof(mac_address_t)) == 0) {
            /* Unconfigured VAP with no BSSID assigned; do not emit metrics for it. */
            continue;
        }

        tlv = reinterpret_cast<em_tlv_t *> (tmp);
        tlv->type = em_tlv_type_ap_metrics;
        sz = create_ap_metrics_tlv(tlv->value, dm->m_bss[bss_index]);
        tlv->len =  htons(static_cast<unsigned short> (sz));

        tmp += (sizeof(em_tlv_t) + static_cast<size_t> (sz));
        len += (sizeof(em_tlv_t) + static_cast<size_t> (sz));

        //AP Extended Metrics TLV (17.2.61)
        if (get_profile_type() > em_profile_type_1) {
            tlv = reinterpret_cast<em_tlv_t *> (tmp);
            tlv->type = em_tlv_type_ap_ext_metric;
            sz = create_ap_ext_metrics_tlv(tlv->value, dm->m_bss[bss_index]);
            tlv->len =  htons(static_cast<unsigned short> (sz));

            tmp += (sizeof(em_tlv_t) + static_cast<size_t> (sz));
            len += (sizeof(em_tlv_t) + static_cast<size_t> (sz));
        }

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
            if (get_profile_type() > em_profile_type_1) {
                tlv = reinterpret_cast<em_tlv_t *> (tmp);
                tlv->type = em_tlv_type_assoc_sta_ext_link_metric;
                sz = create_assoc_ext_sta_link_metrics_tlv(tlv->value, sta->m_sta_info.id, sta);
                tlv->len =  htons(static_cast<unsigned short> (sz));

                tmp += (sizeof(em_tlv_t) + static_cast<size_t> (sz));
                len += (sizeof(em_tlv_t) + static_cast<size_t> (sz));
            }

            //Associated Wi-Fi 6 STA Status Report TLV (17.2.73)
            //Profile-3 msg, hence failing even though optional
            if (get_profile_type() > em_profile_type_2) {
                tlv = reinterpret_cast<em_tlv_t *> (tmp);
                tlv->type = em_tlv_type_assoc_wifi6_sta_rprt;
                sz = create_assoc_wifi6_sta_sta_report_tlv(tlv->value, sta);
                tlv->len =  htons(static_cast<unsigned short> (sz));

                tmp += (sizeof(em_tlv_t) + static_cast<size_t> (sz));
                len += (sizeof(em_tlv_t) + static_cast<size_t> (sz));
            }

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
        if (get_profile_type() > em_profile_type_1) {
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
    }

    // End of message
    tlv = reinterpret_cast<em_tlv_t *> (tmp);
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof(em_tlv_t));
    len += (sizeof(em_tlv_t));

    if (em_msg_t(em_msg_type_ap_metrics_rsp, get_profile_type(), buff, static_cast<unsigned int> (len)).validate(errors) == 0) {
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
    em_op_class_info_t *op_class = nullptr;
    
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

    if (ssid_found == false) {
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

    // Derive op_class and channel from the operating channel report data
    for (unsigned int i = 0; i < dm->m_num_opclass; i++) {
        em_op_class_info_t *candidate = &dm->m_op_class[i].m_op_class_info;
        if ((memcmp(candidate->id.ruid, dm->m_bss[j].m_bss_info.id.ruid, sizeof(mac_address_t)) == 0) &&
                (candidate->id.type == em_op_class_type_current)) {
            op_class = candidate;
            break;
        }
    }
    if (op_class == nullptr) {
        em_printfout("Could not get current op_class from operating channel report for ruid, cannot build beacon query");
        return -1;
    }

    unsigned char def_channel = (op_class->channel == 0) ? 255 : static_cast<unsigned char>(op_class->channel);
    if (op_class->channel == 0) {
        em_printfout("Operating channel report had channel 0, falling back to channel 255 (wildcard)");
    } else {
        em_printfout("Using AP operating channel %u from operating channel report for beacon request", op_class->channel);
    }

    em_beacon_metrics_query_t *beacon_metrics = reinterpret_cast<em_beacon_metrics_query_t*> (buff);

    memcpy(beacon_metrics->sta_mac_addr, sta_mac, sizeof(mac_addr_t));
    len += sizeof(beacon_metrics->sta_mac_addr);

    beacon_metrics->op_class = op_class->op_class;
    len += sizeof(beacon_metrics->op_class);

    beacon_metrics->channel_num = def_channel;
    len += sizeof(beacon_metrics->channel_num);

    memcpy(beacon_metrics->bssid, bssid, sizeof(bssid_t));
    len += sizeof(beacon_metrics->bssid);

    beacon_metrics->rprt_detail = 1;
    len += sizeof(beacon_metrics->rprt_detail);

    beacon_metrics->ssid_len = strlen(ssid);
    len += sizeof(beacon_metrics->ssid_len);

    memcpy(beacon_metrics->ssid, ssid, beacon_metrics->ssid_len);
    len += beacon_metrics->ssid_len;

    // Single AP Channel Report with only the current operating channel
    uint8_t num_rprts = 1;
    *(buff + len) = num_rprts;
    len += sizeof(uint8_t);

    // AP Channel Report: length = 2 (1 byte op_class + 1 byte channel)
    uint8_t rprt_len = 2;
    *(buff + len) = rprt_len;
    len += sizeof(uint8_t);

    *(buff + len) = static_cast<uint8_t>(op_class->op_class);
    len += sizeof(uint8_t);

    *(buff + len) = def_channel;
    len += sizeof(uint8_t);

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

short em_metrics_t::create_error_code_tlv(unsigned char *buff, mac_address_t sta, bool sta_found, bool is_associated)
{
    short len = 0;
    unsigned char *tmp = buff;
    unsigned char reason = 0;

    /* if(sta_found == false)
    {
        reason = 0x02;
    } */

    (void)sta_found;
    if (is_associated) {
        reason = 0x01;   // STA is associated (Unassoc Query error)
    } else {
        reason = 0x00;   // default / no error / legacy behavior
    }

    memcpy(tmp, &reason, sizeof(unsigned char));
    tmp += sizeof(unsigned char);
    len += static_cast<short> (sizeof(unsigned char));

    memcpy(tmp, sta, sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += static_cast<short> (sizeof(mac_address_t));

    return len;
}

int em_metrics_t::handle_1905_ack(unsigned char *buff, unsigned int len)
{
    std::vector<em_t *> em_radios;
    em_t *matched_em = nullptr;
    mac_address_t src_mac;
    bool is_beacon_query_ack = false;

    (void)len;

    em_cmdu_t *cmdu = reinterpret_cast<em_cmdu_t *>(buff + sizeof(em_raw_hdr_t));

    unsigned short response_msg_id = ntohs(cmdu->id);

    em_raw_hdr_t *hdr = reinterpret_cast<em_raw_hdr_t *>(buff);

    memcpy(src_mac, hdr->src, sizeof(mac_address_t));

    get_mgr()->get_all_em_for_al_mac(src_mac, em_radios);

    for (auto &em : em_radios) {
        if ((em->get_state() == em_state_ctrl_unassoc_sta_link_metrics_pending) &&
            (response_msg_id == em->get_unassoc_sta_query_msg_id())) {
            matched_em = em;
            em->clear_unassoc_sta_query_msg_id();
            break;
        }

        em_cmd_t *cmd = em->get_current_cmd();
        if (cmd != NULL &&
            cmd->supports_retry_state() &&
            em->get_state() == em_state_beacon_report_pending &&
            cmd->get_data_model() != NULL &&
            response_msg_id == cmd->get_data_model()->get_msg_id()) {
            matched_em = em;
            is_beacon_query_ack = true;
            cmd->get_data_model()->set_msg_id(0);
            cmd->clear_query_tx_time();
            break;
        }
    }

    if (matched_em != nullptr) {
        if (is_beacon_query_ack) {
            matched_em->set_state(em_state_beacon_report_complete);
        }
    }

    em_radios.clear();
    if (is_beacon_query_ack) {
        em_printfout("Beacon Metrics Query ACK handled successfully, moving beacon_report to fini");
    } else {
        em_printfout("Unassociated STA Link Metrics Query Ack handled successfully");
    }
    return 0;
}

int em_metrics_t::send_1905_ack_unassoc_sta_query(mac_address_t *sta_list, 
		                        int sta_count, unsigned short msg_id)
{
    unsigned char buff[MAX_EM_BUFF_SZ];
    char *errors[EM_MAX_TLV_MEMBERS] = {0};

    unsigned int len = 0;
    unsigned char *tmp = buff;
    unsigned short type = htons(ETH_P_1905);

    em_cmdu_t *cmdu;
    em_tlv_t *tlv;

    dm_easy_mesh_t *dm = get_data_model();

    // --------------------------------------
    // Ethernet Header and CMDU
    // --------------------------------------
    memcpy(tmp, dm->get_ctrl_al_interface_mac(), sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len +=  static_cast<short> (sizeof(mac_address_t));

    memcpy(tmp, dm->get_agent_al_interface_mac(), sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len +=  static_cast<short> (sizeof(mac_address_t));

    memcpy(tmp, &type, sizeof(unsigned short));
    tmp += sizeof(unsigned short);
    len += static_cast<unsigned int>(sizeof(unsigned short));;

    cmdu = reinterpret_cast<em_cmdu_t *>(tmp);
    memset(tmp, 0, sizeof(em_cmdu_t));

    cmdu->type = htons(em_msg_type_1905_ack);
    cmdu->id = htons(msg_id);
    cmdu->last_frag_ind = 1;
    tmp += sizeof(em_cmdu_t);
    len += static_cast<unsigned int>(sizeof(em_cmdu_t));

    // Error Code TLVs (if any)
    for (int i = 0; i < sta_count; i++) {

        tlv = reinterpret_cast<em_tlv_t *>(tmp);
        tlv->type = em_tlv_type_error_code;

        short sz =  create_error_code_tlv(tlv->value, sta_list[i], true, true);

	tlv->len = htons(static_cast<short unsigned int> (sz));

        tmp += (sizeof(em_tlv_t) + static_cast<size_t> (sz));
        len += (sizeof(em_tlv_t) + static_cast<size_t> (sz));

    }

    tlv = reinterpret_cast<em_tlv_t *>(tmp);
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += sizeof(em_tlv_t);
    len += sizeof(em_tlv_t);

    if (em_msg_t(em_msg_type_1905_ack, em_profile_type_3, buff, len).validate(errors) == 0) {
        printf("%s:%d: ACK validation failed\n", __func__, __LINE__);
        return -1;
    }

    if (send_frame(buff, len) < 0) {
        printf("%s:%d: ACK send failed, error:%d\n", __func__, __LINE__, errno);
        return -1;
    }
    printf("%s:%d: ACK sent (Unassoc STA Query)\n", __func__, __LINE__);

    return static_cast<int> (len);
}

int em_metrics_t::handle_unassoc_sta_link_metrics_query(unsigned char *buff, unsigned int len)
{
    char *errors[EM_MAX_TLV_MEMBERS] = {0};

    if (em_msg_t(em_msg_type_unassoc_sta_link_metrics_query, em_profile_type_3, buff, len).validate(errors) == 0) {
        em_printfout("%s:%d validation failed", __func__,__LINE__);
        return -1;
    }

    em_cmdu_t *cmdu = reinterpret_cast<em_cmdu_t *>(buff + sizeof(em_raw_hdr_t));

    uint16_t msg_id = ntohs(cmdu->id);

    dm_easy_mesh_t *dm = get_data_model();
    dm->set_msg_id(msg_id);

    mac_address_t error_sta_list[EM_MAX_STA_PER_AGENT];
    int error_sta_count = 0;

    unsigned char work_buff[MAX_EM_BUFF_SZ] = {0};
    unsigned char *work_ptr = work_buff;

    auto remaining_work_buf = [&](unsigned char *ptr) -> size_t {
	    return MAX_EM_BUFF_SZ - static_cast<size_t>(ptr - work_buff);
        };

    unsigned char *tlv_ptr = buff + sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t);

    unsigned char *cmdu_end = buff + len;

    while (tlv_ptr + sizeof(em_tlv_t) <= cmdu_end) {

        em_tlv_t *tlv = reinterpret_cast<em_tlv_t *>(tlv_ptr);

        if (tlv->type == em_tlv_type_eom) {
            break;
        }

        uint16_t tlv_len = ntohs(tlv->len);

        if ((tlv_ptr + sizeof(em_tlv_t) + tlv_len) > cmdu_end) {
            em_printfout("%s:%d TLV overflow", __func__,__LINE__);
            return -1;
        }

        if (tlv->type == em_tlv_type_unassoc_sta_link_metric_query) {

            unsigned char *query_ptr = tlv->value;
            unsigned char *query_end = query_ptr + tlv_len;

            while (query_ptr + 2 <= query_end) {

                uint8_t op_class = *query_ptr++;
                uint8_t num_channels = *query_ptr++;

                if (num_channels > EM_MAX_CHANNELS_PER_OPCLASS) {
                    em_printfout("%s:%d Invalid num_channels=%u (max=%u)", __func__, __LINE__, num_channels, EM_MAX_CHANNELS_PER_OPCLASS);
                    return -1;
                }

                if (remaining_work_buf(work_ptr) < 2) {
                    em_printfout("%s:%d work buffer exhausted", __func__, __LINE__);
                    return -1;
                }

                unsigned char *opclass_start = work_ptr;

                *work_ptr++ = op_class;

                uint8_t *num_channels_field = work_ptr++;
                uint8_t valid_channel_count = 0;

                for (uint8_t channel_idx = 0; channel_idx < num_channels; channel_idx++) {

                    if (query_ptr + 2 > query_end) {
                        break;
                    }

                    uint8_t channel = *query_ptr++;
                    uint8_t num_sta = *query_ptr++;

		    if (num_sta > EM_MAX_STA_PER_CHANNEL) {
                        em_printfout("%s:%d Invalid num_sta=%u (max=%u)",__func__, __LINE__, num_sta, EM_MAX_STA_PER_CHANNEL);
                        return -1;
                    }

                    constexpr size_t CHANNEL_BUF_SIZE = 2 + (EM_MAX_STA_PER_CHANNEL * sizeof(mac_address_t));

                    unsigned char channel_buf[CHANNEL_BUF_SIZE];
                    unsigned char *channel_ptr = channel_buf;

                    *channel_ptr++ = channel;

                    uint8_t *num_sta_field = channel_ptr++;
                    uint8_t valid_sta_count = 0;

                    for (uint8_t sta_idx = 0; sta_idx < num_sta; sta_idx++) {

                        if (query_ptr + sizeof(mac_address_t) > query_end) {
                            break;
                        }

                        mac_address_t sta;
                        memcpy(sta, query_ptr, sizeof(mac_address_t));

                        query_ptr += sizeof(mac_address_t);

			// Check if the STA is associated with any BSS on this agent
                        dm_sta_t *assoc_sta = dm->get_first_sta(sta);
		        bool sta_is_associated = (assoc_sta != NULL);
                        
		        if (sta_is_associated) {
                            bool already_added = false;

                            for (int err_idx = 0; err_idx < error_sta_count; err_idx++) {
                                if (memcmp(error_sta_list[err_idx], sta, sizeof(mac_address_t)) == 0) {
                                    already_added = true;
                                    break;
                                }
                            }

                            if (!already_added && error_sta_count < EM_MAX_STA_PER_AGENT) {
                                memcpy(error_sta_list[error_sta_count], sta, sizeof(mac_address_t));
                                error_sta_count++;
                            }
                        } else {
                            size_t required = sizeof(mac_address_t);

                            if (static_cast<size_t>(channel_ptr - channel_buf) + required > CHANNEL_BUF_SIZE) {

                                em_printfout("%s:%d channel buffer overflow",__func__, __LINE__);
                                return -1;
                            }

                            memcpy(channel_ptr, sta, sizeof(mac_address_t));
                            channel_ptr += sizeof(mac_address_t);
                            valid_sta_count++;
                        }
                    }

                    if (valid_sta_count > 0) {
                        *num_sta_field = valid_sta_count;

                        uint16_t channel_len = static_cast<uint16_t>(2 + (valid_sta_count * sizeof(mac_address_t)));

                        if (remaining_work_buf(work_ptr) < channel_len) {
                            em_printfout("%s:%d work buffer overflow", __func__,  __LINE__);
                            return -1;
                        }

                        memcpy(work_ptr, channel_buf, channel_len);
                        work_ptr += channel_len;
                        valid_channel_count++;
                    }
                }

                if (valid_channel_count == 0) {
                    /* rollback empty opclass */
                    work_ptr = opclass_start;
                } else {
                    *num_channels_field = valid_channel_count;
                }
            }
        }
        tlv_ptr += sizeof(em_tlv_t) + tlv_len;
    }
    send_1905_ack_unassoc_sta_query(error_sta_list, error_sta_count, msg_id);

    if (work_ptr > work_buff) {
        uint16_t work_len = static_cast<uint16_t>(work_ptr - work_buff);
        get_mgr()->io_process(em_bus_event_type_unassoc_sta_link_metrics_query, work_buff, work_len);
        em_printfout("%s:%d Sent Unassoc STA Query to Agent len=%u", __func__, __LINE__, work_len);
    }
    return 0;
}

unsigned short em_metrics_t::create_unassoc_sta_link_metrics_query_tlv(unsigned char *buff, em_unassoc_query_opclass_t *op)
{
    unsigned char *ptr = buff;
    unsigned short len = 0;

    if (op == NULL) {
        em_printfout("op is NULL");
        return 0;
    }

    *ptr++ = op->op_class;
    len++;

    *ptr++ = op->num_channels;
    len++;

    for (int j = 0; j < op->num_channels; j++) {
        auto &ch = op->channel_list[j];

	*ptr++ = ch.channel;
        len++;

        *ptr++ = ch.num_sta;
        len++;
        for (int k = 0; k < ch.num_sta; k++) {
            //Adding STA
            memcpy(ptr, ch.sta_list[k], sizeof(mac_address_t));
            ptr += sizeof(mac_address_t);
            len += static_cast<short>(sizeof(mac_address_t));	    
        }
    }
    return len;
}

int em_metrics_t::send_unassoc_sta_link_metrics_query_msg()
{
    unsigned char buff[MAX_EM_BUFF_SZ];
    unsigned char *tmp = buff;
    unsigned int len = 0;
    char *errors[EM_MAX_TLV_MEMBERS] = {0};

    dm_easy_mesh_t *dm = get_data_model();

    if (dm == NULL) {
        return -1;
    }

    em_cmd_unassoc_sta_query_t *cmd = static_cast<em_cmd_unassoc_sta_query_t *>(get_current_cmd());
    if (cmd == NULL) {
        return -1;
    }

    em_unassoc_query_list_t *query = cmd->get_query();

    if (query == NULL) {
        return -1;
    }

    memset(buff, 0, sizeof(buff));

    memcpy(tmp, dm->get_agent_al_interface_mac(), sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += sizeof(mac_address_t);

    memcpy(tmp, dm->get_ctrl_al_interface_mac(),  sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += sizeof(mac_address_t);

    unsigned short type = htons(ETH_P_1905);
    memcpy(tmp, &type, sizeof(type));
    tmp += sizeof(type);
    len += sizeof(type);

    em_cmdu_t *cmdu = reinterpret_cast<em_cmdu_t *>(tmp);
    memset(cmdu, 0, sizeof(em_cmdu_t));
    cmdu->type = htons(em_msg_type_unassoc_sta_link_metrics_query);

    cmdu->id = htons(get_mgr()->get_next_msg_id());
    cmdu->last_frag_ind = 1;
    cmdu->relay_ind = 0;

    tmp += sizeof(em_cmdu_t);
    len += sizeof(em_cmdu_t);

    // TLVs
    for (int i = 0; i < query->num_opclass; i++) {
        auto &op = query->opclass_list[i];
        unsigned int required_payload = 2;   // op_class + num_channels

        for (int j = 0; j < op.num_channels; j++) {
            required_payload += 2;     // channel + num_sta
            required_payload += static_cast<unsigned int>(op.channel_list[j].num_sta) * sizeof(mac_address_t);
        }

        unsigned int remaining = MAX_EM_BUFF_SZ - static_cast<unsigned int>(tmp - buff);

        if (remaining < (sizeof(em_tlv_t) + required_payload)) {
            em_printfout("%s:%d insufficient buffer space (remaining=%u required=%u)", __func__, __LINE__, remaining, sizeof(em_tlv_t) + required_payload);
            return -1;
        }

        em_tlv_t *tlv = reinterpret_cast<em_tlv_t *>(tmp);
        tlv->type = em_tlv_type_unassoc_sta_link_metric_query;
       
        unsigned int sz = static_cast<unsigned int>(create_unassoc_sta_link_metrics_query_tlv(tlv->value, &op));
       tlv->len = htons(static_cast<uint16_t>(sz));

       tmp += sizeof(em_tlv_t) + static_cast<size_t>(sz);
   
       len += static_cast<unsigned int>(sizeof(em_tlv_t) + static_cast<size_t>(sz));
    }
   
    unsigned int remaining = MAX_EM_BUFF_SZ - static_cast<unsigned int>(tmp - buff);

    if (remaining < sizeof(em_tlv_t)) {
        em_printfout("%s:%d insufficient buffer space for EOM TLV", __func__, __LINE__);
        return -1;
    } 

    em_tlv_t *eom = reinterpret_cast<em_tlv_t *>(tmp);
    eom->type = em_tlv_type_eom;
    eom->len = 0;

    tmp += sizeof(em_tlv_t);
    len += static_cast<unsigned int>(sizeof(em_tlv_t));;

    if (em_msg_t(em_msg_type_unassoc_sta_link_metrics_query, em_profile_type_3, buff, len).validate(errors) == 0) {
        em_printfout("Unassociated STA Link Metrics Query validation failed");
        return -1;
    }

   if (send_frame(buff, len) < 0) {
        em_printfout("%s:%d: Unassoc Query send failed errno=%d",__func__, __LINE__, errno);
        return -1;
    }

    em_printfout("%s:%d: Unassoc Query sent to Agent successfully", __func__, __LINE__);

    em_t *em = static_cast<em_t *>(this);
    em->m_unassoc_sta_query_msg_id = ntohs(cmdu->id);
    em_printfout("%s:%d Stored query msg_id=%u", 
             __func__, __LINE__, em->m_unassoc_sta_query_msg_id);

    m_unassoc_sta_query_msg_id  =  ntohs(cmdu->id);
    
    return static_cast<int>(len);
}

//Unassociated STA Link Metrics Response Part
/*
 * create_unassoc_sta_link_metrics_tlv()
 *
 * Purpose:
 * --------
 * Creates ONE TLV for ONE operating class.
 *
 * Output:
 * -------
 * TLV contains:
 * - op_class
 * - num_sta
 * - all STA metrics for that op_class
 */

unsigned short em_metrics_t::create_unassoc_sta_link_metrics_resp_tlv(unsigned char *buff, unsigned char op_class, em_unassoc_sta_metrics_rsp_t *rsp)
{
    em_unassoc_sta_link_metrics_rsp_t *tlv = reinterpret_cast<em_unassoc_sta_link_metrics_rsp_t *>(buff);

    unsigned short len = 0;
    unsigned char count = 0;

    tlv->op_class = op_class;


    /*
     * Advance length for op_class field
     */
    len += 1;

    /*
     * Reserve space for num_sta field.
     *
     * We do not yet know how many STA entries
     * belong to this op_class.
     *
     * We'll fill tlv->num_sta later.
     */
    len += 1;

    /*
     * TLV buffer layout:
     *
     * --------------------------------------------------
     * | op_class | num_sta | STA metric entries ... |
     * --------------------------------------------------
     *
     * Each STA metric entry contains:
     *   - STA MAC
     *   - channel
     *   - time_delta
     *   - rcpi
     */
    for (unsigned int i = 0; i < rsp->num_entries; i++) {
        /*
         * Skip entries belonging to
         * different operating classes.
         */
        if (rsp->entry[i].op_class != op_class) {
            continue;
        }
        
        em_unassoc_sta_metric_t *sta_metric = reinterpret_cast<em_unassoc_sta_metric_t *>(buff + len);

        memcpy(sta_metric->sta_mac, rsp->entry[i].sta_mac, sizeof(mac_address_t));
        sta_metric->channel = rsp->entry[i].channel;
        sta_metric->time_delta = htonl(rsp->entry[i].time_delta);
        sta_metric->rcpi = rsp->entry[i].rcpi;
        len += sizeof(em_unassoc_sta_metric_t);
        count++;
    }

    tlv->num_sta = count;

    return len;
}

/*
 * send_unassoc_sta_link_metrics_response()
 *
 * Builds and sends ONE response message
 * containing ONE Unassoc STA Link Metrics TLV
 * for ONE operating class.
 */
void em_metrics_t::send_unassoc_sta_link_metrics_resp_msg()	
{
    unsigned char buff[MAX_EM_BUFF_SZ];
    unsigned char *tmp = buff;

    em_cmdu_t *cmdu;
    em_tlv_t *tlv;

    size_t len = 0;

    bool sent_opclass[256] = {false};
    unsigned short type = htons(ETH_P_1905);
    unsigned short msg_type = em_msg_type_unassoc_sta_link_metrics_rsp;

    dm_easy_mesh_t *dm = get_data_model();
    unsigned short msg_id = dm->get_msg_id();
    em_unassoc_sta_metrics_rsp_t *rsp = &dm->m_unassoc_sta_metrics_rsp;

    memcpy(tmp, dm->get_ctl_mac(), sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += sizeof(mac_address_t);

    memcpy(tmp, dm->get_agent_al_interface_mac(), sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += sizeof(mac_address_t);

    memcpy(tmp, &type, sizeof(unsigned short));
    tmp += sizeof(unsigned short);
    len += sizeof(unsigned short);

    cmdu = reinterpret_cast<em_cmdu_t *>(tmp);
    memset(cmdu, 0, sizeof(em_cmdu_t));
    cmdu->type = htons(msg_type);
    cmdu->id = htons(msg_id);
    cmdu->last_frag_ind = 1;
    tmp += sizeof(em_cmdu_t);
    len +=  static_cast<unsigned int>(sizeof(em_cmdu_t)); 

    for (unsigned int i = 0; i < rsp->num_entries; i++) {

        unsigned char op_class = rsp->entry[i].op_class;

        if (sent_opclass[op_class]) {
            continue;
        }

        em_tlv_t *tlv = reinterpret_cast<em_tlv_t *>(tmp);
        memset(tlv, 0, sizeof(em_tlv_t));

        tlv->type = em_tlv_type_unassoc_sta_link_metric_rsp;

        unsigned short sz = create_unassoc_sta_link_metrics_resp_tlv(tlv->value, op_class, rsp);

        unsigned int required = sizeof(em_tlv_t) + sz;

        if ((len + required) > MAX_EM_BUFF_SZ) {
            em_printfout("%s:%d insufficient buffer space for Unassoc STA Metrics TLV (len=%u required=%u max=%u)",__func__, __LINE__,
                                       static_cast<unsigned int>(len), required, MAX_EM_BUFF_SZ);
            return;
        }

        tlv->len = htons(sz);

        tmp += required;
        len += required;
        sent_opclass[op_class] = true;
    }

    tlv = reinterpret_cast<em_tlv_t *>(tmp);
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;
    tmp += sizeof(em_tlv_t);
    len += sizeof(em_tlv_t);

    if (send_frame(buff, static_cast<unsigned int>(len)) < 0) {
        em_printfout("%s:%d: UnAssociated STA Link Metrics Response send failed, error:%d\n", __func__, __LINE__, errno);
	return;
    }
    /*
     * Clear the processed entries after successfully sending the response.
     * This prevents the same Unassociated STA metrics data from being
     * retransmitted if the command is executed again or the state handler 
     * is invoked multiple times for the same response object.
     */
    em_printfout("%s:%d Clearing num_entries after successful response send\n",__func__, __LINE__);
    rsp->num_entries = 0;
    set_state(em_state_agent_configured);
}

void em_metrics_t::process_msg(unsigned char *data, unsigned int len)
{
    em_cmdu_t *cmdu = reinterpret_cast<em_cmdu_t *> (data + sizeof(em_raw_hdr_t));
    em_raw_hdr_t *hdr = reinterpret_cast<em_raw_hdr_t *>(data);
    std::vector<em_t *> em_radios;

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
            em_radios.clear();
            get_mgr()->get_all_em_for_al_mac(hdr->src, em_radios);
            for (auto &em : em_radios) {
                em->handle_beacon_metrics_response(data, len);
                break;
            }
            break;

        case em_msg_type_ap_metrics_rsp:
            handle_ap_metrics_response(data, len);
            break;
        case em_msg_type_topo_vendor:
            handle_vendor_msg(data, len);
            break;
        case em_msg_type_unassoc_sta_link_metrics_query:
            handle_unassoc_sta_link_metrics_query(data, len);
            break;
        case em_msg_type_unassoc_sta_link_metrics_rsp:
            handle_unassoc_sta_link_metrics_rsp(data, len);
            break;
        case em_msg_type_1905_ack:
            handle_1905_ack(data, len);
            break;

        case em_msg_type_failed_conn:
            get_mgr()->handle_failed_conn_msg(data, len);
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
        case em_state_ctrl_unassoc_sta_link_metrics_pending:
            send_unassoc_sta_link_metrics_query_msg();
            break;
	    
        default:
            printf("%s:%d: unhandled case %s\n", __func__, __LINE__, em_t::state_2_str(get_state()));
            break;
    }
}

void em_metrics_t::process_agent_state()
{
    em_cmd_t *cmd = get_current_cmd();

    switch (get_state()) {
        case em_state_agent_sta_link_metrics_pending:
            send_associated_sta_link_metrics_resp_msg();
            break;

        case em_state_agent_link_quality_report_pending:
            send_link_quality_report();
            break;

        case em_state_agent_unassoc_sta_metrics_report_pending:
            send_unassoc_sta_link_metrics_resp_msg();
            break;

        case em_state_beacon_report_pending:
            send_beacon_metrics_response();
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

em_metrics_t::em_metrics_t()
{

}

em_metrics_t::~em_metrics_t()
{

}
