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
#include "dm_sta.h"
#include "dm_easy_mesh.h"
#include "dm_easy_mesh_ctrl.h"
#include "util.h"

int dm_sta_t::decode(const cJSON *obj, void *parent_id)
{
    cJSON *tmp;
    mac_addr_str_t  mac_str;

    mac_address_t *bssid = static_cast<mac_address_t *>(parent_id);

    memset(&m_sta_info, 0, sizeof(em_sta_info_t));
    memcpy(&m_sta_info.bssid,bssid,sizeof(mac_address_t));

    if ((tmp = cJSON_GetObjectItem(obj, "MACAddress")) != NULL) {
        snprintf(mac_str, sizeof(mac_str), "%s", cJSON_GetStringValue(tmp));
        dm_easy_mesh_t::string_to_macbytes(mac_str, m_sta_info.id);
    }

    if ((tmp = cJSON_GetObjectItem(obj, "LastDataUplinkRate")) != NULL) {
        m_sta_info.last_ul_rate = static_cast<unsigned int>(tmp->valuedouble);
    }

    if ((tmp = cJSON_GetObjectItem(obj, "TimeStamp")) != NULL) {
        snprintf(m_sta_info.timestamp, sizeof(m_sta_info.timestamp), "%s", cJSON_GetStringValue(tmp));
    }

    if ((tmp = cJSON_GetObjectItem(obj, "LastDataDownlinkRate")) != NULL) {
        m_sta_info.last_dl_rate = static_cast<unsigned int>(tmp->valuedouble);
    }

    if ((tmp = cJSON_GetObjectItem(obj, "EstMACDataRateUplink")) != NULL) {
        m_sta_info.est_ul_rate = static_cast<unsigned int>(tmp->valuedouble);
    }

    if ((tmp = cJSON_GetObjectItem(obj, "EstMACDataRateDownlink")) != NULL) {
        m_sta_info.est_dl_rate = static_cast<unsigned int>(tmp->valuedouble);
    }

    if ((tmp = cJSON_GetObjectItem(obj, "LastConnectTime")) != NULL) {
        m_sta_info.last_conn_time = static_cast<unsigned int>(tmp->valuedouble);
    }

    if ((tmp = cJSON_GetObjectItem(obj, "RetransCount")) != NULL) {
        m_sta_info.retrans_count = static_cast<unsigned int>(tmp->valuedouble);
    }

    if ((tmp = cJSON_GetObjectItem(obj, "SignalStrength")) != NULL) {
        m_sta_info.signal_strength = static_cast<int>(tmp->valuedouble);
    }

    if ((tmp = cJSON_GetObjectItem(obj, "RCPI")) != NULL) {
        m_sta_info.rcpi = static_cast<unsigned char>(tmp->valuedouble);
    }

    if ((tmp = cJSON_GetObjectItem(obj, "UtilizationTransmit")) != NULL) {
        m_sta_info.util_tx = static_cast<unsigned int>(tmp->valuedouble);
    }

    if ((tmp = cJSON_GetObjectItem(obj, "UtilizationReceive")) != NULL) {
        m_sta_info.util_rx = static_cast<unsigned int>(tmp->valuedouble);
    }

    if ((tmp = cJSON_GetObjectItem(obj, "PacketsSent")) != NULL) {
        m_sta_info.pkts_tx = static_cast<unsigned int>(tmp->valuedouble);
    }

    if ((tmp = cJSON_GetObjectItem(obj, "PacketsReceived")) != NULL) {
        m_sta_info.pkts_rx = static_cast<unsigned int>(tmp->valuedouble);
    }

    if ((tmp = cJSON_GetObjectItem(obj, "BytesSent")) != NULL) {
        m_sta_info.bytes_tx = static_cast<unsigned int>(tmp->valuedouble);
    }

    if ((tmp = cJSON_GetObjectItem(obj, "BytesReceived")) != NULL) {
        m_sta_info.bytes_rx = static_cast<unsigned int>(tmp->valuedouble);
    }

    if ((tmp = cJSON_GetObjectItem(obj, "ErrorsSent")) != NULL) {
        m_sta_info.errors_tx = static_cast<unsigned int>(tmp->valuedouble);
    }

    if ((tmp = cJSON_GetObjectItem(obj, "ErrorsReceived")) != NULL) {
        m_sta_info.errors_rx = static_cast<unsigned int>(tmp->valuedouble);
    }

    if ((tmp = cJSON_GetObjectItem(obj, "ClientCapabilities")) != NULL) {
        snprintf(m_sta_info.cap, sizeof(m_sta_info.cap), "%s", cJSON_GetStringValue(tmp));
    }

    if ((tmp = cJSON_GetObjectItem(obj, "HTCapabilities")) != NULL) {
        snprintf(m_sta_info.ht_cap, sizeof(m_sta_info.ht_cap), "%s", cJSON_GetStringValue(tmp));
    }

    if ((tmp = cJSON_GetObjectItem(obj, "VHTCapabilities")) != NULL) {
        snprintf(m_sta_info.vht_cap, sizeof(m_sta_info.vht_cap), "%s", cJSON_GetStringValue(tmp));
    }

    if ((tmp = cJSON_GetObjectItem(obj, "HECapabilities")) != NULL) {
        snprintf(m_sta_info.he_cap, sizeof(m_sta_info.he_cap), "%s", cJSON_GetStringValue(tmp));
    }

    if ((tmp = cJSON_GetObjectItem(obj, "CellularDataPreference")) != NULL) {
        snprintf(m_sta_info.cellular_data_pref, sizeof(m_sta_info.cellular_data_pref), "%s", cJSON_GetStringValue(tmp));
    }

    return 0;

}

void dm_sta_t::encode(cJSON *obj, em_get_sta_list_reason_t reason)
{
    mac_addr_str_t  mac_str;
    cJSON *reason_obj, *request_obj;

    dm_sta_t::decode_sta_capability(this);
    dm_sta_t::decode_beacon_report(this);
    dm_easy_mesh_t::macbytes_to_string(m_sta_info.id, mac_str);
    if (strlen(m_sta_info.sta_client_type) != 0) {
        cJSON_AddStringToObject(obj, "ClientType", m_sta_info.sta_client_type);
    }
    cJSON_AddStringToObject(obj, "MACAddress", mac_str);
    cJSON_AddBoolToObject(obj, "Associated", m_sta_info.associated);

    if (reason == em_get_sta_list_reason_none) {
		encode_beacon_report(obj);
	
        cJSON_AddNumberToObject(obj, "LastDataUplinkRate", m_sta_info.last_ul_rate);
        cJSON_AddStringToObject(obj, "TimeStamp", m_sta_info.timestamp);
        cJSON_AddNumberToObject(obj, "EstMACDataRateUplink", m_sta_info.est_ul_rate);
        cJSON_AddNumberToObject(obj, "LastConnectTime", m_sta_info.last_conn_time);
        cJSON_AddNumberToObject(obj, "RetransCount", m_sta_info.retrans_count);
        cJSON_AddNumberToObject(obj, "EstMACDataRateDownlink", m_sta_info.est_dl_rate);
        cJSON_AddStringToObject(obj, "HTCapabilities", m_sta_info.ht_cap);
        cJSON_AddNumberToObject(obj, "SignalStrength", m_sta_info.signal_strength);
        cJSON_AddNumberToObject(obj, "RCPI", m_sta_info.rcpi);
        cJSON_AddNumberToObject(obj, "UtilizationTransmit", m_sta_info.util_tx);
        cJSON_AddStringToObject(obj, "VHTCapabilities", m_sta_info.vht_cap);
        cJSON_AddStringToObject(obj, "HECapabilities", m_sta_info.he_cap);
        cJSON_AddStringToObject(obj, "ClientCapabilities", m_sta_info.cap);
        cJSON_AddNumberToObject(obj, "LastDataDownlinkRate", m_sta_info.last_dl_rate);
        cJSON_AddNumberToObject(obj, "PacketsReceived", m_sta_info.pkts_rx);
        cJSON_AddNumberToObject(obj, "UtilizationReceive", m_sta_info.util_rx);
        cJSON_AddNumberToObject(obj, "BytesSent", m_sta_info.bytes_tx);
        cJSON_AddNumberToObject(obj, "PacketsSent", m_sta_info.pkts_tx);
        cJSON_AddNumberToObject(obj, "BytesReceived", m_sta_info.bytes_rx);
        cJSON_AddNumberToObject(obj, "ErrorsSent", m_sta_info.errors_tx);
        cJSON_AddNumberToObject(obj, "ErrorsReceived", m_sta_info.errors_rx);
        cJSON_AddStringToObject(obj, "CellularDataPreference", m_sta_info.cellular_data_pref);
        cJSON_AddStringToObject(obj, "ListenInterval", m_sta_info.listen_interval);
        cJSON_AddStringToObject(obj, "SSID", m_sta_info.ssid);
        cJSON_AddStringToObject(obj, "SupportedRates", m_sta_info.supp_rates);
        cJSON_AddStringToObject(obj, "PowerCapability", m_sta_info.power_cap);
        cJSON_AddStringToObject(obj, "SupportedChannels", m_sta_info.supp_channels);
        cJSON_AddStringToObject(obj, "RSNInformation", m_sta_info.rsn_info);
        cJSON_AddStringToObject(obj, "ExtendedSupportedRates", m_sta_info.ext_supp_rates);
        cJSON_AddStringToObject(obj, "SupportedOperatingClasses", m_sta_info.supp_op_classes);
        cJSON_AddStringToObject(obj, "ExtendedCapabilities", m_sta_info.ext_cap);
        cJSON_AddStringToObject(obj, "RMEnabledCapabilities", m_sta_info.rm_cap);
        cJSON *vendor_info = cJSON_CreateArray();
        for (unsigned int i = 0; i < m_sta_info.num_vendor_infos; i++) {
            cJSON *vendor = cJSON_CreateObject();
            cJSON_AddStringToObject(vendor, "VendorInfo", m_sta_info.vendor_info[i]);
            cJSON_AddItemToArray(vendor_info, vendor);
        }
        cJSON_AddItemToObject(obj, "VendorSpecific", vendor_info);
    } else if (reason == em_get_sta_list_reason_steer) {
        reason_obj = cJSON_CreateObject();
        cJSON_AddItemToObject(obj, "ClientSteer", reason_obj);
        cJSON_AddStringToObject(reason_obj, "TargetBSSID", "00:00:00:00:00:00");
        request_obj = cJSON_CreateObject();
        cJSON_AddItemToObject(reason_obj, "RequestMode", request_obj);
        cJSON_AddNumberToObject(request_obj, "Steering_Opportunity", 0);
        cJSON_AddNumberToObject(request_obj, "Steering_Mandate", 1);
        cJSON_AddFalseToObject(reason_obj, "BTMDisassociationImminent");
        cJSON_AddFalseToObject(reason_obj, "BTMAbridged");
        cJSON_AddFalseToObject(reason_obj, "LinkRemovalImminent");
        cJSON_AddNumberToObject(reason_obj, "SteeringOpportunityWindow", 1);
        cJSON_AddNumberToObject(reason_obj, "BTMDisassociationTimer", 5);
        cJSON_AddNumberToObject(reason_obj, "TargetBSSOperatingClass", 81);
        cJSON_AddNumberToObject(reason_obj, "TargetBSSChannel", 6);
    } else if (reason == em_get_sta_list_reason_disassoc) {
        reason_obj = cJSON_CreateObject();
        cJSON_AddItemToObject(obj, "Disassociate", reason_obj);
        cJSON_AddNumberToObject(reason_obj, "DisassociationTimer", 0);
        cJSON_AddNumberToObject(reason_obj, "ReasonCode", 0);
        cJSON_AddFalseToObject(reason_obj, "Silent");
    } else if (reason == em_get_sta_list_reason_btm) {
        reason_obj = cJSON_CreateObject();
        cJSON_AddItemToObject(obj, "BTMRequest", reason_obj);
        cJSON_AddTrueToObject(reason_obj, "DisassociationImminent");
        cJSON_AddNumberToObject(reason_obj, "DisassociationTimer", 0);
        cJSON_AddNumberToObject(reason_obj, "BSSTerminationDuration", 0);
        cJSON_AddNumberToObject(reason_obj, "ValidityInterval", 0);
        cJSON_AddNumberToObject(reason_obj, "SteeringTimer", 0);
        cJSON_AddStringToObject(reason_obj, "TargetBSS", "00:00:00:00:00:00");
    } else if (reason == em_get_sta_list_reason_neighbors) {
		encode_beacon_report(obj);
	}
}

void dm_sta_t::encode_beacon_report(cJSON *obj)
{
	mac_addr_str_t mac_str;
    cJSON *neighbors_arr_obj, *neighbor_obj;
	unsigned int i;

	neighbors_arr_obj = cJSON_AddArrayToObject(obj, "Neighbors");
	for (i = 0; i < m_sta_info.num_beacon_meas_report; i++) {
		neighbor_obj = cJSON_CreateObject();
		dm_easy_mesh_t::macbytes_to_string(m_sta_info.beacon_reports[i].bssid, mac_str);
		cJSON_AddStringToObject(neighbor_obj, "BSSID", mac_str);
		cJSON_AddNumberToObject(neighbor_obj, "OpClass", m_sta_info.beacon_reports[i].opClass);
		cJSON_AddNumberToObject(neighbor_obj, "Channel", m_sta_info.beacon_reports[i].channel);
		cJSON_AddNumberToObject(neighbor_obj, "RCPI", m_sta_info.beacon_reports[i].rcpi);

		cJSON_AddItemToArray(neighbors_arr_obj, neighbor_obj);
	}
		
}

bool dm_sta_t::operator == (const dm_sta_t& obj)
{
    int ret = 0;
    ret += (memcmp(&this->m_sta_info.id, &obj.m_sta_info.id, sizeof(mac_address_t)) != 0);
    ret += (memcmp(&this->m_sta_info.sta_client_type, &obj.m_sta_info.sta_client_type, sizeof(em_string_t)) != 0);
    ret += (memcmp(&this->m_sta_info.bssid, &obj.m_sta_info.bssid, sizeof(mac_address_t)) != 0);
    ret += (memcmp(&this->m_sta_info.radiomac, &obj.m_sta_info.radiomac, sizeof(mac_address_t)) != 0);

    ret += !(this->m_sta_info.associated == obj.m_sta_info.associated);
    ret += !(this->m_sta_info.last_ul_rate == obj.m_sta_info.last_ul_rate);
    ret += !(this->m_sta_info.last_dl_rate == obj.m_sta_info.last_dl_rate);
    ret += !(this->m_sta_info.est_ul_rate == obj.m_sta_info.est_ul_rate);
    ret += !(this->m_sta_info.est_dl_rate == obj.m_sta_info.est_dl_rate);
    ret += !(this->m_sta_info.last_conn_time == obj.m_sta_info.last_conn_time);
    ret += !(this->m_sta_info.retrans_count == obj.m_sta_info.retrans_count);
    ret += !(this->m_sta_info.signal_strength == obj.m_sta_info.signal_strength);
    ret += !(this->m_sta_info.rcpi == obj.m_sta_info.rcpi);
    ret += !(this->m_sta_info.util_tx == obj.m_sta_info.util_tx);
    ret += !(this->m_sta_info.util_rx == obj.m_sta_info.util_rx);
    ret += !(this->m_sta_info.pkts_tx == obj.m_sta_info.pkts_tx);
    ret += !(this->m_sta_info.pkts_rx == obj.m_sta_info.pkts_rx);
    ret += !(this->m_sta_info.bytes_tx == obj.m_sta_info.bytes_tx);
    ret += !(this->m_sta_info.bytes_rx == obj.m_sta_info.bytes_rx);
    ret += !(this->m_sta_info.errors_tx == obj.m_sta_info.errors_tx);
    ret += !(this->m_sta_info.errors_rx == obj.m_sta_info.errors_rx);
    //em_util_info_print(EM_MGR, "%s:%d: MUH ret=%d\n", __func__, __LINE__,ret);

    if (ret > 0)
        return false;
    else
        return true;
}

void dm_sta_t::operator = (const dm_sta_t& obj)
{
    if (this == &obj) { return; }
    memcpy(&this->m_sta_info.id, &obj.m_sta_info.id, sizeof(mac_address_t));
    memcpy(&this->m_sta_info.sta_client_type, &obj.m_sta_info.sta_client_type, sizeof(em_string_t));
    memcpy(&this->m_sta_info.bssid, &obj.m_sta_info.bssid, sizeof(mac_address_t));
    memcpy(&this->m_sta_info.radiomac, &obj.m_sta_info.radiomac, sizeof(mac_address_t));
    this->m_sta_info.last_ul_rate = obj.m_sta_info.last_ul_rate;
    this->m_sta_info.last_dl_rate = obj.m_sta_info.last_dl_rate;
    this->m_sta_info.est_ul_rate = obj.m_sta_info.est_ul_rate;
    this->m_sta_info.est_dl_rate = obj.m_sta_info.est_dl_rate;
    this->m_sta_info.last_conn_time = obj.m_sta_info.last_conn_time;
    this->m_sta_info.retrans_count = obj.m_sta_info.retrans_count;
    this->m_sta_info.signal_strength = obj.m_sta_info.signal_strength;
    this->m_sta_info.rcpi = obj.m_sta_info.rcpi;
    this->m_sta_info.util_tx = obj.m_sta_info.util_tx;
    this->m_sta_info.util_rx = obj.m_sta_info.util_rx;
    this->m_sta_info.pkts_tx = obj.m_sta_info.pkts_tx;
    this->m_sta_info.pkts_rx = obj.m_sta_info.pkts_rx;
    this->m_sta_info.bytes_tx = obj.m_sta_info.bytes_tx;
    this->m_sta_info.bytes_rx = obj.m_sta_info.bytes_rx;
    this->m_sta_info.errors_tx = obj.m_sta_info.errors_tx;
    this->m_sta_info.errors_rx = obj.m_sta_info.errors_rx;

    memcpy(&this->m_sta_info.frame_body, &obj.m_sta_info.frame_body, obj.m_sta_info.frame_body_len);
    this->m_sta_info.num_vendor_infos = obj.m_sta_info.num_vendor_infos;
    memcpy(&this->m_sta_info.ht_cap, &obj.m_sta_info.ht_cap, sizeof(em_long_string_t));
    memcpy(&this->m_sta_info.vht_cap, &obj.m_sta_info.vht_cap, sizeof(em_long_string_t));
    memcpy(&this->m_sta_info.listen_interval, &obj.m_sta_info.listen_interval, sizeof(em_long_string_t));
    memcpy(&this->m_sta_info.ssid, &obj.m_sta_info.ssid, sizeof(em_long_string_t));
    memcpy(&this->m_sta_info.supp_rates, &obj.m_sta_info.supp_rates, sizeof(em_long_string_t));
    memcpy(&this->m_sta_info.power_cap, &obj.m_sta_info.power_cap, sizeof(em_long_string_t));
    memcpy(&this->m_sta_info.supp_channels, &obj.m_sta_info.supp_channels, sizeof(em_long_string_t));
    memcpy(&this->m_sta_info.rsn_info, &obj.m_sta_info.rsn_info, sizeof(em_long_string_t));
    memcpy(&this->m_sta_info.ext_supp_rates, &obj.m_sta_info.ext_supp_rates, sizeof(em_long_string_t));
    memcpy(&this->m_sta_info.supp_op_classes, &obj.m_sta_info.supp_op_classes, sizeof(em_long_string_t));
    memcpy(&this->m_sta_info.ext_cap, &obj.m_sta_info.ext_cap, sizeof(em_long_string_t));
    memcpy(&this->m_sta_info.rm_cap, &obj.m_sta_info.rm_cap, sizeof(em_long_string_t));
    for (unsigned int i = 0; i < this->m_sta_info.num_vendor_infos; i++) {
        memcpy(&this->m_sta_info.vendor_info, &obj.m_sta_info.vendor_info, sizeof(em_long_string_t));
    }
}

void dm_sta_t::parse_sta_bss_radio_from_key(const char *key, mac_address_t sta, bssid_t bssid, mac_address_t ruid)
{
    em_long_string_t   str;
    char *tmp, *remain;
    unsigned int i = 0;

    strncpy(str, key, strlen(key) + 1);
    remain = str;
    while ((tmp = strchr(remain, '@')) != NULL) {
        *tmp = 0;
        if (i == 0) {
            dm_easy_mesh_t::string_to_macbytes(remain, sta);
        } else if (i == 1) {
            dm_easy_mesh_t::string_to_macbytes(remain, bssid);
            tmp++;
            dm_easy_mesh_t::string_to_macbytes(tmp, ruid);
        }
        tmp++;
        remain = tmp;
        i++;
    }

}

void dm_sta_t::decode_sta_capability(dm_sta_t *sta)
{
    unsigned int offset = 0;
    unsigned char length;
    tag_type_t tag_id;

    sta->m_sta_info.num_vendor_infos = 0;

    while (offset < sta->m_sta_info.frame_body_len) {
        if (offset + 2 > sta->m_sta_info.frame_body_len) {
            printf("%s:%d: Insufficient data for tag header\n", __func__, __LINE__);
            return;
        }

        tag_id = static_cast<tag_type_t>(sta->m_sta_info.frame_body[offset]);
        length = sta->m_sta_info.frame_body[offset + 1];

        if (offset + 2 + length > sta->m_sta_info.frame_body_len) {
            printf("%s:%d: Tag length exceeds remaining packet length\n", __func__, __LINE__);
            return;
        }

        ieee80211_tagvalue_t *tag = static_cast<ieee80211_tagvalue_t *> (malloc(sizeof(ieee80211_tagvalue_t) + length));
        if (!tag) {
            printf("%s:%d: Memory allocation failed\n", __func__, __LINE__);
            return;
        }

        tag->tag_id = tag_id;
        tag->length = length;
        memcpy(tag->value, &sta->m_sta_info.frame_body[offset + 2], length);

        switch (tag->tag_id) {
            case tag_ssid:
                memset(sta->m_sta_info.ssid, 0, sizeof(em_long_string_t));
                memcpy(sta->m_sta_info.ssid, tag->value, tag->length);
                break;

            case tag_supported_rates:
                dm_easy_mesh_t::hex(tag->length, tag->value, sizeof(em_long_string_t), sta->m_sta_info.supp_rates);
                break;

            case tag_extended_supported_rates:
                dm_easy_mesh_t::hex(tag->length, tag->value, sizeof(em_long_string_t), sta->m_sta_info.ext_supp_rates);
                break;

            case tag_power_capability:
                dm_easy_mesh_t::hex(tag->length, tag->value, sizeof(em_long_string_t), sta->m_sta_info.power_cap);
                break;

            case tag_supported_channels:
                dm_easy_mesh_t::hex(tag->length, tag->value, sizeof(em_long_string_t), sta->m_sta_info.supp_channels);
                break;

            case tag_rsn_information:
                dm_easy_mesh_t::hex(tag->length, tag->value, sizeof(em_long_string_t), sta->m_sta_info.rsn_info);
                break;

            case tag_supported_operating_classes:
                dm_easy_mesh_t::hex(tag->length, tag->value, sizeof(em_long_string_t), sta->m_sta_info.supp_op_classes);
                break;

            case tag_rm_enabled_capability:
                dm_easy_mesh_t::hex(tag->length, tag->value, sizeof(em_long_string_t), sta->m_sta_info.rm_cap);
                break;

            case tag_ht_capabilities:
                dm_easy_mesh_t::hex(tag->length, tag->value, sizeof(em_long_string_t), sta->m_sta_info.ht_cap);
                break;

            case tag_extended_capabilities:
                dm_easy_mesh_t::hex(tag->length, tag->value, sizeof(em_long_string_t), sta->m_sta_info.ext_cap);
                if (tag->length >= 3) {
                    if (tag->value[2] & (1 << 3)) {
                        sta->m_sta_info.multi_band_cap = true;
                    } else {
                        sta->m_sta_info.multi_band_cap = false;
                    }
                } else {
                    sta->m_sta_info.multi_band_cap = false;
                }
                break;

            case tag_vht_capability:
                dm_easy_mesh_t::hex(tag->length, tag->value, sizeof(em_long_string_t), sta->m_sta_info.vht_cap);
                break;

            case tag_vendor_specific:
                if (sta->m_sta_info.num_vendor_infos < MAX_VENDOR_INFO) {
                    dm_easy_mesh_t::hex(tag->length, tag->value, sizeof(sta->m_sta_info.vendor_info[sta->m_sta_info.num_vendor_infos]), sta->m_sta_info.vendor_info[sta->m_sta_info.num_vendor_infos]);
                    sta->m_sta_info.num_vendor_infos++;
                }
                break;

            default:
                printf("%s:%d: Unknown Tag ID: %d\n", __func__, __LINE__, tag->tag_id);
                break;
        }
    offset += 2 + tag->length;
    free(tag);
    }

}

void dm_sta_t::decode_beacon_report(dm_sta_t *sta)
{
    unsigned int i =0;
    unsigned char *ie;
    int current_pkt_len = 0;

    em_sta_info_t *sta_info = &sta->m_sta_info;
    ie = static_cast<unsigned char *>(sta->m_sta_info.beacon_report_elem);

    for (i = 0; i < sta_info->num_beacon_meas_report; i++) {
        current_pkt_len = ie[1];
        ie += 2;

        sta_info->beacon_reports[i].opClass       = ie[3];
        sta_info->beacon_reports[i].channel       = ie[4];
        sta_info->beacon_reports[i].rcpi          = ie[16];
        sta_info->beacon_reports[i].rsni          = ie[17];
        memcpy(sta_info->beacon_reports[i].bssid, &ie[18], sizeof(bssid_t));
        sta_info->beacon_reports[i].antenna       = ie[24];

       ie += current_pkt_len;
   }
}

dm_sta_t::dm_sta_t(em_sta_info_t *sta)
{
    memcpy(&m_sta_info, sta, sizeof(em_sta_info_t));
}

dm_sta_t::dm_sta_t(const dm_sta_t& sta)
{
    memcpy(&m_sta_info, &sta.m_sta_info, sizeof(em_sta_info_t));
}

dm_sta_t::dm_sta_t()
{

}

dm_sta_t::~dm_sta_t()
{

}
