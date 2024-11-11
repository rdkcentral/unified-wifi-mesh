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
    cJSON *tmp, *tmp_arr;
    mac_addr_str_t  mac_str;
    unsigned int i;

    mac_address_t *bssid = (mac_address_t *)parent_id;

    memset(&m_sta_info, 0, sizeof(em_sta_info_t));
    memcpy(&m_sta_info.bssid,bssid,sizeof(mac_address_t));

    if ((tmp = cJSON_GetObjectItem(obj, "MACAddress")) != NULL) {
        snprintf(mac_str, sizeof(mac_str), "%s", cJSON_GetStringValue(tmp));
        dm_easy_mesh_t::string_to_macbytes(mac_str, m_sta_info.id);
    }

    if ((tmp = cJSON_GetObjectItem(obj, "LastDataUplinkRate")) != NULL) {
        m_sta_info.last_ul_rate = tmp->valuedouble;
    }

    if ((tmp = cJSON_GetObjectItem(obj, "TimeStamp")) != NULL) {
        snprintf(m_sta_info.timestamp, sizeof(m_sta_info.timestamp), "%s", cJSON_GetStringValue(tmp));
    }

    if ((tmp = cJSON_GetObjectItem(obj, "LastDataDownlinkRate")) != NULL) {
        m_sta_info.last_dl_rate = tmp->valuedouble;
    }

    if ((tmp = cJSON_GetObjectItem(obj, "EstMACDataRateUplink")) != NULL) {
        m_sta_info.est_ul_rate = tmp->valuedouble;
    }

    if ((tmp = cJSON_GetObjectItem(obj, "EstMACDataRateDownlink")) != NULL) {
        m_sta_info.est_dl_rate = tmp->valuedouble;
    }

    if ((tmp = cJSON_GetObjectItem(obj, "LastConnectTime")) != NULL) {
        m_sta_info.last_conn_time = tmp->valuedouble;
    }

    if ((tmp = cJSON_GetObjectItem(obj, "RetransCount")) != NULL) {
        m_sta_info.retrans_count = tmp->valuedouble;
    }

    if ((tmp = cJSON_GetObjectItem(obj, "SignalStrength")) != NULL) {
        m_sta_info.signal_strength = tmp->valuedouble;
    }

    if ((tmp = cJSON_GetObjectItem(obj, "UtilizationTransmit")) != NULL) {
        m_sta_info.util_tx = tmp->valuedouble;
    }

    if ((tmp = cJSON_GetObjectItem(obj, "UtilizationReceive")) != NULL) {
        m_sta_info.util_rx = tmp->valuedouble;
    }

    if ((tmp = cJSON_GetObjectItem(obj, "PacketsSent")) != NULL) {
        m_sta_info.pkts_tx = tmp->valuedouble;
    }

    if ((tmp = cJSON_GetObjectItem(obj, "PacketsReceived")) != NULL) {
        m_sta_info.pkts_rx = tmp->valuedouble;
    }

    if ((tmp = cJSON_GetObjectItem(obj, "BytesSent")) != NULL) {
        m_sta_info.bytes_tx = tmp->valuedouble;
    }

    if ((tmp = cJSON_GetObjectItem(obj, "BytesReceived")) != NULL) {
        m_sta_info.bytes_rx = tmp->valuedouble;
    }

    if ((tmp = cJSON_GetObjectItem(obj, "ErrorsSent")) != NULL) {
        m_sta_info.errors_tx = tmp->valuedouble;
    }

    if ((tmp = cJSON_GetObjectItem(obj, "ErrorsReceived")) != NULL) {
        m_sta_info.errors_rx = tmp->valuedouble;
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

    /*if ((tmp = cJSON_GetObjectItem(obj, "ReAssociationDelay")) != NULL) {
        m_sta_info.reassoc_delay = tmp->valuedouble;
    }

    if ((tmp = cJSON_GetObjectItem(obj, "SecurityAssociation")) != NULL) {
        snprintf(m_sta_info.sec_association, sizeof(m_sta_info.sec_association), "%s", cJSON_GetStringValue(tmp));
    }

    if ((tmp = cJSON_GetObjectItem(obj, "SleepMode")) != NULL) {
        snprintf(m_sta_info.sleep_mode, sizeof(m_sta_info.sleep_mode), "%s", cJSON_GetStringValue(tmp));
    }*///TODO:
    return 0;

}

void dm_sta_t::encode(cJSON *obj)
{
    mac_addr_str_t  mac_str;

    dm_easy_mesh_t::macbytes_to_string(m_sta_info.id, mac_str);
    cJSON_AddStringToObject(obj, "MACAddress", mac_str);
    cJSON_AddNumberToObject(obj, "LastDataUplinkRate", m_sta_info.last_ul_rate);
    cJSON_AddStringToObject(obj, "TimeStamp", m_sta_info.timestamp);
    cJSON_AddNumberToObject(obj, "EstMACDataRateUplink", m_sta_info.est_ul_rate);
    cJSON_AddNumberToObject(obj, "LastConnectTime", m_sta_info.last_conn_time);
    cJSON_AddNumberToObject(obj, "RetransCount", m_sta_info.retrans_count);
    cJSON_AddNumberToObject(obj, "EstMACDataRateDownlink", m_sta_info.est_dl_rate);
    cJSON_AddStringToObject(obj, "HTCapabilities", m_sta_info.ht_cap);
    cJSON_AddNumberToObject(obj, "SignalStrength", m_sta_info.signal_strength);
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
    /*cJSON_AddNumberToObject(obj, "ReAssociationDelay", m_sta_info.reassoc_delay);
    cJSON_AddStringToObject(obj, "SecurityAssociation", m_sta_info.sec_association);
    cJSON_AddStringToObject(obj, "SleepMode", m_sta_info.sleep_mode);*/
}

bool dm_sta_t::operator == (const dm_sta_t& obj)
{
    int ret = 0;
    ret += (memcmp(&this->m_sta_info.id ,&obj.m_sta_info.id,sizeof(mac_address_t)) != 0);
    ret += (memcmp(&this->m_sta_info.bssid ,&obj.m_sta_info.bssid,sizeof(mac_address_t)) != 0);
    ret += !(this->m_sta_info.last_ul_rate == obj.m_sta_info.last_ul_rate);
    ret += !(this->m_sta_info.last_dl_rate == obj.m_sta_info.last_dl_rate);
    ret += !(this->m_sta_info.est_ul_rate == obj.m_sta_info.est_ul_rate);
    ret += !(this->m_sta_info.est_dl_rate == obj.m_sta_info.est_dl_rate);
    ret += !(this->m_sta_info.last_conn_time == obj.m_sta_info.last_conn_time);
    ret += !(this->m_sta_info.retrans_count == obj.m_sta_info.retrans_count);
    ret += !(this->m_sta_info.signal_strength == obj.m_sta_info.signal_strength);
    ret += !(this->m_sta_info.util_tx == obj.m_sta_info.util_tx);
    ret += !(this->m_sta_info.util_rx == obj.m_sta_info.util_rx);
    ret += !(this->m_sta_info.pkts_tx == obj.m_sta_info.pkts_tx);
    ret += !(this->m_sta_info.pkts_rx == obj.m_sta_info.pkts_rx);
    ret += !(this->m_sta_info.bytes_tx == obj.m_sta_info.bytes_tx);
    ret += !(this->m_sta_info.bytes_rx == obj.m_sta_info.bytes_rx);
    ret += !(this->m_sta_info.errors_tx == obj.m_sta_info.errors_tx);
    ret += !(this->m_sta_info.errors_rx == obj.m_sta_info.errors_rx);
    ret += (memcmp(&this->m_sta_info.cap,&obj.m_sta_info.cap,sizeof(em_long_string_t)) != 0);
    ret += (memcmp(&this->m_sta_info.ht_cap,&obj.m_sta_info.ht_cap,sizeof(em_long_string_t)) != 0);
    ret += (memcmp(&this->m_sta_info.vht_cap,&obj.m_sta_info.vht_cap,sizeof(em_long_string_t)) != 0);
    ret += (memcmp(&this->m_sta_info.he_cap,&obj.m_sta_info.he_cap,sizeof(em_long_string_t)) != 0);
    ret += (memcmp(&this->m_sta_info.wifi6_cap,&obj.m_sta_info.wifi6_cap,sizeof(em_long_string_t)) != 0);
    ret += (memcmp(&this->m_sta_info.cellular_data_pref,&obj.m_sta_info.cellular_data_pref,sizeof(em_long_string_t)) != 0);
    /*ret += !(this->m_sta_info.reassoc_delay == obj.m_sta_info.reassoc_delay);
    ret += (memcmp(&this->m_sta_info.sec_association,&obj.m_sta_info.sec_association,sizeof(em_long_string_t)) != 0);
    ret += (memcmp(&this->m_sta_info.sleep_mode,&obj.m_sta_info.sleep_mode,sizeof(em_short_string_t)) != 0);
    ret += !(this->m_sta_info.sec_cap == obj.m_sta_info.sec_cap);*/

    //em_util_info_print(EM_MGR, "%s:%d: MUH ret=%d\n", __func__, __LINE__,ret);

    if (ret > 0)
        return false;
    else
        return true;
}
void dm_sta_t::operator = (const dm_sta_t& obj)
{
    memcpy(&this->m_sta_info.id ,&obj.m_sta_info.id,sizeof(mac_address_t));
    memcpy(&this->m_sta_info.bssid ,&obj.m_sta_info.bssid,sizeof(mac_address_t));
    this->m_sta_info.last_ul_rate = obj.m_sta_info.last_ul_rate;
    this->m_sta_info.last_dl_rate = obj.m_sta_info.last_dl_rate;
    this->m_sta_info.est_ul_rate = obj.m_sta_info.est_ul_rate;
    this->m_sta_info.est_dl_rate = obj.m_sta_info.est_dl_rate;
    this->m_sta_info.last_conn_time = obj.m_sta_info.last_conn_time;
    this->m_sta_info.retrans_count = obj.m_sta_info.retrans_count;
    this->m_sta_info.signal_strength = obj.m_sta_info.signal_strength;
    this->m_sta_info.util_tx = obj.m_sta_info.util_tx;
    this->m_sta_info.util_rx = obj.m_sta_info.util_rx;
    this->m_sta_info.pkts_tx = obj.m_sta_info.pkts_tx;
    this->m_sta_info.pkts_rx = obj.m_sta_info.pkts_rx;
    this->m_sta_info.bytes_tx = obj.m_sta_info.bytes_tx;
    this->m_sta_info.bytes_rx = obj.m_sta_info.bytes_rx;
    this->m_sta_info.errors_tx = obj.m_sta_info.errors_tx;
    this->m_sta_info.errors_rx = obj.m_sta_info.errors_rx;
    memcpy(&this->m_sta_info.cap,&obj.m_sta_info.cap,sizeof(em_long_string_t));
    memcpy(&this->m_sta_info.ht_cap,&obj.m_sta_info.ht_cap,sizeof(em_long_string_t));
    memcpy(&this->m_sta_info.vht_cap,&obj.m_sta_info.vht_cap,sizeof(em_long_string_t));
    memcpy(&this->m_sta_info.he_cap,&obj.m_sta_info.he_cap,sizeof(em_long_string_t));
    memcpy(&this->m_sta_info.wifi6_cap,&obj.m_sta_info.wifi6_cap,sizeof(em_long_string_t));
    memcpy(&this->m_sta_info.cellular_data_pref,&obj.m_sta_info.cellular_data_pref,sizeof(em_long_string_t));
    /*this->m_sta_info.reassoc_delay = obj.m_sta_info.reassoc_delay;
    memcpy(&this->m_sta_info.sec_association,&obj.m_sta_info.sec_association,sizeof(em_long_string_t));
    memcpy(&this->m_sta_info.sleep_mode,&obj.m_sta_info.sleep_mode,sizeof(em_short_string_t));
    this->m_sta_info.sec_cap = obj.m_sta_info.sec_cap;*/

}

void dm_sta_t::parse_sta_bss_radio_from_key(const char *key, mac_address_t sta, bssid_t bssid, mac_address_t ruid)
{
    em_long_string_t   str;
    char *tmp;
    unsigned int i = 0;

    strncpy(str, key, strlen(key) + 1);
    while ((tmp = strchr(str, '@')) != NULL) {
        *tmp = 0;
        if (i == 0) {
            dm_easy_mesh_t::string_to_macbytes(str, sta);
        } else if (i == 1) {
            dm_easy_mesh_t::string_to_macbytes(str, bssid);
        } else {
            dm_easy_mesh_t::string_to_macbytes(str, ruid);
        }
        tmp++;
        strncpy(str, tmp, strlen(tmp) + 1);
        i++;
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
