/**
 * Copyright 2026 Comcast Cable Communications Management, LLC
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

#include "dm_sta.h"
#include "custom/inc/dm_sta_ext.h"
#include <cjson/cJSON.h>


void dm_sta_ext_t::handle_vendor_ext_tlv(const unsigned char *tlv_value,
                                        unsigned int         tlv_len,
                                        dm_easy_mesh_t      *dm)
{
    if (tlv_len < sizeof(em_vendor_specific_t) + 1) {
        return;
    }

    const em_vendor_specific_t *vs = reinterpret_cast<const em_vendor_specific_t *>(tlv_value);

    
    return;
}

dm_sta_ext_t::dm_sta_ext_t()
    : ap_mac_str()
    , vap_index(0), radio_index(0), channel_utilization(0)
    , cli_snr(0)
    , cli_pkts_tx(0), cli_pkts_rx(0), cli_retrans(0), cli_rx_retries(0)
    , cli_max_dl_rate(0), cli_max_ul_rate(0)
    , cli_last_dl_rate(0), cli_last_ul_rate(0)
    , cli_power_save(false)
    , total_connected_time_sec(0), total_disconnected_time_sec(0)
{}

dm_sta_t::dm_sta_t()
    : m_sta_ext(new dm_sta_ext_t())
{
    memset(&m_sta_info, 0, sizeof(em_sta_info_t));
}

dm_sta_t::dm_sta_t(em_sta_info_t *sta)
    : m_sta_ext(new dm_sta_ext_t())
{
    memcpy(&m_sta_info, sta, sizeof(em_sta_info_t));
}

dm_sta_t::dm_sta_t(const dm_sta_t& sta)
    : m_sta_ext(sta.m_sta_ext ? new dm_sta_ext_t(*sta.m_sta_ext) : nullptr)
{
    memcpy(&m_sta_info, &sta.m_sta_info, sizeof(em_sta_info_t));
}

dm_sta_t::~dm_sta_t()
{
    delete m_sta_ext;
    m_sta_ext = nullptr;
}


// Parses vendor-private JSON fields from the same cJSON object that
// dm_sta_t::decode() used for public fields.
//
void dm_sta_ext_t::decode_from_json(dm_sta_t *sta, const cJSON *obj)
{
    if (!sta->get_priv()) {
        sta->set_priv(new dm_sta_ext_t());
    }
    dm_sta_ext_t *ext = sta->get_priv();

    cJSON *tmp;

    if ((tmp = cJSON_GetObjectItem(obj, "CustomScore")) != NULL) {
        ext->custom_score = static_cast<unsigned int>(tmp->valueint);
    }
    if ((tmp = cJSON_GetObjectItem(obj, "IsManagedClient")) != NULL) {
        ext->is_managed_client = static_cast<bool>(tmp->valueint);
    }
    if ((tmp = cJSON_GetObjectItem(obj, "CustomTag")) != NULL) {
        const char *tag = cJSON_GetStringValue(tmp);
        if (tag) ext->custom_tag = tag;
    }
}

// Strong override of the weak no-op in dm_sta.cpp — delegates to the class.
extern "C" void custom_decode_sta(dm_sta_t *sta, const cJSON *obj)
{
    dm_sta_ext_t::decode_from_json(sta, obj);
}
