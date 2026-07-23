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

#include <string.h>
#include "dm_sta.h"
#include "dm_easy_mesh.h"
#include "em_vendor.h"
// #include "custom/inc/em_vendor_tlv_handler.h"
#include "custom/inc/dm_sta_ext.h"
// #include "custom/inc/vendor_sta_tlv.h"
#include "vendor_sta_ctrl.h"

// int em_vendor_ctrl_t::process(const unsigned char *tlv_value,
//                                   unsigned int         tlv_len,
//                                   dm_easy_mesh_t      *dm)
// {
//     const em_vendor_specific_t *vs =
//         reinterpret_cast<const em_vendor_specific_t *>(tlv_value);

//     if (memcmp(vs->vendor_oui, vendor_sta_oui, EM_VENDOR_OUI_SIZE) != 0)
//         return 0;  // not our OUI

//     unsigned int offset = EM_VENDOR_OUI_SIZE
//                         + sizeof(vs->num)
//                         + sizeof(vs->data[0].attr_id);
//     if (tlv_len <= offset)
//         return 0;

//     const unsigned char *ptr = tlv_value + offset;
//     unsigned int remaining   = tlv_len - offset;
//     int updated = 0;

//     while (remaining >= sizeof(vendor_sta_private_wire_t)) {
//         const vendor_sta_private_wire_t *wire =
//             reinterpret_cast<const vendor_sta_private_wire_t *>(ptr);

//         mac_address_t mac;
//         memcpy(mac, wire->sta_mac, sizeof(mac_address_t));

//         dm_sta_t *sta = dm->get_first_sta(mac);
//         while (sta != nullptr) {
//             if (memcmp(sta->m_sta_info.id, wire->sta_mac, sizeof(mac_address_t)) == 0) {
//                 if (!sta->get_priv()) sta->set_priv(new dm_sta_ext_t());

//                 dm_sta_ext_t *ext = sta->get_priv();

//                 ext->ap_mac_str                  = wire->ap_mac_str;
//                 ext->vap_index                   = wire->vap_index;
//                 ext->radio_index                 = wire->radio_index;
//                 ext->channel_utilization         = wire->channel_utilization;
//                 ext->cli_pkts_tx                 = static_cast<unsigned long>(wire->cli_pkts_tx);
//                 ext->cli_pkts_rx                 = static_cast<unsigned long>(wire->cli_pkts_rx);
//                 ext->cli_retrans                 = static_cast<unsigned long>(wire->cli_retrans);
//                 ext->cli_rx_retries              = wire->cli_rx_retries;
//                 ext->cli_snr                     = wire->cli_snr;
//                 ext->cli_max_dl_rate             = wire->cli_max_dl_rate;
//                 ext->cli_max_ul_rate             = wire->cli_max_ul_rate;
//                 ext->cli_last_dl_rate            = wire->cli_last_dl_rate;
//                 ext->cli_last_ul_rate            = wire->cli_last_ul_rate;
//                 ext->cli_power_save              = (wire->cli_power_save != 0);
//                 ext->total_connected_time_sec    = static_cast<long long>(wire->total_connected_time_sec);
//                 ext->total_disconnected_time_sec = static_cast<long long>(wire->total_disconnected_time_sec);
//                 ext->lq_event                    = wire->lq_event;
//                 ext->status_code                 = wire->status_code;

//                 ext->custom_score      = wire->custom_score;
//                 ext->is_managed_client = (wire->is_managed_client != 0);
//                 size_t tag_len = wire->tag_len;
//                 if (tag_len > VENDOR_STA_TAG_MAX_LEN) tag_len = VENDOR_STA_TAG_MAX_LEN;
//                 ext->custom_tag.assign(wire->tag, tag_len);

//                 ++updated;
//                 break;
//             }
//             sta = dm->get_next_sta(mac, sta);
//         }

//         ptr       += sizeof(vendor_sta_private_wire_t);
//         remaining -= sizeof(vendor_sta_private_wire_t);
//     }

//     return updated;
// }

                    // handle_vendor_ext_tlv(tlv->value, ntohs(tlv->len), get_data_model());
//
int em_vendor_ctrl_t::handle_vendor_tlv_ext(const unsigned char *tlv_value,
                                        unsigned int         tlv_len,
                                        dm_easy_mesh_t      *dm)
{
    if (tlv_len < sizeof(em_vendor_specific_t) + 1)
        return 0;

    const em_vendor_specific_t *vs =
        reinterpret_cast<const em_vendor_specific_t *>(tlv_value);
    const unsigned char attr_id = vs->data[0].attr_id;

    em_vendor_data_t *vendor_data_ptr = vendor_data->data;
    em_printfout("vendor_data->attri [%d]", vendor_data_ptr->attr_id);

    if (vendor_data_ptr->attr_id != vendor_ext_attr_id_link_report) {
        return 0;
    }

    wei_data_t *wei_data = reinterpret_cast<const wei_data_t *>(vendor_data_ptr->vendor_data);

    sta = dm->get_first_sta(wei_data->sta_mac);
    while (sta != NULL) {
        if (memcmp(sta->m_sta_info.id, wei_data->sta_mac, sizeof(mac_address_t)) == 0) {
            break;
        }
        sta = dm->get_next_sta(wei_data->sta_mac, sta);
    }

    if(sta == NULL)
    {
        em_printfout("sta[%s] not found", sta_str);
        //todo: handle this case, shouldnot return, should goto next after incrementing
        return -1;
    }

    // save the data?
    // no reqs to save, directly publish to wei_app. 

    return 0;
}
