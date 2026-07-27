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
#include "custom/inc/dm_sta_ext.h"
#include "vendor_sta_ctrl.h"
#include "util.h"

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

// typedef struct {
//     unsigned long cli_PacketsSent;
//     unsigned long cli_PacketsReceived;
//     unsigned long cli_RetransCount;
//     unsigned long long cli_RxRetries;
//     int cli_SNR;
//     unsigned int   cli_MaxDownlinkRate;
//     unsigned int cli_MaxUplinkRate;
//     unsigned int cli_LastDataDownlinkRate;
//     unsigned int cli_LastDataUplinkRate;
//     bool cli_PowerSaveMode;
// } dev_stats_t;

// typedef struct {
//     mac_addr_str_t sta_mac;
//     mac_addr_str_t ap_mac;
//     unsigned int vap_index;
//     unsigned int radio_index;
//     int channel_utilization;
//     dev_stats_t dev;
//     struct timespec total_connected_time;
//     struct timespec total_disconnected_time;
//     int event;
//     unsigned int status_code;
//     int dhcp_event;
//     int dhcp_msg_type;
//     char dhcp_hostname[256];
//     char dhcp_vendor_class[256];
//     char dhcp_param_list[512];
// } wei_data_t;


// Override weak symbol so em_vendor_t constructor automatically instantiates this
em_vendor_ext_interface_t* create_em_vendor_ext() {
    return new em_vendor_ctrl_t();
}

int em_vendor_ctrl_t::handle_vendor_tlv_ext(const unsigned char *tlv_value,
                                        unsigned int         tlv_len,
                                        dm_easy_mesh_t      *dm)
{

    em_printfout("Handling vendor TLV extension, length: %u", tlv_len);

    if (tlv_len < sizeof(em_vendor_specific_t) + 1)
        return 0;

    const em_vendor_specific_t *vs =
        reinterpret_cast<const em_vendor_specific_t *>(tlv_value);
    const unsigned char attr_id = vs->data[0].attr_id;

    const em_vendor_data_t *vendor_data_ptr = &vs->data[0];
    em_printfout("  vendor_data->attri [%d]", vendor_data_ptr->attr_id);

    if (vendor_data_ptr->attr_id != vendor_ext_attr_id_wei_data) {
        return 0;
    }

    const wei_data_t *wei_data = reinterpret_cast<const wei_data_t *>(vendor_data_ptr->vendor_data);

    mac_addr_t sta_mac;
    dm_easy_mesh_t::string_to_macbytes(const_cast<char *>(wei_data->mac_str), sta_mac);

    em_printfout("  wei sta_mac[%s]", wei_data->mac_str);
    dm_sta_t *sta = dm->get_first_sta(sta_mac);

    if (sta == NULL) {
        em_printfout("  sta not found for mac[%s]", wei_data->mac_str);
        return 0;
    }
    while (sta != NULL) {
        em_printfout("  dm sta[%s] vs . mac[%s]", util::mac_to_string(sta->m_sta_info.id).c_str(),
                     wei_data->mac_str);

        if (memcmp(sta->m_sta_info.id, sta_mac, sizeof(mac_address_t)) == 0) {
            em_printfout("sta[%s] found", wei_data->mac_str);
            em_printfout("Print wei data rcvd for sta\n"
                "    ap_mac: %s\n"
                "    vap_index: %u\n"
                "    radio_index: %u\n"
                "    channel_utilization: %d\n"
                "    cli_PacketsSent: %u\n"
                "    cli_PacketsReceived: %u\n"
                "    cli_RetransCount: %u\n"
                "    cli_RxRetries: %u\n"
                "    cli_SNR: %u\n"
                "    cli_MaxDownlinkRate: %u\n"
                "    cli_MaxUplinkRate: %u\n"
                "    cli_LastDataDownlinkRate: %u\n"
                "    cli_LastDataUplinkRate: %u\n"
                "    cli_PowerSaveMode: %u\n"
                "    total_connected_time: %lu\n"
                "    total_disconnected_time: %lu\n",
                wei_data->ap_mac_str,
                wei_data->vap_index,
                wei_data->radio_index,
                wei_data->channel_utilization,
                wei_data->dev.cli_PacketsSent,
                wei_data->dev.cli_PacketsReceived,
                wei_data->dev.cli_RetransCount,
                wei_data->dev.cli_RxRetries,
                wei_data->dev.cli_SNR,
                wei_data->dev.cli_MaxDownlinkRate,
                wei_data->dev.cli_MaxUplinkRate,
                wei_data->dev.cli_LastDataDownlinkRate,
                wei_data->dev.cli_LastDataUplinkRate,
                wei_data->dev.cli_PowerSaveMode,
                wei_data->total_connected_time.tv_sec,
                wei_data->total_disconnected_time.tv_sec);

            break;
        }
        sta = dm->get_next_sta(sta_mac, const_cast<dm_sta_t*>(sta));
    }

    if(sta == NULL) {
        em_printfout("sta[%s] not found", wei_data->mac_str);
        //todo: handle this case, shouldnot return, should goto next after incrementing
        return -1;
    }

    // save the data?
    // no reqs to save, directly publish to wei_app. 

    publish_wei_app(*wei_data);
    return 0;
}

void em_vendor_ctrl_t::publish_wei_app(wei_data_t wei_data) {
    // Implementation of publish_wei_app

    em_printfout("Publishing wei app for sta[%s]", wei_data.mac_str);
    lq_ipc_send_wei_data(LQ_IPC_MSG_PERIODIC_STATS, &wei_data, 1);

}
