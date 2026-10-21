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
#include "vendor_sta_ctrl.h"
#include "util.h"
#include "em_ctrl.h"

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

    const stats_arg_t *wei_data = reinterpret_cast<const stats_arg_t *>(vendor_data_ptr->vendor_data);

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

void em_vendor_ctrl_t::publish_wei_app(stats_arg_t wei_data) {
    // Implementation of publish_wei_app

    em_printfout("Publishing wei app for sta[%s]", wei_data.mac_str);
    //shoul dbe non blocking?
    lq_ipc_send_wei_data(LQ_IPC_MSG_PERIODIC_STATS, &wei_data, 1);
}
