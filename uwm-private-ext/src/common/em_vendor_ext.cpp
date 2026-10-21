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
#include "vendor_wei.h"
#include "dm_sta.h"
#include "dm_easy_mesh.h"
#include "em_base.h"
#include "em_base_comcast.h"
#include "wei_stats_wire.h"
#include "util.h"

// Override weak symbol so em_vendor_t constructor automatically instantiates this
em_vendor_ext_interface_t* create_em_vendor_ext() {
    return new em_vendor_wei_t();
}

// stats_arg_t/dev_stats_t use platform-native types (unsigned long, bool, ...)
// and can't be memcpy'd as-is into the vendor TLV, since that only works when
// agent and controller share the same endianness *and* struct ABI. Serialize
// it field-by-field over the wei_put_*/wei_get_* cursor helpers instead.

// Total wire size of one packed stats_arg_t (fixed, independent of struct
// padding/ABI on either end).
#define STATS_ARG_WIRE_SIZE \
    (18 + 18 + 4 + 4 + 4 + /* mac_str, ap_mac_str, vap_index, radio_index, channel_utilization */ \
     8 + 8 + 8 + 8 + 4 + 4 + 4 + 4 + 4 + 8 + 1 + /* dev_stats_t fields */ \
     1 + /* is_be */ \
     8 + 8 + /* total_connected/disconnected_time */ \
     4 + 4 + 4 + 4 + /* event, status_code, dhcp_event, dhcp_msg_type */ \
     256 + 256 + 512 + /* dhcp_hostname, dhcp_vendor_class, dhcp_param_list */ \
     4 + 4 + 4 + 4 + 4 + 4 + /* eapol_* counters */ \
     1) /* connection_authorized */

// Serializes h into buf (must be >= STATS_ARG_WIRE_SIZE bytes); returns bytes written.
static size_t stats_arg_pack(const stats_arg_t *h, unsigned char *buf)
{
    unsigned char *p = buf;
    p = wei_put_bytes(p, h->mac_str, sizeof(h->mac_str));
    p = wei_put_bytes(p, h->ap_mac_str, sizeof(h->ap_mac_str));
    p = wei_put_u32(p, h->vap_index);
    p = wei_put_u32(p, h->radio_index);
    p = wei_put_u32(p, static_cast<uint32_t>(h->channel_utilization));
    p = wei_put_u64(p, h->dev.cli_PacketsSent);
    p = wei_put_u64(p, h->dev.cli_PacketsReceived);
    p = wei_put_u64(p, h->dev.cli_RetransCount);
    p = wei_put_u64(p, h->dev.cli_RxRetries);
    p = wei_put_u32(p, static_cast<uint32_t>(h->dev.cli_SNR));
    p = wei_put_u32(p, h->dev.cli_MaxDownlinkRate);
    p = wei_put_u32(p, h->dev.cli_MaxUplinkRate);
    p = wei_put_u32(p, h->dev.cli_LastDataDownlinkRate);
    p = wei_put_u32(p, h->dev.cli_LastDataUplinkRate);
    p = wei_put_u64(p, h->dev.cli_sleepTime);
    p = wei_put_u8(p, h->dev.cli_PowerSaveMode ? 1 : 0);
    p = wei_put_u8(p, h->is_be ? 1 : 0);
    p = wei_put_u64(p, static_cast<uint64_t>(h->total_connected_time.tv_sec));
    p = wei_put_u64(p, static_cast<uint64_t>(h->total_disconnected_time.tv_sec));
    p = wei_put_u32(p, static_cast<uint32_t>(h->event));
    p = wei_put_u32(p, h->status_code);
    p = wei_put_u32(p, static_cast<uint32_t>(h->dhcp_event));
    p = wei_put_u32(p, static_cast<uint32_t>(h->dhcp_msg_type));
    p = wei_put_bytes(p, h->dhcp_hostname, sizeof(h->dhcp_hostname));
    p = wei_put_bytes(p, h->dhcp_vendor_class, sizeof(h->dhcp_vendor_class));
    p = wei_put_bytes(p, h->dhcp_param_list, sizeof(h->dhcp_param_list));
    p = wei_put_u32(p, h->eapol_m1_count);
    p = wei_put_u32(p, h->eapol_m2_count);
    p = wei_put_u32(p, h->eapol_m3_count);
    p = wei_put_u32(p, h->eapol_m4_count);
    p = wei_put_u32(p, h->eapol_attempts);
    p = wei_put_u32(p, h->eapol_failures);
    p = wei_put_u8(p, h->connection_authorized ? 1 : 0);
    return static_cast<size_t>(p - buf);
}

// Deserializes buf (must be >= STATS_ARG_WIRE_SIZE bytes) into h; returns bytes read.
static size_t stats_arg_unpack(const unsigned char *buf, stats_arg_t *h)
{
    const unsigned char *p = buf;
    uint32_t u32;
    uint64_t u64;
    uint8_t  u8;

    memset(h, 0, sizeof(*h));
    p = wei_get_bytes(p, h->mac_str, sizeof(h->mac_str));
    p = wei_get_bytes(p, h->ap_mac_str, sizeof(h->ap_mac_str));
    p = wei_get_u32(p, &u32); h->vap_index = u32;
    p = wei_get_u32(p, &u32); h->radio_index = u32;
    p = wei_get_u32(p, &u32); h->channel_utilization = static_cast<int>(u32);
    p = wei_get_u64(p, &u64); h->dev.cli_PacketsSent = u64;
    p = wei_get_u64(p, &u64); h->dev.cli_PacketsReceived = u64;
    p = wei_get_u64(p, &u64); h->dev.cli_RetransCount = u64;
    p = wei_get_u64(p, &u64); h->dev.cli_RxRetries = u64;
    p = wei_get_u32(p, &u32); h->dev.cli_SNR = static_cast<int>(u32);
    p = wei_get_u32(p, &u32); h->dev.cli_MaxDownlinkRate = u32;
    p = wei_get_u32(p, &u32); h->dev.cli_MaxUplinkRate = u32;
    p = wei_get_u32(p, &u32); h->dev.cli_LastDataDownlinkRate = u32;
    p = wei_get_u32(p, &u32); h->dev.cli_LastDataUplinkRate = u32;
    p = wei_get_u64(p, &u64); h->dev.cli_sleepTime = u64;
    p = wei_get_u8(p, &u8); h->dev.cli_PowerSaveMode = (u8 != 0);
    p = wei_get_u8(p, &u8); h->is_be = (u8 != 0);
    p = wei_get_u64(p, &u64); h->total_connected_time.tv_sec = static_cast<time_t>(u64);
    p = wei_get_u64(p, &u64); h->total_disconnected_time.tv_sec = static_cast<time_t>(u64);
    p = wei_get_u32(p, &u32); h->event = static_cast<int>(u32);
    p = wei_get_u32(p, &u32); h->status_code = u32;
    p = wei_get_u32(p, &u32); h->dhcp_event = static_cast<int>(u32);
    p = wei_get_u32(p, &u32); h->dhcp_msg_type = static_cast<int>(u32);
    p = wei_get_bytes(p, h->dhcp_hostname, sizeof(h->dhcp_hostname));
    p = wei_get_bytes(p, h->dhcp_vendor_class, sizeof(h->dhcp_vendor_class));
    p = wei_get_bytes(p, h->dhcp_param_list, sizeof(h->dhcp_param_list));
    p = wei_get_u32(p, &u32); h->eapol_m1_count = u32;
    p = wei_get_u32(p, &u32); h->eapol_m2_count = u32;
    p = wei_get_u32(p, &u32); h->eapol_m3_count = u32;
    p = wei_get_u32(p, &u32); h->eapol_m4_count = u32;
    p = wei_get_u32(p, &u32); h->eapol_attempts = u32;
    p = wei_get_u32(p, &u32); h->eapol_failures = u32;
    p = wei_get_u8(p, &u8); h->connection_authorized = (u8 != 0);
    return static_cast<size_t>(p - buf);
}

// --- Agent side: build the outgoing vendor TLV ---

int em_vendor_wei_t::build_vendor_tlv_ext(const unsigned char *raw_data,
                                           unsigned int         raw_len,
                                           unsigned char       *tlv_value,
                                           unsigned int        *tlv_val_len)
{
    /* raw_data = [priv_attr_id (1 byte)][stats_arg_t (native struct)], as built by
     * lq_agent_raw_data_cb() in lq_agent_listener.cpp. */
    if (!raw_data || raw_len != (1 + sizeof(stats_arg_t)) || !tlv_value || !tlv_val_len) {
        em_printfout("%s:%d invalid input parameters", __func__, __LINE__);
        return -1;
    }

    /* OUI + num(1) + attr_id + priv_attr_id + byte-wise packed payload */
    unsigned char *vp = tlv_value;
    memcpy(vp, comcast_vendor_oui, EM_VENDOR_OUI_SIZE);
    vp += EM_VENDOR_OUI_SIZE;
    *vp++ = vendor_attr_id_ext_wei_data;
    *vp++ = raw_data[0];
    vp += stats_arg_pack(reinterpret_cast<const stats_arg_t *>(raw_data + 1), vp);

    *tlv_val_len = static_cast<unsigned int>(vp - tlv_value);
    em_printfout("%s:%d built WEI vendor TLV, len=%u", __func__, __LINE__, *tlv_val_len);
    return 0;
}

// --- Controller side: decode the incoming vendor TLV ---

int em_vendor_wei_t::handle_vendor_tlv_ext(const unsigned char *tlv_value,
                                            unsigned int         tlv_len,
                                            dm_easy_mesh_t      *dm)
{
    em_printfout("Handling vendor TLV extension, length: %u", tlv_len);

    if (tlv_len < sizeof(em_vendor_specific_t) + 1 /* priv_attr_id */ + STATS_ARG_WIRE_SIZE)
        return 0;

    const em_vendor_specific_t *vs =
        reinterpret_cast<const em_vendor_specific_t *>(tlv_value);

    const em_vendor_data_t *vendor_data_ptr = reinterpret_cast<const em_vendor_data_t *>(&vs->data[0]);

    em_printfout("  vendor_data->attri [%d]", vendor_data_ptr->attr_id);

    if (vendor_data_ptr->attr_id != vendor_attr_id_ext_wei_data) {
        return 0;
    }

    // vendor_data = [priv_attr_id (1 byte)][byte-wise packed stats_arg_t...]
    const em_vendor_priv_attr_id_t priv_attr_id =
        static_cast<em_vendor_priv_attr_id_t>(vendor_data_ptr->vendor_data[0]);
    em_printfout("  wei priv_attr_id [%d]", priv_attr_id);

    uint32_t msg_type;
    switch (priv_attr_id) {
    case em_vendor_priv_attr_id_wei_periodic_stats:
        msg_type = LQ_IPC_MSG_PERIODIC_STATS;
        break;
    case em_vendor_priv_attr_id_wei_disconnect:
        msg_type = LQ_IPC_MSG_DISCONNECT;
        break;
    case em_vendor_priv_attr_id_wei_rapid_disconnect:
        msg_type = LQ_IPC_MSG_RAPID_DISCONNECT;
        break;
    case em_vendor_priv_attr_id_wei_caffinity_event:
        msg_type = LQ_IPC_MSG_CAFFINITY_EVENT;
        break;
    default:
        em_printfout("Unsupported WEI private attribute ID: %u", vendor_data_ptr->vendor_data[0]);
        return 0;
    }

    // Unpack the byte-wise, network-byte-order wire payload back into the native struct.
    stats_arg_t wei_data_storage;
    stats_arg_unpack(vendor_data_ptr->vendor_data + 1, &wei_data_storage);
    const stats_arg_t *wei_data = &wei_data_storage;

    mac_addr_t sta_mac;
    dm_easy_mesh_t::string_to_macbytes(const_cast<char *>(wei_data->mac_str), sta_mac);

    em_printfout("  wei sta_mac[%s]", wei_data->mac_str);
    dm_sta_t *sta = dm == nullptr ? nullptr : dm->get_first_sta(sta_mac);
    bool sta_found = false;
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

            sta_found = true;
            break;
        }
        sta = dm->get_next_sta(sta_mac, const_cast<dm_sta_t*>(sta));
    }

    if (!sta_found) {
        em_printfout("STA [%s] not in current model; forwarding %s event",
            wei_data->mac_str, lq_msg_type_str(msg_type));
    }

    // save the data?
    // no reqs to save, directly publish to wei_app.

    publish_wei_app(msg_type, *wei_data);
    return 0;
}

void em_vendor_wei_t::publish_wei_app(uint32_t msg_type, stats_arg_t wei_data) {
    em_printfout("Publishing %s for sta[%s]", lq_msg_type_str(msg_type), wei_data.mac_str);
    //shoul dbe non blocking?
    lq_ipc_send_wei_data(msg_type, &wei_data, 1);
}
