/**
 * Agent-side private code for the vendor STA extension.
 *
 * Responsibilities:
 *  - Register s_populate so that when an em_cmd_type_vendor_data cmd is
 *    created, the raw stats_arg_t[] bytes are also decoded into dm_sta_ext_t
 *    on the local data model (for agent-side use).
 *
 * The vendor CMDU building and sending is handled entirely by the public
 * em_vendor_t::send_vendor_sta_lq_data() which passes m_raw_data straight
 * through as the TLV payload — no dm_sta_ext_t access required there.
 */

#include <string.h>

#include "dm_sta.h"
#include "dm_easy_mesh.h"
#include "em_cmd.h"
#include "em_cmd_sta_lq_data.h"
#include "custom/inc/dm_sta_ext.h"

// wifi_base.h defines stats_arg_t
#include "wifi_base.h"

// ── em_cmd_type_vendor_data populate hook ─────────────────────────────────────
//
// Registered via __attribute__((constructor)) before main().
// Decodes raw stats_arg_t[] bytes from m_raw_data into dm_sta_ext_t so the
// agent has the structured data locally (e.g. for policy decisions).
// The bytes are also sent as-is in the vendor TLV by the public send function.
//
static void sta_lq_data_populate(em_cmd_type_vendor_data &cmd, dm_easy_mesh_t &dm)
{
    const uint8_t *buf = cmd.m_raw_data.data();
    int count = static_cast<int>(cmd.m_raw_data.size() / sizeof(stats_arg_t));
    if (count <= 0) return;

    const stats_arg_t *arr = reinterpret_cast<const stats_arg_t *>(buf);

    for (int i = 0; i < count; i++) {
        const stats_arg_t *s = &arr[i];

        mac_address_t mac;
        dm_easy_mesh_t::string_to_macbytes(const_cast<char *>(s->mac_str), mac);

        dm_sta_t *sta = dm.find_sta(mac);
        if (!sta) continue;

        if (!sta->get_priv()) sta->set_priv(new dm_sta_ext_t());
        dm_sta_ext_t *ext = sta->get_priv();

        ext->ap_mac_str                  = s->ap_mac_str;
        ext->vap_index                   = s->vap_index;
        ext->radio_index                 = s->radio_index;
        ext->channel_utilization         = s->channel_utilization;
        ext->lq_event                    = s->event;
        ext->status_code                 = s->status_code;
        ext->total_connected_time_sec    = static_cast<long long>(s->total_connected_time.tv_sec);
        ext->total_disconnected_time_sec = static_cast<long long>(s->total_disconnected_time.tv_sec);
        ext->cli_snr                     = s->dev.cli_SNR;
        ext->cli_pkts_tx                 = s->dev.cli_PacketsSent;
        ext->cli_pkts_rx                 = s->dev.cli_PacketsReceived;
        ext->cli_retrans                 = s->dev.cli_RetransCount;
        ext->cli_rx_retries              = s->dev.cli_RxRetries;
        ext->cli_max_dl_rate             = s->dev.cli_MaxDownlinkRate;
        ext->cli_max_ul_rate             = s->dev.cli_MaxUplinkRate;
        ext->cli_last_dl_rate            = s->dev.cli_LastDataDownlinkRate;
        ext->cli_last_ul_rate            = s->dev.cli_LastDataUplinkRate;
        ext->cli_power_save              = s->dev.cli_PowerSaveMode;
    }
}

__attribute__((constructor))
static void register_sta_lq_data_populate()
{
    em_cmd_type_vendor_data::s_populate = sta_lq_data_populate;
}
