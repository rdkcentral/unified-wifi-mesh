/**
 * Agent-side: serialize dm_sta_ext_t fields into a vendor TLV and send
 * them to the controller inside an em_msg_type_topo_vendor CMDU.
 *
 * Pattern mirrors em_metrics_t::send_link_quality_report() /
 * create_link_stats_alarm_tlv() in the public repo.
 *
 * Call vendor_sta_send_private_data() from whichever agent state/event
 * handler has access to the em_metrics_t (or equivalent em_t subclass).
 */

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>

#include "dm_sta.h"
#include "dm_easy_mesh.h"
#include "em_metrics.h"
#include "em_agent.h"
#include "em_cmd.h"
#include "em_cmd_sta_lq_data.h"
#include "custom/inc/dm_sta_ext.h"
#include "custom/inc/vendor_sta_tlv.h"

// wifi_base.h defines stats_arg_t — already in the include path via OneWifi/include
#include "wifi_base.h"

/* OUI bytes as an array for memcpy */
static const unsigned char vendor_sta_oui[EM_VENDOR_OUI_SIZE] = VENDOR_STA_PRIVATE_OUI;

/* ── TLV builder ──────────────────────────────────────────────────────────── */

/**
 * Serializes all STAs' dm_sta_ext_t data into buff.
 * Returns the number of bytes written, or -1 on error.
 *
 * Layout inside buff (matches em_vendor_specific_t convention):
 *   [oui:3][num:1][attr_id:1][vendor_sta_private_wire_t * N]
 */
static short vendor_sta_create_private_tlv(unsigned char *buff, dm_easy_mesh_t *dm)
{
    size_t len = 0;
    unsigned char *tmp = buff;

    em_vendor_specific_t *vs = reinterpret_cast<em_vendor_specific_t *>(buff);
    memcpy(vs->vendor_oui, vendor_sta_oui, EM_VENDOR_OUI_SIZE);
    vs->num = 1;

    tmp += EM_VENDOR_OUI_SIZE + sizeof(vs->num);
    len += EM_VENDOR_OUI_SIZE + sizeof(vs->num);

    em_vendor_data_t *vd = vs->data;
    vd->attr_id = VENDOR_ATTR_STA_PRIVATE;
    tmp += sizeof(vd->attr_id);
    len += sizeof(vd->attr_id);

    /* Iterate all STAs in the data model */
    dm_sta_t *sta = static_cast<dm_sta_t *>(hash_map_get_first(dm->m_sta_map));
    while (sta != nullptr) {
        dm_sta_ext_t *priv = sta->get_priv();
        if (priv == nullptr) {
            sta = static_cast<dm_sta_t *>(hash_map_get_next(dm->m_sta_map, sta));
            continue;
        }

        vendor_sta_private_wire_t *wire =
            reinterpret_cast<vendor_sta_private_wire_t *>(tmp);

        memcpy(wire->sta_mac, sta->m_sta_info.id, sizeof(mac_address_t));

        /* stats_arg_t field order */
        strncpy(wire->ap_mac_str, priv->ap_mac_str.c_str(), sizeof(wire->ap_mac_str) - 1);
        wire->ap_mac_str[sizeof(wire->ap_mac_str) - 1] = '\0';
        wire->vap_index                   = priv->vap_index;
        wire->radio_index                 = priv->radio_index;
        wire->channel_utilization         = priv->channel_utilization;
        wire->cli_pkts_tx                 = priv->cli_pkts_tx;
        wire->cli_pkts_rx                 = priv->cli_pkts_rx;
        wire->cli_retrans                 = priv->cli_retrans;
        wire->cli_rx_retries              = priv->cli_rx_retries;
        wire->cli_snr                     = priv->cli_snr;
        wire->cli_max_dl_rate             = priv->cli_max_dl_rate;
        wire->cli_max_ul_rate             = priv->cli_max_ul_rate;
        wire->cli_last_dl_rate            = priv->cli_last_dl_rate;
        wire->cli_last_ul_rate            = priv->cli_last_ul_rate;
        wire->cli_power_save              = priv->cli_power_save ? 1u : 0u;
        wire->total_connected_time_sec    = static_cast<int64_t>(priv->total_connected_time_sec);
        wire->total_disconnected_time_sec = static_cast<int64_t>(priv->total_disconnected_time_sec);
        wire->lq_event                    = priv->lq_event;
        wire->status_code                 = priv->status_code;

        /* Proprietary fields */
        wire->custom_score      = priv->custom_score;
        wire->is_managed_client = priv->is_managed_client ? 1u : 0u;
        size_t tag_len = priv->custom_tag.size();
        if (tag_len > VENDOR_STA_TAG_MAX_LEN) tag_len = VENDOR_STA_TAG_MAX_LEN;
        wire->tag_len = static_cast<uint8_t>(tag_len);
        memset(wire->tag, 0, sizeof(wire->tag));
        memcpy(wire->tag, priv->custom_tag.c_str(), tag_len);

        tmp += sizeof(vendor_sta_private_wire_t);
        len += sizeof(vendor_sta_private_wire_t);

        sta = static_cast<dm_sta_t *>(hash_map_get_next(dm->m_sta_map, sta));
    }

    return static_cast<short>(len);
}

/* ── Public entry point ───────────────────────────────────────────────────── */

/**
 * Build and send the vendor STA private data CMDU.
 * Call this from the agent after populating dm_sta_ext_t fields from HAL.
 *
 * @param  metrics  Pointer to the em_metrics_t instance (provides send_frame,
 *                  get_data_model, get_mgr, etc.)
 * @return number of bytes sent, or -1 on error.
 */
int vendor_sta_send_private_data(em_metrics_t *metrics)
{
    unsigned char buff[EM_LONG_IO_BUFF_SZ] = {0};
    unsigned char *tmp = buff;
    size_t len = 0;
    short sz = 0;
    unsigned short type = htons(ETH_P_1905);
    em_cmdu_t *cmdu;
    em_tlv_t  *tlv;
    dm_easy_mesh_t *dm = metrics->get_data_model();

    /* Ethernet header */
    memcpy(tmp, dm->get_ctl_mac(), sizeof(mac_address_t));
    tmp += sizeof(mac_address_t); len += sizeof(mac_address_t);
    memcpy(tmp, dm->get_agent_al_interface_mac(), sizeof(mac_address_t));
    tmp += sizeof(mac_address_t); len += sizeof(mac_address_t);
    memcpy(tmp, &type, sizeof(unsigned short));
    tmp += sizeof(unsigned short); len += sizeof(unsigned short);

    /* CMDU header */
    cmdu = reinterpret_cast<em_cmdu_t *>(tmp);
    memset(cmdu, 0, sizeof(em_cmdu_t));
    cmdu->type          = htons(em_msg_type_topo_vendor);
    cmdu->id            = htons(metrics->get_mgr()->get_next_msg_id());
    cmdu->last_frag_ind = 1;
    tmp += sizeof(em_cmdu_t); len += sizeof(em_cmdu_t);

    /* Vendor-specific TLV */
    tlv = reinterpret_cast<em_tlv_t *>(tmp);
    tlv->type = em_tlv_type_vendor_specific;
    sz = vendor_sta_create_private_tlv(tlv->value, dm);
    if (sz <= 0) {
        return -1;
    }
    tlv->len = htons(static_cast<unsigned short>(sz));
    tmp += sizeof(em_tlv_t) + static_cast<size_t>(sz);
    len += sizeof(em_tlv_t) + static_cast<size_t>(sz);

    /* EOM TLV */
    tlv = reinterpret_cast<em_tlv_t *>(tmp);
    tlv->type = em_tlv_type_eom;
    tlv->len  = 0;
    tmp += sizeof(em_tlv_t); len += sizeof(em_tlv_t);

    if (metrics->send_frame(buff, static_cast<unsigned int>(len)) < 0) {
        return -1;
    }

    return static_cast<int>(len);
}

// ── em_cmd_type_vendor_data populate hook registration ─────────────────────────
//
// Registered via __attribute__((constructor)) — runs before main().
// The hook receives the fully constructed cmd (with m_raw_data already set)
// and the data model, and extracts stats_arg_t fields into dm_sta_ext_t.
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

// ── Strong override: send dm_sta_ext_t fields as a vendor TLV CMDU ───────────
//
// Called by the em state machine when em_state_agent_vendor_data_pending fires.
// Delegates to vendor_sta_send_private_data() which encodes all dm_sta_ext_t
// entries into a packed vendor-specific TLV and sends it over 1905 to the
// controller.
//
int em_metrics_t::send_vendor_sta_lq_data()
{
    return vendor_sta_send_private_data(this);
}
