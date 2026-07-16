/**
 * Controller-side: receive vendor STA private TLV and update dm_sta_ext_t.
 *
 * em_vendor_sta_ctrl_t is registered via a weak override of
 * em_metrics_t::handle_vendor_tlv_ext() so the controller's handle_vendor_msg()
 * dispatches vendor TLVs here without any changes to the public repo beyond
 * a single weak hook in em_metrics.cpp.
 */

#include <string.h>
#include <arpa/inet.h>

#include "dm_sta.h"
#include "dm_easy_mesh.h"
#include "em_metrics.h"
#include "custom/inc/dm_sta_ext.h"
#include "custom/inc/vendor_sta_tlv.h"

static const unsigned char vendor_sta_oui[EM_VENDOR_OUI_SIZE] = VENDOR_STA_PRIVATE_OUI;

// ── em_vendor_sta_ctrl_t ──────────────────────────────────────────────────
//
// Encapsulates controller-side parsing of the vendor STA private TLV.
// The strong override of em_metrics_t::handle_vendor_tlv_ext() at the bottom
// of this file routes incoming vendor TLVs into this class.
//
class em_vendor_sta_ctrl_t {
public:
    // ── TLV parser ────────────────────────────────────────────────

    static int parse_tlv(const unsigned char *tlv_value,
                         unsigned int         tlv_len,
                         dm_easy_mesh_t      *dm)
    {
        if (tlv_len < (EM_VENDOR_OUI_SIZE + sizeof(unsigned char) /*num*/
                       + sizeof(unsigned char) /*attr_id*/)) {
            return -1;
        }

        const em_vendor_specific_t *vs =
            reinterpret_cast<const em_vendor_specific_t *>(tlv_value);

        if (memcmp(vs->vendor_oui, vendor_sta_oui, EM_VENDOR_OUI_SIZE) != 0) {
            return -1;  // Not our OUI
        }

        const em_vendor_data_t *vd = vs->data;
        if (vd->attr_id != VENDOR_ATTR_STA_PRIVATE) {
            return -1;  // Not our attribute
        }

        unsigned int offset = EM_VENDOR_OUI_SIZE
                            + sizeof(vs->num)
                            + sizeof(vd->attr_id);
        if (tlv_len <= offset) return 0;

        const unsigned char *ptr = tlv_value + offset;
        unsigned int remaining   = tlv_len - offset;
        int updated = 0;

        while (remaining >= sizeof(vendor_sta_private_wire_t)) {
            const vendor_sta_private_wire_t *wire =
                reinterpret_cast<const vendor_sta_private_wire_t *>(ptr);

            mac_address_t mac;
            memcpy(mac, wire->sta_mac, sizeof(mac_address_t));

            dm_sta_t *sta = dm->get_first_sta(mac);
            while (sta != nullptr) {
                if (memcmp(sta->m_sta_info.id, wire->sta_mac, sizeof(mac_address_t)) == 0) {
                    if (!sta->get_priv()) sta->set_priv(new dm_sta_ext_t());

                    dm_sta_ext_t *ext = sta->get_priv();

                    /* stats_arg_t field order */
                    ext->ap_mac_str                  = wire->ap_mac_str;
                    ext->vap_index                   = wire->vap_index;
                    ext->radio_index                 = wire->radio_index;
                    ext->channel_utilization         = wire->channel_utilization;
                    ext->cli_pkts_tx                 = static_cast<unsigned long>(wire->cli_pkts_tx);
                    ext->cli_pkts_rx                 = static_cast<unsigned long>(wire->cli_pkts_rx);
                    ext->cli_retrans                 = static_cast<unsigned long>(wire->cli_retrans);
                    ext->cli_rx_retries              = wire->cli_rx_retries;
                    ext->cli_snr                     = wire->cli_snr;
                    ext->cli_max_dl_rate             = wire->cli_max_dl_rate;
                    ext->cli_max_ul_rate             = wire->cli_max_ul_rate;
                    ext->cli_last_dl_rate            = wire->cli_last_dl_rate;
                    ext->cli_last_ul_rate            = wire->cli_last_ul_rate;
                    ext->cli_power_save              = (wire->cli_power_save != 0);
                    ext->total_connected_time_sec    = static_cast<long long>(wire->total_connected_time_sec);
                    ext->total_disconnected_time_sec = static_cast<long long>(wire->total_disconnected_time_sec);
                    ext->lq_event                    = wire->lq_event;
                    ext->status_code                 = wire->status_code;

                    /* Proprietary fields */
                    ext->custom_score      = wire->custom_score;
                    ext->is_managed_client = (wire->is_managed_client != 0);
                    size_t tag_len = wire->tag_len;
                    if (tag_len > VENDOR_STA_TAG_MAX_LEN) tag_len = VENDOR_STA_TAG_MAX_LEN;
                    ext->custom_tag.assign(wire->tag, tag_len);

                    ++updated;
                    break;
                }
                sta = dm->get_next_sta(mac, sta);
            }

            ptr       += sizeof(vendor_sta_private_wire_t);
            remaining -= sizeof(vendor_sta_private_wire_t);
        }

        return updated;
    }

    // ── Entry point ────────────────────────────────────────────────

    static int handle_tlv(const unsigned char *tlv_value,
                           unsigned int         tlv_len,
                           dm_easy_mesh_t      *dm)
    {
        int n = parse_tlv(tlv_value, tlv_len, dm);
        return (n > 0) ? n : 0;
    }
};

// ── Strong override of the weak hook in em_metrics.cpp ──────────────────
//
// Called for every em_tlv_type_vendor_specific TLV inside a topo_vendor CMDU.
// The public repo's weak default returns 0 (ignore).
//
// Dispatch by attr_id:
//   VENDOR_ATTR_STA_PRIVATE (0x10) → handled here, populates dm_sta_ext_t
//   any other attr_id              → OUI check or attr_id check fails → returns 0
//
int em_metrics_t::handle_vendor_tlv_ext(const unsigned char *tlv_value,
                                         unsigned int         tlv_len,
                                         dm_easy_mesh_t      *dm)
{
    return em_vendor_sta_ctrl_t::handle_tlv(tlv_value, tlv_len, dm);
}
