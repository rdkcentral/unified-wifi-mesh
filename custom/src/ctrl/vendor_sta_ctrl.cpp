/**
 * Controller-side private vendor TLV handlers.
 *
 * Provides the strong override of em_vendor_t::handle_vendor_tlv_ext() and
 * one handler per private attr_id range:
 *
 *   VENDOR_ATTR_STA_PRIVATE (0x10)  ->  em_vendor_sta_ctrl_t
 *   0x100-0x1ff                     ->  reserved (add subclasses here)
 *
 * To add a new attr_id: subclass em_vendor_tlv_handler_t, implement
 * handles() + process(), add a static instance to handlers[] below.
 */

#include <string.h>
#include <arpa/inet.h>

#include "dm_sta.h"
#include "dm_easy_mesh.h"
#include "em_vendor.h"
#include "custom/inc/em_vendor_tlv_handler.h"
#include "custom/inc/dm_sta_ext.h"
#include "custom/inc/vendor_sta_tlv.h"

namespace {
    const unsigned char vendor_sta_oui[EM_VENDOR_OUI_SIZE] = VENDOR_STA_PRIVATE_OUI;
}

// ── em_vendor_sta_ctrl_t ─────────────────────────────────────────────────
//
// Handles VENDOR_ATTR_STA_PRIVATE (0x10): parses an array of
// vendor_sta_private_wire_t records and populates dm_sta_ext_t.
//
class em_vendor_sta_ctrl_t : public em_vendor_tlv_handler_t {
public:
    bool handles(unsigned char attr_id) const override
    {
        return attr_id == VENDOR_ATTR_STA_PRIVATE;
    }

    int process(const unsigned char *tlv_value,
                unsigned int         tlv_len,
                dm_easy_mesh_t      *dm) override
    {
        const em_vendor_specific_t *vs =
            reinterpret_cast<const em_vendor_specific_t *>(tlv_value);

        if (memcmp(vs->vendor_oui, vendor_sta_oui, EM_VENDOR_OUI_SIZE) != 0)
            return 0;  // not our OUI

        unsigned int offset = EM_VENDOR_OUI_SIZE
                            + sizeof(vs->num)
                            + sizeof(vs->data[0].attr_id);
        if (tlv_len <= offset)
            return 0;

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
};

// ── Strong override ───────────────────────────────────────────────────────
//
// Iterates the static handler list and delegates to the first handler
// whose handles() matches the incoming attr_id.
//
int em_vendor_t::handle_vendor_tlv_ext(const unsigned char *tlv_value,
                                        unsigned int         tlv_len,
                                        dm_easy_mesh_t      *dm)
{
    if (tlv_len < sizeof(em_vendor_specific_t) + 1)
        return 0;

    const em_vendor_specific_t *vs =
        reinterpret_cast<const em_vendor_specific_t *>(tlv_value);
    const unsigned char attr_id = vs->data[0].attr_id;

    // ── Handler registry ─────────────────────────────────────────
    // Add a static instance here for each new private attr_id.
    static em_vendor_sta_ctrl_t sta_handler;

    static em_vendor_tlv_handler_t *const handlers[] = {
        &sta_handler,
        // &future_handler,
    };

    for (em_vendor_tlv_handler_t *h : handlers) {
        if (h->handles(attr_id))
            return h->process(tlv_value, tlv_len, dm);
    }
    return 0;
}
