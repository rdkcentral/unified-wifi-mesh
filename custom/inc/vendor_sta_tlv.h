/**
 * Wire format definitions for the private STA vendor TLV.
 *
 * Shared between agent (serialize) and controller (deserialize).
 * Include this only from custom/src/ files — never from the public repo.
 *
 * Message flow:
 *
 *   Agent                                     Controller
 *     |                                           |
 *     |  dm_sta_ext_t populated from HAL      |
 *     |  vendor_sta_tlv_serialize()               |
 *     |   → em_vendor_specific_t                 |
 *     |       oui  = VENDOR_STA_PRIVATE_OUI       |
 *     |       attr_id = VENDOR_ATTR_STA_PRIVATE   |
 *     |       payload = vendor_sta_private_wire_t |
 *     |  → em_tlv_type_vendor_specific TLV        |
 *     |  → em_msg_type_topo_vendor CMDU           |
 *     |  ────────────────────────────────────────►|
 *     |                                           | vendor_sta_tlv_parse()
 *     |                                           |  → find dm_sta_t by MAC
 *     |                                           |  → update dm_sta_ext_t
 */

#ifndef VENDOR_STA_TLV_H
#define VENDOR_STA_TLV_H

#include "em_base.h"

/* ── OUI ─────────────────────────────────────────────────────────────────── */
/* Use the same OUI as the rest of the codebase ({0xd8, 0x9c, 0x8e}) so all
 * vendor TLVs are grouped under one OUI.  The attr_id below disambiguates. */
#define VENDOR_STA_PRIVATE_OUI   { 0xd8, 0x9c, 0x8e }

/* ── Attribute ID ────────────────────────────────────────────────────────── */
/* Must not collide with vendor_ext_attr_id_t values (max is 6 in public repo).
 * Use 0x10 as the base for private-repo attr IDs. */
#define VENDOR_ATTR_STA_PRIVATE  0x10

/* ── Max tag string length on the wire ──────────────────────────────────── */
#define VENDOR_STA_TAG_MAX_LEN   64

/* ── Wire format ─────────────────────────────────────────────────────────── *
 * One record per STA.  Packed; no platform-dependent padding.
 * Fields follow stats_arg_t member order (DHCP fields excluded).
 * Fixed-width integer types used throughout for ABI stability.
 */
typedef struct {
    /* Lookup key */
    mac_address_t  sta_mac;

    /* stats_arg_t: mac_str → looked up by MAC above; ap_mac_str below */
    mac_addr_str_t ap_mac_str;          /* ap_mac_str                         */
    uint32_t       vap_index;           /* vap_index                          */
    uint32_t       radio_index;         /* radio_index                        */
    int32_t        channel_utilization; /* channel_utilization                */

    /* stats_arg_t.dev (dev_stats_t) in declaration order */
    uint64_t       cli_pkts_tx;         /* dev.cli_PacketsSent                */
    uint64_t       cli_pkts_rx;         /* dev.cli_PacketsReceived            */
    uint64_t       cli_retrans;         /* dev.cli_RetransCount               */
    uint64_t       cli_rx_retries;      /* dev.cli_RxRetries                  */
    int32_t        cli_snr;             /* dev.cli_SNR                        */
    uint32_t       cli_max_dl_rate;     /* dev.cli_MaxDownlinkRate            */
    uint32_t       cli_max_ul_rate;     /* dev.cli_MaxUplinkRate              */
    uint32_t       cli_last_dl_rate;    /* dev.cli_LastDataDownlinkRate       */
    uint32_t       cli_last_ul_rate;    /* dev.cli_LastDataUplinkRate         */
    uint8_t        cli_power_save;      /* dev.cli_PowerSaveMode              */

    /* stats_arg_t time fields */
    int64_t        total_connected_time_sec;
    int64_t        total_disconnected_time_sec;

    /* stats_arg_t event / status */
    int32_t        lq_event;            /* event                              */
    uint32_t       status_code;         /* status_code                        */

    /* Proprietary fields */
    uint32_t       custom_score;
    uint8_t        is_managed_client;
    uint8_t        tag_len;             /* length of custom_tag string (≤64)  */
    char           tag[VENDOR_STA_TAG_MAX_LEN];
} __attribute__((__packed__)) vendor_sta_private_wire_t;

#endif /* VENDOR_STA_TLV_H */
