/**
 * Private extension for dm_sta_t — lives in the private/custom repo.
 * This file is NOT part of the public unified-wifi-mesh repo.
 *
 * Include this header only from custom/src/dm_sta_ext.cpp.
 * Never include it from the public repo's sources.
 */

#ifndef DM_STA_EXT_H
#define DM_STA_EXT_H

#include <string>
#include "dm_easy_mesh.h"
#include "dm_sta.h"

#if 0
typedef struct {
    mac_address_t  sta_mac;
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
} __attribute__((__packed__)) vendor_sta_private_wire_t;
#endif

/**
 * @brief Hidden per-STA state, invisible to the public repo.
 *
 * Add whatever private members are needed here without touching
 * em_sta_info_t or dm_sta_t in the public repo.
 */
// class dm_sta_ext_t : public dm_sta_t {
// class dm_sta_ext_t {
class dm_sta_ext_t : public dm_sta_ext_interface_t {
private:
    // Populated from Device.WiFi.EM.StaLQData (stats_arg_t, no DHCP fields)
    std::string    ap_mac_str;
    unsigned int   vap_index;
    unsigned int   radio_index;
    int            channel_utilization;

    int            cli_snr;
    unsigned long  cli_pkts_tx;
    unsigned long  cli_pkts_rx;
    unsigned long  cli_retrans;
    unsigned long long cli_rx_retries;
    unsigned int   cli_max_dl_rate;
    unsigned int   cli_max_ul_rate;
    unsigned int   cli_last_dl_rate;
    unsigned int   cli_last_ul_rate;
    bool           cli_power_save;

    long long      total_connected_time_sec;
    long long      total_disconnected_time_sec;


public:

    dm_sta_ext_t();

    dm_sta_ext_t(const dm_sta_ext_t&) = default;
    dm_sta_ext_t& operator=(const dm_sta_ext_t&) = default;

    ~dm_sta_ext_t() override;
    // void handle_vendor_ext_tlv(const unsigned char *tlv_value, unsigned int tlv_len, dm_easy_mesh_t *dm) override;
    // Called by the extern "C" hook in dm_sta_ext.cpp at the end of
    // dm_sta_t::decode() — parses vendor-private JSON fields from the
    // same cJSON object that decode() used for public fields.
    // static void decode_from_json(dm_sta_t *sta, const cJSON *obj);

    // encode
    // decode
    // publish

    // Deep copy implementation for copy constructor of dm_sta_t
    dm_sta_ext_interface_t* clone() const override {
        return new dm_sta_ext_t(*this);
    }
};

#endif // DM_STA_EXT_H
