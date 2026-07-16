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

/**
 * @brief Hidden per-STA state, invisible to the public repo.
 *
 * Add whatever private members are needed here without touching
 * em_sta_info_t or dm_sta_t in the public repo.
 */
class dm_sta_ext_t {
public:
    // Proprietary fields
    unsigned int   custom_score;
    bool           is_managed_client;
    std::string    custom_tag;

    // Populated from Device.WiFi.EM.StaLQData (stats_arg_t, no DHCP fields)
    std::string    ap_mac_str;
    unsigned int   vap_index;
    unsigned int   radio_index;
    int            channel_utilization;
    int            lq_event;
    unsigned int   status_code;
    long long      total_connected_time_sec;
    long long      total_disconnected_time_sec;
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

    dm_sta_ext_t()
        : custom_score(0), is_managed_client(false), custom_tag()
        , ap_mac_str()
        , vap_index(0), radio_index(0), channel_utilization(0)
        , lq_event(0), status_code(0)
        , total_connected_time_sec(0), total_disconnected_time_sec(0)
        , cli_snr(0)
        , cli_pkts_tx(0), cli_pkts_rx(0), cli_retrans(0), cli_rx_retries(0)
        , cli_max_dl_rate(0), cli_max_ul_rate(0)
        , cli_last_dl_rate(0), cli_last_ul_rate(0)
        , cli_power_save(false)
    {}

    dm_sta_ext_t(const dm_sta_ext_t&) = default;
    dm_sta_ext_t& operator=(const dm_sta_ext_t&) = default;
};

#endif // DM_STA_EXT_H
