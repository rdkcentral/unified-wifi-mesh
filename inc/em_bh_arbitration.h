/**
 * Copyright 2023 Comcast Cable Communications Management, LLC
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

#ifndef EM_BH_ARBITRATION_H
#define EM_BH_ARBITRATION_H

#include <net/if.h>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>

/* Payload of em_bus_event_type_backhaul_change, sent from the STP monitor to the EM agent. */
struct em_backhaul_interface_notify_t {
    char ifname[IFNAMSIZ] = {};
    uint8_t mac_addr[6] = {};
    uint32_t ifindex = 0;
    uint32_t root_port = 0;
    uint32_t port_state = 0;
    bool ethernet_backhaul_active = false;
};

/*
 * Configures STP on the EasyMesh linux bridge and tracks the STP root port
 * through RTNETLINK link events and periodic sysfs reconciliation. Backhaul
 * changes are reported through the notify callback.
 */
class em_stp_monitor_t {
public:
    static constexpr unsigned int STP_FORWARDING = 3;

    using notify_cb_t = std::function<void(const em_backhaul_interface_notify_t &)>;

    explicit em_stp_monitor_t(notify_cb_t notify);
    ~em_stp_monitor_t();

    em_stp_monitor_t(const em_stp_monitor_t &) = delete;
    em_stp_monitor_t &operator=(const em_stp_monitor_t &) = delete;

    /* True when this build monitors the STP root port (EXT_NETLINK_MONITOR). */
    static bool is_enabled();

    /* Configures bridge STP/priority and opens the netlink socket when monitoring is enabled. */
    bool init();
    void shutdown();

    /* Netlink socket to be added to the caller's select() set, -1 when not open. */
    int fd() const { return m_netlink_socket; }

    /* Drains pending netlink events and re-evaluates the STP root. */
    void on_readable();

    /* Re-evaluates the STP root from sysfs without waiting for a netlink event. */
    void reconcile();

private:
    static constexpr size_t EM_NETLINK_RECV_BUFFER = 16384;
    static constexpr int EM_NETLINK_MAX_BATCH = 8;

    enum em_stp_root_status_t {
        STP_ROOT_SUCCESS=0,
        INVALID_STP_BRIDGE_INTF=1,
        STP_STATE_READ_FAILED,
        STP_DISABLED_BRIDGE_INTF,
        STP_ROOT_PORT_READ_FAILED,
        STP_ROOT_IS_BRIDGE,
        STP_ROOT_BRIF_OPEN_FAILED,
        STP_ROOT_NOT_FOUND,
        STP_ROOT_STATE_READ_FAILED,
        STP_ROOT_CHANGED,
        STP_ROOT_NOT_GATEWAY,
        STP_ROOT_NOT_FORWARDING,
        STP_ROOT_IFINDEX_FAILED,
        STP_ROOT_BRIF_READ_FAILED
    };

    struct em_stp_root_info_t {
        std::string ifname;
        unsigned int ifindex = 0;
        unsigned int root_port = 0;
        unsigned int port_state = 0;
    };

    enum em_stp_root_track_state_t {
        STP_ROOT_TRACK_UNKNOWN = 0,
        STP_ROOT_TRACK_CONVERGING,
        STP_ROOT_TRACK_FORWARDING,
        STP_ROOT_TRACK_UNAVAILABLE
    };

    struct em_stp_root_tracker_t {
        em_stp_root_track_state_t state;
        em_stp_root_info_t current_root;
        em_stp_root_info_t last_valid_root;
        bool has_last_valid_root;

        em_stp_root_tracker_t()
        : state(STP_ROOT_TRACK_UNKNOWN),
          current_root(),
          last_valid_root(),
          has_last_valid_root(false)
        {
        }
    };

    notify_cb_t m_notify;
    std::string m_stp_bridge_name;
    int m_netlink_socket = -1;
    em_stp_root_tracker_t m_stp_root_tracker;
    em_stp_root_info_t m_last_notified_backhaul_interface;
    bool m_backhaul_interface_notify_initialized = false;
    bool m_backhaul_status_notified = false;
    bool m_backhaul_status_active = false;
    unsigned int m_gateway_stp_priority = 0;

    bool initialize_stp();
    int create_netlink_socket();
    void close_netlink_socket();
    void process_netlink_events();
    int read_stp_root_port(em_stp_root_info_t &info);
    void evaluate_stp_root_port();
    void update_stp_root_tracker(int status, const em_stp_root_info_t &root_info);
    bool notify_backhaul_interface_change(const em_stp_root_info_t &root_info);
    bool get_backhaul_interface_mac(const std::string &ifname, uint8_t (&mac_addr)[6]) const;

    static bool parse_stp_priority(const char *value, unsigned int &priority);
    static bool write_stp_sysfs(const std::string &path, const std::string &value);
    static bool read_sysfs_uint(const std::string &path, unsigned int &uivalue, int ibase);
    static bool is_valid_ifname(const std::string &name);
    static bool is_same_stp_root(const em_stp_root_info_t &lhs, const em_stp_root_info_t &rhs);
    static bool is_ethernet_backhaul_root(const std::string &ifname);
    static bool read_stp_bridge_priority(const std::string &path, unsigned int &priority);
};

#endif // EM_BH_ARBITRATION_H
