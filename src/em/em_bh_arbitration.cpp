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

#include <arpa/inet.h>
#include <dirent.h>
#include <fcntl.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <sys/socket.h>
#include <unistd.h>
#include <climits>
#include <cstring>
#include <fstream>
#include "em_base.h"
#include "em_bh_arbitration.h"
#include "util.h"

em_stp_monitor_t::em_stp_monitor_t(notify_cb_t notify)
    : m_notify(std::move(notify)), m_stp_bridge_name(), m_stp_root_tracker(), m_last_notified_backhaul_interface()
{
}

em_stp_monitor_t::~em_stp_monitor_t()
{
    close_netlink_socket();
}

bool em_stp_monitor_t::init()
{
    if (!initialize_stp())
        return false;

    if (is_enabled() && m_netlink_socket < 0 && create_netlink_socket() != 0) {
        em_printfout("Netlink socket creation failed");
        return false;
    }

    return true;
}

void em_stp_monitor_t::shutdown()
{
    close_netlink_socket();
}

void em_stp_monitor_t::on_readable()
{
    process_netlink_events();
}

void em_stp_monitor_t::reconcile()
{
    evaluate_stp_root_port();
}

int em_stp_monitor_t::create_netlink_socket()
{
    if (m_netlink_socket >= 0) {
        em_printfout("Netlink socket creation skipped, fd=%d", m_netlink_socket);
        return 0;
    }

    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (fd < 0) {
        em_printfout("Failed to create netlink socket: %s", strerror(errno));
        return -1;
    }

    if (fd >= FD_SETSIZE) {
        em_printfout("Netlink fd %d exceeds FD_SETSIZE (%d)", fd, FD_SETSIZE);
        close(fd);
        return -1;
    }

    // increase kernel receive queue capacity to reduce notification loss during bursts.
    int receive_buffer = 256 * 1024;

    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &receive_buffer, sizeof(receive_buffer)) < 0)
        em_printfout("Netlink receive buffer setup failed, using default buffer: %s", strerror(errno));

    struct sockaddr_nl addr = {};
    addr.nl_family = AF_NETLINK;
    addr.nl_groups = RTMGRP_LINK;
    addr.nl_pid = 0;
    
    if (bind(fd, reinterpret_cast<struct sockaddr *>(&addr), sizeof(addr)) < 0) {
        em_printfout("Netlink bind failed: %s", strerror(errno));
        close(fd);
        return -1;
    }
    m_netlink_socket = fd;
    em_printfout("Netlink RTMGRP_LINK monitoring enabled (fd=%d)", fd);

    return 0;
}

void em_stp_monitor_t::close_netlink_socket()
{
    if (m_netlink_socket >= 0) {
        close(m_netlink_socket);
        m_netlink_socket = -1;
    }
}

bool em_stp_monitor_t::initialize_stp()
{
    const char *bridge_env = getenv("EASYMESH_STP_BRIDGE");
    const char *gateway_priority_env = getenv("EASYMESH_STP_GATEWAY_PRIORITY");
    const char *extender_priority_env = getenv("EASYMESH_STP_EXTENDER_PRIORITY");

    if (!bridge_env || !gateway_priority_env || !extender_priority_env) {
        em_printfout("EM_STP: missing STP environment configuration");
        return false;
    }

    // validate the bridge interface name
    if (!is_valid_ifname(bridge_env)) {
        em_printfout("EM_STP: invalid or missing STP bridge interface");
        return false;
    }
    const std::string bridge_name(bridge_env);

    unsigned int gateway_priority = 0, extender_priority = 0;

    if (!parse_stp_priority(gateway_priority_env, gateway_priority)) {
        em_printfout("EM_STP: invalid STP gateway priority configuration");
        return false;
    }

    if (!parse_stp_priority(extender_priority_env, extender_priority)) {
        em_printfout("EM_STP: invalid STP extender priority configuration");
        return false;
    }

    // gateway should be the STP root and configured with lower priority
    if (gateway_priority >= extender_priority) {
        em_printfout("EM_STP: invalid priority configuration gateway=%u extender=%u", gateway_priority, extender_priority);
        return false;
    }

#ifdef EXT_NETLINK_MONITOR
    const unsigned int local_priority = extender_priority;
#else
    const unsigned int local_priority = gateway_priority;
#endif

    const std::string sysfs_base = "/sys/class/net/" + bridge_name + "/bridge/";
    const std::string priority_path = sysfs_base + "priority";
    const std::string stp_state_path = sysfs_base + "stp_state";

    unsigned int current_priority = 0, current_stp_state = 0;

    // read the current stp state and priority for the configured bridge on the device
    if (!read_sysfs_uint(priority_path, current_priority, 10) || !read_sysfs_uint(stp_state_path, current_stp_state, 10)) {
        em_printfout("EM_STP: failed to read bridge configuration bridge=%s", bridge_name.c_str());
        return false;
    }

    // set the priority only it varies
    if (current_priority != local_priority) {
        em_printfout("EM_STP: updating bridge priority bridge=%s current=%u expected=%u",
            bridge_name.c_str(),
            current_priority,
            local_priority);
	
	if (!write_stp_sysfs(priority_path, std::to_string(local_priority))) {
            em_printfout("EM_STP: failed to configure bridge priority bridge=%s priority=%u",
                bridge_name.c_str(),
                local_priority);
            return false;
        }

    }

    // enable stp for the configured bridge
    if (current_stp_state != 1) {
        em_printfout("EM_STP: enabling STP bridge=%s", bridge_name.c_str());
	if (!write_stp_sysfs(stp_state_path, "1")) {
            em_printfout("EM_STP: failed to enable STP bridge=%s", bridge_name.c_str());
            return false;
        }
    }

    unsigned int verified_priority = 0, verified_stp_state = 0;

    if (!read_sysfs_uint(priority_path, verified_priority, 10) || 
        !read_sysfs_uint(stp_state_path, verified_stp_state, 10) ||
        verified_priority != local_priority || 
        verified_stp_state != 1) {
        em_printfout("EM_STP: bridge configuration failed for bridge=%s expected_priority=%u actual_priority=%u stp_state=%u",
        bridge_name.c_str(),
        local_priority,
        verified_priority,
        verified_stp_state);
        return false;
    }
    
    m_stp_bridge_name = bridge_name;
    m_gateway_stp_priority = gateway_priority;

    em_printfout("EM_STP: initialized bridge=%s local_priority=%u gateway_priority=%u stp_state=%u",
                 m_stp_bridge_name.c_str(),
                 local_priority,
                 m_gateway_stp_priority,
                 verified_stp_state);

    return true;
}

void em_stp_monitor_t::process_netlink_events()
{
    if (m_netlink_socket < 0)
        return;

    alignas(struct nlmsghdr) char buffer[EM_NETLINK_RECV_BUFFER];
    bool relevant_event = false, force_resync = false;

    // process a bounded number of datagrams so that Netlink traffic cannot monopolize the ieee1905 listener thread.
    for (int iloop = 0; iloop < EM_NETLINK_MAX_BATCH; ++iloop) {
        struct sockaddr_nl sender = {};
        struct iovec iov = {};
        iov.iov_base = buffer;
        iov.iov_len = sizeof(buffer);

        struct msghdr msg = {};
        msg.msg_name = &sender;
        msg.msg_namelen = sizeof(sender);
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;

        ssize_t len = recvmsg(m_netlink_socket, &msg, MSG_DONTWAIT);

        if (len < 0) {
            if (errno == EINTR)
                continue;

            if (errno == EAGAIN || errno == EWOULDBLOCK)
                break;

            if (errno == ENOBUFS) {
                // Refresh from sysfs, as notifications may have been lost.
                force_resync = true;
                break;
            }

            em_printfout("Netlink recvmsg() failed: %s", strerror(errno));
            force_resync = true;
            break;
        }

        if (len == 0) {
            force_resync = true;
            break;
        }

        // reject truncated datagrams. A truncated event may hide a link transition.
        if (msg.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) {
            force_resync = true;
            continue;
        }

        if (msg.msg_namelen < sizeof(struct sockaddr_nl) || sender.nl_family != AF_NETLINK || sender.nl_pid != 0)
            continue;

        std::size_t remaining = static_cast<std::size_t>(len);
        auto *nlh = reinterpret_cast<struct nlmsghdr *>(buffer);
        bool malformed = false;

        while (remaining >= sizeof(struct nlmsghdr)) {
            const std::size_t message_len = static_cast<std::size_t>(nlh->nlmsg_len);

            // validate the message length before accessing the payload or advancing to the next message.
            if (message_len < sizeof(struct nlmsghdr) || message_len > remaining) {
                malformed = true;
                break;
            }

            switch (nlh->nlmsg_type) {
                case RTM_NEWLINK:
                case RTM_DELLINK: {
                    if (message_len <
                        NLMSG_LENGTH(sizeof(struct ifinfomsg))) {
                        malformed = true;
                        break;
                    }
                    relevant_event = true;
                    break;
                }

                case NLMSG_ERROR: {
                    if (message_len <
                        NLMSG_LENGTH(sizeof(struct nlmsgerr))) {
                        malformed = true;
                    } else {
                        // Avoid NLMSG_DATA(), which contains a C-style cast.
                        const auto *err =
                            reinterpret_cast<const struct nlmsgerr *>(reinterpret_cast<const char *>(nlh) +
                                NLMSG_HDRLEN);

                        if (err->error != 0)
                            force_resync = true;
                    }
                    break;
                }

                case NLMSG_OVERRUN:
                    force_resync = true;
                    break;

                case NLMSG_DONE:
                    break;

                default:
                    break;
            }

            if (malformed)
                break;

            const std::size_t aligned_len = static_cast<std::size_t>(NLMSG_ALIGN(nlh->nlmsg_len));

            if (aligned_len > remaining) {
                malformed = true;
                break;
            }

            remaining -= aligned_len;
            if (remaining == 0)
                break;

            nlh = reinterpret_cast<struct nlmsghdr *>(reinterpret_cast<char *>(nlh) + aligned_len);
        }

        if (malformed || remaining != 0)
            force_resync = true;
    }

    if (relevant_event || force_resync)
        evaluate_stp_root_port();
}

bool em_stp_monitor_t::is_enabled()
{
#ifdef EXT_NETLINK_MONITOR
    return true;
#else
    return false;
#endif
}

int em_stp_monitor_t::read_stp_root_port(em_stp_root_info_t &info)
{
    info = em_stp_root_info_t{};

    // validate the configured bridge interface name before using it to construct sysfs paths
    if (!is_valid_ifname(m_stp_bridge_name)) {
        em_printfout("Invalid or missing bridge interface name");
        return INVALID_STP_BRIDGE_INTF;
    }

    const std::string bridge_path = "/sys/class/net/" + m_stp_bridge_name;

     // check whether STP is enabled on the configured bridge interface
    unsigned int uistp_enabled = 0;

    if (!read_sysfs_uint(bridge_path + "/bridge/stp_state", uistp_enabled, 10)) {
        em_printfout("Failed to read STP state for bridge=%s", m_stp_bridge_name.c_str());
        return STP_STATE_READ_FAILED;
    }

    if (uistp_enabled == 0) {
        em_printfout("STP is disabled for bridge=%s", m_stp_bridge_name.c_str());
        return STP_DISABLED_BRIDGE_INTF;
    }

     // read the STP root-port number selected by the bridge, please note the bridge root_port value is decimal.
    unsigned int root_port = 0;
    const std::string root_port_path = bridge_path + "/bridge/root_port";

    if (!read_sysfs_uint(root_port_path, root_port, 10)) {
        em_printfout("Failed to read root port for bridge=%s", m_stp_bridge_name.c_str());
        return STP_ROOT_PORT_READ_FAILED;
    }

    // A forwarding Ethernet root port is not sufficient: after the Gateway-to-switch
    // link fails, another Extender can become the root while this port stays up.
    const std::string root_id_path = bridge_path + "/bridge/root_id";
    unsigned int root_priority = 0;
    if (!read_stp_bridge_priority(root_id_path, root_priority)) {
        em_printfout("Failed to read STP root ID bridge=%s", m_stp_bridge_name.c_str());
        return STP_STATE_READ_FAILED;
    }

    info.root_port = root_port;

     // root_port value of 0 means that the local bridge currently considers itself the STP root
    if (root_port == 0)
        return STP_ROOT_IS_BRIDGE;

    if (root_priority != m_gateway_stp_priority) {
        unsigned int verified_priority = 0;
        unsigned int verified_root_port = 0;
        if (!read_stp_bridge_priority(root_id_path, verified_priority) ||
            !read_sysfs_uint(root_port_path, verified_root_port, 10) ||
            verified_priority != root_priority || verified_root_port != root_port)
            return STP_ROOT_CHANGED;

        em_printfout("Non-Gateway STP root bridge=%s priority=0x%04x root_port=%u",
            m_stp_bridge_name.c_str(), root_priority, root_port);
        return STP_ROOT_NOT_GATEWAY;
     }

    // enumerate bridge member interfaces and match their port_no against the selected STP root-port number
    const std::string brif_path = bridge_path + "/brif";

    DIR *dir = opendir(brif_path.c_str());

    if (dir == nullptr) {
        em_printfout("Cannot open bridge member directory=%s: %s", brif_path.c_str(), strerror(errno));
        return STP_ROOT_BRIF_OPEN_FAILED;
    }

    bool found = false, ambiguous = false;
    int dir_error = 0;

    while (true) {
        errno = 0;
        struct dirent *entry = readdir(dir);

        if (entry == nullptr) {
            dir_error = errno;
            break;
        }

        const std::string ifname(entry->d_name);

        if (!is_valid_ifname(ifname))
            continue;

        const std::string port_path = brif_path + "/" + ifname;
        unsigned int port_no = 0;

         // please note the bridge member port_no values are represented in hex value
        if (!read_sysfs_uint(port_path + "/port_no", port_no, 16))
            continue;

         // consider only the bridge-selected root port, other bridge members may also be forwarding
        if (port_no != root_port)
            continue;

         // multiple interfaces with the same port number indicate an inconsistent bridge snapshot
        if (found) {
            ambiguous = true;
            break;
        }

        info.ifname = ifname;
        found = true;
    }

     // preserve errno from readdir() before closedir()
    const int close_ret = closedir(dir);

    if (close_ret != 0)
        em_printfout("Failed to close bridge member directory=%s: %s", brif_path.c_str(), strerror(errno));

    if (dir_error != 0) {
        em_printfout("Failed to enumerate bridge members bridge=%s: %s", m_stp_bridge_name.c_str(), strerror(dir_error));
        return STP_ROOT_BRIF_READ_FAILED;
    }

    if (!found || ambiguous) {
        em_printfout("Root port cannot be uniquely resolved bridge=%s root_port=%u", m_stp_bridge_name.c_str(), root_port);
        return STP_ROOT_NOT_FOUND;
    }

     // read the STP state of the selected root interface.
    const std::string state_path = brif_path + "/" + info.ifname + "/state";

    if (!read_sysfs_uint(state_path, info.port_state, 10)) {
        em_printfout("Failed to read port state bridge=%s interface=%s", m_stp_bridge_name.c_str(), info.ifname.c_str());
        return STP_ROOT_STATE_READ_FAILED;
    }

     // resolve the interface index
    info.ifindex = if_nametoindex(info.ifname.c_str());

    if (info.ifindex == 0) {
        em_printfout("Failed to resolve ifindex interface=%s", info.ifname.c_str());
        return STP_ROOT_IFINDEX_FAILED;
    }

    // read the root_port again after enumerating bridge members to avoid changes in root-port selection during sysfs read sequence.
    unsigned int verify_root_port = 0;

    if (!read_sysfs_uint(root_port_path, verify_root_port, 10) || verify_root_port != root_port) {
        em_printfout("Root port changed during read bridge=%s old_root_port=%u new_root_port=%u",
            m_stp_bridge_name.c_str(),
            root_port,
            verify_root_port);

        return STP_ROOT_CHANGED;
    }

    // a root_port match alone does not prove that the selected port state remained stable while sysfs entries were enumerated
    unsigned int verified_port_state = 0;

    if (!read_sysfs_uint(state_path, verified_port_state, 10))
        return STP_ROOT_STATE_READ_FAILED;

    if (verified_port_state != info.port_state)
        return STP_ROOT_CHANGED;

    unsigned int verified_root_priority = 0;
    if (!read_stp_bridge_priority(root_id_path, verified_root_priority) || verified_root_priority != root_priority)
        return STP_ROOT_CHANGED;


    // the selected root interface must be forwarding before notification
    if (info.port_state != STP_FORWARDING) {
        em_printfout("Root port not forwarding yet bridge=%s root_port=%u interface=%s state=%u",
            m_stp_bridge_name.c_str(),
            info.root_port,
            info.ifname.c_str(),
            info.port_state);

        return STP_ROOT_NOT_FORWARDING;
    }

    return STP_ROOT_SUCCESS;
}

void em_stp_monitor_t::update_stp_root_tracker(int status, const em_stp_root_info_t &root_info)
{
    em_stp_root_tracker_t &tracker = m_stp_root_tracker;
    bool root_changed = false;

    switch (status) {
        case STP_ROOT_SUCCESS:
             // return if the same root is already active, no state transition or notification is necessary.
            if (tracker.state == STP_ROOT_TRACK_FORWARDING && is_same_stp_root(tracker.current_root, root_info)) 
                return;

            // a newly validated forwarding root is available, compare against the last validated root rather
            root_changed = tracker.has_last_valid_root && !is_same_stp_root(tracker.last_valid_root, root_info);

            if (root_changed) {
                em_printfout("Root port changed bridge=%s old_interface=%s old_ifindex=%u new_interface=%s new_ifindex=%u",
                    m_stp_bridge_name.c_str(),
                    tracker.last_valid_root.ifname.c_str(),
                    tracker.last_valid_root.ifindex,
                    root_info.ifname.c_str(),
                    root_info.ifindex);
            } else if (!tracker.has_last_valid_root) {
                em_printfout("Initial forwarding root bridge=%s interface=%s ifindex=%u",
                    m_stp_bridge_name.c_str(),
                    root_info.ifname.c_str(),
                    root_info.ifindex);
            } else {
                em_printfout("Forwarding root restored bridge=%s interface=%s ifindex=%u",
                    m_stp_bridge_name.c_str(),
                    root_info.ifname.c_str(),
                    root_info.ifindex);
            }

            tracker.current_root = root_info;
            tracker.last_valid_root = root_info;
            tracker.has_last_valid_root = true;
            tracker.state = STP_ROOT_TRACK_FORWARDING;
            break;

        case STP_ROOT_NOT_FORWARDING:
             // te bridge has selected a root port, but it is still not ready.
            if (tracker.state != STP_ROOT_TRACK_CONVERGING) {
                em_printfout("Root port convergence bridge=%s interface=%s state=%u",
                    m_stp_bridge_name.c_str(),
                    root_info.ifname.c_str(),
                    root_info.port_state);
            }

            tracker.current_root = em_stp_root_info_t{};
            tracker.state = STP_ROOT_TRACK_CONVERGING;
            break;

        case STP_ROOT_IS_BRIDGE:
        case STP_ROOT_NOT_GATEWAY:
        case STP_DISABLED_BRIDGE_INTF:
             // no usable upstream STP root port exists.
            if (tracker.state != STP_ROOT_TRACK_UNAVAILABLE) {
                em_printfout("No upstream forwarding root bridge=%s status=%d",
                    m_stp_bridge_name.c_str(),
                    status);
            }

            tracker.current_root = em_stp_root_info_t{};
            tracker.state = STP_ROOT_TRACK_UNAVAILABLE;
            break;

        case STP_ROOT_CHANGED:
            if (tracker.state != STP_ROOT_TRACK_UNKNOWN)
                em_printfout("Root-port snapshot unstable bridge=%s; reconciliation required", m_stp_bridge_name.c_str());

            tracker.current_root = em_stp_root_info_t{};
            tracker.state = STP_ROOT_TRACK_UNKNOWN;
            break;

        default:
            if (tracker.state != STP_ROOT_TRACK_UNKNOWN)
                em_printfout("Root-port status unknown bridge=%s status=%d", m_stp_bridge_name.c_str(), status);

            tracker.current_root = em_stp_root_info_t{};
            tracker.state = STP_ROOT_TRACK_UNKNOWN;
            break;
    }
}

bool em_stp_monitor_t::read_sysfs_uint(const std::string &path, unsigned int &uivalue, int ibase)
{
    std::ifstream file(path);

    if (!file.is_open())
        return false;

    std::string text;

    if (!std::getline(file, text))
        return false;

    errno = 0;
    char *end = nullptr;

    const unsigned long result = std::strtoul(text.c_str(), &end, ibase);

    if (errno != 0 || end == text.c_str() || result > UINT_MAX ||
        text.find_first_not_of(" \t") == std::string::npos ||
        text.find('-') != std::string::npos)
        return false;

    while (*end == ' ' || *end == '\t' || *end == '\n' || *end == '\r') {
        ++end;
    }

    if (*end != '\0')
        return false;

    uivalue = static_cast<unsigned int>(result);
    return true;
}

bool em_stp_monitor_t::is_valid_ifname(const std::string &name)
{
    if (name.empty() || name.size() >= IFNAMSIZ || name == "." || name == "..")
        return false;

    for (char c : name) {
        if (c == '/' || c == ':' || c == ' ' || c == '\t' || c == '\n')
            return false;
    }

    return true;
}

bool em_stp_monitor_t::is_same_stp_root(const em_stp_root_info_t &lhs, const em_stp_root_info_t &rhs)
{
    return lhs.ifindex == rhs.ifindex && lhs.root_port == rhs.root_port && lhs.ifname == rhs.ifname;
}

void em_stp_monitor_t::evaluate_stp_root_port()
{
    em_stp_root_info_t root_info = {};

    const int istatus = read_stp_root_port(root_info);
    update_stp_root_tracker(istatus, root_info);

     // ethernet backhaul is preferred and notify the EM agent only when the ETH interface or BH state changes
    if (istatus == STP_ROOT_SUCCESS && is_ethernet_backhaul_root(root_info.ifname)) {

        if (!m_backhaul_status_notified || !m_backhaul_status_active || !m_backhaul_interface_notify_initialized ||
            !is_same_stp_root(m_last_notified_backhaul_interface, root_info)) {
            notify_backhaul_interface_change(root_info);
        }
        return;
    }

    /*
     * STP_ROOT_IS_BRIDGE: Local extender became STP root after losing the upstream Gateway path
     * STP_ROOT_NOT_GATEWAY: Another extender became STP root while the ethernet port remains forwarding
     * STP_ROOT_SUCCESS with non-Ethernet root: A valid forwarding wireless root port exists.
     */
    const bool gateway_root_lost = (istatus == STP_ROOT_IS_BRIDGE || istatus == STP_ROOT_NOT_GATEWAY);
    const bool wireless_root_active = (istatus == STP_ROOT_SUCCESS && !is_ethernet_backhaul_root(root_info.ifname));

    // retain the last BH state and wait for the next STP reconciliation 
    if (!gateway_root_lost && !wireless_root_active) {
        em_printfout("EM_BH: holding backhaul request bridge=%s stp_status=%d", m_stp_bridge_name.c_str(), istatus);
        return;
    }

     // check for duplicate wireless BH requests
    if (m_backhaul_status_notified && !m_backhaul_status_active)
        return;

     /* A valid wireless root is already available, if ETH BH was previously active, notify agent to switch its recorded BH state.
     * If no BH state was previously published, do not generate a request.
     */
    if (wireless_root_active && !m_backhaul_status_active)
        return;

     // request Wireless BH switch and notify EM agent
    em_backhaul_interface_notify_t event = {};
    event.ethernet_backhaul_active = false;

    em_printfout("EM_BH: request wireless bridge=%s stp_status=%d root_if=%s previous_eth_active=%d",
        m_stp_bridge_name.c_str(),
        istatus,
        root_info.ifname.c_str(),
        m_backhaul_status_active);

    m_notify(event);

     /* Update the locally notified BH state.
     * Subsequent reconciliation cycles will not generate duplicate Wireless BH requests.
     * A later validated Ethernet root will trigger notify_backhaul_interface_change() again.
     */
    m_backhaul_status_notified = true;
    m_backhaul_status_active = false;
    m_backhaul_interface_notify_initialized = false;
}

bool em_stp_monitor_t::notify_backhaul_interface_change(const em_stp_root_info_t &root_info)
{
    // notify only for a valid forwarding STP root interface.
    if (root_info.ifname.empty() || root_info.ifindex == 0 || root_info.root_port == 0 || root_info.port_state != STP_FORWARDING)
        return false;

    // avoid duplicate backhaul interface notifications
    if (m_backhaul_interface_notify_initialized &&
        m_backhaul_status_active && is_same_stp_root(m_last_notified_backhaul_interface, root_info)) {
        return false;
    }

    em_backhaul_interface_notify_t event = {};

    if (root_info.ifname.size() >= sizeof(event.ifname) || sizeof(event) > EM_MAX_EVENT_DATA_LEN) {
        em_printfout("Invalid backhaul interface notification payload");
        return false;
    }

    // check the interface still has the expected ifindex.
    if (if_nametoindex(root_info.ifname.c_str()) != root_info.ifindex) {
        em_printfout("Backhaul interface identity changed: %s", root_info.ifname.c_str());
        return false;
    }

    // fetch the MAC address of the selected backhaul interface.
    if (!get_backhaul_interface_mac(root_info.ifname, event.mac_addr)) {
        return false;
    }

    snprintf(event.ifname, sizeof(event.ifname), "%s", root_info.ifname.c_str());
    event.ifindex = root_info.ifindex;
    event.root_port = root_info.root_port;
    event.port_state = root_info.port_state;
    event.ethernet_backhaul_active = true;

    em_printfout("Backhaul interface changed: old=%s new=%s ifindex=%u root_port=%u "
        "mac=%02x:%02x:%02x:%02x:%02x:%02x",
        m_backhaul_interface_notify_initialized ? m_last_notified_backhaul_interface.ifname.c_str() : "<none>",
        root_info.ifname.c_str(),
        root_info.ifindex,
        root_info.root_port,
        event.mac_addr[0], event.mac_addr[1],
        event.mac_addr[2], event.mac_addr[3],
        event.mac_addr[4], event.mac_addr[5]);

    // notify EM Agent for BH change
    m_notify(event);

    // update last-notified state.
    m_last_notified_backhaul_interface = root_info;
    m_backhaul_interface_notify_initialized = true;
    m_backhaul_status_notified = true;
    m_backhaul_status_active = true;

    return true;
}

bool em_stp_monitor_t::get_backhaul_interface_mac(const std::string &ifname, uint8_t (&mac_addr)[6]) const
{
    if(!is_valid_ifname(ifname))
        return false;

    const std::string path = "/sys/class/net/" + ifname + "/address";

    std::ifstream file(path);

    if (!file.is_open()) {
        em_printfout("Failed to open MAC address for interface %s", ifname.c_str());
        return false;
    }

    std::string mac_string;

    if (!std::getline(file, mac_string)) {
        em_printfout("Failed to read MAC address for interface %s", ifname.c_str());
        return false;
    }

    unsigned int bytes[6] = {};
    char extra = '\0';

    const int parsed = sscanf(mac_string.c_str(), "%2x:%2x:%2x:%2x:%2x:%2x%c",
        &bytes[0], &bytes[1], &bytes[2],
        &bytes[3], &bytes[4], &bytes[5],
        &extra);

    if (mac_string.size() != 17 || parsed != 6) {
        em_printfout("Invalid MAC address for interface %s: %s", ifname.c_str(), mac_string.c_str());
        return false;
    }

    for (int iloop = 0; iloop < 6; ++iloop) {
        if (bytes[iloop] > 0xff) {
            return false;
        }
        mac_addr[iloop] = static_cast<uint8_t>(bytes[iloop]);
    }

    return true;
}

bool em_stp_monitor_t::is_ethernet_backhaul_root(const std::string &ifname)
{
    if (ifname.empty() || ifname.size() >= IFNAMSIZ ||
        ifname.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-") != std::string::npos)
        return false;

    const std::string base = "/sys/class/net/" + ifname;
    const auto exists = [](const std::string &path) { return access(path.c_str(), F_OK) == 0; };
    if (exists(base + "/wireless") || exists(base + "/phy80211") ||
        exists(base + "/bridge") || exists(base + "/bonding") ||
        exists(base + "/tun_flags"))
        return false;

    std::ifstream type_file(base + "/type");
    unsigned int type = 0;
    if (!(type_file >> type) || type != 1) // ARPHRD_ETHER
        return false;

    return exists(base + "/phydev") || exists(base + "/dsa") ||
           exists(base + "/device");
}

bool em_stp_monitor_t::read_stp_bridge_priority(const std::string &path, unsigned int &priority)
{
    std::ifstream file(path);
    std::string id;
    if (!file.is_open() || !std::getline(file, id) || id.size() != 17 || id[4] != '.')
        return false;

    for (size_t i = 0; i < id.size(); ++i) {
        if (i != 4 && !std::isxdigit(static_cast<unsigned char>(id[i])))
            return false;
    }

    priority = 0;
    for (size_t i = 0; i < 4; ++i) {
        const char digit = id[i];
        priority = (priority << 4) | static_cast<unsigned int>(
            digit >= '0' && digit <= '9' ? digit - '0' :
            (digit >= 'a' && digit <= 'f' ? digit - 'a' + 10 : digit - 'A' + 10));
    }
    return true;
}


bool em_stp_monitor_t::parse_stp_priority(const char *value, unsigned int &priority)
{
    if (value == nullptr || *value == '\0')
        return false;

    // accept only decimal values
    for (const char *p = value; *p != '\0'; ++p) {
        if (*p < '0' || *p > '9') {
            return false;
        }
    }

    errno = 0;
    char *end = nullptr;
    unsigned long parsed = strtoul(value, &end, 10);

    // STP priortity can be set in step of 4096 and the max value is 61440
    if (errno != 0 || end == value || *end != '\0' || parsed > 61440 || (parsed % 4096) != 0)
        return false;

    priority = static_cast<unsigned int>(parsed);
    return true;
}

bool em_stp_monitor_t::write_stp_sysfs(const std::string &path, const std::string &value)
{
    int fd = open(path.c_str(), O_WRONLY | O_CLOEXEC);

    if (fd < 0) {
        em_printfout("EM_STP: open failed path=%s error=%s", path.c_str(), strerror(errno));
        return false;
    }

    const std::string data = value + "\n";
    ssize_t written;

    do {
        written = write(fd, data.c_str(), data.size());
    } while (written < 0 && errno == EINTR);

    int saved_errno = errno;

    if (close(fd) != 0 && written >= 0) {
        em_printfout("EM_STP: close failed path=%s error=%s", path.c_str(), strerror(errno));
        return false;
    }

    if (written != static_cast<ssize_t>(data.size())) {
        em_printfout("EM_STP: write failed path=%s error=%s", path.c_str(), strerror(written < 0 ? saved_errno : EIO));
        return false;
    }

    return true;
}
