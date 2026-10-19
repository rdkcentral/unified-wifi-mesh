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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <dirent.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/ethtool.h>
#include <linux/sockios.h>
#include <algorithm>
#include <map>
#include <mutex>
#include <cjson/cJSON.h>
#include "em_eth.h"
#include "util.h"

static bool eth_iface_read_int(const std::string &iface, const char *attr, int &val)
{
    std::string path = "/sys/class/net/" + iface + "/" + attr;
    FILE *fp = fopen(path.c_str(), "r");
    if (fp == NULL) {
        return false;
    }
    bool ok = (fscanf(fp, "%d", &val) == 1);
    fclose(fp);
    return ok;
}

static bool eth_iface_is_wlan(const std::string &iface)
{
    std::string path = "/sys/class/net/" + iface + "/uevent";
    FILE *fp = fopen(path.c_str(), "r");
    if (fp == NULL) {
        return true;
    }
    char line[128];
    bool wlan = false;
    while (fgets(line, sizeof(line), fp) != NULL) {
        if (strstr(line, "DEVTYPE=wlan") != NULL) {
            wlan = true;
            break;
        }
    }
    fclose(fp);
    return wlan;
}

/* Ethernet-type netdev backed by hardware (NIC or switch port); veth, VLAN, bridge etc. live under /sys/devices/virtual */
static bool eth_iface_is_wired_hw(const std::string &iface)
{
    int type = 0;
    char resolved[PATH_MAX];

    if (!eth_iface_read_int(iface, "type", type) || (type != 1 /* ARPHRD_ETHER */)) {
        return false;
    }
    if (realpath(("/sys/class/net/" + iface).c_str(), resolved) == NULL) {
        return false;
    }
    return strstr(resolved, "/devices/virtual/") == NULL;
}

static std::vector<std::string> list_dir(const std::string &path)
{
    std::vector<std::string> names;
    DIR *dir = opendir(path.c_str());
    if (dir == NULL) {
        return names;
    }
    struct dirent *ent;
    while ((ent = readdir(dir)) != NULL) {
        if (ent->d_name[0] == '.') {
            continue;
        }
        names.push_back(ent->d_name);
    }
    closedir(dir);
    std::sort(names.begin(), names.end(), [](const std::string &a, const std::string &b) { return strverscmp(a.c_str(), b.c_str()) < 0; });
    return names;
}

static uint8_t eth_assign_port_id(const std::string &iface)
{
    static std::mutex mtx;
    static std::map<std::string, uint8_t> iface_to_id;
    std::lock_guard<std::mutex> lock(mtx);

    auto it = iface_to_id.find(iface);
    if (it != iface_to_id.end()) {
        return it->second;
    }
    uint8_t id = static_cast<uint8_t> (iface_to_id.size() + 1);
    iface_to_id[iface] = id;
    return id;
}

/* Port map from the "EthernetPorts" array in EM_PLUS_FILE: [{"ifname": "lan1", "id": 1}, ...] */
static std::vector<em_eth_port_cfg_t> eth_load_port_map()
{
    std::vector<em_eth_port_cfg_t> map;
    FILE *fp = fopen(EM_PLUS_FILE, "r");
    if (fp == NULL) {
        return map;
    }
    std::string content;
    char chunk[512];
    size_t n;
    while ((n = fread(chunk, 1, sizeof(chunk), fp)) > 0) {
        content.append(chunk, n);
    }
    fclose(fp);

    cJSON *root = cJSON_Parse(content.c_str());
    if (root == NULL) {
        return map;
    }
    cJSON *ports = cJSON_GetObjectItem(root, "EthernetPorts");
    cJSON *entry;
    cJSON_ArrayForEach(entry, ports) {
        cJSON *ifname = cJSON_GetObjectItem(entry, "ifname");
        cJSON *id = cJSON_GetObjectItem(entry, "id");
        if (!cJSON_IsString(ifname) || !cJSON_IsNumber(id) || (id->valueint < 1) || (id->valueint > 255)) {
            em_printfout("Ignoring invalid EthernetPorts entry");
            continue;
        }
        map.push_back(em_eth_port_cfg_t(ifname->valuestring, static_cast<uint8_t> (id->valueint)));
    }
    cJSON_Delete(root);
    return map;
}

/* Hardware-backed, non-wireless members of any bridge on the device; IDs are assigned sequentially */
static std::vector<em_eth_port_cfg_t> eth_discover_ports()
{
    std::vector<em_eth_port_cfg_t> ports;
    std::vector<std::string> lan;

    for (const auto &br : list_dir("/sys/class/net")) {
        if (access(("/sys/class/net/" + br + "/bridge").c_str(), F_OK) != 0) {
            continue;
        }
        for (const auto &iface : list_dir("/sys/class/net/" + br + "/brif")) {
            if (eth_iface_is_wlan(iface) || !eth_iface_is_wired_hw(iface)) {
                continue;
            }
            if (std::find(lan.begin(), lan.end(), iface) == lan.end()) {
                lan.push_back(iface);
            }
        }
    }
    for (const auto &iface : lan) {
        ports.push_back(em_eth_port_cfg_t(iface, eth_assign_port_id(iface)));
    }
    return ports;
}

std::vector<em_eth_port_cfg_t> em_eth_get_ports()
{
    static std::once_flag once;
    static std::vector<em_eth_port_cfg_t> port_map;
    std::call_once(once, []() {
        port_map = eth_load_port_map();
        if (port_map.empty()) {
            em_printfout("No EthernetPorts in " EM_PLUS_FILE ", falling back to port discovery; port IDs may not match the housing");
        }
    });

    if (port_map.empty()) {
        return eth_discover_ports();
    }

    std::vector<em_eth_port_cfg_t> ports;
    for (const auto &p : port_map) {
        if (access(("/sys/class/net/" + p.first).c_str(), F_OK) == 0) {
            ports.push_back(p);
        }
    }
    return ports;
}

bool em_eth_get_stats(const std::string &iface, em_eth_stats_t &st)
{
    FILE *fp = fopen("/proc/net/dev", "r");
    if (fp == NULL) {
        return false;
    }
    char line[512];
    bool found = false;
    while (fgets(line, sizeof(line), fp) != NULL) {
        char *colon = strchr(line, ':');
        if (colon == NULL) {
            continue;
        }
        char *name = line;
        while (*name == ' ') {
            name++;
        }
        *colon = '\0';
        if (iface != name) {
            continue;
        }
        unsigned long long rx_bytes, rx_pkts, rx_errs, rx_drop, rx_fifo, rx_frame, rx_comp, rx_mcast;
        unsigned long long tx_bytes, tx_pkts, tx_errs;
        if (sscanf(colon + 1, "%llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu",
                &rx_bytes, &rx_pkts, &rx_errs, &rx_drop, &rx_fifo, &rx_frame, &rx_comp, &rx_mcast,
                &tx_bytes, &tx_pkts, &tx_errs) == 11) {
            /* Byte counters are reported in KiB */
            st.bytes_sent = tx_bytes / 1024;
            st.bytes_recv = rx_bytes / 1024;
            st.packets_sent = tx_pkts;
            st.packets_recv = rx_pkts;
            st.tx_errors = tx_errs;
            st.rx_errors = rx_errs;
            st.mcast_packets_recv = rx_mcast;
            found = true;
        }
        break;
    }
    fclose(fp);
    return found;
}


static const unsigned int g_link_type_mbps[EM_ETH_LINK_TYPE_MAX + 1] = {0, 10, 100, 1000, 2500, 5000, 10000};

unsigned int em_eth_link_type_to_mbps(uint8_t link_type)
{
    return (link_type <= EM_ETH_LINK_TYPE_MAX) ? g_link_type_mbps[link_type] : 0;
}

static uint8_t eth_mbps_to_link_type(uint32_t mbps)
{
    for (uint8_t t = 1; t <= EM_ETH_LINK_TYPE_MAX; t++) {
        if (g_link_type_mbps[t] == mbps) {
            return t;
        }
    }
    return 0;
}

static bool eth_mask_bit(const uint32_t *mask, unsigned int bit)
{
    return (mask[bit / 32] & (1u << (bit % 32))) != 0;
}

/* Highest speed in Mbit/s among the supported link modes */
static uint32_t eth_max_speed_from_modes(const uint32_t *mask)
{
    static const struct {
        unsigned int bit;
        uint32_t mbps;
    } modes[] = {
        {ETHTOOL_LINK_MODE_10000baseT_Full_BIT, 10000}, {ETHTOOL_LINK_MODE_10000baseKX4_Full_BIT, 10000},
        {ETHTOOL_LINK_MODE_10000baseKR_Full_BIT, 10000}, {ETHTOOL_LINK_MODE_10000baseR_FEC_BIT, 10000},
        {ETHTOOL_LINK_MODE_10000baseCR_Full_BIT, 10000}, {ETHTOOL_LINK_MODE_10000baseSR_Full_BIT, 10000},
        {ETHTOOL_LINK_MODE_10000baseLR_Full_BIT, 10000}, {ETHTOOL_LINK_MODE_10000baseLRM_Full_BIT, 10000},
        {ETHTOOL_LINK_MODE_10000baseER_Full_BIT, 10000}, {ETHTOOL_LINK_MODE_5000baseT_Full_BIT, 5000},
        {ETHTOOL_LINK_MODE_2500baseT_Full_BIT, 2500}, {ETHTOOL_LINK_MODE_2500baseX_Full_BIT, 2500},
        {ETHTOOL_LINK_MODE_1000baseT_Full_BIT, 1000}, {ETHTOOL_LINK_MODE_1000baseT_Half_BIT, 1000},
        {ETHTOOL_LINK_MODE_1000baseX_Full_BIT, 1000},
        {ETHTOOL_LINK_MODE_1000baseKX_Full_BIT, 1000}, {ETHTOOL_LINK_MODE_100baseT_Full_BIT, 100},
        {ETHTOOL_LINK_MODE_100baseT_Half_BIT, 100}, {ETHTOOL_LINK_MODE_10baseT_Full_BIT, 10},
        {ETHTOOL_LINK_MODE_10baseT_Half_BIT, 10},
    };
    uint32_t max = 0;
    for (const auto &m : modes) {
        if (eth_mask_bit(mask, m.bit) && (m.mbps > max)) {
            max = m.mbps;
        }
    }
    return max;
}

/* Current speed, duplex and the maximum supported speed through ETHTOOL_GLINKSETTINGS */
static bool eth_get_link_settings(const std::string &iface, uint32_t &speed, bool &full_duplex, uint32_t &max_speed)
{
    const int nwords = 32; /* ETHTOOL_LINK_MODE_MASK_MAX_KERNEL_NU32 */
    std::vector<uint32_t> storage((sizeof(struct ethtool_link_settings) / sizeof(uint32_t)) + 1 + 3 * nwords, 0);
    struct ethtool_link_settings *req = reinterpret_cast<struct ethtool_link_settings *> (storage.data());
    struct ifreq ifr;
    bool ok = false;

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        return false;
    }

    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", iface.c_str());
    ifr.ifr_data = reinterpret_cast<char *> (req);

    /* The kernel answers with a negative nwords the first time to report the real size */
    req->cmd = ETHTOOL_GLINKSETTINGS;
    req->link_mode_masks_nwords = nwords;
    for (int attempt = 0; attempt < 2; attempt++) {
        if (ioctl(sock, SIOCETHTOOL, &ifr) < 0) {
            break;
        }
        if (req->link_mode_masks_nwords < 0) {
            req->link_mode_masks_nwords = -req->link_mode_masks_nwords;
            if (req->link_mode_masks_nwords > nwords) {
                break;
            }
            continue;
        }
        if (req->link_mode_masks_nwords > 0) {
            speed = (req->speed == static_cast<uint32_t> (SPEED_UNKNOWN)) ? 0 : req->speed;
            full_duplex = (req->duplex == DUPLEX_FULL);
            max_speed = eth_max_speed_from_modes(req->link_mode_masks);
            ok = true;
        }
        break;
    }
    close(sock);
    return ok;
}

bool em_eth_get_info(const std::string &iface, em_eth_port_t &port)
{
    std::string path = "/sys/class/net/" + iface + "/address";
    FILE *fp = fopen(path.c_str(), "r");
    unsigned int m[6];
    bool mac_ok = false;
    if (fp != NULL) {
        char line[64] = {0};
        if (fgets(line, sizeof(line), fp) != NULL) {
            mac_ok = (sscanf(line, "%x:%x:%x:%x:%x:%x", &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]) == 6);
        }
        fclose(fp);
    }
    if (!mac_ok) {
        return false;
    }
    for (int i = 0; i < 6; i++) {
        port.mac[i] = static_cast<unsigned char> (m[i]);
    }
    snprintf(port.name, sizeof(port.name), "%s", iface.c_str());

    int flags = 0;
    path = "/sys/class/net/" + iface + "/flags";
    fp = fopen(path.c_str(), "r");
    if (fp != NULL) {
        if (fscanf(fp, "%i", &flags) != 1) {
            flags = 0;
        }
        fclose(fp);
    }
    port.admin_up = (flags & IFF_UP) ? 1 : 0;
    /* sysfs flags do not carry IFF_RUNNING; carrier is only readable while the port is admin up */
    int carrier = 0;
    port.link_up = (port.admin_up && eth_iface_read_int(iface, "carrier", carrier) && (carrier == 1)) ? 1 : 0;

    uint32_t speed = 0, max_speed = 0;
    bool full_duplex = false;
    if (eth_get_link_settings(iface, speed, full_duplex, max_speed)) {
        port.full_duplex = full_duplex ? 1 : 0;
        port.max_link_type = eth_mbps_to_link_type(max_speed);
        port.cur_link_type = port.link_up ? eth_mbps_to_link_type(speed) : 0;
    } else {
        em_printfout("Failed to get link settings for %s", iface.c_str());
        port.full_duplex = 0;
        port.max_link_type = 0;
        port.cur_link_type = 0;
    }
    return true;
}
