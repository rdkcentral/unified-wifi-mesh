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
#include <array>
#include <chrono>
#include <map>
#include <set>
#include <thread>
#include <poll.h>
#include <netpacket/packet.h>
#include <arpa/inet.h>
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

static std::string eth_iface_read_str(const std::string &iface, const char *attr)
{
    std::string path = "/sys/class/net/" + iface + "/" + attr;
    FILE *fp = fopen(path.c_str(), "r");
    if (fp == NULL) {
        return "";
    }
    char line[64] = {0};
    if (fgets(line, sizeof(line), fp) == NULL) {
        line[0] = '\0';
    }
    fclose(fp);
    line[strcspn(line, "\n")] = '\0';
    return line;
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

bool em_eth_link_changed()
{
    static std::map<uint8_t, std::string> last;
    static bool initialized = false;
    std::map<uint8_t, std::string> cur;

    for (const auto &p : em_eth_get_ports()) {
        const std::string &ifname = p.first;
        unsigned long flags = strtoul(eth_iface_read_str(ifname, "flags").c_str(), NULL, 0);
        bool admin_up = (flags & IFF_UP) != 0;
        /* carrier, speed and duplex are only readable while the port is admin up */
        std::string state = std::string(admin_up ? "1" : "0") + "/" + (admin_up ? eth_iface_read_str(ifname, "carrier") : "") +
            "/" + (admin_up ? eth_iface_read_str(ifname, "speed") : "") + "/" + (admin_up ? eth_iface_read_str(ifname, "duplex") : "");
        cur[p.second] = state;
    }

    bool changed = initialized && (cur != last);
    last = cur;
    initialized = true;
    return changed;
}

typedef std::array<uint8_t, 6> eth_mac_t;
typedef std::chrono::steady_clock eth_clock;

#define ETH_P_LLDP_FRAME 0x88CC
#define ETH_P_1905_FRAME 0x893A
/* LLDP is sent every 10s by the 1905 stack, topology discovery every 60s */
#define EM_ETH_LLDP_TIMEOUT_SEC 35
#define EM_ETH_DISC_TIMEOUT_SEC 190

static std::mutex g_nb_mtx;
static std::map<std::string, std::map<eth_mac_t, eth_clock::time_point> > g_lldp; /* port -> chassis (AL MAC) */
static std::map<eth_mac_t, eth_clock::time_point> g_disc;     /* AL MAC from topology discovery */
static std::map<eth_mac_t, eth_clock::time_point> g_peer_src; /* source MACs of 1905 frames */

static bool eth_fresh(const eth_clock::time_point &seen, int timeout_sec)
{
    return (eth_clock::now() - seen) <= std::chrono::seconds(timeout_sec);
}

/* Chassis ID TLV of an LLDPDU, MAC address subtype only */
static bool eth_parse_lldp_chassis(const unsigned char *pdu, size_t len, eth_mac_t &chassis)
{
    while (len >= 2) {
        unsigned int hdr = (pdu[0] << 8) | pdu[1];
        unsigned int type = hdr >> 9, tlen = hdr & 0x1ff;
        if ((type == 0) || (len < (2 + tlen))) {
            return false;
        }
        if (type == 1) {
            if ((tlen != 7) || (pdu[2] != 4)) {
                return false;
            }
            memcpy(chassis.data(), pdu + 3, chassis.size());
            return true;
        }
        pdu += 2 + tlen;
        len -= 2 + tlen;
    }
    return false;
}

/* AL MAC Address TLV of a Topology Discovery CMDU; 1905 header: version, reserved, type, id, fragment, flags */
static bool eth_parse_discovery_al_mac(const unsigned char *cmdu, size_t len, eth_mac_t &al_mac)
{
    if ((len < 8) || (cmdu[2] != 0) || (cmdu[3] != 0)) {
        return false;
    }
    cmdu += 8;
    len -= 8;
    while (len >= 3) {
        unsigned int tlen = (cmdu[1] << 8) | cmdu[2];
        if ((cmdu[0] == 0) || (len < (3 + tlen))) {
            return false;
        }
        if ((cmdu[0] == 0x01) && (tlen == 6)) {
            memcpy(al_mac.data(), cmdu + 3, al_mac.size());
            return true;
        }
        cmdu += 3 + tlen;
        len -= 3 + tlen;
    }
    return false;
}

static void eth_handle_frame(const unsigned char *frame, size_t len, const std::string &ifname)
{
    if (len < 14) {
        return;
    }
    eth_mac_t src, al;
    memcpy(src.data(), frame + 6, src.size());
    unsigned int type = (frame[12] << 8) | frame[13];
    const unsigned char *payload = frame + 14;
    size_t plen = len - 14;
    eth_clock::time_point now = eth_clock::now();

    if (type == ETH_P_LLDP_FRAME) {
        if (eth_parse_lldp_chassis(payload, plen, al)) {
            std::lock_guard<std::mutex> lock(g_nb_mtx);
            g_lldp[ifname][al] = now;
        }
    } else if (type == ETH_P_1905_FRAME) {
        if (eth_parse_discovery_al_mac(payload, plen, al)) {
            std::lock_guard<std::mutex> lock(g_nb_mtx);
            g_disc[al] = now;
            g_peer_src[src] = now;
        }
    }
}

static void eth_listener()
{
    const int protos[2] = {ETH_P_LLDP_FRAME, ETH_P_1905_FRAME};
    struct pollfd fds[2];
    unsigned char buf[2048];

    for (int i = 0; i < 2; i++) {
        fds[i].fd = socket(AF_PACKET, SOCK_RAW, htons(protos[i]));
        fds[i].events = POLLIN;
        if (fds[i].fd < 0) {
            em_printfout("Failed to open packet socket for ethertype 0x%04x: %s", protos[i], strerror(errno));
            for (int j = 0; j < i; j++) {
                close(fds[j].fd);
            }
            return;
        }
    }

    while (true) {
        if (poll(fds, 2, -1) < 0) {
            if (errno == EINTR) {
                continue;
            }
            em_printfout("Ethernet neighbor listener poll failed: %s", strerror(errno));
            for (int j = 0; j < 2; j++) {
                close(fds[j].fd);
            }
            return;
        }
        for (int i = 0; i < 2; i++) {
            if (!(fds[i].revents & POLLIN)) {
                continue;
            }
            struct sockaddr_ll sll;
            socklen_t slen = sizeof(sll);
            ssize_t n = recvfrom(fds[i].fd, buf, sizeof(buf), 0, reinterpret_cast<struct sockaddr *> (&sll), &slen);
            char ifname[IF_NAMESIZE];
            if ((n <= 0) || (sll.sll_pkttype == PACKET_OUTGOING) || (if_indextoname(sll.sll_ifindex, ifname) == NULL)) {
                continue;
            }
            eth_handle_frame(buf, static_cast<size_t> (n), ifname);
        }
    }
}

static void eth_start_listener()
{
    static std::once_flag once;
    std::call_once(once, []() { std::thread(eth_listener).detach(); });
}

static std::string eth_iface_master(const std::string &iface)
{
    char target[PATH_MAX];
    ssize_t n = readlink(("/sys/class/net/" + iface + "/master").c_str(), target, sizeof(target) - 1);
    if (n <= 0) {
        return "";
    }
    target[n] = '\0';
    const char *base = strrchr(target, '/');
    return base ? base + 1 : target;
}

typedef struct {
    uint8_t mac[6];
    uint8_t port_no;
    uint8_t is_local;
    uint32_t ageing_timer;
    uint8_t port_hi;
    uint8_t pad1;
    uint16_t pad2;
} __attribute__((__packed__)) eth_fdb_entry_t;

/* Non-local MACs the bridge learned on the given port */
static std::vector<eth_mac_t> eth_read_fdb(const std::string &iface)
{
    std::vector<eth_mac_t> macs;
    std::string bridge = eth_iface_master(iface);
    if (bridge.empty()) {
        return macs;
    }
    unsigned long port_no = strtoul(eth_iface_read_str(bridge + "/brif/" + iface, "port_no").c_str(), NULL, 0);
    FILE *fp = fopen(("/sys/class/net/" + bridge + "/brforward").c_str(), "r");
    if (fp == NULL) {
        return macs;
    }
    eth_fdb_entry_t e;
    while (fread(&e, sizeof(e), 1, fp) == 1) {
        if (!e.is_local && (static_cast<unsigned long> (e.port_no | (e.port_hi << 8)) == port_no) && !(e.mac[0] & 1)) {
            eth_mac_t mac;
            memcpy(mac.data(), e.mac, mac.size());
            macs.push_back(mac);
        }
    }
    fclose(fp);
    std::sort(macs.begin(), macs.end());
    macs.erase(std::unique(macs.begin(), macs.end()), macs.end());
    return macs;
}

std::vector<em_eth_port_neigh_t> em_eth_get_neighbors()
{
    std::vector<em_eth_port_neigh_t> result;
    std::map<std::string, std::set<eth_mac_t> > lldp;
    std::set<eth_mac_t> disc, known_1905;

    eth_start_listener();
    {
        std::lock_guard<std::mutex> lock(g_nb_mtx);
        /* Drop stale entries so the tables do not grow forever */
        for (auto it = g_disc.begin(); it != g_disc.end();) {
            if (eth_fresh(it->second, EM_ETH_DISC_TIMEOUT_SEC)) {
                disc.insert(it->first);
                known_1905.insert(it->first);
                ++it;
            } else {
                it = g_disc.erase(it);
            }
        }
        for (auto it = g_peer_src.begin(); it != g_peer_src.end();) {
            if (eth_fresh(it->second, EM_ETH_DISC_TIMEOUT_SEC)) {
                known_1905.insert(it->first);
                ++it;
            } else {
                it = g_peer_src.erase(it);
            }
        }
        for (auto pit = g_lldp.begin(); pit != g_lldp.end();) {
            for (auto it = pit->second.begin(); it != pit->second.end();) {
                if (eth_fresh(it->second, EM_ETH_LLDP_TIMEOUT_SEC)) {
                    lldp[pit->first].insert(it->first);
                    if (disc.count(it->first) != 0) {
                        known_1905.insert(it->first);
                    }
                    ++it;
                } else {
                    it = pit->second.erase(it);
                }
            }
            pit = pit->second.empty() ? g_lldp.erase(pit) : std::next(pit);
        }
    }

    for (const auto &cfg : em_eth_get_ports()) {
        int carrier = 0;
        if (!eth_iface_read_int(cfg.first, "carrier", carrier) || (carrier != 1)) {
            std::lock_guard<std::mutex> lock(g_nb_mtx);
            g_lldp.erase(cfg.first);
            continue;
        }

        em_eth_port_neigh_t n;
        memset(&n, 0, sizeof(n));
        n.port_id = cfg.second;

        /* LLDP is never forwarded by a bridge, so a chassis heard here is directly connected */
        bool full_1905 = false, full_non1905 = false;
        for (const auto &al : lldp[cfg.first]) {
            if (disc.count(al) == 0) {
                continue;
            }
            if (n.num_1905 < EM_MAX_ETH_1905_NEIGH) {
                memcpy(n.neigh_1905[n.num_1905++], al.data(), al.size());
            } else {
                full_1905 = true;
            }
        }
        /* Everything learned behind a 1905 neighbor is reported by that neighbor itself */
        if (n.num_1905 == 0) {
            for (const auto &mac : eth_read_fdb(cfg.first)) {
                if (known_1905.count(mac) != 0) {
                    continue;
                }
                if (n.num_non1905 < EM_MAX_ETH_NON1905_NEIGH) {
                    memcpy(n.neigh_non1905[n.num_non1905++], mac.data(), mac.size());
                } else {
                    full_non1905 = true;
                }
            }
        }
        if (full_1905) {
            em_printfout("Too many 1905 neighbors on port %s, dropping the excess", cfg.first.c_str());
        }
        if (full_non1905) {
            em_printfout("Too many non-1905 neighbors on port %s, dropping the excess", cfg.first.c_str());
        }
        if ((n.num_1905 + n.num_non1905) > 0) {
            result.push_back(n);
        }
    }
    return result;
}

bool em_eth_neighbors_changed()
{
    static std::string last;
    static bool initialized = false;
    std::string cur;

    for (const auto &n : em_eth_get_neighbors()) {
        cur += std::to_string(n.port_id) + ":";
        cur.append(reinterpret_cast<const char *> (n.neigh_1905), n.num_1905 * sizeof(mac_address_t));
        cur += "/";
        cur.append(reinterpret_cast<const char *> (n.neigh_non1905), n.num_non1905 * sizeof(mac_address_t));
        cur += ";";
    }

    bool changed = initialized && (cur != last);
    last = cur;
    initialized = true;
    return changed;
}
