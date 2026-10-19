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

#ifndef EM_ETH_H
#define EM_ETH_H

#include <string>
#include <utility>
#include <vector>
#include "em_base.h"

/* Airties Ethernet link types: 0=undefined, 1=10M, 2=100M, 3=1G, 4=2.5G, 5=5G, 6=10G */
#define EM_ETH_LINK_TYPE_MAX 6

typedef std::pair<std::string, uint8_t> em_eth_port_cfg_t;

/**!
 * @brief Returns the Ethernet ports (interface name, port ID) of this device.
 *
 * Ports come from the "EthernetPorts" array in EM_PLUS_FILE. If it is absent, the hardware
 * backed, non-wireless members of the bridges are used and IDs are assigned sequentially.
 */
std::vector<em_eth_port_cfg_t> em_eth_get_ports();

/**!
 * @brief Fills the traffic counters of a port; byte counters are reported in KiB.
 *
 * @returns true on success, false if the interface is not found in /proc/net/dev.
 */
bool em_eth_get_stats(const std::string &ifname, em_eth_stats_t &stats);

/**!
 * @brief Fills MAC, name, admin/link state, duplex and link types of a port.
 *
 * @returns true on success, false if the MAC address cannot be read.
 */
bool em_eth_get_info(const std::string &ifname, em_eth_port_t &port);

/**!
 * @brief Converts an Airties link type to Mbit/s (0 for undefined).
 */
unsigned int em_eth_link_type_to_mbps(uint8_t link_type);

#endif // EM_ETH_H
