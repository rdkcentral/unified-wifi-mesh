/**
 * Copyright 2025 Comcast Cable Communications Management, LLC
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

#pragma once

#include "em_base.h"
#include "ec_crypto.h"

#include <functional>

struct cJSON;


/**
 * @brief Sends a chirp notification
 * 
 * @param chirp_tlv The chirp TLV to send
 * @param len The length of the chirp TLV
 * @return bool true if successful, false otherwise
 */
using send_chirp_func = std::function<bool(em_dpp_chirp_value_t*, size_t)>;

/**
 * @brief Sends a proxied encapsulated DPP message
 * 
 * @param encap_dpp_tlv The 1905 Encap DPP TLV to include in the message
 * @param encap_dpp_len The length of the 1905 Encap DPP TLV
 * @param chirp_tlv The chirp value to include in the message. If NULL, the message will not include a chirp value
 * @param chirp_len The length of the chirp value
 * @return bool true if successful, false otherwise
 */
using send_encap_dpp_func = std::function<bool(em_encap_dpp_t*, size_t, em_dpp_chirp_value_t*, size_t)>;


/**
 * @brief Sends a direct encapsulated DPP message
 * 
 * @param dpp_frame The DPP frame to send
 * @param dpp_frame_len The length of the DPP frame
 * @return bool true if successful, false otherwise
 */
using send_dir_encap_dpp_func = std::function<bool(uint8_t*, size_t, uint8_t*)>;

/**
 * @brief Send an action frame. Optional to implement.
 * 
 * @param dest_mac The destination MAC address
 * @param action_frame The action frame to send
 * @param action_frame_len The length of the action frame
 * @param frequency The frequency to send the frame on (0 for current frequency)
 * @param wait The time to wait on the channel after sending the frame (0 for no wait)
 * @return true if successful, false otherwise
 */
using send_act_frame_func = std::function<bool(uint8_t*, uint8_t *, size_t, unsigned int, unsigned int)>;

/**
 * @brief Set the CCE IEs in the beacon and probe response frames
 * 
 * @param bool Whether to enable or disable the inclusion of CCE IEs in the beacon and probe response frames
 * @return bool true if successful, false otherwise
 * @note If the operation fails, all CCE IEs are removed before the function exits
 */
using toggle_cce_func = std::function<bool(bool)>;

/**
 * @brief Triggers a scan on a station interface
 * 
 * @return bool true if a request was made successfully, false otherwise
 */
using trigger_sta_scan_func = std::function<bool()>;


/**
 * @brief Attempts a connection between the backhaul STA to the specified BSS.
 * 
 * @param ssid The SSID of the BSS to connect to
 * @param passphrase The passphrase for the BSS
 * @param bssid The BSSID of the BSS to connect to
 * @return bool true if the attempt was performed successfully, false otherwise
 */
using bsta_connect_func = std::function<bool(const std::string&, const std::string&, bssid_t)>;

/**
 * @brief Creates a DPP Configuration Response object for the backhaul STA interface.
 * @param conn_ctx Optional connection context (not needed for Enrollee, needed for Configurator) -- pass nullptr if not needed.
 * @return cJSON * on success, nullptr otherwise
 */
using get_backhaul_sta_info_func = std::function<cJSON*(ec_connection_context_t *)>;

/**
 * @brief Creates a DPP Configuration Response object for the 1905.1 interface.
 * @return cJSON * on success, nullptr otherwise.
 */
using get_1905_info_func = std::function<cJSON*(ec_connection_context_t *)>;

/**
 * @brief Creates a DPP Configuration Response object for the fronthaul BSS interface(s)
 * @return cJSON * on success, nullptr otherwise
 */
using get_fbss_info_func = std::function<cJSON*(ec_connection_context_t *)>;

/**
 * @brief Used to determine if an additional AP can be on-boarded or not.
 * @return True if additional APs can be on-boraded into the mesh, false otherwise.
 */
using can_onboard_additional_aps_func = std::function<bool(void)>;

/**
 * @brief Callback configuration structure for EasyConnect (EC) logic
 * 
 * This struct aggregates a set of optional functional callbacks used by the EasyConnect manager
 * to interact with underlying platform or control-plane behavior. Each callback is expected to be 
 * bound by the entity (e.g., `em_t`) instantiating an `ec_manager_t`, depending on its service role 
 * (controller/configurator, agent/proxy agent, agent/enrollee).
 * 
 * All fields default to `nullptr`
 */
struct ec_ops_t {
    send_chirp_func send_chirp = nullptr;
    send_encap_dpp_func send_encap_dpp = nullptr;
    send_dir_encap_dpp_func send_dir_encap_dpp = nullptr;
    send_act_frame_func send_act_frame = nullptr;
    toggle_cce_func toggle_cce = nullptr;
    trigger_sta_scan_func trigger_sta_scan = nullptr;
    bsta_connect_func bsta_connect = nullptr;
    get_backhaul_sta_info_func get_backhaul_sta_info = nullptr;
    get_1905_info_func get_1905_info = nullptr;
    get_fbss_info_func get_fbss_info = nullptr;
    can_onboard_additional_aps_func can_onboard_additional_aps = nullptr;
};