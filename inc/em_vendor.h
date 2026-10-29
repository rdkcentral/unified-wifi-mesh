/**
 * Copyright 2026 Comcast Cable Communications Management, LLC
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

#ifndef EM_VENDOR_H
#define EM_VENDOR_H

#include <vector>
#include <cstdint>
#include "em_base.h"

class dm_easy_mesh_t;
class em_cmd_t;
class em_mgr_t;

// Largest vendor TLV value build_vendor_tlv_ext() may write; keeps the CMDU within a single unfragmented frame
#define EM_VENDOR_TLV_MAX_LEN MAX_EM_BUFF_SZ

class em_vendor_t {
public:
    virtual dm_easy_mesh_t  *get_data_model() = 0;
    virtual em_state_t       get_state() = 0;
    virtual void             set_state(em_state_t state) = 0;
    virtual int              send_frame(unsigned char *buff, unsigned int len, bool multicast = false) = 0;
    virtual em_mgr_t        *get_mgr() = 0;
    virtual em_cmd_t        *get_current_cmd() = 0;
    virtual em_profile_type_t get_profile_type() = 0;

    // Dispatches to the appropriate handler based on the TLV's attr_id.
    int handle_vendor_msg(unsigned char *buff, unsigned int len);

    // Forwards a received vendor-specific TLV to the vendor extension, if any.
    virtual int handle_vendor_tlv_ext(const unsigned char *tlv_value,
                               unsigned int         tlv_len,
                               dm_easy_mesh_t      *dm);

    // Asks the vendor extension to build the vendor TLV payload, if any.
    virtual int build_vendor_tlv_ext(const unsigned char *raw_data,
                               unsigned int         raw_len,
                               unsigned char       *tlv_value,
                               unsigned int        *tlv_val_len);

    /**!
     * @brief Processes the state of the agent.
     *
     * This function is responsible for handling the current state of the agent and performing necessary actions based on that state.
     *
     * @note This function does not take any parameters and does not return any value.
     */
    void process_agent_state();
    void process_agent_state(em_cmd_event_type_t type);

    // Send: packages m_raw_data from the current cmd as a vendor TLV CMDU.
    int send_vendor_msg();

    em_vendor_t() = default;
    virtual ~em_vendor_t() = default;
};

#endif // EM_VENDOR_H
