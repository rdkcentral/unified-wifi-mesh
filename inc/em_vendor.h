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


/**
 * Abstract interface for private vendor extensions.
 */
class em_vendor_ext_interface_t {
public:
    virtual ~em_vendor_ext_interface_t() = default;

    virtual int handle_vendor_tlv_ext(const unsigned char *tlv_value,
                                       unsigned int         tlv_len,
                                       dm_easy_mesh_t      *dm) = 0;

};

em_vendor_ext_interface_t* create_em_vendor_ext();

class em_vendor_t {
private:
    em_vendor_ext_interface_t *m_vendor_ext;
public:
    virtual dm_easy_mesh_t  *get_data_model() = 0;
    virtual em_state_t       get_state() = 0;
    virtual void             set_state(em_state_t state) = 0;
    virtual int              send_frame(unsigned char *buff, unsigned int len, bool multicast = false) = 0;
    virtual em_mgr_t        *get_mgr() = 0;
    virtual em_cmd_t        *get_current_cmd() = 0;
    virtual em_profile_type_t get_profile_type() = 0;

    unsigned int get_vendor_id(unsigned char *buff);
    // Dispatches to the appropriate handler based on the TLV's attr_id.
    int handle_vendor_msg(unsigned char *buff, unsigned int len);

    // Weak hook for unrecognised attr_ids — overridden by private repo
    // to parse vendor STA private TLVs and populate dm_sta_ext_t.
    virtual int handle_vendor_tlv_ext(const unsigned char *tlv_value,
                               unsigned int         tlv_len,
                               dm_easy_mesh_t      *dm);

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
    // int send_vendor_sta_lq_data();

    int send_vendor_msg();

    // Helper getter for the extension pointer
    em_vendor_ext_interface_t* get_ext() const { return m_vendor_ext; }

    em_vendor_t();
    virtual ~em_vendor_t();
};

#endif // EM_VENDOR_H
