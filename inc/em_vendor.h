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

class em_vendor_t {

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

    // Generic dispatch point — pure virtual so em_t owns the routing logic
    // and can forward to em_metrics_t, em_steering_t, etc. as needed.
    // For unrecognised attr_ids, em_t falls back to handle_vendor_tlv_ext().
    virtual int dispatch_vendor_attr(vendor_ext_attr_id_t attr_id,
                                     unsigned char        *buff,
                                     unsigned int          len) = 0;

    // Weak hook for unrecognised attr_ids — overridden by private repo
    // to parse vendor STA private TLVs and populate dm_sta_ext_t.
    int handle_vendor_tlv_ext(const unsigned char *tlv_value,
                               unsigned int         tlv_len,
                               dm_easy_mesh_t      *dm);

    // Send: packages m_raw_data from the current cmd as a vendor TLV CMDU.
    int send_vendor_sta_lq_data();

    em_vendor_t();
    virtual ~em_vendor_t();
};

#endif // EM_VENDOR_H
