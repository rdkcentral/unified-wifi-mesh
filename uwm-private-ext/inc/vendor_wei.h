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

#ifndef VENDOR_WEI_H
#define VENDOR_WEI_H

#include "em_vendor.h"
#include "lq_socket.h"

// WEI private vendor extension: builds the vendor-specific TLV payload on the
// agent (build_vendor_tlv_ext) and decodes it on the controller
// (handle_vendor_tlv_ext). Compiled into both the agent and controller
// binaries (like em_capability_t), so each side only exercises the half of
// this class relevant to its role.
class em_vendor_wei_t : public em_vendor_ext_interface_t {
public:
    int handle_vendor_tlv_ext(const unsigned char *tlv_value,
                               unsigned int         tlv_len,
                               dm_easy_mesh_t      *dm) override;

    int build_vendor_tlv_ext(const unsigned char *raw_data,
                              unsigned int         raw_len,
                              unsigned char       *tlv_value,
                              unsigned int        *tlv_val_len) override;

private:
    void publish_wei_app(uint32_t msg_type, stats_arg_t wei_data);
};

#endif // VENDOR_WEI_H
