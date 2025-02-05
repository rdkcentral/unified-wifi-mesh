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

#ifndef EM_POLICY_CFG_H
#define EM_POLICY_CFG_H

#include "em_base.h"

class em_cmd_t;
class em_policy_cfg_t {

    virtual int send_frame(unsigned char *buff, unsigned int len, bool multicast = false) = 0;

public:
    virtual dm_easy_mesh_t *get_data_model() = 0;
    virtual unsigned char *get_radio_interface_mac() = 0;
    virtual em_state_t get_state() = 0;
    virtual void set_state(em_state_t state) = 0;
    virtual em_service_type_t get_service_type() = 0;
    virtual em_device_info_t *get_device_info() = 0;
    virtual em_cmd_t *get_current_cmd() = 0;

	short create_steering_policy_tlv(unsigned char *buff);
	short create_metrics_rep_policy_tlv(unsigned char *buff);
    short create_vendor_policy_cfg_tlv(unsigned char *buff);

    int send_policy_cfg_request_msg();

    int handle_policy_cfg_req(unsigned char *buff, unsigned int len);

    void    process_msg(unsigned char *data, unsigned int len);
    void    process_ctrl_state();
    void    process_state();

    em_policy_cfg_t();
    ~em_policy_cfg_t();

};

#endif
