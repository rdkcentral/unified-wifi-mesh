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

#ifndef EM_STEERING_H
#define EM_STEERING_H

#include "em_base.h"

class em_steering_t {

    unsigned int m_client_steering_req_tx_cnt;
    unsigned int m_client_assoc_ctrl_req_tx_cnt;

    int send_client_steering_req_msg();
    int send_client_assoc_ctrl_req_msg();
    int send_client_assoc_ctrl_req_msg(em_client_assoc_ctrl_req_t *assoc_ctrl);
    int send_btm_report_msg(mac_address_t sta, bssid_t bss);
    int send_1905_ack_message(mac_addr_t sta_mac);
    int handle_client_steering_req(unsigned char *buff, unsigned int len);
    int handle_client_steering_report(unsigned char *buff, unsigned int len);
    short create_error_code_tlv(unsigned char *buff, int val, mac_addr_t sta_mac);
    short create_btm_report_tlv(unsigned char *buff);
    short create_btm_request_tlv(unsigned char *buff);

public:
    virtual int send_frame(unsigned char *buff, unsigned int len, bool multicast = false) = 0;
    virtual dm_easy_mesh_t *get_data_model() = 0;
    virtual unsigned char *get_radio_interface_mac() = 0;
    virtual em_state_t get_state() = 0;
    virtual void set_state(em_state_t state) = 0;
    virtual em_cmd_t *get_current_cmd() = 0;

public:

    int get_client_steering_req_tx_count() { return m_client_steering_req_tx_cnt; }
    void set_client_steering_req_tx_count(unsigned int cnt) { m_client_steering_req_tx_cnt = cnt; }
    int get_client_assoc_ctrl_req_tx_count() { return m_client_assoc_ctrl_req_tx_cnt; }
    void set_client_assoc_ctrl_req_tx_count(unsigned int cnt) { m_client_assoc_ctrl_req_tx_cnt = cnt; }

    void    process_msg(unsigned char *data, unsigned int len);
    void    process_agent_state();
    void    process_ctrl_state();

    em_steering_t();
    ~em_steering_t();

};

#endif
