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

#ifndef EM_PROVISIONING_H
#define EM_PROVISIONING_H

#include "em_base.h"
#include "ec_session.h"
#include <memory>

class em_cmd_t;
class em_provisioning_t {

    int create_cce_ind_msg(uint8_t *buff);
    int create_cce_ind_cmd(uint8_t *buff);
    
    int create_bss_config_req_msg(uint8_t *buff);
    int create_bss_config_rsp_msg(uint8_t *buff);
    int create_bss_config_res_msg(uint8_t *buff);
    int create_dpp_direct_encap_msg(uint8_t *buff, uint8_t *frame, uint16_t len);

    int handle_cce_ind_msg(uint8_t *buff, unsigned int len);
    int handle_dpp_chirp_notif(uint8_t *buff, unsigned int len);
    int handle_proxy_encap_dpp(uint8_t *buff, unsigned int len);

    int send_chirp_notif_msg(em_dpp_chirp_value_t *chirp, size_t chirp_len);
    int send_prox_encap_dpp_msg(em_encap_dpp_t* encap_dpp_tlv, size_t encap_dpp_len, em_dpp_chirp_value_t *chirp, size_t chirp_len);
    // states
    void handle_state_prov_none();
    void handle_state_prov();
    void handle_state_auth_req_pending();
    void handle_state_auth_rsp_pending();
    void handle_state_auth_cnf_pending();
    void handle_state_config_req_pending();
    void handle_state_config_rsp_pending();
    void handle_state_config_res_pending();

    virtual em_service_type_t   get_service_type() = 0;
    virtual em_state_t get_state() = 0;
    virtual void set_state(em_state_t state) = 0;
    virtual char *get_radio_interface_name() = 0;
    virtual uint8_t *get_peer_mac() = 0;
    virtual uint8_t *get_al_interface_mac() = 0;
    virtual uint8_t *get_radio_interface_mac() = 0;
    virtual int send_frame(uint8_t *buff, unsigned int len, bool multicast = false) = 0;
    virtual int send_cmd(em_cmd_type_t type, em_service_type_t svc, uint8_t *buff, unsigned int len) = 0;
    virtual em_cmd_t *get_current_cmd() = 0;

public:
    void    process_msg(uint8_t *data, unsigned int len);
    void    process_agent_state();
    void    process_ctrl_state();

    std::unique_ptr<ec_session_t> m_ec_session;

    em_provisioning_t();
    ~em_provisioning_t();

};

#endif
