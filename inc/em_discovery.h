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

#ifndef EM_DISCOVERY_H
#define EM_DISCOVERY_H

#include "em_base.h"

class em_cmd_t;
class em_discovery_t {

    unsigned int create_topo_discovery_msg(unsigned char *buff);
    unsigned int create_topo_query_msg(unsigned char *buff);
    unsigned int create_topo_rsp_msg(unsigned char *buff);

    int analyze_topo_disc_msg(unsigned char *buff, unsigned int len);
    int analyze_topo_query_msg(unsigned char *buff, unsigned int len);
    int analyze_topo_resp_msg(unsigned char *buff, unsigned int len);
    
    virtual em_state_t get_state() = 0;
    virtual unsigned char   *get_radio_interface_mac() = 0;
    virtual unsigned char *get_al_interface_mac() = 0;

    virtual int send_frame(unsigned char *buff, unsigned int len, bool multicast = false) = 0;
    virtual em_cmd_t *get_current_cmd() = 0;
    
public:
    void    process_msg(unsigned char *data, unsigned int len);
    void    process_state();

    em_discovery_t();
    ~em_discovery_t();

};

#endif
