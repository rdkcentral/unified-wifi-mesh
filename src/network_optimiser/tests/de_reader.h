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

#ifndef DE_READER_H
#define DE_READER_H

#include <unistd.h>
#include <fcntl.h>
#include <cjson/cJSON.h>
#include "em_base.h"
#include "de_network.h"
#include "de_service.h"
#include "de_device.h"
#include "de_radio.h"
#include "de_bss.h"
#include "de_sta.h"
#include "de_net_ssid.h"
#include "de_curr_op_class.h"
#include "de_cap.h"
#include "de_op_class.h"

class de_reader_t {
    
    cJSON *m_obj;
    struct stat m_info;
    em_long_string_t    m_name;

public:
    int init();
    void deinit();

    int reinit() { deinit(); return init(); }
    bool has_modified();

    cJSON *get_object_item(const char *fmt, ...);

    void update_network(de_network_t& net);

    unsigned int get_num_services();
    void update_service(de_service_t& svc, unsigned int pos);

    unsigned int get_num_devices();
    void update_device(de_device_t& dev, unsigned int pos);

    unsigned int get_num_radios(unsigned int pos);
    void update_radio(de_radio_t& radio, unsigned int dpos, unsigned int rpos);

    unsigned int get_num_bsss(unsigned int dpos, unsigned int rpos);
    void update_bss(de_bss_t& bss, unsigned int dpos, unsigned int rpos, unsigned int bpos);

    unsigned int get_num_curr_op_classes(unsigned int dpos, unsigned int rpos);
    void update_curr_op_class(de_curr_op_class_t& curr_op_class, unsigned int dpos, unsigned int rpos, unsigned int opos);

    void update_cap(de_cap_t& cap, unsigned int dpos, unsigned int rpos);

    unsigned int get_num_op_classes(unsigned int dpos, unsigned int rpos);
    void update_op_class(de_op_class_t& op_class, unsigned int dpos, unsigned int rpos, unsigned int opos);

    unsigned int get_num_stas(unsigned int dpos, unsigned int rpos, unsigned int bpos);
    void update_sta(de_sta_t& sta, unsigned int dpos, unsigned int rpos, unsigned int bpos, unsigned int spos);

    unsigned int get_num_net_ssids();
    void update_net_ssid(de_net_ssid_t& net_ssid, unsigned int pos);

    de_reader_t(const char *name);
    ~de_reader_t();
};

#endif
