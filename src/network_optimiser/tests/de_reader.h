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

    de_reader_t(const char *name);
    ~de_reader_t();
};

#endif
