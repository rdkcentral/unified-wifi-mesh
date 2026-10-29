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

#ifndef DE_NET_SSID_H
#define DE_NET_SSID_H

#include "em_base.h"

class de_net_ssid_t {

public:
    em_string_t m_key;
    em_string_t m_ssid;
    bool    m_enabled;
    em_string_t m_op;
    bool    m_advertisement;
    em_string_t m_mfp_config;
    em_string_t m_mob_domain;

public:
    int init(const char *key);
    void deinit();
    void update(de_net_ssid_t& dev);

    de_net_ssid_t();
    ~de_net_ssid_t();
};

#endif
