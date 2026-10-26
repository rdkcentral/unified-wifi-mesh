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

#ifndef DE_STA_H
#define DE_STA_H

#include "em_base.h"

class de_sta_t {

public:

    em_long_string_t m_key;    
    em_string_t m_mac;
    int     m_rssi;
    unsigned int    m_ul_rate;
    unsigned int    m_dl_rate;
    unsigned int    m_retrans;
    unsigned int    m_pkts_rx;
    unsigned int    m_pkts_tx;
    unsigned int    m_bytes_rx;
    unsigned int    m_bytes_tx;
    em_long_string_t    m_cap;
    //em_long_string_t    m_wifi6_cap;
    em_long_string_t    m_ht_cap;
    em_long_string_t    m_vht_cap;
    em_long_string_t    m_he_cap;
    em_string_t     m_sec_assoc;

public:
    int init(const char *key);
    void deinit();
    void update(de_sta_t& sta);

    de_sta_t();
    ~de_sta_t();
};

#endif
