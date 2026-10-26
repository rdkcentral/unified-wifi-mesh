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

#ifndef DE_BSS_H
#define DE_BSS_H

#include "em_base.h"

class de_bss_t {

public:

    em_long_string_t m_key;    
    em_string_t m_bssid;
    em_string_t m_ssid;
    bool m_enabled;
    bool m_broadcast;
    bool m_fronthaul;
    bool m_backhaul;

public:
    int init(const char *key);
    void deinit();
    void update(de_bss_t& radio);

    de_bss_t();
    ~de_bss_t();
};

#endif
