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

#ifndef DE_SCAN_RESULT_H
#define DE_SCAN_RESULT_H

#include "em_base.h"
#include "rbus.h"

class de_scan_result_t {

public:
    em_long_string_t m_key;    
    em_long_string_t    m_timestamp;
    unsigned int    m_agg_scan_dur;
    bool    m_scan_type;

public:
    int init(const char *key);
    void deinit();
    void update(de_scan_result_t& res);

    void serialize(rbusObject_t& ob);
    void deserialize(rbusObject_t& ob);

    void serialize(cJSON *ob);
    void deserialize(cJSON *ob);

    de_scan_result_t();
    ~de_scan_result_t();
};

#endif
