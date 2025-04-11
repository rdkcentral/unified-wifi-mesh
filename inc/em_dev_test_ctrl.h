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

#ifndef EMDEVTEST_H
#define EMDEVTEST_H

#include "em_base.h"

class em_dev_test_t {

public:
    em_dev_test_info dev_test_info;
    void encode(em_subdoc_info_t *subdoc, hash_map_t *m_em_map, bool update, bool autconfig_renew_status);
    void analyze_set_dev_test(em_bus_event_t *evt, hash_map_t *m_em_map);
    void decode(em_subdoc_info_t *subdoc, hash_map_t *m_em_map, const char *str);
    em_dev_test_t();
    ~em_dev_test_t();

};

#endif
