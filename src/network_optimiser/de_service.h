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

#ifndef DE_SERVICE_H
#define DE_SERVICE_H

#include "em_base.h"

typedef enum {
    service_type_unknown,
    service_type_localize,
    service_type_sensing,
    service_type_optimizer,
    service_type_max
} service_type_t;

class de_service_t {

public:
    service_type_t  m_type;
    em_string_t m_operator_name;
    em_string_t m_url;
    em_string_t m_key; 

public:
    int init(const char *key);
    void deinit();
    void update(de_service_t& svc);

    de_service_t();
    ~de_service_t();
};

#endif
