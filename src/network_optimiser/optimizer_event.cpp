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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "util.h"
#include "optimizer_event.h"

optimizer_event_t::optimizer_event_t(optimizer_event_type_t type, void *data, unsigned int len, bool zero_cp)
{
    m_type = type;
    m_copy = !zero_cp;
    if (zero_cp == false) {
        m_data = malloc(len);
        memcpy(m_data, data, len);
    } else {
        m_data = data;
    }

    m_len = len; 
}

optimizer_event_t::~optimizer_event_t()
{
    if (m_copy == true) {
        free(m_data);
    }
}
