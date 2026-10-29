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
#include <errno.h>
#include <signal.h>
#include "util.h"
#include "de_cap.h"

void de_cap_t::update(de_cap_t& cap)
{
    m_num_op_class = cap.m_num_op_class;
    strncpy(m_ht_cap, cap.m_ht_cap, strlen(cap.m_ht_cap) + 1);
}

int de_cap_t::init(const char *key)
{
    strncpy(m_key, key, strlen(key) + 1);
    return 0;
}

void de_cap_t::deinit()
{

}

de_cap_t::de_cap_t()
{
    m_num_op_class = 0;
    memset(m_ht_cap, 0, sizeof(em_string_t));
}

de_cap_t::~de_cap_t()
{

}
