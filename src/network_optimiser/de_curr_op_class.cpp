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
#include "de_curr_op_class.h"

void de_curr_op_class_t::update(de_curr_op_class_t& curr_op_class)
{
    m_class = curr_op_class.m_class;
    m_tx_power = curr_op_class.m_tx_power;
    m_channel = curr_op_class.m_channel;
}

int de_curr_op_class_t::init(const char *key)
{
    strncpy(m_key, key, strlen(key) + 1);
    return 0;
}

void de_curr_op_class_t::deinit()
{

}

de_curr_op_class_t::de_curr_op_class_t()
{

}

de_curr_op_class_t::~de_curr_op_class_t()
{

}
