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

#ifndef DE_CURR_OP_CLASS_H
#define DE_CURR_OP_CLASS_H

#include "em_base.h"

class de_curr_op_class_t {

public:

    em_long_string_t m_key;    
    unsigned int m_class;
    unsigned int m_tx_power;
    unsigned int m_channel;

public:
    int init(const char *key);
    void deinit();
    void update(de_curr_op_class_t& curr_op_class);

    de_curr_op_class_t();
    ~de_curr_op_class_t();
};

#endif
