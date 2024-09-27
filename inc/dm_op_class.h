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

#ifndef DM_OP_CLASS_H
#define DM_OP_CLASS_H

#include "em_base.h"

class dm_op_class_t {
public:
    em_op_class_info_t    m_op_class_info;

public:
    int init() { memset(&m_op_class_info, 0, sizeof(em_op_class_info_t)); return 0; }
    em_op_class_info_t *get_op_class_info() { return &m_op_class_info; }
    int decode(const cJSON *obj, void *parent_id);
    void encode(cJSON *obj);

    bool operator == (const dm_op_class_t& obj);
    void operator = (const dm_op_class_t& obj);

    dm_op_class_t(em_op_class_info_t *op_class);
    dm_op_class_t(const dm_op_class_t& op_class);
    dm_op_class_t();
    ~dm_op_class_t();
};

#endif
