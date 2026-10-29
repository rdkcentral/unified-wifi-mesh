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

#ifndef DE_CURR_OP_CLASSES_H
#define DE_CURR_OP_CLASSES_H

#include "rbus.h"
#include "em_base.h"
#include "collection.h"
#include "de.h"
#include "de_curr_op_class.h"

class de_curr_op_classes_t : public de_t {

public:
    hash_map_t  *m_op_class_map;   

public:

    int init(rbusHandle_t handle);
    void deinit(bool bus_close);

    void update(de_curr_op_class_t& curr_op_class, unsigned int dpos, unsigned int rpos, unsigned int opos);

    void publish(const char *event_name);

    rbusError_t add(rbusHandle_t handle, char const* table_name, char const* alias_name, uint32_t* inst_num);
    rbusError_t remove(rbusHandle_t handle, char const* row_name);
    rbusError_t set(rbusHandle_t handle, rbusProperty_t property, rbusSetHandlerOptions_t* options);
    rbusError_t get(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t* options);
    void handler(rbusHandle_t handle, rbusEvent_t const* event, rbusEventSubscription_t* subscription);

    de_curr_op_classes_t(const char *name, bool provider = false, notifier_t func = notifier_t());
};

#endif
