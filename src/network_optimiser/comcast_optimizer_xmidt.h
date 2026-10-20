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

#ifndef COMCAST_OPTIMIZER_XMIDT_H
#define COMCAST_OPTIMIZER_XMIDT_H

#include "optimizer.h"
#include "comcast_optimizer.h"
#include "libparodus.h"

class comcast_optimizer_xmidt_t: public comcast_optimizer_t {

    libpd_instance_t m_instance;

    int init_optimizer_interface(const char *url);
    void deinit_optimizer_interface();

public:

    comcast_optimizer_xmidt_t();
    ~comcast_optimizer_xmidt_t(); 
};

#endif
