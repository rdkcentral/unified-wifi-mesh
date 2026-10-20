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

#ifndef COMCAST_OPTIMIZER_H
#define COMCAST_OPTIMIZER_H

#include "optimizer.h"

class comcast_optimizer_t: public optimizer_t {

    virtual int init_optimizer_interface(const char *url) = 0;
    virtual void deinit_optimizer_interface() = 0;
    void process_event(optimizer_event_t *ev);
    void process_timeout(char *time_str);

public:
    const char *get_topology(char *buff, unsigned int len);

    comcast_optimizer_t();
    ~comcast_optimizer_t(); 
};

#endif
