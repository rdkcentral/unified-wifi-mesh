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
#include "bus.h"
#include "bus_common.h"
#include "optimizer.h"
#include "comcast_optimizer_web.h"
#include "util.h"
#include <cjson/cJSON.h>

const char *comcast_optimizer_web_t::handle_get(optimizer_event_type_t type, char *buff, unsigned int len)
{
    switch (type) {
        case optimizer_event_type_get_topology:
            get_topology(buff, len);
            break;

        default:
            break;
    }

    return buff;
}

int comcast_optimizer_web_t::init_optimizer_interface(const char *url)
{
    web_t::init(url);
    start();

    return 0;
}

void comcast_optimizer_web_t::deinit_optimizer_interface()
{
    stop();
}

comcast_optimizer_web_t::comcast_optimizer_web_t()
{
    set_optimizer_type(optimizer_type_comcast);

}

comcast_optimizer_web_t::~comcast_optimizer_web_t()
{

}
