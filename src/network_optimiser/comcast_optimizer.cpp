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
#include "comcast_optimizer.h"
#include "util.h"

const char *comcast_optimizer_t::get_topology(char *buff, unsigned int len)
{
    cJSON *obj, *parent, *arr;
 
    parent = cJSON_CreateObject();
    obj = cJSON_AddObjectToObject(parent, "wfa-dataelements:Network");
    
    cJSON_AddStringToObject(obj, "ID", "NetworkID");
    cJSON_AddStringToObject(obj, "ControllerID", "ControllerID");

    arr = cJSON_AddArrayToObject(obj, "Services");

    obj = cJSON_CreateObject(); 
    cJSON_AddItemToArray(arr, obj); 

    cJSON_AddNumberToObject(obj, "Type", service_type_optimizer);
    cJSON_AddStringToObject(obj, "Operator", "comcast");
    cJSON_AddStringToObject(obj, "URL", "data");
    obj = cJSON_AddObjectToObject(obj, "Vendor");
    cJSON_AddStringToObject(obj, "Mode", "RDKMesh");
    cJSON_AddStringToObject(obj, "Type", "Topology");


    cJSON_PrintPreallocated(parent, buff, len, true);
    cJSON_Delete(parent);

    return (const char *)buff;
}

void comcast_optimizer_t::process_event(optimizer_event_t *ev)
{

}

void comcast_optimizer_t::process_timeout(char *time_str)
{

}

comcast_optimizer_t::comcast_optimizer_t()
{

}

comcast_optimizer_t::~comcast_optimizer_t()
{

}
