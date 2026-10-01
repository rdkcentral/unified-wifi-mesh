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

#include <string.h>
#include "db_client.h"
#include "db_client_local.h"
#include "db_client_cloud.h"
#include "db_client_none.h"

db_client_t *db_client_create(db_client_type_t type)
{
    switch (type) {
        case db_client_type_local: return new db_client_local_t();
        case db_client_type_cloud: return new db_client_cloud_t();
        case db_client_type_none:  return new db_client_none_t();
        default:                   return nullptr;
    }
}

db_client_type_t db_client_type_from_string(const char *name)
{
    if (name == nullptr) {
        return db_client_type_local;
    }
    if (strcasecmp(name, "none") == 0 || strcasecmp(name, "no_db") == 0 || strcasecmp(name, "nodb") == 0) {
        return db_client_type_none;
    }
    if (strcasecmp(name, "cloud") == 0) {
        return db_client_type_cloud;
    }
    return db_client_type_local;
}
