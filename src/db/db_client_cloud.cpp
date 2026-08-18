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
#include "db_client_cloud.h"

// TODO(cloud-db): implement against the chosen cloud DB backend/API.
// Everything below fails fast on purpose - see db_client_cloud.h.

int db_client_cloud_t::init(const char *path)
{
    (void) path;
    printf("%s:%d: Cloud DB backend is not implemented yet\n", __func__, __LINE__);
    return -1;
}

void *db_client_cloud_t::execute(const char *query)
{
    (void) query;
    return NULL;
}

bool db_client_cloud_t::next_result(void *ctx)
{
    (void) ctx;
    return false;
}

char *db_client_cloud_t::get_string(void *ctx, char *res, unsigned int col)
{
    (void) ctx;
    (void) col;
    if (res != NULL) {
        res[0] = 0;
    }
    return NULL;
}

int db_client_cloud_t::get_number(void *ctx, unsigned int col)
{
    (void) ctx;
    (void) col;
    return 0;
}

int db_client_cloud_t::recreate_db()
{
    return -1;
}

db_client_cloud_t::db_client_cloud_t()
{

}

db_client_cloud_t::~db_client_cloud_t()
{

}
