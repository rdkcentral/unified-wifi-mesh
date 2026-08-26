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
#include "db_client_none.h"
#include "util.h"

int db_client_none_t::init(const char *path)
{
    // No backend to connect to - always succeeds.
    (void) path;
    return 0;
}

void *db_client_none_t::execute(const char *query)
{
    // Nothing to run against; there is never a result set to iterate.
    em_printfout("No backend to execute query: %s\n", query);
    (void) query;
    return NULL;
}

bool db_client_none_t::next_result(void *ctx)
{
    (void) ctx;
    return false;
}

char *db_client_none_t::get_string(void *ctx, char *res, unsigned int col)
{
    (void) ctx;
    (void) col;
    if (res != NULL) {
        res[0] = 0;
    }
    return NULL;
}

int db_client_none_t::get_number(void *ctx, unsigned int col)
{
    (void) ctx;
    (void) col;
    return 0;
}

int db_client_none_t::recreate_db()
{
    // Nothing persisted, nothing to recreate.
    return 0;
}

db_client_none_t::db_client_none_t()
{

}

db_client_none_t::~db_client_none_t()
{

}
