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

#ifndef DB_CLIENT_CLOUD_H
#define DB_CLIENT_CLOUD_H

#include "db_client.h"

/**!
 * @brief db_client_type_cloud implementation of db_client_t. Placeholder for
 * a future cloud-hosted database backend (e.g. a REST/gRPC-fronted managed
 * DB). Deliberately out of scope for this change.
 *
 * The interface is wired end-to-end (enum value, factory case) so that when
 * this is implemented, it is purely additive: nothing in db_easy_mesh_t or
 * any dm_*_list_t class needs to change, and dm_easy_mesh_ctrl_t just needs
 * to be told to select db_client_type_cloud.
 *
 * @note Currently every method fails/no-ops so that accidentally selecting
 * this backend is loud rather than silently behaving like db_client_none_t.
 */
class db_client_cloud_t : public db_client_t {

public:

    int init(const char *path) override;
    void *execute(const char *query) override;
    bool next_result(void *ctx) override;
    char *get_string(void *ctx, char *res, unsigned int col) override;
    int get_number(void *ctx, unsigned int col) override;
    int recreate_db() override;
    db_client_type_t get_type() const override { return db_client_type_cloud; }

    db_client_cloud_t();
    virtual ~db_client_cloud_t();
};

#endif
