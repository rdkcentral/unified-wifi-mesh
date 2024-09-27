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


#ifndef DB_CLIENT_H
#define DB_CLIENT_H

class db_client_t {
    void *m_driver;
    void *m_con;

    int connect(const char *path);

public:
    int init(const char *path);
    void *execute(const char *query);
    bool next_result(void *ctx);
    char *get_string(void *ctx, char *res, unsigned int col);
    int get_number(void *ctx, unsigned int col);

    db_client_t();
    ~db_client_t();	
};

#endif
