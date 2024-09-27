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

#ifndef DB_COLUMN_H
#define DB_COLUMN_H

#include "em_base.h"
#include "db_client.h"

class db_column_t {
public:
    db_column_name_t   m_name;
    db_data_type_t   m_type;
    db_data_type_args_t   m_type_args;
public:
    void operator = (const db_column_t& col); 
    
    db_column_t(const db_column_name_t name, const db_data_type_t type, const db_data_type_args_t args);
    db_column_t();
    ~db_column_t();
};

#endif
