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
#include <assert.h>
#include <signal.h>
#include "db_column.h"

void db_column_t::operator = (const db_column_t& col)
{
    if (this == &col) { return; }
    snprintf(m_name, sizeof(m_name), "%s", col.m_name);
    m_type = col.m_type;
    m_type_args = col.m_type_args;
}

db_column_t::db_column_t(const db_column_name_t name, const db_data_type_t type, const db_data_type_args_t args)
{
    snprintf(m_name, sizeof(m_name), "%s", name);
    m_type = type;
    m_type_args = args;
}

db_column_t::db_column_t()
{

}

db_column_t::~db_column_t()
{

}
