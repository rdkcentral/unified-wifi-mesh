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
#include <stdarg.h>
#include <errno.h>
#include <assert.h>
#include <signal.h>
#include "db_easy_mesh.h"

char *db_easy_mesh_t::get_column_format(db_fmt_t fmt, unsigned int pos)
{
    memset(fmt, 0, sizeof(db_fmt_t));

    switch (m_columns[pos].m_type) {
        case db_data_type_char:
        case db_data_type_varchar:
        case db_data_type_binary:
        case db_data_type_varbinary:
        case db_data_type_text:
            snprintf(fmt, sizeof(fmt), "%s", "'%s', ");
            break;

        case db_data_type_integer:
        case db_data_type_int:
        case db_data_type_smallint:
        case db_data_type_tinyint:
        case db_data_type_mediumint:
        case db_data_type_bigint:
            snprintf(fmt, sizeof(fmt), "%s", "%d, ");
            break;
    }

    return fmt;
}

bool db_easy_mesh_t::is_table_empty(db_client_t& db_client)
{
    db_query_t query;
    void *ctx;
    bool ret = false;

    snprintf(query, sizeof(db_query_t), "select * from %s", m_table_name);
    ctx = db_client.execute(query);

    if (db_client.next_result(ctx) == false) {
        ret = true;
    } else {
        while (db_client.next_result(ctx) == true);
    }

    return ret;
}

int db_easy_mesh_t::get_strings_by_token(char *parent, int token, unsigned int argc, char *argv[])
{
    unsigned int num = 0, i;
    em_long_string_t str_copy;
    char *tmp, *orig;

	if (*parent == 0) {
		return 0;
	}

    for (i = 0; i < argc; i++) {
        memset(argv[i], 0, sizeof(em_long_string_t));
    }
    
    snprintf(str_copy, sizeof(str_copy), "%s", parent);
    tmp = str_copy;
    orig = str_copy;

    while (tmp != NULL) {
        if ((tmp = strchr(orig, token)) != NULL) {
            *tmp = 0;
            snprintf(argv[num], sizeof(argv[num]), "%s", orig);
            tmp++; num++;
            orig = tmp;
        }
    }	

    snprintf(argv[num], sizeof(argv[num]), "%s", orig);
    num++;

    return num;
}

int db_easy_mesh_t::insert_row(db_client_t& db_client, ...)
{
    unsigned int i;
    va_list list;
    db_query_t format, query;
    db_fmt_t	col_fmt;
    void *ctx;

    snprintf(format, sizeof(db_query_t), "insert into %s (", m_table_name);
    for (i = 0; i < m_num_cols; i++) {
        snprintf(format + strlen(format), sizeof(format) - strlen(format), "%s", m_columns[i].m_name);
        snprintf(format + strlen(format), sizeof(format) - strlen(format), "%s", ", ");
    }

    format[strlen(format) - 2] = ')';
    format[strlen(format) - 1] = 0;
    snprintf(format + strlen(format), sizeof(format) - strlen(format), "%s", " values(");
    for (i = 0; i < m_num_cols; i++) {
        snprintf(format + strlen(format), sizeof(format) - strlen(format), "%s", get_column_format(col_fmt, i));
    }

    format[strlen(format) - 2] = ')';
    format[strlen(format) - 1] = 0;


    va_start(list, format);
    (void) vsnprintf(query, sizeof(db_query_t), format, list);
    va_end(list);

    //printf("%s:%d: Query: %s\n", __func__, __LINE__, query);

    ctx = db_client.execute(query);
    while (db_client.next_result(ctx) == true);

    return 0;
}

int db_easy_mesh_t::update_row(db_client_t& db_client, ...)
{
    unsigned int i;
    db_query_t	tmp, format, query;
    va_list list;
    db_fmt_t	col_fmt;
    void *ctx;

    snprintf(format, sizeof(db_query_t), "update %s set ", m_table_name);

    for (i = 1; i < m_num_cols; i++) {
        memset(tmp, 0, sizeof(db_query_t));
        snprintf(tmp, sizeof(db_query_t), "%s = ", m_columns[i].m_name);
        snprintf(format + strlen(format), sizeof(format) - strlen(format), "%s", tmp);
        snprintf(format + strlen(format), sizeof(format) - strlen(format), "%s", get_column_format(col_fmt, i));
    }

    format[strlen(format) - 2] = 0;
    snprintf(tmp, sizeof(db_query_t), " where %s = ", m_columns[0].m_name);
    snprintf(format + strlen(format), sizeof(format) - strlen(format), "%s", tmp);

    snprintf(format + strlen(format), sizeof(format) - strlen(format), "%s", get_column_format(col_fmt, 0));
    format[strlen(format) - 2] = 0;

    va_start(list, format);
    (void) vsnprintf(query, sizeof(db_query_t), format, list);
    va_end(list);

    //printf("%s:%d: Query: %s\n", __func__, __LINE__, query);

    ctx = db_client.execute(query);
    while (db_client.next_result(ctx) == true);

    return 0;
}

int db_easy_mesh_t::compare_row(db_client_t& db_client, ...)
{
    unsigned int i;
    db_query_t tmp, format, query;
    va_list list;
    db_fmt_t col_fmt;
    void *ctx;

    snprintf(format, sizeof(db_query_t), "select * from %s where ", m_table_name);

    for (i = 0; i < m_num_cols; i++) {
        memset(tmp, 0, sizeof(db_query_t));
        snprintf(tmp, sizeof(db_query_t), "%s = ", m_columns[i].m_name);
        snprintf(format + strlen(format), sizeof(format) - strlen(format), "%s", tmp);
        snprintf(format + strlen(format), sizeof(format) - strlen(format), "%s", get_column_format(col_fmt, i));

        if (i < m_num_cols - 1) {
            snprintf(format + strlen(format), sizeof(format) - strlen(format), " and ");
        }
    }

    ctx = db_client.execute(query);
    bool comparison_success = false;

    while (db_client.next_result(ctx) == true) {
        // Process each row to compare
        comparison_success = true;
    }

    return comparison_success;
}

int db_easy_mesh_t::delete_row(db_client_t& db_client, ...)
{
    db_query_t	tmp, format, query;
    va_list list;
    db_fmt_t	col_fmt;
    void *ctx;

    snprintf(format, sizeof(db_query_t), "delete from %s", m_table_name);
    snprintf(tmp, sizeof(db_query_t), " where %s =  ", m_columns[0].m_name);
    snprintf(format + strlen(format), sizeof(format) - strlen(format), "%s", tmp);

    snprintf(format + strlen(format), sizeof(format) - strlen(format), "%s", get_column_format(col_fmt, 0));
    format[strlen(format) - 2] = 0;
    
    va_start(list, format);
    (void) vsnprintf(query, sizeof(db_query_t), format, list);
    va_end(list);

    //printf("%s:%d: Query: %s\n", __func__, __LINE__, query);

    ctx = db_client.execute(query);
    while (db_client.next_result(ctx) == true);

    return 0;
}


int db_easy_mesh_t::sync_table(db_client_t& db_client)
{
    db_query_t    query;
    db_result_t   result;
    void *ctx;

    memset(query, 0, sizeof(db_query_t));
    snprintf(query, sizeof(db_query_t), "select * from %s", m_table_name);

    ctx = db_client.execute(query);

    return sync_db(db_client, ctx);

}

bool db_easy_mesh_t::entry_exists_in_table(db_client_t& db_client, void *key)
{
    db_query_t    query;
    db_result_t   result;
    void *ctx;
    
    memset(query, 0, sizeof(db_query_t));
    snprintf(query, sizeof(db_query_t), "select * from %s", m_table_name);

    ctx = db_client.execute(query);

    return search_db(db_client, ctx, key);
}

void db_easy_mesh_t::delete_table(db_client_t& db_client)
{
    db_query_t    query;
    void *ctx;

    memset(query, 0, sizeof(db_query_t));
    snprintf(query, sizeof(db_query_t), "drop table %s", m_table_name);
    ctx = db_client.execute(query);
}

int db_easy_mesh_t::create_table(db_client_t& db_client)
{
    db_query_t    query;
    void *ctx;
    unsigned int i;
    char type_str[64];

    memset(query, 0, sizeof(db_query_t));
    snprintf(query, sizeof(db_query_t), "create table %s (", m_table_name);

    for (i = 0; i < m_num_cols; i++) {
        snprintf(query + strlen(query), sizeof(query) - strlen(query), "%s", m_columns[i].m_name);
        snprintf(query + strlen(query), sizeof(query) - strlen(query), "%s", " ");

        switch (m_columns[i].m_type) {
            case db_data_type_char:
                snprintf(type_str, sizeof(type_str), "char(%d)", m_columns[i].m_type_args);
                break;

            case db_data_type_varchar:
                snprintf(type_str, sizeof(type_str), "varchar(%d)", m_columns[i].m_type_args);
                break;

            case db_data_type_binary:
                snprintf(type_str, sizeof(type_str), "binary(%d)", m_columns[i].m_type_args);
                break;

            case db_data_type_varbinary:
                snprintf(type_str, sizeof(type_str), "varbinary(%d)", m_columns[i].m_type_args);
                break;

            case db_data_type_text:
                snprintf(type_str, sizeof(type_str), "text(%d)", m_columns[i].m_type_args);
                break;

            case db_data_type_integer:
                snprintf(type_str, sizeof(type_str), "integer");
                break;

            case db_data_type_int:
                snprintf(type_str, sizeof(type_str), "int");
                break;

            case db_data_type_smallint:
                snprintf(type_str, sizeof(type_str), "smallint");
                break;

            case db_data_type_bigint:
                snprintf(type_str, sizeof(type_str), "bigint");
                break;

            case db_data_type_tinyint:
                snprintf(type_str, sizeof(type_str), "tinyint");
                break;

            case db_data_type_mediumint:
                snprintf(type_str, sizeof(type_str), "mediumint");
                break;

            default:
                assert(0);
                break;	
        }
        snprintf(query + strlen(query), sizeof(query) - strlen(query), "%s", type_str);
        snprintf(query + strlen(query), sizeof(query) - strlen(query), "%s", ", ");
    }

    query[strlen(query) - 2] = ')';
    query[strlen(query) - 1] = 0;

    //printf("%s:%d: Query: %s\n", __func__, __LINE__, query);
    ctx = db_client.execute(query);

    return 0;
}

int db_easy_mesh_t::load_table(db_client_t& db_client)
{
    db_query_t    query;
    db_result_t   result;
    void *ctx;
    bool present = false;

    memset(query, 0, sizeof(db_query_t));
    snprintf(query, sizeof(db_query_t), "show tables");

    ctx = db_client.execute(query);

    while (db_client.next_result(ctx)) {
        db_client.get_string(ctx, result, 1);
        if (strncmp(result, m_table_name, strlen(m_table_name)) == 0) {
            present = true;
        }
    }

    //printf("%s:%d: Table: %s %s\n", __func__, __LINE__, m_table_name, (present == true) ? "present":"not present");

    if (present == true) {
        sync_table(db_client);
    } else {
        create_table(db_client);
    }

    return (present == true) ? 0:-1;
}

db_easy_mesh_t::db_easy_mesh_t()
{

}

db_easy_mesh_t::~db_easy_mesh_t()
{

}
