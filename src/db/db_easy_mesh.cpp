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
#include "util.h"

char *db_easy_mesh_t::get_column_format(db_fmt_t fmt, unsigned int pos)
{
    memset(fmt, 0, sizeof(db_fmt_t));

    switch (m_columns[pos].m_type) {
        case db_data_type_char:
        case db_data_type_varchar:
        case db_data_type_binary:
        case db_data_type_varbinary:
        case db_data_type_text:
            snprintf(fmt, sizeof(db_fmt_t), "%s", "'%s', ");
            break;

        case db_data_type_integer:
        case db_data_type_int:
        case db_data_type_smallint:
        case db_data_type_tinyint:
        case db_data_type_mediumint:
        case db_data_type_bigint:
            snprintf(fmt, sizeof(db_fmt_t), "%s", "%d, ");
            break;

        default:
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

    if (ctx == NULL) {
        // A failed check requires the same initialization recovery as an empty table.
        printf("%s:%d: Error: Select query failed for table %s; requesting database initialization\n",
               __func__, __LINE__, m_table_name);
        return true;
    }

    if (db_client.next_result(ctx) == false) {
        ret = true;
    } else {
        db_client.free_result(ctx);
    }

    return ret;
}

int db_easy_mesh_t::get_strings_by_token(char *parent, int token, unsigned int argc, char *argv[])
{
    unsigned int num = 0, i, max_len;
    em_2xlong_string_t str_copy;
    char *tmp, *orig;

	if (*parent == 0) {
		return 0;
	}

    for (i = 0; i < argc; i++) {
        memset(argv[i], 0, sizeof(em_short_string_t));
    }
    
    snprintf(str_copy, sizeof(str_copy), "%s", parent);
    tmp = str_copy;
    orig = str_copy;
    max_len = sizeof(em_short_string_t) - 1;

    while (tmp != NULL) {
        if ((tmp = strchr(orig, token)) != NULL) {
            *tmp = 0;
            assert (num < argc - 1 && "number of extracted values exceeds the limit");
            snprintf(argv[num], sizeof(em_short_string_t), "%.*s", max_len, orig);
            tmp++; num++;
            orig = tmp;
        }
    }

    snprintf(argv[num], sizeof(em_short_string_t), "%.*s", max_len, orig);
    num++;

    return static_cast<int> (num);
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


    va_start(list, db_client);
    (void) vsnprintf(query, sizeof(db_query_t), format, list);
    va_end(list);

    //printf("%s:%d: Query: %s\n", __func__, __LINE__, query);

    ctx = db_client.execute(query);
    db_client.free_result(ctx);

    return db_client.last_query_succeeded() ? 0 : -1;
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

    va_start(list, db_client);
    (void) vsnprintf(query, sizeof(db_query_t), format, list);
    va_end(list);

    //printf("%s:%d: Query: %s\n", __func__, __LINE__, query);

    ctx = db_client.execute(query);
    db_client.free_result(ctx);

    return db_client.last_query_succeeded() ? 0 : -1;
}

int db_easy_mesh_t::compare_row(db_client_t& db_client, ...)
{
    unsigned int i;
    va_list list;
    db_query_t tmp, format, query;
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

    va_start(list, db_client);
    (void) vsnprintf(query, sizeof(db_query_t), format, list);
    va_end(list);

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
    
    va_start(list, db_client);
    (void) vsnprintf(query, sizeof(db_query_t), format, list);
    va_end(list);

    //printf("%s:%d: Query: %s\n", __func__, __LINE__, query);

    ctx = db_client.execute(query);
    db_client.free_result(ctx);

    return db_client.last_query_succeeded() ? 0 : -1;
}


int db_easy_mesh_t::sync_table(db_client_t& db_client)
{
    db_query_t    query;
    void *ctx;
    int ret;

    memset(query, 0, sizeof(db_query_t));
    snprintf(query, sizeof(db_query_t), "select * from %s", m_table_name);

    ctx = db_client.execute(query);

    ret = sync_db(db_client, ctx);

    return ret;

}

bool db_easy_mesh_t::entry_exists_in_table(db_client_t& db_client, void *key)
{
    db_query_t    query;
    void *ctx;
    
    memset(query, 0, sizeof(db_query_t));
    snprintf(query, sizeof(db_query_t), "select * from %s", m_table_name);

    ctx = db_client.execute(query);

    return search_db(db_client, ctx, key);
}

void db_easy_mesh_t::delete_table(db_client_t& db_client)
{
    db_query_t    query;

    memset(query, 0, sizeof(db_query_t));
    snprintf(query, sizeof(db_query_t), "drop table %s", m_table_name);
    db_client.execute(query);
}

int db_easy_mesh_t::create_table(db_client_t& db_client)
{
    db_query_t    query;
    unsigned int i;
    char type_str[64];

    memset(query, 0, sizeof(db_query_t));
    snprintf(query, sizeof(db_query_t), "create table %s (", m_table_name);

    for (i = 0; i < m_num_cols; i++) {
        snprintf(query + strlen(query), sizeof(query) - strlen(query), "%s", m_columns[i].m_name);
        snprintf(query + strlen(query), sizeof(query) - strlen(query), "%s", " ");

        get_column_type(i, type_str, sizeof(type_str));
        snprintf(query + strlen(query), sizeof(query) - strlen(query), "%s", type_str);
        snprintf(query + strlen(query), sizeof(query) - strlen(query), "%s", ", ");
    }

    query[strlen(query) - 2] = ')';
    query[strlen(query) - 1] = 0;
    db_client.execute(query);
    //printf("%s:%d: Query: %s\n", __func__, __LINE__, query);

    return 0;
}

char *db_easy_mesh_t::get_column_type(unsigned int pos, char *type_str, unsigned int sz)
{
    switch (m_columns[pos].m_type) {
        case db_data_type_char:
            snprintf(type_str, sz, "char(%d)", m_columns[pos].m_type_args);
            break;

        case db_data_type_varchar:
            snprintf(type_str, sz, "varchar(%d)", m_columns[pos].m_type_args);
            break;

        case db_data_type_binary:
            snprintf(type_str, sz, "binary(%d)", m_columns[pos].m_type_args);
            break;

        case db_data_type_varbinary:
            snprintf(type_str, sz, "varbinary(%d)", m_columns[pos].m_type_args);
            break;

        case db_data_type_text:
            snprintf(type_str, sz, "text(%d)", m_columns[pos].m_type_args);
            break;

        case db_data_type_integer:
            snprintf(type_str, sz, "integer");
            break;

            case db_data_type_tinyint:
                snprintf(type_str, sizeof(type_str), "integer");
                break;

            case db_data_type_datetime:
                snprintf(type_str, sizeof(type_str), "text");
                break;

    return type_str;
}

int db_easy_mesh_t::align_table_columns(db_client_t& db_client)
{
    db_query_t    query;
    db_result_t   result;
    char type_str[64];
    char column_type[64];
    bool present[EM_MAX_COLS];
    bool migrate_bss_mac_filter_mode = false;
    bool migrate_bss_acl_columns = false;
    bool migrate_bss_acl_validity_period = false;
    void *ctx;
    unsigned int i;

    memset(present, 0, sizeof(present));

    memset(query, 0, sizeof(db_query_t));
    snprintf(query, sizeof(db_query_t), "show columns from %s", m_table_name);

    ctx = db_client.execute(query);
    while (db_client.next_result(ctx)) {
        memset(result, 0, sizeof(db_result_t));
        if (db_client.get_string(ctx, result, 1) == NULL) {
            continue;
        }
        if ((strcmp(m_table_name, "BSSList") == 0) &&
                (strcmp(result, "MACFilterMode") == 0)) {
            memset(column_type, 0, sizeof(column_type));
            db_client.get_string(ctx, column_type, 2, sizeof(column_type));
            migrate_bss_mac_filter_mode = (strncmp(column_type, "tinyint", 7) == 0);
        }
        if ((strcmp(m_table_name, "BSSList") == 0) &&
                ((strcmp(result, "MACsDisallowed") == 0) || (strcmp(result, "MACsAllowed") == 0))) {
            memset(column_type, 0, sizeof(column_type));
            db_client.get_string(ctx, column_type, 2, sizeof(column_type));
            migrate_bss_acl_columns = migrate_bss_acl_columns ||
                    (strcmp(column_type, "varchar(512)") == 0);
        }
        if ((strcmp(m_table_name, "BSSList") == 0) &&
                (strcmp(result, "ACLValidityPeriod") == 0)) {
            memset(column_type, 0, sizeof(column_type));
            db_client.get_string(ctx, column_type, 2, sizeof(column_type));
            migrate_bss_acl_validity_period = (strncmp(column_type, "smallint", 8) == 0);
        }
        for (i = 0; i < m_num_cols; i++) {
            if (strcmp(result, m_columns[i].m_name) == 0) {
                present[i] = true;
                break;
            }
        }
    }

    for (i = 0; i < m_num_cols; i++) {
        if (present[i] == true) {
            continue;
        }

        get_column_type(i, type_str, sizeof(type_str));
        memset(query, 0, sizeof(db_query_t));
        snprintf(query, sizeof(db_query_t), "alter table %s add column %s %s",
                    m_table_name, m_columns[i].m_name, type_str);
        db_client.execute(query);
    }

    if (migrate_bss_mac_filter_mode) {
        snprintf(query, sizeof(db_query_t), "alter table BSSList modify MACFilterMode char(9)");
        db_client.execute(query);
    }
    if (migrate_bss_acl_columns) {
        snprintf(query, sizeof(db_query_t), "alter table BSSList modify MACsDisallowed varchar(%d)",
                EM_MAX_ACL_LIST_CHARS);
        db_client.execute(query);
        snprintf(query, sizeof(db_query_t), "alter table BSSList modify MACsAllowed varchar(%d)",
                EM_MAX_ACL_LIST_CHARS);
        db_client.execute(query);
    }
    if (migrate_bss_acl_validity_period) {
        snprintf(query, sizeof(db_query_t), "alter table BSSList modify ACLValidityPeriod int");
        db_client.execute(query);
        if (!db_client.last_query_succeeded()) {
            printf("%s:%d: Failed to migrate BSSList.ACLValidityPeriod to int\n", __func__, __LINE__);
            return -1;
        }
    }

    return 0;
}

int db_easy_mesh_t::load_table(db_client_t& db_client)
{
    db_query_t    query;
    db_result_t   result;
    void *ctx;
    bool present = false;

    memset(query, 0, sizeof(db_query_t));
    snprintf(query, sizeof(db_query_t), "select name from sqlite_master where type = 'table'");

    ctx = db_client.execute(query);

    while (db_client.next_result(ctx)) {
        db_client.get_string(ctx, result, 1);
        if (strncmp(result, m_table_name, strlen(m_table_name)) == 0) {
            present = true;
        }
    }

    //printf("%s:%d: Table: %s %s\n", __func__, __LINE__, m_table_name, (present == true) ? "present":"not present");

    if (present == true) {
        if (align_table_columns(db_client) != 0) {
            return -1;
        }
        sync_table(db_client);
    } else {
        create_table(db_client);
    }

    return 0;
}

db_easy_mesh_t::db_easy_mesh_t()
{

}

db_easy_mesh_t::~db_easy_mesh_t()
{

}
