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
 #include <stdlib.h>
 #include <assert.h>
 #include "db_client.h"
 #include "em_base.h"

 // Structure to hold the result set and associated data
 struct result_context_t {
     MYSQL_RES *result;
     MYSQL_ROW row;
 };

 int db_client_t::recreate_db()
 {
     if (!m_con) {
         printf("%s:%d: No database connection\n", __func__, __LINE__);
         return -1;
     }

     // Drop existing database
     if (mysql_query(m_con, "DROP DATABASE IF EXISTS OneWifiMesh")) {
         printf("%s:%d: Error dropping database: %s\n", __func__, __LINE__, mysql_error(m_con));
         return -1;
     }

     // Create new database
     if (mysql_query(m_con, "CREATE DATABASE OneWifiMesh")) {
         printf("%s:%d: Error creating database: %s\n", __func__, __LINE__, mysql_error(m_con));
         return -1;
     }

     return 0;
 }

 void *db_client_t::execute(const char *query)
 {
     if (!m_con) {
         printf("%s:%d: Query: %s m_con is NULL, exiting\n", __func__, __LINE__, query);
         return NULL;
     }

     if (mysql_query(m_con, query)) {
         printf("%s:%d: Query failed: %s, Error: %s\n", __func__, __LINE__, query, mysql_error(m_con));
         return NULL;
     }

     MYSQL_RES *result = mysql_store_result(m_con);
     if (!result) {
         // This might not be an error - could be a query that doesn't return results (INSERT, UPDATE, etc.)
         if (mysql_field_count(m_con) == 0) {
             return NULL;  // Query was successful but didn't return data
         } else {
             printf("%s:%d: Error storing result: %s\n", __func__, __LINE__, mysql_error(m_con));
             return NULL;
         }
     }

     // Create a context structure to hold the result and current row
     result_context_t *ctx = new result_context_t;
     ctx->result = result;
     ctx->row = NULL;

     return ctx;
 }

 bool db_client_t::next_result(void *ctx)
 {
     if (ctx == NULL) {
         return false;
     }

     result_context_t *res_ctx = static_cast<result_context_t *>(ctx);
     res_ctx->row = mysql_fetch_row(res_ctx->result);

     if (res_ctx->row == NULL) {
         // No more rows - clean up
         mysql_free_result(res_ctx->result);
         delete res_ctx;
         return false;
     }

     return true;
 }

 char *db_client_t::get_string(void *ctx, char *str, unsigned int col)
 {
     if (ctx == NULL) {
         return NULL;
     }

     result_context_t *res_ctx = static_cast<result_context_t *>(ctx);

     if (res_ctx->row == NULL || res_ctx->row[col - 1] == NULL) {
         return NULL;
     }

     // Note: Column indices in MariaDB C API are 0-based
     unsigned long *lengths = mysql_fetch_lengths(res_ctx->result);
     if (!lengths) {
         return NULL;
     }

     snprintf(str, lengths[col - 1] + 1, "%s", res_ctx->row[col - 1]);
     return str;
 }

 int db_client_t::get_number(void *ctx, unsigned int col)
 {
     assert(ctx != NULL);

     result_context_t *res_ctx = static_cast<result_context_t *>(ctx);

     if (res_ctx->row == NULL || res_ctx->row[col - 1] == NULL) {
         return 0;
     }

     // Note: Column indices in MariaDB C API are 0-based
     return atoi(res_ctx->row[col - 1]);
 }

 int db_client_t::connect(const char *path)
 {
     if (path == NULL || strlen(path) <= 0) {
         return -1;
     }

     // Parse the path format: "username@password"
     char *tmp = strchr(const_cast<char *>(path), '@');
     if (tmp == NULL) {
         printf("%s:%d: invalid path: %s\n", __func__, __LINE__, path);
         return -1;
     }

     // Split username and password
     char username[256];
     char password[256];

     size_t user_len = tmp - path;
     if (user_len >= sizeof(username)) {
         printf("%s:%d: username too long\n", __func__, __LINE__);
         return -1;
     }

     strncpy(username, path, user_len);
     username[user_len] = '\0';

     tmp++; // Move past '@'
     strncpy(password, tmp, sizeof(password) - 1);
     password[sizeof(password) - 1] = '\0';

     printf("%s:%d: user:%s pass:%s\n", __func__, __LINE__, username, password);

     // Initialize MySQL connection
     m_con = mysql_init(NULL);
     if (m_con == NULL) {
         printf("%s:%d: mysql_init() failed\n", __func__, __LINE__);
         return -1;
     }

     // Connect to the database
     if (mysql_real_connect(m_con,
                           "localhost",
                           username,
                           password,
                           NULL,        // Don't select database yet
                           3306,       // Default port
                           NULL,       // Unix socket
                           0) == NULL) {
         printf("%s:%d: mysql_real_connect() failed: %s\n", __func__, __LINE__,
                mysql_error(m_con));
         mysql_close(m_con);
         m_con = NULL;
         return -1;
     }

     // Select the database
     if (mysql_select_db(m_con, "OneWifiMesh") != 0) {
         printf("%s:%d: Error selecting database: %s\n", __func__, __LINE__,
                mysql_error(m_con));
         // Don't fail here - the database might not exist yet
     }

     return 0;
 }

 int db_client_t::init(const char *path)
 {
     if (connect(path) != 0) {
         printf("%s:%d: Connect failed\n", __func__, __LINE__);
         return -1;
     }

     return 0;
 }

 db_client_t::db_client_t()
 {
     m_con = NULL;
 }

 db_client_t::~db_client_t()
 {
     if (m_con) {
         mysql_close(m_con);
         m_con = NULL;
     }
 }
