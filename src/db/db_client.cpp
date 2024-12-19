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

#include "mysql_connection.h"
#include <cppconn/driver.h>
#include <cppconn/exception.h>
#include <cppconn/resultset.h>
#include <cppconn/statement.h>
#include <string.h>
#include <stdlib.h>
#include "db_client.h"
#include "em_base.h"

int db_client_t::recreate_db()
{
	execute("drop database OneWifiMesh");
	execute("create database OneWifiMesh");
}

void *db_client_t::execute(const char *query)
{
    void *tmp = NULL;

    try {
        sql::Statement *stmt;
        sql::ResultSet *res;

        if (m_con) {
            stmt = ((sql::Connection *)m_con)->createStatement();
        } else {
            printf("%s:%d: Query: %s m_con is NULL, exciting\n", __func__, __LINE__, query);
            return tmp;
        }

        if (stmt) {
            res = stmt->executeQuery(query);
        } else {
            printf("%s:%d: Query: %s stmt is NULL, exciting\n", __func__, __LINE__, query);
            return tmp;
        }
        tmp = res;
        delete stmt;

    } catch (sql::SQLException &e) {
        //printf("%s:%d: Exception in executing query, error code:%d\n", __func__, __LINE__, e.getErrorCode());
    }

    return tmp;
}

bool db_client_t::next_result(void *ctx)
{
    bool ret = false;

    if (ctx == NULL) {
        return ret;
    }

    try {
        sql::ResultSet *res = (sql::ResultSet *)ctx;
        ret = res->next();
        if (ret == false) {
            //printf("%s:%d: result set deleted\n", __func__, __LINE__);
            delete res;    
        }

    } catch (sql::SQLException &e) {
        printf("%s:%d: Exception, error code:%d\n", __func__, __LINE__, e.getErrorCode());
    }

    return ret;
}

char *db_client_t::get_string(void *ctx, char *str, unsigned int col)
{
    if (ctx == NULL) {
        return NULL;
    }

    try {
        sql::ResultSet *res = (sql::ResultSet *)ctx;
        snprintf(str, strlen(res->getString(col).c_str()) + 1, "%s", res->getString(col).c_str());
        //printf("%s:%d: str:%s\n", __func__, __LINE__, str);
    } catch (sql::SQLException &e) {
        printf("%s:%d: Exception, error code:%d\n", __func__, __LINE__, e.getErrorCode());
    }

    return str;
}

int db_client_t::get_number(void *ctx, unsigned int col)
{
    int n;

    assert(ctx != NULL);

    try {
        sql::ResultSet *res = (sql::ResultSet *)ctx;
        n = res->getInt(col);

    } catch (sql::SQLException &e) {
        printf("%s:%d: Exception, error code:%d\n", __func__, __LINE__, e.getErrorCode());
    }

    return n;
}

int db_client_t::connect(const char *path)
{
    int ret = 0;
    char *tmp;

    if (path == NULL || strlen(path) <= 0) return -1;

    if ((tmp = strchr((char *)path, '@')) == NULL) {
        printf("%s:%d: invalid path: %s\n", __func__, __LINE__, path);
        return -1;
    }

    *tmp = 0; tmp++;

    printf("%s:%d: user:%s pass:%s\n", __func__, __LINE__, path, tmp); 
    try {
        m_driver = get_driver_instance();
        m_con = ((sql::Driver *)m_driver)->connect("tcp://127.0.0.1:3306", path, tmp);

        ((sql::Connection *)m_con)->setSchema("OneWifiMesh");


    } catch (sql::SQLException &e) {
        printf("%s:%d: Exception in connecting to database, error code:%d\n", __func__, __LINE__, e.getErrorCode());
        ret = -1;
    }

    return ret;
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

}

db_client_t::~db_client_t()
{

}
