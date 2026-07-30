/**
 * If not stated otherwise in this file or this component's LICENSE file the
 * following copyright and licenses apply:
 *
 * Copyright 2025 RDK Management
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
 */
 
#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <stdio.h>
#include "db_client.h"

class db_client_t_Test : public ::testing::Test {
protected:
    db_client_t* dbClient;
    void SetUp() override {
        dbClient = new db_client_t();
        dbClient->init("bpi@root");
    }
    void TearDown() override {
        delete dbClient;
    }
};

class db_client_crud_Test : public ::testing::Test {
protected:
    db_client_t* dbClient;
    struct result_context_t {
        MYSQL_RES *result;
        MYSQL_ROW row;
    };
    void SetUp() override {
        dbClient = new db_client_t();
        dbClient->init("bpi@root");
        // Step 1: Create table
        free_result(dbClient->execute(
            "CREATE TABLE IF NOT EXISTS users ("
            "id INT AUTO_INCREMENT PRIMARY KEY,"
            "username VARCHAR(50) NOT NULL,"
            "email VARCHAR(100),"
            "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP"
            ");"
        ));
        // Step 2: Insert two rows
        free_result(dbClient->execute(
            "INSERT INTO users (username, email) VALUES "
            "('alice', 'alice@example.com'),"
            "('bob', 'bob@example.com');"
        ));
    }
    void TearDown() override {
        // Drop table
        free_result(dbClient->execute("DROP TABLE IF EXISTS users;"));
        delete dbClient;
    }
    // Helper to free memory
    void free_result(void* result) {
        if (result) {
            result_context_t* ctx = static_cast<result_context_t*>(result);
            if (ctx->result) mysql_free_result(ctx->result);
            delete ctx;
        }
    }
};

/**
 * @brief Test the execution of a valid SELECT query on the database client.
 *
 * This test verifies that the database client can successfully execute a valid SELECT query and return a non-null result.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 001
 * **Priority:** High
 * @n
 * **Pre-Conditions:** The `users` table exists with at least one entry.@n
 * **Dependencies:** None
 * **User Interaction:** None
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Define a valid Select query to be executed. | Query is defined. | Should be successful |
 * | 02 | Execute the defined query using the db_client_t instance. | execute should pass. | Should Pass |
 * | 03 | Verify the result of select query execution. | result should not be null | Assertion passes. | Should Pass |
 */
TEST_F(db_client_crud_Test, ExecuteValidSelectQuery) {
    std::cout << "Entering ExecuteValidSelectQuery test" << std::endl;
    const char* selectQuery = "SELECT id, username, email FROM users;";
    void* result = dbClient->execute(selectQuery);
    ASSERT_NE(result, nullptr) << "SELECT query failed.";
    free_result(result);
    std::cout << "Exiting ExecuteValidSelectQuery test" << std::endl;
}

/**
 * @brief Test the execution of an empty query in the database client.
 *
 * This test verifies that executing an empty query string returns a nullptr result, ensuring that the database client handles empty queries correctly.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 002@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Define an empty query string. | query = "" | Empty query string is defined | Should be successful |
 * | 02 | Execute the empty query using the db_client_t instance. | query = "" | Result is nullptr | Should Pass |
 * | 03 | Assert that the result of the empty query execution is nullptr. | result = nullptr | Assertion passes | Should Pass |
 */
TEST_F(db_client_t_Test, ExecuteEmptyQuery) {
    std::cout << "Entering ExecuteEmptyQuery test" << std::endl;
    const char* query = "";
    void* result = dbClient->execute(query);
    ASSERT_EQ(result, nullptr);
    std::cout << "Exiting ExecuteEmptyQuery test" << std::endl;
}

/**
 * @brief Test the execution of a null query in the database client
 *
 * This test verifies that the database client correctly handles the execution of a null query. 
 * It ensures that the function returns a null result when a null query is passed, which is a 
 * critical check to prevent potential crashes or undefined behavior in the application.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 003@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Define a null query | query = nullptr | None | Should be successful |
 * | 02 | Execute the null query using dbClient->execute | query = nullptr | result = nullptr | Should Pass |
 * | 03 | Assert that the result is null | result = nullptr | result = nullptr | Should Pass |
 */
TEST_F(db_client_t_Test, ExecuteNullQuery) {
    std::cout << "Entering ExecuteNullQuery test" << std::endl;
    const char* query = nullptr;
    void* result = dbClient->execute(query);
    ASSERT_EQ(result, nullptr);
    std::cout << "Exiting ExecuteNullQuery test" << std::endl;
}

/**
 * @brief Test to validate the behavior of the execute function with invalid SQL syntax
 *
 * This test checks if the execute function correctly handles and returns a null result when provided with an invalid SQL query. This is important to ensure that the function can gracefully handle syntax errors in SQL queries.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 004@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Execute the invalid SQL query | query = "SELEC * FROM users;", result = nullptr | result should be nullptr | Should Pass |
 * | 02 | Assert that the result is nullptr | result = nullptr | Assertion should pass | Should Pass |
 */
TEST_F(db_client_t_Test, ExecuteInvalidSQLSyntax) {
    std::cout << "Entering ExecuteInvalidSQLSyntax test" << std::endl;
    const char* query = "SELEC * FROM users;";
    void* result = dbClient->execute(query);
    ASSERT_EQ(result, nullptr);
    std::cout << "Exiting ExecuteInvalidSQLSyntax test" << std::endl;
}

/**
 * @brief Test to verify retrieving an integer from a valid column.
 *
 * This test checks the behavior of the `get_number` function when provided with a valid
 * result context pointing to the first entry of a query result. It ensures that the
 * function returns the expected integer value.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 005@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** The `users` table exists with at least one entry.@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Execute a SELECT query to retrieve the first user's ID | query = "SELECT id FROM users ORDER BY id ASC LIMIT 1;" | Result context is not null | Should Pass |
 * | 02 | Fetch the first row from the result | ctx->row = mysql_fetch_row(ctx->result) | Row is not null | Should Pass |
 * | 03 | Call `get_number` with the valid context and column index 1 | ctx, column_index = 1 | Returns integer value `1` | Expected ID of first row |
 * | 04 | Verify the returned value matches expected | id == 1 | Assertion passes | Should Pass |
 */
TEST_F(db_client_crud_Test, GetNumberValidColumn) {
    std::cout << "Entering GetNumberValidColumn test" << std::endl;

    // Step 1: Execute SELECT query
    void* result = dbClient->execute("SELECT id FROM users ORDER BY id ASC LIMIT 1;");
    ASSERT_NE(result, nullptr);
    // Step 2: Fetch first row
    result_context_t* ctx = static_cast<result_context_t*>(result);
    ctx->row = mysql_fetch_row(ctx->result);
    ASSERT_NE(ctx->row, nullptr);
    // Step 3: Retrieve number from valid column
    int id = dbClient->get_number(ctx, 1);
    EXPECT_EQ(id, 1);
    // Cleanup
    free_result(result);
    std::cout << "Exiting GetNumberValidColumn test" << std::endl;
}

/**
 * @brief Test to verify the behavior of retrieving an integer from an invalid context
 *
 * This test checks the behavior of the `get_number` function when provided with an invalid context. 
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 006@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Define an invalid context | invalid_ctx = nullptr | None | Should be successful |
 * | 02 | Call `get_number` with invalid context | invalid_ctx = nullptr, number = 2 | Program terminates (assertion failure) | Checked using EXPECT_DEATH |
 * | 03 | Verify that the test correctly detects the invalid access. | — | Assertion triggers; test passes | Handled by EXPECT_DEATH |
 */
TEST_F(db_client_t_Test, RetrieveIntegerFromInvalidContext) {
    std::cout << "Entering RetrieveIntegerFromInvalidContext test" << std::endl;
    void* invalid_ctx = nullptr;
    EXPECT_DEATH(dbClient->get_number(invalid_ctx, 2), ".*");
    std::cout << "Exiting RetrieveIntegerFromInvalidContext test" << std::endl;
}
/**
 * @brief Test to verify the behavior of `get_number` when called on a non-numeric column
 *
 * This test checks that the `get_number` function correctly handles a column that contains
 * non-numeric data. When attempting to retrieve a number from such a column, the function
 * should return `0`.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 007@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** The `users` table exists with at least one entry, containing both `id` (numeric) and `username` (string) columns.@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Execute a SELECT query to retrieve the first user's ID and username | query = "SELECT id, username FROM users ORDER BY id ASC LIMIT 1;" | Result context is not null | Should Pass |
 * | 02 | Fetch the first row from the result | ctx->row = mysql_fetch_row(ctx->result) | Row is not null | Should Pass |
 * | 03 | Call `get_number` on the second column (non-numeric) | ctx, column_index = 2 | Returns 0 | Non-numeric column handled correctly |
 * | 04 | Verify that the returned value is 0 | value == 0 | Assertion passes | Should Pass |
 */
TEST_F(db_client_crud_Test, GetNumberNonNumericColumn) {
    std::cout << "Entering GetNumberNonNumericColumn test" << std::endl;
    // Step 1: Execute SELECT query
    void* result = dbClient->execute("SELECT id, username FROM users ORDER BY id ASC LIMIT 1;");
    ASSERT_NE(result, nullptr);
    // Step 2: Fetch first row
    result_context_t* ctx = static_cast<result_context_t*>(result);
    ctx->row = mysql_fetch_row(ctx->result);
    ASSERT_NE(ctx->row, nullptr);
    // Step 3: Attempt to retrieve number from non-numeric column
    int value = dbClient->get_number(ctx, 2);
    EXPECT_EQ(value, 0);
    // Cleanup
    free_result(result);
    std::cout << "Exiting GetNumberNonNumericColumn test" << std::endl;
}

/**
 * @brief Test to verify the behavior of `get_number` when called with an invalid column index
 *
 * This test checks that the `get_number` function correctly handles an invalid column index
 * (0 in this case, which is out of bounds). The function should return `0` when the column
 * index is invalid.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 008@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** The `users` table exists with at least one entry.@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Execute a SELECT query to retrieve the first user's ID | query = "SELECT id FROM users ORDER BY id ASC LIMIT 1;" | Result context is not null | Should Pass |
 * | 02 | Call `get_number` with an invalid column index (0) | ctx, column_index = 0 | Returns 0 | Invalid column handled correctly |
 * | 03 | Verify that the returned value is 0 | number == 0 | Assertion passes | Should Pass |
 */
TEST_F(db_client_crud_Test, GetNumberInvalidColumn) {
    std::cout << "Entering GetNumberInvalidColumn test" << std::endl;
    // Step 1: Execute SELECT query
    void* result = dbClient->execute("SELECT id FROM users ORDER BY id ASC LIMIT 1;");
    ASSERT_NE(result, nullptr) << "execute() returned null — query failed or DB not initialized";
    // Step 2: Attempt to retrieve number from invalid column index
    int number = dbClient->get_number(result, 0);
    EXPECT_EQ(number, 0);
    // Cleanup
    free_result(result);
    std::cout << "Exiting GetNumberInvalidColumn test" << std::endl;
}

/**
 * @brief Test to verify retrieving a string from a valid column in the first row
 *
 * This test checks the behavior of the `get_string` function when provided with a valid
 * result context pointing to the first row of a query result. It ensures that the
 * function correctly retrieves a non-empty string.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 009@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** The `users` table exists with at least one row containing a `username` column.@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Execute a SELECT query to retrieve the first user's username | query = "SELECT username FROM users ORDER BY id ASC LIMIT 1;" | Result context is not null | Should Pass |
 * | 02 | Fetch the first row from the result | ctx->row = mysql_fetch_row(ctx->result) | Row is not null | Should Pass |
 * | 03 | Call `get_string` with valid context and column index 1 | ctx, column_index = 1, buffer[256] | Returns pointer to non-empty string | String successfully retrieved |
 * | 04 | Verify that the returned string is not empty | strlen(str) > 0 | Assertion passes | Should Pass |
 */
TEST_F(db_client_crud_Test, GetStringValidColumn) {
    std::cout << "Entering GetStringValidColumn test" << std::endl;
    // Step 1: Execute SELECT query
    void* result = dbClient->execute("SELECT username FROM users ORDER BY id ASC LIMIT 1;");
    ASSERT_NE(result, nullptr);
    // Step 2: Fetch first row
    result_context_t* ctx = static_cast<result_context_t*>(result);
    ctx->row = mysql_fetch_row(ctx->result);
    ASSERT_NE(ctx->row, nullptr) << "First row is null — query returned no data";
    // Step 3: Retrieve string from valid column
    char buffer[256] = {0};
    char* str = dbClient->get_string(result, buffer, 1);
    ASSERT_NE(str, nullptr);
    std::cout << "Retrieved username: " << str << std::endl;
    // Step 4: Verify string is non-empty
    EXPECT_GT(strlen(str), 0);
    // Cleanup
    free_result(result);
    std::cout << "Exiting GetStringValidColumn test" << std::endl;
}

/**
 * @brief Test to verify the behavior of `get_string` when called with an invalid column index
 *
 * This test checks that the `get_string` function correctly handles an invalid column index
 * (0 in this case, which is out of bounds). The function is expected to cause an assertion
 * failure or program termination when the column index is invalid.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 010@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** The `users` table exists with at least one row containing a `username` column.@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Execute a SELECT query to retrieve the first user's username | query = "SELECT username FROM users ORDER BY id ASC LIMIT 1;" | Result context is not null | Should Pass |
 * | 02 | Fetch the first row from the result | ctx->row = mysql_fetch_row(ctx->result) | Row is not null | Should Pass |
 * | 03 | Call `get_string` with invalid column index (0) | ctx, buffer[256], column_index = 0 | Program terminates / assertion triggers | Handled by EXPECT_DEATH |
 * | 04 | Verify that the invalid access is detected | — | Assertion triggers; test passes | Checked using EXPECT_DEATH |
 */
TEST_F(db_client_crud_Test, GetStringInvalidColumn) {
    std::cout << "Entering GetStringInvalidColumn test" << std::endl;
    // Step 1: Execute SELECT query
    void* result = dbClient->execute("SELECT username FROM users ORDER BY id ASC LIMIT 1;");
    ASSERT_NE(result, nullptr) << "execute() returned null — query failed or DB not initialized";
    // Step 2: Fetch first row
    result_context_t* ctx = static_cast<result_context_t*>(result);
    ctx->row = mysql_fetch_row(ctx->result);
    ASSERT_NE(ctx->row, nullptr);
    char buffer[256] = {0};
    // Step 3: Attempt to retrieve string from invalid column index
    EXPECT_DEATH({
        dbClient->get_string(result, buffer, 0);
    }, ".*");
    // Cleanup
    free_result(result);
    std::cout << "Exiting GetStringInvalidColumn test" << std::endl;
}

/**
 * @brief Test the retrieval of a string with null result and null context
 *
 * This test checks the behavior of the `get_string` method when both the result and context are null. 
 * It ensures that the method handles null inputs gracefully and returns a null pointer as expected.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 011@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Call get_string with null result and null context | result = nullptr, context = nullptr, size = 0 | result = nullptr | Should Pass |
 */
TEST_F(db_client_t_Test, RetrieveStringWithNullResultAndNullContext) {
    std::cout << "Entering RetrieveStringWithNullResultAndNullContext" << std::endl;
    char* result = dbClient->get_string(nullptr, nullptr, 0);
    ASSERT_EQ(result, nullptr);
    std::cout << "Exiting RetrieveStringWithNullResultAndNullContext" << std::endl;
}

/**
 * @brief Test the connection to a database with a valid database path.
 *
 * This test verifies that the db_client_t class can successfully initialize a connection to a database when provided with a valid database path. It ensures that the init function returns 0, indicating a successful connection.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 012@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize the database connection with a valid path | dbClient->init("bpi@root") | result = 0 | Should Pass |
 * | 02 | Verify the result of the initialization | EXPECT_EQ(result, 0) | result = 0 | Should be successful |
 */
TEST(db_client_tTest, ConnectWithValidDatabasePath) {
    std::cout << "Entering ConnectWithValidDatabasePath test" << std::endl;
    db_client_t* dbClient = new db_client_t();
    int result = dbClient->init("bpi@root");
    EXPECT_EQ(result, 0);
    delete dbClient;
    std::cout << "Exiting ConnectWithValidDatabasePath test" << std::endl;
}

/**
 * @brief Test to verify the behavior of db_client_t::init with an empty path
 *
 * This test checks the behavior of the db_client_t::init function when provided with an empty string as the path. The expected behavior is that the function should return an error code, specifically -1, indicating that the initialization failed due to the invalid input.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 013@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Call db_client_t::init with an empty path | path = "" | result = -1 | Should Pass |
 * | 02 | Verify the result of the init function | result = -1 | EXPECT_EQ(result, -1) | Should be successful |
 */
TEST(db_client_tTest, ConnectWithEmptyPath) {
    std::cout << "Entering ConnectWithEmptyPath test" << std::endl;
    db_client_t* dbClient = new db_client_t();
    int result = dbClient->init("");
    EXPECT_EQ(result, -1);
    delete dbClient;
    std::cout << "Exiting ConnectWithEmptyPath test" << std::endl;
}

/**
 * @brief Test the database client initialization with a path containing special characters.
 *
 * This test verifies that the database client can successfully initialize when provided with a database path that includes special characters. This is important to ensure that the client can handle paths with various characters without errors.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 014@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize the database client with a path containing special characters. | path = "bpi@root@#$.db" | result should be -1 | Should Pass |
 * | 02 | Verify that the initialization result is -1. | result = -1 | Should pass. | Should Pass |
 */
TEST(db_client_tTest, ConnectWithPathContainingSpecialCharacters) {
    std::cout << "Entering ConnectWithPathContainingSpecialCharacters test" << std::endl;
    db_client_t* dbClient = new db_client_t();
    int result = dbClient->init("bpi@root@#$.db");
    EXPECT_EQ(result, -1);
    delete dbClient;
    std::cout << "Exiting ConnectWithPathContainingSpecialCharacters test" << std::endl;
}

/**
 * @brief Test to verify the behavior of `next_result` on a valid context with rows
 *
 * This test checks that the `next_result` function correctly advances the result context
 * to the first row when the query returns multiple rows. The function should return `true`
 * if a row is available.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 015@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** The `users` table exists with at least one row.@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Execute a SELECT query returning multiple rows | query = "SELECT username FROM users ORDER BY id ASC;" | Result context is not null | Should Pass |
 * | 02 | Call `next_result` to advance to the first row | ctx | Returns true | Row exists |
 * | 03 | Verify that `next_result` indicates a valid row | hasRow == true | Assertion passes | Should Pass |
 */
TEST_F(db_client_crud_Test, NextResultValidContextHasRows) {
    std::cout << "Entering NextResultValidContextHasRows test" << std::endl;
    // Step 1: Execute SELECT query
    void* result = dbClient->execute("SELECT username FROM users ORDER BY id ASC;");
    ASSERT_NE(result, nullptr) << "execute() returned null — query failed";
    // Step 2: Advance to first row
    bool hasRow = dbClient->next_result(result);
    EXPECT_TRUE(hasRow) << "Expected next_result() to find first row";
    // Cleanup
    free_result(result);
    std::cout << "Exiting NextResultValidContextHasRows test" << std::endl;
}

/**
 * @brief Test to verify `next_result` behavior when there are no more rows
 *
 * This test checks that `next_result` correctly returns `false` when the result context
 * has been fully iterated and no additional rows are available.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 016@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** The `users` table exists with at least one row.@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Execute a SELECT query returning exactly one row | query = "SELECT username FROM users WHERE id = 1;" | Result context is not null | Should Pass |
 * | 02 | Call `next_result` to advance to first row | ctx | Returns true | Row exists |
 * | 03 | Call `next_result` again | ctx | Returns false | No more rows; context freed |
 */
TEST_F(db_client_crud_Test, NextResultNoMoreRows) {
    std::cout << "Entering NextResultNoMoreRows test" << std::endl;

    void* result = dbClient->execute("SELECT username FROM users WHERE id = 1;");
    ASSERT_NE(result, nullptr);
    bool hasRow = dbClient->next_result(result);
    EXPECT_TRUE(hasRow) << "Expected first row to be available";
    bool hasNext = dbClient->next_result(result);
    EXPECT_FALSE(hasNext) << "Expected no more rows";
    std::cout << "Exiting NextResultNoMoreRows test" << std::endl;
}

/**
 * @brief Test to verify `next_result` behavior on an invalid/freed context
 *
 * This test ensures that calling `next_result` on a context that has already been fully
 * iterated (and freed) triggers a program crash (use-after-free), which is caught using
 * `EXPECT_DEATH`.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 017@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** The `users` table exists with at least two rows.@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Execute a SELECT query returning two rows | query = "SELECT username FROM users ORDER BY id ASC LIMIT 2;" | Result context is not null | Should Pass |
 * | 02 | Call `next_result` to advance to first row | ctx | Returns true | Row exists |
 * | 03 | Call `next_result` to advance to second row | ctx | Returns true | Row exists |
 * | 04 | Call `next_result` when no more rows | ctx | Returns false | Context freed |
 * | 05 | Call `next_result` on freed context | ctx | Program terminates / assertion triggers | Checked using EXPECT_DEATH |
 */
TEST_F(db_client_crud_Test, NextResultInvalidContext) {
    std::cout << "Entering NextResultInvalidContext test" << std::endl;
    void* result = dbClient->execute("SELECT username FROM users ORDER BY id ASC LIMIT 2;");
    ASSERT_NE(result, nullptr) << "execute() returned null — query failed";
    bool first = dbClient->next_result(result);
    EXPECT_TRUE(first) << "Expected first row to be available";
    bool second = dbClient->next_result(result);
    EXPECT_TRUE(second) << "Expected second row to be available";
    bool third = dbClient->next_result(result);
    EXPECT_FALSE(third) << "Expected no more rows; context should now be freed";
    EXPECT_DEATH({
        dbClient->next_result(result);
    }, ".*");

    std::cout << "Exiting NextResultInvalidContext test" << std::endl;
}

/**
 * @brief Test to verify the behavior of next_result when the context is null
 *
 * This test checks the behavior of the db_client_t::next_result method when a null context is passed. 
 * It ensures that the method returns false, indicating that the operation cannot proceed with a null context.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 018@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Set the context to null | ctx = nullptr | None | Should be successful |
 * | 02 | Call next_result with null context | ctx = nullptr | result = false | Should Pass |
 */
TEST_F(db_client_t_Test, NullResultContext) {
    std::cout << "Entering NullResultContext test" << std::endl;
    void* ctx = nullptr;
    bool result = dbClient->next_result(ctx);
    EXPECT_FALSE(result);
    std::cout << "Exiting NullResultContext test" << std::endl;
}

/**
 * @brief Test to verify the recreation of the database with a valid connection
 *
 * This test ensures that the database can be successfully recreated when a valid connection path is provided. It initializes the database client, recreates the database, and verifies the result.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 019@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize the database with a valid path | dbClient->init("bpi@root") | Return value = 0 | Should Pass |
 * | 02 | Recreate the database | dbClient->recreate_db() | Return value = 0 | Should Pass |
 */
TEST_F(db_client_t_Test, RecreateDatabaseWithValidConnection) {
    std::cout << "Entering RecreateDatabaseWithValidConnection test" << std::endl;
    int result = dbClient->recreate_db();
    EXPECT_EQ(result, 0);
    std::cout << "Exiting RecreateDatabaseWithValidConnection test" << std::endl;
}

/**
 * @brief Test the recreation of the database with an invalid connection path.
 *
 * This test verifies that the database client correctly handles the scenario where the database is attempted to be recreated with an invalid connection path. It ensures that the initialization fails and the recreation of the database also fails.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 020
 * **Priority:** High
 * @n
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Set up the db_client_t instance | None | None | Done by Pre-requisite SetUp function |
 * | 02 | Initialize the database client with an invalid path | invalid_path!@# | Non-zero return value | Should Fail |
 * | 03 | Attempt to recreate the database | None | return value: -1 | Should Fail |
 * | 04 | Tear down the db_client_t instance | None | None | Done by Pre-requisite TearDown function |
 */
TEST(db_client_tTest, RecreateDatabaseWithInvalidConnection) {
    std::cout << "Entering RecreateDatabaseWithInvalidConnection test" << std::endl;
    db_client_t* dbClient = new db_client_t();
    EXPECT_NE(dbClient->init("invalid_path!@#"), 0);
    int result = dbClient->recreate_db();
    EXPECT_EQ(result, -1);
    delete dbClient;
    std::cout << "Exiting RecreateDatabaseWithInvalidConnection test" << std::endl;
}

/**
 * @brief Verify that the default construction of db_client_t initializes its internal members to NULL
 *
 * This test invokes the default constructor of db_client_t and verifies that its internal members (m_driver and m_con) are set to NULL. The test ensures that no exceptions are thrown during construction and that pointer arithmetic confirms the internal state.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 021@n
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Invoke the default constructor of db_client_t and access internal members (m_driver, m_con) via pointer arithmetic | constructor = default | db_client_t instance is created with m_driver == nullptr and m_con == nullptr; assertions (EXPECT_EQ) pass without exceptions | Should Pass |
 */
TEST(db_client_tTest, DefaultConstruction)
{
    std::cout << "Entering DefaultConstruction test" << std::endl;
    // Invoking the default constructor and ensuring no exception is thrown.
    EXPECT_NO_THROW({
        db_client_t client;
        std::cout << "Invoked db_client_t::db_client_t() constructor." << std::endl;
    });
    std::cout << "Exiting DefaultConstruction test" << std::endl;
}

/**
 * @brief Verify that db_client_t destructor correctly releases allocated database resources
 *
 * This test ensures that when a db_client_t object goes out of scope, its destructor is invoked automatically and effectively releases the internal database resources without throwing any exceptions. The test verifies that the internal state modifications related to m_driver and m_con are properly handled.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 022@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                                                   | Test Data                                   | Expected Result                                                                                           | Notes       |
 * | :--------------: | --------------------------------------------------------------------------------------------- | ------------------------------------------- | --------------------------------------------------------------------------------------------------------- | ----------- |
 * | 01               | Invoke the default constructor of db_client_t and allow the object to go out of scope triggering the destructor | constructor = default, scope = automatic    | Destructor should release database resources without throwing an exception; internal state changes occur as expected | Should Pass |
 */
TEST(db_client_tTest, DestructorReleasesDatabaseResourcesCorrectly) {
    std::cout << "Entering Destructor releases database resources correctly test" << std::endl;
    EXPECT_NO_THROW({
        std::cout << "Invoking db_client_t default constructor." << std::endl;
        {
            db_client_t client;
            std::cout << "db_client_t object created successfully." << std::endl;
        }
        std::cout << "db_client_t object went out of scope; destructor should have been invoked automatically." << std::endl;
    });
    std::cout << "Exiting Destructor releases database resources correctly test" << std::endl;
}
