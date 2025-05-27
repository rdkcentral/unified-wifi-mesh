/*
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
#include "db_column.h"


/**
* @brief Test to verify the assignment operator for db_column_t class
*
* This test checks if the assignment operator correctly assigns the values from one db_column_t object to another.@n
*
* **Test Group ID:** Basic: 01@n
* **Test Case ID:** 001@n
* **Priority:** High@n
* @n
* **Pre-Conditions:** None@n
* **Dependencies:** None@n
* **User Interaction:** None@n
* @n
* **Test Procedure:**@n
* | Variation / Step | Description | Test Data |Expected Result |Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01| Create a db_column_t object with specific values | col1("column1", db_data_type_int, 10) | Object col1 should be created with name "column1", type db_data_type_int, and type_args 10 | Should be successful |
* | 02| Create a default db_column_t object | col2 | Object col2 should be created with default values | Should be successful |
* | 03| Assign col1 to col2 | col2 = col1 | col2 should have the same values as col1 | Should Pass |
* | 04| Check if col2 has the correct name | col2.m_name == "column1" | col2.m_name should be "column1" | Should Pass |
* | 05| Check if col2 has the correct type | col2.m_type == db_data_type_int | col2.m_type should be db_data_type_int | Should Pass |
* | 06| Check if col2 has the correct type_args | col2.m_type_args == 10 | col2.m_type_args should be 10 | Should Pass |
*/
TEST(db_column_tTest, AssignValidDbColumn) {
    std::cout << "Entering AssignValidDbColumn" << std::endl;
    db_column_t col1("column1", db_data_type_int, 10);
    db_column_t col2;
    col2 = col1;
    EXPECT_EQ(col2.m_name, "column1");
    EXPECT_EQ(col2.m_type, db_data_type_int);
    EXPECT_EQ(col2.m_type_args, 10);
    std::cout << "Exiting AssignValidDbColumn" << std::endl;
}

/**
* @brief Test to verify the assignment operator for db_column_t with an empty name
*
* This test checks the assignment operator of the db_column_t class when the source object has an empty name. 
* It ensures that the target object correctly copies the name, type, and type arguments from the source object.
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
* | 01 | Create a db_column_t object with an empty name | name = "", type = db_data_type_varchar, type_args = 255 | Object created successfully | Should be successful |
* | 02 | Create a default db_column_t object | None | Object created successfully | Should be successful |
* | 03 | Assign the first object to the second object | col2 = col1 | col2.m_name = "", col2.m_type = db_data_type_varchar, col2.m_type_args = 255 | Should Pass |
* | 04 | Verify the name of the second object | col2.m_name | "" | Should Pass |
* | 05 | Verify the type of the second object | col2.m_type | db_data_type_varchar | Should Pass |
* | 06 | Verify the type arguments of the second object | col2.m_type_args | 255 | Should Pass |
*/
TEST(db_column_tTest, AssignEmptyNameDbColumn) {
    std::cout << "Entering AssignEmptyNameDbColumn" << std::endl;
    db_column_t col1("", db_data_type_varchar, 255);
    db_column_t col2;
    col2 = col1;
    EXPECT_EQ(col2.m_name, "");
    EXPECT_EQ(col2.m_type, db_data_type_varchar);
    EXPECT_EQ(col2.m_type_args, 255);
    std::cout << "Exiting AssignEmptyNameDbColumn" << std::endl;
}

/**
* @brief Test to verify the assignment operator for db_column_t with a maximum length column name
*
* This test checks the assignment operator of the db_column_t class when assigning a column with a very long name that exceeds normal length. It ensures that the name, type, and type arguments are correctly assigned.
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
* | Variation / Step | Description | Test Data |Expected Result |Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01| Create a db_column_t object with a long name | input: name = "a_very_long_column_name_exceeding_normal_length", type = db_data_type_text, type_args = 0 | Object should be created successfully | Should be successful |
* | 02| Assign the created object to another db_column_t object | input: col2 = col1 | col2 should have the same name, type, and type_args as col1 | Should Pass |
* | 03| Verify the name of the assigned object | input: col2.m_name | Expected: "a_very_long_column_name_exceeding_normal_length" | Should Pass |
* | 04| Verify the type of the assigned object | input: col2.m_type | Expected: db_data_type_text | Should Pass |
* | 05| Verify the type arguments of the assigned object | input: col2.m_type_args | Expected: 0 | Should Pass |
*/
TEST(db_column_tTest, AssignMaxLengthNameDbColumn) {
    std::cout << "Entering AssignMaxLengthNameDbColumn" << std::endl;
    db_column_t col1("a_very_long_column_name_exceeding_normal_length", db_data_type_text, 0);
    db_column_t col2;
    col2 = col1;
    EXPECT_EQ(col2.m_name, "a_very_long_column_name_exceeding_normal_length");
    EXPECT_EQ(col2.m_type, db_data_type_text);
    EXPECT_EQ(col2.m_type_args, 0);
    std::cout << "Exiting AssignMaxLengthNameDbColumn" << std::endl;
}

/**
* @brief Test the assignment operator for db_column_t with different data types
*
* This test checks the assignment operator of the db_column_t class by assigning a column with a float data type to another column and verifying that all attributes are correctly copied.@n
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
* | Variation / Step | Description | Test Data |Expected Result |Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01| Create a db_column_t object with float data type | col1("column2", db_data_type_float, 0) | Object col1 should be created successfully | Should be successful |
* | 02| Create a default db_column_t object | db_column_t col2 | Object col2 should be created successfully | Should be successful |
* | 03| Assign col1 to col2 | col2 = col1 | col2 should have the same attributes as col1 | Should Pass |
* | 04| Check the name attribute of col2 | EXPECT_EQ(col2.m_name, "column2") | col2.m_name should be "column2" | Should Pass |
* | 05| Check the type attribute of col2 | EXPECT_EQ(col2.m_type, db_data_type_float) | col2.m_type should be db_data_type_float | Should Pass |
* | 06| Check the type_args attribute of col2 | EXPECT_EQ(col2.m_type_args, 0) | col2.m_type_args should be 0 | Should Pass |
*/
TEST(db_column_tTest, AssignDifferentDataTypesDbColumn) {
    std::cout << "Entering AssignDifferentDataTypesDbColumn" << std::endl;
    db_column_t col1("column2", db_data_type_float, 0);
    db_column_t col2;
    col2 = col1;
    EXPECT_EQ(col2.m_name, "column2");
    EXPECT_EQ(col2.m_type, db_data_type_float);
    EXPECT_EQ(col2.m_type_args, 0);
    std::cout << "Exiting AssignDifferentDataTypesDbColumn" << std::endl;
}

/**
* @brief Test the assignment operator for db_column_t with zero type arguments
*
* This test verifies that the assignment operator correctly assigns a db_column_t object with zero type arguments to another db_column_t object.@n
*
* **Test Group ID:** Basic: 01@n
* **Test Case ID:** 005@n
* **Priority:** High@n
* @n
* **Pre-Conditions:** None@n
* **Dependencies:** None@n
* **User Interaction:** None@n
* @n
* **Test Procedure:**@n
* | Variation / Step | Description | Test Data |Expected Result |Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01| Create a db_column_t object with name "column4", type db_data_type_char, and type_args 0 | col1("column4", db_data_type_char, 0) | Object col1 should be created successfully | Should be successful |
* | 02| Create a default db_column_t object | col2 | Object col2 should be created successfully | Should be successful |
* | 03| Assign col1 to col2 | col2 = col1 | col2 should have the same values as col1 | Should Pass |
* | 04| Check if col2.m_name is "column4" | col2.m_name | "column4" | Should Pass |
* | 05| Check if col2.m_type is db_data_type_char | col2.m_type | db_data_type_char | Should Pass |
* | 06| Check if col2.m_type_args is 0 | col2.m_type_args | 0 | Should Pass |
*/
TEST(db_column_tTest, AssignZeroTypeArgsDbColumn) {
    std::cout << "Entering AssignZeroTypeArgsDbColumn" << std::endl;
    db_column_t col1("column4", db_data_type_char, 0);
    db_column_t col2;
    col2 = col1;
    EXPECT_EQ(col2.m_name, "column4");
    EXPECT_EQ(col2.m_type, db_data_type_char);
    EXPECT_EQ(col2.m_type_args, 0);
    std::cout << "Exiting AssignZeroTypeArgsDbColumn" << std::endl;
}

/**
* @brief Test for self-assignment of db_column_t object
*
* This test checks the self-assignment operation of a db_column_t object to ensure that the object remains unchanged after assigning it to itself.@n
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
* | 01 | Create a db_column_t object | name = "column6", type = db_data_type_date, type_args = 0 | Object should be created successfully | Should be successful |
* | 02 | Assign the object to itself | col1 = col1 | Object should remain unchanged | Should Pass |
* | 03 | Check the name of the column | col1.m_name | "column6" | Should Pass |
* | 04 | Check the type of the column | col1.m_type | db_data_type_date | Should Pass |
* | 05 | Check the type arguments of the column | col1.m_type_args | 0 | Should Pass |
*/
TEST(db_column_tTest, SelfAssignmentDbColumn) {
    std::cout << "Entering SelfAssignmentDbColumn" << std::endl;
    db_column_t col1("column6", db_data_type_date, 0);
    col1 = col1;
    EXPECT_EQ(col1.m_name, "column6");
    EXPECT_EQ(col1.m_type, db_data_type_date);
    EXPECT_EQ(col1.m_type_args, 0);
    std::cout << "Exiting SelfAssignmentDbColumn" << std::endl;
}

/**
* @brief Test the assignment operator for db_column_t with special characters in the column name
*
* This test verifies that the assignment operator correctly assigns a db_column_t object with a name containing special characters to another db_column_t object. It ensures that all attributes (name, type, and type_args) are properly copied.@n
*
* **Test Group ID:** Basic: 01@n
* **Test Case ID:** 007@n
* **Priority:** High@n
* @n
* **Pre-Conditions:** None@n
* **Dependencies:** None@n
* **User Interaction:** None@n
* @n
* **Test Procedure:**@n
* | Variation / Step | Description | Test Data |Expected Result |Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01| Create a db_column_t object with special characters in the name | input: name = "col@mn#7$", type = db_data_type_timestamp, type_args = 0 | Object should be created successfully | Should be successful |
* | 02| Assign the created object to another db_column_t object | input: col2 = col1 | col2 should have the same attributes as col1 | Should Pass |
* | 03| Verify the name attribute of the assigned object | input: col2.m_name | Expected: "col@mn#7$" | Should Pass |
* | 04| Verify the type attribute of the assigned object | input: col2.m_type | Expected: db_data_type_timestamp | Should Pass |
* | 05| Verify the type_args attribute of the assigned object | input: col2.m_type_args | Expected: 0 | Should Pass |
*/
TEST(db_column_tTest, AssignSpecialCharsNameDbColumn) {
    std::cout << "Entering AssignSpecialCharsNameDbColumn" << std::endl;
    db_column_t col1("col@mn#7$", db_data_type_timestamp, 0);
    db_column_t col2;
    col2 = col1;
    EXPECT_EQ(col2.m_name, "col@mn#7$");
    EXPECT_EQ(col2.m_type, db_data_type_timestamp);
    EXPECT_EQ(col2.m_type_args, 0);
    std::cout << "Exiting AssignSpecialCharsNameDbColumn" << std::endl;
}

/**
* @brief Test to verify the assignment operator for db_column_t when the name is null.
*
* This test checks the behavior of the assignment operator for the db_column_t class when the source object has a null name. 
* It ensures that the destination object correctly copies the null name, type, and type arguments from the source object.
*
* **Test Group ID:** Basic: 01@n
* **Test Case ID:** 008@n
* **Priority:** High@n
* @n
* **Pre-Conditions:** None@n
* **Dependencies:** None@n
* **User Interaction:** None@n
* @n
* **Test Procedure:**@n
* | Variation / Step | Description | Test Data |Expected Result |Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01| Create a db_column_t object with null name | name = nullptr, type = db_data_type_binary, type_args = 0 | Object created successfully | Should be successful |
* | 02| Create a default db_column_t object | None | Object created successfully | Should be successful |
* | 03| Assign the first object to the second object | col2 = col1 | col2.m_name = nullptr, col2.m_type = db_data_type_binary, col2.m_type_args = 0 | Should Pass |
* | 04| Verify the name of the second object | col2.m_name | nullptr | Should Pass |
* | 05| Verify the type of the second object | col2.m_type | db_data_type_binary | Should Pass |
* | 06| Verify the type arguments of the second object | col2.m_type_args | 0 | Should Pass |
*/
TEST(db_column_tTest, AssignNullNameDbColumn) {
    std::cout << "Entering AssignNullNameDbColumn" << std::endl;
    db_column_t col1(nullptr, db_data_type_binary, 0);
    db_column_t col2;
    col2 = col1;
    EXPECT_EQ(col2.m_name, nullptr);
    EXPECT_EQ(col2.m_type, db_data_type_binary);
    EXPECT_EQ(col2.m_type_args, 0);
    std::cout << "Exiting AssignNullNameDbColumn" << std::endl;
}

/**
* @brief Test to validate the creation of a database column with valid name, type, and arguments.
*
* This test checks if a database column object is correctly initialized with a valid name, type, and arguments. It ensures that the member variables of the column object match the expected values provided during its creation.
*
* **Test Group ID:** Basic: 01@n
* **Test Case ID:** 009@n
* **Priority:** High@n
* @n
* **Pre-Conditions:** None@n
* **Dependencies:** None@n
* **User Interaction:** None@n
* @n
* **Test Procedure:**@n
* | Variation / Step | Description | Test Data | Expected Result | Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01 | Initialize db_column_t with valid name, type, and args | name = "column1", type = db_data_type_integer, args = 10 | Column object should be initialized with the provided values | Should Pass |
* | 02 | Check if column.m_name matches the expected name | name = "column1" | EXPECT_EQ(column.m_name, name) | Should Pass |
* | 03 | Check if column.m_type matches the expected type | type = db_data_type_integer | EXPECT_EQ(column.m_type, type) | Should Pass |
* | 04 | Check if column.m_type_args matches the expected args | args = 10 | EXPECT_EQ(column.m_type_args, args) | Should Pass |
*/
TEST(db_column_tTest, ValidNameValidTypeValidArgs) {
    std::cout << "Entering ValidNameValidTypeValidArgs test";
    db_column_name_t name = "column1";
    db_data_type_t type = db_data_type_integer;
    db_data_type_args_t args = 10;
    db_column_t column(name, type, args);
    EXPECT_EQ(column.m_name, name);
    EXPECT_EQ(column.m_type, type);
    EXPECT_EQ(column.m_type_args, args);
    std::cout << "Exiting ValidNameValidTypeValidArgs test";
}

/**
* @brief Test the creation of a db_column_t object with valid name, type, and zero arguments.
*
* This test verifies that a db_column_t object is correctly initialized when provided with a valid column name, a valid data type, and zero arguments. It checks that the member variables of the db_column_t object match the expected values.
*
* **Test Group ID:** Basic: 01@n
* **Test Case ID:** 010@n
* **Priority:** High@n
* @n
* **Pre-Conditions:** None@n
* **Dependencies:** None@n
* **User Interaction:** None@n
* @n
* **Test Procedure:**@n
* | Variation / Step | Description | Test Data |Expected Result |Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01| Initialize db_column_t with valid name, type, and zero arguments | name = "column2", type = db_data_type_varchar, args = 0 | db_column_t object is created with m_name = "column2", m_type = db_data_type_varchar, m_type_args = 0 | Should Pass |
* | 02| Check if m_name is correctly assigned | name = "column2" | m_name should be "column2" | Should Pass |
* | 03| Check if m_type is correctly assigned | type = db_data_type_varchar | m_type should be db_data_type_varchar | Should Pass |
* | 04| Check if m_type_args is correctly assigned | args = 0 | m_type_args should be 0 | Should Pass |
*/
TEST(db_column_tTest, ValidNameValidTypeZeroArgs) {
    std::cout << "Entering ValidNameValidTypeZeroArgs test";
    db_column_name_t name = "column2";
    db_data_type_t type = db_data_type_varchar;
    db_data_type_args_t args = 0;
    db_column_t column(name, type, args);
    EXPECT_EQ(column.m_name, name);
    EXPECT_EQ(column.m_type, type);
    EXPECT_EQ(column.m_type_args, args);
    std::cout << "Exiting ValidNameValidTypeZeroArgs test";
}

/**
* @brief Test to validate the creation of a db_column_t object with an empty name, valid type, and valid arguments.
*
* This test checks the initialization of a db_column_t object when provided with an empty name, a valid data type, and valid arguments. It ensures that the object is correctly initialized with the provided values and that the member variables match the expected values.
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
* | 01 | Initialize db_column_t with empty name, valid type, and valid args | name = "", type = db_data_type_text, args = 5 | Object should be initialized with provided values | Should Pass |
* | 02 | Check if column.m_name matches the provided name | name = "" | EXPECT_EQ(column.m_name, name) | Should Pass |
* | 03 | Check if column.m_type matches the provided type | type = db_data_type_text | EXPECT_EQ(column.m_type, type) | Should Pass |
* | 04 | Check if column.m_type_args matches the provided args | args = 5 | EXPECT_EQ(column.m_type_args, args) | Should Pass |
*/
TEST(db_column_tTest, EmptyNameValidTypeValidArgs) {
    std::cout << "Entering EmptyNameValidTypeValidArgs test";
    db_column_name_t name = "";
    db_data_type_t type = db_data_type_text;
    db_data_type_args_t args = 5;
    db_column_t column(name, type, args);
    EXPECT_EQ(column.m_name, name);
    EXPECT_EQ(column.m_type, type);
    EXPECT_EQ(column.m_type_args, args);
    std::cout << "Exiting EmptyNameValidTypeValidArgs test";
}

/**
* @brief Test the creation of a db_column_t object with valid name, type, and boundary arguments.
*
* This test verifies that a db_column_t object is correctly initialized when provided with a valid column name, valid data type, and boundary arguments. It checks that the member variables of the db_column_t object match the expected values.
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
* | Variation / Step | Description | Test Data |Expected Result |Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01| Initialize db_column_t object with valid name, type, and boundary arguments | name = "column7", type = db_data_type_date, args = 1 | db_column_t object should be initialized with the provided values | Should Pass |
* | 02| Check if the name is correctly assigned | column.m_name | Expected: "column7" | Should be successful |
* | 03| Check if the type is correctly assigned | column.m_type | Expected: db_data_type_date | Should be successful |
* | 04| Check if the type arguments are correctly assigned | column.m_type_args | Expected: 1 | Should be successful |
*/
TEST(db_column_tTest, ValidNameValidTypeBoundaryArgs1) {
    std::cout << "Entering ValidNameValidTypeBoundaryArgs1 test";
    db_column_name_t name = "column7";
    db_data_type_t type = db_data_type_date;
    db_data_type_args_t args = 1;
    db_column_t column(name, type, args);
    EXPECT_EQ(column.m_name, name);
    EXPECT_EQ(column.m_type, type);
    EXPECT_EQ(column.m_type_args, args);
    std::cout << "Exiting ValidNameValidTypeBoundaryArgs1 test";
}

/**
* @brief Test the creation of a database column with valid name, valid type, and boundary arguments
*
* This test verifies that a database column can be created with a valid name, a valid data type, and boundary arguments. It checks if the column's name, type, and type arguments are correctly set and match the expected values.
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
* | 01 | Create a db_column_t object with valid name, type, and boundary arguments | name = "column8", type = db_data_type_timestamp, args = UINT_MAX - 1 | The column's name, type, and type arguments should match the input values | Should Pass |
*/
TEST(db_column_tTest, ValidNameValidTypeBoundaryArgs2) {
    std::cout << "Entering ValidNameValidTypeBoundaryArgs2 test";
    db_column_name_t name = "column8";
    db_data_type_t type = db_data_type_timestamp;
    db_data_type_args_t args = (1ULL << 32) - 1;
    db_column_t column(name, type, args);
    EXPECT_EQ(column.m_name, name);
    EXPECT_EQ(column.m_type, type);
    EXPECT_EQ(column.m_type_args, args);
    std::cout << "Exiting ValidNameValidTypeBoundaryArgs2 test";
}