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
#include "cjson/cJSON.h"
#include "cjson_util.h"
#include <string>
#include <iostream>

/**
 * @brief Verify that get_cjson_blob_size returns 0 when provided with a NULL JSON pointer
 *
 * This test case confirms that the get_cjson_blob_size function correctly handles a NULL input by returning 0.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 001@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                       | Test Data                                | Expected Result                                               | Notes      |
 * | :--------------: | ----------------------------------------------------------------- | ---------------------------------------- | ------------------------------------------------------------- | ---------- |
 * | 01               | Invoke get_cjson_blob_size with json set to nullptr                 | json = nullptr, output = 0                | API returns 0 and EXPECT_EQ check passes                      | Should Pass|
 */
TEST(CjsonUtils, GetBlobSizeNull) {
    const char* testName = "GetBlobSizeNull";
    std::cout << "Entering " << testName << " test" << std::endl;
    std::cout << "Invoking get_cjson_blob_size with json = NULL" << std::endl;
    EXPECT_EQ(cjson_utils::get_cjson_blob_size(nullptr), 0u);
    std::cout << "Exiting " << testName << " test" << std::endl;
}
/**
 * @brief Validate cjson_utils::stringify handling for NULL input
 *
 * This test validates that passing NULL to cjson_utils::stringify correctly returns an empty string. It ensures that the API gracefully handles null pointers without crashing or unexpected behavior.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 002
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                | Test Data                | Expected Result                                                      | Notes      |
 * | :--------------: | ------------------------------------------ | ------------------------ | -------------------------------------------------------------------- | ---------- |
 * | 01               | Invoke stringify with blob set to NULL     | blob = nullptr           | Return value is an empty string and assertion check passes           | Should Pass|
 */
TEST(CjsonUtils, StringifyNull) {
    const char* testName = "StringifyNull";
    std::cout << "Entering " << testName << " test" << std::endl;
    std::cout << "Invoking stringify with blob = NULL" << std::endl;
    EXPECT_EQ(cjson_utils::stringify(nullptr), "");
    std::cout << "Exiting " << testName << " test" << std::endl;
}
/**
 * @brief Verify that the serialization functions correctly process a simple JSON object
 *
 * This test creates a simple cJSON object with one key-value pair and then uses the get_cjson_blob_size and stringify APIs to compute the size and convert the object to a string, respectively. The test validates that the size returned is greater than zero, that it matches the size of the generated string, and that the output string contains the expected key. This ensures that basic object serialization is functioning as expected.@n
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 003@n
 * **Priority:** High@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Create a new cJSON object and validate its creation | No input, output: obj pointer = valid pointer | The JSON object is successfully created (obj != nullptr) | Should Pass |
 * | 02 | Add a string key-value pair ("k", "v") to the JSON object | Input: key = "k", value = "v", output: updated obj | The object now contains the key "k" with value "v" | Should be successful |
 * | 03 | Invoke get_cjson_blob_size and stringify on the JSON object | Input: obj pointer, output: len (size_t) and s (string) | get_cjson_blob_size returns a size > 0 and stringify returns a string with matching size | Should Pass |
 * | 04 | Check that the serialized string contains the expected key substring | Input: s (string), output: search result for "\"k\"" | The string contains the substring "\"k\"" and the length of the string equals the returned size len | Should Pass |
 * | 05 | Delete the JSON object to free memory | Input: obj pointer | JSON object is successfully deleted with no memory leaks | Should be successful |
 */
TEST(CjsonUtils, SerializeSimpleObject) {
    std::cout << "Entering SerializeSimpleObject test" << std::endl;
    cJSON *obj = cJSON_CreateObject();
    EXPECT_NE(obj, nullptr);
    cJSON_AddStringToObject(obj, "k", "v");
    std::cout << "Invoking get_cjson_blob_size and stringify on a simple object" << std::endl;
    size_t len = cjson_utils::get_cjson_blob_size(obj);
    std::string s = cjson_utils::stringify(obj);
    EXPECT_GT(len, 0u);
    EXPECT_EQ(len, s.size());
    EXPECT_NE(s.find("\"k\""), std::string::npos);    
    std::cout << "Invoked get_cjson_blob_size -> " << len << " bytes, stringify() size -> " << s.size() << std::endl;
    cJSON_Delete(obj);
    std::cout << "Exiting SerializeSimpleObject test" << std::endl;
}
/**
 * @brief Test the stringify function with unformatted option in cjson_utils
 *
 * This test validates that when a valid JSON object is created and populated with a numeric value, calling cjson_utils::stringify with the unformatted flag set to true returns a string that contains the expected numeric value. This ensures that the JSON serialization maintains the data integrity in unformatted mode.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 004@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Create a JSON object using cJSON_CreateObject and verify it is not null | output: obj = cJSON_CreateObject() | obj is not null | Should Pass |
 * | 02 | Add a number property "n" with the value 42 to the JSON object | input: key = "n", value = 42 | The JSON object contains the property "n" with value 42 | Should be successful |
 * | 03 | Invoke cjson_utils::stringify with unformatted flag set to true | input: obj, unformatted = true | Returns a JSON string representation including the numeric data | Should Pass |
 * | 04 | Validate that the returned string contains the value "42" | input: s (output from stringify) | s.find("42") is not std::string::npos | Should Pass |
 * | 05 | Delete the JSON object to free memory | input: obj passed to cJSON_Delete | JSON object is deleted without memory leak | Should be successful |
 */
TEST(CjsonUtils, StringifyUnformatted) {
    const char* testName = "StringifyUnformatted";
    std::cout << "Entering " << testName << " test" << std::endl;
    cJSON *obj = cJSON_CreateObject();
    EXPECT_NE(obj, nullptr);
    cJSON_AddNumberToObject(obj, "n", 42);    
    std::cout << "Invoking stringify with unformatted=true" << std::endl;
    std::string s = cjson_utils::stringify(obj, true);
    std::cout << "Invoked stringify(unformatted) -> " << s << std::endl;
    EXPECT_NE(s.find("42"), std::string::npos);
    cJSON_Delete(obj);
    std::cout << "Exiting " << testName << " test" << std::endl;
}
/**
 * @brief Validate nested JSON structure serialization and size calculation
 *
 * This test verifies that a nested JSON structure is correctly serialized into both formatted and compact string representations using the stringify function. It also checks that the helper function accurately calculates the size of the JSON blob. The test ensures that the formatted string contains newline characters while the compact string does not, and validates that the blob size matches the formatted string length.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 005@n
 * **Priority:** High@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Create the root JSON object. | No inputs; output: root pointer | root pointer should be non-null. | Should Pass |
 * | 02 | Create a JSON array intended to hold nested objects. | No inputs; output: array pointer | array pointer should be non-null. | Should Pass |
 * | 03 | Add three nested JSON objects to the array in a loop with incremental "idx" values. | Loop index: i = 0,1,2; key "idx" = corresponding value | Three objects added with keys "idx" set to 0, 1, and 2 respectively. | Should Pass |
 * | 04 | Add the JSON array to the root object using the key "items". | Input key: "items", value: array pointer | The root JSON object must contain an "items" array. | Should Pass |
 * | 05 | Serialize the JSON object into formatted and compact string representations. | Input: root object; Parameters: formatted flag false for formatted string, true for compact string | The formatted string must contain newline characters while the compact string must not. | Should Pass |
 * | 06 | Calculate the JSON blob size using the helper function and compare with the formatted string size. | Input: root object; Expected: formatted string size value | The blob size should be greater than 0 and equal to the formatted string size. | Should Pass |
 * | 07 | Clean up by deleting the root JSON object to free allocated memory. | Input: root pointer | JSON memory is freed without memory leaks. | Should be successful |
 */
TEST(CjsonUtils, NestedStructureFormattedVsUnformatted) {
    const char* testName = "NestedStructureFormattedVsUnformatted";
    std::cout << "Entering " << testName << " test" << std::endl;
    cJSON *root = cJSON_CreateObject();
    EXPECT_NE(root, nullptr);

    cJSON *arr = cJSON_CreateArray();
    EXPECT_NE(arr, nullptr);
    for (int i = 0; i < 3; ++i) {
        cJSON *o = cJSON_CreateObject();
        cJSON_AddNumberToObject(o, "idx", i);
        cJSON_AddItemToArray(arr, o);
    }
    cJSON_AddItemToObject(root, "items", arr);

    std::cout << "Invoking stringify(formatted), stringify(unformatted) and get_cjson_blob_size on nested structure" << std::endl;
    std::string formatted = cjson_utils::stringify(root, false);
    std::string compact   = cjson_utils::stringify(root, true);
    size_t size_via_helper = cjson_utils::get_cjson_blob_size(root);    
    EXPECT_GT(size_via_helper, 0u);
    EXPECT_EQ(size_via_helper, formatted.size());
    EXPECT_NE(formatted.find('\n'), std::string::npos);
    EXPECT_EQ(compact.find('\n'), std::string::npos);
    std::cout << "Formatted size: " << formatted.size() << ", Compact size: " << compact.size() << std::endl;
    cJSON_Delete(root);
    std::cout << "Exiting " << testName << " test" << std::endl;
}
/**
 * @brief Verify that escaped characters in JSON strings are preserved after serialization
 *
 * This test creates a JSON object, adds a string containing escaped characters 
 * (a double quote and a backslash) to the object, serializes the JSON object using 
 * the unformatted stringify function, and checks that the escaped characters are 
 * correctly preserved in the resulting string. This validates that the JSON 
 * serialization process handles escape sequences as expected.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 006@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                                          | Test Data                                                                                                  | Expected Result                                                                                            | Notes         |
 * | :--------------: | ---------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------- | ------------- |
 * | 01               | Create a JSON object using cJSON_CreateObject().                                                     | No input parameters                                                                                        | Should return a valid non-null pointer                                                                     | Should Pass   |
 * | 02               | Add a string with escaped characters ("quote\"and\\backslash") to the JSON object with key "s".      | input: obj pointer, key = "s", raw string = "quote\"and\\backslash"                                         | The key "s" is added to the JSON object with the corresponding string value                                | Should Pass   |
 * | 03               | Serialize the JSON object using cjson_utils::stringify with the unformatted flag activated.          | input: obj pointer, flag = true                                                                              | Returns a string representation of the JSON object that preserves the escaped characters                     | Should Pass   |
 * | 04               | Verify that the serialized string contains the escaped sequences for a double quote and a backslash. | input: serialized string s                                                                                   | The serialized string contains "\\\"" and "\\\\", indicating the escaped characters are correctly preserved | Should Pass   |
 * | 05               | Delete the JSON object using cJSON_Delete to free allocated memory.                                  | input: obj pointer                                                                                           | The JSON object is successfully deleted without memory leaks                                               | Should be successful |
 */
TEST(CjsonUtils, EscapedCharactersArePreserved) {
    const char* testName = "EscapedCharactersArePreserved";
    std::cout << "Entering " << testName << " test" << std::endl;
    cJSON *obj = cJSON_CreateObject();
    EXPECT_NE(obj, nullptr);
    const char *raw = "quote\"and\\backslash";
    cJSON_AddStringToObject(obj, "s", raw);    
    std::cout << "Invoking stringify(unformatted) to serialize escaped string" << std::endl;
    std::string s = cjson_utils::stringify(obj, true);
    std::cout << "Serialized: " << s << std::endl;
    EXPECT_NE(s.find("\\\""), std::string::npos);
    EXPECT_NE(s.find("\\\\"), std::string::npos);
    cJSON_Delete(obj);
    std::cout << "Exiting " << testName << " test" << std::endl;
}
/**
 * @brief Validate serialization of JSON object with boolean and null values
 *
 * This test verifies that a JSON object containing boolean and null values is correctly created and serialized.
 * It tests the addition of true, false, and null values to a JSON object and confirms that the serialized string
 * includes these values. This ensures that the cjson_utils::stringify method works as expected for these data types.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 007@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Create a JSON object using cJSON_CreateObject | No input | Returns a valid object pointer (not nullptr) | Should Pass |
 * | 02 | Add a boolean true to the JSON object with key "t" using cJSON_AddTrueToObject | key = "t", value = true | The key "t" is added with value true | Should Pass |
 * | 03 | Add a boolean false to the JSON object with key "f" using cJSON_AddFalseToObject | key = "f", value = false | The key "f" is added with value false | Should Pass |
 * | 04 | Add a null value to the JSON object with key "n" using cJSON_AddNullToObject | key = "n", value = null | The key "n" is added with value null | Should Pass |
 * | 05 | Serialize the JSON object using cjson_utils::stringify with unformatted output | input: obj pointer, unformatted = true | Returns a JSON string containing "true", "false", and "null" | Should Pass |
 * | 06 | Validate the serialized string contains "true", "false", and "null" using assertions | input: serialized string s | "true", "false", and "null" are present in the string | Should Pass |
 * | 07 | Delete the JSON object using cJSON_Delete | input: obj pointer | JSON object memory is freed | Should Pass |
 * | 08 | Log the exit of the test case | Output messages printed to console | Appropriate exit log messages are printed | Should be successful |
 */
TEST(CjsonUtils, BoolAndNullValues) {
    const char* testName = "BoolAndNullValues";
    std::cout << "Entering " << testName << " test" << std::endl;
    cJSON *obj = cJSON_CreateObject();
    EXPECT_NE(obj, nullptr);
    cJSON_AddTrueToObject(obj, "t");
    cJSON_AddFalseToObject(obj, "f");
    cJSON_AddNullToObject(obj, "n");        
    std::cout << "Invoking stringify(unformatted) to serialize booleans and null" << std::endl;
    std::string s = cjson_utils::stringify(obj, true);
    std::cout << "Serialized: " << s << std::endl;
    EXPECT_NE(s.find("true"), std::string::npos);
    EXPECT_NE(s.find("false"), std::string::npos);
    EXPECT_NE(s.find("null"), std::string::npos);
    cJSON_Delete(obj);
    std::cout << "Exiting " << testName << " test" << std::endl;
}
/**
 * @brief Verify that repeated calls to stringify produce identical outputs.
 *
 * This test verifies that invoking the cjson_utils::stringify function multiple times on the same JSON object produces the same string output. It ensures consistency and determinism of the JSON stringification process for a given input.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 008@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                                      | Test Data                                                        | Expected Result                                                                                 | Notes           |
 * | :--------------: | ------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------- | ----------------------------------------------------------------------------------------------- | --------------- |
 * | 01               | Create a JSON object using cJSON_CreateObject and verify that the returned object is not null.     | No input; expected output: obj != nullptr                        | Object creation returns a non-null pointer indicating successful allocation.                   | Should Pass     |
 * | 02               | Add a key-value pair ("k", "v") to the JSON object using cJSON_AddStringToObject.                 | input: key = "k", value = "v"                                      | The JSON object should contain the key "k" with the associated value "v".                       | Should be successful |
 * | 03               | Invoke cjson_utils::stringify on the JSON object for the first time to obtain its string representation. | input: obj, format = true; output: s1                              | s1 contains a valid and correctly formatted JSON string representing the object.                | Should Pass     |
 * | 04               | Invoke cjson_utils::stringify on the JSON object for the second time to obtain another string representation. | input: obj, format = true; output: s2                              | s2 contains a valid JSON string that should be identical to s1.                                | Should Pass     |
 * | 05               | Compare the two string outputs obtained from the stringify calls to ensure consistency.          | input: s1, s2; expected output: both strings are equal            | Expect the two JSON string outputs to be equal, confirming deterministic behavior of stringify. | Should Pass     |
 * | 06               | Delete the JSON object using cJSON_Delete to free allocated memory.                              | input: obj                                                       | The JSON object is deleted with no memory leaks.                                               | Should be successful |
 */
TEST(CjsonUtils, RepeatedCallsReturnSameOutput) {
    const char* testName = "RepeatedCallsReturnSameOutput"; 
    std::cout << "Entering " << testName << " test" << std::endl;
    cJSON *obj = cJSON_CreateObject();
    EXPECT_NE(obj, nullptr);
    cJSON_AddStringToObject(obj, "k", "v");       
    std::cout << "Invoking stringify twice (unformatted) to compare outputs" << std::endl;
    std::string s1 = cjson_utils::stringify(obj, true);
    std::string s2 = cjson_utils::stringify(obj, true);
    std::cout << "First: " << s1 << "\nSecond: " << s2 << std::endl;
    EXPECT_EQ(s1, s2);
    cJSON_Delete(obj);
    std::cout << "Exiting " << testName << " test" << std::endl;
}
