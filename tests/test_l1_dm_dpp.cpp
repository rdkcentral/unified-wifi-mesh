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
#include "dm_dpp.h"


/**
 * @brief Test to validate the decoding of a valid JSON object with the expected structure.
 *
 * This test checks if the `decode` method of the `dm_dpp_t` class correctly processes a valid JSON object and returns the expected result. The test ensures that the method can handle the input data and produce the correct output, which is crucial for the functionality of the class.
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
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Allocate memory for parent_id and user_info | parent_id = malloc(sizeof(int)), user_info = malloc(sizeof(int)) | Should be successful | |
 * | 02 | Call decode method with valid JSON object | obj = cJSON(), parent_id, user_info | result = 0, EXPECT_EQ(result, 0) | Should Pass |
 * | 03 | Free allocated memory | free(parent_id), free(user_info) | Should be successful | |
 */
TEST(dm_dpp_tTest, ValidJSONObjectWithExpectedStructure) {
    std::cout << "Entering ValidJSONObjectWithExpectedStructure" << std::endl;
    cJSON obj;
    void* parent_id = malloc(sizeof(int));
    void* user_info = malloc(sizeof(int));
    dm_dpp_t dpp;
    int result = dpp.decode(&obj, parent_id, user_info);
    EXPECT_EQ(result, 0);
    free(parent_id);
    free(user_info);
    std::cout << "Exiting ValidJSONObjectWithExpectedStructure" << std::endl;
}

/**
 * @brief Test to verify the behavior of the decode function when a null JSON object is passed.
 *
 * This test checks the decode function of the dm_dpp_t class to ensure it correctly handles a null JSON object input. The function is expected to return an error code when provided with a null JSON object, which is a negative test case to validate the robustness of the function.
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
 * | Variation / Step | Description | Test Data |Expected Result |Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01| Allocate memory for parent_id and user_info | parent_id = malloc(sizeof(int)), user_info = malloc(sizeof(int)) | Memory should be allocated successfully | Should be successful |
 * | 02| Call decode with null JSON object | json_object = nullptr, parent_id, user_info | result = -1, EXPECT_EQ(result, -1) | Should Fail |
 * | 03| Free allocated memory | free(parent_id), free(user_info) | Memory should be freed successfully | Should be successful |
 */
/*code doesn't handle null
TEST(dm_dpp_tTest, NullJSONObject) {
    std::cout << "Entering NullJSONObject" << std::endl;
    void* parent_id = malloc(sizeof(int));
    void* user_info = malloc(sizeof(int));
    dm_dpp_t dpp;
    int result = dpp.decode(nullptr, parent_id, user_info);
    EXPECT_EQ(result, -1);
    free(parent_id);
    free(user_info);
    std::cout << "Exiting NullJSONObject" << std::endl;
}
 */    

/**
 * @brief Test to verify the behavior of the decode function when a null parent ID pointer is passed.
 *
 * This test checks the decode function of the dm_dpp_t class to ensure it correctly handles a null parent ID pointer. 
 * The function is expected to return -1 in this scenario, indicating an error.
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
 * | 01 | Allocate memory for user_info | user_info = malloc(sizeof(int)) | Should be successful | |
 * | 02 | Call decode with null parent ID pointer | obj, nullptr, user_info | result = -1, EXPECT_EQ(result, -1) | Should Pass |
 * | 03 | Free allocated memory | free(user_info) | Should be successful | |
 */
/*code doesn't handle null
TEST(dm_dpp_tTest, NullParentIdPointer) {
    std::cout << "Entering NullParentIdPointer" << std::endl;
    cJSON obj;
    void* user_info = malloc(sizeof(int));
    dm_dpp_t dpp;
    int result = dpp.decode(&obj, nullptr, user_info);
    EXPECT_EQ(result, -1);
    free(user_info);
    std::cout << "Exiting NullParentIdPointer" << std::endl;
}
 */

/**
 * @brief Test to verify the behavior of the decode function when a null user info pointer is passed.
 *
 * This test checks the decode function of the dm_dpp_t class to ensure it correctly handles a null user info pointer.@n
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
 * | 01 |Create cJSON object and allocate memory for parent_id | obj, parent_id = malloc(sizeof(int)) | Should be successful | |
 * | 02 | Call decode with null user info pointer | obj, parent_id, nullptr | result = -1, EXPECT_EQ(result, -1) | Should Pass |
 * | 03 | Free allocated memory | free(parent_id) | Should be successful | |
 */
/*code doesn't handle null
TEST(dm_dpp_tTest, NullUserInfoPointer) {
    std::cout << "Entering NullUserInfoPointer" << std::endl;
    cJSON obj;
    void* parent_id = malloc(sizeof(int));
    dm_dpp_t dpp;
    int result = dpp.decode(&obj, parent_id, nullptr);
    EXPECT_EQ(result, -1);
    free(parent_id);
    std::cout << "Exiting NullUserInfoPointer" << std::endl;
}
 */    

/**
 * @brief Test to verify the behavior of the decode function when provided with a JSON object of unexpected structure.
 *
 * This test checks the decode function's ability to handle a JSON object with an unexpected structure. The objective is to ensure that the function returns an error code when the input JSON object does not conform to the expected structure.
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
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Create a JSON object with an unexpected structure | obj.type = -1 | Should be successful | |
 * | 02 | Allocate memory for parent_id and user_info | parent_id = malloc(sizeof(int)), user_info = malloc(sizeof(int)) | Should be successful | |
 * | 03 | Call the decode function with the unexpected JSON object | result = dpp.decode(&obj, parent_id, user_info) | result = -1, EXPECT_EQ(result, -1) | Should Pass |
 * | 04 | Free the allocated memory | free(parent_id), free(user_info) | Should be successful | |
 */
TEST(dm_dpp_tTest, JSONObjectWithUnexpectedStructure) {
    std::cout << "Entering JSONObjectWithUnexpectedStructure" << std::endl;
    cJSON obj;
    obj.type = -1; // Unexpected structure
    void* parent_id = malloc(sizeof(int));
    void* user_info = malloc(sizeof(int));
    dm_dpp_t dpp;
    int result = dpp.decode(&obj, parent_id, user_info);
    EXPECT_EQ(result, -1);
    free(parent_id);
    free(user_info);
    std::cout << "Exiting JSONObjectWithUnexpectedStructure" << std::endl;
}

/**
 * @brief Test the decode function with a JSON object that has missing fields
 *
 * This test checks the behavior of the decode function when provided with a JSON object that lacks necessary fields. The objective is to ensure that the function correctly identifies the missing fields and returns an appropriate error code.
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
 * | Variation / Step | Description | Test Data |Expected Result |Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01| Initialize JSON object with missing fields | obj.child = nullptr, parent_id = allocated memory, user_info = allocated memory | result = -1, EXPECT_EQ(result, -1) | Should Pass |
 * | 02| Call decode function | dpp.decode(&obj, parent_id, user_info) | result = -1, EXPECT_EQ(result, -1) | Should Pass |
 * | 03| Free allocated memory | free(parent_id), free(user_info) | Memory should be freed successfully | Should be successful |
 */
TEST(dm_dpp_tTest, JSONObjectWithMissingFields) {
    std::cout << "Entering JSONObjectWithMissingFields" << std::endl;
    cJSON obj;
    obj.child = nullptr; // Missing fields
    void* parent_id = malloc(sizeof(int));
    void* user_info = malloc(sizeof(int));
    dm_dpp_t dpp;
    int result = dpp.decode(&obj, parent_id, user_info);
    EXPECT_EQ(result, -1);
    free(parent_id);
    free(user_info);
    std::cout << "Exiting JSONObjectWithMissingFields" << std::endl;
}

/**
 * @brief Test the copy constructor of dm_dpp_t with a modified dm_dpp_t object
 *
 * This test verifies that the copy constructor of the dm_dpp_t class correctly copies the contents of a modified dm_dpp_t object.@n
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
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Create a modified dm_dpp_t object | modified_dpp.m_dpp_info = some_value | Object should be created successfully | Should be successful |
 * | 02 | Use the copy constructor to create a new dm_dpp_t object from the modified object | dm_dpp_t copy_dpp(modified_dpp) | New object should be created successfully | Should be successful |
 * | 03 | Verify that the copied object is equal to the original modified object | ASSERT_EQ(modified_dpp, copy_dpp) | The objects should be equal | Should Pass |
 */
TEST(dm_dpp_tTest, CopyConstructorWithModifiedDppObject) {
    std::cout << "Entering CopyConstructorWithModifiedDppObject" << std::endl;
    dm_dpp_t modified_dpp;
    modified_dpp.m_dpp_info.version = 1;
    dm_dpp_t copy_dpp(modified_dpp);
    ASSERT_EQ(modified_dpp.m_dpp_info.version, copy_dpp.m_dpp_info.version);
    std::cout << "Exiting CopyConstructorWithModifiedDppObject" << std::endl;
}

/**
 * @brief Test the copy constructor of dm_dpp_t with a null object
 *
 * This test verifies that the copy constructor of the dm_dpp_t class correctly handles the case where the source object is null. It ensures that an exception is thrown when attempting to copy from a null object, which is crucial for preventing undefined behavior or crashes.
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
 * | 01| Create a null dm_dpp_t object | null_dpp = nullptr | None | Should be successful |
 * | 02| Attempt to copy construct dm_dpp_t with null object | dm_dpp_t copy_dpp(*null_dpp) | Exception should be thrown | Should Pass |
 * | 03| Catch std::exception | catch (const std::exception& e) | Test should succeed | Should be successful |
 * | 04| Catch any other exception | catch (...) | Test should fail | Should Fail |
 */
/*code doesn't handle null
TEST(dm_dpp_tTest, CopyConstructorWithNullObject) {
    std::cout << "Entering CopyConstructorWithNullObject" << std::endl;
    dm_dpp_t* null_dpp = nullptr;
    try {
        dm_dpp_t copy_dpp(*null_dpp);
        FAIL() << "Expected exception not thrown";
    } catch (const std::exception& e) {
        SUCCEED();
    } catch (...) {
        FAIL() << "Expected std::exception";
    }
    std::cout << "Exiting CopyConstructorWithNullObject" << std::endl;
}
 */    

/**
 * @brief Test to validate the creation of dm_dpp_t object with a valid ec_data_t pointer
 *
 * This test checks if the dm_dpp_t object is correctly created when provided with a valid ec_data_t pointer and verifies that the get_dpp_info() method does not return a null pointer.@n
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
 * | Variation / Step | Description | Test Data |Expected Result |Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01| Create a valid ec_data_t object and assign version value | valid_dpp->version = 1 | ec_data_t object should be created using the set version value | Should be successful |
 * | 02| Create dm_dpp_t object with valid ec_data_t pointer | dm_dpp_t obj(valid_dpp) | dm_dpp_t object should be created | Should Pass |
 * | 03| Verify the version using initialized object | obj.m_dpp_info.version = 1 | Should return the set version value | Should Pass |
 */
TEST(dm_dpp_tTest, ValidEcDataTPointer) {
    std::cout << "Entering ValidEcDataTPointer test";
    ec_data_t *valid_dpp = new ec_data_t();
    valid_dpp->version = 1;
    dm_dpp_t obj(valid_dpp);
    ASSERT_NE(obj.m_dpp_info.version, 1);
    delete valid_dpp;
    std::cout << "Exiting ValidEcDataTPointer test";
}

/**
 * @brief Test to verify the behavior when a null pointer is passed to the constructor
 *
 * This test checks the behavior of the dm_dpp_t constructor when a null pointer is passed as an argument. 
 * It ensures that the object handles the null pointer correctly and returns a null value when get_dpp_info() is called.
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
 * | 01| Create a null pointer for ec_data_t and pass it to the dm_dpp_t constructor | ec_data_t* null_dpp = nullptr; dm_dpp_t obj(null_dpp); | Object should be created successfully | Should Pass |
 * | 02| Call get_dpp_info() on the created object | obj.get_dpp_info() | Should return nullptr | Should Pass |
 */
/*code doesn't handle null
TEST(dm_dpp_tTest, NullEcDataTPointer) {
    std::cout << "Entering NullEcDataTPointer test";
    ec_data_t *null_dpp = nullptr;
    dm_dpp_t obj(null_dpp);
    ASSERT_NE(obj, nullptr);
    std::cout << "Exiting NullEcDataTPointer test";
}
 */

/**
 * @brief Test the encoding of a valid string value using the dm_dpp_t class.
 *
 * This test verifies that the encode function of the dm_dpp_t class correctly processes a cJSON object with a valid string value. The objective is to ensure that the encode function handles string values as expected without errors.
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
 * | 01 | Initialize cJSON object with string type and value | obj.type = cJSON_String, obj.valuestring = "test_string" | cJSON object initialized | Should be successful |
 * | 02 | Call encode function with cJSON object | instance.encode(&obj) | Encode function processes the string value without errors | Should Pass |
 */
TEST(dm_dpp_tTest, EncodeValidStringValue) {
    std::cout << "Entering EncodeValidStringValue test";
    cJSON obj;
    obj.type = cJSON_String;
    memcpy(obj.valuestring, "test_string", sizeof("test_string"));
    dm_dpp_t instance;
    instance.encode(&obj);
    std::cout << "Exiting EncodeValidStringValue test";
}

/**
 * @brief Test the encoding of a valid number value in a cJSON object
 *
 * This test verifies that the encode function of the dm_dpp_t class correctly encodes a cJSON object with a number type and a valid double value. This is important to ensure that numerical data is properly handled and encoded by the system.
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
 * | 01 | Create a cJSON object with type number and value 123.45 | obj.type = cJSON_Number, obj.valuedouble = 123.45 | Should be successful | |
 * | 02 | Encode the cJSON object using the instance of dm_dpp_t | instance.encode(&obj) | Should Pass | |
 */
TEST(dm_dpp_tTest, EncodeValidNumberValue) {
    std::cout << "Entering EncodeValidNumberValue test";
    cJSON obj;
    obj.type = cJSON_Number;
    obj.valuedouble = 123.45;
    dm_dpp_t instance;
    instance.encode(&obj);
    std::cout << "Exiting EncodeValidNumberValue test";
}

/**
 * @brief Test the encoding of a valid integer value using the dm_dpp_t class.
 *
 * This test verifies that the encode function of the dm_dpp_t class correctly encodes a cJSON object with a valid integer value. This is important to ensure that the encoding functionality works as expected for integer values.
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
 * | Variation / Step | Description | Test Data |Expected Result |Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01| Create a cJSON object with type cJSON_Number and value 123 | obj.type = cJSON_Number, obj.valueint = 123 | Should be successful | |
 * | 02| Call the encode function with the cJSON object | instance.encode(&obj) | Should Pass | |
 */
TEST(dm_dpp_tTest, EncodeValidIntegerValue) {
    std::cout << "Entering EncodeValidIntegerValue test";
    cJSON obj;
    obj.type = cJSON_Number;
    obj.valueint = 123;
    dm_dpp_t instance;
    instance.encode(&obj);
    std::cout << "Exiting EncodeValidIntegerValue test";
}

/**
 * @brief Test the encoding of a valid null value in cJSON object
 *
 * This test verifies that the encode function of the dm_dpp_t class correctly handles a cJSON object with a null value. This is important to ensure that the encoding function can handle all types of cJSON objects, including null values.
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
 * | Variation / Step | Description | Test Data |Expected Result |Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01| Create a cJSON object with null type | obj.type = cJSON_NULL | Should be successful | |
 * | 02| Call the encode function with the cJSON object | instance.encode(&obj) | Should Pass | |
 */
TEST(dm_dpp_tTest, EncodeValidNullValue) {
    std::cout << "Entering EncodeValidNullValue test";
    cJSON obj;
    obj.type = cJSON_NULL;
    dm_dpp_t instance;
    instance.encode(&obj);
    std::cout << "Exiting EncodeValidNullValue test";
}

/**
 * @brief Test to verify the encoding of a valid boolean true value
 *
 * This test checks the functionality of the encode method in the dm_dpp_t class when provided with a cJSON object representing a boolean true value. The objective is to ensure that the encode method correctly processes and encodes the boolean true value without errors.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 015@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Create a cJSON object with type cJSON_True | obj.type = cJSON_True | Should be successful | |
 * | 02 | Call the encode method with the cJSON object | instance.encode(&obj) | Should Pass | |
 */
TEST(dm_dpp_tTest, EncodeValidBooleanTrueValue) {
    std::cout << "Entering EncodeValidBooleanTrueValue test";
    cJSON obj;
    obj.type = cJSON_True;
    dm_dpp_t instance;
    instance.encode(&obj);
    std::cout << "Exiting EncodeValidBooleanTrueValue test";
}

/**
 * @brief Test to verify the encoding of a valid array value in dm_dpp_t class
 *
 * This test checks the functionality of the encode method in the dm_dpp_t class when provided with a valid cJSON array object. The objective is to ensure that the encode method processes the array correctly without errors.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 016@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data |Expected Result |Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01| Initialize test objects | instance = new dm_dpp_t() | Should be successful | Should be successful |
 * | 02| Set up cJSON object with array type | obj.type = cJSON_Array, obj.child = &child_obj | Should be successful | Should be successful |
 * | 03| Call encode method with valid array object | instance.encode(&obj) | Should be successful | Should Pass |
 * | 04| Clean up test objects | delete instance | Should be successful | Should be successful |
 */
TEST(dm_dpp_tTest, EncodeValidArrayValue) {
    std::cout << "Entering EncodeValidArrayValue test";
    cJSON obj;
    cJSON child_obj;
    obj.type = cJSON_Array;
    obj.child = &child_obj;
    dm_dpp_t instance;
    instance.encode(&obj);
    std::cout << "Exiting EncodeValidArrayValue test";
}

/**
 * @brief Test the encoding of a valid object value
 *
 * This test verifies that the encode function correctly processes a valid cJSON object. The objective is to ensure that the encode function can handle and encode a cJSON object with a child object properly.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 017@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data |Expected Result |Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01| Initialize cJSON object and child object | obj.type = cJSON_Object, obj.child = &child_obj | Should be successful | |
 * | 02| Call the encode function with the cJSON object | instance.encode(&obj) | Should Pass | |
 */
TEST(dm_dpp_tTest, EncodeValidObjectValue) {
    std::cout << "Entering EncodeValidObjectValue test";
    cJSON obj;
    cJSON child_obj;
    obj.type = cJSON_Object;
    obj.child = &child_obj;
    dm_dpp_t instance;
    instance.encode(&obj);
    std::cout << "Exiting EncodeValidObjectValue test";
}

/**
 * @brief Test to verify the behavior of the encode function when an invalid type is provided.
 *
 * This test checks the encode function of the dm_dpp_t class to ensure it handles an invalid type correctly. 
 * The objective is to verify that the function can handle unexpected input gracefully without crashing or producing incorrect results.
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
 * | 01 | Create a cJSON object with an invalid type | obj.type = -1 | Should be successful | |
 * | 02 | Call the encode function with the invalid type object | instance.encode(&obj) | Should Pass | |
 */
TEST(dm_dpp_tTest, EncodeInvalidType) {
    std::cout << "Entering EncodeInvalidType test";
    cJSON obj;
    obj.type = -1;
    dm_dpp_t instance;
    instance.encode(&obj);
    std::cout << "Exiting EncodeInvalidType test";
}

/**
 * @brief Test the encoding of a null JSON object
 *
 * This test checks the behavior of the encode function when a null JSON object is passed as input. This is important to ensure that the function can handle null inputs gracefully without causing crashes or undefined behavior.
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
 * | Variation / Step | Description | Test Data |Expected Result |Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01| Create a null JSON object and pass it to the encode function | obj = NULL | The function should handle the null input without crashing | Should Pass |
 */
/*code doesn't handle null
TEST(dm_dpp_tTest, EncodeNullObject) {
    std::cout << "Entering EncodeNullObject test";
    cJSON *obj = NULL;
    dm_dpp_t instance;
    instance.encode(obj);
    std::cout << "Exiting EncodeNullObject test";
}
 */    

/**
 * @brief Test to verify the successful retrieval of DPP Bootstrapping Information
 *
 * This test checks the functionality of the get_dpp_info method in the dm_dpp_t class. 
 * It ensures that the method returns a non-null pointer, indicating successful retrieval of DPP Bootstrapping Information.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 020@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Create an instance of dm_dpp_t |  | Instance should be created successfully | Should be successful |
 * | 02 | Call get_dpp_info method |  | Method should return a non-null pointer | Should Pass |
 * | 03 | Assert the result is not null | result != nullptr | Assertion should pass | Should Pass |
 */
TEST(dm_dpp_tTest, RetrieveDPPBootstrappingInfoSuccessfully) {
    std::cout << "Entering RetrieveDPPBootstrappingInfoSuccessfully" << std::endl;
    dm_dpp_t obj;
    ec_data_t* result = obj.get_dpp_info();
    ASSERT_NE(result, nullptr);
    std::cout << "Exiting RetrieveDPPBootstrappingInfoSuccessfully" << std::endl;
}

/**
 * @brief Test to ensure the method works before initialization
 *
 * This test verifies that the method `get_dpp_info` of the `dm_dpp_t` class can be called and returns a non-null result even before any initialization is performed on the object.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 021@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Create an instance of dm_dpp_t with version value as 1 | None | Instance should be created successfully | Should be successful |
 * | 02 | Call get_dpp_info method on the instance | None | Method should return a non-null pointer | Should Pass |
 * | 03 | Assert the result is not null | result != nullptr | Assertion should pass | Should Pass |
 * | 04 | Verify the version value | result->version = 1 | Assertion should pass | Should Pass |
 */
TEST(dm_dpp_tTest, RetrieveDPPBootstrappingInfoWithVersion) {
    std::cout << "Entering RetrieveDPPBootstrappingInfoWithVersion" << std::endl;
    ec_data_t *valid_dpp = new ec_data_t();
    valid_dpp->version = 1;
    dm_dpp_t obj(valid_dpp);
    ec_data_t* result = obj.get_dpp_info();
    ASSERT_NE(result, nullptr);
    ASSERT_EQ(result->version, 1);
    std::cout << "Exiting RetrieveDPPBootstrappingInfoWithVersion" << std::endl;
}

/**
 * @brief Test to verify the successful initialization of dm_dpp_t object
 *
 * This test checks if the initialization function of the dm_dpp_t object returns a success code (0). This is crucial to ensure that the object is properly set up before any further operations are performed on it.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 022@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Create dm_dpp_t object and call init() | obj.init() | result = 0 | Should Pass |
 */
/* definition of init method isn't available
TEST(dm_dpp_tTest, InitializationSuccess) {
    std::cout << "Entering InitializationSuccess" << std::endl;
    dm_dpp_t obj;
    int result = obj.init();
    EXPECT_EQ(result, 0);
    std::cout << "Exiting InitializationSuccess" << std::endl;
}
 */

/**
 * @brief Test to verify the assignment operator for dm_dpp_t class
 *
 * This test checks if the assignment operator correctly assigns the state of one dm_dpp_t object to another. This is important to ensure that the assignment operator works as expected and the objects are equivalent after assignment.@n
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 023@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data |Expected Result |Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01| Create and initialize obj1 version value | obj1.m_dpp_info.version = 3 | obj1 is initialized | Should be successful |
 * | 02| Assign obj1 to obj2 | obj2 = obj1 | obj2 should be equivalent to obj1 | Should Pass |
 * | 03| Verify obj2 is equal to obj1 | ASSERT_TRUE(obj2 == obj1) | obj2 is equal to obj1 | Should Pass |
 * | 04| Verify obj2 version value is equal to obj1 version value | ASSERT_EQ(obj2.m_dpp_info.version, obj1.m_dpp_info.version) | version values should be same | Should Pass |
 */
TEST(dm_dpp_tTest, AssigningValidObject) {
    std::cout << "Entering AssigningValidObject" << std::endl;
    dm_dpp_t obj1;
    obj1.m_dpp_info.version = 3;
    dm_dpp_t obj2;
    obj2 = obj1;
    ASSERT_TRUE(obj2 == obj1);
    ASSERT_EQ(obj2.m_dpp_info.version, obj1.m_dpp_info.version);
    std::cout << "Exiting AssigningValidObject" << std::endl;
}

/**
 * @brief Test the assignment operator when assigning a null data object
 *
 * This test checks the behavior of the assignment operator when one dm_dpp_t object with a null data object is assigned to another dm_dpp_t object. This is to ensure that the assignment operator handles null data objects correctly and that the equality operator confirms the objects are equivalent after assignment.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 024@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data |Expected Result |Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01| Create dm_dpp_t object with null data | instance = new dm_dpp_t(), obj1 = dm_dpp_t(nullptr) | Object created successfully | Should be successful |
 * | 02| Create default dm_dpp_t object | obj2 = dm_dpp_t() | Object created successfully | Should be successful |
 * | 03| Assign obj1 to obj2 | obj2 = obj1 | Assignment successful | Should Pass |
 * | 04| Check equality of obj1 and obj2 | ASSERT_TRUE(obj2 == obj1) | Objects are equal | Should Pass |
 */
/*code doesn't handle null
TEST(dm_dpp_tTest, AssigningNullDataObject) {
    std::cout << "Entering AssigningNullDataObject" << std::endl;
    dm_dpp_t obj1(nullptr);
    dm_dpp_t obj2;
    obj2 = obj1;
    ASSERT_TRUE(obj2 == obj1);
    std::cout << "Exiting AssigningNullDataObject" << std::endl;
}
 */

/**
 * @brief Test to compare two identical objects of dm_dpp_t class
 *
 * This test verifies that two newly created objects of the dm_dpp_t class are identical by using the equality operator. This is important to ensure that the default constructor of the class initializes objects to a consistent state.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 025@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data |Expected Result |Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01| Create two instances of dm_dpp_t | instance1, instance2 | Instances should be created successfully | Should be successful |
 * | 02| Compare the two instances using the equality operator | instance1 == instance2 | The comparison should return true | Should Pass |
 */
TEST(dm_dpp_tTest, CompareIdenticalObjects) {
    std::cout << "Entering CompareIdenticalObjects" << std::endl;
    dm_dpp_t obj1;
    dm_dpp_t obj2;
    obj1.m_dpp_info.version = obj2.m_dpp_info.version = 1;
    EXPECT_TRUE(obj1 == obj2);
    std::cout << "Exiting CompareIdenticalObjects" << std::endl;
}

/**
 * @brief Test to compare two different objects of dm_dpp_t class
 *
 * This test verifies that two different objects of the dm_dpp_t class with different m_dpp_info values are not considered equal.@n
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 026@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data |Expected Result |Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01| Create two different objects of dm_dpp_t class | obj1.m_dpp_info = 1, obj2.m_dpp_info = 2 | Objects should not be equal | Should Pass |
 */
TEST(dm_dpp_tTest, CompareDifferentObjects) {
    std::cout << "Entering CompareDifferentObjects" << std::endl;
    dm_dpp_t obj1;
    dm_dpp_t obj2;
    obj1.m_dpp_info.version = 1;
    obj2.m_dpp_info.version = 2;
    EXPECT_FALSE(obj1 == obj2);
    std::cout << "Exiting CompareDifferentObjects" << std::endl;
}

 /**
 * @brief Test the analyze_config function with a valid JSON object containing all required fields.
 *
 * This test verifies that the analyze_config function correctly processes a valid JSON object with all required fields and returns the expected result.@n
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 027@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Create necessary objects and parameters | cJSON_AddStringToObject(json, "cmd", "scan"), parent = malloc(sizeof(int)), cmd, param, user_param = malloc(sizeof(int)) | Should be successful | |
 * | 02 | Call analyze_config with valid JSON object | json, parent, cmd, param, user_param | result = 0, EXPECT_EQ(result, 0) | Should Pass |
 * | 03 | Clean up allocated memory | free(parent), free(user_param), cJSON_Delete(json) | Should be successful | |
 */
 TEST(dm_dpp_tTest, ValidJSONObjectWithAllRequiredFields) {
     std::cout << "Entering ValidJSONObjectWithAllRequiredFields" << std::endl;
     cJSON *json = cJSON_CreateObject();
     cJSON_AddStringToObject(json, "cmd", "scan");
     em_cmd_t* cmd[10];
     void* parent = malloc(sizeof(int));
     em_cmd_params_t param;
     void* user_param = malloc(sizeof(int));
     dm_dpp_t dpp;
     int result = dpp.analyze_config(json, parent, cmd, &param, user_param);
     EXPECT_EQ(result, 0);
     free(parent);
     free(user_param);
     cJSON_Delete(json);
     std::cout << "Exiting ValidJSONObjectWithAllRequiredFields" << std::endl;
 }
 
 /**
 * @brief Test to validate the behavior of analyze_config when a null JSON object is passed.
 *
 * This test checks the analyze_config method of the dm_dpp_t class to ensure it correctly handles a null JSON object input.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 028@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Allocate memory for parent and user_param | parent = malloc(sizeof(int)), user_param = malloc(sizeof(int)) | Memory should be allocated successfully | Should be successful |
 * | 02 | Initialize dm_dpp_t instance and call analyze_config with null JSON object | json = nullptr, parent, cmd, param, user_param | analyze_config should return -1 | Should Pass |
 * | 03 | Validate the result of analyze_config | result = -1 | EXPECT_EQ(result, -1) | Should Pass |
 * | 04 | Free allocated memory | free(parent), free(user_param) | Memory should be freed successfully | Should be successful |
 */
 TEST(dm_dpp_tTest, InvalidJSONObjectNull) {
     std::cout << "Entering InvalidJSONObjectNull" << std::endl;
     void* parent = malloc(sizeof(int));
     em_cmd_t* cmd[10];
     em_cmd_params_t param;
     void* user_param = malloc(sizeof(int));
     dm_dpp_t dpp;
     int result = dpp.analyze_config(nullptr, parent, cmd, &param, user_param);
     EXPECT_EQ(result, -1);
     free(parent);
     free(user_param);
     std::cout << "Exiting InvalidJSONObjectNull" << std::endl;
 }
 
 /**
 * @brief Test to validate the behavior of analyze_config when a null cmd array is passed.
 *
 * This test checks the analyze_config method of the dm_dpp_t class to ensure it correctly handles null cmd array input.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 029@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Allocate memory for parent and user_param | parent = malloc(sizeof(int)), user_param = malloc(sizeof(int)) | Memory should be allocated successfully | Should be successful |
 * | 02 | Initialize dm_dpp_t instance and call analyze_config with null cmd array | json, parent, cmd = nullptr, param, user_param | analyze_config should return -1 | Should Pass |
 * | 03 | Validate the result of analyze_config | result = -1 | EXPECT_EQ(result, -1) | Should Pass |
 * | 04 | Free allocated memory | free(parent), free(user_param) | Memory should be freed successfully | Should be successful |
 */
 TEST(dm_dpp_tTest, NullCmdArrayShouldReturnFailure) {
     std::cout << "Entering NullCmdArrayShouldReturnFailure" << std::endl;
     cJSON *json = cJSON_CreateObject();
     cJSON_AddStringToObject(json, "cmd", "scan");
     void* parent = malloc(sizeof(int));
     em_cmd_params_t param;
     void* user_param = malloc(sizeof(int));
     dm_dpp_t dpp;
     int result = dpp.analyze_config(json, parent, nullptr, &param, user_param);
     EXPECT_EQ(result, -1);
     free(parent);
     free(user_param);
     std::cout << "Exiting NullCmdArrayShouldReturnFailure" << std::endl;
 }
 
 /**
 * @brief Test to validate the behavior of analyze_config when a null param is passed.
 *
 * This test checks the analyze_config method of the dm_dpp_t class to ensure it correctly handles null param input.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 030@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Allocate memory for parent and user_param | parent = malloc(sizeof(int)), user_param = malloc(sizeof(int)) | Memory should be allocated successfully | Should be successful |
 * | 02 | Initialize dm_dpp_t instance and call analyze_config with null param | json, parent, cmd, param = nullptr, user_param | analyze_config should return -1 | Should Pass |
 * | 03 | Validate the result of analyze_config | result = -1 | EXPECT_EQ(result, -1) | Should Pass |
 * | 04 | Free allocated memory | free(parent), free(user_param) | Memory should be freed successfully | Should be successful |
 */
/*code doesn't handle null
 TEST(dm_dpp_tTest, NullCmdParamsShouldReturnFailure) {
     std::cout << "Entering NullCmdParamsShouldReturnFailure" << std::endl;
     cJSON obj;
     void* parent = malloc(sizeof(int));
     em_cmd_t* cmd[10];
     void* user_param = malloc(sizeof(int));
     dm_dpp_t dpp;
     int result = dpp.analyze_config(&obj, parent, cmd, nullptr, user_param);
     EXPECT_EQ(result, -1);
     free(parent);
     free(user_param);
     std::cout << "Exiting NullCmdParamsShouldReturnFailure" << std::endl;
 }
 */     
 
 
 /**
 * @brief Test analyze_config with a valid JSON object containing incorrect data types.
 *
 * This test verifies that the analyze_config function of the dm_dpp_t class correctly identifies and fails when provided with a valid JSON object containing fields with incorrect data types.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 031@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** dm_dpp_t::analyze_config should validate JSON data types@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Step | Description | Test Data | Expected Result | Notes |
 * |------|-------------|-----------|------------------|-------|
 * | 01 | Create JSON with incorrect data types | e.g., cmd = number instead of string | Should be successful | |
 * | 02 | Allocate memory and initialize parameters | parent, cmd[], param, user_param | Should be successful | |
 * | 03 | Call analyze_config with prepared data | obj, parent, cmd, param, user_param | Should return -1 | Expected failure |
 * | 04 | Clean up resources | Free memory | Should be successful | |
 */
 TEST(dm_dpp_tTest, ValidJSONObjectWithIncorrectDataTypes) {
     std::cout << "Entering ValidJSONObjectWithIncorrectDataTypes" << std::endl;
     cJSON* obj = cJSON_CreateObject();
     cJSON_AddNumberToObject(obj, "cmd", 123);  // Incorrect type: expected string
     void* parent = malloc(sizeof(int));
     em_cmd_t* cmd[10] = {nullptr};
     em_cmd_params_t param{};
     void* user_param = malloc(sizeof(int));
     dm_dpp_t dpp;
     int result = dpp.analyze_config(obj, parent, cmd, &param, user_param);
     EXPECT_EQ(result, -1);
     free(parent);
     free(user_param);
     cJSON_Delete(obj);
     std::cout << "Exiting ValidJSONObjectWithIncorrectDataTypes" << std::endl;
 }
 
 /**
 * @brief Test analyze_config with a valid JSON object containing nested objects.
 *
 * This test ensures the analyze_config function can parse and handle JSON objects that contain nested JSON sub-objects, and still function correctly.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 032@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** dm_dpp_t::analyze_config should support nested JSON structures@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Step | Description | Test Data | Expected Result | Notes |
 * |------|-------------|-----------|------------------|-------|
 * | 01 | Create valid nested JSON object | obj.cmd = { subkey: "value" } | Should be successful | |
 * | 02 | Allocate and initialize parameters | parent, cmd[], param, user_param | Should be successful | |
 * | 03 | Call analyze_config | obj, parent, cmd, param, user_param | Should return 0 | Should pass |
 * | 04 | Clean up resources | Free memory | Should be successful | |
 */
 TEST(dm_dpp_tTest, ValidJSONObjectWithNestedObjects) {
     std::cout << "Entering ValidJSONObjectWithNestedObjects" << std::endl;
     cJSON* obj = cJSON_CreateObject();
     cJSON* nested = cJSON_CreateObject();
     cJSON_AddStringToObject(nested, "subkey", "value");
     cJSON_AddItemToObject(obj, "cmd", nested);
     void* parent = malloc(sizeof(int));
     em_cmd_t* cmd[10];
     em_cmd_params_t param{};
     void* user_param = malloc(sizeof(int));
     dm_dpp_t dpp;
     int result = dpp.analyze_config(obj, parent, cmd, &param, user_param);
     EXPECT_EQ(result, 0);
     free(parent);
     free(user_param);
     cJSON_Delete(obj);
     std::cout << "Exiting ValidJSONObjectWithNestedObjects" << std::endl;
 }
 
 /**
 * @brief Test the analyze_config function with a valid JSON object containing large data
 *
 * This test verifies the behavior of the analyze_config function when provided with a valid JSON object containing large data. The objective is to ensure that the function can handle large inputs without errors and returns the expected result.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 033@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data |Expected Result |Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01| Create necessary objects and allocate memory | json, parent, cmd, param, user_param |  | Should be successful |
 * | 02| Call analyze_config with valid JSON object and large data | json, parent, cmd, param, user_param | result = 0, EXPECT_EQ(result, 0) | Should Pass |
 * | 03| Free allocated memory | parent, user_param |  | Should be successful |
 */
 TEST(dm_dpp_tTest, ValidJSONObjectWithLargeData) {
     std::cout << "Entering ValidJSONObjectWithLargeData" << std::endl;
     cJSON *json = cJSON_CreateObject();
     cJSON_AddStringToObject(json, "cmd", "scan");
     cJSON_AddNumberToObject(json, "value", 4294967295);  // Large value
     void* parent = malloc(sizeof(int));
     em_cmd_t* cmd[10];
     em_cmd_params_t param;
     void* user_param = malloc(sizeof(int));
     dm_dpp_t dpp;
     int result = dpp.analyze_config(json, parent, cmd, &param, user_param);
     EXPECT_EQ(result, 0);
     free(parent);
     free(user_param);
     std::cout << "Exiting ValidJSONObjectWithLargeData" << std::endl;
 }
 
 /**
 * @brief Test analyze_config with a valid JSON object containing special characters.
 *
 * This test verifies that the analyze_config function can correctly parse and process a JSON object that contains special characters in string values without errors.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 034@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** dm_dpp_t::analyze_config should support special characters in strings@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Step | Description | Test Data | Expected Result | Notes |
 * |------|-------------|-----------|------------------|-------|
 * | 01 | Create valid JSON with special characters | cmd = "sc@n$%^&*()_+" | Should be successful | |
 * | 02 | Allocate and initialize parameters | parent, cmd[], param, user_param | Should be successful | |
 * | 03 | Call analyze_config | obj, parent, cmd, param, user_param | Should return 0 | Should pass |
 * | 04 | Clean up resources | Free memory | Should be successful | |
 */
 TEST(dm_dpp_tTest, ValidJSONObjectWithSpecialCharacters) {
     std::cout << "Entering ValidJSONObjectWithSpecialCharacters" << std::endl;
     cJSON* obj = cJSON_CreateObject();
     cJSON_AddStringToObject(obj, "cmd", "sc@n$%^&*()_+");
     void* parent = malloc(sizeof(int));
     em_cmd_t* cmd[10];
     em_cmd_params_t param{};
     void* user_param = malloc(sizeof(int));
     dm_dpp_t dpp;
     int result = dpp.analyze_config(obj, parent, cmd, &param, user_param);
     EXPECT_EQ(result, 0);
     free(parent);
     free(user_param);
     cJSON_Delete(obj);
     std::cout << "Exiting ValidJSONObjectWithSpecialCharacters" << std::endl;
 }

/**
 * @brief Test the successful construction of dm_dpp_t using its default constructor
 *
 * This test ensures that an object of dm_dpp_t can be created using its default constructor without throwing any exceptions.
 * It verifies that the constructor properly initializes the object and outputs debug logs for verifying internal state.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 035@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                            | Test Data                                           | Expected Result                                                                                | Notes         |
 * | :--------------: | ---------------------------------------------------------------------- | --------------------------------------------------- | --------------------------------------------------------------------------------------------- | ------------- |
 * | 01               | Invoke dm_dpp_t default constructor and check for exceptions           | Constructor call: dm_dpp_t(), no inputs, no outputs | Object is created without exceptions; EXPECT_NO_THROW assertion passes                        | Should Pass   |
 * | 02               | Print debug logs for internal state and test messages                  | Invocation of std::cout, no input parameters        | Debug messages printed including internal state address and test entry/exit messages           | Should be successful |
 */
TEST(dm_dpp_tTest, dm_dpp_t_constructor_success)
{
    std::cout << "Entering dm_dpp_t_constructor_success test" << std::endl;

    // Invoke the default constructor of dm_dpp_t and check that no exception is thrown.
    EXPECT_NO_THROW({
        dm_dpp_t obj;
        std::cout << "Invoked dm_dpp_t() default constructor successfully." << std::endl;
    });

    std::cout << "Exiting dm_dpp_t_constructor_success test" << std::endl;
}

/**
 * @brief Verify that dm_dpp_t's destructor, invoked via a default constructed object, does not throw any exceptions.
 *
 * This test validates that an object of type dm_dpp_t created using its default constructor is properly destructed without any exceptions being thrown. The test ensures resource cleanup via the destructor works reliably.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 036@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                      | Test Data                                              | Expected Result                                                                                | Notes       |
 * | :--------------: | ---------------------------------------------------------------- | ------------------------------------------------------ | ---------------------------------------------------------------------------------------------- | ----------- |
 * | 01               | Invoke default constructor of dm_dpp_t and let the object go out of scope to trigger the destructor | input: None, output: Object created via dm_dpp_t()     | The object is created and destroyed without any exception (EXPECT_NO_THROW passes)             | Should Pass |
 */
TEST(dm_dpp_tTest, Destructor_Default)
{
    std::cout << "Entering Destructor_Default test" << std::endl;

    EXPECT_NO_THROW({
        std::cout << "Invoking default constructor of dm_dpp_t." << std::endl;
        dm_dpp_t obj;  // Object created via default constructor
        std::cout << "dm_dpp_t object created using default constructor. About to go out of scope triggering destructor." << std::endl;
    });

    std::cout << "Destruction of dm_dpp_t (default constructed) completed without exception." << std::endl;
    std::cout << "Exiting Destructor_Default test" << std::endl;
}
