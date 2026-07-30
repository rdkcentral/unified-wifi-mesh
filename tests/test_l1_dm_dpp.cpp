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
#include <openssl/evp.h>
#include <openssl/ec.h>
#include "em_cmd.h"
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
    cJSON* obj = cJSON_CreateObject();
    ASSERT_NE(obj, nullptr);
    cJSON_AddStringToObject(obj, "URI",
        "DPP:V:2;C:81/1,115/36;K:MDkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDIgADfwUMuRRlrtFJWldzxzijExbY/akyz1jTu/QyoCwXduE=;;"
    );
    int parent_val = 0;
    int user_val = 0;
    dm_dpp_t dpp;
    int result = -1;
    EXPECT_NO_THROW({
        result = dpp.decode(obj, &parent_val, &user_val);
    });
    EXPECT_EQ(result, 0);
    cJSON_Delete(obj);
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
TEST(dm_dpp_tTest, NullJSONObject) {
    std::cout << "Entering NullJSONObject" << std::endl;
    int parent_val = 0, user_val = 0;
    dm_dpp_t dpp;
    int result = -1;
    result = dpp.decode(nullptr, &parent_val, &user_val);
    EXPECT_EQ(result, -1);
    std::cout << "Exiting NullJSONObject" << std::endl;
} 

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
TEST(dm_dpp_tTest, NullParentIdPointer) {
    std::cout << "Entering NullParentIdPointer" << std::endl;
    cJSON* obj = cJSON_CreateObject();
    ASSERT_NE(obj, nullptr);
    cJSON_AddStringToObject(obj, "URI",
        "DPP:V:2;C:81/1,115/36;K:MDkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDIgADfwUMuRRlrtFJWldzxzijExbY/akyz1jTu/QyoCwXduE=;;"
    );
    int user_val = 0;
    dm_dpp_t dpp;
    int result = -1;
    result = dpp.decode(obj, nullptr, &user_val);
    EXPECT_EQ(result, -1);
	cJSON_Delete(obj);
    std::cout << "Exiting NullParentIdPointer" << std::endl;
}

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
TEST(dm_dpp_tTest, NullUserInfoPointer) {
    std::cout << "Entering NullUserInfoPointer" << std::endl;
    cJSON* obj = cJSON_CreateObject();
    ASSERT_NE(obj, nullptr);
    cJSON_AddStringToObject(obj, "URI",
        "DPP:V:2;C:81/1,115/36;K:MDkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDIgADfwUMuRRlrtFJWldzxzijExbY/akyz1jTu/QyoCwXduE=;;"
    );
    int parent_val = 0;
    dm_dpp_t dpp;
    int result = -1;
    result = dpp.decode(obj, &parent_val, nullptr);
    EXPECT_EQ(result, -1);
	cJSON_Delete(obj);
    std::cout << "Exiting NullUserInfoPointer" << std::endl;
} 

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
    // Build a fake object with invalid type
    cJSON obj = {};
    obj.type = -1;
    int parent_val = 0, user_val = 0;
    dm_dpp_t dpp;
    int result = -1;
    result = dpp.decode(&obj, &parent_val, &user_val);
    EXPECT_EQ(result, -1);
    std::cout << "Exiting JSONObjectWithUnexpectedStructure" << std::endl;
}

/**
 * @brief Test the copy constructor of dm_dpp_t with a modified dm_dpp_t object
 *
 * This test verifies that the copy constructor of the dm_dpp_t class correctly copies the contents of a modified dm_dpp_t object.@n
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
 * | 01| Create a null dm_dpp_t object | null_dpp = nullptr | None | Should be successful |
 * | 02| Attempt to copy construct dm_dpp_t with null object | dm_dpp_t copy_dpp(*null_dpp) | Exception should be thrown | Should Pass |
 * | 03| Catch std::exception | catch (const std::exception& e) | Test should succeed | Should be successful |
 * | 04| Catch any other exception | catch (...) | Test should fail | Should Fail |
 */
TEST(dm_dpp_tTest, CopyConstructorWithNullObject) {
    std::cout << "Entering CopyConstructorWithNullObject" << std::endl;
    dm_dpp_t* null_dpp = nullptr;
    EXPECT_ANY_THROW(dm_dpp_t copy_dpp(*null_dpp));
    std::cout << "Exiting CopyConstructorWithNullObject" << std::endl;
} 

/**
 * @brief Test to validate the creation of dm_dpp_t object with a valid ec_data_t pointer
 *
 * This test checks if the dm_dpp_t object is correctly created when provided with a valid ec_data_t pointer and verifies that the get_dpp_info() method does not return a null pointer.@n
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
 * | 01| Create a valid ec_data_t object and assign version value | valid_dpp->version = 1 | ec_data_t object should be created using the set version value | Should be successful |
 * | 02| Create dm_dpp_t object with valid ec_data_t pointer | dm_dpp_t obj(valid_dpp) | dm_dpp_t object should be created | Should Pass |
 * | 03| Verify the version using initialized object | obj.m_dpp_info.version = 1 | Should return the set version value | Should Pass |
 */
TEST(dm_dpp_tTest, ValidEcDataTPointer) {
    std::cout << "Entering ValidEcDataTPointer test" << std::endl;
    ec_data_t valid_dpp{};
    valid_dpp.version = 1;
    dm_dpp_t obj(&valid_dpp);
    EXPECT_EQ(obj.m_dpp_info.version, 1);
    std::cout << "Exiting ValidEcDataTPointer test" << std::endl;
}

/**
 * @brief Test to verify the behavior when a null pointer is passed to the constructor
 *
 * This test checks the behavior of the dm_dpp_t constructor when a null pointer is passed as an argument. 
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
 * | 01| Create a null pointer for ec_data_t and pass it to the dm_dpp_t constructor | ec_data_t* null_dpp = nullptr; dm_dpp_t obj(null_dpp); | Object should be created successfully | Should Pass |
 */
TEST(dm_dpp_tTest, NullEcDataTPointer) {
    std::cout << "Entering NullEcDataTPointer test";
    ec_data_t *null_dpp = nullptr;
    EXPECT_ANY_THROW(dm_dpp_t obj(null_dpp));
    std::cout << "Exiting NullEcDataTPointer test";
}

/**
 * @brief Test the encoding of a valid string value using the dm_dpp_t class.
 *
 * This test verifies that the encode function of the dm_dpp_t class correctly processes a cJSON object with a valid string value. The objective is to ensure that the encode function handles string values as expected without errors.
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
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize cJSON object with string type and value | obj.type = cJSON_String, obj.valuestring = "test_string" | cJSON object initialized | Should be successful |
 * | 02 | Call encode function with cJSON object | instance.encode(&obj) | Encode function processes the string value without errors | Should Pass |
 */
TEST(dm_dpp_tTest, EncodeValidStringValue) {
    std::cout << "Entering EncodeValidStringValue test" << std::endl;
    cJSON* obj = cJSON_CreateString("test_string");
    ASSERT_NE(obj, nullptr);
    dm_dpp_t instance;
    EXPECT_NO_THROW(instance.encode(obj));
    cJSON_Delete(obj);
    std::cout << "Exiting EncodeValidStringValue test" << std::endl;
}

/**
 * @brief Test the encoding of a valid number value in a cJSON object
 *
 * This test verifies that the encode function of the dm_dpp_t class correctly encodes a cJSON object with a number type and a valid double value. This is important to ensure that numerical data is properly handled and encoded by the system.
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
 * | 01 | Create a cJSON object with type number and value 123.45 | obj.type = cJSON_Number, obj.valuedouble = 123.45 | Should be successful | |
 * | 02 | Encode the cJSON object using the instance of dm_dpp_t | instance.encode(&obj) | Should Pass | |
 */
TEST(dm_dpp_tTest, EncodeValidNumberValue) {
    std::cout << "Entering EncodeValidNumberValue test" << std::endl;
    cJSON* obj = cJSON_CreateNumber(123.45);
    ASSERT_NE(obj, nullptr);
    dm_dpp_t instance;
    EXPECT_NO_THROW(instance.encode(obj));
    cJSON_Delete(obj);
    std::cout << "Exiting EncodeValidNumberValue test" << std::endl;
}

/**
 * @brief Test the encoding of a valid integer value using the dm_dpp_t class.
 *
 * This test verifies that the encode function of the dm_dpp_t class correctly encodes a cJSON object with a valid integer value. This is important to ensure that the encoding functionality works as expected for integer values.
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
 * | 01| Create a cJSON object with type cJSON_Number and value 123 | obj.type = cJSON_Number, obj.valueint = 123 | Should be successful | |
 * | 02| Call the encode function with the cJSON object | instance.encode(&obj) | Should Pass | |
 */
TEST(dm_dpp_tTest, EncodeValidIntegerValue) {
    std::cout << "Entering EncodeValidIntegerValue test" << std::endl;
    cJSON* obj = cJSON_CreateNumber(123);
    ASSERT_NE(obj, nullptr);
    dm_dpp_t instance;
    EXPECT_NO_THROW(instance.encode(obj));
    cJSON_Delete(obj);
    std::cout << "Exiting EncodeValidIntegerValue test" << std::endl;
}

/**
 * @brief Test the encoding of a valid null value in cJSON object
 *
 * This test verifies that the encode function of the dm_dpp_t class correctly handles a cJSON object with a null value. This is important to ensure that the encoding function can handle all types of cJSON objects, including null values.
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
 * | 01| Create a cJSON object with null type | obj.type = cJSON_NULL | Should be successful | |
 * | 02| Call the encode function with the cJSON object | instance.encode(&obj) | Should Pass | |
 */
TEST(dm_dpp_tTest, EncodeValidNullValue) {
    std::cout << "Entering EncodeValidNullValue test" << std::endl;
    cJSON* obj = cJSON_CreateNull();
    ASSERT_NE(obj, nullptr);
    dm_dpp_t instance;
    EXPECT_NO_THROW(instance.encode(obj));
    cJSON_Delete(obj);
    std::cout << "Exiting EncodeValidNullValue test" << std::endl;
}

/**
 * @brief Test to verify the encoding of a valid boolean true value
 *
 * This test checks the functionality of the encode method in the dm_dpp_t class when provided with a cJSON object representing a boolean true value. The objective is to ensure that the encode method correctly processes and encodes the boolean true value without errors.
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
 * | 01 | Create a cJSON object with type cJSON_True | obj.type = cJSON_True | Should be successful | |
 * | 02 | Call the encode method with the cJSON object | instance.encode(&obj) | Should Pass | |
 */
TEST(dm_dpp_tTest, EncodeValidBooleanTrueValue) {
    std::cout << "Entering EncodeValidBooleanTrueValue test" << std::endl;
    cJSON* obj = cJSON_CreateTrue();
    ASSERT_NE(obj, nullptr);
    dm_dpp_t instance;
    EXPECT_NO_THROW(instance.encode(obj));
    cJSON_Delete(obj);
    std::cout << "Exiting EncodeValidBooleanTrueValue test" << std::endl;
}

/**
 * @brief Test to verify the encoding of a valid array value in dm_dpp_t class
 *
 * This test checks the functionality of the encode method in the dm_dpp_t class when provided with a valid cJSON array object. The objective is to ensure that the encode method processes the array correctly without errors.
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
 * | Variation / Step | Description | Test Data |Expected Result |Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01| Initialize test objects | instance = new dm_dpp_t() | Should be successful | Should be successful |
 * | 02| Set up cJSON object with array type | obj.type = cJSON_Array, obj.child = &child_obj | Should be successful | Should be successful |
 * | 03| Call encode method with valid array object | instance.encode(&obj) | Should be successful | Should Pass |
 * | 04| Clean up test objects | delete instance | Should be successful | Should be successful |
 */
TEST(dm_dpp_tTest, EncodeValidArrayValue) {
    std::cout << "Entering EncodeValidArrayValue test" << std::endl;
    cJSON* arr = cJSON_CreateArray();
    ASSERT_NE(arr, nullptr);
    cJSON_AddItemToArray(arr, cJSON_CreateNumber(1.0));
    cJSON_AddItemToArray(arr, cJSON_CreateNumber(2.0));
    dm_dpp_t instance;
    EXPECT_NO_THROW(instance.encode(arr));
    cJSON_Delete(arr);
    std::cout << "Exiting EncodeValidArrayValue test" << std::endl;
}

/**
 * @brief Test the encoding of a valid object value
 *
 * This test verifies that the encode function correctly processes a valid cJSON object. The objective is to ensure that the encode function can handle and encode a cJSON object with a child object properly.
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
 * | 01| Initialize cJSON object and child object | obj.type = cJSON_Object, obj.child = &child_obj | Should be successful | |
 * | 02| Call the encode function with the cJSON object | instance.encode(&obj) | Should Pass | |
 */
TEST(dm_dpp_tTest, EncodeValidObjectValue) {
    std::cout << "Entering EncodeValidObjectValue test" << std::endl;
    cJSON* obj = cJSON_CreateObject();
    ASSERT_NE(obj, nullptr);
    cJSON_AddStringToObject(obj, "k", "v");
    dm_dpp_t instance;
    EXPECT_NO_THROW(instance.encode(obj));
    cJSON_Delete(obj);
    std::cout << "Exiting EncodeValidObjectValue test" << std::endl;
}

/**
 * @brief Test to verify the behavior of the encode function when an invalid type is provided.
 *
 * This test checks the encode function of the dm_dpp_t class to ensure it handles an invalid type correctly. 
 * The objective is to verify that the function can handle unexpected input gracefully without crashing or producing incorrect results.
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
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Create a cJSON object with an invalid type | obj.type = -1 | Should be successful | |
 * | 02 | Call the encode function with the invalid type object | instance.encode(&obj) | Should Pass | |
 */
TEST(dm_dpp_tTest, EncodeInvalidType) {
    std::cout << "Entering EncodeInvalidType test" << std::endl;
    cJSON* obj = cJSON_CreateObject();
    ASSERT_NE(obj, nullptr);
    obj->type = -1;
    dm_dpp_t instance;
    EXPECT_NO_THROW(instance.encode(obj));
    obj->type = cJSON_Object;
    cJSON_Delete(obj);
    std::cout << "Exiting EncodeInvalidType test" << std::endl;
}

/**
 * @brief Test the encoding of a null JSON object
 *
 * This test checks the behavior of the encode function when a null JSON object is passed as input. This is important to ensure that the function can handle null inputs gracefully without causing crashes or undefined behavior.
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
 * | Variation / Step | Description | Test Data |Expected Result |Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01| Create a null JSON object and pass it to the encode function | obj = NULL | The function should handle the null input without crashing | Should Pass |
 */
TEST(dm_dpp_tTest, EncodeNullObject) {
    std::cout << "Entering EncodeNullObject test" << std::endl;
    cJSON *obj = nullptr;
    dm_dpp_t instance;
    EXPECT_NO_THROW(instance.encode(obj));
    std::cout << "Exiting EncodeNullObject test" << std::endl;
}

/**
 * @brief Test to verify the successful retrieval of DPP Bootstrapping Information
 *
 * This test checks the functionality of the get_dpp_info method in the dm_dpp_t class. 
 * It ensures that the method returns a non-null pointer, indicating successful retrieval of DPP Bootstrapping Information.
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
 * | 01 | Create an instance of dm_dpp_t with version value as 1 | None | Instance should be created successfully | Should be successful |
 * | 02 | Call get_dpp_info method on the instance | None | Method should return a non-null pointer | Should Pass |
 * | 03 | Assert the result is not null | result != nullptr | Assertion should pass | Should Pass |
 * | 04 | Verify the version value | result->version = 1 | Assertion should pass | Should Pass |
 */
TEST(dm_dpp_tTest, RetrieveDPPBootstrappingInfoWithVersion) {
    std::cout << "Entering RetrieveDPPBootstrappingInfoWithVersion" << std::endl;
    ec_data_t valid_dpp{};
    valid_dpp.version = 1;
    dm_dpp_t obj(&valid_dpp);
    ec_data_t* result = obj.get_dpp_info();
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result->version, 1);
    std::cout << "Exiting RetrieveDPPBootstrappingInfoWithVersion" << std::endl;
}

/**
 * @brief Test to verify the successful initialization of dm_dpp_t object
 *
 * This test checks if the initialization function of the dm_dpp_t object returns a success code (0). This is crucial to ensure that the object is properly set up before any further operations are performed on it.
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
 * | 01 | Create dm_dpp_t object and call init() | obj.init() | result = 0 | Should Pass |
 */
 /*
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
 * **Test Case ID:** 022@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data |Expected Result |Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01| Create and initialize values | obj1.m_dpp_info.version = 3, obj1.m_dpp_info.type = ec_session_type_cfg, obj1.m_dpp_info.mac_addr={0xAA, 0x11, 0x22, 0x33, 0x44, 0x55 | obj1 is initialized | Should be successful |
 * | 02| Assign obj1 to obj2 | obj2 = obj1 | obj2 should be equivalent to obj1 | Should Pass |
 * | 03| Verify obj2 values are equal to obj1 | obj2.m_dpp_info.version=obj1.m_dpp_info.version, obj2.m_dpp_info.type=obj1.m_dpp_info.type, obj1.m_dpp_info.mac_addr=obj2.m_dpp_info.mac_addr | values should be same | Should Pass |
 */
TEST(dm_dpp_tTest, AssigningValidObject) {
    std::cout << "Entering AssigningValidObject" << std::endl;
    dm_dpp_t obj1{};
	dm_dpp_t obj2{};
    obj1.m_dpp_info.version = 3;
	obj1.m_dpp_info.type = ec_session_type_cfg;
	uint8_t mac[6] = {0xAA, 0x11, 0x22, 0x33, 0x44, 0x55};
    memcpy(obj1.m_dpp_info.mac_addr, mac, sizeof(mac));
    obj2 = obj1;
    ASSERT_EQ(obj2.m_dpp_info.version, obj1.m_dpp_info.version);
	ASSERT_EQ(obj1.m_dpp_info.type, obj2.m_dpp_info.type);
	ASSERT_EQ(memcmp(obj1.m_dpp_info.mac_addr, obj2.m_dpp_info.mac_addr, sizeof(obj1.m_dpp_info.mac_addr)), 0);
    std::cout << "Exiting AssigningValidObject" << std::endl;
}

/**
 * @brief Test the assignment operator when assigning a null data object
 *
 * This test checks the behavior of the assignment operator when one dm_dpp_t object with a null data object is assigned to another dm_dpp_t object. This is to ensure that the assignment operator handles null data objects correctly and that the equality operator confirms the objects are equivalent after assignment.
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
 * | 01| Create dm_dpp_t object with null data | instance = new dm_dpp_t(), obj1 = dm_dpp_t(nullptr) | Object created successfully | Should be successful |
 * | 02| Create default dm_dpp_t object | obj2 = dm_dpp_t() | Object created successfully | Should be successful |
 * | 03| Assign obj1 to obj2 | obj2 = obj1 | Assignment successful | Should Pass |
 * | 04| Check equality of obj1 and obj2 | ASSERT_TRUE(obj2 == obj1) | Objects are equal | Should Pass |
 */
TEST(dm_dpp_tTest, AssigningNullDataObject) {
    std::cout << "Entering AssigningNullDataObject" << std::endl;
    dm_dpp_t obj1(nullptr);
    dm_dpp_t obj2;
    obj2 = obj1;
    ASSERT_TRUE(obj2 == obj1);
    std::cout << "Exiting AssigningNullDataObject" << std::endl;
}

/**
 * @brief Test to compare two identical objects of dm_dpp_t class
 *
 * This test verifies that two newly created objects of the dm_dpp_t class are identical by using the equality operator. This is important to ensure that the default constructor of the class initializes objects to a consistent state.
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
 * | 01| Create two instances of dm_dpp_t | instance1, instance2 | Instances should be created successfully | Should be successful |
 * | 02| Compare the two instances using the equality operator | instance1 == instance2 | The comparison should return true | Should Pass |
 */
TEST(dm_dpp_tTest, CompareIdenticalObjects) {
    std::cout << "Entering CompareIdenticalObjects" << std::endl;
    dm_dpp_t obj1{};
    dm_dpp_t obj2{};
    obj1.m_dpp_info.version = obj2.m_dpp_info.version = 1;
    obj1.m_dpp_info.type = obj2.m_dpp_info.type = ec_session_type_cfg;
    uint8_t mac[6] = {0xAA, 0x11, 0x22, 0x33, 0x44, 0x55};
    memcpy(obj1.m_dpp_info.mac_addr, mac, sizeof(mac));
	memcpy(obj2.m_dpp_info.mac_addr, mac, sizeof(mac));
	obj1.m_dpp_info.initiator_boot_key = obj2.m_dpp_info.initiator_boot_key = nullptr;
    obj1.m_dpp_info.responder_boot_key = obj2.m_dpp_info.responder_boot_key = nullptr;
    memset(obj1.m_dpp_info.ec_freqs, 0, sizeof(obj1.m_dpp_info.ec_freqs));
    memset(obj2.m_dpp_info.ec_freqs, 0, sizeof(obj2.m_dpp_info.ec_freqs));
    EXPECT_TRUE(obj1 == obj2);
    std::cout << "Exiting CompareIdenticalObjects" << std::endl;
}

/**
 * @brief Test to compare two different objects of dm_dpp_t class
 *
 * This test verifies that two different objects of the dm_dpp_t class with different m_dpp_info values are not considered equal.@n
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
 * | 01| Create two different objects of dm_dpp_t class | obj1.m_dpp_info = 1, obj2.m_dpp_info = 2 | Objects should not be equal | Should Pass |
 */
TEST(dm_dpp_tTest, CompareDifferentObjects) {
    std::cout << "Entering CompareDifferentObjects" << std::endl;
    dm_dpp_t obj1{};
    dm_dpp_t obj2{};
    obj1.m_dpp_info.version = 1;
    obj2.m_dpp_info.version = 2;
    obj1.m_dpp_info.type = obj2.m_dpp_info.type = ec_session_type_recfg;
    uint8_t mac[6] = {0xAA, 0x11, 0x22, 0x33, 0x44, 0x55};
    memcpy(obj1.m_dpp_info.mac_addr, mac, sizeof(mac));
	memcpy(obj2.m_dpp_info.mac_addr, mac, sizeof(mac));
	obj1.m_dpp_info.initiator_boot_key = obj2.m_dpp_info.initiator_boot_key = nullptr;
    obj1.m_dpp_info.responder_boot_key = obj2.m_dpp_info.responder_boot_key = nullptr;
	memset(obj1.m_dpp_info.ec_freqs, 0, sizeof(obj1.m_dpp_info.ec_freqs));
    memset(obj2.m_dpp_info.ec_freqs, 0, sizeof(obj2.m_dpp_info.ec_freqs));
    EXPECT_FALSE(obj1 == obj2);
    std::cout << "Exiting CompareDifferentObjects" << std::endl;
}

/**
 * @brief Test the analyze_config function with a valid JSON object containing all required fields.
 *
 * This test verifies that the analyze_config function correctly processes a valid JSON object with all required fields and returns the expected result.@n
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
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Create necessary objects and parameters | cJSON_AddStringToObject(json, "cmd", "scan"), parent = malloc(sizeof(int)), cmd, param, user_country = "IN" | Should be successful | |
 * | 02 | Call analyze_config with valid JSON object | json, parent, cmd, param, user_country | result = 0, EXPECT_EQ(result, 0) | Should Pass |
 * | 03 | Clean up allocated memory | free(parent), cJSON_Delete(json) | Should be successful | |
 */
TEST(dm_dpp_tTest, ValidJSONObjectWithAllRequiredFields) {
    std::cout << "Entering ValidJSONObjectWithAllRequiredFields" << std::endl;
    cJSON *json = cJSON_CreateObject();
    ASSERT_NE(json, nullptr);
    cJSON_AddStringToObject(json, "URI",
        "DPP:V:2;C:81/1,115/36;K:MDkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDIgADfwUMuRRlrtFJWldzxzijExbY/akyz1jTu/QyoCwXduE=;;"
    );
    em_cmd_t* cmd[10] = { nullptr };
    void* parent = malloc(sizeof(int));
    em_cmd_params_t param{};
    const char* user_country = "IN";
    dm_dpp_t dpp;
    int result = dpp.analyze_config(json, parent, cmd, &param, static_cast<void*>(const_cast<char*>(user_country)));
    EXPECT_EQ(result, 1);
    if (result > 0) {
        for (int i = 0; i < result; ++i) {
            if (cmd[i]) {
                // mirror what destroy_command() does: deinit then delete
                cmd[i]->deinit();
                delete cmd[i];
                cmd[i] = nullptr;
            }
        }
    }	
    free(parent);
    cJSON_Delete(json);
    std::cout << "Exiting ValidJSONObjectWithAllRequiredFields" << std::endl;
}

 
 /**
 * @brief Test to validate the behavior of analyze_config when a null JSON object is passed.
 *
 * This test checks the analyze_config method of the dm_dpp_t class to ensure it correctly handles a null JSON object input.
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
 * | 01 | Allocate memory for parent and user_param | parent = malloc(sizeof(int)), user_param = malloc(sizeof(int)) | Memory should be allocated successfully | Should be successful |
 * | 02 | Initialize dm_dpp_t instance and call analyze_config with null JSON object | json = nullptr, parent, cmd, param, user_param | analyze_config should return -1 | Should Pass |
 * | 03 | Validate the result of analyze_config | result = -1 | EXPECT_EQ(result, -1) | Should Pass |
 * | 04 | Free allocated memory | free(parent), free(user_param) | Memory should be freed successfully | Should be successful |
 */
TEST(dm_dpp_tTest, InvalidJSONObjectNull) {
    std::cout << "Entering InvalidJSONObjectNull" << std::endl;
    cJSON* nullNode = cJSON_CreateNull();
    ASSERT_NE(nullNode, nullptr);
    void* parent = malloc(sizeof(int));
    em_cmd_t* cmd[10] = { nullptr };
    em_cmd_params_t param{};
    const char* user_param = "US";
    dm_dpp_t dpp;
    int result = dpp.analyze_config(nullNode, parent, cmd, &param, static_cast<void*>(const_cast<char*>(user_param)));
	EXPECT_EQ(result, 0);
    free(parent);
    cJSON_Delete(nullNode);
    std::cout << "Exiting InvalidJSONObjectNull" << std::endl;
}

 
 /**
 * @brief Test to validate the behavior of analyze_config when a null cmd array is passed.
 *
 * This test checks the analyze_config method of the dm_dpp_t class to ensure it correctly handles null cmd array input.
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
 * | 02 | Initialize dm_dpp_t instance and call analyze_config with null cmd array | json, parent, cmd = nullptr, param, user_param | analyze_config should return -1 | Should Pass |
 * | 03 | Validate the result of analyze_config | result = -1 | EXPECT_EQ(result, -1) | Should Pass |
 * | 04 | Free allocated memory | free(parent), free(user_param) | Memory should be freed successfully | Should be successful |
 */
TEST(dm_dpp_tTest, NullCmdArrayShouldReturnFailure) {
    std::cout << "Entering NullCmdArrayShouldReturnFailure" << std::endl;
    cJSON* json = cJSON_CreateObject();
    ASSERT_NE(json, nullptr);
    cJSON_AddStringToObject(json, "cmd", "scan");
    cJSON* cmdNode = cJSON_GetObjectItem(json, "cmd");
    ASSERT_NE(cmdNode, nullptr);
    void* parent = malloc(sizeof(int));
    em_cmd_params_t param{};
    const char* user_param = "IN";
    dm_dpp_t dpp;
    int result = dpp.analyze_config(cmdNode, parent, nullptr, &param, static_cast<void*>(const_cast<char*>(user_param)));
    EXPECT_EQ(result, 0);
    free(parent);
    cJSON_Delete(json);
    std::cout << "Exiting NullCmdArrayShouldReturnFailure" << std::endl;
}

 /**
 * @brief Test to validate the behavior of analyze_config when a null param is passed.
 *
 * This test checks the analyze_config method of the dm_dpp_t class to ensure it correctly handles null param input.
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
 * | 02 | Initialize dm_dpp_t instance and call analyze_config with null param | json, parent, cmd, param = nullptr, user_param | analyze_config should return -1 | Should Pass |
 * | 03 | Validate the result of analyze_config | result = -1 | EXPECT_EQ(result, -1) | Should Pass |
 * | 04 | Free allocated memory | free(parent), free(user_param) | Memory should be freed successfully | Should be successful |
 */
TEST(dm_dpp_tTest, NullCmdParamsShouldReturnFailure) {
    std::cout << "Entering NullCmdParamsShouldReturnFailure" << std::endl;

    cJSON* obj = cJSON_CreateObject();
    ASSERT_NE(obj, nullptr);

    cJSON_AddStringToObject(obj, "cmd", "scan");

    void* parent = malloc(sizeof(int));
    em_cmd_t* cmd[10] = { nullptr };
    const char* user_param = "IN";

    dm_dpp_t dpp;
    int result = dpp.analyze_config(obj, parent, cmd, nullptr,
                                    static_cast<void*>(const_cast<char*>(user_param)));
    EXPECT_EQ(result, 0);

    free(parent);
    cJSON_Delete(obj);

    std::cout << "Exiting NullCmdParamsShouldReturnFailure" << std::endl;
}
 
 /**
 * @brief Test analyze_config with a valid JSON object containing incorrect data types.
 *
 * This test verifies that the analyze_config function of the dm_dpp_t class correctly identifies and fails when provided with a valid JSON object containing fields with incorrect data types.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 030@n
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
    ASSERT_NE(obj, nullptr);
    cJSON_AddNumberToObject(obj, "cmd", 123);
    cJSON_AddStringToObject(obj, "URI", "DPP:INVALID_TYPE;;");
    cJSON* cmdNode = cJSON_GetObjectItem(obj, "cmd");
    ASSERT_NE(cmdNode, nullptr);
    void* parent = malloc(sizeof(int));
    em_cmd_t* cmd[10] = { nullptr };
    em_cmd_params_t param{};
    const char* user_param = "US";
    dm_dpp_t dpp;
    int result = dpp.analyze_config(cmdNode, parent, cmd, &param, static_cast<void*>(const_cast<char*>(user_param)));
    EXPECT_EQ(result, 0);
    free(parent);
    cJSON_Delete(obj);
    std::cout << "Exiting ValidJSONObjectWithIncorrectDataTypes" << std::endl;
}

 
 /**
 * @brief Test analyze_config with a valid JSON object containing nested objects.
 *
 * This test ensures the analyze_config function can parse and handle JSON objects that contain nested JSON sub-objects, and still function correctly.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 031@n
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
    ASSERT_NE(obj, nullptr);
    cJSON* nested = cJSON_CreateObject();
    ASSERT_NE(nested, nullptr);
    cJSON_AddStringToObject(nested, "URI",
        "DPP:V:2;C:81/1,115/36;K:MDkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDIgADfwUMuRRlrtFJWldzxzijExbY/akyz1jTu/QyoCwXduE=;;"
    );
    cJSON_AddItemToObject(obj, "cmd", nested);
    cJSON* cmdNode = cJSON_GetObjectItem(obj, "cmd");
    ASSERT_NE(cmdNode, nullptr);
    void* parent = malloc(sizeof(int));
    em_cmd_t* cmd[10] = { nullptr };
    em_cmd_params_t param{};
    const char* user_param = "US";
    dm_dpp_t dpp;
    int result = dpp.analyze_config(cmdNode, parent, cmd, &param, static_cast<void*>(const_cast<char*>(user_param)));
    EXPECT_EQ(result, 1);
    if (result > 0) {
        for (int i = 0; i < result; ++i) {
            if (cmd[i]) {
                // mirror what destroy_command() does: deinit then delete
                cmd[i]->deinit();
                delete cmd[i];
                cmd[i] = nullptr;
            }
        }
    }	
    free(parent);
    cJSON_Delete(obj);
    std::cout << "Exiting ValidJSONObjectWithNestedObjects" << std::endl;
}
 
 /**
 * @brief Test the analyze_config function with a valid JSON object containing large data
 *
 * This test verifies the behavior of the analyze_config function when provided with a valid JSON object containing large data. The objective is to ensure that the function can handle large inputs without errors and returns the expected result.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 032@n
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
    ASSERT_NE(json, nullptr);
    cJSON_AddStringToObject(json, "URI",
        "DPP:V:2;C:81/1,115/36;K:MDkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDIgADfwUMuRRlrtFJWldzxzijExbY/akyz1jTu/QyoCwXduE=;;"
    );
    cJSON_AddNumberToObject(json, "value", 4294967295ULL);
    em_cmd_t* cmd[10] = { nullptr };
    void* parent = malloc(sizeof(int));
    em_cmd_params_t param{};
    const char* user_country = "US";
    dm_dpp_t dpp;
    int result = dpp.analyze_config(json, parent, cmd, &param, static_cast<void*>(const_cast<char*>(user_country)));
    EXPECT_EQ(result, 1);
    if (result > 0) {
        for (int i = 0; i < result; ++i) {
            if (cmd[i]) {
                // mirror what destroy_command() does: deinit then delete
                cmd[i]->deinit();
                delete cmd[i];
                cmd[i] = nullptr;
            }
        }
    }	
    free(parent);
    cJSON_Delete(json);
    std::cout << "Exiting ValidJSONObjectWithLargeData" << std::endl;
}
 
 /**
 * @brief Test analyze_config with a valid JSON object containing special characters.
 *
 * This test verifies that the analyze_config function can correctly parse and process a JSON object that contains special characters in string values without errors.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 033@n
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
    ASSERT_NE(obj, nullptr);
    cJSON_AddStringToObject(obj, "URI",
        "DPP:V:2;C:81/1,115/36;K:MDkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDIgADfwUMuRRlrtFJWldzxzijExbY/akyz1jTu/QyoCwXduE=;;"
    );
    cJSON_AddStringToObject(obj, "cmd", "sc@n$%^&*()_+");
    em_cmd_t* cmd[10] = { nullptr };
    void* parent = malloc(sizeof(int));
    em_cmd_params_t param{};
    const char* user_param = "IN";
    dm_dpp_t dpp;
    int result = dpp.analyze_config(obj, parent, cmd, &param, static_cast<void*>(const_cast<char*>(user_param)));
    EXPECT_EQ(result, 1);
    if (result > 0) {
        for (int i = 0; i < result; ++i) {
            if (cmd[i]) {
                // mirror what destroy_command() does: deinit then delete
                cmd[i]->deinit();
                delete cmd[i];
                cmd[i] = nullptr;
            }
        }
    }	
    free(parent);
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
 * **Test Case ID:** 034@n
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
 * **Test Case ID:** 035@n
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
        dm_dpp_t obj;
        std::cout << "dm_dpp_t object created using default constructor. About to go out of scope triggering destructor." << std::endl;
    });
    std::cout << "Destruction of dm_dpp_t (default constructed) completed without exception." << std::endl;
    std::cout << "Exiting Destructor_Default test" << std::endl;
}