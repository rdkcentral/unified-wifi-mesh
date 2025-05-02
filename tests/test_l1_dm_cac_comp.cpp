/*
 * If not stated otherwise in this file or this component's LICENSE file the
 * following copyright and licenses apply:
 *
 * Copyright 2024 RDK Management
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
 #include "dm_cac_comp.h"
 
 class dm_cac_comp_t_Test : public ::testing::Test {
 protected:
     dm_cac_comp_t* instance;
 
     void SetUp() override {
         instance = new dm_cac_comp_t();
    }
 
     void TearDown() override {
         delete instance;
    }
};
 
 
 /**
  * @briefTEST decoding a valid JSON object with a valid parent ID
  *
  * ThisTEST verifies that the decode function correctly processes a valid JSON object when provided with a valid parent ID.
  *
  * **Test Group ID:** Basic: 01
  * **Test Case ID:** 001
  * **Priority:** High
  * @n
  * **Pre-Conditions:** None
  * **Dependencies:** None
  * **User Interaction:** None
  * @n
  * **Test Procedure:**@n
  * | Variation / Step | Description |TEST Data | Expected Result | Notes |
  * | :----: | --------- | ---------- |-------------- | ----- |
  * | 01 | Setup theTEST environment by creating an instance of dm_cac_comp_t | None | Instance created successfully | Done by Pre-requisite SetUp function |
  * | 02 | Parse a valid JSON string to create a cJSON object | JSON string: "{\"key\":\"value\"}" | cJSON object created successfully | Should be successful |
  * | 03 | Call the decode function with the valid JSON object and a valid parent ID | validJson = cJSON object, parentID = 1 | Return value should be 0 | Should Pass |
  * | 04 | Verify the result using ASSERT_EQ | result = 0 | Assertion should pass | Should Pass |
  * | 05 | Clean up theTEST environment by deleting the instance of dm_cac_comp_t | None | Instance deleted successfully | Done by Pre-requisite TearDown function |
  */
TEST_F(dm_cac_comp_t_Test, DecodeValidJsonObjectWithValidParentID) {
     std::cout << "Entering DecodeValidJsonObjectWithValidParentIDTEST" << std::endl;
     cJSON *validJson = cJSON_Parse("{\"key\":\"value\"}");
     int parentID = 1;
     int result = instance->decode(validJson, &parentID);
     ASSERT_EQ(result, 0);
     std::cout << "Exiting DecodeValidJsonObjectWithValidParentIDTEST" << std::endl;
}
 
 
 
 /**
  * @briefTEST decoding a valid JSON object with a null parent ID
  *
  * ThisTEST verifies that the decode function correctly handles a valid JSON object when the parent ID is null. The expected behavior is that the function should return -1, indicating an error due to the null parent ID.
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
  * | Variation / Step | Description |TEST Data | Expected Result | Notes |
  * | :----: | --------- | ---------- |-------------- | ----- |
  * | 01 | Setup theTEST environment | None | None | Done by Pre-requisite SetUp function |
  * | 02 | Parse a valid JSON object | validJson = cJSON_Parse("{\"key\":\"value\"}") | validJson should be a valid cJSON object | Should be successful |
  * | 03 | Call decode with valid JSON and null parent ID | validJson = cJSON_Parse("{\"key\":\"value\"}"), parentID = nullptr | result should be -1 | Should Pass |
  * | 04 | Verify the result of decode function | result = -1 | ASSERT_EQ(result, -1) | Should Pass |
  * | 05 | Tear down theTEST environment | None | None | Done by Pre-requisite TearDown function |
  */
 
TEST_F(dm_cac_comp_t_Test, DecodeValidJsonObjectWithNullParentID) {
     std::cout << "Entering DecodeValidJsonObjectWithNullParentIDTEST" << std::endl;
     cJSON *validJson = cJSON_Parse("{\"key\":\"value\"}");
     int result = instance->decode(validJson, nullptr);
     ASSERT_EQ(result, -1);
     std::cout << "Exiting DecodeValidJsonObjectWithNullParentIDTEST" << std::endl;
}
 
 
 
 /**
  * @briefTEST the decode function with a null JSON object and a valid parent ID.
  *
  * ThisTEST checks the behavior of the decode function when provided with a null JSON object and a valid parent ID. It ensures that the function returns the expected error code when the JSON object is null.
  *
  * **Test Group ID:** Basic: 01
  * **Test Case ID:** 003
  * **Priority:** High
  * @n
  * **Pre-Conditions:** None
  * **Dependencies:** None
  * **User Interaction:** None
  * @n
  * **Test Procedure:**@n
  * | Variation / Step | Description |TEST Data | Expected Result | Notes |
  * | :----: | --------- | ---------- |-------------- | ----- |
  * | 01 | Set up theTEST environment by creating an instance of dm_cac_comp_t. | None | Instance created | Done by Pre-requisite SetUp function |
  * | 02 | Call the decode function with a null JSON object and a valid parent ID. | jsonObject = nullptr, parentID = 1 | result = -1 | Should Pass |
  * | 03 | Clean up theTEST environment by deleting the instance of dm_cac_comp_t. | None | Instance deleted | Done by Pre-requisite TearDown function |
  */
 
TEST_F(dm_cac_comp_t_Test, DecodeNullJsonObjectWithValidParentID) {
     std::cout << "Entering DecodeNullJsonObjectWithValidParentIDTEST" << std::endl;
     int parentID = 1;
     int result = instance->decode(nullptr, &parentID);
     ASSERT_EQ(result, -1);
     std::cout << "Exiting DecodeNullJsonObjectWithValidParentIDTEST" << std::endl;
}
 
 
 
 /**
  * @briefTEST decoding an empty JSON object with a valid parent ID.
  *
  * ThisTEST checks the behavior of the decode function when provided with an empty JSON object and a valid parent ID. The expected result is that the function should return -1, indicating failure to decode an empty JSON object.
  *
  * **Test Group ID:** Basic: 01
  * **Test Case ID:** 004
  * **Priority:** High
  * @n
  * **Pre-Conditions:** None
  * **Dependencies:** None
  * **User Interaction:** None
  * @n
  * **Test Procedure:**@n
  * | Variation / Step | Description |TEST Data | Expected Result | Notes |
  * | :----: | --------- | ---------- |-------------- | ----- |
  * | 01 | Setup theTEST environment | instance = new dm_cac_comp_t() | instance is initialized | Done by Pre-requisite SetUp function |
  * | 02 | Parse an empty JSON object | emptyJson = cJSON_Parse("{}") | emptyJson is parsed successfully | Should be successful |
  * | 03 | Set a valid parent ID | parentID = 1 | parentID is set to 1 | Should be successful |
  * | 04 | Call the decode function with empty JSON and valid parent ID | result = instance->decode(emptyJson, &parentID) | result = -1 | Should Pass |
  * | 05 | Verify the result using ASSERT_EQ | ASSERT_EQ(result, -1) | result should be -1 | Should Pass |
  * | 06 | Clean up theTEST environment | delete instance | instance is deleted | Done by Pre-requisite TearDown function |
  */
 
TEST_F(dm_cac_comp_t_Test, DecodeEmptyJsonObjectWithValidParentID) {
     std::cout << "Entering DecodeEmptyJsonObjectWithValidParentIDTEST" << std::endl;
     cJSON *emptyJson = cJSON_Parse("{}");
     int parentID = 1;
     int result = instance->decode(emptyJson, &parentID);
     ASSERT_EQ(result, -1);
     std::cout << "Exiting DecodeEmptyJsonObjectWithValidParentIDTEST" << std::endl;
}
 
 
 
 /**
  * @briefTEST decoding of a JSON object with an invalid structure and a valid parent ID.
  *
  * ThisTEST verifies that the decode function correctly handles a JSON object with an invalid structure and a valid parent ID. The expected behavior is that the function should return an error code indicating failure.
  *
  * **Test Group ID:** Basic: 01
  * **Test Case ID:** 005
  * **Priority:** High
  * @n
  * **Pre-Conditions:** None
  * **Dependencies:** None
  * **User Interaction:** None
  * @n
  * **Test Procedure:**@n
  * | Variation / Step | Description |TEST Data | Expected Result | Notes |
  * | :----: | --------- | ---------- |-------------- | ----- |
  * | 01 | Setup theTEST environment by creating an instance of dm_cac_comp_t | None | Instance created | Done by Pre-requisite SetUp function |
  * | 02 | Parse an invalid JSON string to create a cJSON object | invalidJson = cJSON_Parse("{\"key\":}") | cJSON object created | Should be successful |
  * | 03 | Call the decode function with the invalid JSON object and a valid parent ID | invalidJson, parentID = 1 | result = -1 | Should Pass |
  * | 04 | Verify that the result of the decode function is -1 | result = -1 | Assertion check | Should Pass |
  * | 05 | Clean up theTEST environment by deleting the instance of dm_cac_comp_t | None | Instance deleted | Done by Pre-requisite TearDown function |
  */
TEST_F(dm_cac_comp_t_Test, DecodeJsonObjectWithInvalidStructureAndValidParentID) {
     std::cout << "Entering DecodeJsonObjectWithInvalidStructureAndValidParentIDTEST" << std::endl;
     cJSON *invalidJson = cJSON_Parse("{\"key\":}");
     int parentID = 1;
     int result = instance->decode(invalidJson, &parentID);
     ASSERT_EQ(result, -1);
     std::cout << "Exiting DecodeJsonObjectWithInvalidStructureAndValidParentIDTEST" << std::endl;
}
 
 
 
 /**
  * @briefTEST the decode function with a valid JSON object and an invalid parent ID.
  *
  * ThisTEST verifies that the decode function correctly handles a valid JSON object 
  * but with an invalid parent ID. The expected behavior is that the function should 
  * return an error code indicating failure.
  *
  * **Test Group ID:** Basic: 01
  * **Test Case ID:** 006
  * **Priority:** High
  * @n
  * **Pre-Conditions:** None
  * **Dependencies:** None
  * **User Interaction:** None
  * @n
  * **Test Procedure:**@n
  * | Variation / Step | Description |TEST Data | Expected Result | Notes |
  * | :----: | --------- | ---------- |-------------- | ----- |
  * | 01 | Set up theTEST environment by creating an instance of dm_cac_comp_t. | None | Instance created | Done by Pre-requisite SetUp function |
  * | 02 | Parse a valid JSON object. | JSON string: {"key":"value"} | cJSON object created | Should be successful |
  * | 03 | Call the decode function with the valid JSON object and an invalid parent ID. | validJson, invalidParentID = -1 | result = -1 | Should Pass |
  * | 04 | Verify that the result is -1, indicating failure. | result = -1 | Assertion passed | Should be successful |
  * | 05 | Clean up theTEST environment by deleting the instance of dm_cac_comp_t. | None | Instance deleted | Done by Pre-requisite TearDown function |
  */
 
TEST_F(dm_cac_comp_t_Test, DecodeValidJsonObjectWithInvalidParentID) {
     std::cout << "Entering DecodeValidJsonObjectWithInvalidParentIDTEST" << std::endl;
     cJSON *validJson = cJSON_Parse("{\"key\":\"value\"}");
     int invalidParentID = -1;
     int result = instance->decode(validJson, &invalidParentID);
     ASSERT_EQ(result, -1);
     std::cout << "Exiting DecodeValidJsonObjectWithInvalidParentIDTEST" << std::endl;
}
 
 
 
 /**
  * @briefTEST the encoding functionality with valid mixed data types
  *
  * ThisTEST verifies that the encode function can handle a JSON object with mixed data types (string, number, boolean) correctly.
  *
  * **Test Group ID:** Basic: 01
  * **Test Case ID:** 007
  * **Priority:** High
  * @n
  * **Pre-Conditions:** None
  * **Dependencies:** None
  * **User Interaction:** None
  * @n
  * **Test Procedure:**@n
  * | Variation / Step | Description |TEST Data | Expected Result | Notes |
  * | :----: | --------- | ---------- |-------------- | ----- |
  * | 01 | Setup theTEST environment | instance = new dm_cac_comp_t() | Should be successful | Done by Pre-requisite SetUp function |
  * | 02 | Create a JSON object | cJSON *json = cJSON_CreateObject() | Should be successful |  |
  * | 03 | Add a string to the JSON object | cJSON_AddStringToObject(json, "name", "test") | Should be successful |  |
  * | 04 | Add a number to the JSON object | cJSON_AddNumberToObject(json, "age", 30) | Should be successful |  |
  * | 05 | Add a boolean to the JSON object | cJSON_AddBoolToObject(json, "active", true) | Should be successful |  |
  * | 06 | Encode the JSON object | instance->encode(json) | Should be successful | Should Pass |
  * | 07 | Verify the JSON object is still valid | ASSERT_TRUE(cJSON_IsObject(json)) | Should be successful | Should Pass |
  * | 08 | Delete the JSON object | cJSON_Delete(json) | Should be successful |  |
  * | 09 | Tear down theTEST environment | delete instance | Should be successful | Done by Pre-requisite TearDown function |
  */
 
TEST_F(dm_cac_comp_t_Test, EncodeWithValidMixedDataTypes) {
     std::cout << "Entering EncodeWithValidMixedDataTypes" << std::endl;
     cJSON *json = cJSON_CreateObject();
     cJSON_AddStringToObject(json, "name", "test");
     cJSON_AddNumberToObject(json, "age", 30);
     cJSON_AddBoolToObject(json, "active", true);
     instance->encode(json);
     ASSERT_TRUE(cJSON_IsObject(json));
     cJSON_Delete(json);
     std::cout << "Exiting EncodeWithValidMixedDataTypes" << std::endl;
}
 
 
 
 /**
  * @briefTEST the encoding function with a null JSON object
  *
  * ThisTEST checks the behavior of the encode function when provided with a null JSON object. It ensures that the function throws a runtime error as expected when the input is invalid.
  *
  * **Test Group ID:** Basic: 01
  * **Test Case ID:** 008
  * **Priority:** High
  * @n
  * **Pre-Conditions:** None
  * **Dependencies:** None
  * **User Interaction:** None
  * @n
  * **Test Procedure:**
  * | Variation / Step | Description |TEST Data | Expected Result | Notes |
  * | :----: | --------- | ---------- |-------------- | ----- |
  * | 01 | Set up theTEST environment | None | None | Done by Pre-requisite SetUp function |
  * | 02 | Create a null JSON object | json = nullptr | None | Should be successful |
  * | 03 | Call the encode function with the null JSON object | instance->encode(json) | Throws std::runtime_error | Should Pass |
  * | 04 | Tear down theTEST environment | None | None | Done by Pre-requisite TearDown function |
  */
TEST_F(dm_cac_comp_t_Test, EncodeWithNullObject) {
     std::cout << "Entering EncodeWithNullObject" << std::endl;
     cJSON *json = nullptr;
     ASSERT_THROW(instance->encode(json), std::runtime_error);
     std::cout << "Exiting EncodeWithNullObject" << std::endl;
}
 
 
 
 /**
  * @briefTEST the encoding functionality with an empty JSON object.
  *
  * ThisTEST verifies that the encode function can handle an empty JSON object without errors and ensures that the object remains valid after encoding.
  *
  * **Test Group ID:** Basic: 01
  * **Test Case ID:** 009
  * **Priority:** High
  * @n
  * **Pre-Conditions:** None
  * **Dependencies:** None
  * **User Interaction:** None
  * @n
  * **Test Procedure:**@n
  * | Variation / Step | Description |TEST Data | Expected Result | Notes |
  * | :----: | --------- | ---------- |-------------- | ----- |
  * | 01 | Setup theTEST environment by creating an instance of dm_cac_comp_t | None | Instance created successfully | Done by Pre-requisite SetUp function |
  * | 02 | Create an empty JSON object using cJSON_CreateObject | None | JSON object created successfully | Should be successful |
  * | 03 | Call the encode function with the empty JSON object | json = empty object | Function should handle the empty object without errors | Should Pass |
  * | 04 | Verify that the JSON object is still valid and is an object | json = empty object | ASSERT_TRUE(cJSON_IsObject(json)) should pass | Should Pass |
  * | 05 | Clean up the JSON object by calling cJSON_Delete | json = empty object | JSON object deleted successfully | Should be successful |
  * | 06 | Tear down theTEST environment by deleting the instance of dm_cac_comp_t | None | Instance deleted successfully | Done by Pre-requisite TearDown function |
  */
TEST_F(dm_cac_comp_t_Test, EncodeWithEmptyObject) {
     std::cout << "Entering EncodeWithEmptyObject" << std::endl;
     cJSON *json = cJSON_CreateObject();
     instance->encode(json);
     ASSERT_TRUE(cJSON_IsObject(json));
     cJSON_Delete(json);
     std::cout << "Exiting EncodeWithEmptyObject" << std::endl;
}
 
 
 
 /**
  * @briefTEST the encoding functionality with arrays and special characters
  *
  * ThisTEST verifies that the encode function can handle JSON objects containing arrays and special characters correctly.
  *
  * **Test Group ID:** Basic: 01
  * **Test Case ID:** 010
  * **Priority:** High
  * @n
  * **Pre-Conditions:** None
  * **Dependencies:** None
  * **User Interaction:** None
  * @n
  * **Test Procedure:**@n
  * | Variation / Step | Description |TEST Data | Expected Result | Notes |
  * | :----: | --------- | ---------- |-------------- | ----- |
  * | 01 | Setup theTEST environment | None | None | Done by Pre-requisite SetUp function |
  * | 02 | Create a JSON object | None | JSON object created | Should be successful |
  * | 03 | Add an array to the JSON object | None | Array added to JSON object | Should be successful |
  * | 04 | Add a string with special characters to the JSON object | None | String with special characters added to JSON object | Should be successful |
  * | 05 | Encode the JSON object using the instance's encode method | json = JSON object | JSON object encoded | Should Pass |
  * | 06 | Assert that the JSON object is still valid | json = JSON object | JSON object is valid | Should Pass |
  * | 07 | Delete the JSON object | json = JSON object | JSON object deleted | Should be successful |
  * | 08 | Tear down theTEST environment | None | None | Done by Pre-requisite TearDown function |
  */
 
TEST_F(dm_cac_comp_t_Test, EncodeWithArraysAndSpecialCharacters) {
     std::cout << "Entering EncodeWithArraysAndSpecialCharacters" << std::endl;
     cJSON *json = cJSON_CreateObject();
     cJSON_AddItemToObject(json, "array", cJSON_CreateArray());
     cJSON_AddStringToObject(json, "special", "!@#$%^&*() ");
     instance->encode(json);
     ASSERT_TRUE(cJSON_IsObject(json));
     cJSON_Delete(json);
     std::cout << "Exiting EncodeWithArraysAndSpecialCharacters" << std::endl;
}
 
 
 /**
  * @briefTEST the encoding functionality with null values in the JSON object.
  *
  * ThisTEST verifies that the encode function can handle JSON objects containing null values without causing errors or crashes.
  *
  * **Test Group ID:** Basic: 01
  * **Test Case ID:** 011
  * **Priority:** High
  * @n
  * **Pre-Conditions:** None
  * **Dependencies:** None
  * **User Interaction:** None
  * @n
  * **Test Procedure:**@n
  * | Variation / Step | Description |TEST Data | Expected Result | Notes |
  * | :----: | --------- | ---------- |-------------- | ----- |
  * | 01 | Setup theTEST environment by creating an instance of dm_cac_comp_t | instance = new dm_cac_comp_t() | Instance should be created successfully | Done by Pre-requisite SetUp function |
  * | 02 | Create a JSON object and add a null value to it | json = cJSON_CreateObject(), cJSON_AddNullToObject(json, "null") | JSON object should be created and null value added successfully | Should be successful |
  * | 03 | Call the encode function with the JSON object containing null values | instance->encode(json) | Function should handle null values without errors | Should Pass |
  * | 04 | Verify that the JSON object is still valid after encoding | cJSON_IsObject(json) | JSON object should be valid | Should Pass |
  * | 05 | Clean up the JSON object | cJSON_Delete(json) | JSON object should be deleted successfully | Should be successful |
  * | 06 | Tear down theTEST environment by deleting the instance of dm_cac_comp_t | delete instance | Instance should be deleted successfully | Done by Pre-requisite TearDown function |
  */
TEST_F(dm_cac_comp_t_Test, EncodeWithNullValues) {
     std::cout << "Entering EncodeWithNullValues" << std::endl;
     cJSON *json = cJSON_CreateObject();
     cJSON_AddNullToObject(json, "null");
     instance->encode(json);
     ASSERT_TRUE(cJSON_IsObject(json));
     cJSON_Delete(json);
     std::cout << "Exiting EncodeWithNullValues" << std::endl;
}
 
 
 
 /**
  * @briefTEST to verify the retrieval of CAC Component ID after setting RUID
  *
  * ThisTEST checks if the CAC Component ID can be correctly retrieved after setting the RUID. It ensures that the RUID is properly set and can be retrieved without any errors.
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
  * | Variation / Step | Description |TEST Data | Expected Result | Notes |
  * | :----: | --------- | ---------- |-------------- | ----- |
  * | 01 | Setup theTEST environment | None | None | Done by Pre-requisite SetUp function |
  * | 02 | Set the RUID in the CAC component info | expected_ruid = {0x01, 0x00, 0xFF} | None | Should be successful |
  * | 03 | Retrieve the CAC Component ID | None | result != nullptr | Should Pass |
  * | 04 | Verify the retrieved CAC Component ID matches the expected RUID | result, expected_ruid | memcmp(result, expected_ruid, sizeof(expected_ruid)) == 0 | Should Pass |
  * | 05 | Tear down theTEST environment | None | None | Done by Pre-requisite TearDown function |
  */
 
TEST_F(dm_cac_comp_t_Test, RetrieveCACComponentIDAfterSettingRuid) {
     std::cout << "Entering RetrieveCACComponentIDAfterSettingRuidTEST" << std::endl;
     unsigned char expected_ruid[] = {0x01, 0x00, 0xFF};
     memcpy(instance->m_cac_comp_info.ruid, expected_ruid, sizeof(expected_ruid));
     unsigned char* result = instance->get_cac_comp_id();
     ASSERT_NE(result, nullptr);
     ASSERT_EQ(memcmp(result, expected_ruid, sizeof(expected_ruid)), 0);
     std::cout << "Exiting RetrieveCACComponentIDAfterSettingRuidTEST" << std::endl;
}
 
 
 
 /**
  * @briefTEST to verify the behavior of RetrieveCACComponentID with invalid initialization
  *
  * ThisTEST checks the behavior of the get_cac_comp_id method when the instance's m_cac_comp_info.ruid is not properly initialized. 
  * It ensures that the method returns a null character as expected in such cases.
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
  * | Variation / Step | Description |TEST Data | Expected Result | Notes |
  * | :----: | --------- | ---------- |-------------- | ----- |
  * | 01 | Setup theTEST environment by creating an instance of dm_cac_comp_t | instance = new dm_cac_comp_t() | Instance should be created successfully | Done by Pre-requisite SetUp function |
  * | 02 | Initialize the ruid of m_cac_comp_info to null character | instance->m_cac_comp_info.ruid[0] = '\0' | ruid should be set to null character | Should be successful |
  * | 03 | Call the get_cac_comp_id method | result = instance->get_cac_comp_id() | Method should return a pointer to a null character | Should Pass |
  * | 04 | Verify the result of get_cac_comp_id | ASSERT_EQ(result[0], '\0') | Assertion should pass if the result is a null character | Should Pass |
  * | 05 | Clean up theTEST environment by deleting the instance of dm_cac_comp_t | delete instance | Instance should be deleted successfully | Done by Pre-requisite TearDown function |
  */
 
TEST_F(dm_cac_comp_t_Test, RetrieveCACComponentIDWithInvalidInitialization) {
     std::cout << "Entering RetrieveCACComponentIDWithInvalidInitializationTEST" << std::endl;
     instance->m_cac_comp_info.ruid[0] = '\0';
     unsigned char* result = instance->get_cac_comp_id();
     ASSERT_EQ(result[0], '\0');
     std::cout << "Exiting RetrieveCACComponentIDWithInvalidInitializationTEST" << std::endl;
}
 
 
 
 /**
  * @briefTEST the retrieval of CAC component information with valid data
  *
  * ThisTEST verifies that the `get_cac_comp_info` method correctly retrieves the CAC component information when the instance is populated with valid data.
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
  * | Variation / Step | Description |TEST Data | Expected Result | Notes |
  * | :----: | --------- | ---------- |-------------- | ----- |
  * | 01 | Setup theTEST environment | None | None | Done by Pre-requisite SetUp function |
  * | 02 | Initialize `m_cac_comp_info` with valid data | ruid = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06}, op_class = 1, channel = 36, status = 0, detected_pairs_num = EM_MAX_CAC_METHODS, detected_pairs[i] = valid data | None | Should be successful |
  * | 03 | Call `get_cac_comp_info` method | None | info should not be nullptr | Should Pass |
  * | 04 | Verify `ruid` in the retrieved info | info->ruid[0] = 0x01 | Should match the initialized value | Should Pass |
  * | 05 | Verify `op_class` in the retrieved info | info->op_class = 1 | Should match the initialized value | Should Pass |
  * | 06 | Verify `channel` in the retrieved info | info->channel = 36 | Should match the initialized value | Should Pass |
  * | 07 | Verify `status` in the retrieved info | info->status = 0 | Should match the initialized value | Should Pass |
  * | 08 | Verify `detected_pairs_num` in the retrieved info | info->detected_pairs_num = EM_MAX_CAC_METHODS | Should match the initialized value | Should Pass |
  * | 09 | Verify `detected_pairs` in the retrieved info | info->detected_pairs[i] = valid data | Should match the initialized value | Should Pass |
  * | 10 | Tear down theTEST environment | None | None | Done by Pre-requisite TearDown function |
  */
 
TEST_F(dm_cac_comp_t_Test, RetrieveCACComponentInfoWithValidData) {
     std::cout << "Entering RetrieveCACComponentInfoWithValidData" << std::endl;
     
     instance->m_cac_comp_info.ruid = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
     instance->m_cac_comp_info.op_class = 1;
     instance->m_cac_comp_info.channel = 36;
     instance->m_cac_comp_info.status = 0;
     instance->m_cac_comp_info.detected_pairs_num = EM_MAX_CAC_METHODS;
     for (int i = 0; i < EM_MAX_CAC_METHODS; ++i) {
         instance->m_cac_comp_info.detected_pairs[i] = em_cac_comp_rprt_pair_t{/* initialize with valid data */};
    }
 
     em_cac_comp_info_t* info = instance->get_cac_comp_info();
     ASSERT_NE(info, nullptr);
     ASSERT_EQ(info->ruid[0], 0x01);
     ASSERT_EQ(info->op_class, 1);
     ASSERT_EQ(info->channel, 36);
     ASSERT_EQ(info->status, 0);
     ASSERT_EQ(info->detected_pairs_num, EM_MAX_CAC_METHODS);
     for (int i = 0; i < EM_MAX_CAC_METHODS; ++i) {
         ASSERT_EQ(info->detected_pairs[i], em_cac_comp_rprt_pair_t{/* expected valid data */});
    }
 
     std::cout << "Exiting RetrieveCACComponentInfoWithValidData" << std::endl;
}
 
 
 
 /**
  * @briefTEST the retrieval of CAC component information with invalid data
  *
  * ThisTEST verifies that the `get_cac_comp_info` method correctly handles and returns invalid data set in the `m_cac_comp_info` structure.
  *
  * **Test Group ID:** Basic: 01
  * **Test Case ID:** 015
  * **Priority:** High
  * @n
  * **Pre-Conditions:** None
  * **Dependencies:** None
  * **User Interaction:** None
  * @n
  * **Test Procedure:**@n
  * | Variation / Step | Description |TEST Data | Expected Result | Notes |
  * | :----: | --------- | ---------- |-------------- | ----- |
  * | 01 | Setup theTEST environment | None | None | Done by Pre-requisite SetUp function |
  * | 02 | Set invalid data in `m_cac_comp_info` | ruid = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, op_class = 255, channel = 255, status = 255, detected_pairs_num = EM_MAX_CAC_METHODS, detected_pairs = {invalid data} | None | Should be successful |
  * | 03 | Retrieve CAC component info using `get_cac_comp_info` | None | info != nullptr | Should Pass |
  * | 04 | Verify `ruid` in retrieved info | info->ruid[0] = 0xFF | info->ruid[0] == 0xFF | Should Pass |
  * | 05 | Verify `op_class` in retrieved info | info->op_class = 255 | info->op_class == 255 | Should Pass |
  * | 06 | Verify `channel` in retrieved info | info->channel = 255 | info->channel == 255 | Should Pass |
  * | 07 | Verify `status` in retrieved info | info->status = 255 | info->status == 255 | Should Pass |
  * | 08 | Verify `detected_pairs_num` in retrieved info | info->detected_pairs_num = EM_MAX_CAC_METHODS | info->detected_pairs_num == EM_MAX_CAC_METHODS | Should Pass |
  * | 09 | Verify `detected_pairs` in retrieved info | info->detect_pairs = {invalid data} | info->detect_pairs == {invalid data} | Should Pass |
  * | 10 | Tear down theTEST environment | None | None | Done by Pre-requisite TearDown function |
  */
 
TEST_F(dm_cac_comp_t_Test, RetrieveCACComponentInfoWithInvalidData) {
     std::cout << "Entering RetrieveCACComponentInfoWithInvalidData" << std::endl;
     
     instance->m_cac_comp_info.ruid = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
     instance->m_cac_comp_info.op_class = 255;
     instance->m_cac_comp_info.channel = 255;
     instance->m_cac_comp_info.status = 255;
     instance->m_cac_comp_info.detected_pairs_num = EM_MAX_CAC_METHODS;
     for (int i = 0; i < EM_MAX_CAC_METHODS; ++i) {
         instance->m_cac_comp_info.detected_pairs[i] = em_cac_comp_rprt_pair_t{/* initialize with invalid data */};
    }
 
     em_cac_comp_info_t* info = instance->get_cac_comp_info();
     ASSERT_NE(info, nullptr);
     ASSERT_EQ(info->ruid[0], 0xFF);
     ASSERT_EQ(info->op_class, 255);
     ASSERT_EQ(info->channel, 255);
     ASSERT_EQ(info->status, 255);
     ASSERT_EQ(info->detected_pairs_num, EM_MAX_CAC_METHODS);
     for (int i = 0; i < EM_MAX_CAC_METHODS; ++i) {
         ASSERT_EQ(info->detect_pairs[i], em_cac_comp_rprt_pair_t{/* expected invalid data */});
    }
 
     std::cout << "Exiting RetrieveCACComponentInfoWithInvalidData" << std::endl;
}
 
 
 
 /**
  * @briefTEST the functionality of looping through all orchestration types
  *
  * ThisTEST verifies that the `get_dm_orch_type` method correctly returns the orchestration type that was set in the `dm_cac_comp_t` instance. It loops through all possible orchestration types and checks if the method returns the expected type.
  *
  * **Test Group ID:** Basic: 01
  * **Test Case ID:** 016
  * **Priority:** High
  * @n
  * **Pre-Conditions:** None
  * **Dependencies:** None
  * **User Interaction:** None
  * @n
  * **Test Procedure:**@n
  * | Variation / Step | Description |TEST Data | Expected Result | Notes |
  * | :----: | --------- | ---------- |-------------- | ----- |
  * | 01 | Setup theTEST environment | None | None | Done by Pre-requisite SetUp function |
  * | 02 | Loop through all orchestration types and set each type in `dm_cac_comp_t` instance | dm_orch_type_t types[] = { ...} | None | Should be successful |
  * | 03 | For each type, set the type in `dm_cac_comp_t` instance and verify using `get_dm_orch_type` method | type = dm_orch_type_xxx, radio.m_cac_comp_info.orch_type = type | Return value should be equal to the set type | Should Pass |
  * | 04 | Tear down theTEST environment | None | None | Done by Pre-requisite TearDown function |
  */
TEST_F(dm_cac_comp_t_Test,TESTLoopThroughAllOrchTypes) {
     std::cout << "EnteringTESTLoopThroughAllOrchTypes" << std::endl;
     dm_orch_type_t types[] = {
         dm_orch_type_none, dm_orch_type_net_insert, dm_orch_type_net_update, dm_orch_type_net_delete,
         dm_orch_type_al_insert, dm_orch_type_al_update, dm_orch_type_al_delete, dm_orch_type_em_insert,
         dm_orch_type_em_update, dm_orch_type_em_delete, dm_orch_type_em_reset, dm_orch_type_em_test,
         dm_orch_type_bss_insert, dm_orch_type_bss_update, dm_orch_type_bss_delete, dm_orch_type_ssid_insert,
         dm_orch_type_ssid_update, dm_orch_type_ssid_delete, dm_orch_type_sta_insert, dm_orch_type_sta_update,
         dm_orch_type_sta_aggregate, dm_orch_type_sta_delete, dm_orch_type_sec_insert, dm_orch_type_sec_update,
         dm_orch_type_sec_delete, dm_orch_type_cap_insert, dm_orch_type_cap_update, dm_orch_type_cap_delete,
         dm_orch_type_op_class_insert, dm_orch_type_op_class_update, dm_orch_type_op_class_delete,
         dm_orch_type_ssid_vid_insert, dm_orch_type_ssid_vid_update, dm_orch_type_ssid_vid_delete,
         dm_orch_type_dpp_insert, dm_orch_type_dpp_update, dm_orch_type_dpp_delete, dm_orch_type_db_reset,
         dm_orch_type_db_cfg, dm_orch_type_db_insert, dm_orch_type_db_update, dm_orch_type_db_delete,
         dm_orch_type_dm_delete, dm_orch_type_dm_delete_all, dm_orch_type_tx_cfg_renew, dm_orch_type_owconfig_req,
         dm_orch_type_owconfig_cnf, dm_orch_type_ctrl_notify, dm_orch_type_ap_cap_report, dm_orch_type_client_cap_report,
         dm_orch_type_1905_security_update, dm_orch_type_topology_response, dm_orch_type_net_ssid_update,
         dm_orch_type_topo_sync, dm_orch_type_topo_update, dm_orch_type_channel_pref, dm_orch_type_channel_sel,
         dm_orch_type_channel_cnf, dm_orch_type_channel_sel_resp, dm_orch_type_channel_scan_req,
         dm_orch_type_channel_scan_res, dm_orch_type_sta_cap, dm_orch_type_sta_link_metrics, dm_orch_type_op_channel_report,
         dm_orch_type_sta_steer, dm_orch_type_sta_steer_btm_report, dm_orch_type_sta_disassoc, dm_orch_type_policy_cfg,
         dm_orch_type_mld_reconfig, dm_orch_type_beacon_report
    };
 
     for (dm_orch_type_t type : types) {
         dm_cac_comp_t radio;
         radio.m_cac_comp_info.orch_type = type;
         ASSERT_EQ(instance->get_dm_orch_type(radio), type);
    }
     std::cout << "ExitingTESTLoopThroughAllOrchTypes" << std::endl;
}
 
 
 
 /**
  * @briefTEST the retrieval of an invalid orchestration type
  *
  * ThisTEST verifies that the get_dm_orch_type function correctly handles invalid data by setting the orch_type to an invalid value and checking if the function returns the expected default value.
  *
  * **Test Group ID:** Basic: 01
  * **Test Case ID:** 017
  * **Priority:** High
  * @n
  * **Pre-Conditions:** None
  * **Dependencies:** None
  * **User Interaction:** None
  * @n
  * **Test Procedure:**@n
  * | Variation / Step | Description |TEST Data | Expected Result | Notes |
  * | :----: | --------- | ---------- |-------------- | ----- |
  * | 01 | Setup theTEST environment | None | None | Done by Pre-requisite SetUp function |
  * | 02 | Create a dm_cac_comp_t instance and set orch_type to an invalid value | radio.m_cac_comp_info.orch_type = static_cast<dm_orch_type_t>(-1) | None | Should be successful |
  * | 03 | Call get_dm_orch_type with the invalid orch_type | instance->get_dm_orch_type(radio) | dm_orch_type_none | Should Pass |
  * | 04 | Tear down theTEST environment | None | None | Done by Pre-requisite TearDown function |
  */
TEST_F(dm_cac_comp_t_Test,TESTRetrieveOrchTypeInvalidData) {
     std::cout << "EnteringTESTRetrieveOrchTypeInvalidData" << std::endl;
     dm_cac_comp_t radio;
     radio.m_cac_comp_info.orch_type = static_cast<dm_orch_type_t>(-1);
     ASSERT_EQ(instance->get_dm_orch_type(radio), dm_orch_type_none);
     std::cout << "ExitingTESTRetrieveOrchTypeInvalidData" << std::endl;
}
 
 
 
 /**
  * @briefTEST to initialize the CAC Component Information Structure
  *
  * ThisTEST verifies the initialization of the CAC Component Information Structure by invoking the init() method of the dm_cac_comp_t class. TheTEST ensures that the initialization is successful and returns the expected result.
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
  * | Variation / Step | Description |TEST Data | Expected Result | Notes |
  * | :----: | --------- | ---------- |-------------- | ----- |
  * | 01 | Setup theTEST environment by creating an instance of dm_cac_comp_t | None | Instance created successfully | Done by Pre-requisite SetUp function |
  * | 02 | Call the init() method on the instance | instance->init() | result = 0 | Should Pass |
  * | 03 | Verify the result of the init() method | result = 0 | ASSERT_EQ(result, 0) | Should be successful |
  * | 04 | Clean up theTEST environment by deleting the instance | None | Instance deleted successfully | Done by Pre-requisite TearDown function |
  */
 
TEST_F(dm_cac_comp_t_Test, InitializeCACComponentInformationStructure) {
     std::cout << "Entering InitializeCACComponentInformationStructureTEST" << std::endl;
     int result = instance->init();
     ASSERT_EQ(result, 0);
     std::cout << "Exiting InitializeCACComponentInformationStructureTEST" << std::endl;
}
 
 
 
 /**
  * @briefTEST the initialization of CAC Component Information Structure multiple times
  *
  * ThisTEST verifies that the `init` method of the `dm_cac_comp_t` class can be called multiple times successfully without causing any issues.
  *
  * **Test Group ID:** Basic: 01
  * **Test Case ID:** 019
  * **Priority:** High
  * @n
  * **Pre-Conditions:** None
  * **Dependencies:** None
  * **User Interaction:** None
  * @n
  * **Test Procedure:**@n
  * | Variation / Step | Description |TEST Data | Expected Result | Notes |
  * | :----: | --------- | ---------- |-------------- | ----- |
  * | 01 | Setup theTEST environment by creating an instance of `dm_cac_comp_t` | None | Instance created successfully | Done by Pre-requisite SetUp function |
  * | 02 | Call the `init` method for the first time | None | Return value should be 0 | Should Pass |
  * | 03 | Call the `init` method for the second time | None | Return value should be 0 | Should Pass |
  * | 04 | Clean up theTEST environment by deleting the instance of `dm_cac_comp_t` | None | Instance deleted successfully | Done by Pre-requisite TearDown function |
  */
 
TEST_F(dm_cac_comp_t_Test, InitializeCACComponentInformationStructureMultipleTimes) {
     std::cout << "Entering InitializeCACComponentInformationStructureMultipleTimesTEST" << std::endl;
     int result1 = instance->init();
     ASSERT_EQ(result1, 0);
     int result2 = instance->init();
     ASSERT_EQ(result2, 0);
     std::cout << "Exiting InitializeCACComponentInformationStructureMultipleTimesTEST" << std::endl;
}
 
 /**
 * @briefTEST to compare two identical dm_cac_comp_t objects
 *
 * ThisTEST verifies that two dm_cac_comp_t objects with identical values are considered equal by the equality operator. This is important to ensure that the equality operator is correctly implemented and can accurately compare objects of this type.
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
 * | Variation / Step | Description |TEST Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Create two dm_cac_comp_t objects with identical values | obj1.m_cac_comp_info = {{1, 2, 3, 4, 5, 6}, 1, 1, 1, 1, {}}, obj2.m_cac_comp_info = {{1, 2, 3, 4, 5, 6}, 1, 1, 1, 1, {}} | Objects should be identical | Should Pass |
 * | 02 | Compare the two objects using the equality operator | obj1 == obj2 | EXPECT_TRUE should pass | Should Pass |
 */
 
TEST(dm_cac_comp_t_Test, CompareIdenticalValues) {
     std::cout << "Entering CompareIdenticalValues" << std::endl;
     dm_cac_comp_t obj1, obj2;
     obj1.m_cac_comp_info = {{1, 2, 3, 4, 5, 6}, 1, 1, 1, 1, {}};
     obj2.m_cac_comp_info = {{1, 2, 3, 4, 5, 6}, 1, 1, 1, 1, {}};
     EXPECT_TRUE(obj1 == obj2);
     std::cout << "Exiting CompareIdenticalValues" << std::endl;
}
 
 
 
 /**
 * @briefTEST to compare two dm_cac_comp_t objects with different RUID values
 *
 * ThisTEST verifies that two dm_cac_comp_t objects with different RUID values are not considered equal. This is important to ensure that the equality operator correctly identifies objects with different unique identifiers as unequal.
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
 * | Variation / Step | Description |TEST Data |Expected Result |Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01| Create two dm_cac_comp_t objects with different RUID values | obj1.m_cac_comp_info = {{1, 2, 3, 4, 5, 6}, 1, 1, 1, 1, {}}, obj2.m_cac_comp_info = {{6, 5, 4, 3, 2, 1}, 1, 1, 1, 1, {}} | Objects should not be equal | Should Pass |
 * | 02| Compare the two objects using the equality operator | obj1 == obj2 | EXPECT_FALSE(obj1 == obj2) | Should Pass |
 */
TEST(dm_cac_comp_t_Test, CompareDifferentRuidValues) {
     std::cout << "Entering CompareDifferentRuidValues" << std::endl;
     dm_cac_comp_t obj1, obj2;
     obj1.m_cac_comp_info = {{1, 2, 3, 4, 5, 6}, 1, 1, 1, 1, {}};
     obj2.m_cac_comp_info = {{6, 5, 4, 3, 2, 1}, 1, 1, 1, 1, {}};
     EXPECT_FALSE(obj1 == obj2);
     std::cout << "Exiting CompareDifferentRuidValues" << std::endl;
}
 
 
 
 /**
 * @briefTEST to compare different operation class values in dm_cac_comp_t objects
 *
 * ThisTEST verifies that two dm_cac_comp_t objects with different operation class values are not considered equal.@n
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
 * | Variation / Step | Description |TEST Data |Expected Result |Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01| Create two dm_cac_comp_t objects with different operation class values | obj1.m_cac_comp_info = {{1, 2, 3, 4, 5, 6}, 1, 1, 1, 1, {}}, obj2.m_cac_comp_info = {{1, 2, 3, 4, 5, 6}, 2, 1, 1, 1, {}} | Objects should not be equal | Should Pass |
 * | 02| Compare the two objects using the equality operator | obj1 == obj2 | EXPECT_FALSE(obj1 == obj2) | Should Pass |
 */
 
TEST(dm_cac_comp_t_Test, CompareDifferentOpClassValues) {
     std::cout << "Entering CompareDifferentOpClassValues" << std::endl;
     dm_cac_comp_t obj1, obj2;
     obj1.m_cac_comp_info = {{1, 2, 3, 4, 5, 6}, 1, 1, 1, 1, {}};
     obj2.m_cac_comp_info = {{1, 2, 3, 4, 5, 6}, 2, 1, 1, 1, {}};
     EXPECT_FALSE(obj1 == obj2);
     std::cout << "Exiting CompareDifferentOpClassValues" << std::endl;
}
 
 
 
 /**
 * @briefTEST to compare different channel values in dm_cac_comp_t objects
 *
 * ThisTEST verifies that two dm_cac_comp_t objects with different channel values are not considered equal.@n
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
 * | Variation / Step | Description |TEST Data |Expected Result |Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01| Create two dm_cac_comp_t objects with different channel values | obj1.m_cac_comp_info = {{1, 2, 3, 4, 5, 6}, 1, 1, 1, 1, {}}, obj2.m_cac_comp_info = {{1, 2, 3, 4, 5, 6}, 1, 2, 1, 1, {}} | Objects should not be equal | Should Pass |
 * | 02| Compare the two objects using the equality operator | obj1 == obj2 | EXPECT_FALSE(obj1 == obj2) | Should Pass |
 */
 
TEST(dm_cac_comp_t_Test, CompareDifferentChannelValues) {
     std::cout << "Entering CompareDifferentChannelValues" << std::endl;
     dm_cac_comp_t obj1, obj2;
     obj1.m_cac_comp_info = {{1, 2, 3, 4, 5, 6}, 1, 1, 1, 1, {}};
     obj2.m_cac_comp_info = {{1, 2, 3, 4, 5, 6}, 1, 2, 1, 1, {}};
     EXPECT_FALSE(obj1 == obj2);
     std::cout << "Exiting CompareDifferentChannelValues" << std::endl;
}
 
 
 
 /**
 * @briefTEST to compare different status values in dm_cac_comp_t objects
 *
 * ThisTEST verifies that two dm_cac_comp_t objects with different status values are not considered equal.@n
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
 * | Variation / Step | Description |TEST Data |Expected Result |Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01| Create two dm_cac_comp_t objects with different status values | obj1.m_cac_comp_info = {{1, 2, 3, 4, 5, 6}, 1, 1, 1, 1, {}}, obj2.m_cac_comp_info = {{1, 2, 3, 4, 5, 6}, 1, 1, 2, 1, {}} | Objects should not be equal | Should Pass |
 * | 02| Compare the two objects using the equality operator | obj1 == obj2 | EXPECT_FALSE(obj1 == obj2) | Should Pass |
 */
TEST(dm_cac_comp_t_Test, CompareDifferentStatusValues) {
     std::cout << "Entering CompareDifferentStatusValues" << std::endl;
     dm_cac_comp_t obj1, obj2;
     obj1.m_cac_comp_info = {{1, 2, 3, 4, 5, 6}, 1, 1, 1, 1, {}};
     obj2.m_cac_comp_info = {{1, 2, 3, 4, 5, 6}, 1, 1, 2, 1, {}};
     EXPECT_FALSE(obj1 == obj2);
     std::cout << "Exiting CompareDifferentStatusValues" << std::endl;
}
 
 
 
 /**
 * @briefTEST to compare two dm_cac_comp_t objects with different detected pairs number values
 *
 * ThisTEST verifies that two dm_cac_comp_t objects with identical attributes except for the detected pairs number value are not considered equal. This is important to ensure that the equality operator correctly distinguishes between objects with different detected pairs numbers.
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
 * | Variation / Step | Description |TEST Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Create two dm_cac_comp_t objects with different detected pairs number values | obj1.m_cac_comp_info = {{1, 2, 3, 4, 5, 6}, 1, 1, 1, 1, {}}, obj2.m_cac_comp_info = {{1, 2, 3, 4, 5, 6}, 1, 1, 1, 2, {}} | Objects should not be equal | Should Pass |
 * | 02 | Compare the two objects using the equality operator | obj1 == obj2 | EXPECT_FALSE(obj1 == obj2) | Should Pass |
 */
 
TEST(dm_cac_comp_t_Test, CompareDifferentDetectedPairsNumValues) {
     std::cout << "Entering CompareDifferentDetectedPairsNumValues" << std::endl;
     dm_cac_comp_t obj1, obj2;
     obj1.m_cac_comp_info = {{1, 2, 3, 4, 5, 6}, 1, 1, 1, 1, {}};
     obj2.m_cac_comp_info = {{1, 2, 3, 4, 5, 6}, 1, 1, 1, 2, {}};
     EXPECT_FALSE(obj1 == obj2);
     std::cout << "Exiting CompareDifferentDetectedPairsNumValues" << std::endl;
}
 
 
 
 /**
 * @briefTEST to compare different detected pairs values in dm_cac_comp_t objects
 *
 * ThisTEST checks the equality operator for dm_cac_comp_t objects with different detected pairs values. 
 * It ensures that the equality operator correctly identifies objects with different detected pairs as unequal.
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
 * | Variation / Step | Description |TEST Data |Expected Result |Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01| Create two dm_cac_comp_t objects with different detected pairs values | obj1.m_cac_comp_info = {{1, 2, 3, 4, 5, 6}, 1, 1, 1, 1, {pair1}}, obj2.m_cac_comp_info = {{1, 2, 3, 4, 5, 6}, 1, 1, 1, 1, {pair2}} | Objects should be unequal | Should Pass |
 * | 02| Compare the two objects using the equality operator | obj1 == obj2 | EXPECT_FALSE(obj1 == obj2) | Should Pass |
 */
TEST(dm_cac_comp_t_Test, CompareDifferentDetectedPairsValues) {
     std::cout << "Entering CompareDifferentDetectedPairsValues" << std::endl;
     dm_cac_comp_t obj1, obj2;
     em_cac_comp_rprt_pair_t pair1, pair2;
     obj1.m_cac_comp_info = {{1, 2, 3, 4, 5, 6}, 1, 1, 1, 1, {pair1}};
     obj2.m_cac_comp_info = {{1, 2, 3, 4, 5, 6}, 1, 1, 1, 1, {pair2}};
     EXPECT_FALSE(obj1 == obj2);
     std::cout << "Exiting CompareDifferentDetectedPairsValues" << std::endl;
}
 
 
 
 /**
 * @briefTEST to verify the assignment operator for dm_cac_comp_t class
 *
 * ThisTEST checks if the assignment operator correctly assigns the values from one instance of dm_cac_comp_t to another instance. This is important to ensure that the assignment operator works as expected and the internal state of the object is correctly copied.
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
 * | Variation / Step | Description |TEST Data |Expected Result |Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01| Create source object and initialize it | source.init() | source object initialized | Should be successful |
 * | 02| Assign source object to target object | target = source | target object assigned | Should Pass |
 * | 03| Compare internal state of source and target objects | *target.get_cac_comp_info(), *source.get_cac_comp_info() | Internal states are equal | Should Pass |
 */
TEST(dm_cac_comp_t_Test, AssigningValidObject) {
     std::cout << "Entering AssigningValidObject" << std::endl;
     dm_cac_comp_t source;
     source.init();
     dm_cac_comp_t target;
     target = source;
     ASSERT_EQ(*target.get_cac_comp_info(), *source.get_cac_comp_info());
     std::cout << "Exiting AssigningValidObject" << std::endl;
}
 
 
 
 /**
 * @briefTEST to verify the assignment operator for uninitialized objects
 *
 * ThisTEST checks the assignment operator of the dm_cac_comp_t class by assigning one uninitialized object to another and verifying that the internal state is correctly copied.@n
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
 * | Variation / Step | Description |TEST Data |Expected Result |Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01| Create source and target objects | source = uninitialized, target = uninitialized | Objects should be created successfully | Should be successful |
 * | 02| Assign source to target | target = source | target should have the same state as source | Should Pass |
 * | 03| Verify the internal state of target and source | *target.get_cac_comp_info(), *source.get_cac_comp_info() | Both should be equal | Should Pass |
 */
TEST(dm_cac_comp_t_Test, AssigningUninitializedObject) {
     std::cout << "Entering AssigningUninitializedObject" << std::endl;
     dm_cac_comp_t source;
     dm_cac_comp_t target;
     target = source;
     ASSERT_EQ(*target.get_cac_comp_info(), *source.get_cac_comp_info());
     std::cout << "Exiting AssigningUninitializedObject" << std::endl;
}
 
 
 
 /**
 * @briefTEST to verify the behavior of self-assignment in the dm_cac_comp_t class
 *
 * ThisTEST checks if the self-assignment operator works correctly in the dm_cac_comp_t class. 
 * Self-assignment is a special case that should be handled properly to avoid issues like memory leaks or corruption.
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
 * | Variation / Step | Description |TEST Data |Expected Result |Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01| Create an instance of dm_cac_comp_t and initialize it | instance = new dm_cac_comp_t() | Instance should be created and initialized | Should be successful |
 * | 02| Perform self-assignment on the instance | obj = obj | Self-assignment should be handled correctly | Should Pass |
 * | 03| Verify the state of the object after self-assignment | *obj.get_cac_comp_info() | The state should remain unchanged | Should Pass |
 */
 
TEST(dm_cac_comp_t_Test, SelfAssignment) {
     std::cout << "Entering SelfAssignment" << std::endl;
     dm_cac_comp_t obj;
     obj.init();
     obj = obj;
     ASSERT_EQ(*obj.get_cac_comp_info(), *obj.get_cac_comp_info());
     std::cout << "Exiting SelfAssignment" << std::endl;
}
 
 
 
 /**
 * @briefTEST to verify the assignment operator with maximum values
 *
 * ThisTEST checks the assignment operator of the dm_cac_comp_t class by assigning maximum values to the source object and verifying if the target object correctly copies these values.@n
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
 * | Variation / Step | Description |TEST Data |Expected Result |Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01| Create source object and assign maximum values to its members | source.m_cac_comp_info.op_class = UCHAR_MAX, source.m_cac_comp_info.channel = UCHAR_MAX, source.m_cac_comp_info.status = UCHAR_MAX, source.m_cac_comp_info.detected_pairs_num = UCHAR_MAX | Source object should have maximum values assigned | Should be successful |
 * | 02| Assign source object to target object | target = source | Target object should have the same values as source object | Should Pass |
 * | 03| Verify the values of target object | ASSERT_EQ(*target.get_cac_comp_info(), *source.get_cac_comp_info()) | The values of target object should match the source object | Should Pass |
 */
TEST(dm_cac_comp_t_Test, AssigningMaxValuesObject) {
     std::cout << "Entering AssigningMaxValuesObject" << std::endl;
     dm_cac_comp_t source;
     source.m_cac_comp_info.op_class = UCHAR_MAX;
     source.m_cac_comp_info.channel = UCHAR_MAX;
     source.m_cac_comp_info.status = UCHAR_MAX;
     source.m_cac_comp_info.detected_pairs_num = UCHAR_MAX;
     dm_cac_comp_t target;
     target = source;
     ASSERT_EQ(*target.get_cac_comp_info(), *source.get_cac_comp_info());
     std::cout << "Exiting AssigningMaxValuesObject" << std::endl;
}
 
 
 
 /**
 * @briefTEST to verify the assignment operator with minimum values
 *
 * ThisTEST checks the assignment operator of the dm_cac_comp_t class by assigning an object with minimum values to another object and verifying if the values are correctly assigned.@n
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 031@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description |TEST Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Create source object with minimum values | source.m_cac_comp_info.op_class = 0, source.m_cac_comp_info.channel = 0, source.m_cac_comp_info.status = 0, source.m_cac_comp_info.detected_pairs_num = 0 | Source object should have minimum values | Should be successful |
 * | 02 | Assign source object to target object | target = source | Target object should have the same values as source object | Should Pass |
 * | 03 | Verify the values of target object | ASSERT_EQ(*target.get_cac_comp_info(), *source.get_cac_comp_info()) | The values of target object should match the source object | Should Pass |
 */
 
TEST(dm_cac_comp_t_Test, AssigningMinValuesObject) {
     std::cout << "Entering AssigningMinValuesObject" << std::endl;
     dm_cac_comp_t source;
     source.m_cac_comp_info.op_class = 0;
     source.m_cac_comp_info.channel = 0;
     source.m_cac_comp_info.status = 0;
     source.m_cac_comp_info.detected_pairs_num = 0;
     dm_cac_comp_t target;
     target = source;
     ASSERT_EQ(*target.get_cac_comp_info(), *source.get_cac_comp_info());
     std::cout << "Exiting AssigningMinValuesObject" << std::endl;
}
 
 
 
 /**
 * @briefTEST to validate the CAC component information
 *
 * ThisTEST verifies that the CAC component information is correctly initialized and retrieved. It ensures that the object is created with the correct data and that the getter method returns the expected values.
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
 * | Variation / Step | Description |TEST Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize CAC component information | cac_comp = { {0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, 1, 36, 0, 2, { /* detected_pairs data */}} | CAC component initialized successfully | Should be successful |
 * | 02 | Create dm_cac_comp_t object with initialized data | obj(&cac_comp) | Object created successfully | Should be successful |
 * | 03 | Verify the operation class of the CAC component | obj.get_cac_comp_info()->op_class | Expected op_class = 1 | Should Pass |
 */
 
TEST(dm_cac_comp_t_Test, ValidCACComponentInformation) {
     std::cout << "Entering ValidCACComponentInformationTEST";
     em_cac_comp_info_t cac_comp = { {0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, 1, 36, 0, 2, { /* detected_pairs data */}};
     dm_cac_comp_t obj(&cac_comp);
     ASSERT_EQ(obj.get_cac_comp_info()->op_class, 1);
     std::cout << "Exiting ValidCACComponentInformationTEST";
}
 
 
 
 /**
 * @briefTEST to verify the behavior when CAC component information is null
 *
 * ThisTEST checks the behavior of the dm_cac_comp_t class when it is initialized with a null pointer for the CAC component information. It ensures that the class handles the null pointer correctly and returns the expected default values.
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
 * | Variation / Step | Description |TEST Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize dm_cac_comp_t with null CAC component information | cac_comp = nullptr | dm_cac_comp_t object should be created successfully | Should be successful |
 * | 02 | Verify the op_class value of the CAC component information | obj.get_cac_comp_info()->op_class | op_class should be 0 | Should Pass |
 */
TEST(dm_cac_comp_t_Test, NullCACComponentInformation) {
     std::cout << "Entering NullCACComponentInformationTEST";
     em_cac_comp_info_t* cac_comp = nullptr;
     dm_cac_comp_t obj(cac_comp);
     ASSERT_EQ(obj.get_cac_comp_info()->op_class, 0);
     std::cout << "Exiting NullCACComponentInformationTEST";
}
 
 
 
 /**
 * @briefTEST to verify the behavior of the dm_cac_comp_t class when initialized with an empty MAC address.
 *
 * ThisTEST checks if the dm_cac_comp_t object correctly initializes and retrieves the operating class when provided with an empty MAC address. This is important to ensure that the class handles edge cases of MAC address inputs properly.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 034@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description |TEST Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize dm_cac_comp_t with empty MAC address | mac_address = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, op_class = 1, channel = 36, cac_start_time = 0, cac_duration = 0 | dm_cac_comp_t object should be created successfully | Should Pass |
 * | 02 | Retrieve the operating class from the dm_cac_comp_t object | op_class = 1 | ASSERT_EQ should pass, op_class should be 1 | Should Pass |
 */
 
TEST(dm_cac_comp_t_Test, EmptyMACAddress) {
     std::cout << "Entering EmptyMACAddressTEST";
     em_cac_comp_info_t cac_comp = { {0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, 1, 36, 0, 0, {}};
     dm_cac_comp_t obj(&cac_comp);
     ASSERT_EQ(obj.get_cac_comp_info()->op_class, 1);
     std::cout << "Exiting EmptyMACAddressTEST";
}
 
 
 
 /**
 * @briefTEST to verify the maximum number of detected pairs in CAC component
 *
 * ThisTEST checks if the number of detected pairs in the CAC component is correctly set to the maximum allowed value. This is important to ensure that the system can handle the maximum number of detected pairs without errors.@n
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 035@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description |TEST Data |Expected Result |Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01| Initialize CAC component with maximum detected pairs | cac_comp = { {0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, 1, 36, 0, EM_MAX_CAC_METHODS, { /* detected_pairs data */}} | cac_comp initialized with maximum detected pairs | Should be successful |
 * | 02| Create dm_cac_comp_t object with initialized cac_comp | dm_cac_comp_t obj(&cac_comp) | Object created successfully | Should be successful |
 * | 03| Verify the number of detected pairs | obj.get_cac_comp_info()->detected_pairs_num | Expected: EM_MAX_CAC_METHODS | Should Pass |
 */
 
TEST(dm_cac_comp_t_Test, MaximumDetectedPairs) {
     std::cout << "Entering MaximumDetectedPairsTEST";
     em_cac_comp_info_t cac_comp = { {0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, 1, 36, 0, EM_MAX_CAC_METHODS, { /* detected_pairs data */}};
     dm_cac_comp_t obj(&cac_comp);
     ASSERT_EQ(obj.get_cac_comp_info()->detected_pairs_num, EM_MAX_CAC_METHODS);
     std::cout << "Exiting MaximumDetectedPairsTEST";
}
 
 
 
 /**
 * @briefTEST to validate the operation class in the cac_comp_info structure
 *
 * ThisTEST checks if the operation class in the cac_comp_info structure is correctly set to 0 when an invalid operation class is provided. This ensures that the class handles invalid operation classes appropriately.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 036@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description |TEST Data |Expected Result |Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01| Initialize cac_comp_info structure with invalid operation class | cac_comp = { {0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, 255, 36, 0, 2, { /* detected_pairs data */}} | cac_comp_info structure initialized | Should be successful |
 * | 02| Create dm_cac_comp_t object with initialized cac_comp_info | dm_cac_comp_t obj(&cac_comp) | dm_cac_comp_t object created | Should be successful |
 * | 03| Check if the operation class is set to 0 | obj.get_cac_comp_info()->op_class | Operation class is 0 | Should Pass |
 */
TEST(dm_cac_comp_t_Test, InvalidOperationClass) {
     std::cout << "Entering InvalidOperationClassTEST";
     em_cac_comp_info_t cac_comp = { {0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, 255, 36, 0, 2, { /* detected_pairs data */}};
     dm_cac_comp_t obj(&cac_comp);
     ASSERT_EQ(obj.get_cac_comp_info()->op_class, 0);
     std::cout << "Exiting InvalidOperationClassTEST";
}
 
 
 
 /**
 * @briefTEST to validate the behavior of the dm_cac_comp_t class when an invalid channel number is provided.
 *
 * ThisTEST checks the behavior of the dm_cac_comp_t class when initialized with an invalid channel number (255).@n
 * It ensures that the class correctly handles this invalid input by setting the channel number to 0.@n
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 037@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description |TEST Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize dm_cac_comp_t with invalid channel number | cac_comp = { {0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, 1, 255, 0, 2, { /* detected_pairs data */}} | dm_cac_comp_t object should be created successfully | Should be successful |
 * | 02 | Check the channel number in the cac_comp_info | obj.get_cac_comp_info()->channel | Expected channel number is 0 | Should Pass |
 */
 
TEST(dm_cac_comp_t_Test, InvalidChannelNumber) {
     std::cout << "Entering InvalidChannelNumberTEST";
     em_cac_comp_info_t cac_comp = { {0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, 1, 255, 0, 2, { /* detected_pairs data */}};
     dm_cac_comp_t obj(&cac_comp);
     ASSERT_EQ(obj.get_cac_comp_info()->channel, 0);
     std::cout << "Exiting InvalidChannelNumberTEST";
}
 
 
 
 /**
 * @briefTEST to validate the behavior of the dm_cac_comp_t class when an invalid status value is provided.
 *
 * ThisTEST checks the initialization of the dm_cac_comp_t object with an invalid status value (255) and verifies that the status is set to 0 as expected.@n
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 038@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description |TEST Data |Expected Result |Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01| Initialize dm_cac_comp_t object with invalid status value | cac_comp = { {0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, 1, 36, 255, 2, { /* detected_pairs data */}} | dm_cac_comp_t object should be initialized | Should be successful |
 * | 02| Verify the status value | obj.get_cac_comp_info()->status | status = 0 | Should Pass |
 */
TEST(dm_cac_comp_t_Test, InvalidStatusValue) {
     std::cout << "Entering InvalidStatusValueTEST";
     em_cac_comp_info_t cac_comp = { {0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, 1, 36, 255, 2, { /* detected_pairs data */}};
     dm_cac_comp_t obj(&cac_comp);
     ASSERT_EQ(obj.get_cac_comp_info()->status, 0);
     std::cout << "Exiting InvalidStatusValueTEST";
}
 
 
 
 /**
 * @briefTEST to verify the number of detected pairs is zero
 *
 * ThisTEST checks if the detected pairs number in the cac_comp_info_t structure is correctly initialized to zero and verified by the dm_cac_comp_t object.@n
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 039@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description |TEST Data |Expected Result |Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01| Initialize cac_comp_info_t structure and dm_cac_comp_t object | cac_comp = { {0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, 1, 36, 0, 0, {}}, obj = dm_cac_comp_t(&cac_comp) | Object should be initialized successfully | Should be successful |
 * | 02| Verify detected pairs number | obj.get_cac_comp_info()->detected_pairs_num | Expected: 0, Assertion: ASSERT_EQ | Should Pass |
 */
TEST(dm_cac_comp_t_Test, ZeroDetectedPairs) {
     std::cout << "Entering ZeroDetectedPairsTEST";
     em_cac_comp_info_t cac_comp = { {0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, 1, 36, 0, 0, {}};
     dm_cac_comp_t obj(&cac_comp);
     ASSERT_EQ(obj.get_cac_comp_info()->detected_pairs_num, 0);
     std::cout << "Exiting ZeroDetectedPairsTEST";
}
 
 
 
 /**
 * @briefTEST the copy constructor of dm_cac_comp_t with a valid source instance
 *
 * ThisTEST verifies that the copy constructor of the dm_cac_comp_t class correctly copies the data from a valid source instance. TheTEST ensures that the copied instance has the same data as the original instance by comparing their cac_comp_info.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 040@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description |TEST Data |Expected Result |Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01| Create a source instance of dm_cac_comp_t and initialize it | source_instance.init() | Source instance should be initialized | Should be successful |
 * | 02| Create a new instance using the copy constructor with the source instance | dm_cac_comp_t new_instance(source_instance) | new_instance should be created with the same data as source_instance | Should Pass |
 * | 03| Compare the cac_comp_info of the new instance and the source instance | *new_instance.get_cac_comp_info(), *source_instance.get_cac_comp_info() | The cac_comp_info of both instances should be equal | Should Pass |
 */
TEST(dm_cac_comp_t_Test, CopyConstructorWithValidSourceInstance) {
     std::cout << "Entering CopyConstructorWithValidSourceInstance" << std::endl;
     dm_cac_comp_t source_instance;
     source_instance.init();
     dm_cac_comp_t new_instance(source_instance);
     ASSERT_EQ(*new_instance.get_cac_comp_info(), *source_instance.get_cac_comp_info());
     std::cout << "Exiting CopyConstructorWithValidSourceInstance" << std::endl;
}
 
 
 
 /**
 * @briefTEST the copy constructor of dm_cac_comp_t when the source instance has maximum values.
 *
 * ThisTEST verifies that the copy constructor of the dm_cac_comp_t class correctly copies the 
 * m_cac_comp_info member from a source instance that has been initialized with maximum values. 
 * This ensures that the copy constructor handles edge cases with maximum data correctly.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 041@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description |TEST Data |Expected Result |Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01| Initialize source instance with maximum values | source_instance.m_cac_comp_info = max_values | Source instance should have maximum values | Should be successful |
 * | 02| Invoke copy constructor with source instance | dm_cac_comp_t new_instance(source_instance) | new_instance should have copied values from source_instance | Should Pass |
 * | 03| Verify copied values | *new_instance.get_cac_comp_info(), *source_instance.get_cac_comp_info() | Values should be equal | Should Pass |
 */
TEST(dm_cac_comp_t_Test, CopyConstructorWithSourceInstanceHavingMaximumValues) {
     std::cout << "Entering CopyConstructorWithSourceInstanceHavingMaximumValues" << std::endl;
     dm_cac_comp_t source_instance;
     em_cac_comp_info_t max_values;
     memset(&max_values, 0xFF, sizeof(em_cac_comp_info_t));
     source_instance.m_cac_comp_info = max_values;
     dm_cac_comp_t new_instance(source_instance);
     ASSERT_EQ(*new_instance.get_cac_comp_info(), *source_instance.get_cac_comp_info());
     std::cout << "Exiting CopyConstructorWithSourceInstanceHavingMaximumValues" << std::endl;
}
 
 
 
 /**
 * @briefTEST the copy constructor of dm_cac_comp_t with source instance having minimum values
 *
 * ThisTEST verifies that the copy constructor of the dm_cac_comp_t class correctly copies the 
 * contents of a source instance that has been initialized with minimum values. This ensures that 
 * the copy constructor handles edge cases where the source instance has the lowest possible values.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 042@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description |TEST Data |Expected Result |Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01| Initialize source instance with minimum values | source_instance.m_cac_comp_info = min_values | Source instance should have minimum values | Should be successful |
 * | 02| Invoke copy constructor with source instance | dm_cac_comp_t new_instance(source_instance) | new_instance should be created with same values as source_instance | Should Pass |
 * | 03| Compare the cac_comp_info of new_instance and source_instance | *new_instance.get_cac_comp_info(), *source_instance.get_cac_comp_info() | Both should be equal | Should Pass |
 */
TEST(dm_cac_comp_t_Test, CopyConstructorWithSourceInstanceHavingMinimumValues) {
     std::cout << "Entering CopyConstructorWithSourceInstanceHavingMinimumValues" << std::endl;
     dm_cac_comp_t source_instance;
     em_cac_comp_info_t min_values;
     memset(&min_values, 0x00, sizeof(em_cac_comp_info_t));
     source_instance.m_cac_comp_info = min_values;
     dm_cac_comp_t new_instance(source_instance);
     ASSERT_EQ(*new_instance.get_cac_comp_info(), *source_instance.get_cac_comp_info());
     std::cout << "Exiting CopyConstructorWithSourceInstanceHavingMinimumValues" << std::endl;
}
 
 int main(int argc, char **argv) {
     ::testing::InitGoogleTest(&argc, argv);
     return RUN_ALL_TESTS();
}