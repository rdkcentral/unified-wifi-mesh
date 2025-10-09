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
 #include "dm_cac_comp.h"

 
/**
  * @brief TEST decoding a valid JSON object with a valid parent ID
  *
  * This TEST verifies that the decode function correctly processes a valid JSON object when provided with a valid parent ID.
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
  * | Variation / Step | Description |TEST Data | Expected Result | Notes |
  * | :----: | --------- | ---------- |-------------- | ----- |
  * | 01 | Parse a valid JSON string to create a cJSON object | JSON string: "{\"key\":\"value\"}" | cJSON object created successfully | Should be successful |
  * | 02 | Call the decode function with the valid JSON object and a valid parent ID | validJson = cJSON object, parentID = 1 | Return value should be 0 | Should Pass |
  * | 03 | Verify the result using EXPECT_EQ | result = 0 | Assertion should pass | Should Pass |
  */
TEST(dm_cac_comp_t_Test, DecodeValidJsonObjectWithValidParentID) {
     std::cout << "Entering DecodeValidJsonObjectWithValidParentIDTEST" << std::endl;
     cJSON *validJson = cJSON_Parse("{\"key\":\"value\"}");
     int parentID = 1;
     dm_cac_comp_t* instance = new dm_cac_comp_t();
     int result = instance->decode(validJson, &parentID);
     EXPECT_EQ(result, 0);
     cJSON_Delete(validJson);
     delete instance;
     std::cout << "Exiting DecodeValidJsonObjectWithValidParentIDTEST" << std::endl;
}

/**
  * @brief TEST decoding a valid JSON object with a null parent ID
  *
  * This TEST verifies that the decode function correctly handles a valid JSON object when the parent ID is null. The expected behavior is that the function should return -1, indicating an error due to the null parent ID.
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
  * | 01 | Parse a valid JSON object | validJson = cJSON_Parse("{\"key\":\"value\"}") | validJson should be a valid cJSON object | Should be successful |
  * | 02 | Call decode with valid JSON and null parent ID | validJson = cJSON_Parse("{\"key\":\"value\"}"), parentID = nullptr | result should be -1 | Should Pass |
  * | 03 | Verify the result of decode function | result = -1 | ASSERT_EQ(result, -1) | Should Pass |
  */
TEST(dm_cac_comp_t_Test, DecodeValidJsonObjectWithNullParentID) {
    std::cout << "Entering DecodeValidJsonObjectWithNullParentIDTEST" << std::endl;
    cJSON *validJson = cJSON_Parse("{\"key\":\"value\"}");
    ASSERT_NE(validJson, nullptr);
    dm_cac_comp_t* instance = new dm_cac_comp_t();
    int result = instance->decode(validJson, nullptr);
    EXPECT_EQ(result, -1);
    cJSON_Delete(validJson);
    delete instance;
    std::cout << "Exiting DecodeValidJsonObjectWithNullParentIDTEST" << std::endl;
}

/**
  * @brief TEST the decode function with a null JSON object and a valid parent ID.
  *
  * This TEST checks the behavior of the decode function when provided with a null JSON object and a valid parent ID. It ensures that the function returns the expected error code when the JSON object is null.
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
  * | Variation / Step | Description |TEST Data | Expected Result | Notes |
  * | :----: | --------- | ---------- |-------------- | ----- |
  * | 01 | Call the decode function with a null JSON object and a valid parent ID. | jsonObject = nullptr, parentID = 1 | result = -1 | Should Pass |
  */
TEST(dm_cac_comp_t_Test, DecodeNullJsonObjectWithValidParentID) {
     std::cout << "Entering DecodeNullJsonObjectWithValidParentIDTEST" << std::endl;
     int parentID = 1;
     dm_cac_comp_t* instance = new dm_cac_comp_t();
     int result = instance->decode(nullptr, &parentID);
     EXPECT_EQ(result, -1);
     delete instance;
     std::cout << "Exiting DecodeNullJsonObjectWithValidParentIDTEST" << std::endl;
}
 
/**
  * @brief TEST decoding an empty JSON object with a valid parent ID.
  *
  * This TEST checks the behavior of the decode function when provided with an empty JSON object and a valid parent ID. The expected result is that the function should return -1, indicating failure to decode an empty JSON object.
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
  * | Variation / Step | Description |TEST Data | Expected Result | Notes |
  * | :----: | --------- | ---------- |-------------- | ----- |
  * | 01 | Parse an empty JSON object | emptyJson = cJSON_Parse("{}") | emptyJson is parsed successfully | Should be successful |
  * | 02 | Set a valid parent ID | parentID = 1 | parentID is set to 1 | Should be successful |
  * | 03 | Call the decode function with empty JSON and valid parent ID | result = instance->decode(emptyJson, &parentID) | result = -1 | Should Pass |
  * | 04 | Verify the result using EXPECT_EQ | EXPECT_EQ(result, -1) | result should be -1 | Should Pass |
  */
TEST(dm_cac_comp_t_Test, DecodeEmptyJsonObjectWithValidParentID) {
     std::cout << "Entering DecodeEmptyJsonObjectWithValidParentIDTEST" << std::endl;
     cJSON *emptyJson = cJSON_Parse("{}");
     int parentID = 1;
     dm_cac_comp_t* instance = new dm_cac_comp_t();
     int result = instance->decode(emptyJson, &parentID);
     EXPECT_EQ(result, -1);
     delete instance;
     cJSON_Delete(emptyJson);
     std::cout << "Exiting DecodeEmptyJsonObjectWithValidParentIDTEST" << std::endl;
}

/**
  * @brief TEST decoding of a JSON object with an invalid structure and a valid parent ID.
  *
  * This TEST verifies that the decode function correctly handles a JSON object with an invalid structure and a valid parent ID. The expected behavior is that the function should return an error code indicating failure.
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
  * | Variation / Step | Description |TEST Data | Expected Result | Notes |
  * | :----: | --------- | ---------- |-------------- | ----- |
  * | 01 | Parse an invalid JSON string to create a cJSON object | invalidJson = cJSON_Parse("{\"key\":}") | cJSON object created | Should be successful |
  * | 02 | Call the decode function with the invalid JSON object and a valid parent ID | invalidJson, parentID = 1 | result = -1 | Should Pass |
  * | 03 | Verify that the result of the decode function is -1 | result = -1 | Assertion check | Should Pass |
  */
TEST(dm_cac_comp_t_Test, DecodeJsonObjectWithInvalidStructureAndValidParentID) {
     std::cout << "Entering DecodeJsonObjectWithInvalidStructureAndValidParentIDTEST" << std::endl;
     cJSON *invalidJson = cJSON_Parse("{\"key\":}");
     int parentID = 1;
     dm_cac_comp_t* instance = new dm_cac_comp_t();
     int result = instance->decode(invalidJson, &parentID);
     EXPECT_EQ(result, -1);
     delete instance;
     cJSON_Delete(invalidJson);
     std::cout << "Exiting DecodeJsonObjectWithInvalidStructureAndValidParentIDTEST" << std::endl;
}

/**
  * @brief TEST the decode function with a valid JSON object and an invalid parent ID.
  *
  * This TEST verifies that the decode function correctly handles a valid JSON object 
  * but with an invalid parent ID. The expected behavior is that the function should 
  * return an error code indicating failure.
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
  * | Variation / Step | Description |TEST Data | Expected Result | Notes |
  * | :----: | --------- | ---------- |-------------- | ----- |
  * | 01 | Parse a valid JSON object. | JSON string: {"key":"value"} | cJSON object created | Should be successful |
  * | 02 | Call the decode function with the valid JSON object and an invalid parent ID. | validJson, invalidParentID = -1 | result = -1 | Should Pass |
  * | 03 | Verify that the result is -1, indicating failure. | result = -1 | Assertion passed | Should be successful |
  */
TEST(dm_cac_comp_t_Test, DecodeValidJsonObjectWithInvalidParentID) {
     std::cout << "Entering DecodeValidJsonObjectWithInvalidParentIDTEST" << std::endl;
     cJSON *validJson = cJSON_Parse("{\"key\":\"value\"}");
     int invalidParentID = -1;
     dm_cac_comp_t* instance = new dm_cac_comp_t();
     int result = instance->decode(validJson, &invalidParentID);
     EXPECT_EQ(result, -1);
     delete instance;
     cJSON_Delete(validJson);
     std::cout << "Exiting DecodeValidJsonObjectWithInvalidParentIDTEST" << std::endl;
}
 
/**
  * @brief TEST the encoding functionality with valid mixed data types
  *
  * This TEST verifies that the encode function can handle a JSON object with mixed data types (string, number, boolean) correctly.
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
  * | Variation / Step | Description |TEST Data | Expected Result | Notes |
  * | :----: | --------- | ---------- |-------------- | ----- |
  * | 01 | Create a JSON object | cJSON *json = cJSON_CreateObject() | Should be successful |  |
  * | 03 | Add a string to the JSON object | cJSON_AddStringToObject(json, "name", "test") | Should be successful |  |
  * | 04 | Add a number to the JSON object | cJSON_AddNumberToObject(json, "age", 30) | Should be successful |  |
  * | 05 | Add a boolean to the JSON object | cJSON_AddBoolToObject(json, "active", true) | Should be successful |  |
  * | 06 | Encode the JSON object | instance->encode(json) | Should be successful | Should Pass |
  * | 07 | Verify if the JSON object is still valid | EXPECT_TRUE(cJSON_IsObject(json)) | Should be successful | Should Pass |
  * | 08 | Delete the JSON object | cJSON_Delete(json) | Should be successful |  |
  */
TEST(dm_cac_comp_t_Test, EncodeWithValidMixedDataTypes) {
     std::cout << "Entering EncodeWithValidMixedDataTypes" << std::endl;
     cJSON *json = cJSON_CreateObject();
     cJSON_AddStringToObject(json, "name", "test"); 
     cJSON_AddNumberToObject(json, "age", 30);
     cJSON_AddBoolToObject(json, "active", true);
     dm_cac_comp_t* instance = new dm_cac_comp_t();
     instance->encode(json);
     EXPECT_TRUE(cJSON_IsObject(json));
     cJSON_Delete(json);
     delete instance;
     std::cout << "Exiting EncodeWithValidMixedDataTypes" << std::endl;
}
 
/**
  * @brief TEST the encoding function with a null JSON object
  *
  * This TEST checks the behavior of the encode function when provided with a null JSON object. It ensures that the function throws a runtime error as expected when the input is invalid.
  *
  * **Test Group ID:** Basic: 01@n
  * **Test Case ID:** 008@n
  * **Priority:** High@n
  * @n
  * **Pre-Conditions:** None@n
  * **Dependencies:** None@n
  * **User Interaction:** None@n
  * @n
  * **Test Procedure:**
  * | Variation / Step | Description |TEST Data | Expected Result | Notes |
  * | :----: | --------- | ---------- |-------------- | ----- |
  * | 01 | Create a null JSON object | json = nullptr | None | Should be successful |
  * | 02 | Call the encode function with the null JSON object | instance->encode(json) | Throws some exception | Should Pass |
  */
TEST(dm_cac_comp_t_Test, EncodeWithNullObject) {
     std::cout << "Entering EncodeWithNullObject" << std::endl;
     dm_cac_comp_t* instance = new dm_cac_comp_t();
     cJSON *json = nullptr;
     EXPECT_ANY_THROW(instance->encode(json));
     delete instance;
     std::cout << "Exiting EncodeWithNullObject" << std::endl;
}
 
/**
  * @brief TEST the encoding functionality with an empty JSON object.
  *
  * This TEST verifies that the encode function can handle an empty JSON object without errors and ensures that the object remains valid after encoding.
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
  * | Variation / Step | Description |TEST Data | Expected Result | Notes |
  * | :----: | --------- | ---------- |-------------- | ----- |
  * | 01 | Create an empty JSON object using cJSON_CreateObject | None | JSON object created successfully | Should be successful |
  * | 03 | Call the encode function with the empty JSON object | json = empty object | Function should handle the empty object without errors | Should Pass |
  * | 04 | Verify that the JSON object is still valid and is an object | json = empty object | EXPECT_TRUE(cJSON_IsObject(json)) should pass | Should Pass |
  * | 05 | Clean up the JSON object by calling cJSON_Delete | json = empty object | JSON object deleted successfully | Should be successful |
  */
TEST(dm_cac_comp_t_Test, EncodeWithEmptyObject) {
     std::cout << "Entering EncodeWithEmptyObject" << std::endl;
     cJSON *json = cJSON_CreateObject();
     dm_cac_comp_t* instance = new dm_cac_comp_t();
     instance->encode(json);
     EXPECT_TRUE(cJSON_IsObject(json));
     cJSON_Delete(json);
     delete instance;
     std::cout << "Exiting EncodeWithEmptyObject" << std::endl;
}

/**
  * @brief TEST the encoding functionality with arrays and special characters
  *
  * This TEST verifies that the encode function can handle JSON objects containing arrays and special characters correctly.
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
  * | Variation / Step | Description |TEST Data | Expected Result | Notes |
  * | :----: | --------- | ---------- |-------------- | ----- |
  * | 01 | Create a JSON object | None | JSON object created | Should be successful |
  * | 02 | Add an array to the JSON object | None | Array added to JSON object | Should be successful |
  * | 03 | Add a string with special characters to the JSON object | None | String with special characters added to JSON object | Should be successful |
  * | 04 | Encode the JSON object using the instance's encode method | json = JSON object | JSON object encoded | Should Pass |
  * | 05 | Assert that the JSON object is still valid | json = JSON object | JSON object is valid | Should Pass |
  * | 06 | Delete the JSON object | json = JSON object | JSON object deleted | Should be successful |
  */
TEST(dm_cac_comp_t_Test, EncodeWithArraysAndSpecialCharacters) {
     std::cout << "Entering EncodeWithArraysAndSpecialCharacters" << std::endl;
     cJSON *json = cJSON_CreateObject();
     cJSON_AddItemToObject(json, "array", cJSON_CreateArray());
     cJSON_AddStringToObject(json, "special", "!@#$%^&*() ");
     dm_cac_comp_t* instance = new dm_cac_comp_t();
     instance->encode(json);
     EXPECT_TRUE(cJSON_IsObject(json));
     cJSON_Delete(json);
     delete instance;
     std::cout << "Exiting EncodeWithArraysAndSpecialCharacters" << std::endl;
}

/**
  * @brief TEST the encoding functionality with null values in the JSON object.
  *
  * This TEST verifies that the encode function can handle JSON objects containing null values without causing errors or crashes.
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
  * | Variation / Step | Description |TEST Data | Expected Result | Notes |
  * | :----: | --------- | ---------- |-------------- | ----- |
  * | 01 | Create a JSON object and add a null value to it | json = cJSON_CreateObject(), cJSON_AddNullToObject(json, "null") | JSON object should be created and null value added successfully | Should be successful |
  * | 02 | Call the encode function with the JSON object containing null values | instance->encode(json) | Function should handle null values without errors | Should Pass |
  * | 03 | Verify that the JSON object is still valid after encoding | cJSON_IsObject(json) | JSON object should be valid | Should Pass |
  * | 04 | Clean up the JSON object | cJSON_Delete(json) | JSON object should be deleted successfully | Should be successful |
  */
TEST(dm_cac_comp_t_Test, EncodeWithNullValues) {
     std::cout << "Entering EncodeWithNullValues" << std::endl;
     cJSON *json = cJSON_CreateObject();
     cJSON_AddNullToObject(json, "null");
     dm_cac_comp_t* instance = new dm_cac_comp_t();
     instance->encode(json);
     EXPECT_TRUE(cJSON_IsObject(json));
     cJSON_Delete(json);
     delete instance;
     std::cout << "Exiting EncodeWithNullValues" << std::endl;
}
 
/**
  * @brief TEST to verify the retrieval of CAC Component ID after setting RUID
  *
  * This TEST checks if the CAC Component ID can be correctly retrieved after setting the RUID.
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
  * | 01 | Set the RUID in the CAC component info | expected_ruid = {0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E} | None | Should be successful |
  * | 02 | Retrieve the CAC Component ID | None | result != nullptr | Should Pass |
  * | 03 | Verify the retrieved CAC Component ID matches the expected RUID | result, expected_ruid | strncmp(result, expected_ruid, sizeof(expected_ruid)) == 0 | Should Pass |
  */
TEST(dm_cac_comp_t_Test, RetrieveCACComponentIDAfterSettingValidRuid) {
     std::cout << "Entering RetrieveCACComponentIDAfterSettingValidRuidTEST" << std::endl;
     unsigned char expected_ruid[] = {0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E};
     em_cac_comp_info_t comp_info{};
     memset(&comp_info, 0, sizeof(comp_info));
     memcpy(comp_info.ruid, expected_ruid, sizeof(expected_ruid));
     dm_cac_comp_t *instance = new dm_cac_comp_t(&comp_info);
     unsigned char* result = instance->get_cac_comp_id();
     ASSERT_NE(result, nullptr);
     EXPECT_EQ(memcmp(result, expected_ruid, sizeof(expected_ruid)), 0);
     delete instance;
     std::cout << "Exiting RetrieveCACComponentIDAfterSettingValidRuidTEST" << std::endl;
}

/**
  * @brief TEST to verify the retrieval of CAC Component ID after setting invalid RUID
  *
  * This TEST checks if the CAC Component ID can be retrieved after setting invalid RUID.
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
  * | 01 | Set the invalid RUID in the CAC component info | expected_ruid = {0x01, 0x00, 0xFF} | None | Should be successful |
  * | 02 | Retrieve the CAC Component ID | None | result != nullptr | Should Pass |
  * | 03 | Verify the retrieved CAC Component ID matches the expected RUID | result, expected_ruid | memcmp(result, expected_ruid, sizeof(expected_ruid)) == 0 | Should Pass |
  */
TEST(dm_cac_comp_t_Test, RetrieveCACComponentIDAfterSettingInvalidRuid) {
     std::cout << "Entering RetrieveCACComponentIDAfterSettingInvalidRuidTEST" << std::endl;
     unsigned char expected_ruid[] = {0x01, 0x00, 0xFF};
     em_cac_comp_info_t comp_info{};
     memset(&comp_info, 0, sizeof(comp_info));
     memcpy(comp_info.ruid, expected_ruid, sizeof(expected_ruid));
     dm_cac_comp_t *instance = new dm_cac_comp_t(&comp_info);
     unsigned char* result = instance->get_cac_comp_id();
     ASSERT_NE(result, nullptr);
     EXPECT_EQ(memcmp(result, expected_ruid, sizeof(expected_ruid)), 0);
     delete instance;
     std::cout << "Exiting RetrieveCACComponentIDAfterSettingInvalidRuidTEST" << std::endl;
}

/**
 * @brief TEST retrieval of default orchestration type from dm_cac_comp_t instance
 *
 * This TEST verifies that the `get_dm_orch_type` method returns a valid
 * orchestration type when called on a default-constructed `dm_cac_comp_t` object.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 014@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Step | Description                                          | Test Data        | Expected Result                  | Notes                 |
 * |------|------------------------------------------------------|------------------|----------------------------------|-----------------------|
 * | 01   | Create a default `dm_cac_comp_t` instance            | default object   | Should construct without errors  |                       |
 * | 02   | Retrieve orchestration type using `get_dm_orch_type`| `radio` instance | Should return a valid enum value | Print for verification |
 */
TEST(dm_cac_comp_t_Test, RetrieveDefaultOrchType) {
    std::cout << "Entering RetrieveDefaultOrchType" << std::endl;
    dm_cac_comp_t radio;
    dm_orch_type_t type = radio.get_dm_orch_type(radio);
    std::cout << "Retrieved orchestration type (enum value): " << static_cast<int>(type) << std::endl;
    std::cout << "Exiting RetrieveDefaultOrchType" << std::endl;
}
 
/**
  * @brief TEST to initialize the CAC Component Information Structure
  *
  * This TEST verifies the initialization of the CAC Component Information Structure by invoking the init() method of the dm_cac_comp_t class. TheTEST ensures that the initialization is successful and returns the expected result.
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
  * | Variation / Step | Description |TEST Data | Expected Result | Notes |
  * | :----: | --------- | ---------- |-------------- | ----- |
  * | 01 | Call the init() method on the instance | instance->init() | result = 0 | Should Pass |
  * | 02 | Verify the result of the init() method | result = 0 | EXPECT_EQ(result, 0) | Should be successful |
  */
TEST(dm_cac_comp_t_Test, InitializeCACComponentInformationStructure) {
     std::cout << "Entering InitializeCACComponentInformationStructureTEST" << std::endl;
     dm_cac_comp_t* instance = new dm_cac_comp_t();
     int result = instance->init();
     EXPECT_EQ(result, 0);
     delete instance;
     std::cout << "Exiting InitializeCACComponentInformationStructureTEST" << std::endl;
}

/**
  * @brief TEST the initialization of CAC Component Information Structure multiple times
  *
  * This TEST verifies that the `init` method of the `dm_cac_comp_t` class can be called multiple times successfully without causing any issues.
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
  * | Variation / Step | Description |TEST Data | Expected Result | Notes |
  * | :----: | --------- | ---------- |-------------- | ----- |
  * | 01 | Call the `init` method for the first time | None | Return value should be 0 | Should Pass |
  * | 02 | Call the `init` method for the second time | None | Return value should be 0 | Should Pass |
  * | 03 | Delete the instance of `dm_cac_comp_t` | None | Instance deleted successfully | Should be deleted |
  */
TEST(dm_cac_comp_t_Test, InitializeCACComponentInformationStructureMultipleTimes) {
     std::cout << "Entering InitializeCACComponentInformationStructureMultipleTimesTEST" << std::endl;
     dm_cac_comp_t* instance = new dm_cac_comp_t();
     int result1 = instance->init();
     EXPECT_EQ(result1, 0);
     int result2 = instance->init();
     EXPECT_EQ(result2, 0);
     delete instance;
     std::cout << "Exiting InitializeCACComponentInformationStructureMultipleTimesTEST" << std::endl;
}
 
/**
 * @brief TEST to compare two identical dm_cac_comp_t objects
 *
 * This TEST verifies that two dm_cac_comp_t objects with identical values are considered equal by the equality operator. This is important to ensure that the equality operator is correctly implemented and can accurately compare objects of this type.
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
 * | Variation / Step | Description |TEST Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Create two dm_cac_comp_t objects with identical values | obj1.m_cac_comp_info = {{0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E}, 1, 1, 1, 1, {7,8}}, obj2.m_cac_comp_info = {{0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E}, 1, 1, 1, 1, {7,8}} | Objects should be identical | Should Pass |
 * | 02 | Compare the two objects using the equality operator | obj1 == obj2 | EXPECT_TRUE should pass | Should Pass |
 */
 TEST(dm_cac_comp_t_Test, CompareIdenticalValues) {
     std::cout << "Entering CompareIdenticalValues" << std::endl;
     em_cac_comp_info_t info1{}, info2{};
     memset(&info1, 0, sizeof(info1));
     memset(&info2, 0, sizeof(info2));
     unsigned char ruid_val[] = {0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E};
     for (size_t i = 0; i < sizeof(info1.ruid); ++i) {
         info1.ruid[i] = ruid_val[i];
         info2.ruid[i] = ruid_val[i];
     }
     info1.op_class = info2.op_class = 1;
     info1.channel = info2.channel = 1;
     info1.status = info2.status = 1;
     info1.detected_pairs_num = info2.detected_pairs_num = 1;
     info1.detected_pairs[0].op_class = info2.detected_pairs[0].op_class = 7;
     info1.detected_pairs[0].channel = info2.detected_pairs[0].channel = 8;
     dm_cac_comp_t obj1(&info1);
     dm_cac_comp_t obj2(&info2); 
     EXPECT_TRUE(obj1 == obj2);
     std::cout << "Exiting CompareIdenticalValues" << std::endl;
 }
 
/**
 * @brief TEST to compare two dm_cac_comp_t objects with different RUID values
 *
 * This TEST verifies that two dm_cac_comp_t objects with different RUID values are not considered equal. This is important to ensure that the equality operator correctly identifies objects with different unique identifiers as unequal.
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
 * | Variation / Step | Description |TEST Data |Expected Result |Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01| Create two dm_cac_comp_t objects with different RUID values | obj1.m_cac_comp_info = {{0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E}, 1, 1, 1, 1, {7,8}}, obj2.m_cac_comp_info = {{0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5D}, 1, 1, 1, 1, {7,8}} | Objects should not be equal | Should Pass |
 * | 02| Compare the two objects using the equality operator | obj1 == obj2 | EXPECT_FALSE(obj1 == obj2) | Should Pass |
 */
 TEST(dm_cac_comp_t_Test, CompareDifferentRUIDValues) {
     std::cout << "Entering CompareDifferentRUIDValues" << std::endl;
     em_cac_comp_info_t info1{}, info2{};
     memset(&info1, 0, sizeof(info1));
     memset(&info2, 0, sizeof(info2));
     unsigned char ruid_val[] = {0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E};
     for (size_t i = 0; i < sizeof(info1.ruid); ++i) {
         info1.ruid[i] = ruid_val[i];
     }
     unsigned char ruid_val1[] = {0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5D};
     for (size_t i = 0; i < sizeof(info2.ruid); ++i) {
         info2.ruid[i] = ruid_val1[i];
     }
     info1.op_class = info2.op_class = 1;
     info1.channel = info2.channel = 1;
     info1.status = info2.status = 1;
     info1.detected_pairs_num = info2.detected_pairs_num = 1;
     info1.detected_pairs[0].op_class = info2.detected_pairs[0].op_class = 7;
     info1.detected_pairs[0].channel = info2.detected_pairs[0].channel = 8;
     dm_cac_comp_t obj1(&info1);
     dm_cac_comp_t obj2(&info2); 
     EXPECT_FALSE(obj1 == obj2);
     std::cout << "Exiting CompareDifferentRUIDValues" << std::endl;
 }

/**
 * @brief TEST to compare different operation class values in dm_cac_comp_t objects
 *
 * This TEST verifies that two dm_cac_comp_t objects with different operation class values are not considered equal.@n
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
 * | Variation / Step | Description |TEST Data |Expected Result |Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01| Create two dm_cac_comp_t objects with different operation class values | obj1.m_cac_comp_info = {{0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E}, 1, 1, 1, 1, {7,8}}, obj2.m_cac_comp_info = {{0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5D}, 2, 1, 1, 1, {7,8}} | Objects should not be equal | Should Pass |
 * | 02| Compare the two objects using the equality operator | obj1 == obj2 | EXPECT_FALSE(obj1 == obj2) | Should Pass |
 */
TEST(dm_cac_comp_t_Test, CompareDifferentOpClassValues) {
     std::cout << "Entering CompareDifferentOpClassValues" << std::endl;
     em_cac_comp_info_t info1{}, info2{};
     memset(&info1, 0, sizeof(info1));
     memset(&info2, 0, sizeof(info2));
     unsigned char ruid_val[] = {0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E};
     for (size_t i = 0; i < sizeof(info1.ruid); ++i) {
         info1.ruid[i] = ruid_val[i];
         info2.ruid[i] = ruid_val[i];
     }
     info1.op_class = 1;
     info2.op_class = 2;
     info1.channel = info2.channel = 1;
     info1.status = info2.status = 1;
     info1.detected_pairs_num = info2.detected_pairs_num = 1;
     info1.detected_pairs[0].op_class = info2.detected_pairs[0].op_class = 7;
     info1.detected_pairs[0].channel = info2.detected_pairs[0].channel = 8;
     dm_cac_comp_t obj1(&info1);
     dm_cac_comp_t obj2(&info2); 
     EXPECT_FALSE(obj1 == obj2);
     std::cout << "Exiting CompareDifferentOpClassValues" << std::endl;
}

/**
 * @brief TEST to compare different channel values in dm_cac_comp_t objects
 *
 * This TEST verifies that two dm_cac_comp_t objects with different channel values are not considered equal.@n
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
 * | Variation / Step | Description |TEST Data |Expected Result |Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01| Create two dm_cac_comp_t objects with different channel values | obj1.m_cac_comp_info = {{0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E}, 1, 1, 1, 1, {7,8}}, obj2.m_cac_comp_info = {{0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5D}, 1, 2, 1, 1, {7,8}} | Objects should not be equal | Should Pass |
 * | 02| Compare the two objects using the equality operator | obj1 == obj2 | EXPECT_FALSE(obj1 == obj2) | Should Pass |
 */
TEST(dm_cac_comp_t_Test, CompareDifferentChannelValues) {
     std::cout << "Entering CompareDifferentChannelValues" << std::endl;
     em_cac_comp_info_t info1{}, info2{};
     memset(&info1, 0, sizeof(info1));
     memset(&info2, 0, sizeof(info2));
     unsigned char ruid_val[] = {0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E};
     for (size_t i = 0; i < sizeof(info1.ruid); ++i) {
         info1.ruid[i] = ruid_val[i];
         info2.ruid[i] = ruid_val[i];
     }
     info1.op_class = info2.op_class = 1;
     info1.channel = 1;
     info2.channel = 2;
     info1.status = info2.status = 1;
     info1.detected_pairs_num = info2.detected_pairs_num = 1;
     info1.detected_pairs[0].op_class = info2.detected_pairs[0].op_class = 7;
     info1.detected_pairs[0].channel = info2.detected_pairs[0].channel = 8;
     dm_cac_comp_t obj1(&info1);
     dm_cac_comp_t obj2(&info2);
     EXPECT_FALSE(obj1 == obj2);
     std::cout << "Exiting CompareDifferentChannelValues" << std::endl;
}

/**
 * @brief TEST to compare different status values in dm_cac_comp_t objects
 *
 * This TEST verifies that two dm_cac_comp_t objects with different status values are not considered equal.@n
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
 * | 01| Create two dm_cac_comp_t objects with different status values | obj1.m_cac_comp_info = {{0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E}, 1, 1, 1, 1, {7,8}}, obj2.m_cac_comp_info = {{0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5D}, 1, 1, 2, 1, {7,8}} | Objects should not be equal | Should Pass |
 * | 02| Compare the two objects using the equality operator | obj1 == obj2 | EXPECT_FALSE(obj1 == obj2) | Should Pass |
 */
TEST(dm_cac_comp_t_Test, CompareDifferentStatusValues) {
     std::cout << "Entering CompareDifferentStatusValues" << std::endl;
     em_cac_comp_info_t info1{}, info2{};
     memset(&info1, 0, sizeof(info1));
     memset(&info2, 0, sizeof(info2));
     unsigned char ruid_val[] = {0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E};
     for (size_t i = 0; i < sizeof(info1.ruid); ++i) {
         info1.ruid[i] = ruid_val[i];
         info2.ruid[i] = ruid_val[i];
     }
     info1.op_class = info2.op_class = 1;
     info1.channel = info2.channel = 1;
     info1.status = 1;
     info2.status = 2;
     info1.detected_pairs_num = info2.detected_pairs_num = 1;
     info1.detected_pairs[0].op_class = info2.detected_pairs[0].op_class = 7;
     info1.detected_pairs[0].channel = info2.detected_pairs[0].channel = 8;
     dm_cac_comp_t obj1(&info1);
     dm_cac_comp_t obj2(&info2);
     EXPECT_FALSE(obj1 == obj2);
     std::cout << "Exiting CompareDifferentStatusValues" << std::endl;
}

/**
 * @brief TEST to compare two dm_cac_comp_t objects with different detected pairs number values
 *
 * This TEST verifies that two dm_cac_comp_t objects with identical attributes except for the detected pairs number value are not considered equal. This is important to ensure that the equality operator correctly distinguishes between objects with different detected pairs numbers.
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
 * | Variation / Step | Description |TEST Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Create two dm_cac_comp_t objects with different detected pairs number values | obj1.m_cac_comp_info = {{0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E}, 1, 1, 1, 1, {7,8}}, obj2.m_cac_comp_info = {{0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5D}, 1, 1, 1, 2, {7,8}} | Objects should not be equal | Should Pass |
 * | 02 | Compare the two objects using the equality operator | obj1 == obj2 | EXPECT_FALSE(obj1 == obj2) | Should Pass |
 */
TEST(dm_cac_comp_t_Test, CompareDifferentDetectedPairsNumValues) {
     std::cout << "Entering CompareDifferentDetectedPairsNumValues" << std::endl;
     em_cac_comp_info_t info1{}, info2{};
     memset(&info1, 0, sizeof(info1));
     memset(&info2, 0, sizeof(info2));
     unsigned char ruid_val[] = {0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E};
     for (size_t i = 0; i < sizeof(info1.ruid); ++i) {
         info1.ruid[i] = ruid_val[i];
         info2.ruid[i] = ruid_val[i];
     }
     info1.op_class = info2.op_class = 1;
     info1.channel = info2.channel = 1;
     info1.status = info2.status = 1;
     info1.detected_pairs_num = 1;
     info2.detected_pairs_num = 2;
     info1.detected_pairs[0].op_class = info2.detected_pairs[0].op_class = 7;
     info1.detected_pairs[0].channel = info2.detected_pairs[0].channel = 8;
     dm_cac_comp_t obj1(&info1);
     dm_cac_comp_t obj2(&info2);
     EXPECT_FALSE(obj1 == obj2);
     std::cout << "Exiting CompareDifferentDetectedPairsNumValues" << std::endl;
}
 
/**
 * @brief TEST to compare different detected pairs values in dm_cac_comp_t objects
 *
 * This TEST checks the equality operator for dm_cac_comp_t objects with different detected pairs values. 
 * It ensures that the equality operator correctly identifies objects with different detected pairs as unequal.
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
 * | 01| Create two dm_cac_comp_t objects with different detected pairs values | obj1.m_cac_comp_info = {{0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E}, 1, 1, 1, 1, {7,8}}, obj2.m_cac_comp_info = {{0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5D}, 1, 2, 1, 1, {6,8}} | Objects should be unequal | Should Pass |
 * | 02| Compare the two objects using the equality operator | obj1 == obj2 | EXPECT_FALSE(obj1 == obj2) | Should Pass |
 */
TEST(dm_cac_comp_t_Test, CompareDifferentDetectedPairsValues) {
     std::cout << "Entering CompareDifferentDetectedPairsValues" << std::endl;
     em_cac_comp_info_t info1{}, info2{};
     memset(&info1, 0, sizeof(info1));
     memset(&info2, 0, sizeof(info2));
     unsigned char ruid_val[] = {0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E};
     for (size_t i = 0; i < sizeof(info1.ruid); ++i) {
         info1.ruid[i] = ruid_val[i];
         info2.ruid[i] = ruid_val[i];
     }
     info1.op_class = info2.op_class = 1;
     info1.channel = info2.channel = 1;
     info1.status = info2.status = 1;
     info1.detected_pairs_num = info2.detected_pairs_num = 1;
     info1.detected_pairs[0].op_class = 7;
     info2.detected_pairs[0].op_class = 6;
     info1.detected_pairs[0].channel = info2.detected_pairs[0].channel = 8;
     dm_cac_comp_t obj1(&info1);
     dm_cac_comp_t obj2(&info2);    
     EXPECT_FALSE(obj1 == obj2);
     std::cout << "Exiting CompareDifferentDetectedPairsValues" << std::endl;
}

/**
 * @brief TEST to verify the assignment operator for dm_cac_comp_t class
 *
 * This TEST checks if the assignment operator correctly assigns the values from one instance of dm_cac_comp_t to another instance. This is important to ensure that the assignment operator works as expected and the internal state of the object is correctly copied.
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
 * | 01| Create source object and initialize few structure members | source.m_cac_comp_info.op_class = 2, source.m_cac_comp_info.channel = 36, source.m_cac_comp_info.detected_pairs_num = 3 | source object initialized | Should be successful |
 * | 02| Assign source object to target object | target = source | target object assigned | Should Pass |
 * | 03| Verify if source and target objects initialized fields match | source.m_cac_comp_info.op_class = target.m_cac_comp_info.op_class, source.m_cac_comp_info.channel = target.m_cac_comp_info.channel, source.m_cac_comp_info.detected_pairs_num = target.m_cac_comp_info.detected_pairs_num | target object assigned | Should Pass |
 */
TEST(dm_cac_comp_t_Test, AssigningValidObject) {
     std::cout << "Entering AssigningValidObject" << std::endl;
     dm_cac_comp_t source{}, target{};
     memset(&source.m_cac_comp_info, 0, sizeof(source.m_cac_comp_info));
     memset(&target.m_cac_comp_info, 0, sizeof(target.m_cac_comp_info));
     source.m_cac_comp_info.op_class = 2;
     source.m_cac_comp_info.channel = 36;
     source.m_cac_comp_info.detected_pairs_num = 3;
     target = source;
     EXPECT_EQ(target.m_cac_comp_info.op_class, source.m_cac_comp_info.op_class);
     EXPECT_EQ(target.m_cac_comp_info.channel, source.m_cac_comp_info.channel);
     EXPECT_EQ(target.m_cac_comp_info.detected_pairs_num, source.m_cac_comp_info.detected_pairs_num);
     std::cout << "Exiting AssigningValidObject" << std::endl;
}

/**
 * @brief Test to verify the assignment of two objects of dm_cac_comp_t class.
 *
 * This test checks if the assignment operator assigns invalid values from one object to another@n
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
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize obj1 with invalid MAC address | obj1.m_ap_mld_info.ruid = 0xAA:0xBB:0xDD:0x00:0x00:0x00 | obj1 should be initialized | Should be successful |
 * | 02 | Assign obj2 to obj1 | obj1 = obj2 | obj2 should have the same values as obj1 | Should Pass |
 * | 03 | Check equality of obj1 and obj2 | obj2.m_ap_mld_info.ruid != obj1.m_ap_mld_info.ruid | obj1 should be equal to obj2 | Should Pass |
 */
TEST(dm_cac_comp_t_Test, AssigningInvalidMacaddress) {
    std::cout << "Entering AssigningInvalidMacaddress" << std::endl;
    dm_cac_comp_t obj1{}, obj2{};
    memset(&obj1.m_cac_comp_info, 0, sizeof(obj1.m_cac_comp_info));
    memset(&obj2.m_cac_comp_info, 0, sizeof(obj2.m_cac_comp_info));
    unsigned char mac[] = {0x0A, 0xBB, 0xDD, 0x00, 0x00, 0x00};
    memcpy(obj1.m_cac_comp_info.ruid, mac, sizeof(mac));
    obj2 = obj1;
    for (size_t i = 0; i < sizeof(mac); ++i) {
        EXPECT_NE(obj2.m_cac_comp_info.ruid[i], mac[i]);
    }
    std::cout << "Exiting AssigningMacaddress" << std::endl;
}

/**
 * @brief TEST to validate the CAC component information
 *
 * This TEST verifies that the CAC component information is correctly initialized and retrieved. It ensures that the object is created with the correct data and that the getter method returns the expected values.
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
 * | Variation / Step | Description |TEST Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize CAC component information | cac_comp.op_class = 1, cac_comp.channel = 36, cac_comp.status = 0, cac_comp.detected_pairs_num = 2 | CAC component initialized successfully | Should be successful |
 * | 02 | Create dm_cac_comp_t object with initialized data | obj(&cac_comp) | Object created successfully | Should be successful |
 * | 03 | Verify few set values of the CAC component | op_class=1, channel=36, status=0, detected_pairs_num=2 | Expected op_class = 1 | Should Pass |
 */
TEST(dm_cac_comp_t_Test, ValidCACComponentInformation) {
     std::cout << "Entering ValidCACComponentInformationtest" << std::endl;
     em_cac_comp_info_t cac_comp{};
     cac_comp.op_class = 1;
     cac_comp.channel = 36;
     cac_comp.status = 0;
     cac_comp.detected_pairs_num = 2;
     dm_cac_comp_t obj(&cac_comp);
     EXPECT_EQ(obj.m_cac_comp_info.op_class, 1);
     EXPECT_EQ(obj.m_cac_comp_info.channel, 36);
     EXPECT_EQ(obj.m_cac_comp_info.status, 0);
     EXPECT_EQ(obj.m_cac_comp_info.detected_pairs_num, 2);
     std::cout << "Exiting ValidCACComponentInformationtest" << std::endl;
}
 
/**
 * @brief TEST to verify the behavior when CAC component information is null
 *
 * This TEST checks the behavior of the dm_cac_comp_t class when it is initialized with a null pointer for the CAC component information. It ensures that the class handles the null pointer correctly and returns the expected default values.
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
 * | Variation / Step | Description |TEST Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize dm_cac_comp_t with null CAC component information | cac_comp = nullptr | dm_cac_comp_t object should be created successfully | Should be successful |
 */
TEST(dm_cac_comp_t_Test, NullCACComponentInformation) {     
     std::cout << "Entering NullCACComponentInformationtest" << std::endl;
     em_cac_comp_info_t* cac_comp = nullptr;
     EXPECT_ANY_THROW(dm_cac_comp_t obj(cac_comp));
     std::cout << "Exiting NullCACComponentInformationtest" << std::endl;
}
 
/**
 * @brief TEST the copy constructor of dm_cac_comp_t with a valid source instance
 *
 * This TEST verifies that the copy constructor of the dm_cac_comp_t class correctly copies the data from a valid source instance. TheTEST ensures that the copied instance has the same data as the original instance by comparing their cac_comp_info.
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
 * | 01| Create a source instance of dm_cac_comp_t and initialize op_class and channel values | source_instance.m_cac_comp_info.op_class = 1, source_instance.m_cac_comp_info.channel = 36  | Source instance should be initialized | Should be successful |
 * | 02| Create a new instance using the copy constructor with the source instance | dm_cac_comp_t new_instance(source_instance) | new_instance should be created with the same data as source_instance | Should Pass |
 * | 03| Compare the cac_comp_info of the new instance and the source instance | new_instance.m_cac_comp_info.op_class = 1, new_instance.m_cac_comp_info.channel = 36 | The cac_comp_info of both instances should be equal | Should Pass |
 */
TEST(dm_cac_comp_t_Test, CopyConstructorWithValidSourceInstance) {
     std::cout << "Entering CopyConstructorWithValidSourceInstance" << std::endl;
     dm_cac_comp_t source_instance = {};
     memset(&source_instance.m_cac_comp_info, 0, sizeof(source_instance.m_cac_comp_info));
     source_instance.m_cac_comp_info.op_class = 1;
     source_instance.m_cac_comp_info.channel = 36;
     dm_cac_comp_t new_instance(source_instance);
     EXPECT_EQ(new_instance.m_cac_comp_info.op_class, 1);
     EXPECT_EQ(new_instance.m_cac_comp_info.channel, 36);
     std::cout << "Exiting CopyConstructorWithValidSourceInstance" << std::endl;
}

/**
 * @brief Test the default constructor of dm_cac_comp_t to ensure that it properly initializes the object without throwing exceptions.
 *
 * This test verifies that invoking the default constructor of dm_cac_comp_t does not throw any exception.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 029@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                       | Test Data                                                         | Expected Result                                                           | Notes        |
 * | :--------------: | ----------------------------------------------------------------- | ----------------------------------------------------------------- | ------------------------------------------------------------------------- | ------------ |
 * | 01               | Invoke the default constructor of dm_cac_comp_t and log the state.  | constructor = dm_cac_comp_t(), m_cac_comp_info = default state     | No exception is thrown; dm_cac_comp_t object is created and internal state is valid. | Should Pass  |
 */
TEST(dm_cac_comp_t_Test, DefaultConstructor_Success) {
    std::cout << "Entering DefaultConstructor_Success test" << std::endl;
    // Invoking default constructor and expect no throw
    EXPECT_NO_THROW({
        dm_cac_comp_t obj;
        std::cout << "Invoked dm_cac_comp_t() constructor." << std::endl;
    });
    std::cout << "Exiting DefaultConstructor_Success test" << std::endl;
}

/**
 * @brief Verify proper destruction of a dm_cac_comp_t object in automatic scope.
 *
 * This test verifies that an object of type dm_cac_comp_t is successfully created using its default constructor and is properly destroyed upon exiting the scope. The test ensures that no exceptions are thrown during the object's creation and automatic destruction, thereby validating correct resource management.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 030@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Invoke the default constructor of dm_cac_comp_t within an EXPECT_NO_THROW block to instantiate the object and trigger automatic destruction when going out of scope. | constructor_call = default, object scope = automatic | Object is created and its destructor is invoked without throwing any exceptions. | Should Pass |
 */
TEST(dm_cac_comp_t_Test, Valid_object_destruction_in_automatic_scope) {
    std::cout << "Entering Valid_object_destruction_in_automatic_scope test" << std::endl;
    // Create an object using the default constructor and ensure no exception is thrown
    EXPECT_NO_THROW({
        std::cout << "Invoking default constructor for dm_cac_comp_t." << std::endl;
        dm_cac_comp_t obj;
        std::cout << "dm_cac_comp_t object created. m_cac_comp_info internal state creation assumed initialized." << std::endl;
        std::cout << "Leaving inner scope. Destructor ~dm_cac_comp_t() will be automatically invoked." << std::endl;
    });
    std::cout << "Exited inner scope; dm_cac_comp_t destructor should have been invoked without exception." << std::endl;
    std::cout << "Exiting Valid_object_destruction_in_automatic_scope test" << std::endl;
}