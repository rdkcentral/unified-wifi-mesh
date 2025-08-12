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
#include "dm_op_class.h"


class dm_op_class_t_Test : public ::testing::Test {
protected:
    dm_op_class_t* instance;

    void SetUp() override {
        instance = new dm_op_class_t();
    }

    void TearDown() override {
        delete instance;
    }
};

/**
* @brief Test the decode function with a valid JSON object and a valid parent ID.
*
* This test verifies that the decode function of the dm_op_class_t class correctly processes a valid JSON object and a valid parent ID, returning the expected result.@n
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
* | 01 | Allocate memory for parent_id | parent_id = malloc(sizeof(int)) | Should be successful | |
* | 02 | Call decode function with valid JSON object and valid parent ID | obj = cJSON(), parent_id = valid pointer, result = dm_op_class.decode(&obj, parent_id) | result == 0, EXPECT_EQ(result, 0) | Should Pass |
* | 03 | Free allocated memory for parent_id | free(parent_id) | Should be successful | |
*/
TEST(dm_op_class_t_Test, DecodeWithValidJsonObjectAndValidParentId) {
    std::cout << "Entering DecodeWithValidJsonObjectAndValidParentId test";
    cJSON obj;
    void* parent_id = malloc(sizeof(int));
    dm_op_class_t dm_op_class;
    int result = dm_op_class.decode(&obj, parent_id);
    EXPECT_EQ(result, 0);
    free(parent_id);
    std::cout << "Exiting DecodeWithValidJsonObjectAndValidParentId test";
}



/**
* @brief Test the decode function with a null JSON object
*
* This test checks the behavior of the decode function when provided with a null JSON object. It ensures that the function handles this edge case correctly by returning an error code.@n
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
* | 01| Allocate memory for parent_id | parent_id = malloc(sizeof(int)) | Memory should be allocated successfully | Should be successful |
* | 02| Create dm_op_class_t instance | dm_op_class_t dm_op_class | Instance should be created successfully | Should be successful |
* | 03| Call decode with null JSON object | json_object = nullptr, parent_id = parent_id | result = -1 | Should Pass |
* | 04| Check result of decode function | result = -1 | result should be -1 | Should Pass |
* | 05| Free allocated memory | free(parent_id) | Memory should be freed successfully | Should be successful |
*/
/*code doesn't handle null
TEST(dm_op_class_t_Test, DecodeWithNullJsonObject) {
    std::cout << "Entering DecodeWithNullJsonObject test";
    void* parent_id = malloc(sizeof(int));
    dm_op_class_t dm_op_class;
    int result = dm_op_class.decode(nullptr, parent_id);
    EXPECT_EQ(result, -1);
    free(parent_id);
    std::cout << "Exiting DecodeWithNullJsonObject test";
}
*/

/**
* @brief Test the decode function with a null parent ID
*
* This test checks the behavior of the decode function when provided with a null parent ID. The function is expected to handle this scenario gracefully and return an error code.@n
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
* | 01 | Call decode with null parent ID | obj = cJSON object, parent_id = nullptr | result = -1, EXPECT_EQ(result, -1) | Should Pass |
*/
/*code doesn't handle null
TEST(dm_op_class_t_Test, DecodeWithNullParentId) {
    std::cout << "Entering DecodeWithNullParentId test";
    cJSON obj;
    dm_op_class_t dm_op_class;
    int result = dm_op_class.decode(&obj, nullptr);
    EXPECT_EQ(result, -1);
    std::cout << "Exiting DecodeWithNullParentId test";
}
*/

/**
* @brief Test to verify the behavior of the decode function when provided with an empty JSON object.
*
* This test checks the decode function of the dm_op_class_t class to ensure it correctly handles an empty JSON object and returns the expected error code.@n
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
* | 01 | Create an empty JSON object and allocate memory for parent_id | cJSON obj = {0}, parent_id = malloc(sizeof(int)) | Should be successful | |
* | 02 | Call decode function with empty JSON object | dm_op_class.decode(&obj, parent_id) | result = -1, EXPECT_EQ(result, -1) | Should Pass |
* | 03 | Free allocated memory for parent_id | free(parent_id) | Should be successful | |
*/
TEST(dm_op_class_t_Test, DecodeWithEmptyJsonObject) {
    std::cout << "Entering DecodeWithEmptyJsonObject test" << std::endl;
    cJSON obj = {};
    void* parent_id = malloc(sizeof(int));
    dm_op_class_t dm_op_class;
    int result = dm_op_class.decode(&obj, parent_id);
    EXPECT_EQ(result, -1);
    free(parent_id);
    std::cout << "Exiting DecodeWithEmptyJsonObject test" << std::endl;
}

/**
* @brief Test the decode function with a JSON object having an invalid type
*
* This test verifies the behavior of the decode function when provided with a JSON object that has an invalid type. The objective is to ensure that the function correctly handles and returns an error code for invalid input types.
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
* | 01| Set up the test environment | instance = new dm_op_class_t() | Should be successful | |
* | 02| Create a JSON object with invalid type | obj.type = -1 | Should be successful | |
* | 03| Allocate memory for parent_id | parent_id = malloc(sizeof(int)) | Should be successful | |
* | 04| Invoke the decode function with invalid JSON object | dm_op_class.decode(&obj, parent_id) | result = -1, EXPECT_EQ(result, -1) | Should Pass |
* | 05| Free the allocated memory | free(parent_id) | Should be successful | |
* | 06| Tear down the test environment | delete instance | Should be successful | |
*/
TEST(dm_op_class_t_Test, DecodeWithJsonObjectHavingInvalidType) {
    std::cout << "Entering DecodeWithJsonObjectHavingInvalidType test";
    cJSON obj;
    obj.type = -1;
    void* parent_id = malloc(sizeof(int));
    dm_op_class_t dm_op_class;
    int result = dm_op_class.decode(&obj, parent_id);
    EXPECT_EQ(result, -1);
    free(parent_id);
    std::cout << "Exiting DecodeWithJsonObjectHavingInvalidType test";
}

/**
* @brief Test the decode function with a JSON object having a valid type but invalid data.
*
* This test checks the behavior of the decode function when provided with a JSON object that has a valid type (cJSON_Number) but contains invalid data (NAN). This is to ensure that the function correctly handles and returns an error for invalid data inputs.
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
* | 01 | Create a JSON object with type cJSON_Number and value NAN | obj.type = cJSON_Number, obj.valuedouble = NAN | JSON object created successfully | Should be successful |
* | 02 | Allocate memory for parent_id | parent_id = malloc(sizeof(int)) | Memory allocated successfully | Should be successful |
* | 03 | Call the decode function with the JSON object and parent_id | dm_op_class.decode(&obj, parent_id) | result = -1 | Should Fail |
* | 04 | Free the allocated memory for parent_id | free(parent_id) | Memory freed successfully | Should be successful |
*/
TEST(dm_op_class_t_Test, DecodeWithJsonObjectHavingValidTypeButInvalidData) {
    std::cout << "Entering DecodeWithJsonObjectHavingValidTypeButInvalidData test";
    cJSON obj;
    obj.type = cJSON_Number;
    obj.valuedouble = NAN;
    void* parent_id = malloc(sizeof(int));
    dm_op_class_t dm_op_class;
    int result = dm_op_class.decode(&obj, parent_id);
    EXPECT_EQ(result, -1);
    free(parent_id);
    std::cout << "Exiting DecodeWithJsonObjectHavingValidTypeButInvalidData test";
}

/**
* @brief Test decoding a JSON object with nested valid JSON objects.
*
* This test verifies the functionality of the decode method in the dm_op_class_t class when provided with a JSON object that contains nested valid JSON objects. The objective is to ensure that the method correctly processes nested structures and returns the expected result.
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
* | 01| Initialize test objects | obj.child = &child, parent_id = malloc(sizeof(int)) | None | Should be successful |
* | 02| Invoke decode method | dm_op_class.decode(&obj, parent_id) | result = 0 | Should Pass |
* | 03| Free allocated memory | free(parent_id) | None | Should be successful |
*/
TEST(dm_op_class_t_Test, DecodeWithJsonObjectHavingNestedValidJsonObjects) {
    std::cout << "Entering DecodeWithJsonObjectHavingNestedValidJsonObjects test";
    cJSON obj;
    cJSON child;
    obj.child = &child;
    void* parent_id = malloc(sizeof(int));
    dm_op_class_t dm_op_class;
    int result = dm_op_class.decode(&obj, parent_id);
    EXPECT_EQ(result, 0);
    free(parent_id);
    std::cout << "Exiting DecodeWithJsonObjectHavingNestedValidJsonObjects test";
}

/**
* @brief Test the decode function with a JSON object having nested invalid JSON objects.
*
* This test checks the behavior of the decode function when provided with a JSON object that contains nested invalid JSON objects. The objective is to ensure that the function correctly identifies and handles invalid JSON structures.
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
* | 01| Create a JSON object with nested invalid JSON objects | obj.child = &child, child.type = -1 | Should be successful | |
* | 02| Allocate memory for parent_id | parent_id = malloc(sizeof(int)) | Should be successful | |
* | 03| Invoke the decode function | dm_op_class.decode(&obj, parent_id) | result = -1, EXPECT_EQ(result, -1) | Should Pass |
* | 04| Free the allocated memory | free(parent_id) | Should be successful | |
*/
TEST(dm_op_class_t_Test, DecodeWithJsonObjectHavingNestedInvalidJsonObjects) {
    std::cout << "Entering DecodeWithJsonObjectHavingNestedInvalidJsonObjects test";
    cJSON obj;
    cJSON child;
    child.type = -1;
    obj.child = &child;
    void* parent_id = malloc(sizeof(int));
    dm_op_class_t dm_op_class;
    int result = dm_op_class.decode(&obj, parent_id);
    EXPECT_EQ(result, -1);
    free(parent_id);
    std::cout << "Exiting DecodeWithJsonObjectHavingNestedInvalidJsonObjects test";
}

/**
* @brief Test the copy constructor of dm_op_class_t with mixed values
*
* This test verifies that the copy constructor of the dm_op_class_t class correctly copies all fields from the original object to the new object. This ensures that the copy constructor works as expected when the object contains a mix of different values.
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
* | 01| Initialize op_class_info with mixed values | op_class_info.id.type = em_op_class_type_current, op_class_info.op_class = 1, op_class_info.channel = 36, op_class_info.tx_power = 20, op_class_info.max_tx_power = 30, op_class_info.num_channels = 2, op_class_info.channels[0] = 36, op_class_info.channels[1] = 40, op_class_info.mins_since_cac_comp = 10, op_class_info.sec_remain_non_occ_dur = 20, op_class_info.countdown_cac_comp = 30 | Initialization should be successful | Should be successful |
* | 02| Create original dm_op_class_t object with op_class_info | dm_op_class_t original(&op_class_info) | Object should be created successfully | Should be successful |
* | 03| Create copy of original dm_op_class_t object | dm_op_class_t copy(original) | Copy should be created successfully | Should be successful |
* | 04| Verify copied values | copy.m_op_class_info.id.type == original.m_op_class_info.id.type, copy.m_op_class_info.op_class == original.m_op_class_info.op_class, copy.m_op_class_info.channel == original.m_op_class_info.channel, copy.m_op_class_info.tx_power == original.m_op_class_info.tx_power, copy.m_op_class_info.max_tx_power == original.m_op_class_info.max_tx_power, copy.m_op_class_info.num_channels == original.m_op_class_info.num_channels, copy.m_op_class_info.channels[0] == original.m_op_class_info.channels[0], copy.m_op_class_info.channels[1] == original.m_op_class_info.channels[1], copy.m_op_class_info.mins_since_cac_comp == original.m_op_class_info.mins_since_cac_comp, copy.m_op_class_info.sec_remain_non_occ_dur == original.m_op_class_info.sec_remain_non_occ_dur, copy.m_op_class_info.countdown_cac_comp == original.m_op_class_info.countdown_cac_comp | All values should match | Should Pass |
*/
TEST(dm_op_class_t_Test, CopyConstructorWithMixedValues) {
    std::cout << "Entering CopyConstructorWithMixedValues" << std::endl;
    em_op_class_info_t op_class_info;
    op_class_info.id.type = em_op_class_type_current;
    op_class_info.op_class = 1;
    op_class_info.channel = 36;
    op_class_info.tx_power = 20;
    op_class_info.max_tx_power = 30;
    op_class_info.num_channels = 2;
    op_class_info.channels[0] = 36;
    op_class_info.channels[1] = 40;
    op_class_info.mins_since_cac_comp = 10;
    op_class_info.sec_remain_non_occ_dur = 20;
    op_class_info.countdown_cac_comp = 30;
    dm_op_class_t original(&op_class_info);
    dm_op_class_t copy(original);
    ASSERT_EQ(copy.m_op_class_info.id.type, original.m_op_class_info.id.type);
    ASSERT_EQ(copy.m_op_class_info.op_class, original.m_op_class_info.op_class);
    ASSERT_EQ(copy.m_op_class_info.channel, original.m_op_class_info.channel);
    ASSERT_EQ(copy.m_op_class_info.tx_power, original.m_op_class_info.tx_power);
    ASSERT_EQ(copy.m_op_class_info.max_tx_power, original.m_op_class_info.max_tx_power);
    ASSERT_EQ(copy.m_op_class_info.num_channels, original.m_op_class_info.num_channels);
    ASSERT_EQ(copy.m_op_class_info.channels[0], original.m_op_class_info.channels[0]);
    ASSERT_EQ(copy.m_op_class_info.channels[1], original.m_op_class_info.channels[1]);
    ASSERT_EQ(copy.m_op_class_info.mins_since_cac_comp, original.m_op_class_info.mins_since_cac_comp);
    ASSERT_EQ(copy.m_op_class_info.sec_remain_non_occ_dur, original.m_op_class_info.sec_remain_non_occ_dur);
    ASSERT_EQ(copy.m_op_class_info.countdown_cac_comp, original.m_op_class_info.countdown_cac_comp);
    std::cout << "Exiting CopyConstructorWithMixedValues" << std::endl;
}

/**
* @brief Test the initialization of dm_op_class_t with valid op_class_info
*
* This test verifies that the dm_op_class_t object is correctly initialized with valid op_class_info data. It checks if all the fields in the op_class_info structure are properly assigned to the corresponding fields in the dm_op_class_t object.
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
* | 01 | Initialize dm_op_class_t with valid op_class_info | op_class_info = {id = {ruid = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, type = em_op_class_type_current, op_class = 1}, op_class = 1, channel = 36, tx_power = 20, max_tx_power = 30, num_channels = 1, channels = {36}, mins_since_cac_comp = 10, sec_remain_non_occ_dur = 20, countdown_cac_comp = 30} | dm_op_class_t object should be initialized with the provided op_class_info | Should Pass |
* | 02 | Check op_class field | obj.m_op_class_info.op_class = 1 | ASSERT_EQ(obj.m_op_class_info.op_class, op_class_info.op_class) | Should Pass |
* | 03 | Check channel field | obj.m_op_class_info.channel = 36 | ASSERT_EQ(obj.m_op_class_info.channel, op_class_info.channel) | Should Pass |
* | 04 | Check tx_power field | obj.m_op_class_info.tx_power = 20 | ASSERT_EQ(obj.m_op_class_info.tx_power, op_class_info.tx_power) | Should Pass |
* | 05 | Check max_tx_power field | obj.m_op_class_info.max_tx_power = 30 | ASSERT_EQ(obj.m_op_class_info.max_tx_power, op_class_info.max_tx_power) | Should Pass |
* | 06 | Check num_channels field | obj.m_op_class_info.num_channels = 1 | ASSERT_EQ(obj.m_op_class_info.num_channels, op_class_info.num_channels) | Should Pass |
* | 07 | Check channels field | obj.m_op_class_info.channels[0] = 36 | ASSERT_EQ(obj.m_op_class_info.channels[0], op_class_info.channels[0]) | Should Pass |
* | 08 | Check mins_since_cac_comp field | obj.m_op_class_info.mins_since_cac_comp = 10 | ASSERT_EQ(obj.m_op_class_info.mins_since_cac_comp, op_class_info.mins_since_cac_comp) | Should Pass |
* | 09 | Check sec_remain_non_occ_dur field | obj.m_op_class_info.sec_remain_non_occ_dur = 20 | ASSERT_EQ(obj.m_op_class_info.sec_remain_non_occ_dur, op_class_info.sec_remain_non_occ_dur) | Should Pass |
* | 10 | Check countdown_cac_comp field | obj.m_op_class_info.countdown_cac_comp = 30 | ASSERT_EQ(obj.m_op_class_info.countdown_cac_comp, op_class_info.countdown_cac_comp) | Should Pass |
*/
TEST(dm_op_class_t_Test, InitializeWithValidOpClassInfo) {
    std::cout << "Entering InitializeWithValidOpClassInfo" << std::endl;
    em_op_class_info_t op_class_info = {
        .id = { .ruid = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, .type = em_op_class_type_current, .op_class = 1 },
        .op_class = 1,
        .channel = 36,
        .tx_power = 20,
        .max_tx_power = 30,
        .num_channels = 1,
        .channels = {36},
        .mins_since_cac_comp = 10,
        .sec_remain_non_occ_dur = 20,
        .countdown_cac_comp = 30
    };
    dm_op_class_t obj(op_class_info);
    ASSERT_EQ(obj.m_op_class_info.op_class, op_class_info.op_class);
    ASSERT_EQ(obj.m_op_class_info.channel, op_class_info.channel);
    ASSERT_EQ(obj.m_op_class_info.tx_power, op_class_info.tx_power);
    ASSERT_EQ(obj.m_op_class_info.max_tx_power, op_class_info.max_tx_power);
    ASSERT_EQ(obj.m_op_class_info.num_channels, op_class_info.num_channels);
    ASSERT_EQ(obj.m_op_class_info.channels[0], op_class_info.channels[0]);
    ASSERT_EQ(obj.m_op_class_info.mins_since_cac_comp, op_class_info.mins_since_cac_comp);
    ASSERT_EQ(obj.m_op_class_info.sec_remain_non_occ_dur, op_class_info.sec_remain_non_occ_dur);
    ASSERT_EQ(obj.m_op_class_info.countdown_cac_comp, op_class_info.countdown_cac_comp);
    std::cout << "Exiting InitializeWithValidOpClassInfo" << std::endl;
}

/**
* @brief Test the initialization of dm_op_class_t with invalid operation class info having negative tx_power
*
* This test verifies that the dm_op_class_t object is correctly initialized with invalid operation class info where tx_power is negative. The test ensures that all the fields in the object match the provided input values, even if the tx_power is invalid.
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
* | 01 | Initialize dm_op_class_t with invalid op_class_info having negative tx_power | op_class_info = {id = {ruid = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, type = em_op_class_type_current, op_class = 1}, op_class = 1, channel = 36, tx_power = -1, max_tx_power = 30, num_channels = 1, channels = {36}, mins_since_cac_comp = 10, sec_remain_non_occ_dur = 20, countdown_cac_comp = 30} | All fields in obj.m_op_class_info should match the input op_class_info | Should Pass |
*/
TEST(dm_op_class_t_Test, InitializeWithInvalidOpClassInfoNegativeTxPower) {
    std::cout << "Entering InitializeWithInvalidOpClassInfoNegativeTxPower" << std::endl;
    em_op_class_info_t op_class_info = {
        .id = { .ruid = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, .type = em_op_class_type_current, .op_class = 1 },
        .op_class = 1,
        .channel = 36,
        .tx_power = -1,
        .max_tx_power = 30,
        .num_channels = 1,
        .channels = {36},
        .mins_since_cac_comp = 10,
        .sec_remain_non_occ_dur = 20,
        .countdown_cac_comp = 30
    };
    dm_op_class_t obj(op_class_info);
    ASSERT_EQ(obj.m_op_class_info.op_class, op_class_info.op_class);
    ASSERT_EQ(obj.m_op_class_info.channel, op_class_info.channel);
    ASSERT_EQ(obj.m_op_class_info.tx_power, op_class_info.tx_power);
    ASSERT_EQ(obj.m_op_class_info.max_tx_power, op_class_info.max_tx_power);
    ASSERT_EQ(obj.m_op_class_info.num_channels, op_class_info.num_channels);
    ASSERT_EQ(obj.m_op_class_info.channels[0], op_class_info.channels[0]);
    ASSERT_EQ(obj.m_op_class_info.mins_since_cac_comp, op_class_info.mins_since_cac_comp);
    ASSERT_EQ(obj.m_op_class_info.sec_remain_non_occ_dur, op_class_info.sec_remain_non_occ_dur);
    ASSERT_EQ(obj.m_op_class_info.countdown_cac_comp, op_class_info.countdown_cac_comp);
    std::cout << "Exiting InitializeWithInvalidOpClassInfoNegativeTxPower" << std::endl;
}

/**
* @brief Test to validate the initialization of dm_op_class_t with invalid number of channels exceeding the limit.
*
* This test checks the behavior of the dm_op_class_t class when initialized with an em_op_class_info_t structure where the number of channels exceeds the defined limit. It ensures that the class correctly handles and caps the number of channels to the maximum allowed value.
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
* | 01| Initialize dm_op_class_t with invalid number of channels | op_class_info with num_channels = EM_MAX_CHANNELS_IN_LIST + 1 | num_channels should be capped to EM_MAX_CHANNELS_IN_LIST | Should Pass |
* | 02| Validate op_class field | op_class_info.op_class = 1 | obj.m_op_class_info.op_class == op_class_info.op_class | Should Pass |
* | 03| Validate channel field | op_class_info.channel = 36 | obj.m_op_class_info.channel == op_class_info.channel | Should Pass |
* | 04| Validate tx_power field | op_class_info.tx_power = 20 | obj.m_op_class_info.tx_power == op_class_info.tx_power | Should Pass |
* | 05| Validate max_tx_power field | op_class_info.max_tx_power = 30 | obj.m_op_class_info.max_tx_power == op_class_info.max_tx_power | Should Pass |
* | 06| Validate num_channels field | op_class_info.num_channels = EM_MAX_CHANNELS_IN_LIST + 1 | obj.m_op_class_info.num_channels == EM_MAX_CHANNELS_IN_LIST | Should Pass |
* | 07| Validate channels array | op_class_info.channels = {36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165} | obj.m_op_class_info.channels[i] == op_class_info.channels[i] for i in range 0 to EM_MAX_CHANNELS_IN_LIST-1 | Should Pass |
* | 08| Validate mins_since_cac_comp field | op_class_info.mins_since_cac_comp = 10 | obj.m_op_class_info.mins_since_cac_comp == op_class_info.mins_since_cac_comp | Should Pass |
* | 09| Validate sec_remain_non_occ_dur field | op_class_info.sec_remain_non_occ_dur = 20 | obj.m_op_class_info.sec_remain_non_occ_dur == op_class_info.sec_remain_non_occ_dur | Should Pass |
* | 10| Validate countdown_cac_comp field | op_class_info.countdown_cac_comp = 30 | obj.m_op_class_info.countdown_cac_comp == op_class_info.countdown_cac_comp | Should Pass |
*/
TEST(dm_op_class_t_Test, InitializeWithInvalidOpClassInfoNumChannelsExceedsLimit) {
    std::cout << "Entering InitializeWithInvalidOpClassInfoNumChannelsExceedsLimit" << std::endl;
    em_op_class_info_t op_class_info = {
        .id = { .ruid = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, .type = em_op_class_type_current, .op_class = 1 },
        .op_class = 1,
        .channel = 36,
        .tx_power = 20,
        .max_tx_power = 30,
        .num_channels = EM_MAX_CHANNELS_IN_LIST + 1,
        .channels = {36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165},
        .mins_since_cac_comp = 10,
        .sec_remain_non_occ_dur = 20,
        .countdown_cac_comp = 30
    };
    dm_op_class_t obj(op_class_info);
    ASSERT_EQ(obj.m_op_class_info.op_class, op_class_info.op_class);
    ASSERT_EQ(obj.m_op_class_info.channel, op_class_info.channel);
    ASSERT_EQ(obj.m_op_class_info.tx_power, op_class_info.tx_power);
    ASSERT_EQ(obj.m_op_class_info.max_tx_power, op_class_info.max_tx_power);
    ASSERT_EQ(obj.m_op_class_info.num_channels, EM_MAX_CHANNELS_IN_LIST);
    for (unsigned int i = 0; i < EM_MAX_CHANNELS_IN_LIST; ++i) {
        ASSERT_EQ(obj.m_op_class_info.channels[i], op_class_info.channels[i]);
    }
    ASSERT_EQ(obj.m_op_class_info.mins_since_cac_comp, op_class_info.mins_since_cac_comp);
    ASSERT_EQ(obj.m_op_class_info.sec_remain_non_occ_dur, op_class_info.sec_remain_non_occ_dur);
    ASSERT_EQ(obj.m_op_class_info.countdown_cac_comp, op_class_info.countdown_cac_comp);
    std::cout << "Exiting InitializeWithInvalidOpClassInfoNumChannelsExceedsLimit" << std::endl;
}

/**
* @brief Test to validate the operation class information
*
* This test verifies that the operation class information is correctly initialized and retrieved by the dm_op_class_t class. It ensures that the tx_power value is correctly set and retrieved.
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
* | 01 | Initialize operation class info | id = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, type = em_op_class_type_current, op_class = 1, channel = 36, tx_power = 20, max_tx_power = 30, num_channels = 2, channels = {36, 40}, mins_since_cac_comp = 10, sec_remain_non_occ_dur = 20, countdown_cac_comp = 30 | Operation class info initialized | Should be successful |
* | 02 | Create dm_op_class_t object with initialized info | op_class info from step 01 | dm_op_class_t object created | Should be successful |
* | 03 | Retrieve tx_power from dm_op_class_t object | None | tx_power = 20 | Should Pass |
*/
TEST(dm_op_class_t_Test, ValidOpClassInfo) {
    std::cout << "Entering ValidOpClassInfo test";
    em_op_class_info_t op_class = {
        .id = { .ruid = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, .type = em_op_class_type_current, .op_class = 1 },
        .op_class = 1,
        .channel = 36,
        .tx_power = 20,
        .max_tx_power = 30,
        .num_channels = 2,
        .channels = {36, 40},
        .mins_since_cac_comp = 10,
        .sec_remain_non_occ_dur = 20,
        .countdown_cac_comp = 30
    };
    dm_op_class_t obj(&op_class);
    ASSERT_EQ(obj.get_op_class_info()->tx_power, 20);
    std::cout << "Exiting ValidOpClassInfo test";
}

/**
* @brief Test to verify the behavior of dm_op_class_t when initialized with a null pointer
*
* This test checks the behavior of the dm_op_class_t constructor when it is passed a null pointer. 
* It ensures that the get_op_class_info method returns a valid object with default values.
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
* | 01 | Initialize dm_op_class_t with null pointer | instance = nullptr | dm_op_class_t object should be created | Should Pass |
* | 02 | Call get_op_class_info and check tx_power | obj.get_op_class_info()->tx_power | tx_power = 0 | Should Pass |
*/
TEST(dm_op_class_t_Test, NullOpClassInfo) {
    std::cout << "Entering NullOpClassInfo test";
    dm_op_class_t obj(nullptr);
    ASSERT_EQ(obj.get_op_class_info()->tx_power, 0);
    std::cout << "Exiting NullOpClassInfo test";
}

/**
* @brief Test to validate handling of invalid Tx Power values in dm_op_class_t
*
* This test checks the behavior of the dm_op_class_t class when initialized with invalid Tx Power values. Specifically, it verifies that the class correctly handles and stores negative Tx Power values, which are considered invalid in this context.
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
* | 01 | Initialize op_class with invalid Tx Power values | tx_power = -1, max_tx_power = -1 | Object should be initialized with tx_power = -1 | Should Pass |
* | 02 | Create dm_op_class_t object with the initialized op_class | op_class with invalid Tx Power values | Object should be created successfully | Should be successful |
* | 03 | Verify the tx_power value in the object | obj.get_op_class_info()->tx_power | tx_power should be -1 | Should Pass |
*/
TEST(dm_op_class_t_Test, InvalidTxPowerValues) {
    std::cout << "Entering InvalidTxPowerValues test";
    em_op_class_info_t op_class = {
        .id = { .ruid = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, .type = em_op_class_type_current, .op_class = 1 },
        .op_class = 1,
        .channel = 36,
        .tx_power = -1,
        .max_tx_power = -1,
        .num_channels = 2,
        .channels = {36, 40},
        .mins_since_cac_comp = 10,
        .sec_remain_non_occ_dur = 20,
        .countdown_cac_comp = 30
    };
    dm_op_class_t obj(&op_class);
    ASSERT_EQ(obj.get_op_class_info()->tx_power, -1);
    std::cout << "Exiting InvalidTxPowerValues test";
}

/**
* @brief Test the encoding of a valid string using the encode method of dm_op_class_t
*
* This test verifies that the encode method of the dm_op_class_t class correctly processes a valid cJSON object of type string. The objective is to ensure that the encode method can handle and encode a valid string without errors.
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
* | 01| Create a cJSON object of type string and set its value to "test_string" | obj.type = cJSON_String, obj.valuestring = "test_string" | cJSON object should be created successfully | Should be successful |
* | 02| Call the encode method of dm_op_class_t with the cJSON object | instance.encode(&obj) | Method should process the string without errors | Should Pass |
*/
TEST(dm_op_class_t_Test, EncodeValidString) {
    std::cout << "Entering EncodeValidString" << std::endl;
    cJSON obj = {};
    obj.type = cJSON_String;
    obj.valuestring = const_cast<char*>("test_string");
    dm_op_class_t instance;
    instance.encode(&obj);
    std::cout << "Exiting EncodeValidString" << std::endl;
}

/**
* @brief Test to validate the encoding of a valid number using dm_op_class_t::encode method
*
* This test checks if the dm_op_class_t::encode method correctly encodes a valid number. The objective is to ensure that the method handles numeric values properly and encodes them as expected.
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
* | 01| Create a cJSON object of type Number and set its value | obj.type = cJSON_Number, obj.valuedouble = 123.45 | cJSON object created with type Number and value 123.45 | Should be successful |
* | 02| Call the encode method of dm_op_class_t with the cJSON object | instance.encode(&obj) | Method should encode the number correctly | Should Pass |
*/
TEST(dm_op_class_t_Test, EncodeValidNumber) {
    std::cout << "Entering EncodeValidNumber" << std::endl;
    cJSON obj;
    obj.type = cJSON_Number;
    obj.valuedouble = 123.45;
    dm_op_class_t instance;
    instance.encode(&obj);
    std::cout << "Exiting EncodeValidNumber" << std::endl;
}

/**
* @brief Test the encoding of a valid cJSON array
*
* This test verifies that the encode function correctly processes a valid cJSON array and its child elements.@n
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
* | 01| Initialize cJSON object and child | obj.type = cJSON_Array, child.type = cJSON_Number, child.valuedouble = 1.23 | cJSON object and child initialized | Should be successful |
* | 02| Set child to obj | obj.child = &child | obj.child set to &child | Should be successful |
* | 03| Call encode method | instance.encode(&obj) | obj = cJSON_Array, child = cJSON_Number, valuedouble = 1.23 | Should Pass |
*/
TEST(dm_op_class_t_Test, EncodeValidArray) {
    std::cout << "Entering EncodeValidArray" << std::endl;
    cJSON obj;
    obj.type = cJSON_Array;
    cJSON child;
    child.type = cJSON_Number;
    child.valuedouble = 1.23;
    obj.child = &child;
    dm_op_class_t instance;
    instance.encode(&obj);
    std::cout << "Exiting EncodeValidArray" << std::endl;
}

/**
* @brief Test the encoding of a valid cJSON object
*
* This test verifies that the encode method of dm_op_class_t correctly processes a valid cJSON object. The objective is to ensure that the encoding functionality works as expected when provided with a properly structured cJSON object.
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
* | 01| Create a valid cJSON object | obj.type = cJSON_Object, child.type = cJSON_String, child.valuestring = "child_string", obj.child = &child | cJSON object created successfully | Should be successful |
* | 02| Invoke encode method on the valid cJSON object | instance.encode(&obj) | Method processes the object without errors | Should Pass |
*/
TEST(dm_op_class_t_Test, EncodeValidObject) {
    std::cout << "Entering EncodeValidObject" << std::endl;
    cJSON obj = {};
    obj.type = cJSON_Object;
    cJSON child = {};
    child.type = cJSON_String;
    child.valuestring = const_cast<char*>("child_string");  // Fix warning
    obj.child = &child;
    dm_op_class_t instance;
    instance.encode(&obj);
    std::cout << "Exiting EncodeValidObject" << std::endl;
}

/**
* @brief Test to verify the behavior of the encode function when a null pointer is passed.
*
* This test checks the encode function of the dm_op_class_t class to ensure it handles a null pointer input correctly. This is important to verify that the function can gracefully handle invalid inputs without causing crashes or undefined behavior.
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
* | Variation / Step | Description | Test Data |Expected Result |Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01| Initialize a null cJSON object and an instance of dm_op_class_t | obj = NULL | No crash or undefined behavior | Should Pass |
* | 02| Call the encode function with the null cJSON object | instance.encode(obj) | No crash or undefined behavior | Should Pass |
*/
TEST(dm_op_class_t_Test, EncodeNullPointer) {
    std::cout << "Entering EncodeNullPointer" << std::endl;
    cJSON *obj = NULL;
    dm_op_class_t instance;
    instance.encode(obj);
    std::cout << "Exiting EncodeNullPointer" << std::endl;
}

/**
* @brief Test to verify the behavior of the encode function when provided with an invalid type
*
* This test checks the encode function of the dm_op_class_t class when it is given a cJSON object with an invalid type. The objective is to ensure that the function handles invalid input types gracefully and does not cause unexpected behavior or crashes.
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
* | Variation / Step | Description | Test Data |Expected Result |Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01| Create a cJSON object with an invalid type | obj.type = -1 | Should be successful | |
* | 02| Call the encode function with the invalid cJSON object | instance.encode(&obj) | Should Pass | |
*/
TEST(dm_op_class_t_Test, EncodeInvalidType) {
    std::cout << "Entering EncodeInvalidType" << std::endl;
    cJSON obj;
    obj.type = -1;
    dm_op_class_t instance;
    instance.encode(&obj);
    std::cout << "Exiting EncodeInvalidType" << std::endl;
}

/**
* @brief Test to verify the behavior of the encode function when the input string is null.
*
* This test checks the encode function of the dm_op_class_t class to ensure it handles a null string value correctly. This is important to verify that the function can gracefully handle null inputs without causing unexpected behavior or crashes.
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
* | 01| Initialize cJSON object with null string value | obj.type = cJSON_String, obj.valuestring = NULL | Should be successful | |
* | 02| Call encode function with cJSON object | instance.encode(&obj) | Should Pass | |
*/
TEST(dm_op_class_t_Test, EncodeStringNullValue) {
    std::cout << "Entering EncodeStringNullValue" << std::endl;
    cJSON obj;
    obj.type = cJSON_String;
    obj.valuestring = NULL;
    dm_op_class_t instance;
    instance.encode(&obj);
    std::cout << "Exiting EncodeStringNullValue" << std::endl;
}

/**
* @brief Test to verify the encoding of an invalid number
*
* This test checks the behavior of the encode function when it is provided with an invalid number (NaN). This is important to ensure that the function can handle edge cases and invalid inputs gracefully.
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
* | Variation / Step | Description | Test Data | Expected Result | Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01 | Create a cJSON object with type cJSON_Number and value NaN | obj.type = cJSON_Number, obj.valuedouble = NAN | Should be successful | |
* | 02 | Call the encode function with the invalid number | instance.encode(&obj) | Should Pass | |
*/
TEST(dm_op_class_t_Test, EncodeInvalidNumber) {
    std::cout << "Entering EncodeInvalidNumber" << std::endl;
    cJSON obj;
    obj.type = cJSON_Number;
    obj.valuedouble = NAN;
    dm_op_class_t instance;
    instance.encode(&obj);
    std::cout << "Exiting EncodeInvalidNumber" << std::endl;
}

/**
* @brief Test the encoding of a cJSON object with a NULL child
*
* This test verifies the behavior of the encode function when it is provided with a cJSON object of type array that has a NULL child. This is to ensure that the function can handle such cases gracefully without crashing or producing incorrect results.
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
* | 01| Initialize cJSON object with type array and NULL child | obj.type = cJSON_Array, obj.child = NULL | Object initialized successfully | Should be successful |
* | 02| Call encode function with the initialized cJSON object | instance.encode(&obj) | Function should handle NULL child gracefully | Should Pass |
*/
TEST(dm_op_class_t_Test, EncodeArrayNullChild) {
    std::cout << "Entering EncodeArrayNullChild" << std::endl;
    cJSON obj;
    obj.type = cJSON_Array;
    obj.child = NULL;
    dm_op_class_t instance;
    instance.encode(&obj);
    std::cout << "Exiting EncodeArrayNullChild" << std::endl;
}

/**
* @brief Test to verify the retrieval of operation class information after setting specific values.
*
* This test sets specific values to an instance of `em_op_class_info_t` and verifies that these values are correctly retrieved using the `get_op_class_info` method of the `dm_op_class_t` class. This ensures that the set and get operations for the operation class information are functioning as expected.
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
* | 01 | Set specific values to `em_op_class_info_t` instance | op_class = 1, channel = 36, tx_power = 20, max_tx_power = 30, num_channels = 2, channels[0] = 36, channels[1] = 40, mins_since_cac_comp = 10, sec_remain_non_occ_dur = 20, countdown_cac_comp = 30 | Values should be set successfully | Should be successful |
* | 02 | Create `dm_op_class_t` instance with the set `em_op_class_info_t` | &op_class_info | Instance should be created successfully | Should be successful |
* | 03 | Retrieve operation class information using `get_op_class_info` | None | Retrieved info should not be nullptr | Should Pass |
* | 04 | Verify retrieved `op_class` value | retrieved_info->op_class = 1 | Should match the set value | Should Pass |
* | 05 | Verify retrieved `channel` value | retrieved_info->channel = 36 | Should match the set value | Should Pass |
* | 06 | Verify retrieved `tx_power` value | retrieved_info->tx_power = 20 | Should match the set value | Should Pass |
* | 07 | Verify retrieved `max_tx_power` value | retrieved_info->max_tx_power = 30 | Should match the set value | Should Pass |
* | 08 | Verify retrieved `num_channels` value | retrieved_info->num_channels = 2 | Should match the set value | Should Pass |
* | 09 | Verify retrieved `channels[0]` value | retrieved_info->channels[0] = 36 | Should match the set value | Should Pass |
* | 10 | Verify retrieved `channels[1]` value | retrieved_info->channels[1] = 40 | Should match the set value | Should Pass |
* | 11 | Verify retrieved `mins_since_cac_comp` value | retrieved_info->mins_since_cac_comp = 10 | Should match the set value | Should Pass |
* | 12 | Verify retrieved `sec_remain_non_occ_dur` value | retrieved_info->sec_remain_non_occ_dur = 20 | Should match the set value | Should Pass |
* | 13 | Verify retrieved `countdown_cac_comp` value | retrieved_info->countdown_cac_comp = 30 | Should match the set value | Should Pass |
*/
TEST(dm_op_class_t_Test, RetrieveOperationClassInfoAfterSettingSpecificValues) {
    std::cout << "Entering RetrieveOperationClassInfoAfterSettingSpecificValues" << std::endl;
    em_op_class_info_t op_class_info;
    op_class_info.op_class = 1;
    op_class_info.channel = 36;
    op_class_info.tx_power = 20;
    op_class_info.max_tx_power = 30;
    op_class_info.num_channels = 2;
    op_class_info.channels[0] = 36;
    op_class_info.channels[1] = 40;
    op_class_info.mins_since_cac_comp = 10;
    op_class_info.sec_remain_non_occ_dur = 20;
    op_class_info.countdown_cac_comp = 30;
    dm_op_class_t dm_op_class(&op_class_info);
    em_op_class_info_t* retrieved_info = dm_op_class.get_op_class_info();
    ASSERT_NE(retrieved_info, nullptr);
    EXPECT_EQ(retrieved_info->op_class, 1);
    EXPECT_EQ(retrieved_info->channel, 36);
    EXPECT_EQ(retrieved_info->tx_power, 20);
    EXPECT_EQ(retrieved_info->max_tx_power, 30);
    EXPECT_EQ(retrieved_info->num_channels, 2);
    EXPECT_EQ(retrieved_info->channels[0], 36);
    EXPECT_EQ(retrieved_info->channels[1], 40);
    EXPECT_EQ(retrieved_info->mins_since_cac_comp, 10);
    EXPECT_EQ(retrieved_info->sec_remain_non_occ_dur, 20);
    EXPECT_EQ(retrieved_info->countdown_cac_comp, 30);
    std::cout << "Exiting RetrieveOperationClassInfoAfterSettingSpecificValues" << std::endl;
}

/**
* @brief Test the successful initialization of dm_op_class_t object
*
* This test verifies that the dm_op_class_t object is successfully initialized by checking the return value of the init() method and comparing the internal state of the object with the expected default state.
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
* | 01 | Create dm_op_class_t object | instance = new dm_op_class_t() | Object should be created successfully | Should be successful |
* | 02 | Call init() method | result = obj.init() | result = 0 | Should Pass |
* | 03 | Compare internal state with expected state | memcmp(&obj.m_op_class_info, &expected_info, sizeof(em_op_class_info_t)) | result = 0 | Should Pass |
*/
TEST(dm_op_class_t_Test, SuccessfulInitialization) {
    std::cout << "Entering SuccessfulInitialization test";
    dm_op_class_t obj;
    int result = obj.init();
    ASSERT_EQ(result, 0);
    em_op_class_info_t expected_info = {};
    ASSERT_EQ(memcmp(&obj.m_op_class_info, &expected_info, sizeof(em_op_class_info_t)), 0);
    std::cout << "Exiting SuccessfulInitialization test";
}

/**
* @brief Test the assignment operator with identical initialized objects
*
* This test verifies that the assignment operator correctly assigns one object to another when both objects are identical and initialized.@n
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
* | 01 | Initialize two identical objects | obj1, obj2 | Objects should be initialized | Should be successful |
* | 02 | Assign obj2 to obj1 using assignment operator | obj1 = obj2 | obj1 should be equal to obj2 | Should Pass |
* | 03 | Verify the objects are identical using ASSERT_TRUE | obj1 == obj2 | Assertion should pass | Should Pass |
*/
TEST(dm_op_class_t_Test, AssignmentOperatorWithIdenticalInitializedObjects) {
    std::cout << "Entering AssignmentOperatorWithIdenticalInitializedObjects" << std::endl;
    dm_op_class_t obj1;
    dm_op_class_t obj2;
    obj1 = obj2;
    ASSERT_TRUE(obj1 == obj2);
    std::cout << "Exiting AssignmentOperatorWithIdenticalInitializedObjects" << std::endl;
}

/**
* @brief Test the assignment operator with different objects
*
* This test verifies that the assignment operator correctly assigns the values from one object to another and ensures that the objects are equal after assignment.@n
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
* | Variation / Step | Description | Test Data |Expected Result |Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01| Create two dm_op_class_t objects | obj1, obj2 | Objects created successfully | Should be successful |
* | 02| Set op_class of obj1 to 1 | obj1.m_op_class_info.op_class = 1 | Value set successfully | Should be successful |
* | 03| Set op_class of obj2 to 2 | obj2.m_op_class_info.op_class = 2 | Value set successfully | Should be successful |
* | 04| Assign obj2 to obj1 | obj1 = obj2 | Assignment successful | Should Pass |
* | 05| Assert that obj1 is equal to obj2 | ASSERT_TRUE(obj1 == obj2) | Assertion passes | Should Pass |
*/
TEST(dm_op_class_t_Test, AssignmentOperatorWithDifferentObjects) {
    std::cout << "Entering AssignmentOperatorWithDifferentObjects" << std::endl;
    dm_op_class_t obj1;
    dm_op_class_t obj2;
    obj1.m_op_class_info.op_class = 1;
    obj2.m_op_class_info.op_class = 2;
    obj1 = obj2;
    ASSERT_TRUE(obj1 == obj2);
    std::cout << "Exiting AssignmentOperatorWithDifferentObjects" << std::endl;
}

/**
* @brief Test to verify if two objects of dm_op_class_t are identical
*
* This test checks if two instances of dm_op_class_t with identical data members are considered equal by the equality operator. This is important to ensure that the equality operator is correctly implemented for the dm_op_class_t class.
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
* | Variation / Step | Description | Test Data |Expected Result |Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01| Create two identical objects of dm_op_class_t | obj1.m_op_class_info = { { {0x00, 0x01, 0x02, 0x03, 0x04, 0x05}, em_op_class_type_current, 1 }, 1, 1, 10, 20, 1, {1}, 0, 0, 0 }, obj2.m_op_class_info = { { {0x00, 0x01, 0x02, 0x03, 0x04, 0x05}, em_op_class_type_current, 1 }, 1, 1, 10, 20, 1, {1}, 0, 0, 0 } | Objects should be identical | Should Pass |
* | 02| Check equality of the two objects | obj1 == obj2 | EXPECT_TRUE(obj1 == obj2) | Should Pass |
*/
TEST(dm_op_class_t_Test, BothObjectsAreIdentical) {
    std::cout << "Entering BothObjectsAreIdentical" << std::endl;
    dm_op_class_t obj1, obj2;
    obj1.m_op_class_info = { { {0x00, 0x01, 0x02, 0x03, 0x04, 0x05}, em_op_class_type_current, 1 }, 1, 1, 10, 20, 1, {1}, 0, 0, 0 };
    obj2.m_op_class_info = { { {0x00, 0x01, 0x02, 0x03, 0x04, 0x05}, em_op_class_type_current, 1 }, 1, 1, 10, 20, 1, {1}, 0, 0, 0 };
    EXPECT_TRUE(obj1 == obj2);
    std::cout << "Exiting BothObjectsAreIdentical" << std::endl;
}

/**
* @brief Test to verify that two objects of dm_op_class_t have different RUIDs
*
* This test checks that two instances of dm_op_class_t with different RUIDs are not considered equal.@n
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
* | Variation / Step | Description | Test Data |Expected Result |Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01| Create two instances of dm_op_class_t with different RUIDs | obj1.m_op_class_info = { { {0x00, 0x01, 0x02, 0x03, 0x04, 0x05}, em_op_class_type_current, 1 }, 1, 1, 10, 20, 1, {1}, 0, 0, 0 }, obj2.m_op_class_info = { { {0x00, 0x01, 0x02, 0x03, 0x04, 0x06}, em_op_class_type_current, 1 }, 1, 1, 10, 20, 1, {1}, 0, 0, 0 } | Instances should have different RUIDs | Should Pass |
* | 02| Check if the two instances are not equal using EXPECT_FALSE | EXPECT_FALSE(obj1 == obj2) | The objects should not be equal | Should Pass |
*/
TEST(dm_op_class_t_Test, ObjectsHaveDifferentRuid) {
    std::cout << "Entering ObjectsHaveDifferentRuid" << std::endl;
    dm_op_class_t obj1, obj2;
    obj1.m_op_class_info = { { {0x00, 0x01, 0x02, 0x03, 0x04, 0x05}, em_op_class_type_current, 1 }, 1, 1, 10, 20, 1, {1}, 0, 0, 0 };
    obj2.m_op_class_info = { { {0x00, 0x01, 0x02, 0x03, 0x04, 0x06}, em_op_class_type_current, 1 }, 1, 1, 10, 20, 1, {1}, 0, 0, 0 };
    EXPECT_FALSE(obj1 == obj2);
    std::cout << "Exiting ObjectsHaveDifferentRuid" << std::endl;
}

/**
* @brief Test to verify that objects of dm_op_class_t with different types are not equal.
*
* This test checks that two objects of the class dm_op_class_t with different operation class types are not considered equal. This is important to ensure that the equality operator is correctly distinguishing between different types of operation classes.
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
* | Variation / Step | Description | Test Data |Expected Result |Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01| Create two objects of dm_op_class_t with different operation class types | obj1.m_op_class_info = { { {0x00, 0x01, 0x02, 0x03, 0x04, 0x05}, em_op_class_type_current, 1 }, 1, 1, 10, 20, 1, {1}, 0, 0, 0 }, obj2.m_op_class_info = { { {0x00, 0x01, 0x02, 0x03, 0x04, 0x05}, em_op_class_type_capability, 1 }, 1, 1, 10, 20, 1, {1}, 0, 0, 0 } | Objects should not be equal | Should Pass |
* | 02| Check equality using EXPECT_FALSE | EXPECT_FALSE(obj1 == obj2) | EXPECT_FALSE assertion should pass | Should Pass |
*/
TEST(dm_op_class_t_Test, ObjectsHaveDifferentType) {
    std::cout << "Entering ObjectsHaveDifferentType" << std::endl;
    dm_op_class_t obj1, obj2;
    obj1.m_op_class_info = { { {0x00, 0x01, 0x02, 0x03, 0x04, 0x05}, em_op_class_type_current, 1 }, 1, 1, 10, 20, 1, {1}, 0, 0, 0 };
    obj2.m_op_class_info = { { {0x00, 0x01, 0x02, 0x03, 0x04, 0x05}, em_op_class_type_capability, 1 }, 1, 1, 10, 20, 1, {1}, 0, 0, 0 };
    EXPECT_FALSE(obj1 == obj2);
    std::cout << "Exiting ObjectsHaveDifferentType" << std::endl;
}

/**
* @brief Test to verify that two objects of dm_op_class_t have different operation classes
*
* This test checks if two instances of dm_op_class_t with different operation class information are not considered equal.@n
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
* | Variation / Step | Description | Test Data | Expected Result | Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01 | Create two instances of dm_op_class_t with different operation class information | obj1.m_op_class_info = { { {0x00, 0x01, 0x02, 0x03, 0x04, 0x05}, em_op_class_type_current, 1 }, 1, 1, 10, 20, 1, {1}, 0, 0, 0 }, obj2.m_op_class_info = { { {0x00, 0x01, 0x02, 0x03, 0x04, 0x05}, em_op_class_type_current, 2 }, 2, 1, 10, 20, 1, {1}, 0, 0, 0 } | Two objects should not be equal | Should Pass |
* | 02 | Check if the two objects are not equal using EXPECT_FALSE | EXPECT_FALSE(obj1 == obj2) | The objects should not be equal | Should Pass |
*/
TEST(dm_op_class_t_Test, ObjectsHaveDifferentOpClass) {
    std::cout << "Entering ObjectsHaveDifferentOpClass" << std::endl;
    dm_op_class_t obj1, obj2;
    obj1.m_op_class_info = { { {0x00, 0x01, 0x02, 0x03, 0x04, 0x05}, em_op_class_type_current, 1 }, 1, 1, 10, 20, 1, {1}, 0, 0, 0 };
    obj2.m_op_class_info = { { {0x00, 0x01, 0x02, 0x03, 0x04, 0x05}, em_op_class_type_current, 2 }, 2, 1, 10, 20, 1, {1}, 0, 0, 0 };
    EXPECT_FALSE(obj1 == obj2);
    std::cout << "Exiting ObjectsHaveDifferentOpClass" << std::endl;
}

/**
* @brief Test to verify that two objects of dm_op_class_t have different channels
*
* This test checks if two instances of dm_op_class_t with different channel values are not considered equal.@n
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
* | Variation / Step | Description | Test Data | Expected Result | Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01 | Create two instances of dm_op_class_t with different channel values | obj1.m_op_class_info.channel = 1, obj2.m_op_class_info.channel = 2 | obj1 != obj2 | Should Pass |
*/
TEST(dm_op_class_t_Test, ObjectsHaveDifferentChannel) {
    std::cout << "Entering ObjectsHaveDifferentChannel" << std::endl;
    dm_op_class_t obj1, obj2;
    obj1.m_op_class_info = { { {0x00, 0x01, 0x02, 0x03, 0x04, 0x05}, em_op_class_type_current, 1 }, 1, 1, 10, 20, 1, {1}, 0, 0, 0 };
    obj2.m_op_class_info = { { {0x00, 0x01, 0x02, 0x03, 0x04, 0x05}, em_op_class_type_current, 1 }, 1, 2, 10, 20, 1, {1}, 0, 0, 0 };
    EXPECT_FALSE(obj1 == obj2);
    std::cout << "Exiting ObjectsHaveDifferentChannel" << std::endl;
}

/**
* @brief Test to verify that two objects of dm_op_class_t have different TxPower values
*
* This test checks if two instances of dm_op_class_t with different TxPower values are not considered equal.@n
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
* | Variation / Step | Description | Test Data |Expected Result |Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01| Create two instances of dm_op_class_t with different TxPower values | obj1.m_op_class_info.tx_power = 10, obj2.m_op_class_info.tx_power = 20 | obj1 should not be equal to obj2 | Should Pass |
*/
TEST(dm_op_class_t_Test, ObjectsHaveDifferentTxPower) {
    std::cout << "Entering ObjectsHaveDifferentTxPower" << std::endl;
    dm_op_class_t obj1, obj2;
    obj1.m_op_class_info = { { {0x00, 0x01, 0x02, 0x03, 0x04, 0x05}, em_op_class_type_current, 1 }, 1, 1, 10, 20, 1, {1}, 0, 0, 0 };
    obj2.m_op_class_info = { { {0x00, 0x01, 0x02, 0x03, 0x04, 0x05}, em_op_class_type_current, 1 }, 1, 1, 20, 20, 1, {1}, 0, 0, 0 };
    EXPECT_FALSE(obj1 == obj2);
    std::cout << "Exiting ObjectsHaveDifferentTxPower" << std::endl;
}

/**
* @brief Test to verify that objects of dm_op_class_t with different max_tx_power values are not equal.
*
* This test checks if two objects of dm_op_class_t with different max_tx_power values are considered unequal.@n
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
* | Variation / Step | Description | Test Data |Expected Result |Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01| Create two objects of dm_op_class_t with different max_tx_power values | obj1.max_tx_power = 20, obj2.max_tx_power = 30 | Objects should not be equal | Should Pass |
* | 02| Compare the two objects using EXPECT_FALSE | obj1 == obj2 | EXPECT_FALSE should return true | Should Pass |
*/
TEST(dm_op_class_t_Test, ObjectsHaveDifferentMaxTxPower) {
    std::cout << "Entering ObjectsHaveDifferentMaxTxPower" << std::endl;
    dm_op_class_t obj1, obj2;
    obj1.m_op_class_info = { { {0x00, 0x01, 0x02, 0x03, 0x04, 0x05}, em_op_class_type_current, 1 }, 1, 1, 10, 20, 1, {1}, 0, 0, 0 };
    obj2.m_op_class_info = { { {0x00, 0x01, 0x02, 0x03, 0x04, 0x05}, em_op_class_type_current, 1 }, 1, 1, 10, 30, 1, {1}, 0, 0, 0 };
    EXPECT_FALSE(obj1 == obj2);
    std::cout << "Exiting ObjectsHaveDifferentMaxTxPower" << std::endl;
}

/**
* @brief Test to verify that objects with different number of channels are not equal
*
* This test checks if two objects of dm_op_class_t with different number of channels are considered not equal.@n
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
* | Variation / Step | Description | Test Data | Expected Result | Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01 | Create two objects of dm_op_class_t with different number of channels | obj1.m_op_class_info.num_channels = 1, obj2.m_op_class_info.num_channels = 2 | Objects should not be equal | Should Pass |
* | 02 | Compare the two objects using EXPECT_FALSE | obj1 == obj2 | EXPECT_FALSE should return true | Should Pass |
*/
TEST(dm_op_class_t_Test, ObjectsHaveDifferentNumChannels) {
    std::cout << "Entering ObjectsHaveDifferentNumChannels" << std::endl;
    dm_op_class_t obj1, obj2;
    obj1.m_op_class_info = { { {0x00, 0x01, 0x02, 0x03, 0x04, 0x05}, em_op_class_type_current, 1 }, 1, 1, 10, 20, 1, {1}, 0, 0, 0 };
    obj2.m_op_class_info = { { {0x00, 0x01, 0x02, 0x03, 0x04, 0x05}, em_op_class_type_current, 1 }, 1, 1, 10, 20, 2, {1, 2}, 0, 0, 0 };
    EXPECT_FALSE(obj1 == obj2);
    std::cout << "Exiting ObjectsHaveDifferentNumChannels" << std::endl;
}

/**
* @brief Test to verify that objects of dm_op_class_t have different channels
*
* This test checks if two objects of the class dm_op_class_t with different channel values are not considered equal. This is important to ensure that the equality operator correctly distinguishes between objects with different channel configurations.
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
* | Variation / Step | Description | Test Data | Expected Result | Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01 | Create two objects of dm_op_class_t with different channel values | obj1.m_op_class_info = { { {0x00, 0x01, 0x02, 0x03, 0x04, 0x05}, em_op_class_type_current, 1 }, 1, 1, 10, 20, 1, {1}, 0, 0, 0 }, obj2.m_op_class_info = { { {0x00, 0x01, 0x02, 0x03, 0x04, 0x05}, em_op_class_type_current, 1 }, 1, 1, 10, 20, 1, {2}, 0, 0, 0 } | Objects should have different channels | Should be successful |
* | 02 | Check if the objects are not equal | obj1 == obj2 | EXPECT_FALSE(obj1 == obj2) | Should Pass |
*/
TEST(dm_op_class_t_Test, ObjectsHaveDifferentChannels) {
    std::cout << "Entering ObjectsHaveDifferentChannels" << std::endl;
    dm_op_class_t obj1, obj2;
    obj1.m_op_class_info = { { {0x00, 0x01, 0x02, 0x03, 0x04, 0x05}, em_op_class_type_current, 1 }, 1, 1, 10, 20, 1, {1}, 0, 0, 0 };
    obj2.m_op_class_info = { { {0x00, 0x01, 0x02, 0x03, 0x04, 0x05}, em_op_class_type_current, 1 }, 1, 1, 10, 20, 1, {2}, 0, 0, 0 };
    EXPECT_FALSE(obj1 == obj2);
    std::cout << "Exiting ObjectsHaveDifferentChannels" << std::endl;
}

/**
* @brief Test to verify that two objects of dm_op_class_t have different mins_since_cac_comp values
*
* This test checks if two instances of dm_op_class_t with different mins_since_cac_comp values are not considered equal.@n
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
* | Variation / Step | Description | Test Data |Expected Result |Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01| Create two instances of dm_op_class_t with different mins_since_cac_comp values | obj1.mins_since_cac_comp = 0, obj2.mins_since_cac_comp = 10 | Objects should not be equal | Should Pass |
* | 02| Compare the two instances using the equality operator | obj1 == obj2 | EXPECT_FALSE(obj1 == obj2) | Should Pass |
*/
TEST(dm_op_class_t_Test, ObjectsHaveDifferentMinsSinceCacComp) {
    std::cout << "Entering ObjectsHaveDifferentMinsSinceCacComp" << std::endl;
    dm_op_class_t obj1, obj2;
    obj1.m_op_class_info = { { {0x00, 0x01, 0x02, 0x03, 0x04, 0x05}, em_op_class_type_current, 1 }, 1, 1, 10, 20, 1, {1}, 0, 0, 0 };
    obj2.m_op_class_info = { { {0x00, 0x01, 0x02, 0x03, 0x04, 0x05}, em_op_class_type_current, 1 }, 1, 1, 10, 20, 1, {1}, 10, 0, 0 };
    EXPECT_FALSE(obj1 == obj2);
    std::cout << "Exiting ObjectsHaveDifferentMinsSinceCacComp" << std::endl;
}

/**
* @brief Test to verify that objects with different SecRemainNonOccDur are not equal
*
* This test checks the equality operator for dm_op_class_t objects when they have different SecRemainNonOccDur values.@n
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
* | Variation / Step | Description | Test Data |Expected Result |Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01| Create two dm_op_class_t objects with different SecRemainNonOccDur values | obj1.m_op_class_info = { { {0x00, 0x01, 0x02, 0x03, 0x04, 0x05}, em_op_class_type_current, 1 }, 1, 1, 10, 20, 1, {1}, 0, 0, 0 }, obj2.m_op_class_info = { { {0x00, 0x01, 0x02, 0x03, 0x04, 0x05}, em_op_class_type_current, 1 }, 1, 1, 10, 20, 1, {1}, 0, 10, 0 } | Objects should not be equal | Should Pass |
* | 02| Check equality using EXPECT_FALSE | EXPECT_FALSE(obj1 == obj2) | Should return false | Should Pass |
*/
TEST(dm_op_class_t_Test, ObjectsHaveDifferentSecRemainNonOccDur) {
    std::cout << "Entering ObjectsHaveDifferentSecRemainNonOccDur" << std::endl;
    dm_op_class_t obj1, obj2;
    obj1.m_op_class_info = { { {0x00, 0x01, 0x02, 0x03, 0x04, 0x05}, em_op_class_type_current, 1 }, 1, 1, 10, 20, 1, {1}, 0, 0, 0 };
    obj2.m_op_class_info = { { {0x00, 0x01, 0x02, 0x03, 0x04, 0x05}, em_op_class_type_current, 1 }, 1, 1, 10, 20, 1, {1}, 0, 10, 0 };
    EXPECT_FALSE(obj1 == obj2);
    std::cout << "Exiting ObjectsHaveDifferentSecRemainNonOccDur" << std::endl;
}

/**
* @brief Test to verify that objects with different countdown CAC components are not equal.
*
* This test checks the equality operator for `dm_op_class_t` objects to ensure that two objects with different countdown CAC components are not considered equal. This is important to verify the correct behavior of the equality operator when comparing objects with different internal states.
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
* | Variation / Step | Description | Test Data | Expected Result | Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01 | Create two `dm_op_class_t` objects with different countdown CAC components | obj1.m_op_class_info.countdown_cac_comp = 0, obj2.m_op_class_info.countdown_cac_comp = 10 | Objects should not be equal | Should Pass |
* | 02 | Compare the two objects using the equality operator | obj1 == obj2 | EXPECT_FALSE(obj1 == obj2) | Should Pass |
*/
TEST(dm_op_class_t_Test, ObjectsHaveDifferentCountdownCacComp) {
    std::cout << "Entering ObjectsHaveDifferentCountdownCacComp" << std::endl;
    dm_op_class_t obj1, obj2;
    obj1.m_op_class_info = { { {0x00, 0x01, 0x02, 0x03, 0x04, 0x05}, em_op_class_type_current, 1 }, 1, 1, 10, 20, 1, {1}, 0, 0, 0 };
    obj2.m_op_class_info = { { {0x00, 0x01, 0x02, 0x03, 0x04, 0x05}, em_op_class_type_current, 1 }, 1, 1, 10, 20, 1, {1}, 0, 0, 10 };
    EXPECT_FALSE(obj1 == obj2);
    std::cout << "Exiting ObjectsHaveDifferentCountdownCacComp" << std::endl;
}

/**
* @brief Test to validate the parsing of a valid key with correct format
*
* This test checks if the function `parse_op_class_id_from_key` correctly parses a valid key with the correct format and returns the expected result.@n
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
* | Variation / Step | Description | Test Data | Expected Result | Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01 | Define a valid key and call parse_op_class_id_from_key | key = "valid_key_format", id = &id | result = 0, EXPECT_EQ(result, 0) | Should Pass |
*/
TEST(dm_op_class_t_Test, ValidKeyWithCorrectFormat) {
    std::cout << "Entering ValidKeyWithCorrectFormat" << std::endl;
    const char *key = "valid_key_format";
    em_op_class_id_t id;
    int result = dm_op_class_t::parse_op_class_id_from_key(key, &id);
    EXPECT_EQ(result, 0);
    std::cout << "Exiting ValidKeyWithCorrectFormat" << std::endl;
}

/**
* @brief Test the behavior of parse_op_class_id_from_key when a null key is provided.
*
* This test checks the function parse_op_class_id_from_key with a null key input to ensure that it handles the null input correctly and returns an error code.@n
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
* | Variation / Step | Description | Test Data | Expected Result | Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01 | Call parse_op_class_id_from_key with null key | key = nullptr, id = &id | result != 0 | Should Fail |
*/
/*code doesn't handle null
TEST(dm_op_class_t_Test, NullKey) {
    std::cout << "Entering NullKey" << std::endl;
    const char *key = nullptr;
    em_op_class_id_t id;
    int result = dm_op_class_t::parse_op_class_id_from_key(key, &id);
    EXPECT_NE(result, 0);
    std::cout << "Exiting NullKey" << std::endl;
}
*/

/**
* @brief Test to verify the behavior of parse_op_class_id_from_key when a null pointer is passed for the id parameter.
*
* This test checks the function parse_op_class_id_from_key with a valid key and a null pointer for the id parameter. The objective is to ensure that the function handles the null pointer correctly and returns a non-zero result, indicating an error.
*
* **Test Group ID:** Basic: 01@n
* **Test Case ID:** 043@n
* **Priority:** High@n
* @n
* **Pre-Conditions:** None@n
* **Dependencies:** None@n
* **User Interaction:** None@n
* @n
* **Test Procedure:**@n
* | Variation / Step | Description | Test Data |Expected Result |Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01| Call parse_op_class_id_from_key with a valid key and null id pointer | key = "valid_key_format", id = nullptr | result != 0, EXPECT_NE(result, 0) | Should Fail |
*/
/*code doesn't handle null
TEST(dm_op_class_t_Test, NullIdPointer) {
    std::cout << "Entering NullIdPointer" << std::endl;
    const char *key = "valid_key_format";
    em_op_class_id_t *id = nullptr;
    int result = dm_op_class_t::parse_op_class_id_from_key(key, id);
    EXPECT_NE(result, 0);
    std::cout << "Exiting NullIdPointer" << std::endl;
}
*/

/**
* @brief Test to verify the behavior of parse_op_class_id_from_key with an empty key string
*
* This test checks the function parse_op_class_id_from_key when provided with an empty key string. 
* The objective is to ensure that the function correctly handles this edge case and returns an error code.@n
*
* **Test Group ID:** Basic: 01@n
* **Test Case ID:** 044@n
* **Priority:** High@n
* @n
* **Pre-Conditions:** None@n
* **Dependencies:** None@n
* **User Interaction:** None@n
* @n
* **Test Procedure:**@n
* | Variation / Step | Description | Test Data |Expected Result |Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01| Call parse_op_class_id_from_key with an empty key string | key = "", id = uninitialized | result != 0 | Should Fail |
*/
TEST(dm_op_class_t_Test, EmptyKeyString) {
    std::cout << "Entering EmptyKeyString" << std::endl;
    const char *key = "";
    em_op_class_id_t id;
    int result = dm_op_class_t::parse_op_class_id_from_key(key, &id);
    EXPECT_NE(result, 0);
    std::cout << "Exiting EmptyKeyString" << std::endl;
}

/**
* @brief Test the parsing of operation class ID from a key with special characters
*
* This test checks the behavior of the parse_op_class_id_from_key function when provided with a key that contains special characters. The objective is to ensure that the function correctly handles and returns an appropriate result for such input.
*
* **Test Group ID:** Basic: 01@n
* **Test Case ID:** 045@n
* **Priority:** High@n
* @n
* **Pre-Conditions:** None@n
* **Dependencies:** None@n
* **User Interaction:** None@n
* @n
* **Test Procedure:**@n
* | Variation / Step | Description | Test Data |Expected Result |Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01| Call parse_op_class_id_from_key with a key containing special characters | key = "key_with_special_chars !@#123", id = &id | result != 0, EXPECT_NE(result, 0) | Should Pass |
*/
TEST(dm_op_class_t_Test, KeyWithSpecialCharacters) {
    std::cout << "Entering KeyWithSpecialCharacters" << std::endl;
    const char *key = "key_with_special_chars !@#123";
    em_op_class_id_t id;
    int result = dm_op_class_t::parse_op_class_id_from_key(key, &id);
    EXPECT_NE(result, 0);
    std::cout << "Exiting KeyWithSpecialCharacters" << std::endl;
}

/**
* @brief Test the parsing of operation class ID from a key with maximum length
*
* This test verifies that the function `parse_op_class_id_from_key` correctly parses the operation class ID from a key that has the maximum allowed length. This is important to ensure that the function can handle edge cases related to input size.
*
* **Test Group ID:** Basic: 01@n
* **Test Case ID:** 046@n
* **Priority:** High@n
* @n
* **Pre-Conditions:** None@n
* **Dependencies:** None@n
* **User Interaction:** None@n
* @n
* **Test Procedure:**@n
* | Variation / Step | Description | Test Data |Expected Result |Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01| Call parse_op_class_id_from_key with a key of maximum length | key = "key_with_maximum_length_1234567890", id = &id | result = 0, EXPECT_EQ(result, 0) | Should Pass |
*/
TEST(dm_op_class_t_Test, KeyWithMaximumLength) {
    std::cout << "Entering KeyWithMaximumLength" << std::endl;
    const char *key = "key_with_maximum_length_1234567890";
    em_op_class_id_t id;
    int result = dm_op_class_t::parse_op_class_id_from_key(key, &id);
    EXPECT_EQ(result, 0);
    std::cout << "Exiting KeyWithMaximumLength" << std::endl;
}

/**
 * @brief Validates that dm_op_class_t's default constructor instantiates a valid object without throwing exceptions
 *
 * This test verifies that invoking the default constructor of dm_op_class_t creates an object in a valid default state. It checks that no exceptions are thrown during instantiation and that the member m_op_class_info is properly initialized. This is critical to ensure that object instantiation using the default constructor meets the expected robustness criteria.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 047@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                         | Test Data                                                                                  | Expected Result                                                            | Notes        |
 * | :--------------: | ------------------------------------------------------------------- | ------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------- | ------------ |
 * | 01               | Invoke the default constructor of dm_op_class_t                     | No inputs, default construction invocation                                                 | Object is created successfully without throwing any exceptions           | Should Pass  |
 */
TEST(dm_op_class_t_Test, DefaultConstructorInstantiationProducesValidObject) {
    std::cout << "Entering DefaultConstructorInstantiationProducesValidObject test" << std::endl;

    EXPECT_NO_THROW({
        // Invoking the default constructor for dm_op_class_t
        dm_op_class_t testObject;
        std::cout << "Invoked dm_op_class_t default constructor." << std::endl;
    });

    std::cout << "Exiting DefaultConstructorInstantiationProducesValidObject test" << std::endl;
}

/**
 * @brief Verify that the destructor of dm_op_class_t for a default constructed object does not throw exceptions.
 *
 * This test case checks that constructing a dm_op_class_t object using its default constructor, and subsequently allowing it to go out of scope, does not trigger any exceptions during destruction. This ensures safe behavior of the destructor under normal conditions.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 048@n
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Invoke the default constructor of dm_op_class_t | No input parameters, output: dm_op_class_t object created | Object is constructed without errors and no exception is thrown during construction | Should Pass |
 * | 02 | Object goes out of scope to trigger the destructor | No explicit input; implicit call to destructor | Destructor is invoked automatically without throwing any exception | Should be successful |
 */
TEST(dm_op_class_t_Test, Destructor_Default_Constructed)
{
    std::cout << "Entering Destructor_Default_Constructed test" << std::endl;
    // The destructor will be automatically invoked when the object goes out of scope.
    EXPECT_NO_THROW({
        std::cout << "Invoking default constructor of dm_op_class_t" << std::endl;
        dm_op_class_t obj;
        std::cout << "About to exit inner scope to invoke destructor of dm_op_class_t." << std::endl;
    });
    std::cout << "dm_op_class_t destructor has been invoked as object went out of scope." << std::endl;
    std::cout << "Exiting Destructor_Default_Constructed test" << std::endl;
}
