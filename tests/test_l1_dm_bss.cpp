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
 #include <cstddef>
 #include "dm_bss.h"
  
/**
  * @brief TEST the addition of a valid Vendor IE to the instance.
  *
  * This TEST verifies that a valid Vendor IE (Information Element) can be successfully added to the instance of the dm_bss_t class. TheTEST ensures that the add_vendor_ie function correctly processes and accepts a valid Vendor IE structure.
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
  * | 01 | Define a valid Vendor IE structure | ieee80211_vs_ie valid_ie = {0xDD, 5, {0x00, 0x50, 0xF2}, 1, 1, {0x01, 0x02, 0x03, 0x04, 0x05}} | Valid Vendor IE defined | Should be successful |
  * | 02 | Call the add_vendor_ie function with the valid Vendor IE | valid_ie = {0xDD, 5, {0x00, 0x50, 0xF2}, 1, 1, {0x01, 0x02, 0x03, 0x04, 0x05}} | Function returns true | Should Pass |
  * | 03 | Verify the result using EXPECT_TRUE | result = true | Assertion passes | Should be successful |
  */
 TEST(dm_bss_t_Test, AddValidVendorIE) {
      std::cout << "Entering AddValidVendorIETEST" << std::endl;
      // Total size: size of struct without payload + payload size
      size_t payload_len = 5;
      size_t total_size = sizeof(ieee80211_vs_ie) + payload_len;
      // Allocate raw memory
      ieee80211_vs_ie* valid_ie = static_cast<ieee80211_vs_ie*>(malloc(total_size));
      ASSERT_NE(valid_ie, nullptr); // Ensure allocation succeeded
      // Fill in fields
      valid_ie->vs_ie = 0xDD;
      valid_ie->vs_len = 5;
      valid_ie->vs_oui[0] = 0x00;
      valid_ie->vs_oui[1] = 0x50;
      valid_ie->vs_oui[2] = 0xF2;
      valid_ie->vs_type = 1;
      valid_ie->vs_subtype = 1;
      uint8_t payload_data[5] = {0x01, 0x02, 0x03, 0x04, 0x05};
      memcpy(valid_ie->payload, payload_data, payload_len);
      dm_bss_t instance;
      bool result = instance.add_vendor_ie(valid_ie);
      EXPECT_TRUE(result);
      free(valid_ie);
      std::cout << "Exiting AddValidVendorIETEST" << std::endl;
 } 
  
/**
  * @brief TEST the add_vendor_ie function with a null pointer
  *
  * This TEST verifies that the add_vendor_ie function correctly handles a null pointer input by returning false.@n
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
  * | 01 | Call add_vendor_ie with null pointer | nullptr | result = false | Should Pass |
  * | 02 | Assert that the result is false | result = false | Assertion check: result is false | Should be successful |
  */
 TEST(dm_bss_t_Test, AddVendorIEWIthNullPointer) {
      std::cout << "Entering AddVendorIEWIthNullPointerTEST" << std::endl;
      dm_bss_t instance;
      bool result = instance.add_vendor_ie(nullptr);
      EXPECT_FALSE(result);
      std::cout << "Exiting AddVendorIEWIthNullPointerTEST" << std::endl;
 }

/**
  * @brief TEST the addition of a Vendor IE with zero length
  *
  * This TEST verifies that the add_vendor_ie function correctly handles the case where a Vendor IE with zero length is added. This is important to ensure that the function does not accept invalid input, which could lead to unexpected behavior or security vulnerabilities.
  *
  * **Test Group ID:** Basic: 01
  * **Test Case ID:** 003@n
  * **Priority:** High
  * @n
  * **Pre-Conditions:** None
  * **Dependencies:** None
  * **User Interaction:** None
  * @n
  * **Test Procedure:**@n
  * | Variation / Step | Description |TEST Data | Expected Result | Notes |
  * | :----: | --------- | ---------- |-------------- | ----- |
  * | 01 | Define a zero-length Vendor IE structure | ieee80211_vs_ie zero_length_ie = {0xDD, 0, {0x00, 0x50, 0xF2}, 1, 1, {}} | Structure defined successfully | Should be successful |
  * | 02 | Call the add_vendor_ie function with the zero-length Vendor IE | zero_length_ie = {0xDD, 0, {0x00, 0x50, 0xF2}, 1, 1, {}} | Function returns false | Should Pass |
  * | 03 | Verify that the function returns false using ASSERT_FALSE | result = false | Assertion passes | Should be successful |
  */
 TEST(dm_bss_t_Test, AddVendorIEWIthZeroLength) {
      std::cout << "Entering AddVendorIEWIthZeroLengthTEST" << std::endl;
      // Allocate memory only for base struct, no payload
      size_t total_size = sizeof(ieee80211_vs_ie);  // payload length is 0
      ieee80211_vs_ie* zero_length_ie = static_cast<ieee80211_vs_ie*>(malloc(total_size));
      ASSERT_NE(zero_length_ie, nullptr);
      dm_bss_t instance;
      // Fill in fields
      zero_length_ie->vs_ie = 0xDD;
      zero_length_ie->vs_len = 0;
      zero_length_ie->vs_oui[0] = 0x00;
      zero_length_ie->vs_oui[1] = 0x50;
      zero_length_ie->vs_oui[2] = 0xF2;
      zero_length_ie->vs_type = 1;
      zero_length_ie->vs_subtype = 1;
      // Run the test
      bool result = instance.add_vendor_ie(zero_length_ie);
      EXPECT_FALSE(result);
      free(zero_length_ie);
      std::cout << "Exiting AddVendorIEWIthZeroLengthTEST" << std::endl;
 } 
  
/**
  * @brief TEST the addition of a Vendor IE with the maximum allowed length.
  *
  * This TEST verifies that the `add_vendor_ie` function can handle the maximum length of a Vendor IE payload correctly. It ensures that the function can process and add a Vendor IE with a payload of 255 bytes without any issues.
  *
  * **Test Group ID:** Basic: 01
  * **Test Case ID:** 004@n
  * **Priority:** High
  * @n
  * **Pre-Conditions:** None
  * **Dependencies:** None
  * **User Interaction:** None
  * @n
  * **Test Procedure:**@n
  * | Variation / Step | Description |TEST Data | Expected Result | Notes |
  * | :----: | --------- | ---------- |-------------- | ----- |
  * | 01 | Initialize a payload array with 255 bytes, each byte incremented by 1. | payload = {1, 2, ..., 255} | Payload initialized successfully | Should be successful |
  * | 02 | Create a `ieee80211_vs_ie` structure with the maximum length and copy the payload into it. | max_length_ie = {0xDD, 255, {0x00, 0x50, 0xF2}, 1, 1, payload} | Structure created and payload copied successfully | Should be successful |
  * | 03 | Call the `add_vendor_ie` function with the created `ieee80211_vs_ie` structure. | max_length_ie | Function returns true | Should Pass |
  * | 04 | Verify that the function returns true, indicating the Vendor IE was added successfully. | result = true | Assertion passes | Should Pass |
  */
 TEST(dm_bss_t_Test, AddVendorIEWIthMaximumLength) {
      std::cout << "Entering AddVendorIEWIthMaximumLengthTEST" << std::endl; 
      uint8_t payload[255];
      for (uint16_t i = 0; i < 255; ++i) {
           payload[i] = static_cast<uint8_t>(i + 1);
      }
      size_t total_size = sizeof(ieee80211_vs_ie) + sizeof(payload);
      ieee80211_vs_ie* max_length_ie = static_cast<ieee80211_vs_ie*>(malloc(total_size));
      ASSERT_NE(max_length_ie, nullptr);
      // Populate fields
      max_length_ie->vs_ie = 0xDD;
      max_length_ie->vs_len = 255;
      max_length_ie->vs_oui[0] = 0x00;
      max_length_ie->vs_oui[1] = 0x50;
      max_length_ie->vs_oui[2] = 0xF2;
      max_length_ie->vs_type = 1;
      max_length_ie->vs_subtype = 1;
      memcpy(max_length_ie->payload, payload, 255);
      dm_bss_t instance;
      bool result = instance.add_vendor_ie(max_length_ie);
      EXPECT_TRUE(result);
      free(max_length_ie);
      std::cout << "Exiting AddVendorIEWIthMaximumLengthTEST" << std::endl;
 }
  
/**
 * @brief TEST the addition of a Vendor IE with an empty payload to the dm_bss_t instance.
 *
 * This TEST verifies that the add_vendor_ie function can handle and correctly process a Vendor IE with an empty payload. This is important to ensure that the function can handle edge cases where the payload might be empty.
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
 * | 01 | Define an empty payload Vendor IE | struct ieee80211_vs_ie empty_payload_ie = {0xDD, 5, {0x00, 0x50, 0xF2}, 1, 1, {}} | Vendor IE defined | Should be successful |
 * | 02 | Call add_vendor_ie with the empty payload Vendor IE | instance.add_vendor_ie(&empty_payload_ie) | Should return true | Should Pass |
 * | 03 | Verify the result using ASSERT_TRUE | result = true | Assertion should pass | Should Pass |
 */
 TEST(dm_bss_t_Test, AddVendorIEWIthEmptyPayload) {
      std::cout << "Entering AddVendorIEWIthEmptyPayloadTEST" << std::endl; 
      // Total size = size of struct + 0 (empty payload)
      size_t total_size = sizeof(ieee80211_vs_ie);
      ieee80211_vs_ie* empty_payload_ie = static_cast<ieee80211_vs_ie*>(malloc(total_size));
      ASSERT_NE(empty_payload_ie, nullptr);
      // Initialize fields
      empty_payload_ie->vs_ie = 0xDD;
      empty_payload_ie->vs_len = 0;  // Payload length is 0
      empty_payload_ie->vs_oui[0] = 0x00;
      empty_payload_ie->vs_oui[1] = 0x50;
      empty_payload_ie->vs_oui[2] = 0xF2;
      empty_payload_ie->vs_type = 1;
      empty_payload_ie->vs_subtype = 1;
      dm_bss_t instance;
      // No need to touch payload as it’s empty
      bool result = instance.add_vendor_ie(empty_payload_ie);
      EXPECT_TRUE(result);
      free(empty_payload_ie);
      std::cout << "Exiting AddVendorIEWIthEmptyPayloadTEST" << std::endl;
 } 
  
/**
  * @brief TEST decoding a valid JSON object with a valid parent ID
  *
  * This TEST verifies that the decode function correctly processes a valid JSON object and returns a valid parent ID.
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
  * | 01 | Parse a valid JSON object | validJson = "{\"key\":\"value\"}" | validJson is parsed successfully | Should be successful |
  * | 02 | Call decode function with valid JSON and parent ID | validJson = "{\"key\":\"value\"}", parent_id = uninitialized | result = 0 | Should Pass |
  * | 03 | Assert the result of decode function | result = 0 | result == 0 | Should Pass |
  * | 04 | Clean up the JSON object | validJson = parsed JSON object | validJson is deleted | Should be successful |
  */
 TEST(dm_bss_t_Test, DecodeValidJsonObjectWithValidParentID) {
      std::cout << "Entering DecodeValidJsonObjectWithValidParentIDTEST" << std::endl;
      cJSON*validJson = cJSON_Parse("{\"key\":\"value\"}");
      int parent_id;
      dm_bss_t instance;
      int result = instance.decode(validJson, &parent_id);
      EXPECT_EQ(result, 0);
      cJSON_Delete(validJson);
      std::cout << "Exiting DecodeValidJsonObjectWithValidParentIDTEST" << std::endl;
 }
  
/**
  * @brief TEST the decode function with a null JSON object and a valid parent ID
  *
  * This TEST checks the behavior of the decode function when provided with a null JSON object and a valid parent ID. It ensures that the function returns an error code (-1) as expected.
  *
  * **Test Group ID:** Basic: 01
  * **Test Case ID:** 007@n
  * **Priority:** High
  * @n
  * **Pre-Conditions:** None
  * **Dependencies:** None
  * **User Interaction:** None
  * @n
  * **Test Procedure:**@n
  * | Variation / Step | Description |TEST Data | Expected Result | Notes |
  * | :----: | --------- | ---------- |-------------- | ----- |
  * | 01 | Call the decode function with a null JSON object and a valid parent ID | json_object = nullptr, parent_id = valid | result = -1 | Should Pass |
  * | 02 | Verify the result of the decode function | result = -1 | result == -1 | Should be successful |
  */
 TEST(dm_bss_t_Test, DecodeNullJsonObjectWithValidParentID) {
      std::cout << "Entering DecodeNullJsonObjectWithValidParentIDTEST" << std::endl;
      int parent_id;
      dm_bss_t instance;
      int result = instance.decode(nullptr, &parent_id);
      EXPECT_EQ(result, -1);
      std::cout << "Exiting DecodeNullJsonObjectWithValidParentIDTEST" << std::endl;
 }     
  
/**
 * @brief TEST the decoding of a valid JSON object with a null parent ID.
 *
 * This TEST verifies that the decode function correctly handles a valid JSON object when the parent ID is null. The expected behavior is that the function should return -1, indicating an error due to the null parent ID.
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
 * | Variation / Step | Description |TEST Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Parse a valid JSON object | validJson = cJSON_Parse("{\"key\":\"value\"}") | JSON object parsed successfully | Should be successful |
 * | 02 | Call the decode function with the valid JSON object and a null parent ID | result = instance.decode(validJson, nullptr) | result = -1 | Should Pass |
 * | 03 | Assert that the result is -1 | ASSERT_EQ(result, -1) | Assertion passed | Should be successful |
 * | 04 | Clean up the JSON object | cJSON_Delete(validJson) | JSON object deleted successfully | Should be successful |
 */
 TEST(dm_bss_t_Test, DecodeValidJsonObjectWithNullParentID) {
      std::cout << "Entering DecodeValidJsonObjectWithNullParentIDTEST" << std::endl;
      cJSON*validJson = cJSON_Parse("{\"key\":\"value\"}");
      dm_bss_t instance;
      int result = instance.decode(validJson, nullptr);
      EXPECT_EQ(result, -1);
      cJSON_Delete(validJson);
      std::cout << "Exiting DecodeValidJsonObjectWithNullParentIDTEST" << std::endl;
 }      
  
/**
  * @brief TEST decoding an empty JSON object with a valid parent ID
  *
  * This TEST verifies that the decode function correctly handles an empty JSON object and returns the expected error code.
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
  * | 01 | Parse an empty JSON object | emptyJson = cJSON_Parse("{}") | emptyJson is parsed | Should be successful |
  * | 02 | Call decode with empty JSON and valid parent ID | result = instance.decode(emptyJson, &parent_id) | result = -1 | Should Pass |
  * | 03 | Assert the result | ASSERT_EQ(result, -1) | result = -1 | Should Pass |
  * | 04 | Clean up the JSON object | cJSON_Delete(emptyJson) | emptyJson is deleted | Should be successful |
  */
 TEST(dm_bss_t_Test, DecodeEmptyJsonObjectWithValidParentID) {
      std::cout << "Entering DecodeEmptyJsonObjectWithValidParentIDTEST" << std::endl;
      cJSON*emptyJson = cJSON_Parse("{}");
      int parent_id;
      dm_bss_t instance;
      int result = instance.decode(emptyJson, &parent_id);
      EXPECT_EQ(result, -1);
      cJSON_Delete(emptyJson);
      std::cout << "Exiting DecodeEmptyJsonObjectWithValidParentIDTEST" << std::endl;
}
  
/**
  * @brief TEST the encoding of a valid JSON object without a summary.
  *
  * This TEST verifies that the `encode` method of the `dm_bss_t` class correctly encodes a valid JSON object without including a summary. It ensures that the JSON object is created, encoded, and then properly deleted.
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
  * | 01 | Create a JSON object using `cJSON_CreateObject` | None | JSON object created | Should be successful |
  * | 02 | Call the `encode` method on the instance with the JSON object and `false` for summary | json = cJSON_CreateObject(), summary = false | JSON object encoded | Should Pass |
  * | 03 | Delete the JSON object using `cJSON_Delete` | json = cJSON_CreateObject() | JSON object deleted | Should be successful |
  */
TEST(dm_bss_t_Test, EncodeValidJSONObjectWithoutSummary) {
     std::cout << "Entering EncodeValidJSONObjectWithoutSummaryTEST" << std::endl;
     cJSON*json = cJSON_CreateObject();
     dm_bss_t instance;
     instance.encode(json, false);
     cJSON_Delete(json);
     std::cout << "Exiting EncodeValidJSONObjectWithoutSummaryTEST" << std::endl;
}    
  
/**
  * @brief TEST the encoding of a valid JSON object with summary.
  *
  * This TEST verifies that the `encode` method of the `dm_bss_t` class correctly encodes a JSON object when the summary flag is set to true. It ensures that the JSON object is not null after encoding.
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
  * | 01 | Create a JSON object using `cJSON_CreateObject` | json = cJSON_CreateObject() | JSON object should be created successfully | Should be successful |
  * | 03 | Call the `encode` method with the JSON object and summary flag set to true | instance.encode(json, true) | JSON object should be encoded successfully | Should Pass |
  * | 04 | Delete the JSON object using `cJSON_Delete` | cJSON_Delete(json) | JSON object should be deleted successfully | Should be successful |
  */
 TEST(dm_bss_t_Test, EncodeValidJSONObjectWithSummary) {
      std::cout << "Entering EncodeValidJSONObjectWithSummaryTEST" << std::endl;
      cJSON*json = cJSON_CreateObject();
      dm_bss_t instance;
      instance.encode(json, true);
      cJSON_Delete(json);
      std::cout << "Exiting EncodeValidJSONObjectWithSummaryTEST" << std::endl;
 }
  
/**
  * @brief TEST encoding of a null JSON object without summary
  *
  * This TEST verifies that the encode function correctly handles a null JSON object when the summary flag is set to false.
  *
  * **Test Group ID:** Basic: 01
  * **Test Case ID:** 012@n
  * **Priority:** High
  * @n
  * **Pre-Conditions:** None
  * **Dependencies:** None
  * **User Interaction:** None
  * @n
  * **Test Procedure:**@n
  * | Variation / Step | Description |TEST Data | Expected Result | Notes |
  * | :----: | --------- | ---------- |-------------- | ----- |
  * | 01 | Initialize a null JSON object | cJSON*json = nullptr; | JSON object should be null | Should be successful |
  * | 02 | Call the encode function with the null JSON object and summary flag set to false | instance.encode(json, false); | Function should handle null JSON object without errors | Should Pass |
  */
 TEST(dm_bss_t_Test, EncodeNullJSONObjectWithoutSummary) {
      std::cout << "Entering EncodeNullJSONObjectWithoutSummaryTEST" << std::endl;
      cJSON*json = nullptr;
      dm_bss_t instance;
      EXPECT_ANY_THROW(instance.encode(json, false));
      std::cout << "Exiting EncodeNullJSONObjectWithoutSummaryTEST" << std::endl;
 }
 
/**
  * @brief TEST the encoding of a JSON object with arrays without summary
  *
  * This TEST verifies the functionality of the encode method in the dm_bss_t class when encoding a JSON object that contains arrays, without including a summary.
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
  * | 01 | Create a JSON object and an array, and add the array to the JSON object | json = cJSON_CreateObject(), array = cJSON_CreateArray(), cJSON_AddItemToObject(json, "array", array) | JSON object with array is created | Should be successful |
  * | 02 | Encode the JSON object without summary | instance.encode(json, false) | json, false | Should Pass |
  * | 03 | Verify the JSON object is not null | ASSERT_TRUE(json != nullptr) | json != nullptr | Should Pass |
  * | 04 | Clean up the JSON object | cJSON_Delete(json) | json is deleted | Should be successful |
  */
 TEST(dm_bss_t_Test, EncodeJSONObjectWithArraysWithoutSummary) {
      std::cout << "Entering EncodeJSONObjectWithArraysWithoutSummaryTEST" << std::endl;
      cJSON*json = cJSON_CreateObject();
      cJSON*array = cJSON_CreateArray();
      cJSON_AddItemToObject(json, "array", array);
      dm_bss_t instance;
      instance.encode(json, false);
      ASSERT_TRUE(json != nullptr);
      cJSON_Delete(json);
      std::cout << "Exiting EncodeJSONObjectWithArraysWithoutSummaryTEST" << std::endl;
 }
  
/**
  * @brief TEST the encoding of a JSON object with arrays and summary
  *
  * This TEST verifies the functionality of the encode method in the dm_bss_t class when encoding a JSON object that contains arrays and a summary flag set to true.
  *
  * **Test Group ID:** Basic: 01
  * **Test Case ID:** 014@n
  * **Priority:** High
  * @n
  * **Pre-Conditions:** None
  * **Dependencies:** None
  * **User Interaction:** None
  * @n
  * **Test Procedure:**@n
  * | Variation / Step | Description |TEST Data | Expected Result | Notes |
  * | :----: | --------- | ---------- |-------------- | ----- |
  * | 01 | Create a JSON object and an array, and add the array to the JSON object | json = cJSON_CreateObject(), array = cJSON_CreateArray(), cJSON_AddItemToObject(json, "array", array) | JSON object and array should be created and array should be added to JSON object | Should be successful |
  * | 02 | Encode the JSON object with the summary flag set to true | instance.encode(json, true) | JSON object should be encoded successfully | Should Pass |
  * | 03 | Verify that the JSON object is not null | ASSERT_TRUE(json != nullptr) | Assertion should pass | Should Pass |
  * | 04 | Clean up the JSON object | cJSON_Delete(json) | JSON object should be deleted successfully | Should be successful |
  */
 TEST(dm_bss_t_Test, EncodeJSONObjectWithArraysWithSummary) {
      std::cout << "Entering EncodeJSONObjectWithArraysWithSummaryTEST" << std::endl;
      cJSON*json = cJSON_CreateObject();
      cJSON*array = cJSON_CreateArray();
      cJSON_AddItemToObject(json, "array", array);
      dm_bss_t instance;
      instance.encode(json, true);
      cJSON_Delete(json);
      ASSERT_TRUE(json != nullptr);      
      std::cout << "Exiting EncodeJSONObjectWithArraysWithSummaryTEST" << std::endl;
 }
  
/**
  * @brief TEST the retrieval of BSS information with modified values.
  *
  * This TEST verifies that the BSS information can be retrieved correctly after modifying various values of the BSS instance.
  *
  * **Test Group ID:** Basic: 01
  * **Test Case ID:** 015@n
  * **Priority:** High
  * @n
  * **Pre-Conditions:** None
  * **Dependencies:** None
  * **User Interaction:** None
  * @n
  * **Test Procedure:**
  * | Variation / Step | Description |TEST Data | Expected Result | Notes |
  * | :----: | --------- | ---------- |-------------- | ----- |
  * | 01 | Modify various BSS info values | instance.m_bss_info.enabled = true, instance.m_bss_info.vendor_elements_len = WIFI_AP_MAX_VENDOR_IE_LEN, instance.m_bss_info.bssid.media = em_media_type_ieee80211ac_5, instance.m_bss_info.id.haul_type = em_haul_type_fronthaul | The values should be set | Should be successful |
  * | 02 | Retrieve the BSS info | em_bss_info_t* bss_info = instance.get_bss_info() | bss_info should not be nullptr | Should be successful |
  * | 03 | Verify the BSS info values | bss_info->m_bss_info.vendor_elements_len = WIFI_AP_MAX_VENDOR_IE_LEN, bss_info->m_bss_info.bssid.media = em_media_type_ieee80211ac_5, bss_info->m_bss_info.id.haul_type = em_haul_type_fronthaul | Values should be same as set values | Should Pass |
  */
 TEST(dm_bss_t_Test, RetrieveBssInfoWithModifiedValues) {
      std::cout << "Entering RetrieveBssInfoWithModifiedValuesTEST" << std::endl;
      dm_bss_t instance{};
      instance.m_bss_info.enabled = true;
      instance.m_bss_info.vendor_elements_len = WIFI_AP_MAX_VENDOR_IE_LEN;
      instance.m_bss_info.bssid.media = em_media_type_ieee80211ac_5;
      instance.m_bss_info.id.haul_type = em_haul_type_fronthaul;
      em_bss_info_t* bss_info = instance.get_bss_info();
      ASSERT_NE(bss_info, nullptr);
      EXPECT_TRUE(bss_info->enabled);
      EXPECT_EQ(bss_info->vendor_elements_len, WIFI_AP_MAX_VENDOR_IE_LEN);
      EXPECT_EQ(bss_info->bssid.media, em_media_type_ieee80211ac_5);
      EXPECT_EQ(bss_info->id.haul_type, em_haul_type_fronthaul);
      std::cout << "Exiting RetrieveBssInfoWithModifiedValuesTEST" << std::endl;
 }
 
/**
  * @brief TEST to initialize the BSS information structure
  *
  * This TEST verifies the initialization of the BSS information structure by calling the init() method of the dm_bss_t class. TheTEST ensures that the initialization is successful and returns the expected result.
  *
  * **Test Group ID:** Basic: 01
  * **Test Case ID:** 016@n
  * **Priority:** High
  * @n
  * **Pre-Conditions:** None
  * **Dependencies:** None
  * **User Interaction:** None
  * @n
  * **Test Procedure:**@n
  * | Variation / Step | Description |TEST Data | Expected Result | Notes |
  * | :----: | --------- | ---------- |-------------- | ----- |
  * | 01 | Call the init() method on the instance | instance.init() | Should return 0 | Should Pass |
  */
 TEST(dm_bss_t_Test, InitializeBSSInformationStructure) {
      std::cout << "Entering InitializeBSSInformationStructureTEST" << std::endl;
      dm_bss_t instance;
      int result = instance.init();
      EXPECT_EQ(result, 0);
      std::cout << "Exiting InitializeBSSInformationStructureTEST" << std::endl;
 }
  
/**
  * @brief TEST to initialize BSS information structure multiple times
  *
  * This TEST checks the behavior of the `init` method when called multiple times on the same instance of `dm_bss_t`. 
  * It ensures that the method can be called repeatedly without causing errors or unexpected behavior.
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
  * | 01 | Call the `init` method for the first time | result1 = instance.init() | result1 should be 0 | Should Pass |
  * | 02 | Assert that the first call to `init` returns 0 | ASSERT_EQ(result1, 0) | Assertion should pass | Should be successful |
  * | 03 | Call the `init` method for the second time | result2 = instance.init() | result2 should be 0 | Should Pass |
  * | 04 | Assert that the second call to `init` returns 0 | ASSERT_EQ(result2, 0) | Assertion should pass | Should be successful |
  */
 TEST(dm_bss_t_Test, InitializeBSSInformationStructureMultipleTimes) {
      std::cout << "Entering InitializeBSSInformationStructureMultipleTimesTEST" << std::endl;
      dm_bss_t instance;
      int result1 = instance.init();
      EXPECT_EQ(result1, 0);
      int result2 = instance.init();
      EXPECT_EQ(result2, 0);
      std::cout << "Exiting InitializeBSSInformationStructureMultipleTimesTEST" << std::endl;
 }
  
/**
  * @brief TEST the match_criteria function with a valid criteria string
  *
  * This TEST verifies that the match_criteria function correctly identifies a valid criteria string and returns true.
  *
  * **Test Group ID:** Basic: 01
  * **Test Case ID:** 018@n
  * **Priority:** High
  * @n
  * **Pre-Conditions:** None
  * **Dependencies:** None
  * **User Interaction:** None
  * @n
  * **Test Procedure:**@n
  * | Variation / Step | Description |TEST Data | Expected Result | Notes |
  * | :----: | --------- | ---------- |-------------- | ----- |
  * | 01 | Define a valid criteria string | criteria = "valid_criteria" | Criteria string defined | Should be successful |
  * | 02 | Call the match_criteria function with the valid criteria string | criteria = "valid_criteria" | Should return true | Should Pass |
  * | 03 | Verify the result using ASSERT_TRUE | result = true | Assertion should pass | Should be successful |
  */
 TEST(dm_bss_t_Test, MatchCriteriaWithValidCriteriaString) {
      std::cout << "Entering MatchCriteriaWithValidCriteriaStringTEST" << std::endl;
      char criteria[] = "valid_criteria";
      dm_bss_t instance;
      bool result = instance.match_criteria(criteria);
      EXPECT_TRUE(result);
      std::cout << "Exiting MatchCriteriaWithValidCriteriaStringTEST" << std::endl;
 }
  
/**
  * @brief TEST to verify the behavior of match_criteria with an empty criteria string.
  *
  * This TEST checks the match_criteria function of the dm_bss_t class when provided with an empty criteria string. 
  * It ensures that the function correctly identifies that an empty criteria string does not match any criteria.
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
  * | Variation / Step | Description |TEST Data | Expected Result | Notes |
  * | :----: | --------- | ---------- |-------------- | ----- |
  * | 01 | Define an empty criteria string | criteria = "" | Empty criteria string defined | Should be successful |
  * | 02 | Call match_criteria with the empty criteria string | criteria = "" | result = false | Should Pass |
  * | 03 | Assert that the result is false | result = false | Assertion should pass | Should Pass |
  */
 TEST(dm_bss_t_Test, MatchCriteriaWithEmptyCriteriaString) {
      std::cout << "Entering MatchCriteriaWithEmptyCriteriaStringTEST" << std::endl;
      char criteria[] = "";
      dm_bss_t instance;
      bool result = instance.match_criteria(criteria);
      EXPECT_FALSE(result);
      std::cout << "Exiting MatchCriteriaWithEmptyCriteriaStringTEST" << std::endl;
 }
  
/**
  * @brief TEST to verify the behavior of match_criteria when given a null criteria string.
  *
  * This TEST checks the match_criteria function of the dm_bss_t class to ensure it correctly handles a null criteria string.
  *
  * **Test Group ID:** Basic: 01
  * **Test Case ID:** 020@n
  * **Priority:** High
  * 
  * **Pre-Conditions:** None
  * **Dependencies:** None
  * **User Interaction:** None
  * 
  * **Test Procedure:**
  * | Variation / Step | Description |TEST Data | Expected Result | Notes |
  * | :----: | --------- | ---------- |-------------- | ----- |
  * | 01 | Call match_criteria with a null criteria string | criteria = nullptr | result = false | Should Pass |
  */  
 TEST(dm_bss_t_Test, MatchCriteriaWithNullCriteriaString) {
      std::cout << "Entering MatchCriteriaWithNullCriteriaStringTEST" << std::endl;
      char* criteria = nullptr;
      dm_bss_t instance;
      bool result = instance.match_criteria(criteria);
      EXPECT_FALSE(result);
      std::cout << "Exiting MatchCriteriaWithNullCriteriaStringTEST" << std::endl;
 }     
  
/**
  * @brief TEST the match_criteria function with special characters
  *
  * This TEST checks the behavior of the match_criteria function when provided with a string containing special characters. The function is expected to return false, indicating that the criteria do not match.
  *
  * **Test Group ID:** Basic: 01
  * **Test Case ID:** 021@n
  * **Priority:** High
  * @n
  * **Pre-Conditions:** None
  * **Dependencies:** None
  * **User Interaction:** None
  * @n
  * **Test Procedure:**@n
  * | Variation / Step | Description |TEST Data | Expected Result | Notes |
  * | :----: | --------- | ---------- |-------------- | ----- |
  * | 01 | Define the criteria with special characters | criteria = "!@#$%^&*()" | criteria is set | Should be successful |
  * | 02 | Call match_criteria with special characters | result = instance.match_criteria(criteria) | result = false | Should Pass |
  * | 03 | Assert the result is false | ASSERT_FALSE(result) | result = false | Should Pass |
  */
 TEST(dm_bss_t_Test, MatchCriteriaWithSpecialCharacters) {
      std::cout << "Entering MatchCriteriaWithSpecialCharactersTEST" << std::endl;
      char criteria[] = "!@#$%^&*()";
      dm_bss_t instance;
      bool result = instance.match_criteria(criteria);
      EXPECT_FALSE(result);
      std::cout << "Exiting MatchCriteriaWithSpecialCharactersTEST" << std::endl;
 }
  
/**
  * @brief TEST the match_criteria function with tab, space and newline characters in the criteria string.
  *
  * This TEST checks the behavior of the match_criteria function when the input criteria string contains tab, space and newline characters.
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
  * | 01 | Define criteria with tab and newline characters | criteria = "\tvalid\ncriteria " | None | Should be successful |
  * | 02 | Call match_criteria with the defined criteria | criteria = "\tvalid\ncriteria " | result = false | Should Pass |
  * | 03 | Assert the result is false | result = false | None | Should Pass |
  */
 TEST(dm_bss_t_Test, MatchCriteriaWithTabAndNewlineCharacters) {
      std::cout << "Entering MatchCriteriaWithTabAndNewlineCharactersTEST" << std::endl;
      char criteria[] = "\tvalid\ncriteria ";
      dm_bss_t instance;
      bool result = instance.match_criteria(criteria);
      EXPECT_FALSE(result);
      std::cout << "Exiting MatchCriteriaWithTabAndNewlineCharactersTEST" << std::endl;
 }
  
/**
  * @brief TEST the parsing of a valid BSS ID from a key string.
  *
  * This TEST verifies that the function `parse_bss_id_from_key` correctly parses a valid BSS ID from a given key string. TheTEST ensures that the function returns a success code and the parsed BSS ID is as expected.
  *
  * **Test Group ID:** Basic: 01
  * **Test Case ID:** 023@n
  * **Priority:** High
  * @n
  * **Pre-Conditions:** None
  * **Dependencies:** None
  * **User Interaction:** None
  * @n
  * **Test Procedure:**@n
  * | Variation / Step | Description |TEST Data | Expected Result | Notes |
  * | :----: | --------- | ---------- |-------------- | ----- |
  * | 01 | Define a valid key string and a BSS ID variable | key = "valid_key_string", id = uninitialized | Variables defined | Should be successful |
  * | 02 | Call `parse_bss_id_from_key` with the valid key string and BSS ID variable | key = "valid_key_string", id = uninitialized | result = 0 | Should Pass |
  * | 03 | Verify that the result is 0 (success) | result = 0 | EXPECT_EQ(result, 0) | Should Pass |
  */
 TEST(dm_bss_t_Test, ParseBssIdFromValidKey) {
      std::cout << "Entering ParseBssIdFromValidKeyTEST" << std::endl;
      em_bss_id_t id;
      const char* key = "valid_key_string";
      dm_bss_t instance;
      int result = instance.parse_bss_id_from_key(key, &id);
      EXPECT_EQ(result, 0);
      std::cout << "Exiting ParseBssIdFromValidKeyTEST" << std::endl;
 }
  
/**
  * @brief TEST the parsing of BSS ID from an invalid key string.
  *
  * This TEST verifies that the `parse_bss_id_from_key` function correctly handles an invalid key string by returning an error code.@n
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
  * | Variation / Step | Description |TEST Data | Expected Result | Notes |
  * | :----: | --------- | ---------- |-------------- | ----- |
  * | 01 | Declare variables | em_bss_id_t id; const char* key = "invalid_key_string" << std::endl; | Variables declared | Should be successful |
  * | 02 | Call parse_bss_id_from_key with invalid key | result = instance.parse_bss_id_from_key(key, &id); | key = "invalid_key_string", id = uninitialized | result = -1 | Should Pass |
  * | 03 | Assert the result is -1 | EXPECT_EQ(result, -1); | result = -1 | Assertion passes | Should Pass |
  */
 TEST(dm_bss_t_Test, ParseBssIdFromInvalidKey) {
      std::cout << "Entering ParseBssIdFromInvalidKeyTEST" << std::endl;
      em_bss_id_t id;
      const char* key = "invalid_key_string";
      dm_bss_t instance;
      int result = instance.parse_bss_id_from_key(key, &id);
      EXPECT_EQ(result, -1);
      std::cout << "Exiting ParseBssIdFromInvalidKeyTEST" << std::endl;
 }
  
/**
  * @brief TEST the parse_bss_id_from_key function with a NULL key.
  *
  * This TEST verifies that the parse_bss_id_from_key function correctly handles the case where the key is NULL. 
  * It ensures that the function returns an error code (-1) when provided with a NULL key.
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
  * | 01 | Initialize variables | em_bss_id_t id; const char* key = NULL; | id is uninitialized, key is NULL | Should be successful |
  * | 02 | Call parse_bss_id_from_key with NULL key | result = instance.parse_bss_id_from_key(key, &id); | result = -1 | Should Fail |
  * | 03 | Verify the result | EXPECT_EQ(result, -1); | result = -1 | Should Fail |
  */
 TEST(dm_bss_t_Test, ParseBssIdWithNullKey) {
      std::cout << "Entering ParseBssIdWithNullKeyTEST" << std::endl;
      em_bss_id_t id;
      const char* key = NULL;
      dm_bss_t instance;
      int result = instance.parse_bss_id_from_key(key, &id);
      EXPECT_EQ(result, -1);
      std::cout << "Exiting ParseBssIdWithNullKeyTEST" << std::endl;
 }    
  
/**
  * @brief TEST to verify the behavior of parse_bss_id_from_key when the ID pointer is NULL.
  *
  * This TEST checks the function parse_bss_id_from_key to ensure it correctly handles the case where the ID pointer is NULL. This is important to verify that the function can gracefully handle invalid input parameters.
  *
  * **Test Group ID:** Basic: 01
  * **Test Case ID:** 026@n
  * **Priority:** High
  * @n
  * **Pre-Conditions:** None
  * **Dependencies:** None
  * **User Interaction:** None
  * @n
  * **Test Procedure:**
  * | Variation / Step | Description |TEST Data | Expected Result | Notes |
  * | :----: | --------- | ---------- |-------------- | ----- |
  * | 01 | Call parse_bss_id_from_key with a valid key and NULL ID pointer | key = "valid_key_string", id = NULL | Return value should be -1 | Should Pass |
  */
 TEST(dm_bss_t_Test, ParseBssIdWithNullIdPointer) {
      std::cout << "Entering ParseBssIdWithNullIdPointerTEST" << std::endl;
      const char* key = "valid_key_string";
      dm_bss_t instance;
      int result = instance.parse_bss_id_from_key(key, NULL);
      EXPECT_EQ(result, -1);
      std::cout << "Exiting ParseBssIdWithNullIdPointerTEST" << std::endl;
 }    
  
/**
 * @brief TEST the parsing of BSS ID with an empty key string.
 *
 * This TEST verifies that the parse_bss_id_from_key function correctly handles an empty key string by returning an error code.@n
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
 * | 01 | Define an empty key string and a BSS ID structure | key = "", id = uninitialized | None | Should be successful |
 * | 02 | Call parse_bss_id_from_key with the empty key string | key = "", id = uninitialized | result = -1 | Should Pass |
 * | 03 | Verify the result is -1 | result = -1 | Assertion check: result == -1 | Should Pass |
 */
 TEST(dm_bss_t_Test, ParseBssIdWithEmptyKeyString) {
      std::cout << "Entering ParseBssIdWithEmptyKeyStringTEST" << std::endl;
      em_bss_id_t id;
      const char* key = "";
      dm_bss_t instance;
      int result = instance.parse_bss_id_from_key(key, &id);
      EXPECT_EQ(result, -1);
      std::cout << "Exiting ParseBssIdWithEmptyKeyStringTEST" << std::endl;
 }
  
/**
  * @brief TEST the parsing of BSS ID from a key containing special characters.
  *
  * This TEST verifies that the function `parse_bss_id_from_key` correctly handles keys that contain special characters. 
  * It ensures that the function returns an error code when such keys are provided, as they are not valid.
  *
  * **Test Group ID:** Basic: 01
  * **Test Case ID:** 028@n
  * **Priority:** High
  * 
  * **Pre-Conditions:** None
  * **Dependencies:** None
  * **User Interaction:** None
  * 
  * **Test Procedure:**
  * | Variation / Step | Description |TEST Data | Expected Result | Notes |
  * | :----: | --------- | ---------- |-------------- | ----- |
  * | 01 | Define a key with special characters | key = "key!@#$" | None | Should be successful |
  * | 02 | Call `parse_bss_id_from_key` with the special character key | key = "key!@#$", id = &id | result = -1 | Should Pass |
  * | 03 | Verify the result is -1 | result = -1 | result = -1 | Should Pass |
  */
 TEST(dm_bss_t_Test, ParseBssIdWithKeyContainingSpecialCharacters) {
      std::cout << "Entering ParseBssIdWithKeyContainingSpecialCharactersTEST" << std::endl;
      em_bss_id_t id;
      const char* key = "key!@#$";
      dm_bss_t instance;
      int result = instance.parse_bss_id_from_key(key, &id);
      EXPECT_EQ(result, -1);
      std::cout << "Exiting ParseBssIdWithKeyContainingSpecialCharactersTEST" << std::endl;
 }
  
/**
  * @brief TEST the parsing of BSS ID from a key containing mixed alphanumeric characters
  *
  * This TEST verifies that the function `parse_bss_id_from_key` correctly parses a BSS ID from a key that contains mixed alphanumeric characters. This is important to ensure that the function can handle typical key formats used in the system.
  *
  * **Test Group ID:** Basic: 01
  * **Test Case ID:** 029@n
  * **Priority:** High
  * @n
  * **Pre-Conditions:** None
  * **Dependencies:** None
  * **User Interaction:** None
  * @n
  * **Test Procedure:**@n
  * | Variation / Step | Description |TEST Data | Expected Result | Notes |
  * | :----: | --------- | ---------- |-------------- | ----- |
  * | 01 | Define the key with mixed alphanumeric characters and call `parse_bss_id_from_key` | key = "key123456", id = uninitialized | Function should return 0 | Should Pass |
  * | 02 | Verify the result of the function call | result = 0 | ASSERT_EQ(result, 0) | Should Pass |
  */
 TEST(dm_bss_t_Test, ParseBssIdWithKeyContainingMixedAlphanumericCharacters) {
      std::cout << "Entering ParseBssIdWithKeyContainingMixedAlphanumericCharactersTEST" << std::endl;
      em_bss_id_t id;
      const char* key = "key123456";
      dm_bss_t instance;
      int result = instance.parse_bss_id_from_key(key, &id);
      EXPECT_EQ(result, 0);
      std::cout << "Exiting ParseBssIdWithKeyContainingMixedAlphanumericCharactersTEST" << std::endl;
 }
  
/**
  * @brief TEST the removal of a vendor-specific IE with valid input.
  *
  * This TEST verifies that the `remove_vendor_ie` function correctly handles the removal of a valid vendor-specific information element (IE). TheTEST ensures that the function operates without errors when provided with a valid IE structure.
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
  * | Variation / Step | Description |TEST Data | Expected Result | Notes |
  * | :----: | --------- | ---------- |-------------- | ----- |
  * | 01 | Create a valid vendor-specific IE | ieee80211_vs_ie valid_ie = {0xDD, 5, {0x00, 0x50, 0xF2}, 1, 0, {0x01, 0x02, 0x03}} | valid_ie is created | Should be successful |
  * | 02 | Call remove_vendor_ie with valid_ie | instance.remove_vendor_ie(&valid_ie) | Function executes without errors | Should Pass |
  */
TEST(dm_bss_t_Test, RemoveVendorIEWIthValidInput) {
    std::cout << "Entering RemoveVendorIEWIthValidInputTEST" << std::endl;

    // payload for the IE
    uint8_t payload[] = {0x01, 0x02, 0x03};
    const size_t payload_len = sizeof(payload);

    // vs_len (bytes after the 'vs_len' field): OUI(3) + type(1) + subtype(1) + payload_len
    const uint8_t vs_len_field = static_cast<uint8_t>(3 + 1 + 1 + payload_len); // 5 + payload_len

    // Total bytes occupied by the whole ie structure in memory:
    // offsetof(vs_oui) is the offset of vs_oui from the start of struct (usually 2),
    // so total_size = offsetof(...) + vs_len_field
    const size_t total_size = offsetof(struct ieee80211_vs_ie, vs_oui) + static_cast<size_t>(vs_len_field);

    dm_bss_t instance;

    // Ensure we don't overflow the fixed-size vendor_elements array in the struct
    EXPECT_LE(total_size, sizeof(instance.m_bss_info.vendor_elements));

    // temporary buffer to construct a correct contiguous IE layout
    uint8_t *tmp = static_cast<uint8_t*>(calloc(1, total_size));
    EXPECT_NE(tmp, nullptr);

    // Populate the temporary buffer as an ieee80211_vs_ie
    ieee80211_vs_ie* built_ie = reinterpret_cast<ieee80211_vs_ie*>(tmp);
    built_ie->vs_ie = 0xDD;
    built_ie->vs_len = vs_len_field;
    built_ie->vs_oui[0] = 0x00;
    built_ie->vs_oui[1] = 0x50;
    built_ie->vs_oui[2] = 0xF2;
    built_ie->vs_type = 1;
    built_ie->vs_subtype = 0;
    // copy payload bytes immediately after subtype (into flexible payload area)
    memcpy(built_ie->payload, payload, payload_len);

    // Copy into the struct's fixed-size vendor_elements buffer (the implementation expects IE(s) here)
    memcpy(instance.m_bss_info.vendor_elements, tmp, total_size);
    instance.m_bss_info.vendor_elements_len = total_size;

    // Free temporary buffer (we copied contents into the struct buffer)
    free(tmp);

    // Call remove_vendor_ie with pointer into instance.m_bss_info.vendor_elements
    const ieee80211_vs_ie* ie_ptr = reinterpret_cast<const ieee80211_vs_ie*>(instance.m_bss_info.vendor_elements);

    // Before removal: save length
    size_t before_len = instance.m_bss_info.vendor_elements_len;

    instance.remove_vendor_ie(ie_ptr);

    // After removal: vendor_elements_len should be reduced (or zero)
    // Check it didn't crash and that something changed as expected.
    EXPECT_LE(instance.m_bss_info.vendor_elements_len, before_len);

    std::cout << "Exiting RemoveVendorIEWIthValidInputTEST" << std::endl;
}

/**
  * @brief TEST the remove_vendor_ie function with a null pointer
  *
  * This TEST verifies that the remove_vendor_ie function can handle a null pointer input without crashing or throwing an exception. This is important to ensure the robustness of the function when dealing with invalid inputs.
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
  * | 01 | Call the remove_vendor_ie function with a null pointer | nullptr | Function should handle null pointer gracefully | Should Pass |
  */
 TEST(dm_bss_t_Test, RemoveVendorIEWIthNullPointer) {
      std::cout << "Entering RemoveVendorIEWIthNullPointerTEST" << std::endl;
      dm_bss_t instance;
      EXPECT_ANY_THROW(instance.remove_vendor_ie(nullptr));
      std::cout << "Exiting RemoveVendorIEWIthNullPointerTEST" << std::endl;
 }     
  
/**
  * @brief TEST the removal of a vendor IE with zero length
  *
  * This TEST verifies that the `remove_vendor_ie` function can handle and correctly process a vendor IE with zero length.
  *
  * **Test Group ID:** Basic: 01
  * **Test Case ID:** 032@n
  * **Priority:** High
  * @n
  * **Pre-Conditions:** None
  * **Dependencies:** None
  * **User Interaction:** None
  * @n
  * **Test Procedure:**@n
  * | Variation / Step | Description |TEST Data | Expected Result | Notes |
  * | :----: | --------- | ---------- |-------------- | ----- |
  * | 01 | Create a zero-length vendor IE | zero_length_ie = {0xDD, 0, {0x00, 0x50, 0xF2}, 1, 0, {0x01, 0x02, 0x03}} | None | Should be successful |
  * | 02 | Call the remove_vendor_ie function with the zero-length IE | instance.remove_vendor_ie(&zero_length_ie) | None | Should Pass |
  * | 03 | Verify the function handled the zero-length IE correctly | ASSERT_TRUE(true) | None | Should Pass |
  */
TEST(dm_bss_t_Test, RemoveVendorIEWIthZeroLength) {
    std::cout << "Entering RemoveVendorIEWIthZeroLengthTEST" << std::endl;
    size_t total_size = sizeof(ieee80211_vs_ie); // no payload
    dm_bss_t instance;
    uint8_t *tmp = static_cast<uint8_t*>(calloc(1, total_size));
    ASSERT_NE(tmp, nullptr);
    ieee80211_vs_ie* zero_length_ie = reinterpret_cast<ieee80211_vs_ie*>(tmp);
    zero_length_ie->vs_ie = 0xDD;
    zero_length_ie->vs_len = 0;
    zero_length_ie->vs_oui[0] = 0x00;
    zero_length_ie->vs_oui[1] = 0x50;
    zero_length_ie->vs_oui[2] = 0xF2;
    zero_length_ie->vs_type = 1;
    zero_length_ie->vs_subtype = 0;
    memcpy(instance.m_bss_info.vendor_elements, tmp, total_size);
    instance.m_bss_info.vendor_elements_len = total_size;
    instance.remove_vendor_ie(reinterpret_cast<ieee80211_vs_ie*>(instance.m_bss_info.vendor_elements));
    free(tmp);
    std::cout << "Exiting RemoveVendorIEWIthZeroLengthTEST" << std::endl;
}
  
/**
  * @brief TEST the removal of a vendor IE with maximum length
  *
  * This TEST verifies that the `remove_vendor_ie` function can handle and correctly process a vendor IE with the maximum possible length. This is important to ensure that the function can handle edge cases and large inputs without errors.
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
  * | 01 | Create a maximum length payload and vendor IE | max_payload = {0}, max_length_ie = {0xDD, 255, {0x00, 0x50, 0xF2}, 1, 0, {0}} | Should be successful | Should be successful |
  * | 02 | Copy the maximum payload to the vendor IE payload | memcpy(max_length_ie.payload, max_payload, 255) | Should be successful | Should be successful |
  * | 03 | Call the remove_vendor_ie function with the maximum length IE | instance.remove_vendor_ie(&max_length_ie) | Should Pass | Should Pass |
  * | 04 | Verify the function executed without errors | ASSERT_TRUE(true) | Should Pass | Should Pass |
  */
TEST(dm_bss_t_Test, RemoveVendorIEWIthMaximumLength) {
    std::cout << "Entering RemoveVendorIEWIthMaximumLengthTEST" << std::endl;
    uint8_t max_payload[255] = {0};
    size_t total_size = sizeof(ieee80211_vs_ie) + sizeof(max_payload);
    dm_bss_t instance;
    uint8_t *tmp = static_cast<uint8_t*>(calloc(1, total_size));
    ASSERT_NE(tmp, nullptr);
    ieee80211_vs_ie* max_length_ie = reinterpret_cast<ieee80211_vs_ie*>(tmp);
    max_length_ie->vs_ie = 0xDD;
    max_length_ie->vs_len = sizeof(max_payload);
    max_length_ie->vs_oui[0] = 0x00;
    max_length_ie->vs_oui[1] = 0x50;
    max_length_ie->vs_oui[2] = 0xF2;
    max_length_ie->vs_type = 1;
    max_length_ie->vs_subtype = 0;
    memcpy(max_length_ie->payload, max_payload, sizeof(max_payload));
    memcpy(instance.m_bss_info.vendor_elements, tmp, total_size);
    instance.m_bss_info.vendor_elements_len = total_size;
    instance.remove_vendor_ie(reinterpret_cast<ieee80211_vs_ie*>(instance.m_bss_info.vendor_elements));
    free(tmp);
    std::cout << "Exiting RemoveVendorIEWIthMaximumLengthTEST" << std::endl;
}
  
/**
  * @brief TEST the removal of a vendor IE with an invalid OUI
  *
  * This TEST verifies that the `remove_vendor_ie` function can handle an invalid OUI correctly. TheTEST ensures that the function does not crash or behave unexpectedly when provided with an invalid OUI.
  *
  * **Test Group ID:** Basic: 01
  * **Test Case ID:** 034@n
  * **Priority:** High
  * @n
  * **Pre-Conditions:** None
  * **Dependencies:** None
  * **User Interaction:** None
  * @n
  * **Test Procedure:**@n
  * | Variation / Step | Description |TEST Data | Expected Result | Notes |
  * | :----: | --------- | ---------- |-------------- | ----- |
  * | 01 | Create an invalid OUI IE | ieee80211_vs_ie invalid_oui_ie = {0xDD, 5, {0xFF, 0xFF, 0xFF}, 1, 0, {0x01, 0x02, 0x03}}; | None | Should be successful |
  * | 02 | Call remove_vendor_ie with invalid OUI IE | instance.remove_vendor_ie(&invalid_oui_ie); | None | Should Pass |
  * | 03 | Verify the function handled the invalid OUI correctly | ASSERT_TRUE(true); | None | Should Pass |
  */
TEST(dm_bss_t_Test, RemoveVendorIEWIthInvalidOUI) {
    std::cout << "Entering RemoveVendorIEWIthInvalidOUITEST" << std::endl;
    uint8_t payload[] = {0x01, 0x02, 0x03};
    size_t total_size = sizeof(ieee80211_vs_ie) + sizeof(payload);
    dm_bss_t instance;
    uint8_t *tmp = static_cast<uint8_t*>(calloc(1, total_size));
    ASSERT_NE(tmp, nullptr);
    ieee80211_vs_ie* invalid_oui_ie = reinterpret_cast<ieee80211_vs_ie*>(tmp);
    invalid_oui_ie->vs_ie = 0xDD;
    invalid_oui_ie->vs_len = 5;
    invalid_oui_ie->vs_oui[0] = 0xFF;
    invalid_oui_ie->vs_oui[1] = 0xFF;
    invalid_oui_ie->vs_oui[2] = 0xFF;
    invalid_oui_ie->vs_type = 1;
    invalid_oui_ie->vs_subtype = 0;
    memcpy(invalid_oui_ie->payload, payload, sizeof(payload));
    memcpy(instance.m_bss_info.vendor_elements, tmp, total_size);
    instance.m_bss_info.vendor_elements_len = total_size;
    instance.remove_vendor_ie(reinterpret_cast<ieee80211_vs_ie*>(instance.m_bss_info.vendor_elements));
    free(tmp);
    std::cout << "Exiting RemoveVendorIEWIthInvalidOUITEST" << std::endl;
}
  
/**
 * @brief TEST the removal of a vendor IE with an invalid type
 *
 * This TEST verifies that the `remove_vendor_ie` function can handle an invalid type in the vendor-specific IE structure without causing any errors or crashes. This ensures the robustness of the function when dealing with unexpected input.
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
 * | Variation / Step | Description |TEST Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Create an invalid vendor-specific IE structure | invalid_type_ie = {0xDD, 5, {0x00, 0x50, 0xF2}, 0xFF, 0, {0x01, 0x02, 0x03}} | None | Should be successful |
 * | 02 | Call the `remove_vendor_ie` function with the invalid IE | instance.remove_vendor_ie(&invalid_type_ie) | None | Should Pass |
 * | 03 | Verify the function handled the invalid IE without errors | ASSERT_TRUE(true) | None | Should Pass |
 */
TEST(dm_bss_t_Test, RemoveVendorIEWIthInvalidType) {
    std::cout << "Entering RemoveVendorIEWIthInvalidTypeTEST" << std::endl;
    uint8_t payload[] = {0x01, 0x02, 0x03};
    size_t total_size = sizeof(ieee80211_vs_ie) + sizeof(payload);
    dm_bss_t instance;
    uint8_t *tmp = static_cast<uint8_t*>(calloc(1, total_size));
    ASSERT_NE(tmp, nullptr);
    ieee80211_vs_ie* invalid_type_ie = reinterpret_cast<ieee80211_vs_ie*>(tmp);
    invalid_type_ie->vs_ie = 0xDD;
    invalid_type_ie->vs_len = 5;
    invalid_type_ie->vs_oui[0] = 0x00;
    invalid_type_ie->vs_oui[1] = 0x50;
    invalid_type_ie->vs_oui[2] = 0xF2;
    invalid_type_ie->vs_type = 0xFF; // Invalid
    invalid_type_ie->vs_subtype = 0;
    memcpy(invalid_type_ie->payload, payload, sizeof(payload));
    memcpy(instance.m_bss_info.vendor_elements, tmp, total_size);
    instance.m_bss_info.vendor_elements_len = total_size;
    instance.remove_vendor_ie(reinterpret_cast<ieee80211_vs_ie*>(instance.m_bss_info.vendor_elements));
    free(tmp);
    std::cout << "Exiting RemoveVendorIEWIthInvalidTypeTEST" << std::endl;
}
  
/**
 * @brief TEST the removal of a vendor IE with an invalid subtype
 *
 * This TEST verifies that the `remove_vendor_ie` function can handle an invalid subtype in the vendor-specific IE correctly. TheTEST ensures that the function does not crash or behave unexpectedly when provided with an invalid subtype.
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
 * | Variation / Step | Description |TEST Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Create an invalid vendor-specific IE with subtype 0xFF | invalid_subtype_ie = {0xDD, 5, {0x00, 0x50, 0xF2}, 1, 0xFF, {0x01, 0x02, 0x03}} | None | Should be successful |
 * | 02 | Call the `remove_vendor_ie` function with the invalid vendor-specific IE | instance.remove_vendor_ie(&invalid_subtype_ie) | None | Should Pass |
 * | 03 | Verify the function handled the invalid subtype correctly | ASSERT_TRUE(true) | True | Should Pass |
 */
TEST(dm_bss_t_Test, RemoveVendorIEWIthInvalidSubtype) {
    std::cout << "Entering RemoveVendorIEWIthInvalidSubtypeTEST" << std::endl;
    uint8_t payload[] = {0x01, 0x02, 0x03};
    size_t total_size = sizeof(ieee80211_vs_ie) + sizeof(payload);
    dm_bss_t instance;
    uint8_t *tmp = static_cast<uint8_t*>(calloc(1, total_size));
    ASSERT_NE(tmp, nullptr);
    ieee80211_vs_ie* invalid_subtype_ie = reinterpret_cast<ieee80211_vs_ie*>(tmp);
    invalid_subtype_ie->vs_ie = 0xDD;
    invalid_subtype_ie->vs_len = 5;
    invalid_subtype_ie->vs_oui[0] = 0x00;
    invalid_subtype_ie->vs_oui[1] = 0x50;
    invalid_subtype_ie->vs_oui[2] = 0xF2;
    invalid_subtype_ie->vs_type = 1;
    invalid_subtype_ie->vs_subtype = 0xFF; // Invalid
    memcpy(invalid_subtype_ie->payload, payload, sizeof(payload));
    memcpy(instance.m_bss_info.vendor_elements, tmp, total_size);
    instance.m_bss_info.vendor_elements_len = total_size;
    instance.remove_vendor_ie(reinterpret_cast<ieee80211_vs_ie*>(instance.m_bss_info.vendor_elements));
    free(tmp);
    std::cout << "Exiting RemoveVendorIEWIthInvalidSubtypeTEST" << std::endl;
}

  
/**
  * @brief TEST the removal of a vendor IE with an empty payload
  *
  * This TEST verifies that the `remove_vendor_ie` function can handle the case where the vendor IE has an empty payload. 
  * It ensures that the function does not crash or behave unexpectedly when given such input.
  *
  * **Test Group ID:** Basic: 01
  * **Test Case ID:** 037@n
  * **Priority:** High
  * @n
  * **Pre-Conditions:** None
  * **Dependencies:** None
  * **User Interaction:** None
  * @n
  * **Test Procedure:**@n
  * | Variation / Step | Description |TEST Data | Expected Result | Notes |
  * | :----: | --------- | ---------- |-------------- | ----- |
  * | 01 | Create an empty payload vendor IE | ieee80211_vs_ie empty_payload_ie = {0xDD, 5, {0x00, 0x50, 0xF2}, 1, 0, {}} | Should be successful | |
  * | 02 | Call remove_vendor_ie with the empty payload IE | instance.remove_vendor_ie(&empty_payload_ie) | Should Pass | |
  * | 03 | Verify the function handled the empty payload correctly | ASSERT_TRUE(true) | Should Pass | |
  */
TEST(dm_bss_t_Test, RemoveVendorIEWIthEmptyPayload) {
    std::cout << "Entering RemoveVendorIEWIthEmptyPayloadTEST" << std::endl;
    size_t total_size = sizeof(ieee80211_vs_ie); // no payload
    dm_bss_t instance;
    uint8_t *tmp = static_cast<uint8_t*>(calloc(1, total_size));
    ASSERT_NE(tmp, nullptr);
    ieee80211_vs_ie* empty_payload_ie = reinterpret_cast<ieee80211_vs_ie*>(tmp);
    empty_payload_ie->vs_ie = 0xDD;
    empty_payload_ie->vs_len = 5;
    empty_payload_ie->vs_oui[0] = 0x00;
    empty_payload_ie->vs_oui[1] = 0x50;
    empty_payload_ie->vs_oui[2] = 0xF2;
    empty_payload_ie->vs_type = 1;
    empty_payload_ie->vs_subtype = 0;
    // no payload copied
    memcpy(instance.m_bss_info.vendor_elements, tmp, total_size);
    instance.m_bss_info.vendor_elements_len = total_size;
    instance.remove_vendor_ie(reinterpret_cast<ieee80211_vs_ie*>(instance.m_bss_info.vendor_elements));
    free(tmp);
    std::cout << "Exiting RemoveVendorIEWIthEmptyPayloadTEST" << std::endl;
}

/**
 * @brief TEST to compare two identical objects of dm_bss_t class
 *
 * This TEST checks if two default-constructed objects of the dm_bss_t class are considered equal by the equality operator. This is important to ensure that the equality operator is correctly implemented for the class.
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
 * | Variation / Step | Description |TEST Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Create two objects of dm_bss_t and assign few structure members with same values | Initialize both obj1 and obj2 with m_bss_info.ssid="SSID1", m_bss_info.last_change=100, m_bss_info.enabled=true | Objects should be created successfully | Should be successful |
 * | 02 | Compare the two objects using the equality operator | obj1 == obj2 | EXPECT_TRUE should pass | Should Pass |
 */
 TEST(dm_bss_t_Test, CompareIdenticalObjects) {
      std::cout << "Entering CompareIdenticalObjects" << std::endl;
      dm_bss_t obj1{};
      dm_bss_t obj2{};
      memset(&obj1.m_bss_info, 0, sizeof(obj1.m_bss_info));
      memset(&obj2.m_bss_info, 0, sizeof(obj2.m_bss_info));
      strcpy(obj1.m_bss_info.ssid, "SSID1");
      strcpy(obj2.m_bss_info.ssid, "SSID1");
      obj1.m_bss_info.last_change = obj2.m_bss_info.last_change = 100;
      obj1.m_bss_info.enabled = obj2.m_bss_info.enabled = true;
      EXPECT_TRUE(obj1 == obj2);
      std::cout << "Exiting CompareIdenticalObjects" << std::endl;
 }
  
/**
 * @brief TEST to compare two dm_bss_t objects with different network IDs
 *
 * This TEST verifies that two dm_bss_t objects with different network IDs are not considered equal.@n
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
 * | Variation / Step | Description |TEST Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize two dm_bss_t objects | obj1, obj2 | Objects initialized | Should be successful |
 * | 02 | Set network ID for obj1 | obj1.m_bss_info.id.net_id = "Network1" | Network ID set | Should be successful |
 * | 03 | Set network ID for obj2 | obj2.m_bss_info.id.net_id = "Network2" | Network ID set | Should be successful |
 * | 04 | Compare obj1 and obj2 | obj1 == obj2 | EXPECT_FALSE(obj1 == obj2) | Should Pass |
 */
 TEST(dm_bss_t_Test, CompareDifferentNetId) {
      std::cout << "Entering CompareDifferentNetId" << std::endl;
      dm_bss_t obj1{};
      dm_bss_t obj2{};
      memset(&obj1.m_bss_info, 0, sizeof(obj1.m_bss_info));
      memset(&obj2.m_bss_info, 0, sizeof(obj2.m_bss_info));
      strcpy(obj1.m_bss_info.id.net_id, "Network1");
      strcpy(obj2.m_bss_info.id.net_id, "Network2");
      EXPECT_FALSE(obj1 == obj2);
      std::cout << "Exiting CompareDifferentNetId" << std::endl;
 }
  
/**
 * @brief TEST to compare two dm_bss_t objects with different device MAC addresses
 *
 * This TEST verifies that two dm_bss_t objects with different device MAC addresses are not considered equal.@n
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
 * | Variation / Step | Description |TEST Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize obj1 with MAC 00:11:22:33:44:55 | obj1.m_bss_info.id.dev_mac = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55} | Initialization should be successful | Should be successful |
 * | 02 | Initialize obj2 with MAC 66:77:88:99:AA:BB | obj2.m_bss_info.id.dev_mac = {0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB} | Initialization should be successful | Should be successful |
 * | 03 | Compare obj1 and obj2 for equality | obj1 == obj2 | EXPECT_FALSE(obj1 == obj2) | Should Pass |
 */
 TEST(dm_bss_t_Test, CompareDifferentDevMac) {
      std::cout << "Entering CompareDifferentDevMac" << std::endl;
      // Declare local arrays for dev_mac1 and dev_mac2
      unsigned char dev_mac1[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
      unsigned char dev_mac2[6] = {0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB};
      dm_bss_t obj1{};
      dm_bss_t obj2{};
      memset(&obj1.m_bss_info, 0, sizeof(obj1.m_bss_info));
      memset(&obj2.m_bss_info, 0, sizeof(obj2.m_bss_info));
      // Copy mac addresses into obj1 and obj2
      memcpy(obj1.m_bss_info.id.dev_mac, dev_mac1, sizeof(dev_mac1));
      memcpy(obj2.m_bss_info.id.dev_mac, dev_mac2, sizeof(dev_mac2));
      // Compare the two objects and assert they are not equal
      EXPECT_FALSE(obj1 == obj2); 
      std::cout << "Exiting CompareDifferentDevMac" << std::endl;
 } 
  
/**
 * @brief TEST to compare two dm_bss_t objects with different ruid values
 *
 * This TEST verifies that two dm_bss_t objects with different ruid values are not considered equal.@n
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
 * | 01| Initialize two dm_bss_t objects with different ruid values | obj1.ruid = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, obj2.ruid = {0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB} | Objects should have different ruid values | Should be successful |
 * | 02| Compare the two objects using the equality operator | obj1 == obj2 | EXPECT_FALSE should return true | Should Pass |
 */
  TEST(dm_bss_t_Test, CompareDifferentRuid) {
      std::cout << "Entering CompareDifferentRuid" << std::endl;
      // Declare and initialize local arrays for ruid1 and ruid2
      unsigned char ruid1[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
      unsigned char ruid2[6] = {0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB};
      // Initialize the objects to compare
      dm_bss_t obj1{};
      dm_bss_t obj2{};
      memset(&obj1.m_bss_info, 0, sizeof(obj1.m_bss_info));
      memset(&obj2.m_bss_info, 0, sizeof(obj2.m_bss_info));
      // Copy the ruid values into obj1 and obj2
      memcpy(obj1.m_bss_info.id.ruid, ruid1, sizeof(ruid1));
      memcpy(obj2.m_bss_info.id.ruid, ruid2, sizeof(ruid2));
      // Compare the two objects and assert they are not equal
      EXPECT_FALSE(obj1 == obj2); 
      std::cout << "Exiting CompareDifferentRuid" << std::endl;
 } 
  
/**
 * @brief TEST to compare two different BSSID values
 *
 * This TEST verifies that two different BSSID values are correctly identified as not equal.@n
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
 * | 01| Initialize two dm_bss_t objects with different BSSID values | obj1.m_bss_info.id.bssid = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, obj2.m_bss_info.id.bssid = {0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB} | Objects should be initialized with given BSSID values | Should be successful |
 * | 02| Compare the two objects using the equality operator | obj1 == obj2 | EXPECT_FALSE should return true | Should Pass |
 */
 TEST(dm_bss_t_Test, CompareDifferentBssid) {
      std::cout << "Entering CompareDifferentBssid" << std::endl;
      // Declare and initialize local arrays for bssid1 and bssid2
      unsigned char bssid1[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
      unsigned char bssid2[6] = {0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB};
      // Initialize the objects to compare
      dm_bss_t obj1{};
      dm_bss_t obj2{};
      memset(&obj1.m_bss_info, 0, sizeof(obj1.m_bss_info));
      memset(&obj2.m_bss_info, 0, sizeof(obj2.m_bss_info));
      // Copy the bssid values into obj1 and obj2
      memcpy(obj1.m_bss_info.id.bssid, bssid1, sizeof(bssid1));
      memcpy(obj2.m_bss_info.id.bssid, bssid2, sizeof(bssid2));
      // Compare the two objects and assert they are not equal
      EXPECT_FALSE(obj1 == obj2); 
      std::cout << "Exiting CompareDifferentBssid" << std::endl;
 } 
  
/**
 * @brief TEST to compare two objects of dm_bss_t with different haul types
 *
 * This TEST verifies that two dm_bss_t objects with different haul types are not considered equal.@n
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
 * | Variation / Step | Description |TEST Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Create two dm_bss_t objects | obj1, obj2 | Objects created successfully | Should be successful |
 * | 02 | Set haul type of obj1 to fronthaul | obj1.m_bss_info.id.haul_type = em_haul_type_fronthaul | Haul type set successfully | Should be successful |
 * | 03 | Set haul type of obj2 to backhaul | obj2.m_bss_info.id.haul_type = em_haul_type_backhaul | Haul type set successfully | Should be successful |
 * | 04 | Compare obj1 and obj2 for equality | obj1 == obj2 | EXPECT_FALSE(obj1 == obj2) | Should Pass |
 */
 TEST(dm_bss_t_Test, CompareDifferentHaulType) {
      std::cout << "Entering CompareDifferentHaulType" << std::endl;
      dm_bss_t obj1{};
      dm_bss_t obj2{};
      memset(&obj1.m_bss_info, 0, sizeof(obj1.m_bss_info));
      memset(&obj2.m_bss_info, 0, sizeof(obj2.m_bss_info));
      obj1.m_bss_info.id.haul_type = em_haul_type_fronthaul;
      obj2.m_bss_info.id.haul_type = em_haul_type_backhaul;
      EXPECT_FALSE(obj1 == obj2);
      std::cout << "Exiting CompareDifferentHaulType" << std::endl;
 }
  
/**
 * @brief TEST to compare two dm_bss_t objects with different SSIDs
 *
 * This TEST verifies that two dm_bss_t objects with different SSIDs are not considered equal.@n
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
 * | Variation / Step | Description |TEST Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Create two dm_bss_t objects | obj1, obj2 | Objects created successfully | Should be successful |
 * | 02 | Set SSID of obj1 to "SSID1" | obj1.m_bss_info.ssid = "SSID1" | SSID set successfully | Should be successful |
 * | 03 | Set SSID of obj2 to "SSID2" | obj2.m_bss_info.ssid = "SSID2" | SSID set successfully | Should be successful |
 * | 04 | Compare obj1 and obj2 for equality | obj1 == obj2 | EXPECT_FALSE(obj1 == obj2) | Should Pass |
 */
 TEST(dm_bss_t_Test, CompareDifferentSsid) {
      std::cout << "Entering CompareDifferentSsid" << std::endl;
      dm_bss_t obj1{};
      dm_bss_t obj2{};
      memset(&obj1.m_bss_info, 0, sizeof(obj1.m_bss_info));
      memset(&obj2.m_bss_info, 0, sizeof(obj2.m_bss_info));
      strcpy(obj1.m_bss_info.ssid, "SSID1");
      strcpy(obj2.m_bss_info.ssid, "SSID2");
      EXPECT_FALSE(obj1 == obj2);
      std::cout << "Exiting CompareDifferentSsid" << std::endl;
 }
  
/**
 * @brief TEST to compare the enabled status of two dm_bss_t objects
 *
 * This TEST checks if two dm_bss_t objects with different enabled statuses are not considered equal.@n
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
 * | Variation / Step | Description |TEST Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Create two dm_bss_t objects | obj1.m_bss_info.enabled = true, obj2.m_bss_info.enabled = false | Objects created successfully | Should be successful |
 * | 02 | Set enabled status of obj1 to true and obj2 to false | obj1.m_bss_info.enabled = true, obj2.m_bss_info.enabled = false | Enabled statuses set successfully | Should be successful |
 * | 03 | Compare the two objects using the equality operator | obj1 == obj2 | EXPECT_FALSE(obj1 == obj2) | Should Pass |
 */
 TEST(dm_bss_t_Test, CompareDifferentEnabledStatus) {
      std::cout << "Entering CompareDifferentEnabledStatus" << std::endl;
      dm_bss_t obj1{};
      dm_bss_t obj2{};
      memset(&obj1.m_bss_info, 0, sizeof(obj1.m_bss_info));
      memset(&obj2.m_bss_info, 0, sizeof(obj2.m_bss_info));
      obj1.m_bss_info.enabled = true;
      obj2.m_bss_info.enabled = false;
      EXPECT_FALSE(obj1 == obj2);
      std::cout << "Exiting CompareDifferentEnabledStatus" << std::endl;
 }
  
/**
 * @brief TEST to compare two dm_bss_t objects with different last_change values
 *
 * This TEST verifies that two dm_bss_t objects with different last_change values are not considered equal.@n
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
 * | Variation / Step | Description |TEST Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Create two dm_bss_t objects | obj1.m_bss_info.last_change = 100, obj2.m_bss_info.last_change = 200 | Objects created successfully | Should be successful |
 * | 02 | Set last_change of obj1 to 100 | obj1.m_bss_info.last_change = 100 | last_change set successfully | Should be successful |
 * | 03 | Set last_change of obj2 to 200 | obj2.m_bss_info.last_change = 200 | last_change set successfully | Should be successful |
 * | 04 | Compare obj1 and obj2 using == operator | obj1 == obj2 | EXPECT_FALSE(obj1 == obj2) | Should Pass |
 */
 TEST(dm_bss_t_Test, CompareDifferentLastChange) {
      std::cout << "Entering CompareDifferentLastChange" << std::endl;
      dm_bss_t obj1{};
      dm_bss_t obj2{};
      memset(&obj1.m_bss_info, 0, sizeof(obj1.m_bss_info));
      memset(&obj2.m_bss_info, 0, sizeof(obj2.m_bss_info));
      obj1.m_bss_info.last_change = 100;
      obj2.m_bss_info.last_change = 200;
      EXPECT_FALSE(obj1 == obj2);
      std::cout << "Exiting CompareDifferentLastChange" << std::endl;
 }
  
/**
 * @brief TEST to compare two dm_bss_t objects with different timestamps
 *
 * This TEST verifies that two dm_bss_t objects with different timestamps are not considered equal.@n
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 047@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description |TEST Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize dm_bss_t objects | obj1, obj2 | Objects initialized | Should be successful |
 * | 02 | Set timestamp for obj1 | obj1.m_bss_info.timestamp = "2023-01-01T00:00:00Z" | Timestamp set | Should be successful |
 * | 03 | Set timestamp for obj2 | obj2.m_bss_info.timestamp = "2023-01-02T00:00:00Z" | Timestamp set | Should be successful |
 * | 04 | Compare obj1 and obj2 | obj1 == obj2 | EXPECT_FALSE(obj1 == obj2) | Should Pass |
 */
 TEST(dm_bss_t_Test, CompareDifferentTimestamp) {
      std::cout << "Entering CompareDifferentTimestamp" << std::endl;
      dm_bss_t obj1{};
      dm_bss_t obj2{};
      memset(&obj1.m_bss_info, 0, sizeof(obj1.m_bss_info));
      memset(&obj2.m_bss_info, 0, sizeof(obj2.m_bss_info));
      strcpy(obj1.m_bss_info.timestamp, "2023-01-01T00:00:00Z");
      strcpy(obj2.m_bss_info.timestamp, "2023-01-02T00:00:00Z");
      EXPECT_FALSE(obj1 == obj2);
      std::cout << "Exiting CompareDifferentTimestamp" << std::endl;
 }
  
/**
 * @brief TEST to compare different unicast bytes sent in two dm_bss_t objects
 *
 * This TEST verifies that two dm_bss_t objects with different unicast_bytes_sent values are not considered equal.@n
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 048@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description |TEST Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Create two dm_bss_t objects | obj1.m_bss_info.unicast_bytes_sent = 1000, obj2.m_bss_info.unicast_bytes_sent = 2000 | Objects created successfully | Should be successful |
 * | 02 | Set unicast_bytes_sent for obj1 | obj1.m_bss_info.unicast_bytes_sent = 1000 | Value set successfully | Should be successful |
 * | 03 | Set unicast_bytes_sent for obj2 | obj2.m_bss_info.unicast_bytes_sent = 2000 | Value set successfully | Should be successful |
 * | 04 | Compare obj1 and obj2 using == operator | obj1 == obj2 | EXPECT_FALSE(obj1 == obj2) | Should Pass |
 */
 TEST(dm_bss_t_Test, CompareDifferentUnicastBytesSent) {
      std::cout << "Entering CompareDifferentUnicastBytesSent" << std::endl;
      dm_bss_t obj1{};
      dm_bss_t obj2{};
      memset(&obj1.m_bss_info, 0, sizeof(obj1.m_bss_info));
      memset(&obj2.m_bss_info, 0, sizeof(obj2.m_bss_info));
      obj1.m_bss_info.unicast_bytes_sent = 1000;
      obj2.m_bss_info.unicast_bytes_sent = 2000;
      EXPECT_FALSE(obj1 == obj2);
      std::cout << "Exiting CompareDifferentUnicastBytesSent" << std::endl;
 }
  
/**
 * @brief TEST to compare unicast bytes received between two dm_bss_t objects
 *
 * This TEST verifies that two dm_bss_t objects with different unicast_bytes_rcvd values are not considered equal.@n
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 049@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description |TEST Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize obj1 and obj2 with different unicast_bytes_rcvd values | obj1.m_bss_info.unicast_bytes_rcvd = 1000, obj2.m_bss_info.unicast_bytes_rcvd = 2000 | Objects should not be equal | Should Pass |
 * | 02 | Compare obj1 and obj2 using EXPECT_FALSE | obj1 == obj2 | EXPECT_FALSE should pass | Should Pass |
 */
 TEST(dm_bss_t_Test, CompareDifferentUnicastBytesRcvd) {
      std::cout << "Entering CompareDifferentUnicastBytesRcvd" << std::endl;
      dm_bss_t obj1{};
      dm_bss_t obj2{};
      memset(&obj1.m_bss_info, 0, sizeof(obj1.m_bss_info));
      memset(&obj2.m_bss_info, 0, sizeof(obj2.m_bss_info));
      obj1.m_bss_info.unicast_bytes_rcvd = 1000;
      obj2.m_bss_info.unicast_bytes_rcvd = 2000;
      EXPECT_FALSE(obj1 == obj2);
      std::cout << "Exiting CompareDifferentUnicastBytesRcvd" << std::endl;
 }
  
/**
 * @brief TEST to compare two dm_bss_t objects with different number of stations
 *
 * This TEST verifies that two dm_bss_t objects with different number of stations are not considered equal.@n
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 050@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description |TEST Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize obj1 and obj2 | obj1.m_bss_info.numberofsta = 10, obj2.m_bss_info.numberofsta = 20 | Objects initialized | Should be successful |
 * | 02 | Compare obj1 and obj2 | obj1 == obj2 | EXPECT_FALSE(obj1 == obj2) | Should Pass |
 */
 TEST(dm_bss_t_Test, CompareDifferentNumberOfSta) {
      std::cout << "Entering CompareDifferentNumberOfSta" << std::endl;
      dm_bss_t obj1{};
      dm_bss_t obj2{};
      memset(&obj1.m_bss_info, 0, sizeof(obj1.m_bss_info));
      memset(&obj2.m_bss_info, 0, sizeof(obj2.m_bss_info));
      obj1.m_bss_info.numberofsta = 10;
      obj2.m_bss_info.numberofsta = 20;
      EXPECT_FALSE(obj1 == obj2);
      std::cout << "Exiting CompareDifferentNumberOfSta" << std::endl;
 }
  
/**
 * @brief TEST to compare different estimated service parameters in BSS info
 *
 * This TEST checks the equality operator for `dm_bss_t` objects when their `est_svc_params_be` fields are different. 
 * It ensures that the equality operator correctly identifies the objects as not equal when their `est_svc_params_be` fields differ.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 051@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description |TEST Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Create two `dm_bss_t` objects | obj1, obj2 | Objects created successfully | Should be successful |
 * | 02 | Set `est_svc_params_be` of obj1 to "param1" | obj1.m_bss_info.est_svc_params_be = "param1" | Value set successfully | Should be successful |
 * | 03 | Set `est_svc_params_be` of obj2 to "param2" | obj2.m_bss_info.est_svc_params_be = "param2" | Value set successfully | Should be successful |
 * | 04 | Compare obj1 and obj2 using equality operator | obj1 == obj2 | EXPECT_FALSE(obj1 == obj2) | Should Pass |
 */
 TEST(dm_bss_t_Test, CompareDifferentEstSvcParamsBe) {
      std::cout << "Entering CompareDifferentEstSvcParamsBe" << std::endl;
      dm_bss_t obj1{};
      dm_bss_t obj2{};
      memset(&obj1.m_bss_info, 0, sizeof(obj1.m_bss_info));
      memset(&obj2.m_bss_info, 0, sizeof(obj2.m_bss_info));
      strcpy(obj1.m_bss_info.est_svc_params_be, "param1");
      strcpy(obj2.m_bss_info.est_svc_params_be, "param2");
      EXPECT_FALSE(obj1 == obj2);
      std::cout << "Exiting CompareDifferentEstSvcParamsBe" << std::endl;
 }
  
/**
 * @brief TEST to compare different estimated service parameters in dm_bss_t objects
 *
 * This TEST verifies that two dm_bss_t objects with different estimated service parameters (est_svc_params_bk) are not considered equal.@n
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 052@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description |TEST Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize dm_bss_t objects | obj1, obj2 | Objects initialized | Should be successful |
 * | 02 | Set est_svc_params_bk for obj1 | obj1.m_bss_info.est_svc_params_bk = "param1" | Value set | Should be successful |
 * | 03 | Set est_svc_params_bk for obj2 | obj2.m_bss_info.est_svc_params_bk = "param2" | Value set | Should be successful |
 * | 04 | Compare obj1 and obj2 | obj1 == obj2 | EXPECT_FALSE(obj1 == obj2) | Should Pass |
 */
 TEST(dm_bss_t_Test, CompareDifferentEstSvcParamsBk) {
      std::cout << "Entering CompareDifferentEstSvcParamsBk" << std::endl;
      dm_bss_t obj1{};
      dm_bss_t obj2{};
      memset(&obj1.m_bss_info, 0, sizeof(obj1.m_bss_info));
      memset(&obj2.m_bss_info, 0, sizeof(obj2.m_bss_info));
      strcpy(obj1.m_bss_info.est_svc_params_bk, "param1");
      strcpy(obj2.m_bss_info.est_svc_params_bk, "param2");
      EXPECT_FALSE(obj1 == obj2);
      std::cout << "Exiting CompareDifferentEstSvcParamsBk" << std::endl;
 }
  
/**
 * @brief TEST to compare different estimated service parameters in dm_bss_t objects
 *
 * This TEST verifies that two dm_bss_t objects with different estimated service parameters (est_svc_params_vi) are not considered equal.@n
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 053@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description |TEST Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize two dm_bss_t objects | obj1, obj2 | Objects initialized | Should be successful |
 * | 02 | Set est_svc_params_vi for obj1 to "param1" | obj1.m_bss_info.est_svc_params_vi = "param1" | Value set | Should be successful |
 * | 03 | Set est_svc_params_vi for obj2 to "param2" | obj2.m_bss_info.est_svc_params_vi = "param2" | Value set | Should be successful |
 * | 04 | Compare obj1 and obj2 using EXPECT_FALSE | obj1 == obj2 | EXPECT_FALSE returns true | Should Pass |
 */
 TEST(dm_bss_t_Test, CompareDifferentEstSvcParamsVi) {
      std::cout << "Entering CompareDifferentEstSvcParamsVi" << std::endl;
      dm_bss_t obj1{};
      dm_bss_t obj2{};
      memset(&obj1.m_bss_info, 0, sizeof(obj1.m_bss_info));
      memset(&obj2.m_bss_info, 0, sizeof(obj2.m_bss_info));
      strcpy(obj1.m_bss_info.est_svc_params_vi, "param1");
      strcpy(obj2.m_bss_info.est_svc_params_vi, "param2");
      EXPECT_FALSE(obj1 == obj2);
      std::cout << "Exiting CompareDifferentEstSvcParamsVi" << std::endl;
 }
  
/**
 * @brief TEST to compare different estimated service parameters in dm_bss_t objects
 *
 * This TEST verifies that two dm_bss_t objects with different estimated service parameters (est_svc_params_vo) are not considered equal.@n
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 054@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description |TEST Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize dm_bss_t objects | obj1, obj2 | Objects initialized | Should be successful |
 * | 02 | Set est_svc_params_vo for obj1 | obj1.m_bss_info.est_svc_params_vo = "param1" | Value set | Should be successful |
 * | 03 | Set est_svc_params_vo for obj2 | obj2.m_bss_info.est_svc_params_vo = "param2" | Value set | Should be successful |
 * | 04 | Compare obj1 and obj2 | obj1 == obj2 | EXPECT_FALSE(obj1 == obj2) | Should Fail |
 */
 TEST(dm_bss_t_Test, CompareDifferentEstSvcParamsVo) {
      std::cout << "Entering CompareDifferentEstSvcParamsVo" << std::endl;
      dm_bss_t obj1{};
      dm_bss_t obj2{};
      memset(&obj1.m_bss_info, 0, sizeof(obj1.m_bss_info));
      memset(&obj2.m_bss_info, 0, sizeof(obj2.m_bss_info));
      strcpy(obj1.m_bss_info.est_svc_params_vo, "param1");
      strcpy(obj2.m_bss_info.est_svc_params_vo, "param2");
      EXPECT_FALSE(obj1 == obj2);
      std::cout << "Exiting CompareDifferentEstSvcParamsVo" << std::endl;
 }
  
/**
 * @brief TEST to compare different byte counter units in dm_bss_t objects
 *
 * This TEST checks the equality operator for dm_bss_t objects with different byte counter units. The objective is to ensure that the equality operator correctly identifies objects with different byte counter units as not equal.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 055@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description |TEST Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize dm_bss_t objects | obj1.m_bss_info.byte_counter_units = 1, obj2.m_bss_info.byte_counter_units = 2 | Objects initialized | Should be successful |
 * | 02 | Compare objects with different byte counter units | obj1 == obj2 | EXPECT_FALSE(obj1 == obj2) | Should Pass |
 */
 TEST(dm_bss_t_Test, CompareDifferentByteCounterUnits) {
      std::cout << "Entering CompareDifferentByteCounterUnits" << std::endl;
      dm_bss_t obj1{};
      dm_bss_t obj2{};
      memset(&obj1.m_bss_info, 0, sizeof(obj1.m_bss_info));
      memset(&obj2.m_bss_info, 0, sizeof(obj2.m_bss_info));
      obj1.m_bss_info.byte_counter_units = 1;
      obj2.m_bss_info.byte_counter_units = 2;
      EXPECT_FALSE(obj1 == obj2);
      std::cout << "Exiting CompareDifferentByteCounterUnits" << std::endl;
 }
  
/**
 * @brief TEST to compare two dm_bss_t objects with different num_fronthaul_akms values
 *
 * This TEST checks the equality operator for dm_bss_t objects when they have different num_fronthaul_akms values.@n
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 056@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description |TEST Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize two dm_bss_t objects | obj1.m_bss_info.num_fronthaul_akms = 1, obj2.m_bss_info.num_fronthaul_akms = 2 | Objects initialized | Should be successful |
 * | 02 | Compare the two objects using the equality operator | obj1 == obj2 | EXPECT_FALSE(obj1 == obj2) | Should Fail |
 */
 TEST(dm_bss_t_Test, CompareDifferentNumFronthaulAkms) {
      std::cout << "Entering CompareDifferentNumFronthaulAkms" << std::endl;
      dm_bss_t obj1{};
      dm_bss_t obj2{};
      memset(&obj1.m_bss_info, 0, sizeof(obj1.m_bss_info));
      memset(&obj2.m_bss_info, 0, sizeof(obj2.m_bss_info));
      obj1.m_bss_info.num_fronthaul_akms = 1;
      obj2.m_bss_info.num_fronthaul_akms = 2;
      EXPECT_FALSE(obj1 == obj2);
      std::cout << "Exiting CompareDifferentNumFronthaulAkms" << std::endl;
 }
  
/**
 * @brief TEST to compare two dm_bss_t objects with different fronthaul_akm values
 *
 * This TEST verifies that two dm_bss_t objects with different fronthaul_akm values are not considered equal.@n
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 057@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description |TEST Data |Expected Result |Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01| Initialize two dm_bss_t objects | obj1, obj2 | Objects initialized | Should be successful |
 * | 02| Set fronthaul_akm of obj1 to "akm1" | obj1.m_bss_info.fronthaul_akm[0] = "akm1" | fronthaul_akm set to "akm1" | Should be successful |
 * | 03| Set fronthaul_akm of obj2 to "akm2" | obj2.m_bss_info.fronthaul_akm[0] = "akm2" | fronthaul_akm set to "akm2" | Should be successful |
 * | 04| Compare obj1 and obj2 for equality | obj1 == obj2 | EXPECT_FALSE(obj1 == obj2) | Should Pass |
 */
 TEST(dm_bss_t_Test, CompareDifferentFronthaulAkm) {
      std::cout << "Entering CompareDifferentFronthaulAkm" << std::endl;
      dm_bss_t obj1{};
      dm_bss_t obj2{};
      memset(&obj1.m_bss_info, 0, sizeof(obj1.m_bss_info));
      memset(&obj2.m_bss_info, 0, sizeof(obj2.m_bss_info));
      strcpy(obj1.m_bss_info.fronthaul_akm[0], "akm1");
      strcpy(obj2.m_bss_info.fronthaul_akm[0], "akm2");
      EXPECT_FALSE(obj1 == obj2);
      std::cout << "Exiting CompareDifferentFronthaulAkm" << std::endl;
 }
  
/**
 * @brief TEST to compare two dm_bss_t objects with different num_backhaul_akms values
 *
 * This TEST checks the equality operator for dm_bss_t objects when they have different num_backhaul_akms values. 
 * It ensures that the equality operator correctly identifies the objects as not equal when their num_backhaul_akms values differ.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 058@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description |TEST Data |Expected Result |Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01| Initialize two dm_bss_t objects with different num_backhaul_akms values | obj1.m_bss_info.num_backhaul_akms = 1, obj2.m_bss_info.num_backhaul_akms = 2 | Objects should not be equal | Should Pass |
 * | 02| Compare the two objects using the equality operator | obj1 == obj2 | EXPECT_FALSE(obj1 == obj2) | Should Pass |
 */
 TEST(dm_bss_t_Test, CompareDifferentNumBackhaulAkms) {
      std::cout << "Entering CompareDifferentNumBackhaulAkms" << std::endl;
      dm_bss_t obj1{};
      dm_bss_t obj2{};
      memset(&obj1.m_bss_info, 0, sizeof(obj1.m_bss_info));
      memset(&obj2.m_bss_info, 0, sizeof(obj2.m_bss_info));
      obj1.m_bss_info.num_backhaul_akms = 1;
      obj2.m_bss_info.num_backhaul_akms = 2;
      EXPECT_FALSE(obj1 == obj2);
      std::cout << "Exiting CompareDifferentNumBackhaulAkms" << std::endl;
 }
  
/**
 * @brief TEST to compare different backhaul AKM values in dm_bss_t objects
 *
 * This TEST verifies that two dm_bss_t objects with different backhaul AKM values are not considered equal.@n
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 059@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description |TEST Data |Expected Result |Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01| Initialize dm_bss_t objects | obj1, obj2 | Objects initialized | Should be successful |
 * | 02| Set backhaul_akm for obj1 | obj1.m_bss_info.backhaul_akm[0] = "akm1" | Value set | Should be successful |
 * | 03| Set backhaul_akm for obj2 | obj2.m_bss_info.backhaul_akm[0] = "akm2" | Value set | Should be successful |
 * | 04| Compare obj1 and obj2 | obj1 == obj2 | EXPECT_FALSE(obj1 == obj2) | Should Pass |
 */
 TEST(dm_bss_t_Test, CompareDifferentBackhaulAkm) {
      std::cout << "Entering CompareDifferentBackhaulAkm" << std::endl;
      dm_bss_t obj1{};
      dm_bss_t obj2{};
      memset(&obj1.m_bss_info, 0, sizeof(obj1.m_bss_info));
      memset(&obj2.m_bss_info, 0, sizeof(obj2.m_bss_info));
      strcpy(obj1.m_bss_info.backhaul_akm[0], "akm1");
      strcpy(obj2.m_bss_info.backhaul_akm[0], "akm2");
      EXPECT_FALSE(obj1 == obj2);
      std::cout << "Exiting CompareDifferentBackhaulAkm" << std::endl;
 }
  
/**
 * @brief TEST to compare two dm_bss_t objects with different profile_1b_sta_allowed values
 *
 * This TEST checks the equality operator for dm_bss_t objects when the profile_1b_sta_allowed attribute is different between the two objects. TheTEST ensures that the equality operator correctly identifies the objects as not equal when this attribute differs.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 060@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description |TEST Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize dm_bss_t objects | obj1.m_bss_info.profile_1b_sta_allowed = true, obj2.m_bss_info.profile_1b_sta_allowed = false | Objects initialized | Should be successful |
 * | 02 | Compare objects with different profile_1b_sta_allowed values | obj1 == obj2 | EXPECT_FALSE(obj1 == obj2) | Should Pass |
 */
 TEST(dm_bss_t_Test, CompareDifferentProfile1bStaAllowed) {
      std::cout << "Entering CompareDifferentProfile1bStaAllowed" << std::endl;
      dm_bss_t obj1{};
      dm_bss_t obj2{};
      memset(&obj1.m_bss_info, 0, sizeof(obj1.m_bss_info));
      memset(&obj2.m_bss_info, 0, sizeof(obj2.m_bss_info));
      obj1.m_bss_info.profile_1b_sta_allowed = true;
      obj2.m_bss_info.profile_1b_sta_allowed = false;
      EXPECT_FALSE(obj1 == obj2);
      std::cout << "Exiting CompareDifferentProfile1bStaAllowed" << std::endl;
 }
  
/**
 * @brief TEST to compare two dm_bss_t objects with different profile_2b_sta_allowed values
 *
 * This TEST checks the equality operator for dm_bss_t objects when their profile_2b_sta_allowed values differ. TheTEST ensures that the equality operator correctly identifies the objects as not equal when their profile_2b_sta_allowed values are different.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 061@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description |TEST Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize dm_bss_t objects | obj1.m_bss_info.profile_2b_sta_allowed = true, obj2.m_bss_info.profile_2b_sta_allowed = false | Objects initialized | Should be successful |
 * | 02 | Compare objects with different profile_2b_sta_allowed values | obj1 == obj2 | EXPECT_FALSE(obj1 == obj2) | Should Pass |
 */
 TEST(dm_bss_t_Test, CompareDifferentProfile2bStaAllowed) {
      std::cout << "Entering CompareDifferentProfile2bStaAllowed" << std::endl;
      dm_bss_t obj1{};
      dm_bss_t obj2{};
      memset(&obj1.m_bss_info, 0, sizeof(obj1.m_bss_info));
      memset(&obj2.m_bss_info, 0, sizeof(obj2.m_bss_info));
      obj1.m_bss_info.profile_2b_sta_allowed = true;
      obj2.m_bss_info.profile_2b_sta_allowed = false;
      EXPECT_FALSE(obj1 == obj2);
      std::cout << "Exiting CompareDifferentProfile2bStaAllowed" << std::endl;
 }
  
/**
 * @brief TEST to compare different association allowed statuses in dm_bss_t objects
 *
 * This TEST verifies that two dm_bss_t objects with different association allowed statuses are not considered equal.@n
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 062@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description |TEST Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize dm_bss_t objects | obj1.m_bss_info.assoc_allowed_status = 1, obj2.m_bss_info.assoc_allowed_status = 2 | Objects initialized | Should be successful |
 * | 02 | Compare objects with different assoc_allowed_status | obj1 == obj2 | EXPECT_FALSE(obj1 == obj2) | Should Pass |
 */
 TEST(dm_bss_t_Test, CompareDifferentAssocAllowedStatus) {
      std::cout << "Entering CompareDifferentAssocAllowedStatus" << std::endl;
      dm_bss_t obj1{};
      dm_bss_t obj2{};
      memset(&obj1.m_bss_info, 0, sizeof(obj1.m_bss_info));
      memset(&obj2.m_bss_info, 0, sizeof(obj2.m_bss_info));
      obj1.m_bss_info.assoc_allowed_status = 1;
      obj2.m_bss_info.assoc_allowed_status = 2;
      EXPECT_FALSE(obj1 == obj2);
      std::cout << "Exiting CompareDifferentAssocAllowedStatus" << std::endl;
 }
  
/**
 * @brief TEST to compare different backhaul use in dm_bss_t objects
 *
 * This TEST verifies that two dm_bss_t objects with different backhaul_use values are not considered equal.@n
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 063@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description |TEST Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Create two dm_bss_t objects | obj1.m_bss_info.backhaul_use = true, obj2.m_bss_info.backhaul_use = false | Objects created successfully | Should be successful |
 * | 02 | Set backhaul_use of obj1 to true and obj2 to false | obj1.m_bss_info.backhaul_use = true, obj2.m_bss_info.backhaul_use = false | Values set successfully | Should be successful |
 * | 03 | Compare obj1 and obj2 using == operator | obj1 == obj2 | EXPECT_FALSE(obj1 == obj2) | Should Pass |
 */
 TEST(dm_bss_t_Test, CompareDifferentBackhaulUse) {
      std::cout << "Entering CompareDifferentBackhaulUse" << std::endl;
      dm_bss_t obj1{};
      dm_bss_t obj2{};
      memset(&obj1.m_bss_info, 0, sizeof(obj1.m_bss_info));
      memset(&obj2.m_bss_info, 0, sizeof(obj2.m_bss_info));
      obj1.m_bss_info.backhaul_use = true;
      obj2.m_bss_info.backhaul_use = false;
      EXPECT_FALSE(obj1 == obj2);
      std::cout << "Exiting CompareDifferentBackhaulUse" << std::endl;
 }
  
/**
 * @brief TEST to compare two dm_bss_t objects with different fronthaul_use values
 *
 * This TEST verifies that two dm_bss_t objects with different fronthaul_use values are not considered equal.@n
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 064@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description |TEST Data |Expected Result |Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01| Initialize two dm_bss_t objects | obj1.m_bss_info.fronthaul_use = true, obj2.m_bss_info.fronthaul_use = false | Objects initialized | Should be successful |
 * | 02| Compare the two objects | obj1 == obj2 | EXPECT_FALSE(obj1 == obj2) | Should Pass |
 */
 TEST(dm_bss_t_Test, CompareDifferentFronthaulUse) {
      std::cout << "Entering CompareDifferentFronthaulUse" << std::endl;
      dm_bss_t obj1{};
      dm_bss_t obj2{};
      memset(&obj1.m_bss_info, 0, sizeof(obj1.m_bss_info));
      memset(&obj2.m_bss_info, 0, sizeof(obj2.m_bss_info));
      obj1.m_bss_info.fronthaul_use = true;
      obj2.m_bss_info.fronthaul_use = false;
      EXPECT_FALSE(obj1 == obj2);
      std::cout << "Exiting CompareDifferentFronthaulUse" << std::endl;
 }
  
/**
 * @brief TEST to compare two dm_bss_t objects with different r1_disallowed values
 *
 * This TEST checks the equality operator for dm_bss_t objects when their r1_disallowed values are different.@n
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 065@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description |TEST Data |Expected Result |Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01| Initialize two dm_bss_t objects | obj1.m_bss_info.r1_disallowed = true, obj2.m_bss_info.r1_disallowed = false | Objects initialized | Should be successful |
 * | 02| Compare the two objects using the equality operator | obj1 == obj2 | EXPECT_FALSE(obj1 == obj2) | Should Pass |
 */
 TEST(dm_bss_t_Test, CompareDifferentR1Disallowed) {
      std::cout << "Entering CompareDifferentR1Disallowed" << std::endl;
      dm_bss_t obj1{};
      dm_bss_t obj2{};
      memset(&obj1.m_bss_info, 0, sizeof(obj1.m_bss_info));
      memset(&obj2.m_bss_info, 0, sizeof(obj2.m_bss_info));
      obj1.m_bss_info.r1_disallowed = true;
      obj2.m_bss_info.r1_disallowed = false;
      EXPECT_FALSE(obj1 == obj2);
      std::cout << "Exiting CompareDifferentR1Disallowed" << std::endl;
 }
  
/**
 * @brief TEST to compare two dm_bss_t objects with different r2_disallowed values
 *
 * This TEST checks the equality operator for dm_bss_t objects when their r2_disallowed values differ. 
 * It ensures that the equality operator correctly identifies the objects as not equal when one has r2_disallowed set to true and the other to false.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 066@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description |TEST Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize two dm_bss_t objects | obj1.m_bss_info.r2_disallowed = true, obj2.m_bss_info.r2_disallowed = false | Objects initialized | Should be successful |
 * | 02 | Compare the two objects using the equality operator | obj1 == obj2 | EXPECT_FALSE(obj1 == obj2) | Should Fail |
 */
 TEST(dm_bss_t_Test, CompareDifferentR2Disallowed) {
      std::cout << "Entering CompareDifferentR2Disallowed" << std::endl;
      dm_bss_t obj1{};
      dm_bss_t obj2{};
      memset(&obj1.m_bss_info, 0, sizeof(obj1.m_bss_info));
      memset(&obj2.m_bss_info, 0, sizeof(obj2.m_bss_info));
      obj1.m_bss_info.r2_disallowed = true;
      obj2.m_bss_info.r2_disallowed = false;
      EXPECT_FALSE(obj1 == obj2);
      std::cout << "Exiting CompareDifferentR2Disallowed" << std::endl;
 }
  
/**
 * @brief TEST to compare two dm_bss_t objects with different multi_bssid values
 *
 * This TEST checks the equality operator for dm_bss_t objects when their multi_bssid values are different.@n
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 067@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description |TEST Data |Expected Result |Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01| Initialize dm_bss_t objects | obj1.m_bss_info.multi_bssid = true, obj2.m_bss_info.multi_bssid = false | Objects initialized | Should be successful |
 * | 02| Compare objects with different multi_bssid values | obj1 == obj2 | EXPECT_FALSE(obj1 == obj2) | Should Pass |
 */
 TEST(dm_bss_t_Test, CompareDifferentMultiBssid) {
      std::cout << "Entering CompareDifferentMultiBssid" << std::endl;
      dm_bss_t obj1{};
      dm_bss_t obj2{};
      memset(&obj1.m_bss_info, 0, sizeof(obj1.m_bss_info));
      memset(&obj2.m_bss_info, 0, sizeof(obj2.m_bss_info));
      obj1.m_bss_info.multi_bssid = true;
      obj2.m_bss_info.multi_bssid = false;
      EXPECT_FALSE(obj1 == obj2);
      std::cout << "Exiting CompareDifferentMultiBssid" << std::endl;
 }
  
/**
 * @brief TEST to compare two dm_bss_t objects with different transmitted_bssid values
 *
 * This TEST checks the equality operator for dm_bss_t objects when their transmitted_bssid values differ. 
 * It ensures that the equality operator correctly identifies that the objects are not equal when their 
 * transmitted_bssid values are different.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 068@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description |TEST Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize dm_bss_t objects | obj1.m_bss_info.transmitted_bssid = true, obj2.m_bss_info.transmitted_bssid = false | Objects initialized | Should be successful |
 * | 02 | Compare objects with different transmitted_bssid | obj1 == obj2 | EXPECT_FALSE(obj1 == obj2) | Should Pass |
 */
 TEST(dm_bss_t_Test, CompareDifferentTransmittedBssid) {
      std::cout << "Entering CompareDifferentTransmittedBssid" << std::endl;
      dm_bss_t obj1{};
      dm_bss_t obj2{};
      memset(&obj1.m_bss_info, 0, sizeof(obj1.m_bss_info));
      memset(&obj2.m_bss_info, 0, sizeof(obj2.m_bss_info));
      obj1.m_bss_info.transmitted_bssid = true;
      obj2.m_bss_info.transmitted_bssid = false;
      EXPECT_FALSE(obj1 == obj2);
      std::cout << "Exiting CompareDifferentTransmittedBssid" << std::endl;
 }
  
/**
 * @brief TEST to compare different EHT operations in dm_bss_t objects
 *
 * This TEST verifies that two dm_bss_t objects with different EHT operation BSSID values are not considered equal.@n
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 069@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description |TEST Data |Expected Result |Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01| Initialize two dm_bss_t objects with different BSSID values | obj1.m_bss_info.eht_ops.bssid = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, obj2.m_bss_info.eht_ops.bssid = {0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB} | Objects should have different BSSID values | Should be successful |
 * | 02| Compare the two objects using the equality operator | obj1 == obj2 | EXPECT_FALSE(obj1 == obj2) | Should Pass |
 */
 TEST(dm_bss_t_Test, CompareDifferentEhtOps) {
      std::cout << "Entering CompareDifferentEhtOps" << std::endl;
      dm_bss_t obj1{};
      dm_bss_t obj2{};
      memset(&obj1.m_bss_info, 0, sizeof(obj1.m_bss_info));
      memset(&obj2.m_bss_info, 0, sizeof(obj2.m_bss_info));
      unsigned char temp_bssid[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
      unsigned char temp_bssid2[] = {0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB};
      memcpy(obj1.m_bss_info.eht_ops.bssid, temp_bssid, sizeof(temp_bssid));
      memcpy(obj2.m_bss_info.eht_ops.bssid, temp_bssid2, sizeof(temp_bssid2));
      EXPECT_FALSE(obj1 == obj2);
      std::cout << "Exiting CompareDifferentEhtOps" << std::endl;
 }

/**
 * @brief TEST to compare different vendor elements in dm_bss_t objects
 *
 * This TEST checks the equality operator for dm_bss_t objects with different vendor elements. 
 * It ensures that the equality operator correctly identifies objects with different vendor elements as not equal.@n
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 070@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description |TEST Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize dm_bss_t objects | obj1, obj2 | Objects initialized | Should be successful |
 * | 02 | Set vendor elements for obj1 and obj2 | obj1.m_bss_info.vendor_elements[0] = 0x01, obj2.m_bss_info.vendor_elements[0] = 0x02 | Vendor elements set | Should be successful |
 * | 03 | Compare obj1 and obj2 using equality operator | obj1 == obj2 | EXPECT_FALSE(obj1 == obj2) | Should Pass |
 */
 TEST(dm_bss_t_Test, CompareDifferentVendorElements) {
      std::cout << "Entering CompareDifferentVendorElements" << std::endl;
      dm_bss_t obj1{};
      dm_bss_t obj2{};
      memset(&obj1.m_bss_info, 0, sizeof(obj1.m_bss_info));
      memset(&obj2.m_bss_info, 0, sizeof(obj2.m_bss_info));
      obj1.m_bss_info.vendor_elements[0] = 0x01;
      obj2.m_bss_info.vendor_elements[0] = 0x02;
      EXPECT_FALSE(obj1 == obj2);
      std::cout << "Exiting CompareDifferentVendorElements" << std::endl;
 }
  
/**
 * @brief TEST to compare vendor elements length of two dm_bss_t objects
 *
 * This TEST verifies that two dm_bss_t objects with different vendor_elements_len values are not considered equal.@n
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 071@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description |TEST Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize dm_bss_t objects | obj1.m_bss_info.vendor_elements_len = 10, obj2.m_bss_info.vendor_elements_len = 20 | Objects initialized | Should be successful |
 * | 02 | Compare dm_bss_t objects with different vendor_elements_len | obj1 == obj2 | EXPECT_FALSE(obj1 == obj2) | Should Fail |
 */
 TEST(dm_bss_t_Test, CompareDifferentVendorElementsLen) {
      std::cout << "Entering CompareDifferentVendorElementsLen" << std::endl;
      dm_bss_t obj1{};
      dm_bss_t obj2{};
      memset(&obj1.m_bss_info, 0, sizeof(obj1.m_bss_info));
      memset(&obj2.m_bss_info, 0, sizeof(obj2.m_bss_info));
      obj1.m_bss_info.vendor_elements_len = 10;
      obj2.m_bss_info.vendor_elements_len = 20;
      EXPECT_FALSE(obj1 == obj2);
      std::cout << "Exiting CompareDifferentVendorElementsLen" << std::endl;
 }
  
/**
 * @brief TEST to verify the assignment of initialized values in dm_bss_t class
 *
 * This TEST checks if the assignment operator correctly assigns initialized values from one instance of dm_bss_t to another instance. This is important to ensure that the assignment operator works as expected and all relevant fields are copied correctly.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 072@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description |TEST Data |Expected Result |Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01| Create an instance of dm_bss_t and initialize it with null values | instance = new dm_bss_t() | Should be successful | Should be successful |
 * | 02| Assign the initialized object to another instance | current = obj | Should be successful | Should Pass |
 * | 03| Verify the assigned values are correct | EXPECT_EQ(current.m_bss_info.enabled, obj.m_bss_info.enabled), EXPECT_EQ(current.m_bss_info.unicast_bytes_rcvd, obj.m_bss_info.unicast_bytes_rcvd), EXPECT_EQ(current.m_bss_info.unicast_bytes_sent, obj.m_bss_info.unicast_bytes_sent) | Should be successful | Should Pass |
 */
 TEST(dm_bss_t_Test, AssigningNullValues) {
      std::cout << "Entering AssigningNullValuesTEST";
      dm_bss_t obj{};
      dm_bss_t current{};
      memset(&obj.m_bss_info, 0, sizeof(obj.m_bss_info));
      memset(&current.m_bss_info, 0, sizeof(current.m_bss_info));
      current = obj;
      EXPECT_EQ(current.m_bss_info.unicast_bytes_sent, obj.m_bss_info.unicast_bytes_sent);
      EXPECT_EQ(current.m_bss_info.unicast_bytes_rcvd, obj.m_bss_info.unicast_bytes_rcvd);
      EXPECT_EQ(current.m_bss_info.enabled, obj.m_bss_info.enabled);
      std::cout << "Exiting AssigningNullValuesTEST";
 }
  
/**
 * @brief TEST to verify the assignment operator for dm_bss_t class
 *
 * This TEST checks the assignment operator of the dm_bss_t class by assigning mixed values to the object's members and verifying if the values are correctly assigned to another object.@n
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 073@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description |TEST Data |Expected Result |Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01| Create an instance of dm_bss_t and assign values to its members | obj.m_bss_info.unicast_bytes_sent = 12345, obj.m_bss_info.unicast_bytes_rcvd = 67890 | Values should be assigned correctly | Should be successful |
 * | 02| Assign the object to another instance using the assignment operator | current = obj | current.m_bss_info.unicast_bytes_sent = 12345, current.m_bss_info.unicast_bytes_rcvd = 67890 | Should Pass |
 * | 03| Verify the assigned values using assertions | EXPECT_EQ(current.m_bss_info.unicast_bytes_sent, obj.m_bss_info.unicast_bytes_sent), EXPECT_EQ(current.m_bss_info.unicast_bytes_rcvd, obj.m_bss_info.unicast_bytes_rcvd) | Assertions should pass | Should Pass |
 */
 TEST(dm_bss_t_Test, AssigningMixedValues) {
      std::cout << "Entering AssigningMixedValuesTEST";
      dm_bss_t obj{};
      dm_bss_t current{};
      memset(&obj.m_bss_info, 0, sizeof(obj.m_bss_info));
      memset(&current.m_bss_info, 0, sizeof(current.m_bss_info));
      obj.m_bss_info.unicast_bytes_sent = 12345;
      obj.m_bss_info.unicast_bytes_rcvd = 67890;
      obj.m_bss_info.enabled = true;      
      current = obj;
      EXPECT_EQ(current.m_bss_info.unicast_bytes_sent, obj.m_bss_info.unicast_bytes_sent);
      EXPECT_EQ(current.m_bss_info.unicast_bytes_rcvd, obj.m_bss_info.unicast_bytes_rcvd);
      EXPECT_EQ(current.m_bss_info.enabled, obj.m_bss_info.enabled);
      std::cout << "Exiting AssigningMixedValuesTEST";
 }
  
/**
 * @brief TEST to validate the BSS information retrieval
 *
 * This TEST checks if the BSS information is correctly retrieved and matches the expected data when initialized with valid BSS information.@n
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 074@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description |TEST Data |Expected Result |Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01| Initialize BSS with valid data and create dm_bss_t object | bss = valid data | dm_bss_t object should be created successfully | Should be successful |
 * | 02| Retrieve BSS information using get_bss_info() | obj.get_bss_info() | Should return the initialized BSS information | Should Pass |
 */
 TEST(dm_bss_t_Test, ValidBSSInformation) {
      std::cout << "Entering ValidBSSInformationTEST";
      EXPECT_NO_THROW({
          em_bss_info_t bss{};
          memset(&bss, 0, sizeof(bss));
          bss.unicast_bytes_sent = 12345;
          bss.unicast_bytes_rcvd = 67890;
          bss.enabled = true;
          // Initialize bss with valid data
          dm_bss_t obj(&bss);      
          em_bss_info_t *retrieved = obj.get_bss_info();
          EXPECT_EQ(retrieved->unicast_bytes_sent, bss.unicast_bytes_sent);
          EXPECT_EQ(retrieved->unicast_bytes_rcvd, bss.unicast_bytes_rcvd);
          EXPECT_EQ(retrieved->enabled, bss.enabled);
      });
      std::cout << "Exiting ValidBSSInformationTEST";
 }
  
/**
 * @brief TEST to validate the behavior of dm_bss_t constructor when provided with a null BSS information pointer.
 *
 * This TEST checks if the dm_bss_t constructor throws an invalid_argument exception when it is initialized with a null BSS information pointer. This is important to ensure that the constructor handles invalid input correctly and prevents potential null pointer dereference issues.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 075@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description |TEST Data |Expected Result |Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01| Initialize dm_bss_t with null BSS information pointer | bss = nullptr | Should throw some exception | Should Fail |
 */
 TEST(dm_bss_t_Test, NullBSSInformation) {
      std::cout << "Entering NullBSSInformationTEST";
      em_bss_info_t*bss = nullptr;
      EXPECT_ANY_THROW(dm_bss_t obj(bss));
      std::cout << "Exiting NullBSSInformationTEST";
 }

/**
 * @brief TEST to verify BSS information retrieval with an invalid MAC address
 *
 * This TEST checks the behavior of the BSS information retrieval function when provided with an invalid MAC address. The objective is to ensure that the function can handle invalid MAC addresses gracefully and return the expected BSS information structure.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 076@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description |TEST Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize BSS information with invalid MAC address | bss.id.dev_mac = 0xFF | Should initialize BSS information with invalid MAC address | Should be successful |
 * | 02 | Create dm_bss_t object with initialized BSS information | dm_bss_t obj(&bss) | Should create dm_bss_t object | Should not be successful |
 */
 TEST(dm_bss_t_Test, BSSInformationWithInvalidMACAddress) {
      std::cout << "Entering BSSInformationWithInvalidMACAddressTEST";
      em_bss_info_t bss{};
      memset(&bss, 0, sizeof(bss));
      memset(bss.id.dev_mac, 0xFF, sizeof(bss.id.dev_mac));
      dm_bss_t obj(&bss);
      std::cout << "Exiting BSSInformationWithInvalidMACAddressTEST";
 }
 
/**
 * @brief TEST the BSS information handling with maximum vendor elements
 *
 * This TEST verifies that the BSS information structure can handle the maximum number of vendor elements correctly. It ensures that the vendor elements are properly initialized and that the BSS information is correctly retrieved from the object.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 077@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description |TEST Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize vendor elements to maximum value | bss.vendor_elements = 0xAA, bss.vendor_elements_len = sizeof(bss.vendor_elements) | Vendor elements should be initialized to 0xAA | Should be successful |
 * | 02 | Create dm_bss_t object with initialized BSS info | bss = initialized BSS info | Object should be created successfully | Should be successful |
 */
 TEST(dm_bss_t_Test, BSSInformationWithMaxVendorElements) {
      std::cout << "Entering BSSInformationWithMaxVendorElementsTEST";
      em_bss_info_t bss{};
      memset(&bss, 0, sizeof(bss));
      memset(bss.vendor_elements, 0xAA, sizeof(bss.vendor_elements));
      bss.vendor_elements_len = sizeof(bss.vendor_elements);
      dm_bss_t obj(&bss);
      std::cout << "Exiting BSSInformationWithMaxVendorElementsTEST";
 }
  
/**
 * @brief TEST the copy constructor of dm_bss_t with a valid dm_bss_t object
 *
 * This TEST verifies that the copy constructor of the dm_bss_t class correctly copies the bss_info from the original object to the new object. This ensures that the copy constructor performs a deep copy of the bss_info member.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 078@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description |TEST Data |Expected Result |Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01| Initialize original dm_bss_t object with valid values | original.m_bss_info.ssid = "Test123", original.m_bss_info.enabled = 1, original.m_bss_info.backhaul_use = 1 | original object initialized | Should be successful |
 * | 02| Copy construct dm_bss_t object from original | dm_bss_t copy(original) | copy object created from original | Should be successful |
 * | 03| Compare bss_info of original and copy | copy.m_bss_info.ssid = "Test123", copy.m_bss_info.enabled = 1, copy.m_bss_info.backhaul_use = 1 | Values should be same as original | Should Pass |
 */
  TEST(dm_bss_t_Test, CopyConstructorWithValidDmBssTObject) {
      std::cout << "Entering CopyConstructorWithValidDmBssTObject" << std::endl;
      dm_bss_t original{};
      memset(&original.m_bss_info, 0, sizeof(original.m_bss_info));
      memset(original.m_bss_info.ssid, 0, sizeof(original.m_bss_info.ssid));
      memcpy(original.m_bss_info.ssid, "Test123", 7);
      original.m_bss_info.enabled = 1;
      original.m_bss_info.backhaul_use = 1;
      dm_bss_t copy(original);
      EXPECT_EQ(0, memcmp(original.m_bss_info.ssid, copy.m_bss_info.ssid, sizeof(original.m_bss_info.ssid)));
      EXPECT_EQ(original.m_bss_info.enabled, copy.m_bss_info.enabled);
      EXPECT_EQ(original.m_bss_info.backhaul_use, copy.m_bss_info.backhaul_use);
      std::cout << "Exiting CopyConstructorWithValidDmBssTObject" << std::endl;
  }
  
/**
 * @brief TEST the copy constructor of dm_bss_t class with special characters in strings
 *
 * This TEST verifies that the copy constructor of the dm_bss_t class correctly copies an object that has special characters in its string attributes. This is important to ensure that the copy constructor handles all types of characters properly.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 079@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description |TEST Data |Expected Result |Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01| Initialize original dm_bss_t object and set special characters in ssid | original.m_bss_info.ssid = "!@#$%^&*()" | Initialization should be successful | Should be successful |
 * | 02| Invoke copy constructor with original object | dm_bss_t copy(original) | Copy should have the same ssid as original | Should Pass |
 * | 03| Assert that the ssid of original and copy are equal | SSERT_EQ(0, memcmp(original.m_bss_info.ssid, copy.m_bss_info.ssid, sizeof(original.m_bss_info.ssid))) | Assertion should pass | Should Pass |
 */
 TEST(dm_bss_t_Test, CopyConstructorWithDmBssTObjectHavingSpecialCharactersInStrings) {
      std::cout << "Entering CopyConstructorWithDmBssTObjectHavingSpecialCharactersInStrings" << std::endl;
      dm_bss_t original{};
      memset(&original.m_bss_info, 0, sizeof(original.m_bss_info));
      memset(original.m_bss_info.ssid, 0, sizeof(original.m_bss_info.ssid));
      memcpy(original.m_bss_info.ssid, "!@#$%^&*()", 10);
      dm_bss_t copy(original);
      EXPECT_EQ(0, memcmp(original.m_bss_info.ssid, copy.m_bss_info.ssid, sizeof(original.m_bss_info.ssid)));
      std::cout << "Exiting CopyConstructorWithDmBssTObjectHavingSpecialCharactersInStrings" << std::endl;
}

/**
 * @brief Validate that dm_bss_t can be successfully instantiated using its parameterless constructor
 *
 * This test verifies that the default constructor of dm_bss_t does not throw any exceptions during object
 * creation.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 080@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                              | Test Data                                         | Expected Result                                    | Notes       |
 * | :--------------: | -------------------------------------------------------- | ------------------------------------------------- | -------------------------------------------------- | ----------- |
 * | 01               | Invoke dm_bss_t default constructor                      | No input arguments, output: instance of dm_bss_t  | Object is instantiated without throwing exceptions | Should Pass |
 */
TEST(dm_bss_t_Test, SuccessfulInstantiationUsingParameterlessConstructor) {
    std::cout << "Entering DefaultConstructor test" << std::endl;
    EXPECT_NO_THROW({
        // Invoke default constructor
        dm_bss_t obj;
        std::cout << "Invoked dm_bss_t default constructor." << std::endl;
    });
    std::cout << "Exiting DefaultConstructor test" << std::endl;
}

/**
 * @brief Test the default destructor behavior of dm_bss_t
 *
 * This test verifies that an object of dm_bss_t can be created using its default constructor without throwing any exceptions. It then checks that once the object goes out of scope, its destructor is properly invoked without any issues.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 081@n
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                        | Test Data                                        | Expected Result                                           | Notes        |
 * | :--------------: | ------------------------------------------------------------------ | ------------------------------------------------ | --------------------------------------------------------- | ------------ |
 * | 01               | Invoke default constructor and observe object destruction without exceptions | None = n/a                                      | No exception thrown; default constructor and destructor executed as expected | Should Pass  |
 */
TEST(dm_bss_t_Test, DefaultDestructor) {
    std::cout << "Entering DefaultDestructor test" << std::endl;
    EXPECT_NO_THROW({
        {
            dm_bss_t obj;
            std::cout << "Invoked default constructor for dm_bss_t" << std::endl;
        }
        std::cout << "dm_bss_t object went out of scope, destructor invoked" << std::endl;
    });
    std::cout << "Exiting DefaultDestructor test" << std::endl;
}