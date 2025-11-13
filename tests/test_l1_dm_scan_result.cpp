
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
#include <cstring>
#include "dm_scan_result.h"

// Helper utility to populate dm_scan_result_t with valid data
static void fill_common_scan_result_fields(dm_scan_result_t& obj)
{
    std::cout << "[Helper] Filling common scan_result fields..." << std::endl;

    strncpy(obj.m_scan_result.id.net_id, "COMMON_NET", MAC_STR_LEN - 1);
    obj.m_scan_result.id.net_id[MAC_STR_LEN - 1] = '\0';

    unsigned char devMac[6] = {0xAA, 0xBB, 0xCC, 0x11, 0x22, 0x33};
    memcpy(obj.m_scan_result.id.dev_mac, devMac, sizeof(devMac));

    unsigned char scannerMac[6] = {0x99, 0x88, 0x77, 0x66, 0x55, 0x44};
    memcpy(obj.m_scan_result.id.scanner_mac, scannerMac, sizeof(scannerMac));

    obj.m_scan_result.id.op_class = 81;
    obj.m_scan_result.id.channel = 100;

    strncpy(obj.m_scan_result.timestamp, "2025-11-05T10:00:00",
            sizeof(obj.m_scan_result.timestamp) - 1);
    obj.m_scan_result.timestamp[sizeof(obj.m_scan_result.timestamp) - 1] = '\0';

    obj.m_scan_result.scan_status = 5;
    obj.m_scan_result.util = 20;

    obj.m_scan_result.noise = static_cast<unsigned char>(-75);

    obj.m_scan_result.num_neighbors = 3;
    obj.m_scan_result.aggr_scan_duration = 150;
    obj.m_scan_result.scan_type = 1;

    std::cout << "[Helper] Fill complete" << std::endl;
}



// Test Case: Valid JSON object and valid parent ID pointer
/**
 * @brief Verify that the decode method properly decodes a valid JSON input and associates it with a valid parent ID.
 *
 * This test validates the decode function within the dm_scan_result_t class using a valid cJSON pointer and parent ID. The test ensures that instantiation, JSON creation, and proper API invocation lead to successful decoding by verifying the return value is 0.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 001@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                     | Test Data                                                       | Expected Result                                             | Notes           |
 * | :--------------: | ------------------------------------------------------------------------------- | --------------------------------------------------------------- | ----------------------------------------------------------- | --------------- |
 * | 01               | Create an instance of dm_scan_result_t using its default constructor            | None                                                            | Instance created without throwing exceptions                | Should be successful |
 * | 02               | Initialize a valid parent ID variable                                           | parentID = 123                                                  | parentID is initialized with value 123                      | Should be successful |
 * | 03               | Construct a valid cJSON object pointer using a dummy variable                    | dummyForJson = 1, validJson = pointer to dummyForJson             | validJson pointer is constructed and non-null               | Should be successful |
 * | 04               | Invoke decode() method with validJson pointer and address of parentID              | validJson = <pointer>, parentID address = &123                   | decode() returns 0                                          | Should Pass     |
 * | 05               | Validate the decoded result is successfully associated with the parent ID          | result = decode(validJson, &parentID), parentID remains 123         | Assertion passes confirming result equals 0                 | Should Pass     |
 */
TEST(dm_scan_result_t_Test, ValidJsonAndParentId) {
    std::cout << "Entering ValidJsonAndParentId test" << std::endl;
    
    // Creating dm_scan_result_t instance using default constructor
    EXPECT_NO_THROW({
        dm_scan_result_t scanResult{};
        std::cout << "Created dm_scan_result_t instance using default constructor" << std::endl;
        
        // Create a valid parent ID variable
        int parentID = 123;
        std::cout << "Valid parent ID variable created with value: " << parentID << std::endl;
        
        // Simulate a properly constructed valid cJSON object
        int dummyForJson = 1;
        const cJSON* validJson = reinterpret_cast<const cJSON*>(&dummyForJson);
        std::cout << "Constructed valid cJSON object pointer: " << validJson << std::endl;
        
        // Invocation of decode with valid parameters
        std::cout << "Invoking decode(validJson, &parentID)" << std::endl;
        int result = scanResult.decode(validJson, &parentID);
        std::cout << "Returned value from decode: " << result << std::endl;
        
        // Validate expected output
        EXPECT_EQ(result, 0);
        std::cout << "Decoded result associated successfully with parent ID: " << parentID << std::endl;
    });
    
    std::cout << "Exiting ValidJsonAndParentId test" << std::endl;
}
/**
 * @brief Validate that decode() fails when invoked with a NULL JSON object.
 *
 * This test case verifies that passing a NULL JSON pointer to the decode() function results in the expected failure, indicated by a return value of -1. Handling such error conditions is essential for the robustness and reliability of the API.
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
 * | Variation / Step | Description                                                              | Test Data                                                                       | Expected Result                                              | Notes             |
 * | :--------------: | ------------------------------------------------------------------------ | ------------------------------------------------------------------------------- | ------------------------------------------------------------ | ----------------- |
 * | 01               | Create dm_scan_result_t instance using the default constructor           | No input arguments required                                                     | Instance is created successfully                             | Should be successful |
 * | 02               | Create and assign a valid parent ID variable                             | input: parentID = 456                                                             | parentID variable is initialized with value 456              | Should be successful |
 * | 03               | Set the JSON object pointer to NULL                                      | input: nullJson = NULL                                                            | JSON pointer is set to NULL                                   | Should Pass       |
 * | 04               | Invoke decode() method with NULL JSON object and a valid parent ID pointer | input: nullJson = NULL, parentID pointer = &parentID; output: result expected = -1  | decode() returns -1 indicating failure due to NULL JSON object  | Should Pass       |
 */
TEST(dm_scan_result_t_Test, NullJsonObject) {
    std::cout << "Entering NullJsonObject test" << std::endl;
    
    EXPECT_NO_THROW({
        dm_scan_result_t scanResult{};
        std::cout << "Created dm_scan_result_t instance using default constructor" << std::endl;
        
        // Create valid parent ID variable
        int parentID = 456;
        std::cout << "Valid parent ID variable created with value: " << parentID << std::endl;
        
        // Pass NULL for the JSON object
        const cJSON* nullJson = NULL;
        std::cout << "Set JSON object pointer to NULL" << std::endl;
        
        // Invocation of decode with NULL JSON object
        std::cout << "Invoking decode(nullJson, &parentID)" << std::endl;
        int result = scanResult.decode(nullJson, &parentID);
        std::cout << "Returned value from decode: " << result << std::endl;
        
        // Validate expected output indicating failure
        EXPECT_EQ(result, -1);
        std::cout << "decode() correctly returned failure due to NULL JSON object" << std::endl;
    });
    
    std::cout << "Exiting NullJsonObject test" << std::endl;
}
/**
 * @brief Verify that decode() returns failure when provided a valid JSON with a NULL parent ID pointer.
 *
 * This test verifies that the decode() function correctly handles the scenario where a valid cJSON object is passed along with a NULL parent ID pointer. The API is expected to return -1 to indicate failure in decoding due to an invalid parent ID. The test is crucial to ensure that necessary input validations are in place.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 003@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Create a dm_scan_result_t instance, simulate a valid cJSON object, set parent ID to NULL, and invoke decode() | dummyForJson = 2, validJson = pointer to dummyForJson, nullParentId = NULL, output expected from decode = -1 | decode() returns -1 indicating failure due to NULL parent ID pointer | Should Fail |
 */
TEST(dm_scan_result_t_Test, ValidJsonNullParentId) {
    std::cout << "Entering ValidJsonNullParentId test" << std::endl;
    
    EXPECT_NO_THROW({
        dm_scan_result_t scanResult{};
        std::cout << "Created dm_scan_result_t instance using default constructor" << std::endl;
        
        // Simulate a properly constructed valid cJSON object
        int dummyForJson = 2;
        const cJSON* validJson = reinterpret_cast<const cJSON*>(&dummyForJson);
        std::cout << "Constructed valid cJSON object pointer: " << validJson << std::endl;
        
        // Intentionally use NULL for parent ID pointer
        void* nullParentId = NULL;
        std::cout << "Set parent ID pointer to NULL" << std::endl;
        
        // Invocation of decode with valid JSON and NULL parent ID pointer
        std::cout << "Invoking decode(validJson, nullParentId)" << std::endl;
        int result = scanResult.decode(validJson, nullParentId);
        std::cout << "Returned value from decode: " << result << std::endl;
        
        // Validate expected output indicating failure
        EXPECT_EQ(result, -1);
        std::cout << "decode() correctly returned failure due to NULL parent ID pointer" << std::endl;
    });
    
    std::cout << "Exiting ValidJsonNullParentId test" << std::endl;
}
/**
 * @brief Test for verifying the API behavior when provided with an invalid JSON structure
 *
 * This test ensures that when an invalid JSON structure is provided to the dm_scan_result_t::decode method, the method returns an error code (-1). It verifies that the decode function correctly handles an invalid JSON input constructed from a buffer, ensuring proper error detection.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 004@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                                   | Test Data                                          | Expected Result                                   | Notes        |
 * | :--------------: | --------------------------------------------------------------------------------------------- | -------------------------------------------------- | ------------------------------------------------- | ------------ |
 * | 01               | Create a dm_scan_result_t instance, define a valid parent ID, simulate an invalid JSON buffer, and invoke decode. | parentID = 789, invalidJsonBuffer = "invalid", output from decode should be -1 | decode returns -1 and EXPECT_EQ(result, -1) assertion passes | Should Pass  |
 */
TEST(dm_scan_result_t_Test, InvalidJsonStructure) {
    std::cout << "Entering InvalidJsonStructure test" << std::endl;
    
    EXPECT_NO_THROW({
        dm_scan_result_t scanResult{};
        std::cout << "Created dm_scan_result_t instance using default constructor" << std::endl;
        
        // Create a valid parent ID variable
        int parentID = 789;
        std::cout << "Valid parent ID variable created with value: " << parentID << std::endl;
        
        // Simulate an invalid JSON object structure
        char invalidJsonBuffer[10];
        // Using strncpy to fill the buffer with an invalid JSON string "invalid"
        const char* invalidStr = "invalid";
        strncpy(invalidJsonBuffer, invalidStr, sizeof(invalidJsonBuffer)-1);
        invalidJsonBuffer[sizeof(invalidJsonBuffer)-1] = '\0';
        const cJSON* invalidJson = reinterpret_cast<const cJSON*>(invalidJsonBuffer);
        std::cout << "Constructed invalid cJSON object pointer from buffer: " << static_cast<const void*>(invalidJsonBuffer) << std::endl;
        
        // Invocation of decode with invalid JSON structure
        std::cout << "Invoking decode(invalidJson, &parentID)" << std::endl;
        int result = scanResult.decode(invalidJson, &parentID);
        std::cout << "Returned value from decode: " << result << std::endl;
        
        // Validate expected output indicating failure
        EXPECT_EQ(result, -1);
        std::cout << "decode() correctly returned failure due to invalid JSON structure" << std::endl;
    });
    
    std::cout << "Exiting InvalidJsonStructure test" << std::endl;
}
/**
 * @brief Validate the default constructor of dm_scan_result_t creates distinct objects.
 *
 * This test checks that invoking the default constructor for dm_scan_result_t results in two distinct objects with default states. It verifies that the memory addresses of the two separately constructed objects are different, ensuring that each instantiation produces a unique object instance.
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
 * | 01 | Invoke default constructor for obj1 and log its memory address | obj1: default constructor invoked | obj1 is successfully created with its default state | Should Pass |
 * | 02 | Invoke default constructor for obj2 and log its memory address | obj2: default constructor invoked | obj2 is successfully created with its default state | Should Pass |
 * | 03 | Compare the memory addresses of obj1 and obj2 to ensure they are distinct | Comparison: &obj1, &obj2 | EXPECT_NE(&obj1, &obj2) passes confirming distinct objects | Should Pass |
 */
TEST(dm_scan_result_t_Test, DefaultConstructor) {
    std::cout << "Entering DefaultConstructor test" << std::endl;

    dm_scan_result_t obj1{};
    std::cout << "Invoked default constructor for obj1; memory address: " << &obj1 << std::endl;
    std::cout << "obj1.m_scan_result is in its default state" << std::endl;

    dm_scan_result_t obj2{};
    std::cout << "Invoked default constructor for obj2; memory address: " << &obj2 << std::endl;
    std::cout << "obj2.m_scan_result is in its default state" << std::endl;

    // Check that the two objects are distinct
    EXPECT_NE(&obj1, &obj2);

    std::cout << "Exiting DefaultConstructor test" << std::endl;
}
/**
 * @brief Verify that copying a default constructed dm_scan_result_t object results in an identical memory state.
 *
 * This test verifies that an object created using the default constructor has its internal scan result state
 * zeroed and that copying this object using the copy constructor produces an exact duplicate, as confirmed by
 * a memory comparison (memcmp) between the original and the copy.
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
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Instantiate dm_scan_result_t using the default constructor; retrieve the initial scan result pointer; invoke the copy constructor to create a duplicate; compare memory blocks of the source and copy using memcmp. | source = default constructed dm_scan_result_t, copy = dm_scan_result_t(source), m_scan_result (memory comparison) | memcmp returns 0, indicating the copy is identical to the source and all assertions pass. | Should Pass |
 */
TEST(dm_scan_result_t_Test, CopyDefault)
{
    std::cout << "Entering CopyDefault test" << std::endl;
    
    // Create source using default constructor
    EXPECT_NO_THROW({
        dm_scan_result_t source{};
        // Retrieve the current scan result pointer and log its default state
        std::cout << "Source m_scan_result default state assumed zeroed." << std::endl;
        
        // Invoke the copy constructor by copying the default-constructed object
        dm_scan_result_t copy(source);
        std::cout << "Invoked copy constructor on default constructed object." << std::endl;
        
        // Compare the memory blocks of the source and the copy to verify identical values.
        int cmp = memcmp(&(copy.m_scan_result), &(source.m_scan_result), sizeof(em_scan_result_t));
        std::cout << "Memory comparison after copy, result: " << cmp << std::endl;
        EXPECT_EQ(cmp, 0);
    });
    
    std::cout << "Exiting CopyDefault test" << std::endl;
}


/**
 * @brief Verifies that the copy constructor creates an exact duplicate of a populated dm_scan_result_t instance.
 *
 * This test populates a dm_scan_result_t object with specific valid data, then creates a copy using the copy constructor. 
 * The test ensures that the copied object's internal state exactly matches that of the source by performing a memory comparison.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 007@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                 | Test Data                                                                                                                                                                          | Expected Result                                                                      | Notes         |
 * | :--------------: | --------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------- | ------------- |
 * | 01               | Populate the source dm_scan_result_t object with valid non-zero and valid string data. | input: source object's fields set to "Valid_Net_ID", "AA:BB:CC:DD:EE:FF", "11:22:33:44:55:66", op_class=1, channel=6, scanner_type=em_scanner_type_radio, and others. | The source object is populated correctly with all provided values.                   | Should Pass   |
 * | 02               | Invoke the copy constructor to create a new instance from the populated object. | input: source object populated in step 01; output: copy object obtained using copy constructor.                                                                                    | A new instance is created that duplicates the source object's internal state exactly. | Should Pass   |
 * | 03               | Validate that the source and copied objects have identical memory by comparing them. | input: memory content of source and copy objects (dm_scan_result_t's internal em_scan_result_t structure); output: cmp variable from memcmp function.                            | The memory comparison returns 0, indicating that the copy is identical to the source.  | Should Pass   |
 */
TEST(dm_scan_result_t_Test, CopyPopulated)
{
    std::cout << "Entering CopyPopulated test" << std::endl;
    
    dm_scan_result_t source{};
    em_scan_result_t* scan_res = source.get_scan_result();

    // Populate id.net_id with a valid non-empty string using strncpy
    const char* test_net_id = "Valid_Net_ID";
    strncpy(scan_res->id.net_id, test_net_id, sizeof(scan_res->id.net_id));
    
    // Populate dev_mac and scanner_mac with valid MAC addresses using strncpy
    const char* dev_mac = "AA:BB:CC:DD:EE:FF";
    memcpy(scan_res->id.dev_mac, dev_mac, sizeof(scan_res->id.dev_mac));
    const char* scanner_mac = "11:22:33:44:55:66";
    memcpy(scan_res->id.scanner_mac, scanner_mac, sizeof(scan_res->id.scanner_mac));
    
    // Set op_class and channel to non-zero values
    scan_res->id.op_class = 1;
    scan_res->id.channel = 6;
    
    // Set scanner_type to a valid enum value (em_scanner_type_radio)
    scan_res->id.scanner_type = em_scanner_type_radio;
    
    scan_res->scan_status = 1;
    const char* timestamp = "2021-11-11T10:00:00";
    strncpy(scan_res->timestamp, timestamp, sizeof(scan_res->timestamp));
    scan_res->util = 50;
    scan_res->noise = 20;
    scan_res->num_neighbors = 3;
    scan_res->aggr_scan_duration = 150;
    scan_res->scan_type = 2;
    
    std::cout << "Populated source m_scan_result:" << std::endl;
    std::cout << "  net_id: " << scan_res->id.net_id << std::endl;
    std::cout << "  dev_mac: " << scan_res->id.dev_mac << std::endl;
    std::cout << "  scanner_mac: " << scan_res->id.scanner_mac << std::endl;
    std::cout << "  op_class: " << static_cast<int>(scan_res->id.op_class) << std::endl;
    std::cout << "  channel: " << static_cast<int>(scan_res->id.channel) << std::endl;
    std::cout << "  scanner_type: " << static_cast<int>(scan_res->id.scanner_type) << std::endl;
    std::cout << "  scan_status: " << static_cast<int>(scan_res->scan_status) << std::endl;
    std::cout << "  timestamp: " << scan_res->timestamp << std::endl;
    std::cout << "  util: " << static_cast<int>(scan_res->util) << std::endl;
    std::cout << "  noise: " << static_cast<int>(scan_res->noise) << std::endl;
    std::cout << "  num_neighbors: " << scan_res->num_neighbors << std::endl;
    std::cout << "  aggr_scan_duration: " << scan_res->aggr_scan_duration << std::endl;
    std::cout << "  scan_type: " << static_cast<int>(scan_res->scan_type) << std::endl;
    
    dm_scan_result_t copy(source);
    std::cout << "Invoked copy constructor on populated object." << std::endl;
    
    em_scan_result_t* copy_scan = copy.get_scan_result();
    std::cout << "Copied m_scan_result:" << std::endl;
    std::cout << "  net_id: " << copy_scan->id.net_id << std::endl;
    std::cout << "  dev_mac: " << copy_scan->id.dev_mac << std::endl;
    std::cout << "  scanner_mac: " << copy_scan->id.scanner_mac << std::endl;
    std::cout << "  op_class: " << static_cast<int>(copy_scan->id.op_class) << std::endl;
    std::cout << "  channel: " << static_cast<int>(copy_scan->id.channel) << std::endl;
    std::cout << "  scanner_type: " << static_cast<int>(copy_scan->id.scanner_type) << std::endl;
    std::cout << "  scan_status: " << static_cast<int>(copy_scan->scan_status) << std::endl;
    std::cout << "  timestamp: " << copy_scan->timestamp << std::endl;
    std::cout << "  util: " << static_cast<int>(copy_scan->util) << std::endl;
    std::cout << "  noise: " << static_cast<int>(copy_scan->noise) << std::endl;
    std::cout << "  num_neighbors: " << copy_scan->num_neighbors << std::endl;
    std::cout << "  aggr_scan_duration: " << copy_scan->aggr_scan_duration << std::endl;
    std::cout << "  scan_type: " << static_cast<int>(copy_scan->scan_type) << std::endl;
    
    int cmp = memcmp(&(copy.m_scan_result), &(source.m_scan_result), sizeof(em_scan_result_t));
    std::cout << "Memory comparison between source and copy, result: " << cmp << std::endl;
    EXPECT_EQ(cmp, 0);
    
    std::cout << "Exiting CopyPopulated test" << std::endl;
}


/**
 * @brief Verify that the copy of dm_scan_result_t remains independent after modifications to the original object
 *
 * This test verifies that using the copy constructor yields a deep copy of the dm_scan_result_t object. The test first populates the source object with valid data, then creates a copy using the copy constructor. After modifying the original object's values, the test ensures that the copied instance remains unchanged by comparing memory blocks and individual fields.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 008@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Populate the source object with initial valid values and print details. | input: init_net_id = "Initial_Net_ID", init_dev_mac = "00:11:22:33:44:55", init_scanner_mac = "66:77:88:99:AA:BB", op_class = 2, channel = 11, scanner_type = em_scanner_type_sta, scan_status = 2, timestamp = "2022-01-01T12:00:00", util = 60, noise = 25, num_neighbors = 5, aggr_scan_duration = 200, scan_type = 3 | Source object is populated with valid values and details are printed. | Should be successful |
 * | 02 | Invoke the copy constructor to create a deep copy of the source object. | output: copy object with same initial field values as source | Copy object mirrors the original state prior to any modifications. | Should Pass |
 * | 03 | Modify various fields of the original source object's scan result structure. | input: mod_net_id = "Modified_Net_ID", mod_dev_mac = "FF:EE:DD:CC:BB:AA", mod_scanner_mac = "11:22:33:44:55:66", op_class = 5, channel = 3, scanner_type = em_scanner_type_radio, scan_status = 3, timestamp = "2023-05-05T15:30:00", util = 70, noise = 30, num_neighbors = 7, aggr_scan_duration = 250, scan_type = 4 | The source object fields are updated while the copy remains unchanged. | Should Pass |
 * | 04 | Perform a memory comparison and verify that the copied instance remains intact. | compare memory blocks of copy and source, check fields: net_id = "Initial_Net_ID", dev_mac = "00:11:22:33:44:55", op_class = 2 | memcmp returns non-zero, and the copy object's key fields remain as initially set. | Should Pass |
 */
TEST(dm_scan_result_t_Test, IndependenceAfterModification)
{
    std::cout << "Entering IndependenceAfterModification test" << std::endl;
    
    dm_scan_result_t source{};
    em_scan_result_t* scan_res = source.get_scan_result();
    
    const char* init_net_id = "Initial_Net_ID";
    strncpy(scan_res->id.net_id, init_net_id, sizeof(scan_res->id.net_id));
    const char* init_dev_mac = "00:11:22:33:44:55";
    memcpy(scan_res->id.dev_mac, init_dev_mac, sizeof(scan_res->id.dev_mac));
    const char* init_scanner_mac = "66:77:88:99:AA:BB";
    memcpy(scan_res->id.scanner_mac, init_scanner_mac, sizeof(scan_res->id.scanner_mac));
    scan_res->id.op_class = 2;
    scan_res->id.channel = 11;
    scan_res->id.scanner_type = em_scanner_type_sta;
    scan_res->scan_status = 2;
    const char* init_timestamp = "2022-01-01T12:00:00";
    strncpy(scan_res->timestamp, init_timestamp, sizeof(scan_res->timestamp));
    scan_res->util = 60;
    scan_res->noise = 25;
    scan_res->num_neighbors = 5;
    scan_res->aggr_scan_duration = 200;
    scan_res->scan_type = 3;
    
    std::cout << "Source before copy:" << std::endl;
    std::cout << "  net_id: " << scan_res->id.net_id << std::endl;
    std::cout << "  dev_mac: " << scan_res->id.dev_mac << std::endl;
    
    dm_scan_result_t copy(source);
    std::cout << "Invoked copy constructor on the original populated object." << std::endl;
    
    em_scan_result_t* copy_scan = copy.get_scan_result();
    std::cout << "Copied instance before modification:" << std::endl;
    std::cout << "  net_id: " << copy_scan->id.net_id << std::endl;
    std::cout << "  dev_mac: " << copy_scan->id.dev_mac << std::endl;
    
    const char* mod_net_id = "Modified_Net_ID";
    strncpy(scan_res->id.net_id, mod_net_id, sizeof(scan_res->id.net_id));
    const char* mod_dev_mac = "FF:EE:DD:CC:BB:AA";
    memcpy(scan_res->id.dev_mac, mod_dev_mac, sizeof(scan_res->id.dev_mac));
    const char* mod_scanner_mac = "11:22:33:44:55:66";
    memcpy(scan_res->id.scanner_mac, mod_scanner_mac, sizeof(scan_res->id.scanner_mac));
    scan_res->id.op_class = 5;
    scan_res->id.channel = 3;
    scan_res->id.scanner_type = em_scanner_type_radio;
    scan_res->scan_status = 3;
    const char* mod_timestamp = "2023-05-05T15:30:00";
    strncpy(scan_res->timestamp, mod_timestamp, sizeof(scan_res->timestamp));
    scan_res->util = 70;
    scan_res->noise = 30;
    scan_res->num_neighbors = 7;
    scan_res->aggr_scan_duration = 250;
    scan_res->scan_type = 4;
    
    std::cout << "Source after modification:" << std::endl;
    std::cout << "  net_id: " << scan_res->id.net_id << std::endl;
    std::cout << "  dev_mac: " << scan_res->id.dev_mac << std::endl;
    
    std::cout << "Verifying that the copied instance remains unchanged..." << std::endl;
    std::cout << "Copied instance after original modification:" << std::endl;
    std::cout << "  net_id: " << copy_scan->id.net_id << std::endl;
    std::cout << "  dev_mac: " << copy_scan->id.dev_mac << std::endl;
    
    int cmp = memcmp(&(copy.m_scan_result), &(source.m_scan_result), sizeof(em_scan_result_t));
    std::cout << "Memory comparison after source modification, result: " << cmp << std::endl;
    EXPECT_NE(cmp, 0);
    
    // Verify that copied instance still retains its initial state.
    EXPECT_STREQ(reinterpret_cast<const char*>(copy_scan->id.net_id), "Initial_Net_ID");
    EXPECT_STREQ(reinterpret_cast<const char*>(copy_scan->id.dev_mac), "00:11:22:33:44:55");
    EXPECT_EQ(copy_scan->id.op_class, 2);
    
    std::cout << "Exiting IndependenceAfterModification test" << std::endl;
}


/**
 * @brief Verify dm_scan_result_t construction with valid input parameters
 *
 * This test verifies that the dm_scan_result_t constructor correctly initializes its internal state from a given em_scan_result_t structure. Both valid scanner types (em_scanner_type_radio and em_scanner_type_sta) are used in a loop to ensure the proper assignment of network identifier, MAC addresses, channel parameters, scan status, timestamp, and other related fields. The test asserts that no exceptions are thrown and that all fields match the expected values.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 009@n
 * **Priority:** High@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * 
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize scan result structure with network identifier and MAC addresses. | netId = "TestNetwork", dev_mac = {0x00,0x11,0x22,0x33,0x44,0x55}, scanner_mac = {0x66,0x77,0x88,0x99,0xAA,0xBB} | The net_id is set and MAC addresses are copied to the scan result structure. | Should be successful |
 * | 02 | Set scan parameters: operation class, channel, and scanner type (looping through valid types). | op_class = 5, channel = 36, scanner_type = em_scanner_type_radio / em_scanner_type_sta | The op_class, channel, and scanner_type fields in the scan result structure are correctly assigned. | Should be successful |
 * | 03 | Configure additional scan details including scan status, timestamp, utilization, noise, number of neighbors, aggregate scan duration, and scan type. | scan_status = 1, timestamp = "2023-10-10T12:00:00Z", util = 50, noise = 2, num_neighbors = 3, aggr_scan_duration = 1000, scan_type = 1 | Additional fields are correctly set in the scan result structure with the provided values. | Should be successful |
 * | 04 | Invoke dm_scan_result_t constructor and perform assertions to verify internal state copying. | Input: Initialized scan_result structure with all above values; Output: dm_scan_result_t instance with matching fields. | The constructor does not throw any exception and all fields in the dm_scan_result_t instance match the expected values. | Should Pass |
 */
TEST(dm_scan_result_t_Test, TypicalValidInput) {
    std::cout << "Entering TypicalValidInput test" << std::endl;
    em_scanner_type_t validTypes[2] = { em_scanner_type_radio, em_scanner_type_sta };
    for (int i = 0; i < 2; i++) {
        em_scan_result_t scan_result{};
        const char* netId = "TestNetwork";
        std::cout << "Setting net_id: " << netId << std::endl;
        strncpy(scan_result.id.net_id, netId, sizeof(scan_result.id.net_id) - 1);
        
        unsigned char dev_mac[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
        unsigned char scanner_mac[6] = {0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB};
        std::cout << "Setting dev_mac: ";
        for (int m = 0; m < 6; m++) { 
            scan_result.id.dev_mac[m] = dev_mac[m];
            std::cout << std::hex << int(dev_mac[m]) << " "; 
        }
        std::cout << std::dec << std::endl;
        std::cout << "Setting scanner_mac: ";
        for (int m = 0; m < 6; m++) { 
            scan_result.id.scanner_mac[m] = scanner_mac[m];
            std::cout << std::hex << int(scanner_mac[m]) << " "; 
        }
        std::cout << std::dec << std::endl;
        
        scan_result.id.op_class = 5;
        scan_result.id.channel = 36;
        scan_result.id.scanner_type = validTypes[i];
        std::cout << "Setting op_class: " << int(scan_result.id.op_class)
                  << ", channel: " << int(scan_result.id.channel)
                  << ", scanner_type: " << int(scan_result.id.scanner_type) << std::endl;
        
        scan_result.scan_status = 1;
        const char* timestamp = "2023-10-10T12:00:00Z";
        std::cout << "Setting scan_status: " << int(scan_result.scan_status)
                  << ", timestamp: " << timestamp << std::endl;
        strncpy(scan_result.timestamp, timestamp, sizeof(scan_result.timestamp) - 1);
        
        scan_result.util = 50;
        scan_result.noise = 2;
        scan_result.num_neighbors = 3;
        std::cout << "Setting util: " << int(scan_result.util)
                  << ", noise: " << int(scan_result.noise)
                  << ", num_neighbors: " << scan_result.num_neighbors << std::endl;
        scan_result.aggr_scan_duration = 1000;
        scan_result.scan_type = 1;
        std::cout << "Setting aggr_scan_duration: " << scan_result.aggr_scan_duration
                  << ", scan_type: " << int(scan_result.scan_type) << std::endl;
        
        std::cout << "Invoking dm_scan_result_t(const em_scan_result_t&) constructor" << std::endl;
        EXPECT_NO_THROW({
            dm_scan_result_t dm_obj(scan_result);
            std::cout << "dm_obj.m_scan_result.id.net_id: " << dm_obj.m_scan_result.id.net_id << std::endl;
            std::cout << "dm_obj.m_scan_result.id.dev_mac: ";
            for (int m = 0; m < 6; m++)
                std::cout << std::hex << int(dm_obj.m_scan_result.id.dev_mac[m]) << " ";
            std::cout << std::dec << std::endl;
            std::cout << "dm_obj.m_scan_result.id.scanner_mac: ";
            for (int m = 0; m < 6; m++)
                std::cout << std::hex << int(dm_obj.m_scan_result.id.scanner_mac[m]) << " ";
            std::cout << std::dec << std::endl;
            std::cout << "dm_obj.m_scan_result.id.op_class: " << int(dm_obj.m_scan_result.id.op_class)
                      << ", channel: " << int(dm_obj.m_scan_result.id.channel)
                      << ", scanner_type: " << int(dm_obj.m_scan_result.id.scanner_type) << std::endl;
            std::cout << "dm_obj.m_scan_result.scan_status: " << int(dm_obj.m_scan_result.scan_status) << std::endl;
            std::cout << "dm_obj.m_scan_result.timestamp: " << dm_obj.m_scan_result.timestamp << std::endl;
            std::cout << "dm_obj.m_scan_result.util: " << int(dm_obj.m_scan_result.util)
                      << ", noise: " << int(dm_obj.m_scan_result.noise)
                      << ", num_neighbors: " << dm_obj.m_scan_result.num_neighbors << std::endl;
            std::cout << "dm_obj.m_scan_result.aggr_scan_duration: " << dm_obj.m_scan_result.aggr_scan_duration
                      << ", scan_type: " << int(dm_obj.m_scan_result.scan_type) << std::endl;
            
            EXPECT_STREQ(dm_obj.m_scan_result.id.net_id, netId);
            for (int m = 0; m < 6; m++) {
                EXPECT_EQ(dm_obj.m_scan_result.id.dev_mac[m], dev_mac[m]);
                EXPECT_EQ(dm_obj.m_scan_result.id.scanner_mac[m], scanner_mac[m]);
            }
            EXPECT_EQ(dm_obj.m_scan_result.id.op_class, 5);
            EXPECT_EQ(dm_obj.m_scan_result.id.channel, 36);
            EXPECT_EQ(dm_obj.m_scan_result.id.scanner_type, validTypes[i]);
            EXPECT_EQ(dm_obj.m_scan_result.scan_status, 1);
            EXPECT_STREQ(dm_obj.m_scan_result.timestamp, timestamp);
            EXPECT_EQ(dm_obj.m_scan_result.util, 50);
            EXPECT_EQ(dm_obj.m_scan_result.noise, 2);
            EXPECT_EQ(dm_obj.m_scan_result.num_neighbors, 3);
            EXPECT_EQ(dm_obj.m_scan_result.aggr_scan_duration, 1000u);
            EXPECT_EQ(dm_obj.m_scan_result.scan_type, 1);
        });
    }
    std::cout << "Exiting TypicalValidInput test" << std::endl;
}
/**
 * @brief Validate dm_scan_result_t constructor with empty and zero values
 *
 * This test verifies that the dm_scan_result_t object's members are correctly populated when constructed with an em_scan_result_t structure that contains empty strings and zero values for numeric fields and MAC addresses. The test ensures that the constructor does not throw exceptions and that the object state matches the expected input values.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 010@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize an instance of em_scan_result_t with empty net_id, zero MAC addresses, numeric fields set to 0, and valid scanner_type from enum values | net_id = "", dev_mac = [0,0,0,0,0,0], scanner_mac = [0,0,0,0,0,0], op_class = 0, channel = 0, scanner_type = em_scanner_type_radio/em_scanner_type_sta, scan_status = 0, timestamp = "", util = 0, noise = 0, num_neighbors = 0, aggr_scan_duration = 0, scan_type = 0 | em_scan_result_t correctly initialized without data corruption | Should be successful |
 * | 02 | Invoke the dm_scan_result_t(const em_scan_result_t&) constructor with the empty values structure and verify that all fields in dm_scan_result_t match the input values using assertions | Input: All field values as set above | API constructor does not throw and dm_scan_result_t object's member fields equal the corresponding values from em_scan_result_t | Should Pass |
 */
TEST(dm_scan_result_t_Test, EmptyValues) {
    std::cout << "Entering EmptyValues test" << std::endl;
    em_scanner_type_t validTypes[2] = { em_scanner_type_radio, em_scanner_type_sta };
    for (int i = 0; i < 2; i++) {
        em_scan_result_t scan_result{};
        const char* netId = "";
        std::cout << "Setting net_id to empty string" << std::endl;
        strncpy(scan_result.id.net_id, netId, sizeof(scan_result.id.net_id) - 1);
        
        unsigned char zero_mac[6] = {0, 0, 0, 0, 0, 0};
        std::cout << "Setting dev_mac and scanner_mac to zeros" << std::endl;
        for (int m = 0; m < 6; m++) {
            scan_result.id.dev_mac[m] = zero_mac[m];
            scan_result.id.scanner_mac[m] = zero_mac[m];
        }
        
        scan_result.id.op_class = 0;
        scan_result.id.channel = 0;
        scan_result.id.scanner_type = validTypes[i];
        std::cout << "Setting op_class, channel, scanner_type to zero/validTypes[" << i << "]: " << int(validTypes[i]) << std::endl;
        
        scan_result.scan_status = 0;
        const char* timestamp = "";
        std::cout << "Setting scan_status to 0 and timestamp to empty string" << std::endl;
        strncpy(scan_result.timestamp, timestamp, sizeof(scan_result.timestamp) - 1);
        
        scan_result.util = 0;
        scan_result.noise = 0;
        scan_result.num_neighbors = 0;
        std::cout << "Setting util, noise, num_neighbors to 0" << std::endl;
        scan_result.aggr_scan_duration = 0;
        scan_result.scan_type = 0;
        std::cout << "Setting aggr_scan_duration and scan_type to 0" << std::endl;
        
        std::cout << "Invoking dm_scan_result_t(const em_scan_result_t&) constructor" << std::endl;
        EXPECT_NO_THROW({
            dm_scan_result_t dm_obj(scan_result);
            std::cout << "dm_obj.m_scan_result.id.net_id: \"" << dm_obj.m_scan_result.id.net_id << "\"" << std::endl;
            std::cout << "dm_obj.m_scan_result.id.dev_mac: ";
            for (int m = 0; m < 6; m++) 
                std::cout << std::hex << int(dm_obj.m_scan_result.id.dev_mac[m]) << " ";
            std::cout << std::dec << std::endl;
            std::cout << "dm_obj.m_scan_result.id.scanner_mac: ";
            for (int m = 0; m < 6; m++) 
                std::cout << std::hex << int(dm_obj.m_scan_result.id.scanner_mac[m]) << " ";
            std::cout << std::dec << std::endl;
            std::cout << "dm_obj.m_scan_result.id.op_class: " << int(dm_obj.m_scan_result.id.op_class)
                      << ", channel: " << int(dm_obj.m_scan_result.id.channel)
                      << ", scanner_type: " << int(dm_obj.m_scan_result.id.scanner_type) << std::endl;
            std::cout << "dm_obj.m_scan_result.scan_status: " << int(dm_obj.m_scan_result.scan_status) << std::endl;
            std::cout << "dm_obj.m_scan_result.timestamp: \"" << dm_obj.m_scan_result.timestamp << "\"" << std::endl;
            std::cout << "dm_obj.m_scan_result.util: " << int(dm_obj.m_scan_result.util)
                      << ", noise: " << int(dm_obj.m_scan_result.noise)
                      << ", num_neighbors: " << dm_obj.m_scan_result.num_neighbors << std::endl;
            std::cout << "dm_obj.m_scan_result.aggr_scan_duration: " << dm_obj.m_scan_result.aggr_scan_duration
                      << ", scan_type: " << int(dm_obj.m_scan_result.scan_type) << std::endl;
            
            EXPECT_STREQ(dm_obj.m_scan_result.id.net_id, netId);
            for (int m = 0; m < 6; m++) {
                EXPECT_EQ(dm_obj.m_scan_result.id.dev_mac[m], 0);
                EXPECT_EQ(dm_obj.m_scan_result.id.scanner_mac[m], 0);
            }
            EXPECT_EQ(dm_obj.m_scan_result.id.op_class, 0);
            EXPECT_EQ(dm_obj.m_scan_result.id.channel, 0);
            EXPECT_EQ(dm_obj.m_scan_result.id.scanner_type, validTypes[i]);
            EXPECT_EQ(dm_obj.m_scan_result.scan_status, 0);
            EXPECT_STREQ(dm_obj.m_scan_result.timestamp, timestamp);
            EXPECT_EQ(dm_obj.m_scan_result.util, 0);
            EXPECT_EQ(dm_obj.m_scan_result.noise, 0);
            EXPECT_EQ(dm_obj.m_scan_result.num_neighbors, 0);
            EXPECT_EQ(dm_obj.m_scan_result.aggr_scan_duration, 0u);
            EXPECT_EQ(dm_obj.m_scan_result.scan_type, 0);
        });
    }
    std::cout << "Exiting EmptyValues test" << std::endl;
}
/**
 * @brief Test maximum boundary values for dm_scan_result_t initialization.
 *
 * This test verifies that the dm_scan_result_t constructor correctly processes and stores the maximum boundary values passed via an em_scan_result_t instance. The test creates an em_scan_result_t object with maximum allowed values for strings (net_id and timestamp), MAC addresses, and other numerical fields, then checks that the dm_scan_result_t object reflects these values accurately without throwing exceptions.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 011
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize an em_scan_result_t instance with maximum boundary values for net_id (127 'A's), timestamp (127 'T's), MAC addresses (dev_mac: {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF}, scanner_mac: {0xEE,0xEE,0xEE,0xEE,0xEE,0xEE}), op_class, channel, scanner_type, scan_status, util, noise, num_neighbors (0xFFFF), aggr_scan_duration (0xFFFFFFFF), and scan_type. Invoke the dm_scan_result_t constructor and verify that all fields are correctly copied and assertions pass. | input: net_id = 127 'A's, timestamp = 127 'T's; dev_mac = 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF; scanner_mac = 0xEE,0xEE,0xEE,0xEE,0xEE,0xEE; op_class = 255, channel = 255, scanner_type = [em_scanner_type_radio, em_scanner_type_sta], scan_status = 255; util = 255, noise = 255; num_neighbors = 0xFFFF; aggr_scan_duration = 0xFFFFFFFF; scan_type = 255 | Expected: dm_scan_result_t object initializes correctly with field values matching the input without throwing exceptions and all assertions pass | Should Pass |
 */
TEST(dm_scan_result_t_Test, MaximumBoundaryValues) {
    std::cout << "Entering MaximumBoundaryValues test" << std::endl;
    // Loop through both valid scanner types: em_scanner_type_radio and em_scanner_type_sta
    em_scanner_type_t validTypes[2] = { em_scanner_type_radio, em_scanner_type_sta };
    // Create a maximum string of length 127 for net_id and timestamp
    char maxNetId[128];
    char maxTimestamp[128];
    for (int i = 0; i < 127; i++) {
        maxNetId[i] = 'A';
        maxTimestamp[i] = 'T';
    }
    maxNetId[127] = '\0';
    maxTimestamp[127] = '\0';
    
    for (int i = 0; i < 2; i++) {
        em_scan_result_t scan_result{};
        std::cout << "Setting net_id to maximum boundary (127 chars)" << std::endl;
        strncpy(scan_result.id.net_id, maxNetId, sizeof(scan_result.id.net_id) - 1);
        
        // Set MAC addresses to maximum boundary values
        unsigned char dev_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
        unsigned char scanner_mac[6] = {0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE};
        std::cout << "Setting dev_mac to 0xFF and scanner_mac to 0xEE" << std::endl;
        for (int m = 0; m < 6; m++) {
            scan_result.id.dev_mac[m] = dev_mac[m];
            scan_result.id.scanner_mac[m] = scanner_mac[m];
        }
        
        scan_result.id.op_class = 255;
        scan_result.id.channel = 255;
        scan_result.id.scanner_type = validTypes[i];
        std::cout << "Setting op_class and channel to 255, scanner_type: " << int(validTypes[i]) << std::endl;
        
        scan_result.scan_status = 255;
        std::cout << "Setting scan_status to 255" << std::endl;
        strncpy(scan_result.timestamp, maxTimestamp, sizeof(scan_result.timestamp) - 1);
        std::cout << "Setting timestamp to maximum boundary string (127 chars)" << std::endl;
        
        scan_result.util = 255;
        scan_result.noise = 255;
        scan_result.num_neighbors = 0xFFFF;  // maximum unsigned short
        std::cout << "Setting util and noise to 255, num_neighbors to " << scan_result.num_neighbors << std::endl;
        scan_result.aggr_scan_duration = 0xFFFFFFFF;
        scan_result.scan_type = 255;
        std::cout << "Setting aggr_scan_duration to " << scan_result.aggr_scan_duration
                  << ", scan_type to 255" << std::endl;
        
        std::cout << "Invoking dm_scan_result_t(const em_scan_result_t&) constructor" << std::endl;
        EXPECT_NO_THROW({
            dm_scan_result_t dm_obj(scan_result);
            std::cout << "dm_obj.m_scan_result.id.net_id: " << dm_obj.m_scan_result.id.net_id << std::endl;
            std::cout << "dm_obj.m_scan_result.id.dev_mac: ";
            for (int m = 0; m < 6; m++)
                std::cout << std::hex << int(dm_obj.m_scan_result.id.dev_mac[m]) << " ";
            std::cout << std::dec << std::endl;
            std::cout << "dm_obj.m_scan_result.id.scanner_mac: ";
            for (int m = 0; m < 6; m++)
                std::cout << std::hex << int(dm_obj.m_scan_result.id.scanner_mac[m]) << " ";
            std::cout << std::dec << std::endl;
            std::cout << "dm_obj.m_scan_result.id.op_class: " << int(dm_obj.m_scan_result.id.op_class)
                      << ", channel: " << int(dm_obj.m_scan_result.id.channel)
                      << ", scanner_type: " << int(dm_obj.m_scan_result.id.scanner_type) << std::endl;
            std::cout << "dm_obj.m_scan_result.scan_status: " << int(dm_obj.m_scan_result.scan_status) << std::endl;
            std::cout << "dm_obj.m_scan_result.timestamp: " << dm_obj.m_scan_result.timestamp << std::endl;
            std::cout << "dm_obj.m_scan_result.util: " << int(dm_obj.m_scan_result.util)
                      << ", noise: " << int(dm_obj.m_scan_result.noise)
                      << ", num_neighbors: " << dm_obj.m_scan_result.num_neighbors << std::endl;
            std::cout << "dm_obj.m_scan_result.aggr_scan_duration: " << dm_obj.m_scan_result.aggr_scan_duration
                      << ", scan_type: " << int(dm_obj.m_scan_result.scan_type) << std::endl;
            
            EXPECT_STREQ(dm_obj.m_scan_result.id.net_id, maxNetId);
            for (int m = 0; m < 6; m++) {
                EXPECT_EQ(dm_obj.m_scan_result.id.dev_mac[m], dev_mac[m]);
                EXPECT_EQ(dm_obj.m_scan_result.id.scanner_mac[m], scanner_mac[m]);
            }
            EXPECT_EQ(dm_obj.m_scan_result.id.op_class, 255);
            EXPECT_EQ(dm_obj.m_scan_result.id.channel, 255);
            EXPECT_EQ(dm_obj.m_scan_result.id.scanner_type, validTypes[i]);
            EXPECT_EQ(dm_obj.m_scan_result.scan_status, 255);
            EXPECT_STREQ(dm_obj.m_scan_result.timestamp, maxTimestamp);
            EXPECT_EQ(dm_obj.m_scan_result.util, 255);
            EXPECT_EQ(dm_obj.m_scan_result.noise, 255);
            EXPECT_EQ(dm_obj.m_scan_result.num_neighbors, 0xFFFF);
            EXPECT_EQ(dm_obj.m_scan_result.aggr_scan_duration, 0xFFFFFFFFu);
            EXPECT_EQ(dm_obj.m_scan_result.scan_type, 255);
        });
    }
    std::cout << "Exiting MaximumBoundaryValues test" << std::endl;
}
/**
 * @brief Test the dm_scan_result_t construction with an invalid scanner type.
 *
 * This test verifies that the dm_scan_result_t constructor correctly processes an em_scan_result_t object
 * populated with an invalid scanner type (0, which is outside the defined enum values). The test ensures that
 * the object is constructed without throwing exceptions and that the stored scanner type remains invalid.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 012@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize em_scan_result_t with invalid scanner_type (0) and other parameters, then invoke dm_scan_result_t constructor. | netId = "InvalidEnumTest", dev_mac = 0x10,0x20,0x30,0x40,0x50,0x60, scanner_mac = 0x70,0x80,0x90,0xA0,0xB0,0xC0, op_class = 10, channel = 20, scanner_type = 0, scan_status = 1, timestamp = "2023-10-10T12:00:00Z", util = 30, noise = 3, num_neighbors = 1, aggr_scan_duration = 500, scan_type = 1 | dm_scan_result_t is constructed without throwing, and dm_obj.m_scan_result.id.scanner_type equals 0 | Should Pass |
 */
TEST(dm_scan_result_t_Test, InvalidScannerType) {
    std::cout << "Entering InvalidScannerType test" << std::endl;
    em_scan_result_t scan_result{};
    const char* netId = "InvalidEnumTest";
    std::cout << "Setting net_id: " << netId << std::endl;
    strncpy(scan_result.id.net_id, netId, sizeof(scan_result.id.net_id) - 1);
    
    unsigned char dev_mac[6] = {0x10, 0x20, 0x30, 0x40, 0x50, 0x60};
    unsigned char scanner_mac[6] = {0x70, 0x80, 0x90, 0xA0, 0xB0, 0xC0};
    std::cout << "Setting dev_mac: ";
    for (int m = 0; m < 6; m++) {
        scan_result.id.dev_mac[m] = dev_mac[m];
        std::cout << std::hex << int(dev_mac[m]) << " ";
    }
    std::cout << std::dec << std::endl;
    std::cout << "Setting scanner_mac: ";
    for (int m = 0; m < 6; m++) {
        scan_result.id.scanner_mac[m] = scanner_mac[m];
        std::cout << std::hex << int(scanner_mac[m]) << " ";
    }
    std::cout << std::dec << std::endl;
    
    scan_result.id.op_class = 10;
    scan_result.id.channel = 20;
    scan_result.id.scanner_type = static_cast<em_scanner_type_t>(0);
    std::cout << "Setting op_class: " << int(scan_result.id.op_class)
              << ", channel: " << int(scan_result.id.channel)
              << ", scanner_type (invalid): " << int(scan_result.id.scanner_type) << std::endl;
    
    scan_result.scan_status = 1;
    const char* timestamp = "2023-10-10T12:00:00Z";
    std::cout << "Setting scan_status: 1 and timestamp: " << timestamp << std::endl;
    strncpy(scan_result.timestamp, timestamp, sizeof(scan_result.timestamp) - 1);
    
    scan_result.util = 30;
    scan_result.noise = 3;
    scan_result.num_neighbors = 1;
    std::cout << "Setting util: " << int(scan_result.util)
              << ", noise: " << int(scan_result.noise)
              << ", num_neighbors: " << scan_result.num_neighbors << std::endl;
    scan_result.aggr_scan_duration = 500;
    scan_result.scan_type = 1;
    std::cout << "Setting aggr_scan_duration: " << scan_result.aggr_scan_duration
              << ", scan_type: " << int(scan_result.scan_type) << std::endl;
    
    std::cout << "Invoking dm_scan_result_t(const em_scan_result_t&) constructor" << std::endl;
    EXPECT_NO_THROW({
        dm_scan_result_t dm_obj(scan_result);
        std::cout << "dm_obj.m_scan_result.id.scanner_type: " << int(dm_obj.m_scan_result.id.scanner_type) << std::endl;
        EXPECT_EQ(dm_obj.m_scan_result.id.scanner_type, 0);
    });
    std::cout << "Exiting InvalidScannerType test" << std::endl;
}
/**
 * @brief Test that dm_scan_result_t constructor correctly handles scan_result structures with num_neighbors exceeding the allowed maximum.
 *
 * This test verifies that when a scan_result structure with num_neighbors set to EM_MAX_NEIGHBORS + 1 is passed to the dm_scan_result_t constructor,
 * the object is constructed without throwing an exception and retains the num_neighbors value as EM_MAX_NEIGHBORS + 1. The test loops over two valid scanner types.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 013@n
 * **Priority:** High@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * 
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Setup scan_result structure with fields: net_id, dev_mac, scanner_mac, op_class, channel, scanner_type, scan_status, timestamp, util, noise, num_neighbors (set to EM_MAX_NEIGHBORS+1), aggr_scan_duration, scan_type; then invoke dm_scan_result_t constructor and validate num_neighbors value. | netId = "ExceedNeighborsTest", dev_mac = 12,34,56,78,9A,BC, scanner_mac = DE,AD,BE,EF,FE,ED, op_class = 15, channel = 40, scanner_type = (em_scanner_type_radio, em_scanner_type_sta), scan_status = 2, timestamp = "2023-10-10T15:30:00Z", util = 40, noise = 4, num_neighbors = EM_MAX_NEIGHBORS+1, aggr_scan_duration = 750, scan_type = 2 | No exception thrown; dm_scan_result_t object's num_neighbors equals EM_MAX_NEIGHBORS+1 as asserted | Should Pass |
 */
TEST(dm_scan_result_t_Test, ExceedNeighbors) {
    std::cout << "Entering ExceedNeighbors test" << std::endl;
    // Loop through both valid scanner types for scanner_type field as specified
    em_scanner_type_t validTypes[2] = { em_scanner_type_radio, em_scanner_type_sta };
    for (int i = 0; i < 2; i++) {
        em_scan_result_t scan_result{};
        const char* netId = "ExceedNeighborsTest";
        std::cout << "Setting net_id: " << netId << std::endl;
        strncpy(scan_result.id.net_id, netId, sizeof(scan_result.id.net_id) - 1);
        
        unsigned char dev_mac[6] = {0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC};
        unsigned char scanner_mac[6] = {0xDE, 0xAD, 0xBE, 0xEF, 0xFE, 0xED};
        std::cout << "Setting dev_mac: ";
        for (int m = 0; m < 6; m++) {
            scan_result.id.dev_mac[m] = dev_mac[m];
            std::cout << std::hex << int(dev_mac[m]) << " ";
        }
        std::cout << std::dec << std::endl;
        std::cout << "Setting scanner_mac: ";
        for (int m = 0; m < 6; m++) {
            scan_result.id.scanner_mac[m] = scanner_mac[m];
            std::cout << std::hex << int(scanner_mac[m]) << " ";
        }
        std::cout << std::dec << std::endl;
        
        scan_result.id.op_class = 15;
        scan_result.id.channel = 40;
        scan_result.id.scanner_type = validTypes[i];
        std::cout << "Setting op_class: " << int(scan_result.id.op_class)
                  << ", channel: " << int(scan_result.id.channel)
                  << ", scanner_type: " << int(scan_result.id.scanner_type) << std::endl;
        
        scan_result.scan_status = 2;
        const char* timestamp = "2023-10-10T15:30:00Z";
        std::cout << "Setting scan_status: 2 and timestamp: " << timestamp << std::endl;
        strncpy(scan_result.timestamp, timestamp, sizeof(scan_result.timestamp) - 1);
        
        scan_result.util = 40;
        scan_result.noise = 4;
        // Setting num_neighbors to EM_MAX_NEIGHBORS + 1 (exceed the neighbor array size)
        scan_result.num_neighbors = EM_MAX_NEIGHBORS + 1;
        std::cout << "Setting util: " << int(scan_result.util)
                  << ", noise: " << int(scan_result.noise)
                  << ", num_neighbors (exceeding): " << scan_result.num_neighbors << std::endl;
        scan_result.aggr_scan_duration = 750;
        scan_result.scan_type = 2;
        std::cout << "Setting aggr_scan_duration: " << scan_result.aggr_scan_duration
                  << ", scan_type: " << int(scan_result.scan_type) << std::endl;
        
        std::cout << "Invoking dm_scan_result_t(const em_scan_result_t&) constructor" << std::endl;
        EXPECT_NO_THROW({
            dm_scan_result_t dm_obj(scan_result);
            std::cout << "dm_obj.m_scan_result.num_neighbors: " << dm_obj.m_scan_result.num_neighbors << std::endl;
            EXPECT_EQ(dm_obj.m_scan_result.num_neighbors, EM_MAX_NEIGHBORS + 1);
        });
    }
    std::cout << "Exiting ExceedNeighbors test" << std::endl;
}
/**
 * @brief Verify that dm_scan_result_t object is correctly constructed using a valid scan_result pointer.
 *
 * This test ensures that the dm_scan_result_t object initializes its internal m_scan_result member properly based on the provided em_scan_result_t structure with valid test data. It verifies that all assigned values such as net_id, MAC addresses, op_class, channel, scanner_type, scan_status, timestamp, util, noise, num_neighbors, aggr_scan_duration, and scan_type are correctly stored and can be retrieved as expected.
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
 * | Variation / Step | Description                                                                                                   | Test Data                                                                                                                                                                            | Expected Result                                                                                                                         | Notes      |
 * | :--------------: | ------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------- | ---------- |
 * | 01               | Invoke dm_scan_result_t constructor with a pointer to a fully initialized em_scan_result_t structure and verify all member fields. | input: valid_net_id = "ValidNetID", valid_dev_mac = 00,11,22,33,44,55, valid_scanner_mac = AA,BB,CC,DD,EE,FF, op_class = 1, channel = 6, scanner_type = em_scanner_type_radio, scan_status = 0, timestamp = "2023-10-10T12:00:00Z", util = 50, noise = 10, num_neighbors = 3, aggr_scan_duration = 100, scan_type = 1 | dm_scan_result_t object should be constructed successfully without any exception; all internal member values match the provided input values. | Should Pass |
 */
TEST(dm_scan_result_t_Test, ValidScanResult) {
    std::cout << "Entering ValidScanResult test" << std::endl;

    em_scan_result_t scan_result{};

    // Initialize id.net_id with "ValidNetID"
    const char valid_net_id[] = "ValidNetID";
    std::cout << "Setting id.net_id to " << valid_net_id << std::endl;
    strncpy(scan_result.id.net_id, valid_net_id, sizeof(scan_result.id.net_id));

    // Initialize dev_mac with valid MAC address bytes
    unsigned char valid_dev_mac[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    std::cout << "Setting id.dev_mac to valid MAC address bytes" << std::endl;
    memcpy(scan_result.id.dev_mac, valid_dev_mac, sizeof(valid_dev_mac));

    // Initialize scanner_mac with valid MAC address bytes
    unsigned char valid_scanner_mac[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    std::cout << "Setting id.scanner_mac to valid MAC address bytes" << std::endl;
    memcpy(scan_result.id.scanner_mac, valid_scanner_mac, sizeof(valid_scanner_mac));

    scan_result.id.op_class = 1;
    std::cout << "Setting id.op_class to " << static_cast<int>(scan_result.id.op_class) << std::endl;
    scan_result.id.channel = 6;
    std::cout << "Setting id.channel to " << static_cast<int>(scan_result.id.channel) << std::endl;
    scan_result.id.scanner_type = em_scanner_type_radio;
    std::cout << "Setting id.scanner_type to em_scanner_type_radio" << std::endl;

    scan_result.scan_status = 0;
    std::cout << "Setting scan_status to " << static_cast<int>(scan_result.scan_status) << std::endl;

    const char timestamp[] = "2023-10-10T12:00:00Z";
    std::cout << "Setting timestamp to " << timestamp << std::endl;
    strncpy(scan_result.timestamp, timestamp, sizeof(scan_result.timestamp));

    scan_result.util = 50;
    std::cout << "Setting util to " << static_cast<int>(scan_result.util) << std::endl;
    scan_result.noise = 10;
    std::cout << "Setting noise to " << static_cast<int>(scan_result.noise) << std::endl;
    scan_result.num_neighbors = 3;
    std::cout << "Setting num_neighbors to " << scan_result.num_neighbors << std::endl;

    // Initialize neighbor array (assuming EM_MAX_NEIGHBORS elements exist, fill with zero)
    std::cout << "Initializing neighbor array with default values" << std::endl;

    scan_result.aggr_scan_duration = 100;
    std::cout << "Setting aggr_scan_duration to " << scan_result.aggr_scan_duration << std::endl;
    scan_result.scan_type = 1;
    std::cout << "Setting scan_type to " << static_cast<int>(scan_result.scan_type) << std::endl;

    std::cout << "Invoking dm_scan_result_t constructor with valid scan_result pointer" << std::endl;
    EXPECT_NO_THROW({
        dm_scan_result_t obj(&scan_result);
        std::cout << "dm_scan_result_t object constructed successfully" << std::endl;

        // Debug logs for internal state of m_scan_result
        std::cout << "Retrieved m_scan_result.id.net_id: " << obj.m_scan_result.id.net_id << std::endl;
        EXPECT_STREQ(obj.m_scan_result.id.net_id, valid_net_id);

        std::cout << "Retrieved m_scan_result.id.op_class: " << static_cast<int>(obj.m_scan_result.id.op_class) << std::endl;
        EXPECT_EQ(obj.m_scan_result.id.op_class, 1);

        std::cout << "Retrieved m_scan_result.id.channel: " << static_cast<int>(obj.m_scan_result.id.channel) << std::endl;
        EXPECT_EQ(obj.m_scan_result.id.channel, 6);

        std::cout << "Retrieved m_scan_result.id.scanner_type: " << static_cast<int>(obj.m_scan_result.id.scanner_type) << std::endl;
        EXPECT_EQ(obj.m_scan_result.id.scanner_type, em_scanner_type_radio);

        std::cout << "Retrieved m_scan_result.scan_status: " << static_cast<int>(obj.m_scan_result.scan_status) << std::endl;
        EXPECT_EQ(obj.m_scan_result.scan_status, 0);

        std::cout << "Retrieved m_scan_result.timestamp: " << obj.m_scan_result.timestamp << std::endl;
        EXPECT_STREQ(obj.m_scan_result.timestamp, timestamp);

        std::cout << "Retrieved m_scan_result.util: " << static_cast<int>(obj.m_scan_result.util) << std::endl;
        EXPECT_EQ(obj.m_scan_result.util, 50);

        std::cout << "Retrieved m_scan_result.noise: " << static_cast<int>(obj.m_scan_result.noise) << std::endl;
        EXPECT_EQ(obj.m_scan_result.noise, 10);

        std::cout << "Retrieved m_scan_result.num_neighbors: " << obj.m_scan_result.num_neighbors << std::endl;
        EXPECT_EQ(obj.m_scan_result.num_neighbors, 3);

        std::cout << "Retrieved m_scan_result.aggr_scan_duration: " << obj.m_scan_result.aggr_scan_duration << std::endl;
        EXPECT_EQ(obj.m_scan_result.aggr_scan_duration, 100);

        std::cout << "Retrieved m_scan_result.scan_type: " << static_cast<int>(obj.m_scan_result.scan_type) << std::endl;
        EXPECT_EQ(obj.m_scan_result.scan_type, 1);
    });

    std::cout << "Exiting ValidScanResult test" << std::endl;
}
/**
 * @brief Verify that the dm_scan_result_t constructor handles a NULL scan_result pointer correctly.
 *
 * This test verifies that the dm_scan_result_t constructor does not throw any exceptions when invoked with a NULL scan_result pointer. It ensures that the object is constructed gracefully even with an invalid pointer input, thus testing the robustness of the error handling.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 015@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                       | Test Data                                  | Expected Result                                                       | Notes      |
 * | :----:           | ----------------------------------------------------------------- | ------------------------------------------ | --------------------------------------------------------------------- | ---------- |
 * | 01               | Invoke dm_scan_result_t constructor with a NULL scan_result pointer | input: scan_result = nullptr               | No exception thrown; object constructed successfully (EXPECT_NO_THROW) | Should Pass |
 */
TEST(dm_scan_result_t_Test, NullScanResult) {
    std::cout << "Entering NullScanResult test" << std::endl;

    std::cout << "Invoking dm_scan_result_t constructor with NULL scan_result pointer" << std::endl;
    EXPECT_NO_THROW({
        dm_scan_result_t obj(nullptr);
        std::cout << "dm_scan_result_t object constructed with NULL pointer" << std::endl;
    });

    std::cout << "Exiting NullScanResult test" << std::endl;
}
/**
 * @brief Validate dm_scan_result_t construction with boundary long string values.
 *
 * This test verifies that the dm_scan_result_t constructor can correctly handle scan result structures
 * where the id.net_id and timestamp fields are set to boundary strings of exactly 128 characters. It ensures that the
 * string copying operations using strncpy maintain their integrity without buffer overflow and that the object is constructed
 * without throwing exceptions.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 016@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Log entry indicating the start of the test | None | "Entering BoundaryLongStrings test" log printed | Should be successful |
 * | 02 | Create a boundary string of exactly 128 characters filled with 'B' | Boundary string = 128 characters ('B' repeated, terminated with '\0') | Boundary string is correctly constructed | Should be successful |
 * | 03 | Copy the boundary string to scan_result.id.net_id using strncpy | net_id = boundary string | id.net_id is set with boundary string | Should Pass |
 * | 04 | Copy the boundary string to scan_result.timestamp using strncpy | timestamp = boundary string | timestamp is set with boundary string | Should Pass |
 * | 05 | Fill remaining fields of scan_result with valid values (net_id, MAC addresses, op_class, channel, etc.) | valid_net_id = "BoundaryTest", valid_dev_mac = 0x10,0x20,0x30,0x40,0x50,0x60, valid_scanner_mac = 0xF0,0xE0,0xD0,0xC0,0xB0,0xA0, op_class = 2, channel = 11, scanner_type = em_scanner_type_sta, scan_status = 1, util = 75, noise = 20, num_neighbors = 2, aggr_scan_duration = 200, scan_type = 2 | All fields are set correctly in the scan_result structure | Should Pass |
 * | 06 | Invoke dm_scan_result_t constructor within an EXPECT_NO_THROW block | dm_scan_result_t constructor called with pointer to scan_result | Constructor completes without throwing exception and logs successful construction | Should Pass |
 * | 07 | Verify that m_scan_result.id.net_id matches the boundary string using EXPECT_STREQ | output: m_scan_result.id.net_id, expected = boundary string | m_scan_result.id.net_id equals the boundary string | Should Pass |
 * | 08 | Verify that m_scan_result.timestamp matches the boundary string using EXPECT_STREQ | output: m_scan_result.timestamp, expected = boundary string | m_scan_result.timestamp equals the boundary string | Should Pass |
 * | 09 | Log exit of the test | None | "Exiting BoundaryLongStrings test" log printed | Should be successful |
 */
TEST(dm_scan_result_t_Test, BoundaryLongStrings) {
    std::cout << "Entering BoundaryLongStrings test" << std::endl;

    em_scan_result_t scan_result{};

    // Create a boundary string of exactly 128 characters.
    char boundary_string[128];
    for (int i = 0; i < 127; i++) {
        boundary_string[i] = 'B';
    }
    boundary_string[127] = '\0';

    std::cout << "Setting id.net_id to boundary string of length 128" << std::endl;
    strncpy(scan_result.id.net_id, boundary_string, sizeof(scan_result.id.net_id));
    std::cout << "Setting timestamp to boundary string of length 128" << std::endl;
    strncpy(scan_result.timestamp, boundary_string, sizeof(scan_result.timestamp));

    // Fill other fields with valid values.
    unsigned char valid_dev_mac[6] = {0x10, 0x20, 0x30, 0x40, 0x50, 0x60};
    memcpy(scan_result.id.dev_mac, valid_dev_mac, sizeof(valid_dev_mac));
    unsigned char valid_scanner_mac[6] = {0xF0, 0xE0, 0xD0, 0xC0, 0xB0, 0xA0};
    memcpy(scan_result.id.scanner_mac, valid_scanner_mac, sizeof(valid_scanner_mac));

    scan_result.id.op_class = 2;
    scan_result.id.channel = 11;
    scan_result.id.scanner_type = em_scanner_type_sta;
    scan_result.scan_status = 1;
    scan_result.util = 75;
    scan_result.noise = 20;
    scan_result.num_neighbors = 2;
    scan_result.aggr_scan_duration = 200;
    scan_result.scan_type = 2;

    std::cout << "Invoking dm_scan_result_t constructor with boundary long string values" << std::endl;
    EXPECT_NO_THROW({
        dm_scan_result_t obj(&scan_result);
        std::cout << "dm_scan_result_t object constructed successfully" << std::endl;

        std::cout << "Retrieved m_scan_result.id.net_id: " << obj.m_scan_result.id.net_id << std::endl;
        EXPECT_STREQ(obj.m_scan_result.id.net_id, boundary_string);

        std::cout << "Retrieved m_scan_result.timestamp: " << obj.m_scan_result.timestamp << std::endl;
        EXPECT_STREQ(obj.m_scan_result.timestamp, boundary_string);
    });

    std::cout << "Exiting BoundaryLongStrings test" << std::endl;
}
/**
 * @brief Validate dm_scan_result_t object construction with em_scanner_type_radio
 *
 * This test verifies that when a properly initialized em_scan_result_t structure is used, the dm_scan_result_t constructor
 * initializes the object without throwing an exception and sets the scanner_type to em_scanner_type_radio as expected.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 017@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize scan_result with valid parameters including net_id "RadioTest", dev_mac [0x01, 0x02, 0x03, 0x04, 0x05, 0x06], scanner_mac [0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F], op_class=3, channel=7, scanner_type=em_scanner_type_radio, timestamp "2023-11-11T11:11:11Z", util=60, noise=15, num_neighbors=4, aggr_scan_duration=150, scan_type=3 | net_id = RadioTest, dev_mac = 0x01,0x02,0x03,0x04,0x05,0x06, scanner_mac = 0x0A,0x0B,0x0C,0x0D,0x0E,0x0F, op_class = 3, channel = 7, scanner_type = em_scanner_type_radio, timestamp = 2023-11-11T11:11:11Z, util = 60, noise = 15, num_neighbors = 4, aggr_scan_duration = 150, scan_type = 3 | scan_result structure is correctly initialized | Should be successful |
 * | 02 | Invoke dm_scan_result_t constructor with the initialized scan_result and verify that m_scan_result.id.scanner_type equals em_scanner_type_radio | scan_result pointer to initialized structure | Constructor does not throw and m_scan_result.id.scanner_type equals em_scanner_type_radio | Should Pass |
 */
TEST(dm_scan_result_t_Test, ScannerTypeEnumRadio) {
    std::cout << "Entering ScannerTypeEnumRadio test" << std::endl;

    em_scan_result_t scan_result{};

    // Initialize necessary fields with valid data.
    const char valid_net_id[] = "RadioTest";
    std::cout << "Setting id.net_id to " << valid_net_id << std::endl;
    strncpy(scan_result.id.net_id, valid_net_id, sizeof(scan_result.id.net_id));

    unsigned char valid_dev_mac[6] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
    memcpy(scan_result.id.dev_mac, valid_dev_mac, sizeof(valid_dev_mac));
    unsigned char valid_scanner_mac[6] = {0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
    memcpy(scan_result.id.scanner_mac, valid_scanner_mac, sizeof(valid_scanner_mac));

    scan_result.id.op_class = 3;
    scan_result.id.channel = 7;
    scan_result.id.scanner_type = em_scanner_type_radio;
    std::cout << "Setting id.scanner_type to em_scanner_type_radio" << std::endl;

    scan_result.scan_status = 2;
    const char timestamp[] = "2023-11-11T11:11:11Z";
    strncpy(scan_result.timestamp, timestamp, sizeof(scan_result.timestamp));
    scan_result.util = 60;
    scan_result.noise = 15;
    scan_result.num_neighbors = 4;
    scan_result.aggr_scan_duration = 150;
    scan_result.scan_type = 3;

    std::cout << "Invoking dm_scan_result_t constructor with em_scanner_type_radio" << std::endl;
    EXPECT_NO_THROW({
        dm_scan_result_t obj(&scan_result);
        std::cout << "dm_scan_result_t object constructed successfully" << std::endl;

        std::cout << "Retrieved m_scan_result.id.scanner_type: " << static_cast<int>(obj.m_scan_result.id.scanner_type) << std::endl;
        EXPECT_EQ(obj.m_scan_result.id.scanner_type, em_scanner_type_radio);
    });

    std::cout << "Exiting ScannerTypeEnumRadio test" << std::endl;
}
/**
 * @brief Test for verifying that a dm_scan_result_t object constructed with a Station scanner type initializes the scanner type correctly.
 *
 * This test initializes an em_scan_result_t structure with valid data representing a Station (STA) type scan result, including setting fields such as net_id, dev_mac, scanner_mac, and others. The test then constructs a dm_scan_result_t object to ensure that its m_scan_result.id.scanner_type field is correctly set to em_scanner_type_sta. This confirms that the constructor properly assigns the scanner type from a valid scan result.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 018@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * |01|Initialize the em_scan_result_t structure with valid STA scan data including net_id, dev_mac, scanner_mac, op_class, channel, scanner_type, scan_status, timestamp, util, noise, num_neighbors, aggr_scan_duration, and scan_type|input: net_id = "StaTest", dev_mac = {0x11,0x12,0x13,0x14,0x15,0x16}, scanner_mac = {0x1A,0x1B,0x1C,0x1D,0x1E,0x1F}, op_class = 4, channel = 8, scanner_type = em_scanner_type_sta, scan_status = 3, timestamp = "2023-12-12T12:12:12Z", util = 65, noise = 18, num_neighbors = 5, aggr_scan_duration = 180, scan_type = 4 | The em_scan_result_t structure is correctly populated with the provided data | Should be successful |
 * |02|Invoke the dm_scan_result_t constructor using the initialized scan_result structure|input: pointer to the initialized em_scan_result_t structure | dm_scan_result_t object is constructed without throwing an exception | Should Pass |
 * |03|Verify that the m_scan_result.id.scanner_type in the constructed object is equal to em_scanner_type_sta using an assertion|input: m_scan_result.id.scanner_type from dm_scan_result_t object, expected = em_scanner_type_sta | The assertion (EXPECT_EQ) passes confirming the scanner type is correctly set | Should Pass |
 */
TEST(dm_scan_result_t_Test, ScannerTypeEnumSta) {
    std::cout << "Entering ScannerTypeEnumSta test" << std::endl;

    em_scan_result_t scan_result{};

    // Initialize necessary fields with valid data.
    const char valid_net_id[] = "StaTest";
    std::cout << "Setting id.net_id to " << valid_net_id << std::endl;
    strncpy(scan_result.id.net_id, valid_net_id, sizeof(scan_result.id.net_id));

    unsigned char valid_dev_mac[6] = {0x11, 0x12, 0x13, 0x14, 0x15, 0x16};
    memcpy(scan_result.id.dev_mac, valid_dev_mac, sizeof(valid_dev_mac));
    unsigned char valid_scanner_mac[6] = {0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F};
    memcpy(scan_result.id.scanner_mac, valid_scanner_mac, sizeof(valid_scanner_mac));

    scan_result.id.op_class = 4;
    scan_result.id.channel = 8;
    scan_result.id.scanner_type = em_scanner_type_sta;
    std::cout << "Setting id.scanner_type to em_scanner_type_sta" << std::endl;

    scan_result.scan_status = 3;
    const char timestamp[] = "2023-12-12T12:12:12Z";
    strncpy(scan_result.timestamp, timestamp, sizeof(scan_result.timestamp));
    scan_result.util = 65;
    scan_result.noise = 18;
    scan_result.num_neighbors = 5;
    scan_result.aggr_scan_duration = 180;
    scan_result.scan_type = 4;

    std::cout << "Invoking dm_scan_result_t constructor with em_scanner_type_sta" << std::endl;
    EXPECT_NO_THROW({
        dm_scan_result_t obj(&scan_result);
        std::cout << "dm_scan_result_t object constructed successfully" << std::endl;

        std::cout << "Retrieved m_scan_result.id.scanner_type: " << static_cast<int>(obj.m_scan_result.id.scanner_type) << std::endl;
        EXPECT_EQ(obj.m_scan_result.id.scanner_type, em_scanner_type_sta);
    });

    std::cout << "Exiting ScannerTypeEnumSta test" << std::endl;
}
/**
 * @brief Verify proper CJSON encoding in dm_scan_result_t::encode
 *
 * This test verifies that a properly initialized cJSON object is correctly encoded using the dm_scan_result_t::encode method. It checks that no exceptions are thrown during instantiation and encoding, and that the resulting cJSON object can be printed to a string.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 019@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                                  | Test Data                                                                | Expected Result                                                                                   | Notes           |
 * | :--------------: | -------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------- | --------------- |
 * | 01               | Initialize a cJSON object using cJSON_CreateObject()                                         | No input arguments; output: obj pointer                                  | A non-null cJSON pointer is returned                                                              | Should be successful |
 * | 02               | Create dm_scan_result_t instance using the default constructor                               | No input arguments; output: instance created with default values         | Instance is created without throwing exceptions                                                 | Should be successful |
 * | 03               | Invoke encode method on dm_scan_result_t instance with the created cJSON object                | input: obj = pointer value; method: encode(obj)                           | The encode method executes without throwing exceptions and properly encodes the cJSON object      | Should Pass     |
 * | 04               | Retrieve and free the printed string representation of the modified cJSON object               | input: obj pointer; invocation: cJSON_Print(obj), then free(printed)       | A correct string representation is generated and memory is freed without issues                   | Should be successful |
 */
TEST(dm_scan_result_t_Test, ValidCJSONEncoding) {
    std::cout << "Entering ValidCJSONEncoding test" << std::endl;

    cJSON *obj = cJSON_CreateObject();
    std::cout << "Created cJSON object at address: " << obj << std::endl;

    EXPECT_NO_THROW({
        dm_scan_result_t instance{};
        std::cout << "Created dm_scan_result_t instance using default constructor" << std::endl;

        std::cout << "Invoking encode with cJSON object address: " << obj << std::endl;
        EXPECT_NO_THROW(instance.encode(obj));
        std::cout << "encode method invoked successfully" << std::endl;

        char *printed = cJSON_Print(obj);
        std::cout << "Encoded cJSON object: " << printed << std::endl;
        free(printed);
    });

    cJSON_Delete(obj);
    obj = nullptr;

    std::cout << "Exiting ValidCJSONEncoding test" << std::endl;
}

/**
 * @brief Test for encoding behavior of dm_scan_result_t with a NULL cJSON pointer
 *
 * This test verifies that the dm_scan_result_t::encode method can gracefully handle being passed a NULL pointer. 
 * It ensures that the default constructor creates an instance successfully and that the encode method does not throw an exception when provided with a NULL cJSON pointer.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 020@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                       | Test Data                                                       | Expected Result                                                                | Notes         |
 * | :--------------: | ----------------------------------------------------------------- | --------------------------------------------------------------- | ------------------------------------------------------------------------------ | ------------- |
 * | 01               | Create an instance of dm_scan_result_t using the default constructor | No input, Output: instance of dm_scan_result_t successfully created | Instance is created without exceptions and is valid                             | Should be successful |
 * | 02               | Invoke encode method with NULL pointer                            | input: NULL, instance: created dm_scan_result_t, output: void      | encode method should handle NULL pointer gracefully without throwing exceptions | Should Pass   |
 */
TEST(dm_scan_result_t_Test, NullCJSONPointerEncoding) {
    std::cout << "Entering NullCJSONPointerEncoding test" << std::endl;
    
    // Create an instance of dm_scan_result_t using the default constructor
    EXPECT_NO_THROW({
        dm_scan_result_t instance{};
        std::cout << "Created dm_scan_result_t instance using default constructor" << std::endl;
        
        // Log the invocation of encode method with NULL pointer
        std::cout << "Invoking encode with NULL cJSON pointer" << std::endl;
        EXPECT_NO_THROW(instance.encode(NULL));
        std::cout << "encode method handled NULL pointer gracefully" << std::endl;
    });
    
    std::cout << "Exiting NullCJSONPointerEncoding test" << std::endl;
}
/**
 * @brief Verify that dm_scan_result_t::encode correctly handles an empty cJSON object.
 *
 * This test validates that an instance of dm_scan_result_t can be properly used to encode an empty but correctly initialized cJSON object. The test ensures that no exceptions are thrown when constructing the instance and invoking the encode method. It also verifies that the cJSON object is appropriately modified by the encode process.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 021@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                 | Test Data                                                    | Expected Result                                                               | Notes           |
 * | :--------------: | --------------------------------------------------------------------------- | ------------------------------------------------------------ | ----------------------------------------------------------------------------- | --------------- |
 * | 01               | Create an empty cJSON object using cJSON_CreateObject                       | No input, output: obj pointer returned from cJSON_CreateObject | Returns a valid cJSON pointer                                                 | Should be successful |
 * | 02               | Instantiate dm_scan_result_t using the default constructor                  | No input, output: instance of dm_scan_result_t               | Instance is created without throwing any exceptions                         | Should Pass     |
 * | 03               | Invoke the encode() method on dm_scan_result_t instance with the empty cJSON | input: obj pointer with empty cJSON, output: none              | Method completes without throwing exceptions                                  | Should Pass     |
 * | 04               | Retrieve and log the modified cJSON object after encoding                   | input: obj pointer, output: printed JSON string from cJSON_Print | Encoded JSON string correctly represents the encoded dm_scan_result_t data    | Should be successful |
 */
TEST(dm_scan_result_t_Test, EmptyCJSONEncoding) {
    std::cout << "Entering EmptyCJSONEncoding test" << std::endl;

    cJSON *obj = cJSON_CreateObject();
    std::cout << "Created empty cJSON object at address: " << obj << std::endl;

    EXPECT_NO_THROW({
        dm_scan_result_t instance{};
        std::cout << "Created dm_scan_result_t instance using default constructor" << std::endl;

        std::cout << "Invoking encode with empty cJSON object" << std::endl;
        EXPECT_NO_THROW(instance.encode(obj));
        std::cout << "encode method invoked successfully on empty cJSON object" << std::endl;

        char *printed = cJSON_Print(obj);
        if (printed) {
            std::cout << "After encoding, cJSON object: " << printed << std::endl;
            free(printed);
        }
    });

    if (obj) {
        cJSON_Delete(obj);
        obj = nullptr;
    }

    std::cout << "Exiting EmptyCJSONEncoding test" << std::endl;
}

/**
 * @brief Validate that dm_scan_result_t::encode successfully encodes additional information into a cJSON object that already contains pre-existing data.
 *
 * This test creates a cJSON object and preloads it with a key-value pair simulating pre-existing data. It then constructs a dm_scan_result_t instance and invokes its encode method to add extra information to the same cJSON object. The objective is to ensure that the encode operation does not interfere with or overwrite the pre-existing data while executing without throwing any exceptions.
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
 * | Variation / Step | Description | Test Data | Expected Result | Notes |@n
 * | :----: | --------- | ---------- |-------------- | ----- |@n
 * | 01 | Create a cJSON object and add pre-existing data using a key and value | Input: preKey = "preexisting_key", preValue = "preexisting_value", buffer size = 32 | cJSON object created with the pre-existing key-value pair | Should be successful |@n
 * | 02 | Print the cJSON object before encoding to verify initial state | Input: cJSON object from step 01 | Correct output showing the pre-existing data | Should be successful |@n
 * | 03 | Create a dm_scan_result_t instance and invoke its encode method on the cJSON object | Input: dm_scan_result_t instance, cJSON object with pre-existing data | Method executes without throwing an exception and updates the cJSON object as expected | Should Pass |@n
 * | 04 | Print the cJSON object after encoding to log the modified content | Input: cJSON object updated by encode method | Correct output reflecting both pre-existing and newly encoded data | Should be successful |
 */
TEST(dm_scan_result_t_Test, PreExistingDataEncoding) {
    std::cout << "Entering PreExistingDataEncoding test" << std::endl;

    // Create a properly initialized cJSON object and add some pre-existing data
    cJSON *obj = cJSON_CreateObject();
    std::cout << "Created cJSON object at address: " << obj << std::endl;

    const char *preKey = "preexisting_key";
    const char *preValue = "preexisting_value";
    char buffer[32];
    strncpy(buffer, preValue, sizeof(buffer)-1);
    cJSON_AddStringToObject(obj, preKey, buffer);

    char *beforePrint = cJSON_Print(obj);
    std::cout << "cJSON object before encoding: " << beforePrint << std::endl;
    free(beforePrint);

    EXPECT_NO_THROW({
        dm_scan_result_t instance{};
        EXPECT_NO_THROW(instance.encode(obj));
    });

    char *afterPrint = cJSON_Print(obj);
    std::cout << "cJSON object after encoding: " << afterPrint << std::endl;
    free(afterPrint);

    if (obj) {
        cJSON_Delete(obj);
        obj = nullptr;
    }

    std::cout << "Exiting PreExistingDataEncoding test" << std::endl;
}

/**
 * @brief Verify that get_scan_result() returns a valid pointer.
 *
 * This test case creates an instance of dm_scan_result_t using the default constructor and invokes the get_scan_result() method. It then verifies that the returned pointer is not null and logs key information from the retrieved scan result, including net_id and scan_status. This is essential to ensure that the scan result pointer retrieval procedure functions correctly.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 023@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Create dm_scan_result_t object using the default constructor. | No input parameters, output object instance created. | Object instance is created successfully. | Should be successful |
 * | 02 | Invoke get_scan_result() method to retrieve scan result pointer. | Object instance, method call: get_scan_result() | Returns a pointer of type em_scan_result_t* which is expected to be non-null. | Should Pass |
 * | 03 | Validate that the scan result pointer is not null. | Input: pointer value returned from get_scan_result(). | The pointer is confirmed as non-null. | Should Pass |
 * | 04 | Log key scan result information (net_id and scan_status). | Input: pointer content containing net_id and scan_status. | Correct scan result data is retrieved and logged. | Should be successful |
 */
TEST(dm_scan_result_t_Test, Retrieve_Scan_Result_Pointer_Successfully) {
    std::cout << "Entering Retrieve_Scan_Result_Pointer_Successfully test" << std::endl;
    
    EXPECT_NO_THROW({
        // Create object using default constructor
        dm_scan_result_t obj{};
        std::cout << "Created dm_scan_result_t object using default constructor." << std::endl;
        
        // Invoke get_scan_result() method and log the action
        em_scan_result_t* scanResult = obj.get_scan_result();
        std::cout << "Invoked get_scan_result(); pointer obtained: " << scanResult << std::endl;
        
        // Check that the returned pointer is not null
        EXPECT_NE(scanResult, nullptr);
        
        // Log key scan_result information retrieval: net_id and scan_status
        std::cout << "Retrieved net_id from scan_result: " << scanResult->id.net_id << std::endl;
        std::cout << "Retrieved scan_status from scan_result: " 
                  << static_cast<int>(scanResult->scan_status) << std::endl;
    });
    
    std::cout << "Exiting Retrieve_Scan_Result_Pointer_Successfully test" << std::endl;
}
/**
 * @brief Verify that modifying the scan result via the retrieved pointer reflects correctly in the object's state
 *
 * This test creates a dm_scan_result_t object, retrieves the scan_result pointer, modifies its scan_status field,
 * and then verifies that the change is reflected when the pointer is retrieved again.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 024@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                     | Test Data                                             | Expected Result                                               | Notes            |
 * | :--------------: | --------------------------------------------------------------- | ----------------------------------------------------- | ------------------------------------------------------------- | ---------------- |
 * | 01               | Create a dm_scan_result_t object using default constructor      | None                                                  | Object is created successfully                                | Should be successful |
 * | 02               | Invoke get_scan_result() to retrieve the scan result pointer      | Function call: get_scan_result()                      | A valid pointer to em_scan_result_t is returned               | Should be successful |
 * | 03               | Modify the scan_status field via the retrieved pointer            | newStatus = 99, pointer->scan_status set to 99         | The scan_status field is updated to 99                        | Should Pass      |
 * | 04               | Retrieve the scan_result pointer again and verify the modification | Function call: get_scan_result(), check scan_status = 99 | The scan_status field equals 99 ensuring modification is reflected | Should Pass      |
 */
TEST(dm_scan_result_t_Test, Modify_Scan_Result_Through_Retrieved_Pointer) {
    std::cout << "Entering Modify_Scan_Result_Through_Retrieved_Pointer test" << std::endl;
    
    // Create object using default constructor
    dm_scan_result_t obj{};
    std::cout << "Created dm_scan_result_t object using default constructor." << std::endl;
    
    // Retrieve the scan result pointer
    em_scan_result_t* scanResult = obj.get_scan_result();
    std::cout << "Invoked get_scan_result(); pointer obtained: " << scanResult << std::endl;
    
    // Modify the scan_status field via retrieved pointer and log the modification
    unsigned char newStatus = 99;
    scanResult->scan_status = newStatus;
    std::cout << "Modified scan_result's scan_status to value: " << static_cast<int>(newStatus) << std::endl;
    
    // Retrieve the pointer again to check if modification is reflected
    em_scan_result_t* scanResultAfterModification = obj.get_scan_result();
    std::cout << "Re-invoked get_scan_result(); pointer obtained: " << scanResultAfterModification << std::endl;
    std::cout << "Retrieved scan_status from scan_result after modification: " 
              << static_cast<int>(scanResultAfterModification->scan_status) << std::endl;
    
    EXPECT_EQ(scanResultAfterModification->scan_status, newStatus);
    
    std::cout << "Exiting Modify_Scan_Result_Through_Retrieved_Pointer test" << std::endl;
}
/**
 * @brief Validate the deep copy behavior in dm_scan_result_t constructor
 *
 * This test verifies that when a dm_scan_result_t object is constructed using an external pointer to an em_scan_result_t structure, 
 * the internal scan result pointer is allocated separately and the values from the external structure are correctly copied over.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 025
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Log the entry message indicating the start of the test | No input values | Console outputs the entry message | Should be successful |
 * | 02 | Initialize externalScanResult, assign net_id using strncpy | input: testNetId = "ExternalNetworkID", externalScanResult.id.net_id updated to "ExternalNetworkID" | externalScanResult.id.net_id equals "ExternalNetworkID" | Should be successful |
 * | 03 | Set externalScanResult.scan_status to 42 | input: scan_status = 42 | externalScanResult.scan_status equals 42 | Should be successful |
 * | 04 | Construct dm_scan_result_t using the pointer to externalScanResult | input: externalScanResult pointer | Object constructed; internal scan result pointer allocated | Should Pass |
 * | 05 | Retrieve the internal scan result pointer via get_scan_result() | function call: obj.get_scan_result() | internalScanResult is not the same as externalScanResult pointer | Should Pass |
 * | 06 | Compare internal scan result values with external values | inputs: internalScanResult->id.net_id, externalScanResult.id.net_id, internalScanResult->scan_status, externalScanResult.scan_status | EXPECT_STREQ confirms net_id and EXPECT_EQ confirms scan_status match; test assertions pass | Should Pass |
 */
TEST(dm_scan_result_t_Test, Validate_Internal_Member_Usage_On_Constructor_With_External_Pointer) {
    std::cout << "Entering Validate_Internal_Member_Usage_On_Constructor_With_External_Pointer test" << std::endl;
    
    // Create an external scan_result structure and assign test values using strncpy
    em_scan_result_t externalScanResult{};
    const char* testNetId = "ExternalNetworkID";
    std::cout << "Assigning external scan_result net_id value: " << testNetId << std::endl;
    strncpy(externalScanResult.id.net_id, testNetId, sizeof(externalScanResult.id.net_id));
    
    externalScanResult.scan_status = 42;
    std::cout << "Assigning external scan_result scan_status value: " 
              << static_cast<int>(externalScanResult.scan_status) << std::endl;
    
    // Construct dm_scan_result_t using the external pointer
    dm_scan_result_t obj(&externalScanResult);
    std::cout << "Created dm_scan_result_t object using constructor with external pointer." << std::endl;
    
    // Retrieve the internal scan result pointer
    em_scan_result_t* internalScanResult = obj.get_scan_result();
    std::cout << "Invoked get_scan_result(); internal pointer obtained: " << internalScanResult << std::endl;
    
    // Validate that the returned pointer is not the same as the externalScanResult pointer
    EXPECT_NE(internalScanResult, &externalScanResult);
    std::cout << "Confirmed that the internal scan_result pointer is different from the external pointer." << std::endl;
    
    // Check that the internal scan result values match those from the external scan result
    std::cout << "Internal net_id: " << internalScanResult->id.net_id 
              << " | External net_id: " << externalScanResult.id.net_id << std::endl;
    std::cout << "Internal scan_status: " << static_cast<int>(internalScanResult->scan_status) 
              << " | External scan_status: " << static_cast<int>(externalScanResult.scan_status) << std::endl;
    
    EXPECT_STREQ(internalScanResult->id.net_id, externalScanResult.id.net_id);
    EXPECT_EQ(internalScanResult->scan_status, externalScanResult.scan_status);
    
    std::cout << "Exiting Validate_Internal_Member_Usage_On_Constructor_With_External_Pointer test" << std::endl;
}
/**
 * @brief Verify that invoking get_scan_result() on a null dm_scan_result_t instance causes a crash.
 *
 * This test ensures that calling the get_scan_result() method on a null pointer instance of dm_scan_result_t
 * leads to a crash as expected. It uses EXPECT_DEATH to validate that the application terminates (undefined behavior)
 * when the method is invoked on a null object, which is vital for detecting incorrect object instance handling.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 026@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                           | Test Data                                                          | Expected Result                                                              | Notes        |
 * | :--------------: | --------------------------------------------------------------------- | ------------------------------------------------------------------ | ---------------------------------------------------------------------------- | ------------ |
 * | 01               | Create a null dm_scan_result_t pointer and invoke get_scan_result() on it | nullObj = nullptr, invocation of get_scan_result()                   | Program crashes as expected as validated by EXPECT_DEATH with regex ".*"       | Should Pass  |
 */
TEST(dm_scan_result_t_Test, Null_Object_Instance_Invocation) {
    std::cout << "Entering Null_Object_Instance_Invocation test" << std::endl;
    
    // Create a null pointer for dm_scan_result_t
    dm_scan_result_t* nullObj = nullptr;
    std::cout << "Created a null dm_scan_result_t pointer." << std::endl;
    
    // Expect the invocation to result in a crash (undefined behavior) using EXPECT_DEATH
    EXPECT_DEATH({
        // Attempt to call get_scan_result() on the null object
        std::cout << "Invoking get_scan_result() on a null dm_scan_result_t instance." << std::endl;
        nullObj->get_scan_result();
    }, ".*");
    
    std::cout << "Exiting Null_Object_Instance_Invocation test" << std::endl;
}
/**
 * @brief Verify that has_same_id returns true when all fields are identical.
 *
 * This test creates an instance of dm_scan_result_t and initializes an em_scan_result_id_t
 * structure with matching values for all its fields, including net_id, dev_mac, scanner_mac,
 * op_class, channel, and scanner_type. The test then invokes has_same_id and asserts that it returns true,
 * confirming the correct behavior of the comparison logic.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 027@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Create dm_scan_result_t object using default constructor and verify no exception is thrown | No input; dm_scan_result_t constructor invoked | Object constructed successfully without throwing an exception | Should Pass |
 * | 02 | Initialize net_id field of em_scan_result_id_t with "TEST_NET" | id.net_id = "TEST_NET" | net_id field correctly set to "TEST_NET" | Should be successful |
 * | 03 | Set dev_mac field values to [0x01, 0x02, 0x03, 0x04, 0x05, 0x06] | id.dev_mac = 0x01,0x02,0x03,0x04,0x05,0x06 | dev_mac array set with expected values | Should be successful |
 * | 04 | Set scanner_mac field values to [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF] | id.scanner_mac = 0xAA,0xBB,0xCC,0xDD,0xEE,0xFF | scanner_mac array set with expected values | Should be successful |
 * | 05 | Assign op_class, channel, and scanner_type fields in id | op_class = 1, channel = 36, scanner_type = em_scanner_type_radio | op_class, channel, and scanner_type fields correctly assigned | Should be successful |
 * | 06 | Invoke has_same_id and verify its return value | Input: address of id; Expected output: ret = true | has_same_id returns true indicating object id matches the provided id | Should Pass |
 */
TEST(dm_scan_result_t_Test, PositiveMatch_AllFieldsIdentical)
{
    std::cout << "Entering PositiveMatch_AllFieldsIdentical test" << std::endl;
    EXPECT_NO_THROW({ dm_scan_result_t obj; });
    dm_scan_result_t obj{};
    
    em_scan_result_id_t id{};
    std::cout << "Assigning net_id with \"TEST_NET\"" << std::endl;
    strncpy(id.net_id, "TEST_NET", sizeof(id.net_id));

    unsigned char expectedDevMac[6] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
    for (int i = 0; i < 6; ++i) {
        id.dev_mac[i] = expectedDevMac[i];
        std::cout << "Setting dev_mac[" << i << "] = 0x" 
                  << std::hex << static_cast<int>(expectedDevMac[i]) 
                  << std::dec << std::endl;
    }

    unsigned char expectedScannerMac[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    for (int i = 0; i < 6; ++i) {
        id.scanner_mac[i] = expectedScannerMac[i];
        std::cout << "Setting scanner_mac[" << i << "] = 0x" 
                  << std::hex << static_cast<int>(expectedScannerMac[i]) 
                  << std::dec << std::endl;
    }

    id.op_class = 1;
    std::cout << "Setting op_class = " << static_cast<int>(id.op_class) << std::endl;
    id.channel = 36;
    std::cout << "Setting channel = " << static_cast<int>(id.channel) << std::endl;
    id.scanner_type = em_scanner_type_radio;
    std::cout << "Setting scanner_type = " << static_cast<unsigned int>(id.scanner_type) << std::endl;

    std::cout << "Invoking has_same_id with a properly initialized id" << std::endl;
    bool ret = obj.has_same_id(&id);
    std::cout << "has_same_id returned " << (ret ? "true" : "false") << std::endl;
    EXPECT_TRUE(ret);
    std::cout << "Exiting PositiveMatch_AllFieldsIdentical test" << std::endl;
}
/**
 * @brief Verify that passing a NULL pointer to has_same_id returns false.
 *
 * This test verifies that the API method has_same_id behaves correctly when provided with a NULL pointer.
 * The function is expected to handle the NULL input gracefully and return false to indicate that no match was found.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 028@n
 * **Priority:** High@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * 
 * **Test Procedure:** 
 * | Variation / Step | Description                                                 | Test Data                                            | Expected Result                                       | Notes           |
 * | :--------------: | ----------------------------------------------------------- | ---------------------------------------------------- | ----------------------------------------------------- | --------------- |
 * | 01               | Create an instance of dm_scan_result_t using the default constructor  | None                                                 | Object created without throwing any exception       | Should be successful |
 * | 02               | Invoke has_same_id with a NULL pointer on the object         | input: pointer = nullptr                             | API returns false                                   | Should Pass     |
 * | 03               | Validate that the return value is false using an assertion   | output: ret = false                                  | Assertion passes confirming ret is false            | Should Pass     |
 */
TEST(dm_scan_result_t_Test, NegativeMatch_NullPointer)
{
    std::cout << "Entering NegativeMatch_NullPointer test" << std::endl;
    EXPECT_NO_THROW({ dm_scan_result_t obj; });
    dm_scan_result_t obj{};
    
    std::cout << "Invoking has_same_id with a NULL pointer" << std::endl;
    bool ret = obj.has_same_id(nullptr);
    std::cout << "has_same_id returned " << (ret ? "true" : "false") << std::endl;
    EXPECT_FALSE(ret);
    std::cout << "Exiting NegativeMatch_NullPointer test" << std::endl;
}
/**
 * @brief To verify that has_same_id() returns false when a mismatch in net_id is provided.
 *
 * This test validates that the dm_scan_result_t object's has_same_id() method correctly identifies a mismatch in the net_id field. The test creates a dm_scan_result_t instance and an em_scan_result_id_t structure with a net_id value that does not match the expected one and valid values for the other fields. The objective is to ensure the API returns false when there is a mismatch in the net_id, validating proper comparison logic.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 029@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                                                         | Test Data                                                                                                                                                                                        | Expected Result                                                      | Notes         |
 * | :--------------: | --------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------- | ------------- |
 * | 01               | Create a dm_scan_result_t object, initialize em_scan_result_id_t with net_id as "WRONG_NET" and valid dev_mac, scanner_mac, op_class, channel, and scanner_type; invoke has_same_id() to verify mismatch detection. | net_id = WRONG_NET, dev_mac = 0x01,0x02,0x03,0x04,0x05,0x06, scanner_mac = 0xAA,0xBB,0xCC,0xDD,0xEE,0xFF, op_class = 1, channel = 36, scanner_type = em_scanner_type_radio | has_same_id returns false and EXPECT_FALSE assertion passes | Should Fail  |
 */
TEST(dm_scan_result_t_Test, NegativeMatch_Mismatch_net_id)
{
    std::cout << "Entering NegativeMatch_Mismatch_net_id test" << std::endl;
    EXPECT_NO_THROW({ dm_scan_result_t obj; });
    dm_scan_result_t obj{};

    em_scan_result_id_t id{};
    std::cout << "Assigning net_id with \"WRONG_NET\"" << std::endl;
    strncpy(id.net_id, "WRONG_NET", sizeof(id.net_id));

    unsigned char expectedDevMac[6] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
    for (int i = 0; i < 6; ++i) {
        id.dev_mac[i] = expectedDevMac[i];
        std::cout << "Setting dev_mac[" << i << "] = 0x" 
                  << std::hex << static_cast<int>(expectedDevMac[i])
                  << std::dec << std::endl;
    }
    
    unsigned char expectedScannerMac[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    for (int i = 0; i < 6; ++i) {
        id.scanner_mac[i] = expectedScannerMac[i];
        std::cout << "Setting scanner_mac[" << i << "] = 0x" 
                  << std::hex << static_cast<int>(expectedScannerMac[i])
                  << std::dec << std::endl;
    }
    
    id.op_class = 1;
    std::cout << "Setting op_class = " << static_cast<int>(id.op_class) << std::endl;
    id.channel = 36;
    std::cout << "Setting channel = " << static_cast<int>(id.channel) << std::endl;
    id.scanner_type = em_scanner_type_radio;
    std::cout << "Setting scanner_type = " << static_cast<unsigned int>(id.scanner_type) << std::endl;
    
    std::cout << "Invoking has_same_id with mismatched net_id" << std::endl;
    bool ret = obj.has_same_id(&id);
    std::cout << "has_same_id returned " << (ret ? "true" : "false") << std::endl;
    EXPECT_FALSE(ret);
    std::cout << "Exiting NegativeMatch_Mismatch_net_id test" << std::endl;
}
/**
 * @brief Verify the behavior of dm_scan_result_t::has_same_id when provided with a mismatched device MAC address.
 *
 * This test validates that the API correctly identifies a mismatch when the device MAC address in the identifier
 * differs from the expected value. It checks the object's instantiation, proper population of identifier fields,
 * and ensures that has_same_id returns false indicating a mismatch.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 030@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- | -------------- | ----- |
 * | 01 | Instantiate dm_scan_result_t and ensure no exceptions are thrown. | No input arguments. | Object is instantiated without throwing exceptions. | Should be successful |
 * | 02 | Initialize em_scan_result_id_t by setting net_id to "TEST_NET". | net_id = "TEST_NET" | net_id is correctly set in the identifier. | Should be successful |
 * | 03 | Set the device MAC address with mismatched values. | dev_mac = {0xFF, 0x02, 0x03, 0x04, 0x05, 0x06} | The dev_mac field is populated with the provided mismatched MAC address. | Should be successful |
 * | 04 | Populate the scanner MAC address with the expected values. | scanner_mac = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF} | The scanner_mac field is populated with the expected scanner MAC address. | Should be successful |
 * | 05 | Assign op_class, channel, and scanner_type in the identifier. | op_class = 1, channel = 36, scanner_type = em_scanner_type_radio | The identifier fields are correctly assigned. | Should be successful |
 * | 06 | Invoke has_same_id API with the constructed identifier. | id populated with above values | API returns false, indicating a mismatch due to incorrect dev_mac. | Should Fail |
 */
TEST(dm_scan_result_t_Test, NegativeMatch_Mismatch_dev_mac)
{
    std::cout << "Entering NegativeMatch_Mismatch_dev_mac test" << std::endl;
    EXPECT_NO_THROW({ dm_scan_result_t obj; });
    dm_scan_result_t obj{};
    
    em_scan_result_id_t id{};
    std::cout << "Assigning net_id with \"TEST_NET\"" << std::endl;
    strncpy(id.net_id, "TEST_NET", sizeof(id.net_id));
    
    unsigned char wrongDevMac[6] = {0xFF, 0x02, 0x03, 0x04, 0x05, 0x06};
    for (int i = 0; i < 6; ++i) {
        id.dev_mac[i] = wrongDevMac[i];
        std::cout << "Setting dev_mac[" << i << "] = 0x" 
                  << std::hex << static_cast<int>(wrongDevMac[i])
                  << std::dec << std::endl;
    }
    
    unsigned char expectedScannerMac[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    for (int i = 0; i < 6; ++i) {
        id.scanner_mac[i] = expectedScannerMac[i];
        std::cout << "Setting scanner_mac[" << i << "] = 0x" 
                  << std::hex << static_cast<int>(expectedScannerMac[i])
                  << std::dec << std::endl;
    }
    
    id.op_class = 1;
    std::cout << "Setting op_class = " << static_cast<int>(id.op_class) << std::endl;
    id.channel = 36;
    std::cout << "Setting channel = " << static_cast<int>(id.channel) << std::endl;
    id.scanner_type = em_scanner_type_radio;
    std::cout << "Setting scanner_type = " << static_cast<unsigned int>(id.scanner_type) << std::endl;

    
    std::cout << "Invoking has_same_id with mismatched dev_mac" << std::endl;
    bool ret = obj.has_same_id(&id);
    std::cout << "has_same_id returned " << (ret ? "true" : "false") << std::endl;
    EXPECT_FALSE(ret);
    std::cout << "Exiting NegativeMatch_Mismatch_dev_mac test" << std::endl;
}
/**
 * @brief Test that dm_scan_result_t::has_same_id returns false when scanner_mac mismatches
 *
 * This test verifies that the has_same_id method correctly identifies a mismatch in the scanner_mac field.
 * It creates an instance of dm_scan_result_t and populates the identification structure (em_scan_result_id_t)
 * with predefined values, including expected dev_mac and intentionally wrong scanner_mac, and then checks that
 * the function returns false as expected.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 031@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Instantiate dm_scan_result_t object using the default constructor. | N/A | Object created without exception. | Should be successful |
 * | 02 | Initialize em_scan_result_id with net_id "TEST_NET" and assign expected dev_mac values. | net_id = "TEST_NET", dev_mac = 0x01,0x02,0x03,0x04,0x05,0x06 | net_id and dev_mac set correctly. | Should be successful |
 * | 03 | Set scanner_mac with mismatched values. | scanner_mac = 0xFF,0xBB,0xCC,0xDD,0xEE,0xFF | scanner_mac set to wrong values. | Should be successful |
 * | 04 | Assign op_class, channel, and scanner_type fields. | op_class = 1, channel = 36, scanner_type = em_scanner_type_radio | Fields assigned correctly. | Should be successful |
 * | 05 | Invoke has_same_id with the prepared id structure and verify the result is false. | Function call: has_same_id(&id) | has_same_id returns false; EXPECT_FALSE(ret) passes. | Should Fail |
 */
TEST(dm_scan_result_t_Test, NegativeMatch_Mismatch_scanner_mac)
{
    std::cout << "Entering NegativeMatch_Mismatch_scanner_mac test" << std::endl;
    EXPECT_NO_THROW({ dm_scan_result_t obj; });
    dm_scan_result_t obj{};
    
    em_scan_result_id_t id{};
    std::cout << "Assigning net_id with \"TEST_NET\"" << std::endl;
    strncpy(id.net_id, "TEST_NET", sizeof(id.net_id));
    
    unsigned char expectedDevMac[6] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
    for (int i = 0; i < 6; ++i) {
        id.dev_mac[i] = expectedDevMac[i];
        std::cout << "Setting dev_mac[" << i << "] = 0x" 
                  << std::hex << static_cast<int>(expectedDevMac[i])
                  << std::dec << std::endl;
    }
    
    unsigned char wrongScannerMac[6] = {0xFF, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    for (int i = 0; i < 6; ++i) {
        id.scanner_mac[i] = wrongScannerMac[i];
        std::cout << "Setting scanner_mac[" << i << "] = 0x" 
                  << std::hex << static_cast<int>(wrongScannerMac[i])
                  << std::dec << std::endl;
    }
    
    id.op_class = 1;
    std::cout << "Setting op_class = " << static_cast<int>(id.op_class) << std::endl;
    id.channel = 36;
    std::cout << "Setting channel = " << static_cast<int>(id.channel) << std::endl;
    id.scanner_type = em_scanner_type_radio;
    std::cout << "Setting scanner_type = " << static_cast<unsigned int>(id.scanner_type) << std::endl;
 
    std::cout << "Invoking has_same_id with mismatched scanner_mac" << std::endl;
    bool ret = obj.has_same_id(&id);
    std::cout << "has_same_id returned " << (ret ? "true" : "false") << std::endl;
    EXPECT_FALSE(ret);
    std::cout << "Exiting NegativeMatch_Mismatch_scanner_mac test" << std::endl;
}
/**
 * @brief Test for negative match when op_class mismatches
 *
 * This test verifies that the function has_same_id returns false when the op_class in the provided identifier mismatches the expected value. The objective is to ensure that the API properly detects a mismatch in the operation class, which is critical for identifying scan results.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 032@n
 * **Priority:** High@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * 
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Instantiate dm_scan_result_t object | - | Object created successfully | Should be successful |
 * | 02 | Set 'net_id' field to "TEST_NET" | net_id = "TEST_NET" | net_id set as "TEST_NET" | Should be successful |
 * | 03 | Assign dev_mac field with expected values | dev_mac = 0x01,0x02,0x03,0x04,0x05,0x06 | dev_mac correctly set | Should be successful |
 * | 04 | Assign scanner_mac field with expected values | scanner_mac = 0xAA,0xBB,0xCC,0xDD,0xEE,0xFF | scanner_mac correctly set | Should be successful |
 * | 05 | Set 'op_class' field with mismatched value | op_class = 2 | op_class set to 2, mismatching expected value | Should be successful |
 * | 06 | Set 'channel' field to 36 | channel = 36 | channel set to 36 | Should be successful |
 * | 07 | Set 'scanner_type' field to em_scanner_type_radio | scanner_type = em_scanner_type_radio | scanner_type correctly set | Should be successful |
 * | 08 | Invoke has_same_id with the configured id and verify the result | input: id, output: ret, ret expected = false | has_same_id returns false indicating a mismatch | Should Fail |
 */
TEST(dm_scan_result_t_Test, NegativeMatch_Mismatch_op_class)
{
    std::cout << "Entering NegativeMatch_Mismatch_op_class test" << std::endl;
    EXPECT_NO_THROW({ dm_scan_result_t obj; });
    dm_scan_result_t obj{};
    
    em_scan_result_id_t id{};
    std::cout << "Assigning net_id with \"TEST_NET\"" << std::endl;
    strncpy(id.net_id, "TEST_NET", sizeof(id.net_id));

    unsigned char expectedDevMac[6] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
    for (int i = 0; i < 6; ++i) {
        id.dev_mac[i] = expectedDevMac[i];
        std::cout << "Setting dev_mac[" << i << "] = 0x" 
                  << std::hex << static_cast<int>(expectedDevMac[i])
                  << std::dec << std::endl;
    }
    
    unsigned char expectedScannerMac[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    for (int i = 0; i < 6; ++i) {
        id.scanner_mac[i] = expectedScannerMac[i];
        std::cout << "Setting scanner_mac[" << i << "] = 0x" 
                  << std::hex << static_cast<int>(expectedScannerMac[i])
                  << std::dec << std::endl;
    }
    
    id.op_class = 2;
    std::cout << "Setting op_class = " << static_cast<int>(id.op_class) << std::endl;
    id.channel = 36;
    std::cout << "Setting channel = " << static_cast<int>(id.channel) << std::endl;
    id.scanner_type = em_scanner_type_radio;
    std::cout << "Setting scanner_type = " << static_cast<unsigned int>(id.scanner_type) << std::endl;
    
    std::cout << "Invoking has_same_id with mismatched op_class" << std::endl;
    bool ret = obj.has_same_id(&id);
    std::cout << "has_same_id returned " << (ret ? "true" : "false") << std::endl;
    EXPECT_FALSE(ret);
    std::cout << "Exiting NegativeMatch_Mismatch_op_class test" << std::endl;
}
/**
 * @brief Test dm_scan_result_t::has_same_id with mismatched channel
 *
 * This test validates that the dm_scan_result_t::has_same_id function correctly fails when the channel value in the em_scan_result_id_t structure does not match the expected value. The test sets up the id structure with the expected network and MAC addresses, but deliberately assigns a mismatched channel (40 instead of the expected 36) to verify that the function returns false.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 033@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Instantiate dm_scan_result_t object and verify creation | Constructor of dm_scan_result_t, no input parameters | Object instance is successfully created without throwing any exceptions | Should be successful |
 * | 02 | Setup em_scan_result_id_t structure with provided test values including mismatched channel | net_id = "TEST_NET", dev_mac = 0x01,0x02,0x03,0x04,0x05,0x06, scanner_mac = 0xAA,0xBB,0xCC,0xDD,0xEE,0xFF, op_class = 1, channel = 40, scanner_type = em_scanner_type_radio | Structure fields are correctly assigned with the channel set to 40 (mismatched) | Should be successful |
 * | 03 | Invoke has_same_id with the mismatched id and verify the return value | Input: Address of the id structure; Output: bool ret from has_same_id() | API returns false because the channel does not match the expected value | Should Fail |
 */
TEST(dm_scan_result_t_Test, NegativeMatch_Mismatch_channel)
{
    std::cout << "Entering NegativeMatch_Mismatch_channel test" << std::endl;
    EXPECT_NO_THROW({ dm_scan_result_t obj; });
    dm_scan_result_t obj{};
    
    em_scan_result_id_t id{};
    std::cout << "Assigning net_id with \"TEST_NET\"" << std::endl;
    strncpy(id.net_id, "TEST_NET", sizeof(id.net_id));
    
    unsigned char expectedDevMac[6] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
    for (int i = 0; i < 6; ++i) {
        id.dev_mac[i] = expectedDevMac[i];
        std::cout << "Setting dev_mac[" << i << "] = 0x" 
                  << std::hex << static_cast<int>(expectedDevMac[i])
                  << std::dec << std::endl;
    }
    
    unsigned char expectedScannerMac[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    for (int i = 0; i < 6; ++i) {
        id.scanner_mac[i] = expectedScannerMac[i];
        std::cout << "Setting scanner_mac[" << i << "] = 0x" 
                  << std::hex << static_cast<int>(expectedScannerMac[i])
                  << std::dec << std::endl;
    }
    
    id.op_class = 1;
    std::cout << "Setting op_class = " << static_cast<int>(id.op_class) << std::endl;
    id.channel = 40; // Mismatch here, expected should be 36
    std::cout << "Setting channel = " << static_cast<int>(id.channel) << std::endl;
    id.scanner_type = em_scanner_type_radio;
    std::cout << "Setting scanner_type = " << static_cast<unsigned int>(id.scanner_type) << std::endl;
    
    std::cout << "Invoking has_same_id with mismatched channel" << std::endl;
    bool ret = obj.has_same_id(&id);
    std::cout << "has_same_id returned " << (ret ? "true" : "false") << std::endl;
    EXPECT_FALSE(ret);
    std::cout << "Exiting NegativeMatch_Mismatch_channel test" << std::endl;
}
/**
 * @brief Test to verify the behavior of has_same_id for different scanner types
 *
 * This test checks the functionality of the has_same_id method of the dm_scan_result_t class.
 * It validates that when the scanner_type is set to em_scanner_type_radio, the method returns true,
 * and when set to em_scanner_type_sta, it returns false. This ensures that the object correctly identifies
 * the matching scan result IDs based on scanner type.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 034@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :--------------: | ----------- | --------- | -------------- | ----- |
 * | 01 | Create a dm_scan_result_t object and set up idRadio with scanner_type set to em_scanner_type_radio | net_id = TEST_NET, dev_mac = 0x01,0x02,0x03,0x04,0x05,0x06, scanner_mac = 0xAA,0xBB,0xCC,0xDD,0xEE,0xFF, op_class = 1, channel = 36, scanner_type = em_scanner_type_radio | has_same_id returns true and assertion (EXPECT_TRUE) passes | Should Pass |
 * | 02 | Set up idSta with scanner_type set to em_scanner_type_sta and invoke has_same_id | net_id = TEST_NET, dev_mac = 0x01,0x02,0x03,0x04,0x05,0x06, scanner_mac = 0xAA,0xBB,0xCC,0xDD,0xEE,0xFF, op_class = 1, channel = 36, scanner_type = em_scanner_type_sta | has_same_id returns false and assertion (EXPECT_FALSE) passes | Should Fail |
 */
TEST(dm_scan_result_t_Test, ScannerTypeVariation)
{
    std::cout << "Entering ScannerTypeVariation test" << std::endl;
    EXPECT_NO_THROW({ dm_scan_result_t obj; });
    dm_scan_result_t obj{};
    
    // Case 1: scanner_type = em_scanner_type_radio (expected: true)
    em_scan_result_id_t idRadio{};
    std::cout << "Case 1: Setting net_id with \"TEST_NET\"" << std::endl;
    strncpy(idRadio.net_id, "TEST_NET", sizeof(idRadio.net_id));
    
    unsigned char expectedDevMac[6] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
    for (int i = 0; i < 6; ++i) {
        idRadio.dev_mac[i] = expectedDevMac[i];
        std::cout << "Case 1: Setting dev_mac[" << i << "] = 0x" 
                  << std::hex << static_cast<int>(expectedDevMac[i])
                  << std::dec << std::endl;
    }
    
    unsigned char expectedScannerMac[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    for (int i = 0; i < 6; ++i) {
        idRadio.scanner_mac[i] = expectedScannerMac[i];
        std::cout << "Case 1: Setting scanner_mac[" << i << "] = 0x" 
                  << std::hex << static_cast<int>(expectedScannerMac[i])
                  << std::dec << std::endl;
    }
    
    idRadio.op_class = 1;
    std::cout << "Case 1: Setting op_class = " << static_cast<int>(idRadio.op_class) << std::endl;
    idRadio.channel = 36;
    std::cout << "Case 1: Setting scanner_type = " << static_cast<unsigned int>(idRadio.scanner_type) << std::endl;
    idRadio.scanner_type = em_scanner_type_radio;
    std::cout << "Case 1: Setting scanner_type = " << static_cast<unsigned int>(idRadio.scanner_type) << std::endl;
 
    std::cout << "Case 1: Invoking has_same_id with scanner_type radio" << std::endl;
    bool retRadio = obj.has_same_id(&idRadio);
    std::cout << "Case 1: has_same_id returned " << (retRadio ? "true" : "false") << std::endl;
    EXPECT_TRUE(retRadio);
    
    // Case 2: scanner_type = em_scanner_type_sta (expected: false)
    em_scan_result_id_t idSta;
    std::cout << "Case 2: Setting net_id with \"TEST_NET\"" << std::endl;
    strncpy(idSta.net_id, "TEST_NET", sizeof(idSta.net_id));
    
    for (int i = 0; i < 6; ++i) {
        idSta.dev_mac[i] = expectedDevMac[i];
        std::cout << "Case 2: Setting dev_mac[" << i << "] = 0x" 
                  << std::hex << static_cast<int>(expectedDevMac[i])
                  << std::dec << std::endl;
    }
    
    for (int i = 0; i < 6; ++i) {
        idSta.scanner_mac[i] = expectedScannerMac[i];
        std::cout << "Case 2: Setting scanner_mac[" << i << "] = 0x" 
                  << std::hex << static_cast<int>(expectedScannerMac[i])
                  << std::dec << std::endl;
    }
    
    idSta.op_class = 1;
    std::cout << "Case 2: Setting op_class = " << static_cast<int>(idSta.op_class) << std::endl;
    idSta.channel = 36;
    std::cout << "Case 2: Setting channel = " << static_cast<int>(idSta.channel) << std::endl;
    idSta.scanner_type = em_scanner_type_sta;
    std::cout << "Case 2: Setting scanner_type = " << static_cast<unsigned int>(idSta.scanner_type) << std::endl;
    
    std::cout << "Case 2: Invoking has_same_id with scanner_type sta" << std::endl;
    bool retSta = obj.has_same_id(&idSta);
    std::cout << "Case 2: Setting scanner_type = "  << static_cast<unsigned int>(idSta.scanner_type) << std::endl;
    EXPECT_FALSE(retSta);
    
    std::cout << "Exiting ScannerTypeVariation test" << std::endl;
}
/**
 * @brief Test initialization of dm_scan_result_t for a newly constructed object
 *
 * This test verifies that a newly constructed dm_scan_result_t object can be correctly initialized using its init() method. It checks that the init() method returns 0 and that the memory for m_scan_result is properly set to zero.
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
 * | Variation / Step | Description                                                                              | Test Data                                                | Expected Result                                                           | Notes         |
 * | :----:           | :--------------------------------------------------------------------------------------- | :------------------------------------------------------- | :---------------------------------------------------------------------- | :-----------: |
 * | 01               | Construct the dm_scan_result_t object using the default constructor.                     | None                                                     | Object is constructed without throwing exceptions.                      | Should Pass   |
 * | 02               | Invoke the init() method on the object to initialize m_scan_result.                        | scanObj, init() input: None, output1 = ret (expected value = 0) | init() returns 0, indicating successful initialization.                 | Should Pass   |
 * | 03               | Compare the memory of m_scan_result with a zeroed buffer to ensure all bytes are zeroed.     | scanObj.m_scan_result, expected value = 0 for all bytes    | Memory comparison returns 0, confirming that all bytes are set to zero.   | Should Pass   |
 */
TEST(dm_scan_result_t_Test, Initialize_scan_result_for_a_newly_constructed_object) {
    std::cout << "Entering Initialize_scan_result_for_a_newly_constructed_object test" << std::endl;

    // Construct object using the default constructor.
    EXPECT_NO_THROW(dm_scan_result_t scanObj);
    dm_scan_result_t scanObj{};
    std::cout << "Constructed dm_scan_result_t object using default constructor." << std::endl;

    // Invoke init method and log the return value.
    std::cout << "Invoking init() method on the object." << std::endl;
    int ret = scanObj.init();
    std::cout << "init() returned value: " << ret << std::endl;
    EXPECT_EQ(ret, 0);

    // Check that all bytes of m_scan_result are set to 0.
    size_t memSize = sizeof(scanObj.m_scan_result);
    std::vector<unsigned char> zeroBuffer(memSize, 0);

    int cmp = memcmp(&(scanObj.m_scan_result), zeroBuffer.data(), memSize);
    std::cout << "Performed memory comparison on m_scan_result with zero buffer; comparison result: " << cmp << std::endl;
    EXPECT_EQ(cmp, 0);

    std::cout << "Exiting Initialize_scan_result_for_a_newly_constructed_object test" << std::endl;
}

/**
 * @brief Test for deep copy functionality using the assignment operator in dm_scan_result_t
 *
 * This test verifies that the assignment operator of dm_scan_result_t performs a deep copy of all member fields from the source object to the target object. It ensures that after the assignment, every field in the target object mirrors the corresponding field in the source object, even if the target was initially populated with different values.
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
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Create source and target objects using default constructors. | No input/output values. | Both objects are instantiated without errors. | Should be successful |
 * | 02 | Populate the source object with non-default values. | source.m_scan_result.net_id = "SRC_ID", source.m_scan_result.dev_mac = "SRC_DEV", source.m_scan_result.scanner_mac = "SRC_SCAN", source.m_scan_result.id.op_class = 5, source.m_scan_result.id.channel = 11, source.m_scan_result.id.scanner_type = em_scanner_type_sta, source.m_scan_result.scan_status = 9, source.m_scan_result.timestamp = "2023-10-10 10:10:10", source.m_scan_result.util = 3, source.m_scan_result.noise = 2, source.m_scan_result.num_neighbors = 2, source.m_scan_result.aggr_scan_duration = 100, source.m_scan_result.scan_type = 1 | Source object fields are set to specified non-default values. | Should be successful |
 * | 03 | Initialize the target object with different arbitrary values. | target.m_scan_result.net_id = "TGT_ID", target.m_scan_result.timestamp = "TARGET_TIMESTAMP", target.m_scan_result.scan_status = 99, target.m_scan_result.util = 9, target.m_scan_result.noise = 8, target.m_scan_result.num_neighbors = 5, target.m_scan_result.aggr_scan_duration = 500, target.m_scan_result.scan_type = 7, target.m_scan_result.id.op_class = 1, target.m_scan_result.id.channel = 2, target.m_scan_result.id.scanner_type = em_scanner_type_radio | Target object is initialized with distinct values from the source. | Should be successful |
 * | 04 | Invoke the assignment operator to copy the source object into the target. | Execution of 'target = source' | Target object fields copy the values from the source object. | Should Pass |
 * | 05 | Validate that all fields in the target object match the corresponding fields in the source object. | Comparison using EXPECT_STREQ for strings and EXPECT_EQ for numerical values | All assertions pass confirming that the deep copy is accurate. | Should be successful |
 */
TEST(dm_scan_result_t_Test, AssignmentOperatorDeepCopy) {
    std::cout << "Entering AssignmentOperatorDeepCopy test" << std::endl;

    EXPECT_NO_THROW({
        dm_scan_result_t source{};
        dm_scan_result_t target{};

        source.m_scan_result.id.op_class = 5;
        source.m_scan_result.id.channel = 11;
        source.m_scan_result.id.scanner_type = em_scanner_type_sta;

        source.m_scan_result.scan_status = 9;
        source.m_scan_result.util = 3;
        source.m_scan_result.noise = 2;
        source.m_scan_result.num_neighbors = 2;
        source.m_scan_result.aggr_scan_duration = 100;
        source.m_scan_result.scan_type = 1;

        std::cout << "Initialized source m_scan_result: "
                  << " op_class=" << source.m_scan_result.id.op_class
                  << " channel=" << source.m_scan_result.id.channel
                  << " scanner_type=" << static_cast<int>(source.m_scan_result.id.scanner_type)
                  << " scan_status=" << static_cast<int>(source.m_scan_result.scan_status)
                  << " util=" << static_cast<int>(source.m_scan_result.util)
                  << " noise=" << static_cast<int>(source.m_scan_result.noise)
                  << " neighbors=" << source.m_scan_result.num_neighbors
                  << " duration=" << source.m_scan_result.aggr_scan_duration
                  << " scan_type=" << static_cast<int>(source.m_scan_result.scan_type)
                  << std::endl;

        target.m_scan_result.id.op_class = 1;
        target.m_scan_result.id.channel = 2;
        target.m_scan_result.id.scanner_type = em_scanner_type_radio;
        target.m_scan_result.scan_status = 99;
        target.m_scan_result.util = 9;
        target.m_scan_result.noise = 8;
        target.m_scan_result.num_neighbors = 5;
        target.m_scan_result.aggr_scan_duration = 500;
        target.m_scan_result.scan_type = 7;

        std::cout << "Invoking assignment operator: target = source" << std::endl;

        EXPECT_NO_THROW(target = source);

        EXPECT_EQ(target.m_scan_result.id.op_class, source.m_scan_result.id.op_class);
        EXPECT_EQ(target.m_scan_result.id.channel, source.m_scan_result.id.channel);
        EXPECT_EQ(target.m_scan_result.id.scanner_type, source.m_scan_result.id.scanner_type);
        EXPECT_EQ(target.m_scan_result.scan_status, source.m_scan_result.scan_status);
        EXPECT_EQ(target.m_scan_result.util, source.m_scan_result.util);
        EXPECT_EQ(target.m_scan_result.noise, source.m_scan_result.noise);
        EXPECT_EQ(target.m_scan_result.num_neighbors, source.m_scan_result.num_neighbors);
        EXPECT_EQ(target.m_scan_result.aggr_scan_duration, source.m_scan_result.aggr_scan_duration);
        EXPECT_EQ(target.m_scan_result.scan_type, source.m_scan_result.scan_type);
    });

    std::cout << "Exiting AssignmentOperatorDeepCopy test" << std::endl;
}

/**
 * @brief Verify assignment operator resets target object's fields to zero when source object is zeroed
 *
 * This test validates that when the source object's scan result fields are explicitly set to zero using the init() method,
 * the assignment operator correctly transfers these zero values to the target object, overwriting any pre-existing non-default values.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 037@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                         | Test Data                                                                                                                                                                             | Expected Result                                                                                                                     | Notes           |
 * | :--------------: | ------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------- | --------------- |
 * | 01               | Create source and target objects                                    | source = uninitialized dm_scan_result_t object, target = uninitialized dm_scan_result_t object                                                                                         | Objects created successfully                                                                                                        | Should be successful |
 * | 02               | Invoke init() on source to zero out scan_result                       | source.init() invoked; input: source object's scan_result fields, output: source.scan_result fields reset to zero                                                                       | No exception thrown; source.scan_result fields are all zeros                                                                        | Should Pass     |
 * | 03               | Populate target with non-default values                              | target.m_scan_result.net_id = "NON_ZERO", timestamp = "NON_ZERO_TS", scan_status = 55, util = 77, noise = 88, num_neighbors = 3, aggr_scan_duration = 300, scan_type = 2, id fields set accordingly | Target object fields updated with non-zero values                                                                                   | Should be successful |
 * | 04               | Invoke assignment operator (target = source)                         | target = source executed; input: source with zeroed fields, target with non-default fields; output: target object's scan_result fields updated                                 | No exception thrown; assignment operator resets target fields to zero                                                               | Should Pass     |
 * | 05               | Validate that target.m_scan_result fields are set to zero post-assignment | Validation of target.m_scan_result fields: net_id = "", timestamp = "", scan_status = 0, util = 0, noise = 0, num_neighbors = 0, aggr_scan_duration = 0, scan_type = 0, id fields = 0        | All target.m_scan_result fields are zero                                                                                            | Should be successful |
 */
TEST(dm_scan_result_t_Test, AssignmentOperatorSourceZeroFields) {
    std::cout << "Entering AssignmentOperatorSourceZeroFields test" << std::endl;

    EXPECT_NO_THROW({
        dm_scan_result_t source{};
        dm_scan_result_t target{};

        std::cout << "Invoking init() on source object to zero out scan_result" << std::endl;
        source.init();

        strncpy(target.m_scan_result.id.net_id, "NON_ZERO", MAC_STR_LEN - 1);
        target.m_scan_result.id.net_id[MAC_STR_LEN - 1] = '\0';

        strncpy(target.m_scan_result.timestamp, "NON_ZERO_TS", MAC_STR_LEN - 1);
        target.m_scan_result.timestamp[MAC_STR_LEN - 1] = '\0';

        target.m_scan_result.scan_status = 55;
        target.m_scan_result.util = 77;
        target.m_scan_result.noise = 88;
        target.m_scan_result.num_neighbors = 3;
        target.m_scan_result.aggr_scan_duration = 300;
        target.m_scan_result.scan_type = 2;

        target.m_scan_result.id.op_class = 9;
        target.m_scan_result.id.channel = 18;
        target.m_scan_result.id.scanner_type = em_scanner_type_sta;

        std::cout << "Initialized target with non-zero values" << std::endl;

        std::cout << "Invoking assignment operator: target = source" << std::endl;
        EXPECT_NO_THROW(target = source);

        std::cout << "After assignment, validating that target fields are zero" << std::endl;

        EXPECT_STREQ(target.m_scan_result.id.net_id, "");
        EXPECT_STREQ(target.m_scan_result.timestamp, "");
        EXPECT_EQ(target.m_scan_result.scan_status, 0);
        EXPECT_EQ(target.m_scan_result.util, 0);
        EXPECT_EQ(target.m_scan_result.noise, 0);
        EXPECT_EQ(target.m_scan_result.num_neighbors, 0);
        EXPECT_EQ(target.m_scan_result.aggr_scan_duration, 0);
        EXPECT_EQ(target.m_scan_result.scan_type, 0);

        EXPECT_EQ(target.m_scan_result.id.op_class, 0);
        EXPECT_EQ(target.m_scan_result.id.channel, 0);
        EXPECT_EQ(target.m_scan_result.id.scanner_type, 0);
    });

    std::cout << "Exiting AssignmentOperatorSourceZeroFields test" << std::endl;
}

/**
 * @brief Verifies that the assignment operator correctly copies enum values for scanner type.
 *
 * This test iterates over the scanner type enum values and assigns the value from the source object to the target object using the assignment operator. The test validates that after the assignment, the target object's scanner type matches the source object's scanner type. This ensures that the enum values are properly handled during assignment.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 038@n
 * **Priority:** (High)@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * 
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize source and target objects with different scanner type values for each iteration | source.m_scan_result.id.scanner_type = enumVal, target.m_scan_result.id.scanner_type = (if enumVal == em_scanner_type_radio then em_scanner_type_sta else em_scanner_type_radio) | Objects are initialized with distinct scanner type values | Should be successful |
 * | 02 | Invoke the assignment operator: target = source | Invocation of assignment operator with source and target objects | No exception is thrown (EXPECT_NO_THROW passes) | Should Pass |
 * | 03 | Validate that target's scanner type matches source's scanner type | source.m_scan_result.id.scanner_type = enumVal, target.m_scan_result.id.scanner_type after assignment | target.m_scan_result.id.scanner_type equals source.m_scan_result.id.scanner_type (EXPECT_EQ passes) | Should Pass |
 */
TEST(dm_scan_result_t_Test, AssignmentOperatorEnumValues) {
    std::cout << "Entering AssignmentOperatorEnumValues test" << std::endl;

    for (int enumVal = em_scanner_type_radio; enumVal <= em_scanner_type_sta; ++enumVal) {
        std::cout << "Testing with scanner_type: " << enumVal << std::endl;
        dm_scan_result_t source{};
        dm_scan_result_t target{};
        
        // Set source scanner_type to current enum value
        source.m_scan_result.id.scanner_type = static_cast<em_scanner_type_t>(enumVal);
        std::cout << "Assigned source.m_scan_result.id.scanner_type: " 
                  << static_cast<int>(source.m_scan_result.id.scanner_type) << std::endl;
        
        // Set target with a different default value.
        target.m_scan_result.id.scanner_type = (enumVal == em_scanner_type_radio) ? em_scanner_type_sta : em_scanner_type_radio;
        std::cout << "Before assignment, target.m_scan_result.id.scanner_type: " 
                  << static_cast<int>(target.m_scan_result.id.scanner_type) << std::endl;
        
        // Perform assignment
        std::cout << "Invoking assignment operator: target = source" << std::endl;
        EXPECT_NO_THROW(target = source);
        
        // Validate enum value copied.
        std::cout << "After assignment, target.m_scan_result.id.scanner_type: " 
                  << static_cast<int>(target.m_scan_result.id.scanner_type) << std::endl;
        EXPECT_EQ(target.m_scan_result.id.scanner_type, source.m_scan_result.id.scanner_type);
    }
    
    std::cout << "Exiting AssignmentOperatorEnumValues test" << std::endl;
}
/**
 * @brief Verify the assignment operator correctly copies boundary string values between objects
 *
 * This test verifies that the assignment operator (operator=) for dm_scan_result_t properly copies
 * the maximum valid string values (boundary values) for the net_id and timestamp fields from one object
 * to another. The test sets the source object's string fields to a 127-character string and the target
 * object's string fields to different values, then performs the assignment and checks if the target
 * object's fields match those of the source.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 039@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                 | Test Data                                                                                                                          | Expected Result                                                                                                      | Notes         |
 * | :--------------: | ---------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------- | ------------- |
 * | 01               | Set source object's net_id and timestamp with a boundary maximum valid string| source.m_scan_result.net_id = "127-char max string", source.m_scan_result.timestamp = "127-char max string"                        | The source object's string fields are initialized with maximum valid string lengths                                  | Should be successful |
 * | 02               | Set target object's net_id and timestamp with different initial values         | target.m_scan_result.net_id = "DIFFERENT", target.m_scan_result.timestamp = "DIFF_TIMESTAMP"                                      | The target object's string fields are set with initial different values                                              | Should be successful |
 * | 03               | Invoke the assignment operator to copy values from source to target            | Invocation of assignment operator: target = source                                                                             | No exception is thrown during the assignment operation                                                             | Should Pass   |
 * | 04               | Validate that the target's fields exactly match the source's fields after assignment | After assignment, target.m_scan_result.net_id should equal source.m_scan_result.net_id, target.m_scan_result.timestamp should equal source.m_scan_result.timestamp | EXPECT_STREQ assertions pass, confirming that the target object's string fields match the source's                  | Should Pass   |
 */
// MAX_STR_LEN should come from the struct header (scan_result.h)
TEST(dm_scan_result_t_Test, AssignmentOperatorBoundaryStringValues) {
    std::cout << "Entering AssignmentOperatorBoundaryStringValues test" << std::endl;

    EXPECT_NO_THROW({
        dm_scan_result_t source{};
        dm_scan_result_t target{};

        char maxStr[MAC_STR_LEN];
        memset(maxStr, 'A', MAC_STR_LEN - 1);
        maxStr[MAC_STR_LEN - 1] = '\0';

        strncpy(source.m_scan_result.id.net_id, maxStr, MAC_STR_LEN - 1);
        source.m_scan_result.id.net_id[MAC_STR_LEN - 1] = '\0';

        strncpy(source.m_scan_result.timestamp, maxStr, MAC_STR_LEN - 1);
        source.m_scan_result.timestamp[MAC_STR_LEN - 1] = '\0';

        std::cout << "Assigned source.net_id: " << source.m_scan_result.id.net_id << std::endl;
        std::cout << "Assigned source.timestamp: " << source.m_scan_result.timestamp << std::endl;

        strncpy(target.m_scan_result.id.net_id, "DIFFERENT", MAC_STR_LEN - 1);
        target.m_scan_result.id.net_id[MAC_STR_LEN - 1] = '\0';

        strncpy(target.m_scan_result.timestamp, "DIFF_TIMESTAMP", MAC_STR_LEN - 1);
        target.m_scan_result.timestamp[MAC_STR_LEN - 1] = '\0';

        std::cout << "Before assignment, target.net_id: " << target.m_scan_result.id.net_id << std::endl;
        std::cout << "Before assignment, target.timestamp: " << target.m_scan_result.timestamp << std::endl;

        EXPECT_NO_THROW(target = source);

        std::cout << "After assignment, target.net_id: " << target.m_scan_result.id.net_id << std::endl;
        std::cout << "After assignment, target.timestamp: " << target.m_scan_result.timestamp << std::endl;

        EXPECT_STREQ(target.m_scan_result.id.net_id, source.m_scan_result.id.net_id);
        EXPECT_STREQ(target.m_scan_result.timestamp, source.m_scan_result.timestamp);
    });

    std::cout << "Exiting AssignmentOperatorBoundaryStringValues test" << std::endl;
}

/**
 * @brief Verify that the assignment operator correctly copies numerical fields.
 *
 * This test creates two dm_scan_result_t objects, source and target. The source object numerical fields are set to distinct non-default values, while the target object's fields are initialized to different arbitrary values. After invoking the assignment operator (target = source), the test validates that each numerical field in the target is correctly updated to the source’s corresponding value.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 040@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Set source object's numerical fields with distinct non-default values and initialize target object's fields with arbitrary values. | source.m_scan_result.id.op_class = 10, source.m_scan_result.id.channel = 20, source.m_scan_result.scan_status = 30, source.m_scan_result.noise = 40, source.m_scan_result.util = 50, source.m_scan_result.aggr_scan_duration = 600, source.m_scan_result.scan_type = 70; target.m_scan_result.id.op_class = 99, target.m_scan_result.id.channel = 88, target.m_scan_result.scan_status = 77, target.m_scan_result.noise = 66, target.m_scan_result.util = 55, target.m_scan_result.aggr_scan_duration = 444, target.m_scan_result.scan_type = 33 | Source and target objects correctly initialized with respective values. | Should be successful |
 * | 02 | Invoke the assignment operator to copy the numerical fields from source to target. | Invocation: target = source | Assignment operator executed without throwing an exception. | Should Pass |
 * | 03 | Validate that each numerical field in target matches the corresponding field in source. | Compare: op_class, channel, scan_status, noise, util, aggr_scan_duration, scan_type | All numerical fields in target are equal to those in source. | Should Pass |
 */
TEST(dm_scan_result_t_Test, AssignmentOperatorNumericalFields) {
    std::cout << "Entering AssignmentOperatorNumericalFields test" << std::endl;

    EXPECT_NO_THROW({
        dm_scan_result_t source{};
        dm_scan_result_t target{};
        
        // Set source numerical fields to distinct non-default values.
        source.m_scan_result.id.op_class = 10;
        source.m_scan_result.id.channel = 20;
        source.m_scan_result.scan_status = 30;
        source.m_scan_result.noise = 40;
        source.m_scan_result.util = 50;
        source.m_scan_result.aggr_scan_duration = 600;
        source.m_scan_result.scan_type = 70;
        std::cout << "Assigned source numerical fields: op_class=" << static_cast<int>(source.m_scan_result.id.op_class)
                  << ", channel=" << static_cast<int>(source.m_scan_result.id.channel)
                  << ", scan_status=" << static_cast<int>(source.m_scan_result.scan_status)
                  << ", util=" << static_cast<int>(source.m_scan_result.util)
                  << ", noise=" << static_cast<int>(source.m_scan_result.noise)
                  << ", aggr_scan_duration=" << source.m_scan_result.aggr_scan_duration
                  << ", scan_type=" << static_cast<int>(source.m_scan_result.scan_type) << std::endl;
        
        // Set target numerical fields to different arbitrary values.
        target.m_scan_result.id.op_class = 99;
        target.m_scan_result.id.channel = 88;
        target.m_scan_result.scan_status = 77;
        target.m_scan_result.noise = 66;
        target.m_scan_result.util = 55;
        target.m_scan_result.aggr_scan_duration = 444;
        target.m_scan_result.scan_type = 33;
        std::cout << "Before assignment, target numerical fields: op_class=" << static_cast<int>(target.m_scan_result.id.op_class)
                  << ", channel=" << static_cast<int>(target.m_scan_result.id.channel)
                  << ", scan_status=" << static_cast<int>(target.m_scan_result.scan_status)
                  << ", util=" << static_cast<int>(target.m_scan_result.util)
                  << ", noise=" << static_cast<int>(target.m_scan_result.noise)
                  << ", aggr_scan_duration=" << target.m_scan_result.aggr_scan_duration
                  << ", scan_type=" << static_cast<int>(target.m_scan_result.scan_type) << std::endl;
        
        // Invoke assignment operator.
        std::cout << "Invoking assignment operator: target = source" << std::endl;
        EXPECT_NO_THROW(target = source);
        
        // Validate each numerical field is correctly copied.
        std::cout << "After assignment, target numerical fields: op_class=" << static_cast<int>(target.m_scan_result.id.op_class)
                  << ", channel=" << static_cast<int>(target.m_scan_result.id.channel)
                  << ", scan_status=" << static_cast<int>(target.m_scan_result.scan_status)
                  << ", util=" << static_cast<int>(target.m_scan_result.util)
                  << ", noise=" << static_cast<int>(target.m_scan_result.noise)
                  << ", aggr_scan_duration=" << target.m_scan_result.aggr_scan_duration
                  << ", scan_type=" << static_cast<int>(target.m_scan_result.scan_type) << std::endl;
                  
        EXPECT_EQ(target.m_scan_result.id.op_class, source.m_scan_result.id.op_class);
        EXPECT_EQ(target.m_scan_result.id.channel, source.m_scan_result.id.channel);
        EXPECT_EQ(target.m_scan_result.scan_status, source.m_scan_result.scan_status);
        EXPECT_EQ(target.m_scan_result.util, source.m_scan_result.util);
        EXPECT_EQ(target.m_scan_result.noise, source.m_scan_result.noise);
        EXPECT_EQ(target.m_scan_result.aggr_scan_duration, source.m_scan_result.aggr_scan_duration);
        EXPECT_EQ(target.m_scan_result.scan_type, source.m_scan_result.scan_type);
    });
    
    std::cout << "Exiting AssignmentOperatorNumericalFields test" << std::endl;
}
/**
 * @brief Verify equality operator for identical objects across scanner types
 *
 * This test verifies that when two dm_scan_result_t objects, initialized with identical common fields and assigned the same scanner type (iterated over valid scanner types), are compared using operator==, the result is true. This ensures that the equality operator correctly handles comparisons when the scanner type is varied.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 041@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                              | Test Data                                                                                      | Expected Result                                                      | Notes             |
 * | :--------------: | ------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------- | -------------------------------------------------------------------- | ----------------- |
 * | 01               | Loop over both scanner types                                             | type from em_scanner_type_radio, type from em_scanner_type_sta                                   | Iteration over each valid scanner type                               | Should be successful |
 * | 02               | Initialize two objects and verify initialization does not throw          | obj1.init(), obj2.init()                                                                         | No exceptions thrown during initialization                           | Should be successful |
 * | 03               | Fill both objects with common fields                                     | Call fill_common_scan_result_fields(obj1), fill_common_scan_result_fields(obj2)                   | Common fields correctly populated for both objects                  | Should be successful |
 * | 04               | Set scanner type field for both objects based on loop iteration            | obj1.m_scan_result.id.scanner_type = type, obj2.m_scan_result.id.scanner_type = type               | Both objects have the same scanner type set                          | Should Pass         |
 * | 05               | Invoke operator== on the two objects and check for equality                | result = obj1.operator==(obj2)                                                                   | Return value is true and EXPECT_TRUE(result) passes as expected        | Should Pass         |
 */
TEST(dm_scan_result_t_Test, IdenticalObjectsWithLoopedScannerType)
{
    std::cout << "Entering IdenticalObjectsWithLoopedScannerType test" << std::endl;

    for (int type = em_scanner_type_radio; type <= em_scanner_type_sta; ++type)
    {
        std::cout << "Setting scanner_type to: " << type << std::endl;
        dm_scan_result_t obj1{};
        dm_scan_result_t obj2{};

        EXPECT_NO_THROW(obj1.init());
        EXPECT_NO_THROW(obj2.init());

        fill_common_scan_result_fields(obj1);
        fill_common_scan_result_fields(obj2);

        obj1.m_scan_result.id.scanner_type = static_cast<em_scanner_type_t>(type);
        std::cout << "obj1 assigned scanner_type: " << type << std::endl;

        obj2.m_scan_result.id.scanner_type = static_cast<em_scanner_type_t>(type);
        std::cout << "obj2 assigned scanner_type: " << type << std::endl;

        std::cout << "Invoking operator== on obj1 with obj2" << std::endl;
        bool result = obj1.operator==(obj2);
        std::cout << "operator== returned: " << result << std::endl;

        EXPECT_TRUE(result);
    }

    std::cout << "Exiting IdenticalObjectsWithLoopedScannerType test" << std::endl;
}

/**
 * @brief Verifies that dm_scan_result_t objects with different net_id values are not considered equal.
 *
 * This test initializes two dm_scan_result_t objects, fills them with common scan result fields, and then explicitly sets different net_id values ("Net123" for the first object and "Net456" for the second). It subsequently invokes the operator== to compare the two objects and asserts that the operator returns false because the net_id fields differ.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 042@n
 * **Priority:** High@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * 
 * **Test Procedure:**
 * | Variation / Step | Description                                                                                           | Test Data                                                                                   | Expected Result                                              | Notes         |
 * | :--------------: | ----------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------- | ------------------------------------------------------------- | ------------- |
 * |       01       | Initialize two dm_scan_result_t objects and verify init() does not throw an exception                  | obj1, obj2; init() called on both                                                          | Both objects initialized without exceptions                  | Should Pass   |
 * |       02       | Fill common scan result fields for both objects using fill_common_scan_result_fields                    | obj1, obj2; fill_common_scan_result_fields(obj1), fill_common_scan_result_fields(obj2)        | Common fields set correctly without error                     | Should be successful |
 * |       03       | Set net_id for obj1 to "Net123" and for obj2 to "Net456"                                              | obj1.m_scan_result.id.net_id = "Net123", obj2.m_scan_result.id.net_id = "Net456"              | net_id fields updated correctly                                | Should Pass   |
 * |       04       | Invoke operator== on obj1 with obj2                                                                   | Call operator==(obj2) on obj1, output: result                                               | Return value is false as net_id values differ                  | Should Pass   |
 * |       05       | Assert that the result of operator== is false using EXPECT_FALSE                                      | result from operator==                                                                       | EXPECT_FALSE(result) passes if result is false                  | Should Pass   |
 */
TEST(dm_scan_result_t_Test, DifferentNetId)
{
    std::cout << "Entering DifferentNetId test" << std::endl;

    dm_scan_result_t obj1{};
    dm_scan_result_t obj2{};
    EXPECT_NO_THROW(obj1.init());
    EXPECT_NO_THROW(obj2.init());
    
    fill_common_scan_result_fields(obj1);
    fill_common_scan_result_fields(obj2);
    
    // Set net_id differently
    std::cout << "Setting obj1 id.net_id to 'Net123'" << std::endl;
    strncpy(obj1.m_scan_result.id.net_id, "Net123", sizeof(obj1.m_scan_result.id.net_id));
    std::cout << "Setting obj2 id.net_id to 'Net456'" << std::endl;
    strncpy(obj2.m_scan_result.id.net_id, "Net456", sizeof(obj2.m_scan_result.id.net_id));
    
    std::cout << "Invoking operator== on obj1 with obj2" << std::endl;
    bool result = obj1.operator==(obj2);
    std::cout << "operator== returned: " << result << std::endl;
    
    EXPECT_FALSE(result);
    std::cout << "Exiting DifferentNetId test" << std::endl;
}
/**
 * @brief Validate that two dm_scan_result_t objects with different dev_mac addresses are not considered equal
 *
 * This test initializes two dm_scan_result_t objects, populates them with common fields, and then assigns different MAC addresses (MAC_A vs MAC_B) to their dev_mac fields. The test then invokes the operator== to verify that the two objects with differing dev_mac values are not equal.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 043@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize two dm_scan_result_t objects and call init() on each | obj1, obj2: initialization via init() | No exceptions thrown on initialization | Should be successful |
 * | 02 | Populate both objects with common scan result fields | obj1, obj2: common scan result fields set | Common fields successfully populated | Should be successful |
 * | 03 | Assign dev_mac of first object to MAC_A | obj1.m_scan_result.id.dev_mac = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF} | dev_mac set correctly for obj1 | Should be successful |
 * | 04 | Assign dev_mac of second object to MAC_B | obj2.m_scan_result.id.dev_mac = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66} | dev_mac set correctly for obj2 | Should be successful |
 * | 05 | Compare both objects using operator== | Invocation of obj1.operator==(obj2) | Operator returns false indicating objects are not equal | Should Pass |
 */
TEST(dm_scan_result_t_Test, DifferentDevMac)
{
    std::cout << "Entering DifferentDevMac test" << std::endl;

    dm_scan_result_t obj1{};
    dm_scan_result_t obj2{};
    EXPECT_NO_THROW(obj1.init());
    EXPECT_NO_THROW(obj2.init());
    
    fill_common_scan_result_fields(obj1);
    fill_common_scan_result_fields(obj2);
    
    // Set dev_mac differently: MAC_A vs MAC_B
    unsigned char macA[MAC_ADDR_LEN] = { 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };
    unsigned char macB[MAC_ADDR_LEN] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 };
    std::cout << "Assigning obj1 id.dev_mac to MAC_A" << std::endl;
    memcpy(obj1.m_scan_result.id.dev_mac, macA, MAC_ADDR_LEN);
    std::cout << "Assigning obj2 id.dev_mac to MAC_B" << std::endl;
    memcpy(obj2.m_scan_result.id.dev_mac, macB, MAC_ADDR_LEN);
    
    std::cout << "Invoking operator== on obj1 with obj2" << std::endl;
    bool result = obj1.operator==(obj2);
    std::cout << "operator== returned: " << result << std::endl;
    
    EXPECT_FALSE(result);
    std::cout << "Exiting DifferentDevMac test" << std::endl;
}
/**
 * @brief Verify equality operator fails for dm_scan_result_t objects with different scanner MAC addresses.
 *
 * This test verifies that when two dm_scan_result_t objects are initialized, their common scan result fields are filled, and their scanner MAC addresses are set to distinct values, the equality operator (operator==) correctly identifies them as not equal. The objective is to ensure that the operator== method in dm_scan_result_t accurately compares the scanner_mac fields.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 044@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize two dm_scan_result_t objects by calling init() on each object. | obj1, obj2 created; init() called with no parameters. | No exceptions thrown during initialization. | Should be successful |
 * | 02 | Populate common scan result fields using fill_common_scan_result_fields function for each object. | obj1, obj2; fields set by fill_common_scan_result_fields. | Common scan result fields are populated correctly. | Should be successful |
 * | 03 | Assign distinct MAC addresses to the scanner_mac field of each object (MAC_A for obj1, MAC_B for obj2). | obj1.m_scan_result.id.scanner_mac = {AA,BB,CC,DD,EE,FF}, obj2.m_scan_result.id.scanner_mac = {11,22,33,44,55,66} | The scanner_mac fields in obj1 and obj2 are different. | Should be successful |
 * | 04 | Invoke the equality operator (operator==) on obj1 with obj2 and validate the result. | Input: obj1, obj2 as parameters to operator==. | operator== returns false indicating the objects are not equal. | Should Pass |
 */
TEST(dm_scan_result_t_Test, DifferentScannerMac)
{
    std::cout << "Entering DifferentScannerMac test" << std::endl;

    dm_scan_result_t obj1{};
    dm_scan_result_t obj2{};
    EXPECT_NO_THROW(obj1.init());
    EXPECT_NO_THROW(obj2.init());
    
    fill_common_scan_result_fields(obj1);
    fill_common_scan_result_fields(obj2);
    
    // Set scanner_mac differently: MAC_A vs MAC_B
    unsigned char macA[MAC_ADDR_LEN] = { 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };
    unsigned char macB[MAC_ADDR_LEN] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 };
    std::cout << "Assigning obj1 id.scanner_mac to MAC_A" << std::endl;
    memcpy(obj1.m_scan_result.id.scanner_mac, macA, MAC_ADDR_LEN);
    std::cout << "Assigning obj2 id.scanner_mac to MAC_B" << std::endl;
    memcpy(obj2.m_scan_result.id.scanner_mac, macB, MAC_ADDR_LEN);
    
    std::cout << "Invoking operator== on obj1 with obj2" << std::endl;
    bool result = obj1.operator==(obj2);
    std::cout << "operator== returned: " << result << std::endl;
    
    EXPECT_FALSE(result);
    std::cout << "Exiting DifferentScannerMac test" << std::endl;
}
/**
 * @brief Test the equality operator for dm_scan_result_t objects with different op_class values.
 *
 * This test verifies that two dm_scan_result_t objects with identical common fields but different op_class values in their id substructure are not considered equal. The aim is to ensure that the operator== method correctly differentiates objects based solely on the op_class field.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 045
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize two dm_scan_result_t objects and fill them with common scan result fields | No input arguments, Output: Objects obj1 and obj2 are created and initialized | Objects successfully initialized and filled with common fields | Should be successful |
 * | 02 | Modify the op_class values for the two objects to distinct values | For obj1: m_scan_result.id.op_class = 10, for obj2: m_scan_result.id.op_class = 20 | Objects have different op_class values | Should be successful |
 * | 03 | Invoke operator== to compare the two objects | Input: obj1.operator==(obj2), Expected output: result = false | operator== returns false, indicating that the objects are not equal | Should Pass |
 */
TEST(dm_scan_result_t_Test, DifferentOpClass)
{
    std::cout << "Entering DifferentOpClass test" << std::endl;

    dm_scan_result_t obj1{};
    dm_scan_result_t obj2{};
    EXPECT_NO_THROW(obj1.init());
    EXPECT_NO_THROW(obj2.init());
    
    fill_common_scan_result_fields(obj1);
    fill_common_scan_result_fields(obj2);
    
    // Set op_class differently
    std::cout << "Assigning obj1 id.op_class to 10" << std::endl;
    obj1.m_scan_result.id.op_class = 10;
    std::cout << "Assigning obj2 id.op_class to 20" << std::endl;
    obj2.m_scan_result.id.op_class = 20;
    
    std::cout << "Invoking operator== on obj1 with obj2" << std::endl;
    bool result = obj1.operator==(obj2);
    std::cout << "operator== returned: " << result << std::endl;
    
    EXPECT_FALSE(result);
    std::cout << "Exiting DifferentOpClass test" << std::endl;
}
/**
 * @brief Validate dm_scan_result_t inequality when channel values differ
 *
 * This test verifies that two dm_scan_result_t objects with different 'channel' values are not considered equal. It initializes both objects, populates common fields, assigns distinct channel values, and checks that the operator== correctly identifies them as unequal.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 046@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize two dm_scan_result_t objects and invoke init() on both | obj1.init(), obj2.init() | No exception thrown from initialization | Should be successful |
 * | 02 | Populate common scan result fields for both objects using fill_common_scan_result_fields() | fill_common_scan_result_fields(obj1), fill_common_scan_result_fields(obj2) | Common fields set appropriately | Should be successful |
 * | 03 | Assign different channel values to each object | obj1.m_scan_result.id.channel = 5, obj2.m_scan_result.id.channel = 11 | Both objects have differing channel values | Should Pass |
 * | 04 | Invoke operator== to compare the two objects | result = obj1.operator==(obj2) | Operator returns false indicating objects are not equal | Should Pass |
 */
TEST(dm_scan_result_t_Test, DifferentChannel)
{
    std::cout << "Entering DifferentChannel test" << std::endl;

    dm_scan_result_t obj1{};
    dm_scan_result_t obj2{};
    EXPECT_NO_THROW(obj1.init());
    EXPECT_NO_THROW(obj2.init());
    
    fill_common_scan_result_fields(obj1);
    fill_common_scan_result_fields(obj2);
    
    // Set channel differently
    std::cout << "Assigning obj1 id.channel to 5" << std::endl;
    obj1.m_scan_result.id.channel = 5;
    std::cout << "Assigning obj2 id.channel to 11" << std::endl;
    obj2.m_scan_result.id.channel = 11;
    
    std::cout << "Invoking operator== on obj1 with obj2" << std::endl;
    bool result = obj1.operator==(obj2);
    std::cout << "operator== returned: " << result << std::endl;
    
    EXPECT_FALSE(result);
    std::cout << "Exiting DifferentChannel test" << std::endl;
}
/**
 * @brief Validate dm_scan_result_t equality operator for different scanner types
 *
 * This test verifies that when two dm_scan_result_t objects have differing scanner_type values,
 * the equality operator (operator==) correctly identifies them as not equal.
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
 * | Variation / Step | Description                                                                                                                  | Test Data                                                                                                                            | Expected Result                                                 | Notes           |
 * | :--------------: | ---------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------- | --------------- |
 * | 01               | Create dm_scan_result_t objects obj1 and obj2                                                                                 | obj1, obj2                                                                                                                           | Objects created successfully                                     | Should be successful |
 * | 02               | Initialize obj1 and obj2 using the init() method with EXPECT_NO_THROW                                                        | obj1.init(), obj2.init()                                                                                                               | No exceptions thrown                                            | Should Pass     |
 * | 03               | Populate common scan result fields for both objects using fill_common_scan_result_fields                                        | obj1, obj2                                                                                                                           | Common fields are correctly populated                           | Should be successful |
 * | 04               | Assign different scanner types: set obj1 to em_scanner_type_radio and obj2 to em_scanner_type_sta                              | obj1.m_scan_result.id.scanner_type = em_scanner_type_radio, obj2.m_scan_result.id.scanner_type = em_scanner_type_sta                   | Objects have distinct scanner types                               | Should Pass     |
 * | 05               | Invoke the equality operator (operator==) on obj1 with obj2 and store the result                                               | result = obj1.operator==(obj2)                                                                                                         | The operator returns false indicating objects are not equal         | Should Pass     |
 * | 06               | Assert that the result from operator== is false using EXPECT_FALSE                                                           | EXPECT_FALSE(result)                                                                                                                  | The assertion passes if the result is false                         | Should Pass     |
 * | 07               | Print log statements indicating the entry and exit of the test                                                              | Console outputs messages for entering and exiting the test                                                                              | Appropriate log messages printed                                   | Should be successful |
 */
TEST(dm_scan_result_t_Test, DifferentScannerType)
{
    std::cout << "Entering DifferentScannerType test" << std::endl;

    dm_scan_result_t obj1{};
    dm_scan_result_t obj2{};
    EXPECT_NO_THROW(obj1.init());
    EXPECT_NO_THROW(obj2.init());
    
    fill_common_scan_result_fields(obj1);
    fill_common_scan_result_fields(obj2);
    
    // Set scanner_type differently
    std::cout << "Assigning obj1 id.scanner_type to em_scanner_type_radio" << std::endl;
    obj1.m_scan_result.id.scanner_type = em_scanner_type_radio;
    std::cout << "Assigning obj2 id.scanner_type to em_scanner_type_sta" << std::endl;
    obj2.m_scan_result.id.scanner_type = em_scanner_type_sta;
    
    std::cout << "Invoking operator== on obj1 with obj2" << std::endl;
    bool result = obj1.operator==(obj2);
    std::cout << "operator== returned: " << result << std::endl;
    
    EXPECT_FALSE(result);
    std::cout << "Exiting DifferentScannerType test" << std::endl;
}
/**
 * @brief Test to verify that dm_scan_result_t objects with different scan_status values are not equal
 *
 * This test creates two dm_scan_result_t objects and initializes them. It fills both objects with common scan result
 * fields and then assigns different scan_status values to each object. The operator== is then invoked to ensure that the
 * objects are considered unequal, thus validating the comparison functionality when scan_status differs.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 048@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                                              | Test Data                                                                                      | Expected Result                                    | Notes         |
 * | :--------------: | ---------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------- | -------------------------------------------------- | ------------- |
 * | 01               | Call init() on both dm_scan_result_t objects                                              | obj1.init(), obj2.init()                                                                       | No exceptions thrown from init()                   | Should Pass   |
 * | 02               | Populate common scan result fields in both objects                                          | fill_common_scan_result_fields(obj1), fill_common_scan_result_fields(obj2)                     | Fields initialized correctly                       | Should be successful |
 * | 03               | Assign scan_status value 1 to obj1                                                         | obj1.m_scan_result.scan_status = 1                                                             | obj1 scan_status set to 1                           | Should Pass   |
 * | 04               | Assign scan_status value 2 to obj2                                                         | obj2.m_scan_result.scan_status = 2                                                             | obj2 scan_status set to 2                           | Should Pass   |
 * | 05               | Invoke operator== to compare obj1 with obj2                                                | result = obj1.operator==(obj2)                                                                  | Result is false indicating objects are not equal  | Should Pass   |
 * | 06               | Assertion check using EXPECT_FALSE on operator== result                                   | EXPECT_FALSE(result)                                                                           | Test passes if result is false                     | Should Pass   |
 */
TEST(dm_scan_result_t_Test, DifferentScanStatus)
{
    std::cout << "Entering DifferentScanStatus test" << std::endl;

    dm_scan_result_t obj1{};
    dm_scan_result_t obj2{};
    EXPECT_NO_THROW(obj1.init());
    EXPECT_NO_THROW(obj2.init());
    
    fill_common_scan_result_fields(obj1);
    fill_common_scan_result_fields(obj2);
    
    // Set scan_status differently
    std::cout << "Assigning obj1 scan_status to 1" << std::endl;
    obj1.m_scan_result.scan_status = 1;
    std::cout << "Assigning obj2 scan_status to 2" << std::endl;
    obj2.m_scan_result.scan_status = 2;
    
    std::cout << "Invoking operator== on obj1 with obj2" << std::endl;
    bool result = obj1.operator==(obj2);
    std::cout << "operator== returned: " << result << std::endl;
    
    EXPECT_FALSE(result);
    std::cout << "Exiting DifferentScanStatus test" << std::endl;
}
/**
 * @brief Test comparison for dm_scan_result_t objects with different timestamps
 *
 * This test verifies that the operator== for dm_scan_result_t correctly distinguishes objects with different timestamps by setting different timestamp values.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 049@n
 * **Priority:** High@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * 
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize two dm_scan_result_t objects and invoke their init() methods. | obj1.init() = success, obj2.init() = success | Both init() calls complete without throwing an exception. | Should Pass |
 * | 02 | Call fill_common_scan_result_fields on both objects to populate common fields. | fill_common_scan_result_fields(obj1), fill_common_scan_result_fields(obj2) | Common scan result fields are correctly populated. | Should Pass |
 * | 03 | Assign different timestamp values to the two objects. | obj1.timestamp = "2023-01-01T12:00:00", obj2.timestamp = "2023-01-02T12:00:00" | Timestamps are set to the intended values. | Should be successful |
 * | 04 | Invoke the operator== on obj1 with obj2 to compare the scan results. | obj1.operator==(obj2) | operator== returns false due to differing timestamps. | Should Pass |
 * | 05 | Assert that the comparison returns false. | EXPECT_FALSE(result) | The assertion passes confirming the objects are not equal. | Should Pass |
 */
TEST(dm_scan_result_t_Test, DifferentTimestamp)
{
    std::cout << "Entering DifferentTimestamp test" << std::endl;

    dm_scan_result_t obj1{};
    dm_scan_result_t obj2{};
    EXPECT_NO_THROW(obj1.init());
    EXPECT_NO_THROW(obj2.init());
    
    fill_common_scan_result_fields(obj1);
    fill_common_scan_result_fields(obj2);
    
    // Set timestamp differently
    std::cout << "Assigning obj1 timestamp to '2023-01-01T12:00:00'" << std::endl;
    strncpy(obj1.m_scan_result.timestamp, "2023-01-01T12:00:00", sizeof(obj1.m_scan_result.timestamp));
    std::cout << "Assigning obj2 timestamp to '2023-01-02T12:00:00'" << std::endl;
    strncpy(obj2.m_scan_result.timestamp, "2023-01-02T12:00:00", sizeof(obj2.m_scan_result.timestamp));
    
    std::cout << "Invoking operator== on obj1 with obj2" << std::endl;
    bool result = obj1.operator==(obj2);
    std::cout << "operator== returned: " << result << std::endl;
    
    EXPECT_FALSE(result);
    std::cout << "Exiting DifferentTimestamp test" << std::endl;
}
/**
 * @brief Validates that dm_scan_result_t objects with different util values are not considered equal.
 *
 * This test initializes two dm_scan_result_t objects, fills common fields, then sets their 'util'
 * fields to different values (100 and 200 respectively). It then compares the two objects using the
 * overloaded operator== and expects the result to be false, confirming that differing 'util' values
 * lead to inequality.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 050@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                                                                | Test Data                                                             | Expected Result                                                                                        | Notes            |
 * | :--------------: | ---------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------ | ---------------- |
 * | 01               | Initialize two dm_scan_result_t objects and invoke init() on both                                          | obj1: init() with no parameters, obj2: init() with no parameters        | Both objects are initialized without throwing exceptions                                              | Should be successful |
 * | 02               | Populate common scan result fields for both objects using fill_common_scan_result_fields()                   | obj1: fill_common_scan_result_fields(obj1), obj2: fill_common_scan_result_fields(obj2) | Common fields are populated successfully without error                                                 | Should be successful |
 * | 03               | Assign different util values for each object                                                               | obj1: m_scan_result.util = 100, obj2: m_scan_result.util = 200           | The util fields of obj1 and obj2 are set to 100 and 200 respectively                                      | Should Pass      |
 * | 04               | Compare the two objects using the overloaded operator==                                                   | input: obj1, obj2; output: result variable                             | operator== returns false as the 'util' values are different; EXPECT_FALSE(result) succeeds                | Should Pass      |
 * | 05               | Log the test progress and outcomes                                                                          | output: console messages for entering, processing steps and exiting      | Console output reflects the correct sequence of operations, final result being false                     | Should be successful |
 */
TEST(dm_scan_result_t_Test, DifferentUtil)
{
    std::cout << "Entering DifferentUtil test" << std::endl;

    dm_scan_result_t obj1{};
    dm_scan_result_t obj2{};
    EXPECT_NO_THROW(obj1.init());
    EXPECT_NO_THROW(obj2.init());
    
    fill_common_scan_result_fields(obj1);
    fill_common_scan_result_fields(obj2);
    
    // Set util differently
    std::cout << "Assigning obj1 util to 100" << std::endl;
    obj1.m_scan_result.util = 100;
    std::cout << "Assigning obj2 util to 200" << std::endl;
    obj2.m_scan_result.util = 200;
    
    std::cout << "Invoking operator== on obj1 with obj2" << std::endl;
    bool result = obj1.operator==(obj2);
    std::cout << "operator== returned: " << result << std::endl;
    
    EXPECT_FALSE(result);
    std::cout << "Exiting DifferentUtil test" << std::endl;
}
/**
 * @brief Verify that the equality operator returns false when dm_scan_result_t objects have different noise levels.
 *
 * This test initializes two dm_scan_result_t objects, fills them with common scan result fields, and then assigns different noise values (30 for obj1 and 40 for obj2). It invokes the operator== to ensure that the objects are considered unequal due to the differing noise levels.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 051@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Call init() on both dm_scan_result_t objects (obj1 and obj2) | obj1.init(), obj2.init() | No exceptions thrown | Should Pass |
 * | 02 | Populate common scan result fields for both objects | fill_common_scan_result_fields(obj1), fill_common_scan_result_fields(obj2) | Common fields are correctly filled | Should Pass |
 * | 03 | Set noise levels differently on each object | obj1.m_scan_result.noise = 30, obj2.m_scan_result.noise = 40 | Noise values updated to 30 for obj1 and 40 for obj2 | Should be successful |
 * | 04 | Invoke operator== to compare the two objects | obj1.operator==(obj2), result variable | The operator== returns false indicating objects are not equal | Should Pass |
 * | 05 | Assert the inequality result from operator== | result = false | EXPECT_FALSE assertion passes confirming inequality | Should Pass |
 */
TEST(dm_scan_result_t_Test, DifferentNoise)
{
    std::cout << "Entering DifferentNoise test" << std::endl;

    dm_scan_result_t obj1{};
    dm_scan_result_t obj2{};
    EXPECT_NO_THROW(obj1.init());
    EXPECT_NO_THROW(obj2.init());
    
    fill_common_scan_result_fields(obj1);
    fill_common_scan_result_fields(obj2);
    
    // Set noise differently
    std::cout << "Assigning obj1 noise to 30" << std::endl;
    obj1.m_scan_result.noise = 30;
    std::cout << "Assigning obj2 noise to 40" << std::endl;
    obj2.m_scan_result.noise = 40;
    
    std::cout << "Invoking operator== on obj1 with obj2" << std::endl;
    bool result = obj1.operator==(obj2);
    std::cout << "operator== returned: " << result << std::endl;
    
    EXPECT_FALSE(result);
    std::cout << "Exiting DifferentNoise test" << std::endl;
}
/**
 * @brief Tests the dm_scan_result_t equality operator when objects have different num_neighbors values
 *
 * This test case verifies that the equality operator (operator==) for dm_scan_result_t objects returns false when the objects' num_neighbors field is different.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 052@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                            | Test Data                                          | Expected Result                                                                 | Notes          |
 * | :--------------: | ---------------------------------------------------------------------- | -------------------------------------------------- | ------------------------------------------------------------------------------- | -------------- |
 * |       01         | Initialize two dm_scan_result_t objects and invoke init() on each.     | obj1.init(), obj2.init()                           | Both objects initialized successfully without throwing exceptions.           | Should be successful |
 * |       02         | Populate common scan result fields for both objects.                   | fill_common_scan_result_fields(obj1), fill_common_scan_result_fields(obj2) | Common fields correctly set in both obj1 and obj2.                             | Should be successful |
 * |       03         | Assign different num_neighbors values to the objects.                  | obj1.m_scan_result.num_neighbors = 1, obj2.m_scan_result.num_neighbors = 2 | num_neighbors differs for obj1 and obj2.                                       | Should be successful |
 * |       04         | Invoke operator== on obj1 with obj2 and verify the result is false.      | operator==(obj2) returns result; input: obj1, obj2   | operator== returns false; EXPECT_FALSE(result) assertion passes.             | Should Pass    |
 */
TEST(dm_scan_result_t_Test, DifferentNumNeighbors)
{
    std::cout << "Entering DifferentNumNeighbors test" << std::endl;

    dm_scan_result_t obj1{};
    dm_scan_result_t obj2{};
    EXPECT_NO_THROW(obj1.init());
    EXPECT_NO_THROW(obj2.init());
    
    fill_common_scan_result_fields(obj1);
    fill_common_scan_result_fields(obj2);
    
    // Set num_neighbors differently
    std::cout << "Assigning obj1 num_neighbors to 1" << std::endl;
    obj1.m_scan_result.num_neighbors = 1;
    std::cout << "Assigning obj2 num_neighbors to 2" << std::endl;
    obj2.m_scan_result.num_neighbors = 2;
    
    std::cout << "Invoking operator== on obj1 with obj2" << std::endl;
    bool result = obj1.operator==(obj2);
    std::cout << "operator== returned: " << result << std::endl;
    
    EXPECT_FALSE(result);
    std::cout << "Exiting DifferentNumNeighbors test" << std::endl;
}
/**
 * @brief Validate that dm_scan_result_t equality operator returns false when aggr_scan_duration fields differ
 *
 * This test verifies that two dm_scan_result_t objects with different aggr_scan_duration values are not considered equal. It initializes two objects, fills their common fields, assigns different values to the aggr_scan_duration field, and then uses the equality operator to confirm they are not equal.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 053@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Create two dm_scan_result_t objects and call init on each | obj1, obj2: calling init() | Objects are initialized without throwing exceptions | Should be successful |
 * | 02 | Populate common scan result fields in both objects | obj1, obj2: calling fill_common_scan_result_fields() | Common fields are populated correctly | Should be successful |
 * | 03 | Set aggr_scan_duration of obj1 | obj1.m_scan_result.aggr_scan_duration = 500 | obj1 aggr_scan_duration is set to 500 | Should be successful |
 * | 04 | Set aggr_scan_duration of obj2 | obj2.m_scan_result.aggr_scan_duration = 600 | obj2 aggr_scan_duration is set to 600 | Should be successful |
 * | 05 | Compare obj1 and obj2 using operator== | Invocation: result = obj1.operator==(obj2) | operator== returns false indicating the objects are not equal | Should Pass |
 * | 06 | Validate the comparison result with an assertion | EXPECT_FALSE(result) | Assertion passes confirming non-equality | Should Pass |
 */
TEST(dm_scan_result_t_Test, DifferentAggrScanDuration)
{
    std::cout << "Entering DifferentAggrScanDuration test" << std::endl;

    dm_scan_result_t obj1{};
    dm_scan_result_t obj2{};
    EXPECT_NO_THROW(obj1.init());
    EXPECT_NO_THROW(obj2.init());
    
    fill_common_scan_result_fields(obj1);
    fill_common_scan_result_fields(obj2);
    
    // Set aggr_scan_duration differently
    std::cout << "Assigning obj1 aggr_scan_duration to 500" << std::endl;
    obj1.m_scan_result.aggr_scan_duration = 500;
    std::cout << "Assigning obj2 aggr_scan_duration to 600" << std::endl;
    obj2.m_scan_result.aggr_scan_duration = 600;
    
    std::cout << "Invoking operator== on obj1 with obj2" << std::endl;
    bool result = obj1.operator==(obj2);
    std::cout << "operator== returned: " << result << std::endl;
    
    EXPECT_FALSE(result);
    std::cout << "Exiting DifferentAggrScanDuration test" << std::endl;
}
/**
 * @brief Verify that two dm_scan_result_t objects with different scan_type values are not considered equal.
 *
 * This test creates two dm_scan_result_t objects, initializes them, fills common scan fields, and then assigns different scan_type values to each object.
 * It then compares the two objects using the overloaded operator== to ensure that they are not equal since the scan_type fields differ.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 054@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                                   | Test Data                                                         | Expected Result                                                                            | Notes         |
 * | :--------------: | --------------------------------------------------------------------------------------------- | ----------------------------------------------------------------- | ------------------------------------------------------------------------------------------ | ------------- |
 * | 01               | Initialize two dm_scan_result_t objects and call init() on both to ensure proper setup.         | obj1.init(), obj2.init()                                            | No exception thrown by both init() methods                                                 | Should Pass   |
 * | 02               | Fill the common scan result fields for both objects using fill_common_scan_result_fields().      | fill_common_scan_result_fields(obj1), fill_common_scan_result_fields(obj2) | Common scan result fields are set correctly                                                 | Should Pass   |
 * | 03               | Set scan_type field for obj1 to 1 and for obj2 to 2 to create a disparity between the two objects.| obj1.m_scan_result.scan_type = 1, obj2.m_scan_result.scan_type = 2      | scan_type fields are updated with respective values (1 and 2)                                | Should be successful |
 * | 04               | Invoke the overloaded operator== on obj1 with obj2 to compare the two objects.                | obj1.operator==(obj2)                                              | operator== returns false indicating objects are not equal due to different scan_type values  | Should Pass   |
 * | 05               | Assert that the result of operator== is false using EXPECT_FALSE.                            | EXPECT_FALSE(result)                                               | The assertion passes confirming that the objects are not equal                             | Should Pass   |
 */
TEST(dm_scan_result_t_Test, DifferentScanType)
{
    std::cout << "Entering DifferentScanType test" << std::endl;

    dm_scan_result_t obj1{};
    dm_scan_result_t obj2{};
    EXPECT_NO_THROW(obj1.init());
    EXPECT_NO_THROW(obj2.init());
    
    fill_common_scan_result_fields(obj1);
    fill_common_scan_result_fields(obj2);
    
    // Set scan_type differently
    std::cout << "Assigning obj1 scan_type to 1" << std::endl;
    obj1.m_scan_result.scan_type = 1;
    std::cout << "Assigning obj2 scan_type to 2" << std::endl;
    obj2.m_scan_result.scan_type = 2;
    
    std::cout << "Invoking operator== on obj1 with obj2" << std::endl;
    bool result = obj1.operator==(obj2);
    std::cout << "operator== returned: " << result << std::endl;
    
    EXPECT_FALSE(result);
    std::cout << "Exiting DifferentScanType test" << std::endl;
}
/**
 * @brief Validate that parse_scan_result_id_from_key successfully extracts scan result information from a valid key string when BSSID is not provided.
 *
 * This test verifies that the API parse_scan_result_id_from_key correctly parses the key string containing network identifier, device MAC, scanner MAC, operational class, channel, and scanner type, when BSSID is passed as NULL. The test ensures that the returned value is 0 and that the parsed fields in the structure match the expected values.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 055@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Prepare input key and initialize id variable with default values. | key = "NETID:network123;DEV_MAC:00-11-22-33-44-55;SCANNER_MAC:66-77-88-99-AA-BB;OP_CLASS:15;CHANNEL:6;SCANNER_TYPE:1", id = zeroed memory | id is initialized with default values (all zeros) | Should be successful |
 * | 02 | Construct dm_scan_result_t object using the default constructor. | No input parameters | Object is constructed without throwing an exception | Should Pass |
 * | 03 | Invoke parse_scan_result_id_from_key with the prepared key, id pointer, and NULL for BSSID. | key = provided string, id pointer, BSSID = NULL | API returns 0 indicating successful parsing | Should Pass |
 * | 04 | Validate the parsed id fields against the expected values. | id.net_id = "network123", id.dev_mac = "00-11-22-33-44-55", id.scanner_mac = "66-77-88-99-AA-BB", id.op_class = 15, id.channel = 6, id.scanner_type = em_scanner_type_radio | All fields match the expected values and assertions pass | Should Pass |
 */
TEST(dm_scan_result_t_Test, ValidKeyWithoutBSSID) {
    std::cout << "Entering ValidKeyWithoutBSSID test" << std::endl;

    const char key[] = "NETID:network123;DEV_MAC:00-11-22-33-44-55;SCANNER_MAC:66-77-88-99-AA-BB;OP_CLASS:15;CHANNEL:6;SCANNER_TYPE:1";
    em_scan_result_id_t id{};

    EXPECT_NO_THROW({
        dm_scan_result_t obj{};
        std::cout << "Constructed dm_scan_result_t object using default constructor" << std::endl;

        std::cout << "Invoking parse_scan_result_id_from_key with key: " << key
                  << " and id pointer: " << &id << ", BSSID: NULL" << std::endl;

        int ret = obj.parse_scan_result_id_from_key(key, &id, NULL);
        std::cout << "Method returned: " << ret << std::endl;
        EXPECT_EQ(ret, 0);

        char devMacStr[18];
        snprintf(devMacStr, sizeof(devMacStr),
                 "%02X-%02X-%02X-%02X-%02X-%02X",
                 id.dev_mac[0], id.dev_mac[1], id.dev_mac[2],
                 id.dev_mac[3], id.dev_mac[4], id.dev_mac[5]);

        char scannerMacStr[18];
        snprintf(scannerMacStr, sizeof(scannerMacStr),
                 "%02X-%02X-%02X-%02X-%02X-%02X",
                 id.scanner_mac[0], id.scanner_mac[1], id.scanner_mac[2],
                 id.scanner_mac[3], id.scanner_mac[4], id.scanner_mac[5]);

        std::cout << "Parsed id.net_id: " << id.net_id << std::endl;
        std::cout << "Parsed id.dev_mac: " << devMacStr << std::endl;
        std::cout << "Parsed id.scanner_mac: " << scannerMacStr << std::endl;
        std::cout << "Parsed id.op_class: " << static_cast<int>(id.op_class) << std::endl;
        std::cout << "Parsed id.channel: " << static_cast<int>(id.channel) << std::endl;
        std::cout << "Parsed id.scanner_type: " << static_cast<int>(id.scanner_type) << std::endl;

        EXPECT_STREQ(id.net_id, "network123");
        EXPECT_STREQ(devMacStr, "00-11-22-33-44-55");
        EXPECT_STREQ(scannerMacStr, "66-77-88-99-AA-BB");
        EXPECT_EQ(id.op_class, 15);
        EXPECT_EQ(id.channel, 6);
        EXPECT_EQ(id.scanner_type, em_scanner_type_radio);
    });

    std::cout << "Exiting ValidKeyWithoutBSSID test" << std::endl;
}


/**
 * @brief Validate parsing of a valid key containing BSSID information.
 *
 * This test verifies that the dm_scan_result_t object correctly parses a valid key string containing network ID, device MAC, scanner MAC, operating class, channel, and scanner type. It ensures that the method returns 0 and parses the fields into the id struct and BSSID buffer as expected.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 056
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Construct dm_scan_result_t object and invoke parse_scan_result_id_from_key with a valid key string | key = "NETID:network456;DEV_MAC:AA-BB-CC-DD-EE-FF;SCANNER_MAC:11-22-33-44-55-66;OP_CLASS:20;CHANNEL:11;SCANNER_TYPE:2", id pointer = valid pointer to em_scan_result_id_t, bssid pointer = pointer to 64-byte buffer initialized to zeros | API returns 0 without throwing an exception; dm_scan_result_t object is constructed successfully | Should Pass |
 * | 02 | Validate the parsed fields and updated BSSID buffer using assertions | net_id = "network456", dev_mac = "AA-BB-CC-DD-EE-FF", scanner_mac = "11-22-33-44-55-66", op_class = 20, channel = 11, scanner_type = em_scanner_type_sta, updated BSSID = "11-22-33-44-55-66" | Each parsed field and buffer value matches the expected value confirmed by EXPECT_STREQ and EXPECT_EQ checks | Should Pass |
 */
TEST(dm_scan_result_t_Test, ValidKeyWithBSSID) {
    std::cout << "Entering ValidKeyWithBSSID test" << std::endl;

    const char key[] = "NETID:network456;DEV_MAC:AA-BB-CC-DD-EE-FF;SCANNER_MAC:11-22-33-44-55-66;OP_CLASS:20;CHANNEL:11;SCANNER_TYPE:2";
    em_scan_result_id_t id{};
    unsigned char bssid_buffer[64] = {0};

    EXPECT_NO_THROW({
        dm_scan_result_t obj{};
        std::cout << "Constructed dm_scan_result_t object using default constructor" << std::endl;

        std::cout << "Invoking parse_scan_result_id_from_key with key: " << key
                  << ", id pointer: " << &id
                  << ", and bssid pointer: " << static_cast<void*>(bssid_buffer) << std::endl;

        int ret = obj.parse_scan_result_id_from_key(key, &id, bssid_buffer);
        std::cout << "Method returned: " << ret << std::endl;

        EXPECT_EQ(ret, 0);

        char devMacStr[18];
        std::snprintf(devMacStr, sizeof(devMacStr),
                      "%02X-%02X-%02X-%02X-%02X-%02X",
                      id.dev_mac[0], id.dev_mac[1], id.dev_mac[2],
                      id.dev_mac[3], id.dev_mac[4], id.dev_mac[5]);

        char scannerMacStr[18];
        std::snprintf(scannerMacStr, sizeof(scannerMacStr),
                      "%02X-%02X-%02X-%02X-%02X-%02X",
                      id.scanner_mac[0], id.scanner_mac[1], id.scanner_mac[2],
                      id.scanner_mac[3], id.scanner_mac[4], id.scanner_mac[5]);

        char bssidStr[18];
        std::snprintf(bssidStr, sizeof(bssidStr),
                      "%02X-%02X-%02X-%02X-%02X-%02X",
                      bssid_buffer[0], bssid_buffer[1], bssid_buffer[2],
                      bssid_buffer[3], bssid_buffer[4], bssid_buffer[5]);

        std::cout << "Parsed id.net_id: " << id.net_id << std::endl;
        std::cout << "Parsed id.dev_mac: " << devMacStr << std::endl;
        std::cout << "Parsed id.scanner_mac: " << scannerMacStr << std::endl;
        std::cout << "Parsed id.op_class: " << static_cast<int>(id.op_class) << std::endl;
        std::cout << "Parsed id.channel: " << static_cast<int>(id.channel) << std::endl;
        std::cout << "Parsed id.scanner_type: " << static_cast<int>(id.scanner_type) << std::endl;
        std::cout << "Updated BSSID value: " << bssidStr << std::endl;

        EXPECT_STREQ(id.net_id, "network456");
        EXPECT_STREQ(devMacStr, "AA-BB-CC-DD-EE-FF");
        EXPECT_STREQ(scannerMacStr, "11-22-33-44-55-66");
        EXPECT_EQ(id.op_class, 20);
        EXPECT_EQ(id.channel, 11);
        EXPECT_EQ(id.scanner_type, em_scanner_type_sta);

        EXPECT_STREQ(bssidStr, "11-22-33-44-55-66");
    });

    std::cout << "Exiting ValidKeyWithBSSID test" << std::endl;
}


/**
 * @brief Test to verify that parse_scan_result_id_from_key handles a NULL key pointer correctly.
 *
 * This test verifies that providing a NULL key pointer to the parse_scan_result_id_from_key API 
 * results in a negative error code return and that the id structure remains unchanged after the call.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 057
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Construct dm_scan_result_t object using default constructor | None | Object is constructed without throwing an exception | Should be successful |
 * | 02 | Invoke parse_scan_result_id_from_key with NULL key pointer | key = NULL, id pointer (with net_id = "initial", dev_mac = "initial", scanner_mac = "initial", op_class = 0, channel = 0, scanner_type = 0), bssid pointer = &0xAA | Return value is negative (< 0) indicating error | Should Pass |
 * | 03 | Verify that the id structure remains unchanged after the function call | id structure pre-initialized with "initial" values | id.net_id remains "initial" | Should Pass |
 */
TEST(dm_scan_result_t_Test, NullKeyPointer) {
    std::cout << "Entering NullKeyPointer test" << std::endl;

    const char* key = NULL;
    em_scan_result_id_t id{};
    strncpy(reinterpret_cast<char*>(id.net_id), "initial", sizeof(id.net_id) - 1);
    id.net_id[sizeof(id.net_id) - 1] = '\0';

    strncpy(reinterpret_cast<char*>(id.dev_mac), "initial", sizeof(id.dev_mac) - 1);
    id.dev_mac[sizeof(id.dev_mac) - 1] = '\0';

    strncpy(reinterpret_cast<char*>(id.scanner_mac), "initial", sizeof(id.scanner_mac) - 1);
    id.scanner_mac[sizeof(id.scanner_mac) - 1] = '\0';

    id.op_class = 0;
    id.channel = 0;
    id.scanner_type = static_cast<em_scanner_type_t>(0);

    unsigned char bssid_val = 0xAA;
    unsigned char* bssid_ptr = &bssid_val;

    EXPECT_NO_THROW({
        dm_scan_result_t obj{};
        std::cout << "Constructed dm_scan_result_t object using default constructor" << std::endl;
        std::cout << "Invoking parse_scan_result_id_from_key with NULL key, id pointer: "
                  << &id << ", and bssid pointer: " << static_cast<void*>(bssid_ptr) << std::endl;

        int ret = obj.parse_scan_result_id_from_key(key, &id, bssid_ptr);
        std::cout << "Method returned: " << ret << std::endl;

        EXPECT_LT(ret, 0);

        std::cout << "id.net_id after call: " << id.net_id << std::endl;
        EXPECT_STREQ(reinterpret_cast<const char*>(id.net_id), "initial");
    });

    std::cout << "Exiting NullKeyPointer test" << std::endl;
}

/**
 * @brief Verify that parse_scan_result_id_from_key handles a NULL id pointer appropriately
 *
 * This test verifies that when a NULL pointer is passed for the id parameter to the parse_scan_result_id_from_key method, the function returns a negative error code. This is important for validating proper error handling and ensuring robustness against invalid inputs.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 058@n
 * **Priority:** High@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * 
 * **Test Procedure:**
 * | Variation / Step | Description                                                                                     | Test Data                                                                                                                                                           | Expected Result                                                  | Notes        |
 * | :--------------: | ----------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------- | ------------ |
 * | 01               | Invoke parse_scan_result_id_from_key using a valid key string but a NULL id pointer and NULL BSSID | key = "NETID:network789;DEV_MAC:12-34-56-78-9A-BC;SCANNER_MAC:DE-AD-BE-EF-00-01;OP_CLASS:25;CHANNEL:36;SCANNER_TYPE:1", id = NULL, bssid = NULL | The API should return a negative error code and the assertion EXPECT_LT(ret, 0) should pass | Should Fail  |
 */
TEST(dm_scan_result_t_Test, NullIDPointer) {
    std::cout << "Entering NullIDPointer test" << std::endl;
    
    // Prepare test data
    const char key[] = "NETID:network789;DEV_MAC:12-34-56-78-9A-BC;SCANNER_MAC:DE-AD-BE-EF-00-01;OP_CLASS:25;CHANNEL:36;SCANNER_TYPE:1";
    em_scan_result_id_t* id = NULL;
    
    // Create object using default constructor
    EXPECT_NO_THROW({
        dm_scan_result_t obj{};
        std::cout << "Constructed dm_scan_result_t object using default constructor" << std::endl;
        
        std::cout << "Invoking parse_scan_result_id_from_key with key: " << key 
                  << ", NULL id pointer, and BSSID: NULL" << std::endl;
                  
        int ret = obj.parse_scan_result_id_from_key(key, id, NULL);
        std::cout << "Method returned: " << ret << std::endl;
        
        // Expected to return negative error code since id pointer is NULL
        EXPECT_LT(ret, 0);
    });
    
    std::cout << "Exiting NullIDPointer test" << std::endl;
}
/**
 * @brief Test the parse_scan_result_id_from_key API with an invalid key format to ensure it returns a negative error code and does not modify output parameters.
 *
 * This test creates an instance of dm_scan_result_t and calls parse_scan_result_id_from_key with a deliberately invalid key string ("INVALID_KEY_FORMAT"). The ID and BSSID buffer are pre-initialized with "unchanged" values. The test verifies that the function returns a negative error code, indicating failure due to the invalid key, and confirms that both the id and bssid_buffer remain unmodified.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 059@n
 * **Priority:** High@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * 
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :--------------: | ----------- | --------- | --------------- | ----- |
 * | 01 | Prepare test data by initializing key, id, and bssid_buffer to "unchanged". | key = "INVALID_KEY_FORMAT", id.net_id = "unchanged", id.dev_mac = "unchanged", id.scanner_mac = "unchanged", id.op_class = 99, id.channel = 99, id.scanner_type = em_scanner_type_radio, bssid_buffer = "unchanged" | Test data is correctly initialized with expected preset values. | Should be successful |
 * | 02 | Construct a dm_scan_result_t object using the default constructor. | No additional test data. | Object creation does not throw any exceptions. | Should be successful |
 * | 03 | Invoke parse_scan_result_id_from_key with the invalid key and verify that the return value is negative and that both id and bssid_buffer remain unchanged. | key = "INVALID_KEY_FORMAT", id pointer refers to pre-initialized id, bssid_buffer pointer refers to pre-initialized bssid_buffer | API returns a negative error code, id remains "unchanged", and bssid_buffer remains "unchanged". | Should Fail |
 */
TEST(dm_scan_result_t_Test, InvalidKeyFormat) {
    std::cout << "Entering InvalidKeyFormat test" << std::endl;

    // Prepare test data
    const char key[] = "INVALID_KEY_FORMAT";
    em_scan_result_id_t id{};

    // Pre-fill id with known value to compare that it remains unchanged in failure case
    strncpy(reinterpret_cast<char*>(id.net_id), "unchanged", sizeof(id.net_id) - 1);
    id.net_id[sizeof(id.net_id) - 1] = '\0';

    strncpy(reinterpret_cast<char*>(id.dev_mac), "unchanged", sizeof(id.dev_mac) - 1);
    id.dev_mac[sizeof(id.dev_mac) - 1] = '\0';

    strncpy(reinterpret_cast<char*>(id.scanner_mac), "unchanged", sizeof(id.scanner_mac) - 1);
    id.scanner_mac[sizeof(id.scanner_mac) - 1] = '\0';

    id.op_class = 99;
    id.channel = 99;
    id.scanner_type = em_scanner_type_radio;

    unsigned char bssid_buffer[64] = "unchanged";

    // Create object using default constructor
    EXPECT_NO_THROW({
        dm_scan_result_t obj{};
        std::cout << "Constructed dm_scan_result_t object using default constructor" << std::endl;

        std::cout << "Invoking parse_scan_result_id_from_key with invalid key format: " << key
                  << ", id pointer: " << &id
                  << ", and bssid pointer: " << static_cast<void*>(bssid_buffer) << std::endl;

        int ret = obj.parse_scan_result_id_from_key(key, &id, bssid_buffer);
        std::cout << "Method returned: " << ret << std::endl;

        // Expected to return negative error code because key format is invalid
        EXPECT_LT(ret, 0);

        // Verify that id remains unchanged:
        std::cout << "id.net_id remains: " << id.net_id << std::endl;
        EXPECT_STREQ(reinterpret_cast<const char*>(id.net_id), "unchanged");

        // Verify bssid remains unchanged:
        std::cout << "BSSID remains: " << bssid_buffer << std::endl;
        EXPECT_STREQ(reinterpret_cast<const char*>(bssid_buffer), "unchanged");
    });

    std::cout << "Exiting InvalidKeyFormat test" << std::endl;
}

/**
 * @brief Test to verify that parse_scan_result_id_from_key correctly handles an empty key string.
 *
 * This test verifies that when an empty key string is provided, the parse_scan_result_id_from_key API returns a negative error code, and the provided id and bssid buffers remain unchanged. This ensures that the function does not alter output buffers when essential input data is missing.
 *
 * **Test Group ID:** Basic: 01  
 * **Test Case ID:** 060  
 * **Priority:** High  
 * 
 * **Pre-Conditions:** None  
 * **Dependencies:** None  
 * **User Interaction:** None  
 * 
 * **Test Procedure:**  
 * | Variation / Step | Description | Test Data | Expected Result | Notes |  
 * | :--------------: | ----------- | --------- | --------------- | ----- |  
 * | 01 | Construct dm_scan_result_t object using default constructor. | None | Object is constructed successfully without throwing an exception. | Should be successful |  
 * | 02 | Invoke parse_scan_result_id_from_key with an empty key string, while id and bssid buffers are pre-filled with "initial". | key = "", id.net_id = "initial", id.dev_mac = "initial", id.scanner_mac = "initial", id.op_class = 50, id.channel = 50, id.scanner_type = em_scanner_type_sta, bssid = "initial" | Returns a negative error code; id.net_id and bssid remain unchanged (i.e., "initial"). | Should Pass |
 */
TEST(dm_scan_result_t_Test, EmptyKeyString) {
    std::cout << "Entering EmptyKeyString test" << std::endl;

    const char key[] = "";
    em_scan_result_id_t id{};

    strncpy(id.net_id, "initial", sizeof(id.net_id) - 1);
    id.net_id[sizeof(id.net_id) - 1] = '\0';

    const char* initStr = "initial";
    memcpy(id.dev_mac, initStr, strlen(initStr));
    memcpy(id.scanner_mac, initStr, strlen(initStr));

    id.op_class = 50;
    id.channel = 50;
    id.scanner_type = em_scanner_type_sta;

    unsigned char bssid_buffer[64];
    memcpy(bssid_buffer, initStr, strlen(initStr));

    EXPECT_NO_THROW({
        dm_scan_result_t obj{};
        std::cout << "Constructed dm_scan_result_t object using default constructor" << std::endl;

        std::cout << "Invoking parse_scan_result_id_from_key with empty key string" << std::endl;
        int ret = obj.parse_scan_result_id_from_key(key, &id, bssid_buffer);

        std::cout << "Method returned: " << ret << std::endl;
        EXPECT_LT(ret, 0);

        std::cout << "id.net_id remains: " << id.net_id << std::endl;
        EXPECT_STREQ(id.net_id, "initial");

        std::cout << "BSSID remains: " << reinterpret_cast<const char*>(bssid_buffer) << std::endl;
        EXPECT_STREQ(reinterpret_cast<const char*>(bssid_buffer), "initial");
    });

    std::cout << "Exiting EmptyKeyString test" << std::endl;
}

/**
 * @brief Verify that dm_scan_result_t can be constructed and destructed with a valid scan pointer without throwing exceptions.
 *
 * This test constructs an instance of dm_scan_result_t with a valid em_scan_result_t pointer initialized with sample data ("ValidScanResult") and ensures that the object is constructed and destructed properly without any exceptions. The internal member (m_scan_result.info) is printed for verification.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 061@n
 * **Priority:** High@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                                                      | Test Data                                                            | Expected Result                                                    | Notes          |
 * | :--------------: | ------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------- | ------------------------------------------------------------------ | -------------- |
 * | 01               | Create and populate a valid em_scan_result_t pointer with sample info ("ValidScanResult").        | sampleValue = "ValidScanResult"                                      | em_scan_result_t pointer is allocated and its info field is populated| Should be successful |
 * | 02               | Invoke dm_scan_result_t constructor with the valid scan pointer inside an EXPECT_NO_THROW block.    | input_ptr = validScanResult                                          | Object is constructed without throwing an exception               | Should Pass    |
 * | 03               | Invoke the destructor by deleting the dm_scan_result_t object and verify resource release.          | input_ptr = validScanResult (managed by dm_scan_result_t)             | Destructor invoked and object resources are released without error  | Should Pass    |
 */
TEST(dm_scan_result_t_Test, Destruction_WithValidScanPointer) {
    std::cout << "Entering Destruction_WithValidScanPointer test" << std::endl;

    em_scan_result_t* validScanResult = new em_scan_result_t();

    const char sampleValue[] = "ValidScanResult";
    strncpy(validScanResult->timestamp, sampleValue, sizeof(validScanResult->timestamp) - 1);
    validScanResult->timestamp[sizeof(validScanResult->timestamp) - 1] = '\0';

    std::cout << "Created em_scan_result_t with timestamp: " << validScanResult->timestamp << std::endl;

    std::cout << "Invoking dm_scan_result_t(em_scan_result_t*) constructor with validScanResult pointer: "
              << static_cast<void*>(validScanResult) << std::endl;

    EXPECT_NO_THROW({
        dm_scan_result_t* obj = new dm_scan_result_t(validScanResult);
        std::cout << "dm_scan_result_t object constructed using valid pointer." << std::endl;
        std::cout << "Internal m_scan_result.timestamp value: " << obj->m_scan_result.timestamp << std::endl;
        std::cout << "Invoking destructor on dm_scan_result_t object with valid scan result pointer." << std::endl;
        delete obj;
    });

    delete validScanResult;

    std::cout << "Exiting Destruction_WithValidScanPointer test" << std::endl;
}


/**
 * @brief Verifies that a dm_scan_result_t object constructed using the default constructor can be successfully destroyed when the internal scan pointer is null
 *
 * This test verifies that instantiating a dm_scan_result_t object using the default constructor does not throw an exception, and that its destructor correctly cleans up the object even when the internal m_scan_result pointer is null. This is essential to ensure that resources are managed properly and no runtime errors occur during object destruction.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 062@n
 * **Priority:** High@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * 
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                                 | Test Data                                   | Expected Result                                  | Notes         |
 * | :--------------: | --------------------------------------------------------------------------- | ------------------------------------------- | ------------------------------------------------ | ------------- |
 * | 01               | Invoke the default constructor of dm_scan_result_t and verify object creation | constructor = default                         | No exception thrown; object constructed successfully | Should Pass   |
 * | 02               | Allow the object to go out of scope to automatically invoke the destructor    | No input, object goes out of scope          | Destructor invoked without error                | Should be successful |
 */
TEST(dm_scan_result_t_Test, Destruction_WithNullScanPointer_DefaultConstructor) {
    std::cout << "Entering Destruction_WithNullScanPointer_DefaultConstructor test" << std::endl;

    std::cout << "Invoking default constructor dm_scan_result_t()." << std::endl;
    EXPECT_NO_THROW({
        dm_scan_result_t obj{};
        std::cout << "dm_scan_result_t object constructed using default constructor." << std::endl;
        // Log internal state of the placeholder m_scan_result.
        std::cout << "dm_scan_result_t object will go out of scope; destructor will be invoked automatically." << std::endl;
    });

    std::cout << "Exiting Destruction_WithNullScanPointer_DefaultConstructor test" << std::endl;
}
/**
 * @brief Test to validate destruction behavior of dm_scan_result_t via copy constructor when the internal scan pointer is null.
 *
 * This test verifies that constructing a copy of a dm_scan_result_t object (whose internal scan pointer is assumed to be null by default)
 * using the copy constructor does not throw any exceptions during its lifetime and destruction.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 063@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                                   | Test Data                                                       | Expected Result                                                                               | Notes              |
 * | :---------------: | --------------------------------------------------------------------------------------------- | --------------------------------------------------------------- | --------------------------------------------------------------------------------------------- | ------------------ |
 * | 01                | Log the commencement of the test.                                                             | None                                                            | Console displays entry message.                                                               | Should be successful |
 * | 02                | Construct an original dm_scan_result_t object using the default constructor (internal scan pointer is null). | original object creation using default constructor; m_scan_result.info = default | Original object gets constructed with a null scan pointer.                                     | Should Pass        |
 * | 03                | Log the internal m_scan_result.info value for the original object.                            | originalObj.m_scan_result.info = default                          | Console logs the original object's info value.                                               | Should be successful |
 * | 04                | Invoke the copy constructor wrapped in EXPECT_NO_THROW to create a copy of the original object.  | Input: originalObj; Output: new copyObj with identical internal state      | Copy construction succeeds without throwing any exceptions.                                  | Should Pass        |
 * | 05                | Log the internal m_scan_result.info value of the copy constructed object and allow its destructor to be invoked.  | copyObj.m_scan_result.info = default; destructor called on scope exit       | Console logs the copy object's info value and the copy object is destroyed without issues.     | Should be successful |
 * | 06                | Log the exit message indicating completion of the test.                                       | None                                                            | Console displays exit message.                                                                 | Should be successful |
 */
TEST(dm_scan_result_t_Test, Destruction_WithNullScanPointer_CopyConstructor) {
    std::cout << "Entering Destruction_WithNullScanPointer_CopyConstructor test" << std::endl;

    std::cout << "Constructing original dm_scan_result_t object using default constructor." << std::endl;
    dm_scan_result_t originalObj{};

    std::cout << "Original object's internal m_scan_result state:"
              << " noise="     << originalObj.m_scan_result.noise
              << ", channel="  << static_cast<int>(originalObj.m_scan_result.id.channel)
              << ", op_class=" << static_cast<int>(originalObj.m_scan_result.id.op_class)
              << std::endl;

    std::cout << "Invoking copy constructor dm_scan_result_t(const dm_scan_result_t&) to create a copy." << std::endl;
    EXPECT_NO_THROW({
        dm_scan_result_t copyObj(originalObj);
        std::cout << "Copy constructed dm_scan_result_t object." << std::endl;

        std::cout << "Copy object's internal m_scan_result state:"
                  << " noise="     << copyObj.m_scan_result.noise
                  << ", channel="  << static_cast<int>(copyObj.m_scan_result.id.channel)
                  << ", op_class=" << static_cast<int>(copyObj.m_scan_result.id.op_class)
                  << std::endl;

        std::cout << "copyObj will go out of scope; destructor will be invoked automatically." << std::endl;
    });

    std::cout << "Exiting Destruction_WithNullScanPointer_CopyConstructor test" << std::endl;
}

