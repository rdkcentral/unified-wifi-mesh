
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
#include "dm_neighbor.h"
#include <cstring>

void parse_mac(const char* str, mac_address_t mac)
{
    unsigned int bytes[6] = {0};

    sscanf(str, "%02x:%02x:%02x:%02x:%02x:%02x",
           &bytes[0], &bytes[1], &bytes[2],
           &bytes[3], &bytes[4], &bytes[5]);

    for (int i = 0; i < 6; i++) {
        mac[i] = static_cast<unsigned char>(bytes[i]);
    }
}

/**
 * @brief Test to verify correct decoding of all valid neighbor fields.
 *
 * This test verifies that the dm_neighbor_t::decode method correctly extracts all valid fields from a JSON object representing a neighbor. The test ensures that both numeric and string fields, including MAC addresses and positional data, are correctly parsed and stored.
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
 * | Variation / Step | Description                                                                                        | Test Data                                                                                                               | Expected Result                                                                                  | Notes             |
 * | :--------------: | -------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------- | ----------------- |
 * | 01               | Create JSON object and add valid neighbor parameters.                                             | None                                                                                                                    | JSON object created with keys: "Neighbor", "POS_I", "POS_J", "POS_K", "NextHop", "NumHops", "PathLoss". | Should be successful |
 * | 02               | Initialize dummy parent and assign to variable for decoding context.                              | dummy_parent = 100, parent_id = address of dummy_parent                                                                   | Dummy parent variable created and pointer assigned.                                            | Should be successful |
 * | 03               | Invoke the decode method of dm_neighbor_t using the JSON object and parent id.                      | Input: json_obj, parent_id; Output: ret from decode                                                                    | API returns 0 indicating successful decoding.                                                  | Should Pass       |
 * | 04               | Validate the neighbor MAC address field using memcmp.                                             | Expected: input "Neighbor" = "AA:BB:CC:DD:EE:FF", output stored in neighbor.m_neighbor_info.nbr (as byte array)         | memcmp returns 0 if neighbor MAC addresses match the expected byte array.                        | Should Pass       |
 * | 05               | Validate the positional fields pos_x, pos_y, pos_z corresponding to "POS_I", "POS_J", "POS_K".      | Expected: input "POS_I" = 1, "POS_J" = 2, "POS_K" = 3; output stored in neighbor.m_neighbor_info.pos_x, pos_y, pos_z        | Field values match the expected numerical values.                                              | Should Pass       |
 * | 06               | Validate the neighbor's next hop field using memcmp.                                              | Expected: input "NextHop" = "11:22:33:44:55:66", output stored in neighbor.m_neighbor_info.next_hop (as byte array)        | memcmp returns 0 if next hop values match the expected byte array.                               | Should Pass       |
 * | 07               | Validate the "NumHops" and "PathLoss" fields.                                                       | Expected: input "NumHops" = 2, "PathLoss" = 50; output stored in neighbor.m_neighbor_info.num_hops, path_loss                  | Field values match the expected numerical values.                                              | Should Pass       |
 * | 08               | Delete the created JSON object to free resources.                                                 | Input: json_obj                                                                                                         | JSON object is properly deleted using cJSON_Delete, freeing allocated memory.                    | Should be successful |
 */
TEST(dm_neighbor_t, decode_all_valid_fields_present) {
    std::cout << "Entering decode_all_valid_fields_present test" << std::endl;
    cJSON* json_obj = cJSON_CreateObject();
    cJSON_AddItemToObject(json_obj, "Neighbor", cJSON_CreateString("AA:BB:CC:DD:EE:FF"));
    cJSON_AddItemToObject(json_obj, "POS_I", cJSON_CreateNumber(1));
    cJSON_AddItemToObject(json_obj, "POS_J", cJSON_CreateNumber(2));
    cJSON_AddItemToObject(json_obj, "POS_K", cJSON_CreateNumber(3));
    cJSON_AddItemToObject(json_obj, "NextHop", cJSON_CreateString("11:22:33:44:55:66"));
    cJSON_AddItemToObject(json_obj, "NumHops", cJSON_CreateNumber(2));
    cJSON_AddItemToObject(json_obj, "PathLoss", cJSON_CreateNumber(50));
    int dummy_parent = 100;
    void* parent_id = &dummy_parent;
    dm_neighbor_t neighbor;
    int ret = neighbor.decode(json_obj, parent_id);
    EXPECT_EQ(ret, 0);
    unsigned char nbr[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    EXPECT_EQ(0, memcmp(neighbor.m_neighbor_info.nbr, nbr, sizeof(nbr)));
    EXPECT_EQ(neighbor.m_neighbor_info.pos_x, 1);
    EXPECT_EQ(neighbor.m_neighbor_info.pos_y, 2);
    EXPECT_EQ(neighbor.m_neighbor_info.pos_z, 3);
    unsigned char next_hop[6] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
    EXPECT_EQ(0, memcmp(neighbor.m_neighbor_info.next_hop, next_hop, sizeof(next_hop)));
    EXPECT_EQ(neighbor.m_neighbor_info.num_hops, 2);
    EXPECT_EQ(neighbor.m_neighbor_info.path_loss, 50);
    cJSON_Delete(json_obj);
    std::cout << "Exiting decode_all_valid_fields_present test" << std::endl;
}
/**
 * @brief Test decode function for a subset of fields in dm_neighbor_t
 *
 * This test ensures that the decode method of the dm_neighbor_t class correctly extracts and converts the provided JSON fields ("Neighbor" and "NumHops") into the appropriate internal representations. It also verifies that fields not present in the JSON are defaulted to expected initial values.
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
 * | Variation / Step | Description                                                                                          | Test Data                                                                                                                        | Expected Result                                          | Notes          |
 * | :--------------: | ---------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------- | -------------- |
 * | 01               | Create a JSON object and add "Neighbor" and "NumHops" fields                                        | json_obj created; Neighbor = "AA:BB:CC:DD:EE:FF", NumHops = 3, dummy_parent = 200, parent_id = &dummy_parent                      | JSON object is created with the valid fields             | Should be successful |
 * | 02               | Invoke decode() method on dm_neighbor_t with the created JSON object and parent_id                    | dm_neighbor_t instance, json_obj, parent_id                                                                                    | Return value from decode() is 0                          | Should Pass    |
 * | 03               | Validate the decoded neighbor information, ensuring correct conversion and default initializations    | neighbor.m_neighbor_info.nbr = {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF}, num_hops = 3, pos_x = 0, pos_y = 0, pos_z = 0, next_hop = "", path_loss = 0 | All fields match expected values after decoding          | Should Pass    |
 */
TEST(dm_neighbor_t, decode_subset_of_fields) {
    std::cout << "Entering decode_subset_of_fields test" << std::endl;
    cJSON* json_obj = cJSON_CreateObject();
    cJSON_AddItemToObject(json_obj, "Neighbor", cJSON_CreateString("AA:BB:CC:DD:EE:FF"));
    cJSON_AddItemToObject(json_obj, "NumHops", cJSON_CreateNumber(3));
    int dummy_parent = 200;
    void* parent_id = &dummy_parent;
    dm_neighbor_t neighbor;
    int ret = neighbor.decode(json_obj, parent_id);
    EXPECT_EQ(ret, 0);
    unsigned char nbr[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    EXPECT_EQ(0, memcmp(neighbor.m_neighbor_info.nbr, nbr, sizeof(nbr)));
    EXPECT_EQ(neighbor.m_neighbor_info.num_hops, 3);
    EXPECT_EQ(neighbor.m_neighbor_info.pos_x, 0);
    EXPECT_EQ(neighbor.m_neighbor_info.pos_y, 0);
    EXPECT_EQ(neighbor.m_neighbor_info.pos_z, 0);
    EXPECT_EQ(memcmp(neighbor.m_neighbor_info.next_hop, "", 1), 0);
    EXPECT_EQ(neighbor.m_neighbor_info.path_loss, 0);
    cJSON_Delete(json_obj);
    std::cout << "Exiting decode_subset_of_fields test" << std::endl;
}
/**
 * @brief Validate decoding of an empty JSON object into dm_neighbor_t object
 *
 * This test checks that when an empty JSON object is provided to the dm_neighbor_t::decode method,
 * the method initializes the neighbor information fields to their default values. It verifies that the
 * API returns 0 and that all fields such as nbr, pos_x, pos_y, pos_z, next_hop, num_hops, and path_loss are set to zero or empty as expected.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 003
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize empty JSON object and setup dummy parent, and create a dm_neighbor_t instance | json_obj: cJSON_CreateObject(), dummy_parent: 300, parent_id: address of dummy_parent, neighbor: uninitialized instance of dm_neighbor_t | JSON object is created and variables are initialized successfully | Should be successful |
 * | 02 | Invoke neighbor.decode() with the empty JSON object and dummy parent ID, then verify all neighbor fields for default values | input: json_obj: empty JSON object, parent_id: pointer to dummy_parent; output: ret = 0, neighbor.m_neighbor_info.nbr = "", pos_x = 0, pos_y = 0, pos_z = 0, next_hop = "", num_hops = 0, path_loss = 0 | API returns 0 and the dm_neighbor_t instance fields are correctly initialized to default values | Should Pass |
 */
TEST(dm_neighbor_t, decode_empty_json_object) {
    std::cout << "Entering decode_empty_json_object test" << std::endl;
    cJSON* json_obj = cJSON_CreateObject();
    int dummy_parent = 300;
    void* parent_id = &dummy_parent;
    dm_neighbor_t neighbor;
    int ret = neighbor.decode(json_obj, parent_id);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(memcmp(neighbor.m_neighbor_info.nbr, "", 1), 0);
    EXPECT_EQ(neighbor.m_neighbor_info.pos_x, 0);
    EXPECT_EQ(neighbor.m_neighbor_info.pos_y, 0);
    EXPECT_EQ(neighbor.m_neighbor_info.pos_z, 0);
    EXPECT_EQ(memcmp(neighbor.m_neighbor_info.next_hop, "", 1), 0);
    EXPECT_EQ(neighbor.m_neighbor_info.num_hops, 0);
    EXPECT_EQ(neighbor.m_neighbor_info.path_loss, 0);
    cJSON_Delete(json_obj);
    std::cout << "Exiting decode_empty_json_object test" << std::endl;
}
/**
 * @brief Verify that passing a null JSON object to the decode method returns an error code
 *
 * This test case checks that the dm_neighbor_t::decode method correctly handles a null JSON object as input. 
 * It verifies that the method returns a non-zero error code when provided with a nullptr as the JSON object.
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
 * | Variation / Step | Description                                                         | Test Data                                                                  | Expected Result                                                        | Notes       |
 * | :--------------: | ------------------------------------------------------------------- | -------------------------------------------------------------------------- | ---------------------------------------------------------------------- | ----------- |
 * | 01               | Invoke dm_neighbor_t::decode with json_obj as nullptr and valid parent_id | json_obj = nullptr, dummy_parent = 400, parent_id = pointer to dummy_parent, ret expected != 0 | decode returns a non-zero error code and EXPECT_NE(ret, 0) assertion passes | Should Fail |
 */
TEST(dm_neighbor_t, decode_null_json_object) {
    std::cout << "Entering decode_null_json_object test" << std::endl;
    cJSON* json_obj = nullptr;
    int dummy_parent = 400;
    void* parent_id = &dummy_parent;
    dm_neighbor_t neighbor;
    int ret = neighbor.decode(json_obj, parent_id);
    EXPECT_NE(ret, 0);
    std::cout << "Exiting decode_null_json_object test" << std::endl;
}
/**
 * @brief Test the decode function with invalid field types
 *
 * This test verifies that the decode function correctly handles JSON objects when they contain invalid field types.
 * In this case, the "NumHops" field is provided as a string instead of the expected numeric type.
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
 * | 01 | Create a JSON object with "Neighbor" as a number, "NumHops" as a string (invalid type), and other fields ("POS_I", "POS_J", "POS_K") as numbers; invoke neighbor.decode with the JSON object and a valid parent ID pointer, then assert that the function returns a non-zero error code. | Neighbor = 123456, NumHops = three, POS_I = 5, POS_J = 6, POS_K = 7, parent_id = 500 | Expected error return (non-zero) from neighbor.decode and the assertion (EXPECT_NE(ret, 0)) passes | Should Fail |
 */
TEST(dm_neighbor_t, decode_invalid_field_types) {
    std::cout << "Entering decode_invalid_field_types test" << std::endl;
    cJSON* json_obj = cJSON_CreateObject();
    cJSON_AddItemToObject(json_obj, "Neighbor", cJSON_CreateNumber(123456));
    cJSON_AddItemToObject(json_obj, "NumHops", cJSON_CreateString("three"));
    cJSON_AddItemToObject(json_obj, "POS_I", cJSON_CreateNumber(5));
    cJSON_AddItemToObject(json_obj, "POS_J", cJSON_CreateNumber(6));
    cJSON_AddItemToObject(json_obj, "POS_K", cJSON_CreateNumber(7));
    int dummy_parent = 500;
    void* parent_id = &dummy_parent;
    dm_neighbor_t neighbor;
    int ret = neighbor.decode(json_obj, parent_id);
    EXPECT_NE(ret, 0);
    cJSON_Delete(json_obj);
    std::cout << "Exiting decode_invalid_field_types test" << std::endl;
}
/**
 * @brief Test decode method of dm_neighbor_t with valid JSON but null parent pointer
 *
 * This test verifies that the decode method of dm_neighbor_t returns a non-zero error code when a valid JSON object containing neighbor data is provided along with a null parent pointer. It ensures proper error handling in scenarios where the parent pointer is missing.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 006@n
 * **Priority:** (Low/Med/High) High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Create JSON object with neighbor details and call decode with null parent pointer | json_obj = {Neighbor = AA:BB:CC:DD:EE:FF, POS_I = 10, POS_J = 20, POS_K = 30, NextHop = 11:22:33:44:55:66, NumHops = 4, PathLoss = 60}, parent_id = nullptr | Return value should be non-zero indicating an error due to null parent pointer | Should Fail |
 */
TEST(dm_neighbor_t, decode_valid_json_parent_null) {
    std::cout << "Entering decode_valid_json_parent_null test" << std::endl;
    cJSON* json_obj = cJSON_CreateObject();
    cJSON_AddItemToObject(json_obj, "Neighbor", cJSON_CreateString("AA:BB:CC:DD:EE:FF"));
    cJSON_AddItemToObject(json_obj, "POS_I", cJSON_CreateNumber(10));
    cJSON_AddItemToObject(json_obj, "POS_J", cJSON_CreateNumber(20));
    cJSON_AddItemToObject(json_obj, "POS_K", cJSON_CreateNumber(30));
    cJSON_AddItemToObject(json_obj, "NextHop", cJSON_CreateString("11:22:33:44:55:66"));
    cJSON_AddItemToObject(json_obj, "NumHops", cJSON_CreateNumber(4));
    cJSON_AddItemToObject(json_obj, "PathLoss", cJSON_CreateNumber(60));
    void* parent_id = nullptr;
    dm_neighbor_t neighbor;
    int ret = neighbor.decode(json_obj, parent_id);
    EXPECT_NE(ret, 0);
    cJSON_Delete(json_obj);
    std::cout << "Exiting decode_valid_json_parent_null test" << std::endl;
}
/**
 * @brief Test for the default constructor of dm_neighbor_t.
 *
 * This test verifies that invoking the default constructor for dm_neighbor_t does not throw any exceptions and successfully creates an object. It ensures that the class can be instantiated in a basic scenario.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 007
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                               | Test Data                                   | Expected Result                                                                  | Notes      |
 * | :--------------: | --------------------------------------------------------- | ------------------------------------------- | -------------------------------------------------------------------------------- | ---------- |
 * | 01               | Invoke the default constructor of dm_neighbor_t           | No input arguments, output: valid object    | The default constructor is executed without throwing exceptions and the object is created successfully | Should Pass |
 */
TEST(dm_neighbor_t, dm_neighbor_t_default_constructor) {
    std::cout << "Entering dm_neighbor_t_default_constructor test" << std::endl;
    std::cout << "Invoking default constructor for dm_neighbor_t." << std::endl;
    EXPECT_NO_THROW({
        dm_neighbor_t neighborObj;
    });
    std::cout << "Exiting dm_neighbor_t_default_constructor test" << std::endl;
}
/**
 * @brief Verify that the copy construction of a default constructed dm_neighbor_t object copies the neighbor info correctly.
 *
 * This test creates a default constructed dm_neighbor_t instance and then uses the copy constructor to create a second instance. It retrieves the neighbor info pointers from both instances and uses memcmp to compare the memory regions. The test confirms that the neighbor info in the copied instance matches that of the source instance, validating the correctness of the copy constructor for default constructed objects.@n
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
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Construct a default dm_neighbor_t object (source) | No input parameters, creates dm_neighbor_t source object | source object is created with default neighbor_info values | Should be successful |
 * | 02 | Copy construct a dm_neighbor_t object (copy) from the source object | input: source object, output: copy object created using copy constructor | copy object is created and initialized to match the source object's neighbor_info | Should Pass |
 * | 03 | Retrieve neighbor info pointers from both source and copy objects | source.get_neighbor_info(), copy.get_neighbor_info() | Both calls return valid pointers to em_neighbor_info_t structures | Should be successful |
 * | 04 | Compare the neighbor_info of source and copy using memcmp | input1 = pointer from source, input2 = pointer from copy, size = sizeof(em_neighbor_info_t) | memcmp returns 0, indicating matching neighbor_info data | Should Pass |
 */
TEST(dm_neighbor_t, dm_neighbor_t_copy_default_constructor) {
    std::cout << "Entering dm_neighbor_t_copy_default_constructor test" << std::endl;
    dm_neighbor_t source;
    dm_neighbor_t copy(source);
    em_neighbor_info_t* src_info = source.get_neighbor_info();
    em_neighbor_info_t* copy_info = copy.get_neighbor_info();
    EXPECT_EQ(memcmp(src_info, copy_info, sizeof(em_neighbor_info_t)), 0); 
    std::cout << "Exiting dm_neighbor_t_copy_default_constructor test" << std::endl;
}
/**
 * @brief Evaluate that deep copy of dm_neighbor_t is correctly performed
 *
 * This test verifies that when a dm_neighbor_t object is fully populated,
 * the copy constructor replicates all fields accurately. It checks that MAC 
 * addresses, position coordinates, number of hops, and path loss are copied 
 * without data loss, ensuring the correctness of the copy operation.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 009@n
 * **Priority:** High@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * 
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data |Expected Result |Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Populate a dm_neighbor_t object with complete neighbor information including MAC addresses, positions, hops, and path loss. | input: nbr = AA:BB:CC:DD:EE:FF, pos_x = 10.1, pos_y = 20.2, pos_z = 30.3, next_hop = 11:22:33:44:55:66, num_hops = 3, path_loss = -50 | Object is correctly populated with the given values. | Should be successful |
 * | 02 | Invoke the copy constructor to create a new object from the populated source. | input: source (fully populated dm_neighbor_t object) | Copy constructor creates a new object with identical neighbor information as the source. | Should Pass |
 * | 03 | Validate that all fields in the copied object's neighbor information match the source object's fields using assertions. | output: copy.get_neighbor_info() compared against source.m_neighbor_info values | All assertions pass confirming that the copied values are identical to the source. | Should Pass |
 */
TEST(dm_neighbor_t, dm_neighbor_t_copy_fully_populated) {
    std::cout << "Entering dm_neighbor_t_copy_fully_populated test" << std::endl;
    dm_neighbor_t source;
    parse_mac("AA:BB:CC:DD:EE:FF", source.m_neighbor_info.nbr);
    source.m_neighbor_info.pos_x = 10.1f;
    source.m_neighbor_info.pos_y = 20.2f;
    source.m_neighbor_info.pos_z = 30.3f;
    parse_mac("11:22:33:44:55:66", source.m_neighbor_info.next_hop);
    source.m_neighbor_info.num_hops = 3;
    source.m_neighbor_info.path_loss = -50;
    dm_neighbor_t copy(source);
    em_neighbor_info_t* copy_info = copy.get_neighbor_info();
    EXPECT_EQ(memcmp(copy_info->nbr, source.m_neighbor_info.nbr, sizeof(copy_info->nbr)), 0);
    EXPECT_FLOAT_EQ(copy_info->pos_x, source.m_neighbor_info.pos_x);
    EXPECT_FLOAT_EQ(copy_info->pos_y, source.m_neighbor_info.pos_y);
    EXPECT_FLOAT_EQ(copy_info->pos_z, source.m_neighbor_info.pos_z);
    EXPECT_EQ(memcmp(copy_info->next_hop, source.m_neighbor_info.next_hop, sizeof(copy_info->next_hop)), 0);
    EXPECT_EQ(copy_info->num_hops, source.m_neighbor_info.num_hops);
    EXPECT_EQ(copy_info->path_loss, source.m_neighbor_info.path_loss);
    std::cout << "Exiting dm_neighbor_t_copy_fully_populated test" << std::endl;
}
/**
 * @brief Test copying dm_neighbor_t object with extreme negative values.
 *
 * This test verifies that copying a dm_neighbor_t object that contains extreme negative floating-point values 
 * for the position coordinates and INT_MIN for the path_loss field retains all neighbor information correctly. 
 * It also uses MAC address parsing to ensure that the MAC addresses in the neighbor info are copied properly.  
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 010
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize dm_neighbor_t object with extreme negative coordinate values and set MAC addresses using parse_mac. | nbr = "FF:EE:DD:CC:BB:AA", pos_x = -123456.78, pos_y = -98765.43, pos_z = -54321.00, next_hop = "66:55:44:33:22:11", num_hops = 0, path_loss = INT_MIN | dm_neighbor_t object populated with the specified extreme negative values and MAC addresses. | Should be successful |
 * | 02 | Invoke the copy constructor to create a duplicate of the source object. | source object as initialized in step 01 | New dm_neighbor_t object copy created with identical internal neighbor info as the source. | Should Pass |
 * | 03 | Validate that the copied object's neighbor info matches the source's by comparing each field using assertions. | Comparison of nbr, pos_x, pos_y, pos_z, next_hop, num_hops, path_loss | All EXPECT_* assertions pass, confirming deep copy correctness. | Should Pass |
 */
TEST(dm_neighbor_t, dm_neighbor_t_copy_extreme_negative_values) {
    std::cout << "Entering dm_neighbor_t_copy_extreme_negative_values test" << std::endl;
    dm_neighbor_t source;
    parse_mac("FF:EE:DD:CC:BB:AA", source.m_neighbor_info.nbr);
    source.m_neighbor_info.pos_x = -123456.78f;
    source.m_neighbor_info.pos_y = -98765.43f;
    source.m_neighbor_info.pos_z = -54321.00f;
    parse_mac("66:55:44:33:22:11", source.m_neighbor_info.next_hop);
    source.m_neighbor_info.num_hops = 0;
    source.m_neighbor_info.path_loss = INT_MIN;
    dm_neighbor_t copy(source);
    em_neighbor_info_t* copy_info = copy.get_neighbor_info();
    EXPECT_EQ(memcmp(copy_info->nbr, source.m_neighbor_info.nbr, sizeof(copy_info->nbr)),0);
    EXPECT_FLOAT_EQ(copy_info->pos_x, source.m_neighbor_info.pos_x);
    EXPECT_FLOAT_EQ(copy_info->pos_y, source.m_neighbor_info.pos_y);
    EXPECT_FLOAT_EQ(copy_info->pos_z, source.m_neighbor_info.pos_z);
    EXPECT_EQ(memcmp(copy_info->next_hop, source.m_neighbor_info.next_hop, sizeof(copy_info->next_hop)),0);
    EXPECT_EQ(copy_info->num_hops, source.m_neighbor_info.num_hops);
    EXPECT_EQ(copy_info->path_loss, source.m_neighbor_info.path_loss);
    std::cout << "Exiting dm_neighbor_t_copy_extreme_negative_values test" << std::endl;
}
/**
 * @brief Validate that the copy constructor of dm_neighbor_t correctly copies a partially initialized object.
 *
 * This test verifies that when a dm_neighbor_t object is partially initialized (by setting the neighbor MAC address), creating a copy using the copy constructor results in a new object with the same neighbor information. It checks that fields such as the MAC address, positional coordinates (pos_x, pos_y, pos_z), next hop, number of hops, and path loss match between the original and the copied object.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 011@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result |Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Create a source object and initialize its neighbor info by parsing "12:34:56:78:9A:BC", then create a copy of the source using the copy constructor, and finally verify that all relevant fields in the copy match the source. | input: source.m_neighbor_info.nbr = "12:34:56:78:9A:BC", output: copy_info->nbr, pos_x, pos_y, pos_z, next_hop, num_hops, path_loss | The copy's fields must exactly match those of the source object as verified by memcmp and floating-point equality checks. | Should Pass |
 */
TEST(dm_neighbor_t, dm_neighbor_t_copy_partially_initialized) {
    std::cout << "Entering dm_neighbor_t_copy_partially_initialized test" << std::endl;
    dm_neighbor_t source;
    parse_mac("12:34:56:78:9A:BC", source.m_neighbor_info.nbr);
    dm_neighbor_t copy(source);
    em_neighbor_info_t* copy_info = copy.get_neighbor_info();
    EXPECT_EQ(memcmp(copy_info->nbr, source.m_neighbor_info.nbr, sizeof(copy_info->nbr)), 0);
    EXPECT_FLOAT_EQ(copy_info->pos_x, source.m_neighbor_info.pos_x);
    EXPECT_FLOAT_EQ(copy_info->pos_y, source.m_neighbor_info.pos_y);
    EXPECT_FLOAT_EQ(copy_info->pos_z, source.m_neighbor_info.pos_z);
    EXPECT_EQ(memcmp(copy_info->next_hop, source.m_neighbor_info.next_hop, sizeof(copy_info->next_hop)), 0);
    EXPECT_EQ(copy_info->num_hops, source.m_neighbor_info.num_hops);
    EXPECT_EQ(copy_info->path_loss, source.m_neighbor_info.path_loss);
    std::cout << "Exiting dm_neighbor_t_copy_partially_initialized test" << std::endl;
}
/**
 * @brief Validate dm_neighbor_t constructor with valid normal input values
 *
 * This test verifies that the dm_neighbor_t constructor correctly assigns values from a valid neighbor information
 * structure. The test sets proper MAC addresses, position coordinates, number of hops and path loss, and asserts that
 * the values in the constructed neighbor object match those provided.
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
 * | Variation / Step | Description                                                                 | Test Data                                                                                                                    | Expected Result                                                                                                            | Notes      |
 * | :---------------: | --------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------- | ---------- |
 * | 01                | Initialize neighbor info, invoke dm_neighbor_t constructor, and verify fields | nbr = AA:BB:CC:DD:EE:FF, pos_x = 1.0, pos_y = 2.0, pos_z = 3.0, next_hop = 11:22:33:44:55:66, num_hops = 5, path_loss = -10 | Neighbor object fields match the provided info; all assertions comparing inputs to neighbor object values pass            | Should Pass |
 */
TEST(dm_neighbor_t, dm_neighbor_t_valid_normal_values)
{
    std::cout << "Entering dm_neighbor_t_valid_normal_values test" << std::endl;
    em_neighbor_info_t info;
    parse_mac("AA:BB:CC:DD:EE:FF",info.nbr);
    info.pos_x = 1.0f;
    info.pos_y = 2.0f;
    info.pos_z = 3.0f;
    parse_mac("11:22:33:44:55:66", info.next_hop);
    info.num_hops = 5;
    info.path_loss = -10;
    dm_neighbor_t neighbor(&info);
    EXPECT_EQ(memcmp(neighbor.m_neighbor_info.nbr, info.nbr, sizeof(neighbor.m_neighbor_info.nbr)),0); 
    EXPECT_FLOAT_EQ(neighbor.m_neighbor_info.pos_x, info.pos_x);
    EXPECT_FLOAT_EQ(neighbor.m_neighbor_info.pos_y, info.pos_y);
    EXPECT_FLOAT_EQ(neighbor.m_neighbor_info.pos_z, info.pos_z);
    EXPECT_EQ(memcmp(neighbor.m_neighbor_info.next_hop, info.next_hop, sizeof(neighbor.m_neighbor_info.next_hop)),0);
    EXPECT_EQ(neighbor.m_neighbor_info.num_hops, info.num_hops);
    EXPECT_EQ(neighbor.m_neighbor_info.path_loss, info.path_loss);
    std::cout << "Exiting dm_neighbor_t_valid_normal_values test" << std::endl;
}
/**
 * @brief Verify dm_neighbor_t handles edge case limit values correctly.
 *
 * This test verifies that the dm_neighbor_t constructor properly sets and stores extreme edge values for neighbor information.
 * It tests the handling of maximum and minimum floating-point values for coordinates, as well as extreme integer values for hop count and path loss.
 * The MAC addresses are also parsed and validated using memcmp to ensure proper conversion and storage.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 013
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Call parse_mac to set neighbor MAC address. | input: "AA:BB:CC:DD:EE:FF" for info.nbr | Expected MAC stored correctly in info.nbr. | Should Pass |
 * | 02 | Set positional values to their respective edge values. | pos_x = FLT_MAX, pos_y = FLT_MIN, pos_z = -FLT_MAX | Expected values assigned to pos_x, pos_y, pos_z accurately. | Should be successful |
 * | 03 | Call parse_mac to set next hop MAC address. | input: "11:22:33:44:55:66" for info.next_hop | Expected MAC stored correctly in info.next_hop. | Should Pass |
 * | 04 | Set num_hops and path_loss to extreme integer values. | num_hops = UINT_MAX, path_loss = INT_MIN | Expected values assigned to num_hops and path_loss accurately. | Should be successful |
 * | 05 | Instantiate dm_neighbor_t using the prepared neighbor information. | input: pointer to info | Expected dm_neighbor_t object created with accurate copy of neighbor info. | Should Pass |
 * | 06 | Validate MAC address stored in dm_neighbor_t object using memcmp. | input: neighbor.m_neighbor_info.nbr compared with info.nbr | Expected memcmp returns 0 indicating matching MAC address arrays. | Should Pass |
 * | 07 | Validate positional value pos_x using EXPECT_FLOAT_EQ. | input: neighbor.m_neighbor_info.pos_x vs info.pos_x | Expected pos_x values to be equal. | Should Pass |
 * | 08 | Validate positional value pos_y using EXPECT_FLOAT_EQ. | input: neighbor.m_neighbor_info.pos_y vs info.pos_y | Expected pos_y values to be equal. | Should Pass |
 * | 09 | Validate positional value pos_z using EXPECT_FLOAT_EQ. | input: neighbor.m_neighbor_info.pos_z vs info.pos_z | Expected pos_z values to be equal. | Should Pass |
 * | 10 | Validate next hop MAC address using memcmp. | input: neighbor.m_neighbor_info.next_hop compared with info.next_hop | Expected memcmp returns 0 indicating matching next hop MAC address arrays. | Should Pass |
 * | 11 | Validate num_hops using EXPECT_EQ. | input: neighbor.m_neighbor_info.num_hops vs info.num_hops | Expected num_hops values to be equal. | Should Pass |
 * | 12 | Validate path_loss using EXPECT_EQ. | input: neighbor.m_neighbor_info.path_loss vs info.path_loss | Expected path_loss values to be equal. | Should Pass |
 */
TEST(dm_neighbor_t, dm_neighbor_t_edge_case_values)
{
    std::cout << "Entering dm_neighbor_t_edge_case_values test" << std::endl;
    em_neighbor_info_t info;
    parse_mac("AA:BB:CC:DD:EE:FF", info.nbr);
    info.pos_x = FLT_MAX;
    info.pos_y = FLT_MIN;
    info.pos_z = -FLT_MAX;
    parse_mac("11:22:33:44:55:66", info.next_hop);
    info.num_hops = UINT_MAX;
    info.path_loss = INT_MIN;
    dm_neighbor_t neighbor(&info);
    EXPECT_EQ(memcmp(neighbor.m_neighbor_info.nbr, info.nbr, sizeof(neighbor.m_neighbor_info.nbr)),0);
    EXPECT_FLOAT_EQ(neighbor.m_neighbor_info.pos_x, info.pos_x);
    EXPECT_FLOAT_EQ(neighbor.m_neighbor_info.pos_y, info.pos_y);
    EXPECT_FLOAT_EQ(neighbor.m_neighbor_info.pos_z, info.pos_z);
    EXPECT_EQ(memcmp(neighbor.m_neighbor_info.next_hop, info.next_hop, sizeof(neighbor.m_neighbor_info.next_hop)),0);
    EXPECT_EQ(neighbor.m_neighbor_info.num_hops, info.num_hops);
    EXPECT_EQ(neighbor.m_neighbor_info.path_loss, info.path_loss);
    std::cout << "Exiting dm_neighbor_t_edge_case_values test" << std::endl;
}
/**
 * @brief Verify that dm_neighbor_t is correctly instantiated with zero hops and zero pathloss
 *
 * This test validates that dm_neighbor_t is correctly initialized by copying the values from an
 * em_neighbor_info_t structure when the number of hops and the path loss are set to zero. It ensures
 * that the MAC addresses, positions, number of hops, and path loss are accurately transferred to the
 * dm_neighbor_t instance.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 014@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :--------------: | ----------- | --------- | --------------- | ----- |
 * | 01 | Initialize the neighbor information by parsing MAC addresses and setting positional data along with zero hops and zero path loss. | input: nbr = "AA:BB:CC:DD:EE:FF", pos_x = -5.5, pos_y = 0.0, pos_z = 5.5, next_hop = "11:22:33:44:55:66", num_hops = 0, path_loss = 0 | em_neighbor_info_t structure fields are correctly set with the provided values. | Should be successful |
 * | 02 | Create a dm_neighbor_t object using the initialized neighbor info structure. | input: pointer to em_neighbor_info_t (with above values) | dm_neighbor_t object is instantiated with member values matching the info structure. | Should Pass |
 * | 03 | Compare each field of the dm_neighbor_t object with the original neighbor information using assertions. | input: dm_neighbor_t instance and original info | All comparisons (memcmp for MAC addresses and EXPECT_FLOAT_EQ for positions) succeed. | Should Pass |
 */
TEST(dm_neighbor_t, dm_neighbor_t_zero_hops_zero_pathloss)
{
    std::cout << "Entering dm_neighbor_t_zero_hops_zero_pathloss test" << std::endl;
    em_neighbor_info_t info;
    parse_mac("AA:BB:CC:DD:EE:FF", info.nbr);
    info.pos_x = -5.5f;
    info.pos_y = 0.0f;
    info.pos_z = 5.5f;
    parse_mac("11:22:33:44:55:66", info.next_hop);
    info.num_hops = 0;
    info.path_loss = 0;
    dm_neighbor_t neighbor(&info);
    EXPECT_EQ(memcmp(neighbor.m_neighbor_info.nbr, info.nbr, sizeof(neighbor.m_neighbor_info.nbr)),0);
    EXPECT_FLOAT_EQ(neighbor.m_neighbor_info.pos_x, info.pos_x);
    EXPECT_FLOAT_EQ(neighbor.m_neighbor_info.pos_y, info.pos_y);
    EXPECT_FLOAT_EQ(neighbor.m_neighbor_info.pos_z, info.pos_z);
    EXPECT_EQ(memcmp(neighbor.m_neighbor_info.next_hop, info.next_hop, sizeof(neighbor.m_neighbor_info.next_hop)),0);
    EXPECT_EQ(neighbor.m_neighbor_info.num_hops, info.num_hops);
    EXPECT_EQ(neighbor.m_neighbor_info.path_loss, info.path_loss);
    std::cout << "Exiting dm_neighbor_t_zero_hops_zero_pathloss test" << std::endl;
}
/**
 * @brief Test to verify that all fields of dm_neighbor_t are correctly encoded to JSON.
 *
 * This test populates a dm_neighbor_t object with all fields including MAC addresses, position coordinates, hop count, and path loss; it then calls the encode method to produce a JSON object and validates that each field is properly represented in the JSON.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 015@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize the JSON object and dm_neighbor_t instance. | json_obj created via cJSON_CreateObject; dm_neighbor_t instance allocated. | JSON object and neighbor instance are successfully created. | Should be successful |
 * | 02 | Populate the neighbor object with all required fields. | nbr = "AA:BB:CC:DD:EE:FF", pos_x = 10.1, pos_y = 20.2, pos_z = 30.3, next_hop = "11:22:33:44:55:66", num_hops = 3, path_loss = -50. | Neighbor object fields are correctly set with provided values. | Should be successful |
 * | 03 | Invoke the encode method on the neighbor object. | Input: json_obj pointer, flag = false. | The encode method executes without throwing any exceptions and updates the JSON object. | Should Pass |
 * | 04 | Validate the JSON object's fields against expected values. | Expected JSON keys with values: "Neighbor" = "AA:BB:CC:DD:EE:FF", "POS_X" = 10.1, "POS_Y" = 20.2, "POS_Z" = 30.3, "NextHop" = "11:22:33:44:55:66", "NumHops" = 3, "PathLoss" = -50. | All assertions pass, confirming that the JSON object contains the expected values. | Should Pass |
 * | 05 | Clean up resources by deleting the JSON object. | Call to cJSON_Delete(json_obj). | JSON object is deleted and resources are released with no memory leaks. | Should be successful |
 */
TEST(dm_neighbor_t, encode_all_fields_populated) {
    std::cout << "Entering encode_all_fields_populated test" << std::endl;
    cJSON* json_obj = cJSON_CreateObject();
    dm_neighbor_t neighbor;
    parse_mac("AA:BB:CC:DD:EE:FF", neighbor.m_neighbor_info.nbr);
    neighbor.m_neighbor_info.pos_x = 10.1f;
    neighbor.m_neighbor_info.pos_y = 20.2f;
    neighbor.m_neighbor_info.pos_z = 30.3f;
    parse_mac("11:22:33:44:55:66", neighbor.m_neighbor_info.next_hop);
    neighbor.m_neighbor_info.num_hops = 3;
    neighbor.m_neighbor_info.path_loss = -50;
    EXPECT_NO_THROW({
        neighbor.encode(json_obj, false);
    });
    EXPECT_STRCASEEQ(cJSON_GetObjectItem(json_obj, "Neighbor")->valuestring,"AA:BB:CC:DD:EE:FF");
    EXPECT_FLOAT_EQ(cJSON_GetObjectItem(json_obj, "POS_X")->valuedouble, 10.1f);
    EXPECT_FLOAT_EQ(cJSON_GetObjectItem(json_obj, "POS_Y")->valuedouble, 20.2f);
    EXPECT_FLOAT_EQ(cJSON_GetObjectItem(json_obj, "POS_Z")->valuedouble, 30.3f);
    EXPECT_STREQ(cJSON_GetObjectItem(json_obj, "NextHop")->valuestring,"11:22:33:44:55:66");
    EXPECT_EQ(cJSON_GetObjectItem(json_obj, "NumHops")->valueint, 3);
    EXPECT_EQ(cJSON_GetObjectItem(json_obj, "PathLoss")->valueint, -50);
    cJSON_Delete(json_obj);
    std::cout << "Exiting encode_all_fields_populated test" << std::endl;
}
/**
 * @brief Test encoding of dm_neighbor_t in summary mode
 *
 * This test verifies that the neighbor structure is correctly encoded into a JSON object when summary mode is enabled. 
 * It checks that the MAC address is properly parsed and stored in the neighbor structure, and that the encode method successfully
 * inserts the expected key-value pair into the JSON object without throwing exceptions.
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
 * | 01 | Create a JSON object for encoding neighbor information | json_obj initialized via cJSON_CreateObject() | Valid JSON object pointer is returned | Should be successful |
 * | 02 | Parse the MAC address string into the neighbor structure | input: "AA:BB:CC:DD:EE:FF", output: neighbor.m_neighbor_info.nbr populated | MAC address is correctly parsed with proper format | Should be successful |
 * | 03 | Encode the neighbor structure into the JSON object with summary mode enabled | input: json_obj pointer, summary mode = true; output: JSON updated with neighbor info | No exception is thrown during encoding | Should Pass |
 * | 04 | Verify that the encoded JSON object contains the key "Neighbor" with the expected MAC address | input: JSON object with "Neighbor" field, expected value "AA:BB:CC:DD:EE:FF" | The "Neighbor" field value matches "AA:BB:CC:DD:EE:FF" using case-insensitive comparison | Should Pass |
 * | 05 | Delete the JSON object to free allocated memory | input: json_obj pointer provided to cJSON_Delete | JSON object is successfully deleted, freeing memory | Should be successful |
 */
TEST(dm_neighbor_t, encode_summary_mode) {
    std::cout << "Entering encode_summary_mode test" << std::endl;
    cJSON* json_obj = cJSON_CreateObject();
    dm_neighbor_t neighbor;
    parse_mac("AA:BB:CC:DD:EE:FF", neighbor.m_neighbor_info.nbr);
    EXPECT_NO_THROW(neighbor.encode(json_obj, true));
    EXPECT_STRCASEEQ(cJSON_GetObjectItem(json_obj, "Neighbor")->valuestring,"AA:BB:CC:DD:EE:FF");
    cJSON_Delete(json_obj);
    std::cout << "Exiting encode_summary_mode test" << std::endl;
}
/**
 * @brief Verify that the dm_neighbor_t::encode API correctly encodes zero values.
 *
 * This test verifies that when the dm_neighbor_t instance has its num_hops and path_loss 
 * parameters set to zero, the encode method successfully encodes these values into the JSON object without throwing exceptions.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 017@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                                  | Test Data                                                                                                         | Expected Result                                                | Notes          |
 * | :--------------: | -------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------- | -------------- |
 * | 01               | Create a new JSON object using cJSON_CreateObject.                                           | None                                                                                                              | Valid JSON object is created.                                  | Should be successful |
 * | 02               | Initialize dm_neighbor_t instance with zero values for num_hops and path_loss.                 | neighbor.m_neighbor_info.num_hops = 0, neighbor.m_neighbor_info.path_loss = 0                                      | dm_neighbor_t instance has zero values.                        | Should be successful |
 * | 03               | Invoke neighbor.encode() with the JSON object and flag set to false.                         | json_obj pointer, encode flag = false, neighbor values: num_hops = 0, path_loss = 0                                 | API does not throw an exception and populates the JSON object.  | Should Pass    |
 * | 04               | Verify the JSON object's "NumHops" value is correctly set.                                   | json key NumHops, expected value = 0                                                                                | "NumHops" equals 0.                                             | Should be successful |
 * | 05               | Verify the JSON object's "PathLoss" value is correctly set.                                  | json key PathLoss, expected value = 0                                                                               | "PathLoss" equals 0.                                            | Should be successful |
 * | 06               | Delete the JSON object to free memory.                                                       | json_obj pointer                                                                                                  | JSON object is deleted successfully.                           | Should be successful |
 */
TEST(dm_neighbor_t, encode_zero_values) {
    std::cout << "Entering encode_zero_values test" << std::endl;
    cJSON* json_obj = cJSON_CreateObject();
    dm_neighbor_t neighbor;
    neighbor.m_neighbor_info.num_hops = 0;
    neighbor.m_neighbor_info.path_loss = 0;
    EXPECT_NO_THROW({
        neighbor.encode(json_obj, false);
    });
    EXPECT_EQ(cJSON_GetObjectItem(json_obj, "NumHops")->valueint, 0);
    EXPECT_EQ(cJSON_GetObjectItem(json_obj, "PathLoss")->valueint, 0);
    cJSON_Delete(json_obj);
    std::cout << "Exiting encode_zero_values test" << std::endl;
}
/**
 * @brief Verify that the encode() method throws an exception when passed a null pointer.
 *
 * This test ensures that invoking the encode() method with a null object pointer triggers an exception, preventing undefined behavior. The objective is to confirm correct error handling in the API and to ensure that the method does not process invalid inputs.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 018
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                         | Test Data (input/output)                                             | Expected Result                                     | Notes         |
 * | :--------------: | ------------------------------------------------------------------- | -------------------------------------------------------------------- | --------------------------------------------------- | ------------- |
 * | 01               | Invoke encode() with a null pointer on a valid neighbor object and verify that an exception is thrown. | neighbor object instantiated, encode(nullptr, false)                 | Exception is thrown as per EXPECT_ANY_THROW macro.  | Should Fail   |
 */
TEST(dm_neighbor_t, encode_null_obj_pointer) {
    std::cout << "Entering encode_null_obj_pointer test" << std::endl;
    dm_neighbor_t neighbor;
    EXPECT_ANY_THROW({
        neighbor.encode(nullptr, false);
    });
    std::cout << "Exiting encode_null_obj_pointer test" << std::endl;
}
/**
 * @brief Tests that get_neighbor_info returns a non-null pointer that points to the instance's m_neighbor_info member
 *
 * This test creates a default instance of dm_neighbor_t and retrieves the neighbor info pointer via get_neighbor_info.
 * It then confirms that the returned pointer is not null and exactly matches the address of the instance's m_neighbor_info.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 019
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Call get_neighbor_info on a default constructed dm_neighbor_t object and validate its return value | instance = dm_neighbor_t (default constructor), output: infoPtr = instance.get_neighbor_info(), expected: infoPtr equals &instance.m_neighbor_info | infoPtr should not be nullptr and should equal the address of instance.m_neighbor_info | Should Pass |
 */
TEST(dm_neighbor_t, get_neighbor_info_default_non_null)
{
    std::cout << "Entering get_neighbor_info_default_non_null test" << std::endl;
    dm_neighbor_t instance;
    em_neighbor_info_t* infoPtr = instance.get_neighbor_info();
    EXPECT_NE(infoPtr, nullptr);
    EXPECT_EQ(infoPtr, &(instance.m_neighbor_info));
    std::cout << "Exiting get_neighbor_info_default_non_null test" << std::endl;
}
/**
 * @brief Verify that modifications made through the pointer returned by get_neighbor_info are correctly reflected in the instance
 *
 * This test verifies that when the get_neighbor_info method is called, any modifications made via the returned pointer are directly visible in the instance's m_neighbor_info structure. The test sets specific values for pos_x, pos_y, pos_z, num_hops, and path_loss and then asserts that these changes are correctly reflected in the instance.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 020@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                                                 | Test Data                                                             | Expected Result                                                                                   | Notes      |
 * | :--------------: | ------------------------------------------------------------------------------------------- | --------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------- | ---------- |
 * | 01               | Instantiate dm_neighbor_t, call get_neighbor_info(), modify neighbor info fields with test values | instance: dm_neighbor_t, pos_x = 10.5f, pos_y = -5.3f, pos_z = 3.1415f, num_hops = 4, path_loss = -20 | The instance.m_neighbor_info should reflect pos_x=10.5f, pos_y=-5.3f, pos_z=3.1415f, num_hops=4, path_loss=-20; assertions pass | Should Pass |
 */
TEST(dm_neighbor_t, get_neighbor_info_modification_reflected)
{
    std::cout << "Entering get_neighbor_info_modification_reflected test" << std::endl;
    dm_neighbor_t instance;
    em_neighbor_info_t* infoPtr = instance.get_neighbor_info();
    infoPtr->pos_x = 10.5f;
    infoPtr->pos_y = -5.3f;
    infoPtr->pos_z = 3.1415f;
    infoPtr->num_hops = 4;
    infoPtr->path_loss = -20;
    EXPECT_FLOAT_EQ(instance.m_neighbor_info.pos_x, 10.5f);
    EXPECT_FLOAT_EQ(instance.m_neighbor_info.pos_y, -5.3f);
    EXPECT_FLOAT_EQ(instance.m_neighbor_info.pos_z, 3.1415f);
    EXPECT_EQ(instance.m_neighbor_info.num_hops, 4u);
    EXPECT_EQ(instance.m_neighbor_info.path_loss, -20);
    std::cout << "Exiting get_neighbor_info_modification_reflected test" << std::endl;
}
/**
 * @brief Verify that get_neighbor_info returns a consistent non-null pointer for repeated calls.
 *
 * This test validates that the get_neighbor_info API of dm_neighbor_t returns the same pointer each time it is invoked, and that the returned pointer matches the address of the m_neighbor_info member of the instance. This behavior ensures internal consistency in the pointer retrieval.
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
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Instantiate dm_neighbor_t and invoke get_neighbor_info() for the first time. | instance = dm_neighbor_t instance created | Returns a non-null pointer to m_neighbor_info. | Should be successful |
 * | 02 | Invoke get_neighbor_info() a second time on the same instance and verify consistency of the pointer with the first call and the member address. | ptr1 = instance.get_neighbor_info(), ptr2 = instance.get_neighbor_info(), expected = address of instance.m_neighbor_info | ptr1 equals ptr2 and both equal the address of instance.m_neighbor_info. | Should Pass |
 */
TEST(dm_neighbor_t, get_neighbor_info_consistent_pointer)
{
    std::cout << "Entering get_neighbor_info_consistent_pointer test" << std::endl;
    dm_neighbor_t instance;
    em_neighbor_info_t* ptr1 = instance.get_neighbor_info();
    em_neighbor_info_t* ptr2 = instance.get_neighbor_info();
    EXPECT_EQ(ptr1, ptr2);
    EXPECT_EQ(ptr1, &(instance.m_neighbor_info));
    std::cout << "Exiting get_neighbor_info_consistent_pointer test" << std::endl;
}
/**
 * @brief Test to verify that dm_neighbor_t constructor creates an independent copy of neighbor info
 *
 * This test verifies that when a dm_neighbor_t instance is constructed with a pointer to an external 
 * em_neighbor_info_t structure, the internal neighbor info pointer is allocated independently and does not 
 * reference the original external pointer. It checks that the internal pointer is different from the external one 
 * and points to the internal member variable.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 022@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Instantiate dm_neighbor_t with a pointer to external em_neighbor_info_t and verify pointers are independent. | externalInfo: pos_x = 1.0f, pos_y = 2.0f, pos_z = 3.0f, num_hops = 1, path_loss = 0; instance creation with pointer to externalInfo; function call to get_neighbor_info() | The returned pointer from get_neighbor_info() should not equal the address of externalInfo and must equal the address of instance.m_neighbor_info. | Should Pass |
 */
TEST(dm_neighbor_t, get_neighbor_info_constructor_pointer_independent)
{
    std::cout << "Entering get_neighbor_info_constructor_pointer_independent test" << std::endl;
    em_neighbor_info_t externalInfo;
    externalInfo.pos_x = 1.0f;
    externalInfo.pos_y = 2.0f;
    externalInfo.pos_z = 3.0f;
    externalInfo.num_hops = 1;
    externalInfo.path_loss = 0;
    dm_neighbor_t instance(&externalInfo);
    em_neighbor_info_t* internalPtr = instance.get_neighbor_info();
    EXPECT_NE(internalPtr, &externalInfo);
    EXPECT_EQ(internalPtr, &(instance.m_neighbor_info));
    std::cout << "Exiting get_neighbor_info_constructor_pointer_independent test" << std::endl;
}
/**
 * @brief Validate the independence of neighbor info after using the copy constructor
 *
 * This test validates that the copy constructor of dm_neighbor_t creates a new, independent copy of the neighbor info.
 * It confirms that the neighbor info pointer in the copy is not the same as that of the original, and that it correctly points
 * to the copy's internal neighbor info member.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 023
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Create an original dm_neighbor_t object and retrieve its neighbor info pointer | No parameters: dm_neighbor_t original; | Obtains pointer to original neighbor info | Should be successful |
 * | 02 | Use the copy constructor to create a copy of the original object and retrieve the neighbor info pointer from the copy | No parameters: dm_neighbor_t copy(original); | Obtains pointer to neighbor info from the copy that is independent from the original pointer | Should Pass |
 * | 03 | Compare the neighbor info pointers of the original and copy to verify they point to different objects and the copy points to its own member variable | Compare: original.get_neighbor_info() vs. copy.get_neighbor_info(), and validate copy.get_neighbor_info() equals address of copy.m_neighbor_info | EXPECT_NE confirms the pointers differ; EXPECT_EQ confirms the copy's neighbor info pointer equals the address of its internal member | Should Pass |
 */
TEST(dm_neighbor_t, get_neighbor_info_copy_constructor_independence)
{
    std::cout << "Entering get_neighbor_info_copy_constructor_independence test" << std::endl;
    dm_neighbor_t original;
    em_neighbor_info_t* originalPtr = original.get_neighbor_info();
    dm_neighbor_t copy(original);
    em_neighbor_info_t* copyPtr = copy.get_neighbor_info();
    EXPECT_NE(copyPtr, originalPtr);
    EXPECT_EQ(copyPtr, &(copy.m_neighbor_info));
    std::cout << "Exiting get_neighbor_info_copy_constructor_independence test" << std::endl;
}
/**
 * @brief Test basic initialization of dm_neighbor_t object.
 *
 * This test verifies that the dm_neighbor_t object initializes correctly by calling its init() method. 
 * The objective of the test is to ensure that the initialization routine returns a success value (0), indicating successful setup of the neighbor instance.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 024@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                             | Test Data                                                   | Expected Result                          | Notes           |
 * | :--------------: | ------------------------------------------------------- | ----------------------------------------------------------- | ---------------------------------------- | --------------- |
 * | 01               | Print entering message to indicate test start           | output = "Entering init_basic_initialization test"          | Message printed to console               | Should be successful |
 * | 02               | Create an instance of dm_neighbor_t                     | Instance creation, no input arguments                     | Instance created successfully            | Should be successful |
 * | 03               | Invoke the init() method on the dm_neighbor_t instance   | input: dm_neighbor_t instance, call: neighbor.init()        | Return value = 0 returned from init()      | Should Pass     |
 * | 04               | Verify the return value using EXPECT_EQ macro           | input: init_ret = neighbor.init(), expected output: 0       | EXPECT_EQ(init_ret, 0) passes            | Should Pass     |
 * | 05               | Print exiting message to indicate end of test           | output = "Exiting init_basic_initialization test"           | Message printed to console               | Should be successful |
 */
TEST(dm_neighbor_t, init_basic_initialization)
{
    std::cout << "Entering init_basic_initialization test" << std::endl;
    dm_neighbor_t neighbor;
    int init_ret = neighbor.init();
    EXPECT_EQ(init_ret, 0);
    std::cout << "Exiting init_basic_initialization test" << std::endl;
}
/**
 * @brief Validate the assignment operator for a fully populated dm_neighbor_t structure
 *
 * This test verifies that the assignment operator correctly copies all fields of a fully populated
 * dm_neighbor_t object, including MAC addresses, positional data, hop count, and path loss. The test
 * ensures that deep copy semantics are correctly implemented for array data and that numerical values
 * are accurately transferred.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 025@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize dm_neighbor_t source with fully populated data including MAC addresses, positions, hops, and path loss | nbr = "AA:BB:CC:DD:EE:FF", next_hop = "11:22:33:44:55:66", pos_x = 10.5, pos_y = -3.2, pos_z = 7.7, num_hops = 5, path_loss = -42 | dm_neighbor_t source is populated with the specified values | Should be successful |
 * | 02 | Assign the fully populated source object to target and validate that all fields are correctly copied | Assignment operator: target = source; input: all fields of source; outputs: target.m_neighbor_info.nbr, pos_x, pos_y, pos_z, next_hop, num_hops, path_loss | target object has identical values matching source (memory comparisons and float comparisons succeed) | Should Pass |
 */
TEST(dm_neighbor_t, positive_assignment_fully_populated) {
    std::cout << "Entering positive_assignment_fully_populated test" << std::endl;
    dm_neighbor_t source;
    parse_mac("AA:BB:CC:DD:EE:FF", source.m_neighbor_info.nbr);
    parse_mac("11:22:33:44:55:66", source.m_neighbor_info.next_hop);
    source.m_neighbor_info.pos_x = 10.5f;
    source.m_neighbor_info.pos_y = -3.2f;
    source.m_neighbor_info.pos_z = 7.7f;
    source.m_neighbor_info.num_hops = 5;
    source.m_neighbor_info.path_loss = -42;
    dm_neighbor_t target;
    target = source;
    EXPECT_EQ(memcmp(target.m_neighbor_info.nbr, source.m_neighbor_info.nbr, sizeof(target.m_neighbor_info.nbr)),0);
    EXPECT_FLOAT_EQ(target.m_neighbor_info.pos_x, source.m_neighbor_info.pos_x);
    EXPECT_FLOAT_EQ(target.m_neighbor_info.pos_y, source.m_neighbor_info.pos_y);
    EXPECT_FLOAT_EQ(target.m_neighbor_info.pos_z, source.m_neighbor_info.pos_z);
    EXPECT_EQ(memcmp(target.m_neighbor_info.next_hop, source.m_neighbor_info.next_hop, sizeof(target.m_neighbor_info.next_hop)),0);
    EXPECT_EQ(target.m_neighbor_info.num_hops, source.m_neighbor_info.num_hops);
    EXPECT_EQ(target.m_neighbor_info.path_loss, source.m_neighbor_info.path_loss);
    std::cout << "Exiting positive_assignment_fully_populated test" << std::endl;
}
/**
 * @brief Verify assignment operator for dm_neighbor_t retains default neighbor information
 *
 * This test verifies that assigning one default constructed dm_neighbor_t object to another correctly duplicates the neighbor information.
 * It checks whether all data fields, including the neighbor identifier, position coordinates (pos_x, pos_y, pos_z), next hop information, 
 * number of hops, and path loss, are correctly copied from the source object to the target object.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 026@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Invoke assignment operator on two default constructed dm_neighbor_t objects | source = default constructed, target = default constructed; API: target = source, comparisons using memcmp and EXPECT_FLOAT_EQ, EXPECT_EQ | All fields in target should exactly match the corresponding fields in source | Should Pass |
 */
TEST(dm_neighbor_t, positive_assignment_default_neighbor_info) {
    std::cout << "Entering positive_assignment_default_neighbor_info test" << std::endl;
    dm_neighbor_t source;
    dm_neighbor_t target;
    target = source;
    EXPECT_EQ(memcmp(target.m_neighbor_info.nbr, source.m_neighbor_info.nbr, sizeof(target.m_neighbor_info.nbr)), 0);
    EXPECT_FLOAT_EQ(target.m_neighbor_info.pos_x, source.m_neighbor_info.pos_x);
    EXPECT_FLOAT_EQ(target.m_neighbor_info.pos_y, source.m_neighbor_info.pos_y);
    EXPECT_FLOAT_EQ(target.m_neighbor_info.pos_z, source.m_neighbor_info.pos_z);
    EXPECT_EQ(memcmp(target.m_neighbor_info.next_hop, source.m_neighbor_info.next_hop, sizeof(target.m_neighbor_info.next_hop)), 0);
    EXPECT_EQ(target.m_neighbor_info.num_hops, source.m_neighbor_info.num_hops);
    EXPECT_EQ(target.m_neighbor_info.path_loss, source.m_neighbor_info.path_loss);
    std::cout << "Exiting positive_assignment_default_neighbor_info test" << std::endl;
}
/**
 * @brief Tests the assignment operator for dm_neighbor_t with extreme numeric values.
 *
 * This test verifies that the dm_neighbor_t structure correctly handles assignment when its
 * numeric and MAC address fields are populated with extreme values. It checks that all fields,
 * including neighbor MAC, next hop MAC, positional coordinates, number of hops, and path loss,
 * are accurately copied from the source to the target object.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 027@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :--------------: | ----------- | --------- | ------------- | ----- |
 * | 01 | Invoke parse_mac to assign neighbor MAC address for the source object. | input: MAC string = "FF:FF:FF:FF:FF:FF", target field: source.m_neighbor_info.nbr | source.m_neighbor_info.nbr should be correctly set to FF:FF:FF:FF:FF:FF | Should Pass |
 * | 02 | Invoke parse_mac to assign next hop MAC address for the source object. | input: MAC string = "00:00:00:00:00:00", target field: source.m_neighbor_info.next_hop | source.m_neighbor_info.next_hop should be correctly set to 00:00:00:00:00:00 | Should Pass |
 * | 03 | Assign extreme numeric values to the source object's positional and numeric fields. | input: pos_x = 1e30f, pos_y = -1e30f, pos_z = 3.4e38f, num_hops = std::numeric_limits<unsigned int>::max(), path_loss = INT_MIN | The source object fields should hold the assigned extreme values | Should Pass |
 * | 04 | Invoke the assignment operator to copy the source object to the target object. | input: source (with all field values set) assigned to target | target should have identical field values as source | Should Pass |
 * | 05 | Validate that all fields of the target object equal the corresponding fields of the source object using assertion checks. | input: source and target values for nbr, pos_x, pos_y, pos_z, next_hop, num_hops, path_loss | All assertions (EXPECT_EQ and EXPECT_FLOAT_EQ) should pass confirming equality | Should Pass |
 */
TEST(dm_neighbor_t, positive_assignment_extreme_numeric_values) {
    std::cout << "Entering positive_assignment_extreme_numeric_values test" << std::endl;
    dm_neighbor_t source;
    parse_mac("FF:FF:FF:FF:FF:FF", source.m_neighbor_info.nbr);
    parse_mac("00:00:00:00:00:00", source.m_neighbor_info.next_hop);
    source.m_neighbor_info.pos_x = 1e30f;
    source.m_neighbor_info.pos_y = -1e30f;
    source.m_neighbor_info.pos_z = 3.4e38f;
    source.m_neighbor_info.num_hops = std::numeric_limits<unsigned int>::max();
    source.m_neighbor_info.path_loss = INT_MIN;
    dm_neighbor_t target;
    target = source;
    EXPECT_EQ(memcmp(target.m_neighbor_info.nbr, source.m_neighbor_info.nbr, sizeof(target.m_neighbor_info.nbr)),0);
    EXPECT_FLOAT_EQ(target.m_neighbor_info.pos_x, source.m_neighbor_info.pos_x);
    EXPECT_FLOAT_EQ(target.m_neighbor_info.pos_y, source.m_neighbor_info.pos_y);
    EXPECT_FLOAT_EQ(target.m_neighbor_info.pos_z, source.m_neighbor_info.pos_z);
    EXPECT_EQ(memcmp(target.m_neighbor_info.next_hop, source.m_neighbor_info.next_hop, sizeof(target.m_neighbor_info.next_hop)),0);
    EXPECT_EQ(target.m_neighbor_info.num_hops, source.m_neighbor_info.num_hops);
    EXPECT_EQ(target.m_neighbor_info.path_loss, source.m_neighbor_info.path_loss);
    std::cout << "Exiting positive_assignment_extreme_numeric_values test" << std::endl;
}
/**
 * @brief Verifies that the equality operator returns true for two dm_neighbor_t objects 
 *        with identical values.
 *
 * This test creates two dm_neighbor_t objects, assigns identical values to their members,
 * and then invokes the equality operator (==) to ensure that the operator correctly identifies
 * them as equal. The objective is to confirm that all member variables are compared properly.
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
 * | Variation / Step | Description                                                                                                                    | Test Data                                                                                                                                                                              | Expected Result                                                       | Notes       |
 * | :--------------: | ------------------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------- | ----------- |
 * | 01               | Create and initialize two dm_neighbor_t objects with identical values, and invoke the equality operator (==) to verify it. | objA: nbr = "00:11:22:33:44:55", pos_x = 1.0, pos_y = 2.0, pos_z = 3.0, next_hop = "AA:BB:CC:DD:EE:FF", num_hops = 2, path_loss = 10; objB: same as objA values. | The operator should return true, and EXPECT_TRUE should pass.          | Should Pass |
 */
TEST(dm_neighbor_t, operator_equal_identical_values) {
    std::cout << "Entering operator_equal_identical_values test" << std::endl;
    dm_neighbor_t objA;
    dm_neighbor_t objB;
    parse_mac("00:11:22:33:44:55", objA.m_neighbor_info.nbr);
    objA.m_neighbor_info.pos_x = 1.0;
    objA.m_neighbor_info.pos_y = 2.0;
    objA.m_neighbor_info.pos_z = 3.0;
    parse_mac("AA:BB:CC:DD:EE:FF", objA.m_neighbor_info.next_hop);
    objA.m_neighbor_info.num_hops = 2;
    objA.m_neighbor_info.path_loss = 10;
    parse_mac("00:11:22:33:44:55", objB.m_neighbor_info.nbr);
    objB.m_neighbor_info.pos_x = 1.0;
    objB.m_neighbor_info.pos_y = 2.0;
    objB.m_neighbor_info.pos_z = 3.0;
    parse_mac("AA:BB:CC:DD:EE:FF", objB.m_neighbor_info.next_hop);
    objB.m_neighbor_info.num_hops = 2;
    objB.m_neighbor_info.path_loss = 10;
    bool result = (objA == objB);
    EXPECT_TRUE(result);
    std::cout << "Exiting operator_equal_identical_values test" << std::endl;
}
/**
 * @brief Verify that operator== returns false for objects with different neighbor MAC addresses
 *
 * This test case verifies that the equality operator (operator==) for the dm_neighbor_t class 
 * correctly identifies the objects as unequal when their neighbor MAC addresses differ, despite 
 * other attributes being identical. This ensures that the operator takes into account the neighbor 
 * MAC address during comparison, which is critical for proper object identification in network scenarios.
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
 * | Variation / Step | Description                                                                                         | Test Data                                                                                                                                                                                                                                                                     | Expected Result                                                            | Notes        |
 * | :--------------: | --------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------- | ------------ |
 * | 01               | Initialize two dm_neighbor_t objects with identical parameters except for neighbor MAC address     | objA: nbr = 00:11:22:33:44:55, pos_x = 1.0, pos_y = 2.0, pos_z = 3.0, next_hop = AA:BB:CC:DD:EE:FF, num_hops = 2, path_loss = 10; objB: nbr = 66:77:88:99:AA:BB, pos_x = 1.0, pos_y = 2.0, pos_z = 3.0, next_hop = AA:BB:CC:DD:EE:FF, num_hops = 2, path_loss = 10 | Operator== returns false indicating the objects are not equal | Should Pass |
 */
TEST(dm_neighbor_t, operator_inequality_different_nbr) {
    std::cout << "Entering operator_inequality_different_nbr test" << std::endl;
    dm_neighbor_t objA;
    dm_neighbor_t objB;
    parse_mac("00:11:22:33:44:55", objA.m_neighbor_info.nbr);
    objA.m_neighbor_info.pos_x = 1.0;
    objA.m_neighbor_info.pos_y = 2.0;
    objA.m_neighbor_info.pos_z = 3.0;
    parse_mac("AA:BB:CC:DD:EE:FF", objA.m_neighbor_info.next_hop);
    objA.m_neighbor_info.num_hops = 2;
    objA.m_neighbor_info.path_loss = 10;
    parse_mac("66:77:88:99:AA:BB", objB.m_neighbor_info.nbr);
    objB.m_neighbor_info.pos_x = 1.0;
    objB.m_neighbor_info.pos_y = 2.0;
    objB.m_neighbor_info.pos_z = 3.0;
    parse_mac("AA:BB:CC:DD:EE:FF", objB.m_neighbor_info.next_hop);
    objB.m_neighbor_info.num_hops = 2;
    objB.m_neighbor_info.path_loss = 10;
    bool result = (objA == objB);
    EXPECT_FALSE(result);
    std::cout << "Exiting operator_inequality_different_nbr test" << std::endl;
}
/**
 * @brief Verify that dm_neighbor_t equality operator identifies objects with different pos_x values as unequal.
 *
 * This test verifies that the dm_neighbor_t equality operator correctly returns false when
 * two dm_neighbor_t objects have identical MAC addresses and other neighbor info fields,
 * except for a different pos_x coordinate. Ensuring that objects with different positional data
 * are not considered equal is critical for spatial data integrity.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 030
 * **Priority:** High
 * 
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 * 
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize two dm_neighbor_t objects with all identical fields except pos_x | For objA: nbr = "00:11:22:33:44:55", pos_x = 1.0, pos_y = 2.0, pos_z = 3.0, next_hop = "AA:BB:CC:DD:EE:FF", num_hops = 2, path_loss = 10; For objB: nbr = "00:11:22:33:44:55", pos_x = 2.0, pos_y = 2.0, pos_z = 3.0, next_hop = "AA:BB:CC:DD:EE:FF", num_hops = 2, path_loss = 10 | dm_neighbor_t equality operator returns false | Should Pass |
 * | 02 | Compare the two objects using the equality operator | result = (objA == objB) | EXPECT_FALSE(result) passes confirming objects are unequal | Should Pass |
 */
TEST(dm_neighbor_t, operator_inequality_different_pos_x) {
    std::cout << "Entering operator_inequality_different_pos_x test" << std::endl;
    dm_neighbor_t objA;
    dm_neighbor_t objB;
    parse_mac("00:11:22:33:44:55", objA.m_neighbor_info.nbr);
    objA.m_neighbor_info.pos_x = 1.0;
    objA.m_neighbor_info.pos_y = 2.0;
    objA.m_neighbor_info.pos_z = 3.0;
    parse_mac("AA:BB:CC:DD:EE:FF", objA.m_neighbor_info.next_hop);
    objA.m_neighbor_info.num_hops = 2;
    objA.m_neighbor_info.path_loss = 10;
    parse_mac("00:11:22:33:44:55", objB.m_neighbor_info.nbr);
    objB.m_neighbor_info.pos_x = 2.0;
    objB.m_neighbor_info.pos_y = 2.0;
    objB.m_neighbor_info.pos_z = 3.0;
    parse_mac("AA:BB:CC:DD:EE:FF", objB.m_neighbor_info.next_hop);
    objB.m_neighbor_info.num_hops = 2;
    objB.m_neighbor_info.path_loss = 10;
    bool result = (objA == objB);
    EXPECT_FALSE(result);
    std::cout << "Exiting operator_inequality_different_pos_x test" << std::endl;
}
/**
 * @brief Verify that the equality operator returns false when pos_y values differ
 *
 * This test creates two dm_neighbor_t objects with identical values except for the pos_y field.
 * It verifies that the equality operator (==) identifies the objects as unequal, ensuring that positional
 * differences are correctly detected. This is important to maintain data integrity when comparing neighbor information.
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
 * | Variation / Step | Description                                                                               | Test Data                                                                                                                                                                                                                                                          | Expected Result                                                   | Notes       |
 * | :--------------: | ----------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------- | ----------- |
 * | 01               | Invoke operator== on two dm_neighbor_t objects with different pos_y values to check inequality | objA: {nbr = 00:11:22:33:44:55, pos_x = 1.0, pos_y = 2.0, pos_z = 3.0, next_hop = AA:BB:CC:DD:EE:FF, num_hops = 2, path_loss = 10}, objB: {nbr = 00:11:22:33:44:55, pos_x = 1.0, pos_y = 3.0, pos_z = 3.0, next_hop = AA:BB:CC:DD:EE:FF, num_hops = 2, path_loss = 10} | The operator== should return false and EXPECT_FALSE should pass | Should Pass |
 */
TEST(dm_neighbor_t, operator_inequality_different_pos_y) {
    std::cout << "Entering operator_inequality_different_pos_y test" << std::endl;
    dm_neighbor_t objA;
    dm_neighbor_t objB;
    parse_mac("00:11:22:33:44:55", objA.m_neighbor_info.nbr);
    objA.m_neighbor_info.pos_x = 1.0;
    objA.m_neighbor_info.pos_y = 2.0;
    objA.m_neighbor_info.pos_z = 3.0;
    parse_mac("AA:BB:CC:DD:EE:FF", objA.m_neighbor_info.next_hop);
    objA.m_neighbor_info.num_hops = 2;
    objA.m_neighbor_info.path_loss = 10;
    parse_mac("00:11:22:33:44:55", objB.m_neighbor_info.nbr);
    objB.m_neighbor_info.pos_x = 1.0;
    objB.m_neighbor_info.pos_y = 3.0;
    objB.m_neighbor_info.pos_z = 3.0;
    parse_mac("AA:BB:CC:DD:EE:FF", objB.m_neighbor_info.next_hop);
    objB.m_neighbor_info.num_hops = 2;
    objB.m_neighbor_info.path_loss = 10;
    bool result = (objA == objB);
    EXPECT_FALSE(result);
    std::cout << "Exiting operator_inequality_different_pos_y test" << std::endl;
}
/**
 * @brief Validate that the equality operator returns false when the pos_z values of two dm_neighbor_t objects differ
 *
 * This test verifies that the equality operator (==) correctly identifies two dm_neighbor_t objects as not equal when their pos_z fields have different values, while all other fields are identical.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 032
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize two dm_neighbor_t objects (objA and objB) with identical neighbor, pos_x, pos_y, next_hop, num_hops, and path_loss values, but with different pos_z values (objA: pos_z=3.0, objB: pos_z=4.0) | objA: nbr="00:11:22:33:44:55", pos_x=1.0, pos_y=2.0, pos_z=3.0, next_hop="AA:BB:CC:DD:EE:FF", num_hops=2, path_loss=10; objB: nbr="00:11:22:33:44:55", pos_x=1.0, pos_y=2.0, pos_z=4.0, next_hop="AA:BB:CC:DD:EE:FF", num_hops=2, path_loss=10 | Both objects are correctly initialized with the difference in pos_z | Should be successful |
 * | 02 | Compare objA and objB using the equality operator (==) and validate the result using EXPECT_FALSE | Input: objA and objB; Output: result (boolean) | The operator should return false indicating the objects are not equal, and EXPECT_FALSE(result) should pass | Should Pass |
 */
TEST(dm_neighbor_t, operator_inequality_different_pos_z) {
    std::cout << "Entering operator_inequality_different_pos_z test" << std::endl;
    dm_neighbor_t objA;
    dm_neighbor_t objB;
    parse_mac("00:11:22:33:44:55", objA.m_neighbor_info.nbr);
    objA.m_neighbor_info.pos_x = 1.0;
    objA.m_neighbor_info.pos_y = 2.0;
    objA.m_neighbor_info.pos_z = 3.0;
    parse_mac("AA:BB:CC:DD:EE:FF", objA.m_neighbor_info.next_hop);
    objA.m_neighbor_info.num_hops = 2;
    objA.m_neighbor_info.path_loss = 10;
    parse_mac("00:11:22:33:44:55", objB.m_neighbor_info.nbr);
    objB.m_neighbor_info.pos_x = 1.0;
    objB.m_neighbor_info.pos_y = 2.0;
    objB.m_neighbor_info.pos_z = 4.0;
    parse_mac("AA:BB:CC:DD:EE:FF", objB.m_neighbor_info.next_hop);
    objB.m_neighbor_info.num_hops = 2;
    objB.m_neighbor_info.path_loss = 10;
    bool result = (objA == objB);
    EXPECT_FALSE(result);
    std::cout << "Exiting operator_inequality_different_pos_z test" << std::endl;
}
/**
 * @brief Validates that two dm_neighbor_t objects with different next_hop values are considered unequal.
 *
 * This test creates two dm_neighbor_t objects with identical neighbor, position, num_hops, and path_loss values, but with different next_hop addresses. It verifies that the equality operator (==) properly distinguishes between the two objects by returning false.
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
 * | 01 | Initialize two dm_neighbor_t objects with identical values except for next_hop field; invoke the equality operator and assert that the objects are not equal. | objA: nbr = "00:11:22:33:44:55", pos_x = 1.0, pos_y = 2.0, pos_z = 3.0, next_hop = "AA:BB:CC:DD:EE:FF", num_hops = 2, path_loss = 10; objB: nbr = "00:11:22:33:44:55", pos_x = 1.0, pos_y = 2.0, pos_z = 3.0, next_hop = "11:22:33:44:55:66", num_hops = 2, path_loss = 10 | EXPECT_FALSE returns true indicating that the objects are not equal. | Should Pass |
 */
TEST(dm_neighbor_t, operator_inequality_different_next_hop) {
    std::cout << "Entering operator_inequality_different_next_hop test" << std::endl;
    dm_neighbor_t objA;
    dm_neighbor_t objB;
    parse_mac("00:11:22:33:44:55", objA.m_neighbor_info.nbr);
    objA.m_neighbor_info.pos_x = 1.0;
    objA.m_neighbor_info.pos_y = 2.0;
    objA.m_neighbor_info.pos_z = 3.0;
    parse_mac("AA:BB:CC:DD:EE:FF", objA.m_neighbor_info.next_hop);
    objA.m_neighbor_info.num_hops = 2;
    objA.m_neighbor_info.path_loss = 10;
    parse_mac("00:11:22:33:44:55", objB.m_neighbor_info.nbr);
    objB.m_neighbor_info.pos_x = 1.0;
    objB.m_neighbor_info.pos_y = 2.0;
    objB.m_neighbor_info.pos_z = 3.0;
    parse_mac("11:22:33:44:55:66", objB.m_neighbor_info.next_hop);
    objB.m_neighbor_info.num_hops = 2;
    objB.m_neighbor_info.path_loss = 10;
    bool result = (objA == objB);
    EXPECT_FALSE(result);
    std::cout << "Exiting operator_inequality_different_next_hop test" << std::endl;
}
/**
 * @brief Verify that the inequality operator correctly distinguishes objects with different number of hops
 *
 * This test verifies that two dm_neighbor_t objects with identical attributes except for the number of hops are not considered equal when the equality operator is used. The test ensures that the operator correctly identifies the difference in the num_hops field.
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
 * | Variation / Step | Description                                                                                      | Test Data                                                                                                                                                                                                                                                             | Expected Result                                                                       | Notes        |
 * | :--------------: | ------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------- | ------------ |
 * | 01               | Create two dm_neighbor_t objects, set all fields identical except for num_hops                   | For objA: nbr = "00:11:22:33:44:55", pos_x = 1.0, pos_y = 2.0, pos_z = 3.0, next_hop = "AA:BB:CC:DD:EE:FF", num_hops = 2, path_loss = 10; For objB: nbr = "00:11:22:33:44:55", pos_x = 1.0, pos_y = 2.0, pos_z = 3.0, next_hop = "AA:BB:CC:DD:EE:FF", num_hops = 3, path_loss = 10 | The equality operator (==) returns false indicating inequality | Should Pass |
 * | 02               | Verify the result of the equality check using EXPECT_FALSE                                       | result = (objA == objB)                                                                                                                                                                                                                                               | EXPECT_FALSE(result) passes because the objects are not equal                        | Should Pass |
 */
TEST(dm_neighbor_t, operator_inequality_different_num_hops) {
    std::cout << "Entering operator_inequality_different_num_hops test" << std::endl;
    dm_neighbor_t objA;
    dm_neighbor_t objB;
    parse_mac("00:11:22:33:44:55", objA.m_neighbor_info.nbr);
    objA.m_neighbor_info.pos_x = 1.0;
    objA.m_neighbor_info.pos_y = 2.0;
    objA.m_neighbor_info.pos_z = 3.0;
    parse_mac("AA:BB:CC:DD:EE:FF", objA.m_neighbor_info.next_hop);
    objA.m_neighbor_info.num_hops = 2;
    objA.m_neighbor_info.path_loss = 10;
    parse_mac("00:11:22:33:44:55", objB.m_neighbor_info.nbr);
    objB.m_neighbor_info.pos_x = 1.0;
    objB.m_neighbor_info.pos_y = 2.0;
    objB.m_neighbor_info.pos_z = 3.0;
    parse_mac("AA:BB:CC:DD:EE:FF", objB.m_neighbor_info.next_hop);
    objB.m_neighbor_info.num_hops = 3;
    objB.m_neighbor_info.path_loss = 10;
    bool result = (objA == objB);
    EXPECT_FALSE(result);
    std::cout << "Exiting operator_inequality_different_num_hops test" << std::endl;
}
/**
 * @brief Validate that two dm_neighbor_t objects are considered unequal when their path_loss values differ.
 *
 * This test case verifies that the equality operator for dm_neighbor_t objects returns false when the path_loss attribute is different between two objects. Two objects (objA and objB) are initialized with identical values except for the path_loss parameter (10 and 20 respectively). This is to ensure that the operator properly detects the difference in path loss.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 035@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                                                        | Test Data                                                                                                                                                                        | Expected Result                                                          | Notes          |
 * | :--------------: | -------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------ | -------------- |
 * | 01               | Initialize two dm_neighbor_t objects with their respective MAC address, position values, next_hop, number of hops, and different path_loss values. | objA: nbr = "00:11:22:33:44:55", pos_x = 1.0, pos_y = 2.0, pos_z = 3.0, next_hop = "AA:BB:CC:DD:EE:FF", num_hops = 2, path_loss = 10; objB: nbr = "00:11:22:33:44:55", pos_x = 1.0, pos_y = 2.0, pos_z = 3.0, next_hop = "AA:BB:CC:DD:EE:FF", num_hops = 2, path_loss = 20 | Both objects should be correctly initialized with the specified values. | Should be successful |
 * | 02               | Invoke the equality operator to compare the two objects and assert that they are unequal due to the differing path_loss.           | Input: objA and objB; Expected operator result: false                                                                                                                          | The equality check returns false, causing EXPECT_FALSE to pass.         | Should Pass    |
 */
TEST(dm_neighbor_t, operator_inequality_different_path_loss) {
    std::cout << "Entering operator_inequality_different_path_loss test" << std::endl;
    dm_neighbor_t objA;
    dm_neighbor_t objB;
    parse_mac("00:11:22:33:44:55", objA.m_neighbor_info.nbr);
    objA.m_neighbor_info.pos_x = 1.0;
    objA.m_neighbor_info.pos_y = 2.0;
    objA.m_neighbor_info.pos_z = 3.0;
    parse_mac("AA:BB:CC:DD:EE:FF", objA.m_neighbor_info.next_hop);
    objA.m_neighbor_info.num_hops = 2;
    objA.m_neighbor_info.path_loss = 10;
    parse_mac("00:11:22:33:44:55", objB.m_neighbor_info.nbr);
    objB.m_neighbor_info.pos_x = 1.0;
    objB.m_neighbor_info.pos_y = 2.0;
    objB.m_neighbor_info.pos_z = 3.0;
    parse_mac("AA:BB:CC:DD:EE:FF", objB.m_neighbor_info.next_hop);
    objB.m_neighbor_info.num_hops = 2;
    objB.m_neighbor_info.path_loss = 20;
    bool result = (objA == objB);
    EXPECT_FALSE(result);
    std::cout << "Exiting operator_inequality_different_path_loss test" << std::endl;
}
/**
 * @brief Verify that two dm_neighbor_t objects, when zero-initialized, are considered equal.
 *
 * This test invokes the init method on two dm_neighbor_t objects and then checks if they are equal using the overloaded operator==. The purpose is to ensure that the operator== returns true when both objects are in their default, zero-initialized state, indicating that the equality operation is correctly implemented.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 036
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :--------------: | ----------- | --------- | --------------- | ----- |
 * | 01 | Initialize object objA using the init method. | objA = instance of dm_neighbor_t, call init() | objA is zero-initialized. | Should be successful |
 * | 02 | Initialize object objB using the init method. | objB = instance of dm_neighbor_t, call init() | objB is zero-initialized. | Should be successful |
 * | 03 | Compare objA and objB using the overloaded operator==. | objA, objB, expected result = true | operator== returns true, assertion passes. | Should Pass |
 */
TEST(dm_neighbor_t, operator_equal_zero_initialized_objects) {
    std::cout << "Entering operator_equal_zero_initialized_objects test" << std::endl;
    dm_neighbor_t objA;
    dm_neighbor_t objB;
    objA.init();
    objB.init();
    bool result = (objA == objB);
    EXPECT_TRUE(result);
    std::cout << "Exiting operator_equal_zero_initialized_objects test" << std::endl;
}
/**
 * @brief Test to verify that the operator== correctly identifies inequality when multiple fields differ between two dm_neighbor_t objects
 *
 * This test creates two dm_neighbor_t objects (objA and objB) with differences in several neighbor information fields including MAC addresses, position coordinates, number of hops, and path loss. It then invokes the operator== to evaluate their equality. The test ensures that the operator returns false when there are multiple differences between the two objects.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 037@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                                     | Test Data                                                                                                                                                                                                                                                                                                                                                           | Expected Result                                                                    | Notes         |
 * | :--------------: | ----------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------- | ------------- |
 * | 01               | Initialize two dm_neighbor_t objects and set their neighbor information with differing values   | For objA: pos_x=1.0, pos_y=2.0, pos_z=3.0; next_hop parsed from "AA:BB:CC:DD:EE:FF"; num_hops=2; path_loss=10. For objB: nbr parsed first from "00:11:22:33:44:55", then updated with parse_mac("66:77:88:99:AA:BB"); pos_x=2.0, pos_y=3.0, pos_z=4.0; next_hop parsed from "11:22:33:44:55:66"; num_hops=3; path_loss=20                  | Objects initialized with multiple differing fields                               | Should be successful |
 * | 02               | Invoke the operator== function to compare the two objects                                       | Invocation of (objA == objB) with the above initialized objects                                                                                                                                                                                                                                                                                                   | Result should be false indicating inequality                                       | Should Pass   |
 * | 03               | Assert the operator result using EXPECT_FALSE                                                   | EXPECT_FALSE(result) where result is the boolean outcome of (objA == objB)                                                                                                                                                                                                                                                                                           | EXPECT_FALSE verifies that operator== returns false when objects differ             | Should Pass   |
 */
TEST(dm_neighbor_t, operator_inequality_multiple_fields_differ) {
    std::cout << "Entering operator_inequality_multiple_fields_differ test" << std::endl;
    dm_neighbor_t objA;
    dm_neighbor_t objB;
    parse_mac("00:11:22:33:44:55", objB.m_neighbor_info.nbr);
    objA.m_neighbor_info.pos_x = 1.0;
    objA.m_neighbor_info.pos_y = 2.0;
    objA.m_neighbor_info.pos_z = 3.0;
    parse_mac("AA:BB:CC:DD:EE:FF", objA.m_neighbor_info.next_hop);
    objA.m_neighbor_info.num_hops = 2;
    objA.m_neighbor_info.path_loss = 10;
    parse_mac("66:77:88:99:AA:BB", objB.m_neighbor_info.nbr);
    objB.m_neighbor_info.pos_x = 2.0;
    objB.m_neighbor_info.pos_y = 3.0;
    objB.m_neighbor_info.pos_z = 4.0;
    parse_mac("11:22:33:44:55:66", objB.m_neighbor_info.next_hop);
    objB.m_neighbor_info.num_hops = 3;
    objB.m_neighbor_info.path_loss = 20;
    bool result = (objA == objB);
    EXPECT_FALSE(result);
    std::cout << "Exiting operator_inequality_multiple_fields_differ test" << std::endl;
}
/**
 * @brief Verify that the destructor of dm_neighbor_t is correctly invoked upon object scope exit
 *
 * This test verifies that a dm_neighbor_t object, when created using its default constructor, is properly destructed automatically upon exiting its scope without throwing any exceptions. This behavior is essential for confirming that resources are released correctly and the destructor functions as intended.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 038@n
 * **Priority:** (High) High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                                                     | Test Data                                        | Expected Result                                                                                | Notes       |
 * | :--------------: | ----------------------------------------------------------------------------------------------- | ------------------------------------------------ | ---------------------------------------------------------------------------------------------- | ----------- |
 * | 01               | Invoke the default constructor of dm_neighbor_t inside an EXPECT_NO_THROW block to check exception-free object creation and automatic destruction upon scope exit. | Constructor Call: dm_neighbor_t neighbor()       | No exception is thrown and the dm_neighbor_t object is created and destructed successfully on leaving the scope. | Should Pass |
 */
TEST(dm_neighbor_t, destructor_destruction_invocation)
{
    std::cout << "Entering destructor_destruction_invocation test" << std::endl;
    EXPECT_NO_THROW({
        std::cout << "Invoking default constructor dm_neighbor_t()" << std::endl;
        dm_neighbor_t neighbor;
        std::cout << "dm_neighbor_t object created. It will be destructed automatically when going out of this scope." << std::endl;
    });
    std::cout << "Exited inner scope, destructor for dm_neighbor_t has been invoked automatically." << std::endl;
    std::cout << "Exiting destructor_destruction_invocation test" << std::endl;
}
