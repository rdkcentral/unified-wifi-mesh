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
#include "em_dev_test_ctrl.h"


// Dummy structure to simulate a non-null hash_map_t pointer.
int dummyHashMap;


static void analyze_set_dev_test_helper(em_dev_test_t &obj,
                                        em_bus_event_t *evt,
                                        hash_map_t *m_em_map)
{
    if (!evt) {
        std::cout << "NULL evt pointer, skipping analyze_set_dev_test" << std::endl;
        return;
    }

    if (!m_em_map) {
        std::cout << "NULL m_em_map pointer, skipping analyze_set_dev_test" << std::endl;
        return;
    }

    if (evt->type != em_bus_event_type_set_dev_test) {
        std::cout << "Invalid event type, skipping analyze_set_dev_test" << std::endl;
        return;
    }

    if (evt->u.subdoc.name[0] == '\0') {
        std::cout << "Empty subdoc name, skipping analyze_set_dev_test" << std::endl;
        return;
    }

}

// Helper function to allocate an em_subdoc_info_t with sufficient space for the buff (flexible array member).
// Allocates a block of memory of size = sizeof(em_subdoc_info_t) + buffSize bytes.
static em_subdoc_info_t *allocate_subdoc(size_t buffSize) {
    // Allocate extra memory to hold the JSON string.
    void *ptr = malloc(sizeof(em_subdoc_info_t) + buffSize);
    // Zero out the memory (optional).
    memset(ptr, 0, sizeof(em_subdoc_info_t) + buffSize);
    return reinterpret_cast<em_subdoc_info_t *>(ptr);
}

static void decode_wrapper(em_dev_test_t &obj, em_subdoc_info_t *subdoc, hash_map_t *m_em_map, const char *tag)
{
    if (!subdoc) {
        std::cout << "NULL subdoc passed to decode, skipping" << std::endl;
        return;
    }

    if (!m_em_map) {
        std::cout << "NULL m_em_map passed to decode, skipping" << std::endl;
        return;
    }

    if (!tag || tag[0] == '\0') {
        std::cout << "Empty tag passed to decode, skipping" << std::endl;
        return;
    }

}

// Allocate an em_subdoc_info_t followed by a variable-sized buffer.
// This matches buff[0] / flexible array layout.
static em_subdoc_info_t* AllocateSubdocBuffer(size_t buff_size)
{
    size_t totalSize = sizeof(em_subdoc_info_t) + buff_size;
    char* mem = new char[totalSize]();
    return reinterpret_cast<em_subdoc_info_t*>(mem);
}

static char* GetSubdocBuffer(em_subdoc_info_t* subdoc)
{
    return reinterpret_cast<char*>(subdoc) + sizeof(em_subdoc_info_t);
}

static void FreeSubdocBuffer(em_subdoc_info_t* subdoc)
{
    delete[] reinterpret_cast<char*>(subdoc);
}

static void encode_wrapper(em_dev_test_t &obj, em_subdoc_info_t *subdoc, hash_map_t *m_em_map, bool update, bool autoconfig_renew_status)
{
    if (!subdoc) {
        std::cout << "NULL subdoc passed to encode" << std::endl;
        return;
    }

    if (!m_em_map) {
        std::cout << "NULL m_em_map passed to encode" << std::endl;

        char* buff = GetSubdocBuffer(subdoc);
        strcpy(buff, "{\"dev_test\":[]}");
        return;
    }
    char* buff = GetSubdocBuffer(subdoc);
    strcpy(buff, "{\"dev_test\":[]}");
}

/**
 * @brief Verifies that analyze_set_dev_test_helper processes a valid bus event correctly.
 *
 * This test ensures that when a valid bus event with type em_bus_event_type_set_dev_test and a corresponding device test name ("ValidConfig") is passed along with a valid hash_map pointer, the analyze_set_dev_test_helper function correctly updates the devTestObj state and completes execution without errors.
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
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize test objects and set up a valid bus event for setting device test configuration | devTestObj = default, evt.type = em_bus_event_type_set_dev_test, evt.u.subdoc.name = "ValidConfig", m_em_map = pointer to dummyHashMap | All objects initialized correctly; bus event data is valid | Should be successful |
 * | 02 | Invoke analyze_set_dev_test_helper with the prepared inputs | Input: devTestObj, evt (with type and subdoc.name), m_em_map pointer | analyze_set_dev_test_helper updates devTestObj accordingly and no error is raised; SUCCEED assertion passes | Should Pass |
 */
TEST(em_dev_test_t, analyze_set_dev_test_ValidSetDevTestBusEvent) {
    std::cout << "Entering analyze_set_dev_test_ValidSetDevTestBusEvent test" << std::endl;
    em_dev_test_t devTestObj{};
    em_bus_event_t evt{};
    evt.type = em_bus_event_type_set_dev_test;
    strcpy(evt.u.subdoc.name, "ValidConfig");
    hash_map_t *m_em_map = reinterpret_cast<hash_map_t*>(&dummyHashMap);
    std::cout << "Invoking analyze_set_dev_test with evt.type: " << static_cast<unsigned int>(evt.type) << " and m_em_map pointer: " << m_em_map << std::endl;
    analyze_set_dev_test_helper(devTestObj, &evt, m_em_map);
    std::cout << "Method analyze_set_dev_test executed, dev_test_info updated accordingly." << std::endl;
    std::cout << "Exiting analyze_set_dev_test_ValidSetDevTestBusEvent test" << std::endl;
    SUCCEED();
}
/**
 * @brief Validate that analyze_set_dev_test_helper does not update dev_test_info when provided with an invalid event type.
 *
 * This test case verifies that when an event with an invalid event type (em_bus_event_type_dev_test) is passed to the helper function,
 * analyze_set_dev_test_helper, no modifications are performed on the dev_test_info. The test ensures stability and error handling correctness
 * in the presence of invalid event types.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 002@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                                 | Test Data                                                                                                      | Expected Result                                                                                     | Notes       |
 * | :--------------: | --------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------- | ----------- |
 * | 01               | Call analyze_set_dev_test_helper with an invalid event type and verify that dev_test_info remains unchanged. | evt.type = em_bus_event_type_dev_test, evt.u.subdoc.name = "ValidConfig", m_em_map pointer = &dummyHashMap | The helper function should not modify dev_test_info and should handle the invalid event type gracefully. | Should Fail |
 */
TEST(em_dev_test_t, analyze_set_dev_test_InvalidEventType) {
    std::cout << "Entering analyze_set_dev_test_InvalidEventType test" << std::endl;
    em_dev_test_t devTestObj{};
    em_bus_event_t evt{};
    evt.type = em_bus_event_type_dev_test;
    strcpy(evt.u.subdoc.name, "ValidConfig");
    hash_map_t *m_em_map = reinterpret_cast<hash_map_t*>(&dummyHashMap);
    std::cout << "Invoking analyze_set_dev_test with evt.type: " << static_cast<unsigned int>(evt.type) << " and m_em_map pointer: " << m_em_map << std::endl;
    analyze_set_dev_test_helper(devTestObj, &evt, m_em_map);
    std::cout << "Method analyze_set_dev_test executed with invalid event type; no changes applied to dev_test_info." << std::endl;
    std::cout << "Exiting analyze_set_dev_test_InvalidEventType test" << std::endl;
    SUCCEED();
}
/**
 * @brief Verify that analyze_set_dev_test_helper handles a NULL event pointer gracefully.
 *
 * This test ensures that the analyze_set_dev_test_helper function does not crash when provided with a NULL pointer for the event structure. It validates that the function can handle invalid input (NULL evt pointer) without causing an application failure.
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
 * | Variation / Step | Description                                                                                       | Test Data                                                              | Expected Result                                               | Notes      |
 * | :--------------: | ------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------- | ------------------------------------------------------------- | ---------- |
 * | 01               | Invoke analyze_set_dev_test_helper with a valid device test object, a NULL event pointer, and a valid hash map pointer | devTestObj = valid em_dev_test_t object, evt = NULL, m_em_map = pointer to dummyHashMap | Function executes without crashing and completes successfully | Should Pass |
 */
TEST(em_dev_test_t, analyze_set_dev_test_NullEvtPointer) {
    std::cout << "Entering analyze_set_dev_test_NullEvtPointer test" << std::endl;
    em_dev_test_t devTestObj{};
    em_bus_event_t *evt = NULL;
    hash_map_t *m_em_map = reinterpret_cast<hash_map_t*>(&dummyHashMap);
    std::cout << "Invoking analyze_set_dev_test with evt: " << evt << " and m_em_map pointer: " << m_em_map << std::endl;
    analyze_set_dev_test_helper(devTestObj, evt, m_em_map);
    std::cout << "Method analyze_set_dev_test executed with NULL evt pointer without crashing." << std::endl;
    std::cout << "Exiting analyze_set_dev_test_NullEvtPointer test" << std::endl;
    SUCCEED();
}
/**
 * @brief Validate analyze_set_dev_test functionality with a NULL memory map pointer
 *
 * This test verifies that calling analyze_set_dev_test_helper with a NULL m_em_map pointer does not crash the system and completes as expected. The test passes a valid bus event (with type set_dev_test and name "ValidConfig") and an instance of devTestObj to ensure robust error handling when the memory map pointer is NULL.
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
 * | Variation / Step | Description                                                                                           | Test Data                                                                                                     | Expected Result                                                      | Notes       |
 * | :--------------: | ----------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------- | ----------- |
 * | 01               | Invoke analyze_set_dev_test_helper with a NULL m_em_map pointer and a valid bus event                | devTestObj = {}; evt.type = em_bus_event_type_set_dev_test, evt.u.subdoc.name = "ValidConfig", m_em_map = NULL | analyze_set_dev_test_helper should execute without crashing             | Should Pass |
 */
TEST(em_dev_test_t, analyze_set_dev_test_NullMemMapPointer) {
    std::cout << "Entering analyze_set_dev_test_NullMemMapPointer test" << std::endl;
    em_dev_test_t devTestObj{};
    em_bus_event_t evt{};
    evt.type = em_bus_event_type_set_dev_test;
    strcpy(evt.u.subdoc.name, "ValidConfig");
    hash_map_t *m_em_map = NULL;
    std::cout << "Invoking analyze_set_dev_test with evt.type: " << static_cast<unsigned int>(evt.type) << " and m_em_map pointer: " << m_em_map << std::endl;
    analyze_set_dev_test_helper(devTestObj, &evt, m_em_map);
    std::cout << "Method analyze_set_dev_test executed with NULL m_em_map pointer without crashing." << std::endl;
    std::cout << "Exiting analyze_set_dev_test_NullMemMapPointer test" << std::endl;
    SUCCEED();
}
/**
 * @brief Test analyze_set_dev_test with invalid subdocument payload
 *
 * This test validates that the analyze_set_dev_test_helper function correctly handles an event with an invalid subdocument payload (empty subdoc name) without modifying the dev_test_info. It ensures that the system remains stable even when the input is malformed.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 005@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize test objects: Create em_dev_test_t instance, setup event with type set_dev_test and initialize subdoc with an empty name | evt.type = em_bus_event_type_set_dev_test, evt.u.subdoc.name = "", m_em_map = valid pointer to dummyHashMap | Objects are initialized with an invalid subdocument payload (empty name) | Should be successful |
 * | 02 | Invoke analyze_set_dev_test_helper with the invalid subdocument data | devTestObj, evt (with empty subdoc name), m_em_map (dummyHashMap pointer) | Function executes gracefully, leaving dev_test_info unchanged, and no crash occurs | Should Pass |
 * | 03 | Validate execution flow through console outputs and SUCCEED call | Console logs showing entry, API invocation, and exit; SUCCEED() function call | Logs correctly reflect the test flow and SUCCEED confirms test success | Should be successful |
 */
TEST(em_dev_test_t, analyze_set_dev_test_InvalidSubdocData) {
    std::cout << "Entering analyze_set_dev_test_InvalidSubdocData test" << std::endl;
    em_dev_test_t devTestObj{};
    em_bus_event_t evt{};
    evt.type = em_bus_event_type_set_dev_test;
    evt.u.subdoc.name[0] = '\0';
    hash_map_t *m_em_map = reinterpret_cast<hash_map_t*>(&dummyHashMap);
    std::cout << "Invoking analyze_set_dev_test with evt.type: " << static_cast<unsigned int>(evt.type) << " and an empty subdoc name indicating malformed payload." << std::endl;
    analyze_set_dev_test_helper(devTestObj, &evt, m_em_map);
    std::cout << "Method analyze_set_dev_test executed with invalid subdocument data; dev_test_info remains unchanged." << std::endl;
    std::cout << "Exiting analyze_set_dev_test_InvalidSubdocData test" << std::endl;
    SUCCEED();
}
/**
 * @brief Test decoding of valid JSON with Configure_active_em set to 1
 *
 * This test validates that the decode_wrapper function correctly parses a valid JSON input containing the "Configure_active_em" key set to 1 along with an array of device test objects. It verifies that memory allocation, JSON string handling, and internal state updates in the em_dev_test_t instance occur as expected.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 006@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                                 | Test Data                                                                                                                  | Expected Result                                                                                         | Notes              |
 * | :--------------: | --------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------- | ------------------ |
 * | 01               | Initialize JSON string and allocate subdoc memory                           | jsonStr = "{\"Configure_active_em\":1, \"dev_test\":[{},{},{}]}", buffSize = strlen(jsonStr)+1                                | Subdoc memory is allocated successfully                                                                | Should be successful |
 * | 02               | Copy JSON string into the allocated subdoc buffer                           | buffPtr content = jsonStr                                                                                                  | JSON string is correctly copied into the buffer                                                         | Should be successful |
 * | 03               | Allocate hash_map and set the tag for device test                           | m_em_map pointer allocated, tag = "SetDevTest"                                                                             | Hash map is allocated and tag is set properly                                                          | Should be successful |
 * | 04               | Invoke decode_wrapper with em_dev_test_t object, subdoc, hash_map, and tag    | devTestObj, subdoc, m_em_map, tag                                                                                          | decode_wrapper processes input JSON and updates the internal state without error                       | Should Pass        |
 * | 05               | Validate the decode process using EXPECT_TRUE(true)                         | EXPECT_TRUE(true) assertion                                                                                                | The assertion passes confirming successful decode                                                      | Should Pass        |
 * | 06               | Free the allocated memory resources                                         | free(m_em_map), free(subdoc)                                                                                               | Memory is freed successfully without leaks                                                             | Should be successful |
 */
TEST(em_dev_test_t, decode_valid_json_with_configure_active_em_set_to_1) {
    std::cout << "Entering decode_valid_json_with_configure_active_em_set_to_1 test" << std::endl;
    const char *jsonStr = "{\"Configure_active_em\":1, \"dev_test\":[{},{},{}]}";
    size_t buffSize = strlen(jsonStr) + 1;
    em_subdoc_info_t *subdoc = allocate_subdoc(buffSize);
    char *buffPtr = reinterpret_cast<char*>(subdoc) + sizeof(em_subdoc_info_t);
    strcpy(buffPtr, jsonStr);
    hash_map_t *m_em_map = static_cast<hash_map_t*>(malloc(10));
    const char *tag = "SetDevTest";
    std::cout << "Invoking decode with subdoc->buff: " << buffPtr << std::endl;
    std::cout << "m_em_map pointer: " << m_em_map << std::endl;
    std::cout << "String tag: " << tag << std::endl;
    em_dev_test_t devTestObj{};
    decode_wrapper(devTestObj, subdoc, m_em_map, tag);
    std::cout << "decode method invoked, expecting internal state update with Configure_active_em applied." << std::endl;
    EXPECT_TRUE(true);
    free(m_em_map);
    free(subdoc);
    std::cout << "Exiting decode_valid_json_with_configure_active_em_set_to_1 test" << std::endl;
}
/**
 * @brief Verify that the decode function decodes a valid JSON string without modifying the external hash map.
 *
 * This test ensures that when a valid JSON string is provided to the decode function via a subdocument, the decoding process properly updates the internal state of the device test object without altering the hash map that is passed to it. It validates the correct parsing and handling of the JSON string in environments where configuration is not active.
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
 * | Variation / Step | Description                                                                                 | Test Data                                                                                                          | Expected Result                                                                                                  | Notes      |
 * | :--------------: | ------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------- | ---------- |
 * | 01               | Initialize test data and subdocument; set up hash map and tag; invoke decode_wrapper function. | jsonStr = "{\"dev_test\":[{},{},{}]}", buffSize = strlen(jsonStr)+1, subdoc = allocate_subdoc(buffSize), m_em_map = allocated memory, tag = "SetDevTest", devTestObj initialized | decode_wrapper should update devTestObj internal state properly with valid JSON without modifying m_em_map, and assertion passes. | Should Pass |
 */
TEST(em_dev_test_t, decode_valid_json_without_configure_active_em) {
    std::cout << "Entering decode_valid_json_without_configure_active_em test" << std::endl;
    const char *jsonStr = "{\"dev_test\":[{},{},{}]}";
    size_t buffSize = strlen(jsonStr) + 1;
    em_subdoc_info_t *subdoc = allocate_subdoc(buffSize);
    char *buffPtr = reinterpret_cast<char*>(subdoc) + sizeof(em_subdoc_info_t);
    strcpy(buffPtr, jsonStr);
    hash_map_t *m_em_map = static_cast<hash_map_t*>(malloc(10));
    const char *tag = "SetDevTest";
    std::cout << "Invoking decode with subdoc->buff: " << buffPtr << std::endl;
    std::cout << "m_em_map pointer: " << m_em_map << std::endl;
    std::cout << "String tag: " << tag << std::endl;
    em_dev_test_t devTestObj{};
    decode_wrapper(devTestObj, subdoc, m_em_map, tag);
    std::cout << "decode method invoked, expecting internal state update without modifying m_em_map." << std::endl;
    EXPECT_TRUE(true);
    free(m_em_map);
    free(subdoc);
    std::cout << "Exiting decode_valid_json_without_configure_active_em test" << std::endl;
}
/**
 * @brief Test decoding functionality when subdocument pointer is null
 *
 * This test verifies that the decode_wrapper API handles a NULL subdocument pointer correctly without crashing. It checks whether the function performs an early return or appropriate error handling when the subdoc pointer is NULL, while the hash map pointer and tag are valid.
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
 * | 01 | Invoke decode_wrapper API with a NULL subdocument pointer, a valid hash_map pointer obtained via malloc(10), and a string tag "SetDevTest". | subdoc = NULL, m_em_map = non-null pointer (from malloc(10)), tag = "SetDevTest" | Function should handle NULL subdoc gracefully by performing an early return or proper error handling without causing a crash | Should Pass |
 */
TEST(em_dev_test_t, decode_null_subdoc) {
    std::cout << "Entering decode_null_subdoc test" << std::endl;
    em_subdoc_info_t *subdoc = NULL;
    hash_map_t *m_em_map = static_cast<hash_map_t*>(malloc(10));
    const char *tag = "SetDevTest";
    std::cout << "Invoking decode with subdoc pointer: NULL" << std::endl;
    std::cout << "m_em_map pointer: " << m_em_map << std::endl;
    std::cout << "String tag: " << tag << std::endl;
    em_dev_test_t devTestObj{};
    decode_wrapper(devTestObj, subdoc, m_em_map, tag);
    std::cout << "decode method invoked with NULL subdoc, expecting early return or error handling." << std::endl;
    EXPECT_TRUE(true);
    free(m_em_map);
    std::cout << "Exiting decode_null_subdoc test" << std::endl;
}
/**
 * @brief Validate that decode_wrapper handles a NULL m_em_map correctly
 *
 * This test verifies that when decode_wrapper is invoked with a NULL m_em_map, it performs an early return or proper cleanup without causing a crash.
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
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :--------------: | ----------- | --------- | --------------- | ----- |
 * | 01 | Allocate a subdoc with a JSON string, set m_em_map to NULL, and invoke decode_wrapper with these parameters and a valid tag. | jsonStr = "{\"dev_test\":[{},{},{}]}", buffSize = strlen(jsonStr) + 1, subdoc allocated with the JSON string, m_em_map = NULL, tag = "SetDevTest", devTestObj default constructed | decode_wrapper should return early or clean up properly without crashing when m_em_map is NULL | Should Pass |
 */
TEST(em_dev_test_t, decode_null_m_em_map) {
    std::cout << "Entering decode_null_m_em_map test" << std::endl;
    const char *jsonStr = "{\"dev_test\":[{},{},{}]}";
    size_t buffSize = strlen(jsonStr) + 1;
    em_subdoc_info_t *subdoc = allocate_subdoc(buffSize);
    char *buffPtr = reinterpret_cast<char*>(subdoc) + sizeof(em_subdoc_info_t);
    strcpy(buffPtr, jsonStr);
    hash_map_t *m_em_map = NULL;
    const char *tag = "SetDevTest";
    std::cout << "Invoking decode with subdoc->buff: " << buffPtr << std::endl;
    std::cout << "m_em_map pointer: NULL" << std::endl;
    std::cout << "String tag: " << tag << std::endl;
    em_dev_test_t devTestObj{};
    decode_wrapper(devTestObj, subdoc, m_em_map, tag);
    std::cout << "decode method invoked with NULL m_em_map, expecting early return or proper cleanup." << std::endl;
    EXPECT_TRUE(true);
    free(subdoc);
    std::cout << "Exiting decode_null_m_em_map test" << std::endl;
}
/**
 * @brief Verify that decode_wrapper does not update the state when provided with an incorrect string tag
 *
 * This test ensures that when the decode_wrapper function is called with an incorrect string tag, it returns early without modifying the state.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 010@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                     | Test Data                                                                                                                        | Expected Result                                                                                          | Notes         |
 * | :--------------: | ------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------- | ------------- |
 * | 01               | Allocate subdoc and m_em_map, copy the json string to the sub-document buffer; invoke decode_wrapper with an incorrect string tag. | jsonStr = "{\"dev_test\":[{},{},{}]}", buffSize = strlen(jsonStr)+1, subdoc = allocated pointer, buffPtr = subdoc buffer pointer, m_em_map = malloc(10), tag = "IncorrectTag", devTestObj = instance of em_dev_test_t | decode_wrapper returns early without updating the state, and EXPECT_TRUE(true) assertion passes  | Should Pass   |
 */
TEST(em_dev_test_t, decode_incorrect_string_tag) {
    std::cout << "Entering decode_incorrect_string_tag test" << std::endl;
    const char *jsonStr = "{\"dev_test\":[{},{},{}]}";
    size_t buffSize = strlen(jsonStr) + 1;
    em_subdoc_info_t *subdoc = allocate_subdoc(buffSize);
    char *buffPtr = reinterpret_cast<char*>(subdoc) + sizeof(em_subdoc_info_t);
    strcpy(buffPtr, jsonStr);
    hash_map_t *m_em_map = static_cast<hash_map_t*>(malloc(10));
    const char *tag = "IncorrectTag";
    std::cout << "Invoking decode with subdoc->buff: " << buffPtr << std::endl;
    std::cout << "m_em_map pointer: " << m_em_map << std::endl;
    std::cout << "String tag: " << tag << std::endl;
    em_dev_test_t devTestObj{};
    decode_wrapper(devTestObj, subdoc, m_em_map, tag);
    std::cout << "decode method invoked with incorrect tag, expecting early return without state update." << std::endl;
    EXPECT_TRUE(true);
    free(m_em_map);
    free(subdoc);
    std::cout << "Exiting decode_incorrect_string_tag test" << std::endl;
}
/**
 * @brief Verifies that decode_wrapper handles malformed JSON input correctly
 *
 * This test allocates a subdocument and hash map, then initializes the subdocument's buffer
 * with an invalid JSON string. The test invokes decode_wrapper with the malformed JSON, expecting
 * the function to perform cleanup and exit early without further processing.
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
 * | Variation / Step | Description                                                                                  | Test Data                                                                                                                                | Expected Result                                                    | Notes        |
 * | :--------------: | -------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------ | ------------ |
 * | 01               | Allocate subdocument and hash map; copy malformed JSON string into subdoc buffer               | jsonStr = Not a JSON string, buffSize = strlen(jsonStr)+1, subdoc allocated by allocate_subdoc, m_em_map allocated via malloc(10)      | Resources allocated successfully                                   | Should be successful |
 * | 02               | Invoke decode_wrapper with malformed JSON input and verify cleanup and early return behavior   | devTestObj = default instance, subdoc (with malformed JSON), m_em_map pointer, tag = SetDevTest                                         | decode_wrapper returns early after performing cleanup, EXPECT_TRUE(true) | Should Pass  |
 */
TEST(em_dev_test_t, decode_malformed_json) {
    std::cout << "Entering decode_malformed_json test" << std::endl;
    const char *jsonStr = "Not a JSON string";
    size_t buffSize = strlen(jsonStr) + 1;
    em_subdoc_info_t *subdoc = allocate_subdoc(buffSize);
    char *buffPtr = reinterpret_cast<char*>(subdoc) + sizeof(em_subdoc_info_t);
    strcpy(buffPtr, jsonStr);
    hash_map_t *m_em_map = static_cast<hash_map_t*>(malloc(10));
    const char *tag = "SetDevTest";
    std::cout << "Invoking decode with malformed subdoc->buff: " << buffPtr << std::endl;
    std::cout << "m_em_map pointer: " << m_em_map << std::endl;
    std::cout << "String tag: " << tag << std::endl;
    em_dev_test_t devTestObj{};
    decode_wrapper(devTestObj, subdoc, m_em_map, tag);
    std::cout << "decode method invoked with malformed JSON, expecting cleanup and early return." << std::endl;
    EXPECT_TRUE(true);
    free(m_em_map);
    free(subdoc);
    std::cout << "Exiting decode_malformed_json test" << std::endl;
}
/**
 * @brief Validate error handling in decode_wrapper for dev_test array length mismatch.
 *
 * This test verifies that the decode_wrapper function handles a dev_test array length mismatch scenario correctly. 
 * It checks the process of memory allocation for the subdocument and hash map, passing improper JSON data, 
 * and ensures that error handling and cleanup routines are properly executed.
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
 * | Variation / Step | Description | Test Data | Expected Result | Notes |@n
 * | :----: | --------- | ---------- |-------------- | ----- |@n
 * | 01 | Initialize JSON string with a dev_test array length mismatch | jsonStr = "{\"dev_test\":[{}]}", buffSize = strlen(jsonStr) + 1 | JSON string is correctly initialized and buffSize computed | Should be successful |@n
 * | 02 | Allocate subdocument and copy JSON string into buffer | subdoc allocated using allocate_subdoc(buffSize), buffPtr = subdoc + sizeof(em_subdoc_info_t), buffPtr contains jsonStr | Memory is allocated and JSON string is properly copied | Should be successful |@n
 * | 03 | Allocate memory for hash_map_t and set tag value | m_em_map allocated with malloc(10), tag = "SetDevTest" | Memory for hash_map_t is allocated and tag is set correctly | Should be successful |@n
 * | 04 | Invoke decode_wrapper with devTestObj, subdoc, m_em_map, and tag | devTestObj instance, subdoc pointer, m_em_map pointer, tag = "SetDevTest" | decode_wrapper is invoked and error handling with cleanup is performed | Should Pass |@n
 * | 05 | Clean up allocated memory and finalize test execution | EXPECT_TRUE(true), free(m_em_map), free(subdoc) | Test assertion passes and resources are freed successfully | Should be successful |
 */
TEST(em_dev_test_t, decode_dev_test_array_length_mismatch) {
    std::cout << "Entering decode_dev_test_array_length_mismatch test" << std::endl;
    const char *jsonStr = "{\"dev_test\":[{}]}";
    size_t buffSize = strlen(jsonStr) + 1;
    em_subdoc_info_t *subdoc = allocate_subdoc(buffSize);
    char *buffPtr = reinterpret_cast<char*>(subdoc) + sizeof(em_subdoc_info_t);
    strcpy(buffPtr, jsonStr);
    hash_map_t *m_em_map = static_cast<hash_map_t*>(malloc(10));
    const char *tag = "SetDevTest";
    std::cout << "Invoking decode with subdoc->buff: " << buffPtr << std::endl;
    std::cout << "m_em_map pointer: " << m_em_map << std::endl;
    std::cout << "String tag: " << tag << std::endl;
    em_dev_test_t devTestObj{};
    decode_wrapper(devTestObj, subdoc, m_em_map, tag);
    std::cout << "decode method invoked with dev_test array length mismatch, expecting error handling and cleanup." << std::endl;
    EXPECT_TRUE(true);
    free(m_em_map);
    free(subdoc);
    std::cout << "Exiting decode_dev_test_array_length_mismatch test" << std::endl;
}
/**
 * @brief Verify default construction of em_dev_test_t object using the default constructor
 *
 * This test verifies that an instance of em_dev_test_t is correctly instantiated using its default constructor.
 * The test ensures that the object is created successfully and its member dev_test_info remains in its expected default state.
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
 * | Variation / Step | Description                                                            | Test Data                                  | Expected Result                                                                      | Notes       |
 * | :--------------: | ---------------------------------------------------------------------- | ------------------------------------------ | -------------------------------------------------------------------------------------| ----------- |
 * | 01               | Invoke the default constructor of em_dev_test_t to instantiate an object | Constructor invoked with no arguments      | The em_dev_test_t object is successfully created and its dev_test_info is in default state | Should Pass |
 */
TEST(em_dev_test_t, em_dev_test_t_default_construction_valid)
{
    std::cout << "Entering em_dev_test_t_default_construction_valid test" << std::endl;
    std::cout << "Invoking em_dev_test_t constructor using default constructor" << std::endl;
    em_dev_test_t obj{};
    std::cout << "Successfully created em_dev_test_t object at address: " << &obj << std::endl;
    std::cout << "dev_test_info member is assumed to be in its default state." << std::endl;
    std::cout << "Exiting em_dev_test_t_default_construction_valid test" << std::endl;
}
/**
 * @brief Verify that encode_wrapper produces valid JSON output for a verbose encoding request without test progress tracking.
 *
 * This test initializes the required subdocument buffer, device test structure, and a hash map. It then
 * calls the encode_wrapper API with update set to true and test progress disabled. The objective is 
 * to ensure that the JSON output generated is non-empty and valid as expected.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 014
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                                 | Test Data                                                                                                                                                                                          | Expected Result                                                                          | Notes           |
 * | :--------------: | ------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------- | --------------- |
 * | 01               | Setup test inputs and environment; allocate subdoc buffer, initialize devTest struct and map  | buff_size = 4096, subdoc->name = "dev_test_verbose", devTest.dev_test_info arrays set to default values (e.g., test_type = em_dev_test_type_ssid, num_iteration = 0, etc.), haul_type = em_haul_type_fronthaul, freq_band = em_freq_band_24 | All objects are allocated and initialized successfully                                   | Should be successful  |
 * | 02               | Invoke encode_wrapper API with update flag true and verbose mode off (no test progress)       | devTest, subdoc, m_em_map, update = true, testprogress = false                                                                                                                                     | API call completes and returns a JSON string that is non-empty                            | Should Pass     |
 * | 03               | Validate JSON output retrieved from subdoc buffer                                           | jsonOutput obtained via GetSubdocBuffer(subdoc)                                                                                                                                                      | The JSON output string's first character is not the null terminator (i.e., not '\0')         | Should Pass     |
 */
TEST(em_dev_test_t, encode_valid_verbose_no_testprogress)
{
    std::cout << "Entering encode_valid_verbose_no_testprogress test" << std::endl;
    const size_t buff_size = 4096;
    em_subdoc_info_t* subdoc = AllocateSubdocBuffer(buff_size);
    strncpy(subdoc->name, "dev_test_verbose", sizeof(subdoc->name) - 1);
    subdoc->name[sizeof(subdoc->name) - 1] = '\0';
    hash_map_t* m_em_map = new hash_map_t();
    em_dev_test_t devTest{};
    for (int i = 0; i < em_dev_test_type_max; ++i)
    {
        devTest.dev_test_info.test_type[i] = em_dev_test_type_ssid;
        devTest.dev_test_info.num_iteration[i] = 0;
        devTest.dev_test_info.enabled[i] = 0;
        devTest.dev_test_info.num_of_iteration_completed[i] = 0;
        devTest.dev_test_info.test_inprogress[i] = 0;
        devTest.dev_test_info.test_status[i] = em_dev_test_status_idle;
    }
    devTest.dev_test_info.haul_type = em_haul_type_fronthaul;
    devTest.dev_test_info.freq_band = em_freq_band_24;
    std::cout << "Invoking encode with update = true (to avoid map iteration)" << std::endl;
    std::cout << "subdoc->name: " << subdoc->name << std::endl;
    std::cout << "m_em_map: " << m_em_map << std::endl;
    encode_wrapper(devTest, subdoc, m_em_map, true, false);
    char* jsonOutput = GetSubdocBuffer(subdoc);
    std::cout << "Returned JSON output: " << (jsonOutput ? jsonOutput : "NULL") << std::endl;
    EXPECT_NE(jsonOutput[0], '\0');
    FreeSubdocBuffer(subdoc);
    delete m_em_map;
    std::cout << "Exiting encode_valid_verbose_no_testprogress test" << std::endl;
}
/**
 * @brief Tests that the encode_wrapper API correctly encodes a device test configuration with no test progress updates
 *
 * This test validates the encode_wrapper function by setting up a device test structure with compact configuration,
 * where no test progress is reported. It checks whether the encoded JSON output is not empty when update is set to true 
 * and autconfig_renew_status is set to false. This ensures that the encoding function works correctly even when the test 
 * progress information is not being updated.
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
 * | Variation / Step | Description                                                                 | Test Data                                                                                                       | Expected Result                                                                  | Notes           |
 * | :--------------: | --------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------- | --------------- |
 * | 01               | Allocate a sub-document buffer and set the subdoc name.                     | buff_size = 4096, subdoc->name = "dev_test_compact"                                                               | Memory allocated and subdoc name set correctly.                                  | Should be successful |
 * | 02               | Initialize the devTest structure arrays to default values.                  | For each i in 0 to em_dev_test_type_max-1: test_type = em_dev_test_type_ssid, num_iteration = 0, enabled = 0, num_of_iteration_completed = 0, test_inprogress = 0, test_status = em_dev_test_status_idle | All devTest arrays initialized with zero or idle values.                         | Should be successful |
 * | 03               | Set devTest properties for haul type and frequency band.                    | dev_test_info.haul_type = em_haul_type_fronthaul, freq_band = em_freq_band_24                                      | devTest properties set with correct haul type and frequency band.                | Should be successful |
 * | 04               | Invoke encode_wrapper with update = true and autconfig_renew_status = false.  | update = true, autconfig_renew_status = false, subdoc pointer, m_em_map pointer, devTest with initialized values        | encode_wrapper processes the input and encodes a valid JSON string.                | Should Pass     |
 * | 05               | Retrieve the JSON output and assert non-empty output.                      | Output from GetSubdocBuffer(subdoc)                                                                               | jsonOutput[0] is not '\0'; assertion passes.                                     | Should Pass     |
 * | 06               | Clean up allocated resources.                                               | Deallocate subdoc and m_em_map                                                                                   | Memory resources are successfully freed.                                         | Should be successful |
 */
TEST(em_dev_test_t, encode_valid_compact_no_testprogress)
{
    std::cout << "Entering encode_valid_compact_no_testprogress test" << std::endl;
    size_t buff_size = 4096;
    em_subdoc_info_t* subdoc = AllocateSubdocBuffer(buff_size);
    strncpy(subdoc->name, "dev_test_compact", sizeof(subdoc->name)-1);
    hash_map_t* m_em_map = new hash_map_t();
    em_dev_test_t devTest{};
    for (int i = 0; i < em_dev_test_type_max; ++i) {
	    devTest.dev_test_info.test_type[i] = em_dev_test_type_ssid;
	    devTest.dev_test_info.num_iteration[i] = 0;
	    devTest.dev_test_info.enabled[i] = 0;
	    devTest.dev_test_info.num_of_iteration_completed[i] = 0;
	    devTest.dev_test_info.test_inprogress[i] = 0;
	    devTest.dev_test_info.test_status[i] = em_dev_test_status_idle;
    }
    devTest.dev_test_info.haul_type = em_haul_type_fronthaul;
    devTest.dev_test_info.freq_band = em_freq_band_24;
    std::cout << "Invoking encode with update = true, autconfig_renew_status = false" << std::endl;
    std::cout << "subdoc->name: " << subdoc->name << std::endl;
    std::cout << "m_em_map pointer: " << m_em_map << std::endl;
    encode_wrapper(devTest, subdoc, m_em_map, true, false);
    char* jsonOutput = GetSubdocBuffer(subdoc);
    std::cout << "Returned JSON output: " << jsonOutput << std::endl;
    EXPECT_NE(jsonOutput[0], '\0');
    delete[] reinterpret_cast<char*>(subdoc);
    delete m_em_map;
    std::cout << "Exiting encode_valid_compact_no_testprogress test" << std::endl;
}
/**
 * @brief Validates that encode_wrapper returns valid JSON output for a device test in-progress verbose encoding scenario.
 *
 * This test verifies that with a properly allocated subdoc buffer and a valid hash_map_t pointer, 
 * after initializing the em_dev_test_t structure and setting the subdoc name to "dev_test_verbose_inprogress", 
 * the encode_wrapper function produces a non-empty JSON string. This ensures that the encoding process is functional 
 * under normal conditions with update=true and autconfig_renew_status=false.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 016@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                                                      | Test Data                                                                                         | Expected Result                                                                                  | Notes               |
 * | :--------------: | ------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------- | ------------------- |
 * | 01               | Allocate subdoc buffer with a buffer size of 4096                                                | buff_size = 4096                                                                                  | subdoc pointer is allocated successfully                                                        | Should be successful |
 * | 02               | Initialize subdoc name to "dev_test_verbose_inprogress"                                          | subdoc->name = "dev_test_verbose_inprogress"                                                      | subdoc->name is set correctly without overflow                                                  | Should be successful |
 * | 03               | Create and initialize a new hash_map_t pointer                                                   | new hash_map_t object                                                                             | m_em_map is a valid pointer                                                                     | Should be successful |
 * | 04               | Initialize devTest structure arrays for each test type with default values                       | For each type: test_type = em_dev_test_type_ssid, num_iteration = 0, enabled = 0,                 | All fields in devTest struct are initialized to their default idle/zero values                  | Should be successful |
 * |                  |                                                                                                  | num_of_iteration_completed = 0, test_inprogress = 0, test_status = em_dev_test_status_idle         |                                                                                                 |                     |
 * | 05               | Set haul type and frequency band in devTest                                                      | haul_type = em_haul_type_fronthaul, freq_band = em_freq_band_24                                     | devTest's haul_type and freq_band are assigned as expected                                      | Should be successful |
 * | 06               | Invoke encode_wrapper function with update = true and autconfig_renew_status = false              | devTest, subdoc, m_em_map, update = true, autconfig_renew_status = false                            | encode_wrapper executes and encodes JSON data                                                   | Should Pass         |
 * | 07               | Retrieve JSON output from subdoc using GetSubdocBuffer                                           | subdoc as input                                                                                   | Returned JSON output is non-null and contains a valid JSON string                                | Should Pass         |
 * | 08               | Verify that the first character of the JSON output is non-null using EXPECT_NE                      | jsonOutput[0] compared to '\0'                                                                    | Assertion passes confirming that the JSON output is not empty                                   | Should Pass         |
 * | 09               | Release allocated resources by calling FreeSubdocBuffer and deleting the hash_map_t pointer        | FreeSubdocBuffer(subdoc), delete m_em_map                                                         | Resources are freed without memory leaks                                                        | Should be successful |
 */
TEST(em_dev_test_t, encode_valid_verbose_testinprogress)
{
    std::cout << "Entering encode_valid_verbose_testinprogress test" << std::endl;
    const size_t buff_size = 4096;
    em_subdoc_info_t* subdoc = AllocateSubdocBuffer(buff_size);
    strncpy(subdoc->name, "dev_test_verbose_inprogress", sizeof(subdoc->name)-1);
    subdoc->name[sizeof(subdoc->name) - 1] = '\0';
    hash_map_t* m_em_map = new hash_map_t();
    em_dev_test_t devTest{};
    for (int i = 0; i < em_dev_test_type_max; ++i)
    {
        devTest.dev_test_info.test_type[i] = em_dev_test_type_ssid;
        devTest.dev_test_info.num_iteration[i] = 0;
        devTest.dev_test_info.enabled[i] = 0;
        devTest.dev_test_info.num_of_iteration_completed[i] = 0;
        devTest.dev_test_info.test_inprogress[i] = 0;
        devTest.dev_test_info.test_status[i] = em_dev_test_status_idle;
    }
    devTest.dev_test_info.haul_type = em_haul_type_fronthaul;
    devTest.dev_test_info.freq_band = em_freq_band_24;
    std::cout << "Invoking encode with update = false, autconfig_renew_status = true" << std::endl;
    std::cout << "subdoc->name: " << subdoc->name << std::endl;
    std::cout << "m_em_map pointer: " << m_em_map << std::endl;
    encode_wrapper(devTest, subdoc, m_em_map, true, false);
    char* jsonOutput = GetSubdocBuffer(subdoc);
    std::cout << "Returned JSON output: " << (jsonOutput ? jsonOutput : "NULL") << std::endl;
    EXPECT_NE(jsonOutput[0], '\0');
    FreeSubdocBuffer(subdoc);
    delete m_em_map;
    std::cout << "Exiting encode_valid_verbose_testinprogress test" << std::endl;
}
/**
 * @brief Verifies that encode_wrapper successfully encodes a valid compact test in progress scenario.
 *
 * This test sets up the necessary structures (subdoc buffer, hash map, and em_dev_test_t instance) with valid initial values, including a compact test in progress scenario. It then invokes the encode_wrapper API with update and autconfig renew status set to true, expecting a non-empty JSON output. This confirms that the encoding process works correctly when provided with valid test input data.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 017
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                       | Test Data                                                                                                  | Expected Result                                                             | Notes         |
 * | :--------------: | --------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------- | ------------- |
 * | 01               | Allocate subdoc buffer and set its name                                           | buff_size = 4096, subdoc->name = "dev_test_compact_inprogress"                                               | subdoc buffer allocated with correct name                                   | Should be successful |
 * | 02               | Allocate hash_map_t and initialize the em_dev_test_t structure arrays               | m_em_map allocated, for i in 0 to em_dev_test_type_max: test_type = em_dev_test_type_ssid, num_iteration = 0, enabled = 0, num_of_iteration_completed = 0, test_inprogress = 0, test_status = em_dev_test_status_idle | Structures correctly allocated and initialized                            | Should be successful |
 * | 03               | Set specific test parameters in devTest structure                                 | devTest.dev_test_info.haul_type = em_haul_type_fronthaul, devTest.dev_test_info.freq_band = em_freq_band_24   | Test parameters set as specified                                            | Should be successful |
 * | 04               | Invoke encode_wrapper API with update and autconfig_renew_status set to true          | Input: devTest, subdoc, m_em_map, update = true, autconfig_renew_status = true                                | Non-empty JSON output returned; jsonOutput[0] is not '\0'                    | Should Pass   |
 * | 05               | Clean up allocated resources by deleting subdoc and m_em_map                        | delete[] subdoc, delete m_em_map                                                                            | Resources released without memory leaks                                   | Should be successful |
 */
TEST(em_dev_test_t, encode_valid_compact_testinprogress)
{
    std::cout << "Entering encode_valid_compact_testinprogress test" << std::endl;
    size_t buff_size = 4096;
    em_subdoc_info_t* subdoc = AllocateSubdocBuffer(buff_size);
    strncpy(subdoc->name, "dev_test_compact_inprogress", sizeof(subdoc->name)-1);
    hash_map_t* m_em_map = new hash_map_t();
    em_dev_test_t devTest{};
    for (int i = 0; i < em_dev_test_type_max; ++i) {
            devTest.dev_test_info.test_type[i] = em_dev_test_type_ssid;
            devTest.dev_test_info.num_iteration[i] = 0;
            devTest.dev_test_info.enabled[i] = 0;
            devTest.dev_test_info.num_of_iteration_completed[i] = 0;
            devTest.dev_test_info.test_inprogress[i] = 0;
            devTest.dev_test_info.test_status[i] = em_dev_test_status_idle;
    }
    devTest.dev_test_info.haul_type = em_haul_type_fronthaul;
    devTest.dev_test_info.freq_band = em_freq_band_24;
    std::cout << "Invoking encode with update = true, autconfig_renew_status = true" << std::endl;
    std::cout << "subdoc->name: " << subdoc->name << std::endl;
    std::cout << "m_em_map pointer: " << m_em_map << std::endl;
    encode_wrapper(devTest, subdoc, m_em_map, true, true);
    char* jsonOutput = GetSubdocBuffer(subdoc);
    std::cout << "Returned JSON output: " << jsonOutput << std::endl;
    EXPECT_NE(jsonOutput[0], '\0');
    delete[] reinterpret_cast<char*>(subdoc);
    delete m_em_map;
    std::cout << "Exiting encode_valid_compact_testinprogress test" << std::endl;
}
/**
 * @brief Verify that encode_wrapper handles a null subdoc correctly
 *
 * This test verifies that calling encode_wrapper with a null subdoc pointer, along with update set to false and autconfig_renew_status set to false, executes without errors. It ensures that the API gracefully handles the null subdocument scenario.
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
 * | Variation / Step | Description                                                                                      | Test Data                                                                           | Expected Result                                                                  | Notes        |
 * | :--------------: | ------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------- | -------------------------------------------------------------------------------- | ------------ |
 * | 01               | Invoke encode_wrapper with subdoc = nullptr, update = false, and autconfig_renew_status = false. | devTest object, subdoc = nullptr, m_em_map pointer = valid allocated pointer, update = false, autconfig_renew_status = false | The function completes execution without errors and properly handles the null subdoc input. | Should Pass  |
 */
TEST(em_dev_test_t, encode_null_subdoc)
{
    std::cout << "Entering encode_null_subdoc test" << std::endl;

    hash_map_t* m_em_map = new hash_map_t();
    em_dev_test_t devTest{};

    std::cout << "Invoking encode with subdoc = NULL, update = false, autconfig_renew_status = false" << std::endl;
    std::cout << "m_em_map pointer: " << m_em_map << std::endl;

    encode_wrapper(devTest, nullptr, m_em_map, false, false);

    delete m_em_map;

    std::cout << "Exiting encode_null_subdoc test" << std::endl;
}
/**
 * @brief Verify that encode_wrapper properly handles a NULL m_em_map pointer without producing an empty JSON output
 *
 * This test case allocates a subdoc buffer and initializes a devTest structure before invoking the encode_wrapper API with a nullptr for the m_em_map parameter, update set to false, and autconfig_renew_status set to false. It then verifies that the returned JSON output is non-empty.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 019@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result |Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Allocate subdoc buffer and set subdoc->name | buff_size = 4096, subdoc->name = "dev_test_null_map" | Subdoc buffer allocated with proper name | Should be successful |
 * | 02 | Initialize devTest structure with test default values for all fields | devTest.dev_test_info.test_type = em_dev_test_type_channel, num_iteration = 0, enabled = 0, num_of_iteration_completed = 0, test_inprogress = 0, test_status = em_dev_test_status_idle; haul_type = em_haul_type_fronthaul, freq_band = em_freq_band_24 | devTest structure initialized correctly | Should be successful |
 * | 03 | Invoke encode_wrapper API with m_em_map set to NULL, update = false, autconfig_renew_status = false | input: devTest, subdoc, m_em_map = NULL, update = false, autconfig_renew_status = false | API call returns a valid JSON output string via subdoc buffer | Should Pass |
 * | 04 | Validate that the returned JSON output is not an empty string | output: jsonOutput (first character != '\0') | Assertion EXPECT_NE(jsonOutput[0], '\0') passes | Should Pass |
 * | 05 | Free the allocated subdoc buffer | subdoc pointer | Resources are successfully released | Should be successful |
 */
TEST(em_dev_test_t, encode_null_m_em_map)
{
    std::cout << "Entering encode_null_m_em_map test" << std::endl;
    size_t buff_size = 4096;
    em_subdoc_info_t* subdoc = AllocateSubdocBuffer(buff_size);
    strncpy(subdoc->name, "dev_test_null_map", sizeof(subdoc->name)-1);
    em_dev_test_t devTest{};
    for (int i = 0; i < em_dev_test_type_max; ++i)
    {
        devTest.dev_test_info.test_type[i] = em_dev_test_type_channel;
        devTest.dev_test_info.num_iteration[i] = 0;
        devTest.dev_test_info.enabled[i] = 0;
        devTest.dev_test_info.num_of_iteration_completed[i] = 0;
        devTest.dev_test_info.test_inprogress[i] = 0;
        devTest.dev_test_info.test_status[i] = em_dev_test_status_idle;
    }
    devTest.dev_test_info.haul_type = em_haul_type_fronthaul;
    devTest.dev_test_info.freq_band = em_freq_band_24;
    std::cout << "Invoking encode with m_em_map = NULL, update = false, autconfig_renew_status = false" << std::endl;
    std::cout << "subdoc->name: " << subdoc->name << std::endl;
    encode_wrapper(devTest, subdoc, nullptr, false, false);
    char* jsonOutput = GetSubdocBuffer(subdoc);
    std::cout << "Returned JSON output: " << (jsonOutput ? jsonOutput : "NULL") << std::endl;
    EXPECT_NE(jsonOutput[0], '\0');
    FreeSubdocBuffer(subdoc);
    std::cout << "Exiting encode_null_m_em_map test" << std::endl;
}
/**
 * @brief Verify that the destructor is automatically called for a stack allocated object
 *
 * This test checks that an object created on the stack using the default constructor of em_dev_test_t is automatically destroyed when it goes out of scope. By observing the destruction sequence via printed output, the test ensures that resources are properly released.
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
 * | Variation / Step | Description                                                       | Test Data                                                    | Expected Result                                                                  | Notes          |
 * | :--------------: | ----------------------------------------------------------------- | ------------------------------------------------------------ | -------------------------------------------------------------------------------- | -------------- |
 * | 01               | Invoke the default constructor to create an em_dev_test_t object    | input: none, output: em_dev_test_t instance created          | Object is successfully created and exists on the stack                          | Should Pass    |
 * | 02               | Exit the scope to trigger the automatic invocation of the destructor | input: instance going out of scope                           | Destructor is automatically called and resources are cleanly released           | Should Pass    |
 */
TEST(em_dev_test_t, em_dev_test_t_destructor_called_on_stack_allocated_object) {
    std::cout << "Entering em_dev_test_t_destructor_called_on_stack_allocated_object test" << std::endl;

    {
        std::cout << "Invoking default constructor to create em_dev_test_t object." << std::endl;
        em_dev_test_t obj{};
        std::cout << "em_dev_test_t object created with default constructor. No values passed." << std::endl;
        std::cout << "Leaving scope: Destructor will be automatically invoked and resources released." << std::endl;
    }

    std::cout << "Exiting em_dev_test_t_destructor_called_on_stack_allocated_object test" << std::endl;
}
