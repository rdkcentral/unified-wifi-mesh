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
#include "em_network_topo.h"
#include "dm_easy_mesh_ctrl.h"
#include "dm_sta_list.h"
#include "util.h"
#include "dm_easy_mesh.h"
#include "collection.h"

extern em_network_topo_t* g_network_topology;
void init_dm_with_mac(dm_easy_mesh_t* dm, int id, int child_index) {
    // Deterministic MAC for testing: 02:id:child_index:00:00:00
    unsigned char mac[6] = {0x02, static_cast<unsigned char>(id),
                            static_cast<unsigned char>(child_index), 0x00, 0x00, 0x00};
    memcpy(dm->m_device.m_device_info.intf.mac, mac, 6);
    dm->m_num_bss = 0;
}

/**
 * @brief Verify that adding a valid child device to the network topology does not throw an exception
 *
 * This test validates the functionality of adding a child device to the network topology. It creates a root device,
 * initializes it with a specific MAC address, creates a child device with a different MAC address, and verifies that the
 * add operation does not throw an exception. The test also cleans up by removing the added child.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 001
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                              | Test Data                                                         | Expected Result                                                                      | Notes           |
 * | :--------------: | ---------------------------------------------------------------------------------------- | ----------------------------------------------------------------- | ------------------------------------------------------------------------------------ | --------------- |
 * | 01               | Create and initialize the root device manager with a MAC value of 0x10 and channel 0       | root_dm: created, MAC = 0x10, channel = 0                           | Root device is successfully created and initialized                                  | Should be successful |
 * | 02               | Initialize the network topology with the root device manager                             | topo_root: constructed using root_dm                              | Network topology is successfully instantiated                                        | Should be successful |
 * | 03               | Create and initialize the child device manager with a MAC value of 0x20 and channel 0        | child_dm: created, MAC = 0x20, channel = 0                           | Child device is successfully created and initialized                                 | Should be successful |
 * | 04               | Add the child device to the network topology using the add API with no additional context   | Call: topo_root.add(child_dm, nullptr, 0)                         | API call completes without throwing any exceptions; EXPECT_NO_THROW passes              | Should Pass     |
 * | 05               | Remove the child device from the network topology and clean up allocated resources           | Call: topo_root.remove(child_dm, nullptr, nullptr), then delete operations | The child device is successfully removed and resources are freed                        | Should be successful |
 */
TEST(em_network_topo_t, add_one_child)
{
    std::cout << "Entering add_one_child test" << std::endl;
    dm_easy_mesh_t* root_dm = new dm_easy_mesh_t{};
    init_dm_with_mac(root_dm, 0x10, 0);
    em_network_topo_t topo_root(root_dm);
    dm_easy_mesh_t* child_dm = new dm_easy_mesh_t{};
    init_dm_with_mac(child_dm, 0x20, 0);
    EXPECT_NO_THROW({
        topo_root.add(child_dm, nullptr, 0);
    });
    // Cleanup
    topo_root.remove(child_dm, nullptr, nullptr);
    delete child_dm;
    delete root_dm;
    std::cout << "Exiting add_one_child test" << std::endl;
}
/**
 * @brief Test the addition of a child network element with an associated grandchild element.
 *
 * This test verifies that a child network element, along with its grandchild elements, can be correctly added to the network topology without throwing exceptions. It creates and initializes root, child, and grandchild network elements, converts them into topology objects, and then calls the add method on the root topology object. This test is important to ensure the hierarchical addition in the network topology is functioning as expected.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 002@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                                      | Test Data                                                                            | Expected Result                                                                                                      | Notes          |
 * | :--------------: | ------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------- | -------------- |
 * | 01               | Initialize the root network element by allocating memory and initializing with MAC 0x10 and flag 0 | input: root_dm pointer, MAC = 0x10, flag = 0, output: dm_easy_mesh_t* instance        | Root network element is successfully initialized without exceptions                                               | Should be successful |
 * | 02               | Initialize the child network element by allocating memory and initializing with MAC 0x20 and flag 0| input: child_dm pointer, MAC = 0x20, flag = 0, output: dm_easy_mesh_t* instance       | Child network element is successfully initialized without exceptions                                              | Should be successful |
 * | 03               | Initialize the grandchild network element by allocating memory and initializing with MAC 0x30 and flag 0 | input: gc_dm pointer, MAC = 0x30, flag = 0, output: dm_easy_mesh_t* instance          | Grandchild network element is successfully initialized without exceptions                                         | Should be successful |
 * | 04               | Create topology objects for the root and grandchild elements                                      | input: root_dm, gc_dm converted to topology objects, output: em_network_topo_t instances| Topology objects for root and grandchild elements are successfully created                                            | Should be successful |
 * | 05               | Invoke the add method to attach the child element with its grandchild elements to the root topology | input: child_dm = child network element, gc_array = [gc_topo pointer], count = 1, output: updated topology| The add method completes without throwing an exception, indicating successful addition                              | Should Pass    |
 */
TEST(em_network_topo_t, add_child_with_grandchild)
{
    std::cout << "Entering add_child_with_grandchild test" << std::endl;
    dm_easy_mesh_t* root_dm = new dm_easy_mesh_t{};
    init_dm_with_mac(root_dm, 0x10, 0);
    em_network_topo_t topo_root(root_dm);
    dm_easy_mesh_t* child_dm = new dm_easy_mesh_t{};
    init_dm_with_mac(child_dm, 0x20, 0);
    dm_easy_mesh_t* gc_dm = new dm_easy_mesh_t{};
    init_dm_with_mac(gc_dm, 0x30, 0);
    em_network_topo_t* gc_topo = new em_network_topo_t(gc_dm);
    em_network_topo_t* gc_array[1] = { gc_topo };
    EXPECT_NO_THROW({
        topo_root.add(child_dm, gc_array, 1);
    });
    // Cleanup
    topo_root.remove(child_dm, nullptr, nullptr);
    delete gc_topo;
    delete gc_dm;
    delete child_dm;
    delete root_dm;
    std::cout << "Exiting add_child_with_grandchild test" << std::endl;
}
/**
 * @brief Verify that multiple children can be added to the network topology without exceptions.
 *
 * This test verifies that the em_network_topo_t API correctly handles adding multiple child nodes
 * to a parent network device node. The test creates a root node and two child nodes, then calls the add method
 * to include the child nodes in the network topology. The test asserts that no exceptions are thrown during this process.
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
 * | 01 | Initialize the root network device and topology object. | root_dm = new dm_easy_mesh_t{}, init_dm_with_mac(root_dm, 0x10, 0), topo_root = em_network_topo_t(root_dm) | Root device and topology created successfully. | Should be successful |
 * | 02 | Initialize two child nodes to be added to the topology. | c1 = new dm_easy_mesh_t{}, init_dm_with_mac(c1, 0x20, 0); c2 = new dm_easy_mesh_t{}, init_dm_with_mac(c2, 0x21, 1) | Child nodes c1 and c2 initialized correctly. | Should be successful |
 * | 03 | Invoke the add API to add child nodes to the topology. | Call topo_root.add(c1, nullptr, 0) and topo_root.add(c2, nullptr, 0) | API calls complete without throwing exceptions. | Should Pass |
 * | 04 | Cleanup by removing the added child nodes and deallocating dynamic memory. | Call topo_root.remove(c1, nullptr, nullptr), topo_root.remove(c2, nullptr, nullptr), delete c1, delete c2, delete root_dm | Cleanup executed successfully without exceptions and memory freed. | Should be successful |
 */
TEST(em_network_topo_t, add_multiple_children)
{
    std::cout << "Entering add_multiple_children test" << std::endl;
    dm_easy_mesh_t* root_dm = new dm_easy_mesh_t{};
    init_dm_with_mac(root_dm, 0x10, 0);
    em_network_topo_t topo_root(root_dm);
    dm_easy_mesh_t* c1 = new dm_easy_mesh_t{};
    dm_easy_mesh_t* c2 = new dm_easy_mesh_t{};
    init_dm_with_mac(c1, 0x20, 0);
    init_dm_with_mac(c2, 0x21, 1);
    EXPECT_NO_THROW({
        topo_root.add(c1, nullptr, 0);
        topo_root.add(c2, nullptr, 0);
    });
    // Cleanup
    topo_root.remove(c1, nullptr, nullptr);
    topo_root.remove(c2, nullptr, nullptr);
    delete c1;
    delete c2;
    delete root_dm;
    std::cout << "Exiting add_multiple_children test" << std::endl;
}
/**
 * @brief Verify that em_network_topo_t::add throws an exception when provided with null parameters
 *
 * This test checks the robustness of the add() API in handling null pointer inputs. By passing
 * null values for the required parameters, the test validates that the function correctly throws
 * an exception, ensuring that improper usage is appropriately handled.
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
 * | Variation / Step | Description                                                        | Test Data                                                    | Expected Result                                                                | Notes               |
 * | :--------------: | ------------------------------------------------------------------ | ------------------------------------------------------------ | ------------------------------------------------------------------------------ | ------------------- |
 * | 01               | Initialize dm_easy_mesh_t and network topology object              | root_dm = new dm_easy_mesh_t{}, mac = 0x10, param = 0          | dm object is initialized and network topology object is created successfully    | Should be successful |
 * | 02               | Invoke add() function with null parameters                         | input1 = nullptr, input2 = nullptr, additional parameter = 0    | Exception is thrown by add() indicating null input handling works correctly      | Should Pass         |
 * | 03               | Cleanup allocated resources                                         | delete root_dm                                               | Memory is freed without error                                                 | Should be successful |
 */
TEST(em_network_topo_t, add_null_dm)
{
    std::cout << "Entering add_null_dm test" << std::endl;
    dm_easy_mesh_t* root_dm = new dm_easy_mesh_t{};
    init_dm_with_mac(root_dm, 0x10, 0);
    em_network_topo_t topo_root(root_dm);
    EXPECT_ANY_THROW({
        topo_root.add(nullptr, nullptr, 0);
    });
    delete root_dm;
    std::cout << "Exiting add_null_dm test" << std::endl;
}
/**
 * @brief Test to verify the add method handles an empty child array input gracefully
 *
 * This test verifies that the add method of the network topology object can handle being called with a valid child mesh and a dummy array that contains a nullptr (simulating an empty child array). The function is expected to execute without throwing any exceptions.
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
 * | 01 | Invoke the add method on topo_root with child_dm and a dummy array containing a nullptr | child_dm = valid dm_easy_mesh_t instance (mac: 0x20), dummy_array = [nullptr], additional parameter = 0 | EXPECT_NO_THROW: add method should not throw any exception | Should Pass |
 */
TEST(em_network_topo_t, add_child_with_empty_child_array)
{
    std::cout << "Entering add_child_with_empty_child_array test" << std::endl;
    dm_easy_mesh_t* root_dm = new dm_easy_mesh_t{};
    init_dm_with_mac(root_dm, 0x10, 0);
    em_network_topo_t topo_root(root_dm);
    dm_easy_mesh_t* child_dm = new dm_easy_mesh_t{};
    init_dm_with_mac(child_dm, 0x20, 0);
    em_network_topo_t* dummy_array[1] = { nullptr };
    EXPECT_NO_THROW({
        topo_root.add(child_dm, dummy_array, 0);
    });
    topo_root.remove(child_dm, nullptr, nullptr);
    delete child_dm;
    delete root_dm;
    std::cout << "Exiting add_child_with_empty_child_array test" << std::endl;
}
/**
 * @brief Verify that adding a single child network topology to the root topology is successful
 *
 * This test verifies that the function em_network_topo_t::add_network_topo correctly adds a single child device manager instance (dm_easy_mesh_t) to the root topology.
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
 * | Variation / Step | Description                                                                                           | Test Data                                                                | Expected Result                                                                                  | Notes         |
 * | :--------------: | ----------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------ | ------------- |
 * | 01               | Invoke add_network_topo on topo_root with a valid child_dm pointer, null parent pointer, and flag 0     | child_dm = valid dm_easy_mesh_t instance, parent = nullptr, flag = 0     | API call returns without throwing any exceptions and successfully adds the child topology       | Should Pass   |
 * | 02               | Cleanup: Remove the added child topology and free allocated memory                                    | remove(child_dm, nullptr, nullptr) called, delete child_dm, root_dm, topo_root | Resources are released without any memory errors or leaks                                        | Should be successful |
 */
TEST(em_network_topo_t, add_network_topo_single_child) {
    std::cout << "Entering add_network_topo_single_child test" << std::endl;
    dm_easy_mesh_t* root_dm = new dm_easy_mesh_t{};
    em_network_topo_t* topo_root = new em_network_topo_t(root_dm);
    init_dm_with_mac(root_dm, 0x10, 0);
    dm_easy_mesh_t* child_dm = new dm_easy_mesh_t{};
    init_dm_with_mac(child_dm, 0x20, 0);
    EXPECT_NO_THROW(topo_root->add_network_topo(child_dm, nullptr, 0));
    // Cleanup
    topo_root->remove(child_dm, nullptr, nullptr);
    delete child_dm;
    delete root_dm;
    delete topo_root;
    std::cout << "Exiting add_network_topo_single_child test" << std::endl;
}
/**
 * @brief Test the functionality of adding multiple children nodes to a network topology.
 *
 * This test creates a root network topology with an underlying device and then creates three child devices.
 * It subsequently adds each child device to the topology using the add_network_topo() API and verifies that no exceptions are thrown.
 * The purpose of this test is to validate that the API can handle multiple child nodes correctly and does not fail during the addition process.
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
 * | Variation / Step | Description                                                                  | Test Data                                                                                                    | Expected Result                                                  | Notes           |
 * | :--------------: | ----------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------- | --------------- |
 * | 01               | Create a root device and initialize it with a specific MAC address and index | root_dm = new dm_easy_mesh_t instance, init_dm_with_mac(root_dm, 0x10, 0)                                    | Root device created and initialized with mac=0x10, index=0         | Should be successful  |
 * | 02               | Create multiple child devices and initialize them with unique MAC addresses   | For each child: children_dm[i] = new dm_easy_mesh_t instance, init_dm_with_mac(children_dm[i], 0x20+i, i)     | Child device created and initialized with mac starting at 0x20+i, index=i  | Should be successful  |
 * | 03               | Add each child device to the network topology without throwing exceptions     | Call add_network_topo(children_dm[i], nullptr, 0) for each child                                                | No exception is thrown during add_network_topo call              | Should Pass          |
 * | 04               | Remove each child device from the topology and deallocate its memory          | Call topo_root->remove(children_dm[i], nullptr, nullptr) then delete children_dm[i] for each child             | Child device removed from topology and memory deallocated         | Should be successful  |
 * | 05               | Clean up the root device and the topology instance                            | Delete root_dm and topo_root                                                                                   | Root device and topology deallocated without issues               | Should be successful  |
 */
TEST(em_network_topo_t, add_network_topo_multiple_children) {
    std::cout << "Entering add_network_topo_multiple_children test" << std::endl;
    dm_easy_mesh_t* root_dm = new dm_easy_mesh_t{};
    em_network_topo_t* topo_root = new em_network_topo_t(root_dm);
    init_dm_with_mac(root_dm, 0x10, 0);
    const int num_children = 3;
    dm_easy_mesh_t* children_dm[num_children];
    for (int i = 0; i < num_children; ++i) {
        children_dm[i] = new dm_easy_mesh_t{};
        init_dm_with_mac(children_dm[i], 0x20 + i, i);
    }
    for (int i = 0; i < num_children; ++i) {
        EXPECT_NO_THROW(topo_root->add_network_topo(children_dm[i], nullptr, 0));
    }
    // Cleanup: remove children from topology and delete DMs
    for (int i = 0; i < num_children; ++i) {
        topo_root->remove(children_dm[i], nullptr, nullptr);
        delete children_dm[i];
    }
    // Delete root DM and topology
    delete root_dm;
    delete topo_root;
    std::cout << "Exiting add_network_topo_multiple_children test" << std::endl;
}
/**
 * @brief Validate addition of a child network topology node with an associated grandchild node.
 *
 * This test verifies that a network topology tree can correctly manage a child node along with its
 * associated grandchild node by ensuring that add_network_topo() successfully adds both nodes without
 * throwing exceptions. The test then performs cleanup by removing the child node (which also manages the
 * grandchild internally). This is critical for ensuring that the hierarchical addition and removal of network
 * topology elements function as expected.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 008
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                                   | Test Data                                                                 | Expected Result                                                                       | Notes              |
 * | :--------------: | --------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------- | -------------------------------------------------------------------------------------- | ------------------ |
 * | 01               | Create root device management instance and network topology root                              | input: root_dm = new dm_easy_mesh_t{}, topo_root = new em_network_topo_t(root_dm)  | Objects are successfully created and memory allocated                                  | Should be successful |
 * | 02               | Initialize root device management with a specified MAC value                                  | input: root_dm, MAC = 0x10, value = 0                                     | Root device is initialized with the correct MAC values                                 | Should be successful |
 * | 03               | Create and initialize the child device management instance                                    | input: child_dm = new dm_easy_mesh_t{}, MAC = 0x20, value = 0               | Child device is initialized correctly with the respective MAC                          | Should be successful |
 * | 04               | Create and initialize the grandchild device management instance                               | input: grandchild_dm = new dm_easy_mesh_t{}, MAC = 0x30, value = 0          | Grandchild device is initialized correctly with the respective MAC                      | Should be successful |
 * | 05               | Create the network topology for the grandchild and store it in an array                         | input: grandchild_topo[0] = new em_network_topo_t(grandchild_dm)             | Grandchild network topology is created and stored in the array                         | Should be successful |
 * | 06               | Add the child topology along with the associated grandchild topology using add_network_topo()    | input: child_dm, grandchild_topo array, count = 1                         | API call succeeds without throwing exceptions and nodes are added as expected            | Should Pass        |
 * | 07               | Cleanup: Remove the child network topology (which internally manages the grandchild)            | input: child_dm, nullptr, nullptr                                         | Child and grandchild nodes are successfully removed and proper memory cleanup is performed | Should be successful |
 */
TEST(em_network_topo_t, add_network_topo_child_with_grandchild) {
    std::cout << "Entering add_network_topo_child_with_grandchild test" << std::endl;
    dm_easy_mesh_t* root_dm = new dm_easy_mesh_t{};
    em_network_topo_t* topo_root = new em_network_topo_t(root_dm);
    init_dm_with_mac(root_dm, 0x10, 0);
    dm_easy_mesh_t* child_dm = new dm_easy_mesh_t{};
    init_dm_with_mac(child_dm, 0x20, 0);
    dm_easy_mesh_t* grandchild_dm = new dm_easy_mesh_t{};
    init_dm_with_mac(grandchild_dm, 0x30, 0);
    em_network_topo_t* grandchild_topo[1] = { new em_network_topo_t(grandchild_dm) };
    EXPECT_NO_THROW(topo_root->add_network_topo(child_dm, grandchild_topo, 1));
    // Cleanup: remove child (which also manages the grandchild internally)
    topo_root->remove(child_dm, nullptr, nullptr);
    delete grandchild_dm;
    delete child_dm;
    delete root_dm;
    delete grandchild_topo[0];
    delete topo_root;
    std::cout << "Exiting add_network_topo_child_with_grandchild test" << std::endl;
}
/**
 * @brief Validate that a child network topology with multiple grandchildren can be added without error
 *
 * This test verifies that the add_network_topo method correctly attaches a child network topology along with its multiple grandchildren to the root topology. The test ensures no exceptions are thrown during the process and that the topology is structured as expected.
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
 * | Variation / Step | Description                                                                                   | Test Data                                                                                                                      | Expected Result                                                       | Notes         |
 * | :--------------: | --------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------- | ------------- |
 * | 01               | Create root device management object and initialize with MAC 0x10 and parameter 0              | root_dm created with init_dm_with_mac(root_dm, 0x10, 0)                                                                        | Root DM object is created and initialized properly                    | Should be successful |
 * | 02               | Create child device management object and initialize with MAC 0x20 and parameter 0               | child_dm created with init_dm_with_mac(child_dm, 0x20, 0)                                                                      | Child DM object is created and initialized properly                   | Should be successful |
 * | 03               | Create multiple grandchildren device management objects and initialize each with unique MACs   | For i in 0 to 2: grandchildren_dm[i] created with init_dm_with_mac(grandchildren_dm[i], 0x30+i, i)                                 | Grandchildren DM objects are created and initialized with unique MACs   | Should be successful |
 * | 04               | Invoke add_network_topo on the root topology with child and grandchildren arrays               | API call: topo_root->add_network_topo(child_dm, grandchildren_topo, num_grandchildren)                                          | API call does not throw any exception                                  | Should Pass   |
 * | 05               | Clean up the created topology by removing the child and deleting all allocated resources         | Calls to topo_root->remove(child_dm, nullptr, nullptr) and deletion of child_dm, root_dm, grandchildren_dm, grandchildren_topo | Topology is cleaned up without error; all objects deleted properly      | Should be successful |
 */
TEST(em_network_topo_t, add_network_topo_child_with_multiple_grandchildren) {
    std::cout << "Entering add_network_topo_child_with_multiple_grandchildren test" << std::endl;
    dm_easy_mesh_t* root_dm = new dm_easy_mesh_t{};
    em_network_topo_t* topo_root = new em_network_topo_t(root_dm);
    init_dm_with_mac(root_dm, 0x10, 0);
    dm_easy_mesh_t* child_dm = new dm_easy_mesh_t{};
    init_dm_with_mac(child_dm, 0x20, 0);
    const int num_grandchildren = 3;
    dm_easy_mesh_t* grandchildren_dm[num_grandchildren];
    em_network_topo_t* grandchildren_topo[num_grandchildren];
    for (int i = 0; i < num_grandchildren; i++) {
        grandchildren_dm[i] = new dm_easy_mesh_t{};
        init_dm_with_mac(grandchildren_dm[i], 0x30 + i, i); // Unique MAC for each grandchild
        grandchildren_topo[i] = new em_network_topo_t(grandchildren_dm[i]);
    }
    EXPECT_NO_THROW(topo_root->add_network_topo(child_dm, grandchildren_topo, num_grandchildren));
    // Cleanup: remove child (which disconnects topology hierarchy)
    topo_root->remove(child_dm, nullptr, nullptr);
    // Delete allocated grandchildren DMs and their topologies
    for (int i = 0; i < num_grandchildren; i++) {
        delete grandchildren_dm[i];
        delete grandchildren_topo[i];
    }
    delete child_dm;
    delete root_dm;
    delete topo_root;
    std::cout << "Exiting add_network_topo_child_with_multiple_grandchildren test" << std::endl;
}
/**
 * @brief Test the add_network_topo API for exception handling with null DM arguments
 *
 * This test verifies that the add_network_topo API method properly throws an exception when it is invoked with null parameters for the device manager arguments. It ensures that error handling is implemented correctly in scenarios where required DM references are missing.
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
 * | 01 | Create a network topology root without a Device Manager | topo_root = new em_network_topo_t() | Instance is created successfully | Should be successful |
 * | 02 | Invoke add_network_topo with null arguments | input1 = nullptr, input2 = nullptr, input3 = 0 | The API throws an exception | Should Pass |
 * | 03 | Delete the network topology instance to free resources | delete topo_root | Instance is deleted without errors | Should be successful |
 */
TEST(em_network_topo_t, add_network_topo_null_dm) {
    std::cout << "Entering add_network_topo_null_dm test" << std::endl;
    em_network_topo_t* topo_root = new em_network_topo_t(); // Root without DM
    EXPECT_ANY_THROW(topo_root->add_network_topo(nullptr, nullptr, 0));
    delete topo_root;
    std::cout << "Exiting add_network_topo_null_dm test" << std::endl;
}
/**
 * @brief Verifies default construction of em_network_topo_t instance without exceptions.
 *
 * This test ensures that creating an instance of em_network_topo_t using its default constructor does not throw any exceptions and results in a valid instance creation.
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
 * | Variation / Step | Description                                                         | Test Data                                                      | Expected Result                                                                          | Notes      |
 * | :--------------: | ------------------------------------------------------------------- | -------------------------------------------------------------- | ---------------------------------------------------------------------------------------- | ---------- |
 * | 01               | Invoke the default constructor of em_network_topo_t and verify that no exceptions are thrown. | input: default constructor call, output: instance creation success | API executes without throwing exceptions and successfully creates an instance. | Should Pass |
 */
TEST(em_network_topo_t, em_network_topo_t_defaultConstruction_validInstanceCreation) {
    std::cout << "Entering em_network_topo_t_defaultConstruction_validInstanceCreation test" << std::endl;
    EXPECT_NO_THROW({
        em_network_topo_t instance;
        std::cout << "Default constructor executed: em_network_topo_t instance created." << std::endl;
    });
    std::cout << "Exiting em_network_topo_t_defaultConstruction_validInstanceCreation test" << std::endl;
}
/**
 * @brief Validates the initialization of em_network_topo_t with a valid dm pointer
 *
 * This test checks that the em_network_topo_t constructor correctly initializes an object when provided with a valid dm pointer. The test ensures that no exceptions are thrown during the construction process.
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
 * | Variation / Step | Description                                                        | Test Data                                          | Expected Result                                            | Notes      |
 * | :--------------: | ------------------------------------------------------------------ | -------------------------------------------------- | ---------------------------------------------------------- | ---------- |
 * | 01               | Call the em_network_topo_t constructor using a valid dm pointer.     | dm pointer = valid instance of dm_easy_mesh_t      | No exception is thrown; constructor executes successfully. | Should Pass|
 */
TEST(em_network_topo_t, em_network_topo_t_valid_initialization) {
    std::cout << "Entering em_network_topo_t_valid_initialization test" << std::endl;
    dm_easy_mesh_t dm;
    EXPECT_NO_THROW({
        em_network_topo_t topo(&dm);
        std::cout << "Constructor executed with valid dm pointer." << std::endl;
    });
    std::cout << "Exiting em_network_topo_t_valid_initialization test" << std::endl;
}
/**
 * @brief Verify em_network_topo_t construction with a null data manager pointer
 *
 * This test validates that the constructor of em_network_topo_t can handle receiving a nullptr as the data manager pointer without throwing an exception. The test ensures robustness in scenarios where the dependency may be absent.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 013@n
 * **Priority:** High@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * 
 * **Test Procedure:**
 * | Variation / Step | Description                                                                                       | Test Data                        | Expected Result                                                             | Notes      |
 * | :--------------: | ------------------------------------------------------------------------------------------------- | -------------------------------- | --------------------------------------------------------------------------- | ---------- |
 * | 01               | Call the constructor of em_network_topo_t with a null data manager pointer and check that no exception is thrown. | dm pointer = nullptr             | The constructor should execute without throwing an exception and construct the object successfully. | Should Pass |
 */
TEST(em_network_topo_t, em_network_topo_t_null_dm_pointer) {
    std::cout << "Entering em_network_topo_t_null_dm_pointer test" << std::endl;
    EXPECT_NO_THROW({
        em_network_topo_t topo(nullptr);
        std::cout << "Constructor executed with nullptr dm pointer." << std::endl;
    });
    std::cout << "Exiting em_network_topo_t_null_dm_pointer test" << std::endl;
}
/**
 * @brief Verify that encoding a network topology with no child nodes executes without errors
 *
 * This test ensures that the encode method of the em_network_topo_t class properly handles a network topology that has no child nodes. It verifies that no exception is thrown when the encode method is invoked, ensuring robust behavior for basic topologies.
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
 * |01| Initialize the dm_easy_mesh_t object with a MAC and set the backhaul media to IEEE8023ab | root_dm: initialized with mac = 0x10, additional param = 0, m_device.m_device_info.backhaul_mac.media = em_media_type_ieee8023ab | Valid dm_easy_mesh_t object created with the specified settings | Should be successful |
 * |02| Construct the network topology object using the root_dm object | topo_root: instance created using root_dm | Instance of em_network_topo_t created and linked with root_dm | Should be successful |
 * |03| Create a cJSON object to store encoded output | obj: cJSON_CreateObject() | Valid cJSON object created | Should be successful |
 * |04| Call the encode method on the network topology object with the cJSON object | Method Invocation: topo_root->encode(obj) | No exception is thrown as verified by EXPECT_NO_THROW | Should Pass |
 * |05| Clean up allocated memory by deleting topo_root and root_dm, and deleting the cJSON object | Operations: delete topo_root, delete root_dm, cJSON_Delete(obj) | All allocated resources are properly released | Should be successful |
 */
TEST(em_network_topo_t, encode_no_child) {
    std::cout << "Entering encode_no_child test" << std::endl;
    dm_easy_mesh_t* root_dm = new dm_easy_mesh_t{};
    init_dm_with_mac(root_dm, 0x10, 0);
    root_dm->m_device.m_device_info.backhaul_mac.media = em_media_type_ieee8023ab;
    em_network_topo_t* topo_root = new em_network_topo_t(root_dm);
    cJSON* obj = cJSON_CreateObject();
    EXPECT_NO_THROW(topo_root->encode(obj));
    delete topo_root;
    delete root_dm;
    cJSON_Delete(obj);
    std::cout << "Exiting encode_no_child test" << std::endl;
}
/**
 * @brief Test encoding functionality for a network topology with one child node
 *
 * This test verifies that the encode method of the network topology is able to process a topology containing one child device without throwing any exceptions. The topology is built by initializing a root device with the appropriate MAC settings, creating a topology root object, adding a child device to the topology with similar MAC settings, and finally encoding the topology into a cJSON object.
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
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize the root device and set its MAC parameters and backhaul media type | root_dm pointer, mac_id = 0x10, flag = 0, backhaul_mac.media = em_media_type_ieee8023ab | Root device initialized successfully | Should be successful |
 * | 02 | Create the topology root object using the initialized root device | topo_root pointer created using new em_network_topo_t(root_dm) | Topology root object constructed | Should be successful |
 * | 03 | Initialize the child device with MAC parameters and set its backhaul media type, then add it to the topology root | child_dm pointer, mac_id = 0x20, flag = 0, backhaul_mac.media = em_media_type_ieee8023ab; invoke topo_root->add_network_topo(child_dm, nullptr, 0) | Child device added to topology successfully | Should be successful |
 * | 04 | Create a cJSON object and encode the network topology, verifying that no exceptions are thrown | cJSON object created using cJSON_CreateObject(); invoke topo_root->encode(obj) | Encoding executes without throwing an exception | Should Pass |
 * | 05 | Remove the child topology and clean up memory allocations | Invoke topo_root->remove(child_dm, nullptr, nullptr), delete child_dm, delete topo_root, delete root_dm, cJSON_Delete(obj) | Resources cleaned up successfully without memory leaks | Should be successful |
 */
TEST(em_network_topo_t, encode_one_child) {
    std::cout << "Entering encode_one_child test" << std::endl;
    dm_easy_mesh_t* root_dm = new dm_easy_mesh_t{};
    init_dm_with_mac(root_dm, 0x10, 0);
    root_dm->m_device.m_device_info.backhaul_mac.media = em_media_type_ieee8023ab;
    em_network_topo_t* topo_root = new em_network_topo_t(root_dm);
    dm_easy_mesh_t* child_dm = new dm_easy_mesh_t{};
    init_dm_with_mac(child_dm, 0x20, 0);
    child_dm->m_device.m_device_info.backhaul_mac.media = em_media_type_ieee8023ab;
    topo_root->add_network_topo(child_dm, nullptr, 0);
    cJSON* obj = cJSON_CreateObject();
    EXPECT_NO_THROW(topo_root->encode(obj));
    topo_root->remove(child_dm, nullptr, nullptr);
    delete child_dm;
    delete topo_root;
    delete root_dm;
    cJSON_Delete(obj);
    std::cout << "Exiting encode_one_child test" << std::endl;
}
/**
 * @brief Verify encode() handles a child with a grandchild in the topology correctly
 *
 * This test verifies that the encode() method can correctly encode a network topology
 * containing a root device with a child device that in turn has a grandchild device.
 * It ensures that the topology is built properly and that the encode() call does not throw
 * any exceptions when processing a multi-level hierarchy.
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
 * | Variation / Step | Description                                                                                      | Test Data                                                                                                                                        | Expected Result                                                              | Notes            |
 * | :--------------: | ------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------- | ---------------- |
 * | 01               | Initialize the root device and its network topology                                              | root_dm: created, init_dm_with_mac(root_dm, 0x10, 0), root_dm->m_device.m_device_info.backhaul_mac.media = em_media_type_ieee8023ab             | Root device initialized and topology instantiated successfully               | Should be successful |
 * | 02               | Initialize the child and grandchild devices with appropriate media settings                      | child_dm: created, init_dm_with_mac(child_dm, 0x20, 0), child_dm->m_device.m_device_info.backhaul_mac.media = em_media_type_ieee8023ab; grandchild_dm: created, init_dm_with_mac(grandchild_dm, 0x30, 0), grandchild_dm->m_device.m_device_info.backhaul_mac.media = em_media_type_ieee8023ab  | Child and grandchild devices initialized with correct media settings           | Should be successful |
 * | 03               | Create the grandchild topology and associate it with the child device's topology                 | grandchild_topo: created from grandchild_dm, grandchild_array: array containing grandchild_topo, call topo_root->add_network_topo(child_dm, grandchild_array, 1) | Child topology updated to include its grandchild topology                      | Should be successful |
 * | 04               | Invoke the encode method on the root topology and check that no exception is thrown                | cJSON* obj: created, call topo_root->encode(obj)                                                                                                | encode() executes without throwing an exception and returns a valid state      | Should Pass         |
 * | 05               | Clean up all dynamically allocated resources                                                     | Remove child from topology using topo_root->remove(child_dm, nullptr, nullptr), delete grandchild_topo, grandchild_dm, child_dm, topo_root, root_dm, and call cJSON_Delete(obj) | All resources are released without errors                                      | Should be successful |
 */
TEST(em_network_topo_t, encode_child_with_grandchild) {
    std::cout << "Entering encode_child_with_grandchild test" << std::endl;
    dm_easy_mesh_t* root_dm = new dm_easy_mesh_t{};
    init_dm_with_mac(root_dm, 0x10, 0);
    root_dm->m_device.m_device_info.backhaul_mac.media = em_media_type_ieee8023ab;
    em_network_topo_t* topo_root = new em_network_topo_t(root_dm);
    dm_easy_mesh_t* child_dm = new dm_easy_mesh_t{};
    child_dm->m_device.m_device_info.backhaul_mac.media = em_media_type_ieee8023ab;
    init_dm_with_mac(child_dm, 0x20, 0);
    dm_easy_mesh_t* grandchild_dm = new dm_easy_mesh_t{};
    init_dm_with_mac(grandchild_dm, 0x30, 0);
    grandchild_dm->m_device.m_device_info.backhaul_mac.media = em_media_type_ieee8023ab;
    em_network_topo_t* grandchild_topo = new em_network_topo_t(grandchild_dm);
    em_network_topo_t* grandchild_array[1] = { grandchild_topo };
    topo_root->add_network_topo(child_dm, grandchild_array, 1);
    cJSON* obj = cJSON_CreateObject();
    EXPECT_NO_THROW(topo_root->encode(obj));
    // Cleanup
    topo_root->remove(child_dm, nullptr, nullptr); // removes child and detaches grandchild
    delete grandchild_topo;
    delete grandchild_dm;
    delete child_dm;
    delete topo_root;
    delete root_dm;
    cJSON_Delete(obj);
    std::cout << "Exiting encode_child_with_grandchild test" << std::endl;
}
/**
 * @brief Validates encoding of radio BSS information.
 *
 * Tests the proper functioning of the encode method within the network topology class when encoding a topology configured with a single radio and a single BSS. This test ensures that the encoding process completes without throwing exceptions.
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
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize device management structure and configure radio/BSS information | input: root_dm pointer with m_num_radios = 1, m_num_bss = 1, device media set to em_media_type_ieee8023ab | root_dm is correctly initialized with proper configurations | Should be successful |
 * | 02 | Create network topology object using the initialized device management structure | input: root_dm pointer used to instantiate em_network_topo_t object | Network topology object (topo_root) is created successfully | Should be successful |
 * | 03 | Create a cJSON object and call the encode method on the network topology | input: cJSON object with no preset values; method call: topo_root->encode(obj) | No exception is thrown during the encoding process | Should Pass |
 * | 04 | Clean up allocated resources | input: pointers to topo_root, root_dm, and cJSON object | Resources are properly deallocated without errors | Should be successful |
 */
TEST(em_network_topo_t, encode_radio_bss) {
    std::cout << "Entering encode_radio_bss test" << std::endl;
    dm_easy_mesh_t* root_dm = new dm_easy_mesh_t{};
    init_dm_with_mac(root_dm, 0x10, 0);
    root_dm->m_num_radios = 1;
    root_dm->m_num_bss = 1;
    root_dm->m_device.m_device_info.backhaul_mac.media = em_media_type_ieee8023ab;
    em_network_topo_t* topo_root = new em_network_topo_t(root_dm);
    cJSON* obj = cJSON_CreateObject();
    EXPECT_NO_THROW(topo_root->encode(obj));
    delete topo_root;
    delete root_dm;
    cJSON_Delete(obj);
    std::cout << "Exiting encode_radio_bss test" << std::endl;
}
/**
 * @brief Validate that em_network_topo_t::encode throws an exception when no DM is configured.
 *
 * This test verifies that calling the encode method on an em_network_topo_t instance without 
 * a DM configuration results in an exception. The objective is to ensure that the API correctly 
 * handles usage scenarios where required dependency (DM) is absent, in order to prevent undefined 
 * behavior.
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
 * | Variation / Step | Description                                                                                      | Test Data                                        | Expected Result                                                               | Notes       |
 * | :--------------: | ------------------------------------------------------------------------------------------------ | ------------------------------------------------ | ----------------------------------------------------------------------------- | ----------- |
 * | 01               | Invoke the encode method on an em_network_topo_t instance without DM configuration                | input: topo (instance), obj (pointer to cJSON object) | API should throw an exception indicating missing DM configuration and encode fails | Should Fail |
 */
TEST(em_network_topo_t, encode_with_no_dm) {
    std::cout << "Entering encode_with_no_dm test" << std::endl;
    em_network_topo_t topo;
    cJSON* obj = cJSON_CreateObject();
    EXPECT_ANY_THROW({
        topo.encode(obj);
    });
    cJSON_Delete(obj);
    std::cout << "Exiting encode_with_no_dm test" << std::endl;
}
/**
 * @brief Tests the behavior of the encode method when passed a null object.
 *
 * This test verifies that the encode method of the em_network_topo_t class correctly throws an exception when invoked with a null argument. It ensures that the API enforces proper input validation under error conditions.
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
 * | Variation / Step | Description                                                   | Test Data                                                                                                   | Expected Result                                                               | Notes             |
 * | :--------------: | ------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------- | ----------------- |
 * | 01               | Initialize dm_easy_mesh_t and em_network_topo_t objects         | root_dm = new dm_easy_mesh_t{}, topo_root = new em_network_topo_t(root_dm)                                  | Objects created successfully without throwing exceptions                     | Should be successful |
 * | 02               | Set the MAC address in the device info                        | mac = {0x02, 0x10, 0x00, 0x00, 0x00, 0x00}, root_dm->m_device.m_device_info.intf.mac assigned these values  | MAC address set correctly in the root_dm object                                | Should be successful |
 * | 03               | Call encode with a null object                                | Call encode(nullptr) on topo_root                                                                          | Exception is thrown indicating the API handles null input properly             | Should Pass       |
 * | 04               | Clean up allocated objects                                    | delete topo_root, delete root_dm                                                                            | All objects are deleted without memory leaks                                 | Should be successful |
 */
TEST(em_network_topo_t, encode_with_null_object) {
    std::cout << "Entering encode_with_null_object test" << std::endl;
    dm_easy_mesh_t* root_dm = new dm_easy_mesh_t{};
    em_network_topo_t* topo_root = new em_network_topo_t(root_dm);
    unsigned char mac[6] = {0x02, 0x10, 0x00, 0x00, 0x00, 0x00};
    memcpy(root_dm->m_device.m_device_info.intf.mac, mac, 6);
    EXPECT_ANY_THROW({
        topo_root->encode(nullptr);
    });
    delete topo_root;
    delete root_dm;
    std::cout << "Exiting encode_with_null_object test" << std::endl;
}
/**
 * @brief Test to verify that find_topology returns the topology root when invoked with the root node.
 *
 * This test verifies that when the topology is constructed with a root node, invoking find_topology with the root returns the same root. It confirms that the topology search algorithm correctly identifies the topology root.
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
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Allocate and initialize dm_easy_mesh_t object via init_dm_with_mac | root_dm = pointer to new dm_easy_mesh_t, mac = 0x10, param = 0 | dm_easy_mesh_t object properly initialized | Should be successful |
 * | 02 | Create em_network_topo_t object with root_dm | input: root_dm pointer | em_network_topo_t object created with root_dm as root | Should be successful |
 * | 03 | Invoke find_topology API on em_network_topo_t object with root_dm | input: root_dm, output: result pointer | Function returns pointer equal to topology root (&topo_root) | Should Pass |
 * | 04 | Verify returned pointer equals &topo_root using assertion | Expected: result pointer equals &topo_root | EXPECT_EQ(result, &topo_root) passes | Should be successful |
 * | 05 | Deallocate the dm_easy_mesh_t object | input: root_dm pointer | Object deallocated successfully | Should be successful |
 */
TEST(em_network_topo_t, find_topology_root_only) {
    std::cout << "Entering find_topology_root_only test" << std::endl;
    dm_easy_mesh_t* root_dm = new dm_easy_mesh_t{};
    init_dm_with_mac(root_dm, 0x10, 0);
    em_network_topo_t topo_root(root_dm);
    em_network_topo_t* result = topo_root.find_topology(root_dm);
    EXPECT_EQ(result, &topo_root);
    delete root_dm;
    std::cout << "Exiting find_topology_root_only test" << std::endl;
}
/**
 * @brief Verify that the topology search returns a valid topology for a child node.
 *
 * This test verifies that when a child device is added to the network topology, the find_topology
 * method correctly identifies and returns the topology object corresponding to that child node. The
 * test ensures that the returned topology is not null and that its associated data model matches the
 * child device.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 021@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Create and initialize the root data model. | root_dm pointer, MAC = 0x10, flag = 0 | root_dm is correctly initialized | Should be successful |
 * | 02 | Create the topology using the root data model. | root_dm pointer value | Topology root (topo_root) is created with the correct data model | Should be successful |
 * | 03 | Create and initialize the child data model. | child_dm pointer, MAC = 0x20, flag = 0 | child_dm is correctly initialized | Should be successful |
 * | 04 | Add the child data model to the topology. | child_dm pointer, add_network_topo(child_dm, nullptr, 0) | Child topology is successfully added to topo_root | Should Pass |
 * | 05 | Retrieve the topology for the child data model. | find_topology(child_dm) invoked with child_dm pointer | Returned topology is not null and its data model equals child_dm | Should Pass |
 * | 06 | Clean up by removing and deleting the added elements. | remove(child_dm, nullptr, nullptr), delete operations | Resources are freed without error | Should be successful |
 */
TEST(em_network_topo_t, find_topology_one_child) {
    std::cout << "Entering find_topology_one_child test" << std::endl;
    dm_easy_mesh_t* root_dm = new dm_easy_mesh_t{};
    init_dm_with_mac(root_dm, 0x10, 0);
    em_network_topo_t* topo_root = new em_network_topo_t(root_dm);
    dm_easy_mesh_t* child_dm = new dm_easy_mesh_t{};
    init_dm_with_mac(child_dm, 0x20, 0);
    topo_root->add_network_topo(child_dm, nullptr, 0);
    em_network_topo_t* result = topo_root->find_topology(child_dm);
    EXPECT_NE(result, nullptr);
    EXPECT_EQ(result->get_data_model(), child_dm);
    // Cleanup
    topo_root->remove(child_dm, nullptr, nullptr);
    delete child_dm;
    delete root_dm;
    delete topo_root;
    std::cout << "Exiting find_topology_one_child test" << std::endl;
}
/**
 * @brief Test the find_topology function for a topology with multiple children.
 *
 * This test verifies that when two child data models are added to a network topology tree, the find_topology function correctly retrieves the topology corresponding to each child by comparing pointers to their respective data models. This ensures that the topology search mechanism returns the appropriate network topology for each input child.
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
 * | Variation / Step | Description                                                                                             | Test Data                                                                                                          | Expected Result                            | Notes           |
 * | :--------------: | ------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------ | ------------------------------------------ | --------------- |
 * | 01               | Initialize the root data model and instantiate the network topology.                                  | root_dm = new dm_easy_mesh_t{}, mac = 0x10, flag = 0                                                               | Network topology created successfully      | Should be successful |
 * | 02               | Initialize two child data models with specific MAC addresses.                                         | child1 = new dm_easy_mesh_t{} with mac = 0x20, flag = 0; child2 = new dm_easy_mesh_t{} with mac = 0x21, flag = 1     | Child data models initialized              | Should be successful |
 * | 03               | Add the two child data models to the network topology.                                               | add_network_topo(child1, nullptr, 0); add_network_topo(child2, nullptr, 0)                                           | Child topology nodes added                 | Should be successful |
 * | 04               | Retrieve each child topology and validate the data model pointers using the find_topology method.       | find_topology(child1) returns node with get_data_model() == child1; find_topology(child2) returns node with get_data_model() == child2 | Assertions pass (data model pointers match) | Should Pass     |
 * | 05               | Cleanup: Remove child topology nodes and free allocated memory.                                        | remove(child1, nullptr, nullptr); remove(child2, nullptr, nullptr); delete child1; delete child2; delete root_dm        | Cleanup performed successfully             | Should be successful |
 */
TEST(em_network_topo_t, find_topology_multiple_children) {
    std::cout << "Entering find_topology_multiple_children test" << std::endl;
    dm_easy_mesh_t* root_dm = new dm_easy_mesh_t{};
    init_dm_with_mac(root_dm, 0x10, 0);
    em_network_topo_t topo_root(root_dm);
    dm_easy_mesh_t* child1 = new dm_easy_mesh_t{};
    dm_easy_mesh_t* child2 = new dm_easy_mesh_t{};
    init_dm_with_mac(child1, 0x20, 0);
    init_dm_with_mac(child2, 0x21, 1);
    topo_root.add_network_topo(child1, nullptr, 0);
    topo_root.add_network_topo(child2, nullptr, 0);
    EXPECT_EQ(topo_root.find_topology(child1)->get_data_model(), child1);
    EXPECT_EQ(topo_root.find_topology(child2)->get_data_model(), child2);
    // Cleanup
    topo_root.remove(child1, nullptr, nullptr);
    topo_root.remove(child2, nullptr, nullptr);
    delete child1;
    delete child2;
    delete root_dm;
    std::cout << "Exiting find_topology_multiple_children test" << std::endl;
}
/**
 * @brief Test to verify the find_topology API can correctly locate a grandchild topology in the network topology tree.
 *
 * This test creates a network topology tree with a root, a child, and a grandchild. It initializes each data model with a MAC address,
 * builds the topology hierarchy by adding the child (and its grandchild) to the root, and then calls the find_topology API with the grandchild data model.
 * The expected result is that the API returns a valid pointer to the grandchild topology, and its associated data model matches the grandchild data model.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 023@n
 * **Priority:** High@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * 
 * **Test Procedure:**
 * | Variation / Step | Description                                                      | Test Data                                                                      | Expected Result                                                                                              | Notes                |
 * | :--------------: | ---------------------------------------------------------------- | ----------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------ | -------------------- |
 * | 01               | Initialize root data model and topology                          | root_dm: valid pointer, mac = 0x10, param = 0; topo_root: valid pointer created | Data model and network topology objects for root are correctly initialized                                    | Should be successful |
 * | 02               | Initialize child data model with MAC                             | child_dm: valid pointer, mac = 0x20, param = 0                                | Child data model is correctly initialized                                                                    | Should be successful |
 * | 03               | Initialize grandchild data model and its topology object           | grandchild_dm: valid pointer, mac = 0x30, param = 0; grandchild_topo: valid pointer created | Grandchild data model and its network topology object are correctly initialized                                 | Should be successful |
 * | 04               | Add child and grandchild topology to the root topology             | child_dm, grandchild_array = {grandchild_topo}, size = 1                        | Topology tree is updated with the child and its grandchild correctly added to the root topology                 | Should Pass          |
 * | 05               | Invoke find_topology with grandchild data model to locate the grandchild topology | input: grandchild_dm; output: result pointer                                     | API returns a non-null pointer such that result->get_data_model() equals grandchild_dm                         | Should Pass          |
 * | 06               | Cleanup allocated objects                                          | Deletion of root_dm, child_dm, grandchild_dm, topo_root, grandchild_topo         | All allocated resources are freed without memory leaks                                                         | Should be successful |
 */
TEST(em_network_topo_t, find_topology_grandchild) {
    std::cout << "Entering find_topology_grandchild test" << std::endl;
    dm_easy_mesh_t* root_dm = new dm_easy_mesh_t{};
    init_dm_with_mac(root_dm, 0x10, 0);
    em_network_topo_t* topo_root = new em_network_topo_t(root_dm);
    // Child DM
    dm_easy_mesh_t* child_dm = new dm_easy_mesh_t{};
    init_dm_with_mac(child_dm, 0x20, 0);
    dm_easy_mesh_t* grandchild_dm = new dm_easy_mesh_t{};
    init_dm_with_mac(grandchild_dm, 0x30, 0);
    em_network_topo_t* grandchild_topo = new em_network_topo_t(grandchild_dm);
    em_network_topo_t* grandchild_array[1] = { grandchild_topo };
    topo_root->add_network_topo(child_dm, grandchild_array, 1); // child + grandchild
    em_network_topo_t* result = topo_root->find_topology(grandchild_dm);
    EXPECT_NE(result, nullptr);
    EXPECT_EQ(result->get_data_model(), grandchild_dm);
    // Cleanup
    topo_root->remove(child_dm, nullptr, nullptr); // removes child and grandchild
    delete grandchild_topo;
    delete grandchild_dm;
    delete child_dm;
    delete topo_root;
    delete root_dm;
    std::cout << "Exiting find_topology_grandchild test" << std::endl;
}
/**
 * @brief Test to verify that find_topology returns nullptr when provided with an external device manager not present in the network topology.
 *
 * This test verifies that the find_topology API correctly returns a nullptr when the network topology (created via a root dm_easy_mesh_t instance with MAC 0x10) is searched with an external dm_easy_mesh_t instance initialized with a different MAC value (0x99). The objective is to ensure that the API does not erroneously find a match.
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
 * | Variation / Step | Description                                                                                 | Test Data                                                         | Expected Result                                                   | Notes          |
 * | :--------------: | ------------------------------------------------------------------------------------------- | ----------------------------------------------------------------- | ----------------------------------------------------------------- | -------------- |
 * | 01               | Initialize the root dm_easy_mesh_t instance and set its MAC to 0x10                          | root_dm = new dm_easy_mesh_t{}, init_dm_with_mac(root_dm, 0x10, 0)  | root_dm instance initialized successfully                         | Should be successful |
 * | 02               | Create an em_network_topo_t instance using the initialized root dm                           | topo_root created with root_dm pointer                            | Topology instance created successfully                            | Should be successful |
 * | 03               | Initialize the external dm_easy_mesh_t instance and set its MAC to 0x99                        | external_dm = new dm_easy_mesh_t{}, init_dm_with_mac(external_dm, 0x99, 0) | external_dm instance initialized successfully                       | Should be successful |
 * | 04               | Call find_topology API with the external_dm in the topology and check if it returns nullptr     | Call: topo_root.find_topology(external_dm)                         | Returns nullptr and assertion passes                                | Should Pass    |
 * | 05               | Deallocate the allocated dm_easy_mesh_t instances                                             | delete external_dm, delete root_dm                                  | Memory is freed successfully                                        | Should be successful |
 */
TEST(em_network_topo_t, find_topology_no_match) {
    std::cout << "Entering find_topology_no_match test" << std::endl;
    dm_easy_mesh_t* root_dm = new dm_easy_mesh_t{};
    init_dm_with_mac(root_dm, 0x10, 0);
    em_network_topo_t topo_root(root_dm);
    dm_easy_mesh_t* external_dm = new dm_easy_mesh_t{};
    init_dm_with_mac(external_dm, 0x99, 0);
    EXPECT_EQ(topo_root.find_topology(external_dm), nullptr);
    delete external_dm;
    delete root_dm;
    std::cout << "Exiting find_topology_no_match test" << std::endl;
}
/**
 * @brief Test to verify that the find_topology API correctly handles a null pointer.
 *
 * This test verifies that when a null pointer is passed to find_topology, the API returns a null pointer.
 * It ensures that the function safely handles null inputs without causing unexpected behavior.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 025@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:** 
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Create a dm_easy_mesh_t object and initialize it with a MAC value of 0x10 and channel 0 using init_dm_with_mac. | root_dm = new dm_easy_mesh_t{}, MAC = 0x10, channel = 0 | root_dm object is initialized successfully. | Should be successful |
 * | 02 | Create an em_network_topo_t object using the previously initialized root_dm. | Parameter: root_dm pointer | em_network_topo_t object is created successfully. | Should be successful |
 * | 03 | Invoke the find_topology function with a null pointer to test its handling of null inputs. | Function call: find_topology(nullptr) | The API returns a nullptr. | Should Pass |
 * | 04 | Clean up by deleting the root_dm object to free allocated memory. | Function call: delete root_dm | Memory is freed without issues. | Should be successful |
 */
TEST(em_network_topo_t, find_topology_null) {
    std::cout << "Entering find_topology_null test" << std::endl;
    dm_easy_mesh_t* root_dm = new dm_easy_mesh_t{};
    init_dm_with_mac(root_dm, 0x10, 0);
    em_network_topo_t topo_root(root_dm);
    EXPECT_EQ(topo_root.find_topology(nullptr), nullptr);
    delete root_dm;
    std::cout << "Exiting find_topology_null test" << std::endl;
}
/**
 * @brief Validate that find_topology_by_bh_associated returns the correct topology for a backhaul-associated STA in the root topology
 *
 * This test verifies that when a STA is correctly associated with a backhaul BSS in the root DM (Device Manager), the
 * API find_topology_by_bh_associated returns a pointer to the root topology. It ensures that the network topology search function
 * correctly identifies the association based on the provided STA MAC address.
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
 * | Variation / Step | Description                                                                                   | Test Data                                                                                                                         | Expected Result                                                                                                    | Notes        |
 * | :--------------: | --------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------ | ------------ |
 * | 01               | Initialize the device manager (DM) with a MAC and configure a single BSS with backhaul settings | root_dm pointer, init_dm_with_mac(root_dm, 0x10, 0), m_num_bss = 1, bssid = {0x02,0x10,0x00,0x00,0x00,0x01}, haul type = em_haul_type_backhaul | DM and BSS are set up correctly with the backhaul flag enabled                                                       | Should be successful |
 * | 02               | Create a STA, populate its MAC address and associate it with the BSS; insert STA into the STA map | sta pointer, sta_mac = {0x02,0x10,0x01,0x00,0x00,0x01}, associated bssid = {0x02,0x10,0x00,0x00,0x00,0x01}, sta_key generated via snprintf | STA is correctly inserted into the STA map                                                                           | Should be successful |
 * | 03               | Invoke find_topology_by_bh_associated using the STA MAC and verify it returns the correct topology  | Input: sta_mac = {0x02,0x10,0x01,0x00,0x00,0x01}; Output: pointer to topology (found)                                                | API returns topology pointer equal to the root topology instance (&topo_root) as verified by EXPECT_EQ                | Should Pass  |
 */
TEST(em_network_topo_t, find_topology_by_bh_associated_sta_in_root) {
    std::cout << "Entering find_topology_by_bh_associated_sta_in_root test" << std::endl;
    dm_easy_mesh_t* root_dm = new dm_easy_mesh_t();
    init_dm_with_mac(root_dm, 0x10, 0);
    root_dm->m_num_bss = 1;
    mac_address_t bssid = {0x02, 0x10, 0x00, 0x00, 0x00, 0x01};
    memcpy(root_dm->m_bss[0].m_bss_info.id.bssid, bssid, sizeof(mac_address_t));
    root_dm->m_bss[0].m_bss_info.id.haul_type = em_haul_type_backhaul;
    root_dm->m_sta_map = hash_map_create();
    dm_sta_t* sta = new dm_sta_t();
    mac_address_t sta_mac = {0x02, 0x10, 0x01, 0x00, 0x00, 0x01};
    memcpy(sta->m_sta_info.id, sta_mac, sizeof(mac_address_t));
    memcpy(sta->m_sta_info.bssid, bssid, sizeof(mac_address_t));
    char* sta_key = static_cast<char*>(malloc(18));
    snprintf(sta_key, 18, "%02X:%02X:%02X:%02X:%02X:%02X",
             sta_mac[0], sta_mac[1], sta_mac[2],
             sta_mac[3], sta_mac[4], sta_mac[5]);
    hash_map_put(root_dm->m_sta_map, sta_key, sta);
    em_network_topo_t topo_root(root_dm);
    em_network_topo_t* found = topo_root.find_topology_by_bh_associated(sta_mac);
    EXPECT_EQ(found, &topo_root);
    hash_map_remove(root_dm->m_sta_map, sta_key);
    delete sta;
    hash_map_destroy(root_dm->m_sta_map);
    delete root_dm;
    std::cout << "Exiting find_topology_by_bh_associated_sta_in_root test" << std::endl;
}
/**
 * @brief Verifies that the correct child topology is returned when searching by a station associated with a backhaul interface.
 *
 * This test initializes a root data model and a child data model with a backhaul BSS. A station is added 
 * to the child device model's station map. The API find_topology_by_bh_associated is then invoked with the 
 * station's MAC address, and the test asserts that the topology returned corresponds to the child device model.
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
 * | :--------------: | ----------- | --------- | --------------- | ----- |
 * | 01 | Initialize the root device model and create the network topology. | root_dm: new dm_easy_mesh_t with mac = 0x10, parameter = 0 | Root device model is successfully initialized. | Should be successful |
 * | 02 | Initialize the child device model, configure its BSS with a backhaul type, and add it to the root topology. | child_dm: new dm_easy_mesh_t with mac = 0x20, m_num_bss = 1, bssid = 02:20:00:00:00:01, haul_type = em_haul_type_backhaul | Child topology is added successfully to the root topology. | Should be successful |
 * | 03 | Add a station to the child device model's station map with the matching BSSID. | sta_mac = 02:20:01:00:00:01, associated bssid = 02:20:00:00:00:01 | Station is added to child_dm's station map. | Should be successful |
 * | 04 | Invoke find_topology_by_bh_associated with the station's MAC address and verify the returned topology. | input: sta_mac = 02:20:01:00:00:01, output: found topology pointer | API returns a topology whose data model equals child_dm. | Should Pass |
 * | 05 | Cleanup all allocated resources. | Cleanup of all pointers (root_dm, child_dm, topo_root, sta) | All resources are freed without memory leak. | Should be successful |
 */
TEST(em_network_topo_t, find_topology_by_bh_associated_sta_in_child) {
    std::cout << "Entering find_topology_by_bh_associated_sta_in_child test" << std::endl;
    dm_easy_mesh_t* root_dm = new dm_easy_mesh_t();
    init_dm_with_mac(root_dm, 0x10, 0);
    em_network_topo_t* topo_root = new em_network_topo_t(root_dm);
    dm_easy_mesh_t* child_dm = new dm_easy_mesh_t();
    init_dm_with_mac(child_dm, 0x20, 0);
    topo_root->add_network_topo(child_dm,nullptr,0);
    child_dm->m_num_bss = 1;
    mac_address_t bssid = {0x02, 0x20, 0x00, 0x00, 0x00, 0x01};
    memcpy(child_dm->m_bss[0].m_bss_info.id.bssid, bssid, sizeof(mac_address_t));
    child_dm->m_bss[0].m_bss_info.id.haul_type = em_haul_type_backhaul;
    child_dm->m_sta_map = hash_map_create();
    dm_sta_t* sta = new dm_sta_t();
    mac_address_t sta_mac = {0x02, 0x20, 0x01, 0x00, 0x00, 0x01};
    memcpy(sta->m_sta_info.id, sta_mac, sizeof(mac_address_t));
    memcpy(sta->m_sta_info.bssid, bssid, sizeof(mac_address_t));
    char* sta_key = static_cast<char*>(malloc(18));
    snprintf(sta_key, 18, "%02X:%02X:%02X:%02X:%02X:%02X",
             sta_mac[0], sta_mac[1], sta_mac[2],
             sta_mac[3], sta_mac[4], sta_mac[5]);
    hash_map_put(child_dm->m_sta_map, sta_key, sta);
    em_network_topo_t* found = topo_root->find_topology_by_bh_associated(sta_mac);
    EXPECT_EQ(found->get_data_model(), child_dm);
    // Cleanup
    hash_map_remove(child_dm->m_sta_map, sta_key);
    delete sta;
    hash_map_destroy(child_dm->m_sta_map);
    topo_root->remove(child_dm, nullptr, nullptr);
    delete child_dm;
    delete topo_root;
    delete root_dm;
    std::cout << "Exiting find_topology_by_bh_associated_sta_in_child test" << std::endl;
}
/**
 * @brief Validate that find_topology_by_bh_associated correctly returns the grandchild topology when a station associated with backhaul is added in the grandchild node.
 *
 * This test creates a network topology with a root, child, and grandchild node. The grandchild node is configured with backhaul BSS information.
 * A station with a matching backhaul association is added to the grandchild node. The test then invokes find_topology_by_bh_associated using the station MAC address
 * and verifies that the returned topology corresponds to the grandchild node.
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
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize root data model using init_dm_with_mac with parameters (root_dm, 0x10, 0). | root_dm pointer, value=0x10, index=0 | Root data model is initialized successfully | Should be successful |
 * | 02 | Create root network topology and associate it with the root data model. | topo_root pointer, root_dm instance | Root network topology is created successfully | Should be successful |
 * | 03 | Initialize child data model and update its number of BSS. | child_dm pointer, value=0x20, m_num_bss=1 | Child data model is initialized and configured with one BSS | Should be successful |
 * | 04 | Initialize grandchild data model with BSS info for backhaul association. | grandchild_dm pointer, value=0x30, m_num_bss=1, BSSID, haul_type=em_haul_type_backhaul | Grandchild data model is initialized with backhaul details | Should be successful |
 * | 05 | Add child and grandchild topologies to the root network topology. | child_dm, grandchildren array containing grandchild_topo, count=1 | Network topology correctly links child and grandchild nodes | Should be successful |
 * | 06 | Create a station and add it to the grandchild node's station map with matching BSSID. | sta pointer, sta_mac, bssid, sta_key (formatted MAC string) | Station is successfully added to the grandchild station map | Should Pass |
 * | 07 | Invoke find_topology_by_bh_associated using the station MAC address and validate the returned topology. | Input: sta_mac, Expected output: grandchild_dm associated topology | API returns topology containing grandchild data model; EXPECT_EQ check passes | Should Pass |
 * | 08 | Cleanup all allocated resources. | Pointers: root_dm, child_dm, grandchild_dm, topo_root, grandchild_topo, sta, sta_key; hash_map resources | All resources are deallocated without memory leaks | Should be successful |
 */
TEST(em_network_topo_t, find_topology_by_bh_associated_sta_in_grandchild) {
    std::cout << "Entering find_topology_by_bh_associated_sta_in_grandchild test" << std::endl;
    dm_easy_mesh_t* root_dm = new dm_easy_mesh_t();
    init_dm_with_mac(root_dm, 0x10, 0);
    em_network_topo_t* topo_root = new em_network_topo_t(root_dm);
    dm_easy_mesh_t* child_dm = new dm_easy_mesh_t();
    init_dm_with_mac(child_dm, 0x20, 0);
    child_dm->m_num_bss = 1;
    dm_easy_mesh_t* grandchild_dm = new dm_easy_mesh_t();
    init_dm_with_mac(grandchild_dm, 0x30, 0);
    grandchild_dm->m_num_bss = 1;
    em_network_topo_t* grandchild_topo = new em_network_topo_t(grandchild_dm);
    em_network_topo_t* grandchildren[1] = { grandchild_topo };
    topo_root->add_network_topo(child_dm, grandchildren, 1);
    grandchild_dm->m_sta_map = hash_map_create();
    dm_sta_t* sta = new dm_sta_t();
    mac_address_t bssid = {0x02, 0x30, 0x00, 0x00, 0x00, 0x01};
    memcpy(grandchild_dm->m_bss[0].m_bss_info.id.bssid, bssid, sizeof(mac_address_t));
    grandchild_dm->m_bss[0].m_bss_info.id.haul_type = em_haul_type_backhaul;
    mac_address_t sta_mac = {0x02, 0x30, 0x00, 0x00, 0x00, 0x01};
    memcpy(sta->m_sta_info.id, sta_mac, sizeof(mac_address_t));
    memcpy(sta->m_sta_info.bssid, bssid, sizeof(mac_address_t));
    char* sta_key = static_cast<char*>(malloc(18));
    snprintf(sta_key, 18, "%02X:%02X:%02X:%02X:%02X:%02X",
             sta_mac[0], sta_mac[1], sta_mac[2],
             sta_mac[3], sta_mac[4], sta_mac[5]);
    hash_map_put(grandchild_dm->m_sta_map, sta_key, sta);
    em_network_topo_t* found = topo_root->find_topology_by_bh_associated(sta_mac);
    EXPECT_EQ(found->get_data_model(), grandchild_dm);
    // Cleanup
    hash_map_remove(grandchild_dm->m_sta_map, sta_key);
    delete sta;
    hash_map_destroy(grandchild_dm->m_sta_map);
    topo_root->remove(child_dm, nullptr, nullptr); // removes child and grandchild
    delete grandchild_topo;
    delete grandchild_dm;
    delete child_dm;
    delete topo_root;
    delete root_dm;
    std::cout << "Exiting find_topology_by_bh_associated_sta_in_grandchild test" << std::endl;
}
/**
 * @brief Verifies that find_topology_by_bh_associated returns nullptr when the backhaul associated station is not found.
 *
 * This test creates a network topology from a dm_easy_mesh_t instance initialized with a specific MAC and index.
 * An unknown station MAC address (FF:FF:FF:FF:FF:FF) is then used to invoke the find_topology_by_bh_associated method.
 * The test asserts that the method returns a nullptr, indicating that no matching backhaul association exists in the topology.
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
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize dm_easy_mesh_t with defined MAC and index | root_dm: new dm_easy_mesh_t(), MAC = 0x10, index = 0 | dm_easy_mesh_t instance is successfully created | Should be successful |
 * | 02 | Construct network topology using the created dm_easy_mesh_t instance | Input: root_dm pointer to em_network_topo_t constructor | em_network_topo_t instance is successfully created | Should be successful |
 * | 03 | Define an unknown station MAC address | unknown_sta_mac = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF} | An unknown MAC address is defined | Should be successful |
 * | 04 | Invoke find_topology_by_bh_associated with the unknown station MAC | Input: unknown_sta_mac = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, Output: found pointer expected as nullptr | API returns nullptr and ASSERT_EQ validates the result | Should Pass |
 * | 05 | Clean up allocated resources | delete root_dm | Memory is properly freed | Should be successful |
 */
TEST(em_network_topo_t, find_topology_by_bh_associated_sta_not_found) {
    std::cout << "Entering find_topology_by_bh_associated_sta_not_found test" << std::endl;
    dm_easy_mesh_t* root_dm = new dm_easy_mesh_t();
    init_dm_with_mac(root_dm, 0x10, 0);
    em_network_topo_t topo_root(root_dm);
    mac_address_t unknown_sta_mac = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    em_network_topo_t* found = topo_root.find_topology_by_bh_associated(unknown_sta_mac);
    ASSERT_EQ(found, nullptr);
    delete root_dm;
    std::cout << "Exiting find_topology_by_bh_associated_STA_not_found test" << std::endl;
}
/**
 * @brief Test the behavior of find_topology_by_bh_associated when a non-existent station MAC is provided.
 *
 * This test verifies that the find_topology_by_bh_associated API correctly returns a nullptr when invoked with a MAC address that is not associated with any branch in the network topology. The test initializes a dm_easy_mesh_t object with a specified MAC address, creates an em_network_topo_t root topology with this object, and then queries the topology for a MAC address that does not exist. The expected behavior is that the API returns nullptr.
 *
 * **Test Group ID:** Basic: 01@n
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
 * | 01 | Initialize dm_easy_mesh_t with MAC address value 0x10 and a secondary parameter 0 | input: root_dm pointer (new dm_easy_mesh_t), init values: mac = 0x10, secondary = 0 | dm_easy_mesh_t instance is successfully initialized | Should be successful |
 * | 02 | Create an instance of em_network_topo_t using the initialized dm_easy_mesh_t object | input: topo_root (constructed with root_dm) | em_network_topo_t object is successfully created | Should be successful |
 * | 03 | Define a mac_address_t variable representing a MAC address that is not part of the network topology | input: missing_sta_mac = {0x02, 0x99, 0x99, 0x99, 0x99, 0x99} | MAC address variable is correctly defined and does not match any entry in the topology | Should be successful |
 * | 04 | Invoke find_topology_by_bh_associated with the non-existent MAC address | input: calling find_topology_by_bh_associated(missing_sta_mac) on topo_root | API returns a nullptr indicating that the MAC address is not found in the topology | Should Pass |
 * | 05 | Verify the API result by asserting that the returned pointer is nullptr | input: found pointer returned from API, expected value: nullptr | ASSERT_EQ confirms that found is nullptr | Should Pass |
 */
TEST(em_network_topo_t, find_topology_by_bh_associated_empty_root) {
    std::cout << "Entering find_topology_by_bh_associated_empty_root test" << std::endl;
    dm_easy_mesh_t* root_dm = new dm_easy_mesh_t();
    init_dm_with_mac(root_dm, 0x10, 0);
    em_network_topo_t topo_root(root_dm);
    mac_address_t missing_sta_mac = {0x02, 0x99, 0x99, 0x99, 0x99, 0x99};
    em_network_topo_t* found = topo_root.find_topology_by_bh_associated(missing_sta_mac);
    ASSERT_EQ(found, nullptr);
    delete root_dm;
    std::cout << "Exiting find_topology_by_bh_associated_empty_root test" << std::endl;
}
/**
 * @brief Validate that find_topology_by_bh_associated returns the correct topology
 *
 * This test verifies that when a network topology is created from a root network device
 * with properly configured radio, BSS, and station information, the method find_topology_by_bh_associated
 * correctly identifies and returns the network topology associated with the provided backhaul device.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 031@n
 * **Priority:** High@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * 
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :--------------: | ----------- | --------- | --------------- | ----- |
 * | 01 | Initialize the root network device by invoking init_dm_with_mac with specific MAC parameters | Input: root_dm pointer, 0x10, 0 | The root network device (root_dm) is initialized with the correct MAC address | Should be successful |
 * | 02 | Configure radio and BSS parameters for the root device including enabling radio and BSS, setting MAC addresses, BSSID, haul type, and VAP mode | Input: root_dm fields: m_num_radios = 1, m_radio[0].enabled = true, radio_mac = {0x02, 0x10, 0x00, 0x00, 0x00, 0x00}; m_num_bss = 1, m_bss[0].enabled = true, BSSID = {0x02, 0x10, 0x00, 0x00, 0x00, 0x01}, haul_type = em_haul_type_backhaul, vap_mode = em_vap_mode_sta | The radio and BSS configurations are correctly applied to root_dm | Should be successful |
 * | 03 | Insert station (STA) information into the station map using hash_map_create and hash_map_put | Input: Created dm_sta_t with sta_mac = {0x02, 0x10, 0x01, 0x00, 0x00, 0x01}, corresponding key generated from the sta_mac | The station is successfully added to the sta_map | Should be successful |
 * | 04 | Create the network topology object and invoke find_topology_by_bh_associated to retrieve the associated topology | Input: em_network_topo_t pointer created using root_dm, then call find_topology_by_bh_associated(root_dm) | The method returns the topology object equal to the one created (topo_root) and the EXPECT_EQ assertion passes | Should Pass |
 * | 05 | Clean up all allocated resources including removing STA from the map, freeing memory, and deleting objects | Input: Removal via hash_map_remove, deletion of sta, destruction of sta_map, deletion of root_dm and topo_root | All resources are cleaned up without memory leaks or errors | Should be successful |
 */
TEST(em_network_topo_t, find_topology_by_bh_associated_root) {
    std::cout << "Entering find_topology_by_bh_associated_root test" << std::endl;
    dm_easy_mesh_t* root_dm = new dm_easy_mesh_t();
    init_dm_with_mac(root_dm, 0x10, 0);
    root_dm->m_num_radios = 1;
    root_dm->m_radio[0].m_radio_info.enabled = true;
    unsigned char radio_mac[6] = {0x02, 0x10, 0x00, 0x00, 0x00, 0x00};
    memcpy(root_dm->m_radio[0].m_radio_info.intf.mac, radio_mac, 6);
    root_dm->m_num_bss = 1;
    root_dm->m_bss[0].m_bss_info.enabled = true;
    mac_address_t bssid = {0x02, 0x10, 0x00, 0x00, 0x00, 0x01};
    memcpy(root_dm->m_bss[0].m_bss_info.id.bssid, bssid, sizeof(mac_address_t));
    root_dm->m_bss[0].m_bss_info.id.haul_type = em_haul_type_backhaul;
    memcpy(root_dm->m_bss[0].m_bss_info.ruid.mac, radio_mac, 6);
    memcpy(root_dm->m_bss[0].m_bss_info.bssid.mac, bssid, 6);
    root_dm->m_bss[0].m_bss_info.vap_mode = em_vap_mode_sta;
    root_dm->m_sta_map = hash_map_create();
    dm_sta_t* sta = new dm_sta_t();
    mac_address_t sta_mac = {0x02, 0x10, 0x01, 0x00, 0x00, 0x01};
    memcpy(sta->m_sta_info.id, sta_mac, sizeof(mac_address_t));
    memcpy(sta->m_sta_info.bssid, bssid, sizeof(mac_address_t));
    char* sta_key = static_cast<char*>(malloc(18));
    snprintf(sta_key, 18, "%02X:%02X:%02X:%02X:%02X:%02X",
             sta_mac[0], sta_mac[1], sta_mac[2],
             sta_mac[3], sta_mac[4], sta_mac[5]);
    hash_map_put(root_dm->m_sta_map, sta_key, sta);

    em_network_topo_t* topo_root = new em_network_topo_t(root_dm);
    g_network_topology = topo_root;
    em_network_topo_t* found = topo_root->find_topology_by_bh_associated(root_dm);
    EXPECT_EQ(found, topo_root);
    hash_map_remove(root_dm->m_sta_map, sta_key);
    delete sta;
    hash_map_destroy(root_dm->m_sta_map);
    delete root_dm;
    delete topo_root;
    std::cout << "Exiting find_topology_by_bh_associated_root test" << std::endl;
}
/**
 * @brief Test find_topology_by_bh_associated with a null dm pointer
 *
 * This test verifies that when a null dm pointer is provided to the find_topology_by_bh_associated API,
 * the function correctly returns a null topology pointer. This behavior is critical to ensure that the API
 * gracefully handles invalid or absent input data without causing undefined behavior.
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
 * | 01 | Initialize dm pointer to nullptr and invoke find_topology_by_bh_associated API | input: dm = nullptr, output: expected found = nullptr | API returns a null pointer and ASSERT_EQ confirms that found is nullptr | Should Pass |
 */
TEST(em_network_topo_t, find_topology_by_bh_associated_null_dm) {
    std::cout << "Entering find_topology_by_bh_associated_null_dm test" << std::endl;
    dm_easy_mesh_t* dm = nullptr;
    em_network_topo_t* found = g_network_topology->find_topology_by_bh_associated(dm);
    ASSERT_EQ(found, nullptr);
    std::cout << "Exiting find_topology_by_bh_associated_null_dm test" << std::endl;
}
/**
 * @brief Test to verify that find_topology_by_bh_associated returns nullptr when there are no BSS available.
 *
 * This test verifies that when a dm_easy_mesh_t instance is initialized with a valid MAC address and the number of BSS is set to 0, 
 * indicating no backhaul, the function find_topology_by_bh_associated correctly returns a nullptr. 
 * It checks the behavior of em_network_topo_t in handling a case with no BSS to ensure robustness in topology discovery.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 033@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                                                         | Test Data                                                                          | Expected Result                                                                      | Notes       |
 * | :--------------: | ------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------ | ----------- |
 * | 01               | Instantiate dm_easy_mesh_t, initialize it with init_dm_with_mac using 0x40 and 0, set m_num_bss to 0 to simulate no BSS, then instantiate em_network_topo_t and invoke find_topology_by_bh_associated. | dm_easy_mesh_t: init_dm_with_mac(dm, 0x40, 0), dm->m_num_bss = 0; em_network_topo_t created; API call: topo->find_topology_by_bh_associated(dm) | The function returns nullptr, and ASSERT_EQ confirms that the returned pointer is nullptr. | Should Pass |
 */
TEST(em_network_topo_t, find_topology_by_bh_associated_dm_no_bss) {
    std::cout << "Entering find_topology_by_bh_associated_dm_no_bss test" << std::endl;
    dm_easy_mesh_t* dm = new dm_easy_mesh_t();
    init_dm_with_mac(dm, 0x40, 0);
    // No BSS, will cause backhaul to be zero
    dm->m_num_bss = 0;
    em_network_topo_t* topo = new em_network_topo_t(dm);
    g_network_topology = topo;
    em_network_topo_t* found = topo->find_topology_by_bh_associated(dm);
    ASSERT_EQ(found, nullptr);
    delete topo;
    delete dm;
    std::cout << "Exiting find_topology_by_bh_associated_dm_no_bss test" << std::endl;
}
/**
 * @brief Test to verify that the topology can be correctly located using a valid BSS MAC when a single child exists
 *
 * This test creates a root data model and a child data model, initializes them with specific MAC addresses, assigns a valid BSS MAC 
 * to the child's BSS information, and then adds the child to the network topology. The test then queries the topology using the valid BSS MAC to confirm 
 * that the correct child topology is returned. This ensures that the API correctly finds the intended topology node based on BSS MAC address.
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
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Create root data model and network topology objects. | root_dm = new dm_easy_mesh_t{}, topo_root = new em_network_topo_t(root_dm) | Objects are created successfully. | Should be successful |
 * | 02 | Initialize the root data model with a MAC value (0x10). | input: (dm_easy_mesh_t* root_dm, mac = 0x10, index = 0) | Root data model is initialized with the specified MAC. | Should be successful |
 * | 03 | Create and initialize child data model with a MAC value (0x20). | input: (dm_easy_mesh_t* child_dm, mac = 0x20, index = 0) | Child data model is initialized successfully. | Should be successful |
 * | 04 | Set up valid BSS MAC and assign it to the child's BSS information. | input: validBssMac = {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF}, child_dm->m_num_bss = 1, copying validBssMac to child_dm->m_bss[0].m_bss_info.bssid.mac | Child's BSS MAC is set correctly. | Should be successful |
 * | 05 | Add the child topology to the root topology. | input: (child_dm pointer, parent = nullptr, index = 0) | Child topology is added to the network successfully. | Should Pass |
 * | 06 | Invoke find_topology_by_bss_mac using the valid BSS MAC and verify that the returned topology corresponds to the child data model. | input: validBssMac array; output: result (em_network_topo_t*) | result->get_data_model() equals child_dm, confirming the correct topology is found. | Should Pass |
 * | 07 | Remove the child topology from the root topology and perform cleanup. | input: (child_dm pointer via topo_root->remove, followed by deletion of child_dm, root_dm, and topo_root) | All objects are removed and memory is freed without issues. | Should be successful |
 */
TEST(em_network_topo_t, find_topology_by_bss_mac_single_child) {
    std::cout << "Entering find_topology_by_bss_mac_single_child test" << std::endl;
    dm_easy_mesh_t* root_dm = new dm_easy_mesh_t{};
    em_network_topo_t* topo_root = new em_network_topo_t(root_dm);
    init_dm_with_mac(root_dm, 0x10, 0);
    dm_easy_mesh_t* child_dm = new dm_easy_mesh_t{};
    init_dm_with_mac(child_dm, 0x20, 0);
    unsigned char validBssMac[6] = {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF};
    child_dm->m_num_bss = 1;
    memcpy(child_dm->m_bss[0].m_bss_info.bssid.mac, validBssMac, sizeof(validBssMac));
    topo_root->add_network_topo(child_dm, nullptr, 0);
    em_network_topo_t* result = topo_root->find_topology_by_bss_mac(validBssMac);
    EXPECT_EQ(result->get_data_model(), child_dm);
    topo_root->remove(child_dm, nullptr, nullptr);
    delete child_dm;
    delete root_dm;
    delete topo_root;
    std::cout << "Exiting find_topology_by_bss_mac_single_child test" << std::endl;
}
/**
 * @brief Verify that find_topology_by_bss_mac returns the correct topology for multiple child networks.
 *
 * This test verifies that when two child nodes with distinct BSS MAC addresses are added into the topology, 
 * the API find_topology_by_bss_mac returns the correct topology entry corresponding to the provided MAC addresses.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 035
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :--------------: | ----------- | --------- | ------------- | ----- |
 * | 01 | Create root data model and topology root | root_dm = new dm_easy_mesh_t{}, topo_root = new em_network_topo_t(root_dm) | Root topology created successfully | Should be successful |
 * | 02 | Initialize root data model with MAC address | input: root_dm, mac=0x10, index=0 | Root dm initialized with MAC | Should be successful |
 * | 03 | Create two child nodes | child1 = new dm_easy_mesh_t{}, child2 = new dm_easy_mesh_t{} | Child nodes created successfully | Should be successful |
 * | 04 | Set BSS MAC for each child node | child1->m_bss[0].m_bss_info.bssid.mac = {0xAA,0x11,0x22,0x33,0x44,0x55}, child2->m_bss[0].m_bss_info.bssid.mac = {0xBB,0x66,0x77,0x88,0x99,0x00} | BSS MACs assigned to each child node | Should be successful |
 * | 05 | Add child nodes to topology | call: topo_root->add_network_topo(child1, nullptr, 0) and topo_root->add_network_topo(child2, nullptr, 0) | Child nodes added to topology | Should be successful |
 * | 06 | Invoke find_topology_by_bss_mac for first child | input: mac1 = {0xAA,0x11,0x22,0x33,0x44,0x55} | Returns topology node corresponding to child1 | Should Pass |
 * | 07 | Invoke find_topology_by_bss_mac for second child | input: mac2 = {0xBB,0x66,0x77,0x88,0x99,0x00} | Returns topology node corresponding to child2 | Should Pass |
 * | 08 | Validate the returned topology data model pointers | input: res1->get_data_model() vs child1, res2->get_data_model() vs child2 | EXPECT_EQ passes verifying correct mapping | Should Pass |
 * | 09 | Remove child nodes from topology | call: topo_root->remove(child1, nullptr, nullptr) and topo_root->remove(child2, nullptr, nullptr) | Child nodes successfully removed from topology | Should be successful |
 * | 10 | Clean up allocated resources | delete child1, delete child2, delete root_dm, delete topo_root | All resources freed with no memory leaks | Should be successful |
 */
TEST(em_network_topo_t, find_topology_by_bss_mac_multiple_children) {
    std::cout << "Entering find_topology_by_bss_mac_multiple_child test" << std::endl;
    dm_easy_mesh_t* root_dm = new dm_easy_mesh_t{};
    em_network_topo_t* topo_root = new em_network_topo_t(root_dm);
    init_dm_with_mac(root_dm, 0x10, 0);
    dm_easy_mesh_t* child1 = new dm_easy_mesh_t{};
    dm_easy_mesh_t* child2 = new dm_easy_mesh_t{};
    unsigned char mac1[6] = {0xAA,0x11,0x22,0x33,0x44,0x55};
    unsigned char mac2[6] = {0xBB,0x66,0x77,0x88,0x99,0x00};
    child1->m_num_bss = 1;
    memcpy(child1->m_bss[0].m_bss_info.bssid.mac, mac1, sizeof(mac1));
    child2->m_num_bss = 1;
    memcpy(child2->m_bss[0].m_bss_info.bssid.mac, mac2, sizeof(mac2));
    topo_root->add_network_topo(child1, nullptr, 0);
    topo_root->add_network_topo(child2, nullptr, 0);
    em_network_topo_t* res1 = topo_root->find_topology_by_bss_mac(mac1);
    em_network_topo_t* res2 = topo_root->find_topology_by_bss_mac(mac2);
    EXPECT_EQ(res1->get_data_model(), child1);
    EXPECT_EQ(res2->get_data_model(), child2);
    topo_root->remove(child1, nullptr, nullptr);
    topo_root->remove(child2, nullptr, nullptr);
    delete child1;
    delete child2;
    delete root_dm;
    delete topo_root;
    std::cout << "Exiting find_topology_by_bss_mac_multiple_child test" << std::endl;
}
/**
 * @brief Verify that find_topology_by_bss_mac returns the correct topology for both child and grandchild nodes.
 *
 * This test verifies that the em_network_topo_t API's find_topology_by_bss_mac method correctly identifies and returns the topology associated with a given BSS MAC address. It tests both a direct child and a grandchild node in the network topology hierarchy to ensure nested lookup functionality works as expected.
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
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Invoke find_topology_by_bss_mac with child MAC to retrieve the child's topology | input: bss_mac = {0xAA,0x11,0x11,0x11,0x11,0x11}; output: topology->data_model should be child pointer | Returns topology whose data model matches the child object | Should Pass |
 * | 02 | Invoke find_topology_by_bss_mac with grandchild MAC to retrieve the grandchild's topology | input: bss_mac = {0xBB,0x22,0x22,0x22,0x22,0x22}; output: topology->data_model should be grandchild pointer | Returns topology whose data model matches the grandchild object | Should Pass |
 */
TEST(em_network_topo_t, find_topology_by_bss_mac_grandchild) {
    std::cout << "Entering find_topology_by_bss_mac_grandchild test" << std::endl;
    dm_easy_mesh_t* root_dm = new dm_easy_mesh_t{};
    em_network_topo_t* topo_root = new em_network_topo_t(root_dm);
    dm_easy_mesh_t* child = new dm_easy_mesh_t{};
    unsigned char child_mac[6] = {0xAA,0x11,0x11,0x11,0x11,0x11};
    child->m_num_bss = 1;
    memcpy(child->m_bss[0].m_bss_info.bssid.mac, child_mac, sizeof(child_mac));
    dm_easy_mesh_t* grandchild = new dm_easy_mesh_t{};
    unsigned char grandchild_mac[6] = {0xBB,0x22,0x22,0x22,0x22,0x22};
    grandchild->m_num_bss = 1;
    memcpy(grandchild->m_bss[0].m_bss_info.bssid.mac, grandchild_mac, sizeof(grandchild_mac));
    em_network_topo_t* grandchild_topo = new em_network_topo_t(grandchild);
    em_network_topo_t* grandchild_array[1] = { grandchild_topo };
    topo_root->add_network_topo(child, grandchild_array, 1);
    em_network_topo_t* child_topo = topo_root->find_topology_by_bss_mac(child_mac);
    EXPECT_EQ(child_topo->get_data_model(), child);
    em_network_topo_t* res = topo_root->find_topology_by_bss_mac(grandchild_mac);
    EXPECT_EQ(res->get_data_model(), grandchild);
    // Cleanup
    topo_root->remove(child, nullptr, nullptr); // removes child + grandchild
    delete grandchild_topo;
    delete grandchild;
    delete child;
    delete topo_root;
    delete root_dm;
    std::cout << "Exiting find_topology_by_bss_mac_grandchild test" << std::endl;
}
/**
 * @brief Verifies that find_topology_by_bss_mac returns a nullptr for a non-existent BSS MAC address.
 *
 * This test ensures that the API find_topology_by_bss_mac correctly handles cases where the specified BSS MAC address does not exist in the network topology. A network topology is created with a single child node having a predefined MAC address. The function is then invoked with a fake MAC address, and the return value is checked to confirm that it is nullptr.
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
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Create network topology with a single child node having a valid BSS MAC address | root_dm = new dm_easy_mesh_t{}, child = new dm_easy_mesh_t{}, child_mac = {0xAA,0xBB,0xCC,0x00,0x00,0x01} | Topology is created with one node that contains the specified valid MAC address | Should be successful |
 * | 02 | Invoke find_topology_by_bss_mac with a non-existent (fake) MAC address | fake_mac = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF} | Function returns nullptr and assertion check passes | Should Pass |
 * | 03 | Clean up allocated network topology resources | Remove the child from topology, delete child, root_dm, and topo_root | All allocated resources are correctly deallocated without error | Should be successful |
 */
TEST(em_network_topo_t, find_topology_by_bss_mac_not_present) {
    std::cout << "Entering find_topology_by_bss_mac_not_present test" << std::endl;
    dm_easy_mesh_t* root_dm = new dm_easy_mesh_t{};
    em_network_topo_t* topo_root = new em_network_topo_t(root_dm);
    dm_easy_mesh_t* child = new dm_easy_mesh_t{};
    child->m_num_bss = 1;
    unsigned char child_mac[6] = {0xAA,0xBB,0xCC,0x00,0x00,0x01};
    memcpy(child->m_bss[0].m_bss_info.bssid.mac, child_mac, sizeof(child_mac));
    topo_root->add_network_topo(child, nullptr, 0);
    unsigned char fake_mac[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
    em_network_topo_t* res = topo_root->find_topology_by_bss_mac(fake_mac);
    ASSERT_EQ(res, nullptr);
    topo_root->remove(child, nullptr, nullptr);
    delete child;
    delete root_dm;
    delete topo_root;
    std::cout << "Exiting find_topology_by_bss_mac_not_present test" << std::endl;
}
/**
 * @brief This test verifies that calling find_topology_by_bss_mac on an empty topology returns nullptr.
 *
 * This test checks the API behavior when the topology is empty. It validates that the method find_topology_by_bss_mac returns a nullptr, confirming that no topology matches the given BSS MAC address.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 038@n
 * **Priority:** High@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * 
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result |Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize an empty topology and call find_topology_by_bss_mac with a specific MAC address | input: some_mac = {0x11,0x22,0x33,0x44,0x55,0x66}, object: topo_root instantiated with empty dm_easy_mesh_t instance; output: res from API call | API returns nullptr; Assertion check passes confirming res is nullptr | Should Pass |
 */
TEST(em_network_topo_t, find_topology_by_bss_mac_empty_topology) {
    std::cout << "Exiting find_topology_by_bss_mac_empty_topology test" << std::endl;
    dm_easy_mesh_t* root_dm = new dm_easy_mesh_t{};
    em_network_topo_t* topo_root = new em_network_topo_t(root_dm);
    unsigned char some_mac[6] = {0x11,0x22,0x33,0x44,0x55,0x66};
    em_network_topo_t* res = topo_root->find_topology_by_bss_mac(some_mac);
    ASSERT_EQ(res, nullptr);
    delete root_dm;
    delete topo_root;
    std::cout << "Exiting find_topology_by_bss_mac_empty_topology test" << std::endl;
}
/**
 * @brief Verify that get_data_model returns the correct pointer to the data model.
 *
 * This test validates that the em_network_topo_t::get_data_model API returns the same valid dm_easy_mesh_t pointer that was provided during the construction of the em_network_topo_t instance. It ensures that the internal reference to the data model is correctly maintained.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 039
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Create a dm_easy_mesh_t instance and initialize em_network_topo_t with it | root_dm = new dm_easy_mesh_t{}, topo_root = new em_network_topo_t(root_dm) | Both instances are created successfully | Should be successful |
 * | 02 | Invoke get_data_model() on topo_root to retrieve the data model pointer | Call: returned_dm = topo_root->get_data_model() | returned_dm is equal to root_dm, passing the EXPECT_EQ comparison | Should Pass |
 * | 03 | Delete the created instances to free memory | Call: delete topo_root, delete root_dm | Memory is freed without error | Should be successful |
 */
TEST(em_network_topo_t, get_data_model_valid_pointer) {
    std::cout << "Entering get_data_model_valid_pointer test" << std::endl;
    dm_easy_mesh_t* root_dm = new dm_easy_mesh_t{};
    em_network_topo_t* topo_root = new em_network_topo_t(root_dm);
    dm_easy_mesh_t* returned_dm = topo_root->get_data_model();
    EXPECT_EQ(returned_dm, root_dm);
    delete topo_root;
    delete root_dm;
    std::cout << "Exiting get_data_model_valid_pointer test" << std::endl;
}
/**
 * @brief Verify that the topology API correctly handles a null data model pointer.
 *
 * This test creates a topology instance using a null data model pointer and then calls the get_data_model method to ensure it returns a null pointer. The objective is to ensure that the API gracefully handles null inputs without causing unexpected behavior.
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
 * | 01 | Initialize a null data model pointer and create a topology instance with it. | Input: null_dm = nullptr, Constructor input: dm_easy_mesh_t* = nullptr | Topology instance created with a null data model. | Should be successful |
 * | 02 | Invoke get_data_model() method and assert that the returned value is null. | Call: returned_dm = topo.get_data_model(), Expected output: returned_dm = nullptr | The API returns nullptr, satisfying the assertion (ASSERT_EQ returns true). | Should Pass |
 */
TEST(em_network_topo_t, get_data_model_null_pointer) {
    std::cout << "Entering get_data_model_null_pointer test" << std::endl;
    dm_easy_mesh_t* null_dm = nullptr;
    em_network_topo_t topo(null_dm);
    dm_easy_mesh_t* returned_dm = topo.get_data_model();
    ASSERT_EQ(returned_dm, nullptr);
    std::cout << "Exiting get_data_model_null_pointer test" << std::endl;
}
/**
 * @brief Verify that the default constructor of em_network_topo_t sets the data model pointer to nullptr
 *
 * This test case validates that when an instance of em_network_topo_t is created using the default constructor, the associated data model pointer is not allocated and remains a nullptr. This behavior ensures that no unintended memory allocation occurs during object initialization.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 041@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                 | Test Data                                            | Expected Result                                                         | Notes         |
 * | :--------------: | --------------------------------------------------------------------------- | ---------------------------------------------------- | ----------------------------------------------------------------------- | ------------- |
 * | 01               | Instantiate an object of em_network_topo_t using the default constructor      | No input arguments                                   | Object should be created successfully                                   | Should be successful |
 * | 02               | Invoke get_data_model() on the created object                                 | input: em_network_topo_t object, output: data model pointer | Returned data model pointer should be nullptr                           | Should Pass   |
 * | 03               | Validate the returned data model pointer using ASSERT_EQ                      | output: returned_dm = nullptr                        | Assertion passes confirming that returned_dm equals nullptr             | Should Pass   |
 * | 04               | Print exit message indicating the end of the test                            | output: "Exiting get_data_model_default_constructor test" | Correct exit message printed                                             | Should be successful |
 */
TEST(em_network_topo_t, get_data_model_default_constructor) {
    std::cout << "Entering get_data_model_default_constructor test" << std::endl;
    em_network_topo_t topo;
    dm_easy_mesh_t* returned_dm = topo.get_data_model();
    ASSERT_EQ(returned_dm, nullptr);
    std::cout << "Exiting get_data_model_default_constructor test" << std::endl;
}
/**
 * @brief Validates that the print_topology API successfully prints a valid topology.
 *
 * This test creates a dm_easy_mesh_t instance and initializes it with a specific MAC (0x10, 0),
 * then creates an em_network_topo_t topology object using this instance. It calls the print_topology
 * function and verifies that no exceptions are thrown during its execution, ensuring the valid topology
 * is printed without error.
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
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize dm_easy_mesh_t instance and set MAC using init_dm_with_mac | root_dm pointer, init_dm_with_mac(root_dm, 0x10, 0) | dm_easy_mesh_t initialized with MAC: 02:10:00:00:00:00 | Should be successful |
 * | 02 | Create topology object using the initialized dm_easy_mesh_t instance | Input: root_dm pointer; Output: new em_network_topo_t object | Topology object successfully created | Should be successful |
 * | 03 | Invoke print_topology() API and check for exceptions | Input: topo_root->print_topology() call | No exception thrown; output message printed: "Successfully printed single valid topology" | Should Pass |
 * | 04 | Delete allocated objects for cleanup | Deletion of topo_root and root_dm | Resources properly de-allocated | Should be successful |
 */
TEST(em_network_topo_t, print_topology_valid_topology)
{
    std::cout << "Entering print_topology_valid_topology test" << std::endl;
    dm_easy_mesh_t* root_dm = new dm_easy_mesh_t{};
    init_dm_with_mac(root_dm, 0x10, 0); // MAC: 02:10:00:00:00:00
    em_network_topo_t* topo_root = new em_network_topo_t(root_dm);
    EXPECT_NO_THROW({
        topo_root->print_topology();
        std::cout << "Successfully printed single valid topology" << std::endl;
    });
    delete topo_root;
    delete root_dm;
    std::cout << "Exiting print_topology_valid_topology test" << std::endl;
}
/**
 * @brief Verify print_topology prints the network topology along with its child node
 *
 * This test verifies that the print_topology function of the topology root successfully prints the network topology on a topology tree with one child node without throwing exceptions. It creates a root device node and a child device node, adds the child node to the topology, and then prints the topology.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 043@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |@n
 * | :----: | --------- | ---------- |-------------- | ----- |@n
 * | 01 | Create and initialize the root device node | dm_easy_mesh_t* root_dm, mac = 0x10, instance = 0 | root_dm is initialized successfully | Should be successful |@n
 * | 02 | Initialize the topology root with the root device node | em_network_topo_t* topo_root, input: pointer to root_dm | Topology root is created successfully | Should be successful |@n
 * | 03 | Create and initialize the child device node | dm_easy_mesh_t* child_dm, mac = 0x20, instance = 0 | child_dm is initialized successfully | Should be successful |@n
 * | 04 | Add the child device node to the topology | Function call: topo_root->add_network_topo(child_dm, nullptr, 0) | Child is added to topology successfully | Should be successful |@n
 * | 05 | Invoke print_topology and verify no exception is thrown | Function call: topo_root->print_topology() | print_topology executes without throwing exceptions | Should Pass |@n
 * | 06 | Cleanup all allocated resources | Delete pointers: child_dm, topo_root, root_dm | All resources are released successfully | Should be successful |
 */
TEST(em_network_topo_t, print_topology_with_child)
{
    std::cout << "Entering print_topology_with_child test" << std::endl;
    dm_easy_mesh_t* root_dm = new dm_easy_mesh_t{};
    init_dm_with_mac(root_dm, 0x10, 0);
    em_network_topo_t* topo_root = new em_network_topo_t(root_dm);
    dm_easy_mesh_t* child_dm = new dm_easy_mesh_t{};
    init_dm_with_mac(child_dm, 0x20, 0);
    topo_root->add_network_topo(child_dm, nullptr, 0);
    EXPECT_NO_THROW({
        topo_root->print_topology();
        std::cout << "Successfully printed topology with one child" << std::endl;
    });
    // Cleanup
    topo_root->remove(child_dm, nullptr, nullptr);
    delete child_dm;
    delete topo_root;
    delete root_dm;
    std::cout << "Exiting print_topology_with_child test" << std::endl;
}
/**
 * @brief Verify print_topology correctly prints network topology with grandchild nodes.
 *
 * This test verifies that the print_topology method of the em_network_topo_t class works as expected when a network topology 
 * includes both a child and its grandchild node. It ensures that the topology is correctly printed without throwing any exceptions.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 044@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Create and initialize root, child, and grandchild device management structures and their corresponding topology nodes | root_dm: init_dm_with_mac(root_dm, 0x10, 0), child_dm: init_dm_with_mac(child_dm, 0x20, 0), grandchild_dm: init_dm_with_mac(grandchild_dm, 0x30, 0) | Objects are initialized correctly without errors | Should be successful |
 * | 02 | Add the child and grandchild topology to the root topology using add_network_topo API | child_dm pointer, grandchild_array containing em_network_topo_t pointer, count = 1 | Topology is updated without exceptions | Should Pass |
 * | 03 | Invoke print_topology on the root topology node | API call: topo_root->print_topology() | Function executes without throwing exceptions; topology is printed | Should Pass |
 * | 04 | Clean up allocated objects and remove the added topology | Removal: topo_root->remove(child_dm, nullptr, nullptr) and subsequent delete calls | Resources are freed properly without memory issues | Should be successful |
 */
TEST(em_network_topo_t, print_topology_with_grandchild)
{
    std::cout << "Entering print_topology_with_grandchild test" << std::endl;
    dm_easy_mesh_t* root_dm = new dm_easy_mesh_t{};
    init_dm_with_mac(root_dm, 0x10, 0);
    em_network_topo_t* topo_root = new em_network_topo_t(root_dm);
    dm_easy_mesh_t* child_dm = new dm_easy_mesh_t{};
    init_dm_with_mac(child_dm, 0x20, 0);
    dm_easy_mesh_t* grandchild_dm = new dm_easy_mesh_t{};
    init_dm_with_mac(grandchild_dm, 0x30, 0);
    em_network_topo_t* grandchild_topo = new em_network_topo_t(grandchild_dm);
    em_network_topo_t* grandchild_array[1] = { grandchild_topo };
    topo_root->add_network_topo(child_dm, grandchild_array, 1);
    EXPECT_NO_THROW({
        topo_root->print_topology();
        std::cout << "Successfully printed topology with child and grandchild" << std::endl;
    });
    // Cleanup
    topo_root->remove(child_dm, nullptr, nullptr); // removes child and grandchild
    delete grandchild_topo;
    delete grandchild_dm;
    delete child_dm;
    delete topo_root;
    delete root_dm;
    std::cout << "Exiting print_topology_with_grandchild test" << std::endl;
}
/**
 * @brief Validate that the topology printing function works correctly with multiple children.
 *
 * This test verifies that when a topology root is created and multiple child devices are added, the print_topology method outputs the topology correctly without throwing any exceptions. The test initializes a root device and several children, adds them to the topology, and then calls the print_topology method to ensure it operates as expected.
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
 * | Variation / Step | Description | Test Data | Expected Result | Notes |@n
 * | :----: | --------- | ---------- |-------------- | ----- |@n
 * | 01 | Initialize a root device with MAC = 0x10 and index = 0, then create the topology root | input: root_dm with mac=0x10, index=0; output: valid dm_easy_mesh_t object and topology root object | Root device and topology root successfully created | Should be successful |@n
 * | 02 | Create 3 children devices with MAC addresses 0x20, 0x21, 0x22 respectively, each with indexes 0, 1, 2, and add them to the topology root | input: children devices with mac=0x20, index=0; mac=0x21, index=1; mac=0x22, index=2; output: added children to topology | Children devices successfully added to topology root | Should be successful |@n
 * | 03 | Invoke print_topology on the topology root and capture the output while ensuring no exception is thrown | input: call to print_topology(); output: no exceptions and successful print message | print_topology API call completes without throwing exceptions | Should Pass |@n
 * | 04 | Clean up by removing children from the topology and deallocating memory for both children and root devices | input: removal of each child and deletion of objects; output: all resources properly freed | Resources are freed without errors | Should be successful |
 */
TEST(em_network_topo_t, print_topology_multiple_children)
{
    std::cout << "Entering print_topology_multiple_children test" << std::endl;
    dm_easy_mesh_t* root_dm = new dm_easy_mesh_t{};
    init_dm_with_mac(root_dm, 0x10, 0);
    em_network_topo_t* topo_root = new em_network_topo_t(root_dm);
    const int NUM_CHILDREN = 3;
    dm_easy_mesh_t* children[NUM_CHILDREN];
    for (int i = 0; i < NUM_CHILDREN; i++) {
        children[i] = new dm_easy_mesh_t{};
        init_dm_with_mac(children[i], 0x20 + i, i); // 02:20, 02:21, 02:22
        topo_root->add_network_topo(children[i], nullptr, 0);
    }
    EXPECT_NO_THROW({
        topo_root->print_topology();
        std::cout << "Successfully printed topology with multiple children" << std::endl;
    });
    // Cleanup
    for (int i = 0; i < NUM_CHILDREN; i++) {
        topo_root->remove(children[i], nullptr, nullptr);
        delete children[i];
    }
    delete topo_root;
    delete root_dm;
    std::cout << "Exiting print_topology_multiple_children test" << std::endl;
}
/**
 * @brief Validate that print_topology() throws an exception when invoked on an empty topology object
 *
 * This test verifies that calling print_topology() on an uninitialized or empty em_network_topo_t object correctly throws an exception. The test is essential to ensure that the API does not proceed with invalid internal state, thereby preventing undefined behavior.
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
 * | Variation / Step | Description                                                  | Test Data                                                         | Expected Result                                                                    | Notes       |
 * | :--------------: | ------------------------------------------------------------ | ----------------------------------------------------------------- | ---------------------------------------------------------------------------------- | ----------- |
 * | 01               | Call print_topology() on an empty topology object              | topo = empty topology object, print_topology() invoked            | API throws an exception and assertion validates the exception is thrown properly   | Should Pass |
 */
TEST(em_network_topo_t, print_topology_empty_topology)
{
    std::cout << "Entering print_topology_empty_topology test" << std::endl;
    em_network_topo_t topo;
    EXPECT_ANY_THROW({
        topo.print_topology();
        std::cout << "print_topology() invoked on empty topology" << std::endl;
    });
    std::cout << "Exiting print_topology_empty_topology test" << std::endl;
}
/**
 * @brief Test that print_topology() throws an exception when called on a topology constructed with a null DM pointer
 *
 * This test verifies that the print_topology() method properly handles a null domain manager (DM) by throwing an exception.
 * Using a null DM pointer to initialize the topology object, the test checks that the correct error-handling mechanism is in place.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 047
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                 | Test Data                                                         | Expected Result                                                    | Notes       |
 * | :--------------: | --------------------------------------------------------------------------- | ----------------------------------------------------------------- | ------------------------------------------------------------------ | ----------- |
 * | 01               | Invoke topology.print_topology() on topology object constructed with null DM | null_dm = nullptr, topology constructed with dm_easy_mesh_t* = nullptr | API throws exception as expected when print_topology() is invoked   | Should Pass |
 */
TEST(em_network_topo_t, print_topology_null_dm)
{
    std::cout << "Entering print_topology_null_dm test" << std::endl;
    dm_easy_mesh_t* null_dm = nullptr;
    em_network_topo_t topo(null_dm);
    EXPECT_ANY_THROW({
        topo.print_topology();
        std::cout << "print_topology() invoked on topology with null DM" << std::endl;
    });
    std::cout << "Exiting print_topology_null_dm test" << std::endl;
}
/**
 * @brief Test the remove API when the root node has no children
 *
 * This test verifies that attempting to remove the root device from the network topology fails when the root has no children. It ensures that the API returns false, no devices are removed, and output parameters remain unchanged. The test checks that the system correctly handles an edge case without erroneously deleting the root node.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 048@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize the root device via helper function | root_dm = new dm_easy_mesh_t{}, init_dm_with_mac(root_dm, 0x10, 0) | Root device is properly initialized with specified MAC address and parameters | Should be successful |
 * | 02 | Construct the network topology with the initialized root device | topo_root = new em_network_topo_t(root_dm) | A valid topology instance is created using the root device | Should be successful |
 * | 03 | Invoke the remove API on the topology with the root device as target | ret = topo_root->remove(root_dm, removedChildren, &numRemoved) | API returns false, numRemoved remains 0, and removedChildren[0] is still nullptr | Should Fail |
 * | 04 | Validate the API response using assertions | EXPECT_FALSE(ret), EXPECT_EQ(numRemoved, 0u), EXPECT_EQ(removedChildren[0], nullptr) | All assertion checks pass confirming the removal did not occur | Should Pass |
 * | 05 | Cleanup allocated objects to free memory | delete topo_root; delete root_dm; | Memory is released without errors | Should be successful |
 */
TEST(em_network_topo_t, remove_root_no_children)
{
    std::cout << "Entering remove_root_no_children test" << std::endl;
    dm_easy_mesh_t* root_dm = new dm_easy_mesh_t{};
    init_dm_with_mac(root_dm, 0x10, 0);
    em_network_topo_t* topo_root = new em_network_topo_t(root_dm);
    em_network_topo_t* removedChildren[EM_MAX_NETWORKS] = { nullptr };
    unsigned int numRemoved = 0;
    bool ret = topo_root->remove(root_dm, removedChildren, &numRemoved);
    EXPECT_FALSE(ret);
    EXPECT_EQ(numRemoved, 0u);
    EXPECT_EQ(removedChildren[0], nullptr);
    delete topo_root;
    delete root_dm;
    std::cout << "Exiting remove_root_no_children test" << std::endl;
}
/**
 * @brief Test to remove a child network topology without any grandchildren removal.
 *
 * This test verifies that removing a child node from the network topology behaves correctly when the child does not have any grandchildren. The test ensures that the remove function returns true, no grandchildren are reported as removed, and the output parameters (numRemoved and removedChildren) reflect the expected state.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 049
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize root and child dm_easy_mesh_t objects with their respective MAC addresses | root_dm: mac = 0x10, child_dm: mac = 0x20 | Objects are initialized successfully | Should be successful |
 * | 02 | Create the network topology for the root and add the child to it using add_network_topo | Call: topo_root->add_network_topo(child_dm, nullptr, 0) | Child is added to the network topology successfully | Should Pass |
 * | 03 | Invoke the remove method to remove the child and capture any removed grandchildren | Call: ret = topo_root->remove(child_dm, removedChildren, &numRemoved) with removedChildren initialized to {nullptr} and numRemoved = 0 | API returns true; numRemoved equals 0; removedChildren[0] remains nullptr | Should Pass |
 * | 04 | Delete child, root topology, and root dm objects to clean up resources | Call: delete child_dm; delete topo_root; delete root_dm | Objects are deleted successfully without errors | Should be successful |
 */
TEST(em_network_topo_t, remove_child_no_grandchild)
{
    std::cout << "Entering remove_child_no_grandchild test" << std::endl;
    dm_easy_mesh_t* root_dm = new dm_easy_mesh_t{};
    init_dm_with_mac(root_dm, 0x10, 0);
    em_network_topo_t* topo_root = new em_network_topo_t(root_dm);
    dm_easy_mesh_t* child_dm = new dm_easy_mesh_t{};
    init_dm_with_mac(child_dm, 0x20, 0);
    topo_root->add_network_topo(child_dm, nullptr, 0);
    em_network_topo_t* removedChildren[EM_MAX_NETWORKS] = { nullptr };
    unsigned int numRemoved = 0;
    bool ret = topo_root->remove(child_dm, removedChildren, &numRemoved);
    EXPECT_TRUE(ret);
    EXPECT_EQ(numRemoved, 0u);
    EXPECT_EQ(removedChildren[0], nullptr);
    delete child_dm;
    delete topo_root;
    delete root_dm;
    std::cout << "Exiting remove_child_no_grandchild test" << std::endl;
}
/**
 * @brief Test to remove a child network topology node that has one grandchild node
 *
 * This test verifies that removing a child node from the network topology correctly returns the grandchild node. 
 * The test sets up a root topology with one child (which in turn has one grandchild) and then verifies that the 
 * removal of the child network topology returns the grandchild topology as expected.
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
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize root, child, and grandchild network topology objects with specific MAC addresses and flags. | root_dm (mac = 0x10, flag = 0), child_dm (mac = 0x20, flag = 0), grandchild_dm (mac = 0x21, flag = 1) | Network topology objects are successfully created. | Should be successful |
 * | 02 | Add the child network topology with its grandchild to the root topology using add_network_topo method. | add_network_topo(child_dm, grandchild_array, 1) | Child network topology is added along with its grandchild. | Should Pass |
 * | 03 | Remove the child network topology from the root topology using remove method and verify the returned nodes. | remove(child_dm, removedChildren, &numRemoved) | Function returns true, numRemoved equals 1, and removedChildren[0] equals the grandchild topology instance. | Should Pass |
 */
TEST(em_network_topo_t, remove_child_one_grandchild)
{
    std::cout << "Entering remove_child_one_grandchild test" << std::endl;
    dm_easy_mesh_t* root_dm = new dm_easy_mesh_t{};
    init_dm_with_mac(root_dm, 0x10, 0);
    em_network_topo_t* topo_root = new em_network_topo_t(root_dm);
    dm_easy_mesh_t* child_dm = new dm_easy_mesh_t{};
    init_dm_with_mac(child_dm, 0x20, 0);
    dm_easy_mesh_t* grandchild_dm = new dm_easy_mesh_t{};
    init_dm_with_mac(grandchild_dm, 0x21, 1);
    em_network_topo_t* grandchild_topo = new em_network_topo_t(grandchild_dm);
    em_network_topo_t* grandchild_array[1] = { grandchild_topo };
    topo_root->add_network_topo(child_dm, grandchild_array, 1);
    em_network_topo_t* removedChildren[EM_MAX_NETWORKS] = { nullptr };
    unsigned int numRemoved = 0;
    bool ret = topo_root->remove(child_dm, removedChildren, &numRemoved);
    EXPECT_TRUE(ret);
    EXPECT_EQ(numRemoved, 1u);
    EXPECT_EQ(removedChildren[0], grandchild_topo);
    delete grandchild_dm;
    delete child_dm;
    delete grandchild_topo;
    delete topo_root;
    delete root_dm;
    std::cout << "Exiting remove_child_one_grandchild test" << std::endl;
}
/**
 * @brief Validate removal of a child node with multiple grandchildren from the network topology
 *
 * This test verifies that when a child node having multiple grandchildren nodes is removed from the network topology, the API correctly returns the removed grandchildren. It ensures that both grandchildren are identified and removed successfully by the underlying removal mechanism.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 051
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize root device and its topology | root_dm: MAC = 0x10, flag = 0; topo_root created from root_dm | root_dm and topo_root initialized successfully | Should be successful |
 * | 02 | Initialize child device | child_dm: MAC = 0x30, flag = 0 | child_dm initialized successfully | Should be successful |
 * | 03 | Initialize first grandchild device | grandchild1_dm: MAC = 0x31, flag = 0; grandchild1_topo created from grandchild1_dm | grandchild1_dm and grandchild1_topo initialized successfully | Should be successful |
 * | 04 | Initialize second grandchild device | grandchild2_dm: MAC = 0x32, flag = 1; grandchild2_topo created from grandchild2_dm | grandchild2_dm and grandchild2_topo initialized successfully | Should be successful |
 * | 05 | Create network topology with child having both grandchildren | grandkids array = { grandchild1_topo, grandchild2_topo } added to topo_root using child_dm | Topology updated with child and its two grandchildren | Should be successful |
 * | 06 | Remove child from the topology and capture removed grandchildren | Call remove(child_dm, removedChildren, &numRemoved); Input: child_dm, removedChildren (array), pointer to numRemoved | API returns true; numRemoved equals 2; removedChildren contains grandchild1_topo at index 0 and grandchild2_topo at index 1 | Should Pass |
 */
TEST(em_network_topo_t, remove_child_multiple_grandchildren)
{
    std::cout << "Entering remove_child_multiple_grandchildren test" << std::endl;
    dm_easy_mesh_t* root_dm = new dm_easy_mesh_t{};
    init_dm_with_mac(root_dm, 0x10, 0);
    em_network_topo_t* topo_root = new em_network_topo_t(root_dm);
    dm_easy_mesh_t* child_dm = new dm_easy_mesh_t{};
    init_dm_with_mac(child_dm, 0x30, 0);
    dm_easy_mesh_t* grandchild1_dm = new dm_easy_mesh_t{};
    init_dm_with_mac(grandchild1_dm, 0x31, 0);
    em_network_topo_t* grandchild1_topo = new em_network_topo_t(grandchild1_dm);
    dm_easy_mesh_t* grandchild2_dm = new dm_easy_mesh_t{};
    init_dm_with_mac(grandchild2_dm, 0x32, 1);
    em_network_topo_t* grandchild2_topo = new em_network_topo_t(grandchild2_dm);
    em_network_topo_t* grandkids[2] = { grandchild1_topo, grandchild2_topo };
    topo_root->add_network_topo(child_dm, grandkids, 2);
    em_network_topo_t* removedChildren[EM_MAX_NETWORKS] = { nullptr };
    unsigned int numRemoved = 0;
    bool ret = topo_root->remove(child_dm, removedChildren, &numRemoved);
    EXPECT_TRUE(ret);
    EXPECT_EQ(numRemoved, 2u);
    EXPECT_EQ(removedChildren[0], grandchild1_topo);
    EXPECT_EQ(removedChildren[1], grandchild2_topo);
    delete grandchild1_dm;
    delete grandchild2_dm;
    delete child_dm;
    delete grandchild1_topo;
    delete grandchild2_topo;
    delete topo_root;
    delete root_dm;
    std::cout << "Exiting remove_child_multiple_grandchildren test" << std::endl;
}
/**
 * @brief Test the removal of a grandchild from a network topology
 *
 * This test case verifies that the remove function on a network topology correctly handles the removal of a grandchild node without affecting the overall topology structure. It ensures that the API returns the expected values and maintains consistency in the network topology.
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
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Create and initialize the root, child, and grandchild device managers along with their MAC addresses | root_dm: mac=0x10, flag=0; child_dm: mac=0x40, flag=0; grandchild_dm: mac=0x41, flag=0 | All device managers are successfully created and initialized | Should be successful |
 * | 02 | Create topology nodes and add the child topology with the grandchild node using add_network_topo API | topo_root initialized with root_dm; grandchild_topo created from grandchild_dm; child_dm and grandchild_topo array with one element | Topology tree is updated, associating child with its grandchild under the root | Should Pass |
 * | 03 | Invoke the remove API to remove the grandchild node from the topology | Invoke remove(grandchild_dm, removedChildren, &numRemoved) where removedChildren is an array with initial nullptr and numRemoved pointer | API returns true, numRemoved is 0, and removedChildren[0] remains nullptr | Should Pass |
 * | 04 | Remove the child node from the topology and perform cleanup | Invoke remove(child_dm, nullptr, nullptr) | Child node is successfully removed; memory cleanup is properly executed | Should Pass |
 */
TEST(em_network_topo_t, remove_grandchild)
{
    std::cout << "Entering remove_grandchild test" << std::endl;
    dm_easy_mesh_t* root_dm = new dm_easy_mesh_t{};
    init_dm_with_mac(root_dm, 0x10, 0);
    em_network_topo_t* topo_root = new em_network_topo_t(root_dm);
    dm_easy_mesh_t* child_dm = new dm_easy_mesh_t{};
    init_dm_with_mac(child_dm, 0x40, 0);
    dm_easy_mesh_t* grandchild_dm = new dm_easy_mesh_t{};
    init_dm_with_mac(grandchild_dm, 0x41, 0);
    em_network_topo_t* grandchild_topo = new em_network_topo_t(grandchild_dm);
    em_network_topo_t* grandkids[1] = { grandchild_topo };
    topo_root->add_network_topo(child_dm, grandkids, 1);
    em_network_topo_t* removedChildren[EM_MAX_NETWORKS] = { nullptr };
    unsigned int numRemoved = 0;
    bool ret = topo_root->remove(grandchild_dm, removedChildren, &numRemoved);
    EXPECT_TRUE(ret);
    EXPECT_EQ(numRemoved, 0u);
    EXPECT_EQ(removedChildren[0], nullptr);
    topo_root->remove(child_dm,nullptr,nullptr);
    delete grandchild_dm;
    delete child_dm;
    delete topo_root;
    delete root_dm;
    std::cout << "Exiting remove_grandchild test" << std::endl;
}
/**
 * @brief Validate removal of a non-existent device manager from network topology
 *
 * This test verifies that attempting to remove a device manager (DM) that does not exist in the network topology 
 * returns a failure status without modifying the topology. The test sets up a root DM and a child DM, then invokes 
 * the remove API using a DM that was not added. It confirms that the API returns false, no child is removed, and that 
 * the output parameters remain unchanged.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 053
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Invoke the remove API with a non-existent DM after creating the network topology with root and child DMs | input: nonexistent_dm = DM with MAC 0x99, removedChildren = array of EM_MAX_NETWORKS pointers initialized to nullptr, numRemoved pointer; output: ret, numRemoved, removedChildren[0] | API returns false; numRemoved equals 0; removedChildren[0] remains nullptr | Should Fail |
 */
TEST(em_network_topo_t, remove_nonexistent_dm)
{
    std::cout << "Entering remove_nonexistent_dm test" << std::endl;
    dm_easy_mesh_t* root_dm = new dm_easy_mesh_t{};
    init_dm_with_mac(root_dm, 0x10, 0);
    em_network_topo_t* topo_root = new em_network_topo_t(root_dm);
    dm_easy_mesh_t* child_dm = new dm_easy_mesh_t{};
    init_dm_with_mac(child_dm, 0x50, 0);
    topo_root->add_network_topo(child_dm, nullptr, 0);
    dm_easy_mesh_t* nonexistent_dm = new dm_easy_mesh_t{};
    init_dm_with_mac(nonexistent_dm, 0x99, 0);
    em_network_topo_t* removedChildren[EM_MAX_NETWORKS] = { nullptr };
    unsigned int numRemoved = 0;
    bool ret = topo_root->remove(nonexistent_dm, removedChildren, &numRemoved);
    EXPECT_FALSE(ret);
    EXPECT_EQ(numRemoved, 0u);
    EXPECT_EQ(removedChildren[0], nullptr);
    topo_root->remove(child_dm, nullptr, nullptr);
    delete nonexistent_dm;
    delete child_dm;
    delete topo_root;
    delete root_dm;
    std::cout << "Exiting remove_nonexistent_dm test" << std::endl;
}
/**
 * @brief Verify that the destructor of em_network_topo_t correctly releases resources when provided with a valid dm pointer
 *
 * This test ensures that the destructor of the em_network_topo_t class successfully releases all allocated resources for a valid dm pointer.
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
 * | Variation / Step | Description                                                       | Test Data                                                   | Expected Result                                                    | Notes        |
 * | :--------------: | ----------------------------------------------------------------- | ----------------------------------------------------------- | ------------------------------------------------------------------ | ------------ |
 * | 01               | Invoke the constructor em_network_topo_t(dm) with a valid dm pointer. | dm = valid pointer, instance = construction result pointer  | No exception thrown; instance is successfully created.             | Should Pass  |
 * | 02               | Delete the instance to trigger the destructor and release resources. | instance = pointer returned from constructor                | Destructor completes without exceptions, releasing all resources. | Should Pass  |
 */
TEST(em_network_topo_t, destructor_releases_resources_for_valid_dm_pointer) {
    std::cout << "Entering destructor_releases_resources_for_valid_dm_pointer test" << std::endl;
    dm_easy_mesh_t* dm;
    em_network_topo_t* instance;
    EXPECT_NO_THROW({
        instance = new em_network_topo_t(dm);
        std::cout << "Invoked em_network_topo_t(dm) constructor " << std::endl;
        delete instance;
        std::cout << "Deleted instance of em_network_topo_t, destructor ~em_network_topo_t() invoked" << std::endl;
    });
    std::cout << "Exiting destructor_releases_resources_for_valid_dm_pointer test" << std::endl;
}
