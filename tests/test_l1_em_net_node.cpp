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
#include "em_net_node.h"
#include <cstring>
#include <fstream>
#include <cstdio>

/**
 * @brief Verify that clone_network_tree returns a null pointer when given a null input
 *
 * This test checks the behavior of the clone_network_tree function when provided with a null pointer as input.
 * The expected behavior is that the function returns a null pointer. This ensures that the function handles
 * invalid input gracefully without causing undefined behavior.
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
 * | Variation / Step | Description                                        | Test Data                           | Expected Result                                             | Notes      |
 * | :--------------: | -------------------------------------------------- | ----------------------------------- | ----------------------------------------------------------- | ---------- |
 * | 01               | Invoke clone_network_tree with a null pointer      | input = nullptr, output = nullptr   | API returns a null pointer and ASSERT_EQ confirms the result  | Should Pass |
 */
TEST(em_net_node_t, clone_network_tree_null_input)
{
    std::cout << "Entering clone_network_tree_null_input test" << std::endl;
    em_network_node_t* clone = em_net_node_t::clone_network_tree(nullptr);
    ASSERT_EQ(clone, nullptr);
    std::cout << "Exiting clone_network_tree_null_input test" << std::endl;
}
/**
 * @brief Validate that clone_network_tree correctly clones a single node tree without children.
 *
 * This test verifies that the clone_network_tree function creates a deep copy of a network node that has no children.
 * It checks that all the node attributes (key, display_info, type, value_str, value_int, and num_children) in the cloned node
 * exactly match the original node and that the cloned node does not share the same memory address as the original.
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
 * | Variation / Step | Description                                                                                       | Test Data                                                                                                                                                                                          | Expected Result                                                                                                            | Notes         |
 * | :--------------: | ------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------- | ------------- |
 * | 01               | Initialize original network node with specific attribute values.                                | node.key = node1, node.display_info.collapsed = false, node.display_info.orig_node_ctr = 1, node.display_info.node_ctr = 1, node.display_info.node_pos = 0, node.type = em_network_node_data_type_number, node.value_str = 123, node.value_int = 123, node.num_children = 0 | Node is correctly initialized with all intended attribute values.                                                          | Should be successful |
 * | 02               | Invoke clone_network_tree API using the initialized node.                                       | input: pointer to the initialized node                                                                                                                                                              | The API returns a non-null clone pointer that is different from the original node pointer.                                 | Should Pass   |
 * | 03               | Verify that each attribute of the cloned node matches the original node's values.                 | input: cloned node attributes compared with original node attributes (key, display_info values, type, value_str, value_int, num_children)                                                         | All attribute equality assertions (ASSERT_NE, EXPECT_STREQ, EXPECT_EQ) pass successfully ensuring deep clone.               | Should Pass   |
 * | 04               | Free the cloned network tree to clean up test resources.                                        | input: cloned node pointer                                                                                                                                                                      | Memory is freed successfully with no resource leaks.                                                                    | Should be successful |
 */
TEST(em_net_node_t, clone_network_tree_single_node_no_children)
{
    std::cout << "Entering clone_network_tree_single_node_no_children test" << std::endl;
    em_network_node_t node;
    memset(&node, 0, sizeof(em_network_node_t));
    strncpy(node.key, "node1", sizeof(node.key));
    node.display_info.collapsed = false;
    node.display_info.orig_node_ctr = 1;
    node.display_info.node_ctr = 1;
    node.display_info.node_pos = 0;
    node.type = em_network_node_data_type_number;
    strncpy(node.value_str, "123", sizeof(node.value_str));
    node.value_int = 123;
    node.num_children = 0;
    em_network_node_t* clone = em_net_node_t::clone_network_tree(&node);
    ASSERT_NE(clone, nullptr);
    EXPECT_STREQ(clone->key, node.key);
    EXPECT_EQ(clone->display_info.collapsed, node.display_info.collapsed);
    EXPECT_EQ(clone->display_info.orig_node_ctr, node.display_info.orig_node_ctr);
    EXPECT_EQ(clone->display_info.node_ctr, node.display_info.node_ctr);
    EXPECT_EQ(clone->display_info.node_pos, node.display_info.node_pos);
    EXPECT_EQ(clone->type, node.type);
    EXPECT_STREQ(clone->value_str, node.value_str);
    EXPECT_EQ(clone->value_int, node.value_int);
    EXPECT_EQ(clone->num_children, node.num_children);
    EXPECT_NE(clone, &node);
    em_net_node_t::free_network_tree(clone);
    std::cout << "Exiting clone_network_tree_single_node_no_children test" << std::endl;
}
/**
 * @brief Test the clone_network_tree function for a network tree with one child node.
 *
 * This test validates that the clone_network_tree function correctly duplicates a network node tree comprising a root with one child. It verifies that the cloned root and child nodes have all attributes identical to those in the original network tree, ensuring a deep copy.
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
 * | Variation / Step | Description | Test Data | Expected Result |Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize a root network node and its child with specified attributes | root.key = "root", root.display_info.collapsed = false, root.display_info.orig_node_ctr = 1, root.display_info.node_ctr = 1, root.display_info.node_pos = 0, root.type = em_network_node_data_type_obj, root.value_str = "root_val", root.value_int = 0, root.num_children = 1; child.key = "child", child.display_info.collapsed = true, child.display_info.orig_node_ctr = 2, child.display_info.node_ctr = 2, child.display_info.node_pos = 0, child.type = em_network_node_data_type_string, child.value_str = "child_val", child.value_int = 10, child.num_children = 0 | Network node structure is correctly populated | Should be successful |
 * | 02 | Invoke the clone_network_tree API using the initialized network tree | input: pointer to root node | Returns a valid cloned network tree pointer (not nullptr) | Should Pass |
 * | 03 | Verify that the cloned root and child nodes have attributes matching the originals | output: clone_root and clone_child with identical attribute values to the original nodes | Cloned root and child attributes match the original values; assertions pass | Should Pass |
 * | 04 | Free the cloned network tree to clean up allocated memory | clone_root pointer | Cloned network tree is successfully freed with no memory issues | Should be successful |
 */
TEST(em_net_node_t, clone_network_tree_one_child)
{
    std::cout << "Entering clone_network_tree_one_child test" << std::endl;
    em_network_node_t root;
    memset(&root, 0, sizeof(root));
    strncpy(root.key, "root", sizeof(root.key));
    root.display_info.collapsed = false;
    root.display_info.orig_node_ctr = 1;
    root.display_info.node_ctr = 1;
    root.display_info.node_pos = 0;
    root.type = em_network_node_data_type_obj;
    strncpy(root.value_str, "root_val", sizeof(root.value_str));
    root.value_int = 0;
    root.num_children = 1;
    em_network_node_t child;
    memset(&child, 0, sizeof(child));
    strncpy(child.key, "child", sizeof(child.key));
    child.display_info.collapsed = true;
    child.display_info.orig_node_ctr = 2;
    child.display_info.node_ctr = 2;
    child.display_info.node_pos = 0;
    child.type = em_network_node_data_type_string;
    strncpy(child.value_str, "child_val", sizeof(child.value_str));
    child.value_int = 10;
    child.num_children = 0;
    root.child[0] = &child;
    em_network_node_t* clone_root = em_net_node_t::clone_network_tree(&root);
    ASSERT_NE(clone_root, nullptr);
    EXPECT_EQ(clone_root->num_children, root.num_children);
    // Validate root
    EXPECT_STREQ(clone_root->key, root.key);
    EXPECT_EQ(clone_root->display_info.collapsed, root.display_info.collapsed);
    EXPECT_EQ(clone_root->display_info.orig_node_ctr, root.display_info.orig_node_ctr);
    EXPECT_EQ(clone_root->type, root.type);
    EXPECT_STREQ(clone_root->value_str, root.value_str);
    EXPECT_EQ(clone_root->value_int, root.value_int);
    // Validate child
    em_network_node_t* clone_child = clone_root->child[0];
    ASSERT_NE(clone_child, nullptr);
    EXPECT_STREQ(clone_child->key, child.key);
    EXPECT_EQ(clone_child->display_info.collapsed, child.display_info.collapsed);
    EXPECT_EQ(clone_child->display_info.orig_node_ctr, child.display_info.orig_node_ctr);
    EXPECT_EQ(clone_child->type, child.type);
    EXPECT_STREQ(clone_child->value_str, child.value_str);
    EXPECT_EQ(clone_child->value_int, child.value_int);
    EXPECT_EQ(clone_child->num_children, child.num_children);
    em_net_node_t::free_network_tree(clone_root);
    std::cout << "Exiting clone_network_tree_one_child test" << std::endl;
}
/**
 * @brief Validate deep cloning of a network tree with multiple children at the root level.
 *
 * This test verifies that the clone_network_tree API correctly deep copies a network tree structure
 * from a root with multiple child nodes. It checks that all properties of the root and each child node
 * are accurately cloned to ensure integrity and independence of the cloned structure.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 004
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize root network node with multiple children | root: key = "root", collapsed = false, orig_node_ctr = 10, node_ctr = 10, node_pos = 0, type = em_network_node_data_type_obj, value_str = "root_val", value_int = 0, num_children = 2 | Root node initialized successfully | Should be successful |
 * | 02 | Initialize first child node (child1) | child1: key = "child1", collapsed = true, orig_node_ctr = 5, node_ctr = 5, node_pos = 1, type = em_network_node_data_type_string, value_str = "child1_val", value_int = 1, num_children = 0 | First child node initialized successfully | Should be successful |
 * | 03 | Initialize second child node (child2) | child2: key = "child2", collapsed = false, orig_node_ctr = 3, node_ctr = 3, node_pos = 2, type = em_network_node_data_type_number, value_str = "42", value_int = 42, num_children = 0 | Second child node initialized successfully | Should be successful |
 * | 04 | Assign child nodes to root and invoke clone_network_tree | root.child[0] = &child1, root.child[1] = &child2, clone_network_tree(&root) invoked | Returns a valid non-null cloned root | Should Pass |
 * | 05 | Validate cloned root's number of children | clone_root->num_children vs original num_children (2) | Cloned root's num_children equals 2 | Should Pass |
 * | 06 | Validate cloned first child node properties | clone_child1: key = "child1", collapsed = true, orig_node_ctr = 5, type = em_network_node_data_type_string, value_str = "child1_val", value_int = 1 | Cloned first child node properties match original | Should Pass |
 * | 07 | Validate cloned second child node properties | clone_child2: key = "child2", collapsed = false, orig_node_ctr = 3, type = em_network_node_data_type_number, value_str = "42", value_int = 42 | Cloned second child node properties match original | Should Pass |
 * | 08 | Free cloned network tree | free_network_tree(clone_root) invoked | Cloned network tree freed without error | Should be successful |
 */
TEST(em_net_node_t, clone_network_tree_root_with_multiple_children)
{
    std::cout << "Entering clone_network_tree_root_with_multiple_children test" << std::endl;
    em_network_node_t root;
    memset(&root, 0, sizeof(root));
    strncpy(root.key, "root", sizeof(root.key));
    root.display_info.collapsed = false;
    root.display_info.orig_node_ctr = 10;
    root.display_info.node_ctr = 10;
    root.display_info.node_pos = 0;
    root.type = em_network_node_data_type_obj;
    strncpy(root.value_str, "root_val", sizeof(root.value_str));
    root.value_int = 0;
    root.num_children = 2;
    em_network_node_t child1;
    memset(&child1, 0, sizeof(child1));
    strncpy(child1.key, "child1", sizeof(child1.key));
    child1.display_info.collapsed = true;
    child1.display_info.orig_node_ctr = 5;
    child1.display_info.node_ctr = 5;
    child1.display_info.node_pos = 1;
    child1.type = em_network_node_data_type_string;
    strncpy(child1.value_str, "child1_val", sizeof(child1.value_str));
    child1.value_int = 1;
    child1.num_children = 0;
    em_network_node_t child2;
    memset(&child2, 0, sizeof(child2));
    strncpy(child2.key, "child2", sizeof(child2.key));
    child2.display_info.collapsed = false;
    child2.display_info.orig_node_ctr = 3;
    child2.display_info.node_ctr = 3;
    child2.display_info.node_pos = 2;
    child2.type = em_network_node_data_type_number;
    strncpy(child2.value_str, "42", sizeof(child2.value_str));
    child2.value_int = 42;
    child2.num_children = 0;
    root.child[0] = &child1;
    root.child[1] = &child2;
    em_network_node_t* clone_root = em_net_node_t::clone_network_tree(&root);
    ASSERT_NE(clone_root, nullptr);
    EXPECT_EQ(clone_root->num_children, root.num_children);
    // Validate Child 1
    em_network_node_t* clone_child1 = clone_root->child[0];
    ASSERT_NE(clone_child1, nullptr);
    EXPECT_STREQ(clone_child1->key, child1.key);
    EXPECT_EQ(clone_child1->display_info.collapsed, child1.display_info.collapsed);
    EXPECT_EQ(clone_child1->display_info.orig_node_ctr, child1.display_info.orig_node_ctr);
    EXPECT_EQ(clone_child1->type, child1.type);
    EXPECT_STREQ(clone_child1->value_str, child1.value_str);
    EXPECT_EQ(clone_child1->value_int, child1.value_int);
    // Validate Child 2
    em_network_node_t* clone_child2 = clone_root->child[1];
    ASSERT_NE(clone_child2, nullptr);
    EXPECT_STREQ(clone_child2->key, child2.key);
    EXPECT_EQ(clone_child2->display_info.collapsed, child2.display_info.collapsed);
    EXPECT_EQ(clone_child2->display_info.orig_node_ctr, child2.display_info.orig_node_ctr);
    EXPECT_EQ(clone_child2->type, child2.type);
    EXPECT_STREQ(clone_child2->value_str, child2.value_str);
    EXPECT_EQ(clone_child2->value_int, child2.value_int);
    em_net_node_t::free_network_tree(clone_root);
    std::cout << "Exiting clone_network_tree_root_with_multiple_children test" << std::endl;
}
/**
 * @brief Test that clone_network_tree correctly clones a network tree with one child and one grandchild.
 *
 * This test validates that the clone_network_tree API correctly performs a deep copy of a network tree structure composed of a root node with one child and one grandchild. It verifies that all node attributes—including key, display information, type, value, and the number of children—are maintained accurately in the cloned tree.
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
 * | 01 | Initialize the root node with specific attributes. | input: key = "root", display_info.collapsed = false, display_info.orig_node_ctr = 1, display_info.node_ctr = 1, display_info.node_pos = 0, type = em_network_node_data_type_obj, value_str = "root_val", value_int = 0, num_children = 1 | Root node is successfully created and properly initialized. | Should be successful |
 * | 02 | Initialize the child node with specific attributes and one child. | input: key = "child", display_info.collapsed = true, display_info.orig_node_ctr = 2, display_info.node_ctr = 2, display_info.node_pos = 1, type = em_network_node_data_type_string, value_str = "child_val", value_int = 10, num_children = 1 | Child node is successfully created and properly initialized. | Should be successful |
 * | 03 | Initialize the grandchild node with specific attributes. | input: key = "grandchild", display_info.collapsed = false, display_info.orig_node_ctr = 3, display_info.node_ctr = 3, display_info.node_pos = 0, type = em_network_node_data_type_number, value_str = "42", value_int = 42, num_children = 0 | Grandchild node is successfully created and properly initialized. | Should be successful |
 * | 04 | Set up the hierarchical tree by linking the child and grandchild nodes. | input: root.child[0] = pointer to child, child.child[0] = pointer to grandchild | Tree structure is correctly built with one child node linked to root and one grandchild node linked to the child. | Should be successful |
 * | 05 | Call clone_network_tree API to clone the network tree from the root node. | input: pointer to root node; output: pointer to clone_root | The API returns a non-null pointer to a cloned network tree with attributes matching the original. | Should Pass |
 * | 06 | Validate that the cloned root node's attributes match the original root node. | input: cloned root node attributes vs original root node attributes | All attributes of the cloned root node are equal to those of the original root node. | Should Pass |
 * | 07 | Validate that the cloned child node's attributes match the original child node. | input: cloned child node attributes vs original child node attributes | All attributes of the cloned child node are equal to those of the original child node. | Should Pass |
 * | 08 | Validate that the cloned grandchild node's attributes match the original grandchild node. | input: cloned grandchild node attributes vs original grandchild node attributes | All attributes of the cloned grandchild node are equal to those of the original grandchild node. | Should Pass |
 * | 09 | Free the memory allocated for the cloned network tree. | input: pointer to cloned network tree | The allocated memory for the cloned network tree is correctly freed without any memory leaks. | Should be successful |
 */
TEST(em_net_node_t, clone_network_tree_one_child_one_grandchild)
{
    std::cout << "Entering clone_network_tree_one_child_one_grandchild test" << std::endl;
    em_network_node_t root;
    memset(&root, 0, sizeof(root));
    strncpy(root.key, "root", sizeof(root.key));
    root.display_info.collapsed = false;
    root.display_info.orig_node_ctr = 1;
    root.display_info.node_ctr = 1;
    root.display_info.node_pos = 0;
    root.type = em_network_node_data_type_obj;
    strncpy(root.value_str, "root_val", sizeof(root.value_str));
    root.value_int = 0;
    root.num_children = 1;
    em_network_node_t child;
    memset(&child, 0, sizeof(child));
    strncpy(child.key, "child", sizeof(child.key));
    child.display_info.collapsed = true;
    child.display_info.orig_node_ctr = 2;
    child.display_info.node_ctr = 2;
    child.display_info.node_pos = 1;
    child.type = em_network_node_data_type_string;
    strncpy(child.value_str, "child_val", sizeof(child.value_str));
    child.value_int = 10;
    child.num_children = 1;
    em_network_node_t grandchild;
    memset(&grandchild, 0, sizeof(grandchild));
    strncpy(grandchild.key, "grandchild", sizeof(grandchild.key));
    grandchild.display_info.collapsed = false;
    grandchild.display_info.orig_node_ctr = 3;
    grandchild.display_info.node_ctr = 3;
    grandchild.display_info.node_pos = 0;
    grandchild.type = em_network_node_data_type_number;
    strncpy(grandchild.value_str, "42", sizeof(grandchild.value_str));
    grandchild.value_int = 42;
    grandchild.num_children = 0;
    child.child[0] = &grandchild;
    root.child[0] = &child;
    em_network_node_t* clone_root = em_net_node_t::clone_network_tree(&root);
    ASSERT_NE(clone_root, nullptr);
    EXPECT_EQ(clone_root->num_children, root.num_children);
    // Validate root
    EXPECT_STREQ(clone_root->key, root.key);
    EXPECT_EQ(clone_root->display_info.collapsed, root.display_info.collapsed);
    EXPECT_EQ(clone_root->display_info.orig_node_ctr, root.display_info.orig_node_ctr);
    EXPECT_EQ(clone_root->type, root.type);
    EXPECT_STREQ(clone_root->value_str, root.value_str);
    EXPECT_EQ(clone_root->value_int, root.value_int);
    // Validate child
    em_network_node_t* clone_child = clone_root->child[0];
    ASSERT_NE(clone_child, nullptr);
    EXPECT_STREQ(clone_child->key, child.key);
    EXPECT_EQ(clone_child->display_info.collapsed, child.display_info.collapsed);
    EXPECT_EQ(clone_child->display_info.orig_node_ctr, child.display_info.orig_node_ctr);
    EXPECT_EQ(clone_child->type, child.type);
    EXPECT_STREQ(clone_child->value_str, child.value_str);
    EXPECT_EQ(clone_child->value_int, child.value_int);
    EXPECT_EQ(clone_child->num_children, child.num_children);
    // Validate grandchild
    em_network_node_t* clone_grandchild = clone_child->child[0];
    ASSERT_NE(clone_grandchild, nullptr);
    EXPECT_STREQ(clone_grandchild->key, grandchild.key);
    EXPECT_EQ(clone_grandchild->display_info.collapsed, grandchild.display_info.collapsed);
    EXPECT_EQ(clone_grandchild->display_info.orig_node_ctr, grandchild.display_info.orig_node_ctr);
    EXPECT_EQ(clone_grandchild->type, grandchild.type);
    EXPECT_STREQ(clone_grandchild->value_str, grandchild.value_str);
    EXPECT_EQ(clone_grandchild->value_int, grandchild.value_int);
    EXPECT_EQ(clone_grandchild->num_children, grandchild.num_children);
    em_net_node_t::free_network_tree(clone_root);
    std::cout << "Exiting clone_network_tree_one_child_one_grandchild test" << std::endl;
}
/**
 * @brief Verify correct cloning of a multi-level network tree
 *
 * This test creates a multi-level network tree consisting of a root node with two children, where one child further contains a grandchild. It invokes the clone_network_tree API and verifies that each node in the cloned tree retains the exact properties of the original, ensuring that the clone operation preserves both node data and hierarchical structure.
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
 * | 01 | Initialize root node with given properties | root.key = "root", root.display_info.collapsed = false, root.display_info.orig_node_ctr = 10, root.display_info.node_ctr = 10, root.display_info.node_pos = 0, root.type = em_network_node_data_type_obj, root.value_str = "root_val", root.value_int = 0, root.num_children = 2 | Root node is properly initialized with correct values | Should be successful |
 * | 02 | Initialize child1 node with given properties including nested grandchild | child1.key = "child1", child1.display_info.collapsed = true, child1.display_info.orig_node_ctr = 5, child1.display_info.node_ctr = 5, child1.display_info.node_pos = 1, child1.type = em_network_node_data_type_string, child1.value_str = "child1_val", child1.value_int = 1, child1.num_children = 1; grandchild1.key = "grandchild1", grandchild1.display_info.collapsed = false, grandchild1.display_info.orig_node_ctr = 2, grandchild1.display_info.node_ctr = 2, grandchild1.display_info.node_pos = 0, grandchild1.type = em_network_node_data_type_number, grandchild1.value_str = "42", grandchild1.value_int = 42, grandchild1.num_children = 0 | Child1 and its grandchild are properly initialized and linked | Should be successful |
 * | 03 | Initialize child2 node with given properties | child2.key = "child2", child2.display_info.collapsed = false, child2.display_info.orig_node_ctr = 3, child2.display_info.node_ctr = 3, child2.display_info.node_pos = 2, child2.type = em_network_node_data_type_array_obj, child2.value_str = "child2_val", child2.value_int = 2, child2.num_children = 0 | Child2 is properly initialized | Should be successful |
 * | 04 | Invoke clone_network_tree on root node | Input: Pointer to the initialized root node tree | A cloned network tree with identical structure and properties to the original | Should Pass |
 * | 05 | Verify properties of cloned root, child1, grandchild1, and child2 | Input: Cloned tree nodes compared against original nodes values | All corresponding node properties match between the cloned and original tree | Should Pass |
 * | 06 | Free the cloned network tree using free_network_tree | Input: Cloned network tree pointer passed to free_network_tree | The cloned network tree is freed without errors | Should be successful |
 */
TEST(em_net_node_t, clone_network_tree_multi_level_tree)
{
    std::cout << "Entering clone_network_tree_multi_level_tree test" << std::endl;
    em_network_node_t root;
    memset(&root, 0, sizeof(em_network_node_t));
    strncpy(root.key, "root", sizeof(root.key));
    root.display_info.collapsed = false;
    root.display_info.orig_node_ctr = 10;
    root.display_info.node_ctr = 10;
    root.display_info.node_pos = 0;
    root.type = em_network_node_data_type_obj;
    strncpy(root.value_str, "root_val", sizeof(root.value_str));
    root.value_int = 0;
    root.num_children = 2;
    em_network_node_t child1;
    memset(&child1, 0, sizeof(em_network_node_t));
    strncpy(child1.key, "child1", sizeof(child1.key));
    child1.display_info.collapsed = true;
    child1.display_info.orig_node_ctr = 5;
    child1.display_info.node_ctr = 5;
    child1.display_info.node_pos = 1;
    child1.type = em_network_node_data_type_string;
    strncpy(child1.value_str, "child1_val", sizeof(child1.value_str));
    child1.value_int = 1;
    child1.num_children = 1;
    em_network_node_t grandchild1;
    memset(&grandchild1, 0, sizeof(em_network_node_t));
    strncpy(grandchild1.key, "grandchild1", sizeof(grandchild1.key));
    grandchild1.display_info.collapsed = false;
    grandchild1.display_info.orig_node_ctr = 2;
    grandchild1.display_info.node_ctr = 2;
    grandchild1.display_info.node_pos = 0;
    grandchild1.type = em_network_node_data_type_number;
    strncpy(grandchild1.value_str, "42", sizeof(grandchild1.value_str));
    grandchild1.value_int = 42;
    grandchild1.num_children = 0;
    child1.child[0] = &grandchild1;
    em_network_node_t child2;
    memset(&child2, 0, sizeof(em_network_node_t));
    strncpy(child2.key, "child2", sizeof(child2.key));
    child2.display_info.collapsed = false;
    child2.display_info.orig_node_ctr = 3;
    child2.display_info.node_ctr = 3;
    child2.display_info.node_pos = 2;
    child2.type = em_network_node_data_type_array_obj;
    strncpy(child2.value_str, "child2_val", sizeof(child2.value_str));
    child2.value_int = 2;
    child2.num_children = 0;
    root.child[0] = &child1;
    root.child[1] = &child2;
    em_network_node_t* clone_root = em_net_node_t::clone_network_tree(&root);
    ASSERT_NE(clone_root, nullptr);
    std::cout << "Cloned root node key: " << clone_root->key << std::endl;
    // Check root node fields
    EXPECT_STREQ(clone_root->key, root.key);
    EXPECT_EQ(clone_root->display_info.collapsed, root.display_info.collapsed);
    EXPECT_EQ(clone_root->display_info.orig_node_ctr, root.display_info.orig_node_ctr);
    EXPECT_EQ(clone_root->display_info.node_ctr, root.display_info.node_ctr);
    EXPECT_EQ(clone_root->display_info.node_pos, root.display_info.node_pos);
    EXPECT_EQ(clone_root->type, root.type);
    EXPECT_STREQ(clone_root->value_str, root.value_str);
    EXPECT_EQ(clone_root->value_int, root.value_int);
    EXPECT_EQ(clone_root->num_children, root.num_children);
    // Check first child (child1)
    em_network_node_t* clone_child1 = clone_root->child[0];
    ASSERT_NE(clone_child1, nullptr);
    std::cout << "Cloned child1 key: " << clone_child1->key << std::endl;
    EXPECT_STREQ(clone_child1->key, child1.key);
    EXPECT_EQ(clone_child1->display_info.collapsed, child1.display_info.collapsed);
    EXPECT_EQ(clone_child1->display_info.orig_node_ctr, child1.display_info.orig_node_ctr);
    EXPECT_EQ(clone_child1->display_info.node_ctr, child1.display_info.node_ctr);
    EXPECT_EQ(clone_child1->display_info.node_pos, child1.display_info.node_pos);
    EXPECT_EQ(clone_child1->type, child1.type);
    EXPECT_STREQ(clone_child1->value_str, child1.value_str);
    EXPECT_EQ(clone_child1->value_int, child1.value_int);
    EXPECT_EQ(clone_child1->num_children, child1.num_children);
    // Check grandchild of child1
    em_network_node_t* clone_grandchild1 = clone_child1->child[0];
    ASSERT_NE(clone_grandchild1, nullptr);
    std::cout << "Cloned grandchild1 key: " << clone_grandchild1->key << std::endl;
    EXPECT_STREQ(clone_grandchild1->key, grandchild1.key);
    EXPECT_EQ(clone_grandchild1->display_info.collapsed, grandchild1.display_info.collapsed);
    EXPECT_EQ(clone_grandchild1->display_info.orig_node_ctr, grandchild1.display_info.orig_node_ctr);
    EXPECT_EQ(clone_grandchild1->display_info.node_ctr, grandchild1.display_info.node_ctr);
    EXPECT_EQ(clone_grandchild1->display_info.node_pos, grandchild1.display_info.node_pos);
    EXPECT_EQ(clone_grandchild1->type, grandchild1.type);
    EXPECT_STREQ(clone_grandchild1->value_str, grandchild1.value_str);
    EXPECT_EQ(clone_grandchild1->value_int, grandchild1.value_int);
    EXPECT_EQ(clone_grandchild1->num_children, grandchild1.num_children);
    // Check second child (child2)
    em_network_node_t* clone_child2 = clone_root->child[1];
    ASSERT_NE(clone_child2, nullptr);
    std::cout << "Cloned child2 key: " << clone_child2->key << std::endl;
    EXPECT_STREQ(clone_child2->key, child2.key);
    EXPECT_EQ(clone_child2->display_info.collapsed, child2.display_info.collapsed);
    EXPECT_EQ(clone_child2->display_info.orig_node_ctr, child2.display_info.orig_node_ctr);
    EXPECT_EQ(clone_child2->display_info.node_ctr, child2.display_info.node_ctr);
    EXPECT_EQ(clone_child2->display_info.node_pos, child2.display_info.node_pos);
    EXPECT_EQ(clone_child2->type, child2.type);
    EXPECT_STREQ(clone_child2->value_str, child2.value_str);
    EXPECT_EQ(clone_child2->value_int, child2.value_int);
    EXPECT_EQ(clone_child2->num_children, child2.num_children);
    em_net_node_t::free_network_tree(clone_root);
    std::cout << "Exiting clone_network_tree_multi_level_tree test" << std::endl;
}
/**
 * @brief Verify that clone_network_tree correctly clones a network node for each enum type.
 *
 * This test iterates over an array of network node enum values. For each value, it initializes a network node object with fixed attributes and the current enum value, clones it using the clone_network_tree API, and then validates that all attributes in the cloned object match the original. This ensures that the cloning functionality correctly handles different enum values and preserves the node's properties.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 007@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize an array of enum values and prepare a network node with default properties. | enum_values = em_network_node_data_type_invalid, em_network_node_data_type_false, em_network_node_data_type_true, em_network_node_data_type_null, em_network_node_data_type_number, em_network_node_data_type_string, em_network_node_data_type_obj, em_network_node_data_type_array_obj, em_network_node_data_type_array_str, em_network_node_data_type_array_num, em_network_node_data_type_raw | Array is initialized with 11 enum values. | Should be successful |
 * | 02 | For each enum value, create a network node, clone it using clone_network_tree, and verify that all properties in the cloned node match the original node. | node.key = "enum_test", display_info.collapsed = false, display_info.orig_node_ctr = 0, display_info.node_ctr = 0, display_info.node_pos = 0, node.type = [each enum value], node.value_str = "test", node.value_int = 0, node.num_children = 0 | clone != nullptr; key, display_info, type, value_str, value_int, and num_children in the clone must exactly match those in the original node. | Should Pass |
 */
TEST(em_net_node_t, clone_network_tree_enum_loop)
{
    std::cout << "Entering clone_network_tree_enum_loop test" << std::endl;
    em_network_node_data_type_t enum_values[] = {
        em_network_node_data_type_invalid,
        em_network_node_data_type_false,
        em_network_node_data_type_true,
        em_network_node_data_type_null,
        em_network_node_data_type_number,
        em_network_node_data_type_string,
        em_network_node_data_type_obj,
        em_network_node_data_type_array_obj,
        em_network_node_data_type_array_str,
        em_network_node_data_type_array_num,
        em_network_node_data_type_raw
    };
    const int num_enum_values = sizeof(enum_values) / sizeof(enum_values[0]);
    for (int i = 0; i < num_enum_values; i++) {
        em_network_node_t node;
        memset(&node, 0, sizeof(em_network_node_t));
        strncpy(node.key, "enum_test", sizeof(node.key));
        node.display_info.collapsed = false;
        node.display_info.orig_node_ctr = 0;
        node.display_info.node_ctr = 0;
        node.display_info.node_pos = 0;
        node.type = enum_values[i];
        strncpy(node.value_str, "test", sizeof(node.value_str));
        node.value_int = 0;
        node.num_children = 0;
        em_network_node_t* clone = em_net_node_t::clone_network_tree(&node);
        ASSERT_NE(clone, nullptr);
        EXPECT_STREQ(clone->key, node.key);
        EXPECT_EQ(clone->display_info.collapsed, node.display_info.collapsed);
        EXPECT_EQ(clone->display_info.orig_node_ctr, node.display_info.orig_node_ctr);
        EXPECT_EQ(clone->display_info.node_ctr, node.display_info.node_ctr);
        EXPECT_EQ(clone->display_info.node_pos, node.display_info.node_pos);
        EXPECT_EQ(clone->type, node.type);
        EXPECT_STREQ(clone->value_str, node.value_str);
        EXPECT_EQ(clone->value_int, node.value_int);
        EXPECT_EQ(clone->num_children, node.num_children);
        em_net_node_t::free_network_tree(clone);
    }
    std::cout << "Exiting clone_network_tree_enum_loop test" << std::endl;
}
/**
 * @brief Test cloning of a network tree with maximum allowable children.
 *
 * This test verifies the clone_network_tree API when the root node contains the maximum number of children (EM_MAX_DM_CHILDREN). It ensures that all fields of the root node and each child node are correctly cloned and that the cloned network tree mirrors the original tree structure.
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
 * | 01 | Initialize the root node with defined values for the max children test | root.key = "max_children_root", root.display_info.collapsed = false, root.display_info.orig_node_ctr = 100, root.display_info.node_ctr = 100, root.display_info.node_pos = 0, root.type = em_network_node_data_type_obj, root.value_str = "max_root", root.value_int = 0, root.num_children = EM_MAX_DM_CHILDREN | Root node initialized with proper values | Should be successful |
 * | 02 | Create and initialize maximum allowable children nodes and attach them to the root node | For each child[i]: key = "child_i", display_info.collapsed = false, display_info.orig_node_ctr = i, display_info.node_ctr = i, display_info.node_pos = i, type = em_network_node_data_type_string, value_str = "child_val", value_int = i, num_children = 0 | All children nodes initialized and linked to root | Should be successful |
 * | 03 | Invoke clone_network_tree API to clone the network tree | Input: root node with children nodes | Returns non-null pointer to cloned network tree | Should Pass |
 * | 04 | Validate cloned root node properties against the original root node | Compare clone_root->key, display_info.collapsed, display_info.orig_node_ctr, display_info.node_ctr, display_info.node_pos, type, value_str, value_int, num_children | Cloned root node fields match the original | Should Pass |
 * | 05 | Validate each cloned child's properties with expected values | For each cloned child[i]: key = "child_i", display_info.collapsed = false, display_info.orig_node_ctr = i, display_info.node_ctr = i, display_info.node_pos = i, type = em_network_node_data_type_string, value_str = "child_val", value_int = i, num_children = 0 | All cloned children properties match the expected values | Should Pass |
 * | 06 | Free the cloned network tree to ensure no memory leak | Call em_net_node_t::free_network_tree(clone_root) with clone_root pointer | Cloned network tree memory is freed successfully | Should be successful |
 */
TEST(em_net_node_t, clone_network_tree_max_children)
{
    std::cout << "Entering clone_network_tree_max_children test" << std::endl;
    em_network_node_t root;
    memset(&root, 0, sizeof(em_network_node_t));
    strncpy(root.key, "max_children_root", sizeof(root.key));
    root.display_info.collapsed = false;
    root.display_info.orig_node_ctr = 100;
    root.display_info.node_ctr = 100;
    root.display_info.node_pos = 0;
    root.type = em_network_node_data_type_obj;
    strncpy(root.value_str, "max_root", sizeof(root.value_str));
    root.value_int = 0;
    root.num_children = EM_MAX_DM_CHILDREN;
    // Create maximum allowable children
    em_network_node_t children[EM_MAX_DM_CHILDREN];
    for (unsigned int i = 0; i < EM_MAX_DM_CHILDREN; i++) {
        memset(&children[i], 0, sizeof(em_network_node_t));
        char keyBuffer[128];
        std::snprintf(keyBuffer, sizeof(keyBuffer), "child_%u", i);
        strncpy(children[i].key, keyBuffer, sizeof(children[i].key));
        children[i].display_info.collapsed = false;
        children[i].display_info.orig_node_ctr = i;
        children[i].display_info.node_ctr = i;
        children[i].display_info.node_pos = i;
        children[i].type = em_network_node_data_type_string;
        strncpy(children[i].value_str, "child_val", sizeof(children[i].value_str));
        children[i].value_int = i;
        children[i].num_children = 0;
        root.child[i] = &children[i];
    }
    em_network_node_t* clone_root = em_net_node_t::clone_network_tree(&root);
    ASSERT_NE(clone_root, nullptr);
    // Verify root node fields
    EXPECT_STREQ(clone_root->key, root.key);
    EXPECT_EQ(clone_root->display_info.collapsed, root.display_info.collapsed);
    EXPECT_EQ(clone_root->display_info.orig_node_ctr, root.display_info.orig_node_ctr);
    EXPECT_EQ(clone_root->display_info.node_ctr, root.display_info.node_ctr);
    EXPECT_EQ(clone_root->display_info.node_pos, root.display_info.node_pos);
    EXPECT_EQ(clone_root->type, root.type);
    EXPECT_STREQ(clone_root->value_str, root.value_str);
    EXPECT_EQ(clone_root->value_int, root.value_int);
    EXPECT_EQ(clone_root->num_children, root.num_children);
    // Verify each child
    for (unsigned int i = 0; i < EM_MAX_DM_CHILDREN; i++) {
        em_network_node_t* clone_child = clone_root->child[i];
        ASSERT_NE(clone_child, nullptr);
        char expectedKey[128];
        std::snprintf(expectedKey, sizeof(expectedKey), "child_%u", i);
        std::cout << "Cloned child[" << i << "] key: " << clone_child->key << std::endl;
        EXPECT_STREQ(clone_child->key, expectedKey);
        EXPECT_EQ(clone_child->display_info.collapsed, false);
        EXPECT_EQ(clone_child->display_info.orig_node_ctr, i);
        EXPECT_EQ(clone_child->display_info.node_ctr, i);
        EXPECT_EQ(clone_child->display_info.node_pos, i);
        EXPECT_EQ(clone_child->type, em_network_node_data_type_string);
        EXPECT_STREQ(clone_child->value_str, "child_val");
        EXPECT_EQ(clone_child->value_int, i);
        EXPECT_EQ(clone_child->num_children, 0);
    }
    em_net_node_t::free_network_tree(clone_root);
    std::cout << "Exiting clone_network_tree_max_children test" << std::endl;
}
/**
 * @brief Test clone_network_tree_for_display for a single node when collapse is true
 *
 * This test verifies that cloning a network tree with a single node using the collapse true option
 * correctly produces a clone with no children. It sets up a root node, invokes the clone function,
 * and then asserts that the returned clone is not null and that it contains zero children.
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
 * | Variation / Step | Description                                                             | Test Data                                                                                     | Expected Result                                         | Notes         |
 * | :--------------: | ----------------------------------------------------------------------- | --------------------------------------------------------------------------------------------- | ------------------------------------------------------- | ------------- |
 * | 01               | Setup the root network node with key, value, integer value and display info | root->key = "root", root->value_str = "value", root->value_int = 1, root->display_info.node_ctr = 0 | Root node is properly initialized                      | Should be successful |
 * | 02               | Invoke clone_network_tree_for_display with collapse set to true          | API inputs: root pointer, disNode (all fields zeroed), index = 0, collapse = true, ctr pointer | Returns a non-null clone pointer                        | Should Pass   |
 * | 03               | Validate that the cloned node has zero children                          | output validation: clone->num_children, expected value = 0                                     | clone->num_children equals 0                            | Should Pass   |
 */
TEST(em_net_node_t, clone_network_tree_for_display_single_node_collapse_true) {
    std::cout << "Entering clone_network_tree_for_display_single_node_collapse_true test" << std::endl;
    em_net_node_t node;
    em_network_node_t* root = reinterpret_cast<em_network_node_t*>(malloc(sizeof(*root)));
    memset(root, 0, sizeof(*root));
    strncpy(root->key, "root", sizeof(root->key)-1);
    strncpy(root->value_str, "value", sizeof(root->value_str)-1);
    root->value_int = 1;
    root->display_info.node_ctr = 0;
    em_network_node_t disNode;
    memset(&disNode, 0, sizeof(disNode));
    unsigned int ctr = 0;
    em_network_node_t* clone =
        node.clone_network_tree_for_display(root, &disNode, 0, true, &ctr);
    ASSERT_NE(clone, nullptr);
    EXPECT_EQ(clone->num_children, 0);
    em_net_node_t::free_network_tree(clone);
    free(root);
    std::cout << "Exiting clone_network_tree_for_display_single_node_collapse_true test" << std::endl;
}
/**
 * @brief Verify that clone_network_tree_for_display returns a proper clone with zero children when invoked with a single node and collapse flag set to false
 *
 * This test creates a single node network tree and calls clone_network_tree_for_display with collapse flag as false, ensuring that the cloned node has no children. The test verifies that the clone is not null and that the number of children in the clone is zero.
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
 * | Variation / Step | Description                                                                                      | Test Data                                                                     | Expected Result                                                     | Notes       |
 * | :--------------: | ------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------- | ------------------------------------------------------------------- | ----------- |
 * | 01               | Initialize a single node with key "root" and zero children, then call clone_network_tree_for_display with collapse flag as false | root->key = "root", root->num_children = 0, disNode zero initialized, max value = 999, collapse flag = false, counter = 0 | API returns a non-null clone with 0 children, assertions pass | Should Pass |
 */
TEST(em_net_node_t, clone_network_tree_for_display_single_node_collapse_false) {
    std::cout << "Entering clone_network_tree_for_display_single_node_collapse_false test" << std::endl;
    em_net_node_t node;
    em_network_node_t* root = reinterpret_cast<em_network_node_t*>(malloc(sizeof(*root)));
    memset(root, 0, sizeof(*root));
    strncpy(root->key, "root", sizeof(root->key)-1);
    root->num_children = 0;
    em_network_node_t disNode;
    memset(&disNode, 0, sizeof(disNode));
    unsigned int ctr = 0;
    em_network_node_t* clone =
        node.clone_network_tree_for_display(root, &disNode, 999, false, &ctr);
    ASSERT_NE(clone, nullptr);
    EXPECT_EQ(clone->num_children, 0);
    em_net_node_t::free_network_tree(clone);
    free(root);
    std::cout << "Exiting clone_network_tree_for_display_single_node_collapse_false test" << std::endl;
}
/**
 * @brief Test clone_network_tree_for_display with a single node containing a result child.
 *
 * This test verifies the functionality of the clone_network_tree_for_display API when provided with a network tree that includes a single node having a child node labeled "Result". The objective is to ensure that the clone is successfully created, that the returned clone is not null, and that it correctly omits the result child in the cloned tree.
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
 * | Variation / Step | Description | Test Data | Expected Result | Notes |@n
 * | :----: | --------- | ---------- |-------------- | ----- |@n
 * | 01 | Invoke clone_network_tree_for_display API on a network tree with one node having a "Result" child | root.key = "root", root.num_children = 1, child[0].key = "Result", disNode = zeroed, ctr = pointer to unsigned int, param = 999, flag = true | Function returns a non-null cloned node with num_children equal to 0, as verified by assertions | Should Pass |
 */
TEST(em_net_node_t, clone_network_tree_for_display_single_node_with_result_child) {
    std::cout << "Entering clone_network_tree_for_display_single_node_with_result_child test" << std::endl;
    em_net_node_t node;
    em_network_node_t* root = reinterpret_cast<em_network_node_t*>(malloc(sizeof(*root)));
    memset(root, 0, sizeof(*root));
    strncpy(root->key, "root", sizeof(root->key)-1);
    em_network_node_t* resultChild = reinterpret_cast<em_network_node_t*>(malloc(sizeof(*resultChild)));
    memset(resultChild, 0, sizeof(*resultChild));
    strncpy(resultChild->key, "Result", sizeof(resultChild->key)-1);
    root->child[0] = resultChild;
    root->num_children = 1;
    em_network_node_t disNode;
    memset(&disNode, 0, sizeof(disNode));
    unsigned int ctr = 0;
    em_network_node_t* clone =
        node.clone_network_tree_for_display(root, &disNode, 999, true, &ctr);
    ASSERT_NE(clone, nullptr);
    EXPECT_EQ(clone->num_children, 0);
    em_net_node_t::free_network_tree(clone);
    free(resultChild);
    free(root);
    std::cout << "Exiting clone_network_tree_for_display_single_node_with_result_child test" << std::endl;
}
/**
 * @brief Verify that clone_network_tree_for_display creates a proper deep clone of a multi-level network tree when collapse flag is false
 *
 * This test sets up a network tree with a root having one child and invokes clone_network_tree_for_display with the collapse flag set to false.
 * It verifies that the cloned tree maintains the structure of the original tree, ensuring that all nodes are correctly cloned and accessible.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 012@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                                                             | Test Data                                                                                                                    | Expected Result                                                                                                                                           | Notes         |
 * | :--------------: | ------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------- |
 * | 01               | Initialize a network tree with a root node ("root") having one child ("child") and set up helper object | orig_node: root with key "root", num_children=1; child: node with key "child", num_children=0; parameters: dis_node=nullptr, int_param=999, collapse flag=false, ctr pointer | Network tree is properly allocated, and all node values are initialized as expected                                                                           | Should be successful |
 * | 02               | Invoke clone_network_tree_for_display with the initialized tree and verify the cloned structure           | Input: orig_node (root), dis_node=nullptr, int_param=999, collapse flag=false, ctr pointer; Output: clone pointer                | API returns a valid clone where clone is not nullptr, clone->num_children equals 1, clone->child[0] is not nullptr, and clone->child[0]->key equals "child" | Should Pass   |
 * | 03               | Free the allocated memory for the cloned network tree and the original nodes                              | Free clone, child, and root pointers                                                                                         | Memory is free'd without error                                                                                                                              | Should be successful |
 */
TEST(em_net_node_t, clone_multi_level_tree_collapse_false) {
    std::cout << "Entering clone_multi_level_tree_collapse_false test" << std::endl;

    em_net_node_t helper;

    em_network_node_t* root = reinterpret_cast<em_network_node_t*>(malloc(sizeof(*root)));
    memset(root, 0, sizeof(*root));
    strncpy(root->key, "root", sizeof(root->key)-1);
    root->num_children = 1;

    em_network_node_t* child = reinterpret_cast<em_network_node_t*>(malloc(sizeof(*child)));
    memset(child, 0, sizeof(*child));
    strncpy(child->key, "child", sizeof(child->key)-1);
    root->child[0] = child;
    child->num_children = 0;

    unsigned int ctr = 0;

    em_network_node_t* clone =
        helper.clone_network_tree_for_display(root, nullptr, 999, false, &ctr);

    ASSERT_NE(clone, nullptr);
    EXPECT_EQ(clone->num_children, 1);
    ASSERT_NE(clone->child[0], nullptr);
    EXPECT_STREQ(clone->child[0]->key, "child");

    em_net_node_t::free_network_tree(clone);
    free(child);
    free(root);

    std::cout << "Exiting clone_multi_level_tree_collapse_false test" << std::endl;
}
/**
 * @brief Verify that cloning with a null original node returns nullptr
 *
 * This test verifies that when a null original network node is provided to the 
 * clone_network_tree_for_display API, the function correctly returns a nullptr.
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
 * | Variation / Step | Description                                                                                  | Test Data                                                       | Expected Result                                                        | Notes      |
 * | :--------------: | -------------------------------------------------------------------------------------------- | --------------------------------------------------------------- | ---------------------------------------------------------------------- | ---------- |
 * | 01               | Invoke clone_network_tree_for_display using a null original network node to verify nullptr is returned | original node = nullptr, second parameter = nullptr, third parameter = 0, fourth parameter = true, counter pointer = &ctr | API returns nullptr and the ASSERT_EQ(clone, nullptr) passes             | Should Pass |
 */
TEST(em_net_node_t, clone_null_orig_node) {
    std::cout << "Entering clone_null_orig_node test" << std::endl;
    em_net_node_t helper;
    unsigned int ctr = 0;
    em_network_node_t* clone =
        helper.clone_network_tree_for_display(nullptr, nullptr, 0, true, &ctr);
    ASSERT_EQ(clone, nullptr);
    std::cout << "Exiting clone_null_orig_node test" << std::endl;
}
/**
 * @brief Validate clone_network_tree_for_display with a null display counter.
 *
 * This test verifies that the clone_network_tree_for_display method correctly clones a network node initialized with key "root" when the display counter parameter is null. The test confirms that the returned clone is not null and that its number of children is zero.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 014@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                                                | Test Data                                                                                      | Expected Result                                                       | Notes       |
 * | :----:           | ------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------- | --------------------------------------------------------------------- | ----------- |
 * | 01               | Invoke clone_network_tree_for_display on a node with key "root" with a null display counter  | root->key = "root", additional parameter = nullptr, counter = 0, flag = true, extra parameter = nullptr | Returns a non-null clone with num_children equal to 0; assertions pass | Should Pass |
 */
TEST(em_net_node_t, clone_null_node_display_ctr) {
    std::cout << "Entering clone_null_node_display_ctr test" << std::endl;
    em_net_node_t helper;
    em_network_node_t* root = reinterpret_cast<em_network_node_t*>(malloc(sizeof(*root)));
    memset(root, 0, sizeof(*root));
    strncpy(root->key, "root", sizeof(root->key)-1);
    root->num_children = 0;
    em_network_node_t* clone =
        helper.clone_network_tree_for_display(root, nullptr, 0, true, nullptr);
    ASSERT_NE(clone, nullptr);
    EXPECT_EQ(clone->num_children, 0);
    em_net_node_t::free_network_tree(clone);
    free(root);
    std::cout << "Exiting clone_null_node_display_ctr test" << std::endl;
}
/**
 * @brief Validate the behavior of free_network_tree when provided with a null input
 *
 * This test verifies that passing a null pointer to the free_network_tree API results in an exception being thrown. The objective is to ensure that the function handles invalid (null) input correctly by raising an exception, which is critical for robust error handling.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 015
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                     | Test Data                                   | Expected Result                                              | Notes       |
 * | :----:           | ------------------------------------------------|---------------------------------------------|--------------------------------------------------------------|-------------|
 * | 01               | Call free_network_tree with a null input pointer | input: ptr = nullptr                        | Exception is thrown as per the API specification             | Should Pass |
 */
TEST(em_net_node_t, free_network_tree_null_input) {
    std::cout << "Entering free_network_tree_null_input test" << std::endl;
    EXPECT_ANY_THROW({
        em_net_node_t::free_network_tree(nullptr);
    });
    std::cout << "Exiting free_network_tree_null_input test" << std::endl;
}
/**
 * @brief Test free_network_tree API for a single node with no children.
 *
 * This test verifies that the API correctly frees memory for a network node that does not have any children.
 * The test creates a node with valid key, value and display information, sets the number of children to 0,
 * and ensures that calling free_network_tree does not throw any exceptions.
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
 * | Variation / Step | Description                                                                                                   | Test Data                                                                                                                                                                                                                                                   | Expected Result                                  | Notes      |
 * | :--------------: | ------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------ | ---------- |
 * | 01               | Initialize a network node with valid data and no children, then invoke free_network_tree on this node.         | node->key = single_node, node->value_str = value_single, display_info.collapsed = false, display_info.orig_node_ctr = 1, display_info.node_ctr = 1, display_info.node_pos = 0, type = em_network_node_data_type_string, value_int = 100, num_children = 0 | No exception is thrown during the API call.      | Should Pass|
 */
TEST(em_net_node_t, free_network_tree_single_node_no_children) {
    std::cout << "Entering free_network_tree_single_node_no_children test" << std::endl;
    em_network_node_t* node = reinterpret_cast<em_network_node_t*>(malloc(sizeof(em_network_node_t)));
    memset(node, 0, sizeof(em_network_node_t));
    const char *key = "single_node";
    strncpy(node->key, key, sizeof(node->key));
    const char *value = "value_single";
    strncpy(node->value_str, value, sizeof(node->value_str));
    node->display_info.collapsed = false;
    node->display_info.orig_node_ctr = 1;
    node->display_info.node_ctr = 1;
    node->display_info.node_pos = 0;
    node->type = em_network_node_data_type_string;
    node->value_int = 100;
    node->num_children = 0;
    for (unsigned int i = 0; i < EM_MAX_DM_CHILDREN; i++) {
        node->child[i] = nullptr;
    }
    EXPECT_NO_THROW({
        em_net_node_t::free_network_tree(node);
    });
    std::cout << "Exiting free_network_tree_single_node_no_children test" << std::endl;
}
/**
 * @brief Test to verify that the free_network_tree API correctly frees a multi-level network tree.
 *
 * This test constructs a multi-level network node structure that includes a root node with two child nodes, where one child has two grandchildren. The primary objective is to ensure that the free_network_tree function properly deallocates the entire hierarchical tree without throwing any exceptions.
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
 * | :--------------: | ----------- | --------- | --------------- | ----- |
 * | 01 | Initialize a multi-level network tree consisting of a root node with two children, where one child has two grandchildren. | root.key = "root", root.value_str = "root_value", root.display_info.collapsed = true, root.display_info.orig_node_ctr = 1, root.display_info.node_ctr = 1, root.display_info.node_pos = 0, root.type = em_network_node_data_type_obj, root.value_int = 1, root.num_children = 2; child1.key = "child1", child1.value_str = "child1_value", child1.display_info.collapsed = false, child1.display_info.orig_node_ctr = 2, child1.display_info.node_ctr = 2, child1.display_info.node_pos = 0, child1.type = em_network_node_data_type_obj, child1.value_int = 10, child1.num_children = 2; grandchild1.key = "grandchild1", grandchild1.value_str = "grandchild1_value", grandchild1.display_info.collapsed = false, grandchild1.display_info.orig_node_ctr = 3, grandchild1.display_info.node_ctr = 3, grandchild1.display_info.node_pos = 0, grandchild1.type = em_network_node_data_type_string, grandchild1.value_int = 100; grandchild2.key = "grandchild2", grandchild2.value_str = "grandchild2_value", grandchild2.display_info.collapsed = false, grandchild2.display_info.orig_node_ctr = 4, grandchild2.display_info.node_ctr = 4, grandchild2.display_info.node_pos = 1, grandchild2.type = em_network_node_data_type_number, grandchild2.value_int = 200; child2.key = "child2", child2.value_str = "child2_value", child2.display_info.collapsed = false, child2.display_info.orig_node_ctr = 5, child2.display_info.node_ctr = 5, child2.display_info.node_pos = 1, child2.type = em_network_node_data_type_null, child2.value_int = 300 | The network tree is successfully created in memory with proper initializations. | Should be successful |
 * | 02 | Invoke the free_network_tree API using the constructed tree and verify no exceptions are thrown. | API call: free_network_tree(root) with the previously allocated tree pointer. | free_network_tree should complete without throwing any exceptions (EXPECT_NO_THROW). | Should Pass |
 */
TEST(em_net_node_t, free_network_tree_multiple_levels) {
    std::cout << "Entering free_network_tree_multiple_levels test" << std::endl;
    em_network_node_t* root = reinterpret_cast<em_network_node_t*>(malloc(sizeof(*root)));
    memset(root, 0, sizeof(em_network_node_t));
    strncpy(root->key, "root", sizeof(root->key));
    strncpy(root->value_str, "root_value", sizeof(root->value_str));
    root->display_info.collapsed = true;
    root->display_info.orig_node_ctr = 1;
    root->display_info.node_ctr = 1;
    root->display_info.node_pos = 0;
    root->type = em_network_node_data_type_obj;
    root->value_int = 1;
    root->num_children = 2;
    for (unsigned int i = 0; i < EM_MAX_DM_CHILDREN; i++) {
        root->child[i] = nullptr;
    }
    // Child1
    em_network_node_t* child1 = reinterpret_cast<em_network_node_t*>(malloc(sizeof(em_network_node_t)));
    memset(child1, 0, sizeof(em_network_node_t));
    strncpy(child1->key, "child1", sizeof(child1->key));
    strncpy(child1->value_str, "child1_value", sizeof(child1->value_str));
    child1->display_info.collapsed = false;
    child1->display_info.orig_node_ctr = 2;
    child1->display_info.node_ctr = 2;
    child1->display_info.node_pos = 0;
    child1->type = em_network_node_data_type_obj;
    child1->value_int = 10;
    child1->num_children = 2;
    for (unsigned int i = 0; i < EM_MAX_DM_CHILDREN; i++) child1->child[i] = nullptr;
    // Grandchildren
    em_network_node_t *grandchild1 = reinterpret_cast<em_network_node_t*>(malloc(sizeof(em_network_node_t)));
    memset(grandchild1, 0, sizeof(em_network_node_t));
    strncpy(grandchild1->key, "grandchild1", sizeof(grandchild1->key));
    strncpy(grandchild1->value_str, "grandchild1_value", sizeof(grandchild1->value_str));
    grandchild1->display_info.collapsed = false;
    grandchild1->display_info.orig_node_ctr = 3;
    grandchild1->display_info.node_ctr = 3;
    grandchild1->display_info.node_pos = 0;
    grandchild1->type = em_network_node_data_type_string;
    grandchild1->value_int = 100;
    em_network_node_t *grandchild2 = reinterpret_cast<em_network_node_t*>(malloc(sizeof(em_network_node_t)));
    memset(grandchild2, 0, sizeof(em_network_node_t));
    strncpy(grandchild2->key, "grandchild2", sizeof(grandchild2->key));
    strncpy(grandchild2->value_str, "grandchild2_value", sizeof(grandchild2->value_str));
    grandchild2->display_info.collapsed = false;
    grandchild2->display_info.orig_node_ctr = 4;
    grandchild2->display_info.node_ctr = 4;
    grandchild2->display_info.node_pos = 1;
    grandchild2->type = em_network_node_data_type_number;
    grandchild2->value_int = 200;
    child1->child[0] = grandchild1;
    child1->child[1] = grandchild2;
    // Child2
    em_network_node_t *child2 = reinterpret_cast<em_network_node_t*>(malloc(sizeof(em_network_node_t)));
    memset(child2, 0, sizeof(em_network_node_t));
    strncpy(child2->key, "child2", sizeof(child2->key));
    strncpy(child2->value_str, "child2_value", sizeof(child2->value_str));
    child2->display_info.collapsed = false;
    child2->display_info.orig_node_ctr = 5;
    child2->display_info.node_ctr = 5;
    child2->display_info.node_pos = 1;
    child2->type = em_network_node_data_type_null;
    child2->value_int = 300;
    root->child[0] = child1;
    root->child[1] = child2;
    EXPECT_NO_THROW({
        em_net_node_t::free_network_tree(root);
    });
    std::cout << "Exiting free_network_tree_multiple_levels test" << std::endl;
}
/**
 * @brief Validate that the free_network_tree API correctly frees a network tree comprising all possible data types.
 *
 * This test constructs a network tree where each node is assigned a distinct data type from the available enumeration values. It verifies that the free_network_tree API correctly traverses and frees each node without throwing an exception, ensuring robust memory deallocation.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 018@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Construct a network tree with a root node and chained child nodes, each having different data types. | Input: root->key = "root_all_types", root->value_str = "value_root", root->type = em_network_node_data_type_invalid; For each child, key = "node_i", value_str = "value_i", type = corresponding type from the types array; num_children and child pointers set accordingly. | Should construct a valid network tree where each node is correctly allocated and linked based on its data type. | Should Pass |
 * | 02 | Call free_network_tree API on the constructed network tree. | Input: root pointer containing the constructed tree; Output: freed memory without exception. | Should free all nodes and not throw any exception. | Should Pass |
 */
TEST(em_net_node_t, free_network_tree_all_data_types) {
    std::cout << "Entering free_network_tree_all_data_types test" << std::endl;
    em_network_node_data_type_t types[] = { 
        em_network_node_data_type_invalid,
        em_network_node_data_type_false,
        em_network_node_data_type_true,
        em_network_node_data_type_null,
        em_network_node_data_type_number,
        em_network_node_data_type_string,
        em_network_node_data_type_obj,
        em_network_node_data_type_array_obj,
        em_network_node_data_type_array_str,
        em_network_node_data_type_array_num,
        em_network_node_data_type_raw
    };
    const size_t numTypes = sizeof(types) / sizeof(types[0]);
    em_network_node_t *root = reinterpret_cast<em_network_node_t*>(malloc(sizeof(em_network_node_t)));
    memset(root, 0, sizeof(em_network_node_t));
    strncpy(root->key, "root_all_types", sizeof(root->key));
    strncpy(root->value_str, "value_root", sizeof(root->value_str));
    root->type = types[0];
    root->num_children = (numTypes > 1) ? 1 : 0;
    for (unsigned int i = 0; i < EM_MAX_DM_CHILDREN; i++) root->child[i] = nullptr;
    em_network_node_t *current = root;
    for (size_t i = 1; i < numTypes; i++) {
        em_network_node_t *newNode = reinterpret_cast<em_network_node_t*>(malloc(sizeof(em_network_node_t)));
        memset(newNode, 0, sizeof(em_network_node_t));
        char keyBuffer[128];
        snprintf(keyBuffer, sizeof(keyBuffer), "node_%zu", i);
        strncpy(newNode->key, keyBuffer, sizeof(newNode->key));
        char valueBuffer[128];
        snprintf(valueBuffer, sizeof(valueBuffer), "value_%zu", i);
        strncpy(newNode->value_str, valueBuffer, sizeof(newNode->value_str));
        newNode->type = types[i];
        newNode->num_children = (i < numTypes - 1) ? 1 : 0;
        for (unsigned int j = 0; j < EM_MAX_DM_CHILDREN; j++) newNode->child[j] = nullptr;
        current->child[0] = newNode;
        current->num_children = 1;
        current = newNode;
    }
    EXPECT_NO_THROW({
        em_net_node_t::free_network_tree(root);
    });
    std::cout << "Exiting free_network_tree_all_data_types test" << std::endl;
}
/**
 * @brief Verifies that the free_network_tree function successfully frees a network tree with the maximum allowed children.
 *
 * This test creates a root network node with the maximum number of children allocated. It initializes the root node's key, value_str, and node type, and then allocates each child node with a unique key. After setting up the tree structure, the test invokes the free_network_tree function and checks that no exception is thrown during the freeing of the tree. This ensures that the memory management for a network tree at its maximum children limit is correctly implemented.
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
 * | Variation / Step | Description                                                                                   | Test Data                                                                                                                      | Expected Result                                                     | Notes           |
 * | :--------------: | --------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------- | --------------- |
 * | 01               | Initialize root node with maximum children count, and set key, value_str, and type            | root = allocated memory, key = "root_max_children", value_str = "value_root_max", type = em_network_node_data_type_obj, num_children = EM_MAX_DM_CHILDREN | Root node is properly allocated and initialized                     | Should be successful |
 * | 02               | Allocate and initialize each child node with individually formatted keys                      | For each child i from 0 to EM_MAX_DM_CHILDREN-1: allocate memory, key = "child_i"                                              | Each child node is successfully allocated and attached to the root node | Should be successful |
 * | 03               | Invoke free_network_tree function on the initialized network tree                             | Call free_network_tree with the root node pointer                                                                               | No exception is thrown and all allocated node memory is freed         | Should Pass     |
 */
TEST(em_net_node_t, free_network_tree_max_children) {
    std::cout << "Entering free_network_tree_max_children test" << std::endl;
    em_network_node_t *root = reinterpret_cast<em_network_node_t*>(malloc(sizeof(em_network_node_t)));
    memset(root, 0, sizeof(em_network_node_t));
    strncpy(root->key, "root_max_children", sizeof(root->key));
    strncpy(root->value_str, "value_root_max", sizeof(root->value_str));
    root->type = em_network_node_data_type_obj;
    root->num_children = EM_MAX_DM_CHILDREN;

    for (unsigned int i = 0; i < EM_MAX_DM_CHILDREN; i++) {
        em_network_node_t *child = reinterpret_cast<em_network_node_t*>(malloc(sizeof(em_network_node_t)));
        memset(child, 0, sizeof(em_network_node_t));
        char keyBuffer[128];
        snprintf(keyBuffer, sizeof(keyBuffer), "child_%u", i);
        strncpy(child->key, keyBuffer, sizeof(child->key));
        root->child[i] = child;
    }
    EXPECT_NO_THROW({
        em_net_node_t::free_network_tree(root);
    });    
    std::cout << "Exiting free_network_tree_max_children test" << std::endl;
}
/**
 * @brief Verify that free_network_tree_node throws an exception when a null pointer is provided
 *
 * This test verifies that the free_network_tree_node function correctly throws an exception when it is invoked with a nullptr.
 * It ensures the function handles invalid input properly by triggering an exception.
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
 * | Variation / Step | Description                                         | Test Data              | Expected Result                   | Notes       |
 * | :--------------: | --------------------------------------------------- | ---------------------- | --------------------------------- | ----------- |
 * |       01       | Call free_network_tree_node with a null pointer     | node = nullptr         | API throws an exception           | Should Pass |
 */
TEST(em_net_node_t, free_network_tree_node_nullptr_input)
{
    std::cout << "Entering free_network_tree_node_nullptr_input test" << std::endl;
    EXPECT_ANY_THROW({
        em_net_node_t::free_network_tree_node(nullptr);
    });
    std::cout << "Exiting free_network_tree_node_nullptr_input test" << std::endl;
}
/**
 * @brief Test free_network_tree_node function with a single network node.
 *
 * This test verifies that the free_network_tree_node function correctly frees a network node that has been initialized with valid key, value, display information, type, and no children. The objective is to ensure that no exceptions are thrown when freeing a properly constructed single node.
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
 * | Variation / Step | Description                                                                                         | Test Data                                                                                                                                                                                                                                                                                       | Expected Result                                              | Notes           |
 * | :--------------: | --------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------ | --------------- |
 * | 01               | Allocate a single network node and initialize its members with test data                           | input: node allocated using malloc, node->key = "SingleNodeKey", node->value_str = "SingleNodeValue", display_info.collapsed = false, display_info.orig_node_ctr = 1, display_info.node_ctr = 1, display_info.node_pos = 0, type = em_network_node_data_type_string, value_int = 0, num_children = 0 | Node is created and initialized correctly                     | Should be successful |
 * | 02               | Invoke free_network_tree_node on the initialized node within an EXPECT_NO_THROW block and verify  | input: node pointer containing the initialized data                                                                                                                                                                                                                                             | Function frees the node without throwing an exception; EXPECT_NO_THROW passes | Should Pass     |
 */
TEST(em_net_node_t, free_network_tree_node_singlenode)
{
    std::cout << "Entering free_network_tree_node_singlenode test" << std::endl;
    em_network_node_t *node = reinterpret_cast<em_network_node_t*>(malloc(sizeof(em_network_node_t)));
    memset(node, 0, sizeof(em_network_node_t));
    const char *testKey = "SingleNodeKey";
    strncpy(node->key, testKey, sizeof(node->key));
    const char *testValue = "SingleNodeValue";
    strncpy(node->value_str, testValue, sizeof(node->value_str));
    node->display_info.collapsed = false;
    node->display_info.orig_node_ctr = 1;
    node->display_info.node_ctr = 1;
    node->display_info.node_pos = 0;
    node->type = em_network_node_data_type_string;
    node->value_int = 0;
    node->num_children = 0;
    EXPECT_NO_THROW({
        em_net_node_t::free_network_tree_node(node);
    });
    std::cout << "Exiting free_network_tree_node_singlenode test" << std::endl;
}
/**
 * @brief Verify that free_network_tree_node correctly frees a network tree node with children without throwing exceptions
 *
 * This test ensures that em_net_node_t::free_network_tree_node is capable of deallocating a parent node along with its child nodes. The test allocates memory for a parent node, initializes its attributes, and creates multiple child nodes with specific properties. It then calls the free_network_tree_node function and checks that no exceptions are thrown. This confirms that the API properly handles the freeing of a node tree with children.
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
 * | Variation / Step | Description                                                           | Test Data                                                                                                                         | Expected Result                                                         | Notes           |
 * | :--------------: | --------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------- | --------------- |
 * | 01               | Allocate and initialize the parent network node                       | parent = allocated via malloc, key = "ParentNode", value_str = "ParentValue", value_int = 100, num_children = 2                    | Parent node allocated with proper initialization                        | Should be successful |
 * | 02               | Allocate and initialize child nodes for the parent node                 | For each child (i=0,1): allocated via malloc, key = "ChildNode_i", value_str = "ChildValue", value_int = i*10, num_children = 0       | Child nodes allocated and initialized correctly                         | Should be successful |
 * | 03               | Call free_network_tree_node on the parent node                         | Input: parent pointer with initialized children                                                                                   | No exception thrown; memory freed successfully (EXPECT_NO_THROW passes) | Should Pass         |
 */
TEST(em_net_node_t, free_network_tree_node_with_children)
{
    std::cout << "Entering free_network_tree_node_with_children test" << std::endl;
    em_network_node_t *parent = reinterpret_cast<em_network_node_t*>(malloc(sizeof(em_network_node_t)));
    memset(parent, 0, sizeof(em_network_node_t));
    const char *parentKey = "ParentNode";
    strncpy(parent->key, parentKey, sizeof(parent->key));
    parent->display_info.collapsed = false;
    parent->display_info.orig_node_ctr = 1;
    parent->display_info.node_ctr = 1;
    parent->display_info.node_pos = 0;
    parent->type = em_network_node_data_type_obj;
    const char *parentValue = "ParentValue";
    strncpy(parent->value_str, parentValue, sizeof(parent->value_str));
    parent->value_int = 100;
    parent->num_children = 2;
    for (unsigned int i = 0; i < parent->num_children; ++i)
    {
        parent->child[i] = reinterpret_cast<em_network_node_t*>(malloc(sizeof(em_network_node_t)));
        memset(parent->child[i], 0, sizeof(em_network_node_t));
        char childKey[128];
        std::snprintf(childKey, sizeof(childKey), "ChildNode_%u", i);
        strncpy(parent->child[i]->key, childKey, sizeof(parent->child[i]->key));
        parent->child[i]->display_info.collapsed = false;
        parent->child[i]->display_info.orig_node_ctr = 2;
        parent->child[i]->display_info.node_ctr = 1;
        parent->child[i]->display_info.node_pos = i;
        parent->child[i]->type = em_network_node_data_type_string;
        const char *childValue = "ChildValue";
        strncpy(parent->child[i]->value_str, childValue, sizeof(parent->child[i]->value_str));
        parent->child[i]->value_int = i * 10;
        parent->child[i]->num_children = 0;
    }
    EXPECT_NO_THROW({
        em_net_node_t::free_network_tree_node(parent);
    });
    std::cout << "Exiting free_network_tree_node_with_children test" << std::endl;
}
/**
 * @brief Test to free a network tree node with nested child nodes
 *
 * This test verifies that the function free_network_tree_node correctly frees a network tree that contains nested child nodes. It ensures that memory allocated for the root and its nested child nodes is properly released without throwing exceptions.
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
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Allocate and initialize a network tree with nested nodes and invoke free_network_tree_node API | root key = RootNode, display_info.collapsed = false, orig_node_ctr = 1, node_ctr = 1, node_pos = 0, type = em_network_node_data_type_obj, value_str = RootValue, value_int = 200; child[0] key = Level1Child, display_info.collapsed = true, orig_node_ctr = 2, node_ctr = 1, node_pos = 0, type = em_network_node_data_type_obj, value_str = Level1Value, value_int = 300; child[0]->child[0] key = Level2Child, display_info.collapsed = false, orig_node_ctr = 3, node_ctr = 1, node_pos = 0, type = em_network_node_data_type_string, value_str = Level2Value, value_int = 400 | The API should complete without throwing any exceptions and all allocated memory should be freed | Should Pass |
 */
TEST(em_net_node_t, free_network_tree_node_with_nested_nodes)
{
    std::cout << "Entering free_network_tree_node_with_nested_nodes test" << std::endl;
    em_network_node_t *root = reinterpret_cast<em_network_node_t*>(malloc(sizeof(em_network_node_t)));
    memset(root, 0, sizeof(em_network_node_t));
    strncpy(root->key, "RootNode", sizeof(root->key));
    root->display_info.collapsed = false;
    root->display_info.orig_node_ctr = 1;
    root->display_info.node_ctr = 1;
    root->display_info.node_pos = 0;
    root->type = em_network_node_data_type_obj;
    strncpy(root->value_str, "RootValue", sizeof(root->value_str));
    root->value_int = 200;
    root->num_children = 1;
    root->child[0] = reinterpret_cast<em_network_node_t*>(malloc(sizeof(em_network_node_t)));
    memset(root->child[0], 0, sizeof(em_network_node_t));
    strncpy(root->child[0]->key, "Level1Child", sizeof(root->child[0]->key));
    root->child[0]->display_info.collapsed = true;
    root->child[0]->display_info.orig_node_ctr = 2;
    root->child[0]->display_info.node_ctr = 1;
    root->child[0]->display_info.node_pos = 0;
    root->child[0]->type = em_network_node_data_type_obj;
    strncpy(root->child[0]->value_str, "Level1Value", sizeof(root->child[0]->value_str));
    root->child[0]->value_int = 300;
    root->child[0]->num_children = 1;
    root->child[0]->child[0] = reinterpret_cast<em_network_node_t*>(malloc(sizeof(em_network_node_t)));
    memset(root->child[0]->child[0], 0, sizeof(em_network_node_t));
    strncpy(root->child[0]->child[0]->key, "Level2Child", sizeof(root->child[0]->child[0]->key));
    root->child[0]->child[0]->display_info.collapsed = false;
    root->child[0]->child[0]->display_info.orig_node_ctr = 3;
    root->child[0]->child[0]->display_info.node_ctr = 1;
    root->child[0]->child[0]->display_info.node_pos = 0;
    root->child[0]->child[0]->type = em_network_node_data_type_string;
    strncpy(root->child[0]->child[0]->value_str, "Level2Value", sizeof(root->child[0]->child[0]->value_str));
    root->child[0]->child[0]->value_int = 400;
    root->child[0]->child[0]->num_children = 0;
    EXPECT_NO_THROW({
        em_net_node_t::free_network_tree_node(root);
    });
    std::cout << "Exiting free_network_tree_node_with_nested_nodes test" << std::endl;
}
/**
 * @brief Verify that free_network_tree_node handles various enum type values without throwing exceptions
 *
 * This test validates the free_network_tree_node API by iterating over different enumeration values for the node type. 
 * For each enum value, a network node is allocated, initialized with unique data (including key, display_info, value_str, and value_int), 
 * and then passed to the free_network_tree_node function. The test confirms that the function call does not throw any exceptions, ensuring robust behavior 
 * for all defined enum types.
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
 * | Variation / Step | Description                                                                                                      | Test Data                                                                                                                                                                                                                     | Expected Result                                               | Notes      |
 * | :--------------: | ---------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------- | ---------- |
 * | 01               | Iterate over each enum value, allocate and initialize a node, then invoke free_network_tree_node on the node | node->type = one of [em_network_node_data_type_invalid, em_network_node_data_type_false, em_network_node_data_type_true, em_network_node_data_type_null, em_network_node_data_type_number, em_network_node_data_type_string, em_network_node_data_type_obj, em_network_node_data_type_array_obj, em_network_node_data_type_array_str, em_network_node_data_type_array_num, em_network_node_data_type_raw], key = "EnumNode_i", value_str = "EnumValue", value_int = 600 + i | free_network_tree_node does not throw an exception | Should Pass |
 */
TEST(em_net_node_t, free_network_tree_node_VariousEnumTypeValues)
{
    std::cout << "Entering free_network_tree_node_VariousEnumTypeValues test" << std::endl;
    em_network_node_data_type_t enumValues[] = {
        em_network_node_data_type_invalid,
        em_network_node_data_type_false,
        em_network_node_data_type_true,
        em_network_node_data_type_null,
        em_network_node_data_type_number,
        em_network_node_data_type_string,
        em_network_node_data_type_obj,
        em_network_node_data_type_array_obj,
        em_network_node_data_type_array_str,
        em_network_node_data_type_array_num,
        em_network_node_data_type_raw
    };
    const size_t enumCount = sizeof(enumValues) / sizeof(enumValues[0]);
    for (size_t i = 0; i < enumCount; ++i)
    {
        em_network_node_t *node = reinterpret_cast<em_network_node_t*>(malloc(sizeof(em_network_node_t)));
        memset(node, 0, sizeof(em_network_node_t));
        char keyBuffer[128];
        std::snprintf(keyBuffer, sizeof(keyBuffer), "EnumNode_%zu", i);
        strncpy(node->key, keyBuffer, sizeof(node->key));
        node->display_info.collapsed = false;
        node->display_info.orig_node_ctr = 1;
        node->display_info.node_ctr = 1;
        node->display_info.node_pos = static_cast<unsigned int>(i);
        node->type = enumValues[i];
        const char *value = "EnumValue";
        strncpy(node->value_str, value, sizeof(node->value_str));
        node->value_int = 600 + static_cast<unsigned int>(i);
        node->num_children = 0;
        EXPECT_NO_THROW({
            em_net_node_t::free_network_tree_node(node);
        });
    }
    std::cout << "Exiting free_network_tree_node_VariousEnumTypeValues test" << std::endl;
}
/**
 * @brief Verify that free_network_tree_string properly frees dynamically allocated memory without throwing exceptions.
 *
 * This test checks the functionality of the free_network_tree_string method by allocating a dynamic buffer, initializing it with a test string, and invoking the method to free the memory. Ensuring that no exceptions are thrown verifies the proper handling of dynamic memory.
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
 * | Variation / Step | Description                                                                        | Test Data                                                                                             | Expected Result                                                                           | Notes             |
 * | :--------------: | ---------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------- | ----------------- |
 * |       01         | Allocate a buffer of size 50 and initialize it with "Network tree info".           | bufferSize = 50, networkTreeStr = malloc(bufferSize), testString = "Network tree info"                | Buffer should be allocated and correctly initialized.                                   | Should be successful  |
 * |       02         | Invoke free_network_tree_string on the allocated string and verify no exception is thrown. | API input: networkTreeStr, API output: void (no return value)                                         | Function should free the memory without throwing any exceptions (validated by EXPECT_NO_THROW). | Should Pass       |
 */
TEST(em_net_node_t, free_network_tree_string_dynamic) {
    std::cout << "Entering free_network_tree_string_dynamic test" << std::endl;
    size_t bufferSize = 50;
    char* networkTreeStr = reinterpret_cast<char*>(malloc(bufferSize));
    const char* testString = "Network tree info";
    strncpy(networkTreeStr, testString, bufferSize - 1);
    networkTreeStr[bufferSize - 1] = '\0';
    EXPECT_NO_THROW({
        em_net_node_t node;
        node.free_network_tree_string(networkTreeStr);
    });
    std::cout << "Exiting free_network_tree_string_dynamic test" << std::endl;
}
/**
 * @brief Test to verify that free_network_tree_string throws an exception when passed a null pointer.
 *
 * This test verifies that invoking free_network_tree_string with a null pointer as the parameter correctly triggers an exception. The exception behavior is essential to ensure that the API handles invalid input safely.
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
 * | Variation / Step | Description                                           | Test Data                                  | Expected Result                                                      | Notes        |
 * | :--------------: | ----------------------------------------------------- | ------------------------------------------ | -------------------------------------------------------------------- | ------------ |
 * | 01               | Call free_network_tree_string with a null pointer value | networkTreeStr = nullptr                   | API should throw an exception as a null pointer is provided; assertion verifies exception thrown | Should Pass  |
 */
TEST(em_net_node_t, free_network_tree_string_nullptr_input) {
    std::cout << "Entering free_network_tree_string_nullptr_input test" << std::endl;
    char* networkTreeStr = nullptr;
    EXPECT_ANY_THROW({
        em_net_node_t node;
        node.free_network_tree_string(networkTreeStr);
    });
    std::cout << "Exiting free_network_tree_string_nullptr_input test" << std::endl;
}
/**
 * @brief Verify free_node_value properly frees a valid dynamic string without throwing an exception.
 *
 * This test allocates a dynamic string, initializes it, and then verifies that calling free_node_value on it does not throw any exception.
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
 * | Variation / Step | Description                                                                       | Test Data                                                           | Expected Result                                                  | Notes       |
 * | :--------------: | --------------------------------------------------------------------------------- | ------------------------------------------------------------------- | ---------------------------------------------------------------- | ----------- |
 * | 01               | Allocate a dynamic string, initialize it with "Hello, World!", and free it using free_node_value | dynStr = pointer to dynamic memory allocated with size 50, content = "Hello, World!" | Function call does not throw any exception (EXPECT_NO_THROW passes) | Should Pass |
 */
TEST(em_net_node_t, free_node_value_valid_dynamic_string) {
    std::cout << "Entering free_node_value_valid_dynamic_string test" << std::endl;
    char* dynStr = reinterpret_cast<char*>(malloc(50));
    strncpy(dynStr, "Hello, World!", 50);
    dynStr[49] = '\0';
    EXPECT_NO_THROW({
        em_net_node_t::free_node_value(dynStr);
    });
    std::cout << "Exiting free_node_value_valid_dynamic_string test" << std::endl;
}
/**
 * @brief Verify that free_node_value correctly handles a null pointer input by throwing an exception.
 *
 * This test ensures that the em_net_node_t::free_node_value() function properly handles an input of a nullptr by throwing an exception. It validates the function's defensive programming against invalid memory access, ensuring system stability.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 028@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                       | Test Data                  | Expected Result                                                               | Notes       |
 * | :----:           | ---------------------------------------------------------------   | -------------------------- | ----------------------------------------------------------------------------- | ----------- |
 * | 01               | Invoke em_net_node_t::free_node_value() with a null pointer           | input = nullptr            | An exception is thrown, as validated by EXPECT_ANY_THROW                      | Should Pass |
 */
TEST(em_net_node_t, free_node_value_null_pointer) {
    std::cout << "Entering free_node_value_null_pointer test" << std::endl;
    EXPECT_ANY_THROW({
    em_net_node_t::free_node_value(nullptr);
    });
    std::cout << "Exiting free_node_value_null_pointer test" << std::endl;
}

/**
 * @brief Verify that get_child_node_at_index retrieves the correct child node from a parent with a single valid child
 *
 * This test validates that when a parent node contains exactly one valid child, the function get_child_node_at_index correctly returns the child at the specified index. The test ensures that the returned pointer is not null and that the child's key matches the expected value.
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
 * | Variation / Step | Description                                                              | Test Data                                                                                             | Expected Result                                                                               | Notes            |
 * | :--------------: | ------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------- | ---------------- |
 * |       01       | Initialize the parent node and set its number of children to 1, with all child pointers set to nullptr. | parent.num_children = 1, each parent.child[i] = nullptr (for i in 0 to EM_MAX_DM_CHILDREN - 1)          | Parent node is correctly initialized with no valid child nodes yet.                           | Should be successful |
 * |       02       | Allocate a single child node, set its key to "child0", and assign it as the first child of the parent. | Allocation of child0, child0->key = "child0", parent.child[0] = pointer to child0, input: parent's address      | Child node is allocated correctly and assigned to the parent's first child slot.              | Should be successful |
 * |       03       | Invoke the API get_child_node_at_index with index 0 on the initialized parent node. | input1 = &parent, input2 = 0, output pointer ret to child node                                         | The returned pointer is not nullptr and the child's key is "child0". Assertion check should pass.| Should Pass       |
 * |       04       | Clean up dynamically allocated memory by deleting the child node and print exit message. | delete child0                                                                                         | Dynamic memory is freed and test concludes without memory leaks.                              | Should be successful |
 */
TEST(em_net_node_t, get_child_node_at_index_valid_single_child) {
    std::cout << "Entering get_child_node_at_index_valid_single_child test" << std::endl;
    em_network_node_t parent;
    parent.num_children = 1;
    for (unsigned int i = 0; i < EM_MAX_DM_CHILDREN; ++i) parent.child[i] = nullptr;
    em_network_node_t* child0 = new em_network_node_t;
    strncpy(child0->key, "child0", sizeof(child0->key));
    parent.child[0] = child0;
    em_network_node_t* ret = em_net_node_t::get_child_node_at_index(&parent, 0);
    ASSERT_NE(ret, nullptr);
    EXPECT_STREQ(ret->key, "child0");
    delete child0;
    std::cout << "Exiting get_child_node_at_index_valid_single_child test" << std::endl;
}
/**
 * @brief Validate that get_child_node_at_index returns the correct child node for a valid middle index.
 *
 * This test creates a parent network node with three children and verifies that retrieving the middle child (at index 1)
 * returns the child node with the expected key value "child1". This ensures that the function correctly handles valid inputs
 * where the index is within the bounds of the child array.
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
 * | Variation / Step | Description | Test Data | Expected Result | Notes |@n
 * | :----: | --------- | ---------- |-------------- | ----- |@n
 * | 01 | Set up a parent node with three children and call get_child_node_at_index with index 1 to fetch the middle child. | parent.num_children = 3, child0.key = "child0", child1.key = "child1", child2.key = "child2", idx = 1 | The API returns a non-null pointer to the child node whose key is "child1". | Should Pass |
 */
TEST(em_net_node_t, get_child_node_at_index_valid_middle_child) {
    std::cout << "Entering get_child_node_at_index_valid_middle_child test" << std::endl;
    em_network_node_t parent;
    parent.num_children = 3;
    for (unsigned int i = 0; i < EM_MAX_DM_CHILDREN; ++i) parent.child[i] = nullptr;
    em_network_node_t* child0 = new em_network_node_t; strncpy(child0->key, "child0", sizeof(child0->key));
    em_network_node_t* child1 = new em_network_node_t; strncpy(child1->key, "child1", sizeof(child1->key));
    em_network_node_t* child2 = new em_network_node_t; strncpy(child2->key, "child2", sizeof(child2->key));
    parent.child[0] = child0; parent.child[1] = child1; parent.child[2] = child2;
    unsigned int idx = 1;
    em_network_node_t* ret = em_net_node_t::get_child_node_at_index(&parent, idx);
    ASSERT_NE(ret, nullptr);
    EXPECT_STREQ(ret->key, "child1");
    delete child0; delete child1; delete child2;
    std::cout << "Exiting get_child_node_at_index_valid_middle_child test" << std::endl;
}
/**
 * @brief Validate retrieval of the last valid child node in a parent node.
 *
 * This test validates that the get_child_node_at_index API correctly returns the child node pointer when invoked with an index corresponding to the last child in the parent's array. It ensures that for a properly initialized parent with three children, the API returns a non-null pointer and the expected child key ("child2").
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 031
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                                  | Test Data                                                                                                                         | Expected Result                                                                                          | Notes      |
 * | :--------------: | -------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------- | ---------- |
 * | 01               | Initialize a parent node with three children and invoke get_child_node_at_index with idx=2.   | parent.num_children = 3, child[0] key="child0", child[1] key="child1", child[2] key="child2", idx = 2, output ret pointer.     | API returns a non-null pointer; ret->key equals "child2" as verified by ASSERT_NE and EXPECT_STREQ.     | Should Pass |
 */
TEST(em_net_node_t, get_child_node_at_index_valid_last_child) {
    std::cout << "Entering get_child_node_at_index_valid_last_child test" << std::endl;
    em_network_node_t parent;
    parent.num_children = 3;
    for (unsigned int i = 0; i < EM_MAX_DM_CHILDREN; ++i) parent.child[i] = nullptr;
    em_network_node_t* child0 = new em_network_node_t; strncpy(child0->key, "child0", sizeof(child0->key));
    em_network_node_t* child1 = new em_network_node_t; strncpy(child1->key, "child1", sizeof(child1->key));
    em_network_node_t* child2 = new em_network_node_t; strncpy(child2->key, "child2", sizeof(child2->key));
    parent.child[0] = child0; parent.child[1] = child1; parent.child[2] = child2;
    unsigned int idx = 2;
    em_network_node_t* ret = em_net_node_t::get_child_node_at_index(&parent, idx);
    ASSERT_NE(ret, nullptr);
    EXPECT_STREQ(ret->key, "child2");
    delete child0; delete child1; delete child2;
    std::cout << "Exiting get_child_node_at_index_valid_last_child test" << std::endl;
}
/**
 * @brief Test that verifies the behavior of get_child_node_at_index when the parent node has zero children.
 *
 * This test checks whether the get_child_node_at_index API correctly returns a nullptr when it is invoked on a parent node that has no children. The test initializes a parent node with zero children and calls the API with index 0, verifying that the returned pointer is indeed nullptr.
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
 * | Variation / Step | Description                                                                     | Test Data                                                                                          | Expected Result            | Notes         |
 * | :--------------: | ------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------- | -------------------------- | ------------- |
 * |       01         | Initialize parent node with zero children                                       | parent.num_children = 0, child[0...EM_MAX_DM_CHILDREN] = nullptr                                     | Parent node correctly set  | Should be successful |
 * |       02         | Invoke get_child_node_at_index with index 0 on the parent node and verify result | input: parent pointer with num_children = 0 and child pointers = nullptr, idx = 0, output: ret expected as nullptr | ret == nullptr             | Should Pass    |
 */
TEST(em_net_node_t, get_child_node_at_index_out_of_bound_zero_children) {
    std::cout << "Entering get_child_node_at_index_out_of_bound_zero_children test" << std::endl;
    em_network_node_t parent;
    parent.num_children = 0;
    for (unsigned int i = 0; i < EM_MAX_DM_CHILDREN; ++i) parent.child[i] = nullptr;
    unsigned int idx = 0;
    em_network_node_t* ret = em_net_node_t::get_child_node_at_index(&parent, idx);
    EXPECT_EQ(ret, nullptr);
    std::cout << "Exiting get_child_node_at_index_out_of_bound_zero_children test" << std::endl;
}
/**
 * @brief Verify that get_child_node_at_index handles a null parent pointer correctly
 *
 * This test checks that the get_child_node_at_index API correctly detects a null parent pointer and
 * triggers a death test. The objective is to ensure that the API robustly handles erroneous null input.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 033
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                | Test Data                                 | Expected Result                                                       | Notes       |
 * | :--------------: | -----------------------------------------------------------| ------------------------------------------| --------------------------------------------------------------------- | ----------- |
 * | 01               | Invoke get_child_node_at_index with a null parent pointer and index 0 | parent = nullptr, idx = 0                  | API is expected to trigger death and terminate execution as per the assertion check | Should Fail |
 */
TEST(em_net_node_t, get_child_node_at_index_null_parent) {
    std::cout << "Entering get_child_node_at_index_null_parent test" << std::endl;
    unsigned int idx = 0;
    EXPECT_DEATH({
        em_net_node_t::get_child_node_at_index(nullptr, idx);
    }, ".*");
    std::cout << "Exiting get_child_node_at_index_null_parent test" << std::endl;
}
/**
 * @brief Validate that get_child_node_at_index returns nullptr for an out-of-bound index
 *
 * This test validates that the get_child_node_at_index function returns a nullptr when an index beyond the number of children is provided. It ensures proper error handling for out-of-bound indices.
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
 * | :----: | --------- | ---------- | -------------- | ----- |
 * | 01 | Setup parent node with 2 children and invoke get_child_node_at_index with an out-of-bound index | parent.num_children = 2, child[0].key = "child0", child[1].key = "child1", idx = 5 | Function returns nullptr, and ASSERT_EQ(ret, nullptr) confirms that no child node is returned for an invalid index | Should Fail |
 */
TEST(em_net_node_t, get_child_node_at_index_index_out_of_bound) {
    std::cout << "Entering get_child_node_at_index_index_out_of_bound test" << std::endl;
    em_network_node_t parent;
    parent.num_children = 2;
    for (unsigned int i = 0; i < EM_MAX_DM_CHILDREN; ++i) parent.child[i] = nullptr;
    em_network_node_t* child0 = new em_network_node_t; strncpy(child0->key, "child0", sizeof(child0->key));
    em_network_node_t* child1 = new em_network_node_t; strncpy(child1->key, "child1", sizeof(child1->key));
    parent.child[0] = child0; parent.child[1] = child1;
    unsigned int idx = 5;
    em_network_node_t* ret = em_net_node_t::get_child_node_at_index(&parent, idx);
    ASSERT_EQ(ret, nullptr);
    delete child0; delete child1;
    std::cout << "Exiting get_child_node_at_index_index_out_of_bound test" << std::endl;
}
/**
 * @brief Validate behavior of get_child_node_at_index when the children array is null
 *
 * This test verifies that when the parent's child array is initialized with nullptr entries despite a non-zero children count, the get_child_node_at_index API correctly returns a nullptr for the specified index.
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
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize a parent node: set num_children to 3 and all child pointers to nullptr | num_children = 3, child[i] = nullptr for all i in [0, EM_MAX_DM_CHILDREN-1] | Parent node is correctly initialized with null children pointers | Should be successful |
 * | 02 | Invoke get_child_node_at_index with index 1 on the initialized parent node | parent pointer, idx = 1 | The function returns nullptr since child node at given index is null | Should Pass |
 * | 03 | Validate the returned pointer using EXPECT_EQ | ret = nullptr, EXPECT_EQ(ret, nullptr) | Assertion passes confirming that no valid child node was returned | Should Pass |
 */
TEST(em_net_node_t, get_child_node_at_index_null_children_array) {
    std::cout << "Entering get_child_node_at_index_null_children_array test" << std::endl;
    em_network_node_t parent;
    parent.num_children = 3;
    for (unsigned int i = 0; i < EM_MAX_DM_CHILDREN; ++i) parent.child[i] = nullptr;
    unsigned int idx = 1;
    em_network_node_t* ret = em_net_node_t::get_child_node_at_index(&parent, idx);
    EXPECT_EQ(ret, nullptr);
    std::cout << "Exiting get_child_node_at_index_null_children_array test" << std::endl;
}
/**
 * @brief Verify that passing a null buffer to get_network_tree returns a null network tree.
 *
 * This test validates that the get_network_tree API correctly handles a null input by returning a null pointer. This ensures that the API has proper null-check handling to avoid dereferencing invalid memory.
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
 * | Variation / Step | Description                                       | Test Data                                        | Expected Result                                                  | Notes      |
 * | :--------------: | ------------------------------------------------- | ------------------------------------------------ | ---------------------------------------------------------------- | ---------- |
 * | 01               | Invoke get_network_tree with a null buffer input  | input: buffer = nullptr, output: tree = nullptr  | API returns nullptr and ASSERT_EQ confirms tree is null           | Should Pass|
 */
TEST(em_net_node_t, get_network_tree_null_buffer_input) {
    std::cout << "Entering get_network_tree_null_buffer_input test" << std::endl;
    em_net_node_t obj;
    em_network_node_t* tree = em_net_node_t::get_network_tree(nullptr);
    ASSERT_EQ(tree, nullptr);
    std::cout << "Exiting get_network_tree_null_buffer_input test" << std::endl;
}
/**
 * @brief To validate that get_network_tree returns nullptr when provided with an empty string.
 *
 * This test validates that the get_network_tree function correctly handles an empty string input by returning a nullptr. This behavior ensures robustness in handling invalid or empty inputs.
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
 * | 01 | Invoke get_network_tree with an empty string | input: buff[0] = '\0', output: tree expected = nullptr | Returns nullptr and ASSERT_EQ verifies tree is nullptr | Should Pass |
 */
TEST(em_net_node_t, get_network_tree_empty_string_input) {
    std::cout << "Entering get_network_tree_empty_string_input test" << std::endl;
    em_net_node_t obj;
    char buff[1];
    buff[0] = '\0';
    em_network_node_t* tree = em_net_node_t::get_network_tree(buff);
    ASSERT_EQ(tree, nullptr);
    std::cout << "Exiting get_network_tree_empty_string_input test" << std::endl;
}
/**
 * @brief Verify that get_network_tree correctly handles malformed JSON input
 *
 * This test verifies whether the get_network_tree API returns a null pointer when provided with a malformed JSON string.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 038@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                                                     | Test Data                                                        | Expected Result                                                 | Notes       |
 * | :--------------: | ----------------------------------------------------------------------------------------------- | ---------------------------------------------------------------- | --------------------------------------------------------------- | ----------- |
 * | 01               | Initialize a malformed JSON string and invoke get_network_tree API to parse it                  | buff = "{ \"key\": \"value\"", output from get_network_tree = nullptr | The API should return a nullptr indicating failure to parse JSON | Should Pass |
 */
TEST(em_net_node_t, get_network_tree_malformed_JSON_input) {
    std::cout << "Entering get_network_tree_malformed_JSON_input test" << std::endl;
    em_net_node_t obj;
    char buff[50];
    memset(buff, 0, sizeof(buff));
    strncpy(buff, "{ \"key\": \"value\"", sizeof(buff)-1);
    em_network_node_t* tree = em_net_node_t::get_network_tree(buff);
    ASSERT_EQ(tree, nullptr);
    std::cout << "Exiting get_network_tree_malformed_JSON_input test" << std::endl;
}
/**
 * @brief Validate that get_network_tree() returns a valid network tree from simple JSON input.
 *
 * This test verifies that get_network_tree() correctly parses a simple valid JSON string and creates a corresponding network tree with the expected structure. The test ensures that the returned tree is not null, that the root node is of object type, and that it contains exactly one valid child node with the expected key and value.
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
 * | 01 | Initialize input buffer with a valid JSON string and parse network tree | buff = "{ \"key\": \"value\" }" | API returns a non-null pointer to a network tree | Should Pass |
 * | 02 | Validate that the root network node has object type and exactly one child | No additional input | tree->type equals em_network_node_data_type_obj; tree->num_children equals 1 | Should Pass |
 * | 03 | Validate that the first child node exists and contains the correct key and string value | No additional input | tree->child[0] is not null; key equals "key"; value_str equals "value"; type equals em_network_node_data_type_string | Should Pass |
 * | 04 | Free the allocated network tree | No additional input | Memory is properly freed without errors | Should be successful |
 */
TEST(em_net_node_t, get_network_tree_valid_simple_JSON_input) {
    std::cout << "Entering get_network_tree_valid_simple_JSON_input test" << std::endl;
    char buff[128];
    memset(buff, 0, sizeof(buff));
    strncpy(buff, "{ \"key\": \"value\" }", sizeof(buff) - 1);
    em_network_node_t* tree = em_net_node_t::get_network_tree(buff);
    ASSERT_NE(tree, nullptr);
    EXPECT_EQ(tree->type, em_network_node_data_type_obj);
    EXPECT_EQ(tree->num_children, 1u);
    ASSERT_NE(tree->child[0], nullptr);
    EXPECT_STREQ(tree->child[0]->key, "key");
    EXPECT_STREQ(tree->child[0]->value_str, "value");
    EXPECT_EQ(tree->child[0]->type, em_network_node_data_type_string);
    em_net_node_t::free_network_tree(tree);
    std::cout << "Exiting get_network_tree_valid_simple_JSON_input test" << std::endl;
}
/**
 * @brief Validates that get_network_tree correctly parses a valid nested JSON input.
 *
 * This test checks that get_network_tree successfully processes a nested JSON string,
 * correctly builds the corresponding network tree structure, and that the node contents
 * (i.e., keys, types, child count, and values) match the expected values. The test ensures
 * that the API can handle nested JSON objects appropriately.
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
 * | Variation / Step | Description | Test Data |Expected Result |Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize the buffer with a valid nested JSON string. | buff = "{ \"outerKey\": { \"innerKey\": 123 } }" | Buffer is correctly initialized. | Should be successful |
 * | 02 | Call get_network_tree with the initialized buffer. | input buff = "{ \"outerKey\": { \"innerKey\": 123 } }", output tree pointer | API returns a non-null network tree pointer. | Should Pass |
 * | 03 | Validate the outer node properties. | outer->key = "outerKey", outer->type = em_network_node_data_type_obj, outer->num_children = 1 | Outer node properties are verified. | Should Pass |
 * | 04 | Validate the inner node properties. | inner->key = "innerKey", inner->type = em_network_node_data_type_number, inner->value_int = 123 | Inner node properties are verified. | Should Pass |
 * | 05 | Free the allocated network tree. | tree pointer freed via free_network_tree | Network tree memory is released. | Should be successful |
 */
TEST(em_net_node_t, get_network_tree_valid_nested_JSON_input) {
    std::cout << "Entering get_network_tree_valid_nested_JSON_input test" << std::endl;
    char buff[128];
    memset(buff, 0, sizeof(buff));
    strncpy(buff, "{ \"outerKey\": { \"innerKey\": 123 } }", sizeof(buff) - 1);
    std::cout << "Invoking get_network_tree with buff = " << buff << std::endl;
    em_network_node_t* tree = em_net_node_t::get_network_tree(buff);
    ASSERT_NE(tree, nullptr);
    EXPECT_EQ(tree->type, em_network_node_data_type_obj);
    EXPECT_EQ(tree->num_children, 1u);
    em_network_node_t* outer = tree->child[0];
    ASSERT_NE(outer, nullptr);
    EXPECT_STREQ(outer->key, "outerKey");
    EXPECT_EQ(outer->type, em_network_node_data_type_obj);
    EXPECT_EQ(outer->num_children, 1u);
    em_network_node_t* inner = outer->child[0];
    ASSERT_NE(inner, nullptr);
    EXPECT_STREQ(inner->key, "innerKey");
    EXPECT_EQ(inner->type, em_network_node_data_type_number);
    EXPECT_EQ(inner->value_int, 123);
    em_net_node_t::free_network_tree(tree);
    std::cout << "Exiting get_network_tree_valid_nested_JSON_input test" << std::endl;
}
/**
 * @brief Verify that get_network_tree correctly parses a valid JSON array input into a proper network tree
 *
 * This test verifies that when a valid JSON array string "[1, 2, 3]" is provided to get_network_tree, a valid network tree is created.
 * The network tree should have the type indicating an array object, contain exactly three children, and each child should represent a number
 * corresponding to the JSON array elements. This ensures that the JSON parsing logic and the tree creation mechanism work as expected.
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
 * | Variation / Step | Description                                                                                        | Test Data                                                        | Expected Result                                                                                                     | Notes           |
 * | :--------------: | -------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------- | --------------- |
 * | 01               | Initialize a buffer with the valid JSON array string "[1, 2, 3]".                                  | buff = "[1, 2, 3]"                                               | Buffer is correctly initialized with the valid JSON array string.                                                  | Should be successful |
 * | 02               | Invoke em_net_node_t::get_network_tree using the valid JSON string buffer and verify tree creation.  | input: buff = "[1, 2, 3]", output: tree pointer                  | tree != nullptr; tree->type equals em_network_node_data_type_array_obj; tree->num_children equals 3.                 | Should Pass     |
 * | 03               | Iterate over each child node of the tree to verify each child's type and integer value.              | For each child: child[i]->type, child[i]->value_int; i = 0,1,2      | Each child != nullptr; child[i]->type equals em_network_node_data_type_number; child[i]->value_int equals (i+1).      | Should Pass     |
 * | 04               | Free the allocated network tree to clean up resources.                                             | input: tree pointer                                              | The network tree memory is freed successfully.                                                                    | Should be successful |
 */
TEST(em_net_node_t, get_network_tree_valid_JSON_array_input) {
    std::cout << "Entering get_network_tree_valid_JSON_array_input test" << std::endl;
    char buff[128];
    memset(buff, 0, sizeof(buff));
    strncpy(buff, "[1, 2, 3]", sizeof(buff) - 1);
    em_network_node_t* tree = em_net_node_t::get_network_tree(buff);
    ASSERT_NE(tree, nullptr);
    EXPECT_EQ(tree->type, em_network_node_data_type_array_obj);
    EXPECT_EQ(tree->num_children, 3u);
    for (unsigned int i = 0; i < 3; i++) {
        ASSERT_NE(tree->child[i], nullptr);
        EXPECT_EQ(tree->child[i]->type, em_network_node_data_type_number);
        EXPECT_EQ(tree->child[i]->value_int, static_cast<int>(i + 1));
    }
    em_net_node_t::free_network_tree(tree);
    std::cout << "Exiting get_network_tree_valid_JSON_array_input test" << std::endl;
}
/**
 * @brief Validate that get_network_tree_by_file processes a temporary valid JSON file and returns a correctly structured network tree.
 *
 * This test verifies that get_network_tree_by_file reads a valid JSON file, parses it into the expected network tree structure, and returns a non-null root with the proper child details. It ensures that the JSON is correctly interpreted and mapped to the network tree data structure.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 042
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                 | Test Data                                                                                                                                                                   | Expected Result                                                                                                              | Notes      |
 * | :--------------: | --------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------- | ---------- |
 * | 01               | Create a temporary JSON file, call get_network_tree_by_file, and validate the parsed network tree structure. | tmpFile = /tmp/test.json, file content = { "key": "rootValue" }, output: root->type = em_network_node_data_type_obj, num_children = 1, child[0]->key = "key", child[0]->value_str = "rootValue", child[0]->type = em_network_node_data_type_string | get_network_tree_by_file should return a valid network tree with a non-null root and correctly populated child node. | Should Pass |
 */
TEST(em_net_node_t, get_network_tree_by_file_temp_valid_json) {
    std::cout << "Entering get_network_tree_by_file_temp_valid_json test" << std::endl;
    // Create a temporary JSON file
    const char *tmpFile = "/tmp/test.json";
    {
        std::ofstream ofs(tmpFile);
        ofs << "{ \"key\": \"rootValue\" }";
    }
    em_network_node_t *root = em_net_node_t::get_network_tree_by_file(tmpFile);
    ASSERT_NE(root, nullptr);
    EXPECT_EQ(root->type, em_network_node_data_type_obj);
    EXPECT_EQ(root->num_children, 1u);
    ASSERT_NE(root->child[0], nullptr);
    EXPECT_STREQ(root->child[0]->key, "key");
    EXPECT_STREQ(root->child[0]->value_str, "rootValue");
    EXPECT_EQ(root->child[0]->type, em_network_node_data_type_string);
    em_net_node_t::free_network_tree(root);
    std::remove(tmpFile);

    std::cout << "Exiting get_network_tree_by_file_temp_valid_json test" << std::endl;
}
/**
 * @brief This test verifies the behavior of get_network_tree_by_file when provided with a file containing malformed JSON.
 *
 * This test creates a temporary file with invalid JSON content and then attempts to build a network tree using the get_network_tree_by_file function. The objective is to ensure that the function correctly handles malformed JSON input by returning a nullptr.
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
 * | Variation / Step | Description | Test Data | Expected Result |Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Create a temporary file with invalid JSON content | tmpFile = "/tmp/test.json", file content = "{ invalid_json: }" | File is created with malformed JSON | Should be successful |
 * | 02 | Invoke em_net_node_t::get_network_tree_by_file | tmpFile = "/tmp/test.json" | API returns nullptr due to invalid JSON | Should Pass |
 * | 03 | Validate the result using assertion | output: root pointer; Expected = nullptr | Assert that root is equal to nullptr | Should Pass |
 * | 04 | Remove the temporary file | tmpFile = "/tmp/test.json" | File is successfully removed from the system | Should be successful |
 */
TEST(em_net_node_t, get_network_tree_by_file_temp_invalid_json) {
    std::cout << "Entering get_network_tree_by_file_temp_invalid_json test" << std::endl;
    const char *tmpFile = "/tmp/test.json";
    std::ofstream ofs(tmpFile);
    ofs << "{ invalid_json: }"; // malformed JSON
    ofs.close();
    em_network_node_t *root = em_net_node_t::get_network_tree_by_file(tmpFile);
    ASSERT_EQ(root, nullptr);
    std::remove(tmpFile);
    std::cout << "Exiting get_network_tree_by_file_temp_invalid_json test" << std::endl;
}
/**
 * @brief Verify that get_network_tree_by_file returns a nullptr when a non-existent file is provided
 *
 * This test verifies that the get_network_tree_by_file function correctly returns a nullptr when provided with a file path that does not exist. It tests the API's ability to handle erroneous input gracefully, ensuring that it does not crash or return an unexpected value.
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
 * | :--------------: | ----------- | --------- | --------------- | ----- |
 * | 01 | Invoke get_network_tree_by_file with a non-existent file path | input: tmpFile = "/tmp/nonexistent.json", output: root pointer expected as nullptr | The API call returns a nullptr as the file does not exist and ASSERT_EQ verifies that root is nullptr | Should Pass |
 */
TEST(em_net_node_t, get_network_tree_by_file_temp_nonexistent_file) {
    std::cout << "Entering get_network_tree_by_file_temp_nonexistent_file test" << std::endl;
    const char *tmpFile = "/tmp/nonexistent.json";
    em_network_node_t *root = em_net_node_t::get_network_tree_by_file(tmpFile);
    ASSERT_EQ(root, nullptr);
    std::cout << "Exiting get_network_tree_by_file_temp_nonexistent_file test" << std::endl;
}
/**
 * @brief Test get_network_tree_by_file functionality with an empty JSON file.
 *
 * This test creates an empty JSON file and invokes the get_network_tree_by_file API to ensure that the function returns a nullptr when the file content is empty.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 045@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Create an empty file at /tmp/test.json | input: filePath = /tmp/test.json, file content = empty | File created with empty content | Should be successful |
 * | 02 | Call get_network_tree_by_file with the empty file | input: tmpFile = /tmp/test.json; output: root pointer expected to be nullptr | API returns nullptr and assertion passes | Should Pass |
 * | 03 | Remove the temporary file | input: filePath = /tmp/test.json | Temporary file is removed | Should be successful |
 */
TEST(em_net_node_t, get_network_tree_by_file_temp_empty_file) {
    std::cout << "Entering get_network_tree_by_file_temp_empty_file test" << std::endl;
    const char *tmpFile = "/tmp/test.json";
    std::ofstream ofs(tmpFile);
    ofs << ""; // empty content
    ofs.close();
    em_network_node_t *root = em_net_node_t::get_network_tree_by_file(tmpFile);
    ASSERT_EQ(root, nullptr);
    std::remove(tmpFile);
    std::cout << "Exiting get_network_tree_by_file_temp_empty_file test" << std::endl;
}
/**
 * @brief Test get_network_tree_by_file with null file name to verify that the API handles invalid input.
 *
 * This test validates that when a null file name is passed to get_network_tree_by_file, the API correctly returns a nullptr.
 * This ensures that the input validation for file names is performed, preventing further errors in file operations.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 046
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Invoke get_network_tree_by_file with fileName set to nullptr to validate handling of null input | fileName = nullptr, output root = nullptr | API returns nullptr and ASSERT_EQ confirms the returned value is nullptr | Should Pass |
 */
TEST(em_net_node_t, get_network_tree_by_file_null_file_name) {
    std::cout << "Entering get_network_tree_by_file_null_file_name test" << std::endl;
    em_net_node_t nodeObj;
    const char *fileName = nullptr;
    em_network_node_t *root = em_net_node_t::get_network_tree_by_file(fileName);
    ASSERT_EQ(root, nullptr);
    std::cout << "Exiting get_network_tree_by_file_null_file_name test" << std::endl;
}
/**
 * @brief Tests the behavior of get_network_tree_by_key when provided with a null network instance pointer.
 *
 * This test verifies that the API get_network_tree_by_key correctly handles a null input for the network instance by returning a null pointer.
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
 * | Variation / Step | Description                                                                           | Test Data                                  | Expected Result                                           | Notes       |
 * | :--------------: | ------------------------------------------------------------------------------------- | ------------------------------------------ | --------------------------------------------------------- | ----------- |
 * | 01               | Invoke get_network_tree_by_key with a null network instance pointer and a valid key "test". | node = nullptr, key = test                 | Returns nullptr and the assertion (ASSERT_EQ) passes.     | Should Pass |
 */
TEST(em_net_node_t, get_network_tree_by_key_null_input)
{
    std::cout << "Entering get_network_tree_by_key_null_input test" << std::endl;
    em_long_string_t key;
    strncpy(key, "test", sizeof(key));
    em_network_node_t* result = em_net_node_t::get_network_tree_by_key(nullptr, key);
    ASSERT_EQ(result, nullptr);
    std::cout << "Exiting get_network_tree_by_key_null_input test" << std::endl;
}
/**
 * @brief Verify that get_network_tree_by_key returns nullptr when an empty search key is provided.
 *
 * This test checks the behavior of the get_network_tree_by_key function when an empty search key is provided in a valid tree structure. The function should return nullptr since an empty search key does not match any valid node key.
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
 * | Variation / Step | Description                                                                                                             | Test Data                                                                                                   | Expected Result                                             | Notes       |
 * | :--------------: | ----------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------- | ----------- |
 * | 01               | Invoke get_network_tree_by_key with an empty search key on a network tree having a root node with key "anyKey" and no children | root.key = "anyKey", root.num_children = 0, all child pointers = nullptr, searchKey = ""                     | The API returns nullptr and ASSERT_EQ confirms that result is nullptr | Should Pass |
 */
TEST(em_net_node_t, get_network_tree_by_key_EmptyKeyInValidTree)
{
    std::cout << "Entering get_network_tree_by_key_EmptyKeyInValidTree test" << std::endl;
    em_network_node_t root;
    strncpy(root.key, "anyKey", sizeof(root.key));
    root.num_children = 0;
    for (int i = 0; i < EM_MAX_DM_CHILDREN; ++i)
    {
        root.child[i] = nullptr;
    }
    em_long_string_t searchKey;
    strncpy(searchKey, "", sizeof(searchKey));
    em_network_node_t* result = em_net_node_t::get_network_tree_by_key(&root, searchKey);
    ASSERT_EQ(result, nullptr);
    std::cout << "Exiting get_network_tree_by_key_EmptyKeyInValidTree test" << std::endl;
}
/**
 * @brief Verifies that get_network_tree_by_key correctly returns the root node when the search key matches the root's key.
 *
 * This test checks that when a network tree is searched with a key identical to the root node's key, the API returns a valid pointer to the root node. It ensures that the function behaves as expected when the matching key is located at the root.
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
 * | 01 | Invoke get_network_tree_by_key on the root node with key "root_key". | root.key = "root_key", root.num_children = 0, all root.child[i] = nullptr, searchKey = "root_key" | Returns a valid pointer to a node where key equals "root_key"; Assertions: ASSERT_NE(result, nullptr) and EXPECT_STREQ(result->key, "root_key") | Should Pass |
 */
TEST(em_net_node_t, get_network_tree_by_key_MatchingKeyAtRoot)
{
    std::cout << "Entering get_network_tree_by_key_MatchingKeyAtRoot test" << std::endl;
    em_network_node_t root;
    strncpy(root.key, "root_key", sizeof(root.key));
    root.num_children = 0;
    for (int i = 0; i < EM_MAX_DM_CHILDREN; ++i)
    {
        root.child[i] = nullptr;
    }
    em_long_string_t searchKey;
    strncpy(searchKey, "root_key", sizeof(searchKey));
    em_network_node_t* result = em_net_node_t::get_network_tree_by_key(&root, searchKey);
    ASSERT_NE(result, nullptr);
    EXPECT_STREQ(result->key, "root_key");
    std::cout << "Exiting get_network_tree_by_key_MatchingKeyAtRoot test" << std::endl;
}
/**
 * @brief Verify that get_network_tree_by_key correctly locates a matching child node
 *
 * This test verifies that when the network tree has a child node with a key matching the search key,
 * the get_network_tree_by_key API returns a pointer to that child node. The test sets up a root node
 * with one child, initializes the key values, and then searches for the child node by its key. This
 * ensures that child nodes are properly traversed and matched.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 050@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                 | Test Data                                                                      | Expected Result                                                                                      | Notes            |
 * | :--------------: | ----------------------------------------------------------- | ------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------- | ---------------- |
 * | 01               | Create a root node and initialize its child pointers          | root.key = "root", root.num_children = 1, for each child pointer: set to nullptr | Root node correctly created with child pointers initialized                                          | Should be successful |
 * | 02               | Create a child node and assign its key                        | child.key = "child", child.num_children = 0                                    | Child node correctly created with key "child"                                                        | Should be successful |
 * | 03               | Attach the child node to the root node                        | root.child[0] = &child                                                         | Child node successfully attached to root node                                                       | Should be successful |
 * | 04               | Search for the child node using the search key "child"        | searchKey = "child"                                                            | API returns a non-null pointer and the key matches "child" as verified by ASSERT_NE and EXPECT_STREQ  | Should Pass      |
 */
TEST(em_net_node_t, get_network_tree_by_key_MatchingKeyInChild)
{
    std::cout << "Entering get_network_tree_by_key_MatchingKeyInChild test" << std::endl;
    em_network_node_t root;
    strncpy(root.key, "root", sizeof(root.key));
    root.num_children = 1;
    for (int i = 0; i < EM_MAX_DM_CHILDREN; ++i)
    {
        root.child[i] = nullptr;
    }
    em_network_node_t child;
    strncpy(child.key, "child", sizeof(child.key));
    child.num_children = 0;
    root.child[0] = &child;
    em_long_string_t searchKey;
    strncpy(searchKey, "child", sizeof(searchKey));
    em_network_node_t* result = em_net_node_t::get_network_tree_by_key(&root, searchKey);
    ASSERT_NE(result, nullptr);
    EXPECT_STREQ(result->key, "child");
    std::cout << "Exiting get_network_tree_by_key_MatchingKeyInChild test" << std::endl;
}
/**
 * @brief Verify that get_network_tree_by_key returns nullptr when the search key is not found in the network tree.
 *
 * This test case checks that when a key that doesn't exist in the network tree is provided, the function em_net_node_t::get_network_tree_by_key correctly returns a nullptr. It ensures that the API handles non-existent keys gracefully without crashing or producing invalid results.@n
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
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Invoke get_network_tree_by_key with a root node containing two children ("child1" and "child2") and a search key "nonexistent". | input: root.key = "root", root.num_children = 2, child[0]->key = "child1", child[1]->key = "child2"; searchKey = "nonexistent" | API returns nullptr and ASSERT_EQ passes | Should Pass |
 */
TEST(em_net_node_t, get_network_tree_by_key_NoMatchingKey)
{
    std::cout << "Entering get_network_tree_by_key_NoMatchingKey test" << std::endl;
    em_network_node_t root;
    strncpy(root.key, "root", sizeof(root.key));
    root.num_children = 2;
    for (int i = 0; i < EM_MAX_DM_CHILDREN; ++i)
    {
        root.child[i] = nullptr;
    }

    em_network_node_t child1;
    strncpy(child1.key, "child1", sizeof(child1.key));
    child1.num_children = 0;
    em_network_node_t child2;
    strncpy(child2.key, "child2", sizeof(child2.key));
    child2.num_children = 0;
    root.child[0] = &child1;
    root.child[1] = &child2;
    em_long_string_t searchKey;
    strncpy(searchKey, "nonexistent", sizeof(searchKey));
    em_network_node_t* result = em_net_node_t::get_network_tree_by_key(&root, searchKey);
    ASSERT_EQ(result, nullptr);
    std::cout << "Exiting get_network_tree_by_key_NoMatchingKey test" << std::endl;
}
/**
 * @brief Test for get_network_tree_node with a NULL cJSON object.
 *
 * This test verifies that the get_network_tree_node API correctly handles the scenario when a NULL cJSON object is passed as an input. The API is expected to return 0 and set the appropriate output values when the input JSON object is NULL.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 052@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                       | Test Data                                                        | Expected Result                                          | Notes       |
 * | :--------------: | ----------------------------------------------------------------- | ---------------------------------------------------------------- | -------------------------------------------------------- | ----------- |
 * | 01               | Call get_network_tree_node with a NULL cJSON object               | argument1 = NULL, argument2 = pointer to root, argument3 = pointer to node_ctr | Return value 0 and EXPECT_EQ check passes                | Should Pass |
 */
TEST(em_net_node_t, get_network_tree_node_Null_cJSON_input) {
    std::cout << "Entering get_network_tree_node_Null_cJSON_input test" << std::endl;
    em_net_node_t netNode;
    em_network_node_t root;
    unsigned int node_ctr = 0;
    int ret = netNode.get_network_tree_node(NULL, &root, &node_ctr);
    EXPECT_EQ(ret, -1);
    std::cout << "Exiting get_network_tree_node_Null_cJSON_input test" << std::endl;
}
/**
 * @brief Test get_network_tree_node behavior when a NULL root pointer is provided.
 *
 * This test verifies that when a valid cJSON object with a key-value pair is provided along with a NULL root pointer and a valid node counter pointer, the get_network_tree_node function returns 0. This ensures the function correctly handles the null pointer scenario without crashing.
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
 * | Variation / Step | Description                                                                                              | Test Data                                                  | Expected Result                                            | Notes       |
 * | :--------------: | -------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------- | ---------------------------------------------------------- | ----------- |
 * | 01               | Create a valid cJSON object, add a key-value pair, and call get_network_tree_node with a NULL root pointer and a valid node counter pointer. | obj = cJSON object with key:"value", root = NULL, node_ctr = pointer to 0, ret = undefined | The function returns 0 and the EXPECT_EQ check passes.     | Should Pass |
 */
TEST(em_net_node_t, get_network_tree_node_Null_root_pointer) {
    std::cout << "Entering get_network_tree_node_Null_root_pointer test" << std::endl;
    em_net_node_t netNode;
    cJSON* obj = cJSON_CreateObject();
    cJSON_AddStringToObject(obj, "key", "value");
    unsigned int node_ctr = 0;
    int ret = netNode.get_network_tree_node(obj, NULL, &node_ctr);
    EXPECT_EQ(ret,-1);
    cJSON_Delete(obj);
    std::cout << "Exiting get_network_tree_node_Null_root_pointer test" << std::endl;
}
/**
 * @brief Validate that get_network_tree_node handles a NULL node_ctr pointer correctly.
 *
 * This test verifies that when the get_network_tree_node API is invoked with a valid JSON object,
 * a valid pointer to the network node (root), and a NULL pointer for the node_ctr parameter, the API
 * returns the expected result. This ensures that the function can gracefully handle a NULL node_ctr pointer.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 054@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                                                           | Test Data                                                              | Expected Result                                           | Notes       |
 * | :--------------: | ----------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------- | --------------------------------------------------------- | ----------- |
 * | 01               | Invoke get_network_tree_node with a valid JSON object, a valid pointer to em_network_node_t, and NULL for node_ctr. | obj = JSON object with key = "value", root pointer = &root, node_ctr = NULL | Return value equals 0 and the assertion EXPECT_EQ(ret, 0) passes | Should Pass |
 */
TEST(em_net_node_t, get_network_tree_node_Null_node_ctr_pointer) {
    std::cout << "Entering get_network_tree_node_Null_node_ctr_pointer test" << std::endl;
    em_net_node_t netNode;
    cJSON* obj = cJSON_CreateObject();
    cJSON_AddStringToObject(obj, "key", "value");
    em_network_node_t root;
    int ret = netNode.get_network_tree_node(obj, &root, NULL);
    EXPECT_EQ(ret,-1);
    cJSON_Delete(obj);
    std::cout << "Exiting get_network_tree_node_Null_node_ctr_pointer test" << std::endl;
}
/**
 * @brief Validate that get_network_tree_node returns success when provided with an empty cJSON object
 *
 * This test validates that calling get_network_tree_node with a valid empty cJSON object correctly initializes the root network node and returns a success code (0). It ensures that the API functions as expected in a minimal input scenario.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 055@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description                                               | Test Data                                                              | Expected Result                                          | Notes              |
 * | :--------------: | --------------------------------------------------------- | ---------------------------------------------------------------------- | -------------------------------------------------------- | ------------------ |
 * | 01               | Initialize test environment and objects                   | N/A                                                                    | Test environment is set up successfully                | Should be successful |
 * | 02               | Create an empty cJSON object                              | obj = cJSON_CreateObject()                                               | cJSON object is created without error                  | Should be successful |
 * | 03               | Configure root network node with zero children            | root.num_children = 0                                                    | Root node is initialized with no children              | Should be successful |
 * | 04               | Invoke get_network_tree_node API with empty cJSON object    | input: obj, root, node_ctr = 0; output: ret expected = 0                 | API returns 0 and assertion check passes               | Should Pass        |
 * | 05               | Clean up allocated cJSON object                           | cJSON_Delete(obj)                                                        | Memory is freed with no leaks                          | Should be successful |
 */
TEST(em_net_node_t, get_network_tree_node_Valid_empty_cJSON_object) {
    std::cout << "Entering get_network_tree_node_Valid_empty_cJSON_object test" << std::endl;
    em_net_node_t netNode;
    cJSON* obj = cJSON_CreateObject();
    em_network_node_t root;
    root.num_children = 0;
    unsigned int node_ctr = 0;
    int ret = netNode.get_network_tree_node(obj, &root, &node_ctr);
    EXPECT_EQ(0, ret);
    cJSON_Delete(obj);
    std::cout << "Exiting get_network_tree_node_Valid_empty_cJSON_object test" << std::endl;
}
/**
 * @brief Validate get_network_tree_node API with a basic cJSON object containing a single key-value pair
 *
 * This test verifies that the get_network_tree_node API correctly processes a simple cJSON object with one key "name" and value "test". It checks that the API returns the expected result, and that the resulting network tree node contains the correct key, value, and type.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 056@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Create a cJSON object and add a key-value pair ("name": "test") and initialize root node and node counter | cJSON object with "name" = "test", root.num_children = 0, node_ctr = 0 | cJSON object created and variables initialized | Should be successful |
 * | 02 | Invoke get_network_tree_node API with the created cJSON object, root node pointer, and node counter pointer | input: obj, root pointer, node_ctr pointer; no direct output parameter | return value expected as 1 from API invocation | Should Pass |
 * | 03 | Validate that when API returns 1, the first child of the root node is non-null and its key is "name", value is "test", and type is em_network_node_data_type_string | API output: ret = 1, root.child[0]->key = "name", root.child[0]->value_str = "test", root.child[0]->type = em_network_node_data_type_string | API correctly filled child node structure | Should Pass |
 * | 04 | Cleanup allocated memory for the root's children and delete the cJSON object | free allocated memory, delete cJSON object | Memory freed and no leaks | Should be successful |
 */
TEST(em_net_node_t, get_network_tree_node_Valid_simple_cJSON_object) {
    std::cout << "Entering get_network_tree_node_Valid_simple_cJSON_object test" << std::endl;
    em_net_node_t netNode;
    cJSON* obj = cJSON_CreateObject();
    cJSON_AddStringToObject(obj, "name", "test");
    em_network_node_t root;
    root.num_children = 0;
    unsigned int node_ctr = 0;
    int ret = netNode.get_network_tree_node(obj, &root, &node_ctr);
    EXPECT_EQ(1, ret);
    if(ret == 1 && root.num_children > 0 && root.child[0] != nullptr) {
        EXPECT_EQ(0, strncmp(root.child[0]->key, "name", sizeof(root.child[0]->key)));
        EXPECT_EQ(0, strncmp(root.child[0]->value_str, "test", sizeof(root.child[0]->value_str)));
        EXPECT_EQ(em_network_node_data_type_string, root.child[0]->type);
    }
    for (unsigned int i = 0; i < root.num_children; i++) {
       free(root.child[i]);
       root.child[i] = nullptr;
    }
    cJSON_Delete(obj);
    std::cout << "Exiting get_network_tree_node_Valid_simple_cJSON_object test" << std::endl;
}
/**
 * @brief Test get_network_tree_node with valid nested cJSON object containing multiple levels of children
 *
 * This test verifies that the get_network_tree_node API correctly parses a nested cJSON object with a parent containing two children.
 * The test constructs a valid nested cJSON object, invokes get_network_tree_node, and then validates that the network tree node is populated
 * with the appropriate child entries having correct keys, values, and types. The API is expected to return 1 if the operation is successful.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 057@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:** 
 * | Variation / Step | Description                                                                                                    | Test Data                                                                                                                                                          | Expected Result                                                                                                                             | Notes           |
 * | :--------------: | -------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------- | --------------- |
 * | 01               | Construct a nested cJSON object with a parent and two children ("child1" with "value1", "child2" with "value2"). | input: obj = cJSON object, parent_obj = cJSON object with child1="value1", child2="value2"                                                                           | cJSON object is set up correctly with a parent node holding two child key-value pairs.                                                      | Should be successful |
 * | 02               | Initialize network node structure and invoke get_network_tree_node API.                                        | input: obj (constructed above), root (em_network_node_t with num_children = 0), node_ctr = 0                                                                          | API returns 1, and the network tree 'root' is populated with a child node having type em_network_node_data_type_obj and num_children = 2.       | Should Pass     |
 * | 03               | Validate the child nodes within the network tree ensuring keys and values match expected values.                | input: root.child[0]->child[0]: key = "child1", value_str = "value1", type = em_network_node_data_type_string; root.child[0]->child[1]: key = "child2", value_str = "value2", type = em_network_node_data_type_string | Child nodes contain correct key-value pairs and data types as verified by string comparisons and type assertions. | Should Pass     |
 * | 04               | Clean up allocated resources by freeing network tree nodes and deleting the cJSON object.                       | input: allocated root child nodes and the cJSON object                                                                                                              | Resources are freed and cJSON object is deleted without memory leaks.                                                                       | Should be successful |
 */
TEST(em_net_node_t, get_network_tree_node_Valid_nested_cJSON_object) {
    std::cout << "Entering get_network_tree_node_Valid_nested_cJSON_object test" << std::endl;
    em_net_node_t netNode;
    cJSON* obj = cJSON_CreateObject();
    cJSON* parent_obj = cJSON_CreateObject();
    cJSON_AddStringToObject(parent_obj, "child1", "value1");
    cJSON_AddStringToObject(parent_obj, "child2", "value2");
    cJSON_AddItemToObject(obj, "parent", parent_obj);
    em_network_node_t root;
    root.num_children = 0;
    unsigned int node_ctr = 0;
    int ret = netNode.get_network_tree_node(obj, &root, &node_ctr);
    EXPECT_EQ(ret, 1);
    if(ret == 1 && root.num_children > 0 && root.child[0] != nullptr) {
        EXPECT_EQ(em_network_node_data_type_obj, root.child[0]->type);
        EXPECT_EQ(2, root.child[0]->num_children);
        if(root.child[0]->num_children >= 2 && root.child[0]->child[0] != nullptr && root.child[0]->child[1] != nullptr) {
            EXPECT_EQ(0, strncmp(root.child[0]->child[0]->key, "child1", sizeof(root.child[0]->child[0]->key)));
            EXPECT_EQ(0, strncmp(root.child[0]->child[0]->value_str, "value1", sizeof(root.child[0]->child[0]->value_str)));
            EXPECT_EQ(em_network_node_data_type_string, root.child[0]->child[0]->type);

            EXPECT_EQ(0, strncmp(root.child[0]->child[1]->key, "child2", sizeof(root.child[0]->child[1]->key)));
            EXPECT_EQ(0, strncmp(root.child[0]->child[1]->value_str, "value2", sizeof(root.child[0]->child[1]->value_str)));
            EXPECT_EQ(em_network_node_data_type_string, root.child[0]->child[1]->type);
        }
    }
    for (unsigned int i = 0; i < root.num_children; i++) {
        for (unsigned int j = 0; j < root.child[i]->num_children; j++) {
            free(root.child[i]->child[j]);
	    root.child[i]->child[j] = nullptr;
	}
        free(root.child[i]);
        root.child[i] = nullptr;
    }
    cJSON_Delete(obj);
    std::cout << "Exiting get_network_tree_node_Valid_nested_cJSON_object test" << std::endl;
}
/**
 * @brief Validate that get_network_tree_node correctly parses a valid JSON object with multiple children
 *
 * This test verifies that the get_network_tree_node API correctly handles a JSON object containing multiple key-value pairs.
 * The function is expected to correctly parse each element and build a tree node with children corresponding to every key.
 * The verification includes checking the return value of the API, the number of children in the result, and the specific attributes
 * (key, type, and value) of each child node.
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
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Create a JSON object and add key-value pairs | a = 1, b = "text", c = true, d = 55 | JSON object is created with 4 key-value pairs | Should be successful |
 * | 02 | Initialize network node structure and variable for node count | root = zeroed structure, node_ctr = 0 | Network node structure is properly initialized with no children | Should be successful |
 * | 03 | Call get_network_tree_node API with the JSON object and initialized network node | obj = JSON object, root pointer, node_ctr initial value 0 | API returns 4 indicating four elements processed | Should Pass |
 * | 04 | Verify that the root node has the correct number of children | ret from API = 4, root.num_children | root.num_children equals 4 | Should Pass |
 * | 05 | Validate first child's properties (key "a", number type, value 1) | child[0]: key = "a", type = number, value_int = 1 | Child node exists with matching key, type, and integer value | Should Pass |
 * | 06 | Validate second child's properties (key "b", string type, value "text") | child[1]: key = "b", type = string, value_str = "text" | Child node exists with matching key, type, and string value | Should Pass |
 * | 07 | Validate third child's properties (key "c", true type) | child[2]: key = "c", type = true | Child node exists with matching key and boolean type indicating true | Should Pass |
 * | 08 | Validate fourth child's properties (key "d", number type, value 55) | child[3]: key = "d", type = number, value_int = 55 | Child node exists with matching key, type, and integer value | Should Pass |
 * | 09 | Free allocated memory and clean up | Free each child node and delete the JSON object | Memory is properly freed without leaks | Should be successful |
 */
TEST(em_net_node_t, get_network_tree_node_Valid_object_with_multiple_children) {
    std::cout << "Entering get_network_tree_node_Valid_object_with_multiple_children test" << std::endl;
    em_net_node_t netNode;
    cJSON* obj = cJSON_CreateObject();
    cJSON_AddNumberToObject(obj, "a", 1);
    cJSON_AddStringToObject(obj, "b", "text");
    cJSON_AddBoolToObject(obj, "c", true);
    cJSON_AddNumberToObject(obj, "d", 55);
    em_network_node_t root;
    memset(&root, 0, sizeof(root));
    unsigned int node_ctr = 0;
    int ret = netNode.get_network_tree_node(obj, &root, &node_ctr);
    EXPECT_EQ(ret, 4);
    EXPECT_EQ(root.num_children, 4u);
    // Child 0: a = 1
    ASSERT_NE(root.child[0], nullptr);
    EXPECT_STREQ(root.child[0]->key, "a");
    EXPECT_EQ(root.child[0]->type, em_network_node_data_type_number);
    EXPECT_EQ(root.child[0]->value_int, 1);
    // Child 1: b = "text"
    ASSERT_NE(root.child[1], nullptr);
    EXPECT_STREQ(root.child[1]->key, "b");
    EXPECT_EQ(root.child[1]->type, em_network_node_data_type_string);
    EXPECT_STREQ(root.child[1]->value_str, "text");
    // Child 2: c = true
    ASSERT_NE(root.child[2], nullptr);
    EXPECT_STREQ(root.child[2]->key, "c");
    EXPECT_EQ(root.child[2]->type, em_network_node_data_type_true);
    // Child 3: d = 55
    ASSERT_NE(root.child[3], nullptr);
    EXPECT_STREQ(root.child[3]->key, "d");
    EXPECT_EQ(root.child[3]->type, em_network_node_data_type_number);
    EXPECT_EQ(root.child[3]->value_int, 55);
    for (unsigned int i = 0; i < root.num_children; i++) {
        free(root.child[i]);
        root.child[i] = nullptr;
    }
    cJSON_Delete(obj);
    std::cout << "Exiting get_network_tree_node_Valid_object_with_multiple_children test" << std::endl;
}
/**
 * @brief Validate the functionality of get_network_tree_node_string for a simple valid node
 *
 * This test verifies that get_network_tree_node_string correctly processes a simple network node.
 * The node contains a key "node1" and an integer value 42. The function is expected to insert the
 * node's key and value into the provided string buffer and update the identifier accordingly.
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
 * | Variation / Step | Description                                                            | Test Data                                                                                           | Expected Result                                                                                                  | Notes      |
 * | :--------------: | ---------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------- | ---------- |
 * | 01               | Invoke get_network_tree_node_string with valid simple node parameters  | str = char[256]={0}, node.key = "node1", node.type = em_network_node_data_type_number, node.value_int = 42, node.num_children = 0, ident = 0 | The output string should contain "node1" and "42", and ident should be updated to a non-negative number | Should Pass |
 */
TEST(em_net_node_t, get_network_tree_node_string_valid_simple_node) {
    std::cout << "Entering get_network_tree_node_string_valid_simple_node test" << std::endl;
    char str[256] = {0};
    unsigned int ident = 0;
    em_network_node_t node;
    memset(&node, 0, sizeof(node));
    strncpy(node.key, "node1", sizeof(node.key) - 1);
    node.type = em_network_node_data_type_number;
    node.value_int = 42;
    node.num_children = 0;
    em_net_node_t::get_network_tree_node_string(str, &node, &ident);
    EXPECT_NE(std::strstr(str, "node1"), nullptr);
    EXPECT_NE(std::strstr(str, "42"), nullptr);
    EXPECT_GE(ident, 0u);
    std::cout << "Exiting get_network_tree_node_string_valid_simple_node test" << std::endl;
}
/**
 * @brief Test to verify that the network tree node string is correctly composed for a valid composite node.
 *
 * This test creates a composite network tree node with a parent node having one child. The child node is initialized
 * with a valid string value. Upon invoking the get_network_tree_node_string function, the resultant string is checked 
 * to confirm that it contains the key of the parent node, the key of the child node, and the child's string value.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 060@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                                 | Test Data                                                                                                                                          | Expected Result                                                                                      | Notes       |
 * | :--------------: | ------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------- | ----------- |
 * | 01               | Create a composite network tree node with a parent and one child, invoke get_network_tree_node_string | parent.key = "parent", parent.type = em_network_node_data_type_obj, parent.num_children = 1, child.key = "child1", child.type = em_network_node_data_type_string, child.value_str = "example", child.num_children = 0 | The output string should contain "parent", "child1", and "example", as validated by the substring assertions | Should Pass |
 */
TEST(em_net_node_t, get_network_tree_node_string_valid_composite_node) {
    std::cout << "Entering get_network_tree_node_string_valid_composite_node test" << std::endl;
    char str[512] = {0};
    unsigned int ident = 0;
    em_network_node_t parent;
    memset(&parent, 0, sizeof(parent));
    strncpy(parent.key, "parent", sizeof(parent.key) - 1);
    parent.type = em_network_node_data_type_obj;
    parent.num_children = 1;
    em_network_node_t child;
    memset(&child, 0, sizeof(child));
    strncpy(child.key, "child1", sizeof(child.key) - 1);
    child.type = em_network_node_data_type_string;
    strncpy(child.value_str, "example", sizeof(child.value_str) - 1);
    child.num_children = 0;
    parent.child[0] = &child;
    em_net_node_t::get_network_tree_node_string(str, &parent, &ident);
    EXPECT_NE(std::strstr(str, "parent"), nullptr);
    EXPECT_NE(std::strstr(str, "child1"), nullptr);
    EXPECT_NE(std::strstr(str, "example"), nullptr);
    std::cout << "Exiting get_network_tree_node_string_valid_composite_node test" << std::endl;
}
/**
 * @brief Validate that get_network_tree_node_string produces a correct deep recursive string representation of the network tree.
 *
 * This test verifies that the get_network_tree_node_string API correctly traverses a deep recursive network tree structure. The test constructs a tree with a root node having two children, where one child further contains a grandchild. The output string is then checked to ensure that it includes the correct keys for all nodes. This ensures that the API handles recursive tree structures properly.
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
 * | Variation / Step | Description | Test Data | Expected Result | Notes |@n
 * | :----: | --------- | ---------- |-------------- | ----- |@n
 * | 01 | Initialize network tree nodes (root, child nodes and grandchild) | root.key = "root", root.type = em_network_node_data_type_array_obj, root.num_children = 2, child1.key = "child1", child1.type = em_network_node_data_type_false, child1.num_children = 0, child2.key = "child2", child2.type = em_network_node_data_type_array_obj, child2.num_children = 1, grandchild.key = "grandchild", grandchild.type = em_network_node_data_type_true, grandchild.num_children = 0 | Network tree nodes initialized successfully | Should be successful |@n
 * | 02 | Invoke get_network_tree_node_string API with the initialized tree | str = char[1024] (all elements set to 0), ident = 0, network tree node pointers for root, child1, child2, and grandchild | API completes execution and modifies str to include node keys from the tree | Should be successful |@n
 * | 03 | Validate output contains "root" key | str output from API call | strstr(str, "root") != nullptr | Should Pass |@n
 * | 04 | Validate output contains "child1" key | str output from API call | strstr(str, "child1") != nullptr | Should Pass |@n
 * | 05 | Validate output contains "child2" key | str output from API call | strstr(str, "child2") != nullptr | Should Pass |@n
 * | 06 | Validate output contains "grandchild" key | str output from API call | strstr(str, "grandchild") != nullptr | Should Pass |
 */
TEST(em_net_node_t, get_network_tree_node_string_valid_deep_recursive) {
    std::cout << "Entering get_network_tree_node_string_valid_deep_recursive test" << std::endl;
    char str[1024] = {0};
    unsigned int ident = 0;
    em_network_node_t root;
    memset(&root, 0, sizeof(root));
    strncpy(root.key, "root", sizeof(root.key) - 1);
    root.type = em_network_node_data_type_array_obj;
    root.num_children = 2;
    em_network_node_t child1;
    memset(&child1, 0, sizeof(child1));
    strncpy(child1.key, "child1", sizeof(child1.key) - 1);
    child1.type = em_network_node_data_type_false;
    child1.num_children = 0;
    em_network_node_t child2;
    memset(&child2, 0, sizeof(child2));
    strncpy(child2.key, "child2", sizeof(child2.key) - 1);
    child2.type = em_network_node_data_type_array_obj;
    child2.num_children = 1;
    em_network_node_t grandchild;
    memset(&grandchild, 0, sizeof(grandchild));
    strncpy(grandchild.key, "grandchild", sizeof(grandchild.key) - 1);
    grandchild.type = em_network_node_data_type_true;
    grandchild.num_children = 0;
    child2.child[0] = &grandchild;
    root.child[0] = &child1;
    root.child[1] = &child2;
    em_net_node_t::get_network_tree_node_string(str, &root, &ident);
    EXPECT_NE(std::strstr(str, "root"), nullptr);
    EXPECT_NE(std::strstr(str, "child1"), nullptr);
    EXPECT_NE(std::strstr(str, "child2"), nullptr);
    EXPECT_NE(std::strstr(str, "grandchild"), nullptr);
    std::cout << "Exiting get_network_tree_node_string_valid_deep_recursive test" << std::endl;
}
/**
 * @brief Verify that get_network_tree_node_string properly handles a null string pointer parameter.
 *
 * This test verifies that the API function get_network_tree_node_string throws an exception when the first parameter (string pointer) is null. It ensures that the function implements proper error checking to avoid undefined behavior with invalid input.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 062
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                        | Test Data                                                                                                                                                        | Expected Result                                             | Notes      |
 * | :--------------: | ---------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------- | ---------- |
 * | 01               | Invoke get_network_tree_node_string with a null string pointer to verify exception. | string parameter = nullptr, node = { key: "node_null_str", type: em_network_node_data_type_number, value_int: 100, num_children: 0 }, ident = 0                | Exception is thrown as expected from the API call.          | Should Pass |
 */
TEST(em_net_node_t, get_network_tree_node_string_null_str_pointer) {
    std::cout << "Entering get_network_tree_node_string_null_str_pointer test" << std::endl;
    unsigned int ident = 0;
    em_network_node_t node;
    memset(&node, 0, sizeof(node));
    strncpy(node.key, "node_null_str", sizeof(node.key) - 1);
    node.type = em_network_node_data_type_number;
    node.value_int = 100;
    node.num_children = 0;
    EXPECT_ANY_THROW({
        em_net_node_t::get_network_tree_node_string(nullptr, &node, &ident);
    });
    std::cout << "Exiting get_network_tree_node_string_null_str_pointer test" << std::endl;
}
/**
 * @brief Verify get_network_tree_node_string handles null node pointer
 *
 * This test validates that the get_network_tree_node_string function correctly handles the scenario where a null node pointer is provided by throwing an exception. This ensures that the API enforces proper error handling for invalid input.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 063
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                    | Test Data                                                                               | Expected Result                                                           | Notes       |
 * | :--------------: | -------------------------------------------------------------- | --------------------------------------------------------------------------------------- | ------------------------------------------------------------------------- | ----------- |
 * | 01               | Invoke get_network_tree_node_string with a null node pointer     | str = char[256] (initialized with zeros), node pointer = nullptr, ident = address of unsigned int (initialized to 0) | Function throws an exception as validated by EXPECT_ANY_THROW             | Should Pass |
 */
TEST(em_net_node_t, get_network_tree_node_string_null_node_pointer) {
    std::cout << "Entering get_network_tree_node_string_null_node_pointer test" << std::endl;
    char str[256] = {0};
    unsigned int ident = 0;
    EXPECT_ANY_THROW({
        em_net_node_t::get_network_tree_node_string(str, nullptr, &ident);
    });
    std::cout << "Exiting get_network_tree_node_string_null_node_pointer test" << std::endl;
}
/**
 * @brief Verify get_network_tree_node_string handles null pident pointer correctly
 *
 * This test validates that the function get_network_tree_node_string correctly processes a network node when the identifier pointer (pident) is passed as nullptr. It ensures that, even without a valid pident, the output string contains the node's key.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 064@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize a network node with key "node_null_pident", type set to string, value_str as "test", and no children. Invoke get_network_tree_node_string with a null pident pointer. | input: str (char array with size 256, zero initialized), node.key = "node_null_pident", node.type = em_network_node_data_type_string, node.value_str = "test", node.num_children = 0; pident = nullptr | Function throws an exception as validated by EXPECT_ANY_THROW | Should Pass |
 */
TEST(em_net_node_t, get_network_tree_node_string_null_pident_pointer) {
    std::cout << "Entering get_network_tree_node_string_null_pident_pointer test" << std::endl;
    char str[256] = {0};
    em_network_node_t node;
    memset(&node, 0, sizeof(node));
    strncpy(node.key, "node_null_pident", sizeof(node.key) - 1);
    node.type = em_network_node_data_type_string;
    strncpy(node.value_str, "test", sizeof(node.value_str) - 1);
    node.num_children = 0;
    EXPECT_ANY_THROW({
        em_net_node_t::get_network_tree_node_string(str, &node, nullptr);
    });
    std::cout << "Exiting get_network_tree_node_string_null_pident_pointer test" << std::endl;
}
/**
 * @brief Test to verify get_network_tree_node_string handles empty key and invalid type correctly
 *
 * This test checks whether the get_network_tree_node_string function properly processes a network node with an empty key and an invalid data type. The function is expected to leave the provided string empty and not modify the identifier. This ensures that the function behaves as expected in edge case scenarios where the input node does not contain valid data.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 065@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                       | Test Data                                                                                                   | Expected Result                                                                                      | Notes           |
 * | :--------------: | ----------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------- | --------------- |
 * | 01               | Initialize test variables including a zeroed char array, identifier, and network node with invalid type | str = array of 256 zeros, ident = 5, node.type = em_network_node_data_type_invalid, node.num_children = 0 | Variables initialized correctly                                                                       | Should be successful |
 * | 02               | Invoke get_network_tree_node_string with the initialized variables  | Input: str, &node, &ident                                                                                | Function executes without altering ident and keeps str as an empty string                             | Should Pass     |
 * | 03               | Validate the output by checking that the string is empty and the identifier remains unchanged  | Expected: str = "", ident = 5                                                                               | EXPECT_STREQ confirms str is "", and EXPECT_EQ confirms ident is 5u                                    | Should Pass     |
 * | 04               | Log the exit message indicating completion of the test             | Console output of exit message                                                                              | The exit message is printed to the console                                                             | Should be successful |
 */
TEST(em_net_node_t, get_network_tree_node_string_edge_case_empty_key_invalid_type) {
    std::cout << "Entering get_network_tree_node_string_edge_case_empty_key_invalid_type test" << std::endl;
    char str[256] = {0};
    unsigned int ident = 5;
    em_network_node_t node;
    memset(&node, 0, sizeof(node));
    node.type = em_network_node_data_type_invalid;
    node.num_children = 0;
    em_net_node_t::get_network_tree_node_string(str, &node, &ident);
    EXPECT_STREQ(str, "");
    EXPECT_EQ(ident, 5u);
    std::cout << "Exiting get_network_tree_node_string_edge_case_empty_key_invalid_type test" << std::endl;
}
/**
 * @brief Validate get_network_tree_string returns nullptr when input is NULL
 *
 * This test verifies that the get_network_tree_string function correctly handles a NULL input by returning a NULL pointer. The test is crucial for ensuring the API's robustness in handling edge cases.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 066@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                      | Test Data                                             | Expected Result                                              | Notes              |
 * | :--------------: | ---------------------------------------------------------------- | ----------------------------------------------------- | ------------------------------------------------------------ | ------------------ |
 * | 01               | Invoke get_network_tree_string with NULL input                   | netNode instance, input = nullptr                     | API returns a nullptr                                        | Should Pass        |
 * | 02               | Validate the return value is nullptr with an assertion check       | output: result pointer from get_network_tree_string   | ASSERT_EQ confirms that result equals nullptr                 | Should be successful |
 */
TEST(em_net_node_t, get_network_tree_string_NULL_input) {
    std::cout << "Entering get_network_tree_string_NULL_input test\n";
    em_net_node_t netNode;
    char *result = netNode.get_network_tree_string(nullptr);
    ASSERT_EQ(result, nullptr);
    std::cout << "Exiting get_network_tree_string_NULL_input test\n";
}
/**
 * @brief Test to verify that get_network_tree_string correctly generates a tree string representation for a valid single node
 *
 * This test creates a single network node with valid key and value fields and checks that the get_network_tree_string method returns a valid string which contains both the node key and its string value. It ensures that no memory issues occur and that the output is as expected for a valid input.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 067@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                                           | Test Data                                                                                                                                                                                           | Expected Result                                                                                                                                        | Notes      |
 * | :--------------: | ----------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ | ---------- |
 * | 01               | Create a network node with valid parameters and invoke get_network_tree_string to retrieve its string representation | rootNode.key = "root", rootNode.value_str = "sample_value", rootNode.collapsed = false, rootNode.orig_node_ctr = 1, rootNode.node_ctr = 1, rootNode.node_pos = 0, rootNode.type = em_network_node_data_type_string, rootNode.num_children = 0 | The API returns a non-null pointer and the resulting string contains "root" and "sample_value". Assertion checks (ASSERT_NE and EXPECT_NE) pass | Should Pass |
 */
TEST(em_net_node_t, get_network_tree_string_single_valid_node) {
    std::cout << "Entering get_network_tree_string_single_valid_node test\n";
    em_network_node_t rootNode = {};
    strncpy(rootNode.key, "root", sizeof(rootNode.key));
    rootNode.display_info.collapsed = false;
    rootNode.display_info.orig_node_ctr = 1;
    rootNode.display_info.node_ctr = 1;
    rootNode.display_info.node_pos = 0;
    rootNode.type = em_network_node_data_type_string;
    strncpy(rootNode.value_str, "sample_value", sizeof(rootNode.value_str));
    rootNode.value_int = 0;
    rootNode.num_children = 0;

    em_net_node_t netNode;
    char *result = netNode.get_network_tree_string(&rootNode);
    ASSERT_NE(result, nullptr);
    if(result) {
        std::string strResult(result);
        EXPECT_NE(strResult.find("root"), std::string::npos);
        EXPECT_NE(strResult.find("sample_value"), std::string::npos);
	free(result);
    }

    std::cout << "Exiting get_network_tree_string_single_valid_node test\n";
}
/**
 * @brief Test get_network_tree_string API to validate multi-level network tree string representation.
 *
 * This test verifies that the get_network_tree_string API correctly processes a multilevel network tree
 * consisting of a root node and two child nodes. It checks that the returned string contains expected
 * substrings corresponding to node keys and values based on node collapse properties.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 068@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize and configure the root network node and its child nodes (child1 and child2) to form a multilevel tree. | root node: key="root", display_info:{collapsed=false, orig_node_ctr=1, node_ctr=1, node_pos=0}, value_str="root_value", value_int=0; child1: key="child1", display_info:{collapsed=false, orig_node_ctr=2, node_ctr=1, node_pos=0}, value_str="child1_value", value_int=10; child2: key="child2", display_info:{collapsed=true, orig_node_ctr=3, node_ctr=1, node_pos=1}, value_str="child2_value", value_int=20 | Network tree structure is constructed with proper parent-child relationships. | Should be successful |
 * | 02 | Invoke the get_network_tree_string API using the constructed network tree. | Input: pointer to the root node | API returns a valid non-null string pointer representing the network tree. | Should Pass |
 * | 03 | Validate the content of the returned string against expected substrings. | Expected: Contains "root", "child1", "child2"; Excludes "root_value" and "child2_value"; Includes "child1_value" | Returned string contains all required substrings as per the test expectations. | Should Pass |
 * | 04 | Release allocated memory for the returned string. | Output: result pointer | Memory is freed successfully without errors. | Should be successful |
 */
TEST(em_net_node_t, get_network_tree_string_multilevel_tree) {
    std::cout << "Entering get_network_tree_string_multilevel_tree test\n";
    em_network_node_t rootNode = {};
    strncpy(rootNode.key, "root", sizeof(rootNode.key));
    rootNode.display_info.collapsed = false;
    rootNode.display_info.orig_node_ctr = 1;
    rootNode.display_info.node_ctr = 1;
    rootNode.display_info.node_pos = 0;
    rootNode.type = em_network_node_data_type_obj;
    strncpy(rootNode.value_str, "root_value", sizeof(rootNode.value_str));
    rootNode.value_int = 0;

    em_network_node_t child1 = {};
    strncpy(child1.key, "child1", sizeof(child1.key));
    child1.display_info.collapsed = false;
    child1.display_info.orig_node_ctr = 2;
    child1.display_info.node_ctr = 1;
    child1.display_info.node_pos = 0;
    child1.type = em_network_node_data_type_string;
    strncpy(child1.value_str, "child1_value", sizeof(child1.value_str));
    child1.value_int = 10;
    child1.num_children = 0;

    em_network_node_t child2 = {};
    strncpy(child2.key, "child2", sizeof(child2.key));
    child2.display_info.collapsed = true;
    child2.display_info.orig_node_ctr = 3;
    child2.display_info.node_ctr = 1;
    child2.display_info.node_pos = 1;
    child2.type = em_network_node_data_type_number;
    strncpy(child2.value_str, "child2_value", sizeof(child2.value_str));
    child2.value_int = 20;
    child2.num_children = 0;

    rootNode.child[0] = &child1;
    rootNode.child[1] = &child2;
    rootNode.num_children = 2;

    em_net_node_t netNode;
    char *result = netNode.get_network_tree_string(&rootNode);
    ASSERT_NE(result, nullptr);
    if(result) {
        std::string strResult(result);
        EXPECT_NE(strResult.find("root"), std::string::npos);
        EXPECT_NE(strResult.find("child1"), std::string::npos);
        EXPECT_NE(strResult.find("child2"), std::string::npos);
        EXPECT_EQ(strResult.find("root_value"), std::string::npos);
	    EXPECT_NE(strResult.find("child1_value"), std::string::npos);
	    EXPECT_EQ(strResult.find("child2_value"), std::string::npos);
	    free(result);
    }
    std::cout << "Exiting get_network_tree_string_multilevel_tree test\n";
}
/**
 * @brief This test verifies the conversion of em_network_node_t enum values into their network tree string representation.
 *
 * This test iterates over all enum values from em_network_node_data_type_invalid to em_network_node_data_type_raw and constructs an em_network_node_t structure for each value. It then calls the get_network_tree_string API to generate the network tree string. Depending on whether the node type is expected to output a string (for types: em_network_node_data_type_false, em_network_node_data_type_true, em_network_node_data_type_number, em_network_node_data_type_string, em_network_node_data_type_array_obj, em_network_node_data_type_obj) or not, the test asserts that the resulting string includes or excludes the generated key. This ensures that the API returns the proper string content for valid string output types and none or an empty string for other types.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 069@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize the node structure and generate a keyBuffer based on the current enum index | enumIndex = value from em_network_node_data_type_invalid to em_network_node_data_type_raw, keyBuffer = "enum_{enumIndex}" | The node is initialized with key, display_info (collapsed, orig_node_ctr, node_ctr, node_pos), type, value_str ("enum_value"), value_int (enumIndex*100), and num_children = 0 | Should be successful |
 * | 02 | Assign the generated keyBuffer to the node.key field and set display_info accordingly | node.key = keyBuffer, display_info.collapsed = (enumIndex % 2 == 0) | The node.key is correctly populated with the string "enum_{enumIndex}" and display_info fields are set as intended | Should be successful |
 * | 03 | Invoke get_network_tree_string API with the prepared node structure | input: pointer to node; output: char* result from get_network_tree_string | API returns a valid string pointer if applicable or an empty string; result should contain keyBuffer if the node type is one that outputs string | Should Pass |
 * | 04 | Validate the returned string using assertions based on the node type | For node types: em_network_node_data_type_false, em_network_node_data_type_true, em_network_node_data_type_number, em_network_node_data_type_string, em_network_node_data_type_array_obj, em_network_node_data_type_obj, input: result string; output: contains keyBuffer; for others: empty or does not contain keyBuffer | Assertion passes if the result string contains keyBuffer for valid types, otherwise the result is empty or does not include keyBuffer | Should Pass |
 * | 05 | Free the allocated memory for the result string after API invocation | input: char* result (if not NULL) | Memory is successfully freed without leaks | Should be successful |
 */
TEST(em_net_node_t, get_network_tree_string_enum_values_loop) {
    std::cout << "Entering get_network_tree_string_enum_values_loop test\n";

    for (int enumIndex = em_network_node_data_type_invalid; enumIndex <= em_network_node_data_type_raw; ++enumIndex) {
        em_network_node_t node = {};

        char keyBuffer[128] = {0};
        snprintf(keyBuffer, sizeof(keyBuffer), "enum_%d", enumIndex);
        strncpy(node.key, keyBuffer, sizeof(node.key));

        node.display_info.collapsed = (enumIndex % 2 == 0);
	    node.display_info.orig_node_ctr = static_cast<unsigned int>(enumIndex + 1);
        node.display_info.node_ctr = 1;
        node.display_info.node_pos = static_cast<unsigned int>(enumIndex);

        node.type = static_cast<em_network_node_data_type_t>(enumIndex);

        strncpy(node.value_str, "enum_value", sizeof(node.value_str));
        node.value_int = static_cast<unsigned int>(enumIndex * 100);
        node.num_children = 0;

        em_net_node_t netNode;

        char *result = netNode.get_network_tree_string(&node);
        std::string strResult = result ? result : "";

        bool type_outputs_string = (node.type == em_network_node_data_type_false ||
                                    node.type == em_network_node_data_type_true ||
                                    node.type == em_network_node_data_type_number ||
                                    node.type == em_network_node_data_type_string ||
                                    node.type == em_network_node_data_type_array_obj ||
                                    node.type == em_network_node_data_type_obj);

        if (type_outputs_string) {
            EXPECT_NE(strResult.find(keyBuffer), std::string::npos);
        } else {
            EXPECT_TRUE(strResult.empty() || strResult.find(keyBuffer) == std::string::npos);
        }
        if(result) free(result);
    }
    std::cout << "Exiting get_network_tree_string_enum_values_loop test\n";
}
/**
 * @brief Verify that get_node_array_value correctly handles a null node pointer.
 *
 * This test verifies that when get_node_array_value is called with a null node pointer, the API returns a nullptr and maintains the node type as em_network_node_data_type_invalid. This ensures robustness against invalid input.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 070@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description                                             | Test Data                                                          | Expected Result                                                                               | Notes         |
 * | :--------------: | ------------------------------------------------------- | ------------------------------------------------------------------ | --------------------------------------------------------------------------------------------- | ------------- |
 * | 01               | Call get_node_array_value with a null node pointer.     | node = NULL, typeVal = em_network_node_data_type_invalid             | Return value should be nullptr and typeVal remains em_network_node_data_type_invalid.          | Should Pass   |
 */
TEST(em_net_node_t, get_node_array_value_passing_null_node) {
    std::cout << "Entering get_node_array_value_passing_null_node test" << std::endl;
    em_network_node_data_type_t typeVal = em_network_node_data_type_invalid;
    char *result = em_net_node_t::get_node_array_value(NULL, &typeVal);
    ASSERT_EQ(result, nullptr);
    EXPECT_EQ(typeVal, em_network_node_data_type_invalid);
    std::cout << "Exiting get_node_array_value_passing_null_node test" << std::endl;
}
/**
 * @brief Verify that get_node_array_value returns nullptr when invoked with a NULL type argument.
 *
 * This test validates the behavior of the get_node_array_value API by creating a node of array type
 * having two children with string values and then invoking the function with a NULL type argument.
 * The expected behavior is that the function returns a nullptr, indicating that the type parameter is mandatory.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 071@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                                      | Test Data                                                                                                                                         | Expected Result                                               | Notes      |
 * | :--------------: | ------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------- | ---------- |
 * | 01               | Create a network node with array type, allocate two children, assign string values, and call get_node_array_value with NULL type argument. | node.type = em_network_node_data_type_array_str, node.num_children = 2, child[0]->value_str = "str1", child[1]->value_str = "str2", second parameter = NULL | Function returns nullptr and ASSERT_EQ(result, nullptr) passes. | Should Pass |
 */
TEST(em_net_node_t, get_node_array_value_passing_null_type) {
    std::cout << "Entering get_node_array_value_passing_null_type test" << std::endl;
    em_net_node_t instance;
    em_network_node_t node;
    node.type = em_network_node_data_type_array_str;
    node.num_children = 2;
    node.child[0] = new em_network_node_t;
    node.child[1] = new em_network_node_t;
    strncpy(node.child[0]->value_str, "str1", sizeof(node.child[0]->value_str));
    strncpy(node.child[1]->value_str, "str2", sizeof(node.child[1]->value_str));
    char *result = em_net_node_t::get_node_array_value(&node, NULL);
    ASSERT_EQ(result, nullptr);
    delete node.child[0];
    delete node.child[1];
    std::cout << "Exiting get_node_array_value_passing_null_type test" << std::endl;
}
/**
 * @brief Validate the get_node_array_value API for a valid array of string nodes.
 *
 * This test verifies that the get_node_array_value API correctly processes a node structure representing an array of string nodes. It ensures that the returned string representation matches the expected formatted output and that the output data type is appropriately updated.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 072@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                 | Test Data                                                                                                                      | Expected Result                                                                         | Notes                |
 * | :-------------:  | --------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------- | -------------------- |
 * | 01               | Initialize node structure with an array of 3 string child nodes with values "str1", "str2", and "str3". | node.type = em_network_node_data_type_array_str, node.num_children = 3, child[0]="str1", child[1]="str2", child[2]="str3", outType = em_network_node_data_type_invalid | Node and child nodes are properly initialized.                                          | Should be successful |
 * | 02               | Invoke get_node_array_value API using the constructed node.                  | input1 = pointer to node, input2 = pointer to outType                                                                             | Returns "[str1, str2, str3]" and outType is updated to em_network_node_data_type_array_str. | Should Pass          |
 * | 03               | Clean up allocated memory for the result string and each child node.         | result freed, delete each child node                                                                                           | Memory is freed without leaks.                                                          | Should be successful |
 */
TEST(em_net_node_t, get_node_array_value_valid_array_string) {
    std::cout << "Entering get_node_array_value_valid_array_string test" << std::endl;
    em_net_node_t instance;
    em_network_node_t node;
    memset(&node, 0, sizeof(node));
    node.type = em_network_node_data_type_array_str;
    node.num_children = 3;

    for (int i = 0; i < 3; i++) {
        node.child[i] = new em_network_node_t;
        memset(node.child[i], 0, sizeof(em_network_node_t));
        node.child[i]->type = em_network_node_data_type_string;
    }

    strncpy(node.child[0]->value_str, "str1", sizeof(node.child[0]->value_str) - 1);
    strncpy(node.child[1]->value_str, "str2", sizeof(node.child[1]->value_str) - 1);
    strncpy(node.child[2]->value_str, "str3", sizeof(node.child[2]->value_str) - 1);

    em_network_node_data_type_t outType = em_network_node_data_type_invalid;

    char *result = em_net_node_t::get_node_array_value(&node, &outType);

    EXPECT_TRUE(strstr(result, "[str1, str2, str3]") != nullptr);
    EXPECT_EQ(outType, em_network_node_data_type_array_str);
    free(result);

    for (int i = 0; i < 3; i++) {
        delete node.child[i];
    }

    std::cout << "Exiting get_node_array_value_valid_array_string test" << std::endl;
}
/**
 * @brief Validate correct conversion of numeric array node to string representation.
 *
 * This test verifies that a network node with numeric array children is correctly converted to the expected string format when passed to get_node_array_value. It checks that the function returns a valid non-null pointer, the output type is correctly set, and the formatted string matches the expected numeric array representation.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 073
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Create a node with type array numeric and 3 children with integer values 10, 20, and 30; invoke get_node_array_value() with this node | node.type = em_network_node_data_type_array_num, node.num_children = 3, child[0]->value_int = 10, child[1]->value_int = 20, child[2]->value_int = 30, child types = em_network_node_data_type_number | Returns a non-null string "[10, 20, 30]" and outType equal to em_network_node_data_type_array_num with all assertions passing | Should Pass |
 */
TEST(em_net_node_t, get_node_array_value_valid_array_numeric) {
    std::cout << "Entering get_node_array_value_valid_array_numeric test" << std::endl;
    em_net_node_t instance;
    em_network_node_t node;
    node.type = em_network_node_data_type_array_num;
    node.num_children = 3;

    node.child[0] = new em_network_node_t;
    node.child[1] = new em_network_node_t;
    node.child[2] = new em_network_node_t;

    node.child[0]->value_int = 10;
    node.child[1]->value_int = 20;
    node.child[2]->value_int = 30;

    node.child[0]->type = em_network_node_data_type_number;
    node.child[1]->type = em_network_node_data_type_number;
    node.child[2]->type = em_network_node_data_type_number;

    em_network_node_data_type_t outType = em_network_node_data_type_invalid;

    char *result = em_net_node_t::get_node_array_value(&node, &outType);
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(outType, em_network_node_data_type_array_num);

    std::string strResult(result);
    if (!strResult.empty() && strResult.back() == ' ') {
        strResult.pop_back();
    }
    EXPECT_EQ(strResult, "[10, 20, 30]");

    free(result);
    delete node.child[0];
    delete node.child[1];
    delete node.child[2];

    std::cout << "Exiting get_node_array_value_valid_array_numeric test" << std::endl;
}
/**
 * @brief Validates that get_node_array_value returns nullptr for non-array nodes
 *
 * This test verifies that when a node of non-array type is provided to the get_node_array_value
 * API, the function returns a nullptr and sets the output type to an invalid value. This confirms
 * the function's correct handling of nodes that are not arrays.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 074@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                 | Test Data                                                                                                                              | Expected Result                                                                      | Notes        |
 * | :--------------: | --------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------ | ------------ |
 * | 01               | Invoke get_node_array_value with a node of type string and zero children      | input: node.type = em_network_node_data_type_string, node.num_children = 0; output: outType initially = em_network_node_data_type_invalid | Return value is nullptr; outType remains em_network_node_data_type_invalid; assertion passes | Should Pass  |
 */
TEST(em_net_node_t, get_node_array_value_not_array_node) {
    std::cout << "Entering get_node_array_value_not_array_node test" << std::endl;
    em_net_node_t instance;
    em_network_node_t node;
    node.type = em_network_node_data_type_string;
    node.num_children = 0;
    em_network_node_data_type_t outType = em_network_node_data_type_invalid;
    char *result = em_net_node_t::get_node_array_value(&node, &outType);
    ASSERT_EQ(result, nullptr);
    EXPECT_EQ(outType, em_network_node_data_type_invalid);
    free(result);
    std::cout << "Exiting get_node_array_value_not_array_node test" << std::endl;
}
/**
 * @brief Verify that get_node_array_value returns "[]" for an empty array node.
 *
 * This test verifies that when a network node of type array (em_network_node_data_type_array_str) with zero children is provided to the get_node_array_value API, the API correctly returns a string "[]" and sets the output type to array string type. This ensures proper handling of empty arrays.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 075@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize the instance and node with type array_str and zero children | node.type = em_network_node_data_type_array_str, node.num_children = 0, outType = em_network_node_data_type_invalid | Node is properly set to represent an empty array | Should be successful |
 * | 02 | Invoke get_node_array_value API with the initialized node | Input: Pointer to node, Output: Pointer to outType variable | API returns a non-null result with value "[]" and sets outType to em_network_node_data_type_array_str | Should Pass |
 * | 03 | Verify the returned result string and free allocated memory | Result string = "[]", outType = em_network_node_data_type_array_str | ASSERT_NE(result, nullptr), EXPECT_STREQ(result, "[]"), and EXPECT_EQ(outType, em_network_node_data_type_array_str) pass | Should Pass |
 */
TEST(em_net_node_t, get_node_array_value_empty_array) {
    std::cout << "Entering get_node_array_value_empty_array test" << std::endl;
    em_net_node_t instance;
    em_network_node_t node;
    node.type = em_network_node_data_type_array_str;
    node.num_children = 0;
    em_network_node_data_type_t outType = em_network_node_data_type_invalid;
    char *result = em_net_node_t::get_node_array_value(&node, &outType);
    ASSERT_NE(result, nullptr);
    EXPECT_STREQ(result, "[]");
    EXPECT_EQ(outType, em_network_node_data_type_array_str);
    free(result);
    std::cout << "Exiting get_node_array_value_empty_array test" << std::endl;
}
/**
 * @brief Verifies that get_node_display_position returns the correct display position for a valid node.
 *
 * This test initializes a network node with its display position set to 0 and invokes the get_node_display_position API.
 * The objective is to ensure that the API correctly returns 0 for a node configured with display position 0.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 076@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- | -------------- | ----- |
 * | 01 | Set the node display position to 0 and invoke get_node_display_position API | input: node.display_info.node_pos = 0, output: result variable | Return value 0u, and EXPECT_EQ assertion passes | Should Pass |
 */
TEST(em_net_node_t, get_node_display_position_at_display_pos_0) {
    std::cout << "Entering get_node_display_position_at_display_pos_0 test" << std::endl;
    em_net_node_t instance;
    em_network_node_t node;
    node.display_info.node_pos = 0;
    unsigned int result = em_net_node_t::get_node_display_position(&node);
    EXPECT_EQ(result, 0u);
    std::cout << "Exiting get_node_display_position_at_display_pos_0 test" << std::endl;
}
/**
 * @brief Validate the get_node_display_position API retrieves the correct node display position.
 *
 * This test validates that when a valid em_network_node_t instance with a node display position set to 12345 is passed, the get_node_display_position API successfully returns the expected display position (12345). It ensures that the API correctly accesses the node's display_info structure.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 077@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                  | Test Data                                                         | Expected Result                                                     | Notes        |
 * | :--------------: | -----------------------------------------------------------------------------| ----------------------------------------------------------------- | ------------------------------------------------------------------- | ------------ |
 * | 01               | Create an instance of em_network_node_t and set node.display_info.node_pos to 12345 | node.display_info.node_pos = 12345                                | Instance is configured with node position 12345                     | Should be successful |
 * | 02               | Invoke get_node_display_position with the configured node pointer               | input: &node, expected output: 12345                                | API returns 12345u and the assertion EXPECT_EQ(result, 12345u) passes  | Should Pass  |
 */
TEST(em_net_node_t, get_node_display_position_valid_display_pos) {
    std::cout << "Entering get_node_display_position_valid_display_pos test" << std::endl;
    em_net_node_t instance;
    em_network_node_t node;
    node.display_info.node_pos = 12345;
    unsigned int result = em_net_node_t::get_node_display_position(&node);
    EXPECT_EQ(result, 12345u);
    std::cout << "Exiting get_node_display_position_valid_display_pos test" << std::endl;
}
/**
 * @brief Tests that get_node_display_position returns UINT_MAX when the node display position is set to its maximum value.
 *
 * This test verifies that when the input node's display_info.node_pos is set to UINT_MAX, the function get_node_display_position returns UINT_MAX.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 078@n
 * **Priority:** High@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * 
 * **Test Procedure:**
 * | Variation / Step | Description                                                             | Test Data                                            | Expected Result                                                                      | Notes        |
 * | :--------------: | ----------------------------------------------------------------------- | ---------------------------------------------------- | ------------------------------------------------------------------------------------ | ------------ |
 * | 01               | Invoke get_node_display_position with node.display_info.node_pos = UINT_MAX | node.display_info.node_pos = UINT_MAX, result expected = UINT_MAX | Function returns UINT_MAX and EXPECT_EQ assertion passes                             | Should Pass  |
 */
TEST(em_net_node_t, get_node_display_position_at_max_display_pos) {
    std::cout << "Entering get_node_display_position_at_max_display_pos test" << std::endl;
    em_net_node_t instance;
    em_network_node_t node;
    node.display_info.node_pos = UINT_MAX;
    unsigned int result = em_net_node_t::get_node_display_position(&node);
    EXPECT_EQ(result, UINT_MAX);
    std::cout << "Exiting get_node_display_position_at_max_display_pos test" << std::endl;
}
/**
 * @brief Verifies that get_node_display_position handles a null node pointer correctly
 *
 * This test validates that the static method get_node_display_position returns 0 when provided with a NULL pointer, ensuring
 * that the API gracefully handles invalid input without causing undefined behavior.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 079@n
 * **Priority:** High@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * 
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                                   | Test Data                      | Expected Result                                                                       | Notes       |
 * | :--------------: | ----------------------------------------------------------------------------- | ------------------------------ | ------------------------------------------------------------------------------------- | ----------- |
 * | 01               | Invoke em_net_node_t::get_node_display_position with a NULL node pointer       | node pointer = NULL            | Return value is 0; Assertion EXPECT_EQ confirms the result is 0                      | Should Pass |
 */
TEST(em_net_node_t, get_node_display_position_null_node_pointer) {
    std::cout << "Entering get_node_display_position_null_node_pointer test" << std::endl;
    em_net_node_t instance;
    unsigned int result = em_net_node_t::get_node_display_position(nullptr);
    EXPECT_EQ(result, 0);
    std::cout << "Exiting get_node_display_position_null_node_pointer test" << std::endl;
}
/**
 * @brief Test get_node_from_node_ctr with null tree input to verify proper null handling.
 *
 * This test verifies that when a null pointer is provided as the tree input, the get_node_from_node_ctr function returns a nullptr. This behavior is crucial to avoid dereferencing null pointers and ensure that the function gracefully handles invalid inputs.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 080
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                                  | Test Data                                                | Expected Result                                              | Notes            |
 * | :--------------: | -------------------------------------------------------------------------------------------- | -------------------------------------------------------- | ------------------------------------------------------------ | ---------------- |
 * | 01               | Initialize test by printing entry message and setting up test variables (netNodeObj, tree, search_ctr) | netNodeObj, tree = NULL, search_ctr = 10                 | Test variables initialized successfully                     | Should be successful |
 * | 02               | Invoke get_node_from_node_ctr API with tree = NULL and search_ctr = 10                         | input: tree = NULL, search_ctr = 10                      | API returns a nullptr as the tree input is null               | Should Pass      |
 * | 03               | Validate the result using ASSERT_EQ to ensure the returned value is nullptr                    | output: result = nullptr                                 | Assertion passes, confirming that the function correctly returned nullptr | Should Pass      |
 * | 04               | Print exit message indicating completion of the test                                         | None                                                     | Exit message printed successfully                             | Should be successful |
 */
TEST(em_net_node_t, get_node_from_node_ctr_NullTreeInput) {
    std::cout << "Entering get_node_from_node_ctr_NullTreeInput test" << std::endl;
    em_net_node_t netNodeObj;
    em_network_node_t* tree = NULL;
    unsigned int search_ctr = 10;
    em_network_node_t* result = em_net_node_t::get_node_from_node_ctr(tree, search_ctr);
    ASSERT_EQ(result, nullptr);
    std::cout << "Exiting get_node_from_node_ctr_NullTreeInput test" << std::endl;
}
/**
 * @brief Verifies that get_node_from_node_ctr returns the correct node when a single node with a matching display counter exists
 *
 * This test creates a single network node with key "node5" and a display counter value of 5. It then calls get_node_from_node_ctr with a search counter of 5 and verifies that the returned node is not null and its key matches "node5". This ensures that the API correctly identifies and returns a node with a matching display counter.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 081@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Log the entry message for the test. | None | "Entering get_node_from_node_ctr_SingleNodeMatchingDisplayCounter test" is printed. | Should be successful |
 * | 02 | Initialize the network node objects with pre-defined values. | singleNode.key = node5, singleNode.display_info.node_ctr = 5, singleNode.num_children = 0 | Network node objects are successfully initialized. | Should be successful |
 * | 03 | Set the search counter and call get_node_from_node_ctr API. | search_ctr = 5, input: singleNode object with key "node5", display_info.node_ctr = 5 | The API returns a valid pointer to the network node with key "node5". | Should Pass |
 * | 04 | Assert that the result from the API is valid and its key matches "node5". | result->key = node5 | ASSERT_NE(result, nullptr) passes and EXPECT_STREQ(result->key, "node5") passes. | Should Pass |
 * | 05 | Log the exit message for the test. | None | "Exiting get_node_from_node_ctr_SingleNodeMatchingDisplayCounter test" is printed. | Should be successful |
 */
TEST(em_net_node_t, get_node_from_node_ctr_SingleNodeMatchingDisplayCounter) {
    std::cout << "Entering get_node_from_node_ctr_SingleNodeMatchingDisplayCounter test" << std::endl;
    em_net_node_t netNodeObj;
    em_network_node_t singleNode;
    strncpy(singleNode.key, "node5", sizeof(singleNode.key) - 1);
    singleNode.key[sizeof(singleNode.key) - 1] = '\0';
    singleNode.display_info.node_ctr = 5;
    singleNode.num_children = 0;
    unsigned int search_ctr = 5;
    em_network_node_t* result = em_net_node_t::get_node_from_node_ctr(&singleNode, search_ctr);
    ASSERT_NE(result, nullptr);
    EXPECT_STREQ(result->key, "node5");
    std::cout << "Exiting get_node_from_node_ctr_SingleNodeMatchingDisplayCounter test" << std::endl;
}
/**
 * @brief Verify that get_node_from_node_ctr returns nullptr when the node's display counter does not match the search counter.
 *
 * This test verifies that when get_node_from_node_ctr is invoked with a single network node whose display counter is different from the provided search counter, the function correctly returns a nullptr, indicating that no matching node is found.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 082
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Invoke get_node_from_node_ctr with a single node having a non matching display counter | singleNode.key = "node5", singleNode.display_info.node_ctr = 5, singleNode.num_children = 0, search_ctr = 10 | Return value should be nullptr and assertion check should be successful | Should Pass |
 */
TEST(em_net_node_t, get_node_from_node_ctr_SingleNodeNonMatchingDisplayCounter) {
    std::cout << "Entering get_node_from_node_ctr_SingleNodeNonMatchingDisplayCounter test" << std::endl;
    em_net_node_t netNodeObj;
    em_network_node_t singleNode;
    strncpy(singleNode.key, "node5", sizeof(singleNode.key) - 1);
    singleNode.key[sizeof(singleNode.key) - 1] = '\0';
    singleNode.display_info.node_ctr = 5;
    singleNode.num_children = 0;
    unsigned int search_ctr = 10;
    em_network_node_t* result = em_net_node_t::get_node_from_node_ctr(&singleNode, search_ctr);
    ASSERT_EQ(result, nullptr);
    std::cout << "Exiting get_node_from_node_ctr_SingleNodeNonMatchingDisplayCounter test" << std::endl;
}
/**
 * @brief This test verifies that get_node_from_node_ctr returns the correct node when the root node's node_ctr matches the search criteria among multiple nodes.
 *
 * This test creates a root network node with a node_ctr value of 3 and a child node with a node_ctr of 50. It then invokes get_node_from_node_ctr with a search_ctr value of 3 and checks that the returned node is the root node with the key "root_node". The test ensures that the API correctly traverses and selects the node based on the specified criteria.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 083@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Set up the network nodes: initialize a root node with node_ctr = 3 and a child node with node_ctr = 50, linking the child to the root. | rootNode.key = "root_node", rootNode.display_info.node_ctr = 3; childNode.key = "child_node", childNode.display_info.node_ctr = 50 | Nodes are initialized and connected properly; the root node has one child | Should be successful |
 * | 02 | Invoke get_node_from_node_ctr with search_ctr = 3 on the constructed node hierarchy. | input: pointer to rootNode, search_ctr = 3 | Returns a non-null pointer pointing to the node with node_ctr = 3 | Should Pass |
 * | 03 | Validate the returned node's key to verify it is the root node. | output: result->key is compared to "root_node" | The result is non-null and the key matches "root_node" | Should Pass |
 */
TEST(em_net_node_t, get_node_from_node_ctr_MultipleNodesRootMatch) {
    std::cout << "Entering get_node_from_node_ctr_MultipleNodesRootMatch test" << std::endl;
    em_net_node_t netNodeObj;
    em_network_node_t rootNode;
    strncpy(rootNode.key, "root_node", sizeof(rootNode.key) - 1);
    rootNode.key[sizeof(rootNode.key) - 1] = '\0';
    rootNode.display_info.node_ctr = 3;
    em_network_node_t childNode;
    strncpy(childNode.key, "child_node", sizeof(childNode.key) - 1);
    childNode.key[sizeof(childNode.key) - 1] = '\0';
    childNode.display_info.node_ctr = 50;
    childNode.num_children = 0;
    rootNode.child[0] = &childNode;
    rootNode.num_children = 1;
    unsigned int search_ctr = 3;
    em_network_node_t* result = em_net_node_t::get_node_from_node_ctr(&rootNode, search_ctr);
    ASSERT_NE(result, nullptr);
    EXPECT_STREQ(result->key, "root_node");
    std::cout << "Exiting get_node_from_node_ctr_MultipleNodesRootMatch test" << std::endl;
}
/**
 * @brief Test to verify retrieval of the correct child node when multiple nodes exist
 *
 * This test verifies that the get_node_from_node_ctr function returns the correct child node when the root node contains one or more children and one of them has a matching node counter (node_ctr) value. It confirms that the lookup mechanism works correctly in this positive scenario.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 084@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                 | Test Data                                                                                                                           | Expected Result                                                              | Notes           |
 * | :--------------: | --------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------- | --------------- |
 * | 01               | Setup of root and child nodes, including assigning key values and node_ctr. | rootNode.key = root_node, rootNode.display_info.node_ctr = 1, childNode.key = child_node, childNode.display_info.node_ctr = 7, rootNode.num_children = 1 | Nodes are initialized correctly with the child node added to the root node. | Should be successful |
 * | 02               | Invoke get_node_from_node_ctr API with search_ctr equal to 7.               | search_ctr = 7                                                                                                                      | Returns a non-null pointer; the key of the returned node is "child_node".   | Should Pass     |
 */
TEST(em_net_node_t, get_node_from_node_ctr_MultipleNodesChildMatch) {
    std::cout << "Entering get_node_from_node_ctr_MultipleNodesChildMatch test" << std::endl;
    em_net_node_t netNodeObj;
    em_network_node_t rootNode;
    strncpy(rootNode.key, "root_node", sizeof(rootNode.key) - 1);
    rootNode.key[sizeof(rootNode.key) - 1] = '\0';
    rootNode.display_info.node_ctr = 1;
    em_network_node_t childNode;
    strncpy(childNode.key, "child_node", sizeof(childNode.key) - 1);
    childNode.key[sizeof(childNode.key) - 1] = '\0';
    childNode.display_info.node_ctr = 7;
    childNode.num_children = 0;
    rootNode.child[0] = &childNode;
    rootNode.num_children = 1;
    unsigned int search_ctr = 7;
    em_network_node_t* result = em_net_node_t::get_node_from_node_ctr(&rootNode, search_ctr);
    ASSERT_NE(result, nullptr);
    EXPECT_STREQ(result->key, "child_node");
    std::cout << "Exiting get_node_from_node_ctr_MultipleNodesChildMatch test" << std::endl;
}
/**
 * @brief Test to validate get_node_from_node_ctr API with multiple nodes having duplicate display counters
 *
 * This test verifies that when multiple child nodes have the same display counter value, the API get_node_from_node_ctr returns the first encountered node. This is crucial to ensure that the node retrieval mechanism is deterministic and correct when duplicate display counters exist.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 085@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                                  | Test Data                                                                                                                                        | Expected Result                                                                                                  | Notes         |
 * | :--------------: | -------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------- | ------------- |
 * | 01               | Initialize the root node and two child nodes with duplicate display counters                 | root.key = "root", root.display_info.node_ctr = 1; firstChild.key = "first_child_8", firstChild.display_info.node_ctr = 8, firstChild.num_children = 0; secondChild.key = "second_child_8", secondChild.display_info.node_ctr = 8, secondChild.num_children = 0 | Nodes initialized correctly with proper values                                                                  | Should be successful |
 * | 02               | Invoke get_node_from_node_ctr API with search_ctr = 8 on the constructed node tree             | search_ctr = 8, root node containing the two children                                                                                          | API returns a non-null pointer to one of the child nodes                                                          | Should Pass   |
 * | 03               | Validate that the returned node's key is "first_child_8" as expected                           | output result from API should have key = "first_child_8"                                                                                        | ASSERT_NE(result, nullptr) passes and EXPECT_STREQ(result->key, "first_child_8") passes                             | Should Pass   |
 */
TEST(em_net_node_t, get_node_from_node_ctr_MultipleNodesDuplicateDisplayCounters) {
    std::cout << "Entering get_node_from_node_ctr_MultipleNodesDuplicateDisplayCounters test" << std::endl;
    em_net_node_t netNodeObj;
    em_network_node_t rootNode;
    strncpy(rootNode.key, "root", sizeof(rootNode.key) - 1);
    rootNode.key[sizeof(rootNode.key) - 1] = '\0';
    rootNode.display_info.node_ctr = 1;

    em_network_node_t firstChild;
    strncpy(firstChild.key, "first_child_8", sizeof(firstChild.key) - 1);
    firstChild.key[sizeof(firstChild.key) - 1] = '\0';
    firstChild.display_info.node_ctr = 8;
    firstChild.num_children = 0;

    em_network_node_t secondChild;
    strncpy(secondChild.key, "second_child_8", sizeof(secondChild.key) - 1);
    secondChild.key[sizeof(secondChild.key) - 1] = '\0';
    secondChild.display_info.node_ctr = 8;
    secondChild.num_children = 0;
    rootNode.child[0] = &firstChild;
    rootNode.child[1] = &secondChild;
    rootNode.num_children = 2;
    unsigned int search_ctr = 8;
    em_network_node_t* result = em_net_node_t::get_node_from_node_ctr(&rootNode, search_ctr);

    ASSERT_NE(result, nullptr);
    EXPECT_STREQ(result->key, "first_child_8");

    std::cout << "Exiting get_node_from_node_ctr_MultipleNodesDuplicateDisplayCounters test" << std::endl;
}
/**
 * @brief Test get_node_from_node_ctr returns nullptr for a non-existing display counter
 *
 * This test verifies that when get_node_from_node_ctr is invoked with a search counter that does not match any node's display_info.node_ctr in the network node tree, the function returns a nullptr. This is important to ensure that the API correctly handles searches for non-existing elements.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 086@n
 * **Priority:** High@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * 
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                                                              | Test Data                                                                                                         | Expected Result                                                                                  | Notes        |
 * | :--------------: | -------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------- | ------------ |
 * | 01               | Create a network node tree with a root node and one child node with specific display_info.node_ctr values | root.key = "root", root.display_info.node_ctr = 2, child.key = "child", child.display_info.node_ctr = 4, search_ctr = 999 | get_node_from_node_ctr returns nullptr, and ASSERT_EQ confirms the returned value is nullptr      | Should Pass  |
 */
TEST(em_net_node_t, get_node_from_node_ctr_NonExistingDisplayCounter) {
    std::cout << "Entering get_node_from_node_ctr_NonExistingDisplayCounter test" << std::endl;

    em_net_node_t netNodeObj;
    em_network_node_t rootNode;
    strncpy(rootNode.key, "root", sizeof(rootNode.key) - 1);
    rootNode.key[sizeof(rootNode.key) - 1] = '\0';
    rootNode.display_info.node_ctr = 2;
    em_network_node_t childNode;
    strncpy(childNode.key, "child", sizeof(childNode.key) - 1);
    childNode.key[sizeof(childNode.key) - 1] = '\0';
    childNode.display_info.node_ctr = 4;
    childNode.num_children = 0;
    rootNode.child[0] = &childNode;
    rootNode.num_children = 1;
    unsigned int search_ctr = 999;
    em_network_node_t* result = em_net_node_t::get_node_from_node_ctr(&rootNode, search_ctr);
    ASSERT_EQ(result, nullptr);
    std::cout << "Exiting get_node_from_node_ctr_NonExistingDisplayCounter test" << std::endl;
}
/**
 * @brief Verify get_node_from_node_ctr handles a node with a zero display counter correctly
 *
 * This test checks that the API get_node_from_node_ctr correctly processes a network node with a display_info.node_ctr value of zero. The test ensures that the function returns a valid pointer to the node and that the node's key matches the expected value ("zero_node"). This is important to verify that even edge case scenarios, such as a node with no display count, are handled properly.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 087@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                                                                           | Test Data                                                                                              | Expected Result                                                                             | Notes       |
 * | :--------------: | --------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------- | ----------- |
 * | 01               | Invoke the get_node_from_node_ctr API with a node whose display_info.node_ctr is set to 0 and num_children is 0          | zeroNode.key = "zero_node", zeroNode.display_info.node_ctr = 0, zeroNode.num_children = 0, search_ctr = 0 | The API returns a non-null pointer and the returned node's key equals "zero_node"              | Should Pass |
 */
TEST(em_net_node_t, get_node_from_node_ctr_EdgeCaseZeroDisplayCounter) {
    std::cout << "Entering get_node_from_node_ctr_EdgeCaseZeroDisplayCounter test" << std::endl;
    em_net_node_t netNodeObj;
    em_network_node_t zeroNode;
    strncpy(zeroNode.key, "zero_node", sizeof(zeroNode.key) - 1);
    zeroNode.key[sizeof(zeroNode.key) - 1] = '\0';
    zeroNode.display_info.node_ctr = 0;
    zeroNode.num_children = 0;
    unsigned int search_ctr = 0;
    em_network_node_t* result = em_net_node_t::get_node_from_node_ctr(&zeroNode, search_ctr);
    ASSERT_NE(result, nullptr);
    EXPECT_STREQ(result->key, "zero_node");
    std::cout << "Exiting get_node_from_node_ctr_EdgeCaseZeroDisplayCounter test" << std::endl;
}
/**
 * @brief Verify that get_node_scalar_value returns nullptr when provided a null node pointer
 *
 * This test checks that the get_node_scalar_value API correctly handles a scenario where the provided network node pointer is NULL. It ensures that the API returns a null pointer as expected, which is critical for verifying proper error handling and avoiding potential dereference of invalid memory.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 088@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**
 * | Variation / Step | Description                                                        | Test Data                             | Expected Result                                                | Notes      |
 * | :--------------: | ------------------------------------------------------------------ | ------------------------------------- | -------------------------------------------------------------- | ---------- |
 * | 01               | Call get_node_scalar_value with a null network node pointer         | node = NULL, output = nullptr          | API returns nullptr; ASSERT_EQ(result, nullptr) passes           | Should Pass|
 */
TEST(em_net_node_t, get_node_scalar_value_NodeIsNull)
{
    std::cout << "Entering get_node_scalar_value_NodeIsNull test" << std::endl;
    em_net_node_t obj;
    em_network_node_t* node = NULL;
    char *result = em_net_node_t::get_node_scalar_value(node);
    ASSERT_EQ(result, nullptr);
    std::cout << "Exiting get_node_scalar_value_NodeIsNull test" << std::endl;
}
/**
 * @brief Verify that get_node_scalar_value returns the correct string representation for a boolean true node.
 *
 * This test validates that when a node of type boolean true is provided to the API get_node_scalar_value,
 * the function returns a non-null pointer to a string containing "true". The test ensures that the conversion
 * is handled correctly and the returned value matches the expected string.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 089@n
 * **Priority:** High@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * 
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                              | Test Data                                                      | Expected Result                                                         | Notes       |
 * | :--------------: | ------------------------------------------------------------------------ | -------------------------------------------------------------- | ----------------------------------------------------------------------- | ----------- |
 * | 01               | Setup a network node with type indicating boolean true and invoke the API | node.type = em_network_node_data_type_true, output: result pointer | Return value is not nullptr and the result string equals "true" after the API call | Should Pass |
 */
TEST(em_net_node_t, get_node_scalar_value_BooleanTrue)
{
    std::cout << "Entering get_node_scalar_value_BooleanTrue test" << std::endl;
    em_net_node_t obj;
    em_network_node_t node;
    node.type = em_network_node_data_type_true;
    char *result = em_net_node_t::get_node_scalar_value(&node);
    ASSERT_NE(result, nullptr);
    EXPECT_STREQ(result, "true");
    free(result);
    std::cout << "Exiting get_node_scalar_value_BooleanTrue test" << std::endl;
}
/**
 * @brief Validate that the get_node_scalar_value API returns the correct string "false" for a node of Boolean false type
 *
 * This test case verifies that when a network node is instantiated with the Boolean false type, the get_node_scalar_value API correctly returns the string "false". This ensures proper conversion of the Boolean false node value to its expected scalar string representation.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 090@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                          | Test Data                                                          | Expected Result                                                 | Notes       |
 * | :--------------: | -------------------------------------------------------------------- | ------------------------------------------------------------------ | --------------------------------------------------------------- | ----------- |
 * | 01               | Create a node with type set to Boolean false and invoke the API call | node.type = em_network_node_data_type_false, expected_result = "false" | API returns a non-null pointer with string value "false" and assertion passes | Should Pass |
 */
TEST(em_net_node_t, get_node_scalar_value_BooleanFalse)
{
    std::cout << "Entering get_node_scalar_value_BooleanFalse test" << std::endl;
    em_net_node_t obj;
    em_network_node_t node;
    node.type = em_network_node_data_type_false;
    char *result = em_net_node_t::get_node_scalar_value(&node);
    ASSERT_NE(result, nullptr);
    EXPECT_STREQ(result, "false");
    free(result);
    std::cout << "Exiting get_node_scalar_value_BooleanFalse test" << std::endl;
}
/**
 * @brief Verifies that the get_node_scalar_value API correctly converts a numeric node value to its string representation
 *
 * This test checks that when a network node of type number with an integer value is provided, the API correctly returns a dynamically allocated string representing that number. It validates both that the returned pointer is not null and that the content of the string matches the expected conversion result.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 091@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                       | Test Data                                                               | Expected Result                                                  | Notes      |
 * | :--------------: | --------------------------------------------------------------------------------- | ----------------------------------------------------------------------- | ---------------------------------------------------------------- | ---------- |
 * | 01               | Set up a network node with type number and integer value 12345, then invoke get_node_scalar_value  | node.type = em_network_node_data_type_number, node.value_int = 12345; output: result pointer | result != nullptr and result string equals "12345" based on API conversion | Should Pass |
 */
TEST(em_net_node_t, get_node_scalar_value_Number)
{
    std::cout << "Entering get_node_scalar_value_Number test" << std::endl;
    em_net_node_t obj;
    em_network_node_t node;
    node.type = em_network_node_data_type_number;
    node.value_int = 12345;
    char *result = em_net_node_t::get_node_scalar_value(&node);
    ASSERT_NE(result, nullptr);
    EXPECT_STREQ(result, "12345");
    free(result);
    std::cout << "Exiting get_node_scalar_value_Number test" << std::endl;
}
/**
 * @brief Validate retrieval of string scalar value from a node
 *
 * This test verifies that the function em_net_node_t::get_node_scalar_value() correctly retrieves the scalar string value from a node that has been initialized with a string value ("hello world"). It checks whether the returned pointer is non-null and the string content matches the expected value.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 092@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                    | Test Data                                                                                                   | Expected Result                                                          | Notes      |
 * | :--------------: | ------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------ | ---------- |
 * | 01               | Initialize an em_network_node_t with type set to string and value "hello world", then invoke get_node_scalar_value() on the initialized node | input: node.type = em_network_node_data_type_string, node.value_str = "hello world", output: result pointer | Return value is a non-null pointer and the pointed string equals "hello world" | Should Pass |
 */
TEST(em_net_node_t, get_node_scalar_value_String)
{
    std::cout << "Entering get_node_scalar_value_String test" << std::endl;
    em_net_node_t obj;
    em_network_node_t node;
    node.type = em_network_node_data_type_string;
    strncpy(node.value_str, "hello world", sizeof(node.value_str) - 1);
    node.value_str[sizeof(node.value_str) - 1] = '\0';
    char *result = em_net_node_t::get_node_scalar_value(&node);
    ASSERT_NE(result, nullptr);
    EXPECT_STREQ(result, "hello world");
    free(result);
    std::cout << "Exiting get_node_scalar_value_String test" << std::endl;
}
/**
 * @brief Verify that get_node_scalar_value returns "object" for nodes of type object.
 *
 * This test verifies that when a network node's type is set to "object", the API 
 * em_net_node_t::get_node_scalar_value returns a non-null pointer to a string equal to "object".
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 093@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Create a network node with type set to "object" and invoke get_node_scalar_value | node.type = em_network_node_data_type_obj | The API returns a non-null pointer and the returned string equals "object" (ASSERT_NE & EXPECT_STREQ pass) | Should Pass |
 */
TEST(em_net_node_t, get_node_scalar_value_Obj)
{
    std::cout << "Entering get_node_scalar_value_Obj test" << std::endl;
    em_net_node_t obj;
    em_network_node_t node;
    node.type = em_network_node_data_type_obj;
    char *result = em_net_node_t::get_node_scalar_value(&node);
    ASSERT_NE(result, nullptr);
    EXPECT_STREQ(result, "object");
    free(result);
    std::cout << "Exiting get_node_scalar_value_Obj test" << std::endl;
}
/**
 * @brief Verify get_node_scalar_value returns an empty string for nodes of type array_obj
 *
 * This test verifies that when an em_network_node_t instance with its type set to em_network_node_data_type_array_obj is passed to the get_node_scalar_value function, the function returns a non-null pointer and an empty string. This ensures that the API handles array object node types correctly and that the memory allocation and deallocation are performed as expected.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 094@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                                          | Test Data                                                                    | Expected Result                                                                                           | Notes       |
 * | :--------------: | ------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------- | ----------- |
 * | 01               | Invoke get_node_scalar_value on a node configured as array_obj                         | node.type = em_network_node_data_type_array_obj                              | Returns a non-null pointer with an empty string; ASSERT_NE passes and EXPECT_STREQ passes                    | Should Pass |
 */
TEST(em_net_node_t, get_node_scalar_value_ArrayObj)
{
    std::cout << "Entering get_node_scalar_value_ArrayObj test" << std::endl;
    em_net_node_t obj;
    em_network_node_t node;
    node.type = em_network_node_data_type_array_obj;
    char *result = em_net_node_t::get_node_scalar_value(&node);
    ASSERT_NE(result, nullptr);
    EXPECT_STREQ(result, "");
    free(result);
    std::cout << "Exiting get_node_scalar_value_ArrayObj test" << std::endl;
}
/**
 * @brief Verify that get_node_scalar_value returns an empty string for array_str node types
 *
 * This test validates that when a node of type em_network_node_data_type_array_str is used, 
 * the get_node_scalar_value function returns a valid non-null pointer that points to an empty string.
 * It ensures that the API correctly handles nodes with string array data types and adheres to expected behavior.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 095@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                                  | Test Data                                                                              | Expected Result                                                                        | Notes       |
 * | :--------------: | -----------------------------------------------------------------------------| -------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------| ----------- |
 * | 01               | Invoke get_node_scalar_value on a node with type em_network_node_data_type_array_str | node.type = em_network_node_data_type_array_str, output1 = non-null pointer, output2 = empty string | The API returns a non-null pointer with an empty string, verified by EXPECT_STREQ   | Should Pass |
 */
TEST(em_net_node_t, get_node_scalar_value_ArrayStr)
{
    std::cout << "Entering get_node_scalar_value_ArrayStr test" << std::endl;
    em_net_node_t obj;
    em_network_node_t node;
    node.type = em_network_node_data_type_array_str;
    char *result = em_net_node_t::get_node_scalar_value(&node);
    ASSERT_NE(result, nullptr);
    EXPECT_STREQ(result, "");
    free(result);
    std::cout << "Exiting get_node_scalar_value_ArrayStr test" << std::endl;
}
/**
 * @brief Validate get_node_scalar_value for array number node type
 *
 * This test verifies that when a node of type em_network_node_data_type_array_num is passed to 
 * get_node_scalar_value, the API returns a non-null pointer and an empty string as expected. 
 * This confirms that the function handles nodes with array number data type correctly.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 096@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                 | Test Data                                                                            | Expected Result                                                    | Notes            |
 * | :--------------: | --------------------------------------------------------------------------- | ------------------------------------------------------------------------------------ | ------------------------------------------------------------------ | ---------------- |
 * | 01               | Initialize the network node and set its type to em_network_node_data_type_array_num | node.type = em_network_node_data_type_array_num                                      | Node is set with the correct type                                  | Should be successful |
 * | 02               | Call get_node_scalar_value with the initialized node                        | input: &node (with type=em_network_node_data_type_array_num), output: expected string = "" | Returns a non-null pointer and the string equals ""                | Should Pass      |
 * | 03               | Free the allocated memory after function call                                | result pointer as allocated by get_node_scalar_value                                  | Memory is freed successfully                                       | Should be successful |
 */
TEST(em_net_node_t, get_node_scalar_value_ArrayNum)
{
    std::cout << "Entering get_node_scalar_value_ArrayNum test" << std::endl;
    em_net_node_t obj;
    em_network_node_t node;
    node.type = em_network_node_data_type_array_num;
    char *result = em_net_node_t::get_node_scalar_value(&node);
    ASSERT_NE(result, nullptr);
    EXPECT_STREQ(result, "");
    free(result);
    std::cout << "Exiting get_node_scalar_value_ArrayNum test" << std::endl;
}
/**
 * @brief Validate that get_node_scalar_value returns a non-null empty string for a raw node type.
 *
 * This test verifies that when a node of type em_network_node_data_type_raw is passed to get_node_scalar_value,
 * the function returns a valid non-null pointer that points to an empty string. This behavior is critical to ensure
 * that the API properly handles raw node types and allocates memory as expected.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 097@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                                       | Test Data                                                                                               | Expected Result                                                       | Notes      |
 * | :--------------: | ------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------- | ---------- |
 * | 01               | Instantiate a node with type em_network_node_data_type_raw, invoke get_node_scalar_value API, and validate the returned result | node.type = em_network_node_data_type_raw, input: pointer to node, output: result pointer value | The result pointer is not nullptr and the returned string is an empty string ("") | Should Pass |
 */
TEST(em_net_node_t, get_node_scalar_value_Raw)
{
    std::cout << "Entering get_node_scalar_value_Raw test" << std::endl;
    em_net_node_t obj;
    em_network_node_t node;
    node.type = em_network_node_data_type_raw;
    char *result = em_net_node_t::get_node_scalar_value(&node);
    ASSERT_NE(result, nullptr);
    EXPECT_STREQ(result, "");
    free(result);
    std::cout << "Exiting get_node_scalar_value_Raw test" << std::endl;
}
/**
 * @brief Tests that the get_node_scalar_value API returns an empty string when provided with an invalid node type.
 *
 * This test verifies that when a network node with an invalid data type is passed to the get_node_scalar_value function,
 * the function returns a non-null pointer to an empty string. This ensures the API properly handles invalid input types.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 098@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                                      | Test Data                                                                                                  | Expected Result                                                      | Notes        |
 * | :--------------: | -------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------- | ------------ |
 * | 01               | Invoke get_node_scalar_value with a node having an invalid data type              | node.type = em_network_node_data_type_invalid                                                               | Return a non-null pointer to an empty string; ASSERT_NE and EXPECT_STREQ pass | Should Pass  |
 */
TEST(em_net_node_t, get_node_scalar_value_Invalid)
{
    std::cout << "Entering get_node_scalar_value_Invalid test" << std::endl;
    em_net_node_t obj;
    em_network_node_t node;
    node.type = em_network_node_data_type_invalid;
    char *result = em_net_node_t::get_node_scalar_value(&node);
    ASSERT_NE(result, nullptr);
    EXPECT_STREQ(result, "");
    free(result);
    std::cout << "Exiting get_node_scalar_value_Invalid test" << std::endl;
}
/**
 * @brief Validate that get_node_type() returns the correct enumeration value for each valid node type.
 *
 * This test verifies that the get_node_type() API method returns the expected enumeration value for each valid em_network_node_data_type_t provided. It iterates over an array of predefined valid enum values, assigns each to a freshly initialized node structure, calls the API, and asserts that the returned value matches the expected one.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 099@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                                                   | Test Data                                                                                                              | Expected Result                                                           | Notes       |
 * | :--------------: | --------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------- | ----------- |
 * | 01               | Set node type to em_network_node_data_type_invalid and invoke get_node_type()                  | input: node.type = em_network_node_data_type_invalid, output: retVal expected = em_network_node_data_type_invalid      | get_node_type() returns em_network_node_data_type_invalid                 | Should Pass |
 * | 02               | Set node type to em_network_node_data_type_false and invoke get_node_type()                   | input: node.type = em_network_node_data_type_false, output: retVal expected = em_network_node_data_type_false          | get_node_type() returns em_network_node_data_type_false                    | Should Pass |
 * | 03               | Set node type to em_network_node_data_type_true and invoke get_node_type()                    | input: node.type = em_network_node_data_type_true, output: retVal expected = em_network_node_data_type_true            | get_node_type() returns em_network_node_data_type_true                     | Should Pass |
 * | 04               | Set node type to em_network_node_data_type_null and invoke get_node_type()                    | input: node.type = em_network_node_data_type_null, output: retVal expected = em_network_node_data_type_null            | get_node_type() returns em_network_node_data_type_null                     | Should Pass |
 * | 05               | Set node type to em_network_node_data_type_number and invoke get_node_type()                  | input: node.type = em_network_node_data_type_number, output: retVal expected = em_network_node_data_type_number        | get_node_type() returns em_network_node_data_type_number                  | Should Pass |
 * | 06               | Set node type to em_network_node_data_type_string and invoke get_node_type()                  | input: node.type = em_network_node_data_type_string, output: retVal expected = em_network_node_data_type_string        | get_node_type() returns em_network_node_data_type_string                  | Should Pass |
 * | 07               | Set node type to em_network_node_data_type_obj and invoke get_node_type()                     | input: node.type = em_network_node_data_type_obj, output: retVal expected = em_network_node_data_type_obj              | get_node_type() returns em_network_node_data_type_obj                     | Should Pass |
 * | 08               | Set node type to em_network_node_data_type_array_obj and invoke get_node_type()               | input: node.type = em_network_node_data_type_array_obj, output: retVal expected = em_network_node_data_type_array_obj    | get_node_type() returns em_network_node_data_type_array_obj               | Should Pass |
 * | 09               | Set node type to em_network_node_data_type_array_str and invoke get_node_type()               | input: node.type = em_network_node_data_type_array_str, output: retVal expected = em_network_node_data_type_array_str    | get_node_type() returns em_network_node_data_type_array_str               | Should Pass |
 * | 10               | Set node type to em_network_node_data_type_array_num and invoke get_node_type()               | input: node.type = em_network_node_data_type_array_num, output: retVal expected = em_network_node_data_type_array_num    | get_node_type() returns em_network_node_data_type_array_num               | Should Pass |
 * | 11               | Set node type to em_network_node_data_type_raw and invoke get_node_type()                    | input: node.type = em_network_node_data_type_raw, output: retVal expected = em_network_node_data_type_raw              | get_node_type() returns em_network_node_data_type_raw                     | Should Pass |
 */
TEST(em_net_node_t, get_node_type_valid_enum)
{
    std::cout << "Entering get_node_type_valid_enum test" << std::endl;
    em_network_node_data_type_t enumValues[] = {
        em_network_node_data_type_invalid,
        em_network_node_data_type_false,
        em_network_node_data_type_true,
        em_network_node_data_type_null,
        em_network_node_data_type_number,
        em_network_node_data_type_string,
        em_network_node_data_type_obj,
        em_network_node_data_type_array_obj,
        em_network_node_data_type_array_str,
        em_network_node_data_type_array_num,
        em_network_node_data_type_raw
    };
    em_net_node_t netNodeInstance;
    size_t numValues = sizeof(enumValues) / sizeof(enumValues[0]);
    for (size_t i = 0; i < numValues; ++i)
    {
        em_network_node_t node;
        memset(&node, 0, sizeof(em_network_node_t));
        node.type = enumValues[i];
        em_network_node_data_type_t retVal = em_net_node_t::get_node_type(&node);
        EXPECT_EQ(enumValues[i], retVal);
    }
    std::cout << "Exiting get_node_type_valid_enum test" << std::endl;
}
/**
 * @brief Validate get_node_type() behavior when a NULL node pointer is provided
 *
 * This test verifies that the get_node_type() function returns the expected invalid node data type when invoked with a NULL pointer.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 100@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                   | Test Data                                                            | Expected Result                                                      | Notes       |
 * | :--------------: | ------------------------------------------------------------- | -------------------------------------------------------------------- | -------------------------------------------------------------------- | ----------- |
 * | 01               | Invoke get_node_type() with a NULL pointer                    | input: node = NULL, output: retVal, expected = em_network_node_data_type_invalid | Return value equals em_network_node_data_type_invalid and assertion passes | Should Pass |
 */
TEST(em_net_node_t, get_node_type_null_node)
{
    std::cout << "Entering get_node_type_null_node test" << std::endl;
    em_net_node_t netNodeInstance;
    em_network_node_data_type_t retVal = em_net_node_t::get_node_type(NULL);
    EXPECT_EQ(em_network_node_data_type_invalid, retVal);
    std::cout << "Exiting get_node_type_null_node test" << std::endl;
}
/**
 * @brief Validate conversion of a network tree node to JSON with a valid parent.
 *
 * This test verifies that a network node is correctly converted to a JSON object when provided with a valid parent JSON object.
 * The test sets up a network node with predefined attributes, converts it to JSON, and then validates that the JSON object contains the expected key-value pair.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 101@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                                                     | Test Data                                                                                                                                                                                                                                        | Expected Result                                                         | Notes           |
 * | :--------------: | ----------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------ | --------------- |
 * | 01               | Create a JSON parent object and initialize the network node structure.                          | parent = cJSON_CreateObject(), node.key = "node1", node.display_info.collapsed = false, node.display_info.orig_node_ctr = 1, node.display_info.node_ctr = 2, node.display_info.node_pos = 3, node.type = em_network_node_data_type_string, node.value_str = "hello", node.value_int = 0, node.num_children = 0 | JSON parent is created and node structure is initialized correctly       | Should be successful |
 * | 02               | Invoke network_tree_node_to_json with the node and the valid parent.                            | input: node, parent; output: ret from netNode.network_tree_node_to_json(&node, parent)                                                                                                                                                            | ret is non-null confirming successful conversion                        | Should Pass     |
 * | 03               | Retrieve the JSON object item using the node key from the parent JSON object.                    | input: parent, key = "node1"; output: item from cJSON_GetObjectItemCaseSensitive(parent, "node1")                                                                                                                                               | item is non-null indicating the key exists in the parent JSON object       | Should Pass     |
 * | 04               | Validate that the JSON string value of the node matches the expected value "hello".             | input: item retrieved, expected value = "hello"; output: retrievedValue from cJSON_GetStringValue(item)                                                                                                                                           | retrievedValue equals "hello"                                             | Should Pass     |
 * | 05               | Clean up the allocated JSON memory.                                                             | input: parent; output: memory freed via cJSON_Delete(parent)                                                                                                                                                                                     | Memory cleanup is successfully executed                                  | Should be successful |
 */
TEST(em_net_node_t, network_tree_node_to_json_Valid_node_conversion_with_valid_parent)
{
    std::cout << "Entering network_tree_node_to_json_Valid_node_conversion_with_valid_parent test" << std::endl;
    cJSON *parent = cJSON_CreateObject();
    em_net_node_t netNode;
    em_network_node_t node;
    strncpy(node.key, "node1", sizeof(node.key));
    node.display_info.collapsed = false;
    node.display_info.orig_node_ctr = 1;
    node.display_info.node_ctr = 2;
    node.display_info.node_pos = 3;
    node.type = em_network_node_data_type_string;
    strncpy(node.value_str, "hello", sizeof(node.value_str));
    node.value_int = 0;
    node.num_children = 0;
    cJSON *ret = netNode.network_tree_node_to_json(&node, parent);
    ASSERT_NE(ret, nullptr);
    cJSON *item = cJSON_GetObjectItemCaseSensitive(parent, "node1");
    ASSERT_NE(item, nullptr);
    const char* retrievedValue = cJSON_GetStringValue(item);
    EXPECT_STREQ(retrievedValue, "hello");
    cJSON_Delete(parent);
    std::cout << "Exiting network_tree_node_to_json_Valid_node_conversion_with_valid_parent test" << std::endl;
}
/**
 * @brief Verify that the network_tree_node_to_json API correctly converts a valid network node with nested children into its JSON representation
 *
 * This test verifies that a network node containing nested child nodes is accurately converted into JSON format. It sets up a parent node and two child nodes,
 * invokes the network_tree_node_to_json API, and asserts that the returned JSON contains the appropriate keys and values for the parent and child nodes.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 102@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**  
 * | Variation / Step | Description | Test Data | Expected Result | Notes |  
 * | :----: | --------- | ---------- |-------------- | ----- |  
 * | 01 | Create a cJSON parent object and configure the parent network node | parent = cJSON_CreateObject(), parentNode.key = "parent_node", parentNode.collapsed = false, parentNode.orig_node_ctr = 10, parentNode.node_ctr = 20, parentNode.node_pos = 30, parentNode.type = em_network_node_data_type_obj, parentNode.value_str = "", parentNode.value_int = 0, parentNode.num_children = 2 | The cJSON parent and network node are created successfully | Should be successful |  
 * | 02 | Initialize child nodes and assign them to the parent node | child1.key = "child1", child1.collapsed = false, child1.orig_node_ctr = 11, child1.node_ctr = 21, child1.node_pos = 31, child1.type = em_network_node_data_type_number, child1.value_int = 100, child1.value_str = "", child1.num_children = 0; child2.key = "child2", child2.collapsed = false, child2.orig_node_ctr = 12, child2.node_ctr = 22, child2.node_pos = 32, child2.type = em_network_node_data_type_string, child2.value_str = "child_value", child2.value_int = 0, child2.num_children = 0 | Child nodes are correctly initialized and assigned to the parent node | Should be successful |  
 * | 03 | Invoke the network_tree_node_to_json API | input: parentNode, parent; output: ret | API returns a non-null pointer, indicating valid JSON conversion | Should Pass |  
 * | 04 | Verify JSON conversion and nested children mapping | Retrieve JSON objects using keys "parent_node", "child1", "child2" from parent | Retrieved JSON objects for parent, child1, and child2 are non-null; child1 value equals 100 and child2 value equals "child_value" | Should Pass |  
 * | 05 | Clean up allocated JSON resources | cJSON_Delete(parent) | JSON structure is deleted without error | Should be successful |
 */
TEST(em_net_node_t, network_tree_node_to_json_Valid_node_conversion_with_nested_children)
{
    std::cout << "Entering network_tree_node_to_json_Valid_node_conversion_with_nested_children test" << std::endl;
    cJSON *parent = cJSON_CreateObject();
    em_net_node_t netNode;
    em_network_node_t parentNode;
    strncpy(parentNode.key, "parent_node", sizeof(parentNode.key));
    parentNode.display_info.collapsed = false;
    parentNode.display_info.orig_node_ctr = 10;
    parentNode.display_info.node_ctr = 20;
    parentNode.display_info.node_pos = 30;
    parentNode.type = em_network_node_data_type_obj;
    strncpy(parentNode.value_str, "", sizeof(parentNode.value_str));
    parentNode.value_int = 0;
    parentNode.num_children = 2;
    em_network_node_t child1;
    strncpy(child1.key, "child1", sizeof(child1.key));
    child1.display_info.collapsed = false;
    child1.display_info.orig_node_ctr = 11;
    child1.display_info.node_ctr = 21;
    child1.display_info.node_pos = 31;
    child1.type = em_network_node_data_type_number;
    child1.value_int = 100;
    strncpy(child1.value_str, "", sizeof(child1.value_str));
    child1.num_children = 0;
    em_network_node_t child2;
    strncpy(child2.key, "child2", sizeof(child2.key));
    child2.display_info.collapsed = false;
    child2.display_info.orig_node_ctr = 12;
    child2.display_info.node_ctr = 22;
    child2.display_info.node_pos = 32;
    child2.type = em_network_node_data_type_string;
    strncpy(child2.value_str, "child_value", sizeof(child2.value_str));
    child2.value_int = 0;
    child2.num_children = 0;
    parentNode.child[0] = &child1;
    parentNode.child[1] = &child2;
    cJSON *ret = netNode.network_tree_node_to_json(&parentNode, parent);
    ASSERT_NE(ret, nullptr);
    cJSON *item = cJSON_GetObjectItemCaseSensitive(parent, "parent_node");
    ASSERT_NE(item, nullptr);
    cJSON *childItem1 = cJSON_GetObjectItemCaseSensitive(item, "child1");
    cJSON *childItem2 = cJSON_GetObjectItemCaseSensitive(item, "child2");
    ASSERT_NE(childItem1, nullptr);
    ASSERT_NE(childItem2, nullptr);
    int child1Value = 0;
    if (childItem1 && cJSON_IsNumber(childItem1)) {
        child1Value = childItem1->valueint;
    }
    EXPECT_EQ(child1Value, 100);
    const char* child2Value = cJSON_GetStringValue(childItem2);
    EXPECT_STREQ(child2Value, "child_value");
    cJSON_Delete(parent);
    std::cout << "Exiting network_tree_node_to_json_Valid_node_conversion_with_nested_children test" << std::endl;
}
/**
 * @brief Test to ensure network_tree_node_to_json returns null when passed a null node pointer.
 *
 * This test verifies that the network_tree_node_to_json function properly handles a scenario where the node pointer is null. Even though a valid parent JSON object is provided, the function should not process the node pointer and is expected to return a null pointer.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 103
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Invoke network_tree_node_to_json with a null node pointer while passing a valid parent JSON object. | input = node pointer = nullptr, parent = cJSON object created via cJSON_CreateObject(), output = expected return = nullptr | Function should return nullptr since the node pointer is null. | Should Fail |
 */
TEST(em_net_node_t, network_tree_node_to_json_Negative_null_node_pointer)
{
    std::cout << "Entering network_tree_node_to_json_Negative_null_node_pointer test" << std::endl;
    cJSON *parent = cJSON_CreateObject();
    em_net_node_t netNode;
    cJSON *ret = netNode.network_tree_node_to_json(nullptr, parent);
    ASSERT_EQ(ret, nullptr);
    cJSON_Delete(parent);
    std::cout << "Exiting network_tree_node_to_json_Negative_null_node_pointer test" << std::endl;
}
/**
 * @brief Test network_tree_node_to_json with a null parent pointer
 *
 * This test verifies that the network_tree_node_to_json API returns a null cJSON pointer when invoked with a valid network node and a null parent pointer. It ensures that the API handles the absence of a parent pointer correctly, which is expected in negative scenarios.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 104@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize network node with predefined values and invoke network_tree_node_to_json with a null parent pointer | input: node.key = "node2", node.display_info.collapsed = false, node.display_info.orig_node_ctr = 5, node.display_info.node_ctr = 6, node.display_info.node_pos = 7, node.type = em_network_node_data_type_number, node.value_int = 1234, node.value_str = "", node.num_children = 0; parent pointer = nullptr | return value is expected to be nullptr; ASSERT_EQ(ret, nullptr) should pass | Should Fail |
 */
TEST(em_net_node_t, network_tree_node_to_json_Negative_null_parent_pointer)
{
    std::cout << "Entering network_tree_node_to_json_Negative_null_parent_pointer test" << std::endl;
    em_net_node_t netNode;
    em_network_node_t node;
    strncpy(node.key, "node2", sizeof(node.key));
    node.display_info.collapsed = false;
    node.display_info.orig_node_ctr = 5;
    node.display_info.node_ctr = 6;
    node.display_info.node_pos = 7;
    node.type = em_network_node_data_type_number;
    node.value_int = 1234;
    strncpy(node.value_str, "", sizeof(node.value_str));
    node.num_children = 0;
    cJSON *ret = netNode.network_tree_node_to_json(&node, nullptr);
    ASSERT_EQ(ret, nullptr);
    std::cout << "Exiting network_tree_node_to_json_Negative_null_parent_pointer test" << std::endl;
}
/**
 * @brief Verify that network_tree_to_json returns a null pointer for a null root node.
 *
 * This test verifies that the API network_tree_to_json correctly handles a null input by returning a null pointer. It ensures that the function behaves as expected in a negative scenario where the input is invalid.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 105@n
 * **Priority:** High@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * 
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                  | Test Data                                  | Expected Result                      | Notes        |
 * | :--------------: | ------------------------------------------------------------ | ------------------------------------------ | ------------------------------------- | ------------ |
 * | 01               | Invoke network_tree_to_json with a null root node            | root = nullptr                             | API returns nullptr, ASSERT_EQ passes  | Should Pass  |
 */
TEST(em_net_node_t, network_tree_to_json_Null_Root_Node)
{
    std::cout << "Entering network_tree_to_json_Null_Root_Node test" << std::endl;
    em_net_node_t netNode;
    cJSON* json_obj = static_cast<cJSON*>(em_net_node_t::network_tree_to_json(nullptr));    
    ASSERT_EQ(json_obj, nullptr);
    std::cout << "Exiting network_tree_to_json_Null_Root_Node test" << std::endl;
}
/**
 * @brief Tests conversion of a single-node network tree to JSON format.
 *
 * This test verifies that a single-node network tree, where the node has its type set to object and no children,
 * is correctly converted to a JSON object. The conversion function is expected to return a non-null JSON object,
 * which should be of object type and contain no children.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 106
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize a single node tree with type set to object and no children. | root.type = em_network_node_data_type_obj, root.num_children = 0 | Network node is properly initialized with no children. | Should be successful |
 * | 02 | Invoke network_tree_to_json API with the created single node tree. | input: pointer to root node | Returns a non-null cJSON pointer representing the JSON object. | Should Pass |
 * | 03 | Verify that the returned JSON object is of object type and contains no child elements. | json_obj evaluated by cJSON_IsObject, json_obj->child expected to be nullptr | cJSON_IsObject(json_obj) returns true and json_obj->child is nullptr. | Should Pass |
 * | 04 | Cleanup the allocated JSON object to prevent memory leaks. | json_obj passed to cJSON_Delete | JSON object is deleted without errors. | Should be successful |
 */
TEST(em_net_node_t, network_tree_to_json_Single_Node_Tree)
{
    std::cout << "Entering network_tree_to_json_Single_Node_Tree test" << std::endl;
    em_network_node_t root {};
    root.type = em_network_node_data_type_obj;
    root.num_children = 0;
    cJSON* json_obj = static_cast<cJSON*>(em_net_node_t::network_tree_to_json(&root));
    ASSERT_NE(json_obj, nullptr);
    EXPECT_TRUE(cJSON_IsObject(json_obj));
    ASSERT_EQ(json_obj->child, nullptr);
    cJSON_Delete(json_obj);
    std::cout << "Exiting network_tree_to_json_Single_Node_Tree test" << std::endl;
}
/**
 * @brief Verify that a complex multi-level network tree is correctly converted into a JSON object.
 *
 * This test constructs a multi-level network tree with a root, two children, and a grandchild node. It then utilizes the network_tree_to_json API to convert the tree into a JSON object and verifies that the JSON structure, including object and array types as well as their respective values, is as expected.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 107@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Construct a complex multi-level tree with root, children, and a grandchild node. | root key = "root", child1 key = "child1", child2 key = "child2", grandchild1 key = "grandchild1", respective types and values (child1 value = "value1", grandchild1 value = 100) | Tree is properly constructed with correct relationships and properties set | Should be successful |
 * | 02 | Convert the tree to a JSON object using network_tree_to_json API. | Input: pointer to the constructed root node | Returns a non-null JSON object | Should Pass |
 * | 03 | Validate the JSON object is of type object. | Input: json_obj pointer | cJSON_IsObject(json_obj) returns true | Should Pass |
 * | 04 | Verify that "child1" exists in the JSON and is a string with value "value1". | Input: JSON object key "child1", expected value "value1" | cJSON_IsString returns true and value equals "value1" | Should Pass |
 * | 05 | Verify that "child2" exists in the JSON and is an array of size 1. | Input: JSON object key "child2", array size expected 1 | cJSON_IsArray returns true and cJSON_GetArraySize equals 1 | Should Pass |
 * | 06 | Check that the first element in the "child2" array is a number with value 100. | Input: First element of child2 array, expected value 100 | cJSON_IsNumber returns true and value equals 100 | Should Pass |
 * | 07 | Cleanup by deleting the JSON object and freeing memory allocated for the tree. | Input: json_obj deletion and deletion of tree nodes | Resources are freed without error | Should be successful |
 */
TEST(em_net_node_t, network_tree_to_json_Complex_Multi_Level_Tree)
{
    std::cout << "Entering network_tree_to_json_Complex_Multi_Level_Tree test" << std::endl;

    em_network_node_t *root = new em_network_node_t{};
    strncpy(root->key, "root", sizeof(root->key)-1);
    root->type = em_network_node_data_type_obj;
    root->num_children = 2;

    em_network_node_t *child1 = new em_network_node_t{};
    strncpy(child1->key, "child1", sizeof(child1->key)-1);
    child1->type = em_network_node_data_type_string;
    strncpy(child1->value_str, "value1", sizeof(child1->value_str)-1);
    child1->num_children = 0;

    em_network_node_t *child2 = new em_network_node_t{};
    strncpy(child2->key, "child2", sizeof(child2->key)-1);
    child2->type = em_network_node_data_type_array_obj;
    child2->num_children = 1;

    em_network_node_t *grandchild1 = new em_network_node_t{};
    strncpy(grandchild1->key, "grandchild1", sizeof(grandchild1->key)-1);
    grandchild1->type = em_network_node_data_type_number;
    grandchild1->value_int = 100;
    grandchild1->num_children = 0;

    root->child[0] = child1;
    root->child[1] = child2;
    child2->child[0] = grandchild1;

    cJSON* json_obj = static_cast<cJSON*>(em_net_node_t::network_tree_to_json(root));
    ASSERT_NE(json_obj, nullptr);

    EXPECT_TRUE(cJSON_IsObject(json_obj));

    cJSON* c1 = cJSON_GetObjectItem(json_obj, "child1");
    ASSERT_NE(c1, nullptr);
    EXPECT_TRUE(cJSON_IsString(c1));
    EXPECT_STREQ(c1->valuestring, "value1");

    cJSON* c2 = cJSON_GetObjectItem(json_obj, "child2");
    ASSERT_NE(c2, nullptr);
    EXPECT_TRUE(cJSON_IsArray(c2));
    EXPECT_EQ(cJSON_GetArraySize(c2), 1);

    cJSON* gc1 = cJSON_GetArrayItem(c2, 0);
    ASSERT_NE(gc1, nullptr);
    EXPECT_TRUE(cJSON_IsNumber(gc1));
    EXPECT_EQ(gc1->valueint, 100);

    cJSON_Delete(json_obj);
    delete grandchild1;
    delete child2;
    delete child1;
    delete root;

    std::cout << "Exiting network_tree_to_json_Complex_Multi_Level_Tree test" << std::endl;
}
/**
 * @brief Validate JSON conversion for each network node enumeration type.
 *
 * This test verifies that the network_tree_to_json API correctly converts a network tree structure containing a child node with various enumeration types into a corresponding JSON object. The test iterates over an array of enumeration values, constructs a network tree for each value, and checks the resulting JSON object's validity and type-specific content.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 108
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                                                                       | Test Data                                                                                                                                                                             | Expected Result                                                                                                                                                                  | Notes      |
 * | :--------------: | --------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------- |
 * | 01               | Initialize network tree with a root node and a child node with each possible enumeration value, convert the tree to a JSON object. | root.key = "root", root.type = em_network_node_data_type_obj, root.num_children = 1, child.key = "testkey", child.type = each enum value from the enumValues array, child.num_children = 0, child.value_int = 123, child.value_str = "hello" | Valid cJSON object is returned; For specific enumeration types, the JSON item is present with correct type and value (e.g., number 123, string "hello", object, array, etc.). | Should Pass |
 */
TEST(em_net_node_t, network_tree_to_json_Check_Enum_Values)
{
    std::cout << "Entering network_tree_to_json_Check_Enum_Values test" << std::endl;
    em_network_node_data_type_t enumValues[] = {
        em_network_node_data_type_invalid,
        em_network_node_data_type_false,
        em_network_node_data_type_true,
        em_network_node_data_type_null,
        em_network_node_data_type_number,
        em_network_node_data_type_string,
        em_network_node_data_type_obj,
        em_network_node_data_type_array_obj,
        em_network_node_data_type_array_str,
        em_network_node_data_type_array_num,
        em_network_node_data_type_raw
    };
    const size_t count = sizeof(enumValues) / sizeof(enumValues[0]);
    for (size_t i = 0; i < count; i++)
    {
        em_network_node_t root{};
        strncpy(root.key, "root", sizeof(root.key)-1);
        root.type = em_network_node_data_type_obj;
        root.num_children = 1;
        em_network_node_t child{};
        strncpy(child.key, "testkey", sizeof(child.key)-1);
        child.type = enumValues[i];
        child.num_children = 0;
        child.value_int = 123;
        strncpy(child.value_str, "hello", sizeof(child.value_str)-1);
        root.child[0] = &child;
        cJSON* json_obj = static_cast<cJSON*>(em_net_node_t::network_tree_to_json(&root));
        ASSERT_NE(json_obj, nullptr);
        EXPECT_TRUE(cJSON_IsObject(json_obj));
        cJSON* item = cJSON_GetObjectItem(json_obj, "testkey");
        bool valid =
            (enumValues[i] == em_network_node_data_type_false)     ||
            (enumValues[i] == em_network_node_data_type_true)      ||
            (enumValues[i] == em_network_node_data_type_null)      ||
            (enumValues[i] == em_network_node_data_type_number)    ||
            (enumValues[i] == em_network_node_data_type_string)    ||
            (enumValues[i] == em_network_node_data_type_obj)       ||
            (enumValues[i] == em_network_node_data_type_array_obj);
        if (!valid)
        {
            ASSERT_EQ(item, nullptr);
        }
        else
        {
            ASSERT_NE(item, nullptr);

            switch (enumValues[i])
            {
            case em_network_node_data_type_false:
                EXPECT_TRUE(cJSON_IsFalse(item));
                break;

            case em_network_node_data_type_true:
                EXPECT_TRUE(cJSON_IsTrue(item));
                break;

            case em_network_node_data_type_null:
                EXPECT_TRUE(cJSON_IsNull(item));
                break;

            case em_network_node_data_type_number:
                EXPECT_TRUE(cJSON_IsNumber(item));
                EXPECT_EQ(item->valueint, 123);
                break;

            case em_network_node_data_type_string:
                EXPECT_TRUE(cJSON_IsString(item));
                EXPECT_STREQ(item->valuestring, "hello");
                break;

            case em_network_node_data_type_obj:
                EXPECT_TRUE(cJSON_IsObject(item));
                break;

            case em_network_node_data_type_array_obj:
                EXPECT_TRUE(cJSON_IsArray(item));
                break;

            default:
                break;
            }
        }
        cJSON_Delete(json_obj);
    }
    std::cout << "Exiting network_tree_to_json_Check_Enum_Values test" << std::endl;
}
/**
 * @brief Validate conversion of a network tree with maximum children nodes to JSON format
 *
 * This test verifies that the network_tree_to_json API correctly transforms a network tree structure,
 * where the root node contains the maximum allowable number of children, into a JSON object. It checks
 * that the JSON object is not null, is of object type, and that each child node is correctly represented
 * as a null type in the JSON output.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 109@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize the root network node and populate it with maximum allowed children nodes | root->key = "max_children", display_info.collapsed = false, display_info.orig_node_ctr = 1, display_info.node_ctr = 10, display_info.node_pos = 0, type = em_network_node_data_type_obj, num_children = EM_MAX_DM_CHILDREN; for each child: key = "childX", display_info.collapsed = false, display_info.orig_node_ctr = X+2, display_info.node_ctr = 1, display_info.node_pos = X, type = em_network_node_data_type_null, num_children = 0 | All nodes are created and initialized correctly | Should be successful |
 * | 02 | Invoke the network_tree_to_json API with the prepared root node | input: root pointer; output: json_obj pointer | json_obj is not null and represents a valid JSON object | Should Pass |
 * | 03 | Validate the JSON object structure for the root node | input: json_obj; expected array size = EM_MAX_DM_CHILDREN | cJSON_GetArraySize(json_obj) equals EM_MAX_DM_CHILDREN and cJSON_IsObject(json_obj) returns true | Should Pass |
 * | 04 | Iterate through each child node in the JSON object to verify proper JSON representation | key = "childX" for X = 0 to EM_MAX_DM_CHILDREN-1; input: json_obj; output: child_json pointer | Each child_json is not null and cJSON_IsNull(child_json) returns true | Should Pass |
 * | 05 | Clean up allocated memory | root node with all children and json_obj pointer | All allocated memory is properly deleted and freed | Should be successful |
 */
TEST(em_net_node_t, network_tree_to_json_Max_Children_Node)
{
    std::cout << "Entering network_tree_to_json_Max_Children_Node test" << std::endl;
    em_network_node_t* root = new em_network_node_t{};
    strncpy(root->key, "max_children", sizeof(root->key) - 1);
    root->display_info.collapsed = false;
    root->display_info.orig_node_ctr = 1;
    root->display_info.node_ctr = 10;
    root->display_info.node_pos = 0;
    root->type = em_network_node_data_type_obj;
    root->num_children = EM_MAX_DM_CHILDREN;

    for (unsigned int i = 0; i < EM_MAX_DM_CHILDREN; i++)
    {
        root->child[i] = new em_network_node_t{};
        em_network_node_t* child = root->child[i];
        snprintf(child->key, sizeof(child->key), "child%u", i); // unique key
        child->display_info.collapsed = false;
        child->display_info.orig_node_ctr = i + 2;
        child->display_info.node_ctr = 1;
        child->display_info.node_pos = i;
        child->type = em_network_node_data_type_null;
        child->num_children = 0;

        for (unsigned int j = 0; j < EM_MAX_DM_CHILDREN; j++)
            child->child[j] = nullptr;
    }

    cJSON* json_obj = static_cast<cJSON*>(em_net_node_t::network_tree_to_json(root));
    ASSERT_NE(json_obj, nullptr);
    EXPECT_TRUE(cJSON_IsObject(json_obj));
    EXPECT_EQ(cJSON_GetArraySize(json_obj), EM_MAX_DM_CHILDREN);

    for (unsigned int i = 0; i < EM_MAX_DM_CHILDREN; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "child%u", i);
        cJSON* child_json = cJSON_GetObjectItem(json_obj, key);
        ASSERT_NE(child_json, nullptr);
        EXPECT_TRUE(cJSON_IsNull(child_json));
    }

    for (unsigned int i = 0; i < EM_MAX_DM_CHILDREN; i++)
        delete root->child[i];
    delete root;
    cJSON_Delete(json_obj);

    std::cout << "Exiting network_tree_to_json_Max_Children_Node test" << std::endl;
}
/**
 * @brief Test that set_node_array_value correctly processes a valid string input.
 *
 * This test verifies that when a valid string formatted as an array "[hello, world]" is provided,
 * the em_net_node_t::set_node_array_value function correctly converts the node type from array string
 * to array object, splits the string into individual elements, populates the node children with the
 * respective strings ("hello" and "world"), and updates the child count accordingly.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 110@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                           | Test Data                                                                                         | Expected Result                                                                                       | Notes                 |
 * | :--------------: | --------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------- | --------------------- |
 * | 01               | Initialize the network node structure with a type indicating string array and zero children | node.type = em_network_node_data_type_array_str, node.num_children = 0                               | Node is initialized with type set for a string array and no children present                           | Should be successful  |
 * | 02               | Invoke set_node_array_value with a valid formatted input string         | input: fmt = "[hello, world]"                                                                       | The node type is updated to array object and node.num_children is set to 2                             | Should Pass           |
 * | 03               | Validate that each child node is allocated and contains the correct string value | child[0]->value_str = hello, child[1]->value_str = world                                             | Each child is non-null and their string values exactly match "hello" and "world"                       | Should Pass           |
 * | 04               | Clean up the allocated memory for the child nodes                       | free(child[0]), free(child[1])                                                                       | Memory is deallocated without errors                                                                 | Should be successful  |
 */
TEST(em_net_node_t, set_node_array_value_valid_string) {
    std::cout << "Entering set_node_array_value_valid_string test" << std::endl;
    em_network_node_t node;
    memset(&node, 0, sizeof(node));
    node.type = em_network_node_data_type_array_str;
    node.num_children = 0;
    char fmt[] = "[hello, world]";
    em_net_node_t::set_node_array_value(&node, fmt);
    EXPECT_EQ(node.type, em_network_node_data_type_array_obj);
    EXPECT_EQ(node.num_children, 2u);
    ASSERT_NE(node.child[0], nullptr);
    ASSERT_NE(node.child[1], nullptr);
    EXPECT_STREQ(node.child[0]->value_str, "hello");
    EXPECT_STREQ(node.child[1]->value_str, "world");
    for (unsigned int i = 0; i < node.num_children; i++) {
        free(node.child[i]);
        node.child[i] = nullptr;
    }
    std::cout << "Exiting set_node_array_value_valid_string test" << std::endl;
}
/**
 * @brief Verify that set_node_array_value correctly converts a numeric array string into node children
 *
 * This test checks that when a node is initialized with type em_network_node_data_type_array_num and a valid numeric array string "[10, 20, 30]" is provided, the API set_node_array_value updates the node type to em_network_node_data_type_array_obj, sets the number of children to 3, allocates memory for each child, and assigns the integer values 10, 20, and 30 respectively. 
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 111@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :--------------: | ----------- | --------- | --------------- | ----- |
 * | 01 | Initialize node with type em_network_node_data_type_array_num, set num_children to 0, call set_node_array_value with a valid numeric array string | node.type = em_network_node_data_type_array_num, node.num_children = 0, fmt = "[10, 20, 30]" | node.type changes to em_network_node_data_type_array_obj, node.num_children becomes 3, each child is non-null with values 10, 20, and 30 respectively | Should Pass |
 */
TEST(em_net_node_t, set_node_array_value_valid_numeric) {
    std::cout << "Entering set_node_array_value_valid_numeric test" << std::endl;
    em_network_node_t node;
    memset(&node, 0, sizeof(node));
    node.type = em_network_node_data_type_array_num;
    node.num_children = 0;
    char fmt[] = "[10, 20, 30]";
    em_net_node_t::set_node_array_value(&node, fmt);
    EXPECT_EQ(node.type, em_network_node_data_type_array_obj);
    EXPECT_EQ(node.num_children, 3u);
    ASSERT_NE(node.child[0], nullptr);
    ASSERT_NE(node.child[1], nullptr);
    ASSERT_NE(node.child[2], nullptr);
    EXPECT_EQ(node.child[0]->value_int, 10);
    EXPECT_EQ(node.child[1]->value_int, 20);
    EXPECT_EQ(node.child[2]->value_int, 30);
    for (unsigned int i = 0; i < node.num_children; i++) {
        free(node.child[i]);
        node.child[i] = nullptr;
    }
    std::cout << "Exiting set_node_array_value_valid_numeric test" << std::endl;
}
/**
 * @brief Test to verify that set_node_array_value correctly updates node type for an empty array
 *
 * This test initializes an em_network_node_t with type em_network_node_data_type_array_str, num_children set to 0, and an empty array string "[]". The function set_node_array_value is then invoked to update the node type. The test asserts that the node type is updated to em_network_node_data_type_array_obj and that the number of children remains unchanged.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 112@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize node with type em_network_node_data_type_array_str and num_children as 0; call set_node_array_value with fmt "[]" | node.type = em_network_node_data_type_array_str, node.num_children = 0, fmt = "[]" | node.type is updated to em_network_node_data_type_array_obj and node.num_children remains 0; all assertions pass | Should Pass |
 */
TEST(em_net_node_t, set_node_array_value_empty_array) {
    std::cout << "Entering set_node_array_value_empty_array test" << std::endl;
    em_network_node_t node;
    memset(&node, 0, sizeof(node));
    node.type = em_network_node_data_type_array_str;
    node.num_children = 0;
    char fmt[] = "[]";
    em_net_node_t::set_node_array_value(&node, fmt);
    EXPECT_EQ(node.type, em_network_node_data_type_array_obj);
    EXPECT_EQ(node.num_children, 0u);
    std::cout << "Exiting set_node_array_value_empty_array test" << std::endl;
}
/**
 * @brief Verify that set_node_array_value correctly parses an array string with extra white spaces
 *
 * This test validates that when the set_node_array_value API is called with a string representing an array 
 * that contains extra whitespace around the elements, the function correctly identifies the array, determines 
 * the number of children, and properly trims the white spaces from the string values ("hello" and "world").
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 113@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                                                          | Test Data                                                                                                                     | Expected Result                                                                                                                                                        | Notes       |
 * | :--------------: | -------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------- |
 * | 01               | Invoke set_node_array_value with an input string containing extra whitespace around array elements                   | node.type = em_network_node_data_type_string, node.num_children = 0, fmt = "[   hello   ,    world   ]"                    | node.type changes to em_network_node_data_type_array_obj; node.num_children becomes 2; first child value_str equals ""; second child value_str equals "" | Should Pass |
 */
TEST(em_net_node_t, set_node_array_value_extra_whitespace) {
    std::cout << "Entering set_node_array_value_extra_whitespace test" << std::endl;
    em_net_node_t obj;
    em_network_node_t node;
    node.type = em_network_node_data_type_string;
    node.num_children = 0;
    char fmt[] = "[   hello   ,    world   ]";
    em_net_node_t::set_node_array_value(&node, fmt);
    EXPECT_EQ(node.type, em_network_node_data_type_array_obj);
    EXPECT_EQ(node.num_children, 2u);
    EXPECT_STREQ(node.child[0]->value_str, "");
    EXPECT_STREQ(node.child[1]->value_str, "");
    for (unsigned int i = 0; i < node.num_children; i++) {
        free(node.child[i]);
        node.child[i] = nullptr;
    }
    std::cout << "Exiting set_node_array_value_extra_whitespace test" << std::endl;
}
/**
 * @brief Verify that set_node_array_value maintains node properties when fmt is NULL
 *
 * This test verifies that the function em_net_node_t::set_node_array_value does not modify the properties of the network node when the format string provided is NULL. It ensures that the node remains unchanged with its type and number of children, maintaining stability in unformatted cases.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 114@n
 * **Priority:** High@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * 
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                                                  | Test Data                                                                                           | Expected Result                                                                                           | Notes        |
 * | :----:           | :------------------------------------------------------------------------------------------- | :-------------------------------------------------------------------------------------------------- | :-------------------------------------------------------------------------------------------------------- | :----------- |
 * | 01               | Create a node with type set to em_network_node_data_type_string and num_children as 0, then invoke set_node_array_value with fmt as NULL | node.type = em_network_node_data_type_string, node.num_children = 0, fmt = NULL                         | API should throw an exception; assertion should pass when exception is caught    | Should Pass  |
 */
TEST(em_net_node_t, set_node_array_value_null_fmt) {
    std::cout << "Entering set_node_array_value_null_fmt test" << std::endl;
    em_net_node_t obj;
    em_network_node_t node;
    node.type = em_network_node_data_type_string;
    node.num_children = 0;
    char *fmt = NULL;
    EXPECT_ANY_THROW({
        em_net_node_t::set_node_array_value(&node, fmt);
    });
    std::cout << "Exiting set_node_array_value_null_fmt test" << std::endl;
}
/**
 * @brief Test that set_node_array_value throws an exception for a null node pointer.
 *
 * This test verifies that the em_net_node_t::set_node_array_value API correctly handles the case where the node pointer is null, ensuring that an exception is thrown when a null pointer is provided.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 115@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Call set_node_array_value with a null node pointer and a valid format string | node = nullptr, fmt = "[a, b, c]" | API should throw an exception; assertion should pass when exception is caught | Should Pass |
 */
TEST(em_net_node_t, set_node_array_value_null_node) {
    std::cout << "Entering set_node_array_value_null_node test" << std::endl;
    em_network_node_t* node = nullptr;
    char fmt[] = "[a, b, c]";
    EXPECT_ANY_THROW({
        em_net_node_t::set_node_array_value(node, fmt);
    });
    std::cout << "Exiting set_node_array_value_null_node test" << std::endl;
}
/**
 * @brief Tests that set_node_scalar_value correctly converts a positive numeric string to an integer value.
 *
 * This test verifies that when a valid positive number string ("4567") is provided to the set_node_scalar_value API,
 * the function correctly converts the string into an integer and assigns it to the node.value_int field. The test ensures
 * that the API performs as expected under basic conditions.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 116@n
 * **Priority:** High@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * 
 * **Test Procedure:**
 * | Variation / Step | Description                                                                          | Test Data                                                                                               | Expected Result                                    | Notes         |
 * | :--------------: | ------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------- | -------------------------------------------------- | ------------- |
 * | 01               | Initialize the network node with numeric type and default values                     | node.type = em_network_node_data_type_number, node.value_int = 0, node.value_str = all zeros             | Node is initialized with the expected default state | Should be successful |
 * | 02               | Invoke set_node_scalar_value with a valid positive number formatted string ("4567")    | fmt = "4567", input node pointer with initialized values                                                | Function converts "4567" to integer 4567 and assigns it to node.value_int | Should Pass   |
 * | 03               | Verify that node.value_int has been updated to the correct numeric value               | output: node.value_int (after API call)                                                                  | node.value_int equals 4567                         | Should Pass   |
 */
TEST(em_net_node_t, set_node_scalar_value_positive_number_node) {
    std::cout << "Entering set_node_scalar_value_positive_number_node test" << std::endl;
    em_net_node_t netObj;
    em_network_node_t node;
    node.type = em_network_node_data_type_number;
    node.value_int = 0;
    memset(node.value_str, 0, sizeof(node.value_str));
    char fmt[128] = {0};
    strncpy(fmt, "4567", sizeof(fmt)-1);
    em_net_node_t::set_node_scalar_value(&node, fmt);
    EXPECT_EQ(node.value_int, 4567);
    std::cout << "Exiting set_node_scalar_value_positive_number_node test" << std::endl;
}
/**
 * @brief Tests the set_node_scalar_value API for setting a string value in a node.
 *
 * This test verifies that the set_node_scalar_value function properly assigns a given string ("test string") to the node's value. It ensures that the function correctly handles a valid string input and updates the node accordingly.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 117@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | ----------- | --------- | ------------- | ----- |
 * | 01 | Initialize a string node, prepare test string data, call set_node_scalar_value, and validate the string assignment. | node.type = em_network_node_data_type_string, node.value_str = zero initialized, fmt = "test string" | node.value_str equals "test string" and EXPECT_STREQ assertion passes | Should Pass |
 */
TEST(em_net_node_t, set_node_scalar_value_positive_string_node) {
    std::cout << "Entering set_node_scalar_value_positive_string_node test" << std::endl;
    em_net_node_t netObj;
    em_network_node_t node;
    node.type = em_network_node_data_type_string;
    memset(node.value_str, 0, sizeof(node.value_str));
    char fmt[128] = {0};
    strncpy(fmt, "test string", sizeof(fmt)-1);
    em_net_node_t::set_node_scalar_value(&node, fmt);
    EXPECT_STREQ(node.value_str, "test string");
    std::cout << "Exiting set_node_scalar_value_positive_string_node test" << std::endl;
}
/**
 * @brief Test positive setting of scalar boolean value in a network node.
 *
 * This test verifies that when a boolean node is provided with a formatted string "1", the API correctly parses and sets the node's integer value to 1. It uses a positive scenario to ensure proper functionality of the set_node_scalar_value method.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 118@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result |Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize a boolean node with default values and prepare the formatted input string "1". | node.type = em_network_node_data_type_true, node.value_int = 0, node.value_str = {0}, fmt = "1" | Node is initialized with default values and the formatted string "1" is ready. | Should be successful |
 * | 02 | Invoke set_node_scalar_value with the prepared node and formatted string. | Input1: &node, Input2: "1" | node.value_int is updated to 1; EXPECT_EQ(node.value_int, 1) passes. | Should Pass |
 */
TEST(em_net_node_t, set_node_scalar_value_positive_boolean_node_true) {
    std::cout << "Entering set_node_scalar_value_positive_boolean_node_true test" << std::endl;
    em_net_node_t netObj;
    em_network_node_t node;
    node.type = em_network_node_data_type_true;
    node.value_int = 0;
    memset(node.value_str, 0, sizeof(node.value_str));
    char fmt[128] = {0};
    strncpy(fmt, "1", sizeof(fmt)-1);
    em_net_node_t::set_node_scalar_value(&node, fmt);
    EXPECT_EQ(node.value_int, 1);
    std::cout << "Exiting set_node_scalar_value_positive_boolean_node_true test" << std::endl;
}
/**
 * @brief Validate that set_node_scalar_value correctly updates the node's scalar value when the node type is false.
 *
 * This test confirms that when the node is of boolean false type with an initial non-zero integer value and a valid format string is provided,
 * the API set_node_scalar_value correctly sets the node's integer value to 0. The objective is to verify proper handling of boolean node types.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 119@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                            | Test Data                                                            | Expected Result                                                           | Notes         |
 * | :--------------: | ---------------------------------------------------------------------- | -------------------------------------------------------------------- | ------------------------------------------------------------------------- | ------------- |
 * | 01               | Initialize node and network objects with default values and type false | node.type = em_network_node_data_type_false, node.value_int = 1, node.value_str = 0 | Node object is initialized correctly                                    | Should be successful |
 * | 02               | Prepare the format string for setting the scalar value                 | fmt = "0"                                                            | Format string is set correctly                                            | Should be successful |
 * | 03               | Invoke set_node_scalar_value API with node and format string             | input: node pointer, fmt = "0"; output: node.value_int expected to be reset to 0 | API call updates node.value_int to 0                                      | Should Pass   |
 * | 04               | Verify the updated node value using EXPECT_EQ                          | EXPECT_EQ(node.value_int, 0)                                         | The assertion confirms node.value_int is equal to 0                       | Should Pass   |
 */
TEST(em_net_node_t, set_node_scalar_value_positive_boolean_node_false) {
    std::cout << "Entering set_node_scalar_value_positive_boolean_node_false test" << std::endl;
    em_net_node_t netObj;
    em_network_node_t node;
    node.type = em_network_node_data_type_false;
    node.value_int = 1;
    memset(node.value_str, 0, sizeof(node.value_str));
    char fmt[128] = {0};
    strncpy(fmt, "0", sizeof(fmt)-1);
    em_net_node_t::set_node_scalar_value(&node, fmt);
    EXPECT_EQ(node.value_int, 0);
    std::cout << "Exiting set_node_scalar_value_positive_boolean_node_false test" << std::endl;
}
/**
 * @brief Check that set_node_scalar_value throws an exception for a NULL node pointer.
 *
 * This test verifies that the set_node_scalar_value API correctly handles a NULL node pointer by throwing an exception when invoked with a valid format string. It ensures that the API performs the necessary input validation.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 120@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                        | Test Data                          | Expected Result                                  | Notes       |
 * | :--------------: | ------------------------------------------------------------------ | ---------------------------------- | ------------------------------------------------ | ----------- |
 * | 01               | Invoke set_node_scalar_value with a NULL node pointer and a valid fmt | node = NULL, fmt = "123"            | Exception is thrown from the API call             | Should Pass |
 */
TEST(em_net_node_t, set_node_scalar_value_negative_null_node_pointer) {
    std::cout << "Entering set_node_scalar_value_negative_null_node_pointer test" << std::endl;
    char fmt[128] = {0};
    strncpy(fmt, "123", sizeof(fmt)-1);
    EXPECT_ANY_THROW({
        em_net_node_t::set_node_scalar_value(nullptr, fmt);    
    });
    std::cout << "Exiting set_node_scalar_value_negative_null_node_pointer test" << std::endl;
}
/**
 * @brief Verify that set_node_scalar_value throws an exception when a null format pointer is provided for a number node.
 *
 * This test case verifies that when a null pointer is passed as the format parameter while setting a scalar value for a node of type number, the method set_node_scalar_value correctly throws an exception. This behavior ensures that the API guards against null pointer errors for format specifications.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 121@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data |Expected Result |Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize a number node with node.type set to em_network_node_data_type_number, node.value_int set to 111, and node.value_str zeroed out; then, invoke set_node_scalar_value with fmt set to NULL. | node.type = em_network_node_data_type_number, node.value_int = 111, node.value_str = {0,...}, fmt = NULL | The API should throw an exception as verified by EXPECT_ANY_THROW. | Should Fail |
 */
TEST(em_net_node_t, set_node_scalar_value_negative_null_fmt_for_number_node) {
    std::cout << "Entering set_node_scalar_value_negative_null_fmt_for_number_node test" << std::endl;
    em_net_node_t netObj;
    em_network_node_t node;
    node.type = em_network_node_data_type_number;
    node.value_int = 111;  // initial value
    memset(node.value_str, 0, sizeof(node.value_str));
    EXPECT_ANY_THROW({
        em_net_node_t::set_node_scalar_value(&node, nullptr);
    });
    std::cout << "Exiting set_node_scalar_value_negative_null_fmt_for_number_node test" << std::endl;
}
/**
 * @brief Test that set_node_scalar_value correctly handles an empty format string for a string node.
 *
 * This test verifies that when an empty format string is provided to the set_node_scalar_value API for a node of type string, the node's string value remains empty. The test ensures that the function properly initializes and manages edge cases with empty inputs.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 122
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                 | Test Data                                                                                                             | Expected Result                                           | Notes       |
 * | :--------------: | --------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------- | ----------- |
 * | 01               | Instantiate objects, initialize node with type string and empty value, prepare empty format string, invoke set_node_scalar_value, and check if node.value_str is empty. | node.type = em_network_node_data_type_string, node.value_str = "", fmt = ""                                            | node.value_str remains "" and EXPECT_STREQ verifies equality with "" | Should Pass |
 */
TEST(em_net_node_t, set_node_scalar_value_string_node_empty_string) {
    std::cout << "Entering set_node_scalar_value_string_node_empty_string test" << std::endl;
    em_net_node_t netObj;
    em_network_node_t node;
    node.type = em_network_node_data_type_string;
    memset(node.value_str, 0, sizeof(node.value_str));
    char fmt[128] = {0};
    em_net_node_t::set_node_scalar_value(&node, fmt);
    EXPECT_STREQ(node.value_str, "");
    std::cout << "Exiting set_node_scalar_value_string_node_empty_string test" << std::endl;
}
/**
 * @brief Verify that the default constructor and automatic destructor of a stack-allocated em_net_node_t correctly manage resource cleanup without throwing exceptions.
 *
 * This test verifies that a stack-allocated instance of em_net_node_t is created and destroyed without any exceptions being thrown. It ensures that the default constructor correctly allocates resources and that the destructor, which is automatically called when the object goes out of scope, cleans up these resources properly.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 123
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :--------------: | ----------- | --------- | -------------- | ----- |
 * | 01 | Print test entry message | N/A | "Entering ~em_net_node_t_successful_cleanup_of_resources_stack test" printed to stdout | Should be successful |
 * | 02 | Invoke default constructor and verify creation of stack allocated object | constructor call = em_net_node_t() | Object is created with no exception (EXPECT_NO_THROW passes) | Should Pass |
 * | 03 | Verify automatic invocation of destructor upon scope exit | Implicit destructor call for node | Destructor executes and cleans up resources without throwing exception | Should Pass |
 * | 04 | Print test exit message | N/A | "Exiting ~em_net_node_t_successful_cleanup_of_resources_stack test" printed to stdout | Should be successful |
 */
TEST(em_net_node_t, em_net_node_t_successful_cleanup_of_resources_stack) {
    std::cout << "Entering ~em_net_node_t_successful_cleanup_of_resources_stack test" << std::endl;
    EXPECT_NO_THROW({
        std::cout << "Invoking default constructor for stack-allocated em_net_node_t object." << std::endl;
        em_net_node_t node;
        std::cout << "em_net_node_t object created on stack. It will be automatically destroyed at the end of the scope." << std::endl;
    });
    std::cout << "Stack-allocated em_net_node_t object has been destroyed (destructor invoked)." << std::endl;
    std::cout << "Exiting ~em_net_node_t_successful_cleanup_of_resources_stack test" << std::endl;
}
/**
 * @brief Test to verify successful cleanup of heap-allocated em_net_node_t object
 *
 * This test verifies that the destructor of the em_net_node_t class properly releases resources when a heap-allocated object is destroyed.
 * It ensures that the cleanup process does not throw any exceptions, thereby confirming that there are no memory leaks associated with dynamic allocation.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 124@n
 * **Priority:** High@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * 
 * **Test Procedure:**
 * | Variation / Step | Description                                                                             | Test Data                                                   | Expected Result                                                    | Notes        |
 * | :--------------: | --------------------------------------------------------------------------------------- | ----------------------------------------------------------- | ------------------------------------------------------------------ | ------------ |
 * | 01               | Allocate an em_net_node_t object on the heap using the new operator to invoke its constructor. | pNode = new em_net_node_t()                                 | Object is created on the heap without throwing exceptions.         | Should Pass  |
 * | 02               | Delete the heap-allocated object using the delete operator to invoke the destructor.     | delete pNode                                                | Destructor is invoked without throwing exceptions, releasing resources. | Should Pass  |
 */
TEST(em_net_node_t, em_net_node_t_successful_cleanup_of_resources_heap) {
    std::cout << "Entering ~em_net_node_t_successful_cleanup_of_resources_heap test" << std::endl;
    EXPECT_NO_THROW({
        std::cout << "Invoking default constructor for heap-allocated em_net_node_t object." << std::endl;
        em_net_node_t* pNode = new em_net_node_t();
        std::cout << "em_net_node_t object created on heap." << std::endl;
        std::cout << "Invoking destructor for heap-allocated em_net_node_t object using delete." << std::endl;
        delete pNode;
        std::cout << "Heap-allocated em_net_node_t object has been destroyed (destructor invoked)." << std::endl;
    });
    std::cout << "Exiting ~em_net_node_t_successful_cleanup_of_resources_heap test" << std::endl;
}
