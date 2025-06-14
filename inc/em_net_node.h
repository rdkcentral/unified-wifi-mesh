/**
 * Copyright 2023 Comcast Cable Communications Management, LLC
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
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef EM_NET_NODE_H
#define EM_NET_NODE_H

#include "em_base.h"

class em_net_node_t {

public:
    
	/**!
	 * @brief Retrieves the network tree from a specified file.
	 *
	 * This function reads the network configuration from the given file and constructs
	 * a network tree based on the data.
	 *
	 * @param[in] file_name The name of the file containing the network configuration.
	 *
	 * @returns A pointer to the constructed network tree.
	 * @retval NULL if the file cannot be read or the network tree cannot be constructed.
	 *
	 * @note Ensure the file exists and is accessible before calling this function.
	 */
	static em_network_node_t *get_network_tree_by_file(const char *file_name);
    
	/**!
	 * @brief Retrieves the network tree.
	 *
	 * This function processes the provided buffer to extract the network tree structure.
	 *
	 * @param[in] buff A character buffer containing the network data.
	 *
	 * @returns A pointer to the em_network_node_t structure representing the network tree.
	 *
	 * @note Ensure the buffer is properly formatted before calling this function.
	 */
	static em_network_node_t *get_network_tree(char *buff);
    
	/**!
	 * @brief Clones the network tree starting from the given node.
	 *
	 * This function creates a deep copy of the network tree structure
	 * starting from the specified node.
	 *
	 * @param[in] node The root node of the network tree to be cloned.
	 *
	 * @returns A pointer to the cloned network tree.
	 *
	 * @note Ensure that the input node is valid and properly initialized
	 * before calling this function.
	 */
	static em_network_node_t *clone_network_tree(em_network_node_t *node);
    
	/**!
	 * @brief Clones a network tree for display purposes.
	 *
	 * This function creates a copy of the original network node tree for display,
	 * potentially collapsing nodes based on the provided parameters.
	 *
	 * @param[in] orig_node The original network node to be cloned.
	 * @param[in] dis_node The display node where the cloned tree will be attached.
	 * @param[in] index The index at which the node is to be inserted.
	 * @param[in] collapse A boolean indicating whether to collapse nodes in the display tree.
	 * @param[out] node_ctr Optional pointer to an unsigned int to count nodes.
	 *
	 * @returns A pointer to the cloned network node tree.
	 *
	 * @note Ensure that the original node is valid before calling this function.
	 */
	static em_network_node_t *clone_network_tree_for_display(em_network_node_t *orig_node, em_network_node_t *dis_node, 
            unsigned int index, bool collapse, unsigned int *node_ctr = NULL);
    
	/**!
	 * @brief Retrieves a network node from the node counter.
	 *
	 * This function searches through the network node tree and returns the node
	 * that matches the specified display counter.
	 *
	 * @param[in] tree Pointer to the root of the network node tree.
	 * @param[in] node_display_ctr The display counter of the node to retrieve.
	 *
	 * @returns Pointer to the network node that matches the display counter.
	 * @retval NULL if no matching node is found.
	 *
	 * @note Ensure that the tree is properly initialized before calling this function.
	 */
	static em_network_node_t *get_node_from_node_ctr(em_network_node_t *tree, unsigned int node_display_ctr);
    
	/**!
	 * @brief Retrieves the network tree node from a JSON object.
	 *
	 * This function parses the given JSON object to extract the network tree node
	 * and populates the provided root node structure. It also updates the node
	 * counter with the number of nodes processed.
	 *
	 * @param[in] obj The JSON object containing the network tree node data.
	 * @param[out] root The root node structure to be populated with the parsed data.
	 * @param[out] node_ctr Pointer to an unsigned integer to store the node count.
	 *
	 * @returns int
	 * @retval 0 on success.
	 * @retval -1 on failure.
	 *
	 * @note Ensure that the JSON object is properly formatted and that the root
	 * node structure is initialized before calling this function.
	 */
	static int get_network_tree_node(cJSON *obj, em_network_node_t *root, unsigned int *node_ctr);
    
	/**!
	 * @brief Retrieves the child node at a specified index from the given network node.
	 *
	 * This function accesses the children of a network node and returns the child node
	 * located at the specified index.
	 *
	 * @param[in] node The parent network node from which the child node is to be retrieved.
	 * @param[in] idx The index of the child node to retrieve.
	 *
	 * @returns A pointer to the child network node at the specified index.
	 * @retval NULL if the index is out of bounds or the node has no children.
	 *
	 * @note Ensure that the index is within the valid range of child nodes.
	 */
	static em_network_node_t *get_child_node_at_index(em_network_node_t *node, unsigned int idx);
    
	/**!
	 * @brief Retrieves the display position of a network node.
	 *
	 * This function calculates and returns the display position of the specified
	 * network node within the network topology.
	 *
	 * @param[in] node Pointer to the network node whose display position is to be retrieved.
	 *
	 * @returns The display position of the network node as an unsigned integer.
	 */
	static unsigned int get_node_display_position(em_network_node_t *node);
    
	/**!
	 * @brief Retrieves the scalar value of a network node.
	 *
	 * This function accesses the scalar value associated with the specified
	 * network node and returns it as a character string.
	 *
	 * @param[in] node Pointer to the network node whose scalar value is to be retrieved.
	 *
	 * @returns A pointer to a character string representing the scalar value of the node.
	 *
	 * @note Ensure that the node is valid and properly initialized before calling this function.
	 */
	static char *get_node_scalar_value(em_network_node_t *node);
    
	/**!
	 * @brief Retrieves the value from the node array based on the specified data type.
	 *
	 * This function accesses the node array and returns the corresponding value
	 * based on the provided data type.
	 *
	 * @param[in] node Pointer to the network node from which the value is to be retrieved.
	 * @param[in] type Pointer to the data type specifying which value to retrieve from the node array.
	 *
	 * @returns Pointer to a character array containing the node value.
	 *
	 * @note Ensure that the node and type pointers are valid before calling this function.
	 */
	static char *get_node_array_value(em_network_node_t *node, em_network_node_data_type_t *type);
	
	/**!
	 * @brief Sets the scalar value for a network node.
	 *
	 * This function assigns a scalar value to the specified network node using the provided format.
	 *
	 * @param[in] node Pointer to the network node where the scalar value will be set.
	 * @param[in] fmt Format string used to determine the scalar value.
	 *
	 * @note Ensure that the node and fmt are valid and properly initialized before calling this function.
	 */
	static void set_node_scalar_value(em_network_node_t *node, char *fmt);
	
	/**!
	 * @brief Sets the value of a node array using the specified format.
	 *
	 * This function updates the node array with a value formatted according to the provided format string.
	 *
	 * @param[in] node Pointer to the network node structure.
	 * @param[in] fmt Format string used to set the node array value.
	 *
	 * @note Ensure that the format string is valid and the node pointer is not null before calling this function.
	 */
	static void set_node_array_value(em_network_node_t *node, char *fmt);
    
	/**!
	 * @brief Retrieves the type of the network node.
	 *
	 * This function returns the specific type of the network node provided as input.
	 *
	 * @param[in] node Pointer to the network node whose type is to be retrieved.
	 *
	 * @returns The type of the network node as an em_network_node_data_type_t.
	 */
	static em_network_node_data_type_t get_node_type(em_network_node_t *node);
    
	/**!
	 * @brief Frees the memory allocated for the node value.
	 *
	 * This function is responsible for releasing the memory that was allocated
	 * for storing the node value, ensuring there are no memory leaks.
	 *
	 * @param[in] str Pointer to the character array representing the node value.
	 *
	 * @note Ensure that the pointer passed to this function was allocated
	 * dynamically and is not NULL.
	 */
	static void free_node_value(char *str);
    
	/**!
	 * @brief Frees the memory allocated for the network tree.
	 *
	 * This function deallocates the memory used by the network tree pointed to by `tree`.
	 *
	 * @param[in] tree Pointer to the network tree to be freed.
	 *
	 * @note Ensure that the tree is not used after this function is called.
	 */
	static void free_network_tree(em_network_node_t *tree);
    
	/**!
	 * @brief Frees the memory allocated for a network tree node.
	 *
	 * This function is responsible for deallocating the memory associated with a given
	 * network tree node, ensuring that all resources are properly released.
	 *
	 * @param[in] node A pointer to the network node to be freed.
	 *
	 * @note Ensure that the node is not used after this function is called.
	 */
	static void free_network_tree_node(em_network_node_t *node);
    
	/**!
	 * @brief Converts a network tree structure to a JSON representation.
	 *
	 * This function takes the root of a network tree and converts it into a JSON format.
	 *
	 * @param[in] root Pointer to the root node of the network tree.
	 *
	 * @returns Pointer to the JSON representation of the network tree.
	 *
	 * @note Ensure that the root node is properly initialized before calling this function.
	 */
	static void *network_tree_to_json(em_network_node_t *root);
    
	/**!
	 * @brief Converts a network node to a JSON object.
	 *
	 * This function takes a network node and its parent and converts it into a JSON object representation.
	 *
	 * @param[in] node The network node to be converted.
	 * @param[in] parent The parent JSON object to which the node will be added.
	 *
	 * @returns A cJSON object representing the network node.
	 * @retval NULL if the conversion fails.
	 *
	 * @note Ensure that the node and parent are valid and properly initialized before calling this function.
	 */
	static cJSON *network_tree_node_to_json(em_network_node_t *node, cJSON *parent);
    
	/**!
	 * @brief Retrieves the network tree as a string.
	 *
	 * This function takes a network node tree and converts it into a string representation.
	 *
	 * @param[in] tree Pointer to the network node tree to be converted.
	 *
	 * @returns A pointer to a character string representing the network tree.
	 * @retval NULL if the tree is empty or an error occurs during conversion.
	 *
	 * @note The returned string should be freed by the caller to avoid memory leaks.
	 */
	static char *get_network_tree_string(em_network_node_t *tree);
	
	/**!
	 * @brief Frees the memory allocated for the network tree string.
	 *
	 * This function is responsible for deallocating the memory that was
	 * previously allocated for storing the network tree string.
	 *
	 * @param[in] str Pointer to the network tree string to be freed.
	 *
	 * @note Ensure that the pointer passed to this function was allocated
	 *       dynamically and is not NULL to avoid undefined behavior.
	 */
	static void free_network_tree_string(char *str) { free(str); }
    
	/**!
	 * @brief Retrieves the network tree node string.
	 *
	 * This function populates the provided string with the network tree node
	 * information based on the given node and identifier.
	 *
	 * @param[out] str The string to be populated with the network node information.
	 * @param[in] node Pointer to the network node structure containing the node data.
	 * @param[in] pident Pointer to an unsigned integer representing the node identifier.
	 *
	 * @note Ensure that the `str` buffer is large enough to hold the resulting string.
	 */
	static void get_network_tree_node_string(char *str, em_network_node_t *node, unsigned int *pident);

	/**!
     * @brief Retrieves the network tree node string.
     *
     * This function populates the provided string with the network tree node
     * information based on the given node and identifier.
     *
     * @param[out] str The string to be populated with the network node information.
     * @param[in] node Pointer to the network node structure containing the node data.
     * @param[in] pident Pointer to an unsigned integer representing the node identifier.
     *
     * @note Ensure that the `str` buffer is large enough to hold the resulting string.
     */
    static em_network_node_t *get_network_tree_by_key(em_network_node_t *node, em_long_string_t key);

    
	/**!
	 * @brief Default constructor for the em_net_node_t class.
	 *
	 * This constructor initializes a new instance of the em_net_node_t class.
	 *
	 * @note This constructor does not take any parameters and does not return any values.
	 */
	em_net_node_t();
    
	/**!
	 * @brief Destructor for the em_net_node_t class.
	 *
	 * This function cleans up any resources used by the em_net_node_t instance.
	 *
	 * @note Ensure that all network operations are completed before invoking this destructor.
	 */
	~em_net_node_t();
};

#endif

