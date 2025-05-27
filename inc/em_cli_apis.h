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

#ifndef EM_CLI_APIS_H
#define EM_CLI_APIS_H

#ifdef __cplusplus
extern "C" {
#endif

#include "em_base.h"
	


	/**!
	 * @brief Executes a command on a network node.
	 *
	 * This function sends a command to a specified network node and returns the result.
	 *
	 * @param[in] in The command to be executed.
	 * @param[in] in_len The length of the command.
	 * @param[in] node The network node on which the command is to be executed.
	 *
	 * @returns A pointer to the network node structure containing the result of the command execution.
	 * @retval NULL if the execution fails or the node is not found.
	 *
	 * @note Ensure that the node is properly initialized before calling this function.
	 */
	em_network_node_t *exec(char *in, size_t in_len, em_network_node_t *node);

	/**!
	 * @brief Initializes the EM CLI with the given parameters.
	 *
	 * This function sets up the necessary configurations and prepares the
	 * environment for the EM CLI operations using the provided parameters.
	 *
	 * @param[in] params Pointer to the structure containing initialization parameters.
	 *
	 * @returns int
	 * @retval 0 on success
	 * @retval -1 on failure
	 *
	 * @note Ensure that the params structure is properly populated before calling this function.
	 */
	int set_remote_addr(unsigned int ip, unsigned int port);

	bool is_remote_addr_valid();


	/**!
	 * @brief Retrieves the first command string.
	 *
	 * This function returns a constant character pointer to the first command string.
	 *
	 * @returns const char* Pointer to the first command string.
	 *
	 * @note Ensure that the returned string is not modified.
	 */
	const char *get_first_cmd_str();

	/**!
	 * @brief Retrieves the next command string based on the input command.
	 *
	 * This function takes a command string as input and returns the next command string in sequence.
	 *
	 * @param[in] cmd The input command string for which the next command is to be retrieved.
	 *
	 * @returns A pointer to the next command string.
	 *
	 * @note Ensure that the input command string is valid and null-terminated.
	 */
	const char *get_next_cmd_str(const char *cmd);

	/**!
	 * @brief Retrieves the reset tree for a given platform.
	 *
	 * This function returns a pointer to the reset tree structure associated with the specified platform.
	 *
	 * @param[in] platform A character pointer representing the platform for which the reset tree is requested.
	 *
	 * @returns A pointer to the em_network_node_t structure representing the reset tree.
	 * @retval NULL if the platform is not recognized or if an error occurs.
	 *
	 * @note Ensure that the platform string is valid and corresponds to a known platform.
	 */
	em_network_node_t *get_reset_tree(char *platform);

	/**!
	 * @brief Retrieves the network tree from a specified file.
	 *
	 * This function reads the network configuration from the given file and constructs
	 * a network tree based on the data.
	 *
	 * @param[in] file_name The name of the file containing the network configuration.
	 *
	 * @returns A pointer to the network tree structure.
	 * @retval NULL if the file cannot be read or the network tree cannot be constructed.
	 *
	 * @note Ensure the file exists and is accessible before calling this function.
	 */
	em_network_node_t *get_network_tree_by_file(const char *file_name);

	/**!
	 * @brief Retrieves the network tree structure.
	 *
	 * This function processes the provided buffer to extract and return the network tree.
	 *
	 * @param[in] buff A character buffer containing the network data.
	 *
	 * @returns A pointer to the network node structure.
	 *
	 * @note Ensure the buffer is properly formatted before calling this function.
	 */
	em_network_node_t *get_network_tree(char *buff);

	/**!
	 * @brief Retrieves the child node at a specified index from a given network node.
	 *
	 * This function accesses the child node located at the specified index within the
	 * children of the provided network node. It is useful for iterating over or
	 * accessing specific child nodes in a network structure.
	 *
	 * @param[in] node The parent network node from which the child node is to be retrieved.
	 * @param[in] idx The index of the child node to retrieve.
	 *
	 * @returns A pointer to the child node at the specified index.
	 * @retval NULL if the index is out of bounds or the node has no children.
	 *
	 * @note Ensure that the index is within the valid range of child nodes for the given
	 * node to avoid unexpected behavior.
	 */
	em_network_node_t *get_child_node_at_index(em_network_node_t *node, unsigned int idx);

	/**!
	 * @brief Retrieves the display position of a network node.
	 *
	 * This function calculates and returns the display position of the specified
	 * network node within the network topology.
	 *
	 * @param[in] node Pointer to the network node whose display position is to be retrieved.
	 *
	 * @returns The display position of the network node as an unsigned integer.
	 *
	 * @note Ensure that the node pointer is valid and points to a properly initialized
	 * network node structure before calling this function.
	 */
	unsigned int get_node_display_position(em_network_node_t *node);

	/**!
	 * @brief Retrieves the scalar value of a given network node.
	 *
	 * This function accesses the specified network node and returns its scalar value as a string.
	 *
	 * @param[in] node Pointer to the network node whose scalar value is to be retrieved.
	 *
	 * @returns A pointer to a character string representing the scalar value of the node.
	 * @retval NULL if the node is invalid or if the scalar value cannot be retrieved.
	 *
	 * @note Ensure that the node pointer is valid before calling this function to avoid undefined behavior.
	 */
	char *get_node_scalar_value(em_network_node_t *node);

	/**!
	 * @brief Retrieves the value of a node array based on the specified node and data type.
	 *
	 * This function accesses the node array and returns the corresponding value for the given node and data type.
	 *
	 * @param[in] node Pointer to the network node whose array value is to be retrieved.
	 * @param[in] type Pointer to the data type of the network node.
	 *
	 * @returns A pointer to a character array containing the node array value.
	 *
	 * @note Ensure that the node and type pointers are valid before calling this function.
	 */
	char *get_node_array_value(em_network_node_t *node, em_network_node_data_type_t *type);

	/**!
	 * @brief Sets the scalar value of a network node.
	 *
	 * This function assigns a scalar value to the specified network node using the provided format.
	 *
	 * @param[in] node Pointer to the network node whose scalar value is to be set.
	 * @param[in] fmt Format string used to set the scalar value.
	 *
	 * @note Ensure that the node and fmt are valid and properly initialized before calling this function.
	 */
	void set_node_scalar_value(em_network_node_t *node, char *fmt);

	/**!
	 * @brief Sets the value of a node array using a specified format.
	 *
	 * This function assigns a formatted value to a network node array.
	 *
	 * @param[in] node Pointer to the network node structure where the value will be set.
	 * @param[in] fmt Format string used to set the node's value.
	 *
	 * @note Ensure that the node and format string are properly initialized before calling this function.
	 */
	void set_node_array_value(em_network_node_t *node, char *fmt);

	/**!
	 * @brief Frees the memory allocated for a node value.
	 *
	 * This function is responsible for releasing the memory allocated for a node value
	 * represented by the input string pointer.
	 *
	 * @param[in] str Pointer to the string whose memory is to be freed.
	 *
	 * @note Ensure that the pointer passed to this function was dynamically allocated
	 * and is not NULL to avoid undefined behavior.
	 */
	void free_node_value(char *str);

	/**!
	 * @brief Retrieves the type of a network node.
	 *
	 * This function returns the type of the specified network node.
	 *
	 * @param[in] node Pointer to the network node whose type is to be retrieved.
	 *
	 * @returns The type of the network node.
	 *
	 * @note Ensure that the node pointer is valid before calling this function.
	 */
	em_network_node_data_type_t get_node_type(em_network_node_t *node);

	/**!
	 * @brief Sets the type of the network node.
	 *
	 * This function assigns a specific type to a given network node.
	 *
	 * @param[in] node Pointer to the network node whose type is to be set.
	 * @param[in] type Integer representing the type to be assigned to the node.
	 *
	 * @note Ensure that the node pointer is valid before calling this function.
	 */
	void set_node_type(em_network_node_t *node, int type);

	/**!
	 * @brief Frees the memory allocated for the network tree starting from the given node.
	 *
	 * This function traverses the network tree starting from the specified node and
	 * deallocates all associated resources.
	 *
	 * @param[in] node Pointer to the root node of the network tree to be freed.
	 *
	 * @note Ensure that the node passed is the root of a valid network tree.
	 */
	void free_network_tree(em_network_node_t *node);

	/**!
	 * @brief Converts a network tree structure to a JSON format.
	 *
	 * This function takes a network node and converts its structure into a JSON representation.
	 *
	 * @param[in] node Pointer to the network node to be converted.
	 *
	 * @returns A pointer to the JSON representation of the network tree.
	 *
	 * @note Ensure that the node is properly initialized before calling this function.
	 */
	void *network_tree_to_json(em_network_node_t *node);

	/**!
	 * @brief Clones a network tree starting from the given node.
	 *
	 * This function creates a deep copy of the network tree structure
	 * starting from the specified node.
	 *
	 * @param[in] node The root node of the network tree to be cloned.
	 *
	 * @returns A pointer to the root node of the cloned network tree.
	 *
	 * @note Ensure that the input node is valid and properly initialized
	 * before calling this function.
	 */
	em_network_node_t *clone_network_tree(em_network_node_t *node);

	/**!
	 * @brief Clones a network tree for display purposes.
	 *
	 * This function takes an original network node and clones it into a display node,
	 * optionally collapsing the tree based on the provided index.
	 *
	 * @param[in] orig_node The original network node to be cloned.
	 * @param[out] dis_node The display node where the cloned network tree will be stored.
	 * @param[in] index The index used to determine how the tree should be collapsed.
	 * @param[in] collapse A boolean indicating whether the tree should be collapsed.
	 *
	 * @returns A pointer to the cloned network node.
	 *
	 * @note Ensure that the display node is properly initialized before calling this function.
	 */
	em_network_node_t *clone_network_tree_for_display(em_network_node_t *orig_node, em_network_node_t *dis_node, unsigned int index, bool collapse);

	/**!
	 * @brief Retrieves the network tree as a string representation.
	 *
	 * This function takes a network node and returns a string that represents the network tree.
	 *
	 * @param[in] node Pointer to the network node from which the tree string is generated.
	 *
	 * @returns A pointer to a character string representing the network tree.
	 *
	 * @note The caller is responsible for freeing the returned string.
	 */
	char *get_network_tree_string(em_network_node_t *node);

	/**!
	 * @brief Retrieves a network node from the node counter.
	 *
	 * This function searches through the given tree to find and return the network node
	 * that corresponds to the specified node display counter.
	 *
	 * @param[in] tree The root of the network node tree to search through.
	 * @param[in] node_display_ctr The display counter of the node to retrieve.
	 *
	 * @returns A pointer to the network node that matches the given display counter.
	 * @retval NULL if no matching node is found.
	 *
	 * @note Ensure that the tree is not NULL before calling this function.
	 */
	em_network_node_t *get_node_from_node_ctr(em_network_node_t *tree, unsigned int node_display_ctr);

	/**!
	 * @brief Determines if a network node can be collapsed.
	 *
	 * This function checks the given network node and returns whether it can be collapsed based on certain criteria.
	 *
	 * @param[in] node Pointer to the network node to be checked.
	 *
	 * @returns An unsigned integer indicating the result.
	 * @retval 0 if the node cannot be collapsed.
	 * @retval 1 if the node can be collapsed.
	 *
	 * @note Ensure the node is valid and initialized before calling this function.
	 */
	unsigned int can_collapse_node(em_network_node_t *node);

	/**!
	 * @brief Expands the given network node if possible.
	 *
	 * This function attempts to expand the specified network node, allowing it to
	 * accommodate additional connections or data as required by the network's
	 * configuration.
	 *
	 * @param[in] node Pointer to the network node to be expanded.
	 *
	 * @returns unsigned int indicating the success or failure of the operation.
	 * @retval 0 if the node was successfully expanded.
	 * @retval 1 if the node could not be expanded due to constraints.
	 *
	 * @note Ensure that the node is properly initialized before calling this function.
	 */
	unsigned int can_expand_node(em_network_node_t *node);

	/**!
	 * @brief Frees the memory allocated for the network tree string.
	 *
	 * This function is responsible for deallocating the memory that was previously allocated for a network tree string.
	 *
	 * @param[in] str Pointer to the network tree string to be freed.
	 *
	 * @note Ensure that the pointer `str` is valid and was allocated using the corresponding allocation function.
	 */
	void free_network_tree_string(char *str);

	/**!
	 * @brief Initializes the library debugging with the specified file name.
	 *
	 * This function sets up the debugging environment by using the provided file name.
	 *
	 * @param[in] file_name The name of the file to be used for debugging purposes.
	 *
	 * @note Ensure that the file name is valid and accessible.
	 */
	void init_lib_dbg(char *file_name);

	/**!
	 * @brief Dumps library debug information.
	 *
	 * This function formats and outputs debug information for the library.
	 *
	 * @param[in] fmt Format string for the debug output.
	 *
	 * @note Ensure that the format string is correctly specified to avoid runtime errors.
	 */
	void dump_lib_dbg(char *fmt);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif // EM_CLI_APIS_H
