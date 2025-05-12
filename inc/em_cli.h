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

#ifndef EM_CLI_H
#define EM_CLI_H

#include "em_base.h"
#include "em_cmd_exec.h"

class em_cli_t {
    
	/**!
	 * @brief Retrieves the command based on the input parameters.
	 *
	 * This function processes the input string and its length to determine the appropriate command.
	 * Optionally, a network node can be specified to refine the command retrieval.
	 *
	 * @param[in] in The input string to be processed.
	 * @param[in] in_len The length of the input string.
	 * @param[in] node Optional parameter specifying the network node.
	 *
	 * @returns A reference to the command object determined by the input.
	 *
	 * @note Ensure that the input string is properly null-terminated and the length is accurate.
	 */
	em_cmd_t& get_command(char *in, size_t in_len, em_network_node_t *node = NULL);
    em_long_string_t	m_lib_dbg_file_name;

public:

	em_cli_params_t	m_params;

    
	/**!
	 * @brief Executes a command on a network node.
	 *
	 * This function takes an input command and executes it on the specified network node.
	 *
	 * @param[in] in The input command to be executed.
	 * @param[in] in_len The length of the input command.
	 * @param[in,out] node The network node on which the command is executed.
	 *
	 * @returns A pointer to the network node after execution.
	 *
	 * @note Ensure that the input command is properly formatted and the node is initialized before calling this function.
	 */
	em_network_node_t *exec(char *in, size_t in_len, em_network_node_t *node);
    
	/**!
	 * @brief Initializes the EM CLI with the specified parameters.
	 *
	 * This function sets up the necessary configurations and prepares the
	 * environment for the EM CLI to operate.
	 *
	 * @param[in] params Pointer to the structure containing initialization parameters.
	 *
	 * @returns int
	 * @retval 0 on success
	 * @retval non-zero error code on failure
	 *
	 * @note Ensure that the parameters are correctly set before calling this function.
	 */
	int init(em_cli_params_t *params);
	
	/**!
	 * @brief Retrieves the first command string.
	 *
	 * This function returns a constant character pointer to the first command string.
	 *
	 * @returns A constant character pointer to the first command string.
	 *
	 * @note Ensure that the returned string is not modified as it is a constant.
	 */
	const char *get_first_cmd_str();
	
	/**!
	 * @brief Retrieves the next command string based on the input command.
	 *
	 * This function takes a command string as input and returns the next command string.
	 *
	 * @param[in] cmd The input command string for which the next command is to be retrieved.
	 *
	 * @returns A pointer to the next command string.
	 * @retval NULL if there is no next command or an error occurs.
	 *
	 * @note Ensure that the input command string is valid and properly null-terminated.
	 */
	const char *get_next_cmd_str(const char *cmd);
	
	/**!
	 * @brief Retrieves the reset tree for a given platform.
	 *
	 * This function returns a pointer to the reset tree structure associated with the specified platform.
	 *
	 * @param[in] platform A character pointer representing the platform for which the reset tree is requested.
	 *
	 * @returns A pointer to an em_network_node_t structure representing the reset tree.
	 * @retval NULL if the platform is not recognized or if an error occurs.
	 *
	 * @note Ensure that the platform string is valid and corresponds to a known platform.
	 */
	em_network_node_t *get_reset_tree(char *platform);
	
    
	/**!
	 * @brief Initializes the library for debugging purposes.
	 *
	 * This function sets up the necessary environment to enable debugging
	 * by specifying a file where debug information will be logged.
	 *
	 * @param[in] file_name The name of the file where debug logs will be written.
	 *
	 * @note Ensure that the file path is accessible and writable by the application.
	 */
	void init_lib_dbg(char *file_name);
    
	/**!
	 * @brief Dumps the library debug information.
	 *
	 * This function takes a string and processes it to dump debug information
	 * related to the library.
	 *
	 * @param[in] str A pointer to a character string containing the debug information.
	 *
	 * @note Ensure that the string is properly formatted for the debug dump.
	 */
	void dump_lib_dbg(char *str);

    
	/**!
	 * @brief Constructor for the em_cli_t class.
	 *
	 * This constructor initializes an instance of the em_cli_t class.
	 *
	 * @note This is a default constructor and does not take any parameters.
	 */
	em_cli_t();
    
	/**!
	 * @brief Destructor for the em_cli_t class.
	 *
	 * This destructor is responsible for cleaning up resources used by the em_cli_t instance.
	 *
	 * @note Ensure that all resources are properly released before the object is destroyed.
	 */
	~em_cli_t();
};


	/**!
	 * @brief Retrieves the CLI instance.
	 *
	 * This function returns a pointer to the CLI instance used for command line interactions.
	 *
	 * @returns A pointer to the `em_cli_t` instance.
	 * @retval nullptr if the CLI instance is not initialized or an error occurs.
	 *
	 * @note Ensure the CLI instance is initialized before calling this function.
	 */
	em_cli_t *get_cli();

#endif

