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

#ifndef EM_CMD_EXEC_H
#define EM_CMD_EXEC_H

#include "em_base.h"
#include "em_cmd.h"
#include "openssl/ssl.h"
#include "openssl/err.h"

class em_cmd_exec_t {

    pthread_cond_t  m_cond;
    pthread_mutex_t m_lock;
	SSL_CTX *m_ssl_ctx;	

public:
    em_cmd_t m_cmd;
    SSL *m_ssl;

public:
    /**!
     * @brief Retrieves the edited network node.
     *
     * This function fetches the details of the edited network node based on the provided header.
     *
     * @param[in] header The header information used to identify the node.
     * @param[out] node Pointer to the network node structure where the edited node details will be stored.
     * @param[out] buff Buffer to store additional information or data related to the node.
     *
     * @returns int Status code indicating success or failure of the operation.
     * @retval 0 on success.
     * @retval -1 on failure.
     *
     * @note Ensure that the node and buff are properly initialized before calling this function.
     */
    virtual struct sockaddr_in *get_ep_addr() {}

    //char *get_result() { return m_cmd.get_result(); }
    
	/**!
	 * @brief Validates the command.
	 *
	 * This function calls the validate method on the command object to check its validity.
	 *
	 * @returns True if the command is valid, false otherwise.
	 */
	bool validate() { return m_cmd.validate(); }
    
	/**!
	 * @brief Retrieves the current event from the command.
	 *
	 * This function returns a pointer to the current event associated with the command.
	 *
	 * @returns A pointer to the current event.
	 * @retval nullptr If no event is associated with the command.
	 *
	 * @note Ensure that the returned event pointer is valid before use.
	 */
	SSL_CTX *get_ssl_ctx() { return m_ssl_ctx; }
    
	/**!
	 * @brief Retrieves the current event from the command.
	 *
	 * This function returns a pointer to the current event associated with the command.
	 *
	 * @returns A pointer to the current event.
	 * @retval nullptr If no event is associated with the command.
	 *
	 * @note Ensure that the returned event pointer is valid before use.
	 */
	em_event_t *get_event() { return m_cmd.get_event(); }
    
	/**!
	 * @brief Retrieves the length of the event.
	 *
	 * This function returns the length of the event as an unsigned integer.
	 *
	 * @returns The length of the event.
	 */
	unsigned int get_event_length() { return m_cmd.get_event_length(); }
    
	/**!
	 * @brief Retrieves the length of the event data.
	 *
	 * This function returns the length of the event data associated with the command.
	 *
	 * @returns The length of the event data as an unsigned integer.
	 */
	unsigned int get_event_data_length() { return m_cmd.get_event_data_length(); }
	
	/**!
	 * @brief Sets the event data length.
	 *
	 * This function sets the length of the event data by calling the
	 * corresponding method on the command object.
	 *
	 * @param[in] len The length of the event data to be set.
	 */
	void set_event_data_length(unsigned int len) { m_cmd.set_event_data_length(len); }
    
	/**!
	 * @brief Retrieves the command object.
	 *
	 * This function returns a pointer to the command object stored in the
	 * private member variable `m_cmd`.
	 *
	 * @returns A pointer to the `em_cmd_t` command object.
	 */
	em_cmd_t *get_cmd() { return &m_cmd; }
    
	/**!
	 * @brief Retrieves the command parameters.
	 *
	 * This function returns a pointer to the command parameters
	 * associated with the current command execution context.
	 *
	 * @returns A pointer to the command parameters.
	 * @retval em_cmd_params_t* Pointer to the command parameters.
	 *
	 * @note Ensure that the returned pointer is not null before
	 * accessing the parameters.
	 */
	em_cmd_params_t *get_param() { return m_cmd.get_param(); }
    
	/**!
	 * @brief Retrieves the command type.
	 *
	 * This function returns the type of the command encapsulated in the object.
	 *
	 * @returns The type of the command as an em_cmd_type_t.
	 */
	em_cmd_type_t get_type() { return m_cmd.m_type; }
    
	/**!
	 * @brief Retrieves the service type.
	 *
	 * This function returns the service type associated with the command.
	 *
	 * @returns The service type of the command.
	 */
	em_service_type_t get_svc() { return m_cmd.get_svc(); }
    
	/**!
	 * @brief gets socket from service type
	 *
	 * This function returns the socket for service type.
	 *
	 * @returns socket
	 */
	SSL *get_ep_for_dst_svc(SSL_CTX *ctx, em_service_type_t svc);
    
	/**!
	 * @brief gets listener socket from service type
	 *
	 * This function returns the socket for service type.
	 *
	 * @returns socket
	 */
	int get_listener_socket(em_service_type_t svc);
    
	/**!
	 * @brief closes the socket for the service type
	 *
	 * This function closes the socket.
	 *
	 * @returns void
	 */
	void close_listener_socket(int sock, em_service_type_t svc);
    
	/**!
	 * @brief Copies a bus event to the command module.
	 *
	 * This function takes a bus event and copies it to the command module for further processing.
	 *
	 * @param[in] evt Pointer to the bus event to be copied.
	 *
	 * @note Ensure that the event pointer is valid before calling this function.
	 */
	void copy_bus_event(em_bus_event_t *evt) { m_cmd.copy_bus_event(evt); }

    
	/**!
	 * @brief Initializes the command execution environment.
	 *
	 * This function sets up necessary resources and configurations
	 * required for command execution.
	 *
	 * @note This function should be called before any command execution.
	 */
	int init();
    
	/**!
	 * @brief Destroys the command execution environment.
	 *
	 * This function sets up necessary resources and configurations
	 * required for command execution.
	 *
	 * @note This function should be called before any command execution.
	 */
	void deinit();
    
	/**!
	 * @brief Sends a command to a specified service.
	 *
	 * This function sends a command to the specified service type with the given input data.
	 * Optionally, it can also receive output data.
	 *
	 * @param[in] to_svc The service type to which the command is sent.
	 * @param[in] in Pointer to the input data buffer.
	 * @param[in] in_len Length of the input data.
	 * @param[out] out Optional pointer to the output data buffer.
	 * @param[in] out_len Length of the output data buffer.
	 *
	 * @returns int Status of the command execution.
	 * @retval 0 on success.
	 * @retval Non-zero error code on failure.
	 *
	 * @note Ensure that the input and output buffers are properly allocated before calling this function.
	 */
	int send_cmd(em_service_type_t to_svc, unsigned char *in, unsigned int in_len, char *out = NULL, unsigned int out_len = 0);
    
	/**!
	 * @brief Executes a command of a specified type to a given service.
	 *
	 * This function sends a command of the specified type to the designated service
	 * and processes the input data accordingly.
	 *
	 * @param[in] type The type of command to execute.
	 * @param[in] to_svc The service to which the command is sent.
	 * @param[in] in Pointer to the input data buffer.
	 * @param[in] in_len Length of the input data buffer.
	 *
	 * @returns int Status code indicating success or failure of the command execution.
	 * @retval 0 on success.
	 * @retval Non-zero error code on failure.
	 *
	 * @note Ensure that the input data buffer is valid and the length is correctly specified.
	 */
	int execute(em_cmd_type_t type, em_service_type_t to_svc, unsigned char *in, unsigned int in_len);
    
	/**!
	 * @brief Retrieves the socket path from the destination service.
	 *
	 * This function constructs the socket path based on the destination service type provided.
	 *
	 * @param[in] to_svc The destination service type for which the socket path is required.
	 * @param[out] sock_path The buffer where the constructed socket path will be stored.
	 *
	 * @returns A pointer to the socket path string.
	 * @retval NULL if the path could not be constructed.
	 *
	 * @note Ensure that the buffer provided for sock_path is large enough to hold the resulting path.
	 */
	static unsigned short get_port_from_dst_service(em_service_type_t to_svc);
	
	/**!
	 * @brief Retrieves the socket path from the destination service.
	 *
	 * This function constructs the socket path based on the destination service type provided.
	 *
	 * @param[in] to_svc The destination service type for which the socket path is required.
	 * @param[out] sock_path The buffer where the constructed socket path will be stored.
	 *
	 * @returns A pointer to the socket path string.
	 * @retval NULL if the path could not be constructed.
	 *
	 * @note Ensure that the buffer provided for sock_path is large enough to hold the resulting path.
	 */
	static char *get_path_from_dst_service(em_service_type_t to_svc, em_long_string_t sock_path);
	
	/**!
	 * @brief Loads parameters from a file into a buffer.
	 *
	 * This function reads the contents of the specified file and loads it into the provided buffer.
	 *
	 * @param[in] filename The name of the file to be loaded.
	 * @param[out] buff The buffer where the file contents will be stored.
	 *
	 * @returns int
	 * @retval 0 on success
	 * @retval -1 on failure
	 *
	 * @note Ensure that the buffer is large enough to hold the file contents.
	 */
	static int     load_params_file(const char *filename, char *buff);

    
	/**!
	 * @brief Executes a command and stores the result.
	 *
	 * This function is a pure virtual function that must be implemented by derived classes.
	 *
	 * @param[out] result A pointer to a character array where the result of the command execution will be stored.
	 *
	 * @returns An integer indicating the success or failure of the command execution.
	 * @retval 0 on success.
	 * @retval Non-zero error code on failure.
	 *
	 * @note The caller must ensure that the `result` buffer is large enough to hold the command output.
	 */
	virtual int execute(char *result) = 0;
    
	/**!
	 * @brief Releases the wait state.
	 *
	 * This function is used to release any wait state that might be
	 * holding up the execution flow.
	 *
	 * @note Ensure that the system is in a state where releasing the wait
	 * is safe and will not disrupt ongoing processes.
	 */
	void release_wait();
    
	/**!
	 * @brief Waits for the specified amount of time.
	 *
	 * This function causes the calling thread to sleep until the time specified in
	 * the `time_to_wait` parameter has elapsed.
	 *
	 * @param[in] time_to_wait A pointer to a `timespec` structure that specifies
	 * the amount of time to wait. The `timespec` structure should be properly
	 * initialized with the desired wait time.
	 *
	 * @note The function will block the calling thread until the specified time
	 * has passed.
	 */
	void wait(struct timespec *time_to_wait);

public:
    
	/**!
	 * @brief Default constructor for the em_cmd_exec_t class.
	 *
	 * This constructor initializes an instance of the em_cmd_exec_t class.
	 *
	 * @note This constructor does not take any parameters and does not return any values.
	 */
	em_cmd_exec_t();
    
	/**!
	 * @brief Destructor for the em_cmd_exec_t class.
	 *
	 * This function cleans up any resources used by the em_cmd_exec_t instance.
	 *
	 * @note This is a virtual destructor, allowing for proper cleanup of derived class objects.
	 */
	virtual ~em_cmd_exec_t();
};

#endif
