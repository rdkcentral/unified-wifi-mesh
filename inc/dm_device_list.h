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

#ifndef DM_DEVICE_LIST_H
#define DM_DEVICE_LIST_H

#include "em_base.h"
#include "dm_device.h"
#include "db_easy_mesh.h"

class dm_easy_mesh_t;

class dm_device_list_t : public dm_device_t, public db_easy_mesh_t {

public:
    
	/**!
	 * @brief Initializes the device list.
	 *
	 * This function sets up necessary resources and prepares the device list for use.
	 *
	 * @returns int
	 * @retval 0 on success
	 * @retval -1 on failure
	 *
	 * @note Ensure that this function is called before any other operations on the device list.
	 */
	int init();

    
    
	/**!
	 * @brief Retrieves the DM orchestration type for a given device.
	 *
	 * This function queries the database client to determine the orchestration type
	 * associated with the specified device.
	 *
	 * @param[in] db_client Reference to the database client used for querying.
	 * @param[in] dev The device for which the orchestration type is to be retrieved.
	 *
	 * @returns The orchestration type of the specified device.
	 * @retval dm_orch_type_t The type of orchestration for the device.
	 *
	 * @note Ensure that the database client is properly initialized before calling this function.
	 */
	dm_orch_type_t get_dm_orch_type(db_client_t& db_client, const dm_device_t& dev);
    
	/**!
	 * @brief Updates the device list based on the operation type.
	 *
	 * This function modifies the device list by either adding or removing a device
	 * depending on the specified operation type.
	 *
	 * @param[in] dev The device to be added or removed from the list.
	 * @param[in] op The operation type indicating whether to add or remove the device.
	 *
	 * @note Ensure that the device and operation type are valid before calling this function.
	 */
	void update_list(const dm_device_t& dev, dm_orch_type_t op);
    
	/**!
	 * @brief Deletes the device list.
	 *
	 * This function removes all devices from the list and frees associated resources.
	 *
	 * @note Ensure that the list is not being accessed by other threads when calling this function.
	 */
	void delete_list();

    
	/**!
	 * @brief Initializes the device table.
	 *
	 * This function sets up the necessary data structures for managing the device list.
	 *
	 * @note Ensure that this function is called before any operations on the device list.
	 */
	void init_table();
    
	/**!
	 * @brief Initializes the columns for the device list.
	 *
	 * This function sets up the necessary columns required for displaying the device list.
	 *
	 * @note Ensure that the device list is properly initialized before calling this function.
	 */
	void init_columns();
    
	/**!
	 * @brief Synchronize the database using the provided client and context.
	 *
	 * This function synchronizes the database by utilizing the given database client and context.
	 *
	 * @param[in] db_client Reference to the database client used for synchronization.
	 * @param[in] ctx Pointer to the context information required for synchronization.
	 *
	 * @returns int Status code indicating the success or failure of the synchronization.
	 * @retval 0 Synchronization was successful.
	 * @retval -1 Synchronization failed due to an error.
	 *
	 * @note Ensure that the database client is properly initialized before calling this function.
	 */
	int sync_db(db_client_t& db_client, void *ctx);
    
	/**!
	 * @brief Updates the database with the given operation and data.
	 *
	 * This function performs a database update using the specified operation type and data.
	 *
	 * @param[in] db_client Reference to the database client used for the update.
	 * @param[in] op The operation type to be performed on the database.
	 * @param[in] data Pointer to the data to be used in the update operation.
	 *
	 * @returns int Status code indicating the success or failure of the update operation.
	 * @retval 0 Indicates successful update.
	 * @retval -1 Indicates failure in the update operation.
	 *
	 * @note Ensure that the db_client is properly initialized before calling this function.
	 */
	int update_db(db_client_t& db_client, dm_orch_type_t op, void *data);
    
	/**!
	 * @brief Searches the database using the provided key.
	 *
	 * This function attempts to locate an entry in the database using the specified key.
	 *
	 * @param[in] db_client Reference to the database client used for the search operation.
	 * @param[in] ctx Context information for the search operation.
	 * @param[in] key Pointer to the key used for searching the database.
	 *
	 * @returns True if the search operation is successful, false otherwise.
	 *
	 * @note Ensure that the database client is properly initialized before calling this function.
	 */
	bool search_db(db_client_t& db_client, void *ctx, void *key);
	bool compare_db(db_client_t& db_client, const dm_device_t& sta);
    bool operator == (const db_easy_mesh_t& obj);
    
	/**!
	 * @brief Sets the configuration for a database client.
	 *
	 * This function configures the database client using the provided JSON object and associates it with a parent identifier.
	 *
	 * @param[in] db_client Reference to the database client to be configured.
	 * @param[in] obj Pointer to a cJSON object containing the configuration data.
	 * @param[in] parent_id Pointer to the parent identifier associated with the configuration.
	 *
	 * @returns int
	 * @retval 0 on success.
	 * @retval non-zero error code on failure.
	 *
	 * @note Ensure that the JSON object and parent identifier are valid before calling this function.
	 */
	int set_config(db_client_t& db_client, const cJSON *obj, void *parent_id);
    
	/**!
	 * @brief Sets the configuration for a device.
	 *
	 * This function configures the specified device using the provided database client.
	 *
	 * @param[in] db_client Reference to the database client used for configuration.
	 * @param[in] device Reference to the device to be configured.
	 * @param[in] parent_id Pointer to the parent ID, if applicable.
	 *
	 * @returns int Status code indicating success or failure.
	 * @retval 0 on success.
	 * @retval -1 on failure.
	 *
	 * @note Ensure that the database client is properly initialized before calling this function.
	 */
	int set_config(db_client_t& db_client, dm_device_t& device, void *parent_id);
    
	/**!
	 * @brief Retrieves the configuration details from a JSON object.
	 *
	 * This function extracts configuration information from the provided JSON object and associates it with a parent identifier. It can optionally provide a summary of the configuration.
	 *
	 * @param[in] obj The JSON object containing configuration data.
	 * @param[in] parent_id A pointer to the parent identifier to associate with the configuration.
	 * @param[in] summary A boolean flag indicating whether to retrieve a summary of the configuration. Defaults to false.
	 *
	 * @returns An integer status code indicating success or failure of the operation.
	 * @retval 0 on success.
	 * @retval Non-zero error code on failure.
	 *
	 * @note Ensure that the JSON object and parent identifier are valid before calling this function.
	 */
	int get_config(cJSON *obj, void *parent_id, bool summary = false);

    
	/**!
	 * @brief Retrieves the first device in the device list.
	 *
	 * This function returns a pointer to the first device in the list of devices managed by the system.
	 *
	 * @returns A pointer to the first device in the list.
	 * @retval nullptr If the device list is empty.
	 *
	 * @note This is a pure virtual function and must be implemented by the derived class.
	 */
	virtual dm_device_t *get_first_device() = 0;
    
	/**!
	 * @brief Retrieves the next device in the list.
	 *
	 * This function returns the next device in the sequence after the provided device.
	 *
	 * @param[in] dev A pointer to the current device from which the next device is to be retrieved.
	 *
	 * @returns A pointer to the next device in the list.
	 * @retval nullptr If there are no more devices in the list.
	 *
	 * @note This function must be overridden in derived classes.
	 */
	virtual dm_device_t *get_next_device(dm_device_t *dev) = 0;
    
	/**!
	 * @brief Retrieves a device based on the provided key.
	 *
	 * This function searches for a device using the specified key and returns a pointer to the device if found.
	 *
	 * @param[in] key A constant character pointer representing the key used to search for the device.
	 *
	 * @returns A pointer to the dm_device_t structure representing the device if found, otherwise nullptr.
	 *
	 * @note This is a pure virtual function and must be implemented by derived classes.
	 */
	virtual dm_device_t *get_device(const char *key) = 0;
    
	/**!
	 * @brief Removes a device from the list.
	 *
	 * This function removes a device identified by the given key from the device list.
	 *
	 * @param[in] key A constant character pointer representing the key of the device to be removed.
	 *
	 * @note This is a pure virtual function and must be implemented by the derived class.
	 */
	virtual void remove_device(const char *key) = 0;
    
	/**!
	 * @brief Puts a device into the device list.
	 *
	 * This function adds a device to the list using the specified key.
	 *
	 * @param[in] key The key associated with the device.
	 * @param[in] dev The device to be added to the list.
	 *
	 * @note This is a pure virtual function and must be implemented by derived classes.
	 */
	virtual void put_device(const char *key, const dm_device_t *dev) = 0;
};

#endif
