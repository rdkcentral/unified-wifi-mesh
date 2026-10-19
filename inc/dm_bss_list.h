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

#ifndef DM_BSS_LIST_H
#define DM_BSS_LIST_H

#include "em_base.h"
#include "dm_bss.h"
#include "db_easy_mesh.h"
#include "tr_181.h"

class dm_easy_mesh_t;

class dm_bss_list_t : public dm_bss_t, public db_easy_mesh_t, virtual public tr_181_t {

    // Dynamic MAC ACL, keyed by "<bss_key>@<sta_mac>" so a BSS can hold any number of STAs
	hash_map_t  *m_acl_sta_map;

    // BSS whose ACL changed since the last DB write; get_dm_orch_type() cannot detect it
    // because the stored and the incoming dm_bss_t are the same object.
	em_2xlong_string_t m_acl_dirty_key;

	/**!
	 * @brief Returns the ACL map, creating it on first use.
	 */
	hash_map_t *get_acl_map();

	void acl_clear();

	/**!
	 * @brief Flags a BSS as having pending ACL changes to persist.
	 */
	void acl_mark_dirty(const char *bss_key);

	/**!
	 * @brief Builds the ACL map key for a STA on a BSS.
	 */
	static void make_acl_key(const char *bss_key, const unsigned char *mac, char *out, unsigned int sz);

public:
	/** Releases ACL entries and map storage owned by this BSS list. */
	~dm_bss_list_t();

	/**!
	 * @brief Applies a Client Association Control Request to the dynamic ACL of a BSS.
	 *
	 * Blocked STAs end up on the deny list and unblocked STAs on the allow list.
	 *
	 * @param[in] bss_key Composite BSS key ("net_id@dev_mac@ruid@bssid@haul_type").
	 * @param[in] assoc_control ASSOC_CONTROL_BLOCK or ASSOC_CONTROL_UNBLOCK.
	 * @param[in] sta_count Number of entries in sta_list.
	 * @param[in] sta_list STA MAC addresses the request applies to.
	 * @returns 0 on success, -1 if the input is invalid or an ACL entry cannot be stored.
	 */
	int acl_update(const char *bss_key, unsigned char assoc_control,
			unsigned char sta_count, const mac_address_t *sta_list);

	/**!
	 * @brief Removes stations from a BSS allow-list.
	 * @param[in] bss_key Composite key identifying the BSS.
	 * @param[in] sta_count Number of entries in sta_list.
	 * @param[in] sta_list Station MAC addresses to remove.
	 * @returns 0 on success, -1 if the BSS key or station list is invalid.
	 */
	int acl_remove_stas(const char *bss_key, unsigned char sta_count,
			const mac_address_t *sta_list);

	/**!
	 * @brief Counts the ACL entries of a BSS on one of the two lists.
	 *
	 * @param[in] bss_key Composite BSS key.
	 * @param[in] blocked true for the deny list, false for the allow list.
	 *
	 * @returns Number of matching entries.
	 */
	unsigned int acl_num_macs(const char *bss_key, bool blocked);

	/**!
	 * @brief Copies a window of ACL entries of a BSS into a caller supplied array.
	 *
	 * Lets the caller send the ACL in chunks that fit the Client Association Control TLV.
	 *
	 * @param[in] bss_key Composite BSS key.
	 * @param[in] blocked true for the deny list, false for the allow list.
	 * @param[in] skip Number of matching entries to skip.
	 * @param[in] max Capacity of list.
	 * @param[out] list Array receiving the MAC addresses.
	 *
	 * @returns Number of entries written to list.
	 */
	unsigned int acl_get_macs(const char *bss_key, bool blocked, unsigned int skip,
			unsigned int max, mac_address_t *list);

	/**!
	 * @brief Serializes the ACL entries of a BSS into a comma separated MAC list for the database.
	 */
	void acl_to_string(const char *bss_key, bool blocked, char *str, unsigned int sz);

	/**!
	 * @brief Rebuilds the ACL entries of a BSS from a comma separated MAC list read from the database.
	 */
	void acl_from_string(const char *bss_key, bool blocked, const char *str);

	/**!
	 * @brief Drops every ACL entry belonging to a BSS.
	 */
	void acl_remove(const char *bss_key);

	/**!
	 * @brief Adds the ACL MAC lists of a BSS to its JSON representation.
	 */
	void encode_acl(dm_bss_t *pbss, cJSON *obj);

public:
    
	/**!
	 * @brief Initializes the system or component.
	 *
	 * This function is responsible for setting up necessary configurations
	 * and preparing the system for operation.
	 *
	 * @returns int
	 * @retval 0 on success
	 * @retval -1 on failure
	 *
	 * @note Ensure that all prerequisites are met before calling this function.
	 */
	int init();


    
	/**!
	 * @brief Retrieves the DM orchestration type for a given BSS.
	 *
	 * This function determines the DM orchestration type based on the provided
	 * database client and BSS information.
	 *
	 * @param[in] db_client Reference to the database client used for querying.
	 * @param[in] bss Constant reference to the BSS structure containing necessary information.
	 *
	 * @returns The DM orchestration type associated with the specified BSS.
	 * @retval dm_orch_type_t The type of orchestration determined.
	 *
	 * @note Ensure that the database client is properly initialized before calling this function.
	 */
	dm_orch_type_t get_dm_orch_type(db_client_t& db_client, const dm_bss_t& bss);
    
	/**!
	 * @brief Updates the list with the given BSS information and operation type.
	 *
	 * This function modifies the current list based on the provided BSS structure
	 * and operation type. It ensures that the list is updated according to the
	 * specified operation.
	 *
	 * @param[in] bss The BSS information to be used for updating the list.
	 * @param[in] op The operation type that dictates how the list should be updated.
	 *
	 * @note Ensure that the BSS information and operation type are valid before
	 * calling this function to avoid unexpected behavior.
	 */
	void update_list(const dm_bss_t& bss, dm_orch_type_t op);	
    
	/**!
	 * @brief Deletes the list.
	 *
	 * This function is responsible for deleting the list and freeing any associated resources.
	 *
	 * @note Ensure that the list is not accessed after calling this function.
	 */
	void delete_list();

    
	/**!
	 * @brief Initializes the table.
	 *
	 * This function sets up the necessary data structures and state for the table to be used.
	 *
	 * @note Ensure that the table is not already initialized before calling this function.
	 */
	void init_table();
    
	/**!
	 * @brief Initializes the columns for the BSS list.
	 *
	 * This function sets up the necessary columns required for displaying or processing the BSS list.
	 *
	 * @note Ensure that the BSS list is properly initialized before calling this function.
	 */
	void init_columns();
    
	/**!
	 * @brief Synchronizes the database using the provided client and context.
	 *
	 * This function is responsible for ensuring that the database is synchronized
	 * with the current state as defined by the context.
	 *
	 * @param[in] db_client Reference to the database client used for synchronization.
	 * @param[in] ctx Pointer to the context used for synchronization.
	 *
	 * @returns int Status code indicating success or failure of the operation.
	 * @retval 0 on success.
	 * @retval non-zero on failure.
	 *
	 * @note Ensure that the database client is properly initialized before calling this function.
	 * @note Invalid BSS rows are deleted from the table and ACL columns are loaded into the dynamic map.
	 */
	int sync_db(db_client_t& db_client, void *ctx);
    
	/**!
	 * @brief Updates the database with the given operation and data.
	 *
	 * This function performs the specified operation on the database using the provided data.
	 *
	 * @param[in] db_client Reference to the database client.
	 * @param[in] op The operation type to be performed on the database.
	 * @param[in] data Pointer to the data to be used in the operation.
	 *
	 * @returns int Status code indicating success or failure of the operation.
	 * @retval 0 Operation was successful.
	 * @retval -1 Operation failed due to invalid parameters.
	 *
	 * @note Ensure that the database client is properly initialized before calling this function.
	 */
	int update_db(db_client_t& db_client, dm_orch_type_t op, void *data);
    
	/**!
	 * @brief Searches the database using the provided key.
	 *
	 * This function attempts to find an entry in the database using the specified key.
	 *
	 * @param[in] db_client Reference to the database client used for the search operation.
	 * @param[in] ctx Contextual information required for the search.
	 * @param[in] key Pointer to the key used for searching the database.
	 *
	 * @returns True if the entry is found, false otherwise.
	 *
	 * @note Consumes the complete result set so the database result context is released.
	 * @note Ensure that the database client is properly initialized before calling this function.
	 */
	bool search_db(db_client_t& db_client, void *ctx, void *key);
    bool operator == (const db_easy_mesh_t& obj);
    
	/**!
	 * @brief Sets the configuration using the provided JSON object.
	 *
	 * This function updates the configuration settings in the database client
	 * using the JSON object provided. The parent ID is used to specify the
	 * hierarchical context within the configuration.
	 *
	 * @param[in] db_client Reference to the database client where the configuration
	 * will be set.
	 * @param[in] obj Pointer to a cJSON object containing the configuration data.
	 * @param[in] parent_id Pointer to the parent ID used for hierarchical context.
	 *
	 * @returns int Status code indicating success or failure of the operation.
	 * @retval 0 Success
	 * @retval -1 Failure
	 *
	 * @note This overload is retained for interface compatibility; BSSList updates
	 * require device and radio MAC context and are rejected without it.
	 */
	int set_config(db_client_t& db_client, const cJSON *obj, void *parent_id);
	/**!
	 * @brief Applies one radio's BSS snapshot and reconciles its persisted rows.
	 *
	 * Managed STA VAPs are excluded. Invalid AP entries are ignored and prevent stale-row
	 * cleanup; stale rows are removed only after a complete non-empty AP snapshot persists.
	 *
	 * @param[in] db_client Database client used to persist the snapshot.
	 * @param[in] obj Array of BSS objects advertised by the radio.
	 * @param[in] dev_mac Owning agent device MAC.
	 * @param[in] radio_mac Radio MAC that owns the BSS objects.
	 * @returns 0 on success, -1 if an update or cleanup failed.
	 */
	int set_config(db_client_t& db_client, const cJSON *obj, mac_address_t *dev_mac,
			mac_address_t *radio_mac);
    
	/**!
	 * @brief Sets the configuration for a BSS.
	 *
	 * This function configures the BSS using the provided database client and parent ID.
	 *
	 * @param[in] db_client Reference to the database client used for configuration.
	 * @param[in] bss Reference to the BSS structure to be configured.
	 * @param[in] parent_id Pointer to the parent ID used in the configuration.
	 *
	 * @returns int
	 * @retval 0 on success
	 * @retval -1 on failure
	 *
	 * @note Ensure that the db_client and bss are properly initialized before calling this function.
	 */
	int set_config(db_client_t& db_client, dm_bss_t& bss, void *parent_id);
    
	/**!
	 * @brief Retrieves the configuration details from a JSON object.
	 *
	 * This function extracts configuration settings from the provided JSON object and associates them with a parent identifier. It can optionally provide a summary of the configuration.
	 *
	 * @param[in] obj The JSON object containing configuration data.
	 * @param[in] parent_id A pointer to the parent identifier to associate with the configuration.
	 * @param[in] summary A boolean flag indicating whether to return a summary of the configuration. Defaults to false.
	 *
	 * @returns An integer status code indicating success or failure of the operation.
	 * @retval 0 on success.
	 * @retval Non-zero error code on failure.
	 *
	 * @note Ensure that the JSON object and parent identifier are valid before calling this function.
	 */
	int get_config(cJSON *obj, void *parent_id, bool summary = false);

    
	/**!
	 * @brief Retrieves the first BSS (Base Station Subsystem) entry.
	 *
	 * This function returns a pointer to the first BSS entry available.
	 *
	 * @returns A pointer to the first dm_bss_t object.
	 * @retval nullptr if no BSS entries are available.
	 *
	 * @note This is a pure virtual function and must be implemented by derived classes.
	 */
	virtual dm_bss_t *get_first_bss() = 0;
    
	/**!
	 * @brief Retrieves the next BSS (Basic Service Set) in the list.
	 *
	 * This function is used to iterate over the BSS list, returning the next BSS
	 * following the provided one.
	 *
	 * @param[in] bss Pointer to the current BSS from which the next BSS is to be retrieved.
	 *
	 * @returns Pointer to the next BSS in the list.
	 * @retval nullptr if there are no more BSSs in the list.
	 *
	 * @note This is a pure virtual function and must be implemented by derived classes.
	 */
	virtual dm_bss_t *get_next_bss(dm_bss_t *bss) = 0;
    
	/**!
	 * @brief Retrieves the BSS entry associated with the specified key.
	 *
	 * This function searches for the BSS entry that matches the given key and returns it.
	 *
	 * @param[in] key The key used to identify the BSS entry.
	 *
	 * @returns A pointer to the `dm_bss_t` structure if found, otherwise `nullptr`.
	 *
	 * @note This is a pure virtual function and must be implemented by derived classes.
	 */
	virtual dm_bss_t *get_bss(const char *key) = 0;
    
	/**!
	 * @brief Removes a BSS entry identified by the given key.
	 *
	 * This function is a pure virtual function that must be implemented by derived classes.
	 *
	 * @param[in] key A pointer to a character string that uniquely identifies the BSS entry to be removed.
	 *
	 * @note The key must be a valid, null-terminated string.
	 */
	virtual void remove_bss(const char *key) = 0;
    
	/**!
	 * @brief Puts a BSS entry into the data structure.
	 *
	 * This function inserts a BSS (Basic Service Set) entry into the data structure
	 * using the provided key.
	 *
	 * @param[in] key A constant character pointer representing the key associated with the BSS entry.
	 * @param[in] bss A pointer to a dm_bss_t structure containing the BSS data to be inserted.
	 *
	 * @note This is a pure virtual function and must be implemented by derived classes.
	 */
	virtual void put_bss(const char *key, const dm_bss_t *bss) = 0;

	dm_bss_list_t() : m_acl_sta_map(NULL) { m_acl_dirty_key[0] = 0; }
	dm_bss_list_t(const dm_bss_list_t&) = delete;
	dm_bss_list_t& operator=(const dm_bss_list_t&) = delete;

};

#endif
