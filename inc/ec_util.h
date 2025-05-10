/**
 * Copyright 2025 Comcast Cable Communications Management, LLC
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

#ifndef _EC_UTIL_H_
#define _EC_UTIL_H_

#include "em_base.h"
#include "ec_base.h"
#include "em_crypto.h"
#include "ec_crypto.h"
#include <stdint.h>
#include <stddef.h>

#include <map>
#include <vector>
#include <string>
#include <functional>
#include <memory>
#include <optional>
#include <sstream>
#include <chrono>
#include <thread>

#define EC_FRAME_BASE_SIZE (offsetof(ec_frame_t, attributes))

// -100 buffer is for frame overhead (management header, etc).
#define WIFI_MTU_SIZE (1500UL - 100UL)

typedef enum {
    DPP_URI_VERSION = 0,
    DPP_URI_MAC,
    DPP_URI_CHANNEL_LIST,
    DPP_URI_INFORMATION,
    DPP_URI_HOST,
    DPP_URI_SUPPORTED_CURVES,
    DPP_URI_PUBLIC_KEY,
    DPP_URI_MAX // End of ENUM - used for iteration
} dpp_uri_field;

namespace easyconnect {

static const std::map<ec_status_code_t, std::string> status_code_map = {
    {DPP_STATUS_OK, "OK: No errors or abnormal behavior"},
    {DPP_STATUS_NOT_COMPATIBLE, "Not Compatible: The DPP Initiator and Responder have incompatible capabilities"},
    {DPP_STATUS_AUTH_FAILURE, "Authentication Failure: Authentication failed"},
    {DPP_STATUS_BAD_CODE, "Bad Code: The code used in PKEX is bad"},
    {DPP_STATUS_BAD_GROUP, "Bad Group: An unsupported group was offered"},
    {DPP_STATUS_CONFIGURATION_FAILURE, "Configuration Failure: Configurator refused to configure Enrollee"},
    {DPP_STATUS_RESPONSE_PENDING, "Response Pending: Responder will reply later"},
    {DPP_STATUS_INVALID_CONNECTOR, "Invalid Connector: Received Connector is invalid for some reason. The sending device needs to be reconfigured."},
    {DPP_STATUS_NO_MATCH, "No Match: Received Connector is verified and valid but no matching Connector could be found. The receiving device needs to be reconfigured."},
    {DPP_STATUS_CONFIG_REJECTED, "Config Rejected: Enrollee rejected the configuration."},
    {DPP_STATUS_NO_AP_DISCOVERED, "No AP Discovered: Enrollee failed to discover an access point."},
    {DPP_STATUS_CONFIGURE_PENDING, "Configure Pending: Configuration response is not ready yet. The enrollee needs to request again."},
    {DPP_STATUS_CSR_NEEDED, "CSR Needed: Configuration requires a Certificate Signing Request. The enrollee needs to request again."},
    {DPP_STATUS_CSR_BAD, "CSR Bad: The Certificate Signing Request was invalid."},
    {DPP_STATUS_NEW_KEY_NEEDED, "New Key Needed: The Enrollee needs to generate a new Protocol key."}
};

};

class ec_util {
public:

    
	/**
	 * @brief Initialize an EC frame with the default WFA parameters.
	 *
	 * This function sets up the given EC frame with standard Wireless Fidelity Alliance (WFA) parameters, ensuring it is ready for use in subsequent operations.
	 *
	 * @param[in,out] frame The frame to initialize. This parameter is both an input and output as it is modified in place.
	 *
	 * @note Ensure that the frame is properly allocated before calling this function.
	 */
	static void init_frame(ec_frame_t *frame);

    /**
     * @brief Get a host-byte-ordered attribute from the buffer
     * 
	 * This function retrieves an attribute from the specified buffer using the given attribute ID.
	 *
	 * @param[in] buff The buffer to get the attribute from.
	 * @param[in] len The length of the buffer.
	 * @param[in] id The attribute ID.
     * 
     * @return const std::optional<ec_attribute_t> The attribute if found, NULL otherwise
     */
    static std::optional<const ec_attribute_t> get_attrib(uint8_t *buff, size_t len, ec_attrib_id_t id);

    
	/**
	 * @brief Add an attribute to the buffer, (re)allocating the buffer if necessary.
	 *
	 * This function adds an attribute to the specified buffer. If the buffer is not large enough
	 * to accommodate the new attribute, it will be reallocated to a larger size.
	 *
	 * @param[out] buff The buffer to which the attribute will be added. The buffer may be reallocated
	 *                  if it is not large enough to hold the new attribute.
	 * @param[in,out] buff_len The current length of the buffer. This will be updated to reflect the
	 *                         new length after the attribute is added.
	 * @param[in] id The identifier for the attribute to be added, in host byte ordering.
	 * @param[in] len The length of the attribute data, in host byte ordering.
	 * @param[in] data A pointer to the attribute data to be added to the buffer.
	 *
	 * @return uint8_t* A pointer to the buffer offset by the length of the attribute.
	 *
	 * @warning The buffer must be freed by the caller after use to prevent memory leaks.
	 */
	static uint8_t *add_attrib(uint8_t *buff, size_t* buff_len, ec_attrib_id_t id, uint16_t len, uint8_t *data);


    
	/**
	 * @brief Add an attribute to the buffer, (re)allocating the buffer if necessary.
	 *
	 * This function adds an attribute to the specified buffer. If the buffer is not large enough,
	 * it will be reallocated to accommodate the new attribute.
	 *
	 * @param[out] buff The buffer to which the attribute will be added.
	 * @param[in,out] buff_len The length of the buffer. This will be updated to reflect the new size.
	 * @param[in] id The attribute ID that identifies the type of attribute being added, in host byte ordering.
	 * @param[in] len The length of the attribute data, in host byte ordering.
	 * @param[in] data The attribute data to be added to the buffer.
	 *
	 * @return uint8_t* A pointer to the buffer offset by the length of the attribute.
	 *
	 * @warning The buffer must be freed by the caller to avoid memory leaks.
	 */
	static inline uint8_t *add_attrib(uint8_t *buff, size_t* buff_len, ec_attrib_id_t id, uint16_t len, const scoped_buff& data) {
        return add_attrib(buff, buff_len, id, len, data.get());
    }

    
	/**
	 * @brief Add an attribute to the buffer, (re)allocating the buffer if necessary.
	 *
	 * This function adds an attribute to the specified buffer and adjusts the buffer length accordingly.
	 *
	 * @param[in,out] buff The buffer to add the attribute to.
	 * @param[in,out] buff_len The length of the buffer, which will be updated after adding the attribute.
	 * @param[in] id The attribute ID, in host byte ordering.
	 * @param[in] str The attribute as a string, in host byte ordering.
	 *
	 * @return uint8_t* Pointer to the buffer offset by the length of the attribute.
	 *
	 * @warning The buffer must be freed by the caller.
	 */
	static inline uint8_t *add_attrib(uint8_t *buff, size_t* buff_len, ec_attrib_id_t id, std::string str) {
        return add_attrib(buff, buff_len, id, static_cast<uint16_t>(str.length()), const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(str.c_str())));
    }

    
	/**
	 * @brief Add an attribute to the buffer, (re)allocating the buffer if necessary.
	 *
	 * This function adds an attribute to the specified buffer and reallocates the buffer if needed.
	 *
	 * @param[out] buff The buffer to add the attribute to.
	 * @param[in,out] buff_len The current length of the buffer, which may be updated if reallocation occurs.
	 * @param[in] id The attribute ID, in host byte ordering.
	 * @param[in] val The uint8_t attribute value.
	 *
	 * @return uint8_t* The buffer offset by the length of the attribute.
	 *
	 * @warning The buffer must be freed by the caller.
	 */
	static inline uint8_t* add_attrib(uint8_t *buff, size_t* buff_len, ec_attrib_id_t id, uint8_t val) {
        return add_attrib(buff, buff_len, id, sizeof(uint8_t), const_cast<uint8_t*>(&val));
    }

    
	/**
	 * @brief Add an attribute to the buffer, (re)allocating the buffer if necessary.
	 *
	 * This function adds an attribute to the specified buffer. If the buffer
	 * is not large enough to accommodate the new attribute, it will be
	 * reallocated to ensure sufficient space.
	 *
	 * @param[out] buff The buffer to which the attribute will be added.
	 * @param[in,out] buff_len A pointer to the size of the buffer. It will be
	 * updated if the buffer is reallocated.
	 * @param[in] id The attribute ID to be added, in host byte ordering.
	 * @param[in] val The uint16_t attribute value to be added, in host byte ordering.
	 *
	 * @return uint8_t* A pointer to the buffer offset by the length of the
	 * attribute.
	 *
	 * @warning The buffer must be freed by the caller after use.
	 */
	static inline uint8_t* add_attrib(uint8_t *buff, size_t* buff_len, ec_attrib_id_t id, uint16_t val) {
        return add_attrib(buff, buff_len, id, sizeof(uint16_t), const_cast<uint8_t*>(reinterpret_cast<uint8_t*>(&val)));
    }

    
	/**
	 * @brief Heap allocate an EC frame with the default WFA parameters + type.
	 *
	 * This function allocates memory for an EC frame and initializes it with the specified frame type.
	 *
	 * @param[in] type The frame type to be assigned to the allocated frame.
	 *
	 * @return ec_frame_t* Pointer to the heap allocated frame. Returns NULL if memory allocation fails.
	 *
	 * @warning The allocated frame must be freed by the caller to avoid memory leaks.
	 */
	static inline ec_frame_t* alloc_frame(ec_frame_type_t type) {
        uint8_t* buff = static_cast<uint8_t*>(calloc(EC_FRAME_BASE_SIZE, 1));
        if (buff == NULL) {
            printf("%s:%d unable to allocate memory\n", __func__, __LINE__);
            return NULL;
        }
        ec_frame_t    *frame = reinterpret_cast<ec_frame_t*>(buff);
        init_frame(frame);
        frame->frame_type = type;
        return frame;
    }

    
	/**!
	 * @brief Allocates a GAS frame based on the specified action type.
	 *
	 * This function allocates memory for a GAS frame and initializes it based on the action type provided.
	 *
	 * @param[in] action The type of GAS action to perform. Determines the frame structure to allocate.
	 * @param[in] dialog_token The dialog token to be used in the GAS frame.
	 *
	 * @returns A pair containing a pointer to the allocated frame and the size of the frame.
	 * @retval std::pair<void *, size_t> A pair where the first element is a pointer to the allocated frame and the second element is the size of the frame.
	 *
	 * @note If the allocation fails, the function returns a pair with a nullptr and size 0.
	 */
	static std::pair<void *, size_t> alloc_gas_frame(dpp_gas_action_type_t action, uint8_t dialog_token) {
        void *frame = nullptr;
        size_t created_frame_size = 0UL;
        switch(action) {
            case dpp_gas_action_type_t::dpp_gas_initial_req: {
                frame = calloc(1, sizeof(ec_gas_initial_request_frame_t));
                if (!frame) {
                    printf("%s:%d: Failed to allocate GAS frame!\n", __func__, __LINE__);
                    break;
                }
                auto *req_frame = static_cast<ec_gas_initial_request_frame_t *>(frame);
                memcpy(req_frame->ape, DPP_GAS_CONFIG_REQ_APE, sizeof(req_frame->ape));
                memcpy(req_frame->ape_id, DPP_GAS_CONFIG_REQ_PROTO_ID, sizeof(req_frame->ape_id));
                created_frame_size = sizeof(ec_gas_initial_request_frame_t);
            }
            break;

            case dpp_gas_action_type_t::dpp_gas_initial_resp: {
                frame = calloc(1, sizeof(ec_gas_initial_response_frame_t));
                if (!frame) {
                    printf("%s:%d: Failed to allocate GAS frame!\n", __func__, __LINE__);
                    break;
                }
                auto *resp_frame = static_cast<ec_gas_initial_response_frame_t *>(frame);
                memcpy(resp_frame->ape, DPP_GAS_CONFIG_REQ_APE, sizeof(resp_frame->ape));
                memcpy(resp_frame->ape_id, DPP_GAS_CONFIG_REQ_PROTO_ID, sizeof(resp_frame->ape_id));
                // NOTE: Hardcoded since we are not implementing the full GAS protocol
                resp_frame->status_code = 0; // SUCCESS
                created_frame_size = sizeof(ec_gas_initial_response_frame_t);
            }
            break;

			case dpp_gas_action_type_t::dpp_gas_comeback_req: {
				frame = calloc(1, sizeof(ec_gas_comeback_request_frame_t));
				if (!frame) {
					printf("%s:%d: Failed to allocate GAS Comeback Request frame!\n", __func__, __LINE__);
					break;
				}
				created_frame_size = sizeof(ec_gas_comeback_request_frame_t);
			}
			break;
	
			case dpp_gas_action_type_t::dpp_gas_comeback_resp: {
				frame = calloc(1, sizeof(ec_gas_comeback_response_frame_t));
				if (!frame) {
					printf("%s:%d: Failed to allocate GAS Comeback Response frame!\n", __func__, __LINE__);
					break;
				}
				auto *cb_resp_frame = static_cast<ec_gas_comeback_response_frame_t *>(frame);
				memcpy(cb_resp_frame->ape, DPP_GAS_CONFIG_REQ_APE, sizeof(cb_resp_frame->ape));
				memcpy(cb_resp_frame->ape_id, DPP_GAS_CONFIG_REQ_PROTO_ID, sizeof(cb_resp_frame->ape_id));
				cb_resp_frame->status_code = 0;           // SUCCESS
				cb_resp_frame->gas_comeback_delay = 0;    // No delay for now
				cb_resp_frame->fragment_id = 0;
				cb_resp_frame->more_fragments = 0;
				created_frame_size = sizeof(ec_gas_comeback_response_frame_t);
			}
			break;

            default:
                printf("%s:%d: unhandled GAS frame type=%02x\n", __func__, __LINE__, action);
                break;
        }
        // Shared fields
        if (frame) {
            ec_gas_frame_base_t *base = static_cast<ec_gas_frame_base_t *>(frame);
            base->category = 0x04;
            base->action = static_cast<uint8_t>(action);
            base->dialog_token = dialog_token;
        }
        return std::make_pair(frame, created_frame_size);
    }

    
	/**
	 * @brief Copy (override) attributes to a frame.
	 *
	 * This function copies the specified attributes to the given frame. If the frame
	 * needs to be reallocated to accommodate the new attributes, the reallocated
	 * frame is returned.
	 *
	 * @param[in,out] frame The frame to which the attributes will be copied. This
	 * frame may be reallocated if necessary.
	 * @param[in] attrs The attributes to copy to the frame.
	 * @param[in] attrs_len The length of the attributes array.
	 *
	 * @return ec_frame_t* A pointer to the frame with the copied attributes. If the
	 * frame was reallocated, the new pointer is returned.
	 *
	 * @warning The frame must be freed by the caller after use to prevent memory leaks.
	 */
	static ec_frame_t* copy_attrs_to_frame(ec_frame_t *frame, uint8_t *attrs, size_t attrs_len);

	/**
	 * @brief Copy (override) attributes to a frame.
	 *
	 * This function copies the specified attributes to the given frame. If the frame
	 * needs to be reallocated to accommodate the new attributes, the reallocated
	 * frame is returned.
	 *
	 * @param[in,out] frame The frame to which the attributes will be copied. This
	 * frame may be reallocated if necessary.
	 * @param[in] attrs The attributes to copy to the frame.
	 * @param[in] attrs_len The length of the attributes array.
	 *
	 * @return ec_gas_initial_request_frame_t* A pointer to the frame with the copied attributes. If the
	 * frame was reallocated, the new pointer is returned.
	 *
	 * @warning The frame must be freed by the caller after use to prevent memory leaks.
	 */
	static ec_gas_initial_request_frame_t* copy_attrs_to_frame(ec_gas_initial_request_frame_t *frame, uint8_t *attrs, size_t attrs_len);

	/**
	 * @brief Copy (override) attributes to a frame.
	 *
	 * This function copies the specified attributes to the given frame. If the frame
	 * needs to be reallocated to accommodate the new attributes, the reallocated
	 * frame is returned.
	 *
	 * @param[in,out] frame The frame to which the attributes will be copied. This
	 * frame may be reallocated if necessary.
	 * @param[in] attrs The attributes to copy to the frame.
	 * @param[in] attrs_len The length of the attributes array.
	 *
	 * @return ec_gas_initial_response_frame_t* A pointer to the frame with the copied attributes. If the
	 * frame was reallocated, the new pointer is returned.
	 *
	 * @warning The frame must be freed by the caller after use to prevent memory leaks.
	 */
	static ec_gas_initial_response_frame_t* copy_attrs_to_frame(ec_gas_initial_response_frame_t *frame, uint8_t *attrs, size_t attrs_len);

    
	/**
	 * @brief Copy attributes to a frame.
	 *
	 * This function copies the specified attributes to a given frame starting at a specified offset.
	 *
	 * @param[out] frame The frame to which the attributes will be copied.
	 * @param[in] frame_base_size The offset at which to copy attributes to.
	 * @param[in] attrs The attributes to copy.
	 * @param[in] attrs_len The length of the attributes.
	 *
	 * @return uint8_t* Pointer to the base of the frame with newly copied attributes, or nullptr on failure.
	 *
	 * @note Ensure that the frame has enough space to accommodate the attributes starting from the specified offset.
	 */
	static uint8_t* copy_attrs_to_frame(uint8_t *frame, size_t frame_base_size, uint8_t *attrs, size_t attrs_len);

	/**
	 * @brief Copy a payload to a GAS Initial Response or GAS Comeback Response frame
	 * 
	 * @param frame The frame to copy to
	 * @param frame_base_size The offset where the payload will be copied to
	 * @param payload The payload to add to the frame
	 * @param payload_len The size of the payload.
	 * @return uint8_t* Pointer to base of the frame with newly added payload on success, otherwise nullptr
	 */
	static uint8_t *copy_payload_to_gas_resp(uint8_t *frame, size_t frame_base_size, uint8_t *payload, size_t payload_len);

	/**
	 * @brief Copy a payload to a GAS Initial Response frame
	 * 
	 * @param frame The frame to copy to
	 * @param frame_base_size The offset where the payload will be copied to
	 * @param payload The payload to add to the frame
	 * @param payload_len The size of the payload.
	 * @return uint8_t* Pointer to base of the frame with newly added payload on success, otherwise nullptr
	 */
	static ec_gas_initial_response_frame_t *copy_payload_to_gas_resp(ec_gas_initial_response_frame_t *frame, uint8_t *payload, size_t payload_len);

	/**
	 * @brief Copy a payload to a GAS Comeback Response frame
	 * 
	 * @param frame The frame to copy to
	 * @param frame_base_size The offset where the payload will be copied to
	 * @param payload The payload to add to the frame
	 * @param payload_len The size of the payload.
	 * @return uint8_t* Pointer to base of the frame with newly added payload on success, otherwise nullptr
	 */
	static ec_gas_comeback_response_frame_t *copy_payload_to_gas_resp(ec_gas_comeback_response_frame_t *frame, uint8_t *payload, size_t payload_len);

    
	/**
	 * @brief Validate an EC frame based on the WFA parameters.
	 *
	 * This function checks the given EC frame against predefined WFA parameters
	 * to determine its validity.
	 *
	 * @param[in] frame The frame to validate.
	 *
	 * @returns true if the frame is valid, false otherwise.
	 */
	static bool validate_frame(const ec_frame_t *frame);

    
	/**
	* @brief Validate an EC frame based on the WFA parameters and type.
	*
	* This function checks if the given EC frame matches the specified frame type.
	*
	* @param[in] frame The frame to validate.
	* @param[in] type The expected frame type.
	*
	* @return true if the frame is valid and matches the type, false otherwise.
	*/
	static inline bool validate_frame(const ec_frame_t *frame, ec_frame_type_t type) {
        return validate_frame(frame) && frame->frame_type == type;
    }

    
	/**
	 * @brief Parse a DPP Chirp Value TLV
	 *
	 * This function parses a DPP Chirp Value TLV from the provided buffer.
	 *
	 * @param[in] chirp_tlv The buffer containing the chirp TLV.
	 * @param[in] chirp_tlv_len The length of the chirp TLV.
	 * @param[out] mac The MAC address to store in the chirp TLV.
	 * @param[out] hash The hash to store in the chirp TLV.
	 * @param[out] hash_len The length of the hash.
	 *
	 * @return true if the parsing is successful, false otherwise.
	 */
	static bool parse_dpp_chirp_tlv(em_dpp_chirp_value_t* chirp_tlv,  uint16_t chirp_tlv_len, mac_addr_t *mac, uint8_t **hash, uint16_t *hash_len);

    
	/**
	 * @brief Creates and allocates a DPP Chirp Value TLV
	 *
	 * EasyMesh R6, Section 17.2.83, Table 105
	 *
	 * @param[in] mac_present The address of the Enrollee Multi-AP Agent
	 * @param[in] hash_validity Establish/purge any DPP authentication state pertaining to the hash value in this TLV (0 = purge, 1 = establish)
	 * @param[in] dest_mac The destination mac address (NULL if not present)
	 * @param[in] hash The hash value (NULL if not present)
	 * @param[in] hash_len The length of the hash value (0 if not present)
	 * @return std::pair<em_dpp_chirp_value_t*, uint16_t> The heap allocated DPP Chirp Value TLV and its length, NULL if failed
	 *
	 * @warning The `em_dpp_chirp_value_t` must be freed by the caller
	 */
	static std::pair<em_dpp_chirp_value_t*, uint16_t> create_dpp_chirp_tlv(bool mac_present, bool hash_validity, mac_addr_t dest_mac = NULL, uint8_t* hash = NULL, uint16_t hash_len = 0);

    
	/**
	 * @brief Parse an Encap DPP TLV
	 *
	 * This function parses the given Encap DPP TLV buffer and extracts the destination MAC address,
	 * frame type, and encapsulated frame.
	 *
	 * @param[in] encap_tlv The buffer containing the Encap DPP TLV.
	 * @param[in] encap_tlv_len The length of the Encap DPP TLV.
	 * @param[out] dest_mac The destination MAC address (0 if not present).
	 * @param[out] frame_type The frame type.
	 * @param[out] encap_frame The encapsulated frame, allocated on the heap.
	 * @param[out] encap_frame_len The length of the encapsulated frame.
	 *
	 * @return bool True if successful, false otherwise.
	 *
	 * @warning The `encap_frame` must be freed by the caller.
	 */
	static bool parse_encap_dpp_tlv(em_encap_dpp_t* encap_tlv, uint16_t encap_tlv_len, mac_addr_t *dest_mac, uint8_t *frame_type, uint8_t** encap_frame, uint16_t *encap_frame_len);

    
	/**
	 * @brief Creates and allocates an Encap DPP TLV.
	 *
	 * This function is responsible for creating and allocating a DPP TLV based on the provided parameters.
	 *
	 * @param[in] dpp_frame_indicator The DPP frame indicator. Use 0 for DPP Public Action frame and 1 for GAS Frame.
	 * @param[in] dest_mac The destination MAC address. Use 0 if not present.
	 * @param[in] frame_type The type of the frame.
	 * @param[in] encap_frame Pointer to the encapsulated frame.
	 * @param[in] encap_frame_len The length of the encapsulated frame.
	 *
	 * @return std::pair<em_encap_dpp_t*, uint16_t> A pair containing the heap allocated Encap DPP TLV and its length. Returns NULL if allocation fails.
	 *
	 * @note Ensure that the returned Encap DPP TLV is properly deallocated to avoid memory leaks.
	 */
	static std::pair<em_encap_dpp_t*, uint16_t> create_encap_dpp_tlv(bool dpp_frame_indicator, mac_addr_t dest_mac, ec_frame_type_t frame_type, uint8_t *encap_frame, size_t encap_frame_len);


    
	/**
	 * @brief Converts a frequency to a WFA channel attribute format (opclass + channel).
	 *
	 * This function takes a frequency value and converts it into a standardized
	 * channel attribute format used in wireless communication.
	 *
	 * @param[in] freq The frequency to convert.
	 *
	 * @returns `uint16_t` with the MSB as the op class and the LSB as the channel.
	 *
	 * @note Format is standardized as the "Channel Attribute" in Easy Connect 3.0 Section 8.1.1.17.
	 */
	static uint16_t freq_to_channel_attr(unsigned int freq);

    
    
	/**
	* @brief Get the size of an EC attribute\n 
	*
	* This function calculates the total size of an EC attribute based on the
	* length of the data it contains.
	*
	* @param[in] data_len The length of the data in the attribute.
	*
	* @returns The total size of the EC attribute, including the data.
	*/
	static inline size_t get_ec_attr_size(uint16_t data_len) {
        return offsetof(ec_net_attribute_t, data) + data_len;
    };

    
	/**
	 * @brief Get the string representation of a status code
	 *
	 * This function converts a given status code into its corresponding
	 * string representation using a predefined mapping.
	 *
	 * @param[in] status The status code to convert
	 *
	 * @return std::string The string representation of the status code
	 *
	 * @note Ensure that the status code provided exists in the status_code_map
	 * to avoid exceptions.
	 */
	static inline std::string status_code_to_string(ec_status_code_t status) {
        return easyconnect::status_code_map.at(status);
    };

    
	/**
	 * @brief Add a wrapped data attribute to a frame
	 *
	 * This function adds a wrapped data attribute to the specified frame attributes.
	 *
	 * @param[in] frame The frame to use as Additional Authenticated Data (AAD). Can be NULL if no AAD is needed.
	 * @param[in,out] frame_attribs The attributes to add the wrapped data attribute to and to use as AAD.
	 * @param[in,out] non_wrapped_len The length of the non-wrapped attributes (`frame_attribs`).
	 * @param[in] use_aad Whether to use AAD in the encryption.
	 * @param[in] key The key to use for encryption.
	 * @param[in] create_wrap_attribs A function to create the attributes to wrap and their length. Memory is handled by the function (see note).
	 *
	 * @return uint8_t* The new frame attributes with the wrapped data attribute added.
	 *
	 * @note The `create_wrap_attribs` function will allocate heap-memory which is freed inside the `add_wrapped_data_attr` function.
	 *       **The caller should not use statically allocated memory in `create_wrap_attribs` or free the memory returned by `create_wrap_attribs`.**
	 */
	static uint8_t* add_wrapped_data_attr(ec_frame_t *frame, uint8_t* frame_attribs, size_t* non_wrapped_len, 
        bool use_aad, uint8_t* key, std::function<std::pair<uint8_t*, uint16_t>()> create_wrap_attribs);

	/**
	 * @brief Add a wrapped data attribute to an attributes buffer without the frame AAD. 
	 * Not exclusive to configuration frames however accordinf to the spec it is only used in configuration frames.
	 * 
	 * EasyConnect 6.4.1 
	 * 	All DPP Configuration Protocol messages except for the DPP Configuration Request for Fragments frame, are AES-SIV protected. 
	 * 	AAD for use with AES-SIV for protected messages in the DPP Configuration protocol shall consist of all octets in the Query Request 
	 * 	and Query Response fields up to the first octet of the Wrapped Data attribute, which is the last attribute in a 
	 * 	DPP Configuration frame. When the number of octets of AAD is zero, the number of components of AAD passed to AES-SIV is zero.
	 *
	 * @param[in,out] frame_attribs The attributes to add the wrapped data attribute to and to use as AAD.
	 * @param[in,out] non_wrapped_len The length of the non-wrapped attributes (`frame_attribs`).
	 * @param[in] use_aad Whether to use AAD in the encryption.
	 * @param[in] key The key to use for encryption.
	 * @param[in] create_wrap_attribs A function to create the attributes to wrap and their length. Memory is handled by the function (see note).
	 *
	 * @return uint8_t* The new frame attributes with the wrapped data attribute added.
	 *
	 * @note The `create_wrap_attribs` function will allocate heap-memory which is freed inside the `add_wrapped_data_attr` function.
	 *       **The caller should not use statically allocated memory in `create_wrap_attribs` or free the memory returned by `create_wrap_attribs`.**
	 */
	static uint8_t* add_cfg_wrapped_data_attr(uint8_t *frame_attribs, size_t *non_wrapped_len, bool use_aad, uint8_t *key, 
		std::function<std::pair<uint8_t *, uint16_t>()> create_wrap_attribs);

	/**!
	 * @brief Adds wrapped data attributes to a frame.
	 *
	 * This function processes the given frame and adds wrapped data attributes
	 * based on the provided parameters.
	 *
	 * @param[in] frame Pointer to the frame data to be processed.
	 * @param[in] frame_len Length of the frame data.
	 * @param[in] frame_attribs Pointer to the frame attributes.
	 * @param[out] non_wrapped_len Pointer to store the length of non-wrapped data.
	 * @param[in] use_aad Boolean flag indicating whether to use AAD.
	 * @param[in] key Pointer to the key used for wrapping.
	 * @param[in] create_wrap_attribs Function to create wrap attributes.
	 *
	 * @returns Pointer to the processed frame with wrapped data attributes.
	 *
	 * @note Ensure that the frame and key pointers are valid before calling this function.
	 */
	static uint8_t* add_wrapped_data_attr(uint8_t *frame, size_t frame_len, uint8_t* frame_attribs, size_t* non_wrapped_len, 
        bool use_aad, uint8_t* key, std::function<std::pair<uint8_t*, uint16_t>()> create_wrap_attribs);


	/**
	 * @brief Unwrap a wrapped data attribute without frame AAD
	 *
	 * This function unwraps a wrapped attribute using the provided key and
	 * optional additional authenticated data (AAD) from the frame.
	 *
	 * @param[in] wrapped_attrib The wrapped attribute to unwrap (retrieved using `get_attrib`).
	 * @param[in] uses_aad Whether the wrapped attribute uses AAD.
	 * @param[in] key The key to use for decryption.
	 *
	 * @return std::pair<uint8_t*, uint16_t> A heap allocated buffer of unwrapped attributes on success,
	 *         which can then be fetched via `get_attrib`, along with the length of that buffer.
	 *         The buffer is NULL and the size is 0 on failure.
	 *
	 * @warning The caller is responsible for freeing the memory returned by this function.
	 *
	 * @note Forwards to `unwrap_wrapped_attrib(ec_attribute_t wrapped_attrib, uint8_t *frame, size_t frame_len, uint8_t *frame_attribs, bool uses_aad, uint8_t *key);`
	 */
	static std::pair<uint8_t*, uint16_t> unwrap_wrapped_attrib(const ec_attribute_t &wrapped_attrib, uint8_t *frame_attribs, bool uses_aad, uint8_t *key);
    
	/**
	 * @brief Unwrap a wrapped data attribute
	 *
	 * This function unwraps a wrapped attribute using the provided key and
	 * optional additional authenticated data (AAD) from the frame.
	 *
	 * @param[in] wrapped_attrib The wrapped attribute to unwrap (retrieved using `get_attrib`).
	 * @param[in] frame The frame to use as AAD. Can be NULL if no AAD is needed.
	 * @param[in] uses_aad Whether the wrapped attribute uses AAD.
	 * @param[in] key The key to use for decryption.
	 *
	 * @return std::pair<uint8_t*, uint16_t> A heap allocated buffer of unwrapped attributes on success,
	 *         which can then be fetched via `get_attrib`, along with the length of that buffer.
	 *         The buffer is NULL and the size is 0 on failure.
	 *
	 * @warning The caller is responsible for freeing the memory returned by this function.
	 *
	 * @note Forwards to `unwrap_wrapped_attrib(ec_attribute_t wrapped_attrib, uint8_t *frame, size_t frame_len, uint8_t *frame_attribs, bool uses_aad, uint8_t *key);`
	 */
	static std::pair<uint8_t*, uint16_t> unwrap_wrapped_attrib(const ec_attribute_t& wrapped_attrib, ec_frame_t *frame, bool uses_aad, uint8_t* key);

    
	/**
	 * @brief Unwrap a wrapped data attribute.
	 *
	 * This function attempts to unwrap a given wrapped attribute using the provided frame and key.
	 *
	 * @param[in] wrapped_attrib The wrapped attribute to unwrap (retrieved using `get_attribute`).
	 * @param[in] frame The frame to use as AAD. Can be nullptr if `uses_aad` is false.
	 * @param[in] frame_len The length of the frame.
	 * @param[out] frame_attribs Pointer to the attributes to unwrap.
	 * @param[in] uses_aad Whether the wrapped attribute uses AAD.
	 * @param[in] key The key to use for decryption.
	 *
	 * @return std::pair<uint8_t*, uint16_t> The unwrapped attributes and their size on success, nullptr & 0 otherwise.
	 *
	 * @note Ensure that the key is valid and the frame is correctly set up before calling this function.
	 */
	static std::pair<uint8_t*, uint16_t> unwrap_wrapped_attrib(const ec_attribute_t& wrapped_attrib, uint8_t *frame, size_t frame_len, uint8_t *frame_attribs, bool uses_aad, uint8_t *key);

    // Used for storing channels / op-classes searched when looking for a given SSID.
    struct scanned_channels_t {
        uint32_t chan;
        uint32_t opclass;
    };

    
	/**
	 * @brief Generate an EasyConnect `channel-list-2` formatted channel list from a map of scanned channels.
	 *
	 * This function constructs a channel list string based on the provided SSID and a map of scanned channels.
	 *
	 * @param[in] ssid The SSID to build the searched channel list for.
	 * @param[in] scanned_channels_map A map where each key is an SSID and the value is a vector of scanned channels.
	 * @return std::string A formatted channel list as a string, example: "81/1,6,11,117/40,115/48".
	 *
	 * @note This function is based on EasyConnect version 6.4.5.2.
	 */
	static std::string generate_channel_list(const std::string& ssid, std::unordered_map<std::string, std::vector<scanned_channels_t>> scanned_channels_map);

    
	/**
	 * @brief Check if the capabilities of the initiator and responder are compatible.
	 *
	 * This function evaluates the capabilities of both the initiator and the responder
	 * to determine if they are compatible with each other.
	 *
	 * @param[in] init_caps The capabilities of the initiator.
	 * @param[in] resp_caps The capabilities of the responder.
	 *
	 * @return true if the capabilities are compatible (DPP_STATUS_OK),
	 *         false otherwise (DPP_STATUS_NOT_COMPATIBLE).
	 */
	static bool check_caps_compatible(const ec_dpp_capabilities_t& init_caps, const ec_dpp_capabilities_t& resp_caps);

	/**
	 * @brief Decode a DPP URI channel-list string.
	 *
	 * This function parses a channel-list string formatted as per EasyConnect 5.2.1 specifications.
	 * The format is "C:" followed by class-and-channels, where class-and-channels is class "/" channel, and class and channel are 1 to 3 digit numbers.
	 *
	 * Example: "C:81/1,115/36"
	 *
	 * @param[in] class_channel_str The channel list string to decode.
	 * @return std::vector<std::pair<uint32_t, uint32_t>> A vector of pairs containing the op-class and channel parsed.
	 */
	static inline std::vector<std::pair<uint32_t, uint32_t>>
    parse_dpp_uri_channel_list(std::string class_channel_str)
    { 
		std::stringstream ss(class_channel_str);
        std::string pair;

        std::vector<std::pair<uint32_t, uint32_t>> class_channel_pairs;

        while (std::getline(ss, pair, ',')) {
            size_t slash_pos = pair.find('/');
            if (slash_pos != std::string::npos) {
                int op_class = std::stoi(pair.substr(0, slash_pos));
                int channel = std::stoi(pair.substr(slash_pos + 1));

                class_channel_pairs.emplace_back(static_cast<uint32_t>(op_class),
                                                 static_cast<uint32_t>(channel));
            }
        }
        return class_channel_pairs;
    }

    
	/**
	 * @brief Encode the bootstrapping data into a JSON format (same information as the DPP URI)
	 *
	 * This function takes the DPP data provided in `boot_data` and encodes it into a JSON format.
	 *
	 * @param[in] boot_data The DPP data to encode
	 *
	 * @return std::optional<std::string> The encoded bootstrapping data in JSON format, or std::nullopt on failure
	 */
	static std::optional<std::string> encode_bootstrap_data_json(ec_data_t *boot_data);

    
	/**
	 * @brief Encode the bootstrapping data into a URI format (DPP URI)
	 *
	 * This function takes the provided bootstrapping data and encodes it into
	 * a URI format that is compliant with the DPP (Device Provisioning Protocol).
	 *
	 * @param[in] boot_data The DPP data to encode. This parameter is a pointer
	 *                      to the ec_data_t structure containing the data.
	 *
	 * @return std::optional<std::string> The encoded bootstrapping data in DPP URI
	 *                                     format, or std::nullopt on failure.
	 *
	 * @note Ensure that the boot_data is properly initialized before calling
	 *       this function to avoid unexpected behavior.
	 */
	static std::optional<std::string> encode_bootstrap_data_uri(ec_data_t *boot_data);

    
	/**
	 * @brief Decode the bootstrapping data from a URI format (DPP URI).
	 *
	 * This function takes a DPP URI and decodes it into bootstrapping data.
	 *
	 * @param[in] uri The DPP URI to decode.
	 * @param[out] boot_data The DPP data to decode into.
	 * @param[in] country_code The country code used for decoding, default is "US".
	 *
	 * @return true if the DPP boot data was decoded successfully, false otherwise.
	 */
	static bool decode_bootstrap_data_uri(const std::string &uri, ec_data_t *boot_data,
                                          std::string country_code = "US");
    
	/**
	 * @brief Decode the bootstrapping data from a JSON format.
	 *
	 * This function decodes the given JSON object into DPP boot data, using the specified country code for channel decoding.
	 *
	 * @param[in] json_obj The JSON object to decode.
	 * @param[out] boot_data The DPP data to decode into.
	 * @param[in] country_code The country code to use for channel decoding. Defaults to "US".
	 *
	 * @return true if the DPP boot data was decoded successfully, false otherwise.
	 */
	static bool decode_bootstrap_data_json(const cJSON *json_obj, ec_data_t *boot_data,
                                           std::string country_code = "US");

    
	/**
	 * @brief Read the bootstrapping data from a JSON file.
	 *
	 * This function reads the DPP bootstrapping data from a specified JSON file and optionally from a PEM file.
	 *
	 * @param[out] boot_data The DPP data structure to populate with the read data.
	 * @param[in] json_file_path The path to the JSON file to read from.
	 * @param[in] pem_file_path The path to the PEM file for the private key to read from. Pass NULL if not needed (e.g., for initiator).
	 *
	 * @return true if the DPP boot data was read successfully, false otherwise.
	 */
	static bool read_bootstrap_data_from_files(ec_data_t *boot_data, const std::string &json_file_path, const std::optional<std::string> &pem_file_path = std::nullopt);

    
	/**
	 * @brief Write the bootstrapping data to a file.
	 *
	 * This function writes the provided DPP bootstrapping data to the specified file paths.
	 *
	 * @param[in] boot_data The DPP data to write.
	 * @param[in] file_path The path to the file to write the boot data to.
	 * @param[in] pem_file_path The path to the PEM file (for the private key) to write to.
	 *
	 * @return true if the DPP boot data was written successfully, false otherwise.
	 */
	static bool write_bootstrap_data_to_files(ec_data_t *boot_data, const std::string &file_path, const std::string &pem_file_path);

    
	/**
	 * @brief Generate DPP bootstrapping data
	 *
	 * This function generates the DPP bootstrapping data using the provided AL MAC address and optional operating class information.
	 *
	 * @param[out] boot_data The DPP bootstrapping data to generate.
	 * @param[in] al_mac The MAC address of the AL interface.
	 * @param[in] op_class_info The operating class information to use for the DPP bootstrapping data. Optional. If not given, then channel information will not be present in the newly generated bootstrapping data.
	 *
	 * @return true if the DPP boot data was generated successfully, false otherwise.
	 */
	static bool generate_dpp_boot_data(ec_data_t *boot_data, mac_addr_t al_mac,
                                       em_op_class_info_t *op_class_info = NULL);

    
	/**
	 * @brief Get the DPP bootstrapping data from "somewhere".
	 *
	 * In the current "demo" implementation, this function will:
	 * - When `do_recfg` is false:
	 * - Generate a new DPP bootstrapping data, store it in `boot_data`, and write it to the file system
	 * - Write the newly generated responder bootstrapping keypair to a PEM file
	 * - When `do_recfg` is true:
	 * - Read the DPP bootstrapping data from the file system and store it in `boot_data`
	 * - Read the responder bootstrapping keypair from the PEM file and store it in `boot_data`
	 * - If those are not present, it will re-generate everything and switch back to non-reconfiguration mode (since that information is no longer valid)
	 *
	 * @param[out] boot_data The newly filled DPP bootstrapping data
	 * @param[in] al_mac The MAC address of the AL interface
	 * @param[in] do_recfg Whether to fetch the DPP bootstrapping data for DPP reconfig/reauth or not
	 * @param[in] force_regen Whether to force the generation of new DPP bootstrapping data or not
	 * @param[in] op_class_info The operating class information to use for the DPP bootstrapping data. 
	 * Optional. If not given then channel information will not be present in newly generated bootstrapping data.
	 * @return true The DPP boot data was fetched successfully, false otherwise
	 *
	 * @note This function can change as out-of-band mechanisms change. This is **NOT** a constant
	 */
	static bool get_dpp_boot_data(ec_data_t *boot_data, mac_addr_t al_mac, bool do_recfg,
                                  bool force_regen = false, em_op_class_info_t *op_class_info = NULL);


	/**
	 * @brief Interruptible sleep for a thread
	 * 
	 * @param duration How long to sleep for (arbitrary time unit, s, ms, etc)
	 * @param stop_on Callback to determine when to stop the sleep
	 * @param polling_interval How often to wake up and check the `stop_on` condition (ms)
	 * @return True if the sleeping stopped due to the `stop_on` condition, false if the full duration elapsed
	 */
	static bool interruptible_sleep(std::chrono::steady_clock::duration duration, std::function<bool()> stop_on, std::chrono::milliseconds polling_interval = std::chrono::milliseconds(100)) {
		auto start = std::chrono::steady_clock::now();
		while (!stop_on() && (std::chrono::steady_clock::now() - start < duration)) {
			std::this_thread::sleep_for(polling_interval);
		}
		return !stop_on();
	}

private:
    
	/**
	 * @brief Decode the bootstrapping data from a URI format (DPP URI)
	 *
	 * @param[in] uri_map The intermediate map of the DPP URI fields and their string values
	 * @param[out] boot_data The DPP data to decode into
	 * @param[in] country_code The country code for the operation, default is "US"
	 * @return true if the DPP boot data was decoded successfully, false otherwise
	 *
	 * @details
	 * EasyConnect 5.2.1 Bootstrapping Information Format
	 * dpp-qr = “DPP:” *optional-fields public-key “;;”
	 * pkex-bootstrap-info = information
	 * optional-fields = reserved-field / unreserved-field
	 * reserved-field = ( channel-list / mac / information / version / host / supported-curves) ";" ; specified in this spec
	 * channel-list = “C:” class-and-channels *(“,” class-and-channels)
	 * class-and-channels = class “/” channel *(“,” channel)
	 * class = 1*3DIGIT
	 * channel = 1*3DIGIT
	 * mac = “M:” 6hex-octet ; MAC address
	 * hex-octet = 2HEXDIG
	 * information = “I:” *(%x20-3A / %x3C-7E) ; semicolon not allowed
	 * version = "V:" 1*ALPHANUMERIC ; supported DPP version with value from Table 31 in Section 8.1.1.18
	 * host = "H:" 1*255(DIGIT / ALPHA / "." / "-" / ":") ; semicolon not allowed
	 * supported-curves = "B:" 1*HEXDIG ; supported curves as bitmap of Figure 18
	 * ALPHANUMERIC = ALPHA / DIGIT
	 * unreserved-field = dpp-token-pair ";"
	 * dpp-token-pair = unreserved-token “:” *(%x20-3A / %x3C-7E) ; semicolon not allowed
	 * unreserved-token = 1*ALPHA; “M”, “C”, “K”, “I”, "H", "B" are not allowed token names for extensions
	 * public-key = “K:” *PKCHAR ; DER of ASN.1 SubjectPublicKeyInfo encoded in “base64” as per [13]
	 * PKCHAR = ALPHANUMERIC / %x2b / %x2f / %x3d
	 * DIGIT = %x30-39 HEXDIG = DIGIT / "A" / "B" / "C" / "D" / "E" / "F" ALPHA
	 */
	static bool decode_bootstrap_data(std::map<dpp_uri_field, std::string> uri_map,
                                      ec_data_t *boot_data, std::string country_code = "US");

    
	/**
	 * @brief Encode the bootstrapping data into a URI format (DPP URI)
	 *
	 * @param[in] boot_data The DPP data to encode
	 * @return std::map<dpp_uri_field, std::string> The encoded bootstrapping data in DPP URI string format
	 *
	 * @details
	 * EasyConnect 5.2.1 Bootstrapping Information Format
	 * dpp-qr = “DPP:” *optional-fields public-key “;;”
	 * pkex-bootstrap-info = information
	 * optional-fields = reserved-field / unreserved-field
	 * reserved-field = ( channel-list / mac / information / version / host / supported-curves) ";" ; specified in this spec
	 * channel-list = “C:” class-and-channels *(“,” class-and-channels)
	 * class-and-channels = class “/” channel *(“,” channel)
	 * class = 1*3DIGIT
	 * channel = 1*3DIGIT
	 * mac = “M:” 6hex-octet ; MAC address
	 * hex-octet = 2HEXDIG
	 * information = “I:” *(%x20-3A / %x3C-7E) ; semicolon not allowed
	 * version = "V:" 1*ALPHANUMERIC ; supported DPP version with value from Table 31 in Section 8.1.1.18
	 * host = "H:" 1*255(DIGIT / ALPHA / "." / "-" / ":") ; semicolon not allowed
	 * supported-curves = "B:" 1*HEXDIG ; supported curves as bitmap of Figure 18
	 * ALPHANUMERIC = ALPHA / DIGIT
	 * unreserved-field = dpp-token-pair ";"
	 * dpp-token-pair = unreserved-token “:” *(%x20-3A / %x3C-7E) ; semicolon not allowed
	 * unreserved-token = 1*ALPHA; “M”, “C”, “K”, “I", "H", "B" are not allowed token names for extensions
	 * public-key = “K:” *PKCHAR ; DER of ASN.1 SubjectPublicKeyInfo encoded in “base64” as per [13]
	 * PKCHAR = ALPHANUMERIC / %x2b / %x2f / %x3d
	 * DIGIT = %x30-39 HEXDIG = DIGIT / "A" / "B" / "C" / "D" / "E" / "F" ALPHA
	 */
	static std::map<dpp_uri_field, std::string> encode_bootstrap_data(ec_data_t *boot_data);

    
	/**
	 * @brief Get the DPP URI field enum from a string.
	 *
	 * This function converts a single-character string into a corresponding
	 * DPP URI field enum. If the string does not represent a valid field,
	 * the function returns std::nullopt.
	 *
	 * @param[in] field_str The string to convert. Must be a single character.
	 *
	 * @return std::optional<dpp_uri_field> The DPP URI field enum, or std::nullopt if invalid.
	 *
	 * @note This method is used instead of a map to ensure that new fields
	 * require explicit mapping, thus preventing unnoticed errors.
	 */
	static inline std::optional<dpp_uri_field> get_dpp_uri_field(const std::string &field_str)
    {
        ASSERT_MSG_TRUE(field_str.length() == 1, std::nullopt, "Invalid DPP URI field string");
        char field = static_cast<char>(std::toupper(field_str[0]));
        if (field < 'A' || field > 'Z') {
            return std::nullopt;
        }
        switch (field) {
        case 'V':
            return dpp_uri_field::DPP_URI_VERSION;
        case 'M':
            return dpp_uri_field::DPP_URI_MAC;
        case 'C':
            return dpp_uri_field::DPP_URI_CHANNEL_LIST;
        case 'I':
            return dpp_uri_field::DPP_URI_INFORMATION;
        case 'H':
            return dpp_uri_field::DPP_URI_HOST;
        case 'B':
            return dpp_uri_field::DPP_URI_SUPPORTED_CURVES;
        case 'K':
            return dpp_uri_field::DPP_URI_PUBLIC_KEY;
            // Leaving off `default` case so compile error will be thrown if new field is added and not handled
        }
        return std::nullopt;
    }

    
	/**
	 * @brief Get the DPP URI field character from a field enum.
	 *
	 * This function maps a given DPP URI field enum to its corresponding
	 * character representation. If the field is invalid, it returns std::nullopt.
	 *
	 * @param[in] field The field to convert.
	 * @return std::optional<std::string> The DPP URI field character, or std::nullopt if invalid.
	 *
	 * @note This method is used instead of a map to ensure that new fields
	 * require explicit mapping, thus preventing unnoticed errors.
	 */
	static inline std::optional<std::string> get_dpp_uri_field_char(dpp_uri_field field)
    {
        switch (field) {
        case dpp_uri_field::DPP_URI_VERSION:
            return "V";
        case dpp_uri_field::DPP_URI_MAC:
            return "M";
        case dpp_uri_field::DPP_URI_CHANNEL_LIST:
            return "C";
        case dpp_uri_field::DPP_URI_INFORMATION:
            return "I";
        case dpp_uri_field::DPP_URI_HOST:
            return "H";
        case dpp_uri_field::DPP_URI_SUPPORTED_CURVES:
            return "B";
        case dpp_uri_field::DPP_URI_PUBLIC_KEY:
            return "K";
        case dpp_uri_field::DPP_URI_MAX:
            return std::nullopt;
            // Leaving off `default` case so compile error will be thrown if new field is added and not handled
        }
        return std::nullopt;
    }
};

#endif // _EC_UTIL_H_