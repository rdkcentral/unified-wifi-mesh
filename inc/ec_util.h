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

#include "em_base.h"
#include "ec_base.h"
#include <stdint.h>
#include <stddef.h>

#include <map>
#include <vector>
#include <string>
#include <functional>
#include <memory>

#define EC_FRAME_BASE_SIZE (offsetof(ec_frame_t, attributes))

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
     * @brief Initialize an EC frame with the default WFA parameters
     * 
     * @param frame The frame to initialize
     */
    static void init_frame(ec_frame_t *frame);

    /**
     * @brief Get an attribute from the buffer
     * 
     * @param buff The buffer to get the attribute from
     * @param len The length of the buffer to get the attribute from
     * @param id The attribute ID
     * @return ec_attribute_t* The attribute if found, NULL otherwise
     */
    static ec_attribute_t *get_attrib(uint8_t *buff, uint16_t len, ec_attrib_id_t id);

    /**
     * @brief Add an attribute to the buffer, (re)allocating the buffer if necessary
     * 
     * @param buff The buffer to add the attribute to
     * @param buff_len The length of the buffer (in/out)
     * @param id The attribute ID
     * @param len The length of the data
     * @param data The attribute data
     * @return uint8_t* The buffer offset by the length of the attribute
     * 
     * @warning The buffer must be freed by the caller
     */
    static uint8_t *add_attrib(uint8_t *buff, uint16_t* buff_len, ec_attrib_id_t id, uint16_t len, uint8_t *data);

    /**
     * @brief Add an attribute to the buffer, (re)allocating the buffer if necessary
     * 
     * @param buff The buffer to add the attribute to
     * @param id The attribute ID
     * @param val The uint8_t attribute value
     * @return uint8_t* The buffer offset by the length of the attribute
     * 
     * @warning The buffer must be freed by the caller
     */
    static inline uint8_t* add_attrib(uint8_t *buff, uint16_t* buff_len, ec_attrib_id_t id, uint8_t val) {
        return add_attrib(buff, buff_len, id, sizeof(uint8_t), (uint8_t *)&val);
    }

    /**
     * @brief Add an attribute to the buffer, (re)allocating the buffer if necessary
     * 
     * @param buff The buffer to add the attribute to
     * @param id The attribute ID
     * @param val The uint16_t attribute value
     * @return uint8_t* The buffer offset by the length of the attribute
     * 
     * @warning The buffer must be freed by the caller
     */
    static inline uint8_t* add_attrib(uint8_t *buff, uint16_t* buff_len, ec_attrib_id_t id, uint16_t val) {
        return add_attrib(buff, buff_len, id, sizeof(uint16_t), (uint8_t *)&val);
    }

    /**
     * @brief Heap allocate an EC frame with the default WFA parameters + type
     * 
     * @param type The frame type
     * @return ec_frame_t* The heap allocated frame, NULL if failed
     * 
     * @warning The frame must be freed by the caller
     */
    static inline ec_frame_t* alloc_frame(ec_frame_type_t type) {
        uint8_t* buff = (uint8_t*) calloc(EC_FRAME_BASE_SIZE, 1);
        if (buff == NULL) {
            printf("%s:%d unable to allocate memory\n", __func__, __LINE__);
            return NULL;
        }
        ec_frame_t    *frame = (ec_frame_t *)buff;
        init_frame(frame);
        frame->frame_type = type;
        return frame;
    }

    /**
     * @brief Copy (overrride) attributes to a frame
     * 
     * @param frame The frame to copy the attributes to
     * @param attrs The attributes to copy
     * @param attrs_len The length of the attributes
     * @return ec_frame_t* The frame with the copied attributes (returned due to realloc)
     * 
     * @warning The frame must be freed by the caller
     */
    static ec_frame_t* copy_attrs_to_frame(ec_frame_t *frame, uint8_t *attrs, uint16_t attrs_len);

    /**
     * @brief Validate an EC frame based on the WFA parameters
     * 
     * @param frame The frame to validate
     * @return true The frame is valid, false otherwise
     */
    static bool validate_frame(const ec_frame_t *frame);

    /**
     * @brief Validate an EC frame based on the WFA parameters and type
     * 
     * @param frame The frame to validate
     * @param type The frame type that the frame should be
     * @return true The frame is valid, false otherwise
     */
    static inline bool validate_frame(const ec_frame_t *frame, ec_frame_type_t type) {
        return validate_frame(frame) && frame->frame_type == type;
    }

        /**
     * @brief Parse a DPP Chirp TLV
     * 
     * @param buff [in] The buffer containing the chirp TLV
     * @param chirp_tlv_len [in] The length of the chirp TLV
     * @param mac [out] The MAC address to store in the chirp TLV
     * @param hash [out] The hash to store in the chirp TLV
     * @param hash_len [out] The length of the hash
     * @return bool true if successful, false otherwise
     */
    static bool parse_dpp_chirp_tlv(em_dpp_chirp_value_t* chirp_tlv,  uint16_t chirp_tlv_len, mac_addr_t *mac, uint8_t **hash, uint8_t *hash_len);

    /**
     * @brief Parse an Encap DPP TLV
     * 
     * @param encap_tlv [in] The buffer containing the Encap DPP TLV
     * @param encap_tlv_len [in] The length of the Encap DPP TLV
     * @param dest_mac [out] The destination MAC address (0 if not present)
     * @param frame_type [out] The frame type
     * @param encap_frame [out] The encapsulated frame, allocated on the heap
     * @param encap_frame_len [out] The length of the encapsulated frame
     * @return bool true if successful, false otherwise
     * 
     * @warning The `encap_frame` must be freed by the caller
     */
    static bool parse_encap_dpp_tlv(em_encap_dpp_t* encap_tlv, uint16_t encap_tlv_len, mac_addr_t *dest_mac, uint8_t *frame_type, uint8_t** encap_frame, uint8_t *encap_frame_len);

    /**
     * @brief Creates and allocates an Encap DPP TLV
     * 
     * @param dpp_frame_indicator [in] The DPP frame indicator (0 = DPP Public Action frame, 1 = GAS Frame)
     * @param dest_mac [in] The destination MAC address (0 if not present)
     * @param frame_type [in] The frame type
     * @param encap_frame [in] The encapsulated frame
     * @param encap_frame_len [in] The length of the encapsulated frame
     * @return em_encap_dpp_t* The heap allocated Encap DPP TLV, NULL if failed 
     */
    static std::pair<em_encap_dpp_t*, size_t> create_encap_dpp_tlv(bool dpp_frame_indicator, mac_addr_t dest_mac, ec_frame_type_t frame_type, uint8_t *encap_frame, uint8_t encap_frame_len);


    /**
     * @brief Converts a frequency to a WFA channel attribute format (opclass + channel)
     * 
     * @param freq The frequency to convert
     * @return `uint16_t` with the MSB as the op class and the LSB as the channel.
     * 
     * @note Format is standardized as the "Channel Attribute" in Easy Connect 3.0 Section 8.1.1.17 
     */
    static uint16_t freq_to_channel_attr(unsigned int freq);

    
    /**
     * @brief Get the size of an EC attribute
     * 
     * @param data_len The length of the data in the attribute
     * @return size_t The size of the attribute
     */
    static inline size_t get_ec_attr_size(size_t data_len) {
        return offsetof(ec_attribute_t, data) + data_len;
    };

    /**
     * @brief Get the string representation of a status code
     * 
     * @param status The status code to convert
     * @return std::string The string representation of the status code
     */
    static inline std::string status_code_to_string(ec_status_code_t status) {
        return easyconnect::status_code_map.at(status);
    };

    /**
     * @brief Add a wrapped data attribute to a frame
     * 
     * @param frame The frame to use as AAD. Can be NULL if no AAD is needed
     * @param frame_attribs The attributes to add the wrapped data attribute to and to use as AAD
     * @param non_wrapped_len The length of the non-wrapped attributes (`frame_attribs`, In/Out)
     * @param use_aad Whether to use AAD in the encryption
     * @param key The key to use for encryption
     * @param create_wrap_attribs A function to create the attributes to wrap and their length. Memory is handled by function (see note)
     * @return uint8_t* The new frame attributes with the wrapped data attribute added
     * 
     * @note The `create_wrap_attribs` function will allocate heap-memory which is freed inside the `add_wrapped_data_attr` function.
     *     **The caller should not use statically allocated memory in `create_wrap_attribs` or free the memory returned by `create_wrap_attribs`.**
     */
    static uint8_t* add_wrapped_data_attr(ec_frame_t *frame, uint8_t* frame_attribs, uint16_t* non_wrapped_len, 
        bool use_aad, uint8_t* key, std::function<std::pair<uint8_t*, uint16_t>()> create_wrap_attribs);


    /**
     * @brief Unwrap a wrapped data attribute
     * 
     * @param wrapped_attrib The wrapped attribute to unwrap (retreieved using `get_attribute`)
     * @param frame The frame to use as AAD. Can be NULL if no AAD is needed
     * @param uses_aad Whether the wrapped attribute uses AAD
     * @param key The key to use for decryption
     * @return std::pair<uint8_t*, size_t> A heap allocated buffer of unwrapped attributes on success which can then be fetched via `get_attribute`,
     *         along with the length of that buffer. The buffer is NULL and the size is 0 on failure.
     * 
     * @warning The caller is responsible for freeing the memory returned by this function
     */
    static std::pair<uint8_t*, size_t> unwrap_wrapped_attrib(ec_attribute_t* wrapped_attrib, ec_frame_t *frame, bool uses_aad, uint8_t* key);

    /**
     * @brief Convert a hash to a hex string
     * 
     * @param hash The hash to convert
     * @param hash_len The length of the hash
     * @return std::string The hex string representation of the hash
     */
    static std::string hash_to_hex_string(const uint8_t *hash, size_t hash_len);

    /**
     * @brief Check if the capabilities of the initiator and responder are compatible
     * 
     * @param init_caps The capabilities of the initiator
     * @param resp_caps The capabilities of the responder
     * @return true The capabilities are compatible (DPP_STATUS_OK), false otherwise (DPP_STATUS_NOT_COMPATIBLE)
     */
    static bool check_caps_compatible(const ec_dpp_capabilities_t& init_caps, const ec_dpp_capabilities_t& resp_caps);
};