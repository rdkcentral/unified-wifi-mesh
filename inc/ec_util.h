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
    static ec_attribute_t *get_attrib(uint8_t *buff, size_t len, ec_attrib_id_t id);

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
    static uint8_t *add_attrib(uint8_t *buff, size_t* buff_len, ec_attrib_id_t id, uint16_t len, uint8_t *data);


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
    static inline uint8_t *add_attrib(uint8_t *buff, size_t* buff_len, ec_attrib_id_t id, uint16_t len, const scoped_buff& data) {
        return add_attrib(buff, buff_len, id, len, data.get());
    }

    /**
     * @brief Add an attribute to the buffer, (re)allocating the buffer if necessary
     * 
     * @param buff The buffer to add the attribute to
     * @param buff_len The length of the buffer (in/out)
     * @param id The attribute ID
     * @param str The attribute as a string
     * @return uint8_t* The buffer offset by the length of the attribute
     * 
     * @warning The buffer must be freed by the caller
     */
    static inline uint8_t *add_attrib(uint8_t *buff, size_t* buff_len, ec_attrib_id_t id, std::string str) {
        return add_attrib(buff, buff_len, id, static_cast<uint16_t>(str.length()), const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(str.c_str())));
    }

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
    static inline uint8_t* add_attrib(uint8_t *buff, size_t* buff_len, ec_attrib_id_t id, uint8_t val) {
        return add_attrib(buff, buff_len, id, sizeof(uint8_t), const_cast<uint8_t*>(&val));
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
    static inline uint8_t* add_attrib(uint8_t *buff, size_t* buff_len, ec_attrib_id_t id, uint16_t val) {
        return add_attrib(buff, buff_len, id, sizeof(uint16_t), const_cast<uint8_t*>(reinterpret_cast<uint8_t*>(&val)));
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
     * @brief Copy (overrride) attributes to a frame
     * 
     * @param frame The frame to copy the attributes to
     * @param attrs The attributes to copy
     * @param attrs_len The length of the attributes
     * @return ec_frame_t* The frame with the copied attributes (returned due to realloc)
     * 
     * @warning The frame must be freed by the caller
     */
    static ec_frame_t* copy_attrs_to_frame(ec_frame_t *frame, uint8_t *attrs, size_t attrs_len);

    /**
     * @brief Copy (over-write) attributes to a frame
     * 
     * @param frame The frame to copy the attribues to
     * @param frame_base_size The offset at which to copy attributes to
     * @param attrs The attributes to copy
     * @param attrs_len The length of the attributes
     * @return uint8_t *, base of the frame with newly copied attributes, or nullptr on failure
     */
    static uint8_t* copy_attrs_to_frame(uint8_t *frame, size_t frame_base_size, uint8_t *attrs, size_t attrs_len);

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
     * @brief Parse a DPP Chirp Value TLV
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
     * @brief Creates and allocates a DPP Chirp Value TLV
     * 
     * EasyMesh R6, Section 17.2.83, Table 105
     * 
     * @param mac_present [in] The address of the Enrollee Multi-AP Agent 
     * @param hash_validity [in] Establish/purge any DPP authentication state pertaining to the hash value in this TLV (0 = purge, 1 = establish)
     * @param dest_mac [in] The destination mac address (0 if not present)
     * @return em_dpp_chirp_value_t* The heap allocated DPP Chirp Value TLV, NULL if failed
     * 
     * @warning The `em_dpp_chirp_value_t` must be freed by the caller
     */
    static std::pair<em_dpp_chirp_value_t*, uint16_t> create_dpp_chirp_tlv(bool mac_present, bool hash_validity, mac_addr_t dest_mac);

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
    static bool parse_encap_dpp_tlv(em_encap_dpp_t* encap_tlv, uint16_t encap_tlv_len, mac_addr_t *dest_mac, uint8_t *frame_type, uint8_t** encap_frame, uint16_t *encap_frame_len);

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
    static std::pair<em_encap_dpp_t*, uint16_t> create_encap_dpp_tlv(bool dpp_frame_indicator, mac_addr_t dest_mac, ec_frame_type_t frame_type, uint8_t *encap_frame, size_t encap_frame_len);


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
    static inline size_t get_ec_attr_size(uint16_t data_len) {
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
    static uint8_t* add_wrapped_data_attr(ec_frame_t *frame, uint8_t* frame_attribs, size_t* non_wrapped_len, 
        bool use_aad, uint8_t* key, std::function<std::pair<uint8_t*, uint16_t>()> create_wrap_attribs);

    static uint8_t* add_wrapped_data_attr(uint8_t *frame, size_t frame_len, uint8_t* frame_attribs, size_t* non_wrapped_len, 
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
     * @note Forwards to `unwrap_wrapped_attrib(ec_attribute_t *wrapped_attrib, uint8_t *frame, size_t frame_len, uint8_t *frame_attribs, bool uses_aad, uint8_t *key);`
     */
    static std::pair<uint8_t*, uint16_t> unwrap_wrapped_attrib(ec_attribute_t* wrapped_attrib, ec_frame_t *frame, bool uses_aad, uint8_t* key);

    /**
     * @brief Unwrap a wrapped data attribute.
     *
     * @param wrapped_attrib The wrapped attribute to unwrap (retrieved using `get_attribute`)
     * @param frame The frame to use as AAD. Can be nullptr if `uses_aad` is false.
     * @param frame_len The length of the frame.
     * @param frame_attribs Pointer to the attributes to unwrap.
     * @param uses_aad Whether the wrapped attribute uses AAD.
     * @param key The key to use for decryption.
     * @return std::pair<uint8_t*, uint16_t> The unwrapped attributes / size on success, nullptr & 0 otherwise.
     */
    static std::pair<uint8_t*, uint16_t> unwrap_wrapped_attrib(ec_attribute_t *wrapped_attrib, uint8_t *frame, size_t frame_len, uint8_t *frame_attribs, bool uses_aad, uint8_t *key);

    /**
     * @brief Convert a hash to a hex string
     * 
     * @param hash The hash to convert
     * @param hash_len The length of the hash
     * @return std::string The hex string representation of the hash
     */
    static std::string hash_to_hex_string(const uint8_t *hash, size_t hash_len);

    /**
     * @brief Convert a hash to a hex string
     * 
     * @param hash Vector containing the hash to convert.
     * @return std::string  The hex string representation of the hash
     */
    static std::string hash_to_hex_string(const std::vector<uint8_t>& hash);

    // Used for storing channels / op-classes searched when looking for a given SSID.
    struct scanned_channels_t {
        uint32_t chan;
        uint32_t opclass;
    };

    /**
     * @brief Generate an EasyConnect `channel-list-2` formatted channel list from a map of scanned (EasyConnect 6.4.5.2)
     * 
     * @param ssid The SSID to build the searched channel list for.
     * @param scanned_channels_map SSID searched for -> channels / op-classes searched.
     * @return std::string Channel list as a string, example: "81/1,6,11,117/40,115/48"
     */
    static std::string generate_channel_list(const std::string& ssid, std::unordered_map<std::string, std::vector<scanned_channels_t>> scanned_channels_map);

    /**
     * @brief Check if the capabilities of the initiator and responder are compatible
     * 
     * @param init_caps The capabilities of the initiator
     * @param resp_caps The capabilities of the responder
     * @return true The capabilities are compatible (DPP_STATUS_OK), false otherwise (DPP_STATUS_NOT_COMPATIBLE)
     */
    static bool check_caps_compatible(const ec_dpp_capabilities_t& init_caps, const ec_dpp_capabilities_t& resp_caps);

    static inline void free_connection_ctx(ec_connection_context_t& c_ctx) {
        ec_crypto::free_ephemeral_context(&c_ctx.eph_ctx, c_ctx.nonce_len, c_ctx.digest_len);

        auto boot_data = &c_ctx.boot_data;
        if (boot_data->resp_priv_boot_key) {
            BN_free(boot_data->resp_priv_boot_key);
        }
        if (boot_data->resp_pub_boot_key) {
            EC_POINT_free(boot_data->resp_pub_boot_key);
        }
        if (boot_data->init_priv_boot_key) {
            BN_free(boot_data->init_priv_boot_key);
        }
        if (boot_data->init_pub_boot_key) {
            EC_POINT_free(boot_data->init_pub_boot_key);
        }
        if (boot_data->initiator_boot_key) {
            em_crypto_t::free_key(const_cast<SSL_KEY*>(boot_data->initiator_boot_key));
        }
        if (boot_data->responder_boot_key) {
            em_crypto_t::free_key(const_cast<SSL_KEY*>(boot_data->responder_boot_key));
        }

        boot_data->resp_priv_boot_key = nullptr;
        boot_data->resp_pub_boot_key = nullptr;
        boot_data->init_priv_boot_key = nullptr;
        boot_data->init_pub_boot_key = nullptr;
        boot_data->initiator_boot_key = nullptr;
        boot_data->responder_boot_key = nullptr;
    }
};

#endif // _EC_UTIL_H_