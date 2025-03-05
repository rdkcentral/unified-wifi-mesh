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

#include <map>
#include <string>
#include <functional>

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

}

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
     * @brief Converts a frequency to a WFA channel attribute format (opclass + channel)
     * 
     * @param freq The frequency to convert
     * @return `uint16_t` with the MSB as the op class and the LSB as the channel.
     * 
     * @note Format is standardized as the "Channel Attribute" in Easy Connect 3.0 Section 8.1.1.17 
     */
    static uint16_t freq_to_channel_attr(unsigned int freq);

    static void print_bignum (BIGNUM *bn);
    static void print_ec_point (const EC_GROUP *group, BN_CTX *bnctx, EC_POINT *point);

    static inline size_t get_ec_attr_size(size_t data_len) {
        return offsetof(ec_attribute_t, data) + data_len;
    };

    static inline std::string status_code_to_string(ec_status_code_t status) {
        return easyconnect::status_code_map.at(status);
    };

    static int hkdf(const EVP_MD *h, int skip, uint8_t *ikm, int ikmlen, 
        uint8_t *salt, int saltlen, uint8_t *info, int infolen, 
        uint8_t *okm, int okmlen);


    // static int compute_intermediate_key(ec_params_t& params, bool is_first);

    // /**
    //  * @brief Compute the hash of the provided key with an optional prefix
    //  * 
    //  * @param key The key to hash
    //  * @param digest The buffer to store the hash
    //  * @param prefix The optional prefix to add to the key before hashing (NULL by default)
    //  * @return int The length of the hash
    //  */
    // static int compute_key_hash(ec_params_t& params, EC_KEY *key, uint8_t *digest, const char *prefix = NULL);

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

    static inline void rand_zero_free(uint8_t *buff, size_t len) {
        if (buff == NULL) return;
        RAND_bytes(buff, len);
        memset(buff, 0, len);
        free(buff);
    }

    /**
     * @brief Free an ephemeral context by randomizing, zeroing, and freeing all memory
     * 
     * @param ctx The ephemeral context to free
     * @param nonce_len The length of the nonces in the context
     * @param digest_len The length of the digests/keys in the context
     */
    static inline void free_ephemeral_context(ec_ephemeral_context_t* ctx, int nonce_len, int digest_len) {

        if (ctx->protocol_key) EC_KEY_free(ctx->protocol_key);
        if (ctx->E_Id) EC_POINT_free(ctx->E_Id);
        if (ctx->i_nonce) rand_zero_free(ctx->i_nonce, nonce_len);
        if (ctx->r_nonce) rand_zero_free(ctx->r_nonce, nonce_len);
        if (ctx->e_nonce) rand_zero_free(ctx->e_nonce, nonce_len);
        if (ctx->c_nonce) rand_zero_free(ctx->c_nonce, nonce_len);
        if (ctx->k1) rand_zero_free(ctx->k1, digest_len);
        if (ctx->k2) rand_zero_free(ctx->k2, digest_len);
        if (ctx->ke) rand_zero_free(ctx->ke, digest_len);
        if (ctx->bk) rand_zero_free(ctx->bk, digest_len);

        rand_zero_free((uint8_t *)ctx, sizeof(ec_ephemeral_context_t));
    }
};