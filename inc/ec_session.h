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

#ifndef EC_SESSION_H
#define EC_SESSION_H

#include "em_base.h"
#include "ec_base.h"

#include <type_traits>
#include <map>
#include <string>

#define EC_FRAME_BASE_SIZE (offsetof(ec_frame_t, attributes))

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

class ec_session_t {
    mac_address_t   m_enrollee_mac;
    unsigned char m_cfgrtr_ver;
    unsigned char m_enrollee_ver;
    ec_params_t    m_params; 
    wifi_activation_status_t    m_activation_status;
    ec_data_t   m_data;

    /**
     * @brief Compute the hash of the provided key with an optional prefix
     * 
     * @param key The key to hash
     * @param digest The buffer to store the hash
     * @param prefix The optional prefix to add to the key before hashing (NULL by default)
     * @return int The length of the hash
     */
    int compute_key_hash(EC_KEY *key, uint8_t *digest, const char *prefix = NULL);


    int compute_intermediate_key(bool is_first);
    int set_auth_frame_wrapped_data(ec_frame_t *frame, unsigned int non_wrapped_len, bool do_init_auth);

    
    void init_frame(ec_frame_t *frame);

    /**
     * @brief Get an attribute from the buffer
     * 
     * @param buff The buffer to get the attribute from
     * @param len The length of the buffer to get the attribute from
     * @param id The attribute ID
     * @return ec_attribute_t* The attribute if found, NULL otherwise
     */
    ec_attribute_t *get_attrib(uint8_t *buff, unsigned short len, ec_attrib_id_t id);

    /**
     * @brief Add an attribute to the buffer
     * 
     * @param buff The buffer to add the attribute to
     * @param id The attribute ID
     * @param len The length of the data
     * @param data The attribute data
     * @return uint8_t* The buffer offset by the length of the attribute
     */
    uint8_t *add_attrib(uint8_t *buff, ec_attrib_id_t id, unsigned short len, uint8_t *data);

    /**
     * @brief Add an attribute to the buffer
     * 
     * @param buff The buffer to add the attribute to
     * @param id The attribute ID
     * @param val The uint8_t attribute value
     * @return uint8_t* The buffer offset by the length of the attribute
     */
    inline uint8_t* add_attrib(uint8_t *buff, ec_attrib_id_t id, uint8_t val) {
        return add_attrib(buff, id, sizeof(uint8_t), (uint8_t *)&val);
    }

    /**
     * @brief Add an attribute to the buffer
     * 
     * @param buff The buffer to add the attribute to
     * @param id The attribute ID
     * @param val The uint16_t attribute value
     * @return uint8_t* The buffer offset by the length of the attribute
     */
    inline uint8_t* add_attrib(uint8_t *buff, ec_attrib_id_t id, uint16_t val) {
        return add_attrib(buff, id, sizeof(uint16_t), (uint8_t *)&val);
    }
    
    int hkdf(const EVP_MD *h, int skip, uint8_t *ikm, int ikmlen, 
            uint8_t *salt, int saltlen, uint8_t *info, int infolen, 
            uint8_t *okm, int okmlen);

    bool validate_frame(ec_frame_t *frame, ec_frame_type_t type);


    inline size_t get_ec_attr_size(size_t data_len) {
        return offsetof(ec_attribute_t, data) + data_len;
    }

    unsigned short channel_to_frequency(unsigned int channel);
    unsigned short freq_to_channel(unsigned int freq);  

    void print_bignum (BIGNUM *bn);
    void print_ec_point (const EC_GROUP *group, BN_CTX *bnctx, EC_POINT *point);
    void print_hex_dump(unsigned int length, uint8_t *buffer);

public:
    int init_session(ec_data_t* ec_data);

    /**
     * @brief Create an authentication request frame in a pre-allocated buffer
     * 
     * @param buff The buffer to store the frame
     * @return int The length of the frame
     */
    int create_auth_req(uint8_t *buff);

    /**
     * @brief Handle a chirp notification TLV and output the authentication request frame (if necessary)
     * 
     * @param chirp_tlv The chirp TLV to parse and handle
     * @param out_frame The buffer to store the output frame (NULL if no frame is needed)
     * @return int 0 if successful, -1 otherwise
     */
    int handle_chirp_notification(em_dpp_chirp_value_t* chirp_tlv, uint8_t **out_frame);
    
    /**
     * @brief Create an authentication response frame in a pre-allocated buffer
     * 
     * @param buff The buffer to store the frame
     * @return int The length of the frame
     */
    int create_auth_rsp(uint8_t *buff);
    
    /**
     * @brief Create an authentication confirmation frame in a pre-allocated buffer
     * 
     * @param buff The buffer to store the frame
     * @return int The length of the frame
     */
    int create_auth_cnf(uint8_t *buff);

    /**
     * @brief Create a presence announcement frame in a pre-allocated buffer
     * 
     * @param buff The buffer to store the frame
     * @return int The length of the frame
     */
    int create_pres_ann(uint8_t *buff);

    /**
     * @brief Handle a presence announcement frame
     * 
     * @param buff The frame to handle
     * @param len The length of the frame
     * @return int 0 if successful, -1 otherwise
     */
    int handle_pres_ann(uint8_t *buff, unsigned int len);

    static inline std::string status_code_to_string(ec_status_code_t status) {
        return status_code_map.at(status);
    }

    ec_session_t();
    ~ec_session_t();
};

#endif
