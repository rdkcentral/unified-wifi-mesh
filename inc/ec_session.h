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

#define EC_FRAME_BASE_SIZE (offsetof(ec_frame_t, attributes))

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
    int compute_key_hash(EC_KEY *key, unsigned char *digest, const char *prefix = NULL);


    int compute_intermediate_key(bool is_first);
    int set_auth_frame_wrapped_data(ec_frame_t *frame, unsigned int non_wrapped_len, bool do_init_auth);

    /**
     * @brief Get the responder boot key object
     *      If the provided buffer is NULL, a local buffer is used and discarded after use
     * 
     * @param asn1_key The responder boot key in ASN1 format
     * @param asn1_len The length of the responder boot key (initial value is the size of the buffer)
     * @return EC_KEY* The responder boot key in OpenSSL format
     */
    EC_KEY  *get_responder_boot_key(unsigned char *asn1_key, unsigned int* asn1_len);

    /**
     * @brief Get the responder boot key object without the ASN1 format key
     * 
     * @return EC_KEY* The responder boot key in OpenSSL format
     */
    EC_KEY  *get_responder_boot_key() { return get_responder_boot_key(NULL, NULL); }

    /**
     * @brief Get the initiator boot key object.
     *      If the provided buffer is NULL, a local buffer is used and discarded after use
     * 
     * @param key The initiator boot key in ASN1 format
     * @param len The length of the initiator boot key (initial value is the size of the buffer)
     * @return EC_KEY* The initiator boot key in OpenSSL format
     */
    EC_KEY  *get_initiator_boot_key(unsigned char *asn1_key, unsigned int* asn1_len);  

    /**
     * @brief Get the initiator boot key object without the ASN1 format key
     * 
     * @return EC_KEY* The initiator boot key in OpenSSL format
     */
    EC_KEY  *get_initiator_boot_key() { return get_initiator_boot_key(NULL, NULL); } 
    
    /**
     * @brief Get an attribute from the buffer
     * 
     * @param buff The buffer to get the attribute from
     * @param len The length of the buffer to get the attribute from
     * @param id The attribute ID
     * @return ec_attribute_t* The attribute if found, NULL otherwise
     */
    ec_attribute_t *get_attrib(unsigned char *buff, unsigned short len, ec_attrib_id_t id);

    /**
     * @brief Add an attribute to the buffer
     * 
     * @param buff The buffer to add the attribute to
     * @param id The attribute ID
     * @param len The length of the data
     * @param data The attribute data
     * @return uint8_t* The buffer offset by the length of the attribute
     */
    uint8_t *add_attrib(unsigned char *buff, ec_attrib_id_t id, unsigned short len, unsigned char *data);

    /**
     * @brief Add an attribute to the buffer
     * 
     * @param buff The buffer to add the attribute to
     * @param id The attribute ID
     * @param val The uint8_t attribute value
     * @return uint8_t* The buffer offset by the length of the attribute
     */
    inline uint8_t* add_attrib(unsigned char *buff, ec_attrib_id_t id, uint8_t val) {
        return add_attrib(buff, id, sizeof(uint8_t), (unsigned char *)&val);
    }

    /**
     * @brief Add an attribute to the buffer
     * 
     * @param buff The buffer to add the attribute to
     * @param id The attribute ID
     * @param val The uint16_t attribute value
     * @return uint8_t* The buffer offset by the length of the attribute
     */
    inline uint8_t* add_attrib(unsigned char *buff, ec_attrib_id_t id, uint16_t val) {
        return add_attrib(buff, id, sizeof(uint16_t), (unsigned char *)&val);
    }
    
    int hkdf(const EVP_MD *h, int skip, unsigned char *ikm, int ikmlen, 
            unsigned char *salt, int saltlen, unsigned char *info, int infolen, 
            unsigned char *okm, int okmlen);

    bool validate_frame(ec_frame_t *frame, ec_frame_type_t type);


    inline size_t get_ec_attr_size(size_t data_len) {
        return offsetof(ec_attribute_t, data) + data_len;
    }

    unsigned short channel_to_frequency(unsigned int channel);
    unsigned short freq_to_channel(unsigned int freq);  

    void print_bignum (BIGNUM *bn);
    void print_ec_point (const EC_GROUP *group, BN_CTX *bnctx, EC_POINT *point);
    void print_hex_dump(unsigned int length, unsigned char *buffer);

public:
    int init_session(ec_data_t* ec_data);

    /**
     * @brief Create an authentication request frame in a pre-allocated buffer
     * 
     * @param buff The buffer to store the frame
     * @return int The length of the frame
     */
    int create_auth_req(unsigned char *buff);
    
    /**
     * @brief Create an authentication response frame in a pre-allocated buffer
     * 
     * @param buff The buffer to store the frame
     * @return int The length of the frame
     */
    int create_auth_rsp(unsigned char *buff);
    
    /**
     * @brief Create an authentication confirmation frame in a pre-allocated buffer
     * 
     * @param buff The buffer to store the frame
     * @return int The length of the frame
     */
    int create_auth_cnf(unsigned char *buff);

    /**
     * @brief Create a presence announcement frame in a pre-allocated buffer
     * 
     * @param buff The buffer to store the frame
     * @return int The length of the frame
     */
    int create_pres_ann(unsigned char *buff);

    /**
     * @brief Handle a presence announcement frame
     * 
     * @param buff The frame to handle
     * @param len The length of the frame
     * @return int 0 if successful, -1 otherwise
     */
    int handle_pres_ann(unsigned char *buff, unsigned int len);

    ec_session_t();
    ~ec_session_t();
};

#endif
