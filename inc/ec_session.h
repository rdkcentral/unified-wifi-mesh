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
    
    int hkdf(const EVP_MD *h, int skip, uint8_t *ikm, int ikmlen, 
            uint8_t *salt, int saltlen, uint8_t *info, int infolen, 
            uint8_t *okm, int okmlen);

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

    ec_session_t();
    ~ec_session_t();
};

#endif
