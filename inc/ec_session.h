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
#include <functional>
#include <vector>

#define EC_FRAME_BASE_SIZE (offsetof(ec_frame_t, attributes))

class ec_session_t {
    mac_address_t   m_enrollee_mac;
    unsigned char m_cfgrtr_ver;
    unsigned char m_enrollee_ver;
    ec_params_t    m_params; 
    wifi_activation_status_t    m_activation_status;
    ec_data_t   m_data;

    /**
     * @brief Send a chirp notification to the peer
     * 
     * @param chirp_tlv The chirp TLV to send
     * @param len The length of the chirp TLV
     * @return int 0 if successful, -1 otherwise
     */
    std::function<int(em_dpp_chirp_value_t*, size_t)> m_send_chirp_notification;

    /**
     * @brief Send a proxied encapsulated DPP message
     * 
     * @param encap_dpp_tlv The 1905 Encap DPP TLV to include in the message
     * @param encap_dpp_len The length of the 1905 Encap DPP TLV
     * @param chirp_tlv The chirp value to include in the message. If NULL, the message will not include a chirp value
     * @param chirp_len The length of the chirp value
     * @return int 0 if successful, -1 otherwise
     */
    std::function<int(em_encap_dpp_t*, size_t, em_dpp_chirp_value_t*, size_t)> m_send_prox_encap_dpp_msg;

    /**
     * @brief Compute the hash of the provided key with an optional prefix
     * 
     * @param key The key to hash
     * @param digest The buffer to store the hash
     * @param prefix The optional prefix to add to the key before hashing (NULL by default)
     * @return int The length of the hash
     */
    int compute_key_hash(EC_KEY *key, uint8_t *digest, const char *prefix = NULL);

    /**
     * @brief Handle a presence announcement frame
     * 
     * @param buff The frame to handle
     * @param len The length of the frame
     * @return int 0 if successful, -1 otherwise
     */
    int handle_pres_ann(uint8_t *buff, unsigned int len);


    int compute_intermediate_key(bool is_first);

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
    uint8_t* add_wrapped_data_attr(ec_frame_t *frame, uint8_t* frame_attribs, uint16_t* non_wrapped_len, 
        bool use_aad, uint8_t* key, std::function<std::pair<uint8_t*, uint16_t>()> create_wrap_attribs);
    
    int hkdf(const EVP_MD *h, int skip, uint8_t *ikm, int ikmlen, 
            uint8_t *salt, int saltlen, uint8_t *info, int infolen, 
            uint8_t *okm, int okmlen);

public:
    int init_session(ec_data_t* ec_data);

    /**
     * @brief Create an authentication request `ec_frame_t` with the necessary attributes 
     * 
     * @return std::pair<uint8_t*, uint16_t> The buffer containing the `ec_frame_t` and the length of the frame
     */
    std::pair<uint8_t*, uint16_t> create_auth_request();

    /**
     * @brief Handle a chirp notification TLV and output the authentication request frame (if necessary)
     * 
     * @param chirp_tlv The chirp TLV to parse and handle
     * @param out_frame The buffer to store the output frame (NULL if no frame is needed)
     * @return int 0 if successful, -1 otherwise
     */
    int handle_chirp_notification(em_dpp_chirp_value_t* chirp_tlv, uint8_t **out_frame);

    /**
     * @brief Handle a proxied encapsulated DPP TLV and output the correct frame to send (if necessary)
     * 
     * @param encap_tlv The 1905 Encap DPP TLV to parse and handle
     * @param out_frame The buffer to store the output frame (NULL if no frame is needed)
     * @return int 0 if successful, -1 otherwise
     */
    int handle_proxy_encap_dpp_tlv(em_encap_dpp_t *encap_tlv, uint8_t **out_frame);
    
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
     * @brief Handles DPP action frames directed at this nodes ec_session
     * 
     * @param frame The frame recieved to handle
     * @param len The length of the frame
     * @return int 0 if successful, -1 otherwise
     */
    int handle_recv_ec_action_frame(ec_frame_t* frame, size_t len);

    /**
     * @brief Construct an EC session
     * 
     * @param send_chirp_notification The function to send a chirp notification
     * @param send_prox_encap_dpp_msg The function to send a proxied encapsulated DPP message
     */
    ec_session_t( std::function<int(em_dpp_chirp_value_t*, size_t)> send_chirp_notification,
                   std::function<int(em_encap_dpp_t*, size_t, em_dpp_chirp_value_t*, size_t)> send_prox_encap_dpp_msg);
    ~ec_session_t();
};

#endif
