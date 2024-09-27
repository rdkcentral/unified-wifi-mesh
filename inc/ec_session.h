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

class ec_session_t {
    mac_address_t   m_enrollee_mac;
    unsigned char m_cfgrtr_ver;
    unsigned char m_enrollee_ver;
    ec_params_t    m_params;
    ec_data_t   m_data;
    wifi_activation_status_t    m_activation_status;

    int compute_key_hash(EC_KEY *key, unsigned char *digest);
    int compute_intermediate_key(bool first);
    int set_auth_frame_wrapped_data(ec_frame_body_t *frame, unsigned int non_wrapped_len, bool auth_init);
    EC_KEY  *get_responder_boot_key(unsigned char *key, unsigned int len);
    EC_KEY  *get_initiator_boot_key(unsigned char *key, unsigned int len);  
    
    unsigned short channel_to_frequency(unsigned int channel);
    unsigned short freq_to_channel(unsigned int freq);  
    
    ec_tlv_t *get_tlv(unsigned char *buff, ec_attrib_id_t id, unsigned short len);
    ec_tlv_t *set_tlv(unsigned char *buff, ec_attrib_id_t id, unsigned short len, unsigned char *val);
    
    int hkdf(const EVP_MD *h, int skip, unsigned char *ikm, int ikmlen, 
            unsigned char *salt, int saltlen, unsigned char *info, int infolen, 
            unsigned char *okm, int okmlen);

    void prepare_frame(ec_frame_t *frame, ec_frame_type_t type);
    bool validate_frame(ec_frame_t *frame, ec_frame_type_t type);


    void print_bignum (BIGNUM *bn);
    void print_ec_point (const EC_GROUP *group, BN_CTX *bnctx, EC_POINT *point);
    void print_hex_dump(unsigned int length, unsigned char *buffer);

public:
    int init_session();

    int create_auth_req(unsigned char *buff);
    int create_auth_rsp(unsigned char *buff);
    int create_auth_cnf(unsigned char *buff);
    int create_pres_ann(unsigned char *buff);

    int handle_pres_ann(unsigned char *buff, unsigned int len);

    ec_session_t(ec_data_t *data);
    ~ec_session_t();
};

#endif
