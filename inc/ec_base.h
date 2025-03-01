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

/*
 * NOTE: This file is included also in OneWifi project which is C based, thus
 * there should be only usage of C based constructs in this file.
 * C++ constructs are not allowed in this file.
 */

#ifndef EC_BASE_H
#define EC_BASE_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/pem.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#include "wifi_webconfig.h"

#define DPP_OUI_TYPE 0x1A
#define DPP_MAX_EN_CHANNELS 4
static const uint8_t WFA_DPP_OUI[3] = {0x50, 0x6F, 0x9A};

// As defined by EasyConnect 8.2.1 Table 35
typedef enum  {
    ec_frame_type_auth_req = 0,
    ec_frame_type_auth_rsp,
    ec_frame_type_auth_cnf,
    // 3 : Reserved
    // 4 : Reserved
    ec_frame_type_peer_disc_req = 5,
    ec_frame_type_peer_disc_rsp,
    ec_frame_type_pkex_v1_req,
    ec_frame_type_pkex_rsp,
    ec_frame_type_pkex_commit_rev_req,
    ec_frame_type_pkex_commit_rev_rsp,
    ec_frame_type_cfg_result,
    ec_frame_type_conn_status_result,
    ec_frame_type_presence_announcement,
    ec_frame_type_recfg_announcement,
    ec_frame_type_recfg_auth_req,
    ec_frame_type_recfg_auth_rsp,
    ec_frame_type_recfg_auth_cnf,
    ec_frame_type_pkex_exch_req,
    ec_frame_type_push_btn_presence_announcement,
    ec_frame_type_push_btn_presence_announcement_resp,
    ec_frame_type_private_peer_intro_query,
    ec_frame_type_private_peer_intro_notify,
    ec_frame_type_private_peer_intro_update,
    // 24-255 : Reserved
} ec_frame_type_t;

// As defined by EasyConnect 8.1 Table 29
typedef enum {
    // 0x000 - 0x0FFF : Reserved
    ec_attrib_id_dpp_status = 0x1000,
    ec_attrib_id_init_bootstrap_key_hash,
    ec_attrib_id_resp_bootstrap_key_hash,
    ec_attrib_id_init_proto_key,
    ec_attrib_id_wrapped_data,
    ec_attrib_id_init_nonce,
    ec_attrib_id_init_caps,
    ec_attrib_id_resp_nonce,
    ec_attrib_id_resp_caps,
    ec_attrib_id_resp_proto_key,
    ec_attrib_id_init_auth_tag,
    ec_attrib_id_resp_auth_tag,
    ec_attrib_id_dpp_config_obj,
    ec_attrib_id_dpp_connector,
    ec_attrib_id_dpp_config_req_obj,
    ec_attrib_id_bootstrap_key,
    // 0x1010 - 0x1011 : Reserved
    ec_attrib_id_finite_cyclic_group = 0x1012,
    ec_attrib_id_enc_key,
    ec_attrib_id_enrollee_nonce,
    ec_attrib_id_code_identifier,
    ec_attrib_id_trans_id,
    ec_attrib_id_bootstrap_info,
    ec_attrib_id_channel,
    ec_attrib_id_proto_version,
    ec_attrib_id_dpp_enveloped_data,
    ec_attrib_id_send_conn_status,
    ec_attrib_id_conn_status,
    ec_attrib_id_reconfig_flags,
    ec_attrib_id_C_sign_key_hash,
    ec_attrib_id_csr_attrs_req,
    ec_attrib_id_a_nonce,
    ec_attrib_id_e_prime_id, // E'-Id (Enrollee)
    ec_attrib_id_config_nonce,
    // 0x1023 - 0xFFFF : Reserved
} ec_attrib_id_t;

// As defined by EasyConnect 8.3.4 Table 64
typedef enum {
    DPP_STATUS_OK = 0,
    DPP_STATUS_NOT_COMPATIBLE,
    DPP_STATUS_AUTH_FAILURE,
    DPP_STATUS_BAD_CODE,
    DPP_STATUS_BAD_GROUP,
    DPP_STATUS_CONFIGURATION_FAILURE,
    DPP_STATUS_RESPONSE_PENDING,
    DPP_STATUS_INVALID_CONNECTOR,
    DPP_STATUS_NO_MATCH,
    DPP_STATUS_CONFIG_REJECTED,
    DPP_STATUS_NO_AP_DISCOVERED,
    DPP_STATUS_CONFIGURE_PENDING,
    DPP_STATUS_CSR_NEEDED,
    DPP_STATUS_CSR_BAD,
    DPP_STATUS_NEW_KEY_NEEDED,
} ec_status_code_t;

// Used to concisely represent the capabilities of a device while allowing for easy access to the uint8_t value
typedef union {
    struct {
        uint8_t enrollee : 1;    // Bit 0
        uint8_t configurator : 1; // Bit 1
        uint8_t reserved : 6;   // Bits 2-7
    } __attribute__((packed));  // Anonymous struct
    uint8_t byte;
} ec_dpp_capabilities_t;

typedef union {
    struct {
        /**
         * 0 (CONFIG_REUSEKEY)   : The enrollee shall retain and reuse the same public/private key associated
         *                               with the Connector it sent in the Reconfiguration Authentication Response frame
         * 1 (CONFIG_REPLACEKEY) : The enrollee shall discard the original 
         */
        uint8_t connector_key : 1;    // Bit 0
        uint8_t reserved : 7;   // Bits 1-7
    } __attribute__((packed));
    uint8_t byte; // Used to access the entire byte
}  ec_dpp_reconfig_flags_t;


typedef enum {
    EC_TECH_INFRA
} ec_technology_t;

typedef enum {
    EC_KEY_MGMT_PSK,
    EC_KEY_MGMT_DPP,
    EC_KEY_MGMT_SAE,
    EC_KEY_MGMT_PSKSAE,
    EC_KEY_MGMT_DPPPSKSAE
} ec_key_management_t;

typedef struct {
      ec_key_management_t keyManagement;
      union {
          unsigned char    preSharedKey[128];
          char    passPhrase[64];
      } creds;
} ec_credential_object_t;

typedef struct {
    uint16_t attr_id;
    uint16_t length;
    uint8_t data[0];
}__attribute__((packed)) ec_attribute_t;

typedef struct {
    uint8_t category;
    uint8_t action;
    uint8_t oui[3];
    uint8_t oui_type;
    uint8_t crypto_suite;
    uint8_t frame_type;
    uint8_t attributes[0];
} __attribute__((packed)) ec_frame_t;

typedef enum {
    ec_session_type_cfg,
    ec_session_type_recfg,
} ec_session_type_t;

typedef struct {
    const EC_GROUP *group;
    const EVP_MD *hashfcn;
    BIGNUM *x, *y, *prime;
    BIGNUM *m, *n, *l;
    EC_POINT *M, *N;
    BN_CTX *bnctx;
    EC_KEY *initiator_proto_key;
    EC_KEY *responder_proto_key;
    EC_POINT     *responder_proto_pt;
    EC_POINT     *responder_connector;
    int group_num;
    int digestlen;
    int noncelen;
    int nid;
    bool mutual;
    unsigned char initiator_keyhash[SHA512_DIGEST_LENGTH];
    unsigned char responder_keyhash[SHA512_DIGEST_LENGTH];
    unsigned char initiator_nonce[SHA512_DIGEST_LENGTH/2];
    unsigned char responder_nonce[SHA512_DIGEST_LENGTH/2];
    unsigned char enrollee_nonce[SHA512_DIGEST_LENGTH/2];
    unsigned char k1[SHA512_DIGEST_LENGTH];
    unsigned char k2[SHA512_DIGEST_LENGTH];
    unsigned char ke[SHA512_DIGEST_LENGTH];
    unsigned char rauth[SHA512_DIGEST_LENGTH];
    unsigned char iauth[SHA512_DIGEST_LENGTH];
} ec_params_t;

typedef struct {

    // Baseline static, DPP URI data
    unsigned int version;
    int  ec_freqs[DPP_MAX_EN_CHANNELS];
    mac_address_t   mac_addr;
    ec_session_type_t   type;

    // Updated data
    EC_KEY *initiator_boot_key; 
    EC_KEY *responder_boot_key;
} ec_data_t;

#ifdef __cplusplus
}
#endif

#endif // EC_BASE_H
