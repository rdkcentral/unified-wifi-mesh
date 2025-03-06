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

#define DPP_GAS_INITIAL_REQ 0x0A
#define DPP_GAS_INITIAL_RESP 0x0B

#define APEFMT "%02x,%02x,%02x"
#define APE2STR(x) (x[0], x[1], x[2])
#define APEIDFMT "%02x,%02x,%02x,%02x,%02x,%02x,%02x"
#define APEID2STR(x) (x[0], x[1], x[2], x[3], x[4], x[5], x[6])
#define MACSTRFMT "%02x:%02x:%02x:%02x:%02x"
#define MAC2STR(x) (x[0], x[1], x[2], x[3], x[4], x[5])

// EasyConnect 8.3.2
static const uint8_t DPP_GAS_CONFIG_REQ_APE[3] = {0x6c, 0x08, 0x00};
static const uint8_t DPP_GAS_CONFIG_REQ_PROTO_ID[7] = {0xDD, 0x05, 0x50, 0x6F, 0x9A ,0x1A, 0x01};

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

typedef enum {
   dpp_gas_initial_req = 0x0A,
   dpp_gas_initial_resp = 0x0B,
   dpp_gas_comeback_req = 0x0C,
   dpp_gas_comeback_resp = 0x0D,
} dpp_gas_action_type_t;

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

typedef struct {
    uint8_t category;
    uint8_t action;
    uint8_t dialog_token;
} __attribute__((packed)) ec_gas_frame_base_t;

typedef struct {
    uint8_t ape[3];
    uint8_t ape_id[7];
    uint16_t query_len;
    uint8_t query[];
} ec_gas_initial_request_frame_t;

typedef struct {
    uint16_t status_code;
    uint16_t gas_comeback_delay;
    uint8_t ape[3];
    uint8_t ape_id[7];
    uint16_t resp_len;
    uint8_t resp[];
} ec_gas_initial_response_frame_t;

// Used to avoid many many if-not-null checks
#define ASSERT_FALSE(x, ret, errMsg, ...) \
    if(x) { \
        fprintf(stderr, errMsg, ## __VA_ARGS__); \
        return ret; \
    }

#define ASSERT_TRUE(x, ret, errMsg, ...) ASSERT_FALSE(!(x), ret, errMsg, ## __VA_ARGS__)
#define ASSERT_NOT_NULL(x, ret, errMsg, ...) ASSERT_FALSE(x == NULL, ret, errMsg, ## __VA_ARGS__)

/**
 * @brief Asserts that a pointer is not NULL, and if it is, frees up to 3 pointers and returns a value
 * @param x The pointer to check for NULL
 * @param ret The value to return if x is NULL
 * @param ptr1 First pointer to free (can be NULL)
 * @param ptr2 Second pointer to free (can be NULL) 
 * @param ptr3 Third pointer to free (can be NULL)
 * @param errMsg Format string for error message
 * @param ... Additional arguments for the format string
 */
#define ASSERT_NOT_NULL_FREE3(x, ret, ptr1, ptr2, ptr3, errMsg, ...) \
    if(x == NULL) { \
        fprintf(stderr, errMsg, ## __VA_ARGS__); \
        if (ptr1) free(ptr1); \
        if (ptr2) free(ptr2); \
        if (ptr3) free(ptr3); \
        return ret; \
    }

/**
 * @brief Asserts that a pointer is not NULL, and if it is, frees up to 2 pointers and returns a value
 */
#define ASSERT_NOT_NULL_FREE2(x, ret, ptr1, ptr2, errMsg, ...) \
    ASSERT_NOT_NULL_FREE3(x, ret, ptr1, ptr2, NULL, errMsg, ## __VA_ARGS__)

/**
 * @brief Asserts that a pointer is not NULL, and if it is, frees one pointer and returns a value
 */
#define ASSERT_NOT_NULL_FREE(x, ret, ptr1, errMsg, ...) \
    ASSERT_NOT_NULL_FREE2(x, ret, ptr1, NULL, errMsg, ## __VA_ARGS__)


#define ASSERT_NULL(x, ret, errMsg, ...) ASSERT_TRUE(x == 0, ret, errMsg, ## __VA_ARGS__)
#define ASSERT_EQUALS(x, y, ret, errMsg, ...) ASSERT_TRUE(x == y, ret, errMsg, ## __VA_ARGS__)
#define ASSERT_NOT_EQUALS(x, y, ret, errMsg, ...) ASSERT_FALSE(x == y, ret, errMsg, ## __VA_ARGS__)



typedef enum {
    ec_session_type_cfg,
    ec_session_type_recfg,
} ec_session_type_t;

/**
 * @brief The consistent parameters used for all connections between a Configurator and all Enrollees/Agents
 */
typedef struct {
    const EC_GROUP *group;
    const EVP_MD *hash_fcn;
    BIGNUM *prime;
    BN_CTX *bn_ctx;
    int digest_len;
    int nonce_len;
    int nid;


} ec_persistent_context_t;

/**
 * @brief The parameters used only during the creation of a connection between a Configurator and a specific Enrollee/Agent
 */
typedef struct {

    /**
     * Initiator, Responder, Enrollee, and Configurator Nonces.
     * Multiple nonces need to be accounted for at one time.
     * These are heap allocated but freed after the auth/cfg process is complete.
     */
    uint8_t *i_nonce, *r_nonce, *e_nonce, *c_nonce;

    /**
     * The protocol key pairs for the initiator and responder. These are are exchanged/generated during the auth/cfg process.
     * This must be freed after the auth/cfg process is complete.
     * 
     * P_I, P_R
     */
    EC_POINT *public_init_proto_key, *public_resp_proto_key;

    /**
     * The private protocol keys for the initiator and responder. These are used to generate the shared secret.
     * These are heap allocated but freed after the auth/cfg process is complete.
     * 
     * p_I, p_R
     */
    BIGNUM *priv_init_proto_key, *priv_resp_proto_key;

    /**
     * The generated intermediate keys. These are used multiple times during the auth/cfg process.
     * These are heap allocated but freed after the auth/cfg process is complete.
     */
    uint8_t *k1, *k2, *ke, *bk;

    /**
     * The EC x coordinate values for the M, N, and (optional) L points.
     * Once generated, these are used multiple times during the auth/cfg process.
     */
    BIGNUM *m, *n, *l;

    /**
     * A random point on the curve for reconfiguration. The same point is used throughout reconfiguration.
     * Used from the configurator/controller end as short term memory of which enrollee's it's seen before.
     * Used by the enrollee to provide that short term memory to the controller.
     * This must be freed after the reconfiguration process is complete.
     */
    EC_POINT *E_Id;

    uint8_t transaction_id;

    /**
     * Only needs to be known during the auth process to decide wether or not to generate the L key.
     */
    bool is_mutual_auth;

} ec_ephemeral_context_t;

/**
 * @brief The parameters used for a specific connection between a Configurator and a specific Enrollee/Agent
 */
typedef struct {
    /*
        The protocol key of the Enrollee is used as Network Access key (netAccessKey) later in the DPP Configuration and DPP Introduction protocol
    */  
    EC_KEY *net_access_key;

    /* TODO: 
    Add (if needed):
        - C-connector
        - c-sign-key
        - privacy-protection-key (ppk)

    */

    ec_ephemeral_context_t eph_ctx;
} ec_connection_context_t;



/*
REMOVED:
    -k1, k2, ke. These are only generated once per device per authentication session (and it should be that way)
        unsigned char responder_nonce[SHA512_DIGEST_LENGTH/2];
    unsigned char enrollee_nonce[SHA512_DIGEST_LENGTH/2];
*/

typedef struct {

    // Baseline static, DPP URI data
    unsigned int version;
    int  ec_freqs[DPP_MAX_EN_CHANNELS];
    mac_address_t   mac_addr;
    ec_session_type_t   type;

    /*
    Initiator/Configurator bootstrapping key. (ALWAYS REQUIRED on controller, OPTIONAL on enrollee)
        - If this is the Controller, then this key is stored on the Controller. 
        - If this is the Enrollee, then this key is required for "mutual authentication" and must be recieved via an out-of-band mechanism from the controller.
    */
    const EC_KEY *initiator_boot_key; 
    /*
    Responder/Enrollee bootstrapping key. (REQUIRED)
        - If this is the Controller, then this key was recieved out-of-band from the Enrollee in the DPP URI
        - If this is the Enrollee, then this key is stored locally.
    */
    const EC_KEY *responder_boot_key;
} ec_data_t;

#ifdef __cplusplus
}
#endif

#endif // EC_BASE_H
