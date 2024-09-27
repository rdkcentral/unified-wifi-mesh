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

#ifndef EC_BASE_H
#define EC_BASE_H

#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/pem.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#define DPP_OUI_TYPE 0x1A

typedef enum {
    ec_frame_type_auth_req,
    ec_frame_type_auth_rsp,
    ec_frame_type_auth_cnf,
    ec_frame_type_reserved_1,
    ec_frame_type_reserved_2,
    ec_frame_type_peer_disc_req,
    ec_frame_type_peer_disc_rsp,
    ec_frame_type_pkex_req,
    ec_frame_type_pkex_rsp,
    ec_frame_type_pkex_rev_req,
    ec_frame_type_pkex_rev_rsp,
    ec_frame_type_cfg_result,
    ec_frame_type_conn_status_result,
    ec_frame_type_presence_announcement,
    ec_frame_type_recfg_announcement,
    ec_frame_type_recfg_auth_req,
    ec_frame_type_recfg_auth_rsp,
    ec_frame_type_recfg_auth_cnf,
} ec_frame_type_t;

typedef enum {
    ec_attrib_id_status   =   0x1000,
    ec_attrib_id_initiator_boot_hash,
    ec_attrib_id_responder_boot_hash,
    ec_attrib_id_initiator_protocol_key,
    ec_attrib_id_wrapped_data,
    ec_attrib_id_initiator_nonce,
    ec_attrib_id_initiator_cap,
    ec_attrib_id_responder_nonce,
    ec_attrib_id_responder_cap,
    ec_attrib_id_responder_protocol_key,
    ec_attrib_id_initiator_auth_tag,
    ec_attrib_id_responder_auth_tag,
    ec_attrib_id_config_object,
    ec_attrib_id_connector,
    ec_attrib_id_config_req_object,
    ec_attrib_id_bootstrap_key,
    ec_attrib_id_reserved_1,
    ec_attrib_id_reserved_2,
    ec_attrib_id_finite_cyclic_group,
    ec_attrib_id_encrypted_key,
    ec_attrib_id_enrollee_nonce,
    ec_attrib_id_code_id,
    ec_attrib_id_transaction_id,
    ec_attrib_id_bootstrapping_info,
    ec_attrib_id_channel,
    ec_attrib_id_proto_version,
    ec_attrib_id_enveloped_data,
    ec_attrib_id_send_conn_status,
    ec_attrib_id_conn_status,
    ec_attrib_id_reconfig_flags,
    ec_attrib_id_C_sign_key_hash,
} ec_attrib_id_t;

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
    unsigned char cat;
    unsigned char action;
} __attribute__((packed)) ec_frame_hdr_t;

typedef struct {
    unsigned char oui[3];
    unsigned char oui_type;
} __attribute__((packed)) ec_oui_t;

typedef struct
{
    unsigned short type;
    unsigned short length;
    unsigned char value[0];
} __attribute__((packed)) ec_tlv_t;

typedef struct {
    ec_oui_t ec_oui;
    unsigned char crypto;
    unsigned char frame_type;
    unsigned char attrib[0];
} __attribute__((packed)) ec_frame_body_t;

typedef struct {
    ec_frame_hdr_t  hdr;
    ec_frame_body_t     body;
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
    ec_session_type_t   type;
    char            iPubKey[512];
    char            rPubKey[512];   
    unsigned char     tran_id[120];
    unsigned char match_tran_id;
} ec_data_t;

#endif // EC_BASE_H
