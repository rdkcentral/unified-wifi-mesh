// /**
//  * Copyright 2025 Comcast Cable Communications Management, LLC
//  *
//  * Licensed under the Apache License, Version 2.0 (the "License");
//  * you may not use this file except in compliance with the License.
//  * You may obtain a copy of the License at
//  *
//  * http://www.apache.org/licenses/LICENSE-2.0
//  *
//  * Unless required by applicable law or agreed to in writing, software
//  * distributed under the License is distributed on an "AS IS" BASIS,
//  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  * See the License for the specific language governing permissions and
//  * limitations under the License.
//  *
//  * SPDX-License-Identifier: Apache-2.0
//  */

// #include <stdio.h>
// #include <string.h>
// #include "ec_base.h"
// #include "ec_session.h"
// #include "ec_util.h"
// #include "em.h"
// #include "aes_siv.h"






// int ec_session_t::init_session(ec_data_t* ec_data)
// {
//     const EC_POINT *ipt, *rpt = NULL;
//     const BIGNUM *proto_priv;

//     if (ec_data != NULL) {
//         memset(&m_data, 0, sizeof(ec_data_t));
//         memcpy(&m_data, ec_data, sizeof(ec_data_t));
//     }

//     if (m_data.type == ec_session_type_cfg) {
//         // Set in DPP URI 

//         rpt = EC_KEY_get0_public_key(m_data.responder_boot_key);
//         if (rpt == NULL) {
//             printf("%s:%d Could not get responder bootstrap public key\n", __func__, __LINE__);
//             return -1;
//         }

//     } else if (m_data.type == ec_session_type_recfg) {

//         m_params.group = EC_KEY_get0_group(m_data.initiator_boot_key);
//         m_params.responder_connector = EC_POINT_new(m_params.group);
//     }


//     m_params.x = BN_new();
//     m_params.y = BN_new();
//     m_params.m = BN_new();
//     m_params.n = BN_new();
//     m_params.prime = BN_new();
//     m_params.bnctx = BN_CTX_new();

//     if (!m_params.x || !m_params.y || !m_params.m || !m_params.n || 
//         !m_params.prime || !m_params.bnctx) {
//         printf("%s:%d Some BN NULL\n", __func__, __LINE__);
//         BN_free(m_params.x);
//         BN_free(m_params.y);
//         BN_free(m_params.m);
//         BN_free(m_params.n);
//         BN_free(m_params.prime);
//         BN_CTX_free(m_params.bnctx);
//         return -1;
//     }

//     m_params.responder_proto_pt = EC_POINT_new(m_params.group);
//     m_params.nid = EC_GROUP_get_curve_name(m_params.group);

//     //printf("%s:%d nid: %d\n", __func__, __LINE__, m_params.nid);
//     switch (m_params.nid) {
//         case NID_X9_62_prime256v1:
//             m_params.group_num = 19;
//             m_params.digestlen = 32;
//             m_params.hashfcn = EVP_sha256();
//             break;
//         case NID_secp384r1:
//             m_params.group_num = 20;
//             m_params.digestlen = 48;
//             m_params.hashfcn = EVP_sha384();
//             break;
//         case NID_secp521r1:
//             m_params.group_num = 21;
//             m_params.digestlen = 64;
//             m_params.hashfcn = EVP_sha512();
//             break;
//         case NID_X9_62_prime192v1:
//             m_params.group_num = 25;
//             m_params.digestlen = 32;
//             m_params.hashfcn = EVP_sha256();
//             break;
//         case NID_secp224r1:
//             m_params.group_num = 26;
//             m_params.digestlen = 32;
//             m_params.hashfcn = EVP_sha256();
//             break;
//         default:
//             printf("%s:%d nid:%d not handled\n", __func__, __LINE__, m_params.nid);
//             return -1;
//     }

//     m_params.noncelen = m_params.digestlen*4;

//     //printf("%s:%d group_num:%d digestlen:%d\n", __func__, __LINE__, m_params.group_num, m_params.digestlen);
//     if (m_params.initiator_proto_key != NULL){
//         EC_KEY_free(m_params.initiator_proto_key);
//         m_params.initiator_proto_key = NULL;
//     }
//     m_params.initiator_proto_key = EC_KEY_new_by_curve_name(m_params.nid);
//     if (m_params.initiator_proto_key == NULL) {
//         printf("%s:%d Could not create protocol key\n", __func__, __LINE__);
//         return -1;
//     }

//     if (EC_KEY_generate_key(m_params.initiator_proto_key) == 0) {
//         printf("%s:%d Could not generate protocol key\n", __func__, __LINE__);
//         return -1;
//     }

//     ipt = EC_KEY_get0_public_key(m_params.initiator_proto_key);
//     if (ipt == NULL) {
//         printf("%s:%d Could not get initiator protocol public key\n", __func__, __LINE__);
//         return -1;
//     }

//     proto_priv = EC_KEY_get0_private_key(m_params.initiator_proto_key);
//     if (proto_priv == NULL) {
//         printf("%s:%d Could not get initiator protocol private key\n", __func__, __LINE__);
//         return -1;
//     }

//     if ((m_params.N = EC_POINT_new(m_params.group)) == NULL) {
//         printf("%s:%d unable to create bignums to initiate DPP!\n", __func__, __LINE__);
//         return -1;
//     }


//     if ((m_params.M = EC_POINT_new(m_params.group)) == NULL) {
//         printf("%s:%d unable to create bignums to initiate DPP!\n", __func__, __LINE__);
//         return -1;
//     }


//     if (EC_POINT_get_affine_coordinates_GFp(m_params.group, ipt, m_params.x,
//                 m_params.y, m_params.bnctx) == 0) {
//         printf("%s:%d unable to get x, y of the curve\n", __func__, __LINE__);
//         return -1;
//     }

//     if (m_data.type == ec_session_type_cfg) {

//         if (EC_POINT_mul(m_params.group, m_params.M, NULL, rpt, proto_priv, m_params.bnctx) == 0) {
//             printf("%s:%d unable to get x, y of the curve\n", __func__, __LINE__);
//             return -1;
//         }


//         printf("Point M:\n");
//         ec_util::print_ec_point(m_params.group, m_params.bnctx, m_params.M);

//         if (EC_POINT_get_affine_coordinates_GFp(m_params.group, m_params.M,
//                     m_params.m, NULL, m_params.bnctx) == 0) {
//             printf("%s:%d unable to get x, y of the curve\n", __func__, __LINE__);
//             return -1;

//         }
//     }

//     RAND_bytes(m_params.initiator_nonce, m_params.noncelen);
//     if (EC_GROUP_get_curve_GFp(m_params.group, m_params.prime, NULL, NULL,
//                 m_params.bnctx) == 0) {
//         printf("%s:%d unable to get x, y of the curve\n", __func__, __LINE__);
//         return -1;
//     }


//     return 0;

// }



// ec_session_t::~ec_session_t() 
// {
//     // Clean up any allocated resources if necessary
// }

