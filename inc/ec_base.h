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

/**
 * @brief Temporary until halinterface, rdk-wifi-hal, and OneWifi PRs are merged
 * 
 * If defined, the frequency (and other wifi data) is recieved along with the action frame
 * in the action frame subscription handler.
 * 
 * halinterface PR #49: https://github.com/rdkcentral/rdkb-halif-wifi/pull/49
 * rdk-wifi-hal PR #344: https://github.com/rdkcentral/rdk-wifi-hal/pull/344
 * OneWifi PR #576: https://github.com/rdkcentral/OneWifi/pull/576
 */
//#define FEATURE_RECV_FREQ_ACT_SUB 

// START: Hardcoded EasyConnect values
#define DPP_VERSION 0x02
#define DPP_URI_TXT_PATH "/nvram/DPPURI.txt"
#define DPP_BOOT_PEM_PATH "/nvram/DPPURI.pem"
#define DPP_SEC_CTX_DIR_PATH "/nvram"


#define DPP_C_SIGN_KEY_FILE "C-sign-key.pem"
#define DPP_NET_ACCESS_KEY_FILE "net-access-key.pem"
#define DPP_PPK_KEY_FILE "ppk.pem"
#define DPP_CONNECTOR_FILE "connector.txt"

// The NID for generating the local responder keypair
#define DPP_KEY_NID NID_X9_62_prime256v1

#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif // ETH_ALEN

#define DPP_OUI_TYPE 0x1A
#define DPP_MAX_EN_CHANNELS 4

#define DPP_GAS_INITIAL_REQ 0x0A
#define DPP_GAS_INITIAL_RESP 0x0B

#define APEFMT "%02x,%02x,%02x"
#define APE2STR(x) static_cast<unsigned int>((x)[0]), static_cast<unsigned int>((x)[1]), static_cast<unsigned int>((x)[2])
#define APEIDFMT "%02x,%02x,%02x,%02x,%02x,%02x,%02x"
#define APEID2STR(x) static_cast<unsigned int>((x)[0]), static_cast<unsigned int>((x)[1]), static_cast<unsigned int>((x)[2]), \
                     static_cast<unsigned int>((x)[3]), static_cast<unsigned int>((x)[4]), static_cast<unsigned int>((x)[5]), \
                     static_cast<unsigned int>((x)[6])
#define MACSTRFMT "%02x:%02x:%02x:%02x:%02x:%02x"
#define MAC2STR(x) static_cast<unsigned int>((x)[0]), static_cast<unsigned int>((x)[1]), static_cast<unsigned int>((x)[2]), \
                   static_cast<unsigned int>((x)[3]), static_cast<unsigned int>((x)[4]), static_cast<unsigned int>((x)[5])


// For self-documenting code/runtime
#define SPEC_TODO_NOT_FATAL(SPEC, VERSION, SECTION, TEXT) \
    do { \
        fprintf(stderr, "[TODO] Spec: %s v%s, Section: %s\nText: %s\n", SPEC, VERSION, SECTION, TEXT); \
    } while (0)


#define SPEC_TODO_FATAL(SPEC, VERSION, SECTION, TEXT) \
    do { \
        fprintf(stderr, "[TODO - FATAL] Spec: %s v%s, Section: %s\nText: %s\n", SPEC, VERSION, SECTION, TEXT); \
        assert(false); \
    } while (0)

static const uint8_t BROADCAST_MAC_ADDR[ETHER_ADDR_LEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
static const uint8_t ZERO_MAC_ADDR[ETHER_ADDR_LEN] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
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
    // XXX: Note: 255 is "reserved" in EasyConnect spec, but used by EasyMesh
    ec_frame_type_easymesh = 255,
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
} __attribute__((packed)) ec_dpp_capabilities_t;

#define DPP_CONFIG_REUSEKEY 0
#define DPP_CONFIG_REPLACEKEY 1

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
}  __attribute__((packed)) ec_dpp_reconfig_flags_t;


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

/**
 * @brief A DPP attribute as defined in EasyConnect 8.1. Can be sent/received over the network.
 * 
 * @paragraph DPP attributes' ID and length fields are required to be little 
 *            endian when transferred over the network. In general, data 
 *            transmitted over the network is big endian ("network byte 
 *            order"), so DPP attributes must be treated as a different case.
 *            Users of this struct MUST maintain the invariant that the 
 *            `attr_id` and `length` are little endian. If anything needs to be
 *            done with these values on the host, use an `ec_attribute_t`
 *            instead.
 * 
 * @warning When doing any network operations involving DPP attributes, use `ec_net_attribute_t`, not `ec_attribute_t`. 
 * @warning When executing logic on the host related to `attr_id` and `length`, use `ec_attribute_t`, not `ec_net_attribute_t`. 
 */
typedef struct {
    /**
     * @brief Identifies the type of the DPP attribute. Assumed to be little endian, as described in EasyConnect 8.1.
     */
    uint16_t attr_id;
    /**
     * @brief Length of the following fields in the attribute. Assumed to be little endian, as described in EasyConnect 8.1.
     */
    uint16_t length;
    /**
     * @brief Attribute-specific information fields. Endianness varies according to the specific DPP attribute type.
     */
    uint8_t data[0];
}__attribute__((packed)) ec_net_attribute_t;

/**
 * @brief Represents a DPP attribute that has been converted to host byte ordering. Not intended to be sent over the network. 
 * 
 * @paragraph This struct is intended to be used in any operations on DPP
 *            attributes that occur entirely on the host. For example, after an
 *            `ec_net_attribute_t` is read from a frame received from
 *            the network, it must be converted to an `ec_attribute_t` to
 *            ensure that the `attr_id` and `length` use host byte ordering. 
 * 
 * @paragraph Note that this struct includes a pointer, 
 *            `ec_net_attribute_t *original`. This MUST ALWAYS point to the
 *            `ec_net_attribute_t` instance that was used to derive this
 *            `ec_attribute_t` instance. `original` is used in pointer
 *            arithmetic based on its position in a frame. 
 * 
 * @note `ec_net_attribute_t *original` points to the `ec_attribute_t` instance this was derived from.
 * 
 * @warning When doing any network operations involving DPP attributes, use `ec_net_attribute_t`, not `ec_attribute_t`. 
 * @warning When executing logic on the host related to `attr_id` and `length`, use `ec_attribute_t`, not `ec_net_attribute_t`. 
 */
typedef struct {
    /**
     * @brief Identifies the type of the DPP attribute. Assumed to be stored with host byte ordering.
     */
    uint16_t attr_id;
    /**
     * @brief Length of the following fields in the attribute. Assumed to be stored with host byte ordering.
     */
    uint16_t length;
    /**
     * @brief Points to the `ec_net_attribute_t` instance this `ec_net_attribute_t` instance was derived from.
     */
    ec_net_attribute_t *original;
    /**
     * @brief Shorthand for `this.original->data`. Must always equate to `this.original->data`. 
     */
    uint8_t *data;
} ec_attribute_t;

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
    ec_gas_frame_base_t base;
    uint8_t ape[3];
    uint8_t ape_id[7];
    uint16_t query_len;
    uint8_t query[];
} __attribute__((packed)) ec_gas_initial_request_frame_t;

typedef struct {
    ec_gas_frame_base_t base;
    uint16_t status_code; // 802.11 Management Frame Status Code Field (IEEE 802.11 9.4.1.9 <- 9.6.7.46)
    uint16_t gas_comeback_delay;
    uint8_t ape[3];
    uint8_t ape_id[7];
    uint16_t resp_len;
    uint8_t resp[];
} __attribute__((packed)) ec_gas_initial_response_frame_t;

typedef struct {
    ec_gas_frame_base_t base;
} __attribute__((packed)) ec_gas_comeback_request_frame_t;

typedef struct {
    ec_gas_frame_base_t base;
    uint16_t status_code;            // Same field as initial response
    uint8_t fragment_id : 7;             // Fragment ID (0–127)
    uint8_t more_fragments : 1;         // 1 = more fragments to come, 0 = this is the last fragment
    uint16_t gas_comeback_delay;     // 0 if this is the final response
    uint8_t ape[3];
    uint8_t ape_id[7];
    uint16_t comeback_resp_len;
    uint8_t comeback_resp[];
} __attribute__((packed)) ec_gas_comeback_response_frame_t;

// START: Adapted from `eapol_common.h` in hostapd
#define EAPOL_VERSION 3

enum { IEEE802_1X_TYPE_EAP_PACKET = 0,
       IEEE802_1X_TYPE_EAPOL_START = 1,
       IEEE802_1X_TYPE_EAPOL_LOGOFF = 2,
       IEEE802_1X_TYPE_EAPOL_KEY = 3,
       IEEE802_1X_TYPE_EAPOL_ENCAPSULATED_ASF_ALERT = 4,
       IEEE802_1X_TYPE_EAPOL_MKA = 5,
};


/* 
* 802.11 Table 12-10—KDE selectors + EasyMesh 1905 Table 11
* 
* +-------------------+-----------+-------------------------+
* | OUI               | Data type | Meaning                 |
* +-------------------+-----------+-------------------------+
* | 00-0F-AC          | 0         | Reserved                |
* | 00-0F-AC          | 1         | GTK KDE                 |
* | 00-0F-AC          | 2         | Reserved                |
* | 00-0F-AC          | 3         | MAC address KDE         |
* | 00-0F-AC          | 4         | PMKID KDE               |
* | 00-0F-AC          | 5         | Reserved                |
* | 00-0F-AC          | 6         | Nonce KDE               |
* | 00-0F-AC          | 7         | Lifetime KDE            |
* | 00-0F-AC          | 8         | Error KDE               |
* | 00-0F-AC          | 9         | IGTK KDE                |
* | 00-0F-AC          | 10        | Key ID KDE              |
* | 00-0F-AC          | 11        | Multi-band GTK KDE      |
* | 00-0F-AC          | 12        | Multi-band Key ID KDE   |
* | 00-0F-AC          | 13        | OCI KDE                 |
* | 00-0F-AC          | 14        | BIGTK KDE               |
* | (11ba)00-0F-AC    | 15        | WIGTK KDE               |
* | 00-0F-AC          | (11ba)16-255 | Reserved             |
* | Other OUI or CID  | Any       | Vendor specific         |
* +-------------------+-----------+-------------------------+
* | 50-6F-9A          | 0         | 1905 GTK KDE            |
* +-------------------+-----------+-------------------------+
*/

typedef enum {
    EAPOL_KDE_TYPE_1905_GTK = 0, // EasyMesh 1905 GTK KDE
    EAPOL_KDE_TYPE_GTK = 1,
    EAPOL_KDE_TYPE_MAC_ADDR = 3,
    EAPOL_KDE_TYPE_PMKID = 4,
    EAPOL_KDE_TYPE_NONCE = 6,
    EAPOL_KDE_TYPE_LIFETIME = 7,
    EAPOL_KDE_TYPE_ERROR = 8,
    EAPOL_KDE_TYPE_IGTK = 9,
    EAPOL_KDE_TYPE_KEY_ID = 10,
    EAPOL_KDE_TYPE_MULTI_BAND_GTK = 11,
    EAPOL_KDE_TYPE_MULTI_BAND_KEY_ID = 12,
    EAPOL_KDE_TYPE_OCI = 13,
    EAPOL_KDE_TYPE_BIGTK = 14,
    EAPOL_KDE_TYPE_WIGTK = 15,
} eapol_kde_type_t;

typedef struct {
    uint8_t type; 
    uint8_t length; 
    uint8_t oui[3]; 
    uint8_t data_type;
    uint8_t data[0];
} __attribute__((packed)) eapol_kde_t;


#define EAPOL_KDE_BASE_SIZE (sizeof(eapol_kde_t) - offsetof(eapol_kde_t, oui))

typedef struct  {
	uint8_t version;
	uint8_t type;
	uint16_t length;
	/* followed by length octets of data */
} __attribute__((packed)) ieee802_1x_hdr_t;

// END

typedef struct {
    uint8_t desc_type;
    union {
        struct {
            uint16_t key_descriptor_version : 3;  // B0-B2
            uint16_t key_type : 1;                // B3
            uint16_t reserved1 : 2;               // B4-B5
            uint16_t install : 1;                 // B6
            uint16_t key_ack : 1;                 // B7
            uint16_t key_mic : 1;                 // B8
            uint16_t secure : 1;                  // B9
            uint16_t error : 1;                   // B10
            uint16_t request : 1;                 // B11
            uint16_t encrypted_key_data : 1;      // B12
            uint16_t reserved2 : 3;               // B13-B15
        } bits;
        uint16_t raw;  // Direct 16-bit access
    } key_info;
    uint16_t key_length; 
    uint64_t key_replay_counter;
    uint8_t key_nonce[32];
    uint8_t key_iv[16];
    uint8_t key_rsc[8];
    uint8_t _reserved[8]; // Reserved in the EAPOL-PDU
    /*
    - The MIC is optional and is only present if the key_info_t.key_mic bit is set.
    - After the MIC there is a 2 octet key length field
    - After the key length field, there is a key data field of variable length.
    */
    uint8_t mic_len_key[0];
} __attribute__((packed)) eapol_packet_t; // 802.11 12.7.2


typedef struct {
    uint8_t key_id : 2; // Bits 0-1
    uint8_t reserved : 6; // Bits 2-7
    uint8_t gtk[32]; // 1905 GTK
} __attribute__((packed)) gtk_1905_kde_t;

// Used to avoid many many if-not-null checks
#define ASSERT_MSG_FALSE(x, ret, errMsg, ...) \
    if(x) { \
        fprintf(stderr, errMsg, ## __VA_ARGS__); \
        return ret; \
    }

#define ASSERT_MSG_TRUE(x, ret, errMsg, ...) ASSERT_MSG_FALSE(!(x), ret, errMsg, ## __VA_ARGS__)
#define ASSERT_NOT_NULL(x, ret, errMsg, ...) ASSERT_MSG_FALSE(x == NULL, ret, errMsg, ## __VA_ARGS__)

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
    do { \
        if(x == NULL) { \
            fprintf(stderr, errMsg, ## __VA_ARGS__); \
            void *_tmp1 = (ptr1); \
            void *_tmp2 = (ptr2); \
            void *_tmp3 = (ptr3); \
            if (_tmp1) { \
                free(_tmp1); \
            } \
            if (_tmp2) { \
                free(_tmp2); \
            } \
            if (_tmp3) { \
                free(_tmp3); \
            } \
            return ret; \
        } \
    } while (0)

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


#define ASSERT_NULL(x, ret, errMsg, ...) ASSERT_MSG_TRUE(x == 0, ret, errMsg, ## __VA_ARGS__)
#define ASSERT_EQUALS(x, y, ret, errMsg, ...) ASSERT_MSG_TRUE(x == y, ret, errMsg, ## __VA_ARGS__)
#define ASSERT_NOT_EQUALS(x, y, ret, errMsg, ...) ASSERT_MSG_FALSE(x == y, ret, errMsg, ## __VA_ARGS__)

/**
 * @brief Asserts that a std::optional has a value, and if it doesn't, frees up to 3 pointers and returns a value
 * @param x The std::optional to check for a value
 * @param ret The value to return if x is nullopt
 * @param ptr1 First pointer to free (can be NULL)
 * @param ptr2 Second pointer to free (can be NULL) 
 * @param ptr3 Third pointer to free (can be NULL)
 * @param errMsg Format string for error message
 * @param ... Additional arguments for the format string
 */
#define ASSERT_OPT_HAS_VALUE_FREE3(x, ret, ptr1, ptr2, ptr3, errMsg, ...) \
    do { \
        if(!x.has_value()) { \
            fprintf(stderr, errMsg, ## __VA_ARGS__); \
            void *_tmp1 = (ptr1); \
            void *_tmp2 = (ptr2); \
            void *_tmp3 = (ptr3); \
            if (_tmp1) { \
                free(_tmp1); \
            } \
            if (_tmp2) { \
                free(_tmp2); \
            } \
            if (_tmp3) { \
                free(_tmp3); \
            } \
            return ret; \
        } \
    } while (0)

/**
 * @brief Asserts that a std::optional has a value, and if it doesn't, frees up to 2 pointers and returns a value
 * @param x The std::optional to check for a value
 * @param ret The value to return if x is nullopt
 * @param ptr1 First pointer to free (can be NULL)
 * @param ptr2 Second pointer to free (can be NULL) 
 * @param errMsg Format string for error message
 * @param ... Additional arguments for the format string
 */
#define ASSERT_OPT_HAS_VALUE_FREE2(x, ret, ptr1, ptr2, errMsg, ...) \
    ASSERT_OPT_HAS_VALUE_FREE3(x, ret, ptr1, ptr2, NULL, errMsg, ## __VA_ARGS__)

/**
 * @brief Asserts that a std::optional has a value, and if it doesn't, frees a pointer and returns a value
 * @param x The std::optional to check for a value
 * @param ret The value to return if x is nullopt
 * @param ptr1 First pointer to free (can be NULL)
 * @param errMsg Format string for error message
 * @param ... Additional arguments for the format string
 */
#define ASSERT_OPT_HAS_VALUE_FREE(x, ret, ptr1, errMsg, ...) \
    ASSERT_OPT_HAS_VALUE_FREE2(x, ret, ptr1, NULL, errMsg, ## __VA_ARGS__)

/**
 * @brief Asserts that a std::optional has a value, and returns a value if it doesn't
 * @param x The std::optional to check for a value
 * @param ret The value to return if x is nullopt
 * @param errMsg Format string for error message
 * @param ... Additional arguments for the format string
 */
#define ASSERT_OPT_HAS_VALUE(x, ret, errMsg, ...) ASSERT_MSG_TRUE(x.has_value(), ret, errMsg, ## __VA_ARGS__)

#ifndef SSL_KEY
#if OPENSSL_VERSION_NUMBER < 0x30000000L
#define SSL_KEY EC_KEY
#else
#define SSL_KEY EVP_PKEY
#endif
#endif


typedef struct {
    uint8_t pmk[SHA256_DIGEST_LENGTH];
    uint8_t pmkid[16]; // Truncated to 128 bits

    uint8_t ptk[SHA512_DIGEST_LENGTH]; 
    // Saved after PTK is out of RAM for use with other operations (group handshake, etc)
    uint8_t ptk_kck[64]; // PTK KCK (Key Confirmation Key) (802.11 12.7.1.3)
    uint8_t ptk_kek[64]; // PTK KEK (Key Encryption Key) (802.11 12.7.1.3)

    uint8_t a_nonce[SHA256_DIGEST_LENGTH]; // 802.11 12.7.5
    uint8_t s_nonce[SHA256_DIGEST_LENGTH];

    // The current last sent eapol number (1 to 4) in the 4 way handshake.
    // This is used to track which frame in the 4 way handshake has been sent.
    // For example:
    //      If the first frame in the 4 way handshake is sent, this is 1.
    //      If the second frame in the 4 way handshake is sent, this is 2.
    //      If the third frame in the 4 way handshake is sent, this is 3.
    //      If the fourth frame in the 4 way handshake is sent, this is 4.
    uint8_t sent_eapol_idx;

    uint64_t curr_replay_counter;

    bool is_ptk_rekeying;
    
} ec_1905_key_ctx;

typedef enum {
    ec_session_type_cfg,
    ec_session_type_recfg,
} ec_session_type_t;

typedef struct {

    // Baseline static, DPP URI data
    unsigned int version;
    unsigned int  ec_freqs[DPP_MAX_EN_CHANNELS];
    mac_address_t   mac_addr;
    ec_session_type_t   type;

    /*
    Initiator/Configurator bootstrapping key. (ALWAYS REQUIRED on controller, OPTIONAL on enrollee)
        - If this is the Controller, then this key is stored on the Controller. 
        - If this is the Enrollee, then this key is required for "mutual authentication" and must be recieved via an out-of-band mechanism from the controller.
    */
    const SSL_KEY *initiator_boot_key; 
    /*
    Responder/Enrollee bootstrapping key. (REQUIRED)
        - If this is the Controller, then this key was recieved out-of-band from the Enrollee in the DPP URI
        - If this is the Enrollee, then this key is stored locally.
    */
    const SSL_KEY *responder_boot_key;
    
    // B_I, B_R
    EC_POINT *init_pub_boot_key, *resp_pub_boot_key;
    // b_I, b_R
    BIGNUM *init_priv_boot_key, *resp_priv_boot_key;
} ec_data_t;


typedef struct {

   /**
     * Configurator Signing Key.
     * Used to sign all DPP Connectors.
     *  - The Configurator has the private/public key pair
     *  - The Enrollee has the public key only
     */
	SSL_KEY* C_signing_key;

    /**
     * The Configurator's Privacy Protection Key (PPK).
     * Used for configuration / re-authentication.
     *  - The Configurator has the private/public key pair
     *  - The Enrollee has the public key only
     */
	SSL_KEY* pp_key;

    /**
     * The Controller or Agent/Enrollee's netAccessKey (NAK), used as the netAccessKey for the devices's 1905 connector
     * This is the key present in the DPP/1905 Connector
     *  - The Configurator generates it's NAK at initialization (along with connector, EasyMesh 5.3.3)
     *  - The Enrollee generates it's NAK as a protocol key during the DPP Authentication process
     */
	SSL_KEY* net_access_key;

    /**
     * @brief The Controller or Agent/Enrollee's 1905/DPP Connector.
     *  - The differences between devices are the `netRole` (`mapController` or `mapAgent`) and the `netAccessKey` (NAK).
     * - The Configurator generates it's Connector at initialization (along with NAK, EasyMesh 5.3.3)
     * - The Enrollee _recieves_ it's Connector from the Controller/Configurator during the DPP Configuration process.
     * NULL terminated string, NULL if not set.
     * @paragraph
     * EasyConnect 4.2
     *   A Connector is encoded as a JSON Web Signature (JWS) Compact Serialization of a JWS Protected Header (describing
     *   the encoded object and signature), a JWS Payload, and a signature. JSON is a data interchange format (see [12]) that
     *   encodes data as a series of data types (strings, numbers, Booleans, and null) and structure types, formatted as
     *   name/value pairs.
     *   ...
     *   The JWS Compact Serialization is a base64url encoding of each component, with components separated by a dot (“.”).
     *   The JWS Protected Header is a JSON object that describes:
     *   • The type of object in the JWS Payload specified as "dppCon"
     *   • The identifier ("kid" ) for the key used to generate the signature
     *   • The algorithm ("alg") used to generate a signature
     *   The supported algorithms are given in [16]. All devices supporting DPP shall support the ES256 algorithm. Key and nonce
     *   lengths shall be as specified in Table 4. The curve used for the signature may be different from the one used in DPP
     *   Bootstrapping and DPP Authentication protocols.
     *   ...
     * 4.2.1 Connector Signing
     *   The Configurator possesses a signing key pair (c-sign-key, C-sign-key). The c-sign-key is used by the Configurator to sign
     *   Connectors, whereas the C-sign-key is used by provisioned devices to verify Connectors of other devices are signed by
     *   the same Configurator. Connectors signed with the same c-sign-key manage connections in the same network.
     *   The Configurator sets the public key corresponding to the enrollee protocol key as the **netAccessKey** in the Connector
     *   data structure, and assigns the DPP Connector attribute depending on the Peer devices with which the enrollee will be
     *   provisioned to connect.
     * 4.2.1.1 Digital Signature Computation
     *   The procedures to compute the digital signature of a Connector and the procedure to verify such signature are described
     *   in FIPS-186-4 [19] and are specified in this section.  The curve used for the signature may be different from the one used in DPP Bootstrapping and DPP Authentication protocols.
     *   The signature is performed over the concatenation of the base64url encodings of both the JWS Protected Header and the JWS Payload, separated by a dot (“.”), see section 5.1 of [14].
     *   The data passed to the signature algorithm is:
     *   
     *   base64url(UTF8(JWS Protected Header)) | ‘.’ | base64url(JWS Payload)
     *    
     *   where UTF8(s) is the UTF8 representation of the string “s”.
     *   If “sig” is the result of the signature, the Connector is then:
     *   base64url(UTF8(JWS Protected Header)) | ‘.’ | base64url(JWS Payload) | ‘.’ | base64url(sig)
     */
    const char* connector;
} ec_persistent_sec_ctx_t;


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
     * EasyConnect 6.5.2
     * A random point on the curve for reconfiguration. The same point is used throughout reconfiguration.
     * Used from the configurator/controller end as short term memory of which enrollee's it's seen before.
     * Used by the enrollee to provide that short term memory to the controller.
     * This must be freed after the reconfiguration process is complete.
     */
    EC_POINT *E_Id;

    /**
     * @brief The transaction ID used for Reconfiguration
     * 
     * This is created by the Configurator and issued to an Enrollee on a per-Reconfiguration-session basis.
     * This is created by the (no longer Proxy) Agent and issued to an Controller on a per-Network Introduction Protocol-session basis.
     * 
     * Both uses cases are fine and won't collide with each other.
     * 
     */
    uint8_t transaction_id;

    /**
     * Only needs to be known during the auth process to decide wether or not to generate the L key.
     */
    bool is_mutual_auth;

    /**
     * An ephemeral key pair used for storing a NAK between requests.
     * Particularly used during EasyConnect re-authentication to store the temporary but newly generated NAK
     */  
    SSL_KEY *net_access_key;

} ec_ephemeral_context_t;

/**
 * @brief The parameters used for a specific connection between a Configurator and a specific Enrollee/Agent during it's entire lifetime.
 */
typedef struct {
    // BEGIN: Variables that are configured once and persist throughout the lifetime of the program

    ec_data_t boot_data; // The bootstrapping data for the Configurator/Enrollee

    // These variables are either based on the responder bootstrapping key or the C-signing-key based on wether it's a reconfiguration or not
    const EC_GROUP *group;
    const EVP_MD *hash_fcn;
    BIGNUM *order;
    BIGNUM *prime;
    BN_CTX *bn_ctx;
    uint16_t digest_len;
    uint16_t nonce_len;
    int nid;

	/**
     * Current netAccessKey (NAK) of the Agent/Enrollee.
     *  - Stored in the case that the Agent/Enrollee chooses not to replace this key during (re)configuration. 
     *  - Only used by the Controller/Configurator
     * 
     */ 
    SSL_KEY *enrollee_net_access_key;

    /**
     * @brief The **AL* MAC address of the peer device that this connection is established with.
     * 
     * This can be the MAC address of a Controller or an Agent but it **must** be an AL MAC, not
     * a PHY MAC. Therefore, this value will be NULL during the initial onboarding (sending of 802.11/802.3 frames)
     */
    uint8_t peer_al_mac[ETH_ALEN];

    /**
     * @brief The temporary context that is used during the authentication / configuration process and should be securely freed after the process is complete.
     */
    ec_ephemeral_context_t eph_ctx;

    /**
     * @brief True if the DPP process outlined in the EasyConnect specification has been completed.
     * This is true before the enrollee is fully onboarded because there are additional EasyMesh specification
     * steps that need to be completed before the Enrollee is fully onboarded.
     * 
     * For example:
     *   - EasyConnect outlines: Bootstrapping, Authentication, and Configuration.
     *   - EasyMesh outlines: Autoconf+Chirp, 1905 layer security, and BSS Configuration.
     */
    bool is_easyconnect_dpp_complete;

    /**
     * @brief Is this Enrollee onboarding via ethernet?
     */
    bool is_eth;
} ec_connection_context_t;



#ifdef __cplusplus
}
#endif

#endif // EC_BASE_H
