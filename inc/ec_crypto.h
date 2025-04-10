#ifndef EC_CRYPTO_H
#define EC_CRYPTO_H

#include "em_base.h"
#include "ec_base.h"
#include "em_crypto.h"

#include <utility>
#include <memory>
#include <vector>
#include <optional>
#include <string>
#include <cstring>
#include <unordered_map>

// forward decl
struct cJSON;

namespace easyconnect {


    // Custom deleter for uint8_t arrays
    struct byte_arr_deleter {
        void operator()(uint8_t* p) const { delete[] p; }
    };
    
    // Define a smart pointer type for buffers
    using buff_ptr = ::std::unique_ptr<uint8_t[], byte_arr_deleter>;
    
    // Define easyconnect::hash_buffer_t as a vector of smart pointer/length pairs
    using hash_buffer_t = std::vector<std::pair<buff_ptr, size_t>>;

}

class ec_crypto {
public:

    static size_t hkdf(const EVP_MD *h, bool skip_extract, uint8_t *ikm, size_t ikmlen, 
        uint8_t *salt, size_t saltlen, uint8_t *info, size_t infolen, 
        uint8_t *okm, size_t okmlen);


    /**
     * @brief Compute the hash of the provided key with an optional prefix
     * 
     * @param key The key to hash
     * @param digest The buffer to store the hash
     * @param prefix The optional prefix to add to the key before hashing (NULL by default)
     * @return int The length of the hash
     * 
     * @note: Caller must free returned hash.
     */
    static uint8_t* compute_key_hash(const SSL_KEY *key, const char *prefix = NULL);
    
    /**
     * @brief Initialize the persistent context params with the bootstrapping key's group as a basis
     * 
     * @param c_ctx The persistent context to initialize
     * @param boot_key The bootstrapping key to use as a basis
     * @return bool true if successful, false otherwise
     */
    static bool init_connection_ctx(ec_connection_context_t& c_ctx, const SSL_KEY *boot_key);

    /**
     * @brief Compute the hash of the provided buffer
     * 
     * @param buffer The buffer to hash
     * @return uint8_t* The hash of the buffer
     */
    static uint8_t* compute_hash(ec_connection_context_t& c_ctx, const easyconnect::hash_buffer_t& hashing_elements_buffer);


    static size_t compute_ke(ec_connection_context_t& c_ctx, ec_ephemeral_context_t* e_ctx, uint8_t *ke_buffer);

    /**
     * @brief Abstracted HKDF computation that handles both simple and complex inputs
     * 
     * This function provides a unified interface for HKDF computations, handling both
     * simple single-input operations and more complex operations with multiple inputs.
     * It properly formats BIGNUMs with appropriate padding based on prime length.
     *
     * @param key_out Buffer to store the output key (must be pre-allocated)
     * @param key_out_len Length of the output key
     * @param info_str Information string for HKDF
     * @param bn_inputs Array of BIGNUMs to use as IKM
     * @param bn_count Number of BIGNUMs in the array
     * @param raw_salt Raw salt buffer (can be NULL)
     * @param raw_salt_len Length of raw salt buffer
     * 
     * @return Length of the output key on success, 0 on failure
     */
    static size_t compute_hkdf_key(ec_connection_context_t& c_ctx, uint8_t *key_out, size_t key_out_len, const char *info_str,
        const BIGNUM **x_val_inputs, int x_val_count, 
        uint8_t *raw_salt, size_t raw_salt_len);

    /**
     * Calculates L = ((b_R + p_R) modulo q) * B_I then gets the x-coordinate of the result
     * 
     * @param group The EC_GROUP representing the elliptic curve
     * @param bR Private Responder Bootstrapping Key
     * @param pR Private Responder Protocol Key
     * @param BI Public Initiator Bootstrapping Key
     * @return EC_POINT* The calculated L point X value, or NULL on failure. Caller must free with BN_free()
     */
    static BIGNUM* calculate_Lx(ec_connection_context_t& c_ctx, const BIGNUM* bR, const BIGNUM* pR, const EC_POINT* BI);

    static std::pair<BIGNUM *, BIGNUM *> get_ec_x_y(ec_connection_context_t& c_ctx, const EC_POINT *point) {
        if (!point) return {};

        BIGNUM *x = BN_new(), *y = BN_new();
        if (EC_POINT_get_affine_coordinates(c_ctx.group, point,
            x, y, c_ctx.bn_ctx) == 0) {
            printf("%s:%d unable to get x, y of the curve\n", __func__, __LINE__);
            BN_free(x);
            BN_free(y);
            return {};
        }
        return {x, y};
    }

    static inline BIGNUM* get_ec_x(ec_connection_context_t& c_ctx, const EC_POINT *point) {
        auto [x, y] = get_ec_x_y(c_ctx, point);
        BN_free(y);
        return x;
    }

    static inline BIGNUM* get_ec_y(ec_connection_context_t& c_ctx, const EC_POINT *point) {
        auto [x, y] = get_ec_x_y(c_ctx, point);
        BN_free(x);
        return y;
    }

    static std::vector<uint8_t> BN_to_vec(const BIGNUM *bn) {
        if (!bn) return {};

        int num_bytes = BN_num_bytes(bn);
        std::vector<uint8_t> buffer(static_cast<size_t>(num_bytes));
    
        BN_bn2bin(bn, buffer.data()); // Convert BIGNUM to big-endian byte array
        return buffer;
    }
    /**
     * @brief Encode an EC point into a protocol key buffer
     * 
     * @param c_ctx The persistent context containing the EC group
     * @param point The EC point to encode
     * @return scoped_buff The encoded protocol key buffer, or NULL on failure. Caller must free with free()
     * 
     */
    static scoped_buff encode_ec_point(ec_connection_context_t& c_ctx, const EC_POINT *point);
    /**
     * @brief Decode a protocol key buffer into an EC point
     * 
     * @param c_ctx The persistent context containing the EC group
     * @param protocol_key_buff The encoded protocol key buffer
     * @return EC_POINT* The decoded EC point, or NULL on failure. Caller must free with EC_POINT_free()
     */
    static EC_POINT* decode_ec_point(ec_connection_context_t& c_ctx, const uint8_t* protocol_key_buff);
    /**
     * @brief Compute the shared secret X coordinate for an EC key pair
     *  (for example M.x, N.x)
     * 
     * @param priv The private key (for example p_I, p_R, or b_R)
     * @param pub The public key (for example P_I, B_R, or P_R)
     * @return BIGNUM* The X coordinate of the shared secret, or NULL on failure. Caller must free with BN_free()
     */
    static inline BIGNUM* compute_ec_ss_x(ec_connection_context_t& c_ctx, const BIGNUM* priv, const EC_POINT* pub) {
        // TODO: May have to adjust to get the group from the public key
        EC_POINT *ss = EC_POINT_new(c_ctx.group);
        if (EC_POINT_mul(c_ctx.group, ss, NULL, pub, priv, c_ctx.bn_ctx) == 0) {
            printf("%s:%d unable to get x, y of the curve\n", __func__, __LINE__);
            return NULL;
        }
        return get_ec_x(c_ctx, ss);
    }

    /**
     * @brief Generate a protocol key pair for the given EC curve
     * 
     * @param c_ctx The persistent context containing the EC curve
     * @return std::pair<const BIGNUM*, const EC_POINT*> Both the private and public keys, or NULL on failure
     * 
     * @warning The caller must free the BIGNUM and EC_POINT with BN_free() and EC_POINT_free() respectively
     */
    static std::pair<const BIGNUM*, const EC_POINT*> generate_proto_keypair(ec_connection_context_t& c_ctx);

        /**
     * Add a buffer to the hash elements
     * 
     * @note Copies data given into new temporary buffer. Modifications to the original data will not affect the hash elements.
     */
    static inline void add_to_hash(easyconnect::hash_buffer_t& buffer, const uint8_t* data, size_t len) {
        if (data != nullptr) {
            // Create a copy of the data with the correct deleter
            easyconnect::buff_ptr data_copy(new uint8_t[len]);
            memcpy(data_copy.get(), data, len);
            buffer.emplace_back(std::move(data_copy), len);
        }
    }

    static inline void add_to_hash(easyconnect::hash_buffer_t& buffer, const uint8_t* data, uint16_t len) {
        add_to_hash(buffer, data, static_cast<size_t>(len));
    }

    /**
     * Add a BIGNUM to the hash elements
     */
    static inline void add_to_hash(easyconnect::hash_buffer_t& buffer, const BIGNUM* bn) {
        if (bn != nullptr) {
            // Allocate memory for BIGNUM data
            int bn_size = BN_num_bytes(bn);
            easyconnect::buff_ptr bn_buf(new uint8_t[bn_size]);
            int bn_len = BN_bn2bin(bn, bn_buf.get());
            
            // Add to hash elements
            buffer.emplace_back(std::move(bn_buf), bn_len);
        }
    }

    /**
     * Add a single octet to the hash elements
     */
    static inline void add_to_hash(easyconnect::hash_buffer_t& buffer, uint8_t octet) {
        easyconnect::buff_ptr octet_buf(new uint8_t[1]);
        octet_buf[0] = octet;
        
        buffer.emplace_back(std::move(octet_buf), 1);
    }


    /**
     * @brief Get the TLS group ID from an NID
     * 
     * Reference: https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-8
     * 
     * @param nid The NID to get the ID from
     * @return uint16_t The TLS group ID, or UINT16_MAX if the group is unknown or unsupported
     */
    static inline uint16_t get_tls_group_id_from_nid(int nid) {

        switch (nid) {
            case NID_X9_62_prime256v1:  /* same as NID_secp256r1 */
                return 23;  /* secp256r1 (NIST P-256) */
            case NID_secp384r1:
                return 24;  /* secp384r1 (NIST P-384) */
            case NID_secp521r1:
                return 25;  /* secp521r1 (NIST P-521) */
            case NID_X9_62_prime192v1:  /* same as NID_secp192r1 */
                return 19;  /* secp192r1 */
            case NID_secp224r1:
                return 21;  /* secp224r1 */
            case NID_brainpoolP256r1:
                return 26;  /* brainpoolP256r1 */
            case NID_brainpoolP384r1:
                return 27;  /* brainpoolP384r1 */
            case NID_brainpoolP512r1:
                return 28;  /* brainpoolP512r1 */
            case NID_X25519:
                return 29;  /* x25519 */
            case NID_X448:
                return 30;  /* x448 */
            default:
                return UINT16_MAX;  /* Unknown or unsupported curve */
        }
    }

    /**
     * @brief Get the TLS group ID from an EC_GROUP
     * 
     * Reference: https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-8
     * 
     * @param group The EC_GROUP to get the ID from
     * @return uint16_t The TLS group ID, or UINT16_MAX if the group is unknown or unsupported
     */
    static inline uint16_t get_tls_group_id_from_ec_group(const EC_GROUP *group) {
        int nid = EC_GROUP_get_curve_name(group);
        
        return get_tls_group_id_from_nid(nid);
    }

    static void print_bignum (BIGNUM *bn);
    static void print_ec_point (const EC_GROUP *group, BN_CTX *bnctx, EC_POINT *point);

    static inline void rand_zero_free(uint8_t *buff, size_t len) {
        if (buff == NULL) return;
        RAND_bytes(buff, static_cast<int>(len));
        memset(buff, 0, len);
        free(buff);
    };

    static inline void rand_zero(uint8_t *buff, size_t len) {
        if (buff == NULL) return;
        RAND_bytes(buff, static_cast<int>(len));
        memset(buff, 0, len);
    };

    /**
     * @brief Free an ephemeral context by randomizing, zeroing, and freeing all memory 
     * Does not attempt to free the `ctx` pointer which may be statically allocated.
     * 
     * @param ctx The ephemeral context to free
     * @param nonce_len The length of the nonces in the context
     * @param digest_len The length of the digests/keys in the context
     */
    static inline void free_ephemeral_context(ec_ephemeral_context_t* ctx, uint16_t nonce_len, uint16_t digest_len) {

        if (!ctx) return;

        if (ctx->public_init_proto_key) EC_POINT_free(ctx->public_init_proto_key);
        if (ctx->public_resp_proto_key) EC_POINT_free(ctx->public_resp_proto_key);
        if (ctx->priv_init_proto_key) BN_free(ctx->priv_init_proto_key);
        if (ctx->priv_resp_proto_key) BN_free(ctx->priv_resp_proto_key);
        if (ctx->E_Id) EC_POINT_free(ctx->E_Id);
        if (ctx->m) BN_free(ctx->m);
        if (ctx->n) BN_free(ctx->n);
        if (ctx->l) BN_free(ctx->l);
        if (ctx->i_nonce) rand_zero_free(ctx->i_nonce, static_cast<size_t> (nonce_len));
        if (ctx->r_nonce) rand_zero_free(ctx->r_nonce, static_cast<size_t> (nonce_len));
        if (ctx->e_nonce) rand_zero_free(ctx->e_nonce, static_cast<size_t> (nonce_len));
        if (ctx->c_nonce) rand_zero_free(ctx->c_nonce, static_cast<size_t> (nonce_len));
        if (ctx->k1) rand_zero_free(ctx->k1, static_cast<size_t> (digest_len));
        if (ctx->k2) rand_zero_free(ctx->k2, static_cast<size_t> (digest_len));
        if (ctx->ke) rand_zero_free(ctx->ke, static_cast<size_t> (digest_len));
        if (ctx->bk) rand_zero_free(ctx->bk, static_cast<size_t> (digest_len));

        rand_zero(reinterpret_cast<uint8_t*>(ctx), sizeof(ec_ephemeral_context_t));
    }

    static inline void free_connection_ctx(ec_connection_context_t* ctx) {
        if (!ctx) return;

        if (ctx->boot_data.resp_pub_boot_key) EC_POINT_free(ctx->boot_data.resp_pub_boot_key);
        if (ctx->boot_data.init_pub_boot_key) EC_POINT_free(ctx->boot_data.init_pub_boot_key);
        if (ctx->boot_data.resp_priv_boot_key) BN_free(ctx->boot_data.resp_priv_boot_key);
        if (ctx->boot_data.init_priv_boot_key) BN_free(ctx->boot_data.init_priv_boot_key);
        if (ctx->boot_data.responder_boot_key) em_crypto_t::free_key(const_cast<SSL_KEY*>(ctx->boot_data.responder_boot_key));
        if (ctx->boot_data.initiator_boot_key) em_crypto_t::free_key(const_cast<SSL_KEY*>(ctx->boot_data.initiator_boot_key));

        if (ctx->group) EC_GROUP_free(const_cast<EC_GROUP*>(ctx->group));
        if (ctx->order) BN_free(ctx->order);
        if (ctx->prime) BN_free(ctx->prime);
        if (ctx->bn_ctx) BN_CTX_free(ctx->bn_ctx);
        if (ctx->C_signing_key) em_crypto_t::free_key(ctx->C_signing_key);
        if (ctx->ppk) EC_POINT_free(ctx->ppk);
        if (ctx->net_access_key) em_crypto_t::free_key(ctx->net_access_key);
        if (ctx->connector) rand_zero_free(const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(ctx->connector)), strlen(ctx->connector));

        rand_zero(reinterpret_cast<uint8_t*>(ctx), sizeof(ec_connection_context_t));
    }

// START: Connector methods

    /**
     * @brief Split and decode a connector into its constituent parts
     * 
     * @param conn The connector to split and decode
     * @return std::optional<std::vector<cJSON*>> A vector of cJSON objects containing the decoded parts, or nullopt on failure
     * 
     * @note The caller is responsible for freeing the cJSON objects
     */
    static std::optional<std::vector<cJSON*>> split_decode_connector(const char* conn);


    /**
     * @brief Generate a connector from JWS header, payload, and the key to create the signature with
     * 
     * @param jws_header The JWS Protected Header
     * @param jws_payload The JWS Payload
     * @param sign_key The key to sign the connector with (creating 'sig')
     * @return const char* The generated connector, or NULL on failure
     * 
     * @note The caller is responsible for freeing the returned memory
     * 
     * @paragraph
     * EasyConnect 4.2.1.1 Digital Signature Computation
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
    static const char* generate_connector(const cJSON* jws_header, const cJSON* jws_payload, SSL_KEY* sign_key);

    /**
     * @brief Get the JWS Protected Header from a connector
     * 
     * @param conn The connector to extract the header from
     * @return cJSON* The JWS Protected Header, or nullopt on failure
     * 
     * @note The caller is responsible for freeing the cJSON object
     */
    static inline std::optional<cJSON*> get_jws_header(const char* conn) {
        auto parts = split_decode_connector(conn);
        if (!parts.has_value()) return std::nullopt;
        return parts.value()[0]; // JWS header is the first part
    }

    /** 
     * @brief Get the JWS Payload from a connector
     * 
     * @param conn The connector to extract the payload from
     * @return cJSON* The JWS Payload, or nullopt on failure
     * 
     * @note The caller is responsible for freeing the cJSON object
     */
    static inline std::optional<cJSON*> get_jws_payload(const char* conn) {
        auto parts = split_decode_connector(conn);
        if (!parts.has_value()) return std::nullopt;
        return parts.value()[1]; // JWS payload is the second part
    }

    /**
     * @brief Performs connector validation and gets the JWS Signature from a connector
     * 
     * @param conn The connector to extract the signature from
     * @return cJSON* The JWS Signature, or nullopt on failure
     * 
     * @note The caller is responsible for freeing the cJSON object
     */
    static inline std::optional<cJSON*> get_jws_signature(const char* conn) {
        auto parts = split_decode_connector(conn);
        if (!parts.has_value()) return std::nullopt;
        return parts.value()[2]; // JWS signature is the third part
    }

    /**
     * @brief Generate a PSK from SSID, passphrase
     * 
     * @param pass Passphrase
     * @param ssid SSID
     * @return std::vector<uint8_t> Contains PSK on success, empty otherwise.
     */
    static std::vector<uint8_t> gen_psk(const std::string& pass, const std::string& ssid);

    /**
     * @brief Create a JWS header
     * 
     * @param type "typ" key
     * @param c_signing_key Configurator Signing Key from which "kid" is derived.
     * @return cJSON* cJSON Object on success, nullptr otherwise.
     * @note: Caller must free.
     * 
     * Example return (EasyConnect 4.2.2):
     * 
     *
     *    {
     *        "typ":"dppCon",
     *        "kid":"kMcegDBPmNZVakAsBZOzOoCsvQjkr_nEAp9uF-EDmVE",
     *        "alg":"ES256"
     *    }
     * 
     */
    static cJSON* create_jws_header(const std::string& type, const SSL_KEY *c_signing_key);

    /**
     * @brief Create a JWS Payload
     * 
     * @param c_ctx Persistent context
     * @param groups List of "key":"value" pairs to be included in "groups" array.
     * Only possible keys are "groupID" and "netRole"
     * @param net_access_key The netAccessKey
     * @return cJSON* on success, nullptr otherwise
     * @note: Caller must free
     * 
     * Example return (EasyConnect 4.2.2): 
     * Expiry is optional.
     *    {
     *        "groups":
     *        [
     *            {"groupId":"home","netRole":"sta"},
     *            {"groupId":"cottage","netRole":"sta"}
     *        ],
     *        "netAccessKey":
     *        {
     *            "kty":"EC",
     *            "crv":"P-256",
     *            "x":"Xj-zV2iEiH8XwyA9ijpsL6xyLvDiIBthrHO8ZVxwmpA",
     *            "y":"LUsDBmn7nv-LCnn6fBoXKsKpLGJiVpY_knTckGgsgeU"
     *        },
     *        "expiry":"2019-01-31T22:00:00+02:00"
     *   }
     */
    static cJSON* create_jws_payload(ec_connection_context_t& c_ctx, const std::vector<std::unordered_map<std::string, std::string>>& groups, SSL_KEY* net_access_key, std::optional<std::string> expiry = std::nullopt);

    /**
     * @brief Create a csign object object
     * 
     * @param c_signing_key Configurator Signing Key
     * @param c_ctx Persistent context
     * @return cJSON* on success, nullptr otherwise
     * 
     * csign object, example, as part of "cred" object, EasyConnect 4.5.3
     *   "csign":
     *   {
     *       "kty":"EC",
     *       "crv":"P-256",
     *       "x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
     *       "y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
     *       "kid":"kMcegDBPmNZVakAsBZOzOoCsvQjkr_nEAp9uF-EDmVE"
     *   },
     */
    static cJSON* create_csign_object(ec_connection_context_t& c_ctx, SSL_KEY *c_signing_key);

    /**
     * @brief Derive public ppKey from Configurator Signing Key (must share the same key group)
     * 
     * @param c_signing_key Configurator Signing Key
     * @return EC_POINT *on success, nullptr otherwise.
     * 
     */
    static EC_POINT* create_ppkey_public(SSL_KEY *c_signing_key);

    /**
     * @brief Create a ppkey object object
     * 
     * @param c_ctx Persistent context.
     * @return cJSON* ppKey object on succcess, otherwise nullptr.
     * 
     * EasyConnect 6.5.2
     * ppKey object example: 
     *      "ppKey":
     *      {
     *       "kty":"EC",
     *       "crv":"P-256",
     *       "x":"XX_ZuJR9nMDSb54C_okhGiJ7OjCZOlWOU9m8zAxgUrU",
     *       "y":"Fekm5hyGii80amM_REV5sTOG3-sl1H6MDpZ8TSKnb7c"
     *      },
     */
    static cJSON *create_ppkey_object(ec_connection_context_t& c_ctx);
};

#endif // EC_CRYPTO_H
