#ifndef EC_CRYPTO_H
#define EC_CRYPTO_H

#include "em_base.h"
#include "ec_base.h"

#include <utility>
#include <memory>
#include <vector>

namespace easyconnect {


    // Custom deleter for uint8_t arrays
    struct byte_arr_deleter {
        void operator()(uint8_t* p) const { delete[] p; }
    };
    
    // Define a smart pointer type for buffers
    using buff_ptr = ::std::unique_ptr<uint8_t[], byte_arr_deleter>;
    
    // Define easyconnect::hash_buffer_t as a vector of smart pointer/length pairs
    using hash_buffer_t = std::vector<std::pair<buff_ptr, uint32_t>>;

}

class ec_crypto {
public:

    static int hkdf(const EVP_MD *h, int skip, uint8_t *ikm, int ikmlen, 
        uint8_t *salt, int saltlen, uint8_t *info, int infolen, 
        uint8_t *okm, int okmlen);


    /**
     * @brief Compute the hash of the provided key with an optional prefix
     * 
     * @param key The key to hash
     * @param digest The buffer to store the hash
     * @param prefix The optional prefix to add to the key before hashing (NULL by default)
     * @return int The length of the hash
     */
    static uint8_t* compute_key_hash(const EC_KEY *key, const char *prefix = NULL);
    
    /**
     * @brief Initialize the persistent context params with the bootstrapping key's group as a basis
     * 
     * @param p_ctx The persistent context to initialize
     * @param boot_key The bootstrapping key to use as a basis
     * @return bool true if successful, false otherwise
     */
    static bool init_persistent_ctx(ec_persistent_context_t& p_ctx, const EC_KEY* boot_key);

    /**
     * @brief Compute the hash of the provided buffer
     * 
     * @param buffer The buffer to hash
     * @return uint8_t* The hash of the buffer
     */
    static uint8_t* compute_hash(ec_persistent_context_t& p_ctx, const easyconnect::hash_buffer_t& hashing_elements_buffer);


    static int compute_ke(ec_persistent_context_t& p_ctx, ec_ephemeral_context_t* e_ctx, uint8_t *ke_buffer);

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
    static int compute_hkdf_key(ec_persistent_context_t& p_ctx, uint8_t *key_out, int key_out_len, const char *info_str,
        const BIGNUM **x_val_inputs, int x_val_count, 
        uint8_t *raw_salt, int raw_salt_len);

    /**
     * Calculates L = ((b_R + p_R) modulo q) * B_I then gets the x-coordinate of the result
     * 
     * @param group The EC_GROUP representing the elliptic curve
     * @param bR Private Responder Bootstrapping Key
     * @param pR Private Responder Protocol Key
     * @param BI Public Initiator Bootstrapping Key
     * @return EC_POINT* The calculated L point X value, or NULL on failure. Caller must free with BN_free()
     */
    static BIGNUM* calculate_Lx(ec_persistent_context_t& p_ctx, const BIGNUM* bR, const BIGNUM* pR, const EC_POINT* BI);


    static inline BIGNUM* get_ec_x(ec_persistent_context_t& p_ctx, const EC_POINT *point) {
        BIGNUM *x = BN_new();
        if (EC_POINT_get_affine_coordinates_GFp(p_ctx.group, point,
                    x, NULL, p_ctx.bn_ctx) == 0) {
            printf("%s:%d unable to get x, y of the curve\n", __func__, __LINE__);
            return NULL;
        }
        return x;
    }

    /**
     * @brief Encode an EC point into a protocol key buffer
     * 
     * @param p_ctx The persistent context containing the EC group
     * @param point The EC point to encode
     * @return uint8_t* The encoded protocol key buffer, or NULL on failure. Caller must free with free()
     * 
     */
    static uint8_t* encode_proto_key(ec_persistent_context_t& p_ctx, const EC_POINT *point);
    /**
     * @brief Decode a protocol key buffer into an EC point
     * 
     * @param p_ctx The persistent context containing the EC group
     * @param protocol_key_buff The encoded protocol key buffer
     * @return EC_POINT* The decoded EC point, or NULL on failure. Caller must free with EC_POINT_free()
     */
    static EC_POINT* decode_proto_key(ec_persistent_context_t& p_ctx, const uint8_t* protocol_key_buff);
    /**
     * @brief Compute the shared secret X coordinate for an EC key pair
     *  (for example M.x, N.x)
     * 
     * @param priv The private key (for example p_I, p_R, or b_R)
     * @param pub The public key (for example P_I, B_R, or P_R)
     * @return BIGNUM* The X coordinate of the shared secret, or NULL on failure. Caller must free with BN_free()
     */
    static inline BIGNUM* compute_ec_ss_x(ec_persistent_context_t& p_ctx, const BIGNUM* priv, const EC_POINT* pub) {
        // TODO: May have to adjust to get the group from the public key
        EC_POINT *ss = EC_POINT_new(p_ctx.group);
        if (EC_POINT_mul(p_ctx.group, ss, NULL, pub, priv, p_ctx.bn_ctx) == 0) {
            printf("%s:%d unable to get x, y of the curve\n", __func__, __LINE__);
            return NULL;
        }
        return get_ec_x(p_ctx, ss);
    }

    /**
     * @brief Generate a protocol key pair for the given EC curve
     * 
     * @param p_ctx The persistent context containing the EC curve
     * @return std::pair<const BIGNUM*, const EC_POINT*> Both the private and public keys, or NULL on failure
     * 
     * @warning The caller must free the BIGNUM and EC_POINT with BN_free() and EC_POINT_free() respectively
     */
    static std::pair<const BIGNUM*, const EC_POINT*> generate_proto_keypair(ec_persistent_context_t& p_ctx);

        /**
     * Add a buffer to the hash elements
     * 
     * @note Copies data given into new temporary buffer. Modifications to the original data will not affect the hash elements.
     */
    static inline void add_to_hash(easyconnect::hash_buffer_t& buffer, const uint8_t* data, uint32_t len) {
        if (data != nullptr) {
            // Create a copy of the data with the correct deleter
            easyconnect::buff_ptr data_copy(new uint8_t[len]);
            memcpy(data_copy.get(), data, len);
            buffer.emplace_back(std::move(data_copy), len);
        }
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



    static void print_bignum (BIGNUM *bn);
    static void print_ec_point (const EC_GROUP *group, BN_CTX *bnctx, EC_POINT *point);

    static inline void rand_zero_free(uint8_t *buff, int len) {
        if (buff == NULL) return;
        RAND_bytes(buff, static_cast<int> (len));
        memset(buff, 0, (size_t) len);
        free(buff);
    };

    /**
     * @brief Free an ephemeral context by randomizing, zeroing, and freeing all memory
     * 
     * @param ctx The ephemeral context to free
     * @param nonce_len The length of the nonces in the context
     * @param digest_len The length of the digests/keys in the context
     */
    static inline void free_ephemeral_context(ec_ephemeral_context_t* ctx, int nonce_len, int digest_len) {

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

        rand_zero_free(reinterpret_cast<uint8_t *> (ctx), sizeof(ec_ephemeral_context_t));
    }

};

#endif // EC_CRYPTO_H
