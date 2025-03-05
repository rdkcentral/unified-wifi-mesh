#ifndef EC_CRYPTO_H
#define EC_CRYPTO_H

#include "em_base.h"
#include "ec_base.h"

#include <utility>

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


    static int compute_ke(ec_persistent_context_t& p_ctx, ec_ephemeral_context_t e_ctx, uint8_t *ke_buffer);

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
    static inline uint8_t* encode_proto_key(ec_persistent_context_t& p_ctx, const EC_POINT *point) {
        
        BIGNUM *x = BN_new();
        BIGNUM *y = BN_new();

        if (EC_POINT_get_affine_coordinates_GFp(p_ctx.group, point,
            x, y, p_ctx.bn_ctx) == 0) {
            printf("%s:%d unable to get x, y of the curve\n", __func__, __LINE__);
            BN_free(x);
            BN_free(y);
            return NULL;
        }

        int prime_len = BN_num_bytes(p_ctx.prime);

        uint8_t* protocol_key_buff = (uint8_t *)calloc(2*prime_len, 1);
        if (protocol_key_buff == NULL) {
            printf("%s:%d unable to allocate memory\n", __func__, __LINE__);
            BN_free(x);
            BN_free(y);
            return NULL;
        }
        BN_bn2bin((const BIGNUM *)x, &protocol_key_buff[prime_len - BN_num_bytes(x)]);
        BN_bn2bin((const BIGNUM *)y, &protocol_key_buff[2*prime_len - BN_num_bytes(y)]);

        BN_free(x);
        BN_free(y);

        return protocol_key_buff;
    }

    /**
     * @brief Decode a protocol key buffer into an EC point
     * 
     * @param p_ctx The persistent context containing the EC group
     * @param protocol_key_buff The encoded protocol key buffer
     * @return EC_POINT* The decoded EC point, or NULL on failure. Caller must free with EC_POINT_free()
     */
    static inline EC_POINT* decode_proto_key(ec_persistent_context_t& p_ctx, const uint8_t* protocol_key_buff) {
        if (protocol_key_buff == NULL) {
            printf("%s:%d null protocol key buffer\n", __func__, __LINE__);
            return NULL;
        }

        int prime_len = BN_num_bytes(p_ctx.prime);
        BIGNUM *x = BN_bin2bn(protocol_key_buff, prime_len, NULL);
        BIGNUM *y = BN_bin2bn(protocol_key_buff + prime_len, prime_len, NULL);
        EC_POINT *point = EC_POINT_new(p_ctx.group);
        
        if (x == NULL || y == NULL) {
            printf("%s:%d unable to convert buffer to BIGNUMs\n", __func__, __LINE__);
            goto err;
        }
        
        if (point == NULL) {
            printf("%s:%d unable to create EC_POINT\n", __func__, __LINE__);
            goto err;
        }

        if (EC_POINT_set_affine_coordinates_GFp(p_ctx.group, point, x, y, p_ctx.bn_ctx) == 0) {
            printf("%s:%d unable to set coordinates for the point\n", __func__, __LINE__);
            goto err;
        }

        // Verify the point is on the curve
        if (EC_POINT_is_on_curve(p_ctx.group, point, p_ctx.bn_ctx) == 0) {
            printf("%s:%d point is not on the curve\n", __func__, __LINE__);
            goto err;
        }

        BN_free(x);
        BN_free(y);
        
        return point;

    err:
        if (x) BN_free(x);
        if (y) BN_free(y);
        if (point) EC_POINT_free(point);
        return NULL;
    }
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
    static inline std::pair<const BIGNUM*, const EC_POINT*> generate_proto_keypair(ec_persistent_context_t& p_ctx) {
        EC_KEY* proto_key = EC_KEY_new_by_curve_name(p_ctx.nid);
        if (proto_key == NULL) {
            printf("%s:%d Could not create protocol key\n", __func__, __LINE__);
            return std::pair<BIGNUM*, EC_POINT*>(NULL, NULL);
        }
    
        if (EC_KEY_generate_key(proto_key) == 0) {
            printf("%s:%d Could not generate protocol key\n", __func__, __LINE__);
            return std::pair<BIGNUM*, EC_POINT*>(NULL, NULL);
        }
    
        const EC_POINT* proto_pub = EC_KEY_get0_public_key(proto_key);
        if (proto_pub == NULL) {
            printf("%s:%d Could not get protocol public key\n", __func__, __LINE__);
            return std::pair<BIGNUM*, EC_POINT*>(NULL, NULL);
        }
    
        const BIGNUM* proto_priv = EC_KEY_get0_private_key(proto_key);
        if (proto_priv == NULL) {
            printf("%s:%d Could not get protocol private key\n", __func__, __LINE__);
            return std::pair<BIGNUM*, EC_POINT*>(NULL, NULL);
        }

        return std::pair<const BIGNUM*, const EC_POINT*>(proto_priv, proto_pub);
    }



    static void print_bignum (BIGNUM *bn);
    static void print_ec_point (const EC_GROUP *group, BN_CTX *bnctx, EC_POINT *point);

    static inline void rand_zero_free(uint8_t *buff, size_t len) {
        if (buff == NULL) return;
        RAND_bytes(buff, len);
        memset(buff, 0, len);
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
        if (ctx->i_nonce) rand_zero_free(ctx->i_nonce, nonce_len);
        if (ctx->r_nonce) rand_zero_free(ctx->r_nonce, nonce_len);
        if (ctx->e_nonce) rand_zero_free(ctx->e_nonce, nonce_len);
        if (ctx->c_nonce) rand_zero_free(ctx->c_nonce, nonce_len);
        if (ctx->k1) rand_zero_free(ctx->k1, digest_len);
        if (ctx->k2) rand_zero_free(ctx->k2, digest_len);
        if (ctx->ke) rand_zero_free(ctx->ke, digest_len);
        if (ctx->bk) rand_zero_free(ctx->bk, digest_len);

        rand_zero_free((uint8_t *)ctx, sizeof(ec_ephemeral_context_t));
    }

};

#endif // EC_CRYPTO_H