#ifndef EC_CRYPTO_H
#define EC_CRYPTO_H

#include "em_base.h"
#include "ec_base.h"

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
    static int compute_key_hash(EC_KEY *key, uint8_t *digest, const char *prefix = NULL);

    /**
     * @brief Compute intermediate key (k1 or k2)
     * 
     * @param is_first If true, compute k1; if false, compute k2
     * @return 0 on success, -1 on failure
     */
    static int compute_intermediate_key(bool is_first);

    static int compute_ke(uint8_t *ke_buffer);

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
    int compute_hkdf_key(uint8_t *key_out, int key_out_len, const char *info_str,
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
    BIGNUM* calculate_Lx(const BIGNUM* bR, const BIGNUM* pR, const EC_POINT* BI);


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

        if (ctx->protocol_key) EC_KEY_free(ctx->protocol_key);
        if (ctx->E_Id) EC_POINT_free(ctx->E_Id);
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