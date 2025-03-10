#include "ec_crypto.h"
#include "em_crypto.h"
#include "util.h"
#include "ec_util.h"


uint8_t* ec_crypto::compute_key_hash(const EC_KEY *key, const char *prefix)
{
    BIO *bio;
    uint8_t *asn1;
    size_t asn1len;
    uint8_t *addr[2];      // Array of addresses for our two elements
    size_t len[2];       // Array of lengths for our two elements
    
    // Setup the BIO for key conversion
    if ((bio = BIO_new(BIO_s_mem())) == NULL) {
        return NULL;
    }

    // Convert key to DER format
    i2d_EC_PUBKEY_bio(bio, key);
    (void)BIO_flush(bio);
    asn1len = static_cast<size_t>(BIO_get_mem_data(bio, &asn1));

    // Set up our data elements for hashing
    addr[0] = reinterpret_cast<uint8_t *>(const_cast<char *>(prefix));
    len[0] = strlen(prefix);
    addr[1] = asn1;
    len[1] = static_cast<uint32_t> (asn1len);

    // Call platform_SHA256 with our two elements
    uint8_t *digest = new uint8_t[SHA256_DIGEST_LENGTH]();  // () initializes to zero
    uint8_t result = em_crypto_t::platform_SHA256(2, addr, len, digest);

    BIO_free(bio);
    
    if (result == 0) {
        delete[] digest;
        return NULL;
    }
    
    return digest;
}

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
 * @param x_val_inputs Array of BIGNUMs to use as IKM (Concatenated if > 1)
 * @param x_val_count Number of BIGNUMs in the array
 * @param raw_salt Raw salt buffer (can be NULL)
 * @param raw_salt_len Length of raw salt buffer
 * 
 * @return Length of the output key on success, 0 on failure
 */
int ec_crypto::compute_hkdf_key(ec_persistent_context_t& p_ctx, uint8_t *key_out, int key_out_len, const char *info_str,
                     const BIGNUM **x_val_inputs, int x_val_count, 
                     uint8_t *raw_salt, int raw_salt_len)
{
    
    uint8_t *bn_buffer = NULL;
    uint8_t *ikm = NULL;
    int ikm_len = 0;
    int result = 0, offset = 0;
    
    // Calculate prime length for padding and format BIGNUMs
    // Safely convert int to size_t, should always be positive
    int primelen = BN_num_bytes(p_ctx.prime);
    ikm_len = primelen * x_val_count;
    bn_buffer = new uint8_t[ikm_len];
    if (bn_buffer == NULL) {
        perror("malloc");
        return 0;
    }
    memset(bn_buffer, 0, static_cast<size_t>(ikm_len));

    ikm = bn_buffer;
    
    // Format each X Val BIGNUM with proper padding
    for (int i = 0; i < x_val_count; i++) {
        if (x_val_inputs[i] != NULL) {
            int offset = (primelen - BN_num_bytes(x_val_inputs[i]));
            BN_bn2bin(x_val_inputs[i], bn_buffer + (i * primelen) + offset);
        }
    }
    
    // Call the hkdf function
    result = hkdf(p_ctx.hash_fcn, 0, ikm, ikm_len, raw_salt, raw_salt_len, 
                 reinterpret_cast<uint8_t*>(const_cast<char*>(info_str)), strlen(info_str), 
                 key_out, key_out_len);
    
    // Free allocated memory
    if (bn_buffer != NULL) {
        delete[] bn_buffer;
    }
    
    return result;
}


BIGNUM* ec_crypto::calculate_Lx(ec_persistent_context_t& p_ctx, const BIGNUM* bR, const BIGNUM* pR, const EC_POINT* BI)
{
    EC_POINT* L = NULL;
    BIGNUM *sum, *order, *L_x = NULL;
    int success = 0;
    
    // Get the order of the curve (q)
    if (!(order = BN_new()) || !EC_GROUP_get_order(p_ctx.group, order, p_ctx.bn_ctx))
        goto cleanup;
    
    // Calculate (bR + pR) mod q
    if (!(sum = BN_new()) || !BN_mod_add(sum, bR, pR, order, p_ctx.bn_ctx))
        goto cleanup;
    
    // Create result point L
    if (!(L = EC_POINT_new(p_ctx.group)))
        goto cleanup;
    
    // Calculate L = sum * BI (point multiplication)
    if (!EC_POINT_mul(p_ctx.group, L, NULL, BI, sum, p_ctx.bn_ctx))
        goto cleanup;
    
    if (EC_POINT_get_affine_coordinates_GFp(p_ctx.group, L, L_x, NULL, p_ctx.bn_ctx) == 0)
    success = 1;
    
cleanup:
    if (sum) BN_free(sum);
    if (order) BN_free(order);
    
    if (!success && L_x) {
        BN_free(L_x);
        L_x = NULL;
    }
    
    return L_x;
}

// TODO: Might remove, might keep, unsure
/**
 * @brief Compute ke using nonces and coordinate values. Requires, m, n, and (optionally) l to be set before calling.
 * 
 * @param ke_buffer Buffer to store ke (must be pre-allocated)
 * @param I_nonce Initiator nonce
 * @param I_nonce_len Length of initiator nonce
 * @param R_nonce Responder nonce
 * @param R_nonce_len Length of responder nonce
 * @param include_L Whether to include L.x for mutual authentication
 * @return Length of ke on success, 0 on failure
 */
int ec_crypto::compute_ke(ec_persistent_context_t& p_ctx, ec_ephemeral_context_t* e_ctx, uint8_t *ke_buffer)
{
    // Create concatenated nonces buffer (Initiator Nonce | Responder Nonce)
    int total_nonce_len = p_ctx.nonce_len * 2;
    uint8_t *nonces = new uint8_t[total_nonce_len]();
    if (nonces == NULL) {
        printf("%s:%d: Failed to allocate memory for nonces\n", __func__, __LINE__);
        return 0;
    }
    
    // Copy nonces
    memcpy(nonces, e_ctx->i_nonce, static_cast<size_t> (p_ctx.nonce_len));
    memcpy(nonces + p_ctx.nonce_len, e_ctx->r_nonce, static_cast<size_t> (p_ctx.nonce_len));
    
    // Set up BIGNUM array of X values (M, N, and possibly L if mutual auth)
    int x_count = e_ctx->is_mutual_auth ? 3 : 2;
    const BIGNUM **x_val_array = new const BIGNUM*[x_count]();
    if (x_val_array == NULL) {
        delete[] nonces;
        printf("%s:%d: Failed to allocate memory for X values\n", __func__, __LINE__);
        return 0;
    }
    
    x_val_array[0] = e_ctx->m;  // M.x
    x_val_array[1] = e_ctx->n;  // N.x
    if (e_ctx->is_mutual_auth) {
        x_val_array[2] = e_ctx->l;  // L.x if doing mutual auth
    }
    
    // Compute the key
    int result = compute_hkdf_key(
        p_ctx,
        ke_buffer,
        p_ctx.digest_len,
        "DPP Key",
        x_val_array,        // Concatenated X Vals for IKM
        x_count,
        nonces,              // Concatenated Nonces as salt
        total_nonce_len
    );
    
    // Free allocated memory
    delete[] nonces;
    delete[] x_val_array;
    
    return result;
}

int ec_crypto::hkdf (const EVP_MD *h, int skip, uint8_t *ikm, int ikmlen,
        uint8_t *salt, int saltlen, uint8_t *info, size_t infolen,
        uint8_t *okm, int okmlen)
{
    uint8_t *prk, *tweak, ctr, *digest;
    int len;
    int digest_len, prklen, tweaklen;
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    HMAC_CTX ctx;
#else
    HMAC_CTX *ctx = HMAC_CTX_new();
#endif

    digest_len = prklen = EVP_MD_size(h);
    if ((digest = new uint8_t[digest_len]) == NULL) {
        perror("malloc");
        return 0;
    }
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    HMAC_CTX_init(&ctx);
#else
    HMAC_CTX_reset(ctx);
#endif

    if (!skip) {
        /*
         * if !skip then do HKDF-extract
         */
        if ((prk = new uint8_t[digest_len]) == NULL) {
            delete[] digest;
            perror("malloc");
            return 0;
        }
        /*
         * if there's no salt then use all zeros
         */
        if (!salt || (saltlen == 0)) {
            if ((tweak = new uint8_t[digest_len]) == NULL) {
                delete[] digest;
                delete[] prk;
                perror("malloc");
                return 0;
            }
            memset(tweak, 0, static_cast<size_t>(digest_len));
            tweaklen = saltlen;
        } else {
            tweak = salt;
            tweaklen = static_cast<unsigned int> (saltlen);
        }
        (void)HMAC(h, tweak, tweaklen, ikm, static_cast<size_t>(ikmlen), prk, reinterpret_cast<unsigned int*>(&prklen));
        if (!salt || (saltlen == 0)) {
            delete[] tweak;
        }
    } else {
        prk = ikm;
        prklen = static_cast<unsigned int> (ikmlen);
    }
    memset(digest, 0, static_cast<size_t>(digest_len));
    digest_len = 0;
    ctr = 0;
    len = 0;
    while (len < static_cast<unsigned int> (okmlen)) {
        /*
         * T(0) = all zeros
         * T(n) = HMAC(prk, T(n-1) | info | counter)
         * okm = T(0) | ... | T(n)
         */
        ctr++;
#if OPENSSL_VERSION_NUMBER < 0x10100000L
        HMAC_Init_ex(&ctx, prk, prklen, h, NULL);
        HMAC_Update(&ctx, digest, static_cast<size_t>(digest_len));
#else
        HMAC_Init_ex(ctx, prk, prklen, h, NULL);
        HMAC_Update(ctx, digest, static_cast<size_t>(digest_len));
#endif
        if (info && (infolen != 0)) {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
            HMAC_Update(&ctx, info, infolen);
#else
            HMAC_Update(ctx, info, static_cast<size_t> (infolen));
#endif
        }
#if OPENSSL_VERSION_NUMBER < 0x10100000L
        HMAC_Update(&ctx, &ctr, sizeof(uint8_t));
        HMAC_Final(&ctx, digest, reinterpret_cast<unsigned int*>(&digest_len));
#else
        HMAC_Update(ctx, &ctr, sizeof(uint8_t));
        HMAC_Final(ctx, digest, reinterpret_cast<unsigned int*>(&digest_len));
#endif
        if ((len + static_cast<int>(digest_len)) > okmlen) {
            memcpy(okm + len, digest, static_cast<size_t>(okmlen - len));
        } else {
            memcpy(okm + len, digest, static_cast<size_t>(digest_len));
        }
#if OPENSSL_VERSION_NUMBER < 0x10100000L
        HMAC_CTX_cleanup(&ctx);
#else
        HMAC_CTX_free(ctx);
#endif
        len += digest_len;
    }
    if (!skip) {
        delete[] prk;
    }
    delete[] digest;
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    HMAC_CTX_cleanup(&ctx);
#else
    HMAC_CTX_free(ctx);
#endif

    return okmlen;
}

void ec_crypto::print_bignum (BIGNUM *bn)
{
    unsigned char *buf;
    int len = BN_num_bytes(bn);
    if ((buf = new unsigned char[len]) == NULL) {
        printf("Could not print bignum\n");
        return;
    }
    BN_bn2bin(bn, buf);
    util::print_hex_dump(static_cast<unsigned int>(len), buf);
    delete[] buf;
}

void ec_crypto::print_ec_point (const EC_GROUP *group, BN_CTX *bnctx, EC_POINT *point)
{
    BIGNUM *x = NULL, *y = NULL;

    if ((x = BN_new()) == NULL) {
        printf("%s:%d:Could not print ec_point\n", __func__, __LINE__);
        return;
    }

    if ((y = BN_new()) == NULL) {
        BN_free(x);
        printf("%s:%d:Could not print ec_point\n", __func__, __LINE__);
        return;
    }

    if (EC_POINT_get_affine_coordinates_GFp(group, point, x, y, bnctx) == 0) {
        BN_free(y);
        BN_free(x);
        printf("%s:%d:Could not print ec_point\n", __func__, __LINE__);
        return;

    }

    printf("POINT.x:\n");
    print_bignum(x);
    printf("POINT.y:\n");
    print_bignum(y);

    BN_free(y);
    BN_free(x);
}


uint8_t* ec_crypto::compute_hash(ec_persistent_context_t& p_ctx, const easyconnect::hash_buffer_t& hashing_elements_buffer) {
    // Create arrays for platform_hash
    uint8_t hash_buf_size = static_cast<uint8_t>(hashing_elements_buffer.size());
    std::vector<uint8_t*> addr(hash_buf_size);
    std::vector<size_t> len(hash_buf_size);
    
    for (size_t i = 0; i < hash_buf_size; i++) {
        // Get raw pointer from unique_ptr
        addr[i] = hashing_elements_buffer[i].first.get();
        len[i] = hashing_elements_buffer[i].second;
    }

    uint8_t *hash = new uint8_t[p_ctx.digest_len]();
    if (!em_crypto_t::platform_hash(p_ctx.hash_fcn, hash_buf_size, addr.data(), len.data(), hash)) {
        delete[] hash;
        return NULL;
    }
    return hash;
}

bool ec_crypto::init_persistent_ctx(ec_persistent_context_t& p_ctx, const EC_KEY* boot_key){
    p_ctx.group = EC_KEY_get0_group(boot_key);

    p_ctx.prime = BN_new();
    p_ctx.bn_ctx = BN_CTX_new();

    if (!p_ctx.prime || !p_ctx.bn_ctx) {
        printf("%s:%d Some BN NULL\n", __func__, __LINE__);
        BN_free(p_ctx.prime);
        BN_CTX_free(p_ctx.bn_ctx);
        return false;
    }

    p_ctx.nid = EC_GROUP_get_curve_name(p_ctx.group);

    //printf("%s:%d nid: %d\n", __func__, __LINE__, p_ctx.nid);
    switch (p_ctx.nid) {
        case NID_X9_62_prime256v1:
            p_ctx.digest_len = SHA256_DIGEST_LENGTH;
            p_ctx.hash_fcn = EVP_sha256();
            break;
        case NID_secp384r1:
            p_ctx.digest_len = SHA384_DIGEST_LENGTH;
            p_ctx.hash_fcn = EVP_sha384();
            break;
        case NID_secp521r1:
            p_ctx.digest_len = SHA512_DIGEST_LENGTH;
            p_ctx.hash_fcn = EVP_sha512();
            break;
        case NID_X9_62_prime192v1:
            p_ctx.digest_len = SHA256_DIGEST_LENGTH;
            p_ctx.hash_fcn = EVP_sha256();
            break;
        case NID_secp224r1:
            p_ctx.digest_len = SHA256_DIGEST_LENGTH;
            p_ctx.hash_fcn = EVP_sha256();
            break;
        default:
            printf("%s:%d nid:%d not handled\n", __func__, __LINE__, p_ctx.nid);
            return false;
    }

    p_ctx.nonce_len = p_ctx.digest_len*4;

    // Fetch prime
    if (EC_GROUP_get_curve_GFp(p_ctx.group, p_ctx.prime, NULL, NULL, p_ctx.bn_ctx) == 0) {
        printf("%s:%d unable to get x, y of the curve\n", __func__, __LINE__);
        return false;
    }

    printf("Successfully initialized persistent context with params:\n");
    printf("\tNID: %d\n", p_ctx.nid);
    printf("\tDigest Length: %d\n", p_ctx.digest_len);
    printf("\tNonce Length: %d\n", p_ctx.nonce_len);
    printf("\tPrime (Length: %d):\n", BN_num_bytes(p_ctx.prime));
    ec_crypto::print_bignum(p_ctx.prime);
    return true;
}

uint8_t *ec_crypto::encode_proto_key(ec_persistent_context_t &p_ctx, const EC_POINT *point)
{
        
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

    uint8_t* protocol_key_buff = new uint8_t[2*prime_len]();
    if (protocol_key_buff == NULL) {
        printf("%s:%d unable to allocate memory\n", __func__, __LINE__);
        BN_free(x);
        BN_free(y);
        return NULL;
    }
    BN_bn2bin(const_cast<const BIGNUM *>(x), &protocol_key_buff[prime_len - BN_num_bytes(x)]);
    BN_bn2bin(const_cast<const BIGNUM *>(y), &protocol_key_buff[2*prime_len - BN_num_bytes(y)]);

    BN_free(x);
    BN_free(y);

    return protocol_key_buff;
}


EC_POINT *ec_crypto::decode_proto_key(ec_persistent_context_t &p_ctx, const uint8_t *protocol_key_buff)
{
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

std::pair<const BIGNUM *, const EC_POINT *> ec_crypto::generate_proto_keypair(ec_persistent_context_t &p_ctx)
{
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
