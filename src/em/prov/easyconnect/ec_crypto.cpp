#include "ec_crypto.h"
#include "em_crypto.h"
#include "util.h"
#include "ec_util.h"

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/kdf.h>
#endif


uint8_t* ec_crypto::compute_key_hash(const SSL_KEY *key, const char *prefix)
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
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    i2d_PUBKEY_bio(bio, key); // EVP_PKEY
#else
    i2d_EC_PUBKEY_bio(bio, key); // EC_KEY
#endif
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

size_t ec_crypto::compute_hkdf_key(ec_persistent_context_t& p_ctx, uint8_t *key_out, size_t key_out_len, const char *info_str,
                     const BIGNUM **x_val_inputs, int x_val_count, 
                     uint8_t *raw_salt, size_t raw_salt_len)
{
    
    uint8_t *bn_buffer = NULL;
    uint8_t *ikm = NULL;
    int ikm_len = 0;
    size_t result = 0;
    
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
    result = hkdf(p_ctx.hash_fcn, false, ikm, static_cast<size_t>(ikm_len), raw_salt, raw_salt_len, 
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
    
    if (EC_POINT_get_affine_coordinates(p_ctx.group, L, L_x, NULL, p_ctx.bn_ctx) == 0)
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
size_t ec_crypto::compute_ke(ec_persistent_context_t& p_ctx, ec_ephemeral_context_t* e_ctx, uint8_t *ke_buffer)
{
    // Create concatenated nonces buffer (Initiator Nonce | Responder Nonce)
    size_t total_nonce_len = p_ctx.nonce_len * 2;
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
    size_t result = compute_hkdf_key(
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

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
// HKDF implementation using OpenSSL 3.0 APIs
size_t ec_crypto::hkdf(const EVP_MD *h, bool skip_extract, uint8_t *ikm, size_t ikmlen,
    uint8_t *salt, size_t saltlen, uint8_t *info, size_t infolen,
    uint8_t *okm, size_t okmlen)
{
    size_t ret = 0;
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *kctx = NULL;
    OSSL_PARAM params[6], *p = params;
    char *md_name = const_cast<char *>(EVP_MD_name(h));
    if (md_name == NULL) return 0;
    // Set the mode parameter (extract_only, expand_only, or extract_and_expand)
    int mode = EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND;
    if (skip_extract) {
        mode = EVP_KDF_HKDF_MODE_EXPAND_ONLY;
    }

    // Fetch the HKDF implementation
    kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    if (kdf == NULL) {
        goto cleanup;
    }

    // Create a context for the HKDF operation
    kctx = EVP_KDF_CTX_new(kdf);
    if (kctx == NULL) {
        goto cleanup;
    }

    // Set the digest algorithm parameter
    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, md_name, strlen(md_name));

    // Set the key material (IKM) parameter
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, ikm, ikmlen);

    // Set the salt parameter if provided
    if (salt != NULL && saltlen > 0) {
        *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, salt, saltlen);
    }

    // Set the info parameter if provided
    if (info != NULL && infolen > 0) {
        *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, info, infolen);
    }

    *p++ = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode);

    // Terminate the parameter list
    *p = OSSL_PARAM_construct_end();

    // Perform the HKDF operation
    if (EVP_KDF_derive(kctx, okm, okmlen, params) <= 0) {
        goto cleanup;
    }

    ret = okmlen;

cleanup:
    if (kctx != NULL) EVP_KDF_CTX_free(kctx);
    if (kdf != NULL) EVP_KDF_free(kdf);
    return ret;
}
#else
// HKDF implementation using < OpenSSL 3.0 APIs
size_t ec_crypto::hkdf(const EVP_MD *h, bool skip_extract, uint8_t *ikm, size_t ikmlen,
    uint8_t *salt, size_t saltlen, uint8_t *info, size_t infolen,
    uint8_t *okm, size_t okmlen)
{
    uint8_t *prk, *tweak;
    uint8_t ctr;
    uint8_t *digest;
    int len;
    int digest_len, prklen, tweaklen;

    digest_len = prklen = EVP_MD_size(h);
    if ((digest = new uint8_t[digest_len]) == NULL) {
        perror("malloc");
        return 0;
    }

    if (!skip_extract) {
        /*
        * If !skip_extract then perform HKDF-extract phase
        * (normally done unless PRK is already provided)
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
            tweaklen = digest_len;
        } else {
            tweak = salt;
            tweaklen = saltlen;
        }
        
        // Extract phase: PRK = HMAC-Hash(salt, IKM)
        uint8_t *addr[1] = {ikm};
        size_t lengths[1] = {static_cast<size_t>(ikmlen)};
        if (!em_crypto_t::platform_hmac_hash(h, tweak, tweaklen, 1, addr, lengths, prk)) {
            if (!salt || (saltlen == 0)) {
                delete[] tweak;
            }
            delete[] digest;
            delete[] prk;
            return 0;
        }
        
        if (!salt || (saltlen == 0)) {
            delete[] tweak;
        }
    } else {
        // Skip extract phase, use IKM directly as PRK
        prk = ikm;
        prklen = ikmlen;
    }

    // Initialize T(0) as empty
    memset(digest, 0, static_cast<size_t>(digest_len));
    digest_len = 0;
    ctr = 0;
    len = 0;

    // Expansion phase
    while (len < okmlen) {
        /*
        * T(0) = empty string (zero length)
        * T(n) = HMAC(PRK, T(n-1) | info | counter)
        * OKM = T(1) | T(2) | ... | T(n)
        */
        ctr++;
        
        uint8_t *addr[3];  // Maximum possible elements
        size_t lengths[3];
        uint8_t num_elem = 0;
        
        // T(n-1)
        if (digest_len > 0) {
            addr[num_elem] = digest;
            lengths[num_elem] = static_cast<size_t>(digest_len);
            num_elem++;
        }
        
        // info
        if (info && (infolen > 0)) {
            addr[num_elem] = info;
            lengths[num_elem] = infolen;
            num_elem++;
        }
        
        // counter
        addr[num_elem] = &ctr;
        lengths[num_elem] = sizeof(uint8_t);
        num_elem++;
        
        // Calculate T(n) = HMAC(PRK, T(n-1) | info | counter)
        if (!em_crypto_t::platform_hmac_hash(h, prk, prklen, num_elem, addr, lengths, digest)) {
            if (!skip_extract) {
                delete[] prk;
            }
            delete[] digest;
            return 0;
        }
        
        // Set the correct digest length for the next iteration
        digest_len = EVP_MD_size(h);
        
        // Copy the appropriate amount to the output key material
        if ((len + digest_len) > okmlen) {
            memcpy(okm + len, digest, static_cast<size_t>(okmlen - len));
        } else {
            memcpy(okm + len, digest, static_cast<size_t>(digest_len));
        }
        
        len += digest_len;
    }

    if (!skip_extract) {
        delete[] prk;
    }
    delete[] digest;

    return okmlen;
}
#endif
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

    if (EC_POINT_get_affine_coordinates(group, point, x, y, bnctx) == 0) {
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

bool ec_crypto::init_persistent_ctx(ec_persistent_context_t& p_ctx, const SSL_KEY *boot_key){
    p_ctx.group = em_crypto_t::get_key_group(boot_key); 

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
    if (EC_GROUP_get_curve(p_ctx.group, p_ctx.prime, NULL, NULL, p_ctx.bn_ctx) == 0) {
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

    if (EC_POINT_get_affine_coordinates(p_ctx.group, point,
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

    if (EC_POINT_set_affine_coordinates(p_ctx.group, point, x, y, p_ctx.bn_ctx) == 0) {
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
    SSL_KEY *proto_key = em_crypto_t::generate_ec_key(p_ctx.nid);

    const EC_POINT* proto_pub = em_crypto_t::get_pub_key_point(proto_key);
    if (proto_pub == NULL) {
        printf("%s:%d Could not get protocol public key\n", __func__, __LINE__);
        return std::pair<BIGNUM*, EC_POINT*>(NULL, NULL);
    }

    const BIGNUM* proto_priv = em_crypto_t::get_priv_key_bn(proto_key);
    if (proto_priv == NULL) {
        printf("%s:%d Could not get protocol private key\n", __func__, __LINE__);
        return std::pair<BIGNUM*, EC_POINT*>(NULL, NULL);
    }

    return std::pair<const BIGNUM*, const EC_POINT*>(proto_priv, proto_pub);
}
