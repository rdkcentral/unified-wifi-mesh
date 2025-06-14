#include "ec_crypto.h"
#include "em_crypto.h"
#include "util.h"
#include "ec_util.h"

#include "cjson/cJSON.h"
#include <numeric>

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
    i2d_EC_PUBKEY_bio(bio, const_cast<SSL_KEY*>(key)); // EC_KEY
#endif
    (void)BIO_flush(bio);
    asn1len = static_cast<size_t>(BIO_get_mem_data(bio, &asn1));

    // Set up our data elements for hashing
    uint8_t hash_elem_idx = 0;
    if (prefix != NULL) {
        addr[hash_elem_idx] = reinterpret_cast<uint8_t *>(const_cast<char *>(prefix));
        len[hash_elem_idx] = strlen(prefix);
        hash_elem_idx++;
    }

    addr[hash_elem_idx] = asn1;
    len[hash_elem_idx] = static_cast<uint32_t> (asn1len);

    uint8_t hash_elem_count = static_cast<uint8_t>(hash_elem_idx + 1);

    // Call platform_SHA256 with our two elements
    uint8_t *digest = reinterpret_cast<uint8_t*>(calloc(SHA256_DIGEST_LENGTH, 1));
    uint8_t result = em_crypto_t::platform_SHA256(hash_elem_count, addr, len, digest);

    BIO_free(bio);
    
    if (result == 0) {
        free(digest);
        return NULL;
    }
    
    return digest;
}

size_t ec_crypto::compute_hkdf_key(ec_connection_context_t& c_ctx, uint8_t *key_out, size_t key_out_len, const char *info_str,
                     const BIGNUM **x_val_inputs, int x_val_count, 
                     uint8_t *raw_salt, size_t raw_salt_len)
{
    
    uint8_t *bn_buffer = NULL;
    uint8_t *ikm = NULL;
    int ikm_len = 0;
    size_t result = 0;
    
    // Calculate prime length for padding and format BIGNUMs
    // Safely convert int to size_t, should always be positive
    int primelen = BN_num_bytes(c_ctx.prime);
    ikm_len = primelen * x_val_count;
    bn_buffer = new uint8_t[static_cast<size_t>(ikm_len)];
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
    result = hkdf(c_ctx.hash_fcn, false, ikm, static_cast<size_t>(ikm_len), raw_salt, raw_salt_len, 
                 reinterpret_cast<uint8_t*>(const_cast<char*>(info_str)), strlen(info_str), 
                 key_out, key_out_len);
    
    // Free allocated memory
    if (bn_buffer != NULL) {
        delete[] bn_buffer;
    }
    
    return result;
}


BIGNUM* ec_crypto::calculate_Lx(ec_connection_context_t& c_ctx, const BIGNUM* bR, const BIGNUM* pR, const EC_POINT* BI)
{
    EC_POINT* L = NULL;
    BIGNUM *sum = NULL, *order, *L_x = NULL;
    int success = 0;
    
    // Get the order of the curve (q)
    if (!(order = BN_new()) || !EC_GROUP_get_order(c_ctx.group, order, c_ctx.bn_ctx))
        goto cleanup;
    
    // Calculate (bR + pR) mod q
    if (!(sum = BN_new()) || !BN_mod_add(sum, bR, pR, order, c_ctx.bn_ctx))
        goto cleanup;
    
    // Create result point L
    if (!(L = EC_POINT_new(c_ctx.group)))
        goto cleanup;
    
    // Calculate L = sum * BI (point multiplication)
    if (!EC_POINT_mul(c_ctx.group, L, NULL, BI, sum, c_ctx.bn_ctx))
        goto cleanup;
    
    if (EC_POINT_get_affine_coordinates(c_ctx.group, L, L_x, NULL, c_ctx.bn_ctx) == 0)
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
size_t ec_crypto::compute_ke(ec_connection_context_t& c_ctx, ec_ephemeral_context_t* e_ctx, uint8_t *ke_buffer)
{
    // Create concatenated nonces buffer (Initiator Nonce | Responder Nonce)
    size_t total_nonce_len = static_cast<size_t>(c_ctx.nonce_len * 2);
    uint8_t *nonces = new uint8_t[total_nonce_len]();
    if (nonces == NULL) {
        em_printfout("Failed to allocate memory for nonces");
        return 0;
    }
    
    // Copy nonces
    memcpy(nonces, e_ctx->i_nonce, static_cast<size_t> (c_ctx.nonce_len));
    memcpy(nonces + c_ctx.nonce_len, e_ctx->r_nonce, static_cast<size_t> (c_ctx.nonce_len));
    
    // Set up BIGNUM array of X values (M, N, and possibly L if mutual auth)
    int x_count = e_ctx->is_mutual_auth ? 3 : 2;
    const BIGNUM **x_val_array = new const BIGNUM*[x_count]();
    if (x_val_array == NULL) {
        delete[] nonces;
        em_printfout("Failed to allocate memory for X values");
        return 0;
    }
    
    x_val_array[0] = e_ctx->m;  // M.x
    x_val_array[1] = e_ctx->n;  // N.x
    if (e_ctx->is_mutual_auth) {
        x_val_array[2] = e_ctx->l;  // L.x if doing mutual auth
    }
    
    // Compute the key
    size_t result = compute_hkdf_key(
        c_ctx,
        ke_buffer,
        c_ctx.digest_len,
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
    OSSL_PARAM params[6];
    OSSL_PARAM *p = params;
    char *md_name = const_cast<char *>(EVP_MD_name(h));
    if (md_name == NULL) return 0;

    if (okmlen == 0 || okm == NULL) {
        em_printfout("Invalid output key material length or buffer");
        return 0;
    }
    if (h == NULL) {
        em_printfout("Invalid hash function");
        return 0;
    }
    if (ikmlen == 0 || ikm == NULL) {
        em_printfout("Invalid input key material length or buffer");
        return 0;
    }
    if (saltlen > 0 && salt == NULL) {
        em_printfout("Invalid salt");
        return 0;
    }
    if (infolen > 0 && info == NULL) {
        em_printfout("Invalid info");
        return 0;
    }

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
    size_t len;
    size_t digest_len, prklen, tweaklen;

    if (okmlen == 0 || okm == NULL) {
        em_printfout("Invalid output key material length or buffer");
        return 0;
    }
    if (h == NULL) {
        em_printfout("Invalid hash function");
        return 0;
    }
    if (ikmlen == 0 || ikm == NULL) {
        em_printfout("Invalid input key material length or buffer");
        return 0;
    }
    if (saltlen > 0 && salt == NULL) {
        em_printfout("Invalid salt");
        return 0;
    }
    if (infolen > 0 && info == NULL) {
        em_printfout("Invalid info");
        return 0;
    }

    digest_len = prklen = static_cast<size_t>(EVP_MD_size(h));
    if ((digest = reinterpret_cast<uint8_t*>(calloc(digest_len, 1))) == NULL) {
        perror("malloc");
        return 0;
    }

    if (!skip_extract) {
        /*
        * If !skip_extract then perform HKDF-extract phase
        * (normally done unless PRK is already provided)
        */
        if ((prk = reinterpret_cast<uint8_t*>(calloc(digest_len, 1))) == NULL) {
            delete[] digest;
            perror("malloc");
            return 0;
        }
        /*
        * if there's no salt then use all zeros
        */
        if (!salt || (saltlen == 0)) {
            if ((tweak = reinterpret_cast<uint8_t*>(calloc(digest_len, 1))) == NULL) {
                delete[] digest;
                delete[] prk;
                perror("malloc");
                return 0;
            }
            memset(tweak, 0, digest_len);
            tweaklen = digest_len;
        } else {
            tweak = salt;
            tweaklen = saltlen;
        }
        
        // Extract phase: PRK = HMAC-Hash(salt, IKM)
        uint8_t *addr[1] = {ikm};
        size_t lengths[1] = {ikmlen};
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
    memset(digest, 0, digest_len);
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
            lengths[num_elem] = digest_len;
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
        digest_len = static_cast<size_t>(EVP_MD_size(h));
        
        // Copy the appropriate amount to the output key material
        if ((len + digest_len) > okmlen) {
            memcpy(okm + len, digest, okmlen - len);
        } else {
            memcpy(okm + len, digest, digest_len);
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
    if ((buf = reinterpret_cast<uint8_t*>(calloc(static_cast<size_t>(len), 1))) == NULL) {
        printf("Could not print bignum\n");
        return;
    }
    BN_bn2bin(bn, buf);
    util::print_hex_dump(static_cast<unsigned int>(len), buf);
    free(buf);
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


uint8_t* ec_crypto::compute_hash(ec_connection_context_t& c_ctx, const easyconnect::hash_buffer_t& hashing_elements_buffer) {
    // Create arrays for platform_hash
    uint8_t hash_buf_size = static_cast<uint8_t>(hashing_elements_buffer.size());
    std::vector<uint8_t*> addr(hash_buf_size);
    std::vector<size_t> len(hash_buf_size);
    
    for (size_t i = 0; i < hash_buf_size; i++) {
        // Get raw pointer from unique_ptr
        addr[i] = hashing_elements_buffer[i].first.get();
        len[i] = hashing_elements_buffer[i].second;
    }

    uint8_t *hash = reinterpret_cast<uint8_t*>(calloc(c_ctx.digest_len, 1));
    if (!em_crypto_t::platform_hash(c_ctx.hash_fcn, hash_buf_size, addr.data(), len.data(), hash)) {
        free(hash);
        return NULL;
    }
    return hash;
}

bool ec_crypto::init_connection_ctx(ec_connection_context_t& c_ctx, const SSL_KEY *boot_key){
    c_ctx.group = em_crypto_t::get_key_group(boot_key); 

    c_ctx.prime = BN_new();
    c_ctx.bn_ctx = BN_CTX_new();

    if (!c_ctx.prime || !c_ctx.bn_ctx) {
        em_printfout("Some BN NULL");
        BN_free(c_ctx.prime);
        BN_CTX_free(c_ctx.bn_ctx);
        return false;
    }

    c_ctx.order = BN_new();

    if (!EC_GROUP_get_order(c_ctx.group, c_ctx.order, c_ctx.bn_ctx)) {
        BN_free(c_ctx.order);
        BN_free(c_ctx.prime);
        BN_CTX_free(c_ctx.bn_ctx);
        return false;
    }

    c_ctx.nid = EC_GROUP_get_curve_name(c_ctx.group);

    //em_printfout("nid: %d", c_ctx.nid);
    switch (c_ctx.nid) {
        case NID_X9_62_prime256v1:
            c_ctx.digest_len = SHA256_DIGEST_LENGTH;
            c_ctx.hash_fcn = EVP_sha256();
            break;
        case NID_secp384r1:
            c_ctx.digest_len = SHA384_DIGEST_LENGTH;
            c_ctx.hash_fcn = EVP_sha384();
            break;
        case NID_secp521r1:
            c_ctx.digest_len = SHA512_DIGEST_LENGTH;
            c_ctx.hash_fcn = EVP_sha512();
            break;
        case NID_X9_62_prime192v1:
            c_ctx.digest_len = SHA256_DIGEST_LENGTH;
            c_ctx.hash_fcn = EVP_sha256();
            break;
        case NID_secp224r1:
            c_ctx.digest_len = SHA256_DIGEST_LENGTH;
            c_ctx.hash_fcn = EVP_sha256();
            break;
        default:
            em_printfout("nid:%d not handled", c_ctx.nid);
            BN_free(c_ctx.order);
            BN_free(c_ctx.prime);
            BN_CTX_free(c_ctx.bn_ctx);
            return false;
    }

    c_ctx.nonce_len = static_cast<uint16_t>(c_ctx.digest_len*4);

    // Fetch prime
    if (EC_GROUP_get_curve(c_ctx.group, c_ctx.prime, NULL, NULL, c_ctx.bn_ctx) == 0) {
        em_printfout("unable to get x, y of the curve");
        BN_free(c_ctx.order);
        BN_free(c_ctx.prime);
        BN_CTX_free(c_ctx.bn_ctx);
        return false;
    }

    printf("Successfully initialized persistent context with params:\n");
    printf("\tNID: %d\n", c_ctx.nid);
    printf("\tDigest Length: %d\n", c_ctx.digest_len);
    printf("\tNonce Length: %d\n", c_ctx.nonce_len);
    printf("\tPrime (Length: %d):\n", BN_num_bytes(c_ctx.prime));
    ec_crypto::print_bignum(c_ctx.prime);

    // Allocate nonces
    c_ctx.eph_ctx.i_nonce = reinterpret_cast<uint8_t*>(calloc(static_cast<size_t>(c_ctx.nonce_len), 1));
    c_ctx.eph_ctx.r_nonce = reinterpret_cast<uint8_t*>(calloc(static_cast<size_t>(c_ctx.nonce_len), 1));
    c_ctx.eph_ctx.e_nonce = reinterpret_cast<uint8_t*>(calloc(static_cast<size_t>(c_ctx.nonce_len), 1));
    c_ctx.eph_ctx.c_nonce = reinterpret_cast<uint8_t*>(calloc(static_cast<size_t>(c_ctx.nonce_len), 1));
    
    return true;
}

scoped_buff ec_crypto::encode_ec_point(ec_connection_context_t &c_ctx, const EC_POINT *point)
{
    scoped_bn x(BN_new());
    scoped_bn y(BN_new());

    if (EC_POINT_get_affine_coordinates(c_ctx.group, point, x.get(), y.get(), c_ctx.bn_ctx) == 0) {
        em_printfout("unable to get x, y of the curve");
        return nullptr;
    }

    int prime_len = BN_num_bytes(c_ctx.prime);

    uint8_t *key_buff = reinterpret_cast<uint8_t *>(calloc(static_cast<size_t>(2 * prime_len), 1));
    if (key_buff == NULL) {
        em_printfout("unable to allocate memory");
        return nullptr;
    }
    
    BN_bn2bin(const_cast<const BIGNUM *>(x.get()), &key_buff[prime_len - BN_num_bytes(x.get())]);
    BN_bn2bin(const_cast<const BIGNUM *>(y.get()),
              &key_buff[2 * prime_len - BN_num_bytes(y.get())]);

    scoped_buff key_buff_ptr(key_buff);

    return key_buff_ptr;
}

EC_POINT *ec_crypto::decode_ec_point(ec_connection_context_t &c_ctx, const uint8_t *key_buff)
{
    if (key_buff == NULL) {
        em_printfout("null protocol key buffer");
        return NULL;
    }

    int prime_len = BN_num_bytes(c_ctx.prime);
    BIGNUM *x = BN_bin2bn(key_buff, prime_len, NULL);
    BIGNUM *y = BN_bin2bn(key_buff + prime_len, prime_len, NULL);
    EC_POINT *point = EC_POINT_new(c_ctx.group);
    
    if (x == NULL || y == NULL) {
        em_printfout("unable to convert buffer to BIGNUMs");
        goto err;
    }
    
    if (point == NULL) {
        em_printfout("unable to create EC_POINT");
        goto err;
    }

    if (EC_POINT_set_affine_coordinates(c_ctx.group, point, x, y, c_ctx.bn_ctx) == 0) {
        em_printfout("unable to set coordinates for the point");
        goto err;
    }

    // Verify the point is on the curve
    if (EC_POINT_is_on_curve(c_ctx.group, point, c_ctx.bn_ctx) == 0) {
        em_printfout("point is not on the curve");
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




std::pair<const BIGNUM *, const EC_POINT *> ec_crypto::generate_proto_keypair(ec_connection_context_t &c_ctx)
{
    SSL_KEY *proto_key = em_crypto_t::generate_ec_key(c_ctx.nid);

    const EC_POINT* proto_pub = em_crypto_t::get_pub_key_point(proto_key);
    if (proto_pub == NULL) {
        em_printfout("Could not get protocol public key");
        return std::pair<BIGNUM*, EC_POINT*>(NULL, NULL);
    }

    const BIGNUM* proto_priv = em_crypto_t::get_priv_key_bn(proto_key);
    if (proto_priv == NULL) {
        em_printfout("Could not get protocol private key");
        return std::pair<BIGNUM*, EC_POINT*>(NULL, NULL);
    }

    return std::pair<const BIGNUM*, const EC_POINT*>(proto_priv, proto_pub);
}

std::optional<std::vector<cJSON*>> ec_crypto::split_decode_connector(const char* conn) {
    if (conn == NULL) {
        em_printfout("Connector is NULL");
        return std::nullopt;
    }
    std::string connector(conn);
    // Split connector by '.'
    std::vector<std::string> parts = util::split_by_delim(connector, '.');
    if (parts.size() != 3) {
        em_printfout("Connector does not have 3 parts");
        if (parts.size() == 2){
            em_printfout("Connector is missing signature (len=2)");
        }
        return std::nullopt;
    }

    bool did_succeed = true;
    
    // Base 64 URL + JSON decode each part
    std::vector<cJSON*> decoded_parts;
    for (size_t i = 0; i < parts.size(); i++) {
        auto part = parts[i];
        auto decoded = em_crypto_t::base64url_decode(part);
        if (decoded == std::nullopt) {
            em_printfout("Failed to decode part %ld, exiting", i);
            did_succeed = false;
            break;
        }
        std::string decoded_str(decoded->begin(), decoded->end());
        
        // Test if JSON decodes properly
        cJSON *json = cJSON_Parse(decoded_str.c_str());
        
        if (json == NULL) {
            cJSON_Delete(json);
            em_printfout("Failed to parse JSON part %ld, exiting", i);
            did_succeed = false;
            break;
        }
        decoded_parts.push_back(json);
        
    }

    if (!did_succeed) {
        em_printfout("Full validation/decoding failed");
        for (size_t i = 0; i < decoded_parts.size(); i++) {
            em_printfout("Cleaning up part %ld", i);
            cJSON_Delete(decoded_parts[i]);
        }
        return std::nullopt;
    }
    return decoded_parts;
}

std::optional<std::vector<std::string>> ec_crypto::split_connector(const char *conn)
{
    if (conn == nullptr) {
        return std::nullopt;
    }

    std::string connector(conn);
    size_t first_dot = connector.find('.');
    size_t second_dot = connector.find('.', first_dot + 1);

    if (first_dot == std::string::npos || second_dot == std::string::npos) {
        em_printfout("Malformed connector: %s", connector.c_str());
        return std::nullopt;
    }

    std::optional<std::vector<std::string>> parts = std::vector<std::string>{
        connector.substr(0, first_dot), // Header
        connector.substr(first_dot + 1, second_dot - first_dot - 1), // Payload
        connector.substr(second_dot + 1) // Sig
    };

    return parts;
}

std::vector<uint8_t> ec_crypto::concat_nonces(const std::vector<std::vector<uint8_t>>& nonces)
{
    std::vector<uint8_t> result;
    size_t total_size = std::accumulate(nonces.begin(), nonces.end(), size_t{0}, 
        [](size_t sum, const std::vector<uint8_t>& nonce) { return sum + nonce.size(); });

    result.reserve(total_size);

    for (const auto& nonce : nonces) {
        result.insert(result.end(), nonce.begin(), nonce.end());
    }

    return result;
}

EC_POINT *ec_crypto::decode_ec_point_from_connector_netaccesskey(ec_connection_context_t& ctx, cJSON *net_access_key)
{
    if (net_access_key == nullptr) {
        return nullptr;
    }
    cJSON *x = cJSON_GetObjectItem(net_access_key, "x");
    cJSON *y = cJSON_GetObjectItem(net_access_key, "y");
    if (!x || !y || !cJSON_IsString(x) || !cJSON_IsString(y)) {
        em_printfout("Invalid netAccessKey format in C-Connector");
        return nullptr;
    }
    std::optional<std::vector<uint8_t>> x_bytes = em_crypto_t::base64url_decode(x->valuestring);
    std::optional<std::vector<uint8_t>> y_bytes = em_crypto_t::base64url_decode(y->valuestring);
    if (!x_bytes.has_value() || !y_bytes.has_value()) {
        em_printfout("Failed to get x, y points from netAccessKey in C-Connector");
        return nullptr;
    }
    std::vector<uint8_t> key_buff(x_bytes->size() + y_bytes->size());
    key_buff.insert(key_buff.end(), x_bytes->begin(), x_bytes->end());
    key_buff.insert(key_buff.end(), y_bytes->begin(), y_bytes->end());
    return ec_crypto::decode_ec_point(ctx, key_buff.data());
}

std::optional<std::string> ec_crypto::generate_connector(const cJSON * jws_header, const cJSON * jws_payload,  SSL_KEY* sign_key)
{
    if (jws_header == NULL || jws_payload == NULL || sign_key == NULL) {
        em_printfout("Invalid input");
        return std::nullopt;
    }

    char* jws_header_cstr = cJSON_PrintUnformatted(jws_header);
    char* jws_payload_cstr = cJSON_PrintUnformatted(jws_payload);
    if (jws_header_cstr == NULL || jws_payload_cstr == NULL) {
        em_printfout("Failed to convert cJSON to string");
        if (jws_header_cstr) free(jws_header_cstr);
        if (jws_payload_cstr) free(jws_payload_cstr);
        return std::nullopt;
    }
    std::string jws_header_str(jws_header_cstr);
    std::string jws_payload_str(jws_payload_cstr);
    free(jws_header_cstr);
    free(jws_payload_cstr);

    // NOTE: Currently assuming it's always UTF-8 already.
    std::string base64_jws_header = em_crypto_t::base64url_encode(jws_header_str);
    std::string base64_jws_payload = em_crypto_t::base64url_encode(jws_payload_str);

    std::string sig_data = base64_jws_header + "." + base64_jws_payload;
    std::vector<uint8_t> sig_data_vec(sig_data.begin(), sig_data.end());
    std::optional<std::vector<uint8_t>> signature = em_crypto_t::sign_data_ecdsa(sig_data_vec, sign_key);
    if (!signature.has_value()) {
        em_printfout("Failed to sign data");
        return std::nullopt;
    }

    std::string base64_signature = em_crypto_t::base64url_encode(signature.value());
    if (base64_signature.empty()) {
        em_printfout("Failed to encode signature");
        return std::nullopt;
    }

    std::string connector = base64_jws_header + "." + base64_jws_payload + "." + base64_signature;

    return connector;
}

std::vector<uint8_t> ec_crypto::gen_psk(const std::string& pass, const std::string& ssid)
{
    // 4096 -- number of iterations
    // 256 / 8 -- hash size
    // both from 802.11-2020 J.4.1
    std::vector<uint8_t> ret(256/8);
    int ssid_len = static_cast<int>(ssid.length());
    int pass_len = static_cast<int>(pass.length());
    if (PKCS5_PBKDF2_HMAC_SHA1(pass.data(), pass_len, reinterpret_cast<const unsigned char *>(ssid.data()), ssid_len, 4096, static_cast<int>(ret.size()), ret.data()) != 1) return {};
    return ret;
}

cJSON* ec_crypto::create_jws_header(const std::string& type, const SSL_KEY *c_signing_key)
{
    if (c_signing_key == nullptr) return nullptr;
    cJSON *jwsHeaderObj = cJSON_CreateObject();
    uint8_t *hashed_c_sign_key = compute_key_hash(c_signing_key);
    std::string base64_c_sign_key_hash = em_crypto_t::base64_encode(hashed_c_sign_key, SHA256_DIGEST_LENGTH);
    free(hashed_c_sign_key);
    cJSON_AddStringToObject(jwsHeaderObj, "typ", type.c_str());
    cJSON_AddStringToObject(jwsHeaderObj, "kid", base64_c_sign_key_hash.c_str());
    cJSON_AddStringToObject(jwsHeaderObj, "alg", "ES256");
    return jwsHeaderObj;
}

cJSON* ec_crypto::create_jws_payload(ec_connection_context_t& c_ctx, const std::vector<std::unordered_map<std::string, std::string>>& groups, SSL_KEY* net_access_key, std::optional<std::string> expiry, std::optional<uint8_t> version)
{
    if (net_access_key == nullptr) return nullptr;
    
    cJSON* jwsPayloadObj = cJSON_CreateObject();
    cJSON* groupsArr = cJSON_CreateArray();
    cJSON_AddItemToObject(jwsPayloadObj, "groups", groupsArr);

    for (const auto& group : groups) {  
        cJSON* groupObj = cJSON_CreateObject();
        for (const auto& [key, val] : group) {
            cJSON_AddStringToObject(groupObj, key.c_str(), val.c_str());  
        }

        cJSON_AddItemToArray(groupsArr, groupObj);
    }

    cJSON *netAccessKeyObj = cJSON_CreateObject();
    cJSON_AddItemToObject(jwsPayloadObj, "netAccessKey", netAccessKeyObj);
    cJSON_AddStringToObject(netAccessKeyObj, "kty", "EC");
    cJSON_AddStringToObject(netAccessKeyObj, "crv", "P-256");
    EC_GROUP *key_group = em_crypto_t::get_key_group(net_access_key);
    EC_POINT *key_point = em_crypto_t::get_pub_key_point(net_access_key, key_group);
    auto [x, y] = get_ec_x_y(c_ctx, key_point);
    cJSON_AddStringToObject(netAccessKeyObj, "x", em_crypto_t::base64_encode(ec_crypto::BN_to_vec(x)).c_str());
    cJSON_AddStringToObject(netAccessKeyObj, "y", em_crypto_t::base64_encode(ec_crypto::BN_to_vec(y)).c_str());
    if (expiry.has_value()) {
        cJSON_AddStringToObject(jwsPayloadObj, "expiry", expiry.value().c_str());
    }
    if (version.has_value()) {
        cJSON_AddStringToObject(jwsPayloadObj, "version", std::to_string(static_cast<unsigned int>(version.value())).c_str());
    }
    EC_GROUP_free(key_group);
    EC_POINT_free(key_point);
    BN_free(x);
    BN_free(y);
    return jwsPayloadObj;
}

cJSON *ec_crypto::create_csign_object(ec_connection_context_t& c_ctx, SSL_KEY *c_signing_key)
{
    if (c_signing_key == nullptr) return nullptr;
    cJSON *cSignObj = cJSON_CreateObject();
    cJSON_AddStringToObject(cSignObj, "kty", "EC");
    cJSON_AddStringToObject(cSignObj, "crv", "P-256");
    uint8_t *hashed_c_sign_key = compute_key_hash(c_signing_key);
    std::string base64_c_sign_key_hash = em_crypto_t::base64_encode(hashed_c_sign_key, SHA256_DIGEST_LENGTH);
    free(hashed_c_sign_key);
    cJSON_AddStringToObject(cSignObj, "kid", base64_c_sign_key_hash.c_str());
    EC_GROUP *key_group = em_crypto_t::get_key_group(c_signing_key);
    EC_POINT *key_point = em_crypto_t::get_pub_key_point(c_signing_key, key_group);
    auto [x, y] = ec_crypto::get_ec_x_y(c_ctx, key_point);
    cJSON_AddStringToObject(cSignObj, "x", em_crypto_t::base64_encode(ec_crypto::BN_to_vec(x)).c_str());
    cJSON_AddStringToObject(cSignObj, "y", em_crypto_t::base64_encode(ec_crypto::BN_to_vec(y)).c_str());
    EC_GROUP_free(key_group);
    EC_POINT_free(key_point);
    BN_free(x);
    BN_free(y);
    return cSignObj;
}

EC_POINT* ec_crypto::create_ppkey_public(SSL_KEY *c_signing_key)
{
    if (c_signing_key == nullptr) return nullptr;
    EC_GROUP *key_group = em_crypto_t::get_key_group(c_signing_key);
    SSL_KEY *ppKey = em_crypto_t::generate_ec_key(key_group);
    EC_POINT *ret = em_crypto_t::get_pub_key_point(ppKey, const_cast<EC_GROUP*>(key_group));
    EC_GROUP_free(key_group);
    em_crypto_t::free_key(ppKey);
    return ret;
}

cJSON *ec_crypto::create_ppkey_object(ec_connection_context_t& c_ctx)
{
    cJSON *ppKeyObj = cJSON_CreateObject();
    cJSON_AddStringToObject(ppKeyObj, "kty", "EC");
    cJSON_AddStringToObject(ppKeyObj, "crv", "P-256");
    auto [x, y] = ec_crypto::get_ec_x_y(c_ctx, c_ctx.ppk);
    cJSON_AddStringToObject(ppKeyObj, "x", em_crypto_t::base64_encode(ec_crypto::BN_to_vec(x)).c_str());
    cJSON_AddStringToObject(ppKeyObj, "y", em_crypto_t::base64_encode(ec_crypto::BN_to_vec(y)).c_str());
    BN_free(x);
    BN_free(y);
    return ppKeyObj;
}