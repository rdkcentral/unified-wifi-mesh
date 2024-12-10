#include "ec_session.h"
#include "em_crypto.h"

int ec_session_t::compute_intermediate_key(bool is_first)
{       
    unsigned int primelen, offset, keylen;
    

    BIGNUM *x = is_first ? m_params.m : m_params.n;
    const char *info = is_first ? "first intermediate key" : "second intermediate key";

    // The key to store
    unsigned char *key = is_first ? m_params.k1 : m_params.k2;

    primelen = BN_num_bytes(m_params.prime);

    unsigned char m[2048];
    memset(m, 0, primelen);

    offset = primelen - BN_num_bytes(x);

    BN_bn2bin(x, m + offset);
    if ((keylen = hkdf(m_params.hashfcn, 0, m, primelen, NULL, 0, 
                    (unsigned char *)info, strlen(info),
                    key, m_params.digestlen)) == 0) {
        printf("%s:%d: Failed in hashing\n", __func__, __LINE__);
        return -1;
    }

    printf("Key:\n"); 
    print_hex_dump(m_params.digestlen, key);

    return 0;
}       

int ec_session_t::compute_key_hash(EC_KEY *key, unsigned char *digest, const char *prefix)
{
    BIO *bio;
    unsigned char *asn1;
    int asn1len;
    uint8_t *addr[2];      // Array of addresses for our two elements
    uint32_t len[2];       // Array of lengths for our two elements
    
    // Setup the BIO for key conversion
    if ((bio = BIO_new(BIO_s_mem())) == NULL) {
        return -1;
    }

    // Convert key to DER format
    i2d_EC_PUBKEY_bio(bio, key);
    (void)BIO_flush(bio);
    asn1len = BIO_get_mem_data(bio, &asn1);

    // Set up our data elements for hashing
    addr[0] = (uint8_t *)prefix;
    len[0] = strlen(prefix);
    addr[1] = asn1;
    len[1] = asn1len;

    // Call platform_SHA256 with our two elements
    uint8_t result = em_crypto_t::platform_SHA256(2, addr, len, digest);

    BIO_free(bio);
    
    if (result == 0) {
        return -1;
    }
    
    return SHA256_DIGEST_LENGTH;
}



void ec_session_t::print_bignum (BIGNUM *bn)
{
    unsigned char *buf;
    int len;

    len = BN_num_bytes(bn);
    if ((buf = (unsigned char *)malloc(len)) == NULL) {
        printf("Could not print bignum\n");
        return;
    }
    BN_bn2bin(bn, buf);
    print_hex_dump(len, buf);
    free(buf);
}

void ec_session_t::print_ec_point (const EC_GROUP *group, BN_CTX *bnctx, EC_POINT *point)
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


EC_KEY *ec_session_t::get_responder_boot_key(unsigned char *asn1_key, unsigned int* asn1_len)
{
    // Local buffer to be used if the provided buffer is NULL
    unsigned char local_buffer[1024];
    unsigned int local_len = 1024;

    uint8_t* key = NULL;
    unsigned int* len = NULL;
    EC_KEY *responder_boot_key = NULL;

    // If both parameters are NULL, use local buffer to be discarded after
    if (asn1_key == NULL && asn1_len == NULL) {
        key = local_buffer;
        len = &local_len;
    } else {
        // If all parameters are not NULL, use the provided buffer
        if (asn1_key == NULL || asn1_len == NULL || *asn1_len == 0) {
            return NULL;
        }
        key = asn1_key;
        len = asn1_len;
    }


    // Clear the buffer before use
    memset(key, 0, *len);

    // Begin fetching the responder public key

    if ((*len = EVP_DecodeBlock(key, (unsigned char *)m_data.rPubKey, strlen(m_data.rPubKey))) < 0) {
        m_activation_status = ActStatus_Failed;
        printf("%s:%d Failed to decode base 64 initiator public key\n", __func__, __LINE__);
        return NULL;
    }

    responder_boot_key = d2i_EC_PUBKEY(NULL, (const unsigned char **)&key, *len);

    EC_KEY_set_conv_form(responder_boot_key, POINT_CONVERSION_COMPRESSED);
    EC_KEY_set_asn1_flag(responder_boot_key, OPENSSL_EC_NAMED_CURVE);

    return responder_boot_key;
}

EC_KEY *ec_session_t::get_initiator_boot_key(unsigned char *asn1_key, unsigned int* asn1_len)
{
    // Local buffer to be used if the provided buffer is NULL
    unsigned char local_buffer[1024];
    unsigned int local_len = 1024;

    uint8_t* key = NULL;
    unsigned int* len = NULL;
    EC_KEY *initiator_boot_key = NULL;

    // If both parameters are NULL, use local buffer to be discarded after
    if (asn1_key == NULL && asn1_len == NULL) {
        key = local_buffer;
        len = &local_len;
    } else {
        // If all parameters are not NULL, use the provided buffer
        if (asn1_key == NULL || asn1_len == NULL || *asn1_len == 0) {
            return NULL;
        }
        key = asn1_key;
        len = asn1_len;
    }

    // Begin fetching the initiator public key

    // Clear the buffer before use
    memset(key, 0, *len);
    if ((*len  = EVP_DecodeBlock(key, (unsigned char *)m_data.iPubKey, strlen(m_data.iPubKey))) < 0) {
        m_activation_status = ActStatus_Failed;
        printf("%s:%d Failed to decode base 64 initiator public key\n", __func__, __LINE__);
        return NULL;
    }

    initiator_boot_key = d2i_EC_PUBKEY(NULL, (const unsigned char **)&key, *len );

    EC_KEY_set_conv_form(initiator_boot_key, POINT_CONVERSION_COMPRESSED);
    EC_KEY_set_asn1_flag(initiator_boot_key, OPENSSL_EC_NAMED_CURVE);

    return initiator_boot_key;
}


int ec_session_t::hkdf (const EVP_MD *h, int skip, unsigned char *ikm, int ikmlen,
        unsigned char *salt, int saltlen, unsigned char *info, int infolen,
        unsigned char *okm, int okmlen)
{
    unsigned char *prk, *tweak, ctr, *digest;
    int len;
    unsigned int digestlen, prklen, tweaklen;
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    HMAC_CTX ctx;
#else
    HMAC_CTX *ctx = HMAC_CTX_new();
#endif

    digestlen = prklen = EVP_MD_size(h);
    if ((digest = (unsigned char *)malloc(digestlen)) == NULL) {
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
        if ((prk = (unsigned char *)malloc(digestlen)) == NULL) {
            free(digest);
            perror("malloc");
            return 0;
        }
        /*
         * if there's no salt then use all zeros
         */
        if (!salt || (saltlen == 0)) {
            if ((tweak = (unsigned char *)malloc(digestlen)) == NULL) {
                free(digest);
                free(prk);
                perror("malloc");
                return 0;
            }
            memset(tweak, 0, digestlen);
            tweaklen = saltlen;
        } else {
            tweak = salt;
            tweaklen = saltlen;
        }
        (void)HMAC(h, tweak, tweaklen, ikm, ikmlen, prk, &prklen);
        if (!salt || (saltlen == 0)) {
            free(tweak);
        }
    } else {
        prk = ikm;
        prklen = ikmlen;
    }
    memset(digest, 0, digestlen);
    digestlen = 0;
    ctr = 0;
    len = 0;
    while (len < okmlen) {
        /*
         * T(0) = all zeros
         * T(n) = HMAC(prk, T(n-1) | info | counter)
         * okm = T(0) | ... | T(n)
         */
        ctr++;
#if OPENSSL_VERSION_NUMBER < 0x10100000L
        HMAC_Init_ex(&ctx, prk, prklen, h, NULL);
        HMAC_Update(&ctx, digest, digestlen);
#else
        HMAC_Init_ex(ctx, prk, prklen, h, NULL);
        HMAC_Update(ctx, digest, digestlen);
#endif
        if (info && (infolen != 0)) {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
            HMAC_Update(&ctx, info, infolen);
#else
            HMAC_Update(ctx, info, infolen);
#endif
        }
#if OPENSSL_VERSION_NUMBER < 0x10100000L
        HMAC_Update(&ctx, &ctr, sizeof(unsigned char));
        HMAC_Final(&ctx, digest, &digestlen);
#else
        HMAC_Update(ctx, &ctr, sizeof(unsigned char));
        HMAC_Final(ctx, digest, &digestlen);
#endif
        if ((len + digestlen) > okmlen) {
            memcpy(okm + len, digest, okmlen - len);
        } else {
            memcpy(okm + len, digest, digestlen);
        }
#if OPENSSL_VERSION_NUMBER < 0x10100000L
        HMAC_CTX_cleanup(&ctx);
#else
        HMAC_CTX_free(ctx);
#endif
        len += digestlen;
    }
    if (!skip) {
        free(prk);
    }
    free(digest);
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    HMAC_CTX_cleanup(&ctx);
#else
    HMAC_CTX_free(ctx);
#endif

    return okmlen;
}
