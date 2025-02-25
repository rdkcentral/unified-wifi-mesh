#include "ec_session.h"
#include "em_crypto.h"
#include "util.h"

int ec_session_t::compute_intermediate_key(bool is_first)
{       
    unsigned int primelen, offset, keylen;
    

    BIGNUM *x = is_first ? m_params.m : m_params.n;
    const char *info = is_first ? "first intermediate key" : "second intermediate key";

    // The key to store
    uint8_t *key = is_first ? m_params.k1 : m_params.k2;

    primelen = BN_num_bytes(m_params.prime);

    uint8_t m[2048];
    memset(m, 0, primelen);

    offset = primelen - BN_num_bytes(x);

    BN_bn2bin(x, m + offset);
    if ((keylen = hkdf(m_params.hashfcn, 0, m, primelen, NULL, 0, 
                    (uint8_t *)info, strlen(info),
                    key, m_params.digestlen)) == 0) {
        printf("%s:%d: Failed in hashing\n", __func__, __LINE__);
        return -1;
    }

    printf("Key:\n"); 
    util::print_hex_dump(m_params.digestlen, key);

    return 0;
}       

int ec_session_t::compute_key_hash(EC_KEY *key, uint8_t *digest, const char *prefix)
{
    BIO *bio;
    uint8_t *asn1;
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

int ec_session_t::hkdf (const EVP_MD *h, int skip, uint8_t *ikm, int ikmlen,
        uint8_t *salt, int saltlen, uint8_t *info, int infolen,
        uint8_t *okm, int okmlen)
{
    uint8_t *prk, *tweak, ctr, *digest;
    int len;
    unsigned int digestlen, prklen, tweaklen;
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    HMAC_CTX ctx;
#else
    HMAC_CTX *ctx = HMAC_CTX_new();
#endif

    digestlen = prklen = EVP_MD_size(h);
    if ((digest = (uint8_t *)malloc(digestlen)) == NULL) {
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
        if ((prk = (uint8_t *)malloc(digestlen)) == NULL) {
            free(digest);
            perror("malloc");
            return 0;
        }
        /*
         * if there's no salt then use all zeros
         */
        if (!salt || (saltlen == 0)) {
            if ((tweak = (uint8_t *)malloc(digestlen)) == NULL) {
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
        HMAC_Update(&ctx, &ctr, sizeof(uint8_t));
        HMAC_Final(&ctx, digest, &digestlen);
#else
        HMAC_Update(ctx, &ctr, sizeof(uint8_t));
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
