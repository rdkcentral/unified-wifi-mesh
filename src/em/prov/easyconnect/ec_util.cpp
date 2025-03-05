#include <ctype.h>
#include <functional>

#include "ec_util.h"
#include "util.h"
#include "aes_siv.h"
#include "em_crypto.h"

void ec_util::init_frame(ec_frame_t *frame)
{
    memset(frame, 0, sizeof(ec_frame_t));
    frame->category = 0x04;
    frame->action = 0x09;
    frame->oui[0] = 0x50;
    frame->oui[1] = 0x6f;
    frame->oui[2] = 0x9a;
    frame->oui_type = DPP_OUI_TYPE;
    frame->crypto_suite = 0x01; // Section 3.3 (Currently only 0x01 is defined)
}

ec_attribute_t *ec_util::get_attrib(uint8_t *buff, uint16_t len, ec_attrib_id_t id)
{
    unsigned int total_len = 0;
    ec_attribute_t *attrib = (ec_attribute_t *)buff;

    while (total_len < len) {
        if (attrib->attr_id == id) {
            return attrib;
        }

        total_len += (get_ec_attr_size(attrib->length));
        attrib = (ec_attribute_t *)((uint8_t*)attrib + get_ec_attr_size(attrib->length));
    }

    return NULL;
}


uint8_t* ec_util::add_attrib(uint8_t *buff, uint16_t* buff_len, ec_attrib_id_t id, uint16_t len, uint8_t *data)
{
    if (data == NULL || len == 0) {
        fprintf(stderr, "Invalid input\n");
        return NULL;
    }

    
    // Add extra space for the new attribute
    uint16_t new_len = *buff_len + get_ec_attr_size(len);
    // Original start pointer to use for realloc
    uint8_t* base_ptr = NULL;
    if (buff != NULL) base_ptr = buff - *buff_len;
    if ((base_ptr = (uint8_t*)realloc(base_ptr, new_len)) == NULL) {
        fprintf(stderr, "Failed to realloc\n");
        return NULL;
    }

    // Get the start of the new section based on the re-allocated pointer
    uint8_t* tmp = base_ptr + *buff_len;

    memset(tmp, 0, get_ec_attr_size(len));
    ec_attribute_t *attr = (ec_attribute_t *)tmp;
    // EC attribute id and length are in host byte order according to the spec (8.1)
    attr->attr_id = id;
    attr->length = len;
    memcpy(attr->data, data, len);

    *buff_len += get_ec_attr_size(len);
    // Return the next attribute in the buffer
    return tmp + get_ec_attr_size(len);
}

uint16_t ec_util::freq_to_channel_attr(unsigned int freq)
{
    auto op_chan = util::em_freq_to_chan(freq);

    auto [op_class, channel] = op_chan;
    return ((channel << 8) | (0x00ff & op_class));
}

bool ec_util::validate_frame(const ec_frame_t *frame)
{
    if ((frame->category != 0x04) 
            || (frame->action != 0x09)
            || (frame->oui[0] != 0x50)
            || (frame->oui[1] != 0x6f)
            || (frame->oui[2] != 0x9a)
            || (frame->oui_type != DPP_OUI_TYPE)
            || (frame->crypto_suite != 0x01) ) {
        return false;
    }

    return true;
}

void ec_util::print_bignum (BIGNUM *bn)
{
    unsigned char *buf;
    int len;

    len = BN_num_bytes(bn);
    if ((buf = (unsigned char *)malloc(len)) == NULL) {
        printf("Could not print bignum\n");
        return;
    }
    BN_bn2bin(bn, buf);
    util::print_hex_dump(len, buf);
    free(buf);
}

void ec_util::print_ec_point (const EC_GROUP *group, BN_CTX *bnctx, EC_POINT *point)
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

uint8_t* ec_util::add_wrapped_data_attr(ec_frame_t *frame, uint8_t* frame_attribs, uint16_t* non_wrapped_len, bool use_aad, uint8_t* key, std::function<std::pair<uint8_t*, uint16_t>()> create_wrap_attribs)
{
    siv_ctx ctx;

    // Initialize AES-SIV context
// TODO: Come back to
    // switch(params.digestlen) {
    //     case SHA256_DIGEST_LENGTH:
    //         siv_init(&ctx, key, SIV_256);
    //         break;
    //     case SHA384_DIGEST_LENGTH:
    //         siv_init(&ctx, key, SIV_384);
    //         break;
    //     case SHA512_DIGEST_LENGTH:
    //         siv_init(&ctx, key, SIV_512);
    //         break;
    //     default:
    //         printf("%s:%d Unknown digest length\n", __func__, __LINE__);
    //         return NULL;
    // }

    // Use the provided function to create wrap_attribs and wrapped_len
    auto [wrap_attribs, wrapped_len] = create_wrap_attribs();

    // Encapsulate the attributes in a wrapped data attribute
    uint16_t wrapped_attrib_len = wrapped_len + AES_BLOCK_SIZE;
    ec_attribute_t *wrapped_attrib = (ec_attribute_t *)calloc(sizeof(ec_attribute_t) + wrapped_attrib_len, 1); 
    wrapped_attrib->attr_id = ec_attrib_id_wrapped_data;
    wrapped_attrib->length = wrapped_attrib_len;
    memset(wrapped_attrib->data, 0, wrapped_attrib_len);

    /**
    * Encrypt attributes using SIV mode with two additional authenticated data (AAD) inputs:
    * 1. The frame structure and 2. Non-wrapped attributes (per EasyMesh 6.3.1.4)
    * The synthetic IV/tag is stored in the first AES_BLOCK_SIZE bytes of wrapped_attrib->data
    */
   if (use_aad) {
        if (frame == NULL || frame_attribs == NULL || non_wrapped_len == NULL) {
            printf("%s:%d: AAD input is NULL, AAD encryption failed!\n", __func__, __LINE__);
            return NULL;
        }
        siv_encrypt(&ctx, wrap_attribs, &wrapped_attrib->data[AES_BLOCK_SIZE], wrapped_len, wrapped_attrib->data, 2,
            frame, sizeof(ec_frame_t),
            frame_attribs, *non_wrapped_len);
    } else {
        siv_encrypt(&ctx, wrap_attribs, &wrapped_attrib->data[AES_BLOCK_SIZE], wrapped_len, wrapped_attrib->data, 0);
    }

    // Add the wrapped data attribute to the frame
    uint8_t* ret_frame_attribs = ec_util::add_attrib(frame_attribs, non_wrapped_len, ec_attrib_id_wrapped_data, wrapped_attrib_len, (uint8_t *)wrapped_attrib);


    free(wrap_attribs);

    return ret_frame_attribs;
}

int ec_util::hkdf (const EVP_MD *h, int skip, uint8_t *ikm, int ikmlen,
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

/* Commenting out to put back in in some form with the new architecture (given the change in params)
int ec_util::compute_intermediate_key(ec_persistent_context_t& per_ctx, bool is_first)
{       
    unsigned int primelen, offset, keylen;
    

    BIGNUM *x = is_first ? params.m : params.n;
    const char *info = is_first ? "first intermediate key" : "second intermediate key";

    // The key to store
    uint8_t *key = is_first ? params.k1 : params.k2;

    primelen = BN_num_bytes(per_ctx.prime);

    uint8_t m[2048];
    memset(m, 0, primelen);

    offset = primelen - BN_num_bytes(x);

    BN_bn2bin(x, m + offset);
    if ((keylen = hkdf(per_ctx.hash_fcn, 0, m, primelen, NULL, 0, 
                    (uint8_t *)info, strlen(info),
                    key, per_ctx.digest_len)) == 0) {
        printf("%s:%d: Failed in hashing\n", __func__, __LINE__);
        return -1;
    }

    printf("Key:\n"); 
    util::print_hex_dump(per_ctx.digest_len, key);

    return 0;
}
*/     

/*
int ec_util::compute_key_hash(ec_persistent_context_t& per_ctx, EC_KEY *key, uint8_t *digest, const char *prefix)
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
*/