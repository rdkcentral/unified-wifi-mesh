#include "em_crypto.h"

#include <memory>

// Custom deleters for OpenSSL objects to use with std::unique_ptr
struct BIODeleter {
    void operator()(BIO* bio) const { if (bio) BIO_free(bio); }
};

struct BNDeleter {
    void operator()(BIGNUM* bn) const { if (bn) BN_free(bn); }
};

struct ECPointDeleter {
    void operator()(EC_POINT* point) const { if (point) EC_POINT_free(point); }
};

struct ECGroupDeleter {
    void operator()(EC_GROUP* group) const { 
        #if !defined(FORCE_OPENSSL_1_1) && OPENSSL_VERSION_NUMBER >= 0x30000000L
        if (group) EC_GROUP_free(group); 
        #endif
    }
};

struct SSLKeyDeleter {
    void operator()(SSL_KEY* key) const { if (key) em_crypto_t::free_key(key); }
};

struct BuffDeleter {
    void operator()(uint8_t* buff) const { if (buff) OPENSSL_free(buff); }
};

using managed_ssl_key = std::unique_ptr<SSL_KEY, SSLKeyDeleter>;
using managed_bio = std::unique_ptr<BIO, BIODeleter>;
using managed_bn = std::unique_ptr<BIGNUM, BNDeleter>;
using managed_ec_point = std::unique_ptr<EC_POINT, ECPointDeleter>;
using managed_ec_group = std::unique_ptr<EC_GROUP, ECGroupDeleter>;
using managed_buff = std::unique_ptr<uint8_t, BuffDeleter>;