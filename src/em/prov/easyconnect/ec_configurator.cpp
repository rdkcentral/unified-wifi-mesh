#include "ec_configurator.h"

ec_configurator_t::ec_configurator_t(std::string mac_addr, send_chirp_func send_chirp_notification, send_encap_dpp_func send_prox_encap_dpp_msg)
    : m_mac_addr(mac_addr), m_send_chirp_notification(send_chirp_notification), m_send_prox_encap_dpp_msg(send_prox_encap_dpp_msg)
{
}

ec_configurator_t::~ec_configurator_t()
{
}

// TODO: Maybe move to controller
bool ec_configurator_t::start(ec_data_t *ec_data)
{
    memset(&m_boot_data, 0, sizeof(ec_data_t));
    memcpy(&m_boot_data, ec_data, sizeof(ec_data_t));

    const EC_POINT *init_pub_key, *resp_pub_key = NULL;
    const BIGNUM *proto_priv;

    resp_pub_key = EC_KEY_get0_public_key(m_boot_data.responder_boot_key);
    if (resp_pub_key == NULL) {
        printf("%s:%d Could not get responder bootstrap public key\n", __func__, __LINE__);
        return false;
    }
    m_p_ctx.group = EC_KEY_get0_group(m_boot_data.responder_boot_key);


    m_p_ctx.prime = BN_new();
    m_p_ctx.bn_ctx = BN_CTX_new();

    if (!m_p_ctx.prime || !m_p_ctx.bn_ctx) {
        printf("%s:%d Some BN NULL\n", __func__, __LINE__);
        BN_free(m_p_ctx.prime);
        BN_CTX_free(m_p_ctx.bn_ctx);
        return false;
    }

    m_p_ctx.nid = EC_GROUP_get_curve_name(m_p_ctx.group);

    //printf("%s:%d nid: %d\n", __func__, __LINE__, m_p_ctx.nid);
    switch (m_p_ctx.nid) {
        case NID_X9_62_prime256v1:
            m_p_ctx.digest_len = 32;
            m_p_ctx.hash_fcn = EVP_sha256();
            break;
        case NID_secp384r1:
            m_p_ctx.digest_len = 48;
            m_p_ctx.hash_fcn = EVP_sha384();
            break;
        case NID_secp521r1:
            m_p_ctx.digest_len = 64;
            m_p_ctx.hash_fcn = EVP_sha512();
            break;
        case NID_X9_62_prime192v1:
            m_p_ctx.digest_len = 32;
            m_p_ctx.hash_fcn = EVP_sha256();
            break;
        case NID_secp224r1:
            m_p_ctx.digest_len = 32;
            m_p_ctx.hash_fcn = EVP_sha256();
            break;
        default:
            printf("%s:%d nid:%d not handled\n", __func__, __LINE__, m_p_ctx.nid);
            return false;
    }

    m_p_ctx.nonce_len = m_p_ctx.digest_len*4;

    // Fetch prime
    if (EC_GROUP_get_curve_GFp(m_p_ctx.group, m_p_ctx.prime, NULL, NULL, m_p_ctx.bn_ctx) == 0) {
        printf("%s:%d unable to get x, y of the curve\n", __func__, __LINE__);
        return false;
    }

    return true;
}
