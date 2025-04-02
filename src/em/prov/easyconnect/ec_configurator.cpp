#include "ec_configurator.h"
#include "em_crypto.h"
#include "ec_util.h"
#include "util.h"

ec_configurator_t::ec_configurator_t(
    std::string mac_addr,
    send_chirp_func send_chirp_notification,
    send_encap_dpp_func send_prox_encap_dpp_msg,
    send_act_frame_func send_action_frame,
    get_backhaul_sta_info_func backhaul_sta_info_func,
    get_1905_info_func ieee1905_info_func,
    can_onboard_additional_aps_func can_onboard_func) : m_mac_addr(mac_addr),
    m_send_chirp_notification(send_chirp_notification),
    m_send_prox_encap_dpp_msg(send_prox_encap_dpp_msg),
    m_send_action_frame(send_action_frame),
    m_get_backhaul_sta_info(backhaul_sta_info_func),
    m_get_1905_info(ieee1905_info_func),
    m_can_onboard_additional_aps(can_onboard_func)
{
}

ec_configurator_t::~ec_configurator_t()
{

    for (auto& [_, c_ctx] : m_connections) {
        ec_util::free_connection_ctx(c_ctx);
    }
}

// TODO: Maybe move to controller
bool ec_configurator_t::onboard_enrollee(ec_data_t *bootstrapping_data)
{

    if (bootstrapping_data == NULL) {
        printf("%s:%d: Bootstrapping data is NULL\n", __func__, __LINE__);
        return false;
    }
    if (bootstrapping_data->version < 2) {
        printf("%s:%d: Bootstrapping Version '%d' not supported!\n", __func__, __LINE__, bootstrapping_data->version);
        return false;
    }
    if (memcmp(bootstrapping_data->mac_addr, ZERO_MAC_ADDR, ETHER_ADDR_LEN) == 0) {
        printf("%s:%d: Bootstrapping data MAC address is 0 \n", __func__, __LINE__);
        return false;
    }
    if (bootstrapping_data->responder_boot_key == NULL) {
        printf("%s:%d: Bootstrapping data initiator key is NULL\n", __func__, __LINE__);
        return false;
    }

    // Check if the MAC address is already in use
    // TODO: Not sure what to do if the MAC address is already in use
    std::string mac_str = util::mac_to_string(bootstrapping_data->mac_addr);
    if (m_connections.find(mac_str) != m_connections.end()) {
        printf("%s:%d: Bootstrapping data MAC address already in use\n", __func__, __LINE__);
        return false;
    }
    // Create a new connection context
    ec_connection_context_t conn_ctx;
    m_connections[mac_str] = conn_ctx;
    auto& c_ctx = m_connections[mac_str];
    

    // Initialize bootstrapping data
    memset(&c_ctx.boot_data, 0, sizeof(ec_data_t));
    memcpy(&c_ctx.boot_data, bootstrapping_data, sizeof(ec_data_t));

    // Not all of these will be present but it is better to compute them now.
    c_ctx.boot_data.resp_priv_boot_key = em_crypto_t::get_priv_key_bn(c_ctx.boot_data.responder_boot_key);
    c_ctx.boot_data.resp_pub_boot_key = em_crypto_t::get_pub_key_point(c_ctx.boot_data.responder_boot_key);

    c_ctx.boot_data.init_priv_boot_key = em_crypto_t::get_priv_key_bn(c_ctx.boot_data.initiator_boot_key);    
    c_ctx.boot_data.init_pub_boot_key = em_crypto_t::get_pub_key_point(c_ctx.boot_data.initiator_boot_key);


    if (c_ctx.boot_data.resp_priv_boot_key == NULL) {
        printf("%s:%d Could not get responder bootstrap public key\n", __func__, __LINE__);
        return false;
    }

    printf("Configurator MAC: %s\n", m_mac_addr.c_str());
    return ec_crypto::init_persistent_ctx(c_ctx, c_ctx.boot_data.responder_boot_key);
}
