#include "ec_manager.h"
#include "ec_ctrl_configurator.h"

#include "ec_util.h"
#include "util.h"

#include <memory>

ec_manager_t::ec_manager_t(const std::string& al_mac_addr, ec_ops_t& ops, bool is_controller, std::optional<ec_persistent_sec_ctx_t> sec_ctx)
    : m_is_controller(is_controller),  m_ops(ops), m_stored_al_mac_addr(al_mac_addr) {

    printf("EC Manager created with MAC: %s\n", al_mac_addr.c_str());  
    if (m_is_controller) {
        if (!sec_ctx.has_value()) {
            em_printfout("Security context is required for the controller configurator");
            throw std::runtime_error("Security context is required for the controller configurator");
        }

        m_configurator = std::unique_ptr<ec_ctrl_configurator_t>(
            new ec_ctrl_configurator_t(al_mac_addr, ops, *sec_ctx)
        );
    } else {
        m_enrollee = std::unique_ptr<ec_enrollee_t>(
            new ec_enrollee_t(al_mac_addr, ops, sec_ctx)
        );
    }
}

ec_manager_t::~ec_manager_t()
{
}

bool ec_manager_t::handle_recv_ec_action_frame(ec_frame_t *frame, size_t len, uint8_t src_mac[ETHER_ADDR_LEN], unsigned int recv_freq)
{
    if (!ec_util::validate_frame(frame)) {
        em_printfout("frame validation failed");
        return false;
    }
    bool did_succeed = false;
    switch (frame->frame_type) {
        case ec_frame_type_presence_announcement:
            did_succeed = m_configurator->handle_presence_announcement(frame, len, src_mac);
            break;
        case ec_frame_type_auth_req:
            did_succeed = m_enrollee->handle_auth_request(frame, len, src_mac, recv_freq);
            break;
        case ec_frame_type_auth_rsp:
            did_succeed = m_configurator->handle_auth_response(frame, len, src_mac, NULL);
            break;
        case ec_frame_type_auth_cnf:
            did_succeed = m_enrollee->handle_auth_confirm(frame, len, src_mac);
            break;
        case ec_frame_type_cfg_result:
            did_succeed = m_configurator->handle_cfg_result(frame, len, src_mac);
            break;
        case ec_frame_type_conn_status_result:
            did_succeed = m_configurator->handle_connection_status_result(frame, len, src_mac);
            break;
        case ec_frame_type_recfg_announcement:
            did_succeed = m_configurator->handle_recfg_announcement(frame, len, src_mac, NULL);
            break;
        case ec_frame_type_recfg_auth_req:
            did_succeed = m_enrollee->handle_recfg_auth_request(frame, len, src_mac);
            break;
        default:
            em_printfout("frame type (%d) not handled", frame->frame_type);
            break;
    }
    if (!did_succeed) {
        // Teardown connection because of failure
        if (m_configurator) {
            std::string mac = util::mac_to_string(src_mac);
            m_configurator->teardown_connection(mac);
        }
        if (m_enrollee) {
            m_enrollee->teardown_connection();
        }
    }
    return did_succeed;
}

bool ec_manager_t::handle_recv_gas_pub_action_frame(ec_gas_frame_base_t *frame, size_t len, uint8_t source_addr[ETH_ALEN]) {
    if (!frame) {
        em_printfout("EC manager given a NULL DPP GAS frame!");
        return false;
    }
    em_printfout("Got a GAS frame with %02x action!", frame->action);
    bool did_succeed = false;
    switch (static_cast<dpp_gas_action_type_t>(frame->action)) {
        case dpp_gas_initial_req:
            did_succeed = m_configurator->handle_cfg_request(reinterpret_cast<uint8_t*>(frame), static_cast<unsigned int>(len), source_addr);
            break;
        case dpp_gas_initial_resp:
            did_succeed = m_enrollee->handle_gas_initial_response(reinterpret_cast<ec_gas_initial_response_frame_t*>(frame), len, source_addr);
            break;
        case dpp_gas_comeback_req: {
            did_succeed = m_configurator->handle_gas_comeback_request(reinterpret_cast<uint8_t*>(frame), static_cast<unsigned int>(len), source_addr);
            break;
        }
        case dpp_gas_comeback_resp: {
            did_succeed = m_enrollee->handle_gas_comeback_response(reinterpret_cast<ec_gas_comeback_response_frame_t*>(frame), len, source_addr);
            break;
        }
        default:
            em_printfout("unhandled DPP GAS action type=%02x", frame->action);
            break;
    }
    if (!did_succeed) {
        // Teardown connection because of failure
        if (m_configurator) {
            std::string mac = util::mac_to_string(source_addr);
            m_configurator->teardown_connection(mac);
        }
        if (m_enrollee) {
            m_enrollee->teardown_connection();
        }
    }
    return did_succeed;
}

bool ec_manager_t::upgrade_to_onboarded_proxy_agent(uint8_t ctrl_al_mac[ETH_ALEN])
{
    if (m_is_controller) {
        // Only an enrollee agent can be upgraded to a proxy agent
        em_printfout("Can't upgrade a controller to a proxy agent");
        return false;
    }

    if (!ctrl_al_mac) {
        em_printfout("Can't upgrade to a proxy agent without a controller AL MAC address");
        return false;
    }
    if (memcmp(ctrl_al_mac, ZERO_MAC_ADDR, ETH_ALEN) == 0) {
        em_printfout("Can't upgrade to a proxy agent with a zero controller AL MAC address");
        return false;
    }

    // If a configurator is already defined (i.e. the enrollee agent is already upgraded) or somehow it's a controller
    //      return an error
    if (m_configurator && dynamic_cast<ec_ctrl_configurator_t*>(m_configurator.get()) == nullptr) {
        em_printfout("Can't upgrade an already upgraded agent");
        return false;
    }
    if (!m_enrollee) {
        // Can't upgrade an enrollee if it's not defined
        em_printfout("Can't upgrade an enrollee that doesn't exist");
        return false;
    }
    auto sec_ctx = *m_enrollee->get_sec_ctx();
    if (sec_ctx.C_signing_key == NULL || sec_ctx.pp_key == NULL || sec_ctx.net_access_key == NULL || sec_ctx.connector == NULL) {
        em_printfout("!!!!Enrollee doesn't have a valid security context, proxy agent won't be 1905 layer secured!!!!");
    }
    // Free the enrollee object
    m_enrollee->signal_enrollee_is_upgrading();
    m_enrollee.reset();

    // If co-located, the agent will be reading the same key files which, for the controller, will contain the public **and** the private keys.
    // If not co-located, the agent will only have the public keys.
    bool is_colocated = em_crypto_t::get_priv_key_bn(sec_ctx.C_signing_key) != nullptr &&
                        em_crypto_t::get_priv_key_bn(sec_ctx.pp_key) != nullptr;
    
    // Create a new proxy agent configurator
    std::vector<uint8_t> ctrl_al_mac_vec(ctrl_al_mac, ctrl_al_mac + ETH_ALEN);
    m_configurator = std::unique_ptr<ec_pa_configurator_t>(new ec_pa_configurator_t(m_stored_al_mac_addr, ctrl_al_mac_vec, m_ops, sec_ctx, is_colocated));
    em_printfout("Upgraded enrollee agent to proxy agent");
    return true;
}

bool ec_manager_t::handle_assoc_status(const rdk_sta_data_t &sta_data)
{
    if (!m_enrollee) {
        // No Enrollee so we don't care about this spurious association status event
        return true;
    }
    return m_enrollee->handle_assoc_status(sta_data);
}

bool ec_manager_t::handle_bss_info_event(const std::vector<wifi_bss_info_t> &bss_info_list)
{
    if (!m_enrollee) {
        // This is fine, ignore event
        return true;
    }
    return m_enrollee->handle_bss_info_event(bss_info_list);
}
