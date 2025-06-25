#include "ec_manager.h"
#include "ec_ctrl_configurator.h"

#include "ec_util.h"
#include "util.h"

#include <memory>

ec_manager_t::ec_manager_t(const std::string& mac_addr, ec_ops_t& ops, bool is_controller)
    : m_is_controller(is_controller),  m_ops(ops) {

    printf("EC Manager created with MAC: %s\n", mac_addr.c_str());  
    if (m_is_controller) {
        m_configurator = std::unique_ptr<ec_ctrl_configurator_t>(
            new ec_ctrl_configurator_t(mac_addr, ops)
        );
    } else {
        m_enrollee = std::unique_ptr<ec_enrollee_t>(
            new ec_enrollee_t(mac_addr, ops)
        );
    }
}

ec_manager_t::~ec_manager_t()
{
}

bool ec_manager_t::handle_recv_ec_action_frame(ec_frame_t *frame, size_t len, uint8_t src_mac[ETHER_ADDR_LEN])
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
            did_succeed = m_enrollee->handle_auth_request(frame, len, src_mac);
            break;
        case ec_frame_type_auth_rsp:
            did_succeed = m_configurator->handle_auth_response(frame, len, src_mac);
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
            did_succeed = m_configurator->handle_recfg_announcement(frame, len, src_mac);
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

bool ec_manager_t::upgrade_to_onboarded_proxy_agent()
{
    if (m_is_controller) {
        // Only an enrollee agent can be upgraded to a proxy agent
        em_printfout("Can't upgrade a controller to a proxy agent");
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
    std::string enrollee_mac = m_enrollee->get_mac_addr();
    // Free the enrollee object
    m_enrollee.reset();
    
    // Create a new proxy agent configurator
    m_configurator = std::unique_ptr<ec_pa_configurator_t>(new ec_pa_configurator_t(enrollee_mac, m_ops));
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
