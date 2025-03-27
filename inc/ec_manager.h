#ifndef EC_MANAGER_H
#define EC_MANAGER_H

#include "ec_configurator.h"
#include "ec_pa_configurator.h"
#include "ec_enrollee.h"

#include <memory>
#include <functional>

class ec_manager_t {
public:
    /**
     * @brief The Manager (unified dispatcher of sorts) for the EasyConnect Configurator or Enrollee
     * 
     * All non-controller devices are started as (non-onboarding) enrollees until they are told that they are on the network 
     * at which point they can be upgraded to a proxy agent.
     * 
     * @param mac_addr The MAC address of the device
     * @param send_chirp The function to send a chirp notification via 1905
     * @param send_encap_dpp The function to send a proxied encapsulated DPP message via 1905
     * @param send_action_frame The function to send an 802.11 action frame
     * @param m_is_controller Whether the node holding this manager is a controller or not
     * 
     * @note Some method calls are only valid for the controller, proxy agent, or the enrollee, and will return fail if called on the wrong object.
     * If the EasyMesh code is correctly implemented this should not be an issue.
     * 
     */
    ec_manager_t(std::string mac_addr, send_chirp_func send_chirp, send_encap_dpp_func send_encap_dpp, send_act_frame_func send_action_frame, 
        get_backhaul_sta_info_func get_bsta_info, get_1905_info_func get_1905_info, can_onboard_additional_aps_func can_onboard, bool m_is_controller);
    ~ec_manager_t();

    /**
     * @brief Handles DPP action frames directed at this nodes EC manager 
     * 
     * @param frame The frame recieved to handle
     * @param len The length of the frame
     * @param src_mac The MAC address of the source of the frame
     * @return bool true if successful, false otherwise
     */
    bool handle_recv_ec_action_frame(ec_frame_t* frame, size_t len, uint8_t src_mac[ETHER_ADDR_LEN]);


    bool handle_recv_gas_pub_action_frame(ec_gas_frame_base_t *, size_t, uint8_t[ETH_ALEN]);

    /**
     * @brief Start the EC configurator onboarding
     * 
     * @param data The data to use for onboarding (Parsed DPP URI Data)
     * @return bool true if successful, false otherwise
     */
    inline bool cfg_start(ec_data_t* data) {
        if (!m_is_controller || m_configurator == nullptr) {
            return -1;
        }
        return m_configurator->onboard_enrollee(data);
    }

    /**
     * @brief Start the EC enrollee onboarding
     * 
     * @param do_reconfig Whether to reconfigure/reauth the enrollee
     * @param boot_data The bootstrapping data to use for onboarding
     * @return bool true if successful, false otherwise
     */
    inline bool enrollee_start(bool do_reconfig, ec_data_t* boot_data) {
        if (m_is_controller || m_enrollee == nullptr) {
            return -1;
        }
        return m_enrollee->start_onboarding(do_reconfig, boot_data);
    }

    /**
     * @brief Toggle the presence of CCE (Configurator Connectivity Element) in Proxy Agent beacon and probe response IEs
     * 
     * @param enable Whether to enable or disable CCE presence
     * @return bool true if successful, false otherwise
     */
    inline bool pa_cfg_toggle_cce(bool enable) {
        if (!m_is_controller || m_configurator == nullptr) {
            return -1;
        }
        auto pa_cfg = dynamic_cast<ec_pa_configurator_t*>(m_configurator.get());
        if (!pa_cfg) {
            // Only a proxy agent configurator can toggle CCE
            return -1;
        }
        return pa_cfg->m_toggle_cce(enable);
    }

    /**
     * @brief Upgrade an enrollee to an onboarded proxy agent.
     * Called once m1/m2 exchange verifies the enrollee agent is on the network.
     * 
     * @param toggle_cce The function to call to toggle CCE presence
     * @return bool true if successful, false otherwise
     */
    bool upgrade_to_onboarded_proxy_agent(toggle_cce_func toggle_cce);

        /**
     * @brief Handle a chirp notification TLV and direct to the correct place (802.11 or 1905)
     * 
     * @param chirp_tlv The chirp TLV to parse and handle
     * @param tlv_len The length of the chirp TLV
     * @return bool true if successful, false otherwise
     */
    inline bool process_chirp_notification(em_dpp_chirp_value_t* chirp_tlv, uint16_t tlv_len) {
        if (!m_configurator) {
            return -1;
        }
        return m_configurator->process_chirp_notification(chirp_tlv, tlv_len);
    }

    /**
     * @brief Handle a proxied encapsulated DPP message TLVs (including chirp value) and direct to the correct place (802.11 or 1905)
     * 
     * @param encap_tlv The 1905 Encap DPP TLV to parse and handle
     * @param encap_tlv_len The length of the 1905 Encap DPP TLV
     * @param chirp_tlv The DPP Chirp Value TLV to parse and handle (NULL if not present)
     * @param chirp_tlv_len The length of the DPP Chirp Value TLV (0 if not present)
     * @return bool true if successful, false otherwise
     */
    inline bool process_proxy_encap_dpp_msg(em_encap_dpp_t *encap_tlv, uint16_t encap_tlv_len, em_dpp_chirp_value_t *chirp_tlv, uint16_t chirp_tlv_len) {
        if (!m_configurator) {
            return -1;
        }
        return m_configurator->process_proxy_encap_dpp_msg(encap_tlv, encap_tlv_len, chirp_tlv, chirp_tlv_len);
    }



private:
    bool m_is_controller;
    
    // Used to store the function pointers to instantiate objects again
    send_chirp_func m_stored_chirp_fn;
    send_encap_dpp_func m_stored_encap_dpp_fn;
    send_act_frame_func m_stored_action_frame_fn;
    get_backhaul_sta_info_func m_get_bsta_info_fn;
    get_1905_info_func m_get_1905_info_fn;
    can_onboard_additional_aps_func m_can_onboard_fn;
    std::string m_stored_mac_addr;
    
    std::unique_ptr<ec_configurator_t> m_configurator;
    std::unique_ptr<ec_enrollee_t> m_enrollee;
    toggle_cce_func m_stored_toggle_cce_fn;
};

#endif // EC_MANAGER_H