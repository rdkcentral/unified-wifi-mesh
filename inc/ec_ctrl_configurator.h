#ifndef EC_CTRL_CONFIGURATOR_H
#define EC_CTRL_CONFIGURATOR_H

#include "ec_configurator.h" 

class ec_ctrl_configurator_t : public ec_configurator_t {
public:
    ec_ctrl_configurator_t(std::string mac_addr, send_chirp_func send_chirp_notification, send_encap_dpp_func send_prox_encap_dpp_msg) :
        ec_configurator_t(mac_addr, send_chirp_notification, send_prox_encap_dpp_msg, {}) {};
        // No MAC address needed for controller configurator

    /**
     * @brief Handle a chirp notification msg tlv and direct to 1905 agent
     * 
     * @param chirp_tlv The chirp TLV to parse and handle
     * @param tlv_len The length of the chirp TLV
     * @return bool true if successful, false otherwise
     */
    bool process_chirp_notification(em_dpp_chirp_value_t* chirp_tlv, uint16_t tlv_len) override;

    /**
     * @brief Handle a proxied encapsulated DPP message TLVs (including chirp value) and direct to 1905 agent
     * 
     * @param encap_tlv The 1905 Encap DPP TLV to parse and handle
     * @param encap_tlv_len The length of the 1905 Encap DPP TLV
     * @param chirp_tlv The DPP Chirp Value TLV to parse and handle (NULL if not present)
     * @param chirp_tlv_len The length of the DPP Chirp Value TLV (0 if not present)
     * @return bool true if successful, false otherwise
     */
    bool process_proxy_encap_dpp_msg(em_encap_dpp_t *encap_tlv, uint16_t encap_tlv_len, em_dpp_chirp_value_t *chirp_tlv, uint16_t chirp_tlv_len) override;

    /**
     * @brief Handles an authentication request 802.11 frame (unwrapped from the Proxy Encap DPP), performing the necessary actions and possibly passing to 1905
     * 
     * @param buff The frame to handle
     * @param len The length of the frame
     * @return bool true if successful, false otherwise
     * 
     * @note Optional to implement because the controller+configurator does not handle 802.11,
     *     but the proxy agent + configurator does.
     */
    bool handle_auth_response(ec_frame_t *frame, size_t len, uint8_t src_mac[ETHER_ADDR_LEN]) override;

private:
    // Private member variables can be added here

    const ec_dpp_capabilities_t m_dpp_caps = {{
        .enrollee = 0,
        .configurator = 1,
        .reserved = 0
    }};

    std::pair<uint8_t*, uint16_t> create_auth_request(std::string enrollee_mac);
    std::pair<uint8_t*, uint16_t> create_recfg_auth_request();
    std::pair<uint8_t*, uint16_t> create_auth_confirm(std::string enrollee_mac, ec_status_code_t dpp_status, uint8_t* i_auth_tag);
    std::pair<uint8_t*, uint16_t> create_recfg_auth_confirm(std::string enrollee_mac, ec_status_code_t dpp_status);
    std::pair<uint8_t*, uint16_t> create_config_response();
};

#endif // EC_CTRL_CONFIGURATOR_H