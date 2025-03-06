#ifndef EC_PA_CONFIGURATOR_H
#define EC_PA_CONFIGURATOR_H

#include "ec_configurator.h"

#include <map>
#include <vector>

class ec_pa_configurator_t : public ec_configurator_t {
public:
    /**
     * @brief The Proxy Agent side of the EasyConnect Configurator.
     * 
     * Handles the 802.11 frames from the Enrollee and forwards to the Controller.
     * Handles the 1905 frames from the Controller and forwards to the Enrollee.
     * 
     * @param mac_addr The MAC address of the device
     * @param send_chirp_notification The function to send a chirp notification via 1905
     * @param send_prox_encap_dpp_msg The function to send a proxied encapsulated DPP message via 1905
     * @param send_action_frame The function to send an 802.11 action frame
     */
    ec_pa_configurator_t(
        std::string mac_addr,
        send_chirp_func send_chirp_notification,
        send_encap_dpp_func send_prox_encap_dpp_msg,
        send_act_frame_func send_action_frame
    ) : ec_configurator_t(
            mac_addr,
            send_chirp_notification,
            send_prox_encap_dpp_msg,
            send_action_frame
        ) { }


    /**
     * @brief Handles a presence announcement 802.11 frame, performing the necessary actions and possibly passing to 1905
     * 
     * @param buff The frame to handle
     * @param len The length of the frame
     * @return bool true if successful, false otherwise
     * 
     * @note Optional to implement because the controller+configurator does not handle 802.11,
     *      but the proxy agent + configurator does.
     */
    bool handle_presence_announcement(ec_frame_t *frame, size_t len, uint8_t src_mac[ETHER_ADDR_LEN]) override;

    /**
     * @brief Handles an authentication request 802.11 frame, performing the necessary actions and possibly passing to 1905
     * 
     * @param buff The frame to handle
     * @param len The length of the frame
     * @return bool true if successful, false otherwise
     * 
     * @note Optional to implement because the controller+configurator does not handle 802.11,
     *     but the proxy agent + configurator does.
     */
    bool handle_auth_response(ec_frame_t *frame, size_t len, uint8_t src_mac[ETHER_ADDR_LEN]) override;

    /**
     * @brief Handles an configuration request 802.11+GAS frame, performing the necessary actions and possibly passing to 1905
     * 
     * @param buff The frame to handle
     * @param len The length of the frame
     * @param sa The 802.11 source address of the frame (from Enrollee).
     * @return bool true if successful, false otherwise
     * 
     * @note Optional to implement because the controller+configurator does not handle 802.11,
     *     but the proxy agent + configurator does.
     */
    bool handle_cfg_request(uint8_t *buff, unsigned int len, uint8_t sa[ETH_ALEN]) override;

    /**
     * @brief Handles an configuration result 802.11+GAS frame, performing the necessary actions and possibly passing to 1905
     * 
     * @param buff The frame to handle
     * @param len The length of the frame
     * @return bool true if successful, false otherwise
     * 
     * @note Optional to implement because the controller+configurator does not handle 802.11,
     *     but the proxy agent + configurator does.
     */
    bool handle_cfg_result(uint8_t *buff, unsigned int len) override;

    /**
     * @brief Handle a chirp notification TLV and direct to the correct place (802.11 or 1905)
     * 
     * @param chirp_tlv The chirp TLV to parse and handle
     * @param tlv_len The length of the chirp TLV
     * @return bool true if successful, false otherwise
     */
    bool process_chirp_notification(em_dpp_chirp_value_t* chirp_tlv, uint16_t tlv_len) override;

    /**
     * @brief Handle a proxied encapsulated DPP message TLVs (including chirp value) and direct to the correct place (802.11 or 1905)
     * 
     * @param encap_tlv The 1905 Encap DPP TLV to parse and handle
     * @param encap_tlv_len The length of the 1905 Encap DPP TLV
     * @param chirp_tlv The DPP Chirp Value TLV to parse and handle (NULL if not present)
     * @param chirp_tlv_len The length of the DPP Chirp Value TLV (0 if not present)
     * @return bool true if successful, false otherwise
     */
    bool process_proxy_encap_dpp_msg(em_encap_dpp_t *encap_tlv, uint16_t encap_tlv_len, em_dpp_chirp_value_t *chirp_tlv, uint16_t chirp_tlv_len) override;

private:
    // Private member variables go here
    /*
     * Map from Chirp Hash to DPP Authentication Request
     */
    std::map<std::string, std::vector<uint8_t>> m_chirp_hash_frame_map = {};
    /*
     * Vector of all cached DPP Reconfiguration Authentication Requests.
     * Hash does not matter since it is compared against the Controllers C-sign key
     */
    std::vector<std::vector<uint8_t>> m_stored_recfg_auth_frames = {};
protected:
    // Protected member variables and methods go here
};

#endif // EC_PA_CONFIGURATOR_H