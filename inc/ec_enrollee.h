#ifndef EC_ENROLLEE_H
#define EC_ENROLLEE_H

#include "em_base.h"
#include "ec_configurator.h"

#include <map>
#include <string>

class ec_enrollee_t {
public:
    // TODO: Add Send GAS Frame
    /**
     * @brief The EasyConnect Enrollee
     * 
     * Broadcasts 802.11 presence announcements, handles 802.11 frames from Proxy Agents and sends 802.11 responses to Proxy Agents.
     * 
     * @param mac_addr The MAC address of the device
     * @param send_action_frame Callback for sending 802.11 action frames
     * @param get_bsta_info Callback for getting backhaul STA info, used for building DPP Configuration Request JSON objects.
     * 
     * @note The default state of an enrollee is non-onboarding. All non-controller devices are started as (non-onboarding) enrollees 
     *      until they are told that they are on the network at which point they can be upgraded to a proxy agent.
     */
    ec_enrollee_t(std::string mac_addr, send_act_frame_func send_action_frame, get_backhaul_sta_info_func get_bsta_info);
    
    // Destructor
    ~ec_enrollee_t();

    /**
     * @brief Start the EC enrollee onboarding
     * 
     * @param do_reconfig Whether to reconfigure/reauth the enrollee
     * @return bool true if successful, false otherwise
     */
    bool start(bool do_reconfig, ec_data_t* boot_data);

    /**
     * @brief Handle an authentication request 802.11 frame, performing the necessary actions and responding with an authentication response via 802.11
     * 
     * @param buff The frame to handle
     * @param len The length of the frame
     * @return bool true if successful, false otherwise
     */
    bool handle_auth_request(ec_frame_t *frame, size_t len, uint8_t src_mac[ETHER_ADDR_LEN]);

    /**
     * @brief Handle an authentication confirmation 802.11 frame, performing the necessary actions
     * 
     * @param buff The frame to handle
     * @param len The length of the frame
     * @return bool true if successful, false otherwise
     */
    bool handle_auth_confirm(ec_frame_t *frame, size_t len, uint8_t src_mac[ETHER_ADDR_LEN]);

    /**
     * @brief Handle a configuration request 802.11+GAS frame, performing the necessary actions and responding with a configuration result via 802.11
     * 
     * @param buff The frame to handle
     * @param len The length of the frame
     * @param sa The 802.11 source address of this frame.
     * @return bool true if successful, false otherwise
     */
    bool handle_config_response(uint8_t *buff, unsigned int len, uint8_t sa[ETH_ALEN]);

    inline std::string get_mac_addr() { return m_mac_addr; };

    // Disable copy construction and assignment
    // Requires use of references or pointers when working with instances of this class
    ec_enrollee_t(const ec_enrollee_t&) = delete;
    ec_enrollee_t& operator=(const ec_enrollee_t&) = delete;

private:

    std::string m_mac_addr;

    /**
     * @brief Send an action frame. Optional to implement.
     * 
     * @param dest_mac The destination MAC address
     * @param action_frame The action frame to send
     * @param action_frame_len The length of the action frame
     * @param frequency The frequency to send the frame on (0 for current frequency)
     * @return true if successful, false otherwise
     */
    send_act_frame_func m_send_action_frame;

    /**
     * @brief Get backhaul station information to be JSON encoded and added to DPP Configuration Request frame.
     *
     * @return cJSON * on success, nullptr otherwise.
     */
    get_backhaul_sta_info_func m_get_bsta_info;

    // TODO: Send GAS Frame

    const ec_dpp_capabilities_t m_dpp_caps = {{
        .enrollee = 1,
        .configurator = 0,
        .reserved = 0
    }};

    std::pair<uint8_t*, size_t> create_presence_announcement();
    std::pair<uint8_t*, size_t> create_recfg_presence_announcement();
    std::pair<uint8_t*, size_t> create_auth_response(ec_status_code_t dpp_status, uint8_t init_proto_version);
    std::pair<uint8_t*, size_t> create_recfg_auth_response(ec_status_code_t dpp_status);
    std::pair<uint8_t*, size_t> create_config_request();
    std::pair<uint8_t*, size_t> create_config_result(ec_status_code_t dpp_status);

    ec_persistent_context_t m_p_ctx = {};

    // Randomized and cleared at the end of the authentication/configuration process
    ec_ephemeral_context_t m_eph_ctx = {};

    ec_data_t m_boot_data = {};




};

#endif // EC_ENROLLEE_H