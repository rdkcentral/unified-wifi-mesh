#ifndef EC_ENROLLEE_H
#define EC_ENROLLEE_H

#include "em_base.h"
#include "ec_configurator.h"
#include "ec_util.h"

#include <map>
#include <unordered_map>
#include <string>
#include <vector>
#include <unordered_set>
#include <atomic>
#include <thread>

struct cJSON;

class ec_enrollee_t {
public:

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
    bool start_onboarding(bool do_reconfig, ec_data_t* boot_data);

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

    /**
     * @brief Sends presence announcement frames until a DPP Authentication Frame is received.
     * 
     * See: EasyConnect 6.2 DPP Presence Announcement 
     */
    void send_presence_announcement_frames();

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

    /**
     * @brief Create a Configuration Result frame (EasyConnect 8.2.12)
     * 
     * @param dpp_status The status (Enrollee) of the configuration.
     * @return std::pair<uint8_t*, size_t> Pair, pair.first is frame (nullptr on failure), pair.second is the length of the frame (0 on failure).
     */
    std::pair<uint8_t*, size_t> create_config_result(ec_status_code_t dpp_status);

    /**
     * @brief Create a connection status result frame (EasyConnect 8.2.13)
     * 
     * @param dpp_status The status (Enrollee) of Configuration
     * @param ssid The SSID the Enrollee attempted to find / associate to.
     * 
     * @return std::pair<uint8_t*, size_t> Pair, pair.first is frame (nullptr on failure), pair.second is the length of the frame (0 on failure).
     */
    std::pair<uint8_t*, size_t> create_connection_status_result(ec_status_code_t dpp_status, const std::string& ssid);

    /**
     * @brief Create a DPP Connection Status object (EasyConnect 6.5.4.2)
     * @param dpp_status The DPP status code. Can be one of: STATUS_OK, STATUS_AUTH_FAILURE,
     * STATUS_INVALID CONNECTOR, STATUS_NO_MATCH, STATUS_NO_AP. See EasyConnect table 23.
     * @param ssid The SSID the Enrollee attempted to associate to.
     * 
     * @return cJSON* The DPP Connection Status object on success, nullptr otherwise.
     * @note: Heap allocates, caller must free.
     */
    cJSON *create_dpp_connection_status_obj(ec_status_code_t dpp_status, const std::string& ssid);

    // Maps SSID that this Enrollee has attempted to find to the
    // list of channels/op-classes that were scanned.
    std::unordered_map<std::string, std::vector<ec_util::scanned_channels_t>> m_scanned_channels_map;

    ec_connection_context_t m_c_ctx = {};

    /**
     * @brief Connection's bootstrapping data
     */
    inline ec_data_t& m_boot_data(){
        return m_c_ctx.boot_data;
    }
    /**
     * @brief Connection's ephemeral context
     */
    inline ec_ephemeral_context_t& m_eph_ctx(){
        return m_c_ctx.eph_ctx;
    }

    /**
     * @brief Set of frequencies to send presence announcement frames on
     * 
     * This list should be extended as follows (EasyConnect 6.2.2): 
     *  1. opclass/chan pairs in DPP URI, ("channel-list"), if present
     *  2. Default channel per-band
     *  3. Channels where a CCE IE was heard.
     * 
     * Should exclude channels by regional regulation (i.e. DFS channels).
     */
    std::unordered_set<uint32_t> m_pres_announcement_freqs = {2437, 5220};

    /**
     * @brief True if we've received DPP Authentication Frame
     * 
     * Signals that this Enrollee should stop sending presence announcement frames.
     * 
     */
    std::atomic<bool> m_received_auth_frame{false};

    /**
     * @brief Thread for sending DPP Presence Announcement frames upon onboarding start
     * 
     * Need to send DPP Presence Announcement frames periodically, until 
     * a DPP Authentication Frame is received.
     * 
     * Since DPP Authentication Frames will come in asynchronously, this must be
     * on it's own thread, otherwise we'll block forever, never receive
     * our DPP Authentication Frame, and keep Presence Announcing forever
     */
    std::thread m_send_pres_announcement_thread;
};

#endif // EC_ENROLLEE_H
