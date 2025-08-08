#ifndef EC_ENROLLEE_H
#define EC_ENROLLEE_H

#include "em_base.h"
#include "ec_configurator.h"
#include "ec_util.h"
#include "ec_ops.h"
#include "ec_1905_encrypt_layer.h"

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
	 * @brief EasyConnect Enrollee
	 * 
	 * @param al_mac_addr The AL MAC addr of the Enrollee
	 * @param ops Callbacks for the Enrollee
	 */
	ec_enrollee_t(const std::string& al_mac_addr, ec_ops_t& ops, std::optional<ec_persistent_sec_ctx_t> existing_sec_ctx = std::nullopt);
    
	/**!
	 * @brief Destructor for the ec_enrollee_t class.
	 *
	 * This destructor is responsible for cleaning up resources used by the ec_enrollee_t instance.
	 *
	 * @note Ensure that all resources are properly released before the object is destroyed.
	 */
	~ec_enrollee_t();

    
	/**
	 * @brief Start the EC enrollee onboarding process.
	 *
	 * This function initiates the onboarding process for the EC enrollee. It can optionally
	 * reconfigure or reauthenticate the enrollee based on the input parameter.
	 *
	 * @param[in] do_reconfig A boolean flag indicating whether to reconfigure/reauthenticate
	 * the enrollee. If true, the enrollee will be reconfigured.
	 * @param[out] boot_data A pointer to an ec_data_t structure where the boot data will be stored.
	 *
	 * @return bool Returns true if the onboarding process is successful, false otherwise.
	 *
	 * @note Ensure that the enrollee is in a state ready for onboarding before calling this function.
	 */
	bool start_onboarding(bool do_reconfig, ec_data_t* boot_data);

    
	/**
	 * @brief Handle an authentication request 802.11 frame, performing the necessary actions and responding with an authentication response via 802.11.
	 *
	 * This function processes the incoming authentication request frame and generates an appropriate response.
	 *
	 * @param[in] frame Pointer to the frame to handle.
	 * @param[in] len The length of the frame.
	 * @param[in] src_mac Source MAC address of the frame.
	 *
	 * @return true if the authentication request was handled successfully, false otherwise.
	 *
	 * @note Ensure that the frame and MAC address are valid before calling this function.
	 */
	bool handle_auth_request(ec_frame_t *frame, size_t len, uint8_t src_mac[ETHER_ADDR_LEN]);

    
	/**
	 * @brief Handle an authentication confirmation 802.11 frame, performing the necessary actions.
	 *
	 * This function processes the given 802.11 authentication confirmation frame and executes
	 * the required operations based on the frame's content.
	 *
	 * @param[in] frame Pointer to the frame to handle.
	 * @param[in] len The length of the frame.
	 * @param[in] src_mac Source MAC address of the frame.
	 *
	 * @return true if the frame was handled successfully, false otherwise.
	 */
	bool handle_auth_confirm(ec_frame_t *frame, size_t len, uint8_t src_mac[ETHER_ADDR_LEN]);

    
	/**
	 * @brief Handle a configuration request 802.11+GAS frame, performing the necessary actions and responding with a configuration result via 802.11.
	 *
	 * This function processes the incoming configuration request frame and generates a response based on the configuration result.
	 *
	 * @param[in] buff The frame to handle.
	 * @param[in] len The length of the frame.
	 * @param[in] sa The 802.11 source address of this frame.
	 *
	 * @return bool True if the configuration response was handled successfully, false otherwise.
	 */
	bool handle_config_response(uint8_t *buff, size_t len, uint8_t sa[ETH_ALEN]);

	/**
	 * @brief Handles a GAS Comeback Response containing a fragment of a Configuration Response frame.
	 * 
	 * @param frame The GAS Comeback Frame
	 * @param len Length of the frame. 
	 * @param src_mac Where the frame came from
	 * @return true on success, otherwise false.
	 */
	bool handle_gas_comeback_response(ec_gas_comeback_response_frame_t *frame, size_t len, uint8_t src_mac[ETH_ALEN]);

	/**
	 * @brief Handles a GAS Initial Response frame.
	 * 
	 * @param frame The GAS Initial Response frame.
	 * @param len The length of the frame.
	 * @param src_mac Where the frame came from
	 * @return true on success, otherwise false
	 * @note: If this is a "dummy" GAS Initial Response frame, Enrollee responds with a GAS Comeback Request frame to initial frame fragmentation
	 * 
	 * Otherwise, if this is a "real" GAS Initial Response frame, it's forwarded to `handle_config_response`
	 */
	bool handle_gas_initial_response(ec_gas_initial_response_frame_t *frame, size_t len, uint8_t src_mac[ETH_ALEN]);

	/**
	 * @brief Handle a Reconfiguration Authentication Request frame
	 * 
	 * @param frame The Reconfiguration Authentication Request frame
	 * @param len The length of the frame
	 * @param src_mac Where the frame came from (Configurator)
	 * @return true on success, otherwise false
	 */
	bool handle_recfg_auth_request(ec_frame_t *frame, size_t len, uint8_t src_mac[ETH_ALEN]);

	/**
	 * @brief Handles a Reconfiguration Authentication Confirm frame
	 * 
	 * @param frame The Reconfiguration Authentication Confirm frame
	 * @param len The length of the frame
	 * @param src_mac The source address (Configurator)
	 * @return true on success, otherwise false
	 */
	bool handle_recfg_auth_confirm(ec_frame_t *frame, size_t len, uint8_t src_mac[ETH_ALEN]);

	/**
	 * @brief Handle a Direct Encapsulated DPP Message (DPP Message TLV)
	 *
	 * @param[in] dpp_frame The frame parsed from the DPP Message TLV
	 * @param[in] dpp_frame_len The length of the frame from the DPP Message TLV
	 *
	 * @return bool True if the frame was processed successfully, false otherwise.
	 */
	bool process_direct_encap_dpp_msg(uint8_t* dpp_frame, uint16_t dpp_frame_len, uint8_t src_mac[ETH_ALEN]);

	/**
	 * @brief Process a 1905 EAPOL Encapsulated Message (1905 Encap EAPOL TLV)
	 *
	 * @param[in] eapol_frame The frame parsed from the 1905 Encap EAPOL TLV
	 * @param[in] eapol_frame_len The length of the frame from the 1905 Encap EAPOL TLV
	 * @param[in] src_mac The source MAC address of the EAPOL frame
	 *
	 * @return bool True if the frame was processed successfully, false otherwise.
	 */
	bool process_1905_eapol_encap_msg(uint8_t* eapol_frame, uint16_t eapol_frame_len, uint8_t src_mac[ETH_ALEN]) {
		return m_1905_encrypt_layer.handle_eapol_frame(eapol_frame, eapol_frame_len, src_mac);
	}

	/**
	 * @brief Handle a DPP peer discovery response frame.
	 *
	 * This function processes a DPP peer discovery response frame received from a peer device.
	 * It delegates the frame handling to the underlying 1905 encryption layer for processing.
	 *
	 * @param[in] frame Pointer to the DPP peer discovery response frame to be processed.
	 * @param[in] len The length of the frame in bytes.
	 * @param[in] src_mac The source MAC address of the frame sender
	 *
	 * @return true if the frame was processed successfully, otherwise false.
	 */
	bool handle_peer_disc_resp_frame(ec_frame_t *frame, uint16_t len, uint8_t src_mac[ETH_ALEN]) {
		return m_1905_encrypt_layer.handle_peer_disc_resp_frame(frame, len, src_mac);
	}

	/**!
	 * @brief Tears down the existing connection by freeing associated resources.
	 *
	 * This function releases the connection context and ephemeral context resources
	 * associated with the current connection.
	 *
	 * @note Ensure that the connection is no longer needed before calling this function
	 * to avoid any unintended behavior.
	 */
	inline void teardown_connection() {
		// Frees connection context and associated ephemeral context
        ec_crypto::free_connection_ctx(&m_c_ctx);
    }

    
	/**
	 * @brief Retrieves the current security context.
	 */
	inline ec_persistent_sec_ctx_t* get_sec_ctx() { return &m_sec_ctx; };

	/**!
	 * @brief Retrieves the AL MAC address.
	 *
	 * @returns The AL MAC address as a string.
	 */
	inline std::string get_al_mac_addr() { return m_al_mac_addr; };

	/**!
	 * @brief Retrieves wether this enrollee is in onboarding state or not.
	 * 
	 * @returns true if this enrollee is in onboarding state, false otherwise.
	 */
	inline bool is_onboarding() { return m_is_onboarding; };

    // Disable copy construction and assignment
    // Requires use of references or pointers when working with instances of this class
    
	/**!
	 * @brief Deleted copy constructor for ec_enrollee_t.
	 *
	 * This constructor is deleted to prevent copying of ec_enrollee_t instances.
	 *
	 * @note Copying of ec_enrollee_t is not allowed to ensure unique ownership or to prevent resource duplication.
	 */
	ec_enrollee_t(const ec_enrollee_t&) = delete;
    ec_enrollee_t& operator=(const ec_enrollee_t&) = delete;

	/**
	 * @brief Handles an association status event.
	 * 
	 * If this event maps to our bSTA's association attempt, check the association status and send a Configuration Status Result frame
	 * 
	 * If this event does NOT map to our bSTAs association attempt, just throw it away
	 * 
	 * @param sta_data The STA data containing association status
	 * @return true on success, otherwise false
	 */
	bool handle_assoc_status(const rdk_sta_data_t &sta_data);

	/**
	 * @brief Handle a list of BSS info events generated by a scan
	 * 
	 * This callback is triggered by OneWifi scanning
	 * 
	 * If one of these BSS infos contains the SSID that we were instructed to 
	 * connect to (in the Configuration Response from the Configurator), we add
	 * that BSS info's heard frequency to our Reconfiguration Announcement 
	 * broadcast frequency list.
	 * 
	 * If one of these BSS infos contains a CCE IE we add that BSS info's 
	 * heard frequency to our (Reconfiguration) Announcement broadcast frequency list.
	 * 
	 * @param bss_info_list The BSS info containing SSID and frequency
	 * @return true on success, otherwise false
	 */
	bool handle_bss_info_event(const std::vector<wifi_bss_info_t> &bss_info_list);

	/**
     * @brief Initiates secure 1905 layer establishment with peer
     * @param dest_al_mac Destination AL MAC address
     * @return true if peer discovery request sent successfully
     * 
     * @note Creates and sends DPP Peer Discovery Request to begin security establishment process.
     */
	inline bool start_secure_1905_layer(uint8_t dest_al_mac[ETH_ALEN]) {
		return m_1905_encrypt_layer.start_secure_1905_layer(dest_al_mac);
	}

	/**
     * @brief Rekeys existing PTK with established peer
     * @param dest_al_mac Destination AL MAC address
     * @return true if PTK rekey handshake initiated successfully
     * 
     * @note Requires existing key context. Initiates the same 4-way handshake 
     *       as the initial handshake with some minor flags changed.
     */
	inline bool rekey_1905_layer_ptk(uint8_t dest_al_mac[ETH_ALEN]) {
		return m_1905_encrypt_layer.rekey_1905_layer_ptk(dest_al_mac);
	}

	/**
     * @brief Rekeys existing PTK with all established peers
     * @return true if all PTK rekey handshakes initiated successfully
     * 
     * @note Requires existing key contexts. Initiates the same 4-way handshake 
     *       as the initial handshake with some minor flags changed.
     */
	inline bool rekey_1905_layer_ptk() {
		return m_1905_encrypt_layer.rekey_1905_layer_ptk();
	}

	/**
	 * @brief Notifies the destructor that the enrollee is upgrading to a (proxy) agent
	 * 
	 */
	inline void signal_enrollee_is_upgrading() { m_is_upgrading_flag = true; }

private:

	/**
	 * @brief Initializes the corresponding channel list with the default channels
	 * then triggers a channel scan to add channels where BSSs are either broadcasting 
	 * CCE IEs and/or the configured SSID.
	 * 
	 * @param is_reconfig_list If true, generate the reconfiguration channel list.
	 * Otherwise, generate the presence announcement channel list.
	 * 
	 * @note See: EasyConnect 6.2.2 Generation of Channel List for Presence Announcement
	 * @note See: EasyConnect 6.5.2 DPP Reconfiguration Announcement 
	 */
	void generate_bss_channel_list(bool is_reconfig_list);
    
	/**
	 * @brief Sends presence announcement frames until a DPP Authentication Frame is received.
	 *
	 * This function initiates the process of sending presence announcement frames, which
	 * continue until a DPP Authentication Frame is detected. This is part of the DPP
	 * (Device Provisioning Protocol) process.
	 *
	 * @note See: EasyConnect 6.2 DPP Presence Announcement
	 */
	void send_presence_announcement_frames();

	/**
	 * @brief Sends DPP Reconfiguration Announcement frames until a DPP Reconfiguration Authentication Request frame is received
	 * 
	 * 
	 * @note See: EasyConnect 6.5.2 DPP Reconfiguration Announcement
	 */
	void send_reconfiguration_announcement_frames();


	/**
	 * @brief Check that a given BSS Info has a CCE IE present in it's IE buffer
	 * 
	 * @param bss_info The bss info to check
	 * @return True if a CCE IE exists in the IE buffer, false otherwise
	 */
	bool check_bss_info_has_cce(const wifi_bss_info_t& bss_info);

	std::string m_al_mac_addr;

    /**
     * @brief Send an action frame. Optional to implement.
     * 
     * @param dest_mac The destination MAC address
     * @param action_frame The action frame to send
     * @param action_frame_len The length of the action frame
     * @param frequency The frequency to send the frame on (0 for current frequency)
     * @param wait The time to wait on the channel after sending the frame (0 for no wait)
     * @return true if successful, false otherwise
     */
    send_act_frame_func m_send_action_frame;

    /**
     * @brief Get backhaul station information to be JSON encoded and added to DPP Configuration Request frame.
     *
     * @return cJSON * on success, nullptr otherwise.
     */
    get_backhaul_sta_info_func m_get_bsta_info;

	/**
	 * @brief Function to trigger a scan on a station interface 
	 * 
	 * @return bool true if the action was successful, false otherwise
	 */
	trigger_sta_scan_func m_trigger_sta_scan_fn;

	/**
	 * @brief Function to attempt to connect a backhaul STA to a BSS
	 * 
	 * @param bsta_mac The MAC address of the backhaul STA
	 * @param bss_info The BSS information to connect to
	 * @return bool true if successful, false otherwise
	 */	
	bsta_connect_func m_bsta_connect_fn;

	/**
	 * @brief Sends a direct encapsulated DPP message
	 * 
	 * @param dpp_frame The DPP frame to send
	 * @param dpp_frame_len The length of the DPP frame
	 * @return bool true if successful, false otherwise
	 */
	send_dir_encap_dpp_func m_send_dir_encap_fn;
	
    // Maps SSID that this Enrollee has attempted to find to the
    // list of channels/op-classes that were scanned.
    std::unordered_map<std::string, std::vector<ec_util::scanned_channels_t>> m_scanned_channels_map;

	ec_1905_encrypt_layer_t m_1905_encrypt_layer;



    const ec_dpp_capabilities_t m_dpp_caps = {{
        .enrollee = 1,
        .configurator = 0,
        .reserved = 0
    }};

    
	/**!
	 * @brief Creates a presence announcement.
	 *
	 * This function generates a presence announcement and returns it as a pair.
	 *
	 * @returns A pair consisting of a pointer to the announcement data and its size.
	 */
	std::pair<uint8_t*, size_t> create_presence_announcement();
    
	/**!
	 * @brief Creates a reconfiguration presence announcement.
	 *
	 * This function generates a presence announcement for reconfiguration purposes.
	 *
	 * @returns A pair consisting of a pointer to the announcement data and its size.
	 */
	std::pair<uint8_t*, size_t> create_recfg_presence_announcement();
    
	/**!
	 * @brief Creates an authentication response based on the given DPP status and protocol version.
	 *
	 * @param[in] dpp_status The DPP status code used to determine the response.
	 * @param[in] init_proto_version The initial protocol version for the response.
	 *
	 * @returns A pair consisting of a pointer to the response data and its size.
	 *
	 * @note Ensure that the response data is properly managed to avoid memory leaks.
	 */
	std::pair<uint8_t*, size_t> create_auth_response(ec_status_code_t dpp_status, uint8_t init_proto_version);
    
	/**!
	 * @brief Creates a reconfiguration authentication response.
	 *
	 * This function generates a response for reconfiguration authentication based on the provided DPP status code.
	 *
	 * @param trans_id The transaction ID for this Reconfiguration session
	 * @param dpp_version The DPP version for this Reconfiguration session
	 *
	 * @returns A pair consisting of a pointer to the response data and its size.
	 * @retval std::pair<uint8_t*, size_t> A pair where the first element is a pointer to the response data and the second element is the size of the data.
	 *
	 * @note Ensure that the response data is properly managed and freed after use to avoid memory leaks.
	 */
	std::pair<uint8_t*, size_t> create_recfg_auth_response(uint8_t trans_id, uint8_t dpp_version);
    
	/**!
	 * @brief Creates a configuration request.
	 *
	 * This function generates a configuration request and returns it as a pair consisting of a pointer to the data and its size.
	 * @param (optional) reconfiguration flags if being called during Reconfiguration
	 * @returns A pair containing a pointer to the configuration request data and its size.
	 * @retval std::pair<uint8_t*, size_t> A pair where the first element is a pointer to the data and the second element is the size of the data.
	 *
	 * @note Ensure that the returned pointer is managed properly to avoid memory leaks.
	 */
	std::pair<uint8_t*, size_t> create_config_request(std::optional<ec_dpp_reconfig_flags_t> recfg_flags = std::nullopt);

    
	/**
	 * @brief Create a Configuration Result frame (EasyConnect 8.2.12)
	 *
	 * This function generates a configuration result frame based on the provided
	 * status code. The frame is used in the EasyConnect protocol to communicate
	 * the result of a configuration attempt.
	 *
	 * @param[in] dpp_status The status code representing the result of the
	 * configuration process. It indicates whether the enrollee was successful
	 * or encountered an error.
	 *
	 * @return std::pair<uint8_t*, size_t> A pair where:
	 * - pair.first is a pointer to the generated frame. It will be nullptr if
	 *   the frame creation fails.
	 * - pair.second is the length of the frame. It will be 0 if the frame
	 *   creation fails.
	 *
	 * @note Ensure that the status code provided is valid and corresponds to
	 * the expected values in the EasyConnect protocol.
	 */
	std::pair<uint8_t*, size_t> create_config_result(ec_status_code_t dpp_status);

    
	/**
	 * @brief Create a connection status result frame (EasyConnect 8.2.13)
	 *
	 * This function generates a frame representing the connection status
	 * based on the provided status code and SSID.
	 *
	 * @param[in] dpp_status The status code representing the enrollee's
	 * configuration status.
	 * @param[in] ssid The SSID the enrollee attempted to find or associate with.
	 *
	 * @return std::pair<uint8_t*, size_t> A pair where the first element is
	 * a pointer to the frame (nullptr on failure) and the second element is
	 * the length of the frame (0 on failure).
	 */
	std::pair<uint8_t*, size_t> create_connection_status_result(ec_status_code_t dpp_status, const std::string& ssid);

	/**
	 * @brief Create a GAS Comeback Request frame with default fields to be sent to a Peer indicating we're ready to receive the next GAS Comeback Response frame
	 * 
	 * @param dialog_token The dialog token of the GAS session
	 * @return ec_gas_comeback_request_frame_t* The GAS Comeback Frame on success, otherwise nullptr
	 */
	ec_gas_comeback_request_frame_t *create_comeback_request(uint8_t dialog_token);
    
	/**
	 * @brief Create a DPP Connection Status object (EasyConnect 6.5.4.2)
	 *
	 * This function creates a DPP Connection Status object based on the provided
	 * DPP status code and SSID.
	 *
	 * @param[in] dpp_status The DPP status code. Can be one of: STATUS_OK, STATUS_AUTH_FAILURE,
	 * STATUS_INVALID_CONNECTOR, STATUS_NO_MATCH, STATUS_NO_AP. See EasyConnect table 23.
	 * @param[in] ssid The SSID the Enrollee attempted to associate to.
	 *
	 * @return cJSON* The DPP Connection Status object on success, nullptr otherwise.
	 *
	 * @note Heap allocates, caller must free.
	 */
	cJSON *create_dpp_connection_status_obj(ec_status_code_t dpp_status, const std::string& ssid);

    ec_connection_context_t m_c_ctx = {};

    
	/**
	 * @brief Retrieves the connection's bootstrapping data.
	 *
	 * This function provides access to the bootstrapping data used in the connection context.
	 *
	 * @returns A reference to the bootstrapping data of type `ec_data_t`.
	 */
	inline ec_data_t& m_boot_data(){
        return m_c_ctx.boot_data;
    }
    
	/**
	 * @brief Retrieves the connection's ephemeral context.
	 *
	 * This function returns a reference to the ephemeral context associated with the connection.
	 *
	 * @returns A reference to the ephemeral context.
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
    std::unordered_set<uint32_t> m_pres_announcement_freqs = {};

	/**
	 * @brief Set of frequencies to broadcast Reconfiguration Announcement frames on
	 * 
	 * This list should be extended as follows (EasyConnect 6.5.2):
	 * 
	 * 1. If a beacon/probe response is heard advertising the SSID we were given in the Configuration response object,
	 * add the channel where this frame was heard
	 * 
	 * 2. Channels where a CCE IE was heard
	 * 
	 */
	std::unordered_set<uint32_t> m_recnf_announcement_freqs = {};

    /**
     * @brief The frequency to send action frames on
     * 
     * This is determined based on the channel in which the authentication request is recieved
     */
    uint32_t m_selected_freq = 0;

    /**
     * @brief True if we've received DPP Authentication Frame
     * 
     * Signals that this Enrollee should stop sending presence announcement frames.
     * 
     */
    std::atomic<bool> m_received_auth_frame{false};

	/**
	 * @brief True if we've received DPP Reconfiguration Authentication Request frame
	 * 
	 * Signals that this Enrollee should stop sending Reconfiguration Announcement frames
	 */
	std::atomic<bool> m_received_recfg_auth_frame{false};

	/**
	 * @brief True if we've received scan results
	 * 
	 * Signals that this Enrollee should stop waiting for scan results
	 */
	std::atomic<bool> m_received_scan_results{false};

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

	/**
	 * @brief Thread for sending Reconfiguration Announcement frames
	 * 
	 * Sends Reconfig Announcement frames until a Reconfiguration Authentication Request frame is heard
	 * 
	 * Must be on a seperate thread so as not to block the receiving
	 * of the Reconfiguration Authentication Request frame
	 * 
	 */
	std::thread m_send_recfg_announcement_thread;

	/**
	 * @brief Metadata about a fragmented GAS response frame
	 * 
	 */
	struct gas_fragment_buffer_t {
		uint8_t dialog_token = 0;
		std::vector<uint8_t> reassembled_payload = {};
		uint8_t expected_fragment_id = 0;
		bool complete = false;
		std::chrono::steady_clock::time_point last_seen = std::chrono::steady_clock::now();
	};

	// Key -> sender's MAC + dialog_token (example: aabbcceeddff_42) as a string
	// Value -> buffer for re-assembling GAS frame fragments
	std::unordered_map<std::string, gas_fragment_buffer_t> m_gas_fragments;

	/**
	 * @brief Map of BSSIDs (as strings) that we are awaiting association status for
	 * Key: BSSID (as string)
	 * Value: The MAC of the node we're trying to associate to
	 */
	std::unordered_map<std::string, std::vector<uint8_t>> m_awaiting_assoc_status = {};

	bool m_is_onboarding = false;

	/**
	 * @brief The SSID contained in the Configuration Response that we're meant to connect to
	 * 
	 * This is used in part to rebuild a channel list for DPP Reconfiguration
	 * 
	 * EasyConnect 6.5.2:
	 * 	For each channel on which the Enrollee detects the SSID for which it is currently configured, add to the channel list
	 * 
	 */
	std::string m_configured_ssid = {};

	/**
	 * The context filled with security keys for the Enrollee that will be saved 
	 * to the persistent storage on exit.
	 */
	ec_persistent_sec_ctx_t m_sec_ctx = {};

	/**
	 * @brief True if this Enrollee will soon be upgrading
	 * to a (proxy) agent and the destructor will be called.
	 */
	bool m_is_upgrading_flag = false; 
};

#endif // EC_ENROLLEE_H
