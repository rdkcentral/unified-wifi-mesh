#ifndef EC_PA_CONFIGURATOR_H
#define EC_PA_CONFIGURATOR_H

#include "ec_configurator.h"
#include "util.h"

#include <map>
#include <vector>

class ec_pa_configurator_t : public ec_configurator_t {
public:
    
	/**
	 * @brief The Proxy Agent side of the EasyConnect Configurator.
	 *
	 * This constructor initializes the EasyConnect Configurator for the Proxy Agent.
	 * It handles the 802.11 frames from the Enrollee and forwards them to the Controller.
	 * It also handles the 1905 frames from the Controller and forwards them to the Enrollee.
	 *
	 * @param[in] al_mac_addr The AL MAC address of the device.
	 * @param[in] ctrl_al_mac_addr The AL MAC address of the Controller.
	 * @param[in] ops Callbacks for this Configurator
	 * @param[in] sec_ctx The existing security context. Non-optional since the proxy agent must already be onboarded.
	 * @param[in] is_colocated True if this is a colocated agent. False otherwise
	 *
	 * @note This constructor is part of the ec_pa_configurator_t class which extends ec_configurator_t.
	 */
	ec_pa_configurator_t(const std::string& al_mac_addr, const std::vector<uint8_t>& ctrl_al_mac_addr, ec_ops_t& ops, ec_persistent_sec_ctx_t& sec_ctx, bool is_colocated, handshake_completed_handler handshake_complete);
    
	/**
	 * @brief Handles a presence announcement 802.11 frame, performing the necessary actions and possibly passing to 1905.
	 *
	 * This function processes the given 802.11 frame and determines the appropriate actions to take. It may also forward the frame to the 1905 layer if necessary.
	 *
	 * @param[in] frame The 802.11 frame to handle.
	 * @param[in] len The length of the frame.
	 * @param[in] src_mac The source MAC address of the frame.
	 *
	 * @return true if the frame was handled successfully, false otherwise.
	 *
	 * @note This function is optional to implement because the controller+configurator does not handle 802.11 frames, but the proxy agent + configurator does.
	 */
	bool handle_presence_announcement(ec_frame_t *frame, size_t len, uint8_t src_mac[ETHER_ADDR_LEN]) override;

	/**
	 * @brief Handles a Reconfiguration Announcement frame
	 * 
	 * @param frame The Reconfiguration Announcement frame
	 * @param len The length of the frame
	 * @param sa The source MAC of the frame (Enrollee)
	 * @return true on success, otherwise false
	 */
	bool handle_recfg_announcement(ec_frame_t *frame, size_t len, uint8_t sa[ETH_ALEN], uint8_t src_al_mac[ETH_ALEN]) override;
    
	/**
	 * @brief Handles an authentication request 802.11 frame, performing the necessary actions and possibly passing to 1905.
	 *
	 * This function processes the given 802.11 authentication frame and determines the appropriate actions to take.
	 *
	 * @param[in] frame The frame to handle.
	 * @param[in] len The length of the frame.
	 * @param[in] src_mac The source MAC address of the frame.
	 *
	 * @return true if the frame was handled successfully, false otherwise.
	 *
	 * @note This function is optional to implement because the controller+configurator does not handle 802.11,
	 *       but the proxy agent + configurator does.
	 */
	bool handle_auth_response(ec_frame_t *frame, size_t len, uint8_t src_mac[ETHER_ADDR_LEN], uint8_t src_al_mac[ETH_ALEN]) override;

    
	/**
	 * @brief Handles a configuration request 802.11+GAS frame, performing the necessary actions and possibly passing to 1905.
	 *
	 * @param[in] buff The frame to handle.
	 * @param[in] len The length of the frame.
	 * @param[in] sa The 802.11 source address of the frame (from Enrollee).
	 *
	 * @return bool True if successful, false otherwise.
	 *
	 * @note Optional to implement because the controller+configurator does not handle 802.11,
	 *       but the proxy agent + configurator does.
	 */
	bool handle_cfg_request(uint8_t *buff, unsigned int len, uint8_t sa[ETH_ALEN]) override;

    
	/**
	 * @brief Handles a configuration result 802.11+GAS frame, performing the necessary actions and possibly passing to 1905.
	 *
	 * This function processes the given frame and determines the appropriate actions to take.
	 *
	 * @param[in] frame The frame to handle.
	 * @param[in] len The length of the frame.
	 * @param[in] sa The source address of the frame.
	 *
	 * @return true if the frame was handled successfully, false otherwise.
	 *
	 * @note This function is optional to implement because the controller+configurator does not handle 802.11,
	 *       but the proxy agent + configurator does.
	 */
	bool handle_cfg_result(ec_frame_t *frame, size_t len, uint8_t sa[ETH_ALEN]) override;

    
	/**
	 * @brief Handles Connection Status Result frame.
	 *
	 * This function processes the connection status result frame and determines
	 * the success or failure of the operation based on the frame's content.
	 *
	 * @param[in] frame The frame to be processed.
	 * @param[in] len The length of the frame.
	 * @param[in] sa The source address of the frame, represented as an array of
	 * bytes with a length of ETH_ALEN.
	 *
	 * @return true if the frame was processed successfully, otherwise false.
	 */

	bool handle_connection_status_result(ec_frame_t *frame, size_t len, uint8_t sa[ETH_ALEN]) override;

	/**
	 * @brief Handle a proxied encapsulated DPP message TLVs (including chirp value) and direct to the correct place (802.11 or 1905)
	 *
	 * This function processes the encapsulated DPP message TLVs and directs them to the appropriate protocol handler.
	 *
	 * @param[in] encap_tlv The 1905 Encap DPP TLV to parse and handle.
	 * @param[in] encap_tlv_len The length of the 1905 Encap DPP TLV.
	 * @param[in] chirp_tlv The DPP Chirp Value TLV to parse and handle. Pass NULL if not present.
	 * @param[in] chirp_tlv_len The length of the DPP Chirp Value TLV. Pass 0 if not present.
	 * @param[in] src_al_mac The source AL MAC address of this message
	 *
	 * @return bool True if the message was processed successfully, false otherwise.
	 */
	bool process_proxy_encap_dpp_msg(em_encap_dpp_t *encap_tlv, uint16_t encap_tlv_len, em_dpp_chirp_value_t *chirp_tlv, uint16_t chirp_tlv_len, uint8_t src_al_mac[ETH_ALEN]) override;

	/**
	 * @brief Handle a Direct Encapsulated DPP Message (DPP Message TLV)
	 *
	 * @param[in] dpp_frame The frame parsed from the DPP Message TLV
	 * @param[in] dpp_frame_len The length of the frame from the DPP Message TLV
	 *
	 * @return bool True if the frame was processed successfully, false otherwise.
	 */
	bool  process_direct_encap_dpp_msg(uint8_t* dpp_frame, uint16_t dpp_frame_len, uint8_t src_mac[ETH_ALEN]) override;

	/**
	 * @brief Handles a GAS Comeback Request frame
	 * A GAS Comeback Request frame (in the context of DPP) indicates that a peer is ready the to receive the next fragmented frame via GAS Comeback Response frame.
	 * 
	 * For each Comeback Request frame received, we will sent the next fragment (if any) to the requesting peer.
	 * @param buff The frame
	 * @param len The length of the frame
	 * @param sa The source addr of the frame (Enrollee)
	 * @return true on success, otherwise false
	 */
	bool handle_gas_comeback_request(uint8_t *buff, unsigned int len, uint8_t sa[ETH_ALEN]) override;

    /**
     * @brief Set the CCE IEs in the beacon and probe response frames
     * 
     * @param bool Whether to enable or disable the inclusion of CCE IEs in the beacon and probe response frames
     * @return bool true if successful, false otherwise
     * @note If the operation fails, all CCE IEs are removed before the function exits
     */
    toggle_cce_func m_toggle_cce;

private:
    // Private member variables go here
    /*
     * Map from Chirp Hash to DPP Authentication Request
     */
    std::map<std::string, std::vector<uint8_t>> m_chirp_hash_frame_map = {};

	/**
	 * @brief Map of stored DPP Reconfiguration Authentication Requests
	 * 
	 * Key -> C-sign key hash as a string
	 * Value -> Vector of DPP Reconfiguration Authentication Request frames
	 */
	std::unordered_map<std::string, std::vector<uint8_t>> m_stored_recfg_auth_frames_map = {};

	/**
	 * @brief Stored GAS frame session dialog tokens with peers.
	 * 
	 * Key -> Peer MAC, as a string
	 * Value -> GAS session dialog token for the peer.
	 */
	std::unordered_map<std::string, uint8_t> m_gas_session_dialog_tokens = {};


	std::vector<uint8_t> m_ctrl_al_mac_addr = {}; // Controller AL MAC address

	/**
	 * @brief Sends a "dummy" GAS Initial Response frame indicating to the Peer that we have fragmented data for it
	 * 
	 * The peer must respond to this frame with a GAS Comeback Request in order for GAS Comeback Responses to follow
	 * @param dest_mac The destination MAC
	 * @return true on success, otherwise false
	 */
	bool send_prepare_for_fragmented_frames_frame(uint8_t dest_mac[ETH_ALEN]);

	/**
	 * @brief Fragments a frame whose size exceeds the MTU size
	 * 
	 * @param payload The total payload
	 * @param len The full length
	 * @param dialog_token The GAS peer session dialog token
	 * @return std::vector<ec_gas_comeback_response_frame_t *> Vector of frame fragments encapsulated in GAS Comeback Response frames, otherwise empty
	 */
	std::vector<ec_gas_comeback_response_frame_t *> fragment_large_frame(const uint8_t *payload, size_t len, uint8_t dialog_token);

	/**
	 * @brief Queue'd fragments to be sent to a peer once they indicate (via a GAS Comeback Request frame) that they are ready to receive more fragments
	 * 
	 */
	std::unordered_map<std::string, std::vector<ec_gas_comeback_response_frame_t*>> m_gas_frames_to_be_sent = {};

protected:
    // Protected member variables and methods go here
};

#endif // EC_PA_CONFIGURATOR_H