#include "ec_enrollee.h"

#include "ec_crypto.h"
#include "em_crypto.h"
#include "util.h"
#include "cjson/cJSON.h"
#include "cjson_util.h"
#include <unistd.h>

ec_enrollee_t::ec_enrollee_t(const std::string& mac_addr, ec_ops_t& ops)
    : m_mac_addr(mac_addr)
{
    m_send_action_frame = ops.send_act_frame;
    m_get_bsta_info = ops.get_backhaul_sta_info;
    m_trigger_sta_scan_fn = ops.trigger_sta_scan;
    m_bsta_connect_fn = ops.bsta_connect;
    m_send_dir_encap_fn = ops.send_dir_encap_dpp;
    m_scanned_channels_map = {};
}

ec_enrollee_t::~ec_enrollee_t()
{
    teardown_connection();
    if (m_send_pres_announcement_thread.joinable()) m_send_pres_announcement_thread.join();
}

bool ec_enrollee_t::start_onboarding(bool do_reconfig, ec_data_t* boot_data)
{
    m_is_onboarding = false;
    ASSERT_NOT_NULL(boot_data, false, "%s:%d Bootstrapping data is NULL\n", __func__, __LINE__);
    if (boot_data->version < 2) {
        em_printfout("Bootstrapping Version '%d' not supported!", boot_data->version);
        return false;
    }
    if (memcmp(boot_data->mac_addr, ZERO_MAC_ADDR, ETHER_ADDR_LEN) == 0) {
        em_printfout("Bootstrapping data MAC address is 0 ");
        return false;
    }
    if (boot_data->responder_boot_key == NULL) {
        em_printfout("Bootstrapping data responder key is NULL");
        return false;
    }

    memset(&m_boot_data(), 0, sizeof(ec_data_t));
    memcpy(&m_boot_data(), boot_data, sizeof(ec_data_t));


    printf("Enrollee MAC: %s\n", m_mac_addr.c_str());

    const SSL_KEY* resp_key = do_reconfig ? m_c_ctx.C_signing_key : m_boot_data().responder_boot_key;
    if (resp_key == NULL) {
        em_printfout("No bootstrapping key found");
        return false;
    }
    // Not all of these will be present but it is better to compute them now.
    m_boot_data().resp_priv_boot_key = em_crypto_t::get_priv_key_bn(resp_key);
    m_boot_data().resp_pub_boot_key = em_crypto_t::get_pub_key_point(resp_key);

    m_boot_data().init_priv_boot_key = em_crypto_t::get_priv_key_bn(m_boot_data().initiator_boot_key);    
    m_boot_data().init_pub_boot_key = em_crypto_t::get_pub_key_point(m_boot_data().initiator_boot_key);

    // Baseline test to ensure the bootstrapping key is present
    if (m_boot_data().resp_pub_boot_key == NULL) {
        em_printfout("Could not get responder bootstrap public key");
        return false;
    }
    
    if (!ec_crypto::init_connection_ctx(m_c_ctx, resp_key)){
        em_printfout("failed to initialize persistent context");
        return false;
    }

    generate_bss_channel_list(do_reconfig);

    // Begin send presence announcements thread.
    m_send_pres_announcement_thread = std::thread(&ec_enrollee_t::send_presence_announcement_frames, this);
    m_is_onboarding = true;
    return true;
}

void ec_enrollee_t::generate_bss_channel_list(bool is_reconfig_list){
    // EasyConnect 6.2.2:  Generation of Channel List for Presence Announcement (EC)
    // EasyConnect 6.5.2:  DPP Reconfiguration Announcement (EC-Reconfig)

    auto& freq_list = is_reconfig_list ? m_recnf_announcement_freqs : m_pres_announcement_freqs; 


    // Clear existing channel list
    freq_list.erase(freq_list.begin(), freq_list.end());
    

    // This step is not present in EC-Reconfig for some reason (likely because of the SSID check)
    if (!is_reconfig_list) {
        /* EC #1

        If the enrollee includes a list of global operating class/channel pairs in its DPP URI, 
        add all those channels to the channel list excluding channels for which unsolicited transmissions 
        are prohibited by local regulations (e.g., channels subject to Dynamic Frequency Selection);
        */

        for (size_t i = 0; i < std::size(m_boot_data().ec_freqs); i++) {
            if (m_boot_data().ec_freqs[i] == 0) continue;
            freq_list.insert(m_boot_data().ec_freqs[i]);
        }
    }


    /* EC #2 and EC-Reconfig #1

    Select preferred Presence Announcement channels on which to send a DPP Presence Announcement frame 
    to the broadcast address. For interoperability purposes, the preferred channel shall be one from each 
    of the following bands, as supported by the Enrollee:

    - 2.4 GHz: Channel 6 (2.437 GHz)
    - 5 GHz: Channel 44 (5.220 GHz) ...
    - 60 GHz: Channel 2 (60.48 GHz)
    - Sub-1 GHz: Channel 37 (920.5 MHz) ... otherwise Channel 1 (863.5 MHz) ...
    Add the preferred Presence Announcement channels to the channel list;
    */

    freq_list.insert(2437); // 2.4 GHz: Channel 6 (2.437 GHz)
    freq_list.insert(5220); // 5 GHz: Channel 44 (5.220 GHz)
    freq_list.insert(60480); // 60 GHz: Channel 2 (60.48 GHz)
    freq_list.insert(920); // 920 MHz: Channel 37 

    /* EC-Reconfig #2

    For each channel on which the Enrollee detects the SSID for which it is currently configured, 
    add to the channel list;
    */
    /* EC #3 and EC-Reconfig #3

    Scan all supported bands and add each channel on which an AP is advertising 
    the Configurator Connectivity element (CCE, Section 8.5.2) to the channel list;
    */
    // Both checks happen when the scan results are returned
    if (!m_trigger_sta_scan_fn()){
        em_printfout("Failed to start channel scan for DPP Channel List Generation");
        return;
    }

    // Wait to recieve scan results
    bool did_recieve_scan = ec_util::interruptible_sleep(std::chrono::seconds(3), [this]() -> bool {
        return m_received_scan_results.load();
    });

    if (did_recieve_scan) {
        em_printfout("Recieved scan results!");
    } else {
        em_printfout("Timed out while trying to recieve scan results, continuing either way...");
    }

    /* EC #4 and EC-Reconfig #4
    
    Remove any second or subsequent occurrence of duplicate channels in the channel list.
    */
    // This is done by using a set, which automatically handles duplicates.
    
}

void ec_enrollee_t::send_presence_announcement_frames()
{
    uint32_t attempts = 0;
    uint32_t dwell = 2000;

    auto [frame, frame_len] = create_presence_announcement();
    if (frame == nullptr || frame_len == 0) {
        em_printfout("Failed to create DPP Presence Announcement frame");
        return;
    }

    uint32_t current_freq = 0;

    while (!m_received_auth_frame.load()) {
        if (attempts >= 4) {
            // EasyConnect 6.2.3
            // If the device has cycled through the procedure (Steps 1 & 2) four times without receipt of a valid DPP
            // Authentication Request frame, the Enrollee may wait some amount of time before resuming the procedure. Prior
            // to resuming the presence announcement procedure, however, it shall generate a new channel list using the steps
            // specified in Section 6.2.2.
            attempts = 0;
            dwell = 2000;

            if (!ec_util::interruptible_sleep(std::chrono::seconds(5), [this]() -> bool {
                return m_received_auth_frame.load();
            })) {
                break;
            }

            // Generate new channel list
            generate_bss_channel_list(false);
        }

        for (const auto& freq : m_pres_announcement_freqs) {
            // EasyConnect 6.2.3
            // For each channel in the channel list generated as per Section 6.2.2, the Enrollee, shall send a DPP Presence
            // Announcement frame and listen for 2 seconds to receive a DPP Authentication Request frame. If a valid DPP
            // Authentication Request frame is not received, it shall repeat the presence announcement for the next channel in
            // the channel list.

            // Send frame
            if (!m_send_action_frame(const_cast<uint8_t *>(BROADCAST_MAC_ADDR), frame, frame_len, freq, dwell)) {
                em_printfout("Failed to send DPP Presence Announcement frame (broadcast) on freq %d", freq);
            }

            current_freq = freq;

            // Wait `dwell` before moving to next channel.
            if (!ec_util::interruptible_sleep(std::chrono::milliseconds(dwell), [this]() -> bool {
                return m_received_auth_frame.load();
            })) {
                break;
            }
        }
        // EasyConnect 6.2.3
        // When all channels in the channel list have been exhausted, the Enrollee shall pause for at least 30 seconds
        // before repeating the procedure in step 1 above. If the Enrollee's DPP URI includes a "channel-list" (Section 5.2.1)
        // then the Enrollee should dwell on the channels from that list; otherwise, it should dwell on the preferred Presence
        // Announcement channels as specified in Section 6.2.2. The Enrollee should increase the wait time on channels in
        // the channel list each time the procedure in step 1 is repeated
        attempts++;
        dwell *= 2;
        
        if (!ec_util::interruptible_sleep(std::chrono::seconds(30), [this]() -> bool {
            return m_received_auth_frame.load();
        })) {
            break;
        }
    }

    m_selected_freq = current_freq;

    free(frame);
}

void ec_enrollee_t::send_reconfiguration_announcement_frames()
{
    // 2 seconds
    constexpr uint32_t dwell = 2000;
    uint32_t attempts = 0;
    auto [frame, frame_len] = create_recfg_presence_announcement();

    if (frame == nullptr || frame_len == 0) {
        em_printfout("Failed to create DPP Reconfiguration Announcement frame");
        return;
    }

    uint32_t current_freq = 0;

    while (!m_received_recfg_auth_frame.load()) {

        if (attempts >= 2) {
            // EasyConnect 6.5.2
            // If the Enrollee cycles through the DPP Reconfiguration Announcement procedure two times without receipt of a valid
            // DPP Reconfiguration Authentication Request frame, it shall regenerate the channel list using the steps above and 
            // resume the Reconfiguration Announcement procedure.
            attempts = 0;
            
            // Generate new channel list
            generate_bss_channel_list(true);
        }

        for (const auto& freq : m_recnf_announcement_freqs) {
            // EasyConnect 6.5.2
            // the Enrollee selects a channel from the channel list,
            // sends a DPP Reconfiguration Announcement frame and waits for two seconds for a DPP Reconfiguration Authentication
            // Request frame.

            if (!m_send_action_frame(const_cast<uint8_t*>(BROADCAST_MAC_ADDR), frame, frame_len, freq, dwell)) {
                em_printfout("Failed to send DPP Reconfiguration Announcement frame (broadcast) on freq %d", freq);
            }
            current_freq = freq;
        }
        // EasyConnect 6.5.2
        // If a valid DPP Reconfiguration Authentication Request frame is not received, it repeats this procedure for
        // the next channel in the channel list. When all channels have been exhausted, it pauses for at least 30 seconds before
        // repeating the announcement procedure.

        if (!ec_util::interruptible_sleep(std::chrono::seconds(30), [this]() -> bool {
            return m_received_recfg_auth_frame.load();
        })) {
            break;
        }
    }

    m_selected_freq = current_freq;
    free(frame);
}

bool ec_enrollee_t::handle_recfg_auth_request(ec_frame_t *frame, size_t len, uint8_t src_mac[ETH_ALEN])
{
    if (!frame) {
        em_printfout("Reconfiguration Authentication Request frame is nullptr");
        return false;
    }
    // Cease reconfiguration announcements
    m_received_recfg_auth_frame.store(true);
    if (m_send_recfg_announcement_thread.joinable()) m_send_recfg_announcement_thread.join();
    em_printfout("Received a Reconfiguration Authentication request, stopping Reconfiguration Announcements");

    size_t attrs_len = len - EC_FRAME_BASE_SIZE;

    auto trans_id_attr = ec_util::get_attrib(frame->attributes, attrs_len, ec_attrib_id_trans_id);
    ASSERT_OPT_HAS_VALUE(trans_id_attr, false, "%s:%d: No transaction ID attribute found in Reconfiguration Authentication Request frame\n", __func__, __LINE__);
    // Store the transaction ID issued to us
    m_eph_ctx().transaction_id = static_cast<uint8_t>(trans_id_attr->data[0]);

    auto protocol_version_attr = ec_util::get_attrib(frame->attributes, attrs_len, ec_attrib_id_proto_version);
    ASSERT_OPT_HAS_VALUE(protocol_version_attr, false, "%s:%d: No protocol version attribute found in Reconfiguration Authentication Request frame\n", __func__, __LINE__);

    auto c_connector_attr = ec_util::get_attrib(frame->attributes, attrs_len, ec_attrib_id_dpp_connector);
    ASSERT_OPT_HAS_VALUE(c_connector_attr, false, "%s:%d: No DPP Connector attribute found in Reconfiguration Authentication Request frame\n", __func__, __LINE__);

    auto c_nonce_attr = ec_util::get_attrib(frame->attributes, attrs_len, ec_attrib_id_config_nonce);
    ASSERT_OPT_HAS_VALUE(c_nonce_attr, false, "%s:%d: No configuration nonce attribute found in Reconfiguration Authentication Request frame\n", __func__, __LINE__);

    // EasyConnect 6.5.4:
    // When the Enrollee receives a DPP Reconfiguration Authentication Request frame, it verifies that the protocol version is 2
    // or higher
    uint8_t dpp_version = static_cast<uint8_t>(protocol_version_attr->data[0]);
    if (dpp_version < 2) {
        em_printfout("DPP Version '%d' not supported, must be >= 2", dpp_version);
        return false;
    }

    // Ensure c-connector is valid and parsable
    auto payload = ec_crypto::get_jws_payload(std::string(reinterpret_cast<const char *>(c_connector_attr->data), c_connector_attr->length).c_str());
    ASSERT_OPT_HAS_VALUE(payload, false, "%s:%d: Failed to split and decode c-connector from Reconfiguration Authentication Request frame\n", __func__, __LINE__);

    cJSON *c_connector_version = cJSON_GetObjectItem(payload.value(), "version");
    ASSERT_NOT_NULL(c_connector_version, false, "%s:%d: No version in c-connector from Reconfiguration Authentication Request frame\n", __func__, __LINE__);

    if (c_connector_version->valueint != dpp_version) {
        em_printfout("DPP Version mismatch in c-connector, expected %d, got %d", dpp_version, c_connector_version->valueint);
        return false;
    }

    // Ensure C-Connector is signed with the C-sign-key whose hash was indicated in the Reconfiguration Announcement frame
    auto c_connector_raw_parts = ec_crypto::split_connector(std::string(reinterpret_cast<const char *>(c_connector_attr->data), c_connector_attr->length).c_str());
    ASSERT_OPT_HAS_VALUE(c_connector_raw_parts, false, "%s:%d: Failed to split c-connector raw parts from Reconfiguration Authentication Request frame\n", __func__, __LINE__);

    std::string signed_msg = c_connector_raw_parts.value()[0] + "." + c_connector_raw_parts.value()[1];
    std::vector<uint8_t> signed_bytes(signed_msg.begin(), signed_msg.end());
    std::optional<std::vector<uint8_t>> sig_bytes = em_crypto_t::base64url_decode(c_connector_raw_parts.value()[2]);
    ASSERT_OPT_HAS_VALUE(sig_bytes, false, "%s:%d: Failed to decode signature from c-connector in Reconfiguration Authentication Request frame\n", __func__, __LINE__);

    if (!em_crypto_t::verify_signature(signed_bytes, sig_bytes.value(), m_c_ctx.C_signing_key, EVP_sha256())) {
        em_printfout("Signature verification of c-connector failed");
        return false;
    }

    // Final verification: ensure netRole is "configurator"
    cJSON *net_role = cJSON_GetObjectItem(payload.value(), "netRole");
    ASSERT_NOT_NULL(net_role, false, "%s:%d: No netRole in DPP Connector JSON from Reconfiguration Authentication Request frame\n", __func__, __LINE__);
    if (net_role->type != cJSON_String || strcmp(net_role->valuestring, "configurator") != 0) {
        em_printfout("Invalid netRole in DPP Connector JSON from Reconfiguration Authentication Request frame, expected 'configurator', got '%s'", net_role->valuestring);
        return false;
    }

    // Now response generation work can begin

    // Generate new keypair P_R, p_R
    auto [p_R, P_R] = ec_crypto::generate_proto_keypair(m_c_ctx);
    if (P_R == nullptr || p_R == nullptr) {
        em_printfout("Failed to generate new protocol keypair P_R, p_R");
        return false;
    }

    BN_free(m_eph_ctx().priv_resp_proto_key);
    EC_POINT_free(m_eph_ctx().public_resp_proto_key);
    m_eph_ctx().priv_resp_proto_key = const_cast<BIGNUM *>(p_R);
    m_eph_ctx().public_resp_proto_key = const_cast<EC_POINT*>(P_R);


    // Generate new E-Nonce
    ec_crypto::rand_zero(m_eph_ctx().e_nonce, m_c_ctx.nonce_len);
    if (RAND_bytes(m_eph_ctx().e_nonce, m_c_ctx.nonce_len) != 1) {
        em_printfout("Failed to generate E-Nonce");
        return false;
    }

    em_printfout("E-Nonce:\n");
    util::print_hex_dump(m_c_ctx.nonce_len, m_eph_ctx().e_nonce);

    // Store new C-Nonce
    ec_crypto::rand_zero(m_eph_ctx().c_nonce, m_c_ctx.nonce_len);
    memcpy(m_eph_ctx().c_nonce, c_nonce_attr->data, c_nonce_attr->length);


    // Concatenate C-nonce and E-nonce to be used as salt for HKDF
    std::vector<uint8_t> salt = ec_crypto::concat_nonces({
        std::vector<uint8_t>(m_eph_ctx().c_nonce, m_eph_ctx().c_nonce + m_c_ctx.nonce_len),
        std::vector<uint8_t>(m_eph_ctx().e_nonce, m_eph_ctx().e_nonce + m_c_ctx.nonce_len)
    });

    if (salt.empty()) {
        em_printfout("Failed to concatenate C-Nonce and E-Nonce for HKDF");
        return false;
    }

    // Extract C_I (C-Connector netAccessKey, public)
    cJSON *net_access_key = cJSON_GetObjectItem(payload.value(), "netAccessKey");
    ASSERT_NOT_NULL(net_access_key, false, "%s:%d: No netAccessKey in DPP Connector JSON from Reconfiguration Authentication Request frame\n", __func__, __LINE__);
    EC_POINT *C_I = ec_crypto::decode_ec_point_from_connector_netaccesskey(m_c_ctx, net_access_key);
    ASSERT_NOT_NULL(C_I, false, "%s:%d: Failed to decode C-Connector netAccessKey from Reconfiguration Authentication Request frame\n", __func__, __LINE__);


    // Compute M = (c_R + p_R) * C_I
    BN_free(m_eph_ctx().m);
    BIGNUM *sum = BN_new();
    BIGNUM *c_R = em_crypto_t::get_priv_key_bn(m_c_ctx.net_access_key);
    if (c_R == nullptr) {
        em_printfout("Failed to extract c_R");
        BN_free(sum);
        EC_POINT_free(C_I);
        return false;
    }

    // (c_R + p_R)
    if (!BN_mod_add(sum, c_R, m_eph_ctx().priv_resp_proto_key, m_c_ctx.prime, m_c_ctx.bn_ctx)) {
        em_printfout("Failed to compute c_R + p_R");
        BN_free(sum);
        BN_free(c_R);
        EC_POINT_free(C_I);
        return false;
    }

    // sum * C_I = M.x
    m_eph_ctx().m = ec_crypto::compute_ec_ss_x(m_c_ctx, sum, C_I);
    BN_free(sum);
    BN_free(c_R);
    EC_POINT_free(C_I);
    ASSERT_NOT_NULL(m_eph_ctx().m, false, "%s:%d: Failed to compute M.x from (c_R + p_R) * C_I\n", __func__, __LINE__);

    const BIGNUM * bn_inputs[] = { m_eph_ctx().m };
    // Compute ke = HKDF(C-nonce | E-nonce, "dpp reconfig key", M.x)
    if (ec_crypto::compute_hkdf_key(m_c_ctx, m_eph_ctx().ke, static_cast<size_t>(m_c_ctx.digest_len), "dpp reconfig key", bn_inputs, 1, salt.data(), salt.size()) == 0) {
        em_printfout("Failed to compute ke for Reconfiguration");
        return false;
    }

    // Now with new shared secret M and authentication key ke, we can create the Reconfiguration Response frame

    auto [response_frame, response_frame_len] = create_recfg_auth_response(m_eph_ctx().transaction_id, dpp_version);
    if (response_frame == nullptr || response_frame_len == 0) {
        em_printfout("Failed to create Reconfiguration Authentication Response frame");
        return false;
    }

    // EasyConnect 6.5.4:
    // Upon sending the frame, it shall set a timer for five seconds to wait for a
    // DPP Reconfiguration Authentication Confirm frame (5 second dwell)
    bool sent = m_send_action_frame(src_mac, reinterpret_cast<uint8_t*>(response_frame), response_frame_len, m_selected_freq, 5);
    free(response_frame);
    return sent;
}

bool ec_enrollee_t::handle_recfg_auth_confirm(ec_frame_t *frame, size_t len, uint8_t src_mac[ETH_ALEN])
{
    if (frame == nullptr) {
        em_printfout("Reconfiguration Authentication Confirm frame is nullptr");
        return false;
    }

    size_t attrs_len = len - EC_FRAME_BASE_SIZE;

    auto status_attr = ec_util::get_attrib(frame->attributes, attrs_len, ec_attrib_id_dpp_status);
    ASSERT_OPT_HAS_VALUE(status_attr, false, "%s:%d: No DPP Status attribute found in Reconfiguration Authentication Confirm frame\n", __func__, __LINE__);

    const auto restart_recfg_announcement = [this]() -> void {
        ec_crypto::free_ephemeral_context(&m_c_ctx.eph_ctx, m_c_ctx.nonce_len, m_c_ctx.digest_len);
        m_received_recfg_auth_frame.store(false);
        m_send_recfg_announcement_thread = std::thread(&ec_enrollee_t::send_reconfiguration_announcement_frames, this);
    };

    // EasyConnect 6.5.5:
    // If the received DPP Status field value is any other than STATUS_OK, the Enrollee may revert to transmitting DPP
    // Reconfiguration Announcement frames.
    ec_status_code_t status_code = static_cast<ec_status_code_t>(status_attr->data[0]);
    if (status_code != DPP_STATUS_OK) {
        em_printfout("Reconfiguration Authentication Confirm frame status is %d, reverting to transmitting Reconfiguration Announcement frames", status_code);
        restart_recfg_announcement();
        return true;
    }

    auto wrapped_data_attr = ec_util::get_attrib(frame->attributes, attrs_len, ec_attrib_id_wrapped_data);
    ASSERT_OPT_HAS_VALUE(wrapped_data_attr, false, "%s:%d: No wrapped data attribute found in Reconfiguration Authentication Confirm frame\n", __func__, __LINE__);

    // Upon receipt of the DPP Reconfiguration Authentication Confirm frame, the Enrollee attempts to decrypt the encrypted payload.
    // Note: spec, again, doesn't specify what to do if decryption fails, so we assume it to mean restart Recfg Announcements
    auto [unwrapped_data, unwrapped_len] = ec_util::unwrap_wrapped_attrib(*wrapped_data_attr, frame, true, m_eph_ctx().ke);
    if (unwrapped_data == nullptr || unwrapped_len == 0) {
        em_printfout("Failed to unwrap wrapped data attribute in Reconfiguration Authentication Confirm frame with ke, restarting Reconfiguration Announcement frames");
        restart_recfg_announcement();
        return false;
    }

    // Verify transaction ID matches
    auto trans_id_attr = ec_util::get_attrib(unwrapped_data, unwrapped_len, ec_attrib_id_trans_id);
    ASSERT_OPT_HAS_VALUE_FREE(trans_id_attr, false, unwrapped_data, "%s:%d: No transaction ID found in unwrapped data of Reconfiguration Authentication Confirm frame\n", __func__, __LINE__);
    if (static_cast<uint8_t>(trans_id_attr->data[0]) != m_eph_ctx().transaction_id) {
        em_printfout("Mis-matched transaction ID in Reconfiguration Authentication Confirm frame, expected %d, got %d", m_eph_ctx().transaction_id, static_cast<uint8_t>(trans_id_attr->data[0]));
        free(unwrapped_data);
        restart_recfg_announcement();
        return false;
    }

    // Verify nonces
    auto c_nonce_attr = ec_util::get_attrib(unwrapped_data, unwrapped_len, ec_attrib_id_config_nonce);
    ASSERT_OPT_HAS_VALUE_FREE(c_nonce_attr, false, unwrapped_data, "%s:%d: No C-Nonce attribute found in unwrapped data of Reconfiguration Authentication Confirm frame\n", __func__, __LINE__);

    auto e_nonce_attr = ec_util::get_attrib(unwrapped_data, unwrapped_len, ec_attrib_id_enrollee_nonce);
    ASSERT_OPT_HAS_VALUE_FREE(e_nonce_attr, false, unwrapped_data, "%s:%d: No E-Nonce attribute found in unwrapped data of Reconfiguration Authentication Confirm frame\n", __func__, __LINE__);

    if ((memcmp(c_nonce_attr->data, m_eph_ctx().c_nonce, m_c_ctx.nonce_len) != 0) || (memcmp(e_nonce_attr->data, m_eph_ctx().e_nonce, m_c_ctx.nonce_len) != 0)) {
        em_printfout("Mismatched nonce(s) found in Reconfiguration Authentication Confirm frame, restarting Reconfiguration Announcement frames");
        free(unwrapped_data);
        restart_recfg_announcement();
        return false;
    }

    auto version_attr = ec_util::get_attrib(unwrapped_data, unwrapped_len, ec_attrib_id_proto_version);
    ASSERT_OPT_HAS_VALUE_FREE(version_attr, false, unwrapped_data, "%s:%d: No protocol version attribute found in unwrapped data of Reconfiguration Authentication Confirm frame\n", __func__, __LINE__);

    if (static_cast<uint8_t>(version_attr->data[0]) < 2) {
        em_printfout("DPP Version '%d' not supported for Reconfiguration", static_cast<uint8_t>(version_attr->data[0]));
        free(unwrapped_data);
        restart_recfg_announcement();
        return false;
    }

    auto recfg_flags_attr = ec_util::get_attrib(unwrapped_data, unwrapped_len, ec_attrib_id_reconfig_flags);
    ASSERT_OPT_HAS_VALUE_FREE(recfg_flags_attr, false, unwrapped_data, "%s:%d: No Reconfig-Flags attribute found in unwrapped data of Reconfiguration Authentication Confirm frame\n", __func__, __LINE__);

    // If all's well, we can create and send a Configuration request
    auto [config_request_frame, config_request_frame_len] = create_config_request(*reinterpret_cast<ec_dpp_reconfig_flags_t*>(recfg_flags_attr->data[0]));
    if (config_request_frame == nullptr || config_request_frame_len == 0) {
        em_printfout("Failed to create Configuration Request frame for Reconfiguration");
        free(unwrapped_data);
        restart_recfg_announcement();
        return false;
    }

    bool sent = m_send_action_frame(src_mac, reinterpret_cast<uint8_t*>(config_request_frame), config_request_frame_len, m_selected_freq, 0);
    free(config_request_frame);
    free(unwrapped_data);
    return sent;
}

bool ec_enrollee_t::handle_auth_request(ec_frame_t *frame, size_t len, uint8_t src_mac[ETHER_ADDR_LEN])
{
    em_printfout("Recieved a DPP Authentication Request from '" MACSTRFMT "', stopping Presence Announcement\n", MAC2STR(src_mac));
    // Halt presence announcement once DPP Authentication frame is received.
    m_received_auth_frame.store(true);
    if (m_send_pres_announcement_thread.joinable()) m_send_pres_announcement_thread.join();
    size_t attrs_len = len - EC_FRAME_BASE_SIZE;

    auto B_r_hash_attr = ec_util::get_attrib(frame->attributes, static_cast<uint16_t> (attrs_len), ec_attrib_id_resp_bootstrap_key_hash);
    ASSERT_OPT_HAS_VALUE(B_r_hash_attr, false, "%s:%d No responder bootstrapping key hash attribute found\n", __func__, __LINE__);

    uint8_t* responder_keyhash = ec_crypto::compute_key_hash(m_boot_data().responder_boot_key);
    ASSERT_NOT_NULL(responder_keyhash, false, "%s:%d failed to compute responder bootstrapping key hash\n", __func__, __LINE__);

    if (memcmp(B_r_hash_attr->data, responder_keyhash, B_r_hash_attr->length) != 0) {
        em_printfout("Responder key hash mismatch");
        free(responder_keyhash);
        return false;
    }
    free(responder_keyhash);
    
    if (m_boot_data().initiator_boot_key != NULL){
        // Initiator bootstrapping key is present on enrollee, mutual authentication is possible
        auto B_i_hash_attr = ec_util::get_attrib(frame->attributes, static_cast<uint16_t> (attrs_len), ec_attrib_id_init_bootstrap_key_hash);
        ASSERT_OPT_HAS_VALUE(B_i_hash_attr, false, "%s:%d No initiator bootstrapping key hash attribute found\n", __func__, __LINE__);
        uint8_t* initiator_keyhash = ec_crypto::compute_key_hash(m_boot_data().initiator_boot_key);
        if (initiator_keyhash != NULL) {
            if (memcmp(B_i_hash_attr->data, initiator_keyhash, B_i_hash_attr->length) == 0) {
                em_printfout("Initiator key hash matched, mutual authentication can now occur");
                // Hashes match, mutual authentication can occur
                m_eph_ctx().is_mutual_auth = true;
                /*
                Specifically, the Responder shall request mutual authentication when the hash of the Responder
            bootstrapping key in the authentication request indexes an entry in the bootstrapping table corresponding to a
            bidirectional bootstrapping method, for example, PKEX or BTLE.
                */
            }
            free(initiator_keyhash);
        }     
    }

   auto channel_attr = ec_util::get_attrib(frame->attributes, static_cast<uint16_t> (attrs_len), ec_attrib_id_channel);
    if (channel_attr && channel_attr->length == sizeof(uint16_t)) {
        /*
        the Responder determines whether it can use the requested channel for the
following exchanges. If so, it sends the DPP Authentication Response frame on that channel. If not, it discards the DPP
Authentication Request frame without replying to it.
        */
        uint16_t op_chan = *reinterpret_cast<uint16_t*>(channel_attr->data);
        em_printfout("Channel attribute: %d", op_chan);

        uint8_t op_class = static_cast<uint8_t>(op_chan >> 8);
        uint8_t channel = static_cast<uint8_t>(op_chan & 0x00ff);
        em_printfout("op_class: %d channel %d", op_class, channel);
        //TODO: Check One-Wifi for channel selection if possible
        // Maybe just attempt to send it on the channel
    }

    auto pub_init_proto_key_attr = ec_util::get_attrib(frame->attributes, static_cast<uint16_t> (attrs_len), ec_attrib_id_init_proto_key);

    ASSERT_OPT_HAS_VALUE(pub_init_proto_key_attr, false, "%s:%d No public initiator protocol key attribute found\n", __func__, __LINE__);
    ASSERT_EQUALS(pub_init_proto_key_attr->length, BN_num_bytes(m_c_ctx.prime) * 2, false, "%s:%d Invalid public initiator protocol key length\n", __func__, __LINE__);

    if (m_eph_ctx().public_init_proto_key) {
        EC_POINT_free(m_eph_ctx().public_init_proto_key);
    }

    m_eph_ctx().public_init_proto_key = ec_crypto::decode_ec_point(m_c_ctx, pub_init_proto_key_attr->data);
    ASSERT_NOT_NULL(m_eph_ctx().public_init_proto_key, false, "%s:%d failed to decode public initiator protocol key\n", __func__, __LINE__);

    // START Crypto in EasyConnect 6.3.3
    // Compute the M.x
    ASSERT_NOT_NULL(m_boot_data().resp_priv_boot_key, false, "%s:%d failed to get responder bootstrapping private key\n", __func__, __LINE__);

    m_eph_ctx().m = ec_crypto::compute_ec_ss_x(m_c_ctx, m_boot_data().resp_priv_boot_key, m_eph_ctx().public_init_proto_key);
    const BIGNUM *bn_inputs[1] = { m_eph_ctx().m };
    // Compute the "first intermediate key" (k1)
    m_eph_ctx().k1 = static_cast<uint8_t *>(calloc(m_c_ctx.digest_len, 1));
    if (ec_crypto::compute_hkdf_key(m_c_ctx, m_eph_ctx().k1, m_c_ctx.digest_len, "first intermediate key", bn_inputs, 1, NULL, 0) == 0) {
        em_printfout("Failed to compute k1"); 
        return false;
    }

    printf("Key K_1:\n");
    util::print_hex_dump(static_cast<unsigned int> (m_c_ctx.digest_len), m_eph_ctx().k1);

    auto wrapped_data_attr = ec_util::get_attrib(frame->attributes, static_cast<uint16_t> (attrs_len), ec_attrib_id_wrapped_data);
    ASSERT_OPT_HAS_VALUE(wrapped_data_attr, false, "%s:%d No wrapped data attribute found\n", __func__, __LINE__);

    // Attempt to unwrap the wrapped data with generated k1 (from sent keys)
    auto [wrapped_data, wrapped_len] = ec_util::unwrap_wrapped_attrib(*wrapped_data_attr, frame, true, m_eph_ctx().k1); 
    if (wrapped_data == NULL || wrapped_len == 0) {
        em_printfout("failed to unwrap wrapped data");
        // "Abondon the exchange"
        return false;
    }

    auto init_caps_attr = ec_util::get_attrib(wrapped_data, static_cast<uint16_t> (wrapped_len), ec_attrib_id_init_caps);
    ASSERT_OPT_HAS_VALUE_FREE(init_caps_attr, false, wrapped_data, "%s:%d No initiator capabilities attribute found\n", __func__, __LINE__);

    const ec_dpp_capabilities_t init_caps = {
        .byte = init_caps_attr->data[0]
    };

    auto i_nonce_attr = ec_util::get_attrib(wrapped_data, static_cast<uint16_t>(wrapped_len), ec_attrib_id_init_nonce);
    ASSERT_OPT_HAS_VALUE_FREE(init_caps_attr, false, wrapped_data, "%s:%d: No initiator nonce attribute found\n", __func__, __LINE__);
    memcpy(m_eph_ctx().i_nonce, i_nonce_attr->data, i_nonce_attr->length);
    em_printfout("i-nonce (Configurator is initiator)");
    util::print_hex_dump(i_nonce_attr->length, m_eph_ctx().i_nonce);

    // Fetched all of the wrapped data attributes (init caps), free the wrapped data
    free(wrapped_data);

    uint8_t init_proto_version = 0; // Undefined
    auto proto_version_attr = ec_util::get_attrib(frame->attributes, attrs_len, ec_attrib_id_proto_version);
    if (proto_version_attr && proto_version_attr->length == 1) {
        init_proto_version = proto_version_attr->data[0];
    }

    if (!ec_util::check_caps_compatible(init_caps, m_dpp_caps)) {
        em_printfout("Initiator capabilities not supported");

        /*
        STATUS_NOT_COMPATIBLE:
        Responder → Initiator: DPP Status, SHA-256(BR), [ SHA-256(BI),][ Protocol Version ], { I-nonce, R-capabilities}k1
        */
        auto [resp_frame, resp_len] = create_auth_response(DPP_STATUS_NOT_COMPATIBLE, init_proto_version);
        if (resp_frame == NULL || resp_len == 0) {
            em_printfout("failed to create response frame");
            return false;
        }
        if (m_send_action_frame(src_mac, resp_frame, resp_len, m_selected_freq, 0)){
            em_printfout("Successfully sent DPP Status Not Compatible response frame to '" MACSTRFMT "'", MAC2STR(src_mac));
        } else {
            em_printfout("Failed to send DPP Status Not Compatible response frame to " MACSTRFMT "'", MAC2STR(src_mac));
        }
        return false;
    }

    // TODO/NOTE: Unknown: If need more time to process, respond `STATUS_RESPONSE_PENDING` (EasyConnect 6.3.3)
    // If the Responder needs more time to respond, e.g., to complete bootstrapping of the Initiator’s bootstrapping key
    if (false) {
        /*
        STATUS_RESPONSE_PENDING:
        Responder → Initiator: DPP Status, SHA-256(BR), [ SHA-256(BI),][ Protocol Version ], { I-nonce, R-capabilities}k1
        */
        auto [resp_frame, resp_len] = create_auth_response(DPP_STATUS_RESPONSE_PENDING, init_proto_version);
        if (resp_frame == NULL || resp_len == 0) {
            em_printfout("failed to create response frame");
            return false;
        }
        if (m_send_action_frame(src_mac, resp_frame, resp_len, m_selected_freq, 0)){
            em_printfout("Successfully sent DPP Status Response Pending response frame to '" MACSTRFMT "'", MAC2STR(src_mac));
        } else {
            em_printfout("Failed to send DPP Status Response Pending response frame to '" MACSTRFMT "'", MAC2STR(src_mac));
        }
        return true;
    }

    /*
    STATUS_OK:
    Responder → Initiator: DPP Status, SHA-256(BR), [ SHA-256(BI), ] PR, [Protocol Version], { R-nonce, I-nonce, R-capabilities, { R-auth }ke }k2
    */
    auto [resp_frame, resp_len] = create_auth_response(DPP_STATUS_OK, init_proto_version);
    if (resp_frame == NULL || resp_len == 0) {
        em_printfout("failed to create response frame");
        return false;
    }
    bool did_succeed = m_send_action_frame(src_mac, resp_frame, resp_len, m_selected_freq, 0);
    if (did_succeed){
        em_printfout("Successfully sent DPP Status OK response frame to '" MACSTRFMT "'", MAC2STR(src_mac));
    } else {
        em_printfout("Failed to send DPP Status OK response frame to '" MACSTRFMT "'", MAC2STR(src_mac));
    }

    return did_succeed;
}

bool ec_enrollee_t::handle_auth_confirm(ec_frame_t *frame, size_t len, uint8_t src_mac[ETHER_ADDR_LEN])
{
    size_t attrs_len = len - EC_FRAME_BASE_SIZE;

    auto status_attrib = ec_util::get_attrib(frame->attributes, attrs_len, ec_attrib_id_dpp_status);
    ASSERT_OPT_HAS_VALUE(status_attrib, false, "%s:%d: No DPP status attribute found\n", __func__, __LINE__);

    ec_status_code_t dpp_status = static_cast<ec_status_code_t>(status_attrib->data[0]);

    if (dpp_status != DPP_STATUS_OK && dpp_status != DPP_STATUS_AUTH_FAILURE && dpp_status != DPP_STATUS_NOT_COMPATIBLE) {
        em_printfout("Recieved Improper DPP Status: \"%s\"", ec_util::status_code_to_string(dpp_status).c_str());
        return false;
    }

    auto wrapped_attr = ec_util::get_attrib(frame->attributes, attrs_len, ec_attrib_id_wrapped_data);
    ASSERT_OPT_HAS_VALUE(wrapped_attr, false, "%s:%d: No wrapped data attribute found\n", __func__, __LINE__);

    uint8_t* key = (dpp_status == DPP_STATUS_OK) ? m_eph_ctx().ke : m_eph_ctx().k2;
    ASSERT_NOT_NULL(key, false, "%s:%d: k_e or k_2 is NULL!\n", __func__, __LINE__);

    // If DPP Status is OK, wrap the I-auth with the KE key, otherwise wrap the Responder Nonce with the K2 key
    auto [unwrapped_data, unwrapped_data_len] = ec_util::unwrap_wrapped_attrib(*wrapped_attr, frame, true, key);
    if (unwrapped_data == NULL || unwrapped_data_len == 0) {
        em_printfout("Failed to unwrap wrapped data, aborting exchange");
        // Aborts exchange
        return false;
    }
    if (dpp_status != DPP_STATUS_OK) {
        // Unwrapping successfully occured but there is an error, "generate an alert"
        free(unwrapped_data);
        std::string status_str = ec_util::status_code_to_string(dpp_status);
        em_printfout("Authentication Failed with DPP Status: %s", status_str.c_str());
        return false;
    }

    auto i_auth_tag_attr = ec_util::get_attrib(unwrapped_data, unwrapped_data_len, ec_attrib_id_init_auth_tag);
    ASSERT_OPT_HAS_VALUE_FREE(i_auth_tag_attr, false, unwrapped_data, "%s:%d: No initiator authentication tag attribute found\n", __func__, __LINE__);
    
    uint8_t i_auth_tag[i_auth_tag_attr->length] = {0};
    memcpy(i_auth_tag, i_auth_tag_attr->data, i_auth_tag_attr->length);

    free(unwrapped_data);

    if (m_eph_ctx().public_init_proto_key == nullptr) {
        em_printfout("eph ctx public init proto key null");
        return false;
    }

    if (m_eph_ctx().public_resp_proto_key == nullptr) {
        em_printfout("eph ctx resp proto key nullptr");
        return false;
    }

    if (m_boot_data().resp_pub_boot_key == nullptr) {
        em_printfout("Boot data resp pub boot key is nullptr!");
        return false;
    }

    // Generate I-auth’ = H(R-nonce | I-nonce | PR.x | PI.x | BR.x | [ BI.x | ] 1)
    // Get P_I.x, P_R.x, B_I.x, and B_R.x
    BIGNUM* P_I_x = ec_crypto::get_ec_x(m_c_ctx, m_eph_ctx().public_init_proto_key);
    BIGNUM* P_R_x = ec_crypto::get_ec_x(m_c_ctx, m_eph_ctx().public_resp_proto_key);
    BIGNUM* B_I_x = ec_crypto::get_ec_x(m_c_ctx, m_boot_data().init_pub_boot_key);
    BIGNUM* B_R_x = ec_crypto::get_ec_x(m_c_ctx, m_boot_data().resp_pub_boot_key);

    if (P_I_x == NULL || P_R_x == NULL || B_R_x == NULL) {
        em_printfout("Failed to get x-coordinates of P_I, P_R, and B_R");
        if (P_I_x) BN_free(P_I_x);
        if (P_R_x) BN_free(P_R_x);
        if (B_R_x) BN_free(B_R_x);
        if (B_I_x) BN_free(B_I_x);
        return false;
    }

    // B_I.x is not needed (can be null) if mutual authentication is not supported
    if (m_eph_ctx().is_mutual_auth && B_I_x == NULL) {
        em_printfout("Failed to get x-coordinate of B_I");
        BN_free(P_I_x);
        BN_free(P_R_x);
        BN_free(B_R_x);
        return false;
    }

    easyconnect::hash_buffer_t i_auth_hb;
    ec_crypto::add_to_hash(i_auth_hb, m_eph_ctx().r_nonce, m_c_ctx.nonce_len);
    ec_crypto::add_to_hash(i_auth_hb, m_eph_ctx().i_nonce, m_c_ctx.nonce_len);
    ec_crypto::add_to_hash(i_auth_hb, P_R_x); //P_R
    ec_crypto::add_to_hash(i_auth_hb, P_I_x); //P_I
    ec_crypto::add_to_hash(i_auth_hb, B_R_x); //B_R
    if (m_eph_ctx().is_mutual_auth) ec_crypto::add_to_hash(i_auth_hb, B_I_x); //B_I
    ec_crypto::add_to_hash(i_auth_hb, static_cast<uint8_t>(1)); // 1 octet

    uint8_t* i_auth_prime = ec_crypto::compute_hash(m_c_ctx, i_auth_hb);

    BN_free(P_I_x);
    BN_free(P_R_x);
    BN_free(B_R_x);
    if (B_I_x) BN_free(B_I_x);

    if (i_auth_prime == NULL) {
        em_printfout("Failed to compute I-auth'");
        return false;
    }

    if (memcmp(i_auth_prime, i_auth_tag, sizeof(i_auth_tag)) != 0) {
        em_printfout("I-auth' does not match Initiator Auth Tag, authentication failed!");
        // TODO: "ALERT" The user that authentication failed
        free(i_auth_prime);
        return false;
    }

    const auto [config_req, config_req_len] = create_config_request();
    if (config_req == nullptr || config_req_len == 0) {
        em_printfout("Could not create DPP Configuration Request!");
        return false;
    }

    // EasyMesh R6 5.3.1:
    // The DPP onboarding process begins when the Multi-AP Controller receives the bootstrapping information of the Enrollee
    // Multi-AP Agent in the form of a DPP URI. Upon receipt of the DPP URI, the Multi-AP Controller instructs one or more
    // existing Multi-AP Agents to advertise the CCE IE in their Beacon and Probe Response frames, if they are not doing so
    // already, and listen to the Enrollee's DPP Presence Announcement frame. Once the Multi-AP Controller receives a DPP
    // Presence Announcement frame from an Enrollee Multi-AP Agent, it initiates the DPP Authentication procedure by
    // generating a DPP Authentication Request frame. A Multi-AP Agent, acting as a proxy, relays the DPP Authentication
    // messages received from the Multi-AP Controller to the Enrollee when the DPP Presence Announcement frame with the
    // correct hash is received from the Enrollee. The proxy performs a bi-directional conversation between a DPP frame carried
    // in an 802.11 frame to a DPP frame encapsulated in a Multi-AP CMDU message. **Upon successful authentication**, the
    // Enrollee Multi-AP Agent requests configuration by exchanging DPP Configuration Protocol messages (see 6.6 of [18])
    // with the Multi-AP Controller.
    bool sent_dpp_config_gas_frame = m_send_action_frame(src_mac, config_req, config_req_len, m_selected_freq, 0);
    if (sent_dpp_config_gas_frame) {
        em_printfout("Sent DPP Configuration Request 802.11 frame to Proxy Agent!");
    } else {
        em_printfout("Failed to send DPP Configuration Request GAS frame");
    }
    free(config_req);

    return sent_dpp_config_gas_frame;
}

bool ec_enrollee_t::handle_config_response(uint8_t *buff, size_t len, uint8_t sa[ETH_ALEN])
{
    // EasyMesh 5.4.3
    // If an Enrollee Multi-AP Agent receives a DPP Configuration Response frame, it shall send a DPP Configuration Result
    // frame as per [18], configure its 1905 and backhaul STA interfaces with the parameters received in the DPP Configuration
    // Object and:
    //  If the AKM for the backhaul STA in the DPP Configuration Object includes dpp and the backhaul BSS is configured to
    // support the DPP AKM, then the Enrollee Multi-AP Agent shall initiate the DPP Network Introduction protocol in Public
    // Action frames as per [18] to associate to the backhaul BSS
    //  If the AKM for the backhaul STA in the DPP Configuration Object includes PSK or SAE password, then the Enrollee
    // Multi-AP Agent shall scan for and associate with a backhaul BSS with the SSID indicated in DPP Configuration Object
    // as per [18].

    // EasyConnect 6.4.3.2 Enrollee Handling
    em_printfout("Got a DPP Configuration Response from " MACSTRFMT "", MAC2STR(sa));
    ec_gas_initial_response_frame_t *config_response_frame = reinterpret_cast<ec_gas_initial_response_frame_t*>(buff);


    auto status_attrib = ec_util::get_attrib(reinterpret_cast<uint8_t*>(config_response_frame->resp), static_cast<size_t>(config_response_frame->resp_len), ec_attrib_id_dpp_status);
    ASSERT_OPT_HAS_VALUE(status_attrib, false, "%s:%d: No DPP status attribute found\n", __func__, __LINE__);

    ec_status_code_t config_response_status_code = static_cast<ec_status_code_t>(status_attrib->data[0]);

    em_printfout("Configuration response status=%d (%s)", static_cast<int>(config_response_status_code), ec_util::status_code_to_string(config_response_status_code).c_str());

    ec_status_code_t valid_status_codes[4] = {DPP_STATUS_OK, DPP_STATUS_CONFIGURE_PENDING, DPP_STATUS_NEW_KEY_NEEDED, DPP_STATUS_CSR_BAD};
    bool config_response_status_code_valid = false;
    for (int i = 0; i < static_cast<int>(std::size(valid_status_codes)); i++) {
        if (config_response_status_code == valid_status_codes[i]) config_response_status_code_valid = true;
    }

    if (!config_response_status_code_valid) {
        // If invalid status code, may either re-send Configuration Request, or abort.
        em_printfout("Invalid DPP Status code %d (%s) for Configuration response, aborting configuration", static_cast<int>(config_response_status_code), ec_util::status_code_to_string(config_response_status_code).c_str());
        return false;
    }

    // Currently un-handled status codes. 
    if (config_response_status_code == DPP_STATUS_CONFIGURE_PENDING || config_response_status_code == DPP_STATUS_NEW_KEY_NEEDED || config_response_status_code == DPP_STATUS_CSR_BAD) {
        // TODO: EasyConnect 6.4.3.2
        em_printfout("DPP status is %d (%s), not handled!", config_response_status_code, ec_util::status_code_to_string(config_response_status_code).c_str());
        return false;
    }

    auto wrapped_attrs = ec_util::get_attrib(config_response_frame->resp, static_cast<size_t>(config_response_frame->resp_len), ec_attrib_id_wrapped_data);
    ASSERT_OPT_HAS_VALUE(wrapped_attrs, false, "%s:%d: Failed to get wrapped data attribute!\n", __func__, __LINE__);

    auto [unwrapped_attrs, unwrapped_attrs_len] = ec_util::unwrap_wrapped_attrib(*wrapped_attrs, config_response_frame->resp, true, m_eph_ctx().ke);
    if (unwrapped_attrs == nullptr || unwrapped_attrs_len == 0) {
        em_printfout("Failed to unwrap wrapped attributes.");
        return false;
    }
    auto e_nonce_attr = ec_util::get_attrib(unwrapped_attrs, unwrapped_attrs_len, ec_attrib_id_enrollee_nonce);
    ASSERT_OPT_HAS_VALUE_FREE(e_nonce_attr, false, unwrapped_attrs, "%s:%d: No e-nonce in attributes!\n", __func__, __LINE__);

    auto dpp_config_obj_1905 = ec_util::get_attrib(unwrapped_attrs, unwrapped_attrs_len, ec_attrib_id_dpp_config_obj);
    ASSERT_OPT_HAS_VALUE_FREE(dpp_config_obj_1905, false, unwrapped_attrs, "%s:%d: No IEEE1905 Configuration object attribute found\n", __func__, __LINE__);

    auto dpp_config_obj_bsta = ec_util::get_attrib(reinterpret_cast<uint8_t*>(dpp_config_obj_1905->original) + ec_util::get_ec_attr_size(dpp_config_obj_1905->length), unwrapped_attrs_len, ec_attrib_id_dpp_config_obj);
    ASSERT_OPT_HAS_VALUE_FREE(dpp_config_obj_bsta, false, unwrapped_attrs, "%s:%d: No bSTA Configuration object attribute found\n", __func__, __LINE__);

    // This is optional, so can be nullptr.
    auto send_connection_status_attr = ec_util::get_attrib(unwrapped_attrs, unwrapped_attrs_len, ec_attrib_id_send_conn_status);

    // Parse JSON objects
    cJSON *ieee1905_configuration_object = cJSON_ParseWithLength(reinterpret_cast<const char *>(dpp_config_obj_1905->data), static_cast<size_t>(dpp_config_obj_1905->length));
    ASSERT_NOT_NULL(ieee1905_configuration_object, false, "%s:%d: Could not parse IEEE1905 Configuration object, invalid JSON?\n", __func__, __LINE__);

    cJSON *bsta_configuration_object = cJSON_ParseWithLength(reinterpret_cast<const char *>(dpp_config_obj_bsta->data), static_cast<size_t>(dpp_config_obj_bsta->length));
    ASSERT_NOT_NULL(bsta_configuration_object, false, "%s:%d: Could not parse bSTA Configuration object, invalid JSON?\n", __func__, __LINE__);

    // For debugging.
    em_printfout("Enrollee de-serialized 1905 Congiruration Object:\n%s", cjson_utils::stringify(ieee1905_configuration_object).c_str());
    em_printfout("Enrollee de-serialized bSTA Configuration Object:\n%s", cjson_utils::stringify(bsta_configuration_object).c_str());

    cJSON *bsta_cred_obj = cJSON_GetObjectItem(bsta_configuration_object, "cred");
    cJSON *signed_connector = cJSON_GetObjectItem(bsta_cred_obj, "signedConnector");
    if (signed_connector) {
        auto conn_str = cjson_utils::stringify(signed_connector);
        m_eph_ctx().connector = strdup(conn_str.c_str());
    }
    cJSON *bsta_discovery_obj = cJSON_GetObjectItem(bsta_configuration_object, "discovery");
    if (bsta_cred_obj == nullptr || bsta_discovery_obj == nullptr) {
        em_printfout("Incomplete bSTA Configuration object received");
        free(unwrapped_attrs);
        cJSON_Delete(bsta_configuration_object);
        cJSON_Delete(ieee1905_configuration_object);
        return false;
    }

    cJSON *bsta_ssid = cJSON_GetObjectItem(bsta_discovery_obj, "SSID");
    if (bsta_ssid == nullptr) {
        em_printfout("Could not get \"SSID\" from bSTA Configuration object.");
        free(unwrapped_attrs);
        cJSON_Delete(bsta_configuration_object);
        cJSON_Delete(ieee1905_configuration_object);
        return false;
    }

    m_configured_ssid = std::string(bsta_ssid->valuestring);

    cJSON *bsta_bssid = cJSON_GetObjectItem(bsta_discovery_obj, "BSSID");
    bssid_t bssid = {0};
    if (bsta_bssid != nullptr && cJSON_IsString(bsta_bssid)) {
        std::string bssid_str(bsta_bssid->valuestring);
        if (bssid_str.length() != (ETH_ALEN*2)) {
            em_printfout("Invalid BSSID length");
            free(unwrapped_attrs);
            cJSON_Delete(bsta_configuration_object);
            cJSON_Delete(ieee1905_configuration_object);
            return false;
        }
        // Convert hex (non-delimited) string to byte array
        for (size_t i = 0; i < ETH_ALEN; i++) {
            std::string byte_str = bssid_str.substr(i*2, 2);
            bssid[i] = static_cast<uint8_t>(strtol(byte_str.c_str(), nullptr, 16));
        }
    }
    
    if (memcmp(bssid, ZERO_MAC_ADDR, ETH_ALEN) == 0) {
        em_printfout("No BSSID provided in bSTA Configuration object, generating random to still trigger connection");
        // Generate random BSSID
        RAND_bytes(bssid, ETH_ALEN);
        em_printfout("Generated random BSSID: " MACSTRFMT "", MAC2STR(bssid));
    }

    cJSON *bsta_pass = cJSON_GetObjectItem(bsta_cred_obj, "pass");
    if (bsta_pass == nullptr) {
        em_printfout("Could not get \"pass\" from bSTA Configuration object.");
        free(unwrapped_attrs);
        cJSON_Delete(bsta_configuration_object);
        cJSON_Delete(ieee1905_configuration_object);
        return false;
    }

    // First, we immediately send a Connection Status Result frame to Configurator per
    // EasyConnect 6.4.4 after parsing/ensuring the Configuration Response is valid

    // Mandatory Configuration Result frame indicating configuration status.
    // The spec is a bit goofy here and says that DPP Status should indicate
    // the success or failure of _applying the configuration_
    // It does not mention that this status indicates real association success/failure
    // So, just send DPP_STATUS_OK as there's no configuration application mechanism here
    ec_status_code_t connection_status = DPP_STATUS_OK;
    auto [config_result_frame, config_result_frame_len] = create_config_result(connection_status);
    if (config_result_frame == nullptr || config_result_frame_len == 0) {
        em_printfout("Failed to create DPP Configuration Result frame");
        free(unwrapped_attrs);
        cJSON_Delete(ieee1905_configuration_object);
        cJSON_Delete(bsta_configuration_object);
        return false;
    }

    bool ok = m_send_action_frame(sa, config_result_frame, config_result_frame_len, m_selected_freq, 0);
    if (!ok) {
        em_printfout("Failed to send DPP Configuration Result frame");
    } else {
        em_printfout("Sent Configuration Result frame to '" MACSTRFMT "'", MAC2STR(sa));
    }

    // Then, we need to scan and ensure that the Configurator's requested BSS is
    // within range for us / exists.

    // Send connection request to OneWifi to connect to the BSS
    // OneWifi will scan "auto-magically" for us before attempting to connect

    if (!m_bsta_connect_fn(bsta_ssid->valuestring, bsta_pass->valuestring, bssid)){
        em_printfout("Failed to attempt a connection to BSS");
        ok = false;
    } else {
        em_printfout("Attempted to connect to BSS");
    }


    // Only necessary if Configurator includes "sendConnStatus" in Configuration response.
    bool needs_connection_status = (send_connection_status_attr.has_value());

    if (needs_connection_status) {
        // TODO: add BSSID we're attemping to associate to to m_awaiting_assoc_status map!
        std::string bssid_str = util::mac_to_string(bssid);
        std::vector<uint8_t> sender_mac(sa, sa + ETH_ALEN);
        m_awaiting_assoc_status[bssid_str] = sender_mac;
        em_printfout("Added BSSID to awaiting association status map: %s", bssid_str.c_str());
    } 

    free(config_result_frame);
    free(unwrapped_attrs);
    cJSON_Delete(bsta_configuration_object);
    cJSON_Delete(ieee1905_configuration_object);
    return ok;    
}

std::pair<uint8_t *, size_t> ec_enrollee_t::create_presence_announcement()
{
    em_printfout("Enter");

    ec_frame_t *frame =  ec_util::alloc_frame(ec_frame_type_presence_announcement);
    ASSERT_NOT_NULL(frame, {}, "%s:%d failed to allocate memory for frame\n", __func__, __LINE__);

    // Compute the hash of the responder boot key 
    uint8_t *resp_boot_key_chirp_hash = ec_crypto::compute_key_hash(m_boot_data().responder_boot_key, "chirp");
    ASSERT_NOT_NULL_FREE(resp_boot_key_chirp_hash, {}, frame, "%s:%d unable to compute \"chirp\" responder bootstrapping key hash\n", __func__, __LINE__);

    uint8_t* attribs = NULL;
    size_t attribs_len = 0;

    attribs = ec_util::add_attrib(attribs, &attribs_len, ec_attrib_id_resp_bootstrap_key_hash, SHA256_DIGEST_LENGTH, resp_boot_key_chirp_hash);
    free(resp_boot_key_chirp_hash);

    if (!(frame = ec_util::copy_attrs_to_frame(frame, attribs, attribs_len))) {
        em_printfout("unable to copy attributes to frame");
        free(attribs);
        free(frame);
        return {};
    }
    free(attribs);

    return std::make_pair(reinterpret_cast<uint8_t*>(frame), EC_FRAME_BASE_SIZE + attribs_len);
}


std::pair<uint8_t *, size_t> ec_enrollee_t::create_auth_response(ec_status_code_t dpp_status, uint8_t init_proto_version)
{

    /*
    STATUS_NOT_COMPATIBLE:
        Responder → Initiator: DPP Status, SHA-256(BR), [ SHA-256(BI),][ Protocol Version ], { I-nonce, R-capabilities}k1
    STATUS_RESPONSE_PENDING:
        Responder → Initiator: DPP Status, SHA-256(BR), [ SHA-256(BI),][ Protocol Version ], { I-nonce, R-capabilities}k1
    STATUS_OK:
        Responder → Initiator: DPP Status, SHA-256(BR), [ SHA-256(BI), ] PR, [Protocol Version], { R-nonce, I-nonce, R-capabilities, { R-auth }ke }k2
    */

    ec_frame_t *frame =  ec_util::alloc_frame(ec_frame_type_auth_rsp);
    ASSERT_NOT_NULL(frame, {}, "%s:%d failed to allocate memory for frame\n", __func__, __LINE__);

    uint8_t* attribs = NULL;
    size_t attribs_len = 0;

    attribs = ec_util::add_attrib(attribs, &attribs_len, ec_attrib_id_dpp_status, static_cast<uint8_t>(dpp_status));

    // Add Responder Bootstrapping Key Hash (SHA-256(B_R))
    uint8_t* responder_keyhash = ec_crypto::compute_key_hash(m_boot_data().responder_boot_key);
    ASSERT_NOT_NULL_FREE2(responder_keyhash, {}, frame, attribs, "%s:%d failed to compute responder bootstrapping key hash\n", __func__, __LINE__);

    attribs = ec_util::add_attrib(attribs, &attribs_len, ec_attrib_id_resp_bootstrap_key_hash, SHA256_DIGEST_LENGTH, responder_keyhash);
    free(responder_keyhash);
    // Conditional (Only included for mutual authentication) (SHA-256(B_I))
    if (m_eph_ctx().is_mutual_auth) {
        uint8_t* initiator_keyhash = ec_crypto::compute_key_hash(m_boot_data().initiator_boot_key);
        if (initiator_keyhash != NULL) {
            attribs = ec_util::add_attrib(attribs, &attribs_len, ec_attrib_id_init_bootstrap_key_hash, SHA256_DIGEST_LENGTH, initiator_keyhash);
            free(initiator_keyhash);
        }

    }


    // Add remaining NON-OK attributes and return due to complexity with OK attributes
    if (dpp_status != DPP_STATUS_OK) {
        if (init_proto_version >= 2) {
            // Add Protocol Version (TOOD: Add variable for responder protocol version)
            attribs = ec_util::add_attrib(attribs, &attribs_len, ec_attrib_id_proto_version, static_cast<uint8_t>(1));
        }
        attribs = ec_util::add_wrapped_data_attr(frame, attribs, &attribs_len, true, m_eph_ctx().k1, [&](){
            size_t wrapped_len = 0;
            uint8_t* wrap_attribs = ec_util::add_attrib(NULL, &wrapped_len, ec_attrib_id_init_nonce, m_c_ctx.nonce_len, m_eph_ctx().i_nonce);
            wrap_attribs = ec_util::add_attrib(wrap_attribs, &wrapped_len, ec_attrib_id_resp_caps, m_dpp_caps.byte);
            return std::make_pair(wrap_attribs, wrapped_len);
        });
        
        if (!(frame = ec_util::copy_attrs_to_frame(frame, attribs, attribs_len))) {
            em_printfout("unable to copy attributes to frame");
            free(frame);
            free(attribs);
            return {};
        }
        free(attribs);
        return std::make_pair(reinterpret_cast<uint8_t*>(frame), EC_FRAME_BASE_SIZE + attribs_len);
    }
    
    // STATUS_OK

    // Generate R-nonce
    if (!RAND_bytes(m_eph_ctx().r_nonce, m_c_ctx.nonce_len)) {
        em_printfout("failed to generate R-nonce");
        free(attribs);
        free(frame);
        return {};
    }

    // Generate initiator protocol key pair (p_i/P_I)
    auto [priv_resp_proto_key, pub_resp_proto_key] = ec_crypto::generate_proto_keypair(m_c_ctx);
    if (priv_resp_proto_key == NULL || pub_resp_proto_key == NULL) {
        em_printfout("failed to generate responder protocol keypair");
        free(attribs);
        free(frame);
        return {};
    }
    
    // Use const_cast instead of old-style cast
    m_eph_ctx().public_resp_proto_key = const_cast<EC_POINT*>(pub_resp_proto_key);
    m_eph_ctx().priv_resp_proto_key = const_cast<BIGNUM*>(priv_resp_proto_key);

    ASSERT_NOT_NULL_FREE2(m_eph_ctx().public_init_proto_key, {}, frame, attribs, "%s:%d initiator protocol keypair was never generated!\n", __func__, __LINE__);
    m_eph_ctx().n = ec_crypto::compute_ec_ss_x(m_c_ctx, m_eph_ctx().priv_resp_proto_key, m_eph_ctx().public_init_proto_key);
    const BIGNUM *bn_inputs[1] = { m_eph_ctx().n };
    // Compute the "second intermediate key" (k2)
    m_eph_ctx().k2 = static_cast<uint8_t *>(calloc(m_c_ctx.digest_len, 1));
    if (ec_crypto::compute_hkdf_key(m_c_ctx, m_eph_ctx().k2, m_c_ctx.digest_len, "second intermediate key", bn_inputs, 1, NULL, 0) == 0) {
        em_printfout("Failed to compute k2"); 
        free(attribs);
        free(frame);
        return {};
    }

    printf("Key K_2:\n");
    util::print_hex_dump(m_c_ctx.digest_len, m_eph_ctx().k2);

    ASSERT_NOT_NULL_FREE2(m_boot_data().resp_priv_boot_key, {}, frame, attribs, "%s:%d failed to get responder bootstrapping private key\n", __func__, __LINE__);

    // Compute L.x
    if (m_eph_ctx().is_mutual_auth){
        if (m_boot_data().init_pub_boot_key != NULL){
            m_eph_ctx().l = ec_crypto::calculate_Lx(m_c_ctx, m_boot_data().resp_priv_boot_key, m_eph_ctx().priv_resp_proto_key, m_boot_data().init_pub_boot_key);
        }
    }

    if (m_eph_ctx().is_mutual_auth && m_eph_ctx().l == NULL) {
        em_printfout("failed to compute L.x");
        free(attribs);
        free(frame);
        return {};
    }
    

    // Compute k_e
    m_eph_ctx().ke = static_cast<uint8_t *>(calloc(m_c_ctx.digest_len, 1));
    if (ec_crypto::compute_ke(m_c_ctx, &m_eph_ctx(), m_eph_ctx().ke) == 0){
        em_printfout("Failed to compute ke");
        free(attribs);
        free(frame);
        return {};
    }

    // Compute R-auth = H(I-nonce | R-nonce | PI.x | PR.x | [ BI.x | ] BR.x | 0)
    BIGNUM* P_I_x = ec_crypto::get_ec_x(m_c_ctx, m_eph_ctx().public_init_proto_key);
    BIGNUM* P_R_x = ec_crypto::get_ec_x(m_c_ctx, m_eph_ctx().public_resp_proto_key);
    BIGNUM* B_I_x = ec_crypto::get_ec_x(m_c_ctx, m_boot_data().init_pub_boot_key);
    BIGNUM* B_R_x = ec_crypto::get_ec_x(m_c_ctx, m_boot_data().resp_pub_boot_key);

    if (P_I_x == NULL || P_R_x == NULL || B_R_x == NULL) {
        em_printfout("Failed to get x-coordinates of P_I, P_R, and B_R");
        if (P_I_x) BN_free(P_I_x);
        if (P_R_x) BN_free(P_R_x);
        if (B_R_x) BN_free(B_R_x);
        if (B_I_x) BN_free(B_I_x);
        return {};
    }

    // B_I.x is not needed (can be null) if mutual authentication is not supported
    if (m_eph_ctx().is_mutual_auth && B_I_x == NULL) {
        em_printfout("Failed to get x-coordinate of B_I when mutal authentication is occuring");
        BN_free(P_I_x);
        BN_free(P_R_x);
        BN_free(B_R_x);
        return {};
    }

    easyconnect::hash_buffer_t r_auth_hb;
    ec_crypto::add_to_hash(r_auth_hb, m_eph_ctx().i_nonce, m_c_ctx.nonce_len);
    ec_crypto::add_to_hash(r_auth_hb, m_eph_ctx().r_nonce, m_c_ctx.nonce_len);
    ec_crypto::add_to_hash(r_auth_hb, P_I_x); //P_I
    ec_crypto::add_to_hash(r_auth_hb, P_R_x); //P_R
    if (m_eph_ctx().is_mutual_auth) ec_crypto::add_to_hash(r_auth_hb, B_I_x); //B_I
    ec_crypto::add_to_hash(r_auth_hb, B_R_x); //B_R
    ec_crypto::add_to_hash(r_auth_hb, static_cast<uint8_t>(0)); // 1 octet

    uint8_t* r_auth = ec_crypto::compute_hash(m_c_ctx, r_auth_hb);
    if (P_I_x) BN_free(P_I_x);
    if (P_R_x) BN_free(P_R_x);
    if (B_R_x) BN_free(B_R_x);
    if (B_I_x) BN_free(B_I_x);
    ASSERT_NOT_NULL_FREE2(r_auth, {}, frame, attribs, "%s:%d: Failed to compute R-auth\n", __func__, __LINE__);

    // Add P_R
    auto encoded_P_R = ec_crypto::encode_ec_point(m_c_ctx, m_eph_ctx().public_resp_proto_key);
    ASSERT_NOT_NULL_FREE2(encoded_P_R, {}, frame, attribs, "%s:%d failed to encode responder protocol key\n", __func__, __LINE__);

    attribs = ec_util::add_attrib(attribs, &attribs_len, ec_attrib_id_resp_proto_key, static_cast<uint16_t>(BN_num_bytes(m_c_ctx.prime) * 2), encoded_P_R);

    // Add Protocol Version
    if (init_proto_version >= 2) {
        // Add Protocol Version (TOOD: Add variable for responder protocol version)
        attribs = ec_util::add_attrib(attribs, &attribs_len, ec_attrib_id_proto_version, static_cast<uint8_t>(1));
    }

    // Add `{ R-nonce, I-nonce, R-capabilities, { R-auth }k_e }k_2`
    attribs = ec_util::add_wrapped_data_attr(frame, attribs, &attribs_len, true, m_eph_ctx().k2, [&](){
        size_t wrapped_len = 0;
        uint8_t* wrap_attribs = ec_util::add_attrib(NULL, &wrapped_len, ec_attrib_id_resp_nonce, m_c_ctx.nonce_len, m_eph_ctx().r_nonce);
        wrap_attribs = ec_util::add_attrib(wrap_attribs, &wrapped_len, ec_attrib_id_init_nonce, m_c_ctx.nonce_len, m_eph_ctx().i_nonce);
        wrap_attribs = ec_util::add_attrib(wrap_attribs, &wrapped_len, ec_attrib_id_resp_caps, m_dpp_caps.byte);

        // R-auth is wrapped in an additional wrapped data attribute (k_e) inside the main wrapped data attribute (k_2)
        wrap_attribs = ec_util::add_wrapped_data_attr(frame, wrap_attribs, &wrapped_len, false, m_eph_ctx().ke, [&](){
            size_t int_wrapped_len = 0;
            uint8_t* int_wrapped_attrs = ec_util::add_attrib(NULL, &int_wrapped_len, ec_attrib_id_resp_auth_tag, m_c_ctx.digest_len, r_auth);
            return std::make_pair(int_wrapped_attrs, int_wrapped_len);
        });
        return std::make_pair(wrap_attribs, wrapped_len);
    });

    free(r_auth);

    if (!(frame = ec_util::copy_attrs_to_frame(frame, attribs, attribs_len))) {
        em_printfout("unable to copy attributes to frame");
        free(frame);
        free(attribs);
        return {};
    }
    free(attribs);

    return std::make_pair(reinterpret_cast<uint8_t*>(frame), EC_FRAME_BASE_SIZE + attribs_len);

}

std::pair<uint8_t *, size_t> ec_enrollee_t::create_recfg_presence_announcement()
{
    /*
    EasyConnect 6.5.2
    Before every transmission of a DPP Reconfiguration Announcement frame, 
    the Enrollee generates a random nonce a-nonce, with 0 ≤ a-nonce < q, 
    where q is the order of the elliptic curve group of the Configurator signing key, 
    and the corresponding ECC point A-NONCE
        A-NONCE = a-nonce * G
    where G is the generator of the elliptic curve group of the Configurator signing key.
    */

    if (m_c_ctx.group == NULL || m_c_ctx.order == NULL || m_c_ctx.bn_ctx == NULL) {
        em_printfout("Pre-initialized EC parameters not initialized!");
        return {};
    }

    uint8_t a_nonce_buf[m_c_ctx.nonce_len];
    if (!RAND_bytes(a_nonce_buf, m_c_ctx.nonce_len)) {
        em_printfout("Failed to generate A-nonce");
        return {};
    }

    scoped_bn a_nonce(BN_new());
    scoped_ec_point A_NONCE(EC_POINT_new(m_c_ctx.group));
    // a-nonce * Ppk
    scoped_ec_point a_nonce_ppk(EC_POINT_new(m_c_ctx.group));
    scoped_ec_point E_prime_Id(EC_POINT_new(m_c_ctx.group));

    if (a_nonce == NULL || A_NONCE == NULL || a_nonce_ppk == NULL || E_prime_Id == NULL) {
        printf("%s:%d: Failed to allocate memory for a-nonce, A-NONCE, a-nonce * Ppk temp, and "
               "E'-id\n",
               __func__, __LINE__);
        return {};
    }

    // Convert the random bytes to a BIGNUM
    if (!BN_bin2bn(a_nonce_buf, m_c_ctx.nonce_len, a_nonce.get())) {
        em_printfout("Failed to convert a-nonce to BIGNUM");
        return {};
    }

    // modulo to ensure the value is less than the order
    if (!BN_mod(a_nonce.get(), a_nonce.get(), m_c_ctx.order, m_c_ctx.bn_ctx)) {
        em_printfout("Failed to modulo a-nonce");
        return {};
    }

    // Compute A-NONCE = a-nonce * G
    if (!EC_POINT_mul(m_c_ctx.group, A_NONCE.get(), a_nonce.get(), NULL, NULL, m_c_ctx.bn_ctx)) {
        em_printfout("Failed to compute A-NONCE");
        return {};
    }

    // Calculate a-nonce * Ppk
    if (!EC_POINT_mul(m_c_ctx.group, a_nonce_ppk.get(), NULL, m_c_ctx.ppk, a_nonce.get(),
                      m_c_ctx.bn_ctx)) {
        em_printfout("Failed to compute a-nonce * Ppk");
        return {};
    }

    // Calculate E'-id = E-id + (a-nonce * Ppk)
    if (!EC_POINT_add(m_c_ctx.group, E_prime_Id.get(), m_eph_ctx().E_Id, a_nonce_ppk.get(),
                      m_c_ctx.bn_ctx)) {
        em_printfout("Failed to compute E'-id");
        return {};
    }

    /**
     * Reconfiguration Announcement frame (EasyConnect 8.2.15)
     * -------------------------------------------------------
     *   The Reconfiguration Announcement frame uses the DPP Action frame format and is transmitted 
     *   by a DPP Enrollee to signal the DPP Configurator that it wishes to perform a reconfiguration 
     *   exchange with the Configurator.
     * 
     * Frame Attributes:
     *   - Configurator C-sign-key Hash (Required)
     *      - SHA-256 hash of the uncompressed form of the Configurator's public C-sign-key
     *      - This is the base64url decoded value of the "kid" from the JWS Protected Header 
     *        of the Enrollee's Connector
     * 
     *   - Finite Cyclic Group (Required)
     *      - The group from which the Enrollee NAK is drawn
     * 
     *   - A-NONCE (Required)
     *      - The ECC point representing the a-nonce
     * 
     *   - E'-id (Required)
     *      - The ECC point representing the randomly encrypted E-id
     */

    // Create the DPP Reconfiguration Presence Announcement frame
    ec_frame_t *frame = ec_util::alloc_frame(ec_frame_type_recfg_announcement);
    ASSERT_NOT_NULL(frame, {}, "%s:%d failed to allocate memory for frame\n", __func__, __LINE__);

    size_t attribs_len = 0;

    // C-sign-key hash attribute
    // Might need to replace with "kid"
    uint8_t *c_sign_hash = ec_crypto::compute_key_hash(m_c_ctx.C_signing_key);
    uint8_t *attribs = ec_util::add_attrib(NULL, &attribs_len, ec_attrib_id_C_sign_key_hash,
                                           SHA256_DIGEST_LENGTH, c_sign_hash);
    free(c_sign_hash);
    ASSERT_NOT_NULL_FREE2(attribs, {}, frame, attribs,
                          "%s:%d: Failed to add C-signing key hash attribute\n", __func__,
                          __LINE__);

    // Finite Cyclic Group attribute
    // Must be little endian according to EC 8.1.1.12
    scoped_ec_group group(em_crypto_t::get_key_group(m_c_ctx.net_access_key));
    ASSERT_NOT_NULL_FREE2(group.get(), {}, frame, attribs,
                          "%s:%d: Failed to get elliptic curve group from network access key\n",
                          __func__, __LINE__);
    attribs = ec_util::add_attrib(attribs, &attribs_len, ec_attrib_id_finite_cyclic_group,
                                  SWAP_LITTLE_ENDIAN(ec_crypto::get_tls_group_id_from_ec_group(group.get())));
    ASSERT_NOT_NULL_FREE2(attribs, {}, frame, attribs,
                          "%s:%d: Failed to add finite cyclic group attribute\n", __func__,
                          __LINE__);

    uint16_t encoded_len = static_cast<uint16_t>(BN_num_bytes(m_c_ctx.prime) * 2);
    // A-NONCE attribute
    auto encoded_A_NONCE = ec_crypto::encode_ec_point(m_c_ctx, A_NONCE.get());
    ASSERT_NOT_NULL_FREE2(encoded_A_NONCE, {}, frame, attribs, "%s:%d: Failed to encode A-NONCE\n",
                          __func__, __LINE__);
    attribs = ec_util::add_attrib(attribs, &attribs_len, ec_attrib_id_a_nonce, encoded_len,
                                  encoded_A_NONCE);
    ASSERT_NOT_NULL_FREE2(attribs, {}, frame, attribs, "%s:%d: Failed to add A-NONCE attribute\n",
                          __func__, __LINE__);

    // E'-id attribute
    auto encoded_E_prime_Id = ec_crypto::encode_ec_point(m_c_ctx, E_prime_Id.get());
    ASSERT_NOT_NULL_FREE2(encoded_E_prime_Id, {}, frame, attribs, "%s:%d: Failed to encode E'-id\n",
                          __func__, __LINE__);
    attribs = ec_util::add_attrib(attribs, &attribs_len, ec_attrib_id_e_prime_id, encoded_len,
                                  encoded_E_prime_Id);
    ASSERT_NOT_NULL_FREE2(attribs, {}, frame, attribs, "%s:%d: Failed to add E'-id attribute\n",
                          __func__, __LINE__);

    if (!(frame = ec_util::copy_attrs_to_frame(frame, attribs, attribs_len))) {
        em_printfout("unable to copy attributes to frame");
        free(frame);
        free(attribs);
        return {};
    }
    free(attribs);

    return std::make_pair(reinterpret_cast<uint8_t *>(frame), EC_FRAME_BASE_SIZE + attribs_len);
}

std::pair<uint8_t *, size_t> ec_enrollee_t::create_recfg_auth_response(uint8_t trans_id, uint8_t dpp_version)
{
    ec_frame_t *frame = ec_util::alloc_frame(ec_frame_type_recfg_auth_rsp);
    ASSERT_NOT_NULL(frame, {}, "%s:%d: Failed to allocate memory for frame\n", __func__, __LINE__);

    // Encode P_R
    auto encoded_P_R = ec_crypto::encode_ec_point(m_c_ctx, m_eph_ctx().public_resp_proto_key);
    ASSERT_NOT_NULL_FREE(encoded_P_R, {}, frame, "%s:%d failed to encode responder protocol key\n", __func__, __LINE__);

    // Create Conn Status obj
    // Note: spec claims this must be a member of this frame, but doesn't indicate what DPP Status ought to be used
    cJSON *conn_status_obj = create_dpp_connection_status_obj(DPP_STATUS_AUTH_FAILURE, m_configured_ssid);
    ASSERT_NOT_NULL_FREE(conn_status_obj, {}, frame, "%s:%d: Failed to create connection status object\n", __func__, __LINE__);

    size_t attribs_len = 0UL;
    uint8_t *attribs = nullptr;

    attribs = ec_util::add_attrib(attribs, &attribs_len, ec_attrib_id_trans_id, trans_id);
    attribs = ec_util::add_attrib(attribs, &attribs_len, ec_attrib_id_proto_version, dpp_version);
    attribs = ec_util::add_attrib(attribs, &attribs_len, ec_attrib_id_dpp_connector, std::string(m_eph_ctx().connector));
    attribs = ec_util::add_attrib(attribs, &attribs_len, ec_attrib_id_enrollee_nonce, static_cast<uint16_t>(m_c_ctx.nonce_len), m_eph_ctx().e_nonce);
    attribs = ec_util::add_attrib(attribs, &attribs_len, ec_attrib_id_resp_proto_key, static_cast<uint16_t>(BN_num_bytes(m_c_ctx.prime) * 2), encoded_P_R);

    // Wrapped data (k_e)
    attribs = ec_util::add_wrapped_data_attr(frame, attribs, &attribs_len, true, m_eph_ctx().ke, [&]() {
        uint8_t *wrap_attribs = nullptr;
        size_t wrapped_len = 0UL;
        wrap_attribs = ec_util::add_attrib(wrap_attribs, &wrapped_len, ec_attrib_id_config_nonce, static_cast<uint16_t>(m_c_ctx.nonce_len), m_eph_ctx().c_nonce);
        wrap_attribs = ec_util::add_attrib(wrap_attribs, &wrapped_len, ec_attrib_id_conn_status, cjson_utils::stringify(conn_status_obj));
        return std::make_pair(wrap_attribs, wrapped_len);
    });

    cJSON_Delete(conn_status_obj);

    return std::make_pair(reinterpret_cast<uint8_t *>(frame), EC_FRAME_BASE_SIZE + attribs_len);
}

std::pair<uint8_t *, size_t> ec_enrollee_t::create_config_request(std::optional<ec_dpp_reconfig_flags_t> recfg_flags)
{
    // EasyConnect 6.4.2 DPP Configuration Request
    // Regardless of whether the Initiator or Responder took the role of Configurator, the DPP Configuration protocol is always
    // initiated by the Enrollee. To start, the Enrollee generates one or more DPP Configuration Request objects (see section
    // 4.4) and generates a new nonce, E-nonce, whose length is determined according to Table 4. When the Configurator has
    // not indicated support for protocol version number 2 or higher, no more than one DPP Configuration Request object shall
    // be included. The E-nonce attribute and the DPP Configuration Request object attribute(s) are wrapped with ke. The
    // wrapped attributes are then placed in a DPP Configuration Request frame, and sent to the Configurator.
    // Enrollee → Configurator: { E-nonce, configRequest }ke

    if (RAND_bytes(m_eph_ctx().e_nonce, m_c_ctx.nonce_len) != 1) {
        em_printfout("Could not generate E-nonce!");
        return {};
    }

    em_printfout("E-nonce:");
    util::print_hex_dump(m_c_ctx.nonce_len, m_eph_ctx().e_nonce);

    if (m_boot_data().version <= 1) {
        em_printfout("EasyMesh R >= 5 mandates DPP version >= 2, current version is %d, bailing.", m_boot_data().version);
        return {};
    }

    bool replace_key = false;
    if (recfg_flags.has_value()) {
        replace_key = (recfg_flags->connector_key == DPP_CONFIG_REPLACEKEY);
    }

    if (replace_key) {
        em_printfout("Reconfiguration Flags CONFIG_REPLACEKEY set, generating new protocol keypair");
        auto [p_R, P_R] = ec_crypto::generate_proto_keypair(m_c_ctx);
        if (p_R == nullptr || P_R == nullptr) {
            em_printfout("Failed to generate new proto keypair");
            return {};
        }
        BN_free(m_eph_ctx().priv_resp_proto_key);
        EC_POINT_free(m_eph_ctx().public_resp_proto_key);
        m_eph_ctx().priv_resp_proto_key = const_cast<BIGNUM *>(p_R);
        m_eph_ctx().public_resp_proto_key = const_cast<EC_POINT*>(P_R);
        // Also set netAccessKey
        auto [x, y] = ec_crypto::get_ec_x_y(m_c_ctx, m_eph_ctx().public_resp_proto_key);
        m_c_ctx.net_access_key = em_crypto_t::create_ec_key_from_coordinates(ec_crypto::BN_to_vec(x), ec_crypto::BN_to_vec(y), ec_crypto::BN_to_vec(m_eph_ctx().priv_init_proto_key));
        ASSERT_NOT_NULL(m_c_ctx.net_access_key, {}, "%s:%d: Failed to create netAccessKey from Respondor proto keypair\n", __func__, __LINE__);
    }

    // EasyMesh R6 5.3.3
    // If an Enrollee Multi-AP Agent sends a DPP Configuration Request frame (see section 6.4.2 of [18] and Table 5), it shall:
    // - Include one DPP Configuration Request Object (see Table 5)
    // - set the netRole to "mapAgent"
    // - set wi-fi_tech to "map"
    // - include the akm parameter, and
    // - set the akm parameter value to the supported akm of its backhaul STA.
    cJSON *dpp_config_request_obj = cJSON_CreateObject();
    cJSON *netRole = cJSON_CreateString("mapAgent");
    cJSON *wifi_tech = cJSON_CreateString("map");
    char hostname[256] = {0};
    if (gethostname(hostname, sizeof(hostname)) != 0) {
        em_printfout("`gethostname` failed, defaulting DPP Configuration Request object key \"name\" to \"Enrollee\"");
        static const char *default_name = "Enrollee";
        strncpy(hostname, default_name, sizeof(hostname));
    }
    cJSON *name = cJSON_CreateString(hostname);
    if (!dpp_config_request_obj || !netRole || !wifi_tech) {
        em_printfout("Failed to create DPP Configuration Request Object!");
        return {};
    }
    cJSON_AddItemToObject(dpp_config_request_obj, "netRole", netRole);
    cJSON_AddItemToObject(dpp_config_request_obj, "wi-fi_tech", wifi_tech);
    cJSON_AddItemToObject(dpp_config_request_obj, "name", name);
    if (m_get_bsta_info == nullptr) {
        em_printfout("Get bSTA info callback is nullptr! Cannot create DPP Configuration Request Object, bailing.");
        return {};
    }
    cJSON *bsta_info = m_get_bsta_info(nullptr);
    ASSERT_NOT_NULL_FREE(bsta_info, {}, m_eph_ctx().e_nonce, "%s:%d: bSTA info is nullptr!\n", __func__, __LINE__);
    cJSON_AddItemToObject(dpp_config_request_obj, "bSTAList", bsta_info);

    // For debugging
    em_printfout("Enrollee bSTA Configuration Request object:\n%s", cjson_utils::stringify(dpp_config_request_obj).c_str());

    // XXX: Dialog token can be thought of as a session key between Enrollee and Configurator regarding configuration
    // From specs (EasyMesh, EasyConnect, 802.11), it seems this is just arbitrarily chosen (1 byte), but
    // must be unique per GAS frame "session" exchange.
    // See: 802.11-2020 9.4.1.12 Dialog Token field
    unsigned char dialog_token = 1;
    auto [frame, frame_len] = ec_util::alloc_gas_frame(dpp_gas_initial_req, dialog_token);
    if (frame == nullptr || frame_len == 0) {
        em_printfout("Could not create DPP Configuration Request GAS frame!");
        return {};
    }

    ec_gas_initial_request_frame_t *initial_req_frame = static_cast<ec_gas_initial_request_frame_t *> (frame);
    uint8_t *attribs = nullptr;
    size_t attribs_len = 0;
    // Wrap e-nonce, config req obj(s), and (optionally) new pub key with k_e
    attribs = ec_util::add_cfg_wrapped_data_attr(attribs, &attribs_len, false, m_eph_ctx().ke, [&](){
        size_t wrapped_len = 0;
        uint8_t* wrapped_attribs = ec_util::add_attrib(nullptr, &wrapped_len, ec_attrib_id_enrollee_nonce, m_c_ctx.nonce_len, m_eph_ctx().e_nonce);
        if (replace_key) {
            wrapped_attribs = ec_util::add_attrib(wrapped_attribs, &wrapped_len, ec_attrib_id_init_proto_key, static_cast<uint16_t>(BN_num_bytes(m_c_ctx.prime) * 2), ec_crypto::encode_ec_point(m_c_ctx, m_eph_ctx().public_resp_proto_key));
        }
        wrapped_attribs = ec_util::add_attrib(wrapped_attribs, &wrapped_len, ec_attrib_id_dpp_config_req_obj, cjson_utils::stringify(dpp_config_request_obj));
        return std::make_pair(wrapped_attribs, wrapped_len);
    });

    cJSON_Delete(dpp_config_request_obj);

    if ((initial_req_frame = ec_util::copy_attrs_to_frame(initial_req_frame, attribs, attribs_len)) == nullptr) {
        em_printfout("unable to copy attribs to GAS frame");
        free(attribs);
        free(frame);
        return {};
    }
    initial_req_frame->query_len = static_cast<uint16_t>(attribs_len);
    
    return std::make_pair(reinterpret_cast<uint8_t*>(initial_req_frame), sizeof(ec_gas_initial_request_frame_t) + attribs_len);
}

std::pair<uint8_t *, size_t> ec_enrollee_t::create_config_result(ec_status_code_t dpp_status)
{
    // EasyConnect 6.4.4 DPP Configuration Result
    // When both the Enrollee and the Configurator indicate their protocol version numbers to be 2 or higher, the Enrollee
    // reports the result of configuration processing to the Configurator to allow clear indication of the results on the
    // Configurator's user interface. The result is indicated in the DPP Configuration Result frame sent on the same channel
    // immediately after the final DPP Configuration Response frame. The DPP Status field value indicates the result of the
    // configuration: STATUS_OK indicates success and STATUS_CONFIG_REJECTED indicates failure.
    // Enrollee → Configurator: { DPP Status, E-nonce }ke

    ec_frame_t *frame = ec_util::alloc_frame(ec_frame_type_cfg_result);
    ASSERT_NOT_NULL(frame, {}, "%s:%d: Failed to allocate DPP Configuration Result frame\n", __func__, __LINE__);

    uint8_t *attribs = nullptr;
    size_t attribs_len = 0;

    attribs = ec_util::add_wrapped_data_attr(frame, attribs, &attribs_len, false, m_eph_ctx().ke, [&]() {
        size_t wrapped_len = 0;
        uint8_t *wrapped_attrs = ec_util::add_attrib(nullptr, &wrapped_len, ec_attrib_id_dpp_status, static_cast<uint8_t>(dpp_status));
        wrapped_attrs = ec_util::add_attrib(wrapped_attrs, &wrapped_len, ec_attrib_id_enrollee_nonce, m_c_ctx.nonce_len, m_eph_ctx().e_nonce);
        return std::make_pair(wrapped_attrs, wrapped_len);
    });

    if (!(frame = ec_util::copy_attrs_to_frame(frame, attribs, attribs_len))) {
        em_printfout("Failed to copy attributes to DPP Configuration Result frame");
        free(attribs);
        free(frame);
        return {};
    }
    return std::make_pair(reinterpret_cast<uint8_t*>(frame), EC_FRAME_BASE_SIZE + attribs_len);
}

std::pair<uint8_t *, size_t> ec_enrollee_t::create_connection_status_result(ec_status_code_t dpp_status, const std::string &ssid)
{
    ec_frame_t *frame = ec_util::alloc_frame(ec_frame_type_conn_status_result);
    ASSERT_NOT_NULL(frame, {}, "%s:%d: Failed to allocate DPP Connection Status Result frame\n", __func__, __LINE__);

    cJSON *connection_status_object = create_dpp_connection_status_obj(dpp_status, ssid);
    ASSERT_NOT_NULL_FREE(connection_status_object, {}, frame, "%s:%d: Failed to create DPP Connection Status object!\n", __func__, __LINE__);

    uint8_t *attribs   = nullptr;
    size_t attribs_len = 0;

    attribs = ec_util::add_wrapped_data_attr(frame, attribs, &attribs_len, false, m_eph_ctx().ke, [&]() {
        size_t wrapped_len = 0;
        uint8_t *wrapped_attrs = ec_util::add_attrib(nullptr, &wrapped_len, ec_attrib_id_enrollee_nonce, m_c_ctx.nonce_len, m_eph_ctx().e_nonce);
        wrapped_attrs = ec_util::add_attrib(wrapped_attrs, &wrapped_len, ec_attrib_id_conn_status, cjson_utils::stringify(connection_status_object));
        return std::make_pair(wrapped_attrs, wrapped_len);
    });

    cJSON_Delete(connection_status_object);

    frame = ec_util::copy_attrs_to_frame(frame, attribs, attribs_len);
    ASSERT_NOT_NULL_FREE2(frame, {}, attribs, frame, "%s:%d: Failed to copy attributes to DPP Connection Status Result frame\n", __func__, __LINE__);

    free(attribs);
    return std::make_pair(reinterpret_cast<uint8_t *>(frame), EC_FRAME_BASE_SIZE + attribs_len);
}

cJSON *ec_enrollee_t::create_dpp_connection_status_obj(ec_status_code_t dpp_status, const std::string &ssid)
{
    cJSON *connStatusObj = cJSON_CreateObject();
    if (connStatusObj == nullptr)
        return nullptr;

    cJSON_AddNumberToObject(connStatusObj, "result", static_cast<uint8_t>(dpp_status));
    cJSON_AddStringToObject(connStatusObj, "ssid64", em_crypto_t::base64url_encode(ssid).c_str());

    if (dpp_status == DPP_STATUS_NO_AP_DISCOVERED) {
        // channelList is conditionally included if DPP Status == NO_AP
        // We include the list of channels (grouped by opclass) that we scanned on
        // when searching for the BSS to connect to, according to bSTA Configuration Response object.
        cJSON_AddStringToObject(connStatusObj, "channelList", ec_util::generate_channel_list(ssid, m_scanned_channels_map).c_str());
    }
    return connStatusObj;
}

bool ec_enrollee_t::handle_gas_comeback_response(ec_gas_comeback_response_frame_t *frame, size_t len, uint8_t src_mac[ETH_ALEN])
{
    if (frame == nullptr) {
        em_printfout("NULL GAS comeback response frame");
        return false;
    }
    const std::string source_mac_key = util::mac_to_string(src_mac) + "_" + std::to_string(static_cast<int>(frame->base.dialog_token));
    if (frame->fragment_id != m_gas_fragments[source_mac_key].expected_fragment_id) {
        em_printfout("Fragment ID mismatch for dialog=%d from %s", frame->base.dialog_token, source_mac_key.c_str());
        return false;
    }

    bool more_frags_coming = (frame->more_fragments > 0);

    m_gas_fragments[source_mac_key].reassembled_payload.insert(
        m_gas_fragments[source_mac_key].reassembled_payload.end(),
        frame->comeback_resp,
        frame->comeback_resp + frame->comeback_resp_len
    );

    m_gas_fragments[source_mac_key].expected_fragment_id++;
    m_gas_fragments[source_mac_key].last_seen = std::chrono::steady_clock::now();

    if (!more_frags_coming) {
        // No more data coming, we've got a complete frame
        em_printfout("Full fragmented frame reassembled:\n");
        util::print_hex_dump(m_gas_fragments[source_mac_key].reassembled_payload);
        bool did_succeed = handle_config_response(
            m_gas_fragments[source_mac_key].reassembled_payload.data(),
            m_gas_fragments[source_mac_key].reassembled_payload.size(),
            src_mac
        );
        if (!did_succeed) {
            em_printfout("Failed to handle Configuration Response");
            return false;
        }
        m_gas_fragments.erase(source_mac_key);
    }

    if (more_frags_coming) {
        // If there's more frags coming, send a Comeback Request to enable sending of next Comeback Response
        ec_gas_comeback_request_frame_t *cb_frame = create_comeback_request(frame->base.dialog_token);
        ASSERT_NOT_NULL(cb_frame, false, "%s:%d: Failed to allocate a GAS Comeback Request frame\n", __func__, __LINE__);
        bool sent = m_send_action_frame(src_mac, reinterpret_cast<uint8_t*>(cb_frame), sizeof(ec_gas_comeback_request_frame_t), m_selected_freq, 0);
        if (!sent) {
            em_printfout("Failed to send GAS Comeback Request to '" MACSTRFMT "', we made it to frag #%d", MAC2STR(src_mac), frame->fragment_id);
        }
        free(cb_frame);
        return sent;
    }

    // Regardless of if we're still awaiting fragments or if we marshalled a full frame, we've succeeded.
    return true;
}

bool ec_enrollee_t::handle_gas_initial_response(ec_gas_initial_response_frame_t *resp_frame, size_t len, uint8_t src_mac[ETH_ALEN])
{
    if (resp_frame == nullptr) {
        em_printfout("Invalid GAS initial response frame");
        return false;
    }
    bool is_fragmentation_signal_frame = (resp_frame->gas_comeback_delay > 0 || resp_frame->resp_len == 0);

    if (is_fragmentation_signal_frame) {
        em_printfout("Received a fragmentation preperation GAS Initial Response frame from '" MACSTRFMT "'", MAC2STR(src_mac));

        ec_gas_comeback_request_frame_t *cb_frame = create_comeback_request(resp_frame->base.dialog_token);
        ASSERT_NOT_NULL(cb_frame, false, "%s:%d: Failed to allocate GAS Initial Request frame\n", __func__, __LINE__);
        bool sent = m_send_action_frame(src_mac, reinterpret_cast<uint8_t*>(cb_frame), sizeof(ec_gas_comeback_request_frame_t), m_selected_freq, 0);
        free(cb_frame);
        if (!sent) {
            em_printfout("Failed to send GAS Comeback Request to '" MACSTRFMT "'", MAC2STR(src_mac));
            return false;
        }

        em_printfout("Sent GAS Comeback Request for dialog_token=%u to '" MACSTRFMT "'",
                     resp_frame->base.dialog_token, MAC2STR(src_mac));
        return sent;
    }

    // Not a fragmentation prep signal, just a complete response frame.
    return handle_config_response(reinterpret_cast<uint8_t*>(resp_frame), len, src_mac);
}

ec_gas_comeback_request_frame_t *ec_enrollee_t::create_comeback_request(uint8_t dialog_token)
{
    auto [frame, len] = ec_util::alloc_gas_frame(dpp_gas_comeback_req, dialog_token);
    if (frame == nullptr || len == 0) return nullptr;
    return reinterpret_cast<ec_gas_comeback_request_frame_t*>(frame);
}

bool ec_enrollee_t::handle_assoc_status(const rdk_sta_data_t &sta_data)
{
    std::string bssid_str = util::mac_to_string(sta_data.bss_info.bssid);
    
    if (sta_data.stats.connect_status == wifi_connection_status_connected) {
        m_is_onboarding = false;
        em_printfout("Onboarding complete, connected to BSSID: " MACSTRFMT, MAC2STR(sta_data.bss_info.bssid));
    }

    // Is this a BSSID we tried to connect to, and therefore a relevant event for us?
    auto it = m_awaiting_assoc_status.find(bssid_str);
    if (it == m_awaiting_assoc_status.end()) {
        em_printfout("Got association status, but it wasn't for our association attempt.");
        em_printfout("\tBSSID: " MACSTRFMT, MAC2STR(sta_data.bss_info.bssid));
        em_printfout("\tSSID: %s", sta_data.bss_info.ssid);
        em_printfout("\tStatus: %d", sta_data.stats.connect_status);
        for (const auto &pair : m_awaiting_assoc_status) {
            em_printfout("\t\tAwaiting BSSID: %s", pair.first.c_str());
        }
        // This is fine
        return true;
    }
    ec_status_code_t dpp_status;
    switch (sta_data.stats.connect_status) {
        case wifi_connection_status_connected:
            dpp_status = DPP_STATUS_OK;
            break;
        // OneWifi connection statuses disabled and disconnected do not cleanly
        // map to any DPP Status Code (EasyConnect table 22), so map them to
        // STATUS_NO_AP as a generic catch-all.
        case wifi_connection_status_disabled:
        [[fallthrough]];
        case wifi_connection_status_disconnected:
        [[fallthrough]];
        case wifi_connection_status_ap_not_found:
            dpp_status = DPP_STATUS_NO_AP_DISCOVERED;
            break;
        default:
            em_printfout("Unhandled Wi-Fi connection status enum %d", sta_data.stats.connect_status);
            return false;
    }

    auto [frame, frame_len] = create_connection_status_result(dpp_status, std::string(sta_data.bss_info.ssid));
    if (frame == nullptr || frame_len == 0) {
        em_printfout("Failed to create Configuration Connection Status Result frame!");
        return false;
    }

    bool sent = m_send_action_frame(it->second.data(), frame, frame_len, m_selected_freq, 0);
    if (sent) {
        em_printfout("Sent Configuration Connection Status Result frame!");
    } else {
        em_printfout("Failed to send Configuration Connection Status Result Frame to '" MACSTRFMT "'", MAC2STR(it->second));
    }

    // Reset state
    m_awaiting_assoc_status.erase(it);
    free(frame);

    
    return true;
}

bool ec_enrollee_t::check_bss_info_has_cce(const wifi_bss_info_t& bss_info) {

    auto is_cce_ie = [](const uint8_t *const ie, size_t ie_len) -> bool {
        static const uint8_t OUI_WFA[3] = { 0x50, 0x6F, 0x9A };
        static const uint8_t CCE_CONSTANT = 0x1E;
        if (ie_len < 4)
            return false;
        return memcmp(ie, OUI_WFA, sizeof(OUI_WFA)) == 0 && *(ie + 3) == CCE_CONSTANT;
    };


    if (!bss_info.ie || bss_info.ie_len == 0) {
        em_printfout("Invalid BSS info!\n");
        return false;
    }
    uint8_t *ie_pos = const_cast<uint8_t*>(bss_info.ie);
    size_t ie_len_remaining = bss_info.ie_len;
    while (ie_len_remaining > 2) {
        uint8_t id = ie_pos[0];
        uint8_t ie_len = ie_pos[1];
        if (static_cast<size_t>(ie_len + 2) > ie_len_remaining)
            return false;
        // 0xdd == Vendor IE
        if (id == 0xdd && is_cce_ie(ie_pos + 2, ie_len)) {
            return true;
        }
        // next IE
        ie_len_remaining -= (ie_len + 2);
        ie_pos += (ie_len + 2);
    }
    return false;
}

bool ec_enrollee_t::handle_bss_info_event(const std::vector<wifi_bss_info_t> &bss_info_list)
{

    bool did_handle_bss_info = false;
    for (auto& bss_info : bss_info_list) {
        /* EC EC 6.5.2 #2 
        For each channel on which the Enrollee detects the SSID for which it is currently configured, add to the channel list;
        */
        if (m_configured_ssid.length() > 0 &&
            std::string(bss_info.ssid) == m_configured_ssid) {
            em_printfout("SSID %s heard on frequency %d, adding to Reconfiguration Announcement frequency list", bss_info.ssid, bss_info.freq);
            m_recnf_announcement_freqs.insert(bss_info.freq);
            did_handle_bss_info = true;
        }

        /* EC 6.2.2 #3 and EC 6.5.2 #3
        3. Scan all supported bands and add each channel on which an AP is advertising the Configurator Connectivity IE
        (section 8.5.2) to the channel list; then,
        */
        if (check_bss_info_has_cce(bss_info)){
            em_printfout("CCE heard on frequency %d, adding to Presence Announcement frequency list", bss_info.freq);
            m_pres_announcement_freqs.insert(bss_info.freq);
            m_recnf_announcement_freqs.insert(bss_info.freq);
            did_handle_bss_info = true;
        }

    }

    if (!did_handle_bss_info) {
        em_printfout("Did not recieve any relevant data in scan results...");
    }

    return true;
}
