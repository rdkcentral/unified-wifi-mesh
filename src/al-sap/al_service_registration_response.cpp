#include "al_service_registration_enums.h"
#include "al_service_registration_response.h"
#include "al_service_utils.h"
#include <algorithm>
#include <stdexcept>

AlServiceRegistrationResponse::AlServiceRegistrationResponse()
    : alMacAddressLocal{0, 0, 0, 0, 0, 0}, result(RegistrationResult::UNKNOWN) {}

AlServiceRegistrationResponse::AlServiceRegistrationResponse(
    const MacAddress& macAddress,
    RegistrationResult result
) : alMacAddressLocal(macAddress), result(result) {}

void AlServiceRegistrationResponse::setAlMacAddressLocal(const MacAddress& alMac) {
    alMacAddressLocal = alMac;
}

const MacAddress& AlServiceRegistrationResponse::getAlMacAddressLocal() const {
    return alMacAddressLocal;
}

void AlServiceRegistrationResponse::setResult(RegistrationResult result) {
    this->result = result;
}

RegistrationResult AlServiceRegistrationResponse::getResult() const {
    return result;
}

std::vector<unsigned char> AlServiceRegistrationResponse::serializeRegistrationResponse() {
    std::vector<unsigned char> data;
    uint32_t packet_size = alMacAddressLocal.size() + sizeof(uint8_t);
    // Serialize MAC address
    data = convert_u32_into_bytes(packet_size);
    data.insert(data.end(), alMacAddressLocal.begin(), alMacAddressLocal.end());

    // Serialize result
    data.push_back(static_cast<unsigned char>(result));

    return data;
}

void AlServiceRegistrationResponse::deserializeRegistrationResponse(const std::vector<unsigned char>& data) {
    // Ensure data size contains length prefix, MAC address, and result.
    if (data.size() < (sizeof(uint32_t) + sizeof(MacAddress) + sizeof(uint8_t))) {
        throw std::runtime_error("Insufficient data to deserialize AlServiceRegistrationResponse");
    }
    // shadow data variable to limit code changes
    std::vector<unsigned char> data_raw = remove_length_delimited_part(data);

    // Deserialize MAC address
    std::copy(data_raw.begin(), data_raw.begin() + 6, alMacAddressLocal.begin());

    // Deserialize result
    result = static_cast<RegistrationResult>(data_raw[6]);
}
