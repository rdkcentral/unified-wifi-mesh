#include "../../inc/al_service_registration_enums.h"
#include "../../inc/al_service_registration_response.h"

AlServiceRegistrationResponse::AlServiceRegistrationResponse()
    : alMacAddressLocal{0, 0, 0, 0, 0, 0}, messageIdRange{0, 0}, result(RegistrationResult::UNKNOWN) {}

AlServiceRegistrationResponse::AlServiceRegistrationResponse(
    const MacAddress& macAddress, 
    MessageIdRange range, 
    RegistrationResult result
) : alMacAddressLocal(macAddress), messageIdRange(range), result(result) {}

void AlServiceRegistrationResponse::setAlMacAddressLocal(const MacAddress& alMac) {
    alMacAddressLocal = alMac;
}

const MacAddress& AlServiceRegistrationResponse::getAlMacAddressLocal() const {
    return alMacAddressLocal;
}

void AlServiceRegistrationResponse::setMessageIdRange(const MessageIdRange& range) {
    messageIdRange = range;
}

MessageIdRange AlServiceRegistrationResponse::getMessageIdRange() const {
    return messageIdRange;
}

void AlServiceRegistrationResponse::setResult(RegistrationResult result) {
    this->result = result;
}

RegistrationResult AlServiceRegistrationResponse::getResult() const {
    return result;
}

std::vector<unsigned char> AlServiceRegistrationResponse::serializeRegistrationResponse() {
    std::vector<unsigned char> data;
    
    // Serialize MAC address
    data.insert(data.end(), alMacAddressLocal.begin(), alMacAddressLocal.end());

    // Serialize message ID range
    data.push_back(static_cast<unsigned char>(messageIdRange.first >> 8));
    data.push_back(static_cast<unsigned char>(messageIdRange.first & 0xFF));
    data.push_back(static_cast<unsigned char>(messageIdRange.second >> 8));
    data.push_back(static_cast<unsigned char>(messageIdRange.second & 0xFF));

    // Serialize result
    data.push_back(static_cast<unsigned char>(result));

    return data;
}

void AlServiceRegistrationResponse::deserializeRegistrationResponse(const std::vector<unsigned char>& data) {
    // Ensure sufficient data size
    if (data.size() < 9) {
        throw std::runtime_error("Insufficient data to deserialize AlServiceRegistrationResponse");
    }

    // Deserialize MAC address
    std::copy(data.begin(), data.begin() + 6, alMacAddressLocal.begin());

    // Deserialize message ID range
    messageIdRange.first = (data[6] << 8) | data[7];
    messageIdRange.second = (data[8] << 8) | data[9];

    // Deserialize result
    result = static_cast<RegistrationResult>(data[10]);
}