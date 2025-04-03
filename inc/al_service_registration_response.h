#ifndef AL_SERVICE_REGISTRATION_RESPONSE_H
#define AL_SERVICE_REGISTRATION_RESPONSE_H

#include "al_service_registration_enums.h"
#include <array>
#include <utility>
#include <vector>

using MacAddress = std::array<uint8_t, 6>;
using MessageIdRange = std::pair<uint16_t, uint16_t>;

// Class used to manage a registration response from the IEEE1905 applicatoin
class AlServiceRegistrationResponse {
public:
    // Constructors
    AlServiceRegistrationResponse();  
    AlServiceRegistrationResponse(const MacAddress& macAddress, MessageIdRange range, RegistrationResult result);

    // Setters and getters for local AL MAC address
    void setAlMacAddressLocal(const MacAddress& alMac);
    const MacAddress& getAlMacAddressLocal() const;

    // Setters and getters for message ID range assigned from the IEEE1905 agent
    void setMessageIdRange(const MessageIdRange& range);
    MessageIdRange getMessageIdRange() const;

    // Setters and getters for registration result
    void setResult(RegistrationResult result);
    RegistrationResult getResult() const;

    // Serialization and deserialization functions
    std::vector<unsigned char> serializeRegistrationResponse();
    void deserializeRegistrationResponse(const std::vector<unsigned char>& data);

private:
    MacAddress alMacAddressLocal;
    MessageIdRange messageIdRange;
    RegistrationResult result;
};


#endif // AL_SERVICE_REGISTRATION_RESPONSE_H
