#include "al_service_registration_enums.h"
#include "al_service_registration_request.h"
#include "al_service_utils.h"

// Constructor
// Parameterized constructor
AlServiceRegistrationRequest::AlServiceRegistrationRequest(SAPActivation operation, ServiceType type)
    : serviceOperation(operation), serviceType(type) {}

// Default constructor
AlServiceRegistrationRequest::AlServiceRegistrationRequest()
    : serviceOperation(SAPActivation::SAP_ENABLE), serviceType(ServiceType::EmAgent) {}

// Setter for service operation
void AlServiceRegistrationRequest::setSAPActivationStatus(SAPActivation service) {
    serviceOperation = service;
}

// Getter for service operation
SAPActivation AlServiceRegistrationRequest::getSAPActivationStatus() const {
    return serviceOperation;
}

// Setter for service type
void AlServiceRegistrationRequest::setServiceType(ServiceType service) {
    serviceType = service;
}

// Getter for service type
ServiceType AlServiceRegistrationRequest::getServiceType() const {
    return serviceType;
}

// Serialization method: Converts the request data to a byte vector for transmission
std::vector<unsigned char> AlServiceRegistrationRequest::serializeRegistrationRequest() {
    std::vector<unsigned char> data;
    // simple implementation of length delimited packet
    // registration request contains two u8 types
    uint32_t size_of_struct = 2*sizeof(unsigned char);
    // split u32 into four u8
    data = convert_u32_into_bytes(size_of_struct);
    // Serialize service operation and service type as bytes
    data.push_back(static_cast<unsigned char>(serviceOperation));
    data.push_back(static_cast<unsigned char>(serviceType));

    return data;
}

// Deserialization method: Populates the request from a byte vector
void AlServiceRegistrationRequest::deserializeRegistrationRequest(const std::vector<unsigned char>& data) {
    auto data_raw = remove_length_delimited_part(data);
    if (data.size() >= SIZE_BYTES) {
        serviceOperation = static_cast<SAPActivation>(data_raw[0]);
        serviceType = static_cast<ServiceType>(data_raw[1]);

    } else {
        throw std::runtime_error("Invalid data size for deserialization");
    }
}
