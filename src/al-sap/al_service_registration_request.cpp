#include "al_service_registration_enums.h"
#include "al_service_registration_request.h"


// Constructor
// Parameterized constructor
AlServiceRegistrationRequest::AlServiceRegistrationRequest(ServiceOperation operation, ServiceType type)
    : serviceOperation(operation), serviceType(type) {}

// Default constructor
AlServiceRegistrationRequest::AlServiceRegistrationRequest()
    : serviceOperation(ServiceOperation::SOP_ENABLE), serviceType(ServiceType::SAP_TUNNEL_CLIENT) {}

// Setter for service operation
void AlServiceRegistrationRequest::setServiceOperation(ServiceOperation service) {
    serviceOperation = service;
}

// Getter for service operation
ServiceOperation AlServiceRegistrationRequest::getServiceOperation() const {
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
    
    // Serialize service operation and service type as bytes
    data.push_back(static_cast<unsigned char>(serviceOperation));
    data.push_back(static_cast<unsigned char>(serviceType));

    return data;
}

// Deserialization method: Populates the request from a byte vector
void AlServiceRegistrationRequest::deserializeRegistrationRequest(const std::vector<unsigned char>& data) {
    if (data.size() >= 2) {
        serviceOperation = static_cast<ServiceOperation>(data[0]);
        serviceType = static_cast<ServiceType>(data[1]);
    } else {
        throw std::runtime_error("Invalid data size for deserialization");
    }
}