#include "al_service_exception.h"

// Constructor definition
AlServiceException::AlServiceException(const std::string& message, PrimitiveError error)
    : std::runtime_error(message), error(error) {
    if (message.empty()) {
        throw std::invalid_argument("AlServiceException: message must not be empty");
    }
    if (error < PrimitiveError::RequestFailed || error > PrimitiveError::FragmentOutOfOrder) {
        throw std::invalid_argument("AlServiceException: invalid PrimitiveError value");
    }
}

// Method to get the PrimitiveReceipt value
PrimitiveError AlServiceException::getPrimitiveError() const {
    return error;
}