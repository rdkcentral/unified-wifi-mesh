#include "../../inc/al_service_exception.h"

// Constructor definition
AlServiceException::AlServiceException(const std::string& message, PrimitiveError error)
    : std::runtime_error(message), error(error) {}

// Method to get the PrimitiveReceipt value
PrimitiveError AlServiceException::getPrimitiveError() const {
    return error;
}