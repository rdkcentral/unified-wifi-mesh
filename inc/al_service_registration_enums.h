#ifndef AL_SERVICE_REGISTRATION_ENUMS_H
#define AL_SERVICE_REGISTRATION_ENUMS_H

#include <cstdint>

//keeps operation state
enum class ServiceOperation : uint8_t {
    ENABLE = 0x01, 
    DISABLE = 0x02
};
//keeps the service type requested to the IEEE1905 layer
enum class ServiceType : uint8_t {
    SAP_CLIENT = 0x01,
    SAP_SERVER = 0x02,
    SAP_TUNNEL_CLIENT = 0x03,
    SAP_TUNNEL_SERVER = 0x04
};
//keeps registration result
//not all the results are handled for now
enum class RegistrationResult : uint8_t {
    UNKNOWN = 0x00,
    SUCCESS = 0x01,
    NO_RANGES_AVAILABLE = 0x02,
    SERVICE_NOT_SUPPORTED = 0x03,
    OPERATION_NOT_SUPPORTED = 0x03
};

#endif // AL_SERVICE_REGISTRATION_ENUMS_H
