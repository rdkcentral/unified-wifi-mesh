#include <stdio.h>
#include <numeric>
#include <iomanip>
#include <ostream>
#include <string>
#include "al_service_registration_enums.h"

using MacAddress = std::array<uint8_t, 6>;
using MessageIdRange = std::pair<uint16_t, uint16_t>;

MacAddress parseMacAddress(const std::string& macStr);
std::ostream& operator<<(std::ostream& os, const MacAddress& mac);
std::ostream& operator<<(std::ostream& os, const MessageIdRange& range);
std::ostream& operator<<(std::ostream& os, const ServiceOperation& op);
std::ostream& operator<<(std::ostream& os, const ServiceType& type);
