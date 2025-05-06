#include <stdio.h>
#include <numeric>
#include <iomanip>
#include <ostream>


MacAddress parseMacAddress(const std::string& macStr);
std::ostream& operator<<(std::ostream& os, const MacAddress& mac);
std::ostream& operator<<(std::ostream& os, const MessageIdRange& range);
std::ostream& operator<<(std::ostream& os, const ServiceOperation& op);
std::ostream& operator<<(std::ostream& os, const ServiceType& type);
