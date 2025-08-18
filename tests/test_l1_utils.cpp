/*
 * If not stated otherwise in this file or this component's LICENSE file the
 * following copyright and licenses apply:
 *
 * Copyright 2025 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "test_l1_utils.h"
#include <array>
#include <sstream>
#include <cctype>

MacAddress parseMacAddress(const std::string& macStr) {
    std::string cleaned;
    for (char c : macStr) {
        if (std::isalnum(c)) {
            cleaned += c;
        }
    }
    MacAddress mac{};
    for (size_t i = 0; i < 6; ++i) {
        std::string byteStr = cleaned.substr(i * 2, 2);
        std::istringstream(byteStr) >> std::hex >> mac[i];
    }
    return mac;
}


std::ostream& operator<<(std::ostream& os, const MacAddress& mac) {
    for (size_t i = 0; i < mac.size(); ++i) {
        if (i != 0) os << ":";
        os << std::hex << std::setw(2) << std::setfill('0')
           << static_cast<unsigned int>(mac[i]);
    }
    return os;
}

std::ostream& operator<<(std::ostream& os, const MessageIdRange& range) {
    os << "[" << range.first << ", " << range.second << "]";
    return os;
}

std::ostream& operator<<(std::ostream& os, const SAPActivation& op) {
    switch (op) {
        case SAPActivation::SAP_ENABLE:
            os << "SOP_ENABLE";
            break;
        case SAPActivation::SAP_DISABLE:
            os << "SOP_DISABLE";
            break;
        default:
            os << "UNKNOWN_SERVICE_OPERATION";
    }
    return os;
}

std::ostream& operator<<(std::ostream& os, const ServiceType& type) {
    switch (type) {
        case ServiceType::EmAgent:
            os << "EmAgent";
            break;
        case ServiceType::EmController:
            os << "EmController";
            break;
        default:
            os << "UNKNOWN_SERVICE_TYPE";
            break;
    }
    return os;
}
