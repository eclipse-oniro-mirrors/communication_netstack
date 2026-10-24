/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef COMMUNICATIONNETSTACK_COMMON_UTILS_H
#define COMMUNICATIONNETSTACK_COMMON_UTILS_H

#include <iosfwd>
#include <list>
#include <limits>
#include <vector>
#include <string>
#include <optional>
#include <type_traits>
#ifndef LINUX_PLATFORM
#include <charconv>
#endif

namespace OHOS::NetStack::CommonUtils {
static const std::string DOMAIN_TYPE_HTTP_REQUEST = "httpRequest";
static const std::string DOMAIN_TYPE_WEBSOCKET_REQUEST = "webSocket";
const int INVALID_IP_TYPE = -1;
const int MAX_PORT = 65535;
static constexpr const int WEBSOCKET_PER_MESSAGE_MAX_SIZE = 1024 * 1024 * 1024;
static constexpr const char *WEBSOCKET_DATA_LENGTH_EXCEEDED_STR = "websocket data length exceeded";
enum SdkVersion {
    FIVE = 5,
    SIX,
    SEVEN,
    EIGHT,
    NINE,
    TEN,
    ELEVEN,
    TWELVE
};

std::vector<std::string> Split(const std::string &str, const std::string &sep);

std::vector<std::string> Split(const std::string &str, const std::string &sep, size_t size);

std::string Strip(const std::string &str, char ch = ' ');

std::string ToLower(const std::string &s);

std::string ToString(const std::list<std::string> &lists, char tab = ',');

bool HasInternetPermission();

bool IsAtomicService(std::string &bundleName);

bool IsAllowedHostname(const std::string &bundleName, const std::string &domainType, const std::string &url);

bool EndsWith(const std::string &str, const std::string &suffix);

std::string Trim(std::string str);

bool IsMatch(const std::string &str, const std::string &patternStr);

std::string InsertCharBefore(const std::string &input, const char from, const char preChar, const char nextChar);

std::string ReplaceCharacters(const std::string &input);

bool IsRegexValid(const std::string &regex);

std::string GetProtocolFromURL(const std::string &url);

std::string GetPortFromURL(const std::string &url);

std::string GetHostnameFromURL(const std::string& url);

std::string GetHostnameWithProtocolAndPortFromURL(const std::string& url);

bool IsExcluded(const std::string &str, const std::string &exclusions, const std::string &split);

bool IsHostNameExcluded(const std::string &url, const std::string &exclusions, const std::string &split);

int DetectIPType(const std::string &ip);

bool IsValidIP(const std::string& ip, int af);

bool IsValidIPV4(const std::string &ip);

bool IsValidIPV6(const std::string &ip);

std::string MaskIpv4(std::string &maskedResult);

std::string MaskIpv6(std::string &maskedResult);

std::string AnonymizeIp(std::string &input);

std::string AnonymizeHost(const std::string &input);

std::string GetSimpleHost(std::string &input);

std::optional<std::string> GetBundleName();

bool GetFileDataFromFilePath(const std::string& filePath, std::string& fileData);

bool Sha256sum(unsigned char *buf, size_t buflen, std::string &digestStr);

bool IsCertPubKeyInPinned(const std::string &certPubKeyDigest, const std::string &pinnedPubkey);

bool IsCleartextPermitted(const std::string &url, const std::string &protocol);

bool IsValidPort(const uint32_t &Port);

std::string ToAnonymousIp(const std::string &input);

std::string CombineStrings(const std::vector<std::string> &strs, const std::string &spliter);

std::string CombineStringsAnonymous(const std::vector<std::string> &strs, const std::string &spliter);

char *MallocCString(const std::string &origin);

// Parse signed decimal integers without accepting leading whitespace or '+'.
// Set requireFull to false for callers that accept a numeric prefix.
template<typename T>
bool ParseDecimalInteger(const std::string &input, T &output, bool requireFull = true)
{
    static_assert(std::is_integral<T>::value && std::is_signed<T>::value, "Expected a signed integer");
#ifdef LINUX_PLATFORM
    if (input.empty()) {
        return false;
    }
    const bool negative = input.front() == '-';
    size_t pos = negative ? 1 : 0;
    const size_t start = pos;
    using Unsigned = typename std::make_unsigned<T>::type;
    const Unsigned limit = static_cast<Unsigned>(std::numeric_limits<T>::max()) + (negative ? 1 : 0);
    constexpr Unsigned base = 10;
    Unsigned value = 0;
    while (pos < input.size() && input[pos] >= '0' && input[pos] <= '9') {
        const Unsigned digit = static_cast<Unsigned>(input[pos] - '0');
        if (value > limit / base || (value == limit / base && digit > limit % base)) {
            return false;
        }
        value = value * base + digit;
        ++pos;
    }
    if (pos == start || (requireFull && pos != input.size())) {
        return false;
    }
    if (negative && value == limit) {
        output = std::numeric_limits<T>::min();
    } else {
        output = negative ? -static_cast<T>(value) : static_cast<T>(value);
    }
    return true;
#else
    T value = 0;
    auto [ptr, ec] = std::from_chars(input.data(), input.data() + input.size(), value);
    if (ec != std::errc{} || (requireFull && ptr != input.data() + input.size())) {
        return false;
    }
    output = value;
    return true;
#endif
}
} // namespace OHOS::NetStack::CommonUtils
#endif /* COMMUNICATIONNETSTACK_COMMON_UTILS_H */
