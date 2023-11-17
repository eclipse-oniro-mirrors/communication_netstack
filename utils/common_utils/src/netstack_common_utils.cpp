/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include "netstack_common_utils.h"

#ifdef WINDOWS_PLATFORM
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <arpa/inet.h>
#endif

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <regex>
#include <string>
#include <unistd.h>
#include <vector>

#include "curl/curl.h"
#include "netstack_log.h"

constexpr int32_t INET_OPTION_SUC = 1;

namespace OHOS::NetStack::CommonUtils {
std::vector<std::string> Split(const std::string &str, const std::string &sep)
{
    std::string s = str;
    std::vector<std::string> res;
    while (!s.empty()) {
        auto pos = s.find(sep);
        if (pos == std::string::npos) {
            res.emplace_back(s);
            break;
        }
        res.emplace_back(s.substr(0, pos));
        s = s.substr(pos + sep.size());
    }
    return res;
}

std::vector<std::string> Split(const std::string &str, const std::string &sep, size_t size)
{
    std::string s = str;
    std::vector<std::string> res;
    while (!s.empty()) {
        if (res.size() + 1 == size) {
            res.emplace_back(s);
            break;
        }

        auto pos = s.find(sep);
        if (pos == std::string::npos) {
            res.emplace_back(s);
            break;
        }
        res.emplace_back(s.substr(0, pos));
        s = s.substr(pos + sep.size());
    }
    return res;
}

std::string Strip(const std::string &str, char ch)
{
    int64_t i = 0;
    while (static_cast<size_t>(i) < str.size() && str[i] == ch) {
        ++i;
    }
    int64_t j = static_cast<int64_t>(str.size()) - 1;
    while (j > 0 && str[j] == ch) {
        --j;
    }
    if (i >= 0 && static_cast<size_t>(i) < str.size() && j >= 0 && static_cast<size_t>(j) < str.size() &&
        j - i + 1 > 0) {
        return str.substr(i, j - i + 1);
    }
    return "";
}

std::string ToLower(const std::string &s)
{
    std::string res = s;
    std::transform(res.begin(), res.end(), res.begin(), tolower);
    return res;
}

std::string ToString(const std::list<std::string> &lists, char tab)
{
    std::string str;
    int32_t index = 0;
    for (const auto &s : lists) {
        if (index > 0) {
            str = str + tab;
        }
        str = str + s;
        index++;
    }
    return str;
}

bool HasInternetPermission()
{
#ifndef OH_CORE_NETSTACK_PERMISSION_CHECK
#ifdef FUZZ_TEST
    return true;
#endif
    int testSock = socket(AF_INET, SOCK_STREAM, 0);
    if (testSock < 0 && errno == EPERM) {
        NETSTACK_LOGE("make tcp testSock failed errno is %{public}d %{public}s", errno, strerror(errno));
        return false;
    }
    if (testSock > 0) {
        close(testSock);
    }
    return true;
#else
    constexpr int inetGroup = 40002003; // 3003 in gateway shell.
    int groupNum = getgroups(0, nullptr);
    if (groupNum <= 0) {
        NETSTACK_LOGE("no group of INTERNET permission");
        return false;
    }
    auto groups = (gid_t *)malloc(groupNum * sizeof(gid_t));
    groupNum = getgroups(groupNum, groups);
    for (int i = 0; i < groupNum; i++) {
        if (groups[i] == inetGroup) {
            free(groups);
            return true;
        }
    }
    free(groups);
    NETSTACK_LOGE("INTERNET permission denied by group");
    return false;
#endif
}

bool EndsWith(const std::string &str, const std::string &suffix)
{
    if (str.length() < suffix.length()) {
        return false;
    }
    return str.compare(str.length() - suffix.length(), suffix.length(), suffix) == 0;
}

std::string Trim(std::string str)
{
    size_t start = str.find_first_not_of(" \t\n\r");
    size_t end = str.find_last_not_of(" \t\n\r");
    if (start == std::string::npos || end == std::string::npos) {
        return "";
    } else {
        return str.substr(start, end - start + 1);
    }
}

bool IsMatch(const std::string &str, const std::string &patternStr)
{
    if (patternStr.empty()) {
        return false;
    }
    if (patternStr == "*") {
        return true;
    }
    if (!IsRegexValid(patternStr)) {
        NETSTACK_LOGD("Invalid pattern string: %{public}s", patternStr.c_str());
        return patternStr == str;
    }
    std::regex pattern(ReplaceCharacters(patternStr));
    bool isMacth = patternStr != "" && std::regex_match(str, pattern);
    if (isMacth) {
        NETSTACK_LOGD("Match patternStr: %{public}s", patternStr.c_str());
    }
    return isMacth;
}

std::string InsertCharBefore(const std::string &input, const char from, const char preChar, const char nextChar)
{
    std::string output = input;
    char arr[] = {preChar, from};
    unsigned long strSize = sizeof(arr) / sizeof(arr[0]);
    std::string str(arr, strSize);
    std::size_t pos = output.find(from);
    std::size_t length = output.length();
    while (pos <= length - 1 && pos != std::string::npos) {
        char nextCharTemp = pos == length - 1 ? '\0' : output[pos + 1];
        if (nextChar == '\0' || nextCharTemp == '\0' || nextCharTemp != nextChar) {
            output.replace(pos, 1, str);
            length += (strSize - 1);
        }
        pos = output.find(from, pos + strSize);
    }
    return output;
}

std::string ReplaceCharacters(const std::string &input)
{
    std::string output = InsertCharBefore(input, '*', '.', '\0');
    output = InsertCharBefore(output, '.', '\\', '*');
    return output;
}

bool IsRegexValid(const std::string &regex)
{
    if (Trim(regex).empty()) {
        return false;
    }
    return regex_match(regex, std::regex("^[a-zA-Z0-9\\-_\\.*]+$"));
}

std::string GetHostnameFromURL(const std::string &url)
{
    std::string delimiter = "://";
    std::string tempUrl = url;
    size_t posStart = tempUrl.find(delimiter);
    if (posStart != std::string::npos) {
        posStart += delimiter.length();
    } else {
        posStart = 0;
    }
    size_t posEnd = std::min({ tempUrl.find(":", posStart),
        tempUrl.find("/", posStart), tempUrl.find("?", posStart) });
    if (posEnd != std::string::npos) {
        return tempUrl.substr(posStart, posEnd - posStart);
    }
    return tempUrl.substr(posStart);
}

bool IsExcluded(const std::string &str, const std::string &exclusions, const std::string &split)
{
    if (Trim(exclusions).empty()) {
        return false;
    }
    std::size_t start = 0;
    std::size_t end = exclusions.find(split);
    while (end != std::string::npos) {
        if (end - start > 0 && IsMatch(str, Trim(exclusions.substr(start, end - start)))) {
            return true;
        }
        start = end + 1;
        end = exclusions.find(split, start);
    }
    return IsMatch(str, Trim(exclusions.substr(start)));
}

bool IsHostNameExcluded(const std::string &url, const std::string &exclusions, const std::string &split)
{
    std::string hostName = GetHostnameFromURL(url);
    NETSTACK_LOGD("hostName is: %{public}s", hostName.c_str());
    return IsExcluded(hostName, exclusions, split);
}

bool IsValidIPV4(const std::string &ip)
{
    return IsValidIP(ip, AF_INET);
}

bool IsValidIPV6(const std::string &ip)
{
    return IsValidIP(ip, AF_INET6);
}

bool IsValidIP(const std::string& ip, int af)
{
    if (ip.empty()) {
        return false;
    }
#ifdef WINDOWS_PLATFORM
    if (af == AF_INET6) {
        struct sockaddr_in6 sa;
        return inet_pton(af, ip.c_str(), &(sa.sin6_addr)) == INET_OPTION_SUC;
    } else {
        struct sockaddr_in sa;
        return inet_pton(af, ip.c_str(), &(sa.sin_addr)) == INET_OPTION_SUC;
    }
#else
    if (af == AF_INET6) {
        struct in6_addr addr;
        return inet_pton(af, ip.c_str(), reinterpret_cast<void *>(&addr)) == INET_OPTION_SUC;
    } else {
        struct in_addr addr;
        return inet_pton(af, ip.c_str(), reinterpret_cast<void *>(&addr)) == INET_OPTION_SUC;
    }
#endif
}
} // namespace OHOS::NetStack::CommonUtils