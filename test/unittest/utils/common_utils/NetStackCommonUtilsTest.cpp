/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>
#include <iostream>

#include "netstack_common_utils.h"

namespace OHOS {
namespace NetStack {
namespace CommonUtils {
namespace {
using namespace testing::ext;
static constexpr const char SPACE = ' ';
static constexpr const char *STATUS_LINE_COMMA = ",";
static constexpr const char *STATUS_LINE_SEP = " ";
static constexpr const size_t STATUS_LINE_ELEM_NUM = 2;
} // namespace

class NetStackCommonUtilsTest : public testing::Test {
public:
    static void SetUpTestCase() {}

    static void TearDownTestCase() {}

    virtual void SetUp() {}

    virtual void TearDown() {}
};

HWTEST_F(NetStackCommonUtilsTest, CommonUtils, TestSize.Level2)
{
    std::string str = "The,weather,is,fine,today";
    std::vector<std::string> subStr = Split(str, STATUS_LINE_COMMA);
    EXPECT_STREQ(subStr[0].data(), "The");
    EXPECT_STREQ(subStr[1].data(), "weather");
    EXPECT_STREQ(subStr[2].data(), "is");
    EXPECT_STREQ(subStr[3].data(), "fine");
    EXPECT_STREQ(subStr[4].data(), "today");
    EXPECT_EQ(subStr.size(), 5);
}

HWTEST_F(NetStackCommonUtilsTest, CommonUtils1, TestSize.Level2)
{
    std::string str = " The weather is fine today";
    std::string subStr = Strip(str, SPACE);
    EXPECT_STREQ(subStr.data(), "The weather is fine today");
}

HWTEST_F(NetStackCommonUtilsTest, CommonUtils2, TestSize.Level2)
{
    std::string str = "HOWDOYOUDO";
    std::string strLower = ToLower(str);
    EXPECT_STREQ(strLower.data(), "howdoyoudo");
}

HWTEST_F(NetStackCommonUtilsTest, CommonUtils3, TestSize.Level2)
{
    std::string str = "fine today";
    std::vector<std::string> strList = Split(str, STATUS_LINE_SEP, STATUS_LINE_ELEM_NUM);

    EXPECT_STREQ(strList[0].data(), "fine");
    EXPECT_STREQ(strList[1].data(), "today");
    EXPECT_EQ(strList.size(), 2);
}

HWTEST_F(NetStackCommonUtilsTest, CommonUtils4, TestSize.Level2)
{
    std::string str = "    trim   ";
    std::string strResult = Trim(str);
    EXPECT_STREQ(strResult.c_str(), "trim");
}

HWTEST_F(NetStackCommonUtilsTest, CommonUtils5, TestSize.Level2)
{
    bool isMatch = IsMatch("www.alibaba.com", "*");
    EXPECT_EQ(isMatch, true);
}

HWTEST_F(NetStackCommonUtilsTest, CommonUtils6, TestSize.Level2)
{
    bool isMatch = IsMatch("www.alibaba.com", "");
    EXPECT_EQ(isMatch, false);
}

HWTEST_F(NetStackCommonUtilsTest, CommonUtils7, TestSize.Level2)
{
    bool isMatch = IsMatch("www.alibaba.com", "*.alibaba.*");
    EXPECT_EQ(isMatch, true);
}

HWTEST_F(NetStackCommonUtilsTest, CommonUtils8, TestSize.Level2)
{
    bool isMatch = IsMatch("www.alibaba.com", "www.alibaba.com");
    EXPECT_EQ(isMatch, true);
}

HWTEST_F(NetStackCommonUtilsTest, CommonUtils9, TestSize.Level2)
{
    bool isValid = IsRegexValid("*.alibaba.*");
    EXPECT_EQ(isValid, true);
}

HWTEST_F(NetStackCommonUtilsTest, CommonUtils10, TestSize.Level2)
{
    bool isValid = IsRegexValid("*.alibaba./{*");
    EXPECT_EQ(isValid, false);
}

HWTEST_F(NetStackCommonUtilsTest, CommonUtils11, TestSize.Level2)
{
    std::string hostname = GetHostnameFromURL("https://www.alibaba.com/idesk?idesk:idesk");
    EXPECT_STREQ(hostname.c_str(), "www.alibaba.com");
}

HWTEST_F(NetStackCommonUtilsTest, CommonUtils12, TestSize.Level2)
{
    std::string hostname = GetHostnameFromURL("https://www.alibaba.com:8081/idesk?idesk:idesk");
    EXPECT_STREQ(hostname.c_str(), "www.alibaba.com");
}

HWTEST_F(NetStackCommonUtilsTest, CommonUtils13, TestSize.Level2)
{
    std::string hostname = GetHostnameFromURL("https://www.alibaba.com?data_string");
    EXPECT_STREQ(hostname.c_str(), "www.alibaba.com");
}

HWTEST_F(NetStackCommonUtilsTest, CommonUtils14, TestSize.Level2)
{
    std::string url = "https://www.alibaba.com?data_string";
    std::string exclusions = "*.alibaba.*, *.baidu.*";
    bool isExluded = IsHostNameExcluded(url, exclusions, ",");
    EXPECT_EQ(isExluded, true);
}

HWTEST_F(NetStackCommonUtilsTest, CommonUtils15, TestSize.Level2)
{
    std::string url = "https://www.alibaba.com?data_string:abc";
    std::string exclusions = "*.xiaomi.*, *.baidu.*";
    bool isExluded = IsHostNameExcluded(url, exclusions, ",");
    EXPECT_EQ(isExluded, false);
}

HWTEST_F(NetStackCommonUtilsTest, CommonUtils16, TestSize.Level2)
{
    std::string replacedStr = ReplaceCharacters("*alibaba*");
    EXPECT_STREQ(replacedStr.c_str(), ".*alibaba.*");
}

HWTEST_F(NetStackCommonUtilsTest, CommonUtils17, TestSize.Level2)
{
    bool isEndsWith = EndsWith("alibaba", "a");
    EXPECT_EQ(isEndsWith, true);
}

HWTEST_F(NetStackCommonUtilsTest, CommonUtils18, TestSize.Level2)
{
    bool isEndsWith = EndsWith("alibaba", "o");
    EXPECT_EQ(isEndsWith, false);
}

HWTEST_F(NetStackCommonUtilsTest, CommonUtils19, TestSize.Level2)
{
    std::list<std::string> input = { "Hello", "World", "This", "Is", "A", "Test" };
    const char space = ' ';
    std::string expectedOutput = "Hello World This Is A Test";
    std::string actualOutput = ToString(input, space);
    EXPECT_STREQ(actualOutput.c_str(), expectedOutput.c_str());
}

HWTEST_F(NetStackCommonUtilsTest, CommonUtils20, TestSize.Level2)
{
    std::string input = "abcdcefcg";
    char from = 'c';
    char preChar = '=';
    char nextChar = 'e';
    std::string expectedOutput = "ab=cdcef=cg";
    std::string actualOutput = InsertCharBefore(input, from, preChar, nextChar);
    EXPECT_STREQ(actualOutput.c_str(), expectedOutput.c_str());
}

HWTEST_F(NetStackCommonUtilsTest, CommonUtils21, TestSize.Level2)
{
    std::string str = "www.alibaba.com";
    std::string exclusions = "*.xiaomi.*, *.baidu.*";
    std::string split = ",";
    bool actualOutput = IsExcluded(str, exclusions, ",");
    EXPECT_EQ(actualOutput, false);
}

HWTEST_F(NetStackCommonUtilsTest, CommonUtils22, TestSize.Level2)
{
    std::string str = "www.alibaba.com";
    std::string exclusions = "*.alibaba.*, *.baidu.*";
    bool actualOutput = IsExcluded(str, exclusions, ",");
    EXPECT_EQ(actualOutput, true);
}

HWTEST_F(NetStackCommonUtilsTest, CommonUtils23, TestSize.Level2)
{
    std::string ipv4Valid = "192.168.0.1";
    bool isValidIPV4Valid = IsValidIPV4(ipv4Valid);
    EXPECT_EQ(isValidIPV4Valid, true);
}

HWTEST_F(NetStackCommonUtilsTest, CommonUtils24, TestSize.Level2)
{
    std::string ipv4Invalid = "256.0.0.1";
    bool isValidIPV4Invalid = IsValidIPV4(ipv4Invalid);
    EXPECT_EQ(isValidIPV4Invalid, false);
}

HWTEST_F(NetStackCommonUtilsTest, CommonUtils25, TestSize.Level2)
{
    std::string ipv6Valid = "2001:0db8:85a3:0000:0000:8a2e:0370:7334";
    bool isValidIPV6Valid = IsValidIPV6(ipv6Valid);
    EXPECT_EQ(isValidIPV6Valid, true);
}

HWTEST_F(NetStackCommonUtilsTest, CommonUtils26, TestSize.Level2)
{
    std::string ipv6Invalid = "2001:0db8:85a3::8a2e:0370:7334";
    bool isValidIPV6Invalid = IsValidIPV6(ipv6Invalid);
    EXPECT_EQ(isValidIPV6Invalid, true);
}

HWTEST_F(NetStackCommonUtilsTest, CommonUtils27, TestSize.Level2)
{
    std::string ipV6Invalid = "invalid ipv6 string";
    bool isValidIPV6Invalid = IsValidIPV6(ipV6Invalid);
    EXPECT_EQ(isValidIPV6Invalid, false);
}

HWTEST_F(NetStackCommonUtilsTest, CommonUtils28, TestSize.Level2)
{
    std::string ipv6Invalid = "2001:0db8:85a3::8a2e:0370:7334";
    bool isValidIPV6Invalid = IsValidIPV6(ipv6Invalid);
    EXPECT_EQ(isValidIPV6Invalid, true);
}

HWTEST_F(NetStackCommonUtilsTest, CommonUtils29, TestSize.Level2)
{
    std::string ipv6Ip = "2001:0db8:85a3::8a2e:0370:7334";
    std::string actualOutput = AnonymizeIp(ipv6Ip);
    std::string expectedOutput = "2001:0db8:****::****:****:****";
    EXPECT_STREQ(actualOutput.c_str(), expectedOutput.c_str());
}

HWTEST_F(NetStackCommonUtilsTest, CommonUtils30, TestSize.Level2)
{
    std::string ipv4Ips = "8.8.8.8";
    std::string actualOutput = AnonymizeIp(ipv4Ips);
    std::string expectedOutput = "8.8.*.*";
    EXPECT_STREQ(actualOutput.c_str(), expectedOutput.c_str());
}

HWTEST_F(NetStackCommonUtilsTest, CommonUtils31, TestSize.Level2)
{
    std::string bundleName;
    std::string url = "https://www.example.com";
    auto ret = IsAllowedHostname(bundleName, url);
    EXPECT_TRUE(ret);
}

HWTEST_F(NetStackCommonUtilsTest, CommonUtils32, TestSize.Level2)
{
    std::string bundleName;
    auto ret = IsAtomicService(bundleName);
    EXPECT_FALSE(ret);
}

HWTEST_F(NetStackCommonUtilsTest, GetHostnameWithProtocolFromURLTest001, TestSize.Level2)
{
    std::string hostname = GetHostnameWithProtocolFromURL("https:////www.example.com?data_string");
    EXPECT_STREQ(hostname.c_str(), "https://www.example.com");
}

HWTEST_F(NetStackCommonUtilsTest, GetHostnameWithProtocolFromURLTest002, TestSize.Level2)
{
    std::string hostname = GetHostnameWithProtocolFromURL("https://");
    EXPECT_STREQ(hostname.c_str(), "");
}

HWTEST_F(NetStackCommonUtilsTest, GetHostnameWithProtocolFromURLTest003, TestSize.Level2)
{
    std::string hostname = GetHostnameWithProtocolFromURL("https://www.example.com/for/test");
    EXPECT_STREQ(hostname.c_str(), "https://www.example.com");
}

HWTEST_F(NetStackCommonUtilsTest, GetHostnameWithProtocolFromURLTest004, TestSize.Level2)
{
    std::string hostname = GetHostnameWithProtocolFromURL("www.example.com/for/test");
    EXPECT_STREQ(hostname.c_str(), "www.example.com");
}

HWTEST_F(NetStackCommonUtilsTest, GetHostnameWithProtocolFromURLTest005, TestSize.Level2)
{
    std::string hostname = GetHostnameWithProtocolFromURL("ws://www.example.com/for/test");
    EXPECT_STREQ(hostname.c_str(), "ws://www.example.com");
}

HWTEST_F(NetStackCommonUtilsTest, GetHostnameFromURL01, TestSize.Level2)
{
    std::string hostname = GetHostnameFromURL("https:////www.example.com?data_string");
    EXPECT_STREQ(hostname.c_str(), "www.example.com");
}

HWTEST_F(NetStackCommonUtilsTest, GetHostnameFromURL02, TestSize.Level2)
{
    std::string hostname = GetHostnameFromURL(R"(https:/\\\\\\///\\/www.example.com?data_string)");
    EXPECT_STREQ(hostname.c_str(), "www.example.com");
}

HWTEST_F(NetStackCommonUtilsTest, GetHostnameFromURL03, TestSize.Level2)
{
    std::string hostname = GetHostnameFromURL("");
    EXPECT_STREQ(hostname.c_str(), "");
}

HWTEST_F(NetStackCommonUtilsTest, GetHostnameFromURL04, TestSize.Level2)
{
    std::string hostname = GetHostnameFromURL("https://");
    EXPECT_STREQ(hostname.c_str(), "");
}

HWTEST_F(NetStackCommonUtilsTest, GetHostnameFromURL05, TestSize.Level2)
{
    std::string hostname = GetHostnameFromURL("https://www.example.com:8080");
    EXPECT_STREQ(hostname.c_str(), "www.example.com");
}

HWTEST_F(NetStackCommonUtilsTest, GetHostnameFromURL06, TestSize.Level2)
{
    std::string hostname = GetHostnameFromURL("https://www.example.com/for/test");
    EXPECT_STREQ(hostname.c_str(), "www.example.com");
}

HWTEST_F(NetStackCommonUtilsTest, GetHostnameFromURL07, TestSize.Level2)
{
    std::string hostname = GetHostnameFromURL(R"(https:/\\\\\)");
    EXPECT_STREQ(hostname.c_str(), "");
}

HWTEST_F(NetStackCommonUtilsTest, GetHostnameFromURL08, TestSize.Level2)
{
    std::string hostname = GetHostnameFromURL(R"(https://www.example.com/watch/80033982:sadsda?dd\\\df)");
    EXPECT_STREQ(hostname.c_str(), "www.example.com");
}

HWTEST_F(NetStackCommonUtilsTest, GetHostnameFromURL09, TestSize.Level2)
{
    std::string hostname = GetHostnameFromURL(R"(https://www.example.com:8080/watch/80033982:sadsda?dd\\\df)");
    EXPECT_STREQ(hostname.c_str(), "www.example.com");
}

HWTEST_F(NetStackCommonUtilsTest, GetHostnameFromURL10, TestSize.Level2)
{
    std::string url = "example.com:98421/dsdsd?dsdsds";
    std::string hostname = GetHostnameFromURL(url);
    EXPECT_STREQ(hostname.c_str(), "example.com");
}

HWTEST_F(NetStackCommonUtilsTest, GetHostnameFromURL11, TestSize.Level2)
{
    std::string url = R"(\/\/\/\/\/\/\/\////\)";
    std::string hostname = GetHostnameFromURL(url);
    EXPECT_STREQ(hostname.c_str(), "");
}

HWTEST_F(NetStackCommonUtilsTest, GetHostnameFromURL12, TestSize.Level2)
{
    std::string url = "http://www.example.com";
    std::string hostname = GetHostnameFromURL(url);
    EXPECT_STREQ(hostname.c_str(), "www.example.com");
}

HWTEST_F(NetStackCommonUtilsTest, GetHostnameFromURL13, TestSize.Level2)
{
    std::string url = "https://www.example-test.com";
    std::string hostname = GetHostnameFromURL(url);
    EXPECT_STREQ(hostname.c_str(), "www.example-test.com");
}

HWTEST_F(NetStackCommonUtilsTest, GetHostnameFromURL14, TestSize.Level2)
{
    std::string url = "ftp://www.baidu-test.com";
    std::string hostname = GetHostnameFromURL(url);
    EXPECT_STREQ(hostname.c_str(), "www.baidu-test.com");
}

HWTEST_F(NetStackCommonUtilsTest, GetHostnameFromURL15, TestSize.Level2)
{
    std::string url = R"(\\\/\/\/\/\/\///\/\\\:80808)";
    std::string hostname = GetHostnameFromURL(url);
    EXPECT_STREQ(hostname.c_str(), "");
}

HWTEST_F(NetStackCommonUtilsTest, GetHostnameFromURL16, TestSize.Level2)
{
    std::string url = R"(?????DSdsafhu34r3urihiu45t794\\56y&^&*%$^&$&*&^%*&((*)))";
    std::string hostname = GetHostnameFromURL(url);
    EXPECT_STREQ(hostname.c_str(), "");
}

HWTEST_F(NetStackCommonUtilsTest, GetHostnameFromURL17, TestSize.Level2)
{
    std::string url = R"(16456465221-*/*/\)";
    std::string hostname = GetHostnameFromURL(url);
    EXPECT_STREQ(hostname.c_str(), "16456465221-*");
}

HWTEST_F(NetStackCommonUtilsTest, GetHostnameFromURL18, TestSize.Level2)
{
    std::string url = "czvxkhcvjhkgfidkh";
    std::string hostname = GetHostnameFromURL(url);
    EXPECT_STREQ(hostname.c_str(), "czvxkhcvjhkgfidkh");
}

HWTEST_F(NetStackCommonUtilsTest, GetHostnameFromURL19, TestSize.Level2)
{
    std::string url = "hcd   dfdf4efd446576";
    std::string hostname = GetHostnameFromURL(url);
    EXPECT_STREQ(hostname.c_str(), "hcd   dfdf4efd446576");
}

HWTEST_F(NetStackCommonUtilsTest, GetHostnameFromURL20, TestSize.Level2)
{
    std::string url = " ";
    std::string hostname = GetHostnameFromURL(url);
    EXPECT_STREQ(hostname.c_str(), " ");
}

HWTEST_F(NetStackCommonUtilsTest, GetHostnameFromURL21, TestSize.Level2)
{
    std::string url = "                             ";
    std::string hostname = GetHostnameFromURL(url);
    EXPECT_STREQ(hostname.c_str(), "                             ");
}

HWTEST_F(NetStackCommonUtilsTest, GetHostnameFromURL22, TestSize.Level2)
{
    std::string url = R"(dsd!!!@@#$$%%%^df\\)";
    std::string hostname = GetHostnameFromURL(url);
    EXPECT_STREQ(hostname.c_str(), "dsd!!!@@#$$%%%^df");
}

HWTEST_F(NetStackCommonUtilsTest, GetHostnameFromURL23, TestSize.Level2)
{
    std::string url = "http://example.com";
    std::string hostname = GetHostnameFromURL(url);
    EXPECT_STREQ(hostname.c_str(), "example.com");
}

HWTEST_F(NetStackCommonUtilsTest, GetHostnameFromURL24, TestSize.Level2)
{
    std::string url = "example.com";
    std::string hostname = GetHostnameFromURL(url);
    EXPECT_STREQ(hostname.c_str(), "example.com");
}

HWTEST_F(NetStackCommonUtilsTest, GetHostnameFromURL25, TestSize.Level2)
{
    std::string url = "https:////??::||///stackoverflow.com";
    std::string hostname = GetHostnameFromURL(url);
    EXPECT_STREQ(hostname.c_str(), "");
}

HWTEST_F(NetStackCommonUtilsTest, GetHostnameFromURL26, TestSize.Level2)
{
    std::string url = R"(https://\\\154545\\\stackoverflow.com)";
    std::string hostname = GetHostnameFromURL(url);
    EXPECT_STREQ(hostname.c_str(), "154545");
}

HWTEST_F(NetStackCommonUtilsTest, GetHostnameFromURL27, TestSize.Level2)
{
    std::string url = R"(https://\\\\\\////\\\\stackoverflow.com)";
    std::string hostname = GetHostnameFromURL(url);
    EXPECT_STREQ(hostname.c_str(), "stackoverflow.com");
}

HWTEST_F(NetStackCommonUtilsTest, GetHostnameFromURL28, TestSize.Level2)
{
    std::string url = R"(https:/\151\\\\23243435)";
    std::string hostname = GetHostnameFromURL(url);
    EXPECT_STREQ(hostname.c_str(), "151");
}

HWTEST_F(NetStackCommonUtilsTest, GetHostnameFromURL29, TestSize.Level2)
{
    std::string url = R"(https:\\)";
    std::string hostname = GetHostnameFromURL(url);
    EXPECT_STREQ(hostname.c_str(), "");
}

HWTEST_F(NetStackCommonUtilsTest, GetHostnameFromURL30, TestSize.Level2)
{
    std::string url = R"(""""\\"""""""""""""")";
    std::string hostname = GetHostnameFromURL(url);
    EXPECT_STREQ(hostname.c_str(), R"("""")");
}

HWTEST_F(NetStackCommonUtilsTest, GetHostnameFromURL31, TestSize.Level2)
{
    std::string url = ":::::::dfsfd::::::::::::";
    std::string hostname = GetHostnameFromURL(url);
    EXPECT_STREQ(hostname.c_str(), "");
}

HWTEST_F(NetStackCommonUtilsTest, GetHostnameFromURL32, TestSize.Level2)
{
    std::string url = "1--**--4545";
    std::string hostname = GetHostnameFromURL(url);
    EXPECT_STREQ(hostname.c_str(), "1--**--4545");
}

HWTEST_F(NetStackCommonUtilsTest, GetHostnameFromURL33, TestSize.Level2)
{
    std::string url = R"( https:\)";
    std::string hostname = GetHostnameFromURL(url);
    EXPECT_STREQ(hostname.c_str(), " https");
}

HWTEST_F(NetStackCommonUtilsTest, GetHostnameFromURL34, TestSize.Level2)
{
    std::string url = " https:////";
    std::string hostname = GetHostnameFromURL(url);
    EXPECT_STREQ(hostname.c_str(), "");
}

HWTEST_F(NetStackCommonUtilsTest, GetHostnameFromURL35, TestSize.Level2)
{
    std::string url = " saasa";
    std::string hostname = GetHostnameFromURL(url);
    EXPECT_STREQ(hostname.c_str(), " saasa");
}

HWTEST_F(NetStackCommonUtilsTest, GetHostnameFromURL36, TestSize.Level2)
{
    std::string url = R"(|||///\\\)";
    std::string hostname = GetHostnameFromURL(url);
    EXPECT_STREQ(hostname.c_str(), "|||");
}

HWTEST_F(NetStackCommonUtilsTest, GetHostnameFromURL37, TestSize.Level2)
{
    std::string url = "-- fdsf";
    std::string hostname = GetHostnameFromURL(url);
    EXPECT_STREQ(hostname.c_str(), "-- fdsf");
}

HWTEST_F(NetStackCommonUtilsTest, GetHostnameFromURL38, TestSize.Level2)
{
    std::string url = "xnmku:9090?(sdfgjhg)";
    std::string hostname = GetHostnameFromURL(url);
    EXPECT_STREQ(hostname.c_str(), "xnmku");
}

HWTEST_F(NetStackCommonUtilsTest, GetHostnameFromURL39, TestSize.Level2)
{
    std::string url = "oooxxx111-===";
    std::string hostname = GetHostnameFromURL(url);
    EXPECT_STREQ(hostname.c_str(), "oooxxx111-===");
}

HWTEST_F(NetStackCommonUtilsTest, GetHostnameFromURL40, TestSize.Level2)
{
    std::string url = R"($^%(_*_()*+_)(YU(\_)))";
    std::string hostname = GetHostnameFromURL(url);
    EXPECT_STREQ(hostname.c_str(), "$^%(_*_()*+_)(YU(");
}

HWTEST_F(NetStackCommonUtilsTest, GetHostnameFromURL41, TestSize.Level2)
{
    std::string url = R"(万维网.com:9090\)";
    std::string hostname = GetHostnameFromURL(url);
    EXPECT_STREQ(hostname.c_str(), "万维网.com");
}

HWTEST_F(NetStackCommonUtilsTest, GetHostnameFromURL42, TestSize.Level2)
{
    std::string url = R"(https://\\\中文测试)";
    std::string hostname = GetHostnameFromURL(url);
    EXPECT_STREQ(hostname.c_str(), "中文测试");
}

HWTEST_F(NetStackCommonUtilsTest, GetHostnameFromURL43, TestSize.Level2)
{
    std::string url = R"(http://\\\中文测试?中文数据)";
    std::string hostname = GetHostnameFromURL(url);
    EXPECT_STREQ(hostname.c_str(), "中文测试");
}

HWTEST_F(NetStackCommonUtilsTest, GetHostnameFromURL44, TestSize.Level2)
{
    std::string url = R"(http://\\\中文测试：8080?中文数据)";
    std::string hostname = GetHostnameFromURL(url);
    EXPECT_STREQ(hostname.c_str(), "中文测试：8080");
}

HWTEST_F(NetStackCommonUtilsTest, GetHostnameFromURL45, TestSize.Level2)
{
    std::string url = R"(http：：：/\\\中文测试：8080?中文数据)";
    std::string hostname = GetHostnameFromURL(url);
    EXPECT_STREQ(hostname.c_str(), "http：：：");
}

HWTEST_F(NetStackCommonUtilsTest, GetHostnameFromURL46, TestSize.Level2)
{
    std::string url = R"(（）“”{}P{{}:\、、、})";
    std::string hostname = GetHostnameFromURL(url);
    EXPECT_STREQ(hostname.c_str(), "（）“”{}P{{}");
}

HWTEST_F(NetStackCommonUtilsTest, GetHostnameFromURL47, TestSize.Level2)
{
    std::string url = R"(（）“”{}P{http://{}:\、、、})";
    std::string hostname = GetHostnameFromURL(url);
    EXPECT_STREQ(hostname.c_str(), "{}");
}

HWTEST_F(NetStackCommonUtilsTest, GetHostnameFromURL48, TestSize.Level2)
{
    std::string url = R"(（）“===\\///?=”{}P{{的‘；‘’；’}:\、、、})";
    std::string hostname = GetHostnameFromURL(url);
    EXPECT_STREQ(hostname.c_str(), "（）“===");
}

HWTEST_F(NetStackCommonUtilsTest, GetHostnameFromURL49, TestSize.Level2)
{
    std::string url = R"(（）“”{}P{{；‘k:’}:\、、、})";
    std::string hostname = GetHostnameFromURL(url);
    EXPECT_STREQ(hostname.c_str(), "（）“”{}P{{；‘k");
}

HWTEST_F(NetStackCommonUtilsTest, GetHostnameFromURL50, TestSize.Level2)
{
    std::string url = R"(（）“”{}P{0%%%VVV{}:\、、、})";
    std::string hostname = GetHostnameFromURL(url);
    EXPECT_STREQ(hostname.c_str(), "（）“”{}P{0%%%VVV{}");
}
} // namespace CommonUtils
} // namespace NetStack
} // namespace OHOS