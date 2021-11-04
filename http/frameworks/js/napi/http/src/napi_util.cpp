/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#include "napi_util.h"

#include <codecvt>
#include <cstdio>
#include <locale>
#include <vector>
#include <memory>

#include "netmgr_log_wrapper.h"

namespace OHOS {
namespace NetManagerStandard {

std::string NapiUtil::ToUtf8(std::u16string str16)
{
    return std::wstring_convert<std::codecvt_utf8_utf16<char16_t>, char16_t> {}.to_bytes(str16);
}

std::u16string NapiUtil::ToUtf16(std::string str)
{
    return std::wstring_convert<std::codecvt_utf8_utf16<char16_t>, char16_t> {}.from_bytes(str);
}

napi_value NapiUtil::CreateErrorMessage(napi_env env, std::string msg, int32_t errorCode)
{
    napi_value result = nullptr;
    napi_value message = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, msg.c_str(), msg.length(), &message));
    napi_value codeValue = nullptr;
    std::string errCode = std::to_string(errorCode);
    NAPI_CALL(env, napi_create_string_utf8(env, errCode.c_str(), errCode.length(), &codeValue));
    NAPI_CALL(env, napi_create_error(env, codeValue, message, &result));
    return result;
}

napi_value NapiUtil::CreateUndefined(napi_env env)
{
    napi_value result = nullptr;
    NAPI_CALL(env, napi_get_undefined(env, &result));
    return result;
}

bool NapiUtil::MatchValueType(napi_env env, napi_value value, napi_valuetype targetType)
{
    napi_valuetype valueType = napi_undefined;
    NAPI_CALL_BASE(env, napi_typeof(env, value, &valueType), false);
    return valueType == targetType;
}

bool NapiUtil::MatchParameters(
    napi_env env, const napi_value parameters[], std::initializer_list<napi_valuetype> valueTypes)
{
    if (parameters == nullptr) {
        return false;
    }
    int i = 0;
    for (auto beg = valueTypes.begin(); beg != valueTypes.end(); ++beg) {
        if (!MatchValueType(env, parameters[i], *beg)) {
            return false;
        }
        ++i;
    }
    return true;
}

void NapiUtil::SetPropertyInt32(napi_env env, napi_value object, std::string name, int32_t value)
{
    napi_value propertyValue = nullptr;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, value, &propertyValue));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, object, name.c_str(), propertyValue));
}

void NapiUtil::SetPropertyStringUtf8(napi_env env, napi_value object, std::string name, std::string value)
{
    napi_value propertyValue = nullptr;
    char *valueChars = (char *)value.c_str();
    NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, valueChars, std::strlen(valueChars), &propertyValue));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, object, name.c_str(), propertyValue));
}

void NapiUtil::SetPropertyBoolean(napi_env env, napi_value object, std::string name, bool value)
{
    napi_value propertyValue = nullptr;
    NAPI_CALL_RETURN_VOID(env, napi_get_boolean(env, value, &propertyValue));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, object, name.c_str(), propertyValue));
}

napi_value NapiUtil::ToInt32Value(napi_env env, int32_t value)
{
    napi_value staticValue = nullptr;
    NAPI_CALL(env, napi_create_int32(env, value, &staticValue));
    return staticValue;
}

bool NapiUtil::HasNamedProperty(napi_env env, napi_value object, std::string propertyName)
{
    bool hasProperty = false;
    NAPI_CALL_BASE(env, napi_has_named_property(env, object, propertyName.data(), &hasProperty), false);
    return hasProperty;
}

bool NapiUtil::HasNamedTypeProperty(napi_env env, napi_value object, napi_valuetype type, std::string propertyName)
{
    bool hasProperty = false;
    NAPI_CALL_BASE(env, napi_has_named_property(env, object, propertyName.data(), &hasProperty), false);
    if (hasProperty) {
        napi_value value = nullptr;
        NAPI_CALL_BASE(env, napi_get_named_property(env, object, propertyName.data(), &value), false);
        return MatchValueType(env, value, type);
    }
    return false;
}

bool NapiUtil::MatchObjectProperty(
    napi_env env, napi_value object, std::initializer_list<std::pair<std::string, napi_valuetype>> pairList)
{
    if (object == nullptr) {
        return false;
    }
    for (auto beg = pairList.begin(); beg != pairList.end(); ++beg) {
        if (!HasNamedTypeProperty(env, object, beg->second, beg->first)) {
            return false;
        }
    }
    return true;
}

bool NapiUtil::MatchOptionPropertyType(
    napi_env env, napi_value object, napi_valuetype type, std::string propertyName)
{
    bool hasProperty = false;
    NAPI_CALL_BASE(env, napi_has_named_property(env, object, propertyName.data(), &hasProperty), false);
    if (hasProperty) {
        napi_value value = nullptr;
        NAPI_CALL_BASE(env, napi_get_named_property(env, object, propertyName.data(), &value), false);
        return MatchValueType(env, value, type);
    }
    return true;
}

std::string NapiUtil::GetStringFromValue(napi_env env, napi_value value)
{
    char msgChars[MAX_TEXT_LENGTH] = {0};
    size_t msgLength = 0;
    NAPI_CALL_BASE(env, napi_get_value_string_utf8(env, value, msgChars, MAX_TEXT_LENGTH, &msgLength), "");
    NETMGR_LOGD("NapiUtil GetStringFromValue msgLength = %{public}d", msgLength);
    if (msgLength > 0) {
        return std::string(msgChars, 0, msgLength);
    } else {
        return "";
    }
}

napi_value NapiUtil::GetNamedProperty(napi_env env, napi_value object, std::string propertyName)
{
    napi_value value = nullptr;
    NAPI_CALL(env, napi_get_named_property(env, object, propertyName.data(), &value));
    return value;
}

bool NapiUtil::MatchHttpRequestDataParameters(napi_env env, const napi_value parameters[], size_t parameterCount)
{
    switch (parameterCount) {
        case 0:
            return true;
        case 1:
            return MatchParameters(env, parameters, {napi_string});
        case 2:
            if (MatchParameters(env, parameters, {napi_string, napi_function})
                 || MatchParameters(env, parameters, {napi_string, napi_object})) {
                return true;
            }
            return false;
        case 3:
            return MatchParameters(env, parameters, {napi_string, napi_object, napi_function});
        default:
            return false;
    }
}
bool NapiUtil::MatchHttpOnDataParameters(napi_env env, const napi_value parameters[], size_t parameterCount)
{
    switch (parameterCount) {
        case 0:
            return true;
        case 1:
            return false;
        case 2:
            return MatchParameters(env, parameters, {napi_string, napi_function});
        default:
            return false;
    }
}
bool NapiUtil::MatchHttpOffDataParameters(napi_env env, const napi_value parameters[], size_t parameterCount)
{
    switch (parameterCount) {
        case 0:
            return true;
        case 1:
            return MatchParameters(env, parameters, {napi_string});
        case 2:
            return MatchParameters(env, parameters, {napi_string, napi_function});
        default:
            return false;
    }
}
void NapiUtil::SetPropertyArray(napi_env env, napi_value object, std::string name, std::vector<std::string> pdu)
{
    napi_value array = nullptr;
    napi_create_array(env, &array);
    int size = pdu.size();
    for (int i = 0; i < size; i++) {
        napi_value element = nullptr;
        std::string tmp = pdu.at(i);
        napi_create_string_utf8(env, tmp.c_str(), tmp.size(), &element);
        napi_set_element(env, array, i, element);
    }
    napi_set_named_property(env, object, name.c_str(), array);
}
int32_t NapiUtil::GetIntProperty(napi_env env, napi_value object, const std::string &propertyName)
{
    int32_t intValue = 0;
    napi_value value = nullptr;
    napi_status getNameStatus = napi_get_named_property(env, object, propertyName.c_str(), &value);
    if (getNameStatus == napi_ok) {
        napi_status getIntStatus = napi_get_value_int32(env, value, &intValue);
        if (getIntStatus == napi_ok) {
            return intValue;
        }
    }
    return intValue;
}
std::string NapiUtil::GetStringProperty(napi_env env, napi_value object, const std::string &propertyName)
{
    napi_value value = nullptr;
    napi_status getNameStatus = napi_get_named_property(env, object, propertyName.c_str(), &value);
    if (getNameStatus == napi_ok) {
        char buf[maxUrlLength] = {0};
        size_t bufLength = 0;
        napi_status getStringStatus = napi_get_value_string_utf8(env, value, buf, maxUrlLength, &bufLength);
        if (getStringStatus == napi_ok && bufLength > 0) {
            return std::string(buf, bufLength);
        }
    }
    return "";
}
} // namespace NetManagerStandard
} // namespace OHOS