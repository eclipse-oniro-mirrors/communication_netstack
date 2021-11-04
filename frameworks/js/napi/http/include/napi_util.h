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

#ifndef HTTP_NAPI_NAPI_UTIL_H
#define HTTP_NAPI_NAPI_UTIL_H

#include <string>
#include <tuple>
#include <type_traits>
#include <vector>

#include "napi/native_api.h"
#include "napi/native_node_api.h"

namespace OHOS {
namespace NetManagerStandard {
using vecNapiType = std::vector<napi_valuetype>;
constexpr int32_t MAX_CHAR_LENGTH = 64;
constexpr int32_t ERROR_DEFAULT = -1;
constexpr int32_t maxUrlLength = 1024;
constexpr int32_t SWITCH_PARAM_ZERO = 1;
constexpr int32_t SWITCH_PARAM_ONE = 1;
constexpr int32_t SWITCH_PARAM_TWO = 2;
constexpr int32_t SWITCH_PARAM_THREE = 3;

class NapiUtil {
public:
    static const int32_t MAX_TEXT_LENGTH = 4096;
    static std::string ToUtf8(std::u16string str16);
    static std::u16string ToUtf16(std::string str);
    static napi_value CreateErrorMessage(napi_env env, std::string message, int32_t errorCode = ERROR_DEFAULT);
    static napi_value CreateUndefined(napi_env env);
    static bool MatchValueType(napi_env env, napi_value value, napi_valuetype targetType);
    static bool MatchParameters(
        napi_env env, const napi_value parameters[], std::initializer_list<napi_valuetype> valueTypes);
    static void SetPropertyInt32(napi_env env, napi_value object, std::string name, int32_t value);
    static void SetPropertyStringUtf8(napi_env env, napi_value object, std::string name, std::string value);
    static void SetPropertyBoolean(napi_env env, napi_value object, std::string name, bool value);
    static napi_value ToInt32Value(napi_env env, int value);
    static bool HasNamedProperty(napi_env env, napi_value object, std::string propertyName);
    static bool HasNamedTypeProperty(
        napi_env env, napi_value object, napi_valuetype type, std::string propertyName);
    static bool MatchObjectProperty(
        napi_env env, napi_value object, std::initializer_list<std::pair<std::string, napi_valuetype>> pairList);
    static bool MatchOptionPropertyType(
        napi_env env, napi_value object, napi_valuetype type, std::string propertyName);
    static std::string GetStringFromValue(napi_env env, napi_value value);
    static napi_value GetNamedProperty(napi_env env, napi_value object, std::string propertyName);
    static bool MatchHttpRequestDataParameters(napi_env env, const napi_value parameters[], size_t parameterCount);
    static bool MatchHttpOnDataParameters(napi_env env, const napi_value parameters[], size_t parameterCount);
    static bool MatchHttpOffDataParameters(napi_env env, const napi_value parameters[], size_t parameterCount);
    static void SetPropertyArray(napi_env env, napi_value object, std::string name, std::vector<std::string> pdu);
    static int32_t GetIntProperty(napi_env env, napi_value object, const std::string &propertyName);
    static std::string GetStringProperty(napi_env env, napi_value object, const std::string &propertyName);
};

template<typename... Ts>
bool MatchParameters(
    napi_env env, const napi_value argv[], size_t argc, std::tuple<Ts...> &theTuple, const vecNapiType &typeStd)
{
    bool typeMatched = false;
    if (argc == typeStd.size()) {
        vecNapiType paraType;
        paraType.reserve(argc);
        for (size_t i = 0; i < argc; i++) {
            napi_valuetype valueType = napi_undefined;
            napi_typeof(env, argv[i], &valueType);
            paraType.emplace_back(valueType);
        }

        if (paraType == typeStd) {
            std::apply(
                [env, argc, &argv](Ts &...tupleArgs) {
                    size_t index {0};
                    ((index < argc ? NapiValueConverted(env, argv[index++], tupleArgs) : napi_ok), ...);
                },
                theTuple);
            typeMatched = true;
        }
    }
    return typeMatched;
}
} // namespace NetManagerStandard
} // namespace OHOS
#endif // NAPI_UTIL_H