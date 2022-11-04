/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "request_context.h"

#include <algorithm>

#include "constant.h"
#include "http_exec.h"
#include "napi_utils.h"
#include "netstack_common_utils.h"
#include "netstack_log.h"

static constexpr const int PARAM_JUST_URL = 1;

static constexpr const int PARAM_URL_AND_OPTIONS_OR_CALLBACK = 2;

static constexpr const int PARAM_URL_AND_OPTIONS_AND_CALLBACK = 3;

namespace OHOS::NetStack {
static std::map<RequestContext *, napi_env> ENV_MAP;

RequestContext::RequestContext(napi_env env, EventManager *manager) : BaseContext(env, manager), usingCache_(true)
{
    ENV_MAP[this] = env;
}

napi_env RequestContext::GetEnv()
{
    return ENV_MAP[this];
}

void RequestContext::ParseParams(napi_value *params, size_t paramsCount)
{
    bool valid = CheckParamsType(params, paramsCount);
    if (!valid) {
        return;
    }

    if (paramsCount == PARAM_JUST_URL) {
        options.SetUrl(NapiUtils::GetStringFromValueUtf8(GetEnv(), params[0]));
        SetParseOK(true);
        return;
    }

    if (paramsCount == PARAM_URL_AND_OPTIONS_OR_CALLBACK) {
        napi_valuetype type = NapiUtils::GetValueType(GetEnv(), params[1]);
        if (type == napi_function) {
            options.SetUrl(NapiUtils::GetStringFromValueUtf8(GetEnv(), params[0]));
            SetParseOK(SetCallback(params[1]) == napi_ok);
            return;
        }
        if (type == napi_object) {
            UrlAndOptions(params[0], params[1]);
            return;
        }
        return;
    }

    if (paramsCount == PARAM_URL_AND_OPTIONS_AND_CALLBACK) {
        if (SetCallback(params[PARAM_URL_AND_OPTIONS_AND_CALLBACK - 1]) != napi_ok) {
            return;
        }
        UrlAndOptions(params[0], params[1]);
    }
}

bool RequestContext::CheckParamsType(napi_value *params, size_t paramsCount)
{
    if (paramsCount == PARAM_JUST_URL) {
        // just url
        return NapiUtils::GetValueType(GetEnv(), params[0]) == napi_string;
    }
    if (paramsCount == PARAM_URL_AND_OPTIONS_OR_CALLBACK) {
        // should be url, callback or url, options
        napi_valuetype type = NapiUtils::GetValueType(GetEnv(), params[1]);
        return NapiUtils::GetValueType(GetEnv(), params[0]) == napi_string &&
               (type == napi_function || type == napi_object);
    }
    if (paramsCount == PARAM_URL_AND_OPTIONS_AND_CALLBACK) {
        // should be url options and callback
        return NapiUtils::GetValueType(GetEnv(), params[0]) == napi_string &&
               NapiUtils::GetValueType(GetEnv(), params[1]) == napi_object &&
               NapiUtils::GetValueType(GetEnv(), params[PARAM_URL_AND_OPTIONS_AND_CALLBACK - 1]) == napi_function;
    }
    return false;
}

void RequestContext::ParseNumberOptions(napi_value optionsValue)
{
    options.SetReadTimeout(NapiUtils::GetUint32Property(GetEnv(), optionsValue, HttpConstant::PARAM_KEY_READ_TIMEOUT));
    if (options.GetReadTimeout() == 0) {
        options.SetReadTimeout(HttpConstant::DEFAULT_READ_TIMEOUT);
    }

    options.SetConnectTimeout(
        NapiUtils::GetUint32Property(GetEnv(), optionsValue, HttpConstant::PARAM_KEY_CONNECT_TIMEOUT));
    if (options.GetConnectTimeout() == 0) {
        options.SetConnectTimeout(HttpConstant::DEFAULT_CONNECT_TIMEOUT);
    }

    if (NapiUtils::HasNamedProperty(GetEnv(), optionsValue, HttpConstant::PARAM_KEY_USING_CACHE)) {
        napi_value value = NapiUtils::GetNamedProperty(GetEnv(), optionsValue, HttpConstant::PARAM_KEY_USING_CACHE);
        if (NapiUtils::GetValueType(GetEnv(), value) == napi_boolean) {
            usingCache_ = NapiUtils::GetBooleanFromValue(GetEnv(), value);
        }
    }

    if (NapiUtils::HasNamedProperty(GetEnv(), optionsValue, HttpConstant::PARAM_KEY_USING_PROTOCOL)) {
        napi_value value = NapiUtils::GetNamedProperty(GetEnv(), optionsValue, HttpConstant::PARAM_KEY_USING_PROTOCOL);
        if (NapiUtils::GetValueType(GetEnv(), value) == napi_number) {
            uint32_t number = NapiUtils::GetUint32FromValue(GetEnv(), value);
            if (number == static_cast<uint32_t>(HttpProtocol::HTTP1_1) ||
                number == static_cast<uint32_t>(HttpProtocol::HTTP2)) {
                options.SetUsingProtocol(static_cast<HttpProtocol>(number));
            }
        }
    }
    if (NapiUtils::HasNamedProperty(GetEnv(), optionsValue, HttpConstant::PARAM_KEY_EXPECT_DATA_TYPE)) {
        napi_value value =
            NapiUtils::GetNamedProperty(GetEnv(), optionsValue, HttpConstant::PARAM_KEY_EXPECT_DATA_TYPE);
        if (NapiUtils::GetValueType(GetEnv(), value) == napi_number) {
            uint32_t type = NapiUtils::GetUint32FromValue(GetEnv(), value);
            options.SetHttpDataType(static_cast<HttpDataType>(type));
        }
    }

    if (NapiUtils::HasNamedProperty(GetEnv(), optionsValue, HttpConstant::PARAM_KEY_PRIORITY)) {
        napi_value value = NapiUtils::GetNamedProperty(GetEnv(), optionsValue, HttpConstant::PARAM_KEY_PRIORITY);
        if (NapiUtils::GetValueType(GetEnv(), value) == napi_number) {
            uint32_t priority = NapiUtils::GetUint32FromValue(GetEnv(), value);
            options.SetPriority(priority);
        }
    }
}

void RequestContext::ParseHeader(napi_value optionsValue)
{
    if (!NapiUtils::HasNamedProperty(GetEnv(), optionsValue, HttpConstant::PARAM_KEY_HEADER)) {
        return;
    }
    napi_value header = NapiUtils::GetNamedProperty(GetEnv(), optionsValue, HttpConstant::PARAM_KEY_HEADER);
    if (NapiUtils::GetValueType(GetEnv(), header) != napi_object) {
        return;
    }
    auto names = NapiUtils::GetPropertyNames(GetEnv(), header);
    std::for_each(names.begin(), names.end(), [header, this](const std::string &name) {
        auto value = NapiUtils::GetStringPropertyUtf8(GetEnv(), header, name);
        if (!value.empty()) {
            options.SetHeader(CommonUtils::ToLower(name), value);
        }
    });
}

bool RequestContext::ParseExtraData(napi_value optionsValue)
{
    if (!NapiUtils::HasNamedProperty(GetEnv(), optionsValue, HttpConstant::PARAM_KEY_EXTRA_DATA)) {
        NETSTACK_LOGI("no extraData");
        return true;
    }
    napi_value extraData = NapiUtils::GetNamedProperty(GetEnv(), optionsValue, HttpConstant::PARAM_KEY_EXTRA_DATA);

    if (HttpExec::MethodForGet(options.GetMethod())) {
        std::string url = options.GetUrl();
        std::string param;
        auto index = url.find(HttpConstant::HTTP_URL_PARAM_START);
        if (index != std::string::npos) {
            param = url.substr(index + 1);
            url.resize(index);
        }

        napi_valuetype type = NapiUtils::GetValueType(GetEnv(), extraData);
        if (type == napi_string) {
            std::string extraParam = NapiUtils::GetStringFromValueUtf8(GetEnv(), extraData);

            options.SetUrl(HttpExec::MakeUrl(url, param, extraParam));
            return true;
        }
        if (type != napi_object) {
            return true;
        }

        std::string extraParam;
        auto names = NapiUtils::GetPropertyNames(GetEnv(), extraData);
        std::for_each(names.begin(), names.end(), [this, extraData, &extraParam](std::string name) {
            auto value = NapiUtils::GetStringPropertyUtf8(GetEnv(), extraData, name);
            NETSTACK_LOGI("url param name = ..., value = ...");
            if (!name.empty() && !value.empty()) {
                bool encodeName = HttpExec::EncodeUrlParam(name);
                bool encodeValue = HttpExec::EncodeUrlParam(value);
                if (encodeName || encodeValue) {
                    options.SetHeader(CommonUtils::ToLower(HttpConstant::HTTP_CONTENT_TYPE),
                                      HttpConstant::HTTP_CONTENT_TYPE_URL_ENCODE);
                }
                extraParam +=
                    name + HttpConstant::HTTP_URL_NAME_VALUE_SEPARATOR + value + HttpConstant::HTTP_URL_PARAM_SEPARATOR;
            }
        });
        if (!extraParam.empty()) {
            extraParam.pop_back(); // remove the last &
        }

        options.SetUrl(HttpExec::MakeUrl(url, param, extraParam));
        return true;
    }

    if (HttpExec::MethodForPost(options.GetMethod())) {
        return GetRequestBody(extraData);
    }
    return false;
}

bool RequestContext::GetRequestBody(napi_value extraData)
{
    /* if body is empty, return false, or curl will wait for body */

    napi_valuetype type = NapiUtils::GetValueType(GetEnv(), extraData);
    if (type == napi_string) {
        auto body = NapiUtils::GetStringFromValueUtf8(GetEnv(), extraData);
        if (body.empty()) {
            return false;
        }
        options.SetBody(body.c_str(), body.size());
        return true;
    }

    if (NapiUtils::ValueIsArrayBuffer(GetEnv(), extraData)) {
        size_t length = 0;
        void *data = NapiUtils::GetInfoFromArrayBufferValue(GetEnv(), extraData, &length);
        if (data == nullptr) {
            return false;
        }
        options.SetBody(data, length);
        return true;
    }

    if (type == napi_object) {
        std::string body = NapiUtils::GetStringFromValueUtf8(GetEnv(), NapiUtils::JsonStringify(GetEnv(), extraData));
        if (body.empty()) {
            return false;
        }
        options.SetBody(body.c_str(), body.length());
        return true;
    }

    NETSTACK_LOGE("only support string arraybuffer and object");
    return false;
}

void RequestContext::UrlAndOptions(napi_value urlValue, napi_value optionsValue)
{
    options.SetUrl(NapiUtils::GetStringFromValueUtf8(GetEnv(), urlValue));

    std::string method = NapiUtils::GetStringPropertyUtf8(GetEnv(), optionsValue, HttpConstant::PARAM_KEY_METHOD);
    if (method.empty()) {
        method = HttpConstant::HTTP_METHOD_GET;
    }
    options.SetMethod(method);

    ParseHeader(optionsValue);
    ParseNumberOptions(optionsValue);

    /* parse extra data here to recover header */

    SetParseOK(ParseExtraData(optionsValue));
}

bool RequestContext::IsUsingCache() const
{
    return usingCache_;
}
} // namespace OHOS::NetStack
