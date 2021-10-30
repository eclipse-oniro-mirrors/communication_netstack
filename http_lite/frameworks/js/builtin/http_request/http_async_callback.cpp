/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "http_async_callback.h"
#include "http_request.h"
#include "http_request_utils.h"
#include "securec.h"
#include <algorithm>
#include <memory>

template <typename T> void DefaultDelete(T *ptr)
{
    HTTP_REQUEST_INFO("delete %s", typeid(ptr).name());
    delete ptr;
}

namespace OHOS {
namespace ACELite {

HttpAsyncCallback::HttpAsyncCallback(const RequestData *&requestData, JSIValue responseCallback, JSIValue thisVal)
{
    this->requestData = const_cast<RequestData *>(requestData);
    this->responseCallback = responseCallback;
    this->thisVal = thisVal;
}

void HttpAsyncCallback::AsyncExecHttpRequest(void *data)
{
    std::unique_ptr<HttpAsyncCallback, decltype(&DefaultDelete<HttpAsyncCallback>)> asyncCallback(
        static_cast<HttpAsyncCallback *>(data), DefaultDelete<HttpAsyncCallback>);
    if (asyncCallback == nullptr) {
        return;
    }
    std::unique_ptr<RequestData, decltype(&DefaultDelete<RequestData>)> requestData(asyncCallback->requestData,
                                                                                    DefaultDelete<RequestData>);
    if (requestData == nullptr) {
        return;
    }

    ResponseData responseData;
    bool success = HttpRequest::Request(requestData.get(), &responseData);
    std::unique_ptr<JSIVal, decltype(&JSI::ReleaseValue)> responseCallback(asyncCallback->responseCallback,
                                                                           JSI::ReleaseValue);
    if (responseCallback == nullptr || JSI::ValueIsUndefined(responseCallback.get()) ||
        !JSI::ValueIsObject(responseCallback.get())) {
        if (success) {
            HTTP_REQUEST_INFO("http status line: %s", responseData.GetStatusLine().c_str());
        }
        return;
    }

    if (success) {
        asyncCallback->OnSuccess(responseData);
    } else {
        asyncCallback->OnFail(responseData.GetErrString().c_str(), responseData.GetCode());
    }
    asyncCallback->OnComplete();
}

JSIValue HttpAsyncCallback::ResponseDataToJsValue(const ResponseData &responseData)
{
    JSIValue object = JSI::CreateObject();
    if (object == nullptr) {
        return nullptr;
    }

    JSI::SetNumberProperty(object, HttpConstant::KEY_HTTP_RESPONSE_CODE, responseData.GetCode());

    HTTP_REQUEST_INFO("response body size = %zu", responseData.GetData().size());
    std::string responseType = requestData->GetResponseType();
    std::transform(responseType.begin(), responseType.end(), responseType.begin(), tolower);

    if (responseType == HttpConstant::HTTP_RESPONSE_TYPE_JSON) {
        std::unique_ptr<JSIVal, decltype(&JSI::ReleaseValue)> jsonObj(JSI::JsonParse(responseData.GetData().c_str()),
                                                                      JSI::ReleaseValue);
        if (jsonObj != nullptr && !JSI::ValueIsUndefined(jsonObj.get()) && JSI::ValueIsObject(jsonObj.get())) {
            JSI::SetNamedProperty(object, HttpConstant::KEY_HTTP_RESPONSE_DATA, jsonObj.get());
        }
    } else {
        JSI::SetStringProperty(object, HttpConstant::KEY_HTTP_RESPONSE_DATA, responseData.GetData().c_str(),
                               responseData.GetData().size());
    }

    std::unique_ptr<JSIVal, decltype(&JSI::ReleaseValue)> headers(JSI::CreateObject(), JSI::ReleaseValue);
    if (headers == nullptr) {
        JSI::ReleaseValue(object);
    }
    for (const auto &p : responseData.GetHeaders()) {
        JSI::SetStringProperty(headers.get(), p.first.c_str(), p.second.c_str());
    }
    JSI::SetNamedProperty(object, HttpConstant::KEY_HTTP_RESPONSE_HEADERS, headers.get());

    return object;
}

void HttpAsyncCallback::OnSuccess(const ResponseData &responseData)
{
    std::unique_ptr<JSIVal, decltype(&JSI::ReleaseValue)> success(JSI::GetNamedProperty(responseCallback, CB_SUCCESS),
                                                                  JSI::ReleaseValue);
    if (success == nullptr || JSI::ValueIsUndefined(success.get()) || !JSI::ValueIsFunction(success.get())) {
        return;
    }

    std::unique_ptr<JSIVal, decltype(&JSI::ReleaseValue)> obj(ResponseDataToJsValue(responseData), JSI::ReleaseValue);
    if (obj == nullptr || JSI::ValueIsUndefined(obj.get()) || !JSI::ValueIsObject(obj.get())) {
        return;
    }

    JSIValue arg[ARGC_ONE] = {obj.get()};
    JSI::CallFunction(success.get(), thisVal, arg, ARGC_ONE);
}

void HttpAsyncCallback::OnFail(const char *errData, int32_t errCode)
{
    std::unique_ptr<JSIVal, decltype(&JSI::ReleaseValue)> fail(JSI::GetNamedProperty(responseCallback, CB_FAIL),
                                                               JSI::ReleaseValue);
    if (fail == nullptr || JSI::ValueIsUndefined(fail.get()) || !JSI::ValueIsFunction(fail.get())) {
        return;
    }
    std::unique_ptr<JSIVal, decltype(&JSI::ReleaseValue)> errInfo(JSI::CreateString(errData), JSI::ReleaseValue);
    std::unique_ptr<JSIVal, decltype(&JSI::ReleaseValue)> retCode(JSI::CreateNumber(errCode), JSI::ReleaseValue);

    JSIValue argv[ARGC_TWO] = {errInfo.get(), retCode.get()};
    JSI::CallFunction(fail.get(), thisVal, argv, ARGC_TWO);
}

void HttpAsyncCallback::OnComplete()
{
    std::unique_ptr<JSIVal, decltype(&JSI::ReleaseValue)> complete(JSI::GetNamedProperty(responseCallback, CB_COMPLETE),
                                                                   JSI::ReleaseValue);
    if (complete == nullptr || JSI::ValueIsUndefined(complete.get()) || !JSI::ValueIsFunction(complete.get())) {
        return;
    }
    JSI::CallFunction(complete.get(), thisVal, nullptr, 0);
}

} // namespace ACELite
} // namespace OHOS
