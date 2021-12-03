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

#include "http_request.h"
#include "http_event_list.h"
#include "http_napi.h"
#include "napi_util.h"

#include <unistd.h>

namespace OHOS {
namespace NetManagerStandard {
std::string URL_SEPARATOR = "?";
std::string URL_DELIMITER = "&";
constexpr int32_t HEADER_OFFSET = 2;

HttpRequest::HttpRequest()
{
    headers_.clear();
    Initialize();
}

HttpRequest::~HttpRequest()
{
    curl_global_cleanup();
}
/*
 * Init curl all thread only
 */
bool HttpRequest::Initialize()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (initialized_) {
        return true;
    }

    if (curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
        NETMGR_LOGE("curl global init failed");
        return false;
    }
    return true;
}

void HttpRequest::SetHeaders(std::string headersStr)
{
    if (headersStr.empty()) {
        headers_.clear();
        return;
    }

    const char separator = '\n';
    size_t posSeparator = headersStr.find(separator);
    while (std::string::npos != posSeparator) {
        std::string header = headersStr.substr(0, posSeparator - 1);
        if (header == "") {
            break;
        }
        size_t posColon = header.find(':');
        if (std::string::npos == posColon) {
            headers_["null"] = "[\"" + header + "\"]";
        } else {
            headers_["\"" + header.substr(0, posColon) + "\""] = "[\"" + header.substr(posColon
                + HEADER_OFFSET) + "\"]";
        }
        headersStr = headersStr.substr(posSeparator + 1);
        posSeparator = headersStr.find(separator);
    }
}

void HttpRequest::SetHeader(CURL *curl)
{
    struct curl_slist *header = nullptr;
    if (!headers_.empty()) {
        std::map<std::string, std::string>::iterator iter;
        for (iter = headers_.begin(); iter != headers_.end(); iter++) {
            header = curl_slist_append(header, (iter->first + ":" + iter->second).c_str());
        }
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, header);
    }
}

void HttpRequest::SetOptionURL(CURL *curl, HttpRequestOptionsContext *asyncContext)
{
    if (curl == nullptr || asyncContext == nullptr) {
        NETMGR_LOGE("The parameter of curl or asyncContext is nullptr");
        return;
    }
    std::string url(asyncContext->GetUrl());

    std::size_t index = url.find(URL_SEPARATOR);
    std::string caFile(asyncContext->GetCaFile());
    bool isCaFile = IsCaFile(caFile);
    if (index != std::string::npos) {
        int32_t offset = url.rfind(URL_SEPARATOR);
        std::string uri = url.substr(0, offset);
        std::string param = url.substr(offset + 1);

        curl_easy_setopt(curl, CURLOPT_URL, uri.c_str());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, param.c_str());
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, true);
        curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);
        if (url.substr(0, URL_PREFIX_LENGTH) == std::string("https://")) {
            if (!isCaFile) {
                curl_easy_setopt(curl, CURLOPT_CAINFO, "/etc/ssl/cacert.pem");
            } else {
                curl_easy_setopt(curl, CURLOPT_CAINFO, caFile.c_str());
            }
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        }
    } else {
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, true);
        curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);
        if (url.substr(0, URL_PREFIX_LENGTH) == std::string("https://")) {
            if (!isCaFile) {
                curl_easy_setopt(curl, CURLOPT_CAINFO, "/etc/ssl/cacert.pem");
            } else {
                curl_easy_setopt(curl, CURLOPT_CAINFO, caFile.c_str());
            }
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        }
    }

    curl_easy_setopt(curl, CURLOPT_HEADER, 0L);
    curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1L);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, asyncContext->GetConnectTimeout());
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, asyncContext->GetReadTimeout());
}

void HttpRequest::SetMethod(CURL *curl, HttpRequestOptionsContext *asyncContext)
{
    if (curl == nullptr || asyncContext == nullptr) {
        NETMGR_LOGE("The parameter of curl or asyncContext is nullptr");
        return;
    }
    RequestMethod method = asyncContext->GetRequestMethod();
    if (method == RequestMethod::OPTIONS || method == RequestMethod::GET || method == RequestMethod::HEAD
        || method == RequestMethod::DELETE || method == RequestMethod::TRACE || method == RequestMethod::CONNECT) {
        SetOptionForGet(curl, asyncContext);
    } else if (method == RequestMethod::POST || method == RequestMethod::PUT) {
        SetOptionForPost(curl, asyncContext);
    } else {
        NETMGR_LOGE("SetMethod ErrorCode : COMMON_ERROR_CODE");
    }
}

bool HttpRequest::SetOptionForPost(CURL *curl, HttpRequestOptionsContext *asyncContext)
{
    if (curl == nullptr || asyncContext == nullptr) {
        NETMGR_LOGE("The parameter of curl or asyncContext is nullptr");
        return false;
    }
    HTTP_CURL_EASY_SET_OPTION(curl, CURLOPT_URL, asyncContext->GetUrl().c_str());
    HTTP_CURL_EASY_SET_OPTION(curl, CURLOPT_POST, 1L);
    return true;
}

bool HttpRequest::SetOptionForGet(CURL *curl, HttpRequestOptionsContext *asyncContext)
{
    if (curl == nullptr || asyncContext == nullptr) {
        NETMGR_LOGE("The parameter of curl or asyncContext is nullptr");
        return false;
    }

    std::string url(asyncContext->GetUrl());
    if (!asyncContext->GetExtraData().empty()) {
        std::size_t index = url.find(URL_SEPARATOR);
        if (index != std::string::npos) {
            std::string param = url.substr(0, url.rfind(URL_SEPARATOR) + 1);
            std::string encodeIn = param + URL_DELIMITER + asyncContext->GetExtraData();
            char *encodeOut = curl_easy_escape(curl, encodeIn.c_str(), 0);
            if (encodeOut != nullptr) {
                url = param + encodeOut;
                curl_free(encodeOut);
            }
        } else {
            char *encodeOut = curl_easy_escape(curl, asyncContext->GetExtraData().c_str(), 0);
            if (encodeOut != nullptr) {
                url = url + URL_SEPARATOR + encodeOut;
                curl_free(encodeOut);
            }
        }
        HTTP_CURL_EASY_SET_OPTION(curl, CURLOPT_URL, url.c_str());
    } else {
        std::size_t index = url.find(URL_SEPARATOR);
        if (index != std::string::npos) {
            int32_t offset = url.rfind(URL_SEPARATOR);
            std::string uri = url.substr(0, offset);
            std::string param = url.substr(offset + 1);
            curl_easy_setopt(curl, CURLOPT_URL, uri.c_str());
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, param.c_str());
            curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, true);
            curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);
        }
    }

    return true;
}

bool HttpRequest::GetCurlWriteData(HttpRequestOptionsContext *asyncContext)
{
    if (asyncContext == nullptr) {
        return false;
    }

    CURL *curl = curl_easy_init();
    if (curl == nullptr) {
        NETMGR_LOGE("The parameter of curl is nullptr");
        return false;
    }
    SetOptionURL(curl, asyncContext);

    std::string responseBody;
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, OnWritingMemoryBody);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &responseBody);

    std::string responseHeader;
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, OnWritingMemoryHeader);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, &responseHeader);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "libcurl-agent/1.0");

    int32_t responseCode;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &responseCode);

    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        NETMGR_LOGE("curl easy perform error : %{public}s, num: %{public}d", curl_easy_strerror(res), res);
        curl_easy_cleanup(curl);
        return false;
    }
    HttpResponse responseData = asyncContext->GetResponseData();
    responseData.SetResult(responseBody);
    responseData.SetHeader(responseHeader);
    responseData.SetResponseCode((enum ResponseCode)responseCode);

    asyncContext->SetResponseData(responseData);
    EmitHeader(asyncContext->httpRequestInfo_, responseHeader);

    curl_easy_cleanup(curl);
    return true;
}

void HttpRequest::EmitHeader(HttpRequest *obj, const std::string &header)
{
    struct EventListener *eventListener = nullptr;
    for (std::list<EventListener>::iterator listenerIterator = g_eventListenerList.begin();
         listenerIterator != g_eventListenerList.end(); ++listenerIterator) {
        if (listenerIterator->httpRequestInfo_ == obj) {
            struct EventListener eventListtmp = *listenerIterator;
            eventListener = &eventListtmp;
            napi_env env = listenerIterator->env_;
            napi_handle_scope scope = nullptr;
            napi_open_handle_scope(env, &scope);
            napi_value undefine = nullptr;
            napi_get_undefined(env, &undefine);
            napi_ref callbackRef = listenerIterator->callbackRef_;
            napi_value callbackFunc = nullptr;
            napi_get_reference_value(env, callbackRef, &callbackFunc);
            napi_value callbackValues[2] = {0};

            callbackValues[0] = NapiUtil::CreateUndefined(env);
            napi_value object = nullptr;
            napi_create_object(env, &object);
            NapiUtil::SetPropertyStringUtf8(env, object, "header", header);

            callbackValues[1] = object;
            napi_value callbackResult = nullptr;
            napi_call_function(env, undefine, callbackFunc, std::size(callbackValues), callbackValues,
                &callbackResult);
            napi_close_handle_scope(env, scope);
            napi_delete_reference(env, listenerIterator->callbackRef_);
            break;
        }
    }
    if (eventListener != nullptr) {
        g_eventListenerList.remove_if(
            [obj](EventListener listener) -> bool { return listener.httpRequestInfo_ == obj; });
    }
}

bool HttpRequest::NativeRequest(HttpRequestOptionsContext *asyncContext)
{
    return GetCurlWriteData(asyncContext);
}

bool HttpRequest::IsCaFile(const std::string &caFile)
{
    if (caFile.empty()) {
        return false;
    }
    if (access(caFile.c_str(), F_OK) == -1) {
        return false;
    }
    return true;
}
} // namespace NetManagerStandard
} // namespace OHOS