/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include <iostream>

#include "http_client_error.h"
#include "netstack_log.h"

namespace OHOS {
namespace NetStack {
namespace HttpClient {

static const std::map<int32_t, const std::string> HTTP_ERR_MAP = {
    {HTTP_NONE_ERR, "No errors occurred"},
    {HTTP_PERMISSION_DENIED_CODE, "Permission denied"},
    {HTTP_PARSE_ERROR_CODE, "Parameter error"},
    {HTTP_UNSUPPORTED_PROTOCOL, "Unsupported protocol"},
    {HTTP_FAILED_INIT, "Failed to initialize"},
    {HTTP_URL_MALFORMAT, "URL using bad/illegal format or missing URL"},
    {HTTP_COULDNT_RESOLVE_PROXY, "Couldn't resolve proxy name"},
    {HTTP_COULDNT_RESOLVE_HOST, "Couldn't resolve host name"},
    {HTTP_COULDNT_CONNECT, "Couldn't connect to server"},
    {HTTP_WEIRD_SERVER_REPLY, "Weird server reply"},
    {HTTP_REMOTE_ACCESS_DENIED, "Access denied to remote resource"},
    {HTTP_HTTP2_ERROR, "Error in the HTTP2 framing layer"},
    {HTTP_PARTIAL_FILE, "Transferred a partial file"},
    {HTTP_WRITE_ERROR, "Failed writing received data to disk/application"},
    {HTTP_UPLOAD_FAILED, "Upload failed"},
    {HTTP_READ_ERROR, "Failed to open/read local data from file/application"},
    {HTTP_OUT_OF_MEMORY, "Out of memory"},
    {HTTP_POST_ERROR, "Post error"},
    {HTTP_OPERATION_TIMEDOUT, "Timeout was reached"},
    {HTTP_TASK_CANCELED, "Task was canceled"},
    {HTTP_TOO_MANY_REDIRECTS, "Number of redirects hit maximum amount"},
    {HTTP_GOT_NOTHING, "Server returned nothing (no headers, no data)"},
    {HTTP_SEND_ERROR, "Failed sending data to the peer"},
    {HTTP_RECV_ERROR, "Failure when receiving data from the peer"},
    {HTTP_SSL_CERTPROBLEM, "Problem with the local SSL certificate"},
    {HTTP_SSL_CIPHER, "Couldn't use specified SSL cipher"},
    {HTTP_PEER_FAILED_VERIFICATION, "SSL peer certificate or SSH remote key was not OK"},
    {HTTP_BAD_CONTENT_ENCODING, "Unrecognized or bad HTTP Content or Transfer-Encoding"},
    {HTTP_FILESIZE_EXCEEDED, "Maximum file size exceeded"},
    {HTTP_REMOTE_DISK_FULL, "Disk full or allocation exceeded"},
    {HTTP_REMOTE_FILE_EXISTS, "Remote file already exists"},
    {HTTP_SSL_CACERT_BADFILE, "Problem with the SSL CA cert (path? access rights?)"},
    {HTTP_REMOTE_FILE_NOT_FOUND, "Remote file not found"},
    {HTTP_AUTH_ERROR, "An authentication function returned an error"},
    {HTTP_SSL_PINNEDPUBKEYNOTMATCH, "Specified pinned public key did not match"},
    {HTTP_UNKNOWN_OTHER_ERROR, "Unknown Other Error"},
};

const std::string &HttpClientError::GetErrorMessage() const
{
    auto err = errorCode_;
    if (HTTP_ERR_MAP.find(err) == HTTP_ERR_MAP.end()) {
        err = HTTP_UNKNOWN_OTHER_ERROR;
    }

    return HTTP_ERR_MAP.find(err)->second;
}

void HttpClientError::SetErrorCode(HttpErrorCode code)
{
    errorCode_ = code;
}

HttpErrorCode HttpClientError::GetErrorCode() const
{
    return errorCode_;
}

void HttpClientError::SetCURLResult(CURLcode result)
{
    HttpErrorCode err = HTTP_UNKNOWN_OTHER_ERROR;
    if (result > CURLE_OK) {
        if (HTTP_ERR_MAP.find(result + HTTP_ERROR_CODE_BASE) != HTTP_ERR_MAP.end()) {
            err = static_cast<HttpErrorCode>(result + HTTP_ERROR_CODE_BASE);
        }
    } else {
        err = HTTP_NONE_ERR;
    }

    NETSTACK_LOGD("HttpClientError::SetCURLResult: result=%d, err=%d", result, err);
    SetErrorCode(err);
}
} // namespace HttpClient
} // namespace NetStack
} // namespace OHOS