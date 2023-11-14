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

#ifndef COMMUNICATIONNETSTACK_CONNECT_CONTEXT_H
#define COMMUNICATIONNETSTACK_CONNECT_CONTEXT_H

#include <map>
#include <string>

#include "base_context.h"
#include "nocopyable.h"
#include "libwebsockets.h"
#include "secure_char.h" 

namespace OHOS::NetStack::Websocket {
class ConnectContext final : public BaseContext {
public:
    DISALLOW_COPY_AND_MOVE(ConnectContext);

    ConnectContext() = delete;

    explicit ConnectContext(napi_env env, EventManager *manager);

    ~ConnectContext() override;

    void ParseParams(napi_value *params, size_t paramsCount) override;

    [[nodiscard]] int32_t GetErrorCode() const override;

    [[nodiscard]] std::string GetErrorMessage() const override;

    std::string url;

    std::map<std::string, std::string> header;

    std::string caPath_;

    std::string clientCert_;

    Secure::SecureChar clientKey_;

    Secure::SecureChar keyPasswd_;    

private:
    void ParseHeader(napi_value optionsValue);

    void ParseCaPath(napi_value optionsValue);

    void ParseClientCert(napi_value optionsValue);

    void SetClientCert(std::string &cert, Secure::SecureChar &key, Secure::SecureChar &keyPasswd);

    void GetClientCert(std::string &cert, Secure::SecureChar &key, Secure::SecureChar &keyPasswd);

    bool CheckParamsType(napi_value *params, size_t paramsCount);
};
} // namespace OHOS::NetStack::Websocket

#endif /* COMMUNICATIONNETSTACK_CONNECT_CONTEXT_H */
