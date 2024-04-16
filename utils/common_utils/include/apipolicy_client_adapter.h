/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef COMMUNICATION_NETSTACK_APIPOLICY_CLIENT_ADAPTER_H
#define COMMUNICATION_NETSTACK_APIPOLICY_CLIENT_ADAPTER_H

#include <string>

namespace OHOS::NetStack::CommonUtils {
    class ApiPolicyAdapter {
    public:
        static std::string DOMAIN_TYPE_HTTP_REQUEST;
        static std::string DOMAIN_TYPE_WEB_SOCKET;
        static std::string DOMAIN_TYPE_DOWNLOAD;
        static std::string DOMAIN_TYPE_UPLOAD;
        static std::string DOMAIN_TYPE_WEBVIEW;

        static int32_t RESULT_ACCEPT;
        static int32_t RESULT_REJECT;

        ApiPolicyAdapter();

        ~ApiPolicyAdapter();

        int32_t CheckUrl(std::string bundle_name, std::string domain_type, std::string url);

    private:
        bool isInit = false;
        void *libHandle = nullptr;
    };
}

#endif //COMMUNICATION_NETSTACK_APIPOLICY_CLIENT_ADAPTER_H