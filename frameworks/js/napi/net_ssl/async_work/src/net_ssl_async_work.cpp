/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "net_ssl_async_work.h"

#include "base_async_work.h"
#include "napi_utils.h"
#include "net_ssl_exec.h"

namespace OHOS::NetStack::Ssl {
void NetSslAsyncWork::ExecVerify(napi_env env, void *data)
{
    BaseAsyncWork::ExecAsyncWork<CertContext, SslExec::ExecVerify>(env, data);
}

void NetSslAsyncWork::VerifyCallback(napi_env env, napi_status status, void *data)
{
    BaseAsyncWork::AsyncWorkCallback<CertContext, SslExec::VerifyCallback>(env, status, data);
}
} // namespace OHOS::NetStack::Ssl