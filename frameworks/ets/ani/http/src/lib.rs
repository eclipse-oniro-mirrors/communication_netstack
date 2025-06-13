// Copyright (C) 2025 Huawei Device Co., Ltd.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

const LOG_LABEL: hilog_rust::HiLogLabel = hilog_rust::HiLogLabel {
    log_type: hilog_rust::LogType::LogCore,
    domain: 0xD0015B0,
    tag: "HttpAni",
};

#[macro_use]
extern crate netstack_common;

mod bridge;
mod callback;
mod http;

ani_rs::ani_constructor! {
    namespace "L@ohos/net/http/http"
    [
        "createHttp" : http::create_http
    ]
    class "L@ohos/net/http/http/HttpRequestInner"
    [
        "requestInner" : http::request,
        "requestInStreamInner" : http::request_in_stream,
        "destroy" : http::destroy,
        "onHeaderReceive" : http::on_header_receive,
        "onHeadersReceive" : http::on_headers_receive,
        "onDataReceive" : http::on_data_receive,
        "onDataEnd" : http::on_data_end,
        "onDataReceiveProgress" : http::on_data_receive_progress,
        "onDataSendProgress" : http::on_data_send_progress,
        "offHeaderReceive" : http::off_header_receive,
        "offHeadersReceive" : http::off_headers_receive,
        "offDataReceive" : http::off_data_receive,
        "offDataEnd" : http::off_data_end,
        "offDataReceiveProgress" : http::off_data_receive_progress,
        "offDataSendProgress" : http::off_data_send_progress,
        "once" : http::once,
    ]
    class "L@ohos/net/http/http/HttpResponseCacheInner"
    [
        "flushSync" : http::flush,
        "deleteSync": http::delete,
    ]
    class "L@ohos/net/http/http/Cleaner"
    [
        "cleanHttp" : http::clean_http_request,
        "cleanCache" : http::clean_http_cache,
    ]
}

#[used]
#[link_section = ".init_array"]
static A: extern "C" fn() = {
    #[link_section = ".text.startup"]
    extern "C" fn init() {
        std::panic::set_hook(Box::new(|info| {
            info!("Panic occurred: {:?}", info);
        }));
    }
    init
};
