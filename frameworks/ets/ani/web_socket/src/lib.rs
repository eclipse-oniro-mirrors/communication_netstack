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
    tag: "WebSocketAni",
};

#[macro_use]
extern crate netstack_common;

mod bridge;
mod web_socket;
mod wrapper;

ani_rs::ani_constructor! {
    namespace "L@ohos/net/webSocket/webSocket"
    [
        "createWebSocket" : web_socket::create_web_socket
    ]
    class "L@ohos/net/webSocket/webSocket/WebSocketInner"
    [
        "connectSync" : web_socket::connect_sync,
        "sendSync" : web_socket::send_sync,
        "closeSync" : web_socket::close_sync,
    ]
    class "L@ohos/net/webSocket/webSocket/Cleaner"
    [
        "clean" : web_socket::web_socket_clean,
    ]
}

#[used]
#[link_section = ".init_array"]
static WEBSOCKET_PANIC_HOOK: extern "C" fn() = {
    #[link_section = ".text.startup"]
    extern "C" fn init() {
        std::panic::set_hook(Box::new(|info| {
            error!("Panic occurred: {:?}", info);
        }));
    }
    init
};
