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

mod bridge;
mod web_socket;
mod wrapper;

ani_rs::ani_constructor! {
    namespace "L@ohos/net/webSocket/webSocket"
    [
        "create_webSocket" : web_socket::create_web_socket
    ]
    class "L@ohos/net/webSocket/webSocket/WebSocketInner"
    [
        "connect_sync" : web_socket::connect_sync,
        "send_sync" : web_socket::send_sync,
        "close_sync" : web_socket::close_sync,
    ]
    class "L@ohos/net/webSocket/webSocket/Cleaner"
    [
        "clean" : web_socket::web_socket_clean,
    ]
}
