# Copyright (C) 2022 Huawei Device Co., Ltd.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

include_directories(../../../frameworks/js/napi/websocket/async_context/include)
include_directories(../../../frameworks/js/napi/websocket/async_work/include)
include_directories(../../../frameworks/js/napi/websocket/constant/include)
include_directories(../../../frameworks/js/napi/websocket/websocket_exec/include)
include_directories(../../../frameworks/js/napi/websocket/websocket_module/include)
include_directories(../../../../../../third_party/libwebsockets/include)
include_directories(../../../../../../third_party/libwebsockets/cmake-build-debug)

link_directories(../../../../../../third_party/libwebsockets/cmake-build-debug/lib)

add_executable(
    test_napi_websocket_exec
    test_napi_exec.cpp
    ../log/test_hilog.cpp
    ../../../frameworks/js/napi/websocket/async_context/src/connect_context.cpp
    ../../../frameworks/js/napi/websocket/async_context/src/send_context.cpp
    ../../../frameworks/js/napi/websocket/async_context/src/close_context.cpp
    ../../../frameworks/js/napi/websocket/websocket_module/src/websocket_module.cpp
    ../../../frameworks/js/napi/websocket/websocket_exec/src/websocket_exec.cpp
    ../../../frameworks/js/napi/websocket/async_work/src/websocket_async_work.cpp
    ../../../frameworks/js/napi/websocket/constant/src/constant.cpp
)

target_link_libraries(test_napi_websocket_exec websockets)
target_link_libraries(test_napi_websocket_exec crypto)
target_link_libraries(test_napi_websocket_exec ssl)
target_link_libraries(test_napi_websocket_exec ace_napi_quickjs)
target_link_libraries(test_napi_websocket_exec quickjs)
target_link_libraries(test_napi_websocket_exec uv)
target_link_libraries(test_napi_websocket_exec securec)
target_link_libraries(test_napi_websocket_exec gtestd)
target_link_libraries(test_napi_websocket_exec gmockd)
target_link_libraries(test_napi_websocket_exec gtest_maind)
target_link_libraries(test_napi_websocket_exec gmock_maind)
target_link_libraries(test_napi_websocket_exec pthread)
target_link_libraries(test_napi_websocket_exec dl)
target_link_libraries(test_napi_websocket_exec nghttp2)
target_link_libraries(test_napi_websocket_exec netstack_utils)

set(CMAKE_CXX_FLAGS -g)
