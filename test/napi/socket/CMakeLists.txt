# Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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

include_directories(../../../frameworks/js/napi/socket/socket_module/include)
include_directories(../../../frameworks/js/napi/socket/options/include)
include_directories(../../../frameworks/js/napi/socket/async_context/include)
include_directories(../../../frameworks/js/napi/socket/constant/include)
include_directories(../../../frameworks/js/napi/socket/async_work/include)
include_directories(../../../frameworks/js/napi/socket/socket_exec/include)
include_directories(../../../frameworks/js/napi/socket/task_queue/include)

add_executable(
    test_napi_socket_exec
    test_napi_exec.cpp
    ../log/test_hilog.cpp

    ../../../frameworks/js/napi/socket/socket_module/src/socket_module.cpp
    ../../../frameworks/js/napi/socket/options/src/net_address.cpp
    ../../../frameworks/js/napi/socket/options/src/extra_options_base.cpp
    ../../../frameworks/js/napi/socket/options/src/udp_extra_options.cpp
    ../../../frameworks/js/napi/socket/options/src/udp_send_options.cpp
    ../../../frameworks/js/napi/socket/options/src/socket_state_base.cpp
    ../../../frameworks/js/napi/socket/options/src/socket_remote_info.cpp
    ../../../frameworks/js/napi/socket/options/src/tcp_connect_options.cpp
    ../../../frameworks/js/napi/socket/options/src/tcp_send_options.cpp
    ../../../frameworks/js/napi/socket/options/src/tcp_extra_options.cpp
    ../../../frameworks/js/napi/socket/async_context/src/bind_context.cpp
    ../../../frameworks/js/napi/socket/async_context/src/common_context.cpp
    ../../../frameworks/js/napi/socket/async_context/src/connect_context.cpp
    ../../../frameworks/js/napi/socket/async_context/src/udp_send_context.cpp
    ../../../frameworks/js/napi/socket/async_context/src/tcp_send_context.cpp
    ../../../frameworks/js/napi/socket/async_context/src/tcp_extra_context.cpp
    ../../../frameworks/js/napi/socket/async_context/src/udp_extra_context.cpp
    ../../../frameworks/js/napi/socket/async_work/src/socket_async_work.cpp
    ../../../frameworks/js/napi/socket/socket_exec/src/socket_exec.cpp
    ../../../frameworks/js/napi/socket/task_queue/src/task_queue.cpp
)

target_link_libraries(test_napi_socket_exec ace_napi_quickjs)
target_link_libraries(test_napi_socket_exec quickjs)
target_link_libraries(test_napi_socket_exec uv)
target_link_libraries(test_napi_socket_exec securec)
target_link_libraries(test_napi_socket_exec gtestd)
target_link_libraries(test_napi_socket_exec gmockd)
target_link_libraries(test_napi_socket_exec gtest_maind)
target_link_libraries(test_napi_socket_exec gmock_maind)
target_link_libraries(test_napi_socket_exec pthread)
target_link_libraries(test_napi_socket_exec dl)
target_link_libraries(test_napi_socket_exec netstack_utils)

add_compile_definitions(LOCAL_IPV4_IP="x.x.x.x")
add_compile_definitions(REMOTE_IPV4_IP="x.x.x.x")
add_compile_definitions(LOCAL_IPV6_IP="::1")
add_compile_definitions(REMOTE_IPV6_IP="::1")

set(CMAKE_CXX_FLAGS -g)
