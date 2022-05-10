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

include_directories(../../../frameworks/js/napi/fetch/fetch_module/include)
include_directories(../../../frameworks/js/napi/fetch/async_work/include)
include_directories(../../../frameworks/js/napi/fetch/fetch_exec/include)
include_directories(../../../frameworks/js/napi/fetch/constant/include)
include_directories(../../../frameworks/js/napi/fetch/async_context/include)
include_directories(../../../frameworks/js/napi/fetch/options/include)

include_directories(../../../../../../third_party/curl/include)

link_directories(../../../../../../third_party/curl/cmake-build-debug/lib)

add_executable(
    test_napi_fetch_exec
    test_napi_exec.cpp
    ../log/test_hilog.cpp

    ../../../frameworks/js/napi/fetch/fetch_module/src/fetch_module.cpp
    ../../../frameworks/js/napi/fetch/constant/src/constant.cpp
    ../../../frameworks/js/napi/fetch/async_context/src/fetch_context.cpp
    ../../../frameworks/js/napi/fetch/async_work/src/fetch_async_work.cpp
    ../../../frameworks/js/napi/fetch/options/src/fetch_response.cpp
    ../../../frameworks/js/napi/fetch/options/src/fetch_request.cpp
    ../../../frameworks/js/napi/fetch/fetch_exec/src/fetch_exec.cpp
)

target_link_libraries(test_napi_fetch_exec curl-d)
target_link_libraries(test_napi_fetch_exec ace_napi_quickjs)
target_link_libraries(test_napi_fetch_exec quickjs)
target_link_libraries(test_napi_fetch_exec uv)
target_link_libraries(test_napi_fetch_exec securec)
target_link_libraries(test_napi_fetch_exec gtestd)
target_link_libraries(test_napi_fetch_exec gmockd)
target_link_libraries(test_napi_fetch_exec gtest_maind)
target_link_libraries(test_napi_fetch_exec gmock_maind)
target_link_libraries(test_napi_fetch_exec pthread)
target_link_libraries(test_napi_fetch_exec dl)
target_link_libraries(test_napi_fetch_exec nghttp2)
target_link_libraries(test_napi_fetch_exec netstack_utils)

add_compile_definitions(NO_SSL_CERTIFICATION=0)
add_compile_definitions(HTTP_CURL_PRINT_VERBOSE=0)
add_compile_definitions(NETSTACK_USE_PROXY=0)
add_compile_definitions(NETSTACK_PROXY_URL_PORT="xxxx:xxxx")
add_compile_definitions(NETSTACK_PROXY_TYPE=CURLPROXY_HTTP)
add_compile_definitions(NETSTACK_PROXY_PASS="xxxx:xxxx")
add_compile_definitions(SERVER_IP="x.x.x.x")
set(CMAKE_CXX_FLAGS -g)
