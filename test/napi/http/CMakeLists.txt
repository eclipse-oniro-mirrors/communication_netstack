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

include_directories(../../../frameworks/js/napi/http/http_module/include)
include_directories(../../../frameworks/js/napi/http/async_work/include)
include_directories(../../../frameworks/js/napi/http/http_exec/include)
include_directories(../../../frameworks/js/napi/http/constant/include)
include_directories(../../../frameworks/js/napi/http/async_context/include)
include_directories(../../../frameworks/js/napi/http/options/include)
include_directories(../../../frameworks/js/napi/http/cache/lru_cache/include)
include_directories(../../../frameworks/js/napi/http/cache/md5/include)
include_directories(../../../frameworks/js/napi/http/cache/base64/include)
include_directories(../../../frameworks/js/napi/http/cache/cache_proxy/include)
include_directories(../../../frameworks/js/napi/http/cache/cache_strategy/include)

include_directories(../../../../../../third_party/curl/include)
include_directories(../../../../../../third_party/glib/glib/)
include_directories(../../../../../../third_party/glib/)

link_directories(../../../../../../third_party/curl/cmake-build-debug/lib)

add_executable(
    test_napi_http_exec
    test_napi_exec.cpp
    ../log/test_hilog.cpp

    ../../../frameworks/js/napi/http/http_module/src/http_module.cpp
    ../../../frameworks/js/napi/http/constant/src/constant.cpp
    ../../../frameworks/js/napi/http/async_context/src/request_context.cpp
    ../../../frameworks/js/napi/http/async_work/src/http_async_work.cpp
    ../../../frameworks/js/napi/http/options/src/http_response.cpp
    ../../../frameworks/js/napi/http/options/src/http_request_options.cpp
    ../../../frameworks/js/napi/http/cache/lru_cache/src/lru_cache.cpp
    ../../../frameworks/js/napi/http/http_exec/src/http_exec.cpp
    ../../../frameworks/js/napi/http/cache/lru_cache/src/lru_cache_disk_handler.cpp
    ../../../frameworks/js/napi/http/cache/lru_cache/src/disk_handler.cpp
    ../../../frameworks/js/napi/http/cache/md5/src/calculate_md5.cpp
    ../../../frameworks/js/napi/http/cache/base64/src/base64_utils.cpp
    ../../../frameworks/js/napi/http/cache/cache_proxy/src/cache_proxy.cpp
    ../../../frameworks/js/napi/http/cache/cache_strategy/src/http_cache_strategy.cpp
    ../../../frameworks/js/napi/http/cache/cache_strategy/src/http_time.cpp
    ../../../frameworks/js/napi/http/cache/cache_strategy/src/http_cache_request.cpp
    ../../../frameworks/js/napi/http/cache/cache_strategy/src/http_cache_response.cpp
)

target_link_libraries(test_napi_http_exec curl-d)
target_link_libraries(test_napi_http_exec ace_napi_quickjs)
target_link_libraries(test_napi_http_exec quickjs)
target_link_libraries(test_napi_http_exec uv)
target_link_libraries(test_napi_http_exec securec)
target_link_libraries(test_napi_http_exec gtestd)
target_link_libraries(test_napi_http_exec gmockd)
target_link_libraries(test_napi_http_exec gtest_maind)
target_link_libraries(test_napi_http_exec gmock_maind)
target_link_libraries(test_napi_http_exec pthread)
target_link_libraries(test_napi_http_exec dl)
target_link_libraries(test_napi_http_exec nghttp2)
target_link_libraries(test_napi_http_exec netstack_utils)

add_compile_definitions(NO_SSL_CERTIFICATION=0)
add_compile_definitions(HTTP_CURL_PRINT_VERBOSE=0)
add_compile_definitions(NETSTACK_USE_PROXY=0)
add_compile_definitions(NETSTACK_PROXY_URL_PORT="xxxx:xxxx")
add_compile_definitions(NETSTACK_PROXY_TYPE=CURLPROXY_HTTP)
add_compile_definitions(NETSTACK_PROXY_PASS="xxxx:xxxx")
add_compile_definitions(SERVER_IP="x.x.x.x")
set(CMAKE_CXX_FLAGS -g)
