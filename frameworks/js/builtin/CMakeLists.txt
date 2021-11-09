# Copyright (c) 2021 Huawei Device Co., Ltd.
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

cmake_minimum_required(VERSION 3.19)
project(ohos_acelite)

set(CMAKE_CXX_STANDARD 14)

include_directories(test/include)

include_directories(../../../../../ace/ace_engine_lite/interfaces/innerkits/builtin/jsi)
include_directories(../../../../../ace/ace_engine_lite/interfaces/innerkits/builtin/async)

include_directories(../../../../../ace/ace_engine_lite/frameworks/common/utils)
include_directories(../../../../../ace/ace_engine_lite/frameworks/src/core/context)
include_directories(../../../../../ace/ace_engine_lite/frameworks/targets/simulator)

include_directories(../../../../../../third_party/jerryscript/jerry-core/include)
include_directories(../../../../../../third_party/jerryscript/jerry-ext/include/jerryscript-ext)
include_directories(../../../../../../third_party/jerryscript/jerry-port/default/include)
include_directories(../../../../../../third_party/curl/include)
include_directories(../../../../../../third_party/bounds_checking_function/include)

link_directories(../../../../../../third_party/jerryscript/cmake-build-debug/lib)
link_directories(../../../../../../third_party/curl/cmake-build-debug/lib)
link_directories(../../../../../../third_party/bounds_checking_function/cmake-build-debug)

add_library(test_fetch_module
    fetch_module.cpp
    http_request/http_async_callback.cpp
    http_request/http_request.cpp
    http_request/http_constant.cpp
    http_request/response_data.cpp
    http_request/request_data.cpp
    http_request/http_request_utils.cpp

    ../../../../../ace/ace_engine_lite/frameworks/native_engine/jsi/jsi.cpp
    ../../../../../ace/ace_engine_lite/frameworks/native_engine/async/js_async_work.cpp
    ../../../../../ace/ace_engine_lite/frameworks/native_engine/async/message_queue_utils.cpp
    ../../../../../ace/ace_engine_lite/frameworks/common/memory/memory_heap.cpp
    )

target_link_libraries(test_fetch_module jerry-core)
target_link_libraries(test_fetch_module jerry-ext)
target_link_libraries(test_fetch_module jerry-libm)
target_link_libraries(test_fetch_module jerry-port-default)
target_link_libraries(test_fetch_module curl-d)
target_link_libraries(test_fetch_module securec)

add_compile_definitions(NO_SSL_CERTIFICATION=1)

add_subdirectory(test)