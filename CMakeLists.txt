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

cmake_minimum_required(VERSION 3.20)
project(CommunicationNetStack)

set(CMAKE_CXX_STANDARD 23)

include_directories(
    ../../arkui/napi/interfaces/kits
    ../../arkui/napi/native_engine/impl/quickjs
    ../../arkui/napi/
    ../../../third_party/node/src
)

include_directories(utils/napi_utils/include)
include_directories(utils/common_utils/include)
include_directories(utils/event_manager/include)
include_directories(utils/base_context/include)
include_directories(utils/base_async_work/include)
include_directories(utils/module_template/include)

include_directories(../../../for_linux)

include_directories(../../../utils/native/base/include/)

include_directories(utils/log/include)
include_directories(../../../base/hiviewdfx/hilog/interfaces/native/innerkits/include)

include_directories(test/napi/common)

include_directories(../../../foundation/arkui/ace_engine/frameworks/base/utils)
include_directories(../../../foundation/arkui/napi/interfaces/inner_api)
include_directories(../../../for_linux)

include_directories(../../../third_party/quickjs)
include_directories(../../../third_party/openssl/include)

include_directories(../../../third_party/googletest/googletest/include)
include_directories(../../../third_party/libuv/include)
include_directories(../../../third_party/jsoncpp/include)

link_directories(../../../utils/native/base/cmake-build-debug/src/securec)

link_directories(../../../foundation/arkui/napi/cmake-build-debug)

link_directories(../../../third_party/quickjs)

link_directories(../../../third_party/googletest/cmake-build-debug/googlemock/gtest)
link_directories(../../../third_party/googletest/cmake-build-debug/googlemock)
link_directories(../../../third_party/libuv/cmake-build-debug)

link_directories(cmake-build-debug/utils)

# add_subdirectory(frameworks/js/builtin)
add_subdirectory(utils)
add_subdirectory(test/napi/http)
add_subdirectory(test/napi/socket)
add_subdirectory(test/napi/fetch)
add_subdirectory(test/napi/websocket)
add_subdirectory(test/utils/napi_utils/unittest)