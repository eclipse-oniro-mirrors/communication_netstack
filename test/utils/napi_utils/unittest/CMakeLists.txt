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

add_executable(
    napi_utils_unittest
    test_napi_utils.cpp
    ../../../napi/log/test_hilog.cpp
)

target_link_libraries(napi_utils_unittest ace_napi_quickjs)
target_link_libraries(napi_utils_unittest quickjs)
target_link_libraries(napi_utils_unittest uv)
target_link_libraries(napi_utils_unittest securec)
target_link_libraries(napi_utils_unittest gtestd)
target_link_libraries(napi_utils_unittest gmockd)
target_link_libraries(napi_utils_unittest gtest_maind)
target_link_libraries(napi_utils_unittest gmock_maind)
target_link_libraries(napi_utils_unittest pthread)
target_link_libraries(napi_utils_unittest dl)
target_link_libraries(napi_utils_unittest netstack_utils)

set(CMAKE_CXX_FLAGS -g)
