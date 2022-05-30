include_directories(../../../../frameworks/js/napi/http/cache/cache_strategy/include)
include_directories(../../../../frameworks/js/napi/http/cache/cache_constant/include)
include_directories(../../../../frameworks/js/napi/http/options/include)
include_directories(../../../../frameworks/js/napi/http/constant/include)
include_directories(../../../../utils/common_utils/include)
include_directories(../../../../utils/log/include)
include_directories(../../../../../../../third_party/curl)

add_executable(
    cache_test
    cache_test.cpp
    ../../../../frameworks/js/napi/http/options/src/http_response.cpp
    ../../../../frameworks/js/napi/http/options/src/http_request_options.cpp
    ../../../../frameworks/js/napi/http/constant/src/constant.cpp
    ../../../../utils/common_utils/src/netstack_common_utils.cpp
    ../../../napi/log/test_hilog.cpp
    ../../../../frameworks/js/napi/http/cache/cache_strategy/src/http_time.cpp
    ../../../../frameworks/js/napi/http/cache/cache_strategy/src/http_cache_request.cpp
    ../../../../frameworks/js/napi/http/cache/cache_strategy/src/http_cache_response.cpp
    ../../../../frameworks/js/napi/http/cache/cache_strategy/src/http_cache_strategy.cpp
)

target_link_libraries(cache_test gtestd)
target_link_libraries(cache_test gmockd)
target_link_libraries(cache_test gtest_maind)
target_link_libraries(cache_test gmock_maind)