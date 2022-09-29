/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "test_common.h"

#include "context_key.h"
#include "event_list.h"
#include "net_address.h"
#include "securec.h"
#include "socket_module.h"

#define TCP_COMMON_DEFINES                                                                                           \
    auto env = (napi_env)engine_;                                                                                    \
                                                                                                                     \
    napi_value exports = NapiUtils::CreateObject(env);                                                               \
                                                                                                                     \
    SocketModuleExports::InitSocketModule(env, exports);                                                             \
                                                                                                                     \
    napi_value newTcp =                                                                                              \
        NapiUtils::GetNamedProperty(env, exports, SocketModuleExports::FUNCTION_CONSTRUCTOR_TCP_SOCKET_INSTANCE);    \
    ASSERT_CHECK_VALUE_TYPE(env, newTcp, napi_function);                                                             \
                                                                                                                     \
    napi_value tcpThis = NapiUtils::CallFunction(env, exports, newTcp, 0, nullptr);                                  \
    ASSERT_CHECK_VALUE_TYPE(env, tcpThis, napi_object);                                                              \
                                                                                                                     \
    napi_value tcpBind = NapiUtils::GetNamedProperty(env, tcpThis, SocketModuleExports::TCPSocket::FUNCTION_BIND);   \
    ASSERT_CHECK_VALUE_TYPE(env, tcpBind, napi_function);                                                            \
                                                                                                                     \
    napi_value tcpConnect =                                                                                          \
        NapiUtils::GetNamedProperty(env, tcpThis, SocketModuleExports::TCPSocket::FUNCTION_CONNECT);                 \
    ASSERT_CHECK_VALUE_TYPE(env, tcpConnect, napi_function);                                                         \
                                                                                                                     \
    napi_value tcpSend = NapiUtils::GetNamedProperty(env, tcpThis, SocketModuleExports::TCPSocket::FUNCTION_SEND);   \
    ASSERT_CHECK_VALUE_TYPE(env, tcpSend, napi_function);                                                            \
                                                                                                                     \
    napi_value tcpClose = NapiUtils::GetNamedProperty(env, tcpThis, SocketModuleExports::TCPSocket::FUNCTION_CLOSE); \
    ASSERT_CHECK_VALUE_TYPE(env, tcpClose, napi_function);                                                           \
                                                                                                                     \
    napi_value tcpGetRemoteAddress =                                                                                 \
        NapiUtils::GetNamedProperty(env, tcpThis, SocketModuleExports::TCPSocket::FUNCTION_GET_REMOTE_ADDRESS);      \
    ASSERT_CHECK_VALUE_TYPE(env, tcpGetRemoteAddress, napi_function);                                                \
                                                                                                                     \
    napi_value tcpGetState =                                                                                         \
        NapiUtils::GetNamedProperty(env, tcpThis, SocketModuleExports::TCPSocket::FUNCTION_GET_STATE);               \
    ASSERT_CHECK_VALUE_TYPE(env, tcpGetState, napi_function);                                                        \
                                                                                                                     \
    napi_value tcpSetExtraOptions =                                                                                  \
        NapiUtils::GetNamedProperty(env, tcpThis, SocketModuleExports::TCPSocket::FUNCTION_SET_EXTRA_OPTIONS);       \
    ASSERT_CHECK_VALUE_TYPE(env, tcpSetExtraOptions, napi_function);                                                 \
                                                                                                                     \
    napi_value tcpOn = NapiUtils::GetNamedProperty(env, tcpThis, SocketModuleExports::TCPSocket::FUNCTION_ON);       \
    ASSERT_CHECK_VALUE_TYPE(env, tcpOn, napi_function);                                                              \
                                                                                                                     \
    napi_value tcpOff = NapiUtils::GetNamedProperty(env, tcpThis, SocketModuleExports::TCPSocket::FUNCTION_OFF);     \
    ASSERT_CHECK_VALUE_TYPE(env, tcpOff, napi_function);

#define UDP_COMMON_DEFINES                                                                                           \
    auto env = (napi_env)engine_;                                                                                    \
                                                                                                                     \
    napi_value exports = NapiUtils::CreateObject(env);                                                               \
                                                                                                                     \
    SocketModuleExports::InitSocketModule(env, exports);                                                             \
                                                                                                                     \
    napi_value newUdp =                                                                                              \
        NapiUtils::GetNamedProperty(env, exports, SocketModuleExports::FUNCTION_CONSTRUCTOR_UDP_SOCKET_INSTANCE);    \
    ASSERT_CHECK_VALUE_TYPE(env, newUdp, napi_function);                                                             \
                                                                                                                     \
    napi_value udpThis = NapiUtils::CallFunction(env, exports, newUdp, 0, nullptr);                                  \
    ASSERT_CHECK_VALUE_TYPE(env, udpThis, napi_object);                                                              \
                                                                                                                     \
    napi_value udpBind = NapiUtils::GetNamedProperty(env, udpThis, SocketModuleExports::UDPSocket::FUNCTION_BIND);   \
    ASSERT_CHECK_VALUE_TYPE(env, udpBind, napi_function);                                                            \
                                                                                                                     \
    napi_value udpSend = NapiUtils::GetNamedProperty(env, udpThis, SocketModuleExports::UDPSocket::FUNCTION_SEND);   \
    ASSERT_CHECK_VALUE_TYPE(env, udpSend, napi_function);                                                            \
                                                                                                                     \
    napi_value udpClose = NapiUtils::GetNamedProperty(env, udpThis, SocketModuleExports::UDPSocket::FUNCTION_CLOSE); \
    ASSERT_CHECK_VALUE_TYPE(env, udpClose, napi_function);                                                           \
                                                                                                                     \
    napi_value udpGetState =                                                                                         \
        NapiUtils::GetNamedProperty(env, udpThis, SocketModuleExports::UDPSocket::FUNCTION_GET_STATE);               \
    ASSERT_CHECK_VALUE_TYPE(env, udpGetState, napi_function);                                                        \
                                                                                                                     \
    napi_value udpSetExtraOptions =                                                                                  \
        NapiUtils::GetNamedProperty(env, udpThis, SocketModuleExports::UDPSocket::FUNCTION_SET_EXTRA_OPTIONS);       \
    ASSERT_CHECK_VALUE_TYPE(env, udpSetExtraOptions, napi_function);                                                 \
                                                                                                                     \
    napi_value udpOn = NapiUtils::GetNamedProperty(env, udpThis, SocketModuleExports::UDPSocket::FUNCTION_ON);       \
    ASSERT_CHECK_VALUE_TYPE(env, udpOn, napi_function);                                                              \
                                                                                                                     \
    napi_value udpOff = NapiUtils::GetNamedProperty(env, udpThis, SocketModuleExports::UDPSocket::FUNCTION_OFF);     \
    ASSERT_CHECK_VALUE_TYPE(env, udpOff, napi_function);

#define MAKE_ON_MESSAGE(FUNC_NAME)                                                                            \
    [](napi_env env, napi_callback_info info) -> napi_value {                                                 \
        NETSTACK_LOGI("%s", FUNC_NAME);                                                                       \
                                                                                                              \
        napi_value thisVal = nullptr;                                                                         \
        size_t paramsCount = 1;                                                                               \
        napi_value params[1] = {nullptr};                                                                     \
        NAPI_CALL(env, napi_get_cb_info(env, info, &paramsCount, params, &thisVal, nullptr));                 \
                                                                                                              \
        napi_value remoteInfo = NapiUtils::GetNamedProperty(env, params[0], KEY_REMOTE_INFO);                 \
        NETSTACK_LOGI("On recv message");                                                                     \
        NETSTACK_LOGI("address: %s", NapiUtils::GetStringPropertyUtf8(env, remoteInfo, KEY_ADDRESS).c_str()); \
        NETSTACK_LOGI("port: %u", NapiUtils::GetUint32Property(env, remoteInfo, KEY_PORT));                   \
        NETSTACK_LOGI("size: %u", NapiUtils::GetUint32Property(env, remoteInfo, KEY_SIZE));                   \
                                                                                                              \
        napi_value msgBuffer = NapiUtils::GetNamedProperty(env, params[0], KEY_MESSAGE);                      \
        size_t len = 0;                                                                                       \
        void *data = NapiUtils::GetInfoFromArrayBufferValue(env, msgBuffer, &len);                            \
        std::string s;                                                                                        \
        s.append((char *)data, len);                                                                          \
        NETSTACK_LOGI("data:\n%s", s.c_str());                                                                \
                                                                                                              \
        NETSTACK_LOGI("\n\n\n");                                                                              \
        return NapiUtils::GetUndefined(env);                                                                  \
    }

#define TEST_TCP(TEST_NAME, LOCAL_IP, REMOTE_IP, FAMILY, MAKER, PNG)                                            \
    [[maybe_unused]] HWTEST_F(NativeEngineTest, TEST_NAME, testing::ext::TestSize.Level0) /* NOLINT */          \
    {                                                                                                           \
        TCP_COMMON_DEFINES                                                                                      \
                                                                                                                \
        napi_value tcpBindAddress = NapiUtils::CreateObject(env);                                               \
        NapiUtils::SetStringPropertyUtf8(env, (napi_value)tcpBindAddress, KEY_ADDRESS, LOCAL_IP);               \
        NapiUtils::SetUint32Property(env, tcpBindAddress, KEY_FAMILY, (uint32_t)NetAddress::Family::FAMILY);    \
        NapiUtils::SetUint32Property(env, tcpBindAddress, KEY_PORT, 5126);                                      \
                                                                                                                \
        napi_value tcpConnectAddress = NapiUtils::CreateObject(env);                                            \
        NapiUtils::SetStringPropertyUtf8(env, (napi_value)tcpConnectAddress, KEY_ADDRESS, REMOTE_IP);           \
        NapiUtils::SetUint32Property(env, tcpConnectAddress, KEY_FAMILY, (uint32_t)NetAddress::Family::FAMILY); \
        NapiUtils::SetUint32Property(env, tcpConnectAddress, KEY_PORT, 1314);                                   \
                                                                                                                \
        napi_value tcpConnectOptions = NapiUtils::CreateObject(env);                                            \
        NapiUtils::SetNamedProperty(env, (napi_value)tcpConnectOptions, KEY_ADDRESS, tcpConnectAddress);        \
                                                                                                                \
        const char *sendStr = nullptr;                                                                          \
        size_t len = 0;                                                                                         \
        if (!(PNG)) {                                                                                           \
            sendStr = "Hello This is Tcp Test" #TEST_NAME;                                                      \
            len = strlen(sendStr);                                                                              \
        } else {                                                                                                \
            FILE *fp = fopen("for-post.png", "rb");                                                             \
            fseek(fp, 0L, SEEK_END);                                                                            \
            long size = ftell(fp);                                                                              \
            void *buffer = malloc(size);                                                                        \
            fseek(fp, 0, SEEK_SET);                                                                             \
            size_t readSize = fread((void *)buffer, 1, size, fp);                                               \
            NETSTACK_LOGI("file size = %ld read size = %zu", size, readSize);                                   \
                                                                                                                \
            sendStr = (const char *)buffer;                                                                     \
            len = readSize;                                                                                     \
        }                                                                                                       \
                                                                                                                \
        void *data = nullptr;                                                                                   \
        napi_value msgBuffer = NapiUtils::CreateArrayBuffer(env, len, &data);                                   \
        memcpy_s(data, (size_t)len, sendStr, (size_t)len);                                                      \
        napi_value tcpSendOptions = NapiUtils::CreateObject(env);                                               \
        NapiUtils::SetNamedProperty(env, (napi_value)tcpSendOptions, KEY_DATA, msgBuffer);                      \
                                                                                                                \
        napi_value event = NapiUtils::CreateStringUtf8(env, EVENT_MESSAGE);                                     \
        napi_value eventCallback = NapiUtils::CreateFunction(env, #TEST_NAME, MAKER(#TEST_NAME), nullptr);      \
        napi_value arg[2] = {event, eventCallback};                                                             \
        NapiUtils::CallFunction(env, tcpThis, tcpOn, 2, arg);                                                   \
                                                                                                                \
        NapiUtils::CallFunction(env, tcpThis, tcpBind, 1, &tcpBindAddress);                                     \
                                                                                                                \
        NapiUtils::CallFunction(env, tcpThis, tcpConnect, 1, &tcpConnectOptions);                               \
                                                                                                                \
        NapiUtils::CallFunction(env, tcpThis, tcpSend, 1, &tcpSendOptions);                                     \
                                                                                                                \
        NapiUtils::CallFunction(env, tcpThis, tcpClose, 0, nullptr);                                            \
    }

#define TEST_UDP(TEST_NAME, LOCAL_IP, REMOTE_IP, FAMILY, MAKER, PNG)                                         \
    [[maybe_unused]] HWTEST_F(NativeEngineTest, TEST_NAME, testing::ext::TestSize.Level0) /* NOLINT */       \
    {                                                                                                        \
        UDP_COMMON_DEFINES                                                                                   \
                                                                                                             \
        napi_value udpBindAddress = NapiUtils::CreateObject(env);                                            \
        NapiUtils::SetStringPropertyUtf8(env, (napi_value)udpBindAddress, KEY_ADDRESS, LOCAL_IP);            \
        NapiUtils::SetUint32Property(env, udpBindAddress, KEY_FAMILY, (uint32_t)NetAddress::Family::FAMILY); \
        NapiUtils::SetUint32Property(env, udpBindAddress, KEY_PORT, 5126);                                   \
                                                                                                             \
        napi_value udpSendAddress = NapiUtils::CreateObject(env);                                            \
        NapiUtils::SetStringPropertyUtf8(env, (napi_value)udpSendAddress, KEY_ADDRESS, REMOTE_IP);           \
        NapiUtils::SetUint32Property(env, udpSendAddress, KEY_FAMILY, (uint32_t)NetAddress::Family::FAMILY); \
        NapiUtils::SetUint32Property(env, udpSendAddress, KEY_PORT, 4556);                                   \
                                                                                                             \
        const char *sendStr = nullptr;                                                                       \
        size_t len = 0;                                                                                      \
        if (!(PNG)) {                                                                                        \
            sendStr = "Hello UDP UDP Test" #TEST_NAME;                                                       \
            len = strlen(sendStr);                                                                           \
        } else {                                                                                             \
            FILE *fp = fopen("for-post.png", "rb");                                                          \
            fseek(fp, 0L, SEEK_END);                                                                         \
            long size = ftell(fp);                                                                           \
            void *buffer = malloc(size);                                                                     \
            fseek(fp, 0, SEEK_SET);                                                                          \
            size_t readSize = fread((void *)buffer, 1, size, fp);                                            \
            NETSTACK_LOGI("file size = %ld read size = %zu", size, readSize);                                \
                                                                                                             \
            sendStr = (const char *)buffer;                                                                  \
            len = readSize;                                                                                  \
        }                                                                                                    \
                                                                                                             \
        void *data = nullptr;                                                                                \
        napi_value msgBuffer = NapiUtils::CreateArrayBuffer(env, len, &data);                                \
        memcpy_s(data, len, sendStr, len);                                                                   \
                                                                                                             \
        napi_value udpSendOptions = NapiUtils::CreateObject(env);                                            \
        NapiUtils::SetNamedProperty(env, (napi_value)udpSendOptions, KEY_ADDRESS, udpSendAddress);           \
        NapiUtils::SetNamedProperty(env, (napi_value)udpSendOptions, KEY_DATA, msgBuffer);                   \
                                                                                                             \
        napi_value event = NapiUtils::CreateStringUtf8(env, EVENT_MESSAGE);                                  \
        napi_value eventCallback = NapiUtils::CreateFunction(env, #TEST_NAME, MAKER(#TEST_NAME), nullptr);   \
        napi_value arg[2] = {event, eventCallback};                                                          \
        NapiUtils::CallFunction(env, udpThis, udpOn, 2, arg);                                                \
                                                                                                             \
        NapiUtils::CallFunction(env, udpThis, udpBind, 1, &udpBindAddress);                                  \
                                                                                                             \
        napi_value extraOptions = NapiUtils::CreateObject(env);                                              \
        NapiUtils::SetUint32Property(env, extraOptions, KEY_RECEIVE_BUFFER_SIZE, 1024);                      \
        NapiUtils::SetUint32Property(env, extraOptions, KEY_SEND_BUFFER_SIZE, 1024);                         \
        NapiUtils::CallFunction(env, udpThis, udpSetExtraOptions, 1, &extraOptions);                         \
                                                                                                             \
        NapiUtils::CallFunction(env, udpThis, udpSend, 1, &udpSendOptions);                                  \
                                                                                                             \
        NapiUtils::CallFunction(env, udpThis, udpClose, 0, nullptr);                                         \
    }

#define MAKE_PNG_ON_MESSAGE(FUNC_NAME)                                                                        \
    [](napi_env env, napi_callback_info info) -> napi_value {                                                 \
        NETSTACK_LOGI("%s", FUNC_NAME);                                                                       \
                                                                                                              \
        napi_value thisVal = nullptr;                                                                         \
        size_t paramsCount = 1;                                                                               \
        napi_value params[1] = {nullptr};                                                                     \
        NAPI_CALL(env, napi_get_cb_info(env, info, &paramsCount, params, &thisVal, nullptr));                 \
                                                                                                              \
        napi_value remoteInfo = NapiUtils::GetNamedProperty(env, params[0], KEY_REMOTE_INFO);                 \
        NETSTACK_LOGI("On recv message");                                                                     \
        NETSTACK_LOGI("address: %s", NapiUtils::GetStringPropertyUtf8(env, remoteInfo, KEY_ADDRESS).c_str()); \
        NETSTACK_LOGI("port: %u", NapiUtils::GetUint32Property(env, remoteInfo, KEY_PORT));                   \
        NETSTACK_LOGI("size: %u", NapiUtils::GetUint32Property(env, remoteInfo, KEY_SIZE));                   \
                                                                                                              \
        napi_value msgBuffer = NapiUtils::GetNamedProperty(env, params[0], KEY_MESSAGE);                      \
        size_t len = 0;                                                                                       \
        void *data = NapiUtils::GetInfoFromArrayBufferValue(env, msgBuffer, &len);                            \
        std::string s;                                                                                        \
                                                                                                              \
        FILE *fp = fopen(FUNC_NAME ".png", "ab");                                                             \
        if (fp != nullptr) {                                                                                  \
                                                                                                              \
            fwrite(data, 1, len, fp);                                                                         \
            fclose(fp);                                                                                       \
        }                                                                                                     \
                                                                                                              \
        NETSTACK_LOGI("\n\n\n");                                                                              \
        return NapiUtils::GetUndefined(env);                                                                  \
    }

namespace OHOS::NetStack {
TEST_TCP(TEST_TCP1, LOCAL_IPV4_IP, REMOTE_IPV4_IP, IPv4, MAKE_ON_MESSAGE, false)
TEST_TCP(TEST_TCP2, LOCAL_IPV4_IP, REMOTE_IPV4_IP, IPv4, MAKE_ON_MESSAGE, false)
TEST_TCP(TEST_TCP3, LOCAL_IPV4_IP, REMOTE_IPV4_IP, IPv4, MAKE_ON_MESSAGE, false)
TEST_TCP(TEST_TCP4, LOCAL_IPV4_IP, REMOTE_IPV4_IP, IPv4, MAKE_ON_MESSAGE, false)
TEST_UDP(TEST_UDP1, LOCAL_IPV4_IP, REMOTE_IPV4_IP, IPv4, MAKE_ON_MESSAGE, false)
TEST_UDP(TEST_UDP2, LOCAL_IPV4_IP, REMOTE_IPV4_IP, IPv4, MAKE_ON_MESSAGE, false)
TEST_UDP(TEST_UDP3, LOCAL_IPV4_IP, REMOTE_IPV4_IP, IPv4, MAKE_ON_MESSAGE, false)
TEST_UDP(TEST_UDP4, LOCAL_IPV4_IP, REMOTE_IPV4_IP, IPv4, MAKE_ON_MESSAGE, false)

TEST_TCP(TEST_TCP1_IPv6, LOCAL_IPV6_IP, REMOTE_IPV6_IP, IPv6, MAKE_ON_MESSAGE, false)
TEST_TCP(TEST_TCP2_IPv6, LOCAL_IPV6_IP, REMOTE_IPV6_IP, IPv6, MAKE_ON_MESSAGE, false)
TEST_TCP(TEST_TCP3_IPv6, LOCAL_IPV6_IP, REMOTE_IPV6_IP, IPv6, MAKE_ON_MESSAGE, false)
TEST_TCP(TEST_TCP4_IPv6, LOCAL_IPV6_IP, REMOTE_IPV6_IP, IPv6, MAKE_ON_MESSAGE, false)
TEST_UDP(TEST_UDP1_IPv6, LOCAL_IPV6_IP, REMOTE_IPV6_IP, IPv6, MAKE_ON_MESSAGE, false)
TEST_UDP(TEST_UDP2_IPv6, LOCAL_IPV6_IP, REMOTE_IPV6_IP, IPv6, MAKE_ON_MESSAGE, false)
TEST_UDP(TEST_UDP3_IPv6, LOCAL_IPV6_IP, REMOTE_IPV6_IP, IPv6, MAKE_ON_MESSAGE, false)
TEST_UDP(TEST_UDP4_IPv6, LOCAL_IPV6_IP, REMOTE_IPV6_IP, IPv6, MAKE_ON_MESSAGE, false)

TEST_TCP(TEST_TCP1_PNG, LOCAL_IPV4_IP, REMOTE_IPV4_IP, IPv4, MAKE_PNG_ON_MESSAGE, true)
TEST_TCP(TEST_TCP2_PNG, LOCAL_IPV4_IP, REMOTE_IPV4_IP, IPv4, MAKE_PNG_ON_MESSAGE, true)
TEST_TCP(TEST_TCP3_PNG, LOCAL_IPV4_IP, REMOTE_IPV4_IP, IPv4, MAKE_PNG_ON_MESSAGE, true)
TEST_TCP(TEST_TCP4_PNG, LOCAL_IPV4_IP, REMOTE_IPV4_IP, IPv4, MAKE_PNG_ON_MESSAGE, true)
TEST_UDP(TEST_UDP1_PNG, LOCAL_IPV4_IP, REMOTE_IPV4_IP, IPv4, MAKE_PNG_ON_MESSAGE, true)
TEST_UDP(TEST_UDP2_PNG, LOCAL_IPV4_IP, REMOTE_IPV4_IP, IPv4, MAKE_PNG_ON_MESSAGE, true)
TEST_UDP(TEST_UDP3_PNG, LOCAL_IPV4_IP, REMOTE_IPV4_IP, IPv4, MAKE_PNG_ON_MESSAGE, true)
TEST_UDP(TEST_UDP4_PNG, LOCAL_IPV4_IP, REMOTE_IPV4_IP, IPv4, MAKE_PNG_ON_MESSAGE, true)

TEST_TCP(TEST_TCP1_IPv6_PNG, LOCAL_IPV6_IP, REMOTE_IPV6_IP, IPv6, MAKE_PNG_ON_MESSAGE, true)
TEST_TCP(TEST_TCP2_IPv6_PNG, LOCAL_IPV6_IP, REMOTE_IPV6_IP, IPv6, MAKE_PNG_ON_MESSAGE, true)
TEST_TCP(TEST_TCP3_IPv6_PNG, LOCAL_IPV6_IP, REMOTE_IPV6_IP, IPv6, MAKE_PNG_ON_MESSAGE, true)
TEST_TCP(TEST_TCP4_IPv6_PNG, LOCAL_IPV6_IP, REMOTE_IPV6_IP, IPv6, MAKE_PNG_ON_MESSAGE, true)
TEST_UDP(TEST_UDP1_IPv6_PNG, LOCAL_IPV6_IP, REMOTE_IPV6_IP, IPv6, MAKE_PNG_ON_MESSAGE, true)
TEST_UDP(TEST_UDP2_IPv6_PNG, LOCAL_IPV6_IP, REMOTE_IPV6_IP, IPv6, MAKE_PNG_ON_MESSAGE, true)
TEST_UDP(TEST_UDP3_IPv6_PNG, LOCAL_IPV6_IP, REMOTE_IPV6_IP, IPv6, MAKE_PNG_ON_MESSAGE, true)
TEST_UDP(TEST_UDP4_IPv6_PNG, LOCAL_IPV6_IP, REMOTE_IPV6_IP, IPv6, MAKE_PNG_ON_MESSAGE, true)
} // namespace OHOS::NetStack

int main(int argc, char **argv)
{
    testing::GTEST_FLAG(output) = "xml:./";
    testing::InitGoogleTest(&argc, argv);

    JSRuntime *rt = JS_NewRuntime();

    if (rt == nullptr) {
        return 0;
    }

    JSContext *ctx = JS_NewContext(rt);
    if (ctx == nullptr) {
        return 0;
    }

    js_std_add_helpers(ctx, 0, nullptr);

    g_nativeEngine = new QuickJSNativeEngine(rt, ctx, nullptr); // default instance id 0

    int ret = RUN_ALL_TESTS();
    (void)ret;

    g_nativeEngine->Loop(LOOP_DEFAULT);

    return 0;
}