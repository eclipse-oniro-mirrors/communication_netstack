/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

 
#include <cstring>
#include <iostream>
#include <vector>
#include <string>
#include "gtest/gtest.h"

#include "net_http.h"
#include "netstack_hash_map.h"
#include "netstack_log.h"
#include "net_http_inner_types.h"
#include "http_client_request.h"
#include "http_client.h"
#include "http_client_constant.h"
#include "net_http_type.h"

using namespace OHOS::NetStack::HttpClient;

class NetHttpTest : public testing::Test {
public:
    static void SetUpTestCase() {}

    static void TearDownTestCase() {}

    virtual void SetUp() {}

    virtual void TearDown() {}
};

namespace {
using namespace std;
using namespace testing::ext;

static void myCallbackFunction()
{
    NETSTACK_LOGI("myCallbackFunction function called!");
}

static void testResponseCallback(struct Http_Response *response, uint32_t errCode)
{
    NETSTACK_LOGI("testResponseCallback function called!");
}

static void TestDataReceiveCallback(const char *data, size_t length)
{
    NETSTACK_LOGI("testDataReceiveCallback function called!");
    return;
}

static void testHeaderReceiveCallback(Http_Headers *headers)
{
    NETSTACK_LOGI("testHeaderReceiveCallback function called!");
}

HWTEST_F(NetHttpTest, CreateHeaders001, TestSize.Level1)
{
    Http_Headers *header = OH_Http_CreateHeaders();
    EXPECT_TRUE(header != nullptr);
    OH_Http_DestroyHeaders(&header);
}

HWTEST_F(NetHttpTest, DestroyHeaders001, TestSize.Level1)
{
    Http_Headers *header = OH_Http_CreateHeaders();
    EXPECT_TRUE(header != nullptr);
    EXPECT_EQ(OH_Http_SetHeaderValue(header, "key", "value"), OH_HTTP_RESULT_OK);
    OH_Http_DestroyHeaders(&header);
}

HWTEST_F(NetHttpTest, DestroyHeaders002, TestSize.Level1)
{
    Http_Headers *header = nullptr;
    OH_Http_DestroyHeaders(&header);

    OH_Http_DestroyHeaders(nullptr);
}

HWTEST_F(NetHttpTest, ToLowerCase001, TestSize.Level1)
{
    Http_Headers *header = OH_Http_CreateHeaders();
    EXPECT_TRUE(header != nullptr);
    
    OH_Http_SetHeaderValue(header, "TEST", "value");
    OH_Http_DestroyHeaders(&header);
}

HWTEST_F(NetHttpTest, SetHeaderValue001, TestSize.Level1)
{    
    uint32_t ret = OH_Http_SetHeaderValue(nullptr, "key", "test");
    EXPECT_EQ(ret, OH_HTTP_PARAMETER_ERROR);

    Http_Headers *header = OH_Http_CreateHeaders();
    EXPECT_TRUE(header != nullptr);
    ret = OH_Http_SetHeaderValue(header, nullptr, "test");
    EXPECT_EQ(ret, OH_HTTP_PARAMETER_ERROR);

    ret = OH_Http_SetHeaderValue(header, "key2", nullptr);
    EXPECT_EQ(ret, OH_HTTP_PARAMETER_ERROR);
    OH_Http_DestroyHeaders(&header);
}

HWTEST_F(NetHttpTest, SetHeaderValue002, TestSize.Level1)
{    
    Http_Headers *header = OH_Http_CreateHeaders();
    EXPECT_TRUE(header != nullptr);
    OH_Http_SetHeaderValue(header, "key1", "test1");

    uint32_t ret = OH_Http_SetHeaderValue(header, "key2", "test2");
    EXPECT_EQ(ret, OH_HTTP_RESULT_OK);
    OH_Http_DestroyHeaders(&header);
}

HWTEST_F(NetHttpTest, SetHeaderValue003, TestSize.Level1)
{    
    Http_Headers *header = OH_Http_CreateHeaders();
    EXPECT_TRUE(header != nullptr);
    OH_Http_SetHeaderValue(header, "key1", "test1");

    uint32_t ret = OH_Http_SetHeaderValue(header, "key1", "test1");
    EXPECT_EQ(ret, OH_HTTP_RESULT_OK);
    OH_Http_DestroyHeaders(&header);
}

HWTEST_F(NetHttpTest, SetHeaderValue004, TestSize.Level1)
{    
    Http_Headers *header = OH_Http_CreateHeaders();
    EXPECT_TRUE(header != nullptr);
    OH_Http_SetHeaderValue(header, "key1", "test1");

    uint32_t ret = OH_Http_SetHeaderValue(header, "key1", "test2");
    EXPECT_EQ(ret, OH_HTTP_RESULT_OK);
    OH_Http_DestroyHeaders(&header);
}

HWTEST_F(NetHttpTest, SetHeaderValue005, TestSize.Level1)
{    
    Http_Headers *header = OH_Http_CreateHeaders();
    
    EXPECT_TRUE(header != nullptr);
    OH_Http_SetHeaderValue(header, "key1", "test1");
    header->fields->capacity = MAX_MAP_CAPACITY + 1;
    uint32_t ret = OH_Http_SetHeaderValue(header, "key1", "test2");
    EXPECT_EQ(ret, OH_HTTP_PARAMETER_ERROR);
    OH_Http_DestroyHeaders(&header);
}

HWTEST_F(NetHttpTest, GetHeaderValue001, TestSize.Level1)
{       
    Http_Headers *header = OH_Http_CreateHeaders();
    EXPECT_TRUE(header != nullptr);
    header->fields = nullptr;
    Http_HeaderValue *value = OH_Http_GetHeaderValue(header, "key");
    EXPECT_EQ(value, nullptr);
    OH_Http_DestroyHeaders(&header);
}

HWTEST_F(NetHttpTest, GetHeaderValue002, TestSize.Level1)
{    
    Http_HeaderValue *value = OH_Http_GetHeaderValue(nullptr, "key");
    EXPECT_EQ(value, nullptr);

    Http_Headers *header = OH_Http_CreateHeaders();
    EXPECT_TRUE(header != nullptr);
    value = OH_Http_GetHeaderValue(header, nullptr);
    EXPECT_EQ(value, nullptr);
    OH_Http_DestroyHeaders(&header);
}

HWTEST_F(NetHttpTest, GetHeaderValue003, TestSize.Level1)
{    
    Http_Headers *header = OH_Http_CreateHeaders();
    EXPECT_TRUE(header != nullptr);
    OH_Http_SetHeaderValue(header, "key1", "test1");
    Http_HeaderValue *value = OH_Http_GetHeaderValue(header, "key1");
    EXPECT_TRUE(value != nullptr);
    OH_Http_DestroyHeaders(&header);
}

HWTEST_F(NetHttpTest, GetHeaderEntries001, TestSize.Level1)
{    
    EXPECT_EQ(OH_Http_GetHeaderEntries(nullptr), nullptr);
        
    Http_Headers *header = OH_Http_CreateHeaders();
    EXPECT_TRUE(header != nullptr);
    header->fields = nullptr;
    EXPECT_EQ(OH_Http_GetHeaderEntries(header), nullptr);
    OH_Http_DestroyHeaders(&header);
}

HWTEST_F(NetHttpTest, GetHeaderEntries002, TestSize.Level1)
{    
    Http_Headers *header = OH_Http_CreateHeaders();
    EXPECT_TRUE(header != nullptr);
    header->fields->capacity = MAX_MAP_CAPACITY + 1;
    EXPECT_EQ(OH_Http_GetHeaderEntries(header), nullptr);
    OH_Http_DestroyHeaders(&header);
}

HWTEST_F(NetHttpTest, GetHeaderEntries003, TestSize.Level1)
{    
    Http_Headers *header = OH_Http_CreateHeaders();
    EXPECT_TRUE(header != nullptr);
    OH_Http_SetHeaderValue(header, "a", "test1");
    OH_Http_SetHeaderValue(header, "cc", "test2");
    OH_Http_SetHeaderValue(header, "b", "test3");
 
    EXPECT_TRUE(OH_Http_GetHeaderEntries(header) != nullptr);
    OH_Http_DestroyHeaders(&header);
}

HWTEST_F(NetHttpTest, CreateRequest001, TestSize.Level1)
{ 
    EXPECT_EQ(OH_Http_CreateRequest(nullptr), nullptr);

    const char *url = "https://www.baidu.com";
    EXPECT_TRUE(OH_Http_CreateRequest(url) != nullptr);
}

HWTEST_F(NetHttpTest, SetOption001, TestSize.Level1)
{ 
    Http_Request *request = OH_Http_CreateRequest("https://www.baidu.com");
    request->options = (Http_RequestOptions *)calloc(1, sizeof(Http_RequestOptions));
    Http_ResponseCallback callback = testResponseCallback;
    Http_EventsHandler handler;
    
    request->options->method = "GET";
    int ret = OH_Http_Request(request, callback, handler);
    EXPECT_EQ(ret, 0);
    free(request->options);
    OH_Http_Destroy(&request);
}

HWTEST_F(NetHttpTest, SetOption002, TestSize.Level1)
{
    Http_Request *request = OH_Http_CreateRequest("https://www.baidu.com");
    request->options = (Http_RequestOptions *)calloc(1, sizeof(Http_RequestOptions));
    Http_ResponseCallback callback = testResponseCallback;
    Http_EventsHandler handler;
    
    request->options->priority = -1;
    int ret = OH_Http_Request(request, callback, handler);
    EXPECT_EQ(ret, 0);

    request->options->priority = 2000;
    ret = OH_Http_Request(request, callback, handler);
    EXPECT_EQ(ret, 0);

    request->options->priority = 1;
    ret = OH_Http_Request(request, callback, handler);
    EXPECT_EQ(ret, 0);

    request->options->readTimeout = 10;
    ret = OH_Http_Request(request, callback, handler);
    EXPECT_EQ(ret, 0);

    request->options->connectTimeout = 10;
    ret = OH_Http_Request(request, callback, handler);
    EXPECT_EQ(ret, 0);

    Http_Headers *header = OH_Http_CreateHeaders();
    EXPECT_TRUE(header != nullptr);
    OH_Http_SetHeaderValue(header, "Accept", "application/json");
    request->options->headers = header;
    ret = OH_Http_Request(request, callback, handler);
    EXPECT_EQ(ret, 0);
    free(request->options);
    OH_Http_DestroyHeaders(&header);
    OH_Http_Destroy(&request);
}

HWTEST_F(NetHttpTest, SetOption003, TestSize.Level1)
{
    Http_Request *request = OH_Http_CreateRequest("https://www.baidu.com");
    Http_ResponseCallback callback = testResponseCallback;
    Http_EventsHandler handler;
    request->options = (Http_RequestOptions *)calloc(1, sizeof(Http_RequestOptions));
    
    Http_Proxy httpProxy;
    httpProxy.proxyType = Http_ProxyType::HTTP_PROXY_NOT_USE;
    request->options->httpProxy = &httpProxy;
    int ret = OH_Http_Request(request, callback, handler);
    EXPECT_EQ(ret, 0);

    httpProxy.customProxy.host = "host test";
    ret = OH_Http_Request(request, callback, handler);
    EXPECT_EQ(ret, 0);

    httpProxy.customProxy.host = nullptr;
    httpProxy.customProxy.exclusionLists = "exclusionLists test";
    ret = OH_Http_Request(request, callback, handler);
    EXPECT_EQ(ret, 0);

    httpProxy.customProxy.host = "host test";
    ret = OH_Http_Request(request, callback, handler);
    EXPECT_EQ(ret, 0);

    request->options->caPath = "capath test";
    ret = OH_Http_Request(request, callback, handler);
    EXPECT_EQ(ret, 0);

    request->options->method = nullptr;
    request->options->resumeFrom = 10;
    request->options->resumeTo = 20;
    ret = OH_Http_Request(request, callback, handler);
    EXPECT_EQ(ret, 0);

    request->options->method = "PUT";
    request->options->resumeFrom = 10;
    request->options->resumeTo = 20;
    ret = OH_Http_Request(request, callback, handler);
    EXPECT_EQ(ret, 0);

    request->options->method = "GET";
    request->options->resumeFrom = 10;
    request->options->resumeTo = 20;
    ret = OH_Http_Request(request, callback, handler);
    EXPECT_EQ(ret, 0);
    free(request->options);
    OH_Http_Destroy(&request);
}

HWTEST_F(NetHttpTest, SetOtherOption001, TestSize.Level1)
{
    Http_Request *request = OH_Http_CreateRequest("https://www.baidu.com");
    request->options = (Http_RequestOptions *)calloc(1, sizeof(Http_RequestOptions));
    Http_ResponseCallback callback = testResponseCallback;
    Http_EventsHandler handler;
    int ret = OH_Http_Request(request, callback, handler);
    EXPECT_EQ(ret, 0);

    std::string clientCertTest = "test";
    request->options->clientCert = (Http_ClientCert *)calloc(1, sizeof(Http_ClientCert));
    request->options->clientCert->certPath = strdup(clientCertTest.c_str());
    ret = OH_Http_Request(request, callback, handler);
    EXPECT_EQ(ret, 0);

    request->options->clientCert->keyPassword = strdup(clientCertTest.c_str());
    ret = OH_Http_Request(request, callback, handler);
    EXPECT_EQ(ret, 0);

    request->options->clientCert->keyPath = strdup(clientCertTest.c_str());
    ret = OH_Http_Request(request, callback, handler);
    EXPECT_EQ(ret, 0);

    request->options->clientCert->type = Http_CertType::OH_HTTP_PEM;
    ret = OH_Http_Request(request, callback, handler);
    EXPECT_EQ(ret, 0);

    request->options->clientCert->type = Http_CertType::OH_HTTP_DER;
    ret = OH_Http_Request(request, callback, handler);
    EXPECT_EQ(ret, 0);

    request->options->clientCert->type = Http_CertType::OH_HTTP_P12;
    ret = OH_Http_Request(request, callback, handler);
    EXPECT_EQ(ret, 0);

    request->options->addressFamily = Http_AddressFamilyType::HTTP_ADDRESS_FAMILY_ONLY_V4;
    ret = OH_Http_Request(request, callback, handler);
    EXPECT_EQ(ret, 0);

    request->options->addressFamily = Http_AddressFamilyType::HTTP_ADDRESS_FAMILY_ONLY_V6;
    ret = OH_Http_Request(request, callback, handler);
    EXPECT_EQ(ret, 0);

    request->options->addressFamily = Http_AddressFamilyType::HTTP_ADDRESS_FAMILY_DEFAULT;
    ret = OH_Http_Request(request, callback, handler);
    EXPECT_EQ(ret, 0);
    free(request->options->clientCert->certPath);
    free(request->options->clientCert->keyPassword);
    free(request->options->clientCert->keyPath);
    free(request->options->clientCert);
    free(request->options);
    OH_Http_Destroy(&request);
}

HWTEST_F(NetHttpTest, HttpRequest001, TestSize.Level1)
{ 
    Http_ResponseCallback callback = testResponseCallback;
    Http_Request *request = OH_Http_CreateRequest("https://www.baidu.com");
    Http_EventsHandler handler;
    EXPECT_EQ(OH_Http_Request(nullptr, callback, handler), HTTP_OUT_OF_MEMORY);
    EXPECT_EQ(OH_Http_Request(request, nullptr, handler), HTTP_OUT_OF_MEMORY);
    OH_Http_Destroy(&request);
}

HWTEST_F(NetHttpTest, HttpRequest002, TestSize.Level1)
{ 
    Http_ResponseCallback callback = testResponseCallback;
    Http_Request *req = OH_Http_CreateRequest("https://www.baidu.com");
    req->options = (Http_RequestOptions *)calloc(1, sizeof(Http_RequestOptions));
    req->options->httpProtocol = Http_HttpProtocol::OH_HTTP1_1;
    Http_EventsHandler handler;
    EXPECT_EQ(OH_Http_Request(req, callback, handler), 0);
    OH_Http_Destroy(&req);
}

HWTEST_F(NetHttpTest, HttpDestroy001, TestSize.Level1)
{ 
    OH_Http_Destroy(nullptr);
    
    Http_Request *req = OH_Http_CreateRequest("https://www.baidu.com");
    EXPECT_TRUE(req != nullptr);
    OH_Http_Destroy(&req);
    
    Http_ResponseCallback callback = testResponseCallback;
    Http_EventsHandler handler;
    req = OH_Http_CreateRequest("https://www.baidu.com");
    EXPECT_TRUE(req != nullptr);
    OH_Http_Request(req, callback, handler);
    OH_Http_Destroy(&req);

    req = OH_Http_CreateRequest("https://www.baidu.com");
    EXPECT_TRUE(req != nullptr);
    OH_Http_Request(req, callback, handler);
    OH_Http_Destroy(&req);
    OH_Http_Destroy(&req);
}

HWTEST_F(NetHttpTest, RequestOnSuccess001, TestSize.Level1)
{
    Http_Request *req = OH_Http_CreateRequest("https://www.baidu.com");
    EXPECT_TRUE(req != nullptr);
    
    Http_ResponseCallback callback = testResponseCallback;
    Http_EventsHandler handler;
    OH_Http_Request(req, callback, handler);
    OH_Http_Destroy(&req);
}

HWTEST_F(NetHttpTest, RequestOnSuccess002, TestSize.Level1)
{
    Http_Request *request = OH_Http_CreateRequest("https://www.baidu.com");
    EXPECT_TRUE(request != nullptr);
    
    Http_ResponseCallback callback = testResponseCallback;
    Http_EventsHandler handler;
    Http_OnVoidCallback onDataEndCallback = myCallbackFunction;
    handler.onDataEnd = onDataEndCallback;
    OH_Http_Request(request, callback, handler);
    OH_Http_Destroy(&request);
}

HWTEST_F(NetHttpTest, RequestOnCancel001, TestSize.Level1)
{
    Http_Request *request = OH_Http_CreateRequest("https://www.baidu.com");
    EXPECT_TRUE(request != nullptr);
    
    Http_ResponseCallback callback = testResponseCallback;
    Http_EventsHandler handler;
    OH_Http_Request(request, callback, handler);
    OH_Http_Destroy(&request);
}

HWTEST_F(NetHttpTest, RequestOnCancel002, TestSize.Level1)
{
    Http_Request *request = OH_Http_CreateRequest("https://www.baidu.com");
    EXPECT_TRUE(request != nullptr);
    
    Http_ResponseCallback callback = testResponseCallback;
    Http_EventsHandler handler;
    Http_OnVoidCallback onDataEndCallback = myCallbackFunction;
    handler.onCanceled = onDataEndCallback;
    OH_Http_Request(request, callback, handler);
    OH_Http_Destroy(&request);
}

HWTEST_F(NetHttpTest, RequestOnFail001, TestSize.Level1)
{
    Http_Request *request = OH_Http_CreateRequest("https://www.baidu.com");
    EXPECT_TRUE(request != nullptr);
    
    Http_ResponseCallback callback = testResponseCallback;
    Http_EventsHandler handler;
    Http_OnVoidCallback onDataEndCallback = myCallbackFunction;
    handler.onDataEnd = onDataEndCallback;
    OH_Http_Request(request, callback, handler);
    OH_Http_Destroy(&request);
}

HWTEST_F(NetHttpTest, RequestOnDataReceive001, TestSize.Level1)
{
    Http_Request *request = OH_Http_CreateRequest("https://www.baidu.com");
    EXPECT_TRUE(request != nullptr);
    
    Http_ResponseCallback callback = testResponseCallback;
    Http_EventsHandler handler;
    Http_OnDataReceiveCallback onDataReceiveCallback = TestDataReceiveCallback;
    handler.onDataReceive = onDataReceiveCallback; 
    OH_Http_Request(request, callback, handler);
    OH_Http_Destroy(&request);
}

HWTEST_F(NetHttpTest, RequestOnHeadersReceive001, TestSize.Level1)
{
    Http_Request *request = OH_Http_CreateRequest("https://www.baidu.com");
    
    Http_EventsHandler handler;
    Http_ResponseCallback callback = testResponseCallback;
    Http_OnHeaderReceiveCallback onHeaderReceiveCallback = testHeaderReceiveCallback;
    handler.onHeadersReceive = onHeaderReceiveCallback;
    OH_Http_Request(request, callback, handler); 
    OH_Http_Destroy(&request);
}
}