/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "../fetch_module.h"
#include "../http_request/http_async_callback.h"
#include "../http_request/http_request_utils.h"
#include "jerryscript-core.h"
#include "js_async_work.h"
#include "message_queue_utils.h"

#define FUNC_BEGIN()                                            \
    do {                                                        \
        HTTP_REQUEST_INFO("%s BEGIN ##########", __FUNCTION__); \
    } while (0)

#define FUNC_END_NO_NEW_LINE()                                \
    do {                                                      \
        HTTP_REQUEST_INFO("%s END ##########", __FUNCTION__); \
    } while (0)

#define FUNC_END()                                                  \
    do {                                                            \
        HTTP_REQUEST_INFO("%s END ##########\n\n\n", __FUNCTION__); \
    } while (0)

namespace OHOS {
namespace ACELite {
void InitFetchModule(JSIValue exports);
class JerryInitializer {
private:
    int *temp;
    JSIValue exports;

public:
    JerryInitializer()
    {
        temp = new int;
        jerry_init(JERRY_INIT_EMPTY);
        JsAsyncWork::SetAppQueueHandler(temp);
        exports = JSI::CreateObject();
        InitFetchModule(exports);
    }

    ~JerryInitializer()
    {
        jerry_cleanup();
        delete temp;
        JSI::ReleaseValue(exports);
    }
};

void TestPutMessage(void *data)
{
    auto msg = static_cast<AbilityInnerMsg *>(data);
    auto asyncWork = static_cast<AsyncWork *>(msg->data);
    asyncWork->workHandler(asyncWork->data);
}

JSIValue TestCallbackOnSuccess(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum)
{
    FUNC_BEGIN();
    (void)thisVal;
    (void)argsNum;

    JSIValue para = args[0];
    HTTP_REQUEST_INFO("code = %d",
                      static_cast<int>(JSI::GetNumberProperty(para, HttpConstant::KEY_HTTP_RESPONSE_CODE)));

    size_t size = 0;
    char *data = JSI::GetStringProperty(para, HttpConstant::KEY_HTTP_RESPONSE_DATA, size);
    std::string body;
    for (uint32_t index = 0; index < size; ++index) {
        if (data[index] != 0) {
            body += data[index];
        } else {
            body += "0";
        }
    }
    HTTP_REQUEST_INFO("%s", body.c_str());

    JSIValue head = JSI::GetNamedProperty(para, HttpConstant::KEY_HTTP_RESPONSE_HEADERS);

    JSIValue keys = JSI::GetObjectKeys(head);
    uint32_t length = JSI::GetArrayLength(keys);
    for (uint32_t i = 0; i < length; ++i) {
        JSIValue k = JSI::GetPropertyByIndex(keys, i);
        char *s = JSI::ValueToString(k);
        char *v = JSI::GetStringProperty(head, s);
        HTTP_REQUEST_INFO("%s ---------------- %s", s, v);
    }

    FUNC_END_NO_NEW_LINE();
    return JSI::CreateUndefined();
}

JSIValue TestCallbackOnFail(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum)
{
    FUNC_BEGIN();
    (void)thisVal;
    (void)argsNum;

    HTTP_REQUEST_INFO("err = %s", JSI::ValueToString(args[0]));
    HTTP_REQUEST_INFO("code = %d", static_cast<int>(JSI::ValueToNumber(args[1])));

    FUNC_END_NO_NEW_LINE();
    return JSI::CreateUndefined();
}

JSIValue TestCallbackOnComplete(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum)
{
    FUNC_BEGIN();
    (void)thisVal;
    (void)args;
    (void)argsNum;

    HTTP_REQUEST_INFO("request complete");

    FUNC_END_NO_NEW_LINE();
    return JSI::CreateUndefined();
}

void TestHttpModuleMethodAndHeaderByDefault()
{
    FUNC_BEGIN();

    JSIValue object = JSI::CreateObject();
    if (object == nullptr) {
        return;
    }

    JSIValue header = JSI::CreateObject();
    JSI::SetStringProperty(header, "no-use", "test value");
    JSI::SetNamedProperty(object, HttpConstant::KEY_HTTP_REQUEST_HEADER, header);

    JSIValue url = JSI::CreateString("https://www.zhihu.com");
    JSI::SetNamedProperty(object, HttpConstant::KEY_HTTP_REQUEST_URL, url);

    JSI::SetNamedProperty(object, CB_SUCCESS, JSI::CreateFunction(TestCallbackOnSuccess));
    JSI::SetNamedProperty(object, CB_FAIL, JSI::CreateFunction(TestCallbackOnFail));
    JSI::SetNamedProperty(object, CB_COMPLETE, JSI::CreateFunction(TestCallbackOnComplete));

    JSIValue arg[1] = {object};
    FetchModule::Fetch(nullptr, arg, 1);

    FUNC_END();
}

} // namespace ACELite
} // namespace OHOS

int main()
{
    OHOS::ACELite::JerryInitializer jerryInitializer;

    OHOS::ACELite::TestHttpModuleMethodAndHeaderByDefault();

    return 0;
}