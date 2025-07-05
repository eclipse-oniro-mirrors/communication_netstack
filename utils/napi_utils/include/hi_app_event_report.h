/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: HiAppEvent report
 */

#ifndef HI_SDK_REPORT
#define HI_SDK_REPORT

#ifdef ENABLE_EVENT_HANDLER
#include "app_event.h"
#include "app_event_processor_mgr.h"
#endif

#include <vector>
#include <cstdint>
#include <string>

namespace OHOS {
namespace NetStack {
static constexpr int RESULT_SUCCESS = 0;
static constexpr int RESULT_FAIL = 1;
static constexpr int ERR_NONE = 0;

class HiAppEventReport {
public:
    HiAppEventReport(std::string sdk, std::string api);
    ~HiAppEventReport();
    void ReportSdkEvent(const int result, const int errCode);

#ifdef ENABLE_EVENT_HANDLER
private:
    int64_t AddProcessor();

    int64_t beginTime_ = 0;
    std::string transId_ = "";
    std::string apiName_ = "";
    std::string sdkName_ = "";
#endif
};
} // namespace NetStack
} // namespace OHOS
#endif //HI_SDK_REPORT
