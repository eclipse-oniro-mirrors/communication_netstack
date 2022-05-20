/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "disk_handler.h"
#include "netstack_log.h"

#include <cerrno>
#include <fcntl.h>
#include <memory>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

namespace OHOS::NetStack {
DiskHandler::DiskHandler(std::string fileName) : fileName_(std::move(fileName)) {}

void DiskHandler::Write(const std::string &str)
{
    char buffer[500] = {0};
    getcwd(buffer, sizeof(buffer));
    if (strlen(buffer)) {
        NETSTACK_LOGI("pwd: %{public}s", buffer);
    } else {
        NETSTACK_LOGI("pwd: can not get pwd");
    }


    int fd = open(fileName_.c_str(), O_CREAT | O_WRONLY, S_IWUSR | S_IRUSR);
    if (fd < 0) {
        NETSTACK_LOGE("errmsg: Write open [%{public}d] %{public}s|\n", errno, strerror(errno));
        return;
    }

    int ret = flock(fd, LOCK_NB | LOCK_EX);
    if (ret < 0) {
        NETSTACK_LOGE("errmsg: Write open [%{public}d] %{public}s|\n", errno, strerror(errno));
        close(fd);
        return;
    }

    if (write(fd, str.c_str(), str.size()) < 0) {
        NETSTACK_LOGE("errmsg: Write open [%{public}d] %{public}s|\n", errno, strerror(errno));
    }

    flock(fd, LOCK_UN);
    close(fd);
}

std::string DiskHandler::Read()
{
    int fd = open(fileName_.c_str(), O_RDONLY);
    if (fd < 0) {
        NETSTACK_LOGE("errmsg: Read open [%{public}d] %{public}s|\n", errno, strerror(errno));
        return {};
    }

    int ret = flock(fd, LOCK_NB | LOCK_EX);
    if (ret < 0) {
        NETSTACK_LOGE("errmsg: Read flock [%{public}d] %{public}s|\n", errno, strerror(errno));
        close(fd);
        return {};
    }

    struct stat buf = {0};
    if (fstat(fd, &buf) < 0 || buf.st_size <= 0) {
        flock(fd, LOCK_UN);
        close(fd);
        return {};
    }

    std::unique_ptr<char> mem = std::unique_ptr<char>(new char[buf.st_size]);
    if (read(fd, mem.get(), buf.st_size) < 0) {
        NETSTACK_LOGE("errmsg: Read read [%{public}d] %{public}s|\n", errno, strerror(errno));
    }

    flock(fd, LOCK_UN);
    close(fd);
    std::string str;
    str.append(mem.get(), buf.st_size);
    return str;
}
} // namespace OHOS::NetStack
