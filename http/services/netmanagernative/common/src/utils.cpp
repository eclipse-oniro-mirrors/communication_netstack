#include <utils.h>
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <sys/types.h>
#include <unistd.h>
#include <dirent.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

namespace OHOS {
namespace nmd {
namespace common {

std::time_t utils::getCurrentTime()
{
    auto now = std::chrono::system_clock::now();
    return std::chrono::system_clock::to_time_t(now);
}

int nmd::common::utils::removeDirectory(const char *path)
{
    DIR *d = opendir(path);
    size_t path_len = strlen(path);
    int r = -1;

    if (d) {
        struct dirent *p = nullptr;

        r = 0;
        while (!r && (p = readdir(d))) {
            int r2 = -1;
            char *buf = nullptr;

            /* Skip the names "." and ".." as we don't want to recurse on them. */
            if (!strcmp(p->d_name, ".") || !strcmp(p->d_name, "..")) {
                continue;
            }

            size_t len = path_len + strlen(p->d_name) + 2;
            buf = reinterpret_cast<char *>(malloc(len));

            if (buf) {
                struct stat statbuf;

                snprintf(buf, len, "%s/%s", path, p->d_name);
                if (!stat(buf, &statbuf)) {
                    if (S_ISDIR(statbuf.st_mode)) {
                        r2 = removeDirectory(buf);
                    } else {
                        r2 = unlink(buf);
                    }
                }
                free(buf);
            }
            r = r2;
        }
        closedir(d);
    }

    if (!r) {
        r = rmdir(path);
    }

    return r;
}
} // namespace common
} // namespace nmd
} // namespace OHOS
