#include "iptables_process.h"
#include <errno.h>
#include <fcntl.h>
#include <iostream>
#include <memory>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
#include <linux/limits.h>
#include <logger.h>
#include "netnative_log_wrapper.h"

static int MAX_RETRIES = 50;
static int POLL_TIMEOUT_MS = 100;
static constexpr size_t STDOUT_IDX = 0;
static constexpr char PING[] = "#PING\n";
static constexpr size_t PING_SIZE = sizeof(PING) - 1;

namespace OHOS {
namespace nmd {
iptables_process::iptables_process(/* args */) {}

iptables_process::~iptables_process() {}

iptables_process::iptables_process(pid_t pid, int in, int out, int err)
    : pid_(pid), stdin_(in), stdout_(out), stderr_(err)
{}

void iptables_process::terminate()
{
    int err = kill(this->pid_, SIGTERM);
    if (err) {
        NETNATIVE_LOGE(
            "iptables_process::terminate [IpTablesRestore]  terminate failed: %{public}s", strerror(errno));
    }
}

bool iptables_process::waitForAck(std::string &output)
{
    bool receivedAck = false;
    int timeout = 0;
    while (!receivedAck && (timeout++ < MAX_RETRIES)) {
        int numEvents = poll(this->pollFds_, 2, POLL_TIMEOUT_MS);
        if (numEvents == -1) {
            NETNATIVE_LOGE("iptables_process::waitForAck: [IpTablesRestore]  poll failed:");
            return false;
        }
        if (numEvents == 0) {
            continue;
        }
        char buffer[PIPE_BUF];
        for (size_t i = 0; i < 2; ++i) {
            const struct pollfd &pollfd = this->pollFds_[i];
            if (pollfd.revents & POLLIN) {
                ssize_t size;
                do {
                    size = read(pollfd.fd, buffer, sizeof(buffer));

                    if (size == -1) {
                        if (errno != EAGAIN) {
                            NETNATIVE_LOGE(
                                "[IpTablesRestore] unable to read from descriptor:  %{public}s", strerror(errno));
                        }
                        break;
                    }

                    if (i == STDOUT_IDX) {
                        output.append(buffer, static_cast<unsigned long>(size));
                        size_t pos = output.find(PING);
                        if (pos != std::string::npos) {
                            if (output.size() > pos + PING_SIZE) {
                                size_t extra = output.size() - (pos + PING_SIZE);
                                NETNATIVE_LOGE(
                                    "[IpTablesRestore]  %{public}d extra characters after iptables response: "
                                    "%{public}s",
                                    extra, output.substr(pos + PING_SIZE, 128).c_str());
                            }
                            output.resize(pos);
                            receivedAck = true;
                        }
                    } else {
                        this->errBuf.append(buffer, static_cast<unsigned long>(size));
                    }
                } while (size > 0);
            }
            if (pollfd.revents & POLLHUP) {
                this->terminate();
                break;
            }
        }
    }
    return true;
}

/*********************************************************************/
struct data_test {
    int stdin_pipe[2] = {};
    int stdout_pipe[2] = {};
    int stderr_pipe[2] = {};
};

static std::shared_ptr<nmd::iptables_process> pProcess = nullptr;
std::shared_ptr<nmd::iptables_process> publicProcess = NULL;

static pthread_mutex_t test_lock;

data_test data;

static void *Test_Function(void *tmp)
{
    NETNATIVE_LOGI("[IpTablesRestore] iptables_restore starting...");
    if (dup2(data.stdin_pipe[0], 0) == -1 || dup2(data.stdout_pipe[1], 1) == -1 ||
        dup2(data.stderr_pipe[1], 2) == -1) {
        NETNATIVE_LOGE("[IpTablesRestore] iptables_restore command execute failed");
    }
    // char *argv[] = {const_cast<char *>("iptables-restore"), const_cast<char *>("--noflush"),const_cast<char
    // *>("-v"), NULL}; if (execvp("iptables-restore", argv) == -1) { 	NETNATIVE_LOGE("[IpTablesRestore]
    //iptables_restore command execute failed.");
    //}
    NETNATIVE_LOGI("[IpTablesRestore] iptables_restore running... ");

    if (close(data.stdin_pipe[0]) == -1 || close(data.stdout_pipe[1]) == -1 || close(data.stderr_pipe[1]) == -1) {
        // LogError <std::make_shared<nmd::iptables_process>(0, data->stdin_pipe[1], data->stdout_pipe[0],
        // data->st< "[IpTablesRestore] close unusing fds in pipe failed." << endl;
        NETNATIVE_LOGE("[IpTablesRestore] close unusing fds in pipe failed.");
    }
    pthread_mutex_lock(&test_lock);
    // std::make_shared<iptables_process>(0, data->stdin_pipe[1], data->stdout_pipe[0], data->stderr_pipe[0]);
    pProcess =
        std::make_shared<nmd::iptables_process>(0, data.stdin_pipe[1], data.stdout_pipe[0], data.stderr_pipe[0]);
    pthread_mutex_unlock(&test_lock);
    return NULL;
}

std::shared_ptr<nmd::iptables_process> nmd::iptables_process::forkAndExecute()
{
    // int stdin_pipe[2] = {};
    // int stdout_pipe[2] = {};
    // int stderr_pipe[2] = {};

    if (pipe2(data.stdin_pipe, O_CLOEXEC) == -1 || pipe2(data.stdout_pipe, O_CLOEXEC | O_NONBLOCK) == -1 ||
        pipe2(data.stderr_pipe, O_CLOEXEC | O_NONBLOCK) == -1) {
        NETNATIVE_LOGE("[IpTablesRestore] pipe create failed.");
    }

    pthread_t thread_test;
    pthread_create(&thread_test, NULL, Test_Function, NULL);

    pthread_mutex_lock(&test_lock);
    publicProcess = pProcess;
    pthread_mutex_unlock(&test_lock);
    return publicProcess;

    /*
    if (fork() == 0) {
        common::logger::info() << "[IpTablesRestore] iptables_restore starting..." << endl;
        if (dup2(stdin_pipe[0], 0) == -1 || dup2(stdout_pipe[1], 1) == -1 || dup2(stderr_pipe[1], 2) == -1) {
            LogError << "[IpTablesRestore] iptables_restore command execute failed" << endl;
        }
        char *argv[] = {const_cast<char *>("iptables-restore"), const_cast<char *>("--noflush"),
            const_cast<char *>("-v"), NULL};
        if (execvp("iptables-restore", argv) == -1) {
            LogError << "[IpTablesRestore] iptables_restore command execute failed，" << strerror(errno) << endl;
        }
        common::logger::info() << "[IpTablesRestore] iptables_restore running... " << endl;
        return nullptr;
    }

    if (close(stdin_pipe[0]) == -1 || close(stdout_pipe[1]) == -1 || close(stderr_pipe[1]) == -1) {
        LogError << "[IpTablesRestore] close unusing fds in pipe failed." << endl;
    }

    return std::make_shared<iptables_process>(0, stdin_pipe[1], stdout_pipe[0], stderr_pipe[0]);
    */
}
} // namespace nmd
} // namespace OHOS
