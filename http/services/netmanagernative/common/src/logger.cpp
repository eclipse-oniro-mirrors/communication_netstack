#include "logger.h"
#include <fstream>
#include <iostream>
#include <time.h>

nmd::common::logger *nmd::common::logger::logger_ = nullptr;
nmd::common::log_config nmd::common::logger::config_;

const char *g_log_level_name[8] = {"Info", "Debug", "Error", "Warn", "Fatal"};
nmd::common::logger::logger()
{
    std::string logFileName = this->getLogFileName();
    this->osWrite_ = new std::ofstream(logFileName, std::ofstream::app);
}

nmd::common::logger::~logger()
{
    this->osWrite_->close();
}

void nmd::common::logger::writeTime()
{
    char logStr[2048] = {'\0'};
    time_t t = time(0);
    char date[32] = {'\0'};
    strftime(date, sizeof(date), "[%Y-%m-%d %H:%M:%S]", localtime(&t));
    sprintf(logStr, "%s[%s]", date, g_log_level_name[this->level_]);
    *(this->osWrite_) << logStr;
    std::cout << logStr;
}

void nmd::common::logger::write(std::string log)
{
    *(this->osWrite_) << log;
    std::cout << log;
}

std::string nmd::common::logger::getLogFileName()
{
    time_t t = time(0);
    char tmp[32] = {'\0'};
    strftime(tmp, sizeof(tmp), "%Y-%m-%d", localtime(&t));
    std::string path(config_.path);
    path.append(tmp);
    path.append(".log");
    return path;
}