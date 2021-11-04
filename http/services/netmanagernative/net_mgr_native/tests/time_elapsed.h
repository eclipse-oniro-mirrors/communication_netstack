#ifndef __TESTS_TIME_ELAPSED_H__
#define __TESTS_TIME_ELAPSED_H__

#include <iostream>
#include <chrono>
#include <stdint.h>

static inline int64_t elapsed_ns(std::chrono::time_point<std::chrono::high_resolution_clock> m_begin)
{
    return std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::high_resolution_clock::now() - m_begin)
        .count();
}

static inline int64_t elapsed_us(std::chrono::time_point<std::chrono::high_resolution_clock> m_begin)
{
    return std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::high_resolution_clock::now() - m_begin)
        .count();
}

static inline int64_t elapsed_ms(std::chrono::time_point<std::chrono::high_resolution_clock> m_begin)
{
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::high_resolution_clock::now() - m_begin)
        .count();
}

#define GEN_INVOKE_US(name, title, expr)                                                        \
    auto name = [&] {                                                                           \
        std::chrono::time_point<std::chrono::high_resolution_clock> m_begin =                   \
            std::chrono::high_resolution_clock::now();                                          \
        auto result = expr;                                                                     \
        std::cout << #name << "," << #title << "," << elapsed_us(m_begin) << "us" << std::endl; \
        return result;                                                                          \
    };

#define GEN_INVOKE_MS(name, title, expr)                                                        \
    auto name = [&] {                                                                           \
        std::chrono::time_point<std::chrono::high_resolution_clock> m_begin =                   \
            std::chrono::high_resolution_clock::now();                                          \
        auto result = expr;                                                                     \
        std::cout << #name << "," << #title << "," << elapsed_ms(m_begin) << "ms" << std::endl; \
        return result;                                                                          \
    };

#define GEN_INVOKE_NS(name, title, expr)                                                        \
    auto name = [&] {                                                                           \
        std::chrono::time_point<std::chrono::high_resolution_clock> m_begin =                   \
            std::chrono::high_resolution_clock::now();                                          \
        auto result = expr;                                                                     \
        std::cout << #name << "," << #title << "," << elapsed_ns(m_begin) << "ns" << std::endl; \
        return result;                                                                          \
    };

#endif //!__TESTS_TIME_ELAPSED_H__