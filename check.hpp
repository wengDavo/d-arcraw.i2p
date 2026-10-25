// Minimal check macro for the test executables. Mirrors the assert-and-print style
// of the reference tests, and stays active regardless of NDEBUG.
#pragma once
#include <cstdio>
#include <cstdlib>

#define REQUIRE(cond)                                                          \
    do {                                                                       \
        if (!(cond)) {                                                         \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);\
            std::exit(1);                                                      \
        }                                                                      \
    } while (0)
