#ifndef ASMC_COMMON_H
#define ASMC_COMMON_H

#include <stdio.h>

void AsmCrt_abort(void) __attribute__((noreturn));
void AsmCrt_panic_at(const char* file, int line, const char* message) __attribute__((noreturn));

#define AsmCrt_trace(...) do {\
    printf("[TRACE at %s:%d]\t", __FILE__, __LINE__);\
    printf(__VA_ARGS__);\
    printf("\n");\
} while (0)

#define AsmCrt_panic(...) do {\
    fprintf(stderr, "[PANIC at %s:%d]\t", __FILE__, __LINE__);\
    fprintf(stderr, __VA_ARGS__);\
    fprintf(stderr, "\n");\
    AsmCrt_abort();\
} while (0)

#define AsmCrt_not_implemented(what) AsmCrt_panic_at(__FILE__, __LINE__, "Not implemented: " #what)

#endif
