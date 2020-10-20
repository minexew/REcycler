#include "AsmC-common.h"

#include <stdlib.h>

__attribute__((noinline)) __attribute__((noreturn)) void AsmCrt_abort(void) {
    abort();
}

__attribute__((noreturn)) void AsmCrt_panic_at(const char* file, int line, const char* message) {
    fprintf(stderr, "[PANIC at %s:%d]\t", __FILE__, __LINE__);
    fprintf(stderr, "%s", message);
    fprintf(stderr, "\n");
    AsmCrt_abort();
}
