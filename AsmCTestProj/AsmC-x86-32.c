#include "AsmC-x86-32.h"

#include <stdio.h>

AsmC_State_x86_32_t AsmC_state_x86_32;
#define cpu AsmC_state_x86_32

void AsmC_init_state_x86_32(uint32_t eip) {
    cpu.eip = eip;
}

void AsmC_run_program_x86_32(AsmC_BbTableEntry32_t const* bbtable) {
    for (;;) {
        printf("[AsmC_run_program_x86_32: eip=%08Xh]\n", cpu.eip);

        // find basic block to execute
        void (*f)() = NULL;

        for (size_t i = 0; bbtable[i].func; i++) {
            if (bbtable[i].addr == cpu.eip) {
                f = bbtable[i].func;
                break;
            }
        }

        if (!f) {
            AsmCrt_panic("No basic block corresponding to eip=%08Xh", cpu.eip);
        }
        else {
            printf("Resolved to %p\n", f);
        }

        f();
    }
}

// TODO: how to handle 32-/64-bit address spaces?
// One option is to prefix the function names by architecture (x86_32_Load8 etc.)
uint8_t Load_8(uint32_t addr) { AsmCrt_not_implemented(Load_8); }
uint16_t Load_16(uint32_t addr) { AsmCrt_not_implemented(Load_16); }
uint32_t Load_32(uint32_t addr) { AsmCrt_not_implemented(Load_32); }
uint64_t Load_64(uint32_t addr) { AsmCrt_not_implemented(Load_64); }

void Store_8(uint32_t addr, uint8_t value) {
    AsmCrt_not_implemented(Store_8);
}
void Store_16(uint32_t addr, uint16_t value) {
    AsmCrt_not_implemented(Store_16);
}
void Store_32(uint32_t addr, uint32_t value) {
    AsmCrt_trace("Store_32(%08X, %08X)", addr, value);
    AsmCrt_not_implemented(Store_32);
}
void Store_64(uint32_t addr, uint64_t value) {
    AsmCrt_not_implemented(Store_64);
}

// TODO: can we steal the implementations from some VEX interpreter ?
uint32_t Iop_CmpF64(double a, double b) { AsmCrt_not_implemented(Iop_CmpF64); }
float Iop_F64toF32(uint32_t rounding_mode, double value) { AsmCrt_not_implemented(Iop_F64toF32); }
int64_t Iop_F64toI64S(uint32_t rounding_mode, double value) { AsmCrt_not_implemented(Iop_F64toI64S); }
