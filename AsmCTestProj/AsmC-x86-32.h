#ifndef ASMC_X86_32_H
#define ASMC_X86_32_H

#include "AsmC-common.h"

#include <stdint.h>
#include <stdlib.h>

typedef struct {
    /* TODO: 32-bit safety */
    uint32_t entry_addr;
} AsmC_ProgramInfo32_t;

typedef struct {
    uint32_t addr;
    void (*func)(void);
} AsmC_BbTableEntry32_t;

#define MAKE_ExX(enamex, namex, namel, nameh) union {\
    uint32_t enamex;\
    uint16_t namex;\
    struct {\
        uint8_t namel, nameh;\
    };\
}

typedef struct {
    // 8 eax
    MAKE_ExX(eax, ax, al, ah);
    // 12 ecx
    MAKE_ExX(ecx, cx, cl, ch);
    // 16 edx
    MAKE_ExX(edx, dx, dl, dh);
    // 20 ebx
    MAKE_ExX(ebx, bx, bl, bh);
    // 24 esp
    uint32_t esp;
    // 28 ebp
    uint32_t ebp;
    // 32 esi
    uint32_t esi;
    // 36 edi
    uint32_t edi;
    // 40 cc_op, cc_dep1, cc_dep2, cc_ndep
    uint32_t cc_op, cc_dep1, cc_dep2, cc_ndep;

    // 56 d (helper for the [Direction flag](https://en.wikipedia.org/wiki/Direction_flag))
    int d;

    // 68 eip
    uint32_t eip;

    // 144 fpround
    uint32_t fpround;
    // 148 fc3210
    uint32_t fc3210;        // wtf
    // 152 ftop
    uint32_t ftop;

    // 294 fs
    uint16_t fs;

    // 304 ldf
    uint64_t ldt;
    // 312 gdt
    uint64_t gdt;

    // 320 emnote
    uint32_t emnote;        // wtf
} AsmC_State_x86_32_t;

extern AsmC_State_x86_32_t AsmC_state_x86_32;

void AsmC_init_state_x86_32(uint32_t eip);
void AsmC_run_program_x86_32(AsmC_BbTableEntry32_t const* bbtable);

// TODO: how to handle 32-/64-bit address spaces?
// One option is to prefix the function names by architecture (x86_32_Load8 etc.)
uint8_t Load_8(uint32_t addr);
uint16_t Load_16(uint32_t addr);
uint32_t Load_32(uint32_t addr);
uint64_t Load_64(uint32_t addr);
void Store_8(uint32_t addr, uint8_t value);
void Store_16(uint32_t addr, uint16_t value);
void Store_32(uint32_t addr, uint32_t value);
void Store_64(uint32_t addr, uint64_t value);

// TODO: can we steal the implementations from some VEX interpreter ?
uint32_t Iop_CmpF64(double, double);
float Iop_F64toF32(uint32_t rounding_mode, double value);
int64_t Iop_F64toI64S(uint32_t rounding_mode, double value);


// Valgrind built-ins (GPL code !!)

uint32_t x86g_calculate_condition(uint32_t/*X86Condcode*/ cond, uint32_t cc_op, uint32_t cc_dep1, uint32_t cc_dep2, uint32_t cc_ndep);

uint32_t x86g_calculate_eflags_c(uint32_t cc_op, uint32_t cc_dep1, uint32_t cc_dep2, uint32_t cc_ndep);

uint32_t x86g_check_fldcw(uint32_t fpucw);
uint32_t x86g_create_fpucw(uint32_t fpround);

/* Translate a guest virtual_addr into a guest linear address by
   consulting the supplied LDT/GDT structures.  Their representation
   must be as specified in pub/libvex_guest_x86.h.  To indicate a
   translation failure, 1<<32 is returned.  On success, the lower 32
   bits of the returned result indicate the linear address.
*/
uint32_t x86g_use_seg_selector(uint16_t ldt, uint16_t gdt, uint32_t seg_selector, uint32_t virtual_addr);

#endif
