#include "AsmC-x86-32.h"

uint32_t x86g_calculate_condition(uint32_t/*X86Condcode*/ cond, uint32_t cc_op, uint32_t cc_dep1, uint32_t cc_dep2, uint32_t cc_ndep) {
    AsmCrt_not_implemented(x86g_calculate_condition);
}

uint32_t x86g_calculate_eflags_c(uint32_t cc_op, uint32_t cc_dep1, uint32_t cc_dep2, uint32_t cc_ndep) {
    AsmCrt_not_implemented(x86g_calculate_eflags_c);
}

uint32_t x86g_use_seg_selector(uint16_t ldt, uint16_t gdt, uint32_t seg_selector, uint32_t virtual_addr) {
    AsmCrt_not_implemented(x86g_use_seg_selector);
}

uint32_t x86g_check_fldcw(uint32_t fpucw) { AsmCrt_not_implemented(x86g_check_fldcw); }
uint32_t x86g_create_fpucw(uint32_t fpround) { AsmCrt_not_implemented(x86g_create_fpucw); }
