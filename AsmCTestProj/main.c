#include "AsmC-x86-32.h"

extern const AsmC_ProgramInfo32_t Heroes3_info;
extern const AsmC_BbTableEntry32_t Heroes3_bb_table[];

int main() {
    AsmC_init_state_x86_32(Heroes3_info.entry_addr);

    AsmC_run_program_x86_32(Heroes3_bb_table);
}
