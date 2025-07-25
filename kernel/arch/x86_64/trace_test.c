#include <kernel/arch/x86_64/trace_test.h>

void execute_test(void){
    if(apic_id==0){
        write_pte(0x3008, 0x5000, true);
        read_memory(0x200000);
        write_pte(0x6000, 0x1000, true);
    }else if(apic_id==1){
        write_pte(0x4000, 0x0, true);
        invalidate_page(0x1000);
    }else if(apic_id==2){
        write_pte(0x3000, 0x5000, true);
        write_pte(0x3000, 0x4000, true);
        write_pte(0x3008, 0x6000, true);
        read_memory(0x1000);
        invalidate_page(0x1000);
        write_pte(0x3008, 0x3008, false);
    }
}

