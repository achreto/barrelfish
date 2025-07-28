#include <kernel/arch/x86_64/trace_test.h>

void execute_test(void){
    if(apic_id==0){
        barrier();
        invalidate_page(0x201000);
        barrier();
        read_memory(0x1000);
    }else if(apic_id==1){
        invalidate_page(0x201000);
        invalidate_page(0x0);
        write_pte(0x4000, 0x1000, true);
        write_pte(0x3008, 0x4000, true);
        write_pte(0x4000, 0x4000, false);
    }else if(apic_id==2){
        write_pte(0x0, 0x0, false);
        read_memory(0x0);
    }
}

