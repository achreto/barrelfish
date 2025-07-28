#include <kernel/arch/x86_64/trace_test.h>
#include <kernel/arch/x86_64/paging_test_utils.h>
#include <kernel/arch/x86_64/apic.h>

void execute_test(void){
    if(apic_id==0){
        invalidate_page(0x1000);
        invalidate_page(0x201000);
        write_pte(0x3000, 0x5000, true);
        write_pte(0x4000, 0x4000, false);
        barrier();
    }else if(apic_id==1){
        write_pte(0x3008, 0x4000, true);
        write_pte(0x3000, 0x3000, false);
        write_pte(0x3008, 0x3008, false);
    }else if(apic_id==2){
        write_pte(0x3000, 0x6000, true);
        read_memory(0x201000);
        read_memory(0x200000);
    }
}

