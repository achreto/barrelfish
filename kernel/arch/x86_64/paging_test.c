#include <arch/x86_64/paging_test.h>

#include <kernel.h>
#include <paging_kernel_arch.h>
#include <arch/x86_64/paging_test_utils.h>
#include <arch/x86/apic.h>

void execute_function(void* pd_start, void* pt_start, void* data_start){
    if(apic_id==1){
        write_pte(pd_start + BASE_PAGE_SIZE*0, 2, 0b000000000_000000000_000000000000, pt_start+BASE_PAGE_SIZE*1, true);
    }
}