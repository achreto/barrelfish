#include <kernel.h>
#include <sys_debug.h>
#include <paging_kernel_arch.h>
#include <arch/x86/global.h>
#include <dev/amd64_dev.h>
#include <systime.h>

errval_t debug_pt_model_test(void)
{
    printf("PTModel: Running test on core %d...\n", my_core_id);
    if (my_core_id != 0) {
        printf("PTModel: global->pml4 = 0x%lx\n", (uint64_t)global->pml4);
        uint64_t cr3_val = 0;
        __asm__ volatile("mov %%cr3, %0" : "=r"(cr3_val));
        printf("PTModel: CR3 register value = 0x%lx\n", cr3_val);
        
        // Switch to core 0's page table (which has kernel mappings)
        paging_x86_64_context_switch((lpaddr_t)global->pml4);
        
        // Your operations here - now using core 0's page table
        printf("PTModel: Now using core 0's page table on core %d\n", my_core_id);
    }
    
    return SYS_ERR_OK;
}