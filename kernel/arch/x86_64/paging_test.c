#include <arch/x86_64/paging_test.h>

#include <kernel.h>
#include <paging_kernel_arch.h>
#include <arch/x86_64/paging_test_utils.h>
#include <arch/x86/apic.h>

void execute_test(void* pd_start, void* pt_start, void* data_start){
    lpaddr_t pd_phys = mem_to_local_phys((lvaddr_t)pd_start);
    lpaddr_t pt_phys = mem_to_local_phys((lvaddr_t)pt_start);
    lpaddr_t data_phys = mem_to_local_phys((lvaddr_t)data_start);
    sync_cores();
    printf("PTModel: Core %d executing test\n", apic_id);
    if(apic_id==1 || apic_id==2 || apic_id==3){
        write_pte(pd_phys + BASE_PAGE_SIZE*0, 2, 0, pt_phys+BASE_PAGE_SIZE*0, true);
        printf("PTModel: Core %d mapped PD to PT\n", apic_id);
        for (int i = 0; i < 2; i++) {
            lvaddr_t vaddr = 0b000000000000000000000000000000;
            lpaddr_t paddr = data_phys + (i + 10 * apic_id)*BASE_PAGE_SIZE;  
            lvaddr_t vaddr_2 = local_phys_to_mem(paddr);
            printf("PTModel: Core %d reading value from vaddr %lx\n", apic_id, vaddr);
            int read_value;
            read_value = read_memory(vaddr);
            // map_virtual_to_physical(&hierarchy, vaddr, paddr, base_flags);
            write_pte(pt_phys + BASE_PAGE_SIZE*0, 3, 0, paddr, true);
            
            // Now we can safely write to the mapped virtual address
            int value = 20 + i;
            write_memory(vaddr_2, value);
            
            // Verify the mapping works
            read_value = read_memory(vaddr);
            if (read_value == value) {
                printf("PTModel: Successfully mapped and wrote value %d to 0x%lx\n", value, vaddr);
            } else {
                printf("PTModel: Mapping verification failed: wrote %d, read %d\n", value, read_value);
            }
            write_pte(pt_phys + BASE_PAGE_SIZE*0, 3, 0, paddr, false);
        }
    }
}