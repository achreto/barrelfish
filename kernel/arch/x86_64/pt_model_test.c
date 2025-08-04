#include <kernel.h>
#include <sys_debug.h>
#include <paging_kernel_arch.h>
#include <arch/x86/global.h>
#include <dev/amd64_dev.h>
#include <systime.h>

#define NUM_PD_PAGES 1
#define NUM_PT_PAGES 1
#define NUM_PDPT_PAGES 4 

// Structure to hold page table hierarchy information
struct page_table_hierarchy {
    union x86_64_pdir_entry *pml4;      // PML4 table (uses global->pml4)
    union x86_64_pdir_entry *pdpt;      // Page Directory Pointer Table (uses global->mem pages)
    union x86_64_ptable_entry *pd;      // Page Directory (uses global->mem pages)
    union x86_64_ptable_entry *pt;      // Page Table (uses global->mem pages)
    size_t pml4_index;                  // Which PML4 entry to use
    size_t mem_page_pdpt;               // Which page from global->mem to use for PDPT
    size_t mem_page_pd;                 // Which page from global->mem to use for PD
    size_t mem_page_pt;                 // Which page from global->mem to use for PT
};

// Function to check if a PML4 entry is safe to use (not used by kernel)
static bool is_safe_pml4_index(size_t pml4_index)
{
    // Kernel uses the highest PML4 entries (indices 508-511 in a 512-entry PML4)
    // Based on the constants from pmap.h:
    // - NPML4EPG = 512 (number of PML4 entries per page)
    // - NKPML4E = 4 (number of kernel PML4 entries)
    // - KPML4BASE = (NPML4EPG-NKPML4E) = 508
    // - KPML4I = (NPML4EPG-1) = 511
    
    const size_t KERNEL_PML4_START = 508;  // KPML4BASE
    const size_t KERNEL_PML4_END = 511;    // KPML4I
    
    // Check if the index is in the kernel range
    if (pml4_index >= KERNEL_PML4_START && pml4_index <= KERNEL_PML4_END) {
        return false;
    }
        
    return true;
}

// Function to create empty page directories using pages from global->mem
static errval_t create_page_table_hierarchy(size_t pml4_index,
                                   size_t mem_page_pdpt,
                                   size_t mem_page_pd,
                                   size_t mem_page_pt,
                                   struct page_table_hierarchy *hierarchy)
{
    printf("PTModel: Creating page table hierarchy using global->mem pages:\n");
    printf("  PML4 index: %zu, PDPT page: %zu, PD page: %zu, PT page: %zu\n",
           pml4_index, mem_page_pdpt, mem_page_pd, mem_page_pt);
    
    // Verify that the PML4 index is safe to use
    if (!is_safe_pml4_index(pml4_index)) {
        printf("PTModel: ERROR - PML4 index %zu is not safe to use (kernel space or already in use)\n", pml4_index);
        return SYS_ERR_OK;
    }
    
    // Use the existing global PML4
    hierarchy->pml4 = (union x86_64_pdir_entry *)local_phys_to_mem((lpaddr_t)global->pml4);
    hierarchy->pml4_index = pml4_index;
    
    // Use pages from global->mem for page directories
    // global->mem contains a physical address, so we need to convert it to virtual
    lpaddr_t global_mem_phys = (lpaddr_t)global->mem;
    lvaddr_t global_mem_virt = local_phys_to_mem(global_mem_phys);
    
    hierarchy->pdpt = (union x86_64_pdir_entry *)(global_mem_virt + (mem_page_pdpt * BASE_PAGE_SIZE));
    hierarchy->pd = (union x86_64_ptable_entry *)(global_mem_virt + (mem_page_pd * BASE_PAGE_SIZE));
    hierarchy->pt = (union x86_64_ptable_entry *)(global_mem_virt + (mem_page_pt * BASE_PAGE_SIZE));
    hierarchy->mem_page_pdpt = mem_page_pdpt;
    hierarchy->mem_page_pd = mem_page_pd;
    hierarchy->mem_page_pt = mem_page_pt;
    
    printf("PTModel: Using global->mem pages:\n");
    printf("  PML4: global->pml4 at index %zu (safe)\n", pml4_index);
    printf("  PDPT: global->mem page %zu (addr: %p)\n", mem_page_pdpt, hierarchy->pdpt);
    printf("  PD:   global->mem page %zu (addr: %p)\n", mem_page_pd, hierarchy->pd);
    printf("  PT:   global->mem page %zu (addr: %p)\n", mem_page_pt, hierarchy->pt);
    printf("  Global mem phys: 0x%lx, virt: %p\n", global_mem_phys, (void*)global_mem_virt);
    
    // Clear the specific pages we're using
    paging_x86_64_clear_pdir(hierarchy->pdpt);
    paging_x86_64_clear_pdir((union x86_64_pdir_entry *)hierarchy->pd);
    paging_x86_64_clear_ptable(hierarchy->pt);
    
    printf("PTModel: Cleared page directory pages\n");
    
    // Set up the page table hierarchy
    // PML4[pml4_index] -> PDPT (using physical address of global->mem page)
    lpaddr_t pdpt_phys = mem_to_local_phys((lvaddr_t)hierarchy->pdpt);
    paging_x86_64_map_table(&hierarchy->pml4[pml4_index], pdpt_phys);
    
    // PDPT[0] -> PD (using physical address of global->mem page)
    lpaddr_t pd_phys = mem_to_local_phys((lvaddr_t)hierarchy->pd);
    paging_x86_64_map_table(&hierarchy->pdpt[0], pd_phys);
    
    // PD[0] -> PT (using physical address of global->mem page)
    lpaddr_t pt_phys = mem_to_local_phys((lvaddr_t)hierarchy->pt);
    paging_x86_64_map_table((union x86_64_pdir_entry *)&hierarchy->pd[0], pt_phys);
    
    printf("PTModel: Set up page table hierarchy using global->mem pages\n");
    
    // Flush TLB to ensure the new mappings are visible
    __asm__ volatile("invlpg (%0)" : : "r" (0) : "memory");
    
    return SYS_ERR_OK;
}

// Function to map a virtual address to a physical address using the hierarchy
static errval_t map_virtual_to_physical(struct page_table_hierarchy *hierarchy,
                                lvaddr_t vaddr, lpaddr_t paddr, uint64_t flags)
{
    // Calculate indices for the virtual address
    size_t pml4_index = X86_64_PML4_BASE(vaddr);
    size_t pdpt_index = X86_64_PDPT_BASE(vaddr);
    size_t pd_index = X86_64_PDIR_BASE(vaddr);
    size_t pt_index = X86_64_PTABLE_BASE(vaddr);
    
    printf("PTModel: Mapping 0x%lx -> 0x%lx (PML4:%zu PDPT:%zu PD:%zu PT:%zu)\n",
           vaddr, paddr, pml4_index, pdpt_index, pd_index, pt_index);
    
    // Verify that the PML4 index matches our hierarchy
    if (pml4_index != hierarchy->pml4_index) {
        printf("PTModel: ERROR - PML4 index mismatch: expected %zu, got %zu\n", 
               hierarchy->pml4_index, pml4_index);
        return SYS_ERR_OK;
    }
    
    // Map the page using the appropriate function based on page size
    if ((vaddr & X86_64_LARGE_PAGE_MASK) == 0 && (paddr & X86_64_LARGE_PAGE_MASK) == 0) {
        // 2MB large page
        paging_x86_64_map_large(&hierarchy->pd[pd_index], paddr, flags);
        printf("PTModel: Mapped as large page (2MB)\n");
    } else {
        // 4KB base page
        paging_x86_64_map(&hierarchy->pt[pt_index], paddr, flags);
        printf("PTModel: Mapped as base page (4KB)\n");
    }
    
    // Flush TLB for this virtual address to ensure the mapping is immediately visible
    __asm__ volatile("invlpg (%0)" : : "r" (vaddr) : "memory");
    
    return SYS_ERR_OK;
}

// Function to create multiple page directories using global->mem pages
static errval_t create_multiple_page_directories(void)
{
    printf("PTModel: Creating multiple page directories example using global->mem pages...\n");
    
    size_t safe_pml4_index = 0;
    
    // Example: Create a hierarchy using pages from global->mem
    // Use PML4 index 1, and pages 0, 1, 2 from global->mem
    struct page_table_hierarchy hierarchy;
    errval_t err = create_page_table_hierarchy(safe_pml4_index, 0, NUM_PDPT_PAGES, NUM_PDPT_PAGES + NUM_PD_PAGES, &hierarchy);
    if (err_is_fail(err)) {
        return err;
    }
    
    // Example mappings with different page sizes
    uint64_t base_flags = X86_64_PTABLE_PRESENT | X86_64_PTABLE_READ_WRITE;
    
    // Map some 4KB pages (using PML4 index 0)
    for (int i = 0; i < 5; i++) {
        // Use virtual addresses that correspond to PML4 index 0
        // PML4 index 0 means bits 39-47 should be 0
        // PD index 0 means bits 21-29 should be 0
        // So we use addresses starting from 0x1000 (4KB)
        lvaddr_t vaddr = 0x1000 + (i * BASE_PAGE_SIZE);
        lpaddr_t paddr = 0x100000 + (i * BASE_PAGE_SIZE);  // Use more realistic physical addresses
        map_virtual_to_physical(&hierarchy, vaddr, paddr, base_flags);
        
        // Now we can safely write to the mapped virtual address
        int value = 20 + i;
        *(int *)vaddr = value;
        
        // Verify the mapping works
        int read_value = *(int *)vaddr;
        if (read_value == value) {
            printf("PTModel: Successfully mapped and wrote value %d to 0x%lx\n", value, vaddr);
        } else {
            printf("PTModel: Mapping verification failed: wrote %d, read %d\n", value, read_value);
        }
    }
    
    // Map a 2MB large page
    lvaddr_t large_vaddr = 0x1000 + 0x200000;  // 2MB aligned, PML4 index 0
    lpaddr_t large_paddr = 0x400000;  // 2MB aligned
    map_virtual_to_physical(&hierarchy, large_vaddr, large_paddr, base_flags);
    
    
    printf("PTModel: Completed multiple page directory creation using global->mem pages\n");
    
    return SYS_ERR_OK;
}

errval_t debug_pt_model_test(void)
{
    printf("PTModel: Running test on core %d...\n", my_core_id);
    if (my_core_id != 0) {
        printf("PTModel: global->pml4 = 0x%lx\n", (uint64_t)global->pml4);
        printf("PTModel: global->mem = %p\n", global->mem);
        // Print the contents of the page at the physical address global->pml4
        // uint64_t *pml4_virt = (uint64_t *)local_phys_to_mem((lpaddr_t)global->pml4);
        
        uint64_t cr3_val = 0;
        __asm__ volatile("mov %%cr3, %0" : "=r"(cr3_val));
        printf("PTModel: CR3 register value = 0x%lx\n", cr3_val);
        
        // Switch to core 0's page table (which has kernel mappings)
        paging_x86_64_context_switch((lpaddr_t)global->pml4);

        create_multiple_page_directories();
        
        // Your operations here - now using core 0's page table
        printf("PTModel: Now using core 0's page table on core %d\n", my_core_id);
        
        while(1){
        }
    }
    
    return SYS_ERR_OK;
}