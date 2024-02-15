#ifndef __ARBUTUS_MYOS_H_
#define __ARBUTUS_MYOS_H_


extern paddr_t memory_alloc(size_t sz, paddr_t align);

extern void memory_free(paddr_t pa, size_t sz);

// extern vaddr_t local_phys_to_mem(paddr_t pa);

// extern paddr_t mem_to_local_phys(vaddr_t va);

#endif