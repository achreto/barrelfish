#ifndef PAGING_TEST_UTILS_H
#define PAGING_TEST_UTILS_H

#include <kernel.h>

void write_pte(lpaddr_t source, size_t level, lvaddr_t virt_addr, lpaddr_t dest, bool valid);

void read_memory(lvaddr_t addr);

void write_phys_memory(lpaddr_t addr, uint32_t value);

void invalidate_page(lvaddr_t addr);

void barrier(void);


#endif // PAGING_TEST_UTILS_H