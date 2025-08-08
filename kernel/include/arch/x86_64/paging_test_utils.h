#ifndef PAGING_TEST_UTILS_H
#define PAGING_TEST_UTILS_H

#include <kernel.h>

void write_pte(lpaddr_t source, size_t level, size_t index, lpaddr_t dest, bool valid);

int read_memory(lvaddr_t addr);

void write_phys_memory(lpaddr_t addr, uint32_t value);

void write_memory(lvaddr_t addr, uint32_t value);

void invalidate_page(lvaddr_t addr);

void barrier(void);

void sync_cores(void);

#endif // PAGING_TEST_UTILS_H