#ifndef PAGING_TEST_UTILS_H
#define PAGING_TEST_UTILS_H

void write_pte(lpaddr_t source, lpaddr_t dest, bool valid);

void read_memory(lvaddr_t addr);

void write_memory(lvaddr_t addr, uint64 value);

void invalidate_page(lvaddr_t addr);

void barrier(void);


#endif // PAGING_TEST_UTILS_H