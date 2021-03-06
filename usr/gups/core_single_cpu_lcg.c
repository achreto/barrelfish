/* -*- mode: C; tab-width: 2; indent-tabs-mode: nil; -*- */

/*
 * This code has been contributed by the DARPA HPCS program.  Contact
 * David Koester <dkoester@mitre.org> or Bob Lucas <rflucas@isi.edu>
 * if you have questions.
 *
 * GUPS (Giga UPdates per Second) is a measurement that profiles the memory
 * architecture of a system and is a measure of performance similar to MFLOPS.
 * The HPCS HPCchallenge RandomAccess benchmark is intended to exercise the
 * GUPS capability of a system, much like the LINPACK benchmark is intended to
 * exercise the MFLOPS capability of a computer.  In each case, we would
 * expect these benchmarks to achieve close to the "peak" capability of the
 * memory system. The extent of the similarities between RandomAccess and
 * LINPACK are limited to both benchmarks attempting to calculate a peak system
 * capability.
 *
 * GUPS is calculated by identifying the number of memory locations that can be
 * randomly updated in one second, divided by 1 billion (1e9). The term "randomly"
 * means that there is little relationship between one address to be updated and
 * the next, except that they occur in the space of one half the total system
 * memory.  An update is a read-modify-write operation on a table of 64-bit words.
 * An address is generated, the value at that address read from memory, modified
 * by an integer operation (add, and, or, xor) with a literal value, and that
 * new value is written back to memory.
 *
 * We are interested in knowing the GUPS performance of both entire systems and
 * system subcomponents --- e.g., the GUPS rating of a distributed memory
 * multiprocessor the GUPS rating of an SMP node, and the GUPS rating of a
 * single processor.  While there is typically a scaling of FLOPS with processor
 * count, a similar phenomenon may not always occur for GUPS.
 *
 * For additional information on the GUPS metric, the HPCchallenge RandomAccess
 * Benchmark,and the rules to run RandomAccess or modify it to optimize
 * performance -- see http://icl.cs.utk.edu/hpcc/
 *
 */

/*
 * This file contains the computational core of the single cpu version
 * of GUPS.  The inner loop should easily be vectorized by compilers
 * with such support.
 *
 * This core is used by both the single_cpu and star_single_cpu tests.
 */

#include "RandomAccess.h"

/* Number of updates to table (suggested: 4x number of table entries) */
#define NUPDATE (4 * TableSize)

/* Utility routine to start LCG random number generator at Nth step */
static uint64_t HPCC_starts_LCG(int64_t n)
{
  uint64_t mul_k, add_k, ran, un;

  mul_k = LCG_MUL64;
  add_k = LCG_ADD64;

  ran = 1;
  for (un = (uint64_t)n; un; un >>= 1) {
    if (un & 1)
      ran = mul_k * ran + add_k;
    add_k *= (mul_k + 1);
    mul_k *= mul_k;
  }

  return ran;
}

static void RandomAccessUpdate_LCG(uint64_t TableSize, uint64_t *Table)
{
    uint64_t i;
    uint64_t ran[128]; /* Current random numbers */
    int j, logTableSize;

    /* Perform updates to main table.  The scalar equivalent is:
     *
     *     uint64_t ran;
     *     ran = 1;
     *     for (i=0; i<NUPDATE; i++) {
     *       ran = LCG_MUL64 * ran + LCG_ADD64;
     *       table[ran >> (64 - logTableSize)] ^= ran;
     *     }
     */
    for (j = 0; j < 128; j++)
        ran[j] = HPCC_starts_LCG((NUPDATE / 128) * j);

    logTableSize = 0;
    for (i = 1; i < TableSize; i <<= 1)
        logTableSize += 1;

    for (i = 0; i < NUPDATE / 128; i++) {
        /* #pragma ivdep */
#ifdef _OPENMP
#pragma omp parallel for
#endif
        for (j = 0; j < 128; j++) {
            ran[j] = LCG_MUL64 * ran[j] + LCG_ADD64;
            Table[ran[j] >> (64 - logTableSize)] ^= ran[j];
        }
    }
}

int HPCC_RandomAccess_LCG(HPCC_Params *params,
                          int doIO,
                          double *GUPs,
                          int *failure)
{
    uint64_t i;
    uint64_t temp;
    double totalMem;
    uint64_t *Table;
    uint64_t logTableSize, TableSize;

    /* calculate local memory per node for the update table */
    totalMem = params->HPLMaxProcMem;
    totalMem /= sizeof(uint64_t);

    /* calculate the size of update array (must be a power of 2) */
    for (totalMem *= 0.5, logTableSize = 0, TableSize = 1; totalMem >= 1.0;
                    totalMem *= 0.5, logTableSize++, TableSize <<= 1)
        ; /* EMPTY */

    Table = HPCC_malloc(sizeof(uint64_t) * TableSize, params->TableAlignment);
    if (!Table) {
        printf("could not allocate table");
        return 1;
    }

    params->RandomAccess_N = (int64_t) TableSize;

    /* Print parameters for run */

    printf("# GUPSLGC: Main table (@%p)size   = 2^%" PRIu64 " = %" PRIu64 " words\n", Table,
           logTableSize, TableSize);
    printf("# GUPSLGC: Number of updates = %" PRIu64 "\n", NUPDATE);

    printf("# GUPSLGC: Starting GUPS benchmark with %" PRIu32 " runs\n", params->NumReps);
    bench_ctl_t *bench = bench_ctl_init(BENCH_MODE_FIXEDRUNS, 1, params->NumReps);

    cycles_t t_diff;

    do {
        /* Initialize main table for each run */
        for (i = 0; i < TableSize; i++) {
            Table[i] = i;
        }

        /* Begin timing here */
#ifdef BARRELFISH
        cycles_t t_start = bench_tsc();
#else
        cycles_t t_start = get_timems();
#endif
        RandomAccessUpdate_LCG(TableSize, Table);

        /* End timed section */
#ifdef BARRELFISH
        cycles_t t_end = bench_tsc();
        t_diff = bench_tsc_to_ms(bench_time_diff(t_start, t_end));
#else
        cycles_t t_end = get_timems();
        t_diff = bench_time_diff(t_start, t_end);
#endif
        printf("# GUPSLGC: Round: %" PRIu64 "ms\n", t_diff);

    } while (!bench_ctl_add_run(bench, &t_diff));

    cycles_t *bench_data = bench->data;
    cycles_t avg;
    cycles_t stddev;
    bench_stddev(bench_data, bench->result_count, 0, &avg, &stddev);
    double t_elapsed = ((double) avg) / 1000.0;
    double t_err = ((double) stddev) / 1000000.0;

    /* make sure no division by zero */
    *GUPs = (t_elapsed > 0.0 ? 1.0 / t_elapsed : -1.0);
    *GUPs *= 1e-9 * NUPDATE;
    /* Print timing results */

    printf("GUPSLGC: CPU time used  = %.6f seconds (LCG)\n", t_elapsed);
    printf("GUPSLGC: %.9f Billion(10^9) (s=%.9f) Updates per second [GUP/s] using %" PRIu64
    " pages (LCG)\n",
           *GUPs, t_err, params->TableAlignment);

    /* Verification of results (in serial or "safe" mode; optional) */
    temp = 0x1;
    for (i = 0; i < NUPDATE; i++) {
        temp = LCG_MUL64 * temp + LCG_ADD64;
        Table[temp >> (64 - (int) logTableSize)] ^= temp;
    }

    temp = 0;
    for (i = 0; i < TableSize; i++) {
        if (Table[i] != i) {
            temp++;
        }
    }
    printf("Found %" PRIu64 " errors in %" PRIu64 " locations (%s).\n", temp,
           TableSize, (temp <= 0.01 * TableSize) ? "passed" : "failed");

    if (temp <= 0.01 * TableSize) {
        *failure = 0;
    } else {
        *failure = 1;
    }

    bench_ctl_destroy(bench);
    HPCC_free(Table);

    return 0;
}
