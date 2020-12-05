/**
 * \file
 * \brief capops benchmarks
 */

/*
 * Copyright (c) 2020, ETH Zurich.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached LICENSE file.
 * If you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, Universitaetstrasse 6, CH-8092 Zurich. Attn: Systems Group.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <barrelfish/barrelfish.h>
#include <barrelfish/spawn_client.h>
#include <limits.h>
#include <bench/bench.h>
#include <barrelfish/nameservice_client.h>
#include <if/bench_distops_defs.h>

static struct capref mem;
static char *path = "capopsbenchmsg";
static char *service_name = "maprevoke";
static size_t memsize = BASE_PAGE_SIZE;
static size_t ncores = 1;

struct benchstate {
    size_t ncores;
    size_t seen;

    struct bench_distops_binding **nodes;
    void *st;
};

static struct benchstate benchstate;


//#define DEBUG(x...) printf(x)
#define DEBUG(x...)

#define PANIC_IF_ERR(err, msg...)                                                        \
    do {                                                                                 \
        if (err_is_fail(err)) {                                                          \
            USER_PANIC_ERR(err, msg);                                                    \
        }                                                                                \
    } while (0)


static struct capref mem_cap;
static void *mapped;

/* Flounder Stuff  */

static void node_rx_hello(struct bench_distops_binding *b, uint32_t coreid)
{
    DEBUG("rx_hello %" PRIu32 "\n", coreid);
    benchstate.seen++;
}

#define CMD_ACK 0
#define CMD_NACK 1
#define CMD_MAP 2
#define CMD_UNMAP 3


static void node_rx_cmd(struct bench_distops_binding *b, uint32_t cmd, uint32_t arg)
{
    errval_t err;

    if (cmd == CMD_MAP) {
        DEBUG("node_rx_cmd MAP %" PRIu32 ": b->st = %p\n", arg, b->st);
        err = vspace_map_one_frame(&mapped, memsize, mem_cap, NULL, NULL);
    } else {
        DEBUG("node_rx_cmd UNMAP %" PRIu32 ": b->st = %p\n", arg, b->st);
        err = vspace_unmap(mapped);
    }

    uint32_t retcmd = CMD_ACK;
    if (err_is_fail(err)) {
        retcmd = CMD_NACK;
    }

    err = bench_distops_cmd__tx(b, NOP_CONT, retcmd, disp_get_core_id());
    PANIC_IF_ERR(err, "in node %d: sending cmd to server", disp_get_core_id());
}

static void mgmt_rx_cmd(struct bench_distops_binding *b, uint32_t cmd, uint32_t arg)
{
    if (cmd == CMD_ACK) {
        DEBUG("mgmt_rx_cmd ACK %" PRIu32 ": b->st = %p\n", arg, b->st);
        benchstate.seen++;
        return;
    }
    printf("unknown command; %d\n", cmd);
}


static void node_rx_caps(struct bench_distops_binding *b, uint32_t cmd, uint32_t arg,
                         struct capref cap1)
{
    errval_t err;
    DEBUG("node %d rx_caps: cmd=%" PRIu32 "\n", disp_get_core_id(), cmd);

    mem_cap = cap1;

    /* send reply back */
    err = bench_distops_cmd__tx(b, NOP_CONT, CMD_ACK, disp_get_core_id());
    PANIC_IF_ERR(err, "in node %d: sending cmd to server", disp_get_core_id());
}


static struct bench_distops_rx_vtbl node_rx_vtbl = {
    .cmd = node_rx_cmd,
    .caps = node_rx_caps,
};

static struct bench_distops_rx_vtbl mgmt_rx_vtbl = {
    .cmd = mgmt_rx_cmd,
    .hello = node_rx_hello,
};


static void bind_cb(void *st, errval_t err, struct bench_distops_binding *b)
{
    PANIC_IF_ERR(err, "bind failed");

    printf("node %d bound!\n", disp_get_core_id());

    // copy my message receive handler vtable to the binding
    b->rx_vtbl = node_rx_vtbl;

    // Send hello message
    printf("%s: node %d sending hello msg\n", __FUNCTION__, disp_get_core_id());
    err = bench_distops_hello__tx(b, NOP_CONT, disp_get_core_id());
    PANIC_IF_ERR(err, "in node %d: sending cap to server", disp_get_core_id());
}


static errval_t connect_cb(void *st, struct bench_distops_binding *b)
{
    printf("service got a connection!\n");

    b->rx_vtbl = mgmt_rx_vtbl;

    static int nidx = 0;
    benchstate.nodes[nidx++] = b;

    return SYS_ERR_OK;
}


static void export_cb(void *st, errval_t err, iref_t iref)
{
    PANIC_IF_ERR(err, "export failed");

    printf("service exported at iref %" PRIuIREF "\n", iref);

    // register this iref with the name service
    err = nameservice_register(service_name, iref);
    PANIC_IF_ERR(err, "nameservice_register failed");

    for (size_t i = 0; i < ncores; i++) {
        struct capref domcap;
        char *argv[] = { NULL };
        err = spawn_program(i + 1, path, argv, NULL, SPAWN_FLAGS_DEFAULT, &domcap);
        PANIC_IF_ERR(err, "export failed");
    }
}


static void run_node(void)
{
    errval_t err;
    iref_t iref;

    printf("node %d looking up '%s' in name service...\n", disp_get_core_id(),
           service_name);
    err = nameservice_blocking_lookup(service_name, &iref);
    PANIC_IF_ERR(err, "nameservice_blocking_lookup failed");

    printf("node %d binding to %" PRIuIREF "...\n", disp_get_core_id(), iref);

    err = bench_distops_bind(iref, bind_cb, NULL, get_default_waitset(),
                             IDC_BIND_FLAGS_DEFAULT);
    PANIC_IF_ERR(err, "bind failed");

    struct waitset *ws = get_default_waitset();
    while (true) {
        err = event_dispatch(ws);
        PANIC_IF_ERR(err, "in node %d event_dispatch\n", disp_get_core_id());
    }
}


static void run_benchmark(size_t _ncores)
{
    errval_t err;


    benchstate.seen = 0;
    benchstate.ncores = _ncores;

    struct waitset *ws = get_default_waitset();
    for (size_t i = 0; i < _ncores; i++) {
        DEBUG("%s: sending map command to node %zu \n", __FUNCTION__, i);
        err = bench_distops_cmd__tx(benchstate.nodes[i], NOP_CONT, CMD_MAP, 0);
        PANIC_IF_ERR(err, "in node %d: sending cap to server", disp_get_core_id());
        event_dispatch_non_block(ws);
    }

    void *addr;
    err = vspace_map_one_frame(&addr, memsize, mem, NULL, NULL);
    PANIC_IF_ERR(err, "failed to map frame");

    if (addr == NULL) {
        printf("WARNING: addr was null?\n");
    }

    for (size_t i = 0; i < _ncores; i++) {
        DEBUG("%s: sending map command to node %zu \n", __FUNCTION__, i);
        err = bench_distops_cmd__tx(benchstate.nodes[i], NOP_CONT, CMD_UNMAP, 0);
        PANIC_IF_ERR(err, "in node %d: sending cap to server", disp_get_core_id());
        event_dispatch_non_block(ws);
    }

    vspace_unmap(addr);

    while (benchstate.seen != 2*_ncores) {
        err = event_dispatch(ws);
        PANIC_IF_ERR(err, "in main: event_dispatch");
    }
}

static void prepare_benchmark(size_t _ncores)
{
    errval_t err;

    benchstate.seen = 0;
    benchstate.ncores = _ncores;

    for (size_t i = 0; i < _ncores; i++) {
        DEBUG("%s: sending cap to node %zu \n", __FUNCTION__, i);
        err = bench_distops_caps__tx(benchstate.nodes[i], NOP_CONT, 0, 0, mem);
        PANIC_IF_ERR(err, "in node %d: sending cap to server", disp_get_core_id());
    }

    while (benchstate.seen != _ncores) {
        err = event_dispatch(get_default_waitset());
        PANIC_IF_ERR(err, "in main: event_dispatch");
    }
}

static void init_benchmark(void)
{
    errval_t err;

    /* allocate memory */

    err = frame_alloc(&mem, memsize, NULL);
    if (err_is_fail(err)) {
        USER_PANIC_ERR(err, "failed to allocate memory\n");
    }

    // Initialize benchmark state
    benchstate.seen = 0;
    benchstate.ncores = ncores;
    benchstate.nodes = malloc(ncores * sizeof(struct bench_distops_binding *));
    if (!benchstate.nodes) {
        USER_PANIC("malloc failed");
    }

    err = bench_distops_export(NULL, export_cb, connect_cb, get_default_waitset(),
                               IDC_EXPORT_FLAGS_DEFAULT);
    PANIC_IF_ERR(err, "export failed");
}


int main(int argc, char *argv[])
{
    bench_init();

#ifndef NDEBUG
    printf("Running with assertions ENABLED!!!\n");
#endif

    size_t nrounds = 40;

    if (argc > 1 && strncmp(argv[1], "mgmt", 4) == 0) {
        if (argc == 3) {
            ncores = strtoul(argv[2], NULL, 10);
        }
        if (argc == 4) {
            ncores = strtoul(argv[2], NULL, 10);
            nrounds = strtoul(argv[3], NULL, 10);
        }
        init_benchmark();
    } else {
        run_node();
    }

    errval_t err;
    struct waitset *ws = get_default_waitset();

    printf("Waiting for nodes to be ready\n");
    while (benchstate.seen != ncores) {
        err = event_dispatch(ws);
        PANIC_IF_ERR(err, "in main: event_dispatch");
    }

    printf("Preparing benchmark..\n");
    prepare_benchmark(ncores);


    size_t ndryrun = 10;
    /* we have all seen, start benchmark rounds */
    printf("Nodes ready starting benchmark rounds..\n");
    printf("===================== BEGIN CSV =====================\n");

    size_t maxcores = ncores;
    for (ncores = 0; ncores <= maxcores; ncores++) {
        printf("NCORES=%zu,", ncores);
        cycles_t sum = 0;
        for (size_t i = 0; i < nrounds; i++) {
            cycles_t t_start = bench_tsc();
            run_benchmark(ncores);
            cycles_t t_end = bench_tsc();
            if (i >= ndryrun) {
                printf(" %zu,", t_end - t_start);
                sum += t_end - t_start;
            }
        }
        printf(" avg=%zu\n", sum / (nrounds - ndryrun));
        do {
            err = event_dispatch_non_block(ws);
        } while(err_is_ok(err));
    }
    printf("====================== END CSV ======================\n");
    printf("done.\n");
}
