/**
 * \brief Implements the handler function for a driver domain
 * to act upon requests from a device manager (i.e., Kaluga).
 *
 * The stubs will create, destroy driver instances using functions
 * mainly found in `modules.c` of this library.
 */

/*
 * Copyright (c) 2016, ETH Zurich.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached LICENSE file.
 * If you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, Universitaetstr. 6, CH-8092 Zurich. Attn: Systems Group.
 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include <barrelfish/barrelfish.h>
#include <barrelfish/nameservice_client.h>

#include <driverkit/driverkit.h>

#include <if/ddomain_defs.h>
#include "debug.h"

/**
 * State for connection.
 */
static struct bind_state {
    struct ddomain_binding* binding;
    bool is_done;
    errval_t err;
} rpc_bind;

/**
 * Act upon request to create a driver instance.
 *
 * \param binding Controller binding
 * \param cls     What class to instantiate?
 * \param cls_len Ignored.
 * \param name    What name the driver instance should have.
 * \param nlen    Ignored.
 * \param cap     Capabilities for the driver instance.
 * \param flags   Flags for the driver instance.
 */
static void create_handler(struct ddomain_binding* binding, const char* cls, size_t cls_len,
                           const char* name, size_t nlen,
                           const char* a1, size_t a1len, const char* a2, size_t a2len, const char* a3, size_t a3len, const char* a4, size_t a4len,
                           struct capref cap1, struct capref cap2, struct capref cap3, struct capref cap4,
                           uint64_t flags) {
    DRIVERKIT_DEBUG("Driver domain got create message from kaluga for %s\n", cls);

    iref_t dev = 0, ctrl = 0;

    // This array is owned by the driver after create:
    struct capref* cap_array = calloc(sizeof(struct capref), 4);
    cap_array[0] = cap1;
    cap_array[1] = cap2;
    cap_array[2] = cap3;
    cap_array[3] = cap4;

    char** args_array = calloc(sizeof(char*), 4);
    args_array[0] = a1 != NULL ? strdup(a1) : NULL;
    args_array[1] = a2 != NULL ? strdup(a2) : NULL;
    args_array[2] = a3 != NULL ? strdup(a3) : NULL;
    args_array[3] = a4 != NULL ? strdup(a4) : NULL;

    errval_t err = driverkit_create_driver(cls, name, cap_array, 4, args_array, 4, flags, &dev, &ctrl);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Instantiating driver failed, report this back to Kaluga.");
    }

    err = binding->tx_vtbl.create_response(binding, NOP_CONT, dev, ctrl, err);
    if (err_is_fail(err)) {
        USER_PANIC_ERR(err, "Sending reply failed.");
    }
}

/**
 * Destroy an existing driver instance.
 *
 * \param binding Controller binding.
 * \param name    Name of the driver instance.
 * \param len     Ignored
 */
static void destroy_handler(struct ddomain_binding* binding, const char* name, size_t len) {
    DRIVERKIT_DEBUG("Driver domain got destroy message for instance %s\n", name);
    errval_t err = driverkit_destroy(name);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Destroying driver failed, report this back to Kaluga.");
    }

    err = binding->tx_vtbl.destroy_response(binding, NOP_CONT, err);
    if (err_is_fail(err)) {
        USER_PANIC_ERR(err, "Sending reply failed.");
    }
}

/**
 * Stubs table for functions to call on driver instance.
 */
static const struct ddomain_rx_vtbl rpc_rx_vtbl = {
    .create = create_handler,
    .destroy_call = destroy_handler,
};

/**
 * Called if connection to the manager has completed.
 *
 * \param st  NULL
 * \param err Connection initiated successfully?
 * \param b   Created binding, this is stored in rpc_bind.
 */
static void rpc_bind_cb(void *st, errval_t err, struct ddomain_binding *b)
{
    b->st = NULL;
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "oct_event bind failed");
        goto out;
    }

    DRIVERKIT_DEBUG("Driver domain has connected to ddomain controller service.\n");
    rpc_bind.binding = b;
    rpc_bind.binding->rx_vtbl = rpc_rx_vtbl;

out:
    assert(!rpc_bind.is_done);
    rpc_bind.is_done = true;
    rpc_bind.err = err;
}

/**
 * Connects to the driver domain manager.
 *
 * \param  connect_to iref where to connect.
 * \retval SYS_ERR_OK Connected to the driver manager.
 */
errval_t ddomain_communication_init(iref_t connect_to)
{
    rpc_bind.err = SYS_ERR_OK;
    rpc_bind.is_done = false;

    errval_t err = ddomain_bind(connect_to, rpc_bind_cb, NULL, get_default_waitset(), IDC_BIND_FLAGS_DEFAULT);
    if (err_is_fail(err)) {
        return err;
    }

    // XXX: broken
    while (!rpc_bind.is_done) {
        messages_wait_and_handle_next();
    }

    return rpc_bind.err;
}