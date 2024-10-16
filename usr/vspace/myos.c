#include <barrelfish/barrelfish.h>
#include <stdio.h>
#include <myos.h>


vaddr_t os_virt_alloc(size_t sz)
{
    return (vaddr_t)(uintptr_t)calloc(1, sz);
}

void os_virt_free(vaddr_t va, size_t sz)
{
   // free((void*)va);
}

MyVNode os_vnode_alloc(UnitType ty)
{
    errval_t err;

    enum objtype vnode_type = ObjType_Null;
    switch (ty) {
        case UnitType_X8664PageTable:
            vnode_type = ObjType_VNode_x86_64_ptable;
            break;
        case UnitType_X8664PDir:
            vnode_type = ObjType_VNode_x86_64_pdir;
            break;
        case UnitType_X8664PML4:
            vnode_type = ObjType_VNode_x86_64_pml4;
            break;
        case UnitType_X8664PDPT:
            vnode_type = ObjType_VNode_x86_64_pdpt;
            break;
        default:
            USER_PANIC("unknown type");
            break;
    }

    MyVNode vn = { 0 };

    err = slot_alloc(&vn.cap);
    USER_PANIC_ON_ERR(err, "slot_alloc for vnode failed");

    err = slot_alloc(&vn.mapping);
    USER_PANIC_ON_ERR(err, "slot_alloc for mapping failed");

    err = vnode_create(vn.cap, vnode_type);
    USER_PANIC_ON_ERR(err, "vnode_create failed");

    return vn;
}

void os_vnode_free(MyVNode vnode)
{
    cap_destroy(vnode.cap);
    cap_delete(vnode.mapping);
}

bool vnode_is_valid(MyVNode vnode)
{
    USER_PANIC("NYI");
}

paddr_t frame_to_paddr(MyFrame pa)
{
    USER_PANIC("NYI");
}

MyCapref get_vnode_for_va(vaddr_t va)
{
    USER_PANIC("NYI");
}

MyCapref get_mapping_for_va(vaddr_t va)
{
    USER_PANIC("NYI");
}

bool errval_to_bool(MyErrval err)
{
    return err_is_ok(err);
}

MyErrval my_vnode_map(MyCapref dest, MyCapref src, vaddr_t va, flags_t attr, genaddr_t off, size_t sz, MyCapref mapping)
{
    errval_t err;

    struct capability thecap;

    err = cap_direct_identify(dest, &thecap);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to identify dest cap!");
        return err;
    }
    assert(thecap.type != ObjType_Null);

    err = cap_direct_identify(src, &thecap);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to identify the cap!");
        return err;
    }

    assert(thecap.type != ObjType_Null);

    uint64_t maping_attrs =  PTABLE_READ_WRITE | PTABLE_USER_SUPERVISOR;

    cslot_t slot = 0;
    size_t pte_count = 1;
    switch (thecap.type) {
        case ObjType_VNode_x86_64_pdpt:
            slot = (va >> 39) & 0x1ff;
            // printf("mapping of a pdpt into a pml4 [ %u ] %lu\n", slot, X86_64_PML4_BASE(va));
            break;
        case ObjType_VNode_x86_64_pdir:
            slot = (va >> 30) & 0x1ff;
            // printf("mapping of a pdir into a pdpt [ %u ] %lu.\n", slot, X86_64_PDPT_BASE(va));
            break;
        case ObjType_VNode_x86_64_ptable:
            slot = (va >> 21) & 0x1ff;
            // printf("mapping of a ptable into a pdir [ %u ] %lu.\n", slot, X86_64_PDIR_BASE(va));
            break;
        case ObjType_Frame:
            if (sz == BASE_PAGE_SIZE) {
                slot = (va >> 12) & 0x1ff;
            } else if (sz == LARGE_PAGE_SIZE) {
                slot = (va >> 21) & 0x1ff;
            } else if (sz == HUGE_PAGE_SIZE) {
                slot = (va >> 30) & 0x1ff;
            } else {
                USER_PANIC("invalid va");
            }
            // printf("mapping of a frame [ %u ].\n", slot);
            break;
        default:
            USER_PANIC("unkown type");
    }

    err = vnode_map(dest, src, slot, maping_attrs, off, pte_count, mapping);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to call vnode map");
        return err;
    }

    return SYS_ERR_OK;
}

MyErrval my_vnode_unmap(MyCapref table, MyCapref mapping)
{
    USER_PANIC("NYI");
}

MyErrval my_vnode_modify_flags(MyCapref table, vaddr_t va, size_t sz, flags_t attr)
{
    USER_PANIC("NYI");
}