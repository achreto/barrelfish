#include <kernel.h>
#include <sys_debug.h>

errval_t debug_pt_model_test(void)
{
    printf("PTModel: Running test on core %d...\n", my_core_id);
    return SYS_ERR_OK;
}