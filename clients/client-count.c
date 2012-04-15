/*********************************************************************
 * Copyright (c) 2010 Massachusetts Institute of Technology          *
 *                                                                   *
 * Permission is hereby granted, free of charge, to any person       *
 * obtaining a copy of this software and associated documentation    *
 * files (the "Software"), to deal in the Software without           *
 * restriction, including without limitation the rights to use,      *
 * copy, modify, merge, publish, distribute, sublicense, and/or sell *
 * copies of the Software, and to permit persons to whom the         *
 * Software is furnished to do so, subject to the following          *
 * conditions:                                                       *
 *                                                                   *
 * The above copyright notice and this permission notice shall be    *
 * included in all copies or substantial portions of the Software.   *
 *                                                                   *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,   *
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES   *
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND          *
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT       *
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,      *
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING      *
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR     *
 * OTHER DEALINGS IN THE SOFTWARE.                                   *
 *********************************************************************/

#ifdef EDDI_CLIENT_COUNT

#include <stddef.h>    /* offsetof */
#include <string.h>    /* memset */

#include "dr_api.h"
#include "global.h"

#define MAX_NUM_THREADS 32

typedef struct _client_proc_data_t {
    int   num_threads;
    void *lock;
} client_proc_data_t;
client_proc_data_t client_proc_data;


typedef struct _client_tls_data_t {
    reg_t num_refs;
} client_tls_data_t;


typedef struct _shadow_data_t {
    byte data;
} shadow_data_t;


static void
instrument_update(void         *drcontext,
                  eddi_info_t  *eddi_info,
                  mem_ref_t    *ref,
                  instrlist_t  *ilist,
                  instr_t      *where)
{
    instr_t *instr;
    opnd_t   opnd1, opnd2;
    int      opsz;
    reg_id_t reg = eddi_info->steal_regs[0];
    reg_id_t r2;
    client_tls_data_t *tls_data;

    tls_data = eddi_info->client_tls_data;
    
    return; /* do nothing */
}


static bool
ref_is_interested(mem_ref_t *ref)
{
    /* I still have no idea how far memory is calculated */
    if (opnd_is_far_base_disp(ref->opnd))
        return false;
    return true;
}


static bool
bb_is_interested(basic_block_t *bb)
{
    int i;
    if (bb->num_refs == 0)
        return false;
    /* check ref one by one */
    for (i = 0; i < bb->num_refs; i++) {
        if (ref_is_interested(&bb->refs[i]))
            return true;
    }
    /* if reach here, no memory reference is interested */
    return false;
}



static void
eddi_client_thread_init(void *drcontext, eddi_info_t *eddi_info)
{
    client_tls_data_t *tls_data;

    /* allocate client tls data */
    tls_data = dr_thread_alloc(drcontext, sizeof(client_tls_data_t));
    eddi_info->client_tls_data = tls_data;
    /* update client proc data */
    dr_mutex_lock(client_proc_data.lock);
    client_proc_data.num_threads++;
    dr_mutex_unlock(client_proc_data.lock);
}


static void
eddi_client_thread_exit(void *drcontext, eddi_info_t *eddi_info)
{
    dr_thread_free(drcontext, eddi_info->client_tls_data, 
                   sizeof(client_tls_data_t));
    return;
}


static void
eddi_client_exit()
{
    dr_mutex_destroy(client_proc_data.lock);
}


void
eddi_client_init()
{
    eddi_client_t *client;

    client_proc_data.lock = dr_mutex_create();
    client = dr_global_alloc(sizeof(eddi_client_t));
    memset(client, 0, sizeof(eddi_client_t));
    client->client_thread_init = eddi_client_thread_init;
    client->client_thread_exit = eddi_client_thread_exit;
    client->client_exit        = eddi_client_exit;
    client->bb_is_interested   = bb_is_interested;
    client->ref_is_interested  = ref_is_interested;
    client->app_unit_bits  = 0;   
    client->shd_unit_bits  = 0;   /* byte-2-byte mapping */
    client->orig_addr      = false;
    client->num_steal_regs = 1;
    client->instrument_update = instrument_update;
    client->shadow_memory_module_destroy = NULL; /* Do nothing on removal */
    client->shadow_memory_module_create  = NULL;
    proc_info.client = client;
}




#endif /* EDDI_CLIENT_NULL_COUNT */
