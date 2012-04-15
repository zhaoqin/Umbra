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
/*
 * Module Name:
 *     client-null-1-to-1.c
 *
 * Description:
 *     Umbra client perform a 1-Byte-to-1-Byte mapping 
 *     with null update operation
 *
 * Author: 
 *     Qin Zhao
 * 
 * Date:
 *     09/15/2009
 * 
 * Note:
 *     09/15/2009: It currently only works in Linux x86_64.
 *                 It currently only works in thread private code cache
 */

#ifdef UMBRA_CLIENT_NULL_1_BYTE_TO_1_BYTE

#include <stddef.h>    /* offsetof */
#include <string.h>    /* memset */

#include "dr_api.h"
#include "../core/global.h"

typedef struct _client_proc_data_t {
    void *lock;
} client_proc_data_t;
client_proc_data_t client_proc_data;


typedef struct _client_tls_data_t {
    thread_id_t tid;
} client_tls_data_t;


typedef struct _shadow_data_t {
    byte data;
} shadow_data_t;


static void
instrument_update(void         *drcontext,
                  umbra_info_t *umbra_info,
                  mem_ref_t    *ref,
                  instrlist_t  *ilist,
                  instr_t      *where)
{
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
umbra_client_thread_init(void *drcontext, umbra_info_t *umbra_info)
{
    client_tls_data_t *tls_data;

    /* allocate client tls data */
    tls_data = dr_thread_alloc(drcontext, sizeof(client_tls_data_t));
    umbra_info->client_tls_data = tls_data;
    tls_data->tid = dr_get_thread_id(drcontext);
}


static void
umbra_client_thread_exit(void *drcontext, umbra_info_t *umbra_info)
{
    dr_thread_free(drcontext, umbra_info->client_tls_data, 
                   sizeof(client_tls_data_t));
    return;
}


static void
umbra_client_exit()
{
    dr_mutex_destroy(client_proc_data.lock);
}


void
umbra_client_init()
{
    umbra_client_t *client;

    client_proc_data.lock = dr_mutex_create();
    client = &proc_info.client;
    memset(client, 0, sizeof(umbra_client_t));
    client->thread_init = umbra_client_thread_init;
    client->thread_exit = umbra_client_thread_exit;
    client->client_exit        = umbra_client_exit;
    client->bb_is_interested   = bb_is_interested;
    client->ref_is_interested  = ref_is_interested;
    client->app_unit_bits[0]  = 0;   
    client->shd_unit_bits[0]  = 0;   /* byte-2-byte mapping */
    client->orig_addr      = false;
    client->num_steal_regs = 1;
    client->instrument_update   = instrument_update;
    client->shadow_memory_module_destroy = NULL; /* Do nothing on removal */
    client->shadow_memory_module_create  = NULL;
}




#endif /* UMBRA_CLIENT_NULL_1_BYTE_TO_1_BYTE */
