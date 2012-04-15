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
 *     client-share-count.c 
 *
 * Description:
 *     Umbra client count number of cacheline accessed
 *
 * Author: 
 *     Qin Zhao
 * 
 * Date:
 *     06/01/2011
 * 
 * Note:
 *     09/15/2009: It currently only works in Linux x86_64.
 *                 It currently only works in thread private code cache
 */
#ifdef UMBRA_CLIENT_SHARE_COUNT

#include <stddef.h>    /* offsetof */
#include <string.h>    /* memset */

#include "dr_api.h"
#include "../core/global.h"

#define MAX_NUM_THREADS 32

typedef struct _client_proc_data_t {
    int   num_threads;
    reg_t read_count;
    reg_t write_count;
    reg_t total_count;
    void *lock;
} client_proc_data_t;
client_proc_data_t client_proc_data;


typedef struct _client_tls_data_t {
    unsigned int tid_map;
} client_tls_data_t;


typedef struct _shadow_data_t {
    /* bit map for cache line status 
     * 0:   shared by multiple threads
     * tid: exclusively owned by one thread 
     */
    unsigned int tid_map; 
    /* number of read that cause the shared cacheline */
    reg_t read_count;     
    /* number of write that causes the exclusive cahce */
    reg_t write_count;    
    /* count of total access */
    reg_t total_count;    
} shadow_data_t;


static void
instrument_write_update(void        *drcontext, 
                        umbra_info_t *umbra_info, 
                        mem_ref_t   *ref,
                        instrlist_t *ilist,
                        instr_t     *where)
{
    instr_t *instr;
    opnd_t   opnd1, opnd2;
    reg_id_t reg = umbra_info->steal_regs[0];
    client_tls_data_t *tls_data;

    tls_data = umbra_info->client_tls_data;
    /* mov tid_map => shadow->tid_map */
    opnd1 = opnd_create_base_disp(reg, REG_NULL, 0,
                                  offsetof(shadow_data_t, tid_map),
                                  OPSZ_4);
    opnd2 = OPND_CREATE_INT32(tls_data->tid_map);
    instr = INSTR_CREATE_mov_st(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);
     /* inc */
    opnd1 = opnd_create_base_disp(reg, REG_NULL, 0,
                                  offsetof(shadow_data_t, write_count),
                                  OPSZ_8);
    instr = INSTR_CREATE_inc(drcontext, opnd1);
    LOCK(instr);
    instrlist_meta_preinsert(ilist, where, instr);
}


static void
instrument_read_update(void        *drcontext, 
                       umbra_info_t *umbra_info, 
                       mem_ref_t   *ref,
                       instrlist_t *ilist,
                       instr_t     *where)
{
    instr_t *instr;
    opnd_t   opnd1, opnd2;
    reg_id_t reg = umbra_info->steal_regs[0];
    client_tls_data_t *tls_data;
 
    tls_data = umbra_info->client_tls_data;

    /* cmp tid_map, 0 */
    opnd1 = opnd_create_base_disp(reg, REG_NULL, 0,
                                  offsetof(shadow_data_t, tid_map),
                                  OPSZ_4);
    opnd2 = OPND_CREATE_INT8(0);
    instr = INSTR_CREATE_cmp(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);
    /* je where */
    opnd1 = opnd_create_instr(where);
    instr = INSTR_CREATE_jcc(drcontext, OP_je, opnd1);
    instrlist_meta_preinsert(ilist, where, instr);
    /* inc */
    opnd1 = opnd_create_base_disp(reg, REG_NULL, 0,
                                  offsetof(shadow_data_t, read_count),
                                  OPSZ_8);
    instr = INSTR_CREATE_inc(drcontext, opnd1);
    instrlist_meta_preinsert(ilist, where, instr);
    /* mov 0 => tid_map */
    opnd1 = opnd_create_base_disp(reg, REG_NULL, 0,
                                  offsetof(shadow_data_t, tid_map),
                                  OPSZ_4);
    opnd2 = OPND_CREATE_INT32(0);
    instr = INSTR_CREATE_mov_st(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);
}


static void
instrument_ref_update(void        *drcontext, 
                      umbra_info_t *umbra_info, 
                      mem_ref_t   *ref,
                      instrlist_t *ilist,
                      instr_t     *where)
{
    instr_t *instr;
    opnd_t   opnd1, opnd2;
    reg_id_t reg = umbra_info->steal_regs[0];
    client_tls_data_t *tls_data;
    tls_data = umbra_info->client_tls_data;

    /* inc shadow->total_count */
    opnd1 = opnd_create_base_disp(reg, REG_NULL, 0,
                                  offsetof(shadow_data_t, total_count),
                                  OPSZ_PTR);
    instr = INSTR_CREATE_inc(drcontext, opnd1);
    instrlist_meta_preinsert(ilist, where, instr);

    /* cmp shadow->tid_map, tid_map */
    opnd1 = opnd_create_base_disp(reg, REG_NULL, 0,
                                  offsetof(shadow_data_t, tid_map),
                                  OPSZ_4);
    opnd2 = OPND_CREATE_INT32(tls_data->tid_map);
    instr = INSTR_CREATE_cmp(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);

    /* je where */
    opnd1 = opnd_create_instr(where);
    instr = INSTR_CREATE_jcc(drcontext, OP_je, opnd1);
    instrlist_meta_preinsert(ilist, where, instr);
}


static void
instrument_update(void         *drcontext,
                  umbra_info_t *umbra_info,
                  mem_ref_t    *ref,
                  instrlist_t  *ilist,
                  instr_t      *where)
{
    
    instrument_ref_update(drcontext, 
                          umbra_info,
                          ref,
                          ilist,
                          where);
    if (ref->type == MemRead) {
        instrument_read_update(drcontext, 
                               umbra_info,
                               ref,
                               ilist,
                               where);
    } else {
        instrument_write_update(drcontext,
                                umbra_info,
                                ref,
                                ilist,
                                where);
    }
}


static bool
ref_is_interested(umbra_info_t *info, mem_ref_t *ref)
{
    if (opnd_is_far_base_disp(ref->opnd))
        return false;
    if (opnd_uses_reg(ref->opnd, REG_XSP))
	return false;
    if (ref->opcode == OP_leave || ref->opcode == OP_enter)
        return false;
    return true;
}


static bool
bb_is_interested(umbra_info_t *info, basic_block_t *bb)
{
    int i;
    if (bb->num_refs == 0)
        return false;
    /* check ref one by one */
    for (i = 0; i < bb->num_refs; i++) {
        if (ref_is_interested(info, &bb->refs[i]))
            return true;
    }
    /* if reach here, no memory reference is interested */
    return false;
}


static void
umbra_client_thread_init(void *drcontext, umbra_info_t *umbra_info)
{
    client_tls_data_t *tls_data;

    tls_data = dr_thread_alloc(drcontext, sizeof(client_tls_data_t));
    umbra_info->client_tls_data = tls_data;
    dr_mutex_lock(client_proc_data.lock);
    tls_data->tid_map = 
        1 << ((client_proc_data.num_threads++) % MAX_NUM_THREADS);
    dr_mutex_unlock(client_proc_data.lock);
}


static void
umbra_client_thread_exit(void *drcontext, umbra_info_t *umbra_info)
{
    dr_fprintf(STDERR, "Thread %d: %llu refs\n", 
               umbra_info->tid, umbra_info->num_dyn_refs);
    dr_thread_free(drcontext, umbra_info->client_tls_data, 
                   sizeof(client_tls_data_t));
    return;
}


static void
umbra_client_exit()
{
    dr_fprintf(STDERR,
               "Total: %llu, Write: %llu, Read: %llu\n",
               client_proc_data.total_count,
               client_proc_data.write_count,
               client_proc_data.read_count
               );
    dr_mutex_destroy(client_proc_data.lock);
}


static void
shadow_memory_remove(memory_map_t *map)
{
    int i;
    shadow_data_t *data;
    byte *shd_addr;

    i = 0;
    dr_fprintf(STDERR, "shadow memory: (%p - %p) (%p - %p)\n",
               map->app_base, map->app_end,
               map->shd_base, map->shd_end);
    for (data = (shadow_data_t *)map->shd_base;
         data < (shadow_data_t *)map->shd_end;
         data++) {
        shd_addr = (byte *)data;
        if ((data->read_count + data->write_count +
             data->total_count) != 0) {
            dr_fprintf(STDERR, "%p: Total %u, Write %u, Read %u\n",
                       shd_addr, 
                       data->total_count, 
                       data->write_count, 
                       data->read_count);
            client_proc_data.read_count  += data->read_count;
            client_proc_data.write_count += data->write_count;
            client_proc_data.total_count += data->total_count;
        }
    }
}


void
umbra_client_init()
{
    umbra_client_t *client;
 
    client_proc_data.lock  = dr_mutex_create();
    client_proc_data.read_count  = 0;
    client_proc_data.write_count = 0;
    client_proc_data.total_count = 0;
    client_proc_data.num_threads = 0;
    client = &proc_info.client;
    memset(client, 0, sizeof(umbra_client_t));
    client->thread_init = umbra_client_thread_init;
    client->thread_exit = umbra_client_thread_exit;
    client->client_exit        = umbra_client_exit;
    client->bb_is_interested   = bb_is_interested;
    client->ref_is_interested  = ref_is_interested;
    client->app_unit_bits[0]  = 6;   
    client->shd_unit_bits[0]  = 6;   /* 64byte-2-64byte mapping */
    client->orig_addr      = false;
    client->num_steal_regs = 1;
    client->instrument_update = instrument_update;
    client->shadow_memory_module_destroy = shadow_memory_remove;
    client->shadow_memory_module_create  = NULL;
    DR_ASSERT(sizeof(shadow_data_t) < 64);
}


#endif /* UMBRA_CLIENT_SHARE_COUNT */
