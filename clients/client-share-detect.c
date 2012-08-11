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
 *     client-share-detect.c
 *
 * Description:
 *     Umbra client to detect number of cache line be accessed
 *     by single/multiple threads
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

#ifdef UMBRA_CLIENT_SHARE_DETECT

#include <stddef.h>    /* offsetof */
#include <string.h>    /* memset */

#include "dr_api.h"
#include "../core/global.h"

/* CACHE LINE GRANULARITY */
#define SHARE_UNIT_BITS 6

#define MAX_NUM_THREADS 32

typedef struct _client_proc_data_t {
    int   num_threads;
    void *lock;
    reg_t total_mem;
    reg_t total_ref;
    reg_t total_shared_ref;
} client_proc_data_t;
client_proc_data_t client_proc_data;


typedef struct _client_tls_data_t {
    unsigned int tid_map;
} client_tls_data_t;


typedef struct _shadow_data_t {
    unsigned int tid_map;
} shadow_data_t;

#define TEST_AND_UPDATE
static void
instrument_update(void         *drcontext,
                  umbra_info_t  *umbra_info,
                  mem_ref_t    *ref,
                  instrlist_t  *ilist,
                  instr_t      *where)
{
    instr_t *instr, *label;
    opnd_t   opnd1, opnd2;
    reg_id_t reg = umbra_info->steal_regs[0];
    client_tls_data_t *tls_data;

    tls_data = umbra_info->client_tls_data;

    label = INSTR_CREATE_label(drcontext);
    instrlist_meta_preinsert(ilist, where, label);

    /* test [%reg].tid_map, tid_map*/
    opnd1 = opnd_create_base_disp(reg, DR_REG_NULL, 0,
                                  offsetof(shadow_data_t, tid_map),
                                  OPSZ_4);
    opnd2 = OPND_CREATE_INT32(tls_data->tid_map);
    instr = INSTR_CREATE_test(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, label, instr);
    instr_set_ok_to_mangle(instr, true);
    instr_set_translation(instr, ref->pc);
    instr_set_meta_may_fault(instr, true);

    /* jnz label */
    opnd1 = opnd_create_instr(label);
    instr = INSTR_CREATE_jcc(drcontext, OP_jnz, opnd1);
    instrlist_meta_preinsert(ilist, label, instr);
    /* racy or */
    opnd1 = opnd_create_base_disp(reg, DR_REG_NULL, 0,
                                  offsetof(shadow_data_t, tid_map),
                                  OPSZ_4);
    opnd2 = OPND_CREATE_INT32(tls_data->tid_map);
    instr = INSTR_CREATE_or(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, label, instr);
    instr_set_ok_to_mangle(instr, true);
    instr_set_translation(instr, ref->pc);
    instr_set_meta_may_fault(instr, true);
}


static bool
ref_is_interested(umbra_info_t *info, mem_ref_t *ref)
{
    if (opnd_is_far_base_disp(ref->opnd))
        return false;
    if (opnd_uses_reg(ref->opnd, DR_REG_XSP))
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
    
    /* allocate client tls data */
    tls_data = dr_thread_alloc(drcontext, sizeof(client_tls_data_t));
    umbra_info->client_tls_data = tls_data;
    dr_mutex_lock(client_proc_data.lock);
    /* bit 0 is always set as for total memory referenced */
    tls_data->tid_map = 
        (1 << ((client_proc_data.num_threads++) % MAX_NUM_THREADS));
    dr_mutex_unlock(client_proc_data.lock);
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
    dr_fprintf(proc_info.log, 
               "Total %llu cacheline is shared accessed,\n"
               "%llu cacheline is access,\n"
               "total mem: %llu bytes\n",
               client_proc_data.total_shared_ref,
               client_proc_data.total_ref + 
               client_proc_data.total_shared_ref,
               client_proc_data.total_mem);
    dr_mutex_destroy(client_proc_data.lock);
}

int bit_count[16] = { 0, 1, 1, 2, 
                      1, 2, 2, 3, 
                      1, 2, 2, 3, 
                      2, 3, 3, 4};
int thd_count[256];

static int
num_of_threads(uint tid_map)
{
    byte *map = (byte *)&tid_map;
    return (thd_count[map[0]] + 
            thd_count[map[1]] +
            thd_count[map[2]] + 
            thd_count[map[3]]);
}


static void
shadow_memory_remove(memory_map_t *map)
{
    int i, j;
    app_pc addr;

    i = 0;
    j = 0;
    for (addr = (uint *)map->shd_base[0];
         addr < (uint *)map->shd_end[0];
         addr += (1 << SHARE_UNIT_BITS)) {
        shadow_data_t *ptr = (shadow_data_t *)addr;
        if (ptr->tid_map != 0) {
            if (num_of_threads(ptr->tid_map) == 1) 
                i++; /* only one thread accessed */
            else 
                j++; /* more than one */
        }
    }
    if (i != 0 || j != 0) {
        dr_fprintf(proc_info.log,
                   "in map: %p - %p\n"
                   "%d cache line of memory is accessed by only one thread,\n"
                   "%d cache line is access by multiplethreads\n",
                   map->app_base, map->app_end, i, j);
    }
    dr_mutex_lock(client_proc_data.lock);
    client_proc_data.total_ref        += i;
    client_proc_data.total_shared_ref += j;
    client_proc_data.total_mem += ((reg_t)map->app_end - 
                                   (reg_t)map->app_base);
    dr_mutex_unlock(client_proc_data.lock);
}


void
umbra_client_init()
{
    umbra_client_t *client;
    int i, j;
 
    client_proc_data.lock  = dr_mutex_create();
    client_proc_data.total_shared_ref = 0;
    client_proc_data.total_ref = 0;
    client_proc_data.total_mem = 0;
    client_proc_data.num_threads = 0;
    client = &proc_info.client;
    memset(client, 0, sizeof(umbra_client_t));
    client->thread_init = umbra_client_thread_init;
    client->thread_exit = umbra_client_thread_exit;
    client->client_exit        = umbra_client_exit;
    client->bb_is_interested   = bb_is_interested;
    client->ref_is_interested  = ref_is_interested;
    client->app_unit_bits[0]  = SHARE_UNIT_BITS;
    client->shd_unit_bits[0]  = SHARE_UNIT_BITS;   /* 64-byte-2-64-byte mapping */
    client->orig_addr      = false;
    client->num_steal_regs = 1;
    client->instrument_update = instrument_update;
    client->shadow_memory_module_destroy = shadow_memory_remove;
    client->shadow_memory_module_create  = NULL;

    for (i = 0; i < 16; i++) {
        for (j = 0; j < 16; j++) {
            thd_count[i * 16 + j] = bit_count[i] + bit_count[j];
        }
    }
}

#endif /* UMBRA_CLIENT_SHARE_DETECT */
