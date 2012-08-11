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
 *     client-ccd.c
 *
 * Description:
 *     Umbra client for cache contention detection
 *
 * Author: 
 *     Qin Zhao
 * 
 */
#ifdef UMBRA_CLIENT_CACHE_CONTENTION_DETECTION

#include <stddef.h>    /* offsetof */
#include <string.h>    /* memset */
#include <unistd.h>    /* sleep */
#include "dr_api.h"
#include "../core/global.h"
#include "../core/table.h"

#define MAX_NUM_THREADS 32
#define CACHE_LINE_SIZE 64
#define CACHE_LINE_BITS 6
#define CACHE_MISS_IDX  0
#define CACHE_INVD_IDX  1
#define FALSE_SHARE_IDX 2

#define LOCATION_READ_BIT  (0x1 << 20)
#define LOCATION_WRITE_BIT (0x1 << 21)

typedef struct _client_proc_data_t {
    int   num_threads;
    void *lock;
    reg_t stats[4];
} client_proc_data_t;
client_proc_data_t client_proc_data;

#define NUM_OF_REGS 16
typedef struct _client_tls_data_t {
    unsigned int tid_map;
    unsigned int myid;
    reg_t stats[4];
} client_tls_data_t;

typedef struct _shadow_data_t {
    unsigned int tid_map;
} shadow_data_t;

#define CLIENT_CODE_CACHE_SIZE PAGE_SIZE

static void
instrument_memory_read(void         *drcontext,
                       umbra_info_t *umbra_info,
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

    /* check if my bit is in it */
    /* test [%reg].tid_map, tid_map */
    opnd1 = opnd_create_base_disp(reg, DR_REG_NULL, 0,
                                  offsetof(shadow_data_t, tid_map),
                                  OPSZ_4);
    opnd2 = OPND_CREATE_INT32((int)tls_data->tid_map);
    instr = INSTR_CREATE_test(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, label, instr);
    instr_set_ok_to_mangle(instr, true);
    instr_set_translation(instr, ref->pc);
    instr_set_meta_may_fault(instr, true);

    /* if in, do nothing jnz label */
    opnd1 = opnd_create_instr(label);
    instr = INSTR_CREATE_jcc(drcontext, OP_jnz, opnd1);
    instrlist_meta_preinsert(ilist, label, instr);
    /* it is a miss */
    /* add myself into the bitmap in shadow memory, or */
    opnd1 = opnd_create_base_disp(reg, DR_REG_NULL, 0,
                                  offsetof(shadow_data_t, tid_map),
                                  OPSZ_4);
    opnd2 = OPND_CREATE_INT32((int)tls_data->tid_map);
    instr = INSTR_CREATE_or(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, label, instr);
    instr_set_ok_to_mangle(instr, true);
    instr_set_translation(instr, ref->pc);
    instr_set_meta_may_fault(instr, true);

    /* increment the cache miss counter */
    opnd1 = OPND_CREATE_ABSMEM(&ref->note[CACHE_MISS_IDX], OPSZ_4);
    instr = INSTR_CREATE_inc(drcontext, opnd1);
    instrlist_meta_preinsert(ilist, label, instr);
}

static void
instrument_memory_write(void         *drcontext,
                        umbra_info_t *umbra_info,
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
    /* check if I am the exclusive owner: cmp [%reg].tid_map, tid_map*/
    opnd1 = opnd_create_base_disp(reg, DR_REG_NULL, 0,
                                  offsetof(shadow_data_t, tid_map),
                                  OPSZ_4);
    opnd2 = OPND_CREATE_INT32((int)tls_data->tid_map);
    instr = INSTR_CREATE_cmp(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, label, instr);
    instr_set_ok_to_mangle(instr, true);
    instr_set_translation(instr, ref->pc);
    instr_set_meta_may_fault(instr, true);

    /* if yes, do nothing je label */
    opnd1 = opnd_create_instr(label);
    instr = INSTR_CREATE_jcc(drcontext, OP_je, opnd1);
    instrlist_meta_preinsert(ilist, label, instr);
    /* else, set me as */
    opnd1 = opnd_create_base_disp(reg, DR_REG_NULL, 0,
                                  offsetof(shadow_data_t, tid_map),
                                  OPSZ_4);
    opnd2 = OPND_CREATE_INT32((int)tls_data->tid_map);
    instr = INSTR_CREATE_mov_st(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, label, instr);
    instr_set_ok_to_mangle(instr, true);
    instr_set_translation(instr, ref->pc);
    instr_set_meta_may_fault(instr, true);

    /* increment the cache invd counter */
    opnd1 = OPND_CREATE_ABSMEM(&ref->note[CACHE_INVD_IDX], OPSZ_4);
    instr = INSTR_CREATE_inc(drcontext, opnd1);
    instrlist_meta_preinsert(ilist, label, instr);
}

static void
instrument_memory_modify(void         *drcontext,
                         umbra_info_t  *umbra_info,
                         mem_ref_t    *ref,
                         instrlist_t  *ilist,
                         instr_t      *where)
{
    instrument_memory_write(drcontext, 
			    umbra_info,
			    ref,
			    ilist,
			    where);
}


static void
instrument_update(void         *drcontext,
                  umbra_info_t  *umbra_info,
                  mem_ref_t    *ref,
                  instrlist_t  *ilist,
                  instr_t      *where)
{
    if (ref->type == MemRead) 
        instrument_memory_read(drcontext, 
                               umbra_info,
                               ref,
                               ilist,
                               where);
    else if (ref->type == MemWrite)
        instrument_memory_write(drcontext,
                                umbra_info,
                                ref,
                                ilist,
                                where);
    else if (ref->type == MemModify) 
        instrument_memory_modify(drcontext,
                                 umbra_info,
                                 ref,
                                 ilist,
                                 where);
}

static bool
ref_is_interested(umbra_info_t *info, mem_ref_t *ref)
{
    /* skip far memory reference */
    if (opnd_is_far_base_disp(ref->opnd))
        return false;
    if (ref->opcode == OP_leave || ref->opcode == OP_enter ||
        ref->opcode == OP_push  || ref->opcode == OP_pop)
        return false;
    /* skip stack reference */
    if (opnd_uses_reg(ref->opnd, DR_REG_XSP))
	return false;
    if ((opnd_is_rel_addr(ref->opnd) || opnd_is_abs_addr(ref->opnd)) && 
        (reg_t)opnd_get_addr(ref->opnd) > (reg_t)0xffffffff00000000)
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
    memset(tls_data, 0, sizeof(client_tls_data_t));
    umbra_info->client_tls_data = tls_data;
    dr_mutex_lock(client_proc_data.lock);
    /* bit 0 is always set as for total memory referenced */
    tls_data->tid_map = 
        (1 << ((client_proc_data.num_threads) % MAX_NUM_THREADS));
    /* skip 0 */
    tls_data->myid = ++client_proc_data.num_threads;
    dr_mutex_unlock(client_proc_data.lock);
}

static void
umbra_client_thread_exit(void *drcontext, umbra_info_t *umbra_info)
{
    /* iterate over the refs to get the total number of miss and invalidation */
    int i;
    mem_ref_t *ref;
    client_tls_data_t *tls_data = umbra_info->client_tls_data;
    for (i = 0; i < umbra_info->table.num_refs; i++) {
        if ((i % INIT_REF_TABLE_SIZE) != (INIT_REF_TABLE_SIZE - 1)) {
            ref = table_get_ref(umbra_info, i);
            tls_data->stats[CACHE_MISS_IDX] += ref->note[CACHE_MISS_IDX];
            tls_data->stats[CACHE_INVD_IDX] += ref->note[CACHE_INVD_IDX];
            if (ref->note[CACHE_MISS_IDX] > 10000)
                dr_fprintf(umbra_info->log, "instr %p cache miss: %u\n", 
                           ref->pc, ref->note[CACHE_MISS_IDX]);
            if (ref->note[CACHE_INVD_IDX] > 10000)
                dr_fprintf(umbra_info->log, "instr %p cache invalidation: %u\n",
                           ref->pc, ref->note[CACHE_INVD_IDX]);
        }
    }
    dr_fprintf(umbra_info->log, "Total cache miss: %llu\n", 
               tls_data->stats[CACHE_MISS_IDX]);
    dr_fprintf(umbra_info->log, "Total cache invalidation: %llu\n", 
               tls_data->stats[CACHE_INVD_IDX]);
    dr_mutex_lock(client_proc_data.lock);
    client_proc_data.stats[CACHE_MISS_IDX] += tls_data->stats[CACHE_MISS_IDX];
    client_proc_data.stats[CACHE_INVD_IDX] += tls_data->stats[CACHE_INVD_IDX];
    dr_mutex_unlock(client_proc_data.lock);
    dr_thread_free(drcontext, umbra_info->client_tls_data, 
                   sizeof(client_tls_data_t));
    return;
}

static void
umbra_client_exit()
{
    dr_fprintf(proc_info.log, "Total cache miss: %llu\n", 
               client_proc_data.stats[CACHE_MISS_IDX]);
    dr_fprintf(proc_info.log, "Total cache invalidation: %llu\n",
               client_proc_data.stats[CACHE_INVD_IDX]);
    dr_mutex_destroy(client_proc_data.lock);
}

void
umbra_client_init()
{
    umbra_client_t *client;
    client_proc_data.lock  = dr_mutex_create();
    client_proc_data.num_threads = 0;
    client = &proc_info.client;
    memset(client, 0, sizeof(umbra_client_t));
    client->thread_init = umbra_client_thread_init;
    client->thread_exit = umbra_client_thread_exit;
    client->client_exit        = umbra_client_exit;
    client->bb_is_interested   = bb_is_interested;
    client->ref_is_interested  = ref_is_interested;
    client->app_unit_bits[0]  = CACHE_LINE_BITS;
    client->shd_unit_bits[0]  = CACHE_LINE_BITS;   /* 64-byte-2-64-byte mapping */
    client->orig_addr      = false;
    client->num_steal_regs = 1;
    client->instrument_update = instrument_update;
}


#endif
