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
 *     client-dep-detect.c
 *
 * Description:
 *     Umbra client detect dependence
 *
 * Author: 
 *     Qin Zhao
 * 
 * Date:
 *     10/30/2009
 * 
 * Note:
 *     09/15/2009: It currently only works in Linux x86_64.
 *                 It currently only works in thread private code cache
 */

#ifdef UMBRA_CLIENT_PDG_SIMPLE

#include <stddef.h>    /* offsetof */
#include <string.h>    /* memset */

#include "dr_api.h"
#include "../core/utils.h"
#include "../core/global.h"
#include "../core/table.h"

#define MAX_NUM_THREADS 32

#define LAST_REF_SLOT SPILL_SLOT_2
#define CACHE_PC_SLOT SPILL_SLOT_3
#define LAST_ENTRY_SLOT SPILL_SLOT_4
#define BUF_END_MARK   0x0e0e0e0e
#define BUF_EMPTY_MARK 0x0f0f0f0f
#define BUF_EMPTY_BYTE 0x0f
#define MIS_MATCH_FLAG 0x1

#define CLIENT_CODE_CACHE_SIZE (PAGE_SIZE << 4)

reg_t last_ref;
reg_t cache_pc;

typedef struct _client_proc_data_t {
    int   num_threads;
    void *lock;
    app_pc code_cache;
    app_pc clean_call_pc;
    app_pc check_pc[NUM_SPILL_REGS][NUM_SPILL_REGS];
    app_pc update_pc[NUM_SPILL_REGS][NUM_SPILL_REGS];
} client_proc_data_t;
client_proc_data_t client_proc_data;

enum {
    INDEX_REF_ID  = 0,
    INDEX_CACHE   = 1,
    INDEX_BUF_CNT = 2,
    INDEX_BUF_PTR = 3
};

typedef struct _client_tls_data_t {
    app_pc code_cache;
    app_pc lean_code[NUM_SPILL_REGS];
    app_pc cache_pc;
    
    
} client_tls_data_t;


typedef struct _shadow_data_t {
    unsigned int ref_id;
} shadow_data_t;

/* Clean call */
static void
client_expand_dep_buf(void *drcontext, mem_ref_t *ref)
{
    int *old_buf, *new_buf;
    int  i, count;
    int *cnt;
    
    cnt     = (int *)&ref->note[INDEX_BUF_CNT];
    count   = *cnt;
    old_buf = (int *)ref->note[INDEX_BUF_PTR];
    new_buf = dr_thread_alloc(drcontext, count * sizeof(int) * 2);
    memset((void *)new_buf, BUF_EMPTY_BYTE, count * sizeof(int) * 2);
    for (i = 0; i < count - 1; i++) {
        /* copy old buf into new buffer in reverse order */
        new_buf[i] = old_buf[count - 2 - i];
    }
    dr_thread_free(drcontext, old_buf, count * sizeof(int));
    count *= 2;
    new_buf[count-1] = BUF_END_MARK;
    *cnt = count;
    ref->note[INDEX_BUF_PTR] = (reg_t)new_buf;
}


static void
client_add_dep_entry(void *drcontext, mem_ref_t *ref, int ref_id)
{
    int *buf;
    int  i;

    buf = (int *)ref->note[INDEX_BUF_PTR];
    for (i = 0; true; i++) {
        if (buf[i] == ref_id)
            break;
        if (buf[i] == BUF_EMPTY_MARK) {
            buf[i] = ref_id;
            if (buf[i + 1] == BUF_END_MARK)
                client_expand_dep_buf(drcontext, ref);
            break;
        }
    }
}


static void
client_clean_call()
{
    void *drcontext;
    mem_ref_t *ref;
    int *ref_id_ptr;
    int *flag;

    drcontext = dr_get_current_drcontext();
#ifdef DEBUG_SINGLE_THREAD
    ref = (mem_ref_t *)last_ref;
#else
    ref = (mem_ref_t *)dr_read_saved_reg(drcontext, LAST_REF_SLOT);
#endif
    ref_id_ptr = (int *)&ref->note[INDEX_CACHE];
    /* XXX: NOT SURE what code below mean */
    if (*ref_id_ptr != *(ref_id_ptr + 1)) {
        client_add_dep_entry(drcontext, ref, *ref_id_ptr);
        client_add_dep_entry(drcontext, ref, *(ref_id_ptr + 1));
        *(ref_id_ptr + 1)= *ref_id_ptr;
        flag  = 1 + (int *)&ref->note[INDEX_BUF_CNT]; 
        *flag = *flag | MIS_MATCH_FLAG;
    } else 
        client_expand_dep_buf(drcontext, ref);
}


static app_pc
emit_clean_call_code(void *drcontext, app_pc pc)
{
    instrlist_t *ilist;
    instr_t     *instr;
    opnd_t       opnd;

    ilist = instrlist_create(drcontext);
    instrlist_init(ilist);
    
    dr_insert_clean_call(drcontext, ilist, NULL, 
                         client_clean_call, false, 0);
#ifdef DEBUG_SINGLE_THREAD
    opnd  = OPND_CREATE_ABSMEM(&cache_pc, OPSZ_PTR);
#else
    opnd  = dr_reg_spill_slot_opnd(drcontext, CACHE_PC_SLOT);
#endif
    instr = INSTR_CREATE_jmp_ind(drcontext, opnd);
    instrlist_meta_append(ilist, instr);
    
    pc = instrlist_encode(drcontext, ilist, pc, true);
    instrlist_clear_and_destroy(drcontext, ilist);
    return pc;
}


static app_pc
emit_ref_id_check_code(void         *drcontext, 
                       app_pc        pc, 
                       reg_id_t      r1,
                       reg_id_t      r2)
{
    instrlist_t *ilist;
    instr_t *instr;
    opnd_t opnd1, opnd2;

    ilist = instrlist_create(drcontext);
    instrlist_init(ilist);

    /* mov last_ref => %r1 */
#ifdef DEBUG_SINGLE_THREAD
    opnd1 = opnd_create_reg(r1);
    opnd2 = OPND_CREATE_ABSMEM(&last_ref, OPSZ_PTR);
    instr = INSTR_CREATE_mov_ld(drcontext, opnd1, opnd2);
    instrlist_meta_append(ilist, instr);
#else
    dr_restore_reg(drcontext, ilist, NULL, r1, LAST_REF_SLOT);
#endif
    
    /* mov %r2 => ref->note[INDEX_CACHE] */
    opnd1 = opnd_create_base_disp(r1, DR_REG_NULL, 0,
                                  offsetof(mem_ref_t, note[INDEX_CACHE]),
                                  OPSZ_PTR);
    opnd2 = opnd_create_reg(r2);
    instr = INSTR_CREATE_mov_st(drcontext, opnd1, opnd2);
    instrlist_meta_append(ilist, instr);
    
    /* cmp %r2_32bit */
    if (reg_is_64bit(r2))
        r2 = reg_64_to_32(r2);
    opnd1 = opnd_create_base_disp(r1, DR_REG_NULL, 0,
                                  offsetof(mem_ref_t, note[INDEX_CACHE]) + 4,
                                  OPSZ_4);
    opnd2 = opnd_create_reg(r2);
    instr = INSTR_CREATE_cmp(drcontext, opnd1, opnd2);
    instrlist_meta_append(ilist, instr);

    /* jnz */
    opnd1 = opnd_create_pc(client_proc_data.clean_call_pc);
    instr = INSTR_CREATE_jcc(drcontext, OP_jne, opnd1);
    instrlist_meta_append(ilist, instr);

    pc = instrlist_encode(drcontext, ilist, pc, true);
    instrlist_clear_and_destroy(drcontext, ilist);
    return pc;
}

/* 
 * reg: a 32-bit reg holds reference id from the shadow memory
 * r2:  a help register (XCX or XDX)
 * 
 */
static app_pc
emit_ref_id_update_code(void         *drcontext, 
                        app_pc        pc, 
                        reg_id_t      r1,
                        reg_id_t      r2)
{
    instrlist_t *ilist;
    instr_t     *instr, *next, *cmp;
    opnd_t       opnd1, opnd2;

    ilist = instrlist_create(drcontext);
    instrlist_init(ilist);
    
    /* mov last_ref => %r1 */
    
#ifdef DEBUG_SINGLE_THREAD
    opnd1 = opnd_create_reg(r1);
    opnd2 = OPND_CREATE_ABSMEM(&last_ref, OPSZ_PTR);
    instr = INSTR_CREATE_mov_ld(drcontext, opnd1, opnd2);
    instrlist_meta_append(ilist, instr);
#else
    dr_restore_reg(drcontext, ilist, NULL, r1, LAST_REF_SLOT);
#endif
    
    /* mov %r2 => ref->note[INDEX_CACHE] */
    opnd1 = OPND_CREATE_MEMPTR(r1, offsetof(mem_ref_t, note[INDEX_CACHE])); 
    opnd2 = opnd_create_reg(r2);
    instr = INSTR_CREATE_mov_st(drcontext, opnd1, opnd2);
    instrlist_meta_append(ilist, instr);

    /* mov ref->note[INDEX_BUF_PTR] %r1 */
    opnd1 = opnd_create_reg(r1);
    opnd2 = OPND_CREATE_MEMPTR(r1, offsetof(mem_ref_t, note[INDEX_BUF_PTR]));
    instr = INSTR_CREATE_mov_ld(drcontext, opnd1, opnd2);
    instrlist_meta_append(ilist, instr);

    if (reg_is_64bit(r2))
        r2 = reg_64_to_32(r2);

    cmp = INSTR_CREATE_label(drcontext);
    instrlist_meta_append(ilist, cmp);

    /* cmp r2 [r1] */
    opnd1 = OPND_CREATE_MEM32(r1, 0);
    opnd2 = opnd_create_reg(r2);
    instr = INSTR_CREATE_cmp(drcontext, opnd1, opnd2);
    instrlist_meta_append(ilist, instr);

    /* jne */
    next  = INSTR_CREATE_label(drcontext);
    opnd1 = opnd_create_instr(next);
    instr = INSTR_CREATE_jcc(drcontext, OP_jne, opnd1);
    instrlist_meta_append(ilist, instr);
    
    /* jmp ind */
#ifdef DEBUG_SINGLE_THREAD
    opnd1 = OPND_CREATE_ABSMEM(&cache_pc, OPSZ_PTR);
#else
    opnd1 = dr_reg_spill_slot_opnd(drcontext, CACHE_PC_SLOT);
#endif
    instr = INSTR_CREATE_jmp_ind(drcontext, opnd1);
    instrlist_meta_append(ilist, instr);

    instrlist_meta_append(ilist, next);
    
    /* cmp BUF_EMPTY_MARK [r1] */
    opnd1 = OPND_CREATE_MEM32(r1, 0);
    opnd2 = OPND_CREATE_INT32(BUF_EMPTY_MARK);
    instr = INSTR_CREATE_cmp(drcontext, opnd1, opnd2);
    instrlist_meta_append(ilist, instr);

    /* je */
    next  = INSTR_CREATE_label(drcontext);
    opnd1 = opnd_create_instr(next);
    instr = INSTR_CREATE_jcc(drcontext, OP_je, opnd1);
    instrlist_meta_append(ilist, instr);

    /* r1 = r1 + 4 */
    opnd1 = opnd_create_reg(r1);
    opnd2 = OPND_CREATE_INT32(4);
    instr = INSTR_CREATE_add(drcontext, opnd1, opnd2);
    instrlist_meta_append(ilist, instr);

    /* jmp */
    opnd1 = opnd_create_instr(cmp);
    instr = INSTR_CREATE_jmp(drcontext, opnd1);
    instrlist_meta_append(ilist, instr);

    instrlist_meta_append(ilist, next);

    /* mov %r2 => [r1] */
    opnd1 = OPND_CREATE_MEM32(r1, 0);
    opnd2 = opnd_create_reg(r2);
    instr = INSTR_CREATE_mov_st(drcontext, opnd1, opnd2);
    instrlist_meta_append(ilist, instr);

    /* cmp BUF_END_MARK [r1]4 */
    opnd1 = OPND_CREATE_MEM32(r1, 4);
    opnd2 = OPND_CREATE_INT32(BUF_END_MARK);
    instr = INSTR_CREATE_cmp(drcontext, opnd1, opnd2);
    instrlist_meta_append(ilist, instr);

    /* je clean_call_pc */
    opnd1 = opnd_create_pc(client_proc_data.clean_call_pc);
    instr = INSTR_CREATE_jcc(drcontext, OP_je, opnd1);
    instrlist_meta_append(ilist, instr);
    
    /* jmp ind */
#ifdef DEBUG_SINGLE_THREAD
    opnd1  = OPND_CREATE_ABSMEM(&cache_pc, OPSZ_PTR);
#else
    opnd1 = dr_reg_spill_slot_opnd(drcontext, CACHE_PC_SLOT);
#endif
    instr = INSTR_CREATE_jmp_ind(drcontext, opnd1);
    instrlist_meta_append(ilist, instr);

    pc = instrlist_encode(drcontext, ilist, pc, true);
    instrlist_clear_and_destroy(drcontext, ilist);
    return pc;
}


/* 
 * mov ref->note[INDEX_REF_ID] => %r2
 * cmp shadow->ref_id, %r2
 * je .app
 * mov %r2 => shadow->ref_id
 * .app
 */
static void
instrument_write_update(void         *drcontext,
                        umbra_info_t *umbra_info,
                        mem_ref_t    *ref,
                        instrlist_t  *ilist,
                        instr_t      *where)
{
    reg_id_t r1, r2;
    instr_t *instr, *label;
    int      size;
    opnd_t   opnd1, opnd2;

    r1 = umbra_info->steal_regs[0];
    r2 = umbra_info->steal_regs[1];
    size = OPSZ_4;
#ifdef X64
    r2 = reg_64_to_32(r2);
#endif

    label = INSTR_CREATE_label(drcontext);

    /* cmp shadow->ref_id, ref->id */
    opnd1 = opnd_create_base_disp(r1, DR_REG_NULL, 0,
                                  offsetof(shadow_data_t, ref_id),
                                  size);
    opnd2 = OPND_CREATE_INT32(ref->id);
    instr = INSTR_CREATE_cmp(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);
    instr_set_translation(instr, ref->pc);
    instr_set_meta_may_fault(instr, true);
    
    /* je label */
    opnd1 = opnd_create_instr(label);
    instr = INSTR_CREATE_jcc(drcontext, OP_je, opnd1);
    instrlist_meta_preinsert(ilist, where, instr);

    /* mov ref->id ==> shadow->ref_id */
    opnd1 = opnd_create_base_disp(r1, DR_REG_NULL, 0,
                                  offsetof(shadow_data_t, ref_id),
                                  size);
    opnd2 = OPND_CREATE_INT32(ref->id);
    instr = INSTR_CREATE_mov_st(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);

    /* label */
    instrlist_meta_preinsert(ilist, where, label);
}


/* 
 * mov shadow->ref_id => %r2
 * cmp ref->note[INDEX_CACHE] %r2
 * je .app
 *   mov ref     => client->last_ref
 *   mov next_pc => client->cache_pc
 *   jmp [r1][r2]
 * .app
 */
static void
instrument_read_update(void         *drcontext,
                       umbra_info_t *umbra_info,
                       mem_ref_t    *ref,
                       instrlist_t  *ilist,
                       instr_t      *where)
{
    reg_id_t r1, r2, reg_addr;
    instr_t *instr, *label;
    int      size, pos1, pos2;
    client_tls_data_t *client;
    opnd_t   opnd1, opnd2;

    label = INSTR_CREATE_label(drcontext);

    if (ref->note[INDEX_BUF_PTR] == 0) {
        int *buf, *cnt;
        buf = dr_thread_alloc(drcontext, 4 * sizeof(int));
        buf[0] = BUF_EMPTY_MARK;
        buf[1] = BUF_EMPTY_MARK;
        buf[2] = BUF_EMPTY_MARK;
        buf[3] = BUF_END_MARK;
        ref->note[INDEX_BUF_PTR] = (reg_t)buf;
        cnt = (int *)&ref->note[INDEX_BUF_CNT];
        *cnt = 4;       /* capacity */
        *(cnt + 1) = 0; /* real cnt */
        ref->note[INDEX_CACHE] = (reg_t)-1;
    }

    client = umbra_info->client_tls_data;
    r1 = umbra_info->steal_regs[0];
    r2 = umbra_info->steal_regs[1];
    reg_addr = r1;
    UMBRA_REG_TO_POS(r1, pos1);
    UMBRA_REG_TO_POS(r2, pos2);
    size = OPSZ_4;
    r2 = reg_64_to_32(r2);
    
    /* load shadow->ref_id => r2 */
    opnd1 = opnd_create_reg(r2);
    opnd2 = opnd_create_base_disp(reg_addr, DR_REG_NULL, 0,
                                  offsetof(shadow_data_t, ref_id),
                                  size);
    instr = INSTR_CREATE_mov_ld(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);
    instr_set_translation(instr, ref->pc);
    instr_set_meta_may_fault(instr, true);

    /* cmp ref->note[INDEX_CACHE] r2 */
    opnd1 = OPND_CREATE_ABSMEM(&ref->note[INDEX_CACHE], size);
    opnd2 = opnd_create_reg(r2);
    instr = INSTR_CREATE_cmp(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);

    /* match, do nothing*/
    /* je label */
    opnd1 = opnd_create_instr(label);
    instr = INSTR_CREATE_jcc(drcontext, OP_je, opnd1);
    instrlist_meta_preinsert(ilist, where, instr);

    /* miss, jump to lean procedure */
    /* mov ref => client_tls_data->last_ref */
    opnd1 = dr_reg_spill_slot_opnd(drcontext, LAST_REF_SLOT);
    opnd2 = OPND_CREATE_INT32(ref);
    instr = INSTR_CREATE_mov_st(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);

    /* save next instr */
    opnd1 = dr_reg_spill_slot_opnd(drcontext, CACHE_PC_SLOT);
    opnd2 = opnd_create_instr(label);
    instr = INSTR_CREATE_mov_st(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);
    
    /* jmp */
    opnd1 = opnd_create_pc(client_proc_data.update_pc[pos1][pos2]);
    instr = INSTR_CREATE_jmp(drcontext, opnd1);
    instrlist_meta_preinsert(ilist, where, instr);

    /* label */
    instrlist_meta_preinsert(ilist, where, label);
}

/* 
 * mov ref->note[INDEX_REF_ID] => %r2
 * cmp shadow->ref_id, %r2
 * je .next
 *   mov  shadow->ref_id => %r2
 *   mov  ref->id <==> shadow->ref_id
 * .next
 * cmp ref->note[INDEX_CACHE] %r2
 * je .app
 *   mov ref     => client->last_ref
 *   mov next_pc => client->cache_pc
 *   jmp [r1][r2]
 * .app
 */
static void
instrument_modify_update(void         *drcontext,
                         umbra_info_t *umbra_info,
                         mem_ref_t    *ref,
                         instrlist_t  *ilist,
                         instr_t      *where)
{
    reg_id_t r1, r2, reg_addr;
    instr_t *instr, *label, *rd_chk;
    int      size, pos1, pos2;
    client_tls_data_t *client;
    opnd_t   opnd1, opnd2;

    if (ref->note[INDEX_BUF_PTR] == 0) {
        int *buf, *cnt;
        buf = dr_thread_alloc(drcontext, 4 * sizeof(int));
        buf[0] = BUF_EMPTY_MARK;
        buf[1] = BUF_EMPTY_MARK;
        buf[2] = BUF_EMPTY_MARK;
        buf[3] = BUF_END_MARK;
        ref->note[INDEX_BUF_PTR] = (reg_t)buf;
        cnt = (int *)&ref->note[INDEX_BUF_CNT];
        *cnt = 4;
        *(cnt + 1) = 0;
        ref->note[INDEX_CACHE] = (reg_t)-1;
    }

    client = umbra_info->client_tls_data;
    r1 = umbra_info->steal_regs[0];
    r2 = umbra_info->steal_regs[1];
    reg_addr = r1;
    UMBRA_REG_TO_POS(r1, pos1);
    UMBRA_REG_TO_POS(r2, pos2);
    size = OPSZ_4;
    r2 = reg_64_to_32(r2);

    /* Store check */
    /* cmp shadow->ref_id, ref->id */
    opnd1 = opnd_create_base_disp(r1, DR_REG_NULL, 0,
                                  offsetof(shadow_data_t, ref_id),
                                  size);
    opnd2 = OPND_CREATE_INT32(ref->id);
    instr = INSTR_CREATE_cmp(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);
    instr_set_translation(instr, ref->pc);
    instr_set_meta_may_fault(instr, true);

    /* mov shadow->ref_id => %r2 */
    opnd1 = opnd_create_reg(r2);
    opnd2 = opnd_create_base_disp(r1, DR_REG_NULL, 0,
                                  offsetof(shadow_data_t, ref_id),
                                  size);
    instr = INSTR_CREATE_mov_ld(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);

    /* je rd_chk */
    rd_chk = INSTR_CREATE_label(drcontext);
    opnd1 = opnd_create_instr(rd_chk);
    instr = INSTR_CREATE_jcc(drcontext, OP_je, opnd1);
    instrlist_meta_preinsert(ilist, where, instr);

    /* mov ref->id => shadow->ref_id */
    opnd1 = opnd_create_base_disp(r1, DR_REG_NULL, 0,
                                  offsetof(shadow_data_t, ref_id),
                                  OPSZ_4);
    opnd2 = OPND_CREATE_INT32(ref->id);
    instr = INSTR_CREATE_mov_st(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);

    /* rd_chk */
    instrlist_meta_preinsert(ilist, where, rd_chk);
    
    /* read ref id check */

    /* cmp ref->note[INDEX_CACHE] r2 */
    opnd1 = OPND_CREATE_ABSMEM(&ref->note[INDEX_CACHE], size);
    opnd2 = opnd_create_reg(r2);
    instr = INSTR_CREATE_cmp(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);

    /* match, do nothing*/
    /* je where */
    opnd1 = opnd_create_instr(where);
    instr = INSTR_CREATE_jcc(drcontext, OP_je, opnd1);
    instrlist_meta_preinsert(ilist, where, instr);

    /* miss, jump to lean procedure */
    /* mov ref => last_ref */
    opnd1 = dr_reg_spill_slot_opnd(drcontext, LAST_REF_SLOT);
    opnd2 = OPND_CREATE_INT32(ref);
    instr = INSTR_CREATE_mov_st(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);

    /* save next instr */
    label = INSTR_CREATE_label(drcontext);
    opnd1 = dr_reg_spill_slot_opnd(drcontext, CACHE_PC_SLOT);
    opnd2 = opnd_create_instr(label);
    instr = INSTR_CREATE_mov_st(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);
    
    /* jmp */
    opnd1 = opnd_create_pc(client_proc_data.update_pc[pos1][pos2]);
    instr = INSTR_CREATE_jmp(drcontext, opnd1);
    instrlist_meta_preinsert(ilist, where, instr);

    /* label */
    instrlist_meta_preinsert(ilist, where, label);
}

static void
instrument_update(void         *drcontext,
                  umbra_info_t  *umbra_info,
                  mem_ref_t    *ref,
                  instrlist_t  *ilist,
                  instr_t      *where)
{
    /* mak ref->node[ref_id] = ref->id, ref->id */
    *(int *)&ref->note[INDEX_REF_ID]       = ref->id;
    *((int *)&ref->note[INDEX_REF_ID] + 1) = ref->id;

    /* instrument for memory reference */
    if (ref->type == MemRead) 
        instrument_read_update(drcontext,
                               umbra_info,
                               ref,
                               ilist,
                               where);
    else if (ref->type == MemWrite)
        instrument_write_update(drcontext,
                                umbra_info,
                                ref,
                                ilist,
                                where);
    else if (ref->type == MemModify)
        instrument_modify_update(drcontext,
                                 umbra_info,
                                 ref,
                                 ilist,
                                 where);
}


static bool
ref_is_interested(umbra_info_t *info, mem_ref_t *ref)
{
    /* I still have no idea how far memory is calculated */
    if (opnd_is_far_base_disp(ref->opnd))
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
}

static void
umbra_client_thread_exit(void *drcontext, umbra_info_t *umbra_info)
{
    int i, j, k, *buf, *cnt;
    basic_block_t *bb;
    mem_ref_t     *refs, *ref;

    for (i = 0; i < umbra_info->table.num_bbs; i++) {
        if (i % INIT_BB_TABLE_SIZE == 0)
            continue;
        bb   = table_get_bb(umbra_info, i);
        refs = bb->refs;
        dr_fprintf(umbra_info->log, "BasicBlock[%d] %p\n", 
                   bb->id, bb->tag);
        for (j = 0; j < bb->num_refs; j++) {
            dr_fprintf(umbra_info->log, "Ref[%d] %p depends on:\n",
                       refs[j].id, refs[j].pc);
            buf = (int *)refs[j].note[INDEX_BUF_PTR];
            if (buf == 0)
                continue;
            for (k = 0; true; k++) {
                if (buf[k] == BUF_EMPTY_MARK || buf[k] == BUF_END_MARK)
                    break;
                ref = table_get_ref(umbra_info, buf[k]);
                dr_fprintf(umbra_info->log, "\t%p %d\n", ref->pc, ref->id);
            }
            cnt = (int *)&refs[k].note[INDEX_BUF_CNT];
            if (*(cnt + 1) != 0)
                dr_fprintf(umbra_info->log, "\thas split dep\n");
        }
    }
    for (i = 0; i < umbra_info->table.num_refs; i++) {
        if (i % INIT_REF_TABLE_SIZE == 0) 
            continue;
        ref = table_get_ref(umbra_info, i);
        cnt = (int *)&ref->note[INDEX_BUF_CNT];
        if (ref->note[INDEX_BUF_PTR] != 0) 
            dr_thread_free(drcontext, (void *)ref->note[INDEX_BUF_PTR],
                           *cnt * sizeof(int));
        else 
            dr_fprintf(umbra_info->log, "ref[%d] has no dependency\n", i);
    }
    dr_thread_free(drcontext, umbra_info->client_tls_data, 
                   sizeof(client_tls_data_t));
    return;
}

static void
umbra_client_exit()
{
    dr_mutex_destroy(client_proc_data.lock);
    dr_nonheap_free(client_proc_data.code_cache, 
                    CLIENT_CODE_CACHE_SIZE);
}

static void
code_cache_init()
{
    void *drcontext;
    uint  prot;
    app_pc pc;
    reg_id_t r1, r2;
    int      p1, p2;
    
    drcontext = dr_get_current_drcontext();
    DR_ASSERT(drcontext != NULL);
    prot = DR_MEMPROT_READ|DR_MEMPROT_WRITE|DR_MEMPROT_EXEC;
    client_proc_data.code_cache = 
        dr_nonheap_alloc(CLIENT_CODE_CACHE_SIZE, prot);

    pc = umbra_align_cache_line(client_proc_data.code_cache);
    client_proc_data.clean_call_pc = pc;
    pc = emit_clean_call_code(drcontext, pc);

    for (p1 = 0; p1 < NUM_SPILL_REGS; p1++) {
        UMBRA_POS_TO_REG(r1, p1);
        if (r1 == DR_REG_XAX || r1 == DR_REG_XSP)
            continue;
        for (p2 = p1 + 1; p2 < NUM_SPILL_REGS; p2++) {
            UMBRA_POS_TO_REG(r2, p2);
            if (r2 == DR_REG_XAX || r2 == DR_REG_XSP)
                continue;
            pc = umbra_align_cache_line(pc);
#ifdef X64
            client_proc_data.check_pc[p1][p2] = pc;
            pc = emit_ref_id_check_code(drcontext, pc, r1, r2);
#endif
            client_proc_data.update_pc[p1][p2] = pc;
            pc = emit_ref_id_update_code(drcontext, pc, r1, r2);
        }
    }
}


void
umbra_client_init()
{
    umbra_client_t *client;

    memset(&client_proc_data, 0, sizeof(client_proc_data_t));
    client_proc_data.lock  = dr_mutex_create();
    client_proc_data.num_threads = 0;
    client = &proc_info.client;
    memset(client, 0, sizeof(umbra_client_t));
    client->thread_init = umbra_client_thread_init;
    client->thread_exit = umbra_client_thread_exit;
    client->client_exit        = umbra_client_exit;
    client->bb_is_interested   = bb_is_interested;
    client->ref_is_interested  = ref_is_interested;
    client->app_unit_bits[0]  = 2;
    client->shd_unit_bits[0]  = 2;   /* 4-byte-2-4-byte mapping */
    client->orig_addr      =  false; /* we do not need original addr */
    client->num_steal_regs = 2;      /* we need two regs */
    client->instrument_update = instrument_update;
    client->shadow_memory_module_destroy = NULL;
    client->shadow_memory_module_create  = NULL;

    code_cache_init();
}

#endif /* UMBRA_CLIENT_PWPD */
