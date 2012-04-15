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
 *     client-fsd.c
 *
 * Description:
 *     Umbra client for false sharing detection
 *
 * Author: 
 *     Qin Zhao
 * 
 */
#ifdef UMBRA_CLIENT_FALSE_SHARING_DETECTION

#include <stddef.h>    /* offsetof */
#include <string.h>    /* memset */
#include <unistd.h>    /* sleep */

#include "dr_api.h"
#include "../core/global.h"
#include "../core/table.h"
#include "../core/utils.h"

#define MAX_NUM_THREADS 8
#define CACHE_LINE_SIZE 64
#define CACHE_LINE_BITS 6
#define CACHE_MISS_IDX  0
#define CACHE_INVD_IDX  1
#define FALSE_SHARE_IDX 2

#define LOCATION_READ_SHIFT   16 
#define LOCATION_WRITE_SHIFT  24
#define LOCATION_READ_BIT_ME      ((1 << tls_data->myid) << LOCATION_READ_SHIFT)
#define LOCATION_WRITE_BIT_ME     ((1 << tls_data->myid) << LOCATION_WRITE_SHIFT)
#define LOCATION_READ_BIT_OTHERS  ((byte)(~(byte)(1 << tls_data->myid))) << LOCATION_READ_SHIFT
#define LOCATION_WRITE_BIT_OTHERS ((byte)(~(byte)(1 << tls_data->myid))) << LOCATION_WRITE_SHIFT


/* XXX: Delinquent access detection, thread correlation detection 
 * and false sharing detection cannot be enabled at the same now
 */

typedef struct _client_proc_data_t {
    int   num_threads;
    reg_t mask;
    void *lock;
    reg_t stats[4];
} client_proc_data_t;
client_proc_data_t client_proc_data;

#define NUM_OF_REGS 16
typedef struct _client_tls_data_t {
    unsigned int bitmap;
    unsigned int myid;
    reg_t stats[4];
    app_pc ret_pc;
    mem_ref_t *ref;
    app_pc code_cache;
    app_pc read_update_pc[NUM_OF_REGS];
    app_pc write_update_pc[NUM_OF_REGS];
    app_pc lean_func_read_pc[NUM_OF_REGS][NUM_OF_REGS];
    app_pc lean_func_write_pc[NUM_OF_REGS][NUM_OF_REGS];
} client_tls_data_t;

typedef struct _shadow_data_t {
    unsigned int bitmap;
} shadow_data_t;

#define CLIENT_CODE_CACHE_SIZE (64 * PAGE_SIZE)

static app_pc
emit_read_update_code(void *drcontext,
		      client_tls_data_t *tls_data,
		      app_pc pc, reg_id_t r1)
{
    instrlist_t *ilist;
    instr_t *instr;
    opnd_t opnd1, opnd2;

    ilist = instrlist_create(drcontext);

    /* align to cacheline */
    opnd1 = opnd_create_reg(r1);
    opnd2 = OPND_CREATE_MEM64(REG_NULL, 
                              (int)(reg_t)&client_proc_data.mask);
    instr = INSTR_CREATE_and(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, NULL, instr);

    /* add current thread */
    opnd1 = OPND_CREATE_MEM32(r1, 0);
    opnd2 = OPND_CREATE_INT32((int)tls_data->bitmap);
    instr = INSTR_CREATE_or(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, NULL, instr);

    /* indirect jump back */
    opnd1 = OPND_CREATE_ABSMEM(&tls_data->ret_pc, OPSZ_8);
    instr = INSTR_CREATE_jmp_ind(drcontext, opnd1);
    instrlist_meta_preinsert(ilist, NULL, instr);

    pc = instrlist_encode(drcontext, ilist, pc, true);
    instrlist_clear_and_destroy(drcontext, ilist);
    return pc;
}

static app_pc
emit_write_update_code(void *drcontext,
		       client_tls_data_t *tls_data,
		       app_pc pc, reg_id_t r1)
{
    instrlist_t *ilist;
    instr_t *instr;
    opnd_t opnd1, opnd2;
    int i;
    
    ilist = instrlist_create(drcontext);

    /* align to cacheline */
    opnd1 = opnd_create_reg(r1);
    opnd2 = OPND_CREATE_ABSMEM(&client_proc_data.mask, OPSZ_PTR);
    instr = INSTR_CREATE_and(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, NULL, instr);

    opnd1 = OPND_CREATE_MEM32(r1, 0);
    opnd2 = OPND_CREATE_INT32((int)tls_data->bitmap);
    instr = INSTR_CREATE_mov_st(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, NULL, instr);
    /* clear all access bit */
    for (i = 1; i < 16; i++) {
        opnd1 = OPND_CREATE_MEM32(r1, i * 4);
        opnd2 = OPND_CREATE_INT32(0);
        instr = INSTR_CREATE_mov_st(drcontext, opnd1, opnd2);
        instrlist_meta_preinsert(ilist, NULL, instr);
    }

    /* indirect jump back */
    opnd1 = OPND_CREATE_ABSMEM(&tls_data->ret_pc, OPSZ_8);
    instr = INSTR_CREATE_jmp_ind(drcontext, opnd1);
    instrlist_meta_preinsert(ilist, NULL, instr);

    pc = instrlist_encode(drcontext, ilist, pc, true);
    instrlist_clear_and_destroy(drcontext, ilist);
    return pc;
}


static app_pc
emit_lean_func_read_code(void *drcontext, 
                         client_tls_data_t *tls_data,
                         app_pc pc, app_pc update_pc,
			 reg_id_t r1, reg_id_t r2)
{
    instrlist_t *ilist;
    instr_t *instr, *label;
    opnd_t opnd1, opnd2;
    
    ilist = instrlist_create(drcontext);
    label = INSTR_CREATE_label(drcontext);

    /* shd addr calculation r1 = r1 + r2 */
    opnd1 = opnd_create_reg(r1);
    opnd2 = opnd_create_reg(r2);
    instr = INSTR_CREATE_add(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, NULL, instr);

    /* get ref */
    opnd1 = opnd_create_reg(r2);
    opnd2 = OPND_CREATE_ABSMEM(&tls_data->ref, OPSZ_PTR);
    instr = INSTR_CREATE_mov_ld(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, NULL, instr);

    /* update delinquent load counter */
    opnd1 = OPND_CREATE_MEM32(r2, offsetof(mem_ref_t, note[CACHE_MISS_IDX]));
    instr = INSTR_CREATE_inc(drcontext, opnd1);
    instrlist_meta_preinsert(ilist, NULL, instr);

    /* check if anyone write this location yet */
    opnd1 = opnd_create_base_disp(r1, REG_NULL, 0,
                                  offsetof(shadow_data_t, bitmap),
                                  OPSZ_4);
    opnd2 = OPND_CREATE_INT32((int)LOCATION_WRITE_BIT_OTHERS);
    instr = INSTR_CREATE_test(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, NULL, instr);

    /* if non zeor, not a false sharing, skip */
    opnd1 = opnd_create_instr(label);
    instr = INSTR_CREATE_jcc(drcontext, OP_jnz, opnd1);
    instrlist_meta_preinsert(ilist, NULL, instr);

    /* inc the false sharing counter */
    opnd1 = OPND_CREATE_MEM32(r2, offsetof(mem_ref_t, note[FALSE_SHARE_IDX]));
    instr = INSTR_CREATE_inc(drcontext, opnd1);
    instrlist_meta_preinsert(ilist, NULL, instr);

    /* .label */
    instrlist_meta_preinsert(ilist, NULL, label);

    /* mov r1 => r2 */
    opnd1 = opnd_create_reg(r2);
    opnd2 = opnd_create_reg(r1);
    instr = INSTR_CREATE_mov_st(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, NULL, instr);

    /* r2 & 0x3c */
    opnd1 = opnd_create_reg(r2);
    opnd2 = OPND_CREATE_INT32(0x3C);
    instr = INSTR_CREATE_and(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, NULL, instr);

    /* jump to cache line update code */
    opnd1 = opnd_create_pc(update_pc);
    instr = INSTR_CREATE_jmp(drcontext, opnd1);
    instrlist_meta_preinsert(ilist, NULL, instr);

    pc = instrlist_encode(drcontext, ilist, pc, true);
    instrlist_clear_and_destroy(drcontext, ilist);
    return pc;
}

/*
 * 1. check if a code miss
 * 2. check if a cold miss
 * 3. save the addr
 * 4. update the cache line
 * 5. 
 */
static app_pc
emit_lean_func_write_code(void *drcontext, 
                          client_tls_data_t *tls_data,
                          app_pc pc, app_pc update_pc,
			  reg_id_t r1, reg_id_t r2)
{
    instrlist_t *ilist;
    instr_t *instr, *label;
    opnd_t opnd1, opnd2;
    
    ilist = instrlist_create(drcontext);
    label = INSTR_CREATE_label(drcontext);

    /* shd addr calculation r1 = r1 + r2 */
    opnd1 = opnd_create_reg(r1);
    opnd2 = opnd_create_reg(r2);
    instr = INSTR_CREATE_add(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, NULL, instr);

    /* get ref */
    opnd1 = opnd_create_reg(r2);
    opnd2 = OPND_CREATE_ABSMEM(&tls_data->ref, OPSZ_PTR);
    instr = INSTR_CREATE_mov_ld(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, NULL, instr);

    /* update delinquent write counter */
    opnd1 = OPND_CREATE_MEM32(r2, offsetof(mem_ref_t, note[CACHE_INVD_IDX]));
    instr = INSTR_CREATE_inc(drcontext, opnd1);
    instrlist_meta_preinsert(ilist, NULL, instr);

    /* check if anyone write this location yet */
    opnd1 = opnd_create_base_disp(r1, REG_NULL, 0,
                                  offsetof(shadow_data_t, bitmap),
                                  OPSZ_4);
    int x = LOCATION_WRITE_BIT_OTHERS;
    int y = LOCATION_READ_BIT_OTHERS;
    opnd2 = OPND_CREATE_INT32((int)(x | y));
    instr = INSTR_CREATE_test(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, NULL, instr);

    /* if non zeor, not a false sharing, skip */
    opnd1 = opnd_create_instr(label);
    instr = INSTR_CREATE_jcc(drcontext, OP_jnz, opnd1);
    instrlist_meta_preinsert(ilist, NULL, instr);

    /* inc the false sharing counter */
    opnd1 = OPND_CREATE_MEM32(r2, offsetof(mem_ref_t, note[FALSE_SHARE_IDX]));
    instr = INSTR_CREATE_inc(drcontext, opnd1);
    instrlist_meta_preinsert(ilist, NULL, instr);

    /* .label */
    instrlist_meta_preinsert(ilist, NULL, label);

    /* mov r1 => r2 */
    opnd1 = opnd_create_reg(r2);
    opnd2 = opnd_create_reg(r1);
    instr = INSTR_CREATE_mov_st(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, NULL, instr);

    /* r2 & 0x3c */
    opnd1 = opnd_create_reg(r2);
    opnd2 = OPND_CREATE_INT32(0x3C);
    instr = INSTR_CREATE_and(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, NULL, instr);

    /* direct jump */
    opnd1 = opnd_create_pc(update_pc);
    instr = INSTR_CREATE_jmp(drcontext, opnd1);
    instrlist_meta_preinsert(ilist, NULL, instr);

    pc = instrlist_encode(drcontext, ilist, pc, true);
    instrlist_clear_and_destroy(drcontext, ilist);
    return pc;
}

static void
code_cache_thread_exit(void *drcontext, umbra_info_t *info)
{
    client_tls_data_t *tls_data;

    tls_data = info->client_tls_data;
    dr_nonheap_free(tls_data->code_cache, CLIENT_CODE_CACHE_SIZE);
}
        
static void
code_cache_thread_init(void *drcontext, umbra_info_t *info)
{
    uint  prot;
    app_pc pc;
    reg_id_t r1, r2;
    int      p1, p2;
    client_tls_data_t *tls_data;
    
    prot = DR_MEMPROT_READ|DR_MEMPROT_WRITE|DR_MEMPROT_EXEC;
    tls_data = info->client_tls_data;
    tls_data->code_cache = 
        dr_nonheap_alloc(CLIENT_CODE_CACHE_SIZE, prot);

    pc = umbra_align_cache_line(tls_data->code_cache);

    for (p1 = 0; p1 < NUM_SPILL_REGS; p1++) {
        UMBRA_POS_TO_REG(r1, p1);
	if (r1 == REG_XAX || r1 == REG_XSP)
            continue;
	pc = umbra_align_cache_line(pc);
	tls_data->read_update_pc[p1] = pc;
	pc = emit_read_update_code(drcontext, tls_data, pc, r1);
	pc = umbra_align_cache_line(pc);
	tls_data->write_update_pc[p1] = pc;
	pc = emit_write_update_code(drcontext, tls_data, pc, r1);
    }

    for (p1 = 0; p1 < NUM_SPILL_REGS; p1++) {
        UMBRA_POS_TO_REG(r1, p1);
        if (r1 == REG_XAX || r1 == REG_XSP)
            continue;
        /* assuming r1 is always before r2*/
        for (p2 = p1 + 1; p2 < NUM_SPILL_REGS; p2++) {
            UMBRA_POS_TO_REG(r2, p2);
            if (r2 == REG_XAX || r2 == REG_XSP)
                continue;
            pc = umbra_align_cache_line(pc);
            tls_data->lean_func_read_pc[p1][p2] = pc;
            pc = emit_lean_func_read_code (drcontext, tls_data, pc, 
					   tls_data->read_update_pc[p1],
					   r1, r2);
            pc = umbra_align_cache_line(pc);
            tls_data->lean_func_write_pc[p1][p2] = pc;
            pc = emit_lean_func_write_code(drcontext, tls_data, pc,
					   tls_data->write_update_pc[p1],
					   r1, r2);
        }
    }
    
    prot = DR_MEMPROT_READ|DR_MEMPROT_EXEC;
    dr_memory_protect(tls_data->code_cache, 
                      CLIENT_CODE_CACHE_SIZE, prot);
}


/*
 *   test bitmap [shd]
 *   jnz .label
 *   # go to lean procedure 
 *   mov .label [ret_pc]
 *   jmp lean_func_read[r1]
 * .label
 *   test read_bit [shd]
 *   jnz .where
 *   or read_bit [shd]
 */
static void
instrument_memory_read(void         *drcontext,
                       umbra_info_t *umbra_info,
                       mem_ref_t    *ref,
                       instrlist_t  *ilist,
                       instr_t      *where)
{
    instr_t *instr, *label, *end;
    opnd_t   opnd1, opnd2;
    reg_id_t r1, r2;
    int p1, p2;
    client_tls_data_t *tls_data;

    /* cacheline aligned shadow memory address */
    r1 = umbra_info->steal_regs[0];
    /* original memory reference address */
    r2 = umbra_info->steal_regs[1];
    UMBRA_REG_TO_POS(r1, p1);
    UMBRA_REG_TO_POS(r2, p2);
    tls_data = umbra_info->client_tls_data;

    label = INSTR_CREATE_label(drcontext);
    end   = INSTR_CREATE_label(drcontext);

    /* 1. check if my bit is in it */
    /* get the location */
    opnd1 = opnd_create_reg(r2);
    opnd2 = OPND_CREATE_INT32(0x3C);
    instr = INSTR_CREATE_and(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);

    /* test [%r1].bitmap, bitmap */
    opnd1 = opnd_create_base_disp(r1, REG_NULL, 0,
                                  offsetof(shadow_data_t, bitmap),
                                  OPSZ_4);
    opnd2 = OPND_CREATE_INT32((int)tls_data->bitmap);
    instr = INSTR_CREATE_test(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);
    /* might cause fault */
    instr_set_ok_to_mangle(instr, true);
    instr_set_translation(instr, ref->pc);
    instr_set_meta_may_fault(instr, true);

    /* if in it, jump to .label for position check */
    opnd1 = opnd_create_instr(label);
    instr = INSTR_CREATE_jcc(drcontext, OP_jnz, opnd1);
    instrlist_meta_preinsert(ilist, where, instr);

    /* jump to lean procedure */
    /* save return target */
    opnd1 = OPND_CREATE_ABSMEM(&tls_data->ret_pc, OPSZ_PTR);
    opnd2 = opnd_create_instr(label);
    instr = INSTR_CREATE_mov_st(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);

    /* mov ref -> tls_data->ref */
    opnd1 = OPND_CREATE_ABSMEM(&tls_data->ref, OPSZ_PTR);
    opnd2 = OPND_CREATE_INT32((int)ref);
    instr = INSTR_CREATE_mov_imm(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);

    /* jump to target */
    opnd1 = opnd_create_pc(tls_data->lean_func_read_pc[p1][p2]);
    instr = INSTR_CREATE_jmp(drcontext, opnd1);
    instrlist_meta_preinsert(ilist, where, instr);

    /* .label */
    instrlist_meta_preinsert(ilist, where, label);

    /* now position access check */
    
    /* check */
    opnd1 = opnd_create_base_disp(r1, r2, 1, 0, OPSZ_4);
    opnd2 = OPND_CREATE_INT32((int)LOCATION_READ_BIT_ME);
    instr = INSTR_CREATE_test(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);
    
    /* jnz .end */
    opnd1 = opnd_create_instr(end);
    instr = INSTR_CREATE_jcc(drcontext, OP_jnz, opnd1);
    instrlist_meta_preinsert(ilist, where, instr);

    /* add myself into the bitmap in shadow memory, OR */
    opnd1 = opnd_create_base_disp(r1, r2, 1, 0, OPSZ_4);
    opnd2 = OPND_CREATE_INT32((int)LOCATION_READ_BIT_ME);
    instr = INSTR_CREATE_or(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);

    /* .end */
    instrlist_meta_preinsert(ilist, where, end);
}

/*
 *   and  r2 0x3c
 *   test bitmap [r1]
 *   jnz .label
 *   # go to lean procedure 
 *   mov .label [ret_pc]
 *   mov ref [tls_data->ref]
 *   jmp lean_func_read[r1]
 * .label
 *   test write_bit [r1, r2]
 *   jnz .where
 *   or read_bit [shd]
 */
static void
instrument_memory_write(void         *drcontext,
                        umbra_info_t *umbra_info,
                        mem_ref_t    *ref,
                        instrlist_t  *ilist,
                        instr_t      *where)
{
    instr_t *instr, *label, *end;
    opnd_t   opnd1, opnd2;
    reg_id_t r1, r2;
    int p1, p2;
    client_tls_data_t *tls_data;

    /* cacheline aligned shadow memory address */
    r1 = umbra_info->steal_regs[0];
    /* original address */
    r2 = umbra_info->steal_regs[1];
    UMBRA_REG_TO_POS(r1, p1);
    UMBRA_REG_TO_POS(r2, p2);
    tls_data = umbra_info->client_tls_data;

    label = INSTR_CREATE_label(drcontext);
    end   = INSTR_CREATE_label(drcontext);


    /* mask the location to the  */
    opnd1 = opnd_create_reg(r2);
    opnd2 = OPND_CREATE_INT32(0x3C);
    instr = INSTR_CREATE_and(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);

    /* check if I am the only owner: cmp [%reg].bitmap, bitmap*/
    opnd1 = opnd_create_base_disp(r1, REG_NULL, 0,
                                  offsetof(shadow_data_t, bitmap),
                                  OPSZ_2);
    opnd2 = OPND_CREATE_INT16(tls_data->bitmap);
    instr = INSTR_CREATE_cmp(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);
    instr_set_ok_to_mangle(instr, true);
    instr_set_translation(instr, ref->pc);
    instr_set_meta_may_fault(instr, true);

    /* if yes, do nothing je label */
    opnd1 = opnd_create_instr(label);
    instr = INSTR_CREATE_jcc(drcontext, OP_je, opnd1);
    instrlist_meta_preinsert(ilist, where, instr);

    /* jump to lean procedure */
    /* save return target */
    opnd1 = OPND_CREATE_ABSMEM(&tls_data->ret_pc, OPSZ_PTR);
    opnd2 = opnd_create_instr(label);
    instr = INSTR_CREATE_mov_st(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);

    /* mov ref -> tls_data->ref */
    opnd1 = OPND_CREATE_ABSMEM(&tls_data->ref, OPSZ_PTR);
    opnd2 = OPND_CREATE_INT32((int)ref);
    instr = INSTR_CREATE_mov_imm(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);

    /* jump to target */
    opnd1 = opnd_create_pc(tls_data->lean_func_write_pc[p1][p2]);
    instr = INSTR_CREATE_jmp(drcontext, opnd1);
    instrlist_meta_preinsert(ilist, where, instr);

    /* .label */
    instrlist_meta_preinsert(ilist, where, label);

    /* now position access check */
    opnd1 = opnd_create_base_disp(r1, r2, 1, 0, OPSZ_4);
    opnd2 = OPND_CREATE_INT32((int)LOCATION_WRITE_BIT_ME);
    instr = INSTR_CREATE_test(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);
    
    /* jnz .end */
    opnd1 = opnd_create_instr(end);
    instr = INSTR_CREATE_jcc(drcontext, OP_jnz, opnd1);
    instrlist_meta_preinsert(ilist, where, instr);

    /* add myself into the bitmap in shadow memory, OR */
    opnd1 = opnd_create_base_disp(r1, r2, 1, 0, OPSZ_4);
    opnd2 = OPND_CREATE_INT32((int)LOCATION_WRITE_BIT_ME);
    instr = INSTR_CREATE_or(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);

    /* .end */
    instrlist_meta_preinsert(ilist, where, end);
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
    /* skip stack reference */
    if (opnd_uses_reg(ref->opnd, REG_XSP))
	return false;
    if (ref->opcode == OP_leave || ref->opcode == OP_enter)
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
    tls_data->bitmap = 
        (1 << ((client_proc_data.num_threads) % MAX_NUM_THREADS));
    tls_data->myid = (client_proc_data.num_threads % MAX_NUM_THREADS);
    ++client_proc_data.num_threads;
    dr_mutex_unlock(client_proc_data.lock);
    code_cache_thread_init(drcontext, umbra_info);
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
            tls_data->stats[FALSE_SHARE_IDX] += ref->note[FALSE_SHARE_IDX];
            if (ref->note[CACHE_MISS_IDX] > 10)
                dr_fprintf(umbra_info->log, "instr %p cache miss: %u\n", 
                           ref->pc, ref->note[CACHE_MISS_IDX]);
            if (ref->note[CACHE_INVD_IDX] > 10)
                dr_fprintf(umbra_info->log, "instr %p cache invalidation: %u\n",
                           ref->pc, ref->note[CACHE_INVD_IDX]);
            if (ref->note[FALSE_SHARE_IDX] > 20)
                dr_fprintf(umbra_info->log, "instr %p false sharing: %u\n", 
                           ref->pc, ref->note[FALSE_SHARE_IDX]);
        }
    }
    dr_fprintf(umbra_info->log, "Total cache miss: %llu\n", 
               tls_data->stats[CACHE_MISS_IDX]);
    dr_fprintf(umbra_info->log, "Total cache invalidation: %llu\n", 
               tls_data->stats[CACHE_INVD_IDX]);
    dr_fprintf(umbra_info->log, "Total false share: %llu\n", 
               tls_data->stats[FALSE_SHARE_IDX]);
    code_cache_thread_exit(drcontext, umbra_info);
    dr_mutex_lock(client_proc_data.lock);
    client_proc_data.stats[CACHE_MISS_IDX] += tls_data->stats[CACHE_MISS_IDX];
    client_proc_data.stats[CACHE_INVD_IDX] += tls_data->stats[CACHE_INVD_IDX];
    client_proc_data.stats[FALSE_SHARE_IDX] += tls_data->stats[FALSE_SHARE_IDX];
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
    dr_fprintf(proc_info.log, "Total false share: %llu\n",
               client_proc_data.stats[FALSE_SHARE_IDX]);
    dr_mutex_destroy(client_proc_data.lock);
}


void
umbra_client_init()
{
    umbra_client_t *client;
    memset(&client_proc_data, 0, sizeof(client_proc_data));
    client_proc_data.lock  = dr_mutex_create();
    client_proc_data.num_threads = 0;
    client_proc_data.mask  = ~((reg_t)0x3f);
    client = &proc_info.client;
    memset(client, 0, sizeof(umbra_client_t));
    client->thread_init = umbra_client_thread_init;
    client->thread_exit = umbra_client_thread_exit;
    client->client_exit        = umbra_client_exit;
    client->bb_is_interested   = bb_is_interested;
    client->ref_is_interested  = ref_is_interested;
    client->app_unit_bits[0]  = CACHE_LINE_BITS;
    client->shd_unit_bits[0]  = CACHE_LINE_BITS;   
    client->orig_addr      = true;
    client->num_steal_regs = 2;
    client->instrument_update = instrument_update;
}


#endif
