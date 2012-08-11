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
 *     Umbra -- umbra.c
 *
 * Description:
 *     driver of the whole Umbra system
 *
 * Author: 
 *     Qin Zhao
 * 
 */

#include <string.h>

#include "umbra.h"
#include "global.h"

#include "shadow.h"
#include "instrument.h"
#include "table.h"
#include "cfg.h"
#include "analyzer.h"
#include "optimize.h"


/* data structure for global process information */
proc_info_t proc_info;
wrap_func_t *wrap_funcs;
static void
umbra_wrap_func_on_module_load(void *drcontext, const module_data_t *info);

/* set default options for umbra */
static void 
proc_info_options_init()
{
    proc_info.options.opt_ems64           = false;
    proc_info.options.opt_inline_check    = true;
    proc_info.options.opt_map_check       = true;
    proc_info.options.opt_aflags_stealing = true;
    proc_info.options.opt_regs_stealing   = true;
    proc_info.options.opt_trace           = false;
    proc_info.options.opt_group           = true;
#ifdef DOUBLE_SHADOW
    proc_info.options.opt_group           = false;
    proc_info.options.opt_regs_stealing   = false;
    proc_info.options.opt_aflags_stealing = false;
#endif
    proc_info.options.stat                = false;
    proc_info.options.adapt_alloc         = false;
    proc_info.options.swap_stack          = false;
}


/* initialize the proc_info */
static void
proc_info_init()
{
    memset(&proc_info, 0, sizeof(proc_info_t));
    proc_info.mutex = dr_mutex_create();
    proc_info.num_offs = 0;
    proc_info.pid   = dr_get_process_id();
    proc_info.log   = umbra_open_proc_log(proc_info.pid);
    proc_info.unit_bits = ADDRESS_SPACE_UNIT_ALIGN_BITS;
    proc_info.unit_mask = ADDRESS_SPACE_UNIT_ALIGN_MASK;
    proc_info.unit_size = ADDRESS_SPACE_UNIT_ALIGN_SIZE;
    proc_info_options_init();
}


/* finalize the proc_info */
static void
proc_info_exit()
{
    dr_fprintf(proc_info.log, "num instr: %llu\n", proc_info.num_instrs);
    dr_mutex_destroy(proc_info.mutex);
    dr_close_file(proc_info.log);
}


/* initialize thread private umbra info */
static void
umbra_info_init(void *drcontext, umbra_info_t *info)
{
    memset(info, 0, sizeof(umbra_info_t));
    info->drcontext = drcontext;
    info->tid = dr_get_thread_id(drcontext);
    info->log = umbra_open_thread_log(info->tid);
    dr_mutex_lock(proc_info.mutex);
    proc_info.num_threads++;
    dr_mutex_unlock(proc_info.mutex);
}


/* finalize thread private umbra info */
static void
umbra_info_exit(void *drcontext, umbra_info_t *info)
{
    /* close log file */
    dr_close_file(info->log);
}


/* print execution statistics */
static void
print_stat_count(void *drcontext, umbra_info_t *info)
{
    if (proc_info.options.stat == false)
        return;
    dr_mutex_lock(proc_info.mutex);
    proc_info.num_instrs += info->num_dyn_instrs;
    dr_mutex_unlock(proc_info.mutex);

    dr_fprintf(info->log,
               "Num of dynamic app instrs: %llu\n",
               info->num_dyn_instrs);

    dr_fprintf(info->log,
               "Num of dynamic app references: %llu\n",
               info->num_dyn_refs);
    dr_fprintf(info->log,
               "Num of bb inline check: %llu," 
               "trace inline check: %llu\n",
               info->num_bb_inline_checks, 
               info->num_trace_inline_checks);
    dr_fprintf(info->log,
               "\ttotal inline check: %llu, "
               "miss: %llu, hit ratio: %f\n",
               info->num_bb_inline_checks +
               info->num_trace_inline_checks,
               info->num_map_checks,
               (info->num_bb_inline_checks == 0) ? 0 :
               ((double)(info->num_bb_inline_checks +
                         info->num_trace_inline_checks - 
                         info->num_map_checks) /
                (double)(info->num_bb_inline_checks +
                         info->num_trace_inline_checks)));
    dr_fprintf(info->log,
               "Num of map checks: %llu, miss: %llu, hit ratio: %f\n",
               info->num_map_checks,
               info->num_map_searchs,
               (info->num_map_checks == 0) ? 0 :
               ((double)(info->num_map_checks - 
                         info->num_map_searchs) /
                (double)(info->num_map_checks)));    
    dr_fprintf(info->log,
               "Num of map searchs: %llu, miss: %llu, hit ratio: %f\n",
               info->num_map_searchs,
               info->num_clean_calls,
               (info->num_map_searchs == 0) ? 0 :
               ((double)(info->num_map_searchs - 
                         info->num_clean_calls) /
                (double)(info->num_map_searchs)));
    dr_fprintf(info->log,
               "Num of clean calls: %llu\n", 
               info->num_clean_calls);
    dr_fprintf(info->log,
               "Num of aflags restore: %llu\n",
               info->num_aflags_restores);
    dr_fprintf(info->log,
               "Num of reg restore: %llu\n",
               info->num_reg_restores);
    dr_fprintf(info->log,
               "Num of static app instrs %llu\n",
               info->num_app_instrs);
    dr_fprintf(info->log,
               "Num of static refs: %llu\n",
               info->num_app_refs);
    dr_fprintf(info->log,
               "Num of ref_cache: %llu\n",
               info->num_ref_caches);
    dr_fprintf(info->log,
               "Num of SIGSEGV/SIGBUS: %llu\n",
               info->num_sigs);
}


/*---------------------------------------------------------------------*
 *                 Exported Function Implementation                    *
 *---------------------------------------------------------------------*/

/* initialize umbra system */
void
umbra_init(client_id_t id)
{
    DR_ASSERT_MSG(dr_using_all_private_caches(),
                  "Error: UMBRA only works in "
                  "thread private cache");
    /* init the process information */
    proc_info_init();
    /* umbra client init function */
    umbra_client_init();
    /* shadow memory manager init */
    shadow_init();
}


/* finalize umbra system */
void
umbra_exit()
{
    /* shadow memory manager exit */
    shadow_exit();
    /* umbra client exit */
    if (proc_info.client.client_exit != NULL)
        proc_info.client.client_exit();
    /* proc_info exit */
    proc_info_exit();
}


/* initialize thread private data structure for umbra */
void
umbra_thread_init(void *drcontext)
{
    umbra_info_t *info;
    
    /* initialize thread private umbra_info */
    info = (umbra_info_t *)
        dr_thread_alloc(drcontext, sizeof(umbra_info_t));

    dr_set_tls_field      (drcontext, info);
    umbra_info_init       (drcontext, info);
    if (proc_info.client.thread_init != NULL)
        proc_info.client.thread_init(drcontext, info);
    table_thread_init     (drcontext, info);
    cfg_thread_init       (drcontext, info);
    shadow_thread_init    (drcontext, info);
    analyzer_thread_init  (drcontext, info);
    instrument_thread_init(drcontext, info);
}


/* finalize thread private data structure for umbra */
void
umbra_thread_exit(void *drcontext)
{
    umbra_info_t *info = 
        (umbra_info_t *)dr_get_tls_field(drcontext);
    print_stat_count(drcontext, info);
    instrument_thread_exit(drcontext, info);
    analyzer_thread_exit  (drcontext, info);
    shadow_thread_exit    (drcontext, info);
    cfg_thread_exit       (drcontext, info);
    if (proc_info.client.thread_exit != NULL)
        proc_info.client.thread_exit(drcontext, info);
    table_thread_exit     (drcontext, info);
    umbra_info_exit       (drcontext, info);
    dr_set_tls_field      (drcontext, NULL);
    dr_thread_free(drcontext, info, sizeof(umbra_info_t));
}

/* fork init */
void
umbra_fork_init(void *drcontext)
{
    proc_info.pid = dr_get_process_id();
    proc_info.log = umbra_open_proc_log(proc_info.pid);
}

/* add the module for stack */
static void
add_stack_module(void *drcontext, umbra_info_t *info)
{
    dr_mcontext_t mcontext = {sizeof(mcontext), DR_MC_ALL, };
    memory_map_t  *map;
    memory_mod_t  *mod;
    int i;

    dr_get_mcontext(drcontext, &mcontext);
    dr_mutex_lock(proc_info.mutex);
    mod = memory_mod_app_lookup((void *)mcontext.xsp);
    DR_ASSERT(mod != NULL);
    /* get system stack */
    if (proc_info.stack_top == NULL)
        proc_info.stack_top = mod->app_base;
    map = mod->map;
    dr_mutex_unlock(proc_info.mutex);
    DR_ASSERT(map != NULL);

    info->stack_ref_cache = table_alloc_ref_cache(drcontext, info);
    info->stack_ref_cache->tag    = (reg_t)map->app_base;
    info->stack_map_tag    = (reg_t)map->app_base;
    for (i = 0; i < MAX_NUM_SHADOWS; i++) {
        info->stack_ref_cache->offset[i] = map->offset[i];
        info->stack_map_offset[i] = map->offset[i];
    }
}


/* invocated on basic block building event */
dr_emit_flags_t
umbra_basic_block(void *drcontext, 
                  void *tag, 
                  instrlist_t *ilist,
                  bool  for_trace,
                  bool  translating)
{
    umbra_info_t *info = (umbra_info_t *)dr_get_tls_field(drcontext);
    basic_block_t *bb;

    if (info->stack_ref_cache == NULL) 
        add_stack_module(drcontext, info);
    /* retrive the basic block data structure */
    bb = cfg_basic_block(drcontext, info, tag, ilist);
    /* instrument the basic block code */
    instrument_basic_block(drcontext, info, bb, ilist,
                           for_trace);
    /* let DR store the translation information */
    return DR_EMIT_STORE_TRANSLATIONS;
}


/* invocated on trace building event */
dr_emit_flags_t
umbra_trace(void *drcontext, 
            void *tag, 
            instrlist_t *ilist,
            bool  translating)
{
    umbra_info_t *info = (umbra_info_t *)dr_get_tls_field(drcontext);
    /* the functionality instrumentation is done on each bb event
     * we try to optimize the instrumentation on trace
     */
    optimize_trace(drcontext, info, tag, ilist);
    return DR_EMIT_STORE_TRANSLATIONS;
}


/* if a trace should be stoped at next_tag bb */
dr_custom_trace_action_t
umbra_end_trace(void *drcontext, 
                void *trace_tag, 
                void *next_tag)
{
    /* let DR decides */
    return CUSTOM_TRACE_DR_DECIDES;
}


/* event on code fragment deletion */
void
umbra_delete(void *drcontext, void *tag)
{
    /* Do nothing */
    return;
}


/* event on restore state */
void 
umbra_restore_state(void *drcontext, 
                    void *tag,
                    dr_mcontext_t *mcontext,
                    bool restore_memory, 
                    bool app_code_consistent)
{
    /* Do nothing */
    return;
}


/* event on which syscall is interested */
bool
umbra_filter_syscall(void *drcontext, int sysnum)
{
    /* intercept every syscall */
    return true;
}


/* invocated before the system call */
bool
umbra_pre_syscall(void *drcontext, int sysnum)
{
    umbra_info_t *info = (umbra_info_t *)dr_get_tls_field(drcontext);
    /* notify shadow memory manager */
    shadow_pre_syscall(drcontext, info, sysnum);
    return true;
}


/* invocated after the system call */
void
umbra_post_syscall(void *drcontext, int sysnum)
{
    umbra_info_t *info = (umbra_info_t *)dr_get_tls_field(drcontext);
    /* notify shadow memory manager */
    shadow_post_syscall(drcontext, info, sysnum);
}


/* invocated on each module load event */
void
umbra_module_load(void *drcontext, 
                  const module_data_t *info, 
                  bool loaded)
{
    umbra_info_t *umbra_info = (umbra_info_t *)dr_get_tls_field(drcontext);
    DR_ASSERT(info != NULL);

    umbra_wrap_func_on_module_load(drcontext, info);
    shadow_module_load(drcontext, umbra_info, info, loaded);
}


/* invocated on each module unload event */
void
umbra_module_unload(void *drcontext, 
                    const module_data_t *info)
{
    umbra_info_t *umbra_info = (umbra_info_t *)dr_get_tls_field(drcontext);
    shadow_module_unload(drcontext, umbra_info, info);
}


#ifdef LINUX
/* invocated on each signal received */
dr_signal_action_t
umbra_signal(void *drcontext, dr_siginfo_t *siginfo)
{
    umbra_info_t *umbra_info = (umbra_info_t *)dr_get_tls_field(drcontext);
    return shadow_signal(drcontext, umbra_info, siginfo);
}

#else /* Windows */

bool
umbra_exception(void *drcontext, dr_exception_t *excpt)
{
    umbra_info_t *umbra_info = (umbra_info_t *)dr_get_tls_field(drcontext);
    return shadow_exception(drcontext, umbra_info, excpt);
}

#endif /* LINUX */

static wrap_func_t *
umbra_create_wf(const char *modname,
                const char *name, app_pc pre_func, app_pc post_func)
{
    wrap_func_t *wf;
    wf = dr_global_alloc(sizeof(wrap_func_t));
    wf->modname = modname;
    wf->name = name;
    wf->func = NULL;
    wf->pre_func = pre_func;
    wf->post_func = post_func;

    dr_mutex_lock(proc_info.mutex);
    wf->next = wrap_funcs;
    wrap_funcs = wf;
    dr_mutex_unlock(proc_info.mutex);

    return wf;
}


/* */
static bool
module_name_match(const module_data_t *data, const char *modname)
{
    if (modname == NULL)
        return true;

    if (strncmp(modname, data->names.file_name, strlen(modname)) == 0)
        return true;
    return false;
}

static void
umbra_wrap_func_on_module_load(void *drcontext, const module_data_t *info)
{
    wrap_func_t *wf;
    dr_mutex_lock(proc_info.mutex);
    for (wf = wrap_funcs; wf != NULL; wf = wf->next) {
        if (wf->func != NULL)
            continue;
        if (module_name_match(info, wf->modname)) {
            wf->func = (app_pc)dr_get_proc_address(info->handle, wf->name);
            if (wf->func != NULL)
                umbra_create_wf(wf->modname, wf->name, wf->pre_func, wf->post_func);
        }
    }
    dr_mutex_unlock(proc_info.mutex);
}


void
umbra_wrap_func(const char *modname,
                const char *name, app_pc pre_func, app_pc post_func)
{
    wrap_func_t *wf;
    dr_module_iterator_t *mi;
    module_data_t *data;

    wf = umbra_create_wf(modname, name, pre_func, post_func);
    
    /* find the mod by the name */
    if (modname != NULL) {
        data = dr_lookup_module_by_name(modname);
        if (data != NULL) {
            wf->func = (app_pc)dr_get_proc_address(data->handle, wf->name);
            return;
        }
    }
    /* the module name is NULL or cannot find the module 
     * iterate over the module.
     */
    mi = dr_module_iterator_start();
    while (dr_module_iterator_hasnext(mi)) {
        module_data_t *data = dr_module_iterator_next(mi);
        if (module_name_match(data, modname)) {
            if (wf->func == NULL) {
                wf->func = (app_pc)dr_get_proc_address(data->handle, wf->name);
            } else {
                /* FIXME: the operation might be racy, i.e.
                 * multiple threads call umbra_wrap_func, and umbra_wrap_func_module
                 * It is possible more than one thread access the same wp.
                 */
                wf = umbra_create_wf(modname, name, pre_func, post_func);
                wf->func = (app_pc)dr_get_proc_address(data->handle, wf->name);
            }
        }
        dr_free_module_data(data);
        if (wf->func != NULL)
            break;
    }
    dr_module_iterator_stop(mi);
}

reg_t 
umbra_get_arg(int index)
{
    void *drcontext;
    dr_mcontext_t mc  = {sizeof(mc), DR_MC_ALL, };
    reg_t arg;
    drcontext = dr_get_current_drcontext();
    dr_get_mcontext(drcontext, &mc);
    switch (index) {
    case 0:
        arg = mc.rdi;
        break;
    case 1:
        arg = mc.rsi;
        break;
    case 2:
        arg = mc.rdx;
        break;
    case 3:
        arg = mc.rcx;
        break;
    case 4:
        arg = mc.r8;
        break;
    case 5:
        arg = mc.r9;
        break;
    default:
        DR_ASSERT(false);
    }
    return arg;
}

reg_t 
umbra_get_ret_value()
{
    void *drcontext = dr_get_current_drcontext();
    dr_mcontext_t mc  = {sizeof(mc), DR_MC_ALL, };
    dr_get_mcontext(drcontext, &mc);
    return mc.rax;
}

umbra_info_t *
umbra_get_info()
{
  void *drcontext = dr_get_current_drcontext();
  return dr_get_tls_field(drcontext);
}


/*---------------------------------------------------------------------*
 *                              End of umbra.c                         *
 *---------------------------------------------------------------------*/
