#ifdef UMBRA_CLIENT_DEP_DETECT

#include <stddef.h>    /* offsetof */
#include <string.h>    /* memset */

#include "dr_api.h"
#include "../core/utils.h"
#include "../core/global.h"
#include "../core/table.h"

#define LAST_REF_SLOT SPILL_SLOT_2
#define NEXT_INSTR_SLOT SPILL_SLOT_3

#define BUF_END_MARK   0x0e0e0e0e
#define BUF_EMPTY_MARK 0x0f0f0f0f
#define BUF_EMPTY_BYTE 0x0f
#define BUF_INITIAL_SIZE 10

#define CLIENT_CODE_CACHE_SIZE (PAGE_SIZE << 4)

typedef struct _buffer_t
{
  int capacity;
  int *storage;
} buffer_t;

typedef struct _instr_note_t
{
  int last_dependency;
  int context;
  int dependency_cache[4];
  buffer_t *buffer;
} instr_note_t;

typedef struct _proc_data_t 
{
  int num_threads;
  void *lock;
  app_pc code_cache;
  app_pc clean_call_pc;
  app_pc update_pc[NUM_SPILL_REGS][NUM_SPILL_REGS];
} proc_data_t;

typedef struct _thread_data_t
{
  app_pc next_pc;
  int last_instr_id;
} thread_data_t;

typedef struct _shadow_data_t
{
  unsigned int writer_instr_id;
} shadow_data_t;

proc_data_t proc_data;

static void
clean_call ()
{
  void *context;
  mem_ref_t *ref;
  instr_note_t* note;
  int writer_id;
  buffer_t* buffer;

  context = dr_get_current_drcontext();
  ref = (mem_ref_t*) dr_read_saved_reg(context,
				       LAST_REF_SLOT);
  note = (instr_note_t*) ref->note;
  writer_id = note->last_dependency;
  buffer = note->buffer;
  
  if (buffer == (void*)-1 || buffer == (void*)NULL)
    {
      buffer = dr_thread_alloc(context,
			       sizeof(buffer_t));
      buffer->capacity = BUF_INITIAL_SIZE;
      buffer->storage = dr_thread_alloc(context,
					sizeof(int)*
					BUF_INITIAL_SIZE);
      
      memset((void*) buffer->storage,
	     BUF_EMPTY_BYTE,
	     BUF_INITIAL_SIZE * sizeof(int));
      
      buffer->storage[BUF_INITIAL_SIZE-1] = BUF_END_MARK;
      
      buffer->storage[0] = writer_id;
      buffer->storage[1] = note->dependency_cache[0];
      buffer->storage[2] = note->dependency_cache[1];
      buffer->storage[3] = note->dependency_cache[2];
      buffer->storage[4] = note->dependency_cache[3];
      
      note->buffer = buffer;
    }
  else
    {
      int i;					
      int unseen_writer, unseen_cache0,
	unseen_cache1, unseen_cache2, unseen_cache3;
      int total_unseen;
      
      unseen_writer = 1;
      unseen_cache0 = 1;
      unseen_cache1 = 1;
      unseen_cache2 = 1;
      unseen_cache3 = 1;
      total_unseen = 5;
      
      for (i = 0; true; i++)
	{
	  if (unseen_writer && buffer->storage[i] == writer_id)
	    {
	      unseen_writer = 0;
	      total_unseen--;
	    }
	  else if (unseen_cache0 && 
		   buffer->storage[i] == note->dependency_cache[0])
	    {
	      unseen_cache0 = 0;
	      total_unseen--;
	    }
	   else if (unseen_cache1 && 
		   buffer->storage[i] == note->dependency_cache[1])
	    {
	      unseen_cache1 = 0;
	      total_unseen--;
	    }
	   else if (unseen_cache2 && 
		    buffer->storage[i] == note->dependency_cache[2])
	     {
	       unseen_cache2 = 0;
	       total_unseen--;
	     }
	   else if (unseen_cache3 && 
		   buffer->storage[i] == note->dependency_cache[3])
	    {
	      unseen_cache3 = 0;
	      total_unseen--;
	    }

	  if (buffer->storage[i] == BUF_EMPTY_MARK)
	    {
	      if (total_unseen == 0)
		return;
	      
	      // one must be EMPTY in buffer
	      if (i + total_unseen - 1 < buffer->capacity - 1)
		{
		  int count;
		  count = 0;
		  
		  if (unseen_writer)
		    {
		      buffer->storage[i] = writer_id;
		      count++;
		    }
		  if (unseen_cache0)
		    {
		      buffer->storage[i+count] = note->dependency_cache[0];
		      count++;
		    }
		  if (unseen_cache1)
		    {
		      buffer->storage[i+count] = note->dependency_cache[1];
		      count++;
		    }
		  if (unseen_cache2)
		    {
		      buffer->storage[i+count] = note->dependency_cache[2];
		      count++;
		    }
		  if (unseen_cache3)
		    {
		      buffer->storage[i+count] = note->dependency_cache[3];
		      count++;
		    }
		}
	      else
		{
		  int count;
		  int* new_storage;
		  
		  count = 0;
		  new_storage = dr_thread_alloc(context,
						buffer->capacity
						* 2 * sizeof(int));
		  memset((void*) new_storage,
			 BUF_EMPTY_BYTE,
			 buffer->capacity * 2 * sizeof(int));
		  
		  if (unseen_writer)
		    {
		      buffer->storage[0] = writer_id;
		      count++;
		    }
		  if (unseen_cache0)
		    {
		      buffer->storage[count] = note->dependency_cache[0];
		      count++;
		    }
		  if (unseen_cache1)
		    {
		      buffer->storage[count] = note->dependency_cache[1];
		      count++;
		    }
		  if (unseen_cache2)
		    {
		      buffer->storage[count] = note->dependency_cache[2];
		      count++;
		    }
		  if (unseen_cache3)
		    {
		      buffer->storage[count] = note->dependency_cache[3];
		      count++;
		    }
		  
		  for (i = 0; i < buffer->capacity-1; i++)
		    {
		      new_storage[total_unseen+i] = 
			buffer->storage[buffer->capacity-2-i];
		    }
		  
		  dr_thread_free(context,
				 buffer->storage,
				 buffer->capacity
				 * sizeof(int));
		  
		  buffer->capacity *= 2;
		  buffer->storage = new_storage;
		}
	    }
	}
    }
}
 /*
  * mov ref->id %r2
  * cmp shadow->id %r2
  * je .read_check
  *   mov shadow->id %r2 
  *   mov ref->id shadow->id
  * .read_check:
  * cmp ref->note.last_dependency %r2
  * je .app
  *   mov ref -> last_ref
  *   mov next-pc -> next-pc
  * jmp [r1][r2]
  * .app
  */

 static void
 instrument_modify_update(void         *context,
			  umbra_info_t *umbra_info,
			  mem_ref_t    *ref,
			  instrlist_t  *ilist,
			  instr_t      *where)
 {
   reg_id_t r1, r2, reg_addr;
   instr_t *instr, *label, *read_check;
   int size, pos1, pos2;
   thread_data_t *data;
   opnd_t opnd1, opnd2;
   instr_note_t* note;

   note = (instr_note_t*)ref->note;

   if (note->buffer == (void*)NULL)
     {
       note->last_dependency = ref->id;
       note->context = -1;

       note->dependency_cache[0] = BUF_EMPTY_MARK;
       note->dependency_cache[1] = BUF_EMPTY_MARK;
       note->dependency_cache[2] = BUF_EMPTY_MARK;
       note->dependency_cache[3] = BUF_EMPTY_MARK;

       note->buffer = (void*)-1;
     }

   data = umbra_info->client_tls_data;
   r1 = umbra_info->steal_regs[0];
   r2 = umbra_info->steal_regs[1];
   reg_addr = r1;

   UMBRA_REG_TO_POS(r1, pos1);
   UMBRA_REG_TO_POS(r2, pos2);

   size = OPSZ_4;
   r2 = reg_64_to_32(r2);

   /* Load Reference ID into r2 */
   opnd1 = opnd_create_reg(r2);
   opnd2 = OPND_CREATE_INT32(ref->id);
   instr = INSTR_CREATE_mov_imm(context, opnd1, opnd2);
   instrlist_meta_preinsert(ilist, where, instr);

   /* Compare r2 (Reference ID) with Last Writer */
   opnd1 = opnd_create_base_disp(r1, DR_REG_NULL, 0,
				 offsetof(shadow_data_t,
					  writer_instr_id),
				 size);
   opnd2 = opnd_create_reg(r2);
   instr = INSTR_CREATE_cmp(context, opnd1, opnd2);
   instrlist_meta_preinsert(ilist, where, instr);
   instr_set_translation(instr, ref->pc);
   instr_set_meta_may_fault(instr, true);

   /* If Reference ID == Last Writer, skip update:
      jmp read_check */
   read_check = INSTR_CREATE_label(context);
   opnd1 = opnd_create_instr(read_check);
   instr = INSTR_CREATE_jcc(context, OP_je, opnd1);
   instrlist_meta_preinsert(ilist, where, instr);

   /* Update Step 1: mov shadow->id %r2 */
   opnd1 = opnd_create_reg(r2);
   opnd2 = opnd_create_base_disp(r1, DR_REG_NULL, 0,
				 offsetof(shadow_data_t, 
					  writer_instr_id),
				 size);
   instr = INSTR_CREATE_mov_ld(context, opnd1, opnd2);
   instrlist_meta_preinsert(ilist, where, instr);

   /* Update Step 2: mov ref->id shadow->id */
   opnd1 = opnd_create_base_disp(r1, DR_REG_NULL, 0,
				 offsetof(shadow_data_t, 
					  writer_instr_id),
				 size);
   opnd2 = OPND_CREATE_INT32(ref->id);
   instr = INSTR_CREATE_mov_st(context, opnd1, opnd2);
   instrlist_meta_preinsert(ilist, where, instr);

   /* Add label: read check */
   instrlist_meta_preinsert(ilist, where, read_check);

   /* Compare last dependency with previous Writer ID
      cmp ref->note.last_dependency r2 */
   opnd1 = OPND_CREATE_ABSMEM(&note->last_dependency,
			      size);
   opnd2 = opnd_create_reg(r2);
   instr = INSTR_CREATE_cmp(context, opnd1, opnd2);
   instrlist_meta_preinsert(ilist, where, instr);

   /* If previous Writer ID == last dependency match, done.*/
   /* je .app (= je where) */
   opnd1 = opnd_create_instr(where);
   instr = INSTR_CREATE_jcc(context, OP_je, opnd1);
   instrlist_meta_preinsert(ilist, where, instr);

   /* Branch not taken: update after saving state */

   /* mov ref last_ref */
   opnd1 = dr_reg_spill_slot_opnd(context, LAST_REF_SLOT);
   opnd2 = OPND_CREATE_INT32(ref);
   instr = INSTR_CREATE_mov_st(context, opnd1, opnd2);
   instrlist_meta_preinsert(ilist, where, instr);

   /* save next instr */
   label = INSTR_CREATE_label(context);
   opnd1 = dr_reg_spill_slot_opnd(context, 
				  NEXT_INSTR_SLOT);
   opnd2 = opnd_create_instr(label);
   instr = INSTR_CREATE_mov_st(context, opnd1, opnd2);
   instrlist_meta_preinsert(ilist, where, instr);

   /* jump to update code */
   opnd1 = opnd_create_pc(proc_data.update_pc[pos1][pos2]);
   instr = INSTR_CREATE_jmp(context, opnd1);
   instrlist_meta_preinsert(ilist, where, instr);

   /* add label .app */
   instrlist_meta_preinsert(ilist, where, label);
 }

 /* 
  * cmp shadow->id, ref->id
  * je .app
  * mov ref->id => shadow->id
  * .app
  */
 static void
 instrument_write_update(void *context,
			 umbra_info_t *umbra_info,
			 mem_ref_t *ref,
			 instrlist_t *ilist,
			 instr_t *where)
 {
   reg_id_t r1, r2;
   instr_t *instr;
   int size;
   opnd_t opnd1, opnd2;

   r1 = umbra_info->steal_regs[0];
   r2 = umbra_info->steal_regs[1];
   
   r2 = reg_64_to_32(r2);
   size = OPSZ_4;
   
   /* High Level: Compare Memory Reference ID <-> Last Writer ID */
   /* Low Level: cmp ref->id shadow->id */
   opnd1 = opnd_create_base_disp(r1, DR_REG_NULL, 0,
				 offsetof(shadow_data_t,
					  writer_instr_id),
				 size);
   opnd2 = OPND_CREATE_INT32(ref->id);
   instr = INSTR_CREATE_cmp(context, opnd1, opnd2);
   instrlist_meta_preinsert(ilist, where, instr);
   instr_set_translation(instr, ref->pc);
   instr_set_meta_may_fault(instr, true);
   
   /* High Level: Done, Memory Reference ID == Last Writer ID */
   /* Low Level: je where */
   opnd1 = opnd_create_instr(where);
   instr = INSTR_CREATE_jcc(context, OP_je, opnd1);
   instrlist_meta_preinsert(ilist, where, instr);

   /* High Level: Update, Memory Reference ID -> Last Writer ID */
   /* Low Level: mov ref->id shadow->id */
   opnd1 = opnd_create_base_disp(r1, DR_REG_NULL, 0,
				 offsetof(shadow_data_t,
					  writer_instr_id),
				 size);
   opnd2 = OPND_CREATE_INT32(ref->id);
   instr = INSTR_CREATE_mov_st(context, opnd1, opnd2);
   instrlist_meta_preinsert(ilist, where, instr);
 }

 /* 
  * mov shadow->id %r2
  * cmp ref->note.last_dependency %r2
  * je .app
  *   mov ref     => client->last_instr_id
  *   mov next_pc => client->next_pc
  *   jmp [r1][r2]
  * .app
  */
 static void
 instrument_read_update(void* context,
			umbra_info_t *umbra_info,
			mem_ref_t *ref,
			instrlist_t *ilist,
			instr_t *where)
 {
   reg_id_t r1, r2, reg_addr;
   instr_t *instr, *label;
   int size, pos1, pos2;
   thread_data_t *client;
   opnd_t opnd1, opnd2;
   instr_note_t *note;
   
   note = (instr_note_t*)ref->note;
   
   if (note->buffer == (void*)NULL)
     {
       note->last_dependency = ref->id;
       note->context = -1;
       
       note->dependency_cache[0] = BUF_EMPTY_MARK;
       note->dependency_cache[1] = BUF_EMPTY_MARK;
       note->dependency_cache[2] = BUF_EMPTY_MARK;
       note->dependency_cache[3] = BUF_EMPTY_MARK;

       note->buffer = (void*)-1;
     }

   client = umbra_info->client_tls_data;
   r1 = umbra_info->steal_regs[0];
   r2 = umbra_info->steal_regs[1];
   reg_addr = r1;

   UMBRA_REG_TO_POS(r1, pos1);
   UMBRA_REG_TO_POS(r2, pos2);

   size = OPSZ_4;
   r1 = reg_64_to_32(r1);
   r2 = reg_64_to_32(r2);

   /* High Level: Load Last Writer for this Location into r2 */
   /* Low Level: move shadow->id -> r2 */
   opnd1 = opnd_create_reg(r2);
   opnd2 = opnd_create_base_disp(reg_addr,
				 DR_REG_NULL, 0,
				 offsetof(shadow_data_t,
					  writer_instr_id),
				 size);
   instr = INSTR_CREATE_mov_ld(context, opnd1, opnd2);
   instrlist_meta_preinsert(ilist, where, instr);
   instr_set_translation(instr, ref->pc);
   instr_set_meta_may_fault(instr, true);

   /* High Level: Compare Last Dep. for Instr <-> Last Writer */
   /* Low Level: cmp ref->note.last_dependency r2 */
   opnd1 = OPND_CREATE_ABSMEM(&note->last_dependency,
			      size);
   opnd2 = opnd_create_reg(r2);
   instr = INSTR_CREATE_cmp(context, opnd1, opnd2);
   instrlist_meta_preinsert(ilist, where, instr);

   /* High Level: Done, Last Writer == Last Dep. for Instr */
   /* Low Level: je where */
   opnd1 = opnd_create_instr(where);
   instr = INSTR_CREATE_jcc(context, OP_je, opnd1);
   instrlist_meta_preinsert(ilist, where, instr);

   /* High Level: Not Done, Move to Update Code */
   /* Low Level: Save ref/next_pc and jump */

   // [save] last instruction
   opnd1 = dr_reg_spill_slot_opnd(context,
				  LAST_REF_SLOT);
   opnd2 = OPND_CREATE_INT32(ref);
   instr = INSTR_CREATE_mov_st(context,
			       opnd1,
			       opnd2);
   instrlist_meta_preinsert(ilist, where, instr);

   // [save] next pc 
   label = INSTR_CREATE_label(context);
   opnd1 = dr_reg_spill_slot_opnd(context,
				  NEXT_INSTR_SLOT);
   opnd2 = opnd_create_instr(label);
   instr = INSTR_CREATE_mov_st(context, opnd1, opnd2);
   instrlist_meta_preinsert(ilist, where, instr);

   // jump [r1][r2]
   opnd1 = opnd_create_pc(proc_data.update_pc[pos1][pos2]);
   instr = INSTR_CREATE_jmp(context, opnd1);
   instrlist_meta_preinsert(ilist, where, instr);

   /* label, insert: .app (next pc) */
   instrlist_meta_preinsert(ilist, where, label);
 }

 static void 
 instrument_update(void *context,
		   umbra_info_t *umbra_info,
		   mem_ref_t *ref,
		   instrlist_t *ilist,
		   instr_t *where)
 {
   if (ref->type == MemRead)
     instrument_read_update(context,
			    umbra_info,
			    ref,
			    ilist,
			    where);
   else if (ref->type == MemWrite)
     instrument_write_update(context,
			     umbra_info,
			     ref,
			     ilist,
			     where);
   else if (ref->type == MemModify)
     instrument_modify_update(context,
			      umbra_info,
			      ref,
			      ilist,
			      where);

 }

 static bool
 ref_is_interested(mem_ref_t *ref)
 {
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

     for (i = 0; i < bb->num_refs; i++) 
       {
	 if (ref_is_interested(&bb->refs[i]))
	   return true;
       }
     return false;
 }

 static void
 umbra_client_thread_init(void *context, 
			  umbra_info_t *umbra_info)
 {
   thread_data_t *thread_data;

   /* allocate per-thread data */
   thread_data = dr_thread_alloc(context, 
				 sizeof(thread_data_t));
   umbra_info->client_tls_data = thread_data;
 }

 static void
 umbra_client_thread_exit(void *context, umbra_info_t *umbra_info)
 {
   int i, j, k, *buf;
   basic_block_t *bb;
   mem_ref_t     *refs, *ref;
   instr_note_t* note;

   //dr_fprintf(umbra_info->log, "calls %d\n", g);
   for (i = 0; i < umbra_info->table.num_bbs; i++) 
     {
       if (i % INIT_BB_TABLE_SIZE == 0)
	 continue;

       bb = table_get_bb(umbra_info, i);
       refs = bb->refs;

       dr_fprintf(umbra_info->log, "BasicBlock[%d] %p\n", 
		  bb->id, bb->tag);
       for (j = 0; j < bb->num_refs; j++)
	 {
	   dr_fprintf(umbra_info->log, "Ref[%d] %p depends on:\n",
		      refs[j].id, refs[j].pc);
	   
	   note = (instr_note_t*)refs[j].note;
	 	   
	   if (note->buffer == (void*)-1 || note->buffer == (void*)NULL)
	     {
	       for (k = 0; k < 4; k++)
		 {
		   if (note->dependency_cache[k] != BUF_EMPTY_MARK)
		     {
		       ref = table_get_ref(umbra_info,
					   note->dependency_cache[k]);
		       dr_fprintf(umbra_info->log, "\t%p %d\n", ref->pc, 
				  ref->id);
		     }
		 } 
	       continue;
	     }
	   else
	     {
	       buf = (note->buffer)->storage;
	       for (k = 0; k < (note->buffer)->capacity; k++) 
		 {
		   if (buf[k] == BUF_EMPTY_MARK || buf[k] == BUF_END_MARK)
		     break;
		   ref = table_get_ref(umbra_info, buf[k]);
		   dr_fprintf(umbra_info->log, "\t%p %d\n", ref->pc, ref->id);
		   
		 }
	     }
	 }
     }
   
   for (i = 0; i < umbra_info->table.num_refs; i++) 
     {
       if (i % INIT_REF_TABLE_SIZE == 0) 
	 continue;
       
       ref = table_get_ref(umbra_info, i);
       note = (instr_note_t*) ref->note;
       
       if (note->buffer != (void*)-1 &&
	   note->buffer != (void*)NULL)
	 { 
	   dr_thread_free(context, 
			  note->buffer->storage,
			  note->buffer->capacity
			  *sizeof(int));
	   
	   dr_thread_free(context,
			  note->buffer,
			  sizeof(buffer_t));
	 }
       else 
	 dr_fprintf(umbra_info->log, 
		    "ref[%d] has no dependency\n", i);
     }
   
   dr_thread_free(context, umbra_info->client_tls_data, 
		  sizeof(thread_data_t));
   return;
 }


/*
 * r2 contains the writer ID that last_ref depended on
 * r1 is a temp register that umbra stole for us
 *
 *   mov &ref r1
 *   mov r2 ref->note.last_dependency
 *
 *   cmp ref->note.cache[0] r2 
 *   jne check_next:
 * exit_app_code:
 *   jind app-pc
 * check_next:
 *   cmp ref->note.cache[1] r2
 *   je exit_app_code
 *   cmp ref->note.cache[2] r2 
 *   je exit_app_code
 *   cmp ref->note.cache[3] r2
 *   je exit_app_code
 *
 *   cmp ref->note.cache[0] BUF_EMPTY_MARK 
 *   jne try_fill_second
 *       r2 -> ref->note.cache[0]
 *       jmp cache-pc
 * try_fill_second:
 *   cmp ref->note.cache[1] BUF_EMPTY_MARK 
 *   jne try_fill_third:
 *       r2 -> ref->note.cache[1]
 *       jmp cache-pc
 * try_fill_third:
 *   cmp ref->note.cache[2] BUF_EMPTY_MARK 
 *   jne try_fill_fourth:
 *       r2 -> ref->note.cache[2]
 *       jmp cache-pc
 * try_fill_fourth:
 *   cmp ref->note.cache[3] BUF_EMPTY_MARK 
 *   jne clean_call_pc
 *       r2 -> ref->note.cache[3]
 *       jmp cache-pc
 */
static app_pc
emit_update_code(void *context,
		 app_pc pc,
		 reg_id_t r1,
		 reg_id_t r2)
{
  instrlist_t *ilist;
  instr_t *instr, *exit_app_code, 
    *check_next, *try_fill_second, *try_fill_third, 
    *try_fill_fourth; 
  opnd_t opnd1, opnd2;
  
  ilist = instrlist_create(context);
  instrlist_init(ilist);
  
  /* Move the pointer to last reference in r1 */
  dr_restore_reg(context, ilist, NULL, r1, LAST_REF_SLOT);

  r1 = reg_64_to_32(r1);
  r2 = reg_64_to_32(r2);

  /* Move the WRITER_ID (r2) to ref->note.last_dependency */
  opnd1 = OPND_CREATE_MEM32(r1, 
			    offsetof(mem_ref_t, note)
			    + offsetof(instr_note_t, 
				       last_dependency));
  
  opnd2 = opnd_create_reg(r2);
  instr = INSTR_CREATE_mov_st(context, opnd1, opnd2);
  instrlist_meta_append(ilist, instr);
  

  /* Compare first element: cmp ref->note.cache[0] r2  */
  opnd1 = OPND_CREATE_MEM32(r1,
			    offsetof(mem_ref_t, note)
			    + offsetof(instr_note_t,
				       dependency_cache[0]));
  opnd2 = opnd_create_reg(r2);
  instr = INSTR_CREATE_cmp(context, opnd1, opnd2);
  instrlist_meta_append(ilist, instr);

  /* Jump to next element if first element misses: 
     jne check_next */
  check_next = INSTR_CREATE_label(context);
  opnd1 = opnd_create_instr(check_next);
  instr = INSTR_CREATE_jcc(context, OP_jne, opnd1);
  instrlist_meta_append(ilist, instr);

  /* Create and insert label: exit_app_code*/
  exit_app_code = INSTR_CREATE_label(context);
  instrlist_meta_append(ilist, exit_app_code);
  
  /* If first element hit, go back to application code:
     jmp next_instr_slot */
  opnd1 = dr_reg_spill_slot_opnd(context, NEXT_INSTR_SLOT);
  instr = INSTR_CREATE_jmp_ind(context, opnd1);
  instrlist_meta_append(ilist, instr);
  
  /* Insert label: check_next */
  instrlist_meta_append(ilist, check_next);

  /* Compare second element: cmp ref->note.cache[1] r2  */
  opnd1 = OPND_CREATE_MEM32(r1,
			     offsetof(mem_ref_t, note)
			     + offsetof(instr_note_t, 
					dependency_cache[1]));
  opnd2 = opnd_create_reg(r2);
  instr = INSTR_CREATE_cmp(context, opnd1, opnd2);
  instrlist_meta_append(ilist, instr);

  /* Jump to exit_code if second element == r2: 
     je exit_app_code */
  opnd1 = opnd_create_instr(exit_app_code);
  instr = INSTR_CREATE_jcc(context, OP_je, opnd1);
  instrlist_meta_append(ilist, instr);
  
  /* Compare third element: cmp ref->note.cache[2] r2  */
  opnd1 = OPND_CREATE_MEM32(r1,
			     offsetof(mem_ref_t, note)
			     + offsetof(instr_note_t, 
					dependency_cache[2]));
  opnd2 = opnd_create_reg(r2);
  instr = INSTR_CREATE_cmp(context, opnd1, opnd2);
  instrlist_meta_append(ilist, instr);

  /* Jump to exit_code if third element == r2: 
     je exit_app_code */
  opnd1 = opnd_create_instr(exit_app_code);
  instr = INSTR_CREATE_jcc(context, OP_je, opnd1);
  instrlist_meta_append(ilist, instr);

  /* Compare fourth element: cmp ref->note.cache[3] r2  */
  opnd1 = OPND_CREATE_MEM32(r1,
			     offsetof(mem_ref_t, note)
			     + offsetof(instr_note_t, 
					dependency_cache[3]));
  opnd2 = opnd_create_reg(r2);
  instr = INSTR_CREATE_cmp(context, opnd1, opnd2);
  instrlist_meta_append(ilist, instr);

  /* Jump to exit_code if fourth element == r2: 
     je exit_app_code */
  opnd1 = opnd_create_instr(exit_app_code);
  instr = INSTR_CREATE_jcc(context, OP_je, opnd1);
  instrlist_meta_append(ilist, instr);

  /* If all elements missed, check for EMPTY elements:
     cmp ref->note.cache[1] BUF_EMPTY_MARK */
  opnd1 = OPND_CREATE_MEM32(r1,
			    offsetof(mem_ref_t, note)
			    + offsetof(instr_note_t, 
				       dependency_cache[0]));
  
  opnd2 = OPND_CREATE_INT32(BUF_EMPTY_MARK);
  instr = INSTR_CREATE_cmp(context, opnd1, opnd2);
  instrlist_meta_append(ilist, instr);

  /* If element is not EMPTY, go to next one: 
     jne try_fill_second */
  try_fill_second = INSTR_CREATE_label(context);
  opnd1 = opnd_create_instr(try_fill_second);
  instr = INSTR_CREATE_jcc(context, OP_jne, opnd1);
  instrlist_meta_append(ilist, instr);

  /* If element IS EMPTY, make the update:
     r2 -> ref->note.cache[0] */
  
  opnd1 = OPND_CREATE_MEM32(r1,
			     offsetof(mem_ref_t, note)
			     + offsetof(instr_note_t, 
					dependency_cache[0]));
  opnd2 = opnd_create_reg(r2);
  instr = INSTR_CREATE_mov_st(context, opnd1, opnd2);
  instrlist_meta_append(ilist, instr);

  /* After update, go back to application code:
     jmp next_instr_slot */
  opnd1 = dr_reg_spill_slot_opnd(context, NEXT_INSTR_SLOT);
  instr = INSTR_CREATE_jmp_ind(context, opnd1);
  instrlist_meta_append(ilist, instr);
  
  /* Insert label: try_fill_second */ 
  instrlist_meta_append(ilist, try_fill_second);
  
  /* Check for EMPTY elements:
     cmp ref->note.cache[1] BUF_EMPTY_MARK */
  opnd1 = OPND_CREATE_MEM32(r1,
			    offsetof(mem_ref_t, note)
			    + offsetof(instr_note_t, 
				       dependency_cache[1]));
  
  opnd2 = OPND_CREATE_INT32(BUF_EMPTY_MARK);
  instr = INSTR_CREATE_cmp(context, opnd1, opnd2);
  instrlist_meta_append(ilist, instr);
  
  /* If element is not EMPTY, go to next one: 
     jne try_fill_third */
  try_fill_third = INSTR_CREATE_label(context);
  opnd1 = opnd_create_instr(try_fill_third);
  instr = INSTR_CREATE_jcc(context, OP_jne, opnd1);
  instrlist_meta_append(ilist, instr);
  
  /* If element IS EMPTY, make the update:
     r2 -> ref->note.cache[1] */
  
  opnd1 = OPND_CREATE_MEM32(r1,
			    offsetof(mem_ref_t, note)
			    + offsetof(instr_note_t, 
				       dependency_cache[1]));
  opnd2 = opnd_create_reg(r2);
  instr = INSTR_CREATE_mov_st(context, opnd1, opnd2);
  instrlist_meta_append(ilist, instr);

  /* After update, go back to application code:
     jmp next_instr_slot */
  opnd1 = dr_reg_spill_slot_opnd(context, NEXT_INSTR_SLOT);
  instr = INSTR_CREATE_jmp_ind(context, opnd1);
  instrlist_meta_append(ilist, instr);
  
  /* Insert label: try_fill_third */ 
  instrlist_meta_append(ilist, try_fill_third);

  /* Check for EMPTY elements:
     cmp ref->note.cache[2] BUF_EMPTY_MARK */
  opnd1 = OPND_CREATE_MEM32(r1,
			    offsetof(mem_ref_t, note)
			    + offsetof(instr_note_t, 
				       dependency_cache[2]));
  
  opnd2 = OPND_CREATE_INT32(BUF_EMPTY_MARK);
  instr = INSTR_CREATE_cmp(context, opnd1, opnd2);
  instrlist_meta_append(ilist, instr);
  
  /* If element is not EMPTY, go to next one: 
     jne try_fill_fourth */
  try_fill_fourth = INSTR_CREATE_label(context);
  opnd1 = opnd_create_instr(try_fill_fourth);
  instr = INSTR_CREATE_jcc(context, OP_jne, opnd1);
  instrlist_meta_append(ilist, instr);
  
  /* If element IS EMPTY, make the update:
     r2 -> ref->note.cache[2] */
  
  opnd1 = OPND_CREATE_MEM32(r1,
			    offsetof(mem_ref_t, note)
			    + offsetof(instr_note_t, 
				       dependency_cache[2]));
  opnd2 = opnd_create_reg(r2);
  instr = INSTR_CREATE_mov_st(context, opnd1, opnd2);
  instrlist_meta_append(ilist, instr);
  
  /* After update, go back to application code:
     jmp next_instr_slot */
  opnd1 = dr_reg_spill_slot_opnd(context, NEXT_INSTR_SLOT);
  instr = INSTR_CREATE_jmp_ind(context, opnd1);
  instrlist_meta_append(ilist, instr);
  
  /* Insert label: try_fill_fourth */ 
  instrlist_meta_append(ilist, try_fill_fourth);

 /* Check for EMPTY elements:
    cmp ref->note.cache[3] BUF_EMPTY_MARK */
  opnd1 = OPND_CREATE_MEM32(r1,
			    offsetof(mem_ref_t, note)
			    + offsetof(instr_note_t, 
				       dependency_cache[3]));
  
  opnd2 = OPND_CREATE_INT32(BUF_EMPTY_MARK);
  instr = INSTR_CREATE_cmp(context, opnd1, opnd2);
  instrlist_meta_append(ilist, instr);
  
  /* If element is not EMPTY, go to next one: 
     jne clean_call_pc */
  opnd1 = opnd_create_pc(proc_data.clean_call_pc);
  instr = INSTR_CREATE_jcc(context, OP_jne, opnd1);
  instrlist_meta_append(ilist, instr);
  
  /* If element IS EMPTY, make the update:
     r2 -> ref->note.cache[3] */
  
  opnd1 = OPND_CREATE_MEM32(r1,
			    offsetof(mem_ref_t, note)
			     + offsetof(instr_note_t, 
					dependency_cache[3]));
  opnd2 = opnd_create_reg(r2);
  instr = INSTR_CREATE_mov_st(context, opnd1, opnd2);
  instrlist_meta_append(ilist, instr);
  
  /* After update, go back to application code:
     jmp next_instr_slot */
  opnd1 = dr_reg_spill_slot_opnd(context, NEXT_INSTR_SLOT);
  instr = INSTR_CREATE_jmp_ind(context, opnd1);
  
  instrlist_meta_append(ilist,
			instr);
  pc = instrlist_encode(context,
			ilist,
			pc, true);
  instrlist_clear_and_destroy(context, ilist);
  return pc;
}

static app_pc
emit_clean_call_code(void *context, app_pc pc)
{
  instrlist_t *ilist;
  instr_t     *instr;
  opnd_t       opnd;
  
  ilist = instrlist_create(context);
  instrlist_init(ilist);
  
  dr_insert_clean_call(context, ilist, NULL, 
		       clean_call, false, 0);
 
  opnd = dr_reg_spill_slot_opnd(context,
				NEXT_INSTR_SLOT);
  
  instr = INSTR_CREATE_jmp_ind(context, opnd);
  instrlist_meta_append(ilist, instr);
  
  pc = instrlist_encode(context, ilist, pc, true);
  instrlist_clear_and_destroy(context, ilist);
  return pc;
}

static void
generate_code_permutations()
{
  void* context;
  uint protection;
  app_pc pc;
  reg_id_t r1, r2;
  int pos1, pos2;

  context = dr_get_current_drcontext();
  DR_ASSERT(context != NULL);
  
  protection = DR_MEMPROT_READ|DR_MEMPROT_WRITE|DR_MEMPROT_EXEC;
  proc_data.code_cache = 
    dr_nonheap_alloc(CLIENT_CODE_CACHE_SIZE, protection);
  
  pc = umbra_align_cache_line(proc_data.code_cache);
  proc_data.clean_call_pc = pc;
  pc = emit_clean_call_code(context, pc);
  
  for (pos1 = 0; pos1 < NUM_SPILL_REGS; pos1++)
    {
      UMBRA_POS_TO_REG(r1, pos1);
      
      if (r1 == DR_REG_XAX || r1 == DR_REG_XSP)
	continue;
      
      for (pos2 = pos1 + 1; pos2 < NUM_SPILL_REGS; pos2++)
	{
	  UMBRA_POS_TO_REG(r2, pos2);
	  if (r2 == DR_REG_XAX || r2 == DR_REG_XSP)
	    continue;
	  
	  pc = umbra_align_cache_line(pc);
	  proc_data.update_pc[pos1][pos2] = pc;
	  pc = emit_update_code(context, pc, r1, r2);
	}
    }
}

void
print_ref_struct()
{
  printf("Size = %d\n",(int) sizeof(instr_note_t));
  printf("Offset: L1 = %d\n", (int) offsetof(instr_note_t, last_dependency));
  printf("Offset: CTXT = %d\n", (int) offsetof(instr_note_t, context));
  printf("Offset: EntryO = %d\n", (int) offsetof(instr_note_t, dependency_cache[0]));
  printf("Offset: Entry1 = %d\n", (int) offsetof(instr_note_t, dependency_cache[1]));
  printf("Offset: Entry2 = %d\n", (int) offsetof(instr_note_t, dependency_cache[2]));
  printf("Offset: Entry3 = %d\n", (int) offsetof(instr_note_t, dependency_cache[3]));
  printf("Offset: Buffer = %d\n", (int) offsetof(instr_note_t, buffer));  
}


void 
umbra_client_init()
{
  umbra_client_t *client;
  
  memset(&proc_data, 0, sizeof(proc_data_t));
  proc_data.lock = dr_mutex_create();
  proc_data.num_threads = 0;

  client = &proc_info.client;
  memset(client, 0, sizeof(umbra_client_t));
  client->thread_init = umbra_client_thread_init;
  client->thread_exit = umbra_client_thread_exit;
  client->bb_is_interested = bb_is_interested;
  client->ref_is_interested = ref_is_interested;
  client->app_unit_bits[0] = 2;
  client->shd_unit_bits[0] = 2;
  client->orig_addr = false;
  client->num_steal_regs = 2;
  client->instrument_update = instrument_update;
  client->shadow_memory_module_destroy = NULL;
  client->shadow_memory_module_create = NULL;

  generate_code_permutations();
  //print_ref_struct();
}

#endif /* UMBRA_CLIENT_CLUSTER_SIMPLE_THREE */
