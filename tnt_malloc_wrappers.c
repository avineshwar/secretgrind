//--------------------------------------------------------------------*/
//--- malloc/free wrappers for Taintgrind    tnt_malloc_wrappers.c ---*/
//--------------------------------------------------------------------*/

/*
   This file is part of Taintgrind.
   usage of programs.

   This program is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   This program is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
   02111-1307, USA.

   The GNU General Public License is contained in the file COPYING.
*/

//------------------------------------------------------------//
//--- malloc() et al replacement wrappers for Taintgrind      ---//
//------------------------------------------------------------//
//--- Simplified version adapted from Massif.              ---//
//--- The main reason for replacing malloc etc. is to      ---//
//--- untaint data when free is called, and to copy taint  ---//
//--- state when realloc is called.                        ---//
//------------------------------------------------------------//

#include "pub_tool_basics.h"
#include "pub_tool_hashtable.h"
#include "pub_tool_libcbase.h"
#include "pub_tool_libcassert.h"
#include "pub_tool_mallocfree.h"
#include "pub_tool_replacemalloc.h"
#include "pub_tool_tooliface.h"
#include "pub_tool_xarray.h"
#include "pub_tool_threadstate.h"
#include "pub_tool_libcprint.h"     // VG_(message)
#include "pub_tool_debuginfo.h"
#include "pub_tool_execontext.h"
#include "pub_tool_stacktrace.h"
#include "pub_tool_libcproc.h"

#include "tnt_include.h"
#include "tnt_summary_names.h"
#include "tnt_subblock_helper.h"
#include "tnt_malloc_wrappers.h"

static
void* record_block( ThreadId tid, void* p, SizeT req_szB, SizeT slop_szB );

/* For tracking malloc'd blocks.  Nb: it's quite important that it's a
   VgHashTable, because VgHashTable allows duplicate keys without complaint.
   This can occur if a user marks a malloc() block as also a custom block with
   MALLOCLIKE_BLOCK. */
static VgHashTable TNT_(malloc_list)  = NULL;   // HP_Chunks

// this one is just to keep free()'ed chunks that have childs
static VgHashTable TNT_(freed_wchild_list)  = NULL;   // HP_Chunks

#if _SECRETGRIND_

static Addr g_heap_min = (Addr)(-1);
static Addr g_heap_max = (Addr)0;

#define UNKNOWN_MALLOCED_OBJ_FMT	"@0x%lx_malloc_%u_%u"

// dummy implementation for testing
Bool TNT_(malloc_get_varname)(Addr a, char *pname, SizeT s, char *pdetailedname, SizeT ds) {
	
	Bool ret = False;
	HP_Chunk* hc = VG_(HT_lookup)( TNT_(malloc_list), (UWord)a );
	if (hc) {
		LOG("malloc_get_varname 0x%lx chunk found '%s'\n", a, hc->vname);
		VG_(strncpy)(pname, hc->vname, s-1);
		pname[s-1] = '\0';
		ret = True;
	} else {
		LOG("malloc_get_varname 0x%lx chunk NOT found, falling back to iteration\n", a);
		VG_(HT_ResetIter)(TNT_(malloc_list));
		while ( (hc = VG_(HT_Next)(TNT_(malloc_list))) ) {
			if ( VG_(addr_is_in_block)(a, hc->data, hc->req_szB, hc->slop_szB) && hc->vname[0] != '\0') {
				
				LOG("Found addr 0x%lx in chunk thru iteration, offset %lu\n", a, a-hc->data);
				
				if (pname && s) {
					*pname = '\0';
					VG_(snprintf)(pname, s, "%s[%lu]", hc->vname, a-hc->data); // TODO: check all written
				}
				
				if ( pdetailedname && ds) {
					*pdetailedname = '\0';
					VG_(snprintf)(pdetailedname, ds, "%s[%lu]", hc->vdetailedname, a-hc->data); // TODO: check all written
				}
				
				ret = True;
				break;
			}
		}
	}
	
	return ret;
}


void TNT_(malloc_set_parent)(HP_Chunk *child, HP_Chunk *parent) {
	tl_assert (child && parent && parent->Alloc.master);
	// sanity checks, just in case: this should never happen coz it may create issues upon releasing
	tl_assert (child != parent);
	child->Alloc.parent = parent;
	parent->Alloc.hasChild = 1;
}

HP_Chunk * TNT_(malloc_get_parent_block)(Addr a, SizeT len) {
	
	HP_Chunk* hc = VG_(HT_lookup)( TNT_(malloc_list), (UWord)a );
	if (hc) {
		LOG("malloc_get_parent_block 0x%lx chunk found '%s'\n", a, hc->vname);
		return hc;
	} else {
		LOG("malloc_get_parent_block 0x%lx chunk NOT found, falling back to iteration\n", a);
		VG_(HT_ResetIter)(TNT_(malloc_list));
		while ( (hc = VG_(HT_Next)(TNT_(malloc_list))) ) {
			
			if ( !hc->Alloc.master ) { continue; } // not sure this is actually needed, since we're only looking at master blocks anyway...
			
			if ( VG_(addr_is_in_block)(a, hc->data, hc->req_szB, hc->slop_szB) && hc->vname[0] != '\0') {
				
				LOG("Found addr 0x%lx in chunk thru iteration, offset %lu\n", a, a-hc->data);
				// WARNING: for now assume the [addr, addr+len] does not overlap with multiple heap-allocated blocks
				// that is, the block is contained within the parent block completly
				tl_assert ( a <= (SizeT)(-1) - len ); // ensures no overflow
				tl_assert ( hc->data <= (SizeT)(-1) - hc->req_szB ); // ensures no overflow
				tl_assert ( a >= hc->data && a+len <= hc->data + hc->req_szB ); // Note: i dont account for the alignment space
				break;
			}
		}
	}
	
	tl_assert (hc && "hc NULL");
	
	return hc;
}

void TNT_(malloc_reset_iter)(void)
{
	VG_(HT_ResetIter)(TNT_(malloc_list));
}

HP_Chunk * TNT_(malloc_get_next_chunk)(void)
{
	return (HP_Chunk*) VG_(HT_Next)(TNT_(malloc_list));
}

Bool TNT_(malloc_is_heap)(Addr a)
{
	return VG_(addr_is_in_block)( a, g_heap_min, g_heap_max-g_heap_min+1, 0 );
}

// use this function because heap range may change and we want to keep track of the entire range
static __inline__
void update_heap_ranges(Addr a, SizeT len)
{		
	tl_assert ( sizeof(len) <= sizeof(a) );
	tl_assert ( a <= (Addr)(-1) - len );
	if (g_heap_max < a+len) {
		g_heap_max = a+len;
	}
	
	// update the low bound
	if ( g_heap_min > a) {
		g_heap_min = a;
	}
}
#endif

static __inline__
void* alloc_and_record_block ( ThreadId tid, SizeT req_szB, SizeT req_alignB,
                               Bool is_zeroed )
{
   SizeT actual_szB, slop_szB;
   void* p;
   
   #if _SECRETGRIND_
   LOG("alloc_and_record_block req_szB %lu alignment %lu\n", req_szB, req_alignB);
   #endif

   if ((SSizeT)req_szB < 0) return NULL;

   // Allocate and zero if necessary.
   p = VG_(cli_malloc)( req_alignB, req_szB );
   if (!p) {
      return NULL;
   }
   #if _SECRETGRIND_
   LOG("malloc returned 0x%lx\n", (Addr)p);
   #endif
   
   if (is_zeroed) VG_(memset)(p, 0, req_szB);
   actual_szB = VG_(malloc_usable_size)(p);
   tl_assert(actual_szB >= req_szB);
   slop_szB = actual_szB - req_szB;

   // Record block.
   record_block(tid, p, req_szB, slop_szB);
	
   return p;
}


static __inline__
void unrecord_block ( void* p )
{
#if _SECRETGRIND_
	
	// remove the old chunk
	Bool tainted = False;
	HP_Chunk* hc = VG_(HT_remove)(TNT_(malloc_list), (UWord)p);
	tl_assert (hc);
		
	// mark the block as free()'ed and free the allocated block
	hc->Alloc.release_trace = TNT_(retrieveExeContext)();
	VG_(cli_free)((void*)hc->data); // do not set hc->data = 0 as it contains an address we may want to read in the taint summary
	
	// warn if block is tainted.
	tainted = subblk_warn_if_tainted(hc, &TNT_(print_MallocExeContext), "free()'d", True);
	
	// remove taint if user asked to do so
	if ( TNT_(clo_taint_remove_on_release) ) {
		TNT_(make_mem_untainted)( (Addr)p, hc->req_szB + hc->slop_szB ); 
	}
	
	if ( !tainted || TNT_(clo_taint_remove_on_release) ) {
		
		// if not tainted, free the hc only if it has no children
		if ( hc->Alloc.hasChild ) {
			// add it to the free()'ed list that have children
			VG_(HT_add_node)(TNT_(freed_wchild_list), hc);
		} else {
			// Actually free the chunk as we no longer need it
			VG_(free)( hc );  hc = NULL;
		}
	} 
	
#else
	// Remove HP_Chunk from malloc_list
	HP_Chunk* hc = VG_(HT_remove)(TNT_(malloc_list), (UWord)p);
	if (NULL == hc) {
		return;   // must have been a bogus free()
	}
   
	// Untaint freed block
	TNT_(make_mem_untainted)( (Addr)p, hc->req_szB + hc->slop_szB ); 
		
	// Actually free the chunk, and the heap block (if necessary)
	VG_(free)( hc );  hc = NULL;

#endif 
}

#if _SECRETGRIND_
static __inline__
Bool is_block_tainted(HP_Chunk *hc) {
	
	Addr curr_addr = (Addr)hc->data, end_addr = hc->data+hc->req_szB +hc->slop_szB;
	while ( curr_addr < end_addr ) {
		if ( TNT_(is_mem_byte_tainted)(curr_addr) ) { return True; }
		++curr_addr;
	}
	return False;
}
#endif

static __inline__
void* realloc_block ( ThreadId tid, void* p_old, SizeT new_req_szB )
{
#if _SECRETGRIND_
	// let's make it simple
	// I dont want to re-use the original hc, because
	// in the taint summary, it may make things harder
	// to folow in a trace. That is, we could think the block
	// was tainted after being reallocated, wherease it is before...
	HP_Chunk* hc;
	void*     p_new;
	SizeT     old_req_szB, old_slop_szB, new_slop_szB, new_actual_szB;
	
	// lookup the old block from hashMap
	// i dont remove it rightaway, as i call unrecord_block
	// which takes care of printing warning and keeping the block
	// if it's tainted
	hc = VG_(HT_lookup)(TNT_(malloc_list), (UWord)p_old);
	tl_assert (hc);
	old_req_szB  = hc->req_szB;
	old_slop_szB = hc->slop_szB;
   
	// create new heap block
	p_new = VG_(cli_malloc)(VG_(clo_alignment), new_req_szB);
    tl_assert (p_new);
    
    // copy data from old to new block
    VG_(memcpy)(p_new, p_old, old_req_szB);
    new_actual_szB = VG_(malloc_usable_size)(p_new);
    tl_assert(new_actual_szB >= new_req_szB);
    new_slop_szB = new_actual_szB - new_req_szB;

	// untaint old block if necessary
	if ( TNT_(clo_taint_remove_on_release) ) {
		TNT_(make_mem_untainted)( (Addr)p_old, old_req_szB + old_slop_szB ); 
	}
	
    // copy taint state
    TNT_(copy_address_range_state)( (Addr)p_old, (Addr)p_new, new_actual_szB );
    
	// unrecord the old block
    unrecord_block(p_old);
    
    // record the new block
    record_block( tid, p_new, new_req_szB, new_slop_szB );
    
    // record a BRAND-NEW block and push it to the summary if it contains taint
    // WARNING: we cannot push the block we just created, we ALWAYS need a different one
    hc = VG_(HT_lookup)(TNT_(malloc_list), (UWord)p_new);
	tl_assert (hc);
	if ( is_block_tainted(hc) ) {
		TNT_(alloc_chunk_from_fn_and_add_sum_block)((Addr)p_new, new_req_szB, new_slop_szB, False, "store");
	}
    
    return p_new;
#else
   HP_Chunk* hc;
   void*     p_new;
   SizeT     old_req_szB, old_slop_szB, new_slop_szB, new_actual_szB;

   // Remove the old block
   hc = VG_(HT_remove)(TNT_(malloc_list), (UWord)p_old);
   if (hc == NULL) {
      return NULL;   // must have been a bogus realloc()
   }

   old_req_szB  = hc->req_szB;
   old_slop_szB = hc->slop_szB;

   // Actually do the allocation, if necessary.
   if (new_req_szB <= old_req_szB + old_slop_szB) {
      // New size is smaller or same;  block not moved.
      p_new = p_old;
      new_slop_szB = old_slop_szB + (old_req_szB - new_req_szB);

   } else {
      // New size is bigger;  make new block, copy shared contents, free old.
      p_new = VG_(cli_malloc)(VG_(clo_alignment), new_req_szB);
      if (!p_new) {
         // Nb: if realloc fails, NULL is returned but the old block is not
         // touched.  What an awful function.
         return NULL;
      }
      
      VG_(memcpy)(p_new, p_old, old_req_szB);

      VG_(cli_free)(p_old);
      new_actual_szB = VG_(malloc_usable_size)(p_new);
      tl_assert(new_actual_szB >= new_req_szB);
      new_slop_szB = new_actual_szB - new_req_szB;

      // Copy taint state
      TNT_(copy_address_range_state)( (Addr)p_old, (Addr)p_new, new_actual_szB );
      
#	if _SECRETGRIND_
	  if ( TNT_(clo_taint_remove_on_release) ) {
		TNT_(make_mem_untainted)( (Addr)p_old, old_req_szB + old_slop_szB ); 
	  }
#	endif
   }

   if (p_new) {
      // Update HP_Chunk.
      hc->data     = (Addr)p_new;
      hc->req_szB  = new_req_szB;
      hc->slop_szB = new_slop_szB;
   }
   
   // Now insert the new hc (with a possibly new 'data' field) into
   // malloc_list.  If this realloc() did not increase the memory size, we
   // will have removed and then re-added hc unnecessarily.  But that's ok
   // because shrinking a block with realloc() is (presumably) much rarer
   // than growing it, and this way simplifies the growing case.
   VG_(HT_add_node)(TNT_(malloc_list), hc);
   return p_new;
#endif
}


void* TNT_(malloc) ( ThreadId tid, SizeT szB )
{
   return alloc_and_record_block( tid, szB, VG_(clo_alignment), /*is_zeroed*/False );
}

void* TNT_(__builtin_new) ( ThreadId tid, SizeT szB )
{
   return alloc_and_record_block( tid, szB, VG_(clo_alignment), /*is_zeroed*/False );
}

void* TNT_(__builtin_vec_new) ( ThreadId tid, SizeT szB )
{
   return alloc_and_record_block( tid, szB, VG_(clo_alignment), /*is_zeroed*/False );
}

void* TNT_(calloc) ( ThreadId tid, SizeT m, SizeT szB )
{
   return alloc_and_record_block( tid, m*szB, VG_(clo_alignment), /*is_zeroed*/True );
}

void *TNT_(memalign) ( ThreadId tid, SizeT alignB, SizeT szB )
{
   return alloc_and_record_block( tid, szB, alignB, False );
}

void TNT_(free) ( ThreadId tid __attribute__((unused)), void* p )
{
   unrecord_block(p);
#if !_SECRETGRIND_ // done in unrecord_block if need be
   VG_(cli_free)(p);
#endif
}

void TNT_(__builtin_delete) ( ThreadId tid, void* p )
{
   unrecord_block(p);
#if !_SECRETGRIND_ // done in unrecord_block if need be
   VG_(cli_free)(p);
#endif
}

void TNT_(__builtin_vec_delete) ( ThreadId tid, void* p )
{
   unrecord_block(p);
#if !_SECRETGRIND_ // done in unrecord_block if need be
   VG_(cli_free)(p);
#endif
}

void* TNT_(realloc) ( ThreadId tid, void* p_old, SizeT new_szB )
{
   return realloc_block(tid, p_old, new_szB);
}

SizeT TNT_(malloc_usable_size) ( ThreadId tid, void* p )
{                                                            
   HP_Chunk* hc = VG_(HT_lookup)( TNT_(malloc_list), (UWord)p );

   return ( hc ? hc->req_szB + hc->slop_szB : 0 );
}

static
void* record_block( ThreadId tid, void* p, SizeT req_szB, SizeT slop_szB )
{
   // Make new HP_Chunk node, add to malloc_list
   HP_Chunk* hc  = 0;
   
#if _SECRETGRIND_
   
   LOG("record_block %p, req_szB:%lu, slop_szB:%lu\n", p, req_szB, slop_szB);
   update_heap_ranges((Addr)p, req_szB + slop_szB); // assume no overflow...

   // Note: initially I wanted to create chunks only if verbose sumary was requested
   //	    This turned out no possible because realloc requires the previous block's
   //		length to copy data and taint
   if ( /*TNT_(clo_summary_verbose)*/ True ) { 
	  
	   char vname[128], vdname[128];
	   
	   //if ( TNT_(clo_var_name) ) {
		
		//char objname[128];
		
		//TNT_(get_object_name)(objname, sizeof(objname));
		//VG_(snprintf)(vname, sizeof(vname), UNKNOWN_MALLOCED_OBJ_FMT, (Addr)p);
		//VG_(snprintf)(vdname, sizeof(vdname), UNKNOWN_MALLOCED_OBJ_FMT, (Addr)p);
	   
	    //TNT_(describe_data)((Addr)p, vname,sizeof(vname), vdname, sizeof(vdname), "", 0, False, True);
	   
	   //} else {
		   
		   // the problem is that the source-code pointer does not correspond to the malloc'ed mem region
		   // the address of the mem region is stored in the pointer. Unless we can firgure out the addr that receives
		   // the value, we cannot give the use a name for this malloc'ed region :(
		
		char objname[128];
		
		TNT_(get_object_name)(objname, sizeof(objname));
		VG_(snprintf)(vname, sizeof(vname), UNKNOWN_MALLOCED_OBJ_FMT, (Addr)p, VG_(getpid)(),  VG_(get_running_tid)());
		VG_(snprintf)(vdname, sizeof(vdname), UNKNOWN_MALLOCED_OBJ_FMT, (Addr)p, VG_(getpid)(),  VG_(get_running_tid)());
	  // }
	   
	   hc = TNT_(alloc_chunk_from_varnames_and_type)((Addr)p, req_szB, slop_szB, vname, vdname, SN_ADDR_HEAP_MALLOC, False);
	   hc->Alloc.master = 1;
   }
   
   // even if we're in batch mode, I still create a chunk to be able to test the validity of addresses
   if (hc)
#else
   
   hc = VG_(malloc)("ms.main.rb.1", sizeof(HP_Chunk));
   tl_assert ( hc && "hc NULL" );
   hc->req_szB  = req_szB;
   hc->slop_szB = slop_szB;
   hc->data     = (Addr)p;
   
#endif
   
   VG_(HT_add_node)(TNT_(malloc_list), hc);

#if !_SECRETGRIND_
   // Untaint malloc'd block
   TNT_(make_mem_untainted)( (Addr)p, hc->req_szB + hc->slop_szB ); 
#endif

   return p;
}
 

void TNT_(malloc_init)(void) {
	
	TNT_(malloc_list)  		= VG_(HT_construct)( "TNT_(malloc_list)" );
	TNT_(freed_wchild_list) = VG_(HT_construct)( "TNT_(freed_wchild_list)" );
}

void TNT_(malloc_release)(void) {
	
	// ======== malloc_list
	// first free all blocks allocated if they have not beed free()'ed yet
	// this may happen if the program under analysis leaks memory itself!
	VG_(HT_ResetIter)(TNT_(malloc_list));
	HP_Chunk *hp = 0;
	while ( (hp=VG_(HT_Next)(TNT_(malloc_list))) ) {
#if _SECRETGRIND_
		if (hp->Alloc.release_trace == 0) {
#endif // _SECRETGRIND_
			VG_(cli_free)((void*)hp->data);
			//hp->release_trace = 1; WARNING: this is executed upon exit()'ing valgrind, we don't need to set a value; even if we did it'd return an erroneous value of fail (i've tried :))
		}
#if _SECRETGRIND_
	}
#endif // _SECRETGRIND_

	// free the chunks
	VG_(HT_destruct)( TNT_(malloc_list), &VG_(free) ); // Note: most blocks have already been removed thru unrecord_block(), except those the user forgot to...
	
	// ========= freed_wchild_list
	// we do not nede to free the allocated blocks because we add only chunks that
	// have the block free()'ed to this list
	VG_(HT_destruct)( TNT_(freed_wchild_list), &VG_(free) ); // Note: most blocks have already been removed thru unrecord_block(), except those the user forgot to...
}

//--------------------------------------------------------------------//
//--- end                                                          ---//
//--------------------------------------------------------------------//
