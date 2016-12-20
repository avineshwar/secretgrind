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

#include "tnt_include.h"
#include "tnt_summary_names.h"

#if _SECRETGRIND_

/* --------------- linked list ----------------- */
typedef HP_Chunk * val_t;
	
typedef
	struct __list_el {
		val_t val;
		struct __list_el * next;
	}
	item;

// 3 different lists, one for each type of mem region
static item *g_heap_malloc_head=NULL, *g_heap_malloc_tail=NULL, *g_heap_curr_it=NULL;
static item *g_other_head=NULL, *g_other_tail=NULL, *g_other_curr_it=NULL;
static item *g_stack_head=NULL, *g_stack_tail=NULL, *g_stack_curr_it=NULL;
static item *g_global_head=NULL, *g_global_tail=NULL, *g_global_curr_it=NULL;
static item *g_mmap_file_head=NULL, *g_mmap_file_tail=NULL, *g_mmap_file_curr_it=NULL;
static item *g_mmap_head=NULL, *g_mmap_tail=NULL, *g_mmap_curr_it=NULL;

static item * insert_head(item *curr, val_t val) {
	
	if (curr) {
		item *head = VG_(malloc)("head", (sizeof(item)));
		if ( head ) {
			head->val = val;
			head->next = curr;
		}
		return head;
	}
	return NULL;
}
/*
static item * insert_tail(item * curr, val_t val) {
	
	if ( curr ) {
		item * tail = VG_(malloc)(VG_(clo_alignment), (sizeof(item)));
		if ( tail ) {
			tail->next = NULL;
			tail->val = val;
			curr->next = tail;
		}
		return tail;
	}
	return NULL;
}
*/
static item * init(val_t val) {
	item * head = VG_(malloc)("head", (sizeof(item)));
	if ( head ) {
		head->next = NULL;
		head->val = val;
	}
	return head;
}

static void free_item( item * it ) {
	
	if ( it ) {
	
		// release the chunk
		if ( it->val ) {
			VG_(free)(it->val);
		}
		
		// release the item
		VG_(free)(it); // note: there does not seem to be a function to free the ExeContext of the HP_Chunk...
	}
}

static void release(item *head) {
	while (head) {
		item *tmp = head->next;
		
		// Note: no need to free the address block from malloc because blocks added to the summary
		// NEVER have their blocks allocated directly, ie they only contain
		// the address value. It is malloc module that is in charge of free()'ing the actual mem blocks
		// release the chunk
		//if ( head->val ) {
		//	VG_(free)(head->val);
		//}
		// release the item
		//VG_(free)(head); // note: there does not seem to be a function to free the ExeContext of the HP_Chunk...
		free_item( head );
		head = tmp;
	}
}

/* --------------- names to keep for the summary ----------------- */

static item ** sum_get_phead(sn_addr_type_t type) {
	if ( type == SN_ADDR_HEAP_MALLOC ) { return &g_heap_malloc_head; }
	if ( type == SN_ADDR_MMAP_FILE ) { return &g_mmap_file_head; }
	if ( type == SN_ADDR_MMAP ) { return &g_mmap_head; }
	if ( type == SN_ADDR_OTHER ) { return &g_other_head; }
	if ( type == SN_ADDR_STACK ) { return &g_stack_head; }
	if ( type == SN_ADDR_GLOBAL ) { return &g_global_head; }
	tl_assert ( 0 && "invalid type" );
}

static item ** sum_get_ptail(sn_addr_type_t type) {
	if ( type == SN_ADDR_HEAP_MALLOC ) { return &g_heap_malloc_tail; }
	if ( type == SN_ADDR_MMAP_FILE ) { return &g_mmap_file_tail; }
	if ( type == SN_ADDR_MMAP ) { return &g_mmap_tail; }
	if ( type == SN_ADDR_OTHER ) { return &g_other_tail; }
	if ( type == SN_ADDR_STACK ) { return &g_stack_tail; }
	if ( type == SN_ADDR_GLOBAL ) { return &g_global_tail; }
	tl_assert ( 0 && "invalid type" );
}

static item ** sum_get_piter(sn_addr_type_t type) {
	if ( type == SN_ADDR_HEAP_MALLOC ) { return &g_heap_curr_it; }
	if ( type == SN_ADDR_MMAP_FILE ) { return &g_mmap_file_curr_it; }
	if ( type == SN_ADDR_MMAP ) { return &g_mmap_curr_it; }
	if ( type == SN_ADDR_OTHER ) { return &g_other_curr_it; }
	if ( type == SN_ADDR_STACK ) { return &g_stack_curr_it; }
	if ( type == SN_ADDR_GLOBAL ) { return &g_global_curr_it; }
	tl_assert ( 0 && "invalid type" );
}

void TNT_(sum_names_reset_iter)(sn_addr_type_t type) {
	
	item ** pit = sum_get_piter(type); // never NULL
	item ** phead = sum_get_phead(type); // never NULL
	(*pit) = (*phead);
}


HP_Chunk * TNT_(sum_names_get_next_chunk)(sn_addr_type_t type) {
	
	item ** pit = sum_get_piter(type); // never NULL
	if ((*pit)) {
		HP_Chunk * hc = (*pit)->val;
		(*pit) = (*pit)->next;
		return hc;
	} 
	return NULL;
}

void TNT_(sum_delete_block)(HP_Chunk *hc) {

	tl_assert (hc && "hc is NULL");
	
	LOG_ENTER();
	
	item ** phead = sum_get_phead(hc->addrType); // never NULL
	item * prev = NULL;
	
	// restart the iterator
	TNT_(sum_names_reset_iter)(hc->addrType);
	
	// get the iterator
	item ** pit = sum_get_piter(hc->addrType); // never NULL
	
	while ((*pit)) {
		
		HP_Chunk * curr = (*pit)->val;
		LOG("hc: 0x%lx, curr:0x%lx, curr->addr:0x%lx, length:%u\n", hc, curr, curr->data, curr->req_szB);
		
		if ( curr == hc ) {
			
			// we found the block to release - in fact we should also release all blocks that have it as parent:TODO
			if ( prev ) {
				prev->next = (*pit)->next;
			} else {
				// no previous block. In this case, we're the head
				tl_assert ((*phead) == (*pit) && "unexpected head");
				(*phead) = (*pit)->next; // this may be null
			}
			
			// now erase the item and block
			free_item( (*pit) );
			hc = NULL;	
			
			break;
		}
		
		// record the prev
		prev = (*pit);
		
		// move forward to next item
		(*pit) = (*pit)->next;
		
	}
	
	tl_assert ( hc == NULL && "Could not find the block to delete" );
	LOG_EXIT();
}

void TNT_(sum_add_block)(HP_Chunk *hc) {
	tl_assert (hc && "hc is NULL");
	
	LOG_ENTER();
	
	//tl_assert ("type != hc->addrType" && type == hc->addrType);
	
	item ** phead = sum_get_phead(hc->addrType); // never NULL
	item ** ptail = sum_get_ptail(hc->addrType); // never NULL
	
	if (!(*phead)) {
		(*phead) = init(hc);
		(*ptail) = (*phead);
		tl_assert ((*phead) && "g_head is NULL");
	} else {
		(*phead) = insert_head((*phead), hc);
	}
	LOG_EXIT();
}

void TNT_(sum_names_init)(void) {
	// nothing to do for now
}

void TNT_(sum_names_release)(void) {
	release(g_heap_malloc_head);
	g_heap_malloc_head = g_heap_malloc_tail = NULL;
	
	release(g_mmap_file_head);
	g_mmap_file_head = g_mmap_file_tail = NULL;
	
	release(g_mmap_head);
	g_mmap_head = g_mmap_tail = NULL;
	
	release(g_other_head);
	g_other_head = g_other_tail = NULL;
	
	release(g_stack_head);
	g_stack_head = g_stack_tail = NULL;
	
	release(g_global_head);
	g_global_head = g_global_tail = NULL;
}

#endif // _SECRETGRIND_
