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
#include "tnt_mmap.h"

#if _SECRETGRIND_

/* --------------- linked list ----------------- */
typedef 
	struct {
		Addr addr;
		SizeT len;
	} 
	val_t;
	
typedef
	struct __list_el {
		val_t * val;
		struct __list_el * next;
	}
	item;

static item *g_mmap_head=NULL, *g_mmap_tail=NULL;

/* --------------------- private function ----------------------- */
static item * insert_head(item *curr, val_t * val) {
	
	if (curr) {
		item *head = VG_(malloc)("mmap", (sizeof(item)));
		if ( head ) {
			head->val = val;
			head->next = curr;
		}
		return head;
	}
	return NULL;
}

static item * insert_tail(item * curr, val_t * val) {
	
	if ( curr ) {
		item * tail = VG_(malloc)("mmap", (sizeof(item)));
		if ( tail ) {
			tail->next = NULL;
			tail->val = val;
			curr->next = tail;
		}
		return tail;
	}
	return NULL;
}

static item * init(val_t * val) {
	item * head = VG_(malloc)("mmap", (sizeof(item)));
	if ( head ) {
		head->next = NULL;
		head->val = val;
	}
	return head;
}

static void release(item *head) {
	while (head) {
		item *tmp = head->next;
		VG_(free)(head->val);
		VG_(free)(head);
		head = tmp;
	}
}

static item ** get_phead(void) {
	return &g_mmap_head;
}

static item ** get_ptail(void) {
	return &g_mmap_tail;
}

static val_t * new_val(Addr addr, SizeT len) {
	val_t * pval = VG_(malloc)("val", (sizeof(val_t)));
	tl_assert (pval);
	
	pval->addr = addr;
	pval->len = len;
	
	return pval;
}


/* ------------------------- public functions -------------------------- */

void TNT_(mmap_init)(void) {
	// nothing to do for now
}

void TNT_(mmap_release)(void) {
	release(g_mmap_head);
	g_mmap_head = g_mmap_tail = NULL;
}

Bool TNT_(mmap_is_region)(Addr a) {
	item *head = g_mmap_head;
	while (head) {
		if ( VG_(addr_is_in_block)( a, head->val->addr, head->val->len, 0 ) ) { return True; }
		head = head->next;
	}
	return False;
}

void TNT_(mmap_add_region)(Addr a, SizeT len) {
	
	item ** phead = get_phead(); 	// never NULL
	item ** ptail = get_ptail(); 	// never NULL
	val_t * val = new_val(a, len);	// never NULL
		
	if (!(*phead)) {
		(*phead) = init(val);
		(*ptail) = (*phead);
		tl_assert ((*phead) && "phead is NULL");
	} else {
		(*ptail) = insert_tail((*ptail), val);
	}
	
}

#endif // _SECRETGRIND_
