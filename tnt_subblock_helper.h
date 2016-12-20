#ifndef TNT_SUBBLOCK_HELPER_H
#define TNT_SUBBLOCK_HELPER_H

#if _SECRETGRIND_

/*
 * these are function used by malloc and mmap files to display
 * sub block of tainted malloc'ed/mmap'ed regions to user
*/

typedef
	struct tainted_blk_lst {
		Addr addr;
		SizeT len;
		struct tainted_blk_lst * next;
	}
	tainted_blk;


static __inline__ 
tainted_blk * subblk_is_tainted(HP_Chunk *hc) {
	tl_assert (hc);
	
	// for simplicity, i do it byte by byte. This is slow... TODO: improve this
	Addr curr_addr = (Addr)hc->data, end_addr = hc->data+hc->req_szB/* +hc->slop_szB*/;
	tainted_blk *tail = NULL, *head = NULL, *curr_blk = NULL;
	Bool taint = False;
	
	unsigned tot = 0;
	while ( curr_addr < end_addr ) {
						
		while ( curr_addr < end_addr && (taint = TNT_(is_mem_byte_tainted)(curr_addr)) == True ) {
			
			if ( UNLIKELY( !curr_blk ) ) {
				curr_blk = VG_(malloc)("tnt.curr_blk.rb.1", sizeof(tainted_blk));
				tl_assert (curr_blk && "curr_blk NULL");
				curr_blk->addr = curr_addr;
				curr_blk->len = 1;
				curr_blk->next = NULL;
			} else {
				++curr_blk->len;
			}
			
			++curr_addr;
		}
		
		// no taint here, record the blk if we got some tainted region 
		if ( curr_blk ) {
			
			if ( UNLIKELY(!head) ) { head = curr_blk; }
			if ( LIKELY(tail) ) { tail->next = curr_blk; }
			tail = curr_blk;
			curr_blk = NULL;
			++tot;
		}
		
		++curr_addr;
	}
	
	return head;
}


static __inline__
Bool inner_subblk_warn_if_tainted(HP_Chunk *hc, void (*print_exe_context)( ExeContext* ec, UInt n_ips ), const char *msg, Bool addToSummary)
{
	// check if any of the bytes in this block are tainted
	Bool tainted = False;
	tainted_blk * pblk = subblk_is_tainted(hc);
	if (pblk) {
		tainted = True;
		EMIT_ERROR("\nBlock [0x%lx - 0x%lx] (%s, %lu bytes) is %s\n", (Addr)hc->data, (Addr)hc->data+hc->req_szB-1, hc->vdetailedname, hc->req_szB, msg);
		tl_assert ( hc->stack_trace );
		(*print_exe_context)( hc->stack_trace, VG_(get_ExeContext_n_ips)(hc->stack_trace) );
		EMIT_INFO("        ---\n");
		TNT_(print_CurrentStackTrace) ( VG_(get_running_tid)(), 20, msg );
		EMIT_INFO("\n");
		
		// WARNING: i've removed this line below now as we no longer add the parent malloc()'ed block to summary
		// instead I use the block containing the taint instruction and set the parent
		//if ( TNT_(clo_summary_verbose) && addToSummary) { TNT_(sum_add_block)(hc/*, hc->addrType*/); }
		
		while (pblk) {
			// read it
			EMIT_INFO("   > Tainted region [0x%lx - 0x%lx] (%lu bytes) -- indexes:[%lu - %lu]\n", pblk->addr, pblk->addr+pblk->len-1, 
							pblk->len, pblk->addr-hc->data, pblk->addr+pblk->len-hc->data-1);
			tainted_blk *tmp = pblk->next;
			VG_(free)(pblk); // delete the blk after processing
			pblk = tmp;	// next blk
		}
		EMIT_ERROR("\n");
	}
	return tainted;
}

static __inline__
Bool subblk_warn_if_tainted(HP_Chunk *hc, void (*print_exe_context)( ExeContext* ec, UInt n_ips ), const char *msg, Bool addToSummary)
{
	// WARNING: addToSummary no longer relevant; it's ignored now
	if ( UNLIKELY( TNT_(clo_taint_warn_on_release) ) ) {
		return inner_subblk_warn_if_tainted(hc, print_exe_context, msg, addToSummary);
	} else {
		// just check byte by byte (slow):TODO: improve it
		Addr curr_addr = (Addr)hc->data, end_addr = hc->data+hc->req_szB/* +hc->slop_szB*/;
		while ( curr_addr < end_addr ) {
			if ( TNT_(is_mem_byte_tainted)(curr_addr) ) { return True; }
			++curr_addr;
		}
		return False;
	}
}

#endif // _SECRETGRIND_

#endif // TNT_SUBBLOCK_HELPER_H
