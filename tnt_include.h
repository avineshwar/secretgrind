
/*--------------------------------------------------------------------*/
/*--- A header file for all parts of Taintgrind.                   ---*/
/*---                                                tnt_include.h ---*/
/*--------------------------------------------------------------------*/

/*
   This file is part of Taintgrind, a heavyweight Valgrind tool for
   taint analysis.

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

#ifndef __TNT_INCLUDE_H
#define __TNT_INCLUDE_H

#include "secretgrind.h"
#include "pub_tool_tooliface.h"	
#include "pub_tool_libcprint.h"

#define STACK_TRACE_SIZE 20

#define TNT_(str)    VGAPPEND(vgTaintgrind_,str)

#define LEN(x) (sizeof(x)/sizeof(x[0]))

/*------------------------------------------------------------*/
/*--- Profiling of memory events                           ---*/
/*------------------------------------------------------------*/

/* Define to collect detailed performance info. */
/* #define TNT_PROFILE_MEMORY */

#ifdef TNT_PROFILE_MEMORY
#  define N_PROF_EVENTS 500

UInt   TNT_(event_ctr)[N_PROF_EVENTS];
HChar* TNT_(event_ctr_name)[N_PROF_EVENTS];

#  define PROF_EVENT(ev, name)                                \
   do { tl_assert((ev) >= 0 && (ev) < N_PROF_EVENTS);         \
        /* crude and inaccurate check to ensure the same */   \
        /* event isn't being used with > 1 name */            \
        if (TNT_(event_ctr_name)[ev])                         \
           tl_assert(name == TNT_(event_ctr_name)[ev]);       \
        TNT_(event_ctr)[ev]++;                                \
        TNT_(event_ctr_name)[ev] = (name);                    \
   } while (False);

#else

#  define PROF_EVENT(ev, name) /* */

#endif   /* TNT_PROFILE_MEMORY */


/*------------------------------------------------------------*/
/*--- V and A bits (Victoria & Albert ?)                   ---*/
/*------------------------------------------------------------*/

/* The number of entries in the primary map can be altered.  However
   we hardwire the assumption that each secondary map covers precisely
   64k of address space. */
#define SM_SIZE 65536            /* DO NOT CHANGE */
#define SM_MASK (SM_SIZE-1)      /* DO NOT CHANGE */

#define V_BIT_UNTAINTED         0
#define V_BIT_TAINTED       1

#define V_BITS8_UNTAINTED       0
#define V_BITS8_TAINTED     0xFF

#define V_BITS16_UNTAINTED      0
#define V_BITS16_TAINTED    0xFFFF

#define V_BITS32_UNTAINTED      0
#define V_BITS32_TAINTED    0xFFFFFFFF

#define V_BITS64_UNTAINTED      0ULL
#define V_BITS64_TAINTED    0xFFFFFFFFFFFFFFFFULL


/*------------------------------------------------------------*/
/*--- Instrumentation                                      ---*/
/*------------------------------------------------------------*/

// Debug variable
//int tnt_read;

/* Functions/vars defined in tnt_main.c */
UChar get_vabits2( Addr a ); // Taintgrind: needed by TNT_(instrument)
void TNT_(make_mem_noaccess)( Addr a, SizeT len );
void TNT_(make_mem_tainted)( Addr a, SizeT len );
void TNT_(make_mem_untainted)( Addr a, SizeT len );

VG_REGPARM(3) void TNT_(h32_exit_t)   ( IRStmt *, UInt, UInt );
VG_REGPARM(3) void TNT_(h32_exit_c)   ( IRStmt *, UInt, UInt );
VG_REGPARM(3) void TNT_(h32_next_t)   ( IRExpr *, UInt, UInt );
VG_REGPARM(3) void TNT_(h32_next_c)   ( IRExpr *, UInt, UInt );
VG_REGPARM(3) void TNT_(h32_store_tt) ( IRStmt *, UInt, UInt );
#if _SECRETGRIND_
VG_REGPARM(3) void TNT_(h32_store_v128or256_tt) ( IRStmt *, ULong, ULong );
VG_REGPARM(3) void TNT_(h32_store_v128or256_ct) ( IRStmt *, ULong, ULong );
VG_REGPARM(3) void TNT_(h32_store_v128or256_tc) ( IRStmt *, ULong, ULong );
VG_REGPARM(2) void TNT_(h32_store_v128or256_prepare_tt) (IRStmt *, UChar); 
VG_REGPARM(2) void TNT_(h32_store_v128or256_prepare_ct) (IRStmt *, UChar);
VG_REGPARM(2) void TNT_(h32_store_v128or256_prepare_tc) (IRStmt *, UChar);
#endif
VG_REGPARM(3) void TNT_(h32_store_tc) ( IRStmt *, UInt, UInt );
VG_REGPARM(3) void TNT_(h32_store_ct) ( IRStmt *, UInt, UInt );
VG_REGPARM(3) void TNT_(h32_load_t)   ( IRStmt *, UInt, UInt );
#if _SECRETGRIND_
VG_REGPARM(3) void TNT_(h32_load_v128or256_t)   ( IRStmt *, UInt, UInt );
#endif
VG_REGPARM(3) void TNT_(h32_load_c)   ( IRStmt *, UInt, UInt );
VG_REGPARM(3) void TNT_(h32_get)      ( IRStmt *, UInt, UInt );
VG_REGPARM(3) void TNT_(h32_geti)     ( IRStmt *, UInt, UInt );
VG_REGPARM(3) void TNT_(h32_put_t)    ( IRStmt *, UInt, UInt );
VG_REGPARM(3) void TNT_(h32_put_c)    ( IRStmt *, UInt, UInt );
VG_REGPARM(3) void TNT_(h32_puti)     ( UInt, UInt, UInt, UInt );
VG_REGPARM(3) void TNT_(h32_wrtmp_c)  ( IRStmt *, UInt, UInt );
VG_REGPARM(3) void TNT_(h32_unop_t)   ( IRStmt *, UInt, UInt );
VG_REGPARM(3) void TNT_(h32_unop_c)   ( IRStmt *, UInt, UInt );
VG_REGPARM(3) void TNT_(h32_binop_tc) ( IRStmt *, UInt, UInt );
VG_REGPARM(3) void TNT_(h32_binop_ct) ( IRStmt *, UInt, UInt );
VG_REGPARM(3) void TNT_(h32_binop_tt) ( IRStmt *, UInt, UInt );
VG_REGPARM(3) void TNT_(h32_binop_cc) ( IRStmt *, UInt, UInt );
VG_REGPARM(3) void TNT_(h32_triop)    ( IRStmt *, UInt, UInt );
VG_REGPARM(3) void TNT_(h32_qop)      ( IRStmt *, UInt, UInt );
VG_REGPARM(3) void TNT_(h32_rdtmp)    ( IRStmt *, UInt, UInt );
VG_REGPARM(3) void TNT_(h32_ite_tc)   ( IRStmt *, UInt, UInt );
VG_REGPARM(3) void TNT_(h32_ite_ct)   ( IRStmt *, UInt, UInt );
VG_REGPARM(3) void TNT_(h32_ite_tt)   ( IRStmt *, UInt, UInt );
VG_REGPARM(3) void TNT_(h32_ite_cc)   ( IRStmt *, UInt, UInt );
VG_REGPARM(3) void TNT_(h32_ccall)    ( IRStmt *, UInt, UInt );
VG_REGPARM(3) void TNT_(h32_none)     ( HChar *, UInt, UInt );

VG_REGPARM(3) void TNT_(h64_exit_t)   ( IRStmt *, ULong, ULong );
VG_REGPARM(3) void TNT_(h64_exit_c)   ( IRStmt *, ULong, ULong );
VG_REGPARM(3) void TNT_(h64_next_t)   ( IRExpr *, ULong, ULong );
VG_REGPARM(3) void TNT_(h64_next_c)   ( IRExpr *, ULong, ULong );
VG_REGPARM(3) void TNT_(h64_store_tt) ( IRStmt *, ULong, ULong );
#if _SECRETGRIND_
VG_REGPARM(3) void TNT_(h64_store_v128or256_tt) ( IRStmt *, ULong, ULong );
VG_REGPARM(3) void TNT_(h64_store_v128or256_ct) ( IRStmt *, ULong, ULong );
VG_REGPARM(3) void TNT_(h64_store_v128or256_tc) ( IRStmt *, ULong, ULong );
VG_REGPARM(2) void TNT_(h64_store_v128or256_prepare_tt) (IRStmt *, UChar); 
VG_REGPARM(2) void TNT_(h64_store_v128or256_prepare_ct) (IRStmt *, UChar);
VG_REGPARM(2) void TNT_(h64_store_v128or256_prepare_tc) (IRStmt *, UChar);

#endif
VG_REGPARM(3) void TNT_(h64_store_tc) ( IRStmt *, ULong, ULong );
VG_REGPARM(3) void TNT_(h64_store_ct) ( IRStmt *, ULong, ULong );
VG_REGPARM(3) void TNT_(h64_load_c)   ( IRStmt *, ULong, ULong );
#if _SECRETGRIND_
VG_REGPARM(3) void TNT_(h64_load_v128or256_t)	( IRStmt *, ULong, ULong );
VG_REGPARM(1) void TNT_(hxx_imark_t) 			( IRStmt *);
#endif
VG_REGPARM(3) void TNT_(h64_load_t)   ( IRStmt *, ULong, ULong );
VG_REGPARM(3) void TNT_(h64_get)      ( IRStmt *, ULong, ULong );
VG_REGPARM(3) void TNT_(h64_geti)     ( IRStmt *, ULong, ULong );
VG_REGPARM(3) void TNT_(h64_put_t)    ( IRStmt *, ULong, ULong );
VG_REGPARM(3) void TNT_(h64_put_c)    ( IRStmt *, ULong, ULong );
VG_REGPARM(3) void TNT_(h64_puti)     ( ULong, ULong, ULong, ULong );
VG_REGPARM(3) void TNT_(h64_wrtmp_c)  ( IRStmt *, ULong, ULong );
VG_REGPARM(3) void TNT_(h64_unop_t)   ( IRStmt *, ULong, ULong );
VG_REGPARM(3) void TNT_(h64_unop_c)   ( IRStmt *, ULong, ULong );
VG_REGPARM(3) void TNT_(h64_binop_tc) ( IRStmt *, ULong, ULong );
VG_REGPARM(3) void TNT_(h64_binop_ct) ( IRStmt *, ULong, ULong );
VG_REGPARM(3) void TNT_(h64_binop_tt) ( IRStmt *, ULong, ULong );
VG_REGPARM(3) void TNT_(h64_binop_cc) ( IRStmt *, ULong, ULong );
VG_REGPARM(3) void TNT_(h64_triop)    ( IRStmt *, ULong, ULong );
VG_REGPARM(3) void TNT_(h64_qop)      ( IRStmt *, ULong, ULong );
VG_REGPARM(3) void TNT_(h64_rdtmp)    ( IRStmt *, ULong, ULong );
VG_REGPARM(3) void TNT_(h64_ite_tc)   ( IRStmt *, ULong, ULong );
VG_REGPARM(3) void TNT_(h64_ite_ct)   ( IRStmt *, ULong, ULong );
VG_REGPARM(3) void TNT_(h64_ite_tt)   ( IRStmt *, ULong, ULong );
VG_REGPARM(3) void TNT_(h64_ite_cc)   ( IRStmt *, ULong, ULong );
VG_REGPARM(3) void TNT_(h64_ccall)    ( IRStmt *, ULong, ULong );
VG_REGPARM(3) void TNT_(h64_none)     ( HChar *, ULong, ULong );

/* Strings used by tnt_translate, printed by tnt_main */
extern const char *IRType_string[];
extern const char *IREndness_string[];
extern const char *IRConst_string[];
extern const char *IROp_string[];
extern const char *IRExpr_string[];
extern const char *IRStmt_string[];
extern const char *IRJumpKind_string[];

/* Functions defined in tnt_translate, used by tnt_main */
extern Int extract_IRConst( IRConst* con );
extern ULong extract_IRConst64( IRConst* con );

/* V-bits load/store helpers */
VG_REGPARM(1) void TNT_(helperc_STOREV64be) ( Addr, ULong );
VG_REGPARM(1) void TNT_(helperc_STOREV64le) ( Addr, ULong );
VG_REGPARM(2) void TNT_(helperc_STOREV32be) ( Addr, UWord );
VG_REGPARM(2) void TNT_(helperc_STOREV32le) ( Addr, UWord );
VG_REGPARM(2) void TNT_(helperc_STOREV16be) ( Addr, UWord );
VG_REGPARM(2) void TNT_(helperc_STOREV16le) ( Addr, UWord );
VG_REGPARM(2) void TNT_(helperc_STOREV8)    ( Addr, UWord );

VG_REGPARM(2) void  TNT_(helperc_LOADV256be) ( /*OUT*/V256*, Addr );
VG_REGPARM(2) void  TNT_(helperc_LOADV256le) ( /*OUT*/V256*, Addr );
VG_REGPARM(2) void  TNT_(helperc_LOADV128be) ( /*OUT*/V128*, Addr );
VG_REGPARM(2) void  TNT_(helperc_LOADV128le) ( /*OUT*/V128*, Addr );
VG_REGPARM(1) ULong TNT_(helperc_LOADV64be)  ( Addr );
VG_REGPARM(1) ULong TNT_(helperc_LOADV64le)  ( Addr );
VG_REGPARM(1) UWord TNT_(helperc_LOADV32be)  ( Addr );
VG_REGPARM(1) UWord TNT_(helperc_LOADV32le)  ( Addr );
VG_REGPARM(1) UWord TNT_(helperc_LOADV16be)  ( Addr );
VG_REGPARM(1) UWord TNT_(helperc_LOADV16le)  ( Addr );
VG_REGPARM(1) UWord TNT_(helperc_LOADV8)     ( Addr );
#if _SECRETGRIND_
VG_REGPARM(1) UWord TNT_(helperc_LOADV8_extended) ( Addr a, UWord taint );
VG_REGPARM(1) UWord TNT_(helperc_LOADV16le_extended) ( Addr a, UWord taint );
VG_REGPARM(1) UWord TNT_(helperc_LOADV16be_extended) ( Addr a, UWord taint );
VG_REGPARM(1) UWord TNT_(helperc_LOADV32le_extended) ( Addr a, UWord taint );
VG_REGPARM(1) UWord TNT_(helperc_LOADV32be_extended) ( Addr a, UWord taint );
VG_REGPARM(1) ULong TNT_(helperc_LOADV64le_extended) ( Addr a, ULong taint );
VG_REGPARM(1) ULong TNT_(helperc_LOADV64be_extended) ( Addr a, ULong taint );
#endif
void TNT_(helperc_MAKE_STACK_UNINIT) ( Addr base, UWord len,
                                                 Addr nia );

/* Taintgrind args */
#define MAX_PATH 256

// Added by Laurent
#define max(x,y) ((x)>(y)?(x):(y))


#if !_SECRETGRIND_
	extern HChar  TNT_(clo_file_filter)[MAX_PATH];
#endif
extern Int    TNT_(clo_filetaint_start);
extern Int    TNT_(clo_filetaint_len);
extern Bool   TNT_(clo_taint_all);
extern Int    TNT_(clo_after_kbb);
extern Int    TNT_(clo_before_kbb);
extern Bool   TNT_(clo_trace_taint_only);
extern Bool   TNT_(clo_critical_ins_only);
extern Int    TNT_(do_print);

#define KRED "\e[31m"
#define KMAG "\e[35m"
#define KNRM "\e[0m"
#define KGRN "\e[32m"
#define KUDL "\e[4m"	// underlined


// see pub_tool_basic.h
#define STR(x) #x
#define UWORD_FMT(z)	STR(l ## z)
#define	ADDR_FMT(z)		UWORD_FMT(z)
#define	SIZE_FMT(z)		UWORD_FMT(l ## z)
#define	UCHAR_FMT(z)	STR(z)
#define ULONG_FMT(z)	STR(ll ## z)

/* Functions defined in malloc_wrappers.c */
#define TNT_MALLOC_REDZONE_SZB    16

#if 0
/* For malloc()/new/new[] vs. free()/delete/delete[] mismatch checking. */
typedef
   enum {
      TNT_AllocMalloc = 0,
      TNT_AllocNew    = 1,
      TNT_AllocNewVec = 2,
      TNT_AllocCustom = 3
   }
   TNT_AllocKind;
#endif

#if _SECRETGRIND_
typedef
	enum {
		SN_ADDR_UNKNOWN = 0, // DO NOT CHANGE THESE VALUES OR THEIR ORDERS -- i use them as index to arrays and assume this order
		SN_ADDR_GLOBAL,
		SN_ADDR_HEAP_MALLOC,
		SN_ADDR_MMAP_FILE,	// mmap a file
		SN_ADDR_MMAP,		// mmap which is not a file
		SN_ADDR_STACK,
		SN_ADDR_OTHER
	} 
	sn_addr_type_t;
	
	
#endif

/* This describes a heap block. Nb: first two fields must match core's
 * VgHashNode. */
#if _SECRETGRIND_

// the maximum number of frames in a stack we want can record
#	define MAX_STACK_FRAME		50
#	define MAX_STACK_DESC_LEN	2048
#	define MAX_FIX_IDS			10
#	define MAX_FILE_FILTER		16

typedef long ID_t;
typedef 
	struct {
		char	mnemonics[32];
		Addr	addr;
		HChar	len;
		ID_t	ID;
		ExeContext *ec; // this is only filled when requested by user, because sometimes valgrind fails to give the fill stack trace after imark
	}
	Inst_t; 
#endif
typedef
   struct _HP_Chunk {
      struct _HP_Chunk* next;		// this is necessary for valgrind hashmap implementation: do not touch
      Addr         data;            // Address of the actual block.
      SizeT        req_szB;         // Size requested
      SizeT        slop_szB;        // Extra bytes given above those requested
#if _SECRETGRIND_
      ExeContext *stack_trace;		// note: there does not seem to be a function to free this afters
									// the content of this trace depends on mem type. It can be the taint trace, the malloc/mmap trace
      sn_addr_type_t addrType;
      char		  vname[256];
      char		  vdetailedname[1024];
      Inst_t 	  inst;
      
      unsigned int		api :1;			// this indicates that the block was tainted as the result of a call to TNT_MAKE_TAINTED()
            
      // this is for blocks that are allocated, ie malloc()'ed, mmap()'ed, etc
      // only valid for heap/file-mmap blocks at the moment:TODO for mmap
      struct {
		struct _HP_Chunk *parent;			// for heap/file-mmap block, this contain its "parent" block
		unsigned int		hasChild : 1;  	// for heap/file-mmap block, this indicates if it has a child pointing to it; and we should not free it
											// TODO: replace hasCHild with a linked list of blocks so that we can list all taint on non-free()'ed blocks
		unsigned int		master : 1;		// for heap/file-mmap blocks, this indicates it's a "master block" in the sense that it was mmap()'ed/malloc()'ed
		ExeContext *		release_trace;	// for heap/file-mmap blocks, contains the trace when the block was free()'ed/mumap()'ed. 0 means the block was not free()'ed
	  }Alloc;
      
#endif
   }
   HP_Chunk;
#if 0
/* Memory pool.  Nb: first two fields must match core's VgHashNode. */
typedef
   struct _TNT_Mempool {
      struct _TNT_Mempool* next;
      Addr          pool;           // pool identifier
      SizeT         rzB;            // pool red-zone size
      Bool          is_zeroed;      // allocations from this pool are zeroed
      VgHashTable   chunks;         // chunks associated with this pool
   }
   TNT_Mempool;


void* TNT_(new_block)  ( ThreadId tid,
                        Addr p, SizeT size, SizeT align,
                        Bool is_zeroed, TNT_AllocKind kind,
                        VgHashTable table);
void TNT_(handle_free) ( ThreadId tid,
                        Addr p, UInt rzB, TNT_AllocKind kind );

void TNT_(create_mempool)  ( Addr pool, UInt rzB, Bool is_zeroed );
void TNT_(destroy_mempool) ( Addr pool );
void TNT_(mempool_alloc)   ( ThreadId tid, Addr pool,
                            Addr addr, SizeT size );
void TNT_(mempool_free)    ( Addr pool, Addr addr );
void TNT_(mempool_trim)    ( Addr pool, Addr addr, SizeT size );
void TNT_(move_mempool)    ( Addr poolA, Addr poolB );
void TNT_(mempool_change)  ( Addr pool, Addr addrA, Addr addrB, SizeT size );
Bool TNT_(mempool_exists)  ( Addr pool );

TNT_Chunk* TNT_(get_freed_list_head)( void );
#endif

extern void TNT_(stop_print)(void);
extern void TNT_(start_print)(Bool all);

#if _SECRETGRIND_
#define RAW_ADDR_FMT "0x%lx"
extern Bool TNT_(is_mem_byte_tainted)(Addr a);
extern ExeContext * TNT_(retrieveExeContext)(void);
extern Bool TNT_(clo_verbose);
extern Bool TNT_(clo_mnemonics);
extern Bool TNT_(clo_taint_warn_on_release);
extern Bool TNT_(clo_taint_show_source);
extern Bool TNT_(clo_trace);
extern SizeT TNT_(clo_mmap_pagesize);
extern Bool TNT_(clo_summary_total_only);
extern Inst_t TNT_(current_inst);
extern Bool TNT_(clo_taint_stdin);
extern ID_t TNT_(clo_list_inst_IDs)[MAX_FIX_IDS];
extern Bool TNT_(inst_need_fix)(long ID);
extern Bool TNT_(mnemoReady);
extern Bool TNT_(clo_taint_df_only);
extern Bool TNT_(clo_taint_remove_on_release);
extern Bool TNT_(clo_batchmode);
extern Bool TNT_(clo_summary);
extern Bool TNT_(clo_summary_verbose);
extern Bool TNT_(clo_summary_exit_only);
extern Bool TNT_(clo_summary_main_only);
extern Bool TNT_(clo_summary_total_only);
extern Bool TNT_(clo_var_name);
extern const char * TNT_(addr_type_to_string)(sn_addr_type_t type);
extern sn_addr_type_t TNT_(get_addr_type)(Addr a);
extern void TNT_(get_object_name)(char *objname, SizeT n);
extern void TNT_(record_receive_taint_for_addr)(Addr addr, SizeT len, Bool api, const char *srcname);
extern void TNT_(display_receive_taint_for_addr)(Addr addr, SizeT len, const char *addrInfo, const char *srcname);
extern IRType TNT_(getTypeOfIRExpr)(IRExpr* e);
extern void TNT_(record_StackTrace)( char *out, SizeT size, SizeT max_n_ips, const char *msg );
extern Bool TNT_(isPowerOfTwo)(SizeT x);
extern Bool TNT_(taint_file_params_are_default)(void);


#define EMIT_ERROR(...) 	do { VG_(printf)(KRED); VG_(printf)(__VA_ARGS__); VG_(printf)(KNRM); }while(0)
#define EMIT_INFO(...) 		do { VG_(printf)(KMAG); VG_(printf)(__VA_ARGS__); VG_(printf)(KNRM); }while(0)
#define EMIT_SUCCESS(...)	do { VG_(printf)(KGRN); VG_(printf)(__VA_ARGS__); VG_(printf)(KNRM); }while(0)

#endif // _SECRETGRIND_

// some debug utility functions. Also useful for taintgrind
#define LOG(...)    			do { /*VG_(printf)(__VA_ARGS__);*/ }while(0)
								
#define LOG_MEM(PTR)    		do { LOG("%s -> [0x%lx]\n", #PTR, (long)PTR); }while(0)

#define LOG_ENTER()     		do { LOG("ENTER \"%s\"\n", __PRETTY_FUNCTION__); }while(0)

#define LOG_EXIT()     			do { LOG("EXIT \"%s\"\n", __PRETTY_FUNCTION__); }while(0)

#define LOG_CALL(EXP)   		do { LOG("CALLING \"%s\"\n", #EXP); EXP; LOG("CALL to \"%s\" OK.\n", #EXP); }while(0)

#define LOG_TRACE()				LOG_ENTER()


/* For tracking memory pools. */
//extern VgHashTable TNT_(mempool_list);

/* Shadow memory functions */
Bool TNT_(check_mem_is_noaccess)( Addr a, SizeT len, Addr* bad_addr );
void TNT_(make_mem_noaccess)        ( Addr a, SizeT len );
void TNT_(make_mem_undefined_w_otag)( Addr a, SizeT len, UInt otag );
void TNT_(make_mem_defined)         ( Addr a, SizeT len );
void TNT_(copy_address_range_state) ( Addr src, Addr dst, SizeT len );

void TNT_(print_malloc_stats) ( void );

void* TNT_(malloc)               ( ThreadId tid, SizeT n );
void* TNT_(__builtin_new)        ( ThreadId tid, SizeT n );
void* TNT_(__builtin_vec_new)    ( ThreadId tid, SizeT n );
void* TNT_(memalign)             ( ThreadId tid, SizeT align, SizeT n );
void* TNT_(calloc)               ( ThreadId tid, SizeT nmemb, SizeT size1 );
void  TNT_(free)                 ( ThreadId tid, void* p );
void  TNT_(__builtin_delete)     ( ThreadId tid, void* p );
void  TNT_(__builtin_vec_delete) ( ThreadId tid, void* p );
void* TNT_(realloc)              ( ThreadId tid, void* p, SizeT new_size );
SizeT TNT_(malloc_usable_size)   ( ThreadId tid, void* p );


/* Functions defined in tnt_syswrap.c */
/* System call wrappers */
extern void TNT_(syscall_read)(ThreadId tid, UWord* args, UInt nArgs, SysRes res);
extern void TNT_(syscall_write)(ThreadId tid, UWord* args, UInt nArgs, SysRes res);
extern void TNT_(syscall_open)(ThreadId tid, UWord* args, UInt nArgs, SysRes res);
extern void TNT_(syscall_close)(ThreadId tid, UWord* args, UInt nArgs, SysRes res);
extern void TNT_(syscall_llseek)(ThreadId tid, UWord* args, UInt nArgs, SysRes res);
extern void TNT_(syscall_lseek)(ThreadId tid, UWord* args, UInt nArgs, SysRes res);
extern void TNT_(syscall_pread)(ThreadId tid, UWord* args, UInt nArgs, SysRes res);
extern Bool TNT_(syscall_allowed_check)(ThreadId tid, int syscallno);
extern void TNT_(syscall_recv)(ThreadId tid, UWord* args, UInt nArgs, SysRes res);
extern void TNT_(syscall_recvfrom)(ThreadId tid, UWord* args, UInt nArgs, SysRes res);


/* Functions defined in tnt_translate.c */
IRSB* TNT_(instrument)( VgCallbackClosure* closure,
                        IRSB* bb_in,
                        VexGuestLayout* layout,
                        VexGuestExtents* vge,
                        VexArchInfo* vai,
                        IRType gWordTy, IRType hWordTy );


/* Client request handler */
extern Bool TNT_(handle_client_requests) ( ThreadId tid, UWord* arg, UWord* ret );

/* SOAAP-related data */
extern HChar* client_binary_name;
#define FNNAME_MAX 100

extern UInt persistent_sandbox_nesting_depth;
extern UInt ephemeral_sandbox_nesting_depth;
extern Bool have_created_sandbox;

#define FD_MAX 256
#define FD_MAX_PATH 256
#define FD_READ 0x1
#define FD_WRITE 0x2
#define FD_STAT 0x4

extern UInt shared_fds[];

#define VAR_MAX 100
#define VAR_READ 0x1
#define VAR_WRITE 0x2

enum VariableType { Local = 3, Global = 4 };
enum VariableLocation { GlobalFromApplication = 5, GlobalFromElsewhere = 6 };

extern struct myStringArray shared_vars;
extern UInt shared_vars_perms[];
extern HChar* next_shared_variable_to_update;

#define IN_SANDBOX (persistent_sandbox_nesting_depth > 0 || ephemeral_sandbox_nesting_depth > 0)

#define FD_SET_PERMISSION(fd,perm) shared_fds[fd] |= perm
#define VAR_SET_PERMISSION(var_idx,perm) shared_vars_perms[var_idx] |= perm

#define SYSCALLS_MAX 500
extern Bool allowed_syscalls[];
#define IS_SYSCALL_ALLOWED(no) (allowed_syscalls[no] == True)

extern UInt callgate_nesting_depth;
#define IN_CALLGATE (nested_callgate_depth > 0)

/* System call array */
extern const char* syscallnames[];

/* Utility functions */
#if _SECRETGRIND_
extern void TNT_(print_CurrentStackTrace) ( ThreadId tid, UInt max_n_ips, const char *msg );
extern void TNT_(print_MallocExeContext)( ExeContext* ec, UInt n_ips );
extern void TNT_(print_FreeParentExeContext)( ExeContext* ec, UInt n_ips );
extern void TNT_(print_MunmapParentExeContext)( ExeContext* ec, UInt n_ips );
extern void TNT_(print_MallocParentExeContext)( ExeContext* ec, UInt n_ips );
extern void TNT_(print_MmapParentExeContext)( ExeContext* ec, UInt n_ips );
extern void TNT_(print_MmapExeContext)( ExeContext* ec, UInt n_ips );
extern void TNT_(display_mem_region_of)(Addr a, SizeT len);
extern void TNT_(describe_data)(Addr addr, HChar* varnamebuf, SizeT bufsize, HChar* detailedvarnamebuf, SizeT detailedbufsize, const char *fn, SizeT len, Bool api);
extern HP_Chunk * TNT_(alloc_chunk_from_varnames)(Addr a, SizeT reqLen, SizeT slopLen, const char *name, const char *dname);
extern HP_Chunk * TNT_(alloc_chunk_from_varnames_and_type)(Addr a, SizeT reqLen, SizeT slopLen, const char *name, const char *dname, sn_addr_type_t type, Bool api);
extern void TNT_(alloc_chunk_from_fn_and_add_sum_block)(Addr a, SizeT reqLen, SizeT slopLen, Bool api, const char *fn);
#else
extern void TNT_(describe_data)(Addr addr, HChar* varnamebuf, UInt bufsize, enum VariableType* type, enum VariableLocation* loc);
#endif // _SECRETGRIND_
extern void TNT_(get_fnname)(ThreadId tid, HChar* buf, UInt buf_size);
extern void TNT_(check_fd_access)(ThreadId tid, UInt fd, Int fd_request);
extern void TNT_(check_var_access)(ThreadId tid, HChar* varname, Int var_request, enum VariableType type, enum VariableLocation var_loc);

#endif /* ndef __TNT_INCLUDE_H */

/*--------------------------------------------------------------------*/
/*--- end                                                          ---*/
/*--------------------------------------------------------------------*/
