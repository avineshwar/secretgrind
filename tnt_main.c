
/*--------------------------------------------------------------------*/
/*--- Taintgrind: The taint analysis Valgrind tool.        tnt_main.c ---*/
/*--------------------------------------------------------------------*/

/*
   This file is part of Taintgrind, the taint analysis Valgrind tool.

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

#include "pub_tool_basics.h"
#include "pub_tool_tooliface.h"

#include "pub_tool_vki.h"           // keeps libcproc.h happy, syscall nums
#include "pub_tool_aspacemgr.h"     // VG_(am_shadow_alloc)
#include "pub_tool_debuginfo.h"     // VG_(get_fnname_w_offset), VG_(get_fnname)
#include "pub_tool_hashtable.h"     // For tnt_include.h, VgHashtable
#include "pub_tool_libcassert.h"    // tl_assert
#include "pub_tool_libcbase.h"      // VG_STREQN
#include "pub_tool_libcprint.h"     // VG_(message)
#include "pub_tool_libcproc.h"      // VG_(getenv)
#include "pub_tool_replacemalloc.h" // VG_(replacement_malloc_process_cmd_line_option)
#include "pub_tool_machine.h"       // VG_(get_IP)
#include "pub_tool_mallocfree.h"    // VG_(out_of_memory_NORETURN)
#include "pub_tool_options.h"       // VG_STR/BHEX/BINT_CLO
#include "pub_tool_oset.h"          // OSet operations
#include "pub_tool_threadstate.h"   // VG_(get_running_tid)
#include "pub_tool_xarray.h"        // VG_(*XA)
#include "pub_tool_stacktrace.h"    // VG_(get_and_pp_StackTrace)
#include "pub_tool_libcfile.h"      // VG_(readlink)
#include "pub_tool_addrinfo.h"      // VG_(describe_addr)

#include "tnt_include.h"
#include "tnt_strings.h"
#include "tnt_structs.h"
#include "tnt_malloc_wrappers.h"
#include "tnt_summary_names.h"
#include "tnt_libc.h"
#include "tnt_syswrap.h"
#include "tnt_asm.h"
#include "tnt_mmap.h"


/*------------------------------------------------------------*/
/*--- Fast-case knobs                                      ---*/
/*------------------------------------------------------------*/

// Comment these out to disable the fast cases (don't just set them to zero).

#define PERF_FAST_LOADV    1
#define PERF_FAST_STOREV   1

#define PERF_FAST_SARP     1

/*---------- Taintgrind DEBUG statements---------*/
//#define DBG_MEM
//#define DBG_LOAD
//#define DBG_STORE
//#define DBG_COPY_ADDR_RANGE_STATE

/* --------------- Basic configuration --------------- */

/* Only change this.  N_PRIMARY_MAP *must* be a power of 2. */

#if VG_WORDSIZE == 4

/* cover the entire address space */
#  define N_PRIMARY_BITS  16

#else

/* Just handle the first 32G fast and the rest via auxiliary
   primaries.  If you change this, Memcheck will assert at startup.
   See the definition of UNALIGNED_OR_HIGH for extensive comments. */
#  define N_PRIMARY_BITS  19

#endif


/* Do not change this. */
#define N_PRIMARY_MAP  ( ((UWord)1) << N_PRIMARY_BITS)	// 524288

/* Do not change this. */
#define MAX_PRIMARY_ADDRESS (Addr)((((Addr)65536) * N_PRIMARY_MAP)-1)

// Taintgrind: UNDEFINED -> TAINTED, DEFINED -> UNTAINTED,
//             PARTDEFINED -> PARTUNTAINTED
// These represent eight bits of memory.
#define VA_BITS2_NOACCESS      0x0      // 00b
#define VA_BITS2_TAINTED       0x1      // 01b
#define VA_BITS2_UNTAINTED     0x2      // 10b
#define VA_BITS2_PARTUNTAINTED 0x3      // 11b

// These represent 16 bits of memory.
#define VA_BITS4_NOACCESS     0x0      // 00_00b
#define VA_BITS4_TAINTED      0x5      // 01_01b
#define VA_BITS4_UNTAINTED    0xa      // 10_10b

// These represent 32 bits of memory.
#define VA_BITS8_NOACCESS     0x00     // 00_00_00_00b
#define VA_BITS8_TAINTED      0x55     // 01_01_01_01b
#define VA_BITS8_UNTAINTED    0xaa     // 10_10_10_10b

// These represent 64 bits of memory.
#define VA_BITS16_NOACCESS    0x0000   // 00_00_00_00b x 2
#define VA_BITS16_TAINTED     0x5555   // 01_01_01_01b x 2
#define VA_BITS16_UNTAINTED   0xaaaa   // 10_10_10_10b x 2

#define SM_CHUNKS             16384	// Laurent: do not change this as it must be 65536/4 to store the vabits2
#define SM_OFF(aaa)           (((aaa) & 0xffff) >> 2)
#define SM_OFF_16(aaa)        (((aaa) & 0xffff) >> 3)

// Paranoia:  it's critical for performance that the requested inlining
// occurs.  So try extra hard.
#define INLINE    inline __attribute__((always_inline))

static INLINE Addr start_of_this_sm ( Addr a ) {
   return (a & (~SM_MASK));
}
static INLINE Bool is_start_of_sm ( Addr a ) {
   return (start_of_this_sm(a) == a);
}

typedef
   struct {
      UChar vabits8[SM_CHUNKS];
   }
   SecMap;

// 3 distinguished secondary maps, one for no-access, one for
// accessible but undefined, and one for accessible and defined.
// Distinguished secondaries may never be modified.
#define SM_DIST_NOACCESS   0
#define SM_DIST_TAINTED    1
#define SM_DIST_UNTAINTED  2

static SecMap sm_distinguished[3];

static INLINE Bool is_distinguished_sm ( SecMap* sm ) {
   return sm >= &sm_distinguished[0] && sm <= &sm_distinguished[2];
}

// -Start- Forward declarations for Taintgrind
Int  ctoi( HChar c );
Int  ctoi_test( HChar c );
Int  atoi( HChar *s );
Int get_and_check_reg( HChar *reg );
Int get_and_check_tvar( HChar *tmp );
void infer_client_binary_name(UInt pc);
// -End- Forward declarations for Taintgrind

static void update_SM_counts(SecMap* oldSM, SecMap* newSM); //285

#if _SECRETGRIND_
#define UNKNOWN_OBJ_FMT			"@0x%lx_unknownvar"
#define UNKNOWN_OBJ_IN_EXE_FMT	"obj_%s@0x%lx_unknownvar_%u_%u"

static SizeT TNT_(size_of_taint)(ULong taint);
static Bool TNT_(parse_data)(const char *in, const char *left, const char *right, char *out, SizeT len);
static void TNT_(display_names_of_mem_region)(Addr a, SizeT len, sn_addr_type_t type);
static void TNT_(show_main_summary)(void);
static void taint_summary(const char *name);
static void var_taint_status(char *desc, Addr a, SizeT len);
static void TNT_(format_varname)(char *varnamebuf, SizeT bufsize, char *loc, char *offset, char *varname, char *filename, char *lineno, char *funcname, char *basename);
static Bool TNT_(is_stack)(Addr a);
static Bool TNT_(is_global)(Addr a);
static SizeT TNT_(size_of_load)(IRType ty, SizeT n);
static void TNT_(format_mnemonics_and_id)(Inst_t *ins, char *out, SizeT olen);

typedef union {
	// for store_tc, ie STORE tmp = c
	struct {
		ULong c;
		UInt atmp;
		UChar offset;
	} tc;
	
	// for store_ct, ie STORE c = tmp
	struct {
		ULong c;
		UInt dtmp;
		UChar offset;
	} ct;
	
	// for store_tt, ie STORE dtmp = atmp
	struct {
		UInt atmp;
		UInt dtmp;
		UChar offset;
	} tt;
	
} _H64_prepare_st;

static _H64_prepare_st GH64_prepare_xx = {};

static void TNT_(h64_reset_prepare_struct)(_H64_prepare_st *st) {
	VG_(memset)(st, 0, sizeof(_H64_prepare_st));
}
typedef union {
	// for store_tc, ie STORE tmp = c
	struct {
		UInt c;
		UInt atmp;
		UChar offset;
	} tc;
	
	// for store_ct, ie STORE c = tmp
	struct {
		UInt c;
		UInt dtmp;
		UChar offset;
	} ct;
	
	// for store_tt, ie STORE dtmp = atmp
	struct {
		UInt atmp;
		UInt dtmp;
		UChar offset;
	} tt;
	
} _H32_prepare_st;

static _H32_prepare_st GH32_prepare_xx = {};

static void TNT_(h32_reset_prepare_struct)(_H32_prepare_st *st) {
	VG_(memset)(st, 0, sizeof(_H32_prepare_st));
}

#endif

/* dist_sm points to one of our three distinguished secondaries.  Make
   a copy of it so that we can write to it.
*/
static SecMap* copy_for_writing ( SecMap* dist_sm )
{
   SecMap* new_sm;
   tl_assert(dist_sm == &sm_distinguished[0]
          || dist_sm == &sm_distinguished[1]
          || dist_sm == &sm_distinguished[2]);

   new_sm = VG_(am_shadow_alloc)(sizeof(SecMap));
   if (new_sm == NULL)
      VG_(out_of_memory_NORETURN)( "memcheck:allocate new SecMap",
                                   sizeof(SecMap) );
   VG_(memcpy)(new_sm, dist_sm, sizeof(SecMap));
   update_SM_counts(dist_sm, new_sm);
   return new_sm;
}

/* --------------- Stats --------------- */

static Int   n_issued_SMs      = 0;
static Int   n_deissued_SMs    = 0;
static Int   n_noaccess_SMs    = N_PRIMARY_MAP; // start with many noaccess DSMs
static Int   n_undefined_SMs   = 0;
static Int   n_defined_SMs     = 0;
static Int   n_non_DSM_SMs     = 0;
static Int   max_noaccess_SMs  = 0;
static Int   max_undefined_SMs = 0;
static Int   max_defined_SMs   = 0;
static Int   max_non_DSM_SMs   = 0;

/* # searches initiated in auxmap_L1, and # base cmps required */
static ULong n_auxmap_L1_searches  = 0;
static ULong n_auxmap_L1_cmps      = 0;
/* # of searches that missed in auxmap_L1 and therefore had to
   be handed to auxmap_L2. And the number of nodes inserted. */
static ULong n_auxmap_L2_searches  = 0;
static ULong n_auxmap_L2_nodes     = 0;

//static Int   n_sanity_cheap     = 0;
//static Int   n_sanity_expensive = 0;

static Int   n_secVBit_nodes   = 0;
static Int   max_secVBit_nodes = 0;

static void update_SM_counts(SecMap* oldSM, SecMap* newSM)
{
   if      (oldSM == &sm_distinguished[SM_DIST_NOACCESS ]) n_noaccess_SMs --;
   else if (oldSM == &sm_distinguished[SM_DIST_TAINTED]) n_undefined_SMs--;
   else if (oldSM == &sm_distinguished[SM_DIST_UNTAINTED  ]) n_defined_SMs  --;
   else                                                  { n_non_DSM_SMs  --;
                                                           n_deissued_SMs ++; }

   if      (newSM == &sm_distinguished[SM_DIST_NOACCESS ]) n_noaccess_SMs ++;
   else if (newSM == &sm_distinguished[SM_DIST_TAINTED]) n_undefined_SMs++;
   else if (newSM == &sm_distinguished[SM_DIST_UNTAINTED  ]) n_defined_SMs  ++;
   else                                                  { n_non_DSM_SMs  ++;
                                                           n_issued_SMs   ++; }

   if (n_noaccess_SMs  > max_noaccess_SMs ) max_noaccess_SMs  = n_noaccess_SMs;
   if (n_undefined_SMs > max_undefined_SMs) max_undefined_SMs = n_undefined_SMs;
   if (n_defined_SMs   > max_defined_SMs  ) max_defined_SMs   = n_defined_SMs;
   if (n_non_DSM_SMs   > max_non_DSM_SMs  ) max_non_DSM_SMs   = n_non_DSM_SMs;
   
}

/* --------------- Primary maps --------------- */

/* The main primary map.  This covers some initial part of the address
   space, addresses 0 .. (N_PRIMARY_MAP << 16)-1.  The rest of it is
   handled using the auxiliary primary map.
*/
static SecMap* primary_map[N_PRIMARY_MAP];

/* An entry in the auxiliary primary map.  base must be a 64k-aligned
   value, and sm points at the relevant secondary map.  As with the
   main primary map, the secondary may be either a real secondary, or
   one of the three distinguished secondaries.  DO NOT CHANGE THIS
   LAYOUT: the first word has to be the key for OSet fast lookups.
*/
typedef
   struct {
      Addr    base;
      SecMap* sm;
   }
   AuxMapEnt;

/* Tunable parameter: How big is the L1 queue? */
#define N_AUXMAP_L1 24

/* Tunable parameter: How far along the L1 queue to insert
   entries resulting from L2 lookups? */
#define AUXMAP_L1_INSERT_IX 12

static struct {
          Addr       base;
          AuxMapEnt* ent; // pointer to the matching auxmap_L2 node
       }
       auxmap_L1[N_AUXMAP_L1];

static OSet* auxmap_L2 = NULL;
static void init_auxmap_L1_L2 ( void )
{
   Int i;
   for (i = 0; i < N_AUXMAP_L1; i++) {
      auxmap_L1[i].base = 0;
      auxmap_L1[i].ent  = NULL;
   }

   tl_assert(0 == offsetof(AuxMapEnt,base));
   tl_assert(sizeof(Addr) == sizeof(void*));
   auxmap_L2 = VG_(OSetGen_Create)( /*keyOff*/  offsetof(AuxMapEnt,base),
                                    /*fastCmp*/ NULL,
                                    VG_(malloc), "mc.iaLL.1", VG_(free) );
}

/* Check representation invariants; if OK return NULL; else a
   descriptive bit of text.  Also return the number of
   non-distinguished secondary maps referred to from the auxiliary
   primary maps. */

//static HChar* check_auxmap_L1_L2_sanity ( Word* n_secmaps_found )
//{
//   Word i, j;
   /* On a 32-bit platform, the L2 and L1 tables should
      both remain empty forever.

      On a 64-bit platform:
      In the L2 table:
       all .base & 0xFFFF == 0
       all .base > MAX_PRIMARY_ADDRESS
      In the L1 table:
       all .base & 0xFFFF == 0
       all (.base > MAX_PRIMARY_ADDRESS
            .base & 0xFFFF == 0
            and .ent points to an AuxMapEnt with the same .base)
           or
           (.base == 0 and .ent == NULL)
   */
//   *n_secmaps_found = 0;
//   if (sizeof(void*) == 4) {
      /* 32-bit platform */
//      if (VG_(OSetGen_Size)(auxmap_L2) != 0)
//         return "32-bit: auxmap_L2 is non-empty";
//      for (i = 0; i < N_AUXMAP_L1; i++)
//        if (auxmap_L1[i].base != 0 || auxmap_L1[i].ent != NULL)
//      return "32-bit: auxmap_L1 is non-empty";
//   } else {
      /* 64-bit platform */
//      UWord elems_seen = 0;
//      AuxMapEnt *elem, *res;
//      AuxMapEnt key;
      /* L2 table */
//      VG_(OSetGen_ResetIter)(auxmap_L2);
//      while ( (elem = VG_(OSetGen_Next)(auxmap_L2)) ) {
//         elems_seen++;
//         if (0 != (elem->base & (Addr)0xFFFF))
//            return "64-bit: nonzero .base & 0xFFFF in auxmap_L2";
//         if (elem->base <= MAX_PRIMARY_ADDRESS)
//            return "64-bit: .base <= MAX_PRIMARY_ADDRESS in auxmap_L2";
//         if (elem->sm == NULL)
//            return "64-bit: .sm in _L2 is NULL";
//         if (!is_distinguished_sm(elem->sm))
//            (*n_secmaps_found)++;
//      }
//      if (elems_seen != n_auxmap_L2_nodes)
//         return "64-bit: disagreement on number of elems in _L2";
      /* Check L1-L2 correspondence */
/*      for (i = 0; i < N_AUXMAP_L1; i++) {
         if (auxmap_L1[i].base == 0 && auxmap_L1[i].ent == NULL)
            continue;
         if (0 != (auxmap_L1[i].base & (Addr)0xFFFF))
            return "64-bit: nonzero .base & 0xFFFF in auxmap_L1";
         if (auxmap_L1[i].base <= MAX_PRIMARY_ADDRESS)
            return "64-bit: .base <= MAX_PRIMARY_ADDRESS in auxmap_L1";
         if (auxmap_L1[i].ent == NULL)
            return "64-bit: .ent is NULL in auxmap_L1";
         if (auxmap_L1[i].ent->base != auxmap_L1[i].base)
            return "64-bit: _L1 and _L2 bases are inconsistent";*/
         /* Look it up in auxmap_L2. */
/*         key.base = auxmap_L1[i].base;
         key.sm   = 0;
         res = VG_(OSetGen_Lookup)(auxmap_L2, &key);
         if (res == NULL)
            return "64-bit: _L1 .base not found in _L2";
         if (res != auxmap_L1[i].ent)
            return "64-bit: _L1 .ent disagrees with _L2 entry";
      }*/
      /* Check L1 contains no duplicates */
/*      for (i = 0; i < N_AUXMAP_L1; i++) {
         if (auxmap_L1[i].base == 0)
            continue;
         for (j = i+1; j < N_AUXMAP_L1; j++) {
            if (auxmap_L1[j].base == 0)
               continue;
            if (auxmap_L1[j].base == auxmap_L1[i].base)
               return "64-bit: duplicate _L1 .base entries";
         }
      }
   }
   return NULL;*/ /* ok */
//}

static void insert_into_auxmap_L1_at ( Word rank, AuxMapEnt* ent )
{
   Word i;
   tl_assert(ent);
   tl_assert(rank >= 0 && rank < N_AUXMAP_L1);
   for (i = N_AUXMAP_L1-1; i > rank; i--)
      auxmap_L1[i] = auxmap_L1[i-1];
   auxmap_L1[rank].base = ent->base;
   auxmap_L1[rank].ent  = ent;
}

static INLINE AuxMapEnt* maybe_find_in_auxmap ( Addr a )
{
   AuxMapEnt  key;
   AuxMapEnt* res;
   Word       i;

   tl_assert(a > MAX_PRIMARY_ADDRESS);
   a &= ~(Addr)0xFFFF;

   /* First search the front-cache, which is a self-organising
      list containing the most popular entries. */

   if (LIKELY(auxmap_L1[0].base == a))
      return auxmap_L1[0].ent;
   if (LIKELY(auxmap_L1[1].base == a)) {
      Addr       t_base = auxmap_L1[0].base;
      AuxMapEnt* t_ent  = auxmap_L1[0].ent;
      auxmap_L1[0].base = auxmap_L1[1].base;
      auxmap_L1[0].ent  = auxmap_L1[1].ent;
      auxmap_L1[1].base = t_base;
      auxmap_L1[1].ent  = t_ent;
      return auxmap_L1[0].ent;
   }

   n_auxmap_L1_searches++;

   for (i = 0; i < N_AUXMAP_L1; i++) {
      if (auxmap_L1[i].base == a) {
         break;
      }
   }
   tl_assert(i >= 0 && i <= N_AUXMAP_L1);

   n_auxmap_L1_cmps += (ULong)(i+1);

   if (i < N_AUXMAP_L1) {
      if (i > 0) {
         Addr       t_base = auxmap_L1[i-1].base;
         AuxMapEnt* t_ent  = auxmap_L1[i-1].ent;
         auxmap_L1[i-1].base = auxmap_L1[i-0].base;
         auxmap_L1[i-1].ent  = auxmap_L1[i-0].ent;
         auxmap_L1[i-0].base = t_base;
         auxmap_L1[i-0].ent  = t_ent;
         i--;
      }
      return auxmap_L1[i].ent;
   }

   n_auxmap_L2_searches++;

   /* First see if we already have it. */
   key.base = a;
   key.sm   = 0;

   res = VG_(OSetGen_Lookup)(auxmap_L2, &key);
   if (res)
      insert_into_auxmap_L1_at( AUXMAP_L1_INSERT_IX, res );
   return res;
}

static AuxMapEnt* find_or_alloc_in_auxmap ( Addr a )
{
   AuxMapEnt *nyu, *res;
	
   /* First see if we already have it. */
   res = maybe_find_in_auxmap( a );
   if (LIKELY(res))
      return res;

   /* Ok, there's no entry in the secondary map, so we'll have
      to allocate one. */
   a &= ~(Addr)0xFFFF;
   nyu = (AuxMapEnt*) VG_(OSetGen_AllocNode)( auxmap_L2, sizeof(AuxMapEnt) );
   tl_assert(nyu);
   nyu->base = a;
   #if _SECRETGRIND_
   nyu->sm   = &sm_distinguished[SM_DIST_UNTAINTED];
   #else
   nyu->sm   = &sm_distinguished[SM_DIST_NOACCESS];
   #endif
   VG_(OSetGen_Insert)( auxmap_L2, nyu );
   insert_into_auxmap_L1_at( AUXMAP_L1_INSERT_IX, nyu );
   n_auxmap_L2_nodes++;
   return nyu;
}

/* --------------- SecMap fundamentals --------------- */ //586

// In all these, 'low' means it's definitely in the main primary map,
// 'high' means it's definitely in the auxiliary table.

static INLINE SecMap** get_secmap_low_ptr ( Addr a )
{
   UWord pm_off = a >> 16;
//#  if VG_DEBUG_MEMORY >= 1
   tl_assert(pm_off < N_PRIMARY_MAP);
//#  endif
   return &primary_map[ pm_off ];
}

static INLINE SecMap** get_secmap_high_ptr ( Addr a )
{
   AuxMapEnt* am = find_or_alloc_in_auxmap(a);
   return &am->sm;
}

static SecMap** get_secmap_ptr ( Addr a )
{
#if _SECRETGRIND_
	//VG_(printf)("get_secmap_ptr: %lx, %lx\n", a, MAX_PRIMARY_ADDRESS);
	//tl_assert (a <= MAX_PRIMARY_ADDRESS && "received memory access above MAX_PRIMARY_ADDRESS");
#endif
   return ( a <= MAX_PRIMARY_ADDRESS
          ? get_secmap_low_ptr(a)
          : get_secmap_high_ptr(a));
}

static INLINE SecMap* get_secmap_for_reading_low ( Addr a )
{
   return *get_secmap_low_ptr(a);
}

static INLINE SecMap* get_secmap_for_reading_high ( Addr a )
{
   return *get_secmap_high_ptr(a);
}

static INLINE SecMap* get_secmap_for_writing_low(Addr a)
{
   SecMap** p = get_secmap_low_ptr(a);
   if (UNLIKELY(is_distinguished_sm(*p)))
      *p = copy_for_writing(*p);
   return *p;
}

static INLINE SecMap* get_secmap_for_writing_high ( Addr a )
{
   SecMap** p = get_secmap_high_ptr(a);
   if (UNLIKELY(is_distinguished_sm(*p)))
      *p = copy_for_writing(*p);
   return *p;
}

/* Produce the secmap for 'a', either from the primary map or by
   ensuring there is an entry for it in the aux primary map.  The
   secmap may be a distinguished one as the caller will only want to
   be able to read it.
*/
static INLINE SecMap* get_secmap_for_reading ( Addr a )
{
   return ( a <= MAX_PRIMARY_ADDRESS
          ? get_secmap_for_reading_low (a)
          : get_secmap_for_reading_high(a) );
}

/* Produce the secmap for 'a', either from the primary map or by
   ensuring there is an entry for it in the aux primary map.  The
   secmap may not be a distinguished one, since the caller will want
   to be able to write it.  If it is a distinguished secondary, make a
   writable copy of it, install it, and return the copy instead.  (COW
   semantics).
*/
static SecMap* get_secmap_for_writing ( Addr a )
{
   return ( a <= MAX_PRIMARY_ADDRESS
          ? get_secmap_for_writing_low (a)
          : get_secmap_for_writing_high(a) );
}

/* If 'a' has a SecMap, produce it.  Else produce NULL.  But don't
   allocate one if one doesn't already exist.  This is used by the
   leak checker.
*/
/*static SecMap* maybe_get_secmap_for ( Addr a )
{
   if (a <= MAX_PRIMARY_ADDRESS) {
      return get_secmap_for_reading_low(a);
   } else {
      AuxMapEnt* am = maybe_find_in_auxmap(a);
      return am ? am->sm : NULL;
   }
}*/

/* --------------- Fundamental functions --------------- */

static INLINE
void insert_vabits2_into_vabits8 ( Addr a, UChar vabits2, UChar* vabits8 ) //682
{
   UInt shift =  (a & 3)  << 1;        // shift by 0, 2, 4, or 6
   *vabits8  &= ~(0x3     << shift);   // mask out the two old bits
   *vabits8  |=  (vabits2 << shift);   // mask  in the two new bits
}

static INLINE
void insert_vabits4_into_vabits8 ( Addr a, UChar vabits4, UChar* vabits8 )
{
   UInt shift;
   tl_assert(VG_IS_2_ALIGNED(a));      // Must be 2-aligned
   shift     =  (a & 2)   << 1;        // shift by 0 or 4
   *vabits8 &= ~(0xf      << shift);   // mask out the four old bits
   *vabits8 |=  (vabits4 << shift);    // mask  in the four new bits
}

static INLINE
UChar extract_vabits2_from_vabits8 ( Addr a, UChar vabits8 )
{
   UInt shift = (a & 3) << 1;          // shift by 0, 2, 4, or 6
   vabits8 >>= shift;                  // shift the two bits to the bottom
   return 0x3 & vabits8;               // mask out the rest
}

static INLINE
UChar extract_vabits4_from_vabits8 ( Addr a, UChar vabits8 )
{
   UInt shift;
   tl_assert(VG_IS_2_ALIGNED(a));      // Must be 2-aligned
   shift = (a & 2) << 1;               // shift by 0 or 4
   vabits8 >>= shift;                  // shift the four bits to the bottom
   return 0xf & vabits8;               // mask out the rest
}

// Note that these four are only used in slow cases.  The fast cases do
// clever things like combine the auxmap check (in
// get_secmap_{read,writ}able) with alignment checks.

// *** WARNING! ***
// Any time this function is called, if it is possible that vabits2
// is equal to VA_BITS2_PARTUNTAINTED, then the corresponding entry in the
// sec-V-bits table must also be set!
static INLINE
void set_vabits2 ( Addr a, UChar vabits2 )
{
   SecMap* sm       = get_secmap_for_writing(a); // Taintgrind: only handle 32-bits
   UWord   sm_off   = SM_OFF(a);

#ifdef DBG_MEM
   // Taintgrind
//   if (vabits2 == VA_BITS2_TAINTED)
      VG_(printf)("set_vabits2 a:0x%08lx vabits2:0x%x sm->vabit8[sm_off]:0x%08x\n",
                  a, vabits2, (Int)&(sm->vabits8[sm_off]));
#endif

   insert_vabits2_into_vabits8( a, vabits2, &(sm->vabits8[sm_off]) );
}


// *** WARNING! ***
// Any time this function is called, if it is possible that any of the
// 4 2-bit fields in vabits8 are equal to VA_BITS2_PARTUNTAINTED, then the
// corresponding entry(s) in the sec-V-bits table must also be set!
static INLINE
UChar get_vabits8_for_aligned_word32 ( Addr a )
{
   SecMap* sm       = get_secmap_for_reading(a);
   UWord   sm_off   = SM_OFF(a);
   UChar   vabits8  = sm->vabits8[sm_off];
   return vabits8;
}

static INLINE
void set_vabits8_for_aligned_word32 ( Addr a, UChar vabits8 )
{
   SecMap* sm       = get_secmap_for_writing(a);
   UWord   sm_off   = SM_OFF(a);
   sm->vabits8[sm_off] = vabits8;
}

// Needed by TNT_(instrument)
//static INLINE
UChar get_vabits2 ( Addr a )
{
#if _SECRETGRIND_
	// re-use existing function
	UChar vabits8 = get_vabits8_for_aligned_word32(a);
#else 
   SecMap* sm       = get_secmap_for_reading(a); // Taintgrind: only handle 32-bits
   UWord   sm_off   = SM_OFF(a);
   UChar   vabits8  = sm->vabits8[sm_off];
#endif

#ifdef DBG_MEM
   // Taintgrind
   UChar result = extract_vabits2_from_vabits8(a, vabits8);
//   if (vabits2 == VA_BITS2_TAINTED)
      VG_(printf)("get_vabits2 a:0x%08lx vabits2:0x%x sm->vabit8[sm_off]:0x%08x\n",
                  a, result, (Int)&vabits8);
   return result;
#endif
   
   return extract_vabits2_from_vabits8(a, vabits8);
}


// Forward declarations
static UWord get_sec_vbits8(Addr a);
static void  set_sec_vbits8(Addr a, UWord vbits8);

// Returns False if there was an addressability error.
// Taintgrind: skip addressability check
static INLINE
Bool set_vbits8 ( Addr a, UChar vbits8 )
{  
   Bool  ok      = True;
   UChar vabits2 = get_vabits2(a);
   //if ( VA_BITS2_NOACCESS != vabits2 ) {
      // Addressable.  Convert in-register format to in-memory format.
      // Also remove any existing sec V bit entry for the byte if no
      // longer necessary.
      if      ( V_BITS8_UNTAINTED == vbits8 ) { vabits2 = VA_BITS2_UNTAINTED; }
      else if ( V_BITS8_TAINTED   == vbits8 ) { vabits2 = VA_BITS2_TAINTED;   }
      else                                    { vabits2 = VA_BITS2_PARTUNTAINTED;
                                                set_sec_vbits8(a, vbits8);  }
      set_vabits2(a, vabits2);

   //} else {
   //   // Unaddressable!  Do nothing -- when writing to unaddressable
   //   // memory it acts as a black hole, and the V bits can never be seen
   //   // again.  So we don't have to write them at all.
   //   ok = False;
   //}
   
   return ok;
}

// Returns False if there was an addressability error.  In that case, we put
// all defined bits into vbits8.
static INLINE
Bool get_vbits8 ( Addr a, UChar* vbits8 )
{ 
   Bool  ok      = True;
   UChar vabits2 = get_vabits2(a);

   // Convert the in-memory format to in-register format.
   if      ( VA_BITS2_UNTAINTED == vabits2 ) { *vbits8 = V_BITS8_UNTAINTED; }
   else if ( VA_BITS2_TAINTED   == vabits2 ) { *vbits8 = V_BITS8_TAINTED;   }
   else if ( VA_BITS2_NOACCESS  == vabits2 ) {
      *vbits8 = V_BITS8_UNTAINTED;    // Make V bits defined!
      ok = False;
   } else {
      tl_assert( VA_BITS2_PARTUNTAINTED == vabits2 );
      *vbits8 = get_sec_vbits8(a);
   }
   return ok;
}

/* --------------- Secondary V bit table ------------ */
static OSet* secVBitTable;

// Stats
static ULong sec_vbits_new_nodes = 0;
static ULong sec_vbits_updates   = 0;

// This must be a power of two;  this is checked in tnt_pre_clo_init().
// The size chosen here is a trade-off:  if the nodes are bigger (ie. cover
// a larger address range) they take more space but we can get multiple
// partially-defined bytes in one if they are close to each other, reducing
// the number of total nodes.  In practice sometimes they are clustered (eg.
// perf/bz2 repeatedly writes then reads more than 20,000 in a contiguous
// row), but often not.  So we choose something intermediate.
#define BYTES_PER_SEC_VBIT_NODE     16

// We make the table bigger if more than this many nodes survive a GC.
#define MAX_SURVIVOR_PROPORTION  0.5

// Each time we make the table bigger, we increase it by this much.
#define TABLE_GROWTH_FACTOR      2

// This defines "sufficiently stale" -- any node that hasn't been touched in
// this many GCs will be removed.
#define MAX_STALE_AGE            2

// We GC the table when it gets this many nodes in it, ie. it's effectively
// the table size.  It can change.
static Int  secVBitLimit = 1024;

// The number of GCs done, used to age sec-V-bit nodes for eviction.
// Because it's unsigned, wrapping doesn't matter -- the right answer will
// come out anyway.
static UInt GCs_done = 0;

typedef
   struct {
      Addr  a;
      UChar vbits8[BYTES_PER_SEC_VBIT_NODE];
      UInt  last_touched;
   }
   SecVBitNode;

static OSet* createSecVBitTable(void)
{
   return VG_(OSetGen_Create)( offsetof(SecVBitNode, a),
                               NULL, // use fast comparisons
                               VG_(malloc), "mc.cSVT.1 (sec VBit table)",
                               VG_(free) );
}

static void gcSecVBitTable(void)
{
   OSet*        secVBitTable2;
   SecVBitNode* n;
   Int          i, n_nodes = 0, n_survivors = 0;

   GCs_done++;

   // Create the new table.
   secVBitTable2 = createSecVBitTable();

   // Traverse the table, moving fresh nodes into the new table.
   VG_(OSetGen_ResetIter)(secVBitTable);
   while ( (n = VG_(OSetGen_Next)(secVBitTable)) ) {
      Bool keep = False;
      if ( (GCs_done - n->last_touched) <= MAX_STALE_AGE ) {
         // Keep node if it's been touched recently enough (regardless of
         // freshness/staleness).
         keep = True;
      } else {
         // Keep node if any of its bytes are non-stale.  Using
         // get_vabits2() for the lookup is not very efficient, but I don't
         // think it matters.
         for (i = 0; i < BYTES_PER_SEC_VBIT_NODE; i++) { VG_(printf)( "gcSecVBitTable() -> get_vabits2\n" );
            if (VA_BITS2_PARTUNTAINTED == get_vabits2(n->a + i)) {
               keep = True;      // Found a non-stale byte, so keep
               break;
            }
         }
      }

      if ( keep ) {
         // Insert a copy of the node into the new table.
         SecVBitNode* n2 =
            VG_(OSetGen_AllocNode)(secVBitTable2, sizeof(SecVBitNode));
         *n2 = *n;
         VG_(OSetGen_Insert)(secVBitTable2, n2);
      }
   }

   // Get the before and after sizes.
   n_nodes     = VG_(OSetGen_Size)(secVBitTable);
   n_survivors = VG_(OSetGen_Size)(secVBitTable2);

   // Destroy the old table, and put the new one in its place.
   VG_(OSetGen_Destroy)(secVBitTable);
   secVBitTable = secVBitTable2;

   if (VG_(clo_verbosity) > 1) {
      HChar percbuf[6];
      VG_(percentify)(n_survivors, n_nodes, 1, 6, percbuf);
      VG_(message)(Vg_DebugMsg, "tnt_main.c: GC: %d nodes, %d survivors (%s)\n",
                   n_nodes, n_survivors, percbuf);
   }

   // Increase table size if necessary.
   if (n_survivors > (secVBitLimit * MAX_SURVIVOR_PROPORTION)) {
      secVBitLimit *= TABLE_GROWTH_FACTOR;
      if (VG_(clo_verbosity) > 1)
         VG_(message)(Vg_DebugMsg, "tnt_main.c: GC: increase table size to %d\n",
                      secVBitLimit);
   }
}

static UWord get_sec_vbits8(Addr a)
{
   Addr         aAligned = VG_ROUNDDN(a, BYTES_PER_SEC_VBIT_NODE);
   Int          amod     = a % BYTES_PER_SEC_VBIT_NODE;
   SecVBitNode* n        = VG_(OSetGen_Lookup)(secVBitTable, &aAligned);
   UChar        vbits8;
   tl_assert2(n, "get_sec_vbits8: no node for address %p (%p)\n", aAligned, a);
   // Shouldn't be fully defined or fully undefined -- those cases shouldn't
   // make it to the secondary V bits table.
   vbits8 = n->vbits8[amod];
   tl_assert(V_BITS8_UNTAINTED != vbits8 && V_BITS8_TAINTED != vbits8);
   return vbits8;
}

static void set_sec_vbits8(Addr a, UWord vbits8)
{
   Addr         aAligned = VG_ROUNDDN(a, BYTES_PER_SEC_VBIT_NODE);
   Int          i, amod  = a % BYTES_PER_SEC_VBIT_NODE;
   SecVBitNode* n        = VG_(OSetGen_Lookup)(secVBitTable, &aAligned);
   // Shouldn't be fully defined or fully undefined -- those cases shouldn't
   // make it to the secondary V bits table.
   tl_assert(V_BITS8_UNTAINTED != vbits8 && V_BITS8_TAINTED != vbits8);
   if (n) {
      n->vbits8[amod] = vbits8;     // update
      n->last_touched = GCs_done;
      sec_vbits_updates++;
   } else {
      // New node:  assign the specific byte, make the rest invalid (they
      // should never be read as-is, but be cautious).
      n = VG_(OSetGen_AllocNode)(secVBitTable, sizeof(SecVBitNode));
      n->a            = aAligned;
      for (i = 0; i < BYTES_PER_SEC_VBIT_NODE; i++) {
         n->vbits8[i] = V_BITS8_TAINTED;
      }
      n->vbits8[amod] = vbits8;
      n->last_touched = GCs_done;

      // Do a table GC if necessary.  Nb: do this before inserting the new
      // node, to avoid erroneously GC'ing the new node.
      if (secVBitLimit == VG_(OSetGen_Size)(secVBitTable)) {
         gcSecVBitTable();
      }

      // Insert the new node.
      VG_(OSetGen_Insert)(secVBitTable, n);
      sec_vbits_new_nodes++;

      n_secVBit_nodes = VG_(OSetGen_Size)(secVBitTable);
      if (n_secVBit_nodes > max_secVBit_nodes)
         max_secVBit_nodes = n_secVBit_nodes;
   }
}

/* --------------- Endianness helpers --------------- */

/* Returns the offset in memory of the byteno-th most significant byte
   in a wordszB-sized word, given the specified endianness. */
static INLINE UWord byte_offset_w ( UWord wordszB, Bool bigendian,
                                    UWord byteno ) {
   return bigendian ? (wordszB-1-byteno) : byteno;
}


/* --------------- Load/store slow cases. --------------- */
static
__attribute__((noinline))
void tnt_LOADV_128_or_256_slow ( /*OUT*/ULong* res,
                                Addr a, SizeT nBits, Bool bigendian )
{
   //ULong  pessim[4];     /* only used when p-l-ok=yes */
   SSizeT szB            = nBits / 8;
   SSizeT szL            = szB / 8;  /* Size in Longs (64-bit units) */
   SSizeT i, j;          /* Must be signed. */
   SizeT  n_addrs_bad = 0;
   Addr   ai;
   UChar  vbits8;
   Bool   ok;

   /* Code below assumes load size is a power of two and at least 64
      bits. */
   tl_assert((szB & (szB-1)) == 0 && szL > 0);

   /* If this triggers, you probably just need to increase the size of
      the pessim array. */
   //tl_assert(szL <= sizeof(pessim) / sizeof(pessim[0]));

   for (j = 0; j < szL; j++) {
      //pessim[j] = V_BITS64_UNTAINTED;
      res[j] = V_BITS64_TAINTED;
   }

   /* Make up a result V word, which contains the loaded data for
      valid addresses and Defined for invalid addresses.  Iterate over
      the bytes in the word, from the most significant down to the
      least.  The vbits to return are calculated into vbits128.  Also
      compute the pessimising value to be used when
      --partial-loads-ok=yes.  n_addrs_bad is redundant (the relevant
      info can be gleaned from the pessim array) but is used as a
      cross-check. */
   for (j = szL-1; j >= 0; j--) {
      ULong vbits64    = V_BITS64_TAINTED;
      //ULong pessim64   = V_BITS64_UNTAINTED;
      UWord long_index = byte_offset_w(szL, bigendian, j);
      for (i = 8-1; i >= 0; i--) {
         PROF_EVENT(31, "tnt_LOADV_128_or_256_slow(loop)");
         ai = a + 8*long_index + byte_offset_w(8, bigendian, i);
         ok = get_vbits8(ai, &vbits8);
         vbits64 <<= 8;
         vbits64 |= vbits8;
         if (!ok) n_addrs_bad++;
         //pessim64 <<= 8;
         //pessim64 |= (ok ? V_BITS8_UNTAINTED : V_BITS8_TAINTED);
      }
      res[long_index] = vbits64;
      //pessim[long_index] = pessim64;
   }

   /* In the common case, all the addresses involved are valid, so we
      just return the computed V bits and have done. */
   //if (LIKELY(n_addrs_bad == 0))
   return;

   /* If there's no possibility of getting a partial-loads-ok
      exemption, report the error and quit. */
   //if (!MC_(clo_partial_loads_ok)) {
   //   MC_(record_address_error)( VG_(get_running_tid)(), a, szB, False );
   //   return;
   //}

   /* The partial-loads-ok excemption might apply.  Find out if it
      does.  If so, don't report an addressing error, but do return
      Undefined for the bytes that are out of range, so as to avoid
      false negatives.  If it doesn't apply, just report an addressing
      error in the usual way. */

   /* Some code steps along byte strings in aligned chunks
      even when there is only a partially defined word at the end (eg,
      optimised strlen).  This is allowed by the memory model of
      modern machines, since an aligned load cannot span two pages and
      thus cannot "partially fault".
      Therefore, a load from a partially-addressible place is allowed
      if all of the following hold:
      - the command-line flag is set [by default, it isn't]
      - it's an aligned load
      - at least one of the addresses in the word *is* valid
      Since this suppresses the addressing error, we avoid false
      negatives by marking bytes undefined when they come from an
      invalid address.
   */

   /* "at least one of the addresses is invalid" */
   //ok = False;
   //for (j = 0; j < szL; j++)
   //   ok |= pessim[j] != V_BITS8_TAINTED; //V_BITS8_UNTAINTED;

   //if (0 == (a & (szB - 1)) && n_addrs_bad < szB) {
   //   /* Exemption applies.  Use the previously computed pessimising
   //      value and return the combined result, but don't flag an
   //      addressing error.  The pessimising value is Defined for valid
   //      addresses and Undefined for invalid addresses. */
   //   /* for assumption that doing bitwise or implements UifU */
   //   tl_assert(V_BIT_TAINTED == 1 && V_BIT_UNTAINTED == 0);
   //   /* (really need "UifU" here...)
   //      vbits[j] UifU= pessim[j]  (is pessimised by it, iow) */
   //   for (j = szL-1; j >= 0; j--)
   //      res[j] |= pessim[j];
   //   return;
   //}

   /* Exemption doesn't apply.  Flag an addressing error in the normal
      way. */
   //MC_(record_address_error)( VG_(get_running_tid)(), a, szB, False );
}

static
#ifndef PERF_FAST_LOADV
INLINE
#endif
ULong tnt_LOADVn_slow ( Addr a, SizeT nBits, Bool bigendian )
{
	
   /* Make up a 64-bit result V word, which contains the loaded data for
      valid addresses and Defined for invalid addresses.  Iterate over
      the bytes in the word, from the most significant down to the
      least. */
   ULong vbits64     = V_BITS64_TAINTED;
   SizeT szB         = nBits / 8;
   SSizeT i;                        // Must be signed.
   SizeT n_addrs_bad = 0;
   Addr  ai;
   //Bool  partial_load_exemption_applies;
   UChar vbits8;
   Bool  ok;

   PROF_EVENT(30, "tnt_LOADVn_slow");

   /* ------------ BEGIN semi-fast cases ------------ */
   /* These deal quickly-ish with the common auxiliary primary map
      cases on 64-bit platforms.  Are merely a speedup hack; can be
      omitted without loss of correctness/functionality.  Note that in
      both cases the "sizeof(void*) == 8" causes these cases to be
      folded out by compilers on 32-bit platforms.  These are derived
      from LOADV64 and LOADV32.
   */
   if (LIKELY(sizeof(void*) == 8
                      && nBits == 64 && VG_IS_8_ALIGNED(a))) {
      SecMap* sm       = get_secmap_for_reading(a);
      UWord   sm_off16 = SM_OFF_16(a);
      UWord   vabits16 = ((UShort*)(sm->vabits8))[sm_off16];
#ifdef DBG_LOAD
      VG_(printf)("tnt_LOADn_slow fully t/ut 0x%lx 0x%x\n", a, vabits16);
#endif
      if (LIKELY(vabits16 == VA_BITS16_UNTAINTED))
         return V_BITS64_UNTAINTED;
      if (LIKELY(vabits16 == VA_BITS16_TAINTED))
         return V_BITS64_TAINTED;
      /* else fall into the slow case */
   }
   if (LIKELY(sizeof(void*) == 8
                      && nBits == 32 && VG_IS_4_ALIGNED(a))) {
      SecMap* sm = get_secmap_for_reading(a);
      UWord sm_off = SM_OFF(a);
      UWord vabits8 = sm->vabits8[sm_off];
      if (LIKELY(vabits8 == VA_BITS8_UNTAINTED))
         return ((UWord)0xFFFFFFFF00000000ULL | (UWord)V_BITS32_UNTAINTED);
      if (LIKELY(vabits8 == VA_BITS8_TAINTED))
         return ((UWord)0xFFFFFFFF00000000ULL | (UWord)V_BITS32_TAINTED);
      /* else fall into slow case */
   }
   /* ------------ END semi-fast cases ------------ */

   tl_assert(nBits == 64 || nBits == 32 || nBits == 16 || nBits == 8);

   for (i = szB-1; i >= 0; i--) {
      PROF_EVENT(31, "tnt_LOADVn_slow(loop)");
      ai = a + byte_offset_w(szB, bigendian, i);
      ok = get_vbits8(ai, &vbits8);
      if (!ok) n_addrs_bad++;
      vbits64 <<= 8;
      vbits64 |= vbits8;
#ifdef DBG_LOAD
      VG_(printf)("tnt_LOADn_slow loop 0x%lx 0x%x\n", ai, vbits8);
#endif
   }

   /* This is a hack which avoids producing errors for code which
      insists in stepping along byte strings in aligned word-sized
      chunks, and there is a partially defined word at the end.  (eg,
      optimised strlen).  Such code is basically broken at least WRT
      semantics of ANSI C, but sometimes users don't have the option
      to fix it, and so this option is provided.  Note it is now
      defaulted to not-engaged.

      A load from a partially-addressible place is allowed if:
      - the command-line flag is set
      - it's a word-sized, word-aligned load
      - at least one of the addresses in the word *is* valid
   */
   //partial_load_exemption_applies
      //= /*TNT_(clo_partial_loads_ok)*/ 0 && szB == VG_WORDSIZE
      //                             && VG_IS_WORD_ALIGNED(a)
      //                             && n_addrs_bad < VG_WORDSIZE;

//   Taintgrind: TODO
//   if (n_addrs_bad > 0 && !partial_load_exemption_applies)
//      TNT_(record_address_error)( VG_(get_running_tid)(), a, szB, False );

#ifdef DBG_LOAD
   if( nBits == 8 &&
       vbits64
//       || (a & 0x80000000)
       )
      VG_(printf)("tnt_LOADn_slow 0x%08lx 0x%lx\n", a, vbits64);
//      VG_(printf)("tnt_LOADn_slow 0x%08lx\n", a);
#endif

   return vbits64;
}


static
#ifndef PERF_FAST_STOREV
INLINE
#endif
void tnt_STOREVn_slow ( Addr a, SizeT nBits, ULong vbytes, Bool bigendian )
{
   SizeT szB = nBits / 8;
   SizeT i, n_addrs_bad = 0;
   UChar vbits8;
   Addr  ai;
   Bool  ok;

   PROF_EVENT(35, "tnt_STOREVn_slow");

   /* ------------ BEGIN semi-fast cases ------------ */
   /* These deal quickly-ish with the common auxiliary primary map
      cases on 64-bit platforms.  Are merely a speedup hack; can be
      omitted without loss of correctness/functionality.  Note that in
      both cases the "sizeof(void*) == 8" causes these cases to be
      folded out by compilers on 32-bit platforms.  These are derived
      from STOREV64 and STOREV32.
   */
   if (LIKELY(sizeof(void*) == 8
                      && nBits == 64 && VG_IS_8_ALIGNED(a))) {
      SecMap* sm       = get_secmap_for_reading(a);
      UWord   sm_off16 = SM_OFF_16(a);
      UWord   vabits16 = ((UShort*)(sm->vabits8))[sm_off16];
      if (LIKELY( !is_distinguished_sm(sm) &&
                          (VA_BITS16_UNTAINTED == vabits16 ||
                           VA_BITS16_TAINTED   == vabits16) )) {
         /* Handle common case quickly: a is suitably aligned, */
         /* is mapped, and is addressible. */
         // Convert full V-bits in register to compact 2-bit form.
         if (LIKELY(V_BITS64_UNTAINTED == vbytes)) {
#ifdef DBG_STORE
            VG_(printf)("tnt_STOREVn_slow likely untainted 0x%lx 0x%lx\n", a, nBits);
#endif
            ((UShort*)(sm->vabits8))[sm_off16] = (UShort)VA_BITS16_UNTAINTED;
            return;
         } else if (V_BITS64_TAINTED == vbytes) {
#ifdef DBG_STORE
            VG_(printf)("tnt_STOREVn_slow tainted 0x%lx 0x%lx\n", a, nBits);
#endif
            ((UShort*)(sm->vabits8))[sm_off16] = (UShort)VA_BITS16_TAINTED;
            return;
         }
         /* else fall into the slow case */
      }
      /* else fall into the slow case */
   }
   if (LIKELY(sizeof(void*) == 8
                      && nBits == 32 && VG_IS_4_ALIGNED(a))) {
      SecMap* sm      = get_secmap_for_reading(a);
      UWord   sm_off  = SM_OFF(a);
      UWord   vabits8 = sm->vabits8[sm_off];
      if (LIKELY( !is_distinguished_sm(sm) &&
                          (VA_BITS8_UNTAINTED   == vabits8 ||
                           VA_BITS8_TAINTED == vabits8) )) {
         /* Handle common case quickly: a is suitably aligned, */
         /* is mapped, and is addressible. */
         // Convert full V-bits in register to compact 2-bit form.
         if (LIKELY(V_BITS32_UNTAINTED == (vbytes & 0xFFFFFFFF))) {
            sm->vabits8[sm_off] = VA_BITS8_UNTAINTED;
            return;
         } else if (V_BITS32_TAINTED == (vbytes & 0xFFFFFFFF)) {
#ifdef DBG_STORE
            VG_(printf)("tnt_STOREVn_slow tainted ffffffff 0x%lx 0x%lx\n", a, nBits);
#endif
            sm->vabits8[sm_off] = VA_BITS8_TAINTED;
            return;
         }
         /* else fall into the slow case */
      }
      /* else fall into the slow case */
   }
   /* ------------ END semi-fast cases ------------ */

   tl_assert(nBits == 64 || nBits == 32 || nBits == 16 || nBits == 8);

   /* Dump vbytes in memory, iterating from least to most significant
      byte.  At the same time establish addressibility of the location. */
   for (i = 0; i < szB; i++) {
      PROF_EVENT(36, "tnt_STOREVn_slow(loop)");
      ai     = a + byte_offset_w(szB, bigendian, i);
      vbits8 = vbytes & 0xff;
      ok     = set_vbits8(ai, vbits8);
      if (!ok) n_addrs_bad++;
      vbytes >>= 8;
#ifdef DBG_STORE
      VG_(printf)("tnt_STOREVn_slow loop 0x%lx 0x%x ok %d\n", ai, vbits8, ok);
#endif
   }

   /* If an address error has happened, report it. */
   // Taintgrind: TODO
//   if (n_addrs_bad > 0)
//      TNT_(record_address_error)( VG_(get_running_tid)(), a, szB, True );
}
                                                                 

/*------------------------------------------------------------*/
/*--- Setting permissions over address ranges.             ---*/
/*------------------------------------------------------------*/

static void set_address_range_perms ( Addr a, SizeT lenT, UWord vabits16,
                                      UWord dsm_num )
{
   UWord    sm_off, sm_off16;
   UWord    vabits2 = vabits16 & 0x3;
   SizeT    lenA, lenB, len_to_next_secmap;
   Addr     aNext;
   SecMap*  sm;
   SecMap** sm_ptr;
   SecMap*  example_dsm;

   //LOG("set_address_range_perms called %08lx %lu %lx\n vabits", a, lenT, vabits16);
   PROF_EVENT(150, "set_address_range_perms");

   /* Check the V+A bits make sense. */
   tl_assert(VA_BITS16_NOACCESS  == vabits16 ||
             VA_BITS16_TAINTED   == vabits16 ||
             VA_BITS16_UNTAINTED == vabits16);

   // This code should never write PDBs;  ensure this.  (See comment above
   // set_vabits2().)
   tl_assert(VA_BITS2_PARTUNTAINTED != vabits2);

   if (lenT == 0)
      return;

   if (lenT > 256 * 1024 * 1024) {
      if (VG_(clo_verbosity) > 0 && !VG_(clo_xml)) {
         const HChar* s = "unknown???";
         if (vabits16 == VA_BITS16_NOACCESS ) s = "noaccess";
         if (vabits16 == VA_BITS16_TAINTED  ) s = "tainted";
         if (vabits16 == VA_BITS16_UNTAINTED) s = "untainted";
         VG_(message)(Vg_UserMsg, "Warning: set address range perms: "
                                  "large range [0x%lx, 0x%lx) (%s)\n",
                                  a, a + lenT, s);
      }
   }

#ifndef PERF_FAST_SARP
   /*------------------ debug-only case ------------------ */
   {
      // Endianness doesn't matter here because all bytes are being set to
      // the same value.
      // Nb: We don't have to worry about updating the sec-V-bits table
      // after these set_vabits2() calls because this code never writes
      // VA_BITS2_PARTUNTAINTED values.
      SizeT i;
      for (i = 0; i < lenT; i++) {
         set_vabits2(a + i, vabits2);
      }
      return;
   }
#endif

   /*------------------ standard handling ------------------ */

   /* Get the distinguished secondary that we might want
      to use (part of the space-compression scheme). */
   example_dsm = &sm_distinguished[dsm_num];

   // Break up total length (lenT) into two parts:  length in the first
   // sec-map (lenA), and the rest (lenB);   lenT == lenA + lenB.
   aNext = start_of_this_sm(a) + SM_SIZE;
   len_to_next_secmap = aNext - a;
   if ( lenT <= len_to_next_secmap ) {
      // Range entirely within one sec-map.  Covers almost all cases.
      PROF_EVENT(151, "set_address_range_perms-single-secmap");
      lenA = lenT;
      lenB = 0;
   } else if (is_start_of_sm(a)) {
      // Range spans at least one whole sec-map, and starts at the beginning
      // of a sec-map; skip to Part 2.
      PROF_EVENT(152, "set_address_range_perms-startof-secmap");
      lenA = 0;
      lenB = lenT;
      goto part2;
   } else {
      // Range spans two or more sec-maps, first one is partial.
      PROF_EVENT(153, "set_address_range_perms-multiple-secmaps");
      lenA = len_to_next_secmap;
      lenB = lenT - lenA;
   }

#ifdef DBG_MEM
   // Taintgrind
   VG_(printf)("set_address_range_perms(0) lenA:0x%x lenB:0x%x\n", (Int)lenA, (Int)lenB);
#endif
	
   //------------------------------------------------------------------------
   // Part 1: Deal with the first sec_map.  Most of the time the range will be
   // entirely within a sec_map and this part alone will suffice.  Also,
   // doing it this way lets us avoid repeatedly testing for the crossing of
   // a sec-map boundary within these loops.
   //------------------------------------------------------------------------

   // If it's distinguished, make it undistinguished if necessary.
   sm_ptr = get_secmap_ptr(a);
   if (is_distinguished_sm(*sm_ptr)) {
      if (*sm_ptr == example_dsm) {
         // Sec-map already has the V+A bits that we want, so skip.
         PROF_EVENT(154, "set_address_range_perms-dist-sm1-quick");
         a    = aNext;
         lenA = 0;
      } else {
         PROF_EVENT(155, "set_address_range_perms-dist-sm1");
         *sm_ptr = copy_for_writing(*sm_ptr);
      }
   }
   sm = *sm_ptr;

   // 1 byte steps
   while (True) {
      if (VG_IS_8_ALIGNED(a)) break;
      if (lenA < 1)           break;
      PROF_EVENT(156, "set_address_range_perms-loop1a");
      sm_off = SM_OFF(a);

#ifdef DBG_MEM
      // Taintgrind
      VG_(printf)("set_address_range_perms(1.1) a:0x%08lx vabits2:0x%lx sm->vabit8[sm_off]:0x%08x\n",
                  a, vabits2, (Int)&(sm->vabits8[sm_off]));
#endif
      insert_vabits2_into_vabits8( a, vabits2, &(sm->vabits8[sm_off]) );
      a    += 1;
      lenA -= 1;
   }
   // 8-aligned, 8 byte steps
   while (True) {
      if (lenA < 8) break;
      PROF_EVENT(157, "set_address_range_perms-loop8a");
      sm_off16 = SM_OFF_16(a);

#ifdef DBG_MEM
      // Taintgrind
      VG_(printf)("set_address_range_perms(1.2) sm->vabits8:0x%08x sm_off16:0x%lx vabits16:0x%08lx\n",
                 (Int) ((UShort*)(sm->vabits8)), sm_off16, vabits16);
#endif
      ((UShort*)(sm->vabits8))[sm_off16] = vabits16;
      a    += 8;
      lenA -= 8;
   }
   // 1 byte steps
   while (True) {
      if (lenA < 1) break;
      PROF_EVENT(158, "set_address_range_perms-loop1b");
      sm_off = SM_OFF(a);

#ifdef DBG_MEM
      // Taintgrind
      VG_(printf)("set_address_range_perms(1.3) a:0x%08lx vabits2:0x%lx sm->vabits8[sm_off]:0x%08x\n",
                  a, vabits2, (Int)&(sm->vabits8[sm_off]));
#endif
      insert_vabits2_into_vabits8( a, vabits2, &(sm->vabits8[sm_off]) );
      a    += 1;
      lenA -= 1;
   }

   // We've finished the first sec-map.  Is that it?
   if (lenB == 0)
      return;

   //------------------------------------------------------------------------
   // Part 2: Fast-set entire sec-maps at a time.
   //------------------------------------------------------------------------
  part2:
   // 64KB-aligned, 64KB steps.
   // Nb: we can reach here with lenB < SM_SIZE
   tl_assert(0 == lenA);
   while (True) {
      if (lenB < SM_SIZE) break;
      tl_assert(is_start_of_sm(a));
      PROF_EVENT(159, "set_address_range_perms-loop64K");
      sm_ptr = get_secmap_ptr(a);
      if (!is_distinguished_sm(*sm_ptr)) {
         PROF_EVENT(160, "set_address_range_perms-loop64K-free-dist-sm");
         // Free the non-distinguished sec-map that we're replacing.  This
         // case happens moderately often, enough to be worthwhile.
         VG_(am_munmap_valgrind)((Addr)*sm_ptr, sizeof(SecMap));
      }
      update_SM_counts(*sm_ptr, example_dsm);
      // Make the sec-map entry point to the example DSM
      *sm_ptr = example_dsm;
      lenB -= SM_SIZE;
      a    += SM_SIZE;
   }

   // We've finished the whole sec-maps.  Is that it?
   if (lenB == 0)
      return;

   //------------------------------------------------------------------------
   // Part 3: Finish off the final partial sec-map, if necessary.
   //------------------------------------------------------------------------

   tl_assert(is_start_of_sm(a) && lenB < SM_SIZE);

   // If it's distinguished, make it undistinguished if necessary.
   sm_ptr = get_secmap_ptr(a);
   if (is_distinguished_sm(*sm_ptr)) {
      if (*sm_ptr == example_dsm) {
         // Sec-map already has the V+A bits that we want, so stop.
         PROF_EVENT(161, "set_address_range_perms-dist-sm2-quick");
         return;
      } else {
         PROF_EVENT(162, "set_address_range_perms-dist-sm2");
         *sm_ptr = copy_for_writing(*sm_ptr);
      }
   }
   sm = *sm_ptr;

   // 8-aligned, 8 byte steps
   while (True) {
      if (lenB < 8) break;
      PROF_EVENT(163, "set_address_range_perms-loop8b");
      sm_off16 = SM_OFF_16(a);
      ((UShort*)(sm->vabits8))[sm_off16] = vabits16;
      a    += 8;
      lenB -= 8;
   }
   // 1 byte steps
   while (True) {
      if (lenB < 1) return;
      PROF_EVENT(164, "set_address_range_perms-loop1c");
      sm_off = SM_OFF(a);
      insert_vabits2_into_vabits8( a, vabits2, &(sm->vabits8[sm_off]) );
      a    += 1;
      lenB -= 1;
   }
}


/* --- Set permissions for arbitrary address ranges --- */

void TNT_(make_mem_noaccess) ( Addr a, SizeT len )
{
   PROF_EVENT(40, "TNT_(make_mem_noaccess)");
//   DEBUG("TNT_(make_mem_noaccess)(%p, %lu)\n", a, len);
   set_address_range_perms ( a, len, VA_BITS16_NOACCESS, SM_DIST_NOACCESS );
//   if (UNLIKELY( TNT_(clo_tnt_level) == 3 ))
//      ocache_sarp_Clear_Origins ( a, len );
}

void TNT_(make_mem_tainted) ( Addr a, SizeT len )//1608
{
   PROF_EVENT(42, "TNT_(make_mem_undefined)");
   #if _SECRETGRIND_
   LOG("make_mem_tainted 0x%lx size %lu\n", a, len);
   #endif
//   DEBUG("TNT_(make_mem_undefined)(%p, %lu)\n", a, len);
   set_address_range_perms ( a, len, VA_BITS16_TAINTED, SM_DIST_TAINTED );
//   if (UNLIKELY( TNT_(clo_tnt_level) == 3 ))
//      ocache_sarp_Clear_Origins ( a, len );
}

void TNT_(make_mem_untainted) ( Addr a, SizeT len )
{
   PROF_EVENT(42, "TNT_(make_mem_untainted)");
//   DEBUG("TNT_(make_mem_untainted)(%p, %lu)\n", a, len);
   set_address_range_perms ( a, len, VA_BITS16_UNTAINTED, SM_DIST_UNTAINTED );
//   if (UNLIKELY( TNT_(clo_tnt_level) == 3 ))
//      ocache_sarp_Clear_Origins ( a, len );
}

#if _SECRETGRIND_

static void TNT_(new_mem_startup)(Addr a, SizeT len, Bool rr, Bool ww, Bool xx, ULong di_handle)
{
	//VgSectKind kind = VG_(DebugInfo_sect_kind)( 0, 0, a);
	//VG_(printf)("%snew_mem_startup 0x%lx %lu rwx=%u%u%u kind:%u%s\n", KGRN, a, len, rr, ww, xx, kind-Vg_SectUnknown,KNRM);
	if ( ww && !xx ) {
		TNT_(mmap_add_region)(a, len);
	}
}

static void TNT_(new_mem_mmap)(Addr a, SizeT len, Bool rr, Bool ww, Bool xx, ULong di_handle)
{
	//VgSectKind kind = VG_(DebugInfo_sect_kind)( 0, 0, a);
	//VG_(printf)("%snew_mem_mmap 0x%lx %lu rwx=%u%u%u kind:%u%s\n", KGRN, a, len, rr, ww, xx, kind, KNRM);
	if ( ww && !xx ) {
		TNT_(mmap_add_region)(a, len);
	}
}

static void TNT_(copy_mem_remap) ( Addr src, Addr dst, SizeT len )
{
	//TNT_(removeHeapRange)(src, len);
	//TNT_(addHeapRange)(dst, len);
	//VG_(printf)("%scopy_mem_remap 0x%lx 0x%lx %lu%s\n", KGRN, src, dst, len, KNRM);
	
	// Note: uncomment the line below if you hit this assertion.
	// The only thing that won't work is the verbose summary, because all the mem blocks
	// recorded until now are being remapped to a new address
	// TODO: add support for this
	tl_assert (0 && "Not supported");
	
	// if original region is one of interest, then add this one too
	if ( TNT_(mmap_is_region)(src) ) {
		TNT_(mmap_add_region)(dst, len);
	}
	TNT_(copy_address_range_state) ( src, dst, len );
}

#endif // _SECRETGRIND_

#if 0//_SECRETGRIND_


void TNT_(new_mem_brk)(Addr a, SizeT len, ThreadId tid)
{
	VG_(printf)("%snew_mem_brk 0x%lx %lu %u%s\n", KGRN, a, len, tid, KNRM);
}

void TNT_(die_mem_brk)(Addr a, SizeT n)
{
    VG_(printf)("%sdie_mem_brk 0x%lx %lu%s\n", KGRN, a, n, KNRM);
}

void TNT_(die_mem_munmap)(Addr a,  SizeT len)
{
	VG_(printf)("%sdie_mem_munmap 0x%lx %lu%s\n", KGRN, a, len, KNRM);
}
	
#endif
/* --- Block-copy permissions (needed for implementing realloc() and
       sys_mremap). --- */

void TNT_(copy_address_range_state) ( Addr src, Addr dst, SizeT len )
{
   SizeT i, j;
   UChar vabits2, vabits8;
   Bool  aligned, nooverlap;

#ifdef DBG_COPY_ADDR_RANGE_STATE
   VG_(printf)( "copy_addr_range_state 0x%x 0x%x 0x%x\n", (Int)src, (Int)dst, (Int)len );
#endif
//   DEBUG("TNT_(copy_address_range_state)\n");
   PROF_EVENT(50, "TNT_(copy_address_range_state)");

   if (len == 0 || src == dst)
      return;

   aligned   = VG_IS_4_ALIGNED(src) && VG_IS_4_ALIGNED(dst);
   nooverlap = src+len <= dst || dst+len <= src;

   if (nooverlap && aligned) {

      /* Vectorised fast case, when no overlap and suitably aligned */
      /* vector loop */
      i = 0;
      while (len >= 4) {
         vabits8 = get_vabits8_for_aligned_word32( src+i ); 
         set_vabits8_for_aligned_word32( dst+i, vabits8 );
         if (LIKELY(VA_BITS8_UNTAINTED == vabits8
                            || VA_BITS8_TAINTED == vabits8
                            || VA_BITS8_NOACCESS == vabits8)) {
            /* do nothing */
         } else { 
            /* have to copy secondary map info */
            if (VA_BITS2_PARTUNTAINTED == get_vabits2( src+i+0 ))
               set_sec_vbits8( dst+i+0, get_sec_vbits8( src+i+0 ) );
            if (VA_BITS2_PARTUNTAINTED == get_vabits2( src+i+1 ))
               set_sec_vbits8( dst+i+1, get_sec_vbits8( src+i+1 ) );
            if (VA_BITS2_PARTUNTAINTED == get_vabits2( src+i+2 ))
               set_sec_vbits8( dst+i+2, get_sec_vbits8( src+i+2 ) );
            if (VA_BITS2_PARTUNTAINTED == get_vabits2( src+i+3 ))
               set_sec_vbits8( dst+i+3, get_sec_vbits8( src+i+3 ) );
         }
         i += 4;
         len -= 4;
      }
      /* fixup loop */
      while (len >= 1) { 
         vabits2 = get_vabits2( src+i ); 
         set_vabits2( dst+i, vabits2 );
         if (VA_BITS2_PARTUNTAINTED == vabits2) {
            set_sec_vbits8( dst+i, get_sec_vbits8( src+i ) );
         }
         i++;
         len--;
      }

   } else {

      /* We have to do things the slow way */
      if (src < dst) {
         for (i = 0, j = len-1; i < len; i++, j--) {
            PROF_EVENT(51, "TNT_(copy_address_range_state)(loop)"); 
            vabits2 = get_vabits2( src+j );
            set_vabits2( dst+j, vabits2 );
            if (VA_BITS2_PARTUNTAINTED == vabits2) {
               set_sec_vbits8( dst+j, get_sec_vbits8( src+j ) );
            }
         }
      }

      if (src > dst) {
         for (i = 0; i < len; i++) {
            PROF_EVENT(52, "TNT_(copy_address_range_state)(loop)"); 
            vabits2 = get_vabits2( src+i );
            set_vabits2( dst+i, vabits2 );
            if (VA_BITS2_PARTUNTAINTED == vabits2) {
               set_sec_vbits8( dst+i, get_sec_vbits8( src+i ) );
            }
         }
      }
   }

}

/*static
void tnt_new_mem_mmap ( Addr a, SizeT len, Bool rr, Bool ww, Bool xx,
                       ULong di_handle )
{
   if (rr || ww || xx)
      TNT_(make_mem_defined)(a, len);
   else
      TNT_(make_mem_noaccess)(a, len);
}*/


//void TNT_(helperc_MAKE_STACK_UNINIT) ( Addr base, UWord len, Addr nia )
//{
//   //UInt otag;
//   tl_assert(sizeof(UWord) == sizeof(SizeT));
//   if (0)
//      VG_(printf)("helperc_MAKE_STACK_UNINIT (%#lx,%lu,nia=%#lx)\n",
//                  base, len, nia );
//
///*   if (UNLIKELY( MC_(clo_mc_level) == 3 )) {
//      UInt ecu = convert_nia_to_ecu ( nia );
//      tl_assert(VG_(is_plausible_ECU)(ecu));
//      otag = ecu | MC_OKIND_STACK;
//   } else {*/
//      tl_assert(nia == 0);
//      //otag = 0;
///*   }*/
//
//   /* Idea is: go fast when
//         * 8-aligned and length is 128
//         * the sm is available in the main primary map
//         * the address range falls entirely with a single secondary map
//      If all those conditions hold, just update the V+A bits by writing
//      directly into the vabits array.  (If the sm was distinguished, this
//      will make a copy and then write to it.)
//   */
//
//   if (LIKELY( len == 128 && VG_IS_8_ALIGNED(base) )) {
//      /* Now we know the address range is suitably sized and aligned. */
//      UWord a_lo = (UWord)(base);
//      UWord a_hi = (UWord)(base + 128 - 1);
//      tl_assert(a_lo < a_hi);             // paranoia: detect overflow
//      if (a_hi <= MAX_PRIMARY_ADDRESS) {
//         // Now we know the entire range is within the main primary map.
//         SecMap* sm    = get_secmap_for_writing_low(a_lo);
//         SecMap* sm_hi = get_secmap_for_writing_low(a_hi);
//         /* Now we know that the entire address range falls within a
//            single secondary map, and that that secondary 'lives' in
//            the main primary map. */
//         if (LIKELY(sm == sm_hi)) {
//            // Finally, we know that the range is entirely within one secmap.
//            UWord   v_off = SM_OFF(a_lo);
//            UShort* p     = (UShort*)(&sm->vabits8[v_off]);
//            p[ 0] = VA_BITS16_TAINTED;
//            p[ 1] = VA_BITS16_TAINTED;
//            p[ 2] = VA_BITS16_TAINTED;
//            p[ 3] = VA_BITS16_TAINTED;
//            p[ 4] = VA_BITS16_TAINTED;
//            p[ 5] = VA_BITS16_TAINTED;
//            p[ 6] = VA_BITS16_TAINTED;
//            p[ 7] = VA_BITS16_TAINTED;
//            p[ 8] = VA_BITS16_TAINTED;
//            p[ 9] = VA_BITS16_TAINTED;
//            p[10] = VA_BITS16_TAINTED;
//            p[11] = VA_BITS16_TAINTED;
//            p[12] = VA_BITS16_TAINTED;
//            p[13] = VA_BITS16_TAINTED;
//            p[14] = VA_BITS16_TAINTED;
//            p[15] = VA_BITS16_TAINTED;
//            return;
//         }
//      }
//   }
//
//   /* 288 bytes (36 ULongs) is the magic value for ELF ppc64. */
//   if (LIKELY( len == 288 && VG_IS_8_ALIGNED(base) )) {
//      /* Now we know the address range is suitably sized and aligned. */
//      UWord a_lo = (UWord)(base);
//      UWord a_hi = (UWord)(base + 288 - 1);
//      tl_assert(a_lo < a_hi);             // paranoia: detect overflow
//      if (a_hi <= MAX_PRIMARY_ADDRESS) {
//         // Now we know the entire range is within the main primary map.
//         SecMap* sm    = get_secmap_for_writing_low(a_lo);
//         SecMap* sm_hi = get_secmap_for_writing_low(a_hi);
//         /* Now we know that the entire address range falls within a
//            single secondary map, and that that secondary 'lives' in
//            the main primary map. */
//         if (LIKELY(sm == sm_hi)) {
//            // Finally, we know that the range is entirely within one secmap.
//            UWord   v_off = SM_OFF(a_lo);
//            UShort* p     = (UShort*)(&sm->vabits8[v_off]);
//            p[ 0] = VA_BITS16_TAINTED;
//            p[ 1] = VA_BITS16_TAINTED;
//            p[ 2] = VA_BITS16_TAINTED;
//            p[ 3] = VA_BITS16_TAINTED;
//            p[ 4] = VA_BITS16_TAINTED;
//            p[ 5] = VA_BITS16_TAINTED;
//            p[ 6] = VA_BITS16_TAINTED;
//            p[ 7] = VA_BITS16_TAINTED;
//            p[ 8] = VA_BITS16_TAINTED;
//            p[ 9] = VA_BITS16_TAINTED;
//            p[10] = VA_BITS16_TAINTED;
//            p[11] = VA_BITS16_TAINTED;
//            p[12] = VA_BITS16_TAINTED;
//            p[13] = VA_BITS16_TAINTED;
//            p[14] = VA_BITS16_TAINTED;
//            p[15] = VA_BITS16_TAINTED;
//            p[16] = VA_BITS16_TAINTED;
//            p[17] = VA_BITS16_TAINTED;
//            p[18] = VA_BITS16_TAINTED;
//            p[19] = VA_BITS16_TAINTED;
//            p[20] = VA_BITS16_TAINTED;
//            p[21] = VA_BITS16_TAINTED;
//            p[22] = VA_BITS16_TAINTED;
//            p[23] = VA_BITS16_TAINTED;
//            p[24] = VA_BITS16_TAINTED;
//            p[25] = VA_BITS16_TAINTED;
//            p[26] = VA_BITS16_TAINTED;
//            p[27] = VA_BITS16_TAINTED;
//            p[28] = VA_BITS16_TAINTED;
//            p[29] = VA_BITS16_TAINTED;
//            p[30] = VA_BITS16_TAINTED;
//            p[31] = VA_BITS16_TAINTED;
//            p[32] = VA_BITS16_TAINTED;
//            p[33] = VA_BITS16_TAINTED;
//            p[34] = VA_BITS16_TAINTED;
//            p[35] = VA_BITS16_TAINTED;
//            return;
//         }
//      }
//   }
//
//   /* else fall into slow case */
////   TNT_(make_mem_undefined_w_otag)(base, len, otag);
//   TNT_(make_mem_tainted)(base, len);
//}


/*------------------------------------------------------------*/
/*--- Functions called directly from generated code:       ---*/
/*--- Load/store handlers.                                 ---*/
/*------------------------------------------------------------*/

/* If any part of '_a' indicated by the mask is 1, either '_a' is not
   naturally '_sz/8'-aligned, or it exceeds the range covered by the
   primary map.  This is all very tricky (and important!), so let's
   work through the maths by hand (below), *and* assert for these
   values at startup. */
#define MASK(_szInBytes) \
   ( ~((0x10000UL-(_szInBytes)) | ((N_PRIMARY_MAP-1) << 16)) )

/* MASK only exists so as to define this macro. */
#define UNALIGNED_OR_HIGH(_a,_szInBits) \
   ((_a) & MASK((_szInBits>>3)))

/* ------------------------ Size = 16 ------------------------ */

static INLINE
void tnt_LOADV_128_or_256 ( /*OUT*/ULong* res,
                           Addr a, SizeT nBits, Bool isBigEndian )
{
   PROF_EVENT(200, "tnt_LOADV_128_or_256");

   #if _SECRETGRIND_
   //TNT_(malloc_update_track_on_load)(a, __FUNCTION__);
   #endif

#ifndef PERF_FAST_LOADV
   tnt_LOADV_128_or_256_slow( res, a, nBits, isBigEndian );
   return;
#else
   {
      UWord   sm_off16, vabits16, j;
      UWord   nBytes  = nBits / 8;
      UWord   nULongs = nBytes / 8;
      SecMap* sm;

      if (UNLIKELY( UNALIGNED_OR_HIGH(a,nBits) )) {
         PROF_EVENT(201, "tnt_LOADV_128_or_256-slow1");
         tnt_LOADV_128_or_256_slow( res, a, nBits, isBigEndian );
         return;
      }

      /* Handle common cases quickly: a (and a+8 and a+16 etc.) is
         suitably aligned, is mapped, and addressible. */
      for (j = 0; j < nULongs; j++) {
         sm       = get_secmap_for_reading_low(a + 8*j);
         sm_off16 = SM_OFF_16(a + 8*j);
         vabits16 = ((UShort*)(sm->vabits8))[sm_off16];

         // Convert V bits from compact memory form to expanded
         // register form.
         if (LIKELY(vabits16 == VA_BITS16_UNTAINTED)) {
            res[j] = V_BITS64_UNTAINTED;
         } else if (LIKELY(vabits16 == VA_BITS16_TAINTED)) {
            res[j] = V_BITS64_TAINTED;
         } else {
            /* Slow case: some block of 8 bytes are not all-defined or
               all-undefined. */
            PROF_EVENT(202, "tnt_LOADV_128_or_256-slow2");
            tnt_LOADV_128_or_256_slow( res, a, nBits, isBigEndian );
            return;
         }
      }
      return;
   }
#endif
}

VG_REGPARM(2) void TNT_(helperc_LOADV256be) ( /*OUT*/V256* res, Addr a )
{
   tnt_LOADV_128_or_256(&res->w64[0], a, 256, True);
}
VG_REGPARM(2) void TNT_(helperc_LOADV256le) ( /*OUT*/V256* res, Addr a )
{
   tnt_LOADV_128_or_256(&res->w64[0], a, 256, False);
}

VG_REGPARM(2) void TNT_(helperc_LOADV128be) ( /*OUT*/V128* res, Addr a )
{
   tnt_LOADV_128_or_256(&res->w64[0], a, 128, True);
}

VG_REGPARM(2) void TNT_(helperc_LOADV128le) ( /*OUT*/V128* res, Addr a )
{
   tnt_LOADV_128_or_256(&res->w64[0], a, 128, False);
}

/* ------------------------ Size = 8 ------------------------ */

static INLINE
ULong tnt_LOADV64 ( Addr a, Bool isBigEndian )
{
   PROF_EVENT(200, "tnt_LOADV64");
#ifdef DBG_LOAD
   VG_(printf)("tnt_LOADV64 0x%lx\n", a);
#endif
	
   #if _SECRETGRIND_
   //TNT_(malloc_update_track_on_load)(a, __FUNCTION__);
   #endif

#ifndef PERF_FAST_LOADV
   return tnt_LOADVn_slow( a, 64, isBigEndian );
#else
   {
      UWord   sm_off16, vabits16;
      SecMap* sm;

      if (UNLIKELY( UNALIGNED_OR_HIGH(a,64) )) {
         PROF_EVENT(201, "tnt_LOADV64-slow1");
         return (ULong)tnt_LOADVn_slow( a, 64, isBigEndian );
      }

      sm       = get_secmap_for_reading_low(a);
      sm_off16 = SM_OFF_16(a);
      vabits16 = ((UShort*)(sm->vabits8))[sm_off16];

      // Handle common case quickly: a is suitably aligned, is mapped, and
      // addressible.
      // Convert V bits from compact memory form to expanded register form.
      if (LIKELY(vabits16 == VA_BITS16_UNTAINTED)) {
         return V_BITS64_UNTAINTED;
      } else if (LIKELY(vabits16 == VA_BITS16_TAINTED)) {
         return V_BITS64_TAINTED;
      } else {
         /* Slow case: the 8 bytes are not all-defined or all-undefined. */
         PROF_EVENT(202, "tnt_LOADV64-slow2");
         return tnt_LOADVn_slow( a, 64, isBigEndian );
      }
   }
#endif
}

#if _SECRETGRIND_
VG_REGPARM(1) ULong TNT_(helperc_LOADV64be_extended) ( Addr a, ULong taint )
{
	if ( !TNT_(clo_taint_df_only) && taint ) { LOG("helperc_LOADV64be_extended addr 0x%lx taint:%llx\n", a, taint); return taint;}
	return TNT_(helperc_LOADV64be)(a);
}

#endif

VG_REGPARM(1) ULong TNT_(helperc_LOADV64be) ( Addr a )
{
   return tnt_LOADV64(a, True);
}


#if _SECRETGRIND_
VG_REGPARM(1) ULong TNT_(helperc_LOADV64le_extended) ( Addr a, ULong taint )
{
	if ( !TNT_(clo_taint_df_only) && taint ) { LOG("helperc_LOADV64le_extended addr 0x%lx taint:%llx\n", a, taint); return taint;}
	return TNT_(helperc_LOADV64le)(a);
}

#endif

VG_REGPARM(1) ULong TNT_(helperc_LOADV64le) ( Addr a )
{
   ULong result = tnt_LOADV64(a, False);

#ifdef DBG_LOAD
   // Taintgrind
   if( result
//       || a & 0x80000000
     )
      VG_(printf)("TNT_(helperc_LOADV64le) 0x%08lx 0x%lx\n", a, result);
//      VG_(printf)("TNT_(helperc_LOADV64le) 64 0x%08lx\n", a);
#endif

   return result;
//   return tnt_LOADV64(a, False);
}


static INLINE
void tnt_STOREV64 ( Addr a, ULong vbits64, Bool isBigEndian )
{ 
   PROF_EVENT(210, "tnt_STOREV64");
	
#ifndef PERF_FAST_STOREV
   // XXX: this slow case seems to be marginally faster than the fast case!
   // Investigate further.
   tnt_STOREVn_slow( a, 64, vbits64, isBigEndian );
#else
   {
      UWord   sm_off16, vabits16;
      SecMap* sm;

      if (UNLIKELY( UNALIGNED_OR_HIGH(a,64) )) {
         PROF_EVENT(211, "tnt_STOREV64-slow1");
#ifdef DBG_STORE
         VG_(printf)("tnt_STOREV64 unlikely 0x%lx 0x%lx\n", a, vbits64);
#endif
         tnt_STOREVn_slow( a, 64, vbits64, isBigEndian );
         return;
      }
#ifdef DBG_STORE
      VG_(printf)("tnt_STOREV64 0x%08lx 0x%lx\n", a, vbits64);
#endif

      sm       = get_secmap_for_reading_low(a);
      sm_off16 = SM_OFF_16(a);
      vabits16 = ((UShort*)(sm->vabits8))[sm_off16];

      if (LIKELY( !is_distinguished_sm(sm) &&
                          (VA_BITS16_UNTAINTED   == vabits16 ||
                           VA_BITS16_TAINTED == vabits16) ))
      {
         /* Handle common case quickly: a is suitably aligned, */
         /* is mapped, and is addressible. */
         // Convert full V-bits in register to compact 2-bit form.
         if (V_BITS64_UNTAINTED == vbits64) {
            ((UShort*)(sm->vabits8))[sm_off16] = (UShort)VA_BITS16_UNTAINTED;
         } else if (V_BITS64_TAINTED == vbits64) {
            ((UShort*)(sm->vabits8))[sm_off16] = (UShort)VA_BITS16_TAINTED;
#ifdef DBG_STORE
            VG_(printf)("tnt_STOREV64 V_BITS64_TAINTED\n");
#endif
         } else {
            /* Slow but general case -- writing partially defined bytes. */
            PROF_EVENT(212, "tnt_STOREV64-slow2");
            tnt_STOREVn_slow( a, 64, vbits64, isBigEndian );
         }
      } else {
         /* Slow but general case. */
         PROF_EVENT(213, "tnt_STOREV64-slow3");
         tnt_STOREVn_slow( a, 64, vbits64, isBigEndian );
      }
   }
#endif

	
}

VG_REGPARM(1) void TNT_(helperc_STOREV64be) ( Addr a, ULong vbits64 )
{ 
#ifdef DBG_STORE
   // Taintgrind
   if( vbits64
//       || a & 0x80000000
     )
      VG_(printf)("TNT_(helperc_STOREV64be) 0x%08lx 0x%lx\n", a, vbits64);
//      VG_(printf)("TNT_(helperc_STOREV64be) 64 0x%08lx\n", a);
#endif

	#if _SECRETGRIND_
	//if ( TNT_(malloc_finish_tracking)(a) == True) {
	//	vbits64 = 0x0; // remove taint
	//}
	#endif
	
   tnt_STOREV64(a, vbits64, True);
}
VG_REGPARM(1) void TNT_(helperc_STOREV64le) ( Addr a, ULong vbits64 )
{ 
#ifdef DBG_STORE
   // Taintgrind
   if( vbits64
//      || a & 0x80000000
     )
      VG_(printf)("TNT_(helperc_STOREV64le) 0x%08lx 0x%lx\n", a, vbits64);
//      VG_(printf)("TNT_(helperc_STOREV64le) 64 0x%08lx\n", a);
#endif

	#if _SECRETGRIND_
	//if ( TNT_(malloc_finish_tracking)(a) == True) {
	//	vbits64 = 0x0; // remove taint
	//}
	#endif
	
   tnt_STOREV64(a, vbits64, False);
}

/* ------------------------ Size = 4 ------------------------ */

static INLINE
UWord tnt_LOADV32 ( Addr a, Bool isBigEndian )
{
	
   PROF_EVENT(220, "tnt_LOADV32");

   #if _SECRETGRIND_
   //TNT_(malloc_update_track_on_load)(a, __FUNCTION__);
   #endif

#ifndef PERF_FAST_LOADV
   return (UWord)tnt_LOADVn_slow( a, 32, isBigEndian );
#else
   {
      UWord   sm_off, vabits8;
      SecMap* sm;

      if (UNLIKELY( UNALIGNED_OR_HIGH(a,32) )) {
         PROF_EVENT(221, "tnt_LOADV32-slow1");
         return (UWord)tnt_LOADVn_slow( a, 32, isBigEndian );
      }

      sm      = get_secmap_for_reading_low(a);
      sm_off  = SM_OFF(a);
      vabits8 = sm->vabits8[sm_off];

      // Handle common case quickly: a is suitably aligned, is mapped, and the
      // entire word32 it lives in is addressible.
      // Convert V bits from compact memory form to expanded register form.
      // For 64-bit platforms, set the high 32 bits of retval to 1 (undefined).
      // Almost certainly not necessary, but be paranoid.
      if (LIKELY(vabits8 == VA_BITS8_UNTAINTED)) {
         return ((UWord)0xFFFFFFFF00000000ULL | (UWord)V_BITS32_UNTAINTED);
      } else if (LIKELY(vabits8 == VA_BITS8_TAINTED)) {
         return ((UWord)0xFFFFFFFF00000000ULL | (UWord)V_BITS32_TAINTED);
      } else {
         /* Slow case: the 4 bytes are not all-defined or all-undefined. */
         PROF_EVENT(222, "tnt_LOADV32-slow2");
         return (UWord)tnt_LOADVn_slow( a, 32, isBigEndian );
      }
   }
#endif
}

#if _SECRETGRIND_
VG_REGPARM(1) UWord TNT_(helperc_LOADV32be_extended) ( Addr a, UWord taint )
{
	if ( !TNT_(clo_taint_df_only) && taint ) { LOG("helperc_LOADV32be_extended addr 0x%lx taint:%lx\n", a, taint); return taint;}
	return TNT_(helperc_LOADV32be)(a);
}

#endif

VG_REGPARM(1) UWord TNT_(helperc_LOADV32be) ( Addr a )
{
   UWord result = tnt_LOADV32(a, True);
#ifdef DBG_LOAD
   // Taintgrind
   if( result
//       || a & 0x80000000
     )
      VG_(printf)("TNT_(helperc_LOADV32be) 0x%08lx 0x%lx\n", a, result);
//      VG_(printf)("TNT_(helperc_LOADV32be) 32 0x%08lx\n", a);
#endif

   return result;
//   return tnt_LOADV32(a, True);
}

#if _SECRETGRIND_
VG_REGPARM(1) UWord TNT_(helperc_LOADV32le_extended) ( Addr a, UWord taint )
{
	if ( !TNT_(clo_taint_df_only) && taint ) { LOG("helperc_LOADV32le_extended addr 0x%lx taint:%lx\n", a, taint); return taint;}
	return TNT_(helperc_LOADV32le)(a);
}

#endif

VG_REGPARM(1) UWord TNT_(helperc_LOADV32le) ( Addr a )
{
   UWord result = tnt_LOADV32(a, False);

#ifdef DBG_LOAD
   // Taintgrind
   if( result
//       || a & 0x80000000
     )
      VG_(printf)("TNT_(helperc_LOADV32le) 0x%08lx 0x%lx\n", a, result);
//      VG_(printf)("TNT_(helperc_LOADV32le) 32 0x%08lx\n", a);
#endif

   return result;
//   return tnt_LOADV32(a, False);
}


static INLINE
void tnt_STOREV32 ( Addr a, UWord vbits32, Bool isBigEndian )
{
	
   PROF_EVENT(230, "tnt_STOREV32");
   
#ifndef PERF_FAST_STOREV
   tnt_STOREVn_slow( a, 32, (ULong)vbits32, isBigEndian );
#else
   {
      UWord   sm_off, vabits8;
      SecMap* sm;

      if (UNLIKELY( UNALIGNED_OR_HIGH(a,32) )) {
         PROF_EVENT(231, "tnt_STOREV32-slow1");
         tnt_STOREVn_slow( a, 32, (ULong)vbits32, isBigEndian );
         return;
      }

      sm      = get_secmap_for_reading_low(a);
      sm_off  = SM_OFF(a);
      vabits8 = sm->vabits8[sm_off];

      // Cleverness:  sometimes we don't have to write the shadow memory at
      // all, if we can tell that what we want to write is the same as what is
      // already there.  The 64/16/8 bit cases also have cleverness at this
      // point, but it works a little differently to the code below.
      if (V_BITS32_UNTAINTED == vbits32) {
         if (vabits8 == (UInt)VA_BITS8_UNTAINTED) {
            return;
         } else if (!is_distinguished_sm(sm) && VA_BITS8_TAINTED == vabits8) {
            sm->vabits8[sm_off] = (UInt)VA_BITS8_UNTAINTED;
         } else {
            // not defined/undefined, or distinguished and changing state
            PROF_EVENT(232, "tnt_STOREV32-slow2");
            tnt_STOREVn_slow( a, 32, (ULong)vbits32, isBigEndian );
         }
      } else if (V_BITS32_TAINTED == vbits32) {
         if (vabits8 == (UInt)VA_BITS8_TAINTED) {
            return;
         } else if (!is_distinguished_sm(sm) && VA_BITS8_UNTAINTED == vabits8) {
            sm->vabits8[sm_off] = (UInt)VA_BITS8_TAINTED;
         } else {
            // not defined/undefined, or distinguished and changing state
            PROF_EVENT(233, "tnt_STOREV32-slow3");
            tnt_STOREVn_slow( a, 32, (ULong)vbits32, isBigEndian );
         }
      } else {
         // Partially defined word
         PROF_EVENT(234, "tnt_STOREV32-slow4");
         tnt_STOREVn_slow( a, 32, (ULong)vbits32, isBigEndian );
      }
   }
#endif
}

VG_REGPARM(2) void TNT_(helperc_STOREV32be) ( Addr a, UWord vbits32 )
{  
#ifdef DBG_STORE
   // Taintgrind
   if( vbits32
//       || a & 0x80000000
     )
      VG_(printf)("TNT_(helperc_STOREV32be) 0x%08lx 0x%lx\n", a, vbits32);
//      VG_(printf)("TNT_(helperc_STOREV32be) 32 0x%08lx\n", a);
#endif

	#if _SECRETGRIND_
	//if (TNT_(malloc_finish_tracking)(a) == True) {
	//	vbits32 = 0x0; // remove taint
	//}
	#endif
   tnt_STOREV32(a, vbits32, True);
}


VG_REGPARM(2) void TNT_(helperc_STOREV32le) ( Addr a, UWord vbits32 )
{ 
#ifdef DBG_STORE
   // Taintgrind
   if( vbits32
//       || a & 0x80000000
     )
      VG_(printf)("TNT_(helperc_STOREV32le) 0x%08lx 0x%lx\n", a, vbits32);
//      VG_(printf)("TNT_(helperc_STOREV32le) 32 0x%08lx\n", a);
#endif

	#if _SECRETGRIND_
	//if (TNT_(malloc_finish_tracking)(a) == True) {
	//	vbits32 = 0x0; // remove taint
	//}
	#endif
   tnt_STOREV32(a, vbits32, False);
}


/* ------------------------ Size = 2 ------------------------ */

static INLINE
UWord tnt_LOADV16 ( Addr a, Bool isBigEndian )
{
   PROF_EVENT(240, "tnt_LOADV16");

   #if _SECRETGRIND_
   // note: probably useless since address are 32/64 bits
   //TNT_(malloc_update_track_on_load)(a, __FUNCTION__);
   #endif
   
#ifndef PERF_FAST_LOADV
   return (UWord)tnt_LOADVn_slow( a, 16, isBigEndian );
#else
   {
      UWord   sm_off, vabits8;
      SecMap* sm;

      if (UNLIKELY( UNALIGNED_OR_HIGH(a,16) )) {
         PROF_EVENT(241, "tnt_LOADV16-slow1");
         return (UWord)tnt_LOADVn_slow( a, 16, isBigEndian );
      }

      sm      = get_secmap_for_reading_low(a);
      sm_off  = SM_OFF(a);
      vabits8 = sm->vabits8[sm_off];
      // Handle common case quickly: a is suitably aligned, is mapped, and is
      // addressible.
      // Convert V bits from compact memory form to expanded register form
      if      (vabits8 == VA_BITS8_UNTAINTED  ) { return V_BITS16_UNTAINTED;   }
      else if (vabits8 == VA_BITS8_TAINTED) { return V_BITS16_TAINTED; }
      else {
         // The 4 (yes, 4) bytes are not all-defined or all-undefined, check
         // the two sub-bytes.
         UChar vabits4 = extract_vabits4_from_vabits8(a, vabits8);
         if      (vabits4 == VA_BITS4_UNTAINTED  ) { return V_BITS16_UNTAINTED;   }
         else if (vabits4 == VA_BITS4_TAINTED) { return V_BITS16_TAINTED; }
         else {
            /* Slow case: the two bytes are not all-defined or all-undefined. */
            PROF_EVENT(242, "tnt_LOADV16-slow2");
            return (UWord)tnt_LOADVn_slow( a, 16, isBigEndian );
         }
      }
   }
#endif
}

#if _SECRETGRIND_
VG_REGPARM(1) UWord TNT_(helperc_LOADV16be_extended) ( Addr a, UWord taint )
{
	if ( !TNT_(clo_taint_df_only) && taint ) { LOG("helperc_LOADV16be_extended addr 0x%lx taint:%lx\n", a, taint); return taint;}
	return TNT_(helperc_LOADV16be)(a);
}

#endif

VG_REGPARM(1) UWord TNT_(helperc_LOADV16be) ( Addr a )
{
   return tnt_LOADV16(a, True);
}

#if _SECRETGRIND_
VG_REGPARM(1) UWord TNT_(helperc_LOADV16le_extended) ( Addr a, UWord taint )
{
	if ( !TNT_(clo_taint_df_only) && taint ) { LOG("helperc_LOADV16le_extended addr 0x%lx taint:%lx\n", a, taint); return taint;}
	return TNT_(helperc_LOADV16le)(a);
}

#endif

VG_REGPARM(1) UWord TNT_(helperc_LOADV16le) ( Addr a )
{ 
   UWord result = tnt_LOADV16(a, False);

#ifdef DBG_LOAD
   // Taintgrind
   if( result
//       || a & 0x80000000
     )
      VG_(printf)("TNT_(helperc_LOADV16le) 0x%08lx 0x%lx\n", a, result);
//      VG_(printf)("TNT_(helperc_LOADV16le) 16 0x%08lx\n", a);
#endif

   return result;
//   return tnt_LOADV16(a, False);
}


static INLINE
void tnt_STOREV16 ( Addr a, UWord vbits16, Bool isBigEndian )
{
	if ( (a >= 0x5ae0f77 && a <= 0x5ae0faf) ) { tl_assert (0); }
   PROF_EVENT(250, "tnt_STOREV16");

#ifndef PERF_FAST_STOREV
   tnt_STOREVn_slow( a, 16, (ULong)vbits16, isBigEndian );
#else
   {
      UWord   sm_off, vabits8;
      SecMap* sm;

      if (UNLIKELY( UNALIGNED_OR_HIGH(a,16) )) {
         PROF_EVENT(251, "tnt_STOREV16-slow1");
         tnt_STOREVn_slow( a, 16, (ULong)vbits16, isBigEndian );
         return;
      }

      sm      = get_secmap_for_reading_low(a);
      sm_off  = SM_OFF(a);
      vabits8 = sm->vabits8[sm_off];
      if (LIKELY( !is_distinguished_sm(sm) &&
                          (VA_BITS8_UNTAINTED   == vabits8 ||
                           VA_BITS8_TAINTED == vabits8) ))
      {
         /* Handle common case quickly: a is suitably aligned, */
         /* is mapped, and is addressible. */
         // Convert full V-bits in register to compact 2-bit form.
         if (V_BITS16_UNTAINTED == vbits16) {
            insert_vabits4_into_vabits8( a, VA_BITS4_UNTAINTED ,
                                         &(sm->vabits8[sm_off]) );
         } else if (V_BITS16_TAINTED == vbits16) {
            insert_vabits4_into_vabits8( a, VA_BITS4_TAINTED,
                                         &(sm->vabits8[sm_off]) );
         } else {
            /* Slow but general case -- writing partially defined bytes. */
            PROF_EVENT(252, "tnt_STOREV16-slow2");
            tnt_STOREVn_slow( a, 16, (ULong)vbits16, isBigEndian );
         }
      } else {
         /* Slow but general case. */
         PROF_EVENT(253, "tnt_STOREV16-slow3");
         tnt_STOREVn_slow( a, 16, (ULong)vbits16, isBigEndian );
      }
   }
#endif
}

VG_REGPARM(2) void TNT_(helperc_STOREV16be) ( Addr a, UWord vbits16 )
{ 
#ifdef DBG_STORE
   // Taintgrind
   if( vbits16
//       || a & 0x80000000
     )
      VG_(printf)("TNT_(helperc_STOREV16be) 0x%08lx 0x%lx\n", a, vbits16);
//      VG_(printf)("TNT_(helperc_STOREV16be) 16 0x%08lx\n", a);
#endif

	#if _SECRETGRIND_
	//if (TNT_(malloc_finish_tracking)(a) == True) {
	//	vbits16 = 0x0; // remove taint
	//}
	#endif
	
   tnt_STOREV16(a, vbits16, True);
}
VG_REGPARM(2) void TNT_(helperc_STOREV16le) ( Addr a, UWord vbits16 )
{ 
#ifdef DBG_STORE
   // Taintgrind
   if( vbits16
//       || a & 0x80000000
     )
      VG_(printf)("TNT_(helperc_STOREV16le) 0x%08lx 0x%lx\n", a, vbits16);
//      VG_(printf)("TNT_(helperc_STOREV16le) 16 0x%08lx\n", a);
#endif

	#if _SECRETGRIND_
	//if (TNT_(malloc_finish_tracking)(a) == True) {
	//	vbits16 = 0x0; // remove taint
	//}
	#endif
   tnt_STOREV16(a, vbits16, False);
}


/* ------------------------ Size = 1 ------------------------ */
/* Note: endianness is irrelevant for size == 1 */
#if _SECRETGRIND_
VG_REGPARM(1)
UWord TNT_(helperc_LOADV8_extended) ( Addr a, UWord taint )
{ 
	if ( !TNT_(clo_taint_df_only) && taint ) { LOG("helperc_LOADV8_extended addr 0x%lx taint:%lx\n", a, taint); return taint;}
	return TNT_(helperc_LOADV8)(a);
}
#endif

VG_REGPARM(1)
UWord TNT_(helperc_LOADV8) ( Addr a )
{ 
   PROF_EVENT(260, "tnt_LOADV8");
   
   //if (a== 0x401110) { LOG("helperc_LOADV8 0x%lx\n", a); return 0xff; }
   #if _SECRETGRIND_
   // Note: probably useless since address are 32/64 bits
   //TNT_(malloc_update_track_on_load)(a, __FUNCTION__);
   #endif
   
#ifndef PERF_FAST_LOADV
   return (UWord)tnt_LOADVn_slow( a, 8, False/*irrelevant*/ );
#else
   {
      UWord   sm_off, vabits8;
      SecMap* sm;

      if (UNLIKELY( UNALIGNED_OR_HIGH(a,8) )) {
         PROF_EVENT(261, "tnt_LOADV8-slow1");
         return (UWord)tnt_LOADVn_slow( a, 8, False/*irrelevant*/ );
      }

      sm      = get_secmap_for_reading_low(a);
      sm_off  = SM_OFF(a);
      vabits8 = sm->vabits8[sm_off];
      // Convert V bits from compact memory form to expanded register form
      // Handle common case quickly: a is mapped, and the entire
      // word32 it lives in is addressible.
      if      (vabits8 == VA_BITS8_UNTAINTED  ) { return V_BITS8_UNTAINTED;   }
      else if (vabits8 == VA_BITS8_TAINTED) {

#ifdef DBG_LOAD
         // Taintgrind
         VG_(printf)("TNT_(helperc_LOADV8) 0x%08lx 0x%x\n", a, V_BITS8_TAINTED);
         //VG_(printf)("TNT_(helperc_LOADV8) 8 0x%08lx\n", a);
#endif

         return V_BITS8_TAINTED; }
      else {
         // The 4 (yes, 4) bytes are not all-defined or all-undefined, check
         // the single byte.
         UChar vabits2 = extract_vabits2_from_vabits8(a, vabits8);
         if      (vabits2 == VA_BITS2_UNTAINTED  ) { return V_BITS8_UNTAINTED;   }
         else if (vabits2 == VA_BITS2_TAINTED) {

#ifdef DBG_LOAD
         // Taintgrind
         VG_(printf)("TNT_(helperc_LOADV8) 0x%08lx 0x%x\n", a, V_BITS8_TAINTED);
         //VG_(printf)("TNT_(helperc_LOADV8) 8 0x%08lx\n", a);
#endif

         return V_BITS8_TAINTED; }
         else {
            /* Slow case: the byte is not all-defined or all-undefined. */
            PROF_EVENT(262, "tnt_LOADV8-slow2");
            return (UWord)tnt_LOADVn_slow( a, 8, False/*irrelevant*/ );
         }
      }
   }
#endif
}


VG_REGPARM(2)
void TNT_(helperc_STOREV8) ( Addr a, UWord vbits8 )
{ 
#ifdef DBG_STORE
   // Taintgrind
   if( vbits8
//       || a & 0x80000000
     )
      VG_(printf)("TNT_(helperc_STOREV8) 0x%08lx 0x%lx\n", a, vbits8);
//      VG_(printf)("TNT_(helperc_STOREV8) 8 0x%08lx\n", a);
#endif
	
   PROF_EVENT(270, "tnt_STOREV8");

#ifndef PERF_FAST_STOREV
   tnt_STOREVn_slow( a, 8, (ULong)vbits8, False/*irrelevant*/ );
#else
   {
      UWord   sm_off, vabits8;
      SecMap* sm;

      if (UNLIKELY( UNALIGNED_OR_HIGH(a,8) )) {
         PROF_EVENT(271, "tnt_STOREV8-slow1");
         tnt_STOREVn_slow( a, 8, (ULong)vbits8, False/*irrelevant*/ );
         return;
      }

      sm      = get_secmap_for_reading_low(a);
      sm_off  = SM_OFF(a);
      vabits8 = sm->vabits8[sm_off];
      if (LIKELY
            ( !is_distinguished_sm(sm) &&
              ( (VA_BITS8_UNTAINTED == vabits8 || VA_BITS8_TAINTED == vabits8)
             || (VA_BITS2_NOACCESS != extract_vabits2_from_vabits8(a, vabits8))
              )
            )
         )
      {
         /* Handle common case quickly: a is mapped, the entire word32 it
            lives in is addressible. */
         // Convert full V-bits in register to compact 2-bit form.
         if (V_BITS8_UNTAINTED == vbits8) {
            insert_vabits2_into_vabits8( a, VA_BITS2_UNTAINTED,
                                          &(sm->vabits8[sm_off]) );
         } else if (V_BITS8_TAINTED == vbits8) {
            insert_vabits2_into_vabits8( a, VA_BITS2_TAINTED,
                                          &(sm->vabits8[sm_off]) );
         } else {
            /* Slow but general case -- writing partially defined bytes. */
            PROF_EVENT(272, "tnt_STOREV8-slow2");
            tnt_STOREVn_slow( a, 8, (ULong)vbits8, False/*irrelevant*/ );
         }
      } else {
         /* Slow but general case. */
         PROF_EVENT(273, "tnt_STOREV8-slow3");
         tnt_STOREVn_slow( a, 8, (ULong)vbits8, False/*irrelevant*/ );
      }
   }
#endif
}

Int ctoi_test( HChar c ){
   switch(c){
   case '0':
   case '1':
   case '2':
   case '3':
   case '4':
   case '5':
   case '6':
   case '7':
   case '8':
   case '9':
   case 'a':
   case 'A':
   case 'b':
   case 'B':
   case 'c':
   case 'C':
   case 'd':
   case 'D':
   case 'e':
   case 'E':
   case 'f':
   case 'F':
      return 1;
   default:
      return 0;
   }
}

Int ctoi( HChar c ){
   tl_assert( ctoi_test(c) );

   switch(c){
   case '0':
      return 0;
   case '1':
      return 1;
   case '2':
      return 2;
   case '3':
      return 3;
   case '4':
      return 4;
   case '5':
      return 5;
   case '6':
      return 6;
   case '7':
      return 7;
   case '8':
      return 8;
   case '9':
      return 9;
   case 'a':
   case 'A':
      return 0xa;
   case 'b':
   case 'B':
      return 0xb;
   case 'c':
   case 'C':
      return 0xc;
   case 'd':
   case 'D':
      return 0xd;
   case 'e':
   case 'E':
      return 0xe;
   case 'f':
   case 'F':
      return 0xf;
   default: {
      tl_assert(0);
      break;
   }
   }
   return -1; // unreachable
}

Int atoi( HChar *s ){
   Int result = 0;
   Int multiplier = 1;
   Int i;

   for( i = VG_(strlen)(s)-1; i>=0; i-- ){
      tl_assert( ctoi_test( s[i] ) );
      result += multiplier * ctoi(s[i]);
      // Assume decimal
      multiplier *= 10;
   }

   return result;
}

/*-----------------------------------------------
   Helper functions for taint information flows
-------------------------------------------------*/

// tmp variables go from t0, t1, t2,..., t255
// reg variables go from r0, r4, r8,..., r320
// see libvex_guest_amd64.h
#define TI_MAX 1024
#define RI_MAX 740 
// These arrays are initialised to 0 in TNT_(clo_post_init)
// Tmp variable indices; the MSB indicates whether it's tainted (1) or not (0)
UInt  ti[TI_MAX];
// Tmp variable values
ULong tv[TI_MAX];
// Reg variable indices; values are obtained in real-time
UInt  ri[RI_MAX];


struct   myStringArray lvar_s;
int      lvar_i[STACK_SIZE];

////////////////////////////////
// Start of SOAAP-related data
////////////////////////////////
HChar* client_binary_name = NULL;

UInt shared_fds[FD_MAX];
UInt persistent_sandbox_nesting_depth = 0;
UInt ephemeral_sandbox_nesting_depth = 0;
Bool have_created_sandbox = False;

struct myStringArray shared_vars;
UInt shared_vars_perms[VAR_MAX];
HChar* next_shared_variable_to_update = NULL;

Bool allowed_syscalls[SYSCALLS_MAX];

UInt callgate_nesting_depth = 0;
////////////////////////////////
// End of SOAAP-related data
////////////////////////////////

Int get_and_check_reg( HChar *reg ){

   Int regnum = atoi( reg );
//   if( regnum % 4 ){
//      VG_(printf)("get_and_check_tvar: regnum %d mod 4 != 0\n", regnum );
//      tl_assert( !( regnum % 4 ) );
//   }
   if( regnum >= RI_MAX ){
      VG_(printf)("get_and_check_reg: regnum %d >= %d\n", regnum, RI_MAX );
      tl_assert( regnum < RI_MAX );
   }

   return regnum;
}

Int get_and_check_tvar( HChar *tmp ){

   Int tmpnum = atoi( tmp );
   tl_assert( tmpnum < TI_MAX );
   return tmpnum;
}

#if !_SECRETGRIND_
void infer_client_binary_name(UInt pc) {

   if (client_binary_name == NULL) {
      DebugInfo* di = VG_(find_DebugInfo)(pc);
      if (di && VG_(strcmp)(VG_(DebugInfo_get_soname)(di), "NONE") == 0) {
		 #if _SECRETGRIND_
         LOG("client_binary_name: %s\n", VG_(DebugInfo_get_filename)(di));
         #endif
         tl_assert (client_binary_name==0);
         client_binary_name = (HChar*)VG_(malloc)("client_binary_name",sizeof(HChar)*(VG_(strlen)(VG_(DebugInfo_get_filename)(di)+1)));
         VG_(strcpy)(client_binary_name, VG_(DebugInfo_get_filename)(di));
      }  
   }

}
#endif

// If stdout is not a tty, don't highlight text
int istty = 0;

/**** 32-bit helpers ****/

// macros
#define _ti(ltmp) ti[ltmp] & 0x7fffffff
#define is_tainted(ltmp) (ti[ltmp] >> 31)




//LOG("HVAR %s\n", __FUNCTION__); 
#if _SECRETGRIND_
static void TNT_(print_TaintExeContext)( ExeContext* ec, UInt n_ips, Int fixed );

   #define H_VAR \
	HChar varname[256] = "\0"; \
	HChar vardname[256] = "\0"; \
	LOG("HVAR from %s\n", __FUNCTION__); \
	TNT_(describe_data)(address, varname, sizeof(varname), vardname, sizeof(vardname), __FUNCTION__, TNT_(size_of_taint)(taint), False); 
   /*
	const SizeT ll = TNT_(size_of_taint)(taint); \
    if ( VG_(addr_is_in_block)( 0xffeffd6a0, address, ll, 0 )  ) { \
    ExeContext* e = VG_(record_ExeContext)( VG_(get_running_tid)(), 0 ); \
    TNT_(print_TaintExeContext)( e, VG_(get_ExeContext_n_ips)(e) ); \
	VG_(printf)("H_VAR [0x%lx 0x%lx] '%s' '%s'\n", (Addr)address, (Addr)address+ll-1, __FUNCTION__, varname); \
   }*/
   // 0xffeffd670, 0xffeffd658, 0xffeffd668
   
   #define H_VAR_128or256(n) \
   HChar varname[256] = "\0"; \
   HChar vardname[256] = "\0"; \
   LOG("H_VAR_128or256 from %s\n", __FUNCTION__); \
   TNT_(describe_data)(address, varname, sizeof(varname), vardname, sizeof(vardname), __FUNCTION__, loadSize*n, False);
   
   #define H_EXIT_BASE(T)	if ( ! (TNT_(clo_summary_verbose) && (T)) ) { 	/* if verbose summary and tainted, always proceed. Note: don't proceeed if not tainted as it's not needed by summary */  \
								if ( !TNT_(clo_trace) )	{ return; }		/* if no trace , stop */						\
								if ( TNT_(clo_trace_taint_only) ) {			/* if all instructions, always proceeed */		\
									if ( !(T) ) { return; }				/* only proceed if instructions are tainted */	\
								}																							\
							}
   //if( !(TNT_(clo_summary_verbose) || TNT_(clo_trace)) || !( (T) || !TNT_(clo_trace_taint_only) ) ) return;
   
   #define H_EXIT_EARLY_LDST	H_EXIT_BASE( taint || is_tainted(atmp) )
   #define H_EXIT_EARLY		 	H_EXIT_BASE( taint )
   
   #define H_VEX_IR_DISPLAY		if ( TNT_(clo_show_vex) ) { \
									ppIRStmt(clone);			\
									VG_(printf)("\n");		\
								} 
   
   #define HXX_PC	UInt  pc = VG_(get_IP)( VG_(get_running_tid)() ); \
					HChar fnname[FNNAME_MAX]; \
					HChar aTmp[128]; \
					VG_(describe_IP) ( pc, fnname, FNNAME_MAX, NULL ); 
   
   #define H32_PC	HXX_PC
   #define H64_PC	HXX_PC
   							
#else
   #define H_VAR \
   HChar varname[256]; \
   ThreadId tid = VG_(get_running_tid()); \
   VG_(memset)( varname, 0, sizeof(varname) ); \
   enum VariableType type = 0; \
   enum VariableLocation var_loc; \
   TNT_(describe_data)(address, varname, sizeof(varname), &type, &var_loc); \
   TNT_(check_var_access)(tid, varname, VAR_WRITE, type, var_loc);
   
   #define H_EXIT_EARLY \
   if(!TNT_(do_print) && taint)  TNT_(do_print) = 1; \
   if(!TNT_(do_print))  return; \
   if(!(TNT_(clo_trace_taint_only) && taint) && TNT_(clo_trace_taint_only)) return;


   #define H_EXIT_EARLY_LDST \
   if(!TNT_(do_print) && taint)  TNT_(do_print) = 1;  \
   if(!TNT_(do_print))  return; \
   if(!(TNT_(clo_trace_taint_only) && (taint | is_tainted(atmp))) && TNT_(clo_trace_taint_only)) return;
   
   #define H32_PC \
   UInt  pc = VG_(get_IP)( VG_(get_running_tid)() ); \
   HChar fnname[FNNAME_MAX]; \
   HChar aTmp[128]; \
   infer_client_binary_name(pc); \
   VG_(describe_IP) ( pc, fnname, FNNAME_MAX, NULL );

   #define H64_PC \
   ULong pc = VG_(get_IP)( VG_(get_running_tid)() ); \
   HChar fnname[FNNAME_MAX]; \
   HChar aTmp[128]; \
   infer_client_binary_name(pc); \
   VG_(describe_IP) ( pc, fnname, FNNAME_MAX, NULL );
   
#endif



#define H_WRTMP_BOOKKEEPING \
   UInt ltmp = clone->Ist.WrTmp.tmp; \
   if ( ltmp >= TI_MAX ) { \
      VG_(printf)("ltmp %d\n", ltmp); \
   } \
   tl_assert( ltmp < TI_MAX ); \
   ti[ltmp]++; \
   if ( taint ) { \
      ti[ltmp] |= 0x80000000; \
  } \
   else \
      ti[ltmp] &= 0x7fffffff; \
   tv[ltmp] = value; 

// laurent: took this idea from https://github.com/dpoetzsch/taintgrind/blob/6625e5e3c1d2c45253a888036dfe62f6d7b7f54d/tnt_main.c
#define H_PID	VG_(getpid)()

#if _SECRETGRIND_

#	define H_WRTMP_BOOKKEEPING_128or256 \
   UInt ltmp = clone->Ist.WrTmp.tmp; \
   if ( ltmp >= TI_MAX ) \
      LOG("ltmp %d\n", ltmp); \
   tl_assert( ltmp < TI_MAX ); \
   ti[ltmp]++; \
   if ( isTainted ) { \
      ti[ltmp] |= 0x80000000; \
  } \
   else \
      ti[ltmp] &= 0x7fffffff; \
   tv[ltmp] = value; 
   
#	define H_EXIT_EARLY_LDST_128or256 H_EXIT_BASE( isTainted || is_tainted(atmp) )
   

#	define H_PRINT_BASE_128or256(n,s) \
   VG_(printf)("==%u== %s | %s | 0x", H_PID, fnname, aTmp); \
   for (i=0; i<n*s; ++i) { VG_(printf)("%02x", ((UChar*)&valueArr)[i]); } \
   VG_(printf)(" | 0x"); \
   for (i=0; i<n*s; ++i) { VG_(printf)("%02x", ((UChar*)&taintArr)[i]); } \
   VG_(printf)(" | ");


#	define H_PRINTC_BASE_128or256(n,s) \
   VG_(printf)("%s==%u== %s%s | %s | 0x", KMAG, H_PID, fnname, KNRM, aTmp); \
   for (i=0; i<n*s; ++i) { VG_(printf)("%02x", ((UChar*)&valueArr)[i]); } \
   VG_(printf)(" | 0x"); \
   for (i=0; i<n*s; ++i) { VG_(printf)("%02x", ((UChar*)&taintArr)[i]); } \
   VG_(printf)(" | ");

#	define H_PRINT_MNEMONICS \
	if ( TNT_(mnemoReady) ) { \
		char mnemonicsBuffer[256] = "\0"; \
		TNT_(format_mnemonics_and_id)(&TNT_(current_inst), mnemonicsBuffer, sizeof(mnemonicsBuffer)); \
		VG_(printf)("\n==%u== %s\n", H_PID, mnemonicsBuffer); \
		TNT_(mnemoReady) = False; \
	}
	
#	define H_PRINT_BASE(n) \
   unsigned i; \
   H_PRINT_MNEMONICS \
   VG_(printf)("==%u== %s | %s | 0x", H_PID, fnname, aTmp); \
   for (i=0; i<n; ++i) { VG_(printf)("%02x", ((UChar*)&value)[i]); } \
   VG_(printf)(" | 0x"); \
   for (i=0; i<n; ++i) { VG_(printf)("%02x", ((UChar*)&taint)[i]); } \
   VG_(printf)(" | ");

#	define H_PRINTC_BASE(n) \
   unsigned i; \
   H_PRINT_MNEMONICS \
   VG_(printf)("%s==%u== %s%s | %s | 0x", KMAG, H_PID, fnname, KNRM, aTmp); \
   for (i=0; i<n; ++i) { VG_(printf)("%02x", ((UChar*)&value)[i]); } \
   VG_(printf)(" | 0x"); \
   for (i=0; i<n; ++i) { VG_(printf)("%02x", ((UChar*)&taint)[i]); } \
   VG_(printf)(" | ");

#	define H32_PRINT  H_PRINT_BASE(sizeof(UInt) /* always 4 */)
#	define H32_PRINTC H_PRINTC_BASE(sizeof(UInt) /* always 4 */)
#	define H32_PRINT_128or256(n) H_PRINT_BASE_128or256(n,sizeof(UInt) /* always 4 */)
#	define H32_PRINTC_128or256(n) H_PRINTC_BASE_128or256(n,sizeof(UInt) /* always 4 */)

#	define H64_PRINT  H_PRINT_BASE(sizeof(ULong) /* always 8 */)
#	define H64_PRINTC H_PRINTC_BASE(sizeof(ULong) /* always 8 */)
#	define H64_PRINT_128or256(n) H_PRINT_BASE_128or256(n,sizeof(ULong) /* always 8 */)
#	define H64_PRINTC_128or256(n) H_PRINTC_BASE_128or256(n,sizeof(ULong) /* always 8 */)
		   
#else

#	define H32_PRINT \
   VG_(printf)("==%u== %s | %s | 0x%x | 0x%x | ", H_PID, fnname, aTmp, value, taint);

#	define H32_PRINTC \
   VG_(printf)("%s==%u== %s%s | %s | 0x%x | 0x%x | ", KMAG, H_PID, fnname, KNRM, aTmp, value, taint);

#	define H64_PRINT \
   VG_(printf)("==%u== %s | %s | 0x%llx | 0x%llx | ", H_PID, fnname, aTmp, value, taint);

#	define H64_PRINTC \
   VG_(printf)("%s==%u== %s%s | %s | 0x%llx | 0x%llx | ", KMAG, H_PID, fnname, KNRM, aTmp, value, taint);

#endif // _SECRETGRIND_

// if <gtmp> goto <jk> dst
VG_REGPARM(3)
void TNT_(h32_exit_t) (
   IRStmt *clone, 
   UInt value, 
   UInt taint ) {
   
   #if _SECRETGRIND_
   //LOG_ENTER();
   #endif

#if _SECRETGRIND_
   if (!TNT_(clo_trace)) { return; }
#endif

   H_EXIT_EARLY
   H32_PC
   
   IRExpr *guard = clone->Ist.Exit.guard;
   UInt gtmp     = guard->Iex.RdTmp.tmp;
   IRConst *dst  = clone->Ist.Exit.dst;
   ULong address    = extract_IRConst64(dst);

   tl_assert( gtmp < TI_MAX );
   
   if ( istty && is_tainted(gtmp) )
   {
      VG_(sprintf)( aTmp, "IF %st%d_%d%s GOTO 0x%llx",
                               KRED,
                               gtmp, _ti(gtmp),
                               KNRM,
                               address );
      H32_PRINTC
   } else {
      VG_(sprintf)( aTmp, "IF t%d_%d GOTO 0x%llx", gtmp, _ti(gtmp), address );
      H32_PRINT
   }

#if _SECRETGRIND_
   if ( !TNT_(clo_trace_taint_only) || is_tainted(gtmp) )
#else
   if ( is_tainted(gtmp) )
#endif
      VG_(printf)( "t%d_%d\n", gtmp, _ti(gtmp) );
   else
      VG_(printf)("\n");
}

// if <const> goto <jk> dst
VG_REGPARM(3)
void TNT_(h32_exit_c) (
   IRStmt *clone, 
   UInt value, 
   UInt taint ) {

   // End of BB
#if _SECRETGRIND_
   //LOG_ENTER();
#endif
}

// JMP tmp
VG_REGPARM(3)
void TNT_(h32_next_t) (
   IRExpr *clone, 
   UInt value, 
   UInt taint ) {

#if _SECRETGRIND_
   //LOG_ENTER();
#endif

#if _SECRETGRIND_
   if (!TNT_(clo_trace)) { return; }
#endif
  
   H_EXIT_EARLY
   H32_PC
   
   UInt next = clone->Iex.RdTmp.tmp;

   tl_assert( next < TI_MAX );
  
   if ( istty && is_tainted(next) )
   {
      VG_(sprintf)( aTmp, "JMP %st%d_%d%s", KRED, next, _ti(next), KNRM );
      H32_PRINTC
   } else {
      VG_(sprintf)( aTmp, "JMP t%d_%d", next, _ti(next) );
      H32_PRINT
   }

#if _SECRETGRIND_
   if ( !TNT_(clo_trace_taint_only) || is_tainted(next) )
#else
   if ( is_tainted(next) )
#endif
      VG_(printf)( "t%d_%d\n", next, _ti(next) );
   else
      VG_(printf)("\n");
}

// JMP const 
VG_REGPARM(3)
void TNT_(h32_next_c) (
   IRExpr *clone, 
   UInt value, 
   UInt taint ) {

   // End of BB
#if _SECRETGRIND_
   //LOG_ENTER();
#endif
}

#if _SECRETGRIND_

VG_REGPARM(2)
void TNT_(h32_store_v128or256_prepare_tt) (
   IRStmt *clone,
   UChar offset
    ) {
		
	LOG_ENTER();
	
	IRExpr *addr = clone->Ist.Store.addr;
    IRExpr *data = clone->Ist.Store.data;
    UInt atmp = addr->Iex.RdTmp.tmp;
	UInt dtmp = data->Iex.RdTmp.tmp;
	
	tl_assert( atmp < TI_MAX );
	tl_assert( dtmp < TI_MAX );
	
	GH32_prepare_xx.tt.atmp = atmp;
	GH32_prepare_xx.tt.dtmp = dtmp;
	GH32_prepare_xx.tt.offset = offset;
}

VG_REGPARM(3)
void TNT_(h32_store_v128or256_tt) (
   IRStmt *clone, 
   ULong value, 
   ULong taint
    ) {
	LOG_ENTER();
	
	IRExpr *addr = clone->Ist.Store.addr;
    IRExpr *data = clone->Ist.Store.data;
    UInt atmp = addr->Iex.RdTmp.tmp;
	UInt dtmp = data->Iex.RdTmp.tmp;
	UChar offset = 0;
	
	tl_assert( atmp < TI_MAX );
	tl_assert( dtmp < TI_MAX );
	
	/* make sure this is the right data */
	tl_assert ( atmp == GH32_prepare_xx.tt.atmp && dtmp == GH32_prepare_xx.tt.dtmp );
	offset = GH32_prepare_xx.tt.offset; // get the offset
	TNT_(h32_reset_prepare_struct)(&GH32_prepare_xx); // resset immediatly
	
	H_EXIT_EARLY_LDST
	
	UInt address = tv[atmp] + offset;
   
	H_VAR
   
   // we must wait for H_VAR to get mem description before returning
   if( !TNT_(clo_trace) ) { return; }
   
   H32_PC

   // Check if it hasn't been seen before
	/*if( myStringArray_getIndex( &lvar_s, varname ) == -1 ){
      myStringArray_push( &lvar_s, varname );
	}
	lvar_i[ myStringArray_getIndex( &lvar_s, varname ) ]++;
    */
   
   if ( istty && is_tainted(dtmp) )
   {
	  VG_(sprintf)( aTmp, "STORE t%d_%d_v%u = %st%d_%d_v%u%s", atmp, _ti(atmp), offset, KRED, dtmp, _ti(dtmp), offset, KNRM); 
      
      H32_PRINTC
      
   } else {
	 
	  VG_(sprintf)( aTmp, "STORE t%d_%d_v%u = t%d_%d_v%u", atmp, _ti(atmp), offset, dtmp, _ti(dtmp), offset);
      
      H32_PRINT
   }
   
   // Information flow
   // we don't want the user to see an extra _X after the varname
   if ( is_tainted(dtmp) && is_tainted(atmp) ) {
	  VG_(printf)( "%s <- t%d_%d_v%u", varname, dtmp, _ti(dtmp), offset );
	  VG_(printf)( "; %s <*- t%d_%d_v%u\n", varname, atmp, _ti(atmp), offset );

   } else if ( is_tainted(dtmp) ) {
	  VG_(printf)( "%s <- t%d_%d_v%u\n", varname, dtmp, _ti(dtmp), offset );
   }
   else if ( is_tainted(atmp) ) {
	  VG_(printf)( "%s <*- t%d_%d_v%u\n", varname, atmp, _ti(atmp), offset );
   }
   else if ( !TNT_(clo_trace_taint_only) ) {
      VG_(printf)( "%s <- t%d_%d_v%u", varname, dtmp, _ti(dtmp), offset );
	  VG_(printf)( "; %s <*- t%d_%d_v%u\n", varname, atmp, _ti(atmp), offset );
   }
   else
	  VG_(printf)("\n");
	
}
#endif

// STORE <end> atmp = dtmp
VG_REGPARM(3)
void TNT_(h32_store_tt) (
   IRStmt *clone, 
   UInt value, 
   UInt taint) {

#if _SECRETGRIND_
   //LOG_ENTER();
#endif
   
   IRExpr *addr = clone->Ist.Store.addr;
   IRExpr *data = clone->Ist.Store.data;
   UInt atmp = addr->Iex.RdTmp.tmp;
   UInt dtmp = data->Iex.RdTmp.tmp;

   tl_assert( atmp < TI_MAX );
   tl_assert( dtmp < TI_MAX );

   H_EXIT_EARLY_LDST
   
   UInt address = tv[atmp];
   
   H_VAR

#if _SECRETGRIND_
   // we must wait for H_VAR to get mem description before returning
   if( !TNT_(clo_trace) ) { return; }
#endif 

   H32_PC

#if !_SECRETGRIND_
   // Check if it hasn't been seen before
   if( myStringArray_getIndex( &lvar_s, varname ) == -1 ){
      myStringArray_push( &lvar_s, varname );
   }
   lvar_i[ myStringArray_getIndex( &lvar_s, varname ) ]++;
#endif  
   
   if ( istty && is_tainted(dtmp) )
   {
	  VG_(sprintf)( aTmp, "STORE t%d_%d = %st%d_%d%s",
                                  atmp, _ti(atmp),
                                  KRED,
                                  dtmp, _ti(dtmp),
                                  KNRM );
      
      H32_PRINTC
      
   } else {

      VG_(sprintf)( aTmp, "STORE t%d_%d = t%d_%d",
                                  atmp, _ti(atmp),
                                  dtmp, _ti(dtmp) );
      
      H32_PRINT
   }
   
   // Information flow

#if _SECRETGRIND_
   
   // we don't want the user to see an extra _X after the varname
   if ( is_tainted(dtmp) && is_tainted(atmp) ) {
	  VG_(printf)( "%s <- t%d_%d", varname, dtmp, _ti(dtmp) );
	  VG_(printf)( "; %s <*- t%d_%d\n", varname, atmp, _ti(atmp) );

   } else if ( is_tainted(dtmp) ) {
	  VG_(printf)( "%s <- t%d_%d\n", varname, dtmp, _ti(dtmp) );
   }
   else if ( is_tainted(atmp) ) {
	  VG_(printf)( "%s <*- t%d_%d\n", varname, atmp, _ti(atmp) );
   }
   else if ( !TNT_(clo_trace_taint_only) ) {
      VG_(printf)( "%s <- t%d_%d", varname, dtmp, _ti(dtmp) );
	  VG_(printf)( "; %s <*- t%d_%d\n", varname, atmp, _ti(atmp) );
   }
   else
	  VG_(printf)("\n");
	
#else
	
   if ( is_tainted(dtmp) && is_tainted(atmp) ) {
	  VG_(printf)( "%s_%d <- t%d_%d", varname, lvar_i[ myStringArray_getIndex( &lvar_s, varname ) ], dtmp, _ti(dtmp) );
	  VG_(printf)( "; %s_%d <*- t%d_%d\n", varname, lvar_i[ myStringArray_getIndex( &lvar_s, varname ) ], atmp, _ti(atmp) );
   } else if ( is_tainted(dtmp) )
	  VG_(printf)( "%s_%d <- t%d_%d\n", varname, lvar_i[ myStringArray_getIndex( &lvar_s, varname ) ], dtmp, _ti(dtmp) );
   else if ( is_tainted(atmp) )
	  VG_(printf)( "%s_%d <*- t%d_%d\n", varname, lvar_i[ myStringArray_getIndex( &lvar_s, varname ) ], atmp, _ti(atmp) );
   else
	  VG_(printf)("\n");
   
#endif
   
}

#if _SECRETGRIND_

VG_REGPARM(2)
void TNT_(h32_store_v128or256_prepare_tc) (
   IRStmt *clone,
   UChar offset
    ) {
		
	LOG_ENTER();
	
	IRExpr *addr = clone->Ist.Store.addr;
	IRExpr *data = clone->Ist.Store.data;
	UInt atmp    = addr->Iex.RdTmp.tmp;
	UInt c      = extract_IRConst64(data->Iex.Const.con);
   
	GH32_prepare_xx.tc.c = c;
	GH32_prepare_xx.tc.atmp = atmp;
	GH32_prepare_xx.tc.offset = offset;
}

// STORE atmp = c for SIMD instructions
VG_REGPARM(3)
void TNT_(h32_store_v128or256_tc) (
   IRStmt *clone, 
   ULong value, 
   ULong taint ) {
      
   IRExpr *addr = clone->Ist.Store.addr;
   IRExpr *data = clone->Ist.Store.data;
   UInt atmp    = addr->Iex.RdTmp.tmp;
   UInt c      = extract_IRConst64(data->Iex.Const.con);
   UChar offset = 0;
   
   tl_assert( atmp < TI_MAX );
   
   // make sure this contains the expected data
   tl_assert ( GH32_prepare_xx.tc.c == c && GH32_prepare_xx.tc.atmp == atmp );
   offset = GH32_prepare_xx.tc.offset;
   TNT_(h32_reset_prepare_struct)(&GH32_prepare_xx); // reset immediatly
	
   // exit after we've reset the struct above
   H_EXIT_EARLY_LDST

   UInt address = tv[atmp] + offset;
   tl_assert (0 && "never tested so asserting, TODO: check the address is correct");

   H_VAR

   // we must wait for H_VAR to get mem description before returning
   if( !TNT_(clo_trace) ) { return; }

   H32_PC

   VG_(sprintf)( aTmp, "STORE t%d_%d = 0x%x", atmp, _ti(atmp), c );
   H32_PRINT
   
   // Information flow
   
   if ( !TNT_(clo_trace_taint_only) || is_tainted(atmp) )
	  VG_(printf)( "%s <-*- t%d_%d\n", varname, atmp, _ti(atmp) );
   else
	  VG_(printf)("\n");
	   
}

#endif
// STORE atmp = const
VG_REGPARM(3)
void TNT_(h32_store_tc) (
   IRStmt *clone,
   UInt value, 
   UInt taint ) {

#if _SECRETGRIND_
   //LOG_ENTER();
#endif
   
   IRExpr *addr = clone->Ist.Store.addr;
   IRExpr *data = clone->Ist.Store.data;
   UInt atmp    = addr->Iex.RdTmp.tmp;
   UInt c       = extract_IRConst(data->Iex.Const.con);

   tl_assert( atmp < TI_MAX );

   H_EXIT_EARLY_LDST
   
   UInt address = tv[atmp];
   H_VAR

#if _SECRETGRIND_
   // we must wait for H_VAR to get mem description before returning
   if( !TNT_(clo_trace) ) { return; }
#endif

   H32_PC

#if !_SECRETGRIND_
   // Check if it hasn't been seen before
   if( myStringArray_getIndex( &lvar_s, varname ) == -1 ){
      myStringArray_push( &lvar_s, varname );
   }
   lvar_i[ myStringArray_getIndex( &lvar_s, varname ) ]++;
#endif
   
   VG_(sprintf)( aTmp, "STORE t%d_%d = 0x%x", atmp, _ti(atmp), c );
   H32_PRINT
   
   // Information flow
#if _SECRETGRIND_
   
   if ( !TNT_(clo_trace_taint_only) || is_tainted(atmp) )
	  VG_(printf)( "%s <-*- t%d_%d\n", varname, atmp, _ti(atmp) );
   else
	  VG_(printf)("\n");
	   
	   
#else
   
   if ( is_tainted(atmp) )
	  VG_(printf)( "%s_%d <-*- t%d_%d\n", varname, lvar_i[ myStringArray_getIndex( &lvar_s, varname ) ], atmp, _ti(atmp) );
   else
	  VG_(printf)("\n");
    
#endif
}

#if _SECRETGRIND_
VG_REGPARM(2)
void TNT_(h32_store_v128or256_prepare_ct) (
   IRStmt *clone,
   UChar offset
    ) {
		
	LOG_ENTER();
	
	IRExpr *addr = clone->Ist.Store.addr;
	IRExpr *data = clone->Ist.Store.data;
	UInt c      = extract_IRConst64(addr->Iex.Const.con);
	UInt dtmp    = data->Iex.RdTmp.tmp;
   
	GH32_prepare_xx.ct.c = c;
	GH32_prepare_xx.ct.dtmp = dtmp;
	GH32_prepare_xx.ct.offset = offset;
}

// STORE c = dtmp for SIMD instructions
VG_REGPARM(3)
void TNT_(h32_store_v128or256_ct) (
   IRStmt *clone, 
   ULong value, 
   ULong taint
    ) {

	IRExpr *addr = clone->Ist.Store.addr;
	IRExpr *data = clone->Ist.Store.data;
	UInt c      = extract_IRConst64(addr->Iex.Const.con);
	UInt dtmp    = data->Iex.RdTmp.tmp;
	UChar offset = 0;
	
	tl_assert( dtmp < TI_MAX );
	
	// make sure this contains the expected data
	tl_assert ( GH32_prepare_xx.ct.c == c && GH32_prepare_xx.ct.dtmp == dtmp );
	offset = GH32_prepare_xx.ct.offset;
	TNT_(h32_reset_prepare_struct)(&GH32_prepare_xx); // reset immediatly

	// this must come after we're reset the struct
	H_EXIT_EARLY
	
	ULong address = c + offset;
	H_VAR
   
   // we must wait for H_VAR to get mem description before returning
   if( !TNT_(clo_trace) ) { return; }

   H32_PC

   if ( istty && is_tainted(dtmp) )
   {
      VG_(sprintf)( aTmp, "STORE 0x%x = %st%d_%d%s",
                    c, KRED, dtmp, _ti(dtmp), KNRM );
      H32_PRINTC
   } else {
      VG_(sprintf)( aTmp, "STORE 0x%x = t%d_%d", c, dtmp, _ti(dtmp) );
      H32_PRINT
   }

   // Information flow
  
   if ( !TNT_(clo_trace_taint_only) || is_tainted(dtmp) )
	  VG_(printf)( "%s <- t%d_%d\n", varname, dtmp, _ti(dtmp) );
   else
	  VG_(printf)("\n");

}
#endif

// STORE const = dtmp
VG_REGPARM(3)
void TNT_(h32_store_ct) (
   IRStmt *clone,
   UInt value, 
   UInt taint ) {

#if _SECRETGRIND_
   //LOG_ENTER();
#endif
   
   H_EXIT_EARLY
   
   IRExpr *addr = clone->Ist.Store.addr;
   IRExpr *data = clone->Ist.Store.data;
   UInt c       = extract_IRConst(addr->Iex.Const.con);
   UInt dtmp    = data->Iex.RdTmp.tmp;

   tl_assert( dtmp < TI_MAX );

   UInt address = c;
   H_VAR

#if _SECRETGRIND_
   // we must wait for H_VAR to get mem description before returning
   if( !TNT_(clo_trace) ) { return; }
#endif

   H32_PC

#if !_SECRETGRIND_
   if( myStringArray_getIndex( &lvar_s, varname ) == -1 ){
      myStringArray_push( &lvar_s, varname );
   }
   lvar_i[ myStringArray_getIndex( &lvar_s, varname ) ]++;
#endif

   if ( istty && is_tainted(dtmp) )
   {
      VG_(sprintf)( aTmp, "STORE 0x%x = %st%d_%d%s",
                    c, KRED, dtmp, _ti(dtmp), KNRM );
      H32_PRINTC
   } else {
      VG_(sprintf)( aTmp, "STORE 0x%x = t%d_%d", c, dtmp, _ti(dtmp) );
      H32_PRINT
   }

   // Information flow
#if _SECRETGRIND_
   
   if ( !TNT_(clo_trace_taint_only) || is_tainted(dtmp) )
	  VG_(printf)( "%s <- t%d_%d\n", varname, dtmp, _ti(dtmp) );
   else
	  VG_(printf)("\n");
	   
	   
#else
   
   if ( is_tainted(dtmp) )
	  VG_(printf)( "%s_%d <- t%d_%d\n", varname, lvar_i[ myStringArray_getIndex( &lvar_s, varname ) ], dtmp, _ti(dtmp) );
   else
	  VG_(printf)("\n");
     
#endif
}

#if _SECRETGRIND_
// ltmp = LOAD <ty> atmp
void TNT_(h32_load_v128or256_t) (
   IRStmt *clone, 
   UInt value,
   UInt taint    
   ) {
   
   // in a load, we will never need the summary info so stop here
   if(!TNT_(clo_trace)) { return; }

   UInt ty      = clone->Ist.WrTmp.data->Iex.Load.ty - Ity_INVALID;
   IRExpr* addr = clone->Ist.WrTmp.data->Iex.Load.addr;
   UInt atmp    = addr->Iex.RdTmp.tmp;
   tl_assert ( ty+Ity_INVALID==Ity_V128 || ty+Ity_INVALID==Ity_V256 );
   tl_assert( atmp < TI_MAX );
   //LOG("load:atmp:%u, tv[atmp]:%llx\n", atmp, tv[atmp]);
   ULong address = tv[atmp];
        
   UInt taintArr[8] = {0}; // no taint
   UInt valueArr[8] = {0};
   Bool isTainted = False;
   UChar loadSize = TNT_(size_of_load)(ty+Ity_INVALID, sizeof(UInt) /* ULong always 32bits */);
   //LOG("addr:%lx\n", address);
   
   /* WARNING: we must check if the address is valid before deferencing it 
    * Note: not sure the check below is exhaustive.
    * */
   const Addr MAX_ADDR = address+(loadSize*sizeof(UInt))-1;
   if ( !( TNT_(is_stack)(address) || TNT_(malloc_is_heap)(address) || TNT_(is_global)(address) || TNT_(syswrap_is_mmap_file_range)(address) || TNT_(mmap_is_region)(address)) ) { return; }
   if ( !( TNT_(is_stack)(MAX_ADDR) || TNT_(malloc_is_heap)(MAX_ADDR) || TNT_(is_global)(MAX_ADDR) || TNT_(syswrap_is_mmap_file_range)(MAX_ADDR) || TNT_(mmap_is_region)(address) ) ) { return; }
     
   /* read value - check for valid address done above */
   VG_(memcpy)(&valueArr[0], (void*)address, loadSize*sizeof(UInt) );
   
   /* get taint value */
   unsigned i=0;
   for (i=0; i<loadSize*sizeof(UInt); ++i) {
	UChar vbits8 = 0;
	if ( !get_vbits8 ( address+i, &vbits8 ) ) { VG_(tool_panic)("tnt_main.c: h32_load_v128or256_t: Invalid taint"); }
	((UChar*)taintArr)[i] = vbits8;
   }
   
   /* is there taint? */
   isTainted = (taintArr[0] || taintArr[1] || taintArr[2] || taintArr[3] || taintArr[4] || taintArr[5] || taintArr[6] || taintArr[7]);
   
   H_WRTMP_BOOKKEEPING_128or256
   
   H_EXIT_EARLY_LDST_128or256
   
   H32_PC
   
   H_VAR_128or256(sizeof(UInt))
   
   // Check if it hasn't been seen before
   //if( myStringArray_getIndex( &lvar_s, varname ) == -1 ){
   //   myStringArray_push( &lvar_s, varname );
   //}
   //lvar_i[ myStringArray_getIndex( &lvar_s, varname ) ]++;
   
      
   if ( istty && /*is_tainted(ltmp)*/ isTainted )
   {
	  VG_(sprintf)( aTmp, "%st%d_%d%s = LOAD %s t%d_%d", KRED, ltmp, _ti(ltmp), KNRM, IRType_string[ty], atmp, _ti(atmp) );
      H32_PRINTC_128or256(loadSize)
     
   } else {
      VG_(sprintf)( aTmp, "t%d_%d = LOAD %s t%d_%d", ltmp, _ti(ltmp), IRType_string[ty], atmp, _ti(atmp) );
      H32_PRINT_128or256(loadSize)
   }
      
   // Information flow
   if ( /*is_tainted(ltmp)*/ isTainted && is_tainted(atmp) ) {
	  VG_(printf)( "t%d_%d <- %s", ltmp, _ti(ltmp), varname);
	  VG_(printf)( "; t%d_%d <*- t%d_%d\n", ltmp, _ti(ltmp), atmp, _ti(atmp) );
   } else if ( is_tainted(ltmp) )
	  VG_(printf)( "t%d_%d <- %s\n", ltmp, _ti(ltmp), varname );
   else if ( is_tainted(atmp) )
	  VG_(printf)( "t%d_%d <*- t%d_%d\n", ltmp, _ti(ltmp), atmp, _ti(atmp) );
   else if ( !TNT_(clo_trace_taint_only) ) {
      VG_(printf)( "t%d_%d <- %s", ltmp, _ti(ltmp), varname);
	  VG_(printf)( "; t%d_%d <*- t%d_%d\n", ltmp, _ti(ltmp), atmp, _ti(atmp) );
   }
   else
	  VG_(printf)("\n");
		  	   
  
}
#endif

// ltmp = LOAD <ty> atmp
VG_REGPARM(3)
void TNT_(h32_load_t) (
   IRStmt *clone, 
   UInt value, 
   UInt taint ) {

  
   H_WRTMP_BOOKKEEPING
   
#if _SECRETGRIND_
   // in a load, we will never need the summary info so stop here
   if(!TNT_(clo_trace)) { return; }
#endif
   	   
   UInt ty      = clone->Ist.WrTmp.data->Iex.Load.ty - Ity_INVALID;
   IRExpr* addr = clone->Ist.WrTmp.data->Iex.Load.addr;
   UInt atmp    = addr->Iex.RdTmp.tmp;

   tl_assert( atmp < TI_MAX );
   
   Addr address = tv[atmp];
   
   H_EXIT_EARLY_LDST
   H32_PC
   
   H_VAR
   
#if !_SECRETGRIND_
   // Check if it hasn't been seen before
   if( myStringArray_getIndex( &lvar_s, varname ) == -1 ){
      myStringArray_push( &lvar_s, varname );
   }
   //lvar_i[ myStringArray_getIndex( &lvar_s, varname ) ]++;
#endif  
      
   if ( istty && is_tainted(ltmp) )
   {
      VG_(sprintf)( aTmp, "%st%d_%d%s = LOAD %s t%d_%d", KRED, ltmp, _ti(ltmp), KNRM, IRType_string[ty], atmp, _ti(atmp) );
      H32_PRINTC
   } else {
      VG_(sprintf)( aTmp, "t%d_%d = LOAD %s t%d_%d", ltmp, _ti(ltmp), IRType_string[ty], atmp, _ti(atmp) );
      H32_PRINT
   }
   
   
   // Information flow
#if _SECRETGRIND_
 
   if ( is_tainted(ltmp) && is_tainted(atmp) ) {
	  VG_(printf)( "t%d_%d <- %s", ltmp, _ti(ltmp), varname);
	  VG_(printf)( "; t%d_%d <*- t%d_%d\n", ltmp, _ti(ltmp), atmp, _ti(atmp) );
   } else if ( is_tainted(ltmp) )
	  VG_(printf)( "t%d_%d <- %s\n", ltmp, _ti(ltmp), varname );
   else if ( is_tainted(atmp) )
	  VG_(printf)( "t%d_%d <*- t%d_%d\n", ltmp, _ti(ltmp), atmp, _ti(atmp) );
   else if ( !TNT_(clo_trace_taint_only) ) {
      VG_(printf)( "t%d_%d <- %s", ltmp, _ti(ltmp), varname);
	  VG_(printf)( "; t%d_%d <*- t%d_%d\n", ltmp, _ti(ltmp), atmp, _ti(atmp) );
   }
   else
	  VG_(printf)("\n");
		  	   
#else
   
   if ( is_tainted(ltmp) && is_tainted(atmp) ) {
	  VG_(printf)( "t%d_%d <- %s_%d", ltmp, _ti(ltmp), varname, lvar_i[ myStringArray_getIndex( &lvar_s, varname ) ] );
	  VG_(printf)( "; t%d_%d <*- t%d_%d\n", ltmp, _ti(ltmp), atmp, _ti(atmp) );
   } else if ( is_tainted(ltmp) )
	  VG_(printf)( "t%d_%d <- %s_%d\n", ltmp, _ti(ltmp), varname, lvar_i[ myStringArray_getIndex( &lvar_s, varname ) ] );
   else if ( is_tainted(atmp) )
	  VG_(printf)( "t%d_%d <*- t%d_%d\n", ltmp, _ti(ltmp), atmp, _ti(atmp) );
   else
	  VG_(printf)("\n");
  
#endif
}

// ltmp = LOAD <ty> c
VG_REGPARM(3)
void TNT_(h32_load_c) (
   IRStmt *clone,
   UInt value, 
   UInt taint ) {

#if _SECRETGRIND_
   //LOG_ENTER();
#endif
   
   H_WRTMP_BOOKKEEPING
   
#if _SECRETGRIND_
   // in a load, we will never need the summary info so stop here
   if(!TNT_(clo_trace)) { return; }
#endif

   H_EXIT_EARLY
   H32_PC

   UInt ty      = clone->Ist.WrTmp.data->Iex.Load.ty - Ity_INVALID;
   IRExpr* addr = clone->Ist.WrTmp.data->Iex.Load.addr;
   UInt c       = extract_IRConst(addr->Iex.Const.con);

#if _SECRETGRIND_
   /* call this to force a panic if this is not a SIMD type. Copy code from h32_load_t if this occurs */
   TNT_(size_of_load)(ty+Ity_INVALID, sizeof(UInt) /* UInt always 32bits */);
#endif
   
   UInt address = c;
   H_VAR

#if !_SECRETGRIND_  
   if( myStringArray_getIndex( &lvar_s, varname ) == -1 ){
      myStringArray_push( &lvar_s, varname );
   }
   //lvar_i[ myStringArray_getIndex( &lvar_s, varname ) ]++;
#endif
 
   if ( istty && is_tainted(ltmp) )
   {
      VG_(sprintf)( aTmp, "%st%d_%d%s = LOAD %s 0x%x",
                                                 KRED,
                                      ltmp, _ti(ltmp),
                                                 KNRM,
                                IRType_string[ty], c );
      H32_PRINTC
   } else {
      VG_(sprintf)( aTmp, "t%d_%d = LOAD %s 0x%x", ltmp, _ti(ltmp),
                                            IRType_string[ty], c );
      H32_PRINT
   }
   
   // Information flow
#if _SECRETGRIND_
	   
   if ( !TNT_(clo_trace_taint_only) || is_tainted(ltmp) )
	  VG_(printf)( "t%d_%d <- %s\n", ltmp, _ti(ltmp), varname );
   else
	  VG_(printf)("\n");
	   	   
#else
   
   if ( is_tainted(ltmp) )
	  VG_(printf)( "t%d_%d <- %s_%d\n", ltmp, _ti(ltmp), varname, lvar_i[ myStringArray_getIndex( &lvar_s, varname ) ] );
   else
	  VG_(printf)("\n");
   
#endif
}

// tmp = reg
VG_REGPARM(3)
void TNT_(h32_get) (
   IRStmt *clone, 
   UInt value, 
   UInt taint ) {

#if _SECRETGRIND_
   //if (taint) LOG_ENTER();
   //LOG_ENTER();
   TNT_(show_main_summary)();
#endif
   
   H_WRTMP_BOOKKEEPING

   if( TNT_(clo_critical_ins_only) ) return;

#if _SECRETGRIND_
   if (!TNT_(clo_trace)) { return; }
#endif

   H_EXIT_EARLY
   H32_PC

   IRExpr *data = clone->Ist.WrTmp.data;
   UInt ty      = data->Iex.Get.ty - Ity_INVALID;
   UInt reg     = data->Iex.Get.offset;

   tl_assert( reg < RI_MAX );
   
   if ( istty && is_tainted(ltmp) )
   {
      VG_(sprintf)(aTmp, "%st%d_%d%s = r%d_%d %s",
                   KRED,
                   ltmp, _ti(ltmp),
                   KNRM,
                   reg, ri[reg], IRType_string[ty&0xff] );
      H32_PRINTC
   } else {
      VG_(sprintf)(aTmp, "t%d_%d = r%d_%d %s",
                   ltmp, _ti(ltmp),
                   reg, ri[reg], IRType_string[ty&0xff] );
      H32_PRINT
   }

#if _SECRETGRIND_
   if ( !TNT_(clo_trace_taint_only) || is_tainted(ltmp) )
#else
   if ( is_tainted(ltmp) )
#endif
      VG_(printf)( "t%d_%d <- r%d_%d\n", ltmp, _ti(ltmp), reg, ri[reg] );
   else
      VG_(printf)("\n");
}

VG_REGPARM(3)
void TNT_(h32_geti) (
   IRStmt *clone, 
   UInt value, 
   UInt taint ) {

#if _SECRETGRIND_
   //LOG_ENTER();
#endif
   
   H_WRTMP_BOOKKEEPING
}

// reg = tmp
VG_REGPARM(3)
void TNT_(h32_put_t) (
   IRStmt *clone, 
   UInt value, 
   UInt taint ) {

#if _SECRETGRIND_
   //LOG_ENTER();
#endif
   
   if ( TNT_(clo_critical_ins_only) ) return;

#if _SECRETGRIND_
   if (!TNT_(clo_trace)) { return; }
#endif

   H_EXIT_EARLY
   H32_PC

   UInt reg     = clone->Ist.Put.offset;
   IRExpr *data = clone->Ist.Put.data;
   UInt tmp     = data->Iex.RdTmp.tmp;

   tl_assert( reg < RI_MAX );
   tl_assert( tmp < TI_MAX );
   ri[reg]++;
 
   if ( istty && is_tainted(tmp) )
   {
      VG_(sprintf)(aTmp, "r%d_%d = %st%d_%d%s",
                   reg, ri[reg],
                   KRED,
                   tmp, _ti(tmp),
                   KNRM );
      H32_PRINTC
   } else {
      VG_(sprintf)(aTmp, "r%d_%d = t%d_%d", reg, ri[reg],
                                            tmp, _ti(tmp) );
      H32_PRINT
   }
  
#if _SECRETGRIND_
   if ( !TNT_(clo_trace_taint_only) || is_tainted(tmp) )
#else
   if ( is_tainted(tmp) )
#endif
      VG_(printf)("r%d_%d <- t%d_%d\n", reg, ri[reg], tmp, _ti(tmp));
   else
      VG_(printf)("\n");
}

// reg = const 
VG_REGPARM(3)
void TNT_(h32_put_c) (
   IRStmt *clone, 
   UInt value, 
   UInt taint ) {

#if _SECRETGRIND_
   //LOG_ENTER();
#endif
   
   if ( TNT_(clo_critical_ins_only) ) return;

#if _SECRETGRIND_
   if (!TNT_(clo_trace)) { return; }
#endif

   H_EXIT_EARLY
   H32_PC

   UInt reg     = clone->Ist.Put.offset;
   IRExpr *data = clone->Ist.Put.data;
   UInt c       = extract_IRConst(data->Iex.Const.con);

   tl_assert( reg < RI_MAX );
   ri[reg]++;
   
   VG_(sprintf)(aTmp, "r%d_%d = 0x%x", reg, ri[reg], c);
   H32_PRINT

   VG_(printf)("\n");
}

VG_REGPARM(3)
void TNT_(h32_puti) (
   UInt tt1, 
   UInt tt2, 
   UInt value, 
   UInt taint ) {

#if _SECRETGRIND_
   //LOG_ENTER();
#endif
   
   if ( TNT_(clo_critical_ins_only) ) return;

#if _SECRETGRIND_
   if (!TNT_(clo_trace)) { return; }
#endif

   H_EXIT_EARLY
   H32_PC

   UInt elemTy = (tt1 >> 16) & 0xff;
   UInt ix = tt1 & 0xffff;
   UInt bias = (tt2 >> 16) & 0xffff;
   UInt tmp = tt2 & 0xffff;
   
   if ( istty && is_tainted(tmp) )
   {
      VG_(sprintf)(aTmp, "PUTI<%s>[%x,%x] = %st%d%s",
                IRType_string[elemTy], ix, bias,
                KRED, tmp, KNRM );
      H32_PRINTC
   } else {
      VG_(sprintf)(aTmp, "PUTI<%s>[%x,%x] = t%d", IRType_string[elemTy], ix, bias, tmp);
      H32_PRINT
   }

   // TODO: Info flow
   //tl_assert( reg < RI_MAX );
   //tl_assert( tmp < TI_MAX );
   //ri[reg]++;

   //VG_(printf)("r%d_%d <- t%d_%d\n", reg, ri[reg], tmp, ti[tmp]);
   VG_(printf)("\n");
}

// ltmp = <op> const 
VG_REGPARM(3)
void TNT_(h32_wrtmp_c) (
   IRStmt *clone, 
   UInt value, 
   UInt taint ) {

#if _SECRETGRIND_
   //LOG_ENTER();
#endif
   
   H_WRTMP_BOOKKEEPING
   
#if _SECRETGRIND_
   if (!TNT_(clo_trace)) { return; }
#endif
   
   VG_(printf)("%x %x\n", value, taint);
}

// ltmp = <op> rtmp
VG_REGPARM(3)
void TNT_(h32_unop_t) (
   IRStmt *clone, 
   UInt value, 
   UInt taint ) {

#if _SECRETGRIND_
   //if (taint) LOG_ENTER();
   //LOG_ENTER();
#endif
   
   H_WRTMP_BOOKKEEPING

   if( TNT_(clo_critical_ins_only) ) return;

#if _SECRETGRIND_
   if (!TNT_(clo_trace)) { return; }
#endif

   H_EXIT_EARLY
   H32_PC

   UInt op = clone->Ist.WrTmp.data->Iex.Unop.op - Iop_INVALID;
   IRExpr* arg = clone->Ist.WrTmp.data->Iex.Unop.arg;
   UInt rtmp = arg->Iex.RdTmp.tmp;

   tl_assert( rtmp < TI_MAX );

   if ( istty && is_tainted(ltmp) )
   {
      VG_(sprintf)( aTmp, "%st%d_%d%s = %s t%d_%d",
                    KRED,
                    ltmp, _ti(ltmp),
                    KNRM,
                    IROp_string[op],
                    rtmp, _ti(rtmp) );
      H32_PRINTC
   } else {
      VG_(sprintf)( aTmp, "t%d_%d = %s t%d_%d",
                    ltmp, _ti(ltmp), IROp_string[op],
                    rtmp, _ti(rtmp) );
      H32_PRINT
   }

   // Information flow
#if _SECRETGRIND_
   if ( !TNT_(clo_trace_taint_only) || is_tainted(ltmp) )
#else
   if ( is_tainted(ltmp) )
#endif
      VG_(printf)( "t%d_%d <- t%d_%d\n", ltmp, _ti(ltmp), rtmp, _ti(rtmp) );
   else
      VG_(printf)("\n");
}

// ltmp = <op> const
VG_REGPARM(3)
void TNT_(h32_unop_c) (
   IRStmt *clone, 
   UInt value, 
   UInt taint ) {

#if _SECRETGRIND_
   //if (taint) LOG_ENTER();
   //LOG_ENTER();
#endif
   
   H_WRTMP_BOOKKEEPING

   if( TNT_(clo_critical_ins_only) ) return;

#if _SECRETGRIND_
   if (!TNT_(clo_trace)) { return; }
#endif

   H_EXIT_EARLY
   H32_PC

   UInt op = clone->Ist.WrTmp.data->Iex.Unop.op - Iop_INVALID;
   IRExpr* arg = clone->Ist.WrTmp.data->Iex.Unop.arg;
   UInt c = extract_IRConst( arg->Iex.Const.con );

   VG_(sprintf)( aTmp, "t%d_%d = %s 0x%x",
                 ltmp, _ti(ltmp), IROp_string[op], c );
   H32_PRINT

   // No information flow
   VG_(printf)("\n");
}

// ltmp = <op> rtmp1, const
VG_REGPARM(3)
void TNT_(h32_binop_tc) (
   IRStmt *clone,
   UInt value, 
   UInt taint ) {

#if _SECRETGRIND_
   //if (taint) LOG_ENTER();
   //LOG_ENTER();
#endif
   
   H_WRTMP_BOOKKEEPING

   if( TNT_(clo_critical_ins_only) ) return;

#if _SECRETGRIND_
   if (!TNT_(clo_trace)) { return; }
#endif

   H_EXIT_EARLY
   H32_PC

   UInt op = clone->Ist.WrTmp.data->Iex.Binop.op - Iop_INVALID;
   IRExpr* arg1 = clone->Ist.WrTmp.data->Iex.Binop.arg1;
   IRExpr* arg2 = clone->Ist.WrTmp.data->Iex.Binop.arg2;
   UInt rtmp1 = arg1->Iex.RdTmp.tmp;
   UInt c = extract_IRConst( arg2->Iex.Const.con );

   tl_assert( rtmp1 < TI_MAX );
   
   if ( istty && is_tainted(ltmp) )
   {
      VG_(sprintf)( aTmp, "%st%d_%d%s = %s t%d_%d 0x%x",
                    KRED,
                    ltmp, _ti(ltmp),
                    KNRM,
                    IROp_string[op], rtmp1, _ti(rtmp1), c );
      H32_PRINTC
   } else {
      VG_(sprintf)( aTmp, "t%d_%d = %s t%d_%d 0x%x",
                    ltmp, _ti(ltmp),
                    IROp_string[op], rtmp1, _ti(rtmp1), c );
      H32_PRINT
   }

   // Information flow
#if _SECRETGRIND_
   if ( !TNT_(clo_trace_taint_only) || is_tainted(ltmp) )
#else
   if ( is_tainted(ltmp) )
#endif
      VG_(printf)( "t%d_%d <- t%d_%d\n", ltmp, _ti(ltmp), rtmp1, _ti(rtmp1) );
   else
      VG_(printf)("\n");
}

// ltmp = <op> Const rtmp1
VG_REGPARM(3)
void TNT_(h32_binop_ct) (
   IRStmt *clone,
   UInt value, 
   UInt taint ) {

#if _SECRETGRIND_
   //if (taint) LOG_ENTER();
   //LOG_ENTER();
#endif
   
   H_WRTMP_BOOKKEEPING

   if( TNT_(clo_critical_ins_only) ) return;

#if _SECRETGRIND_
   if (!TNT_(clo_trace)) { return; }
#endif

   H_EXIT_EARLY
   H32_PC

   UInt op = clone->Ist.WrTmp.data->Iex.Binop.op - Iop_INVALID;
   IRExpr* arg1 = clone->Ist.WrTmp.data->Iex.Binop.arg1;
   IRExpr* arg2 = clone->Ist.WrTmp.data->Iex.Binop.arg2;
   UInt c = extract_IRConst( arg1->Iex.Const.con );
   UInt rtmp2 = arg2->Iex.RdTmp.tmp;

   tl_assert( rtmp2 < TI_MAX );
   
   if ( istty && is_tainted(ltmp) )
   {
      VG_(sprintf)( aTmp, "%st%d_%d%s = %s 0x%x t%d_%d",
                    KRED,
                    ltmp, _ti(ltmp),
                    KNRM,
                    IROp_string[op], c, rtmp2, _ti(rtmp2) );
      H32_PRINTC
   } else {
      VG_(sprintf)( aTmp, "t%d_%d = %s 0x%x t%d_%d",
                    ltmp, _ti(ltmp),
                    IROp_string[op], c, rtmp2, _ti(rtmp2) );
      H32_PRINT
   }

   // Information flow
#if _SECRETGRIND_
   if ( !TNT_(clo_trace_taint_only) || is_tainted(ltmp) )
#else
   if ( is_tainted(ltmp) )
#endif
      VG_(printf)( "t%d_%d <- t%d_%d\n", ltmp, _ti(ltmp), rtmp2, _ti(rtmp2) );
   else
      VG_(printf)("\n");
}

// ltmp = <op> rtmp1 rtmp2
VG_REGPARM(3)
void TNT_(h32_binop_tt) (
   IRStmt *clone,
   UInt value, 
   UInt taint ) {

#if _SECRETGRIND_
   //if (taint) LOG_ENTER();
   //LOG_ENTER();
#endif
   
   H_WRTMP_BOOKKEEPING

   if( TNT_(clo_critical_ins_only) ) return;

#if _SECRETGRIND_
   if (!TNT_(clo_trace)) { return; }
#endif

   H_EXIT_EARLY
   H32_PC

   UInt op = clone->Ist.WrTmp.data->Iex.Binop.op - Iop_INVALID;
   IRExpr* arg1 = clone->Ist.WrTmp.data->Iex.Binop.arg1;
   IRExpr* arg2 = clone->Ist.WrTmp.data->Iex.Binop.arg2;
   UInt rtmp1 = arg1->Iex.RdTmp.tmp;
   UInt rtmp2 = arg2->Iex.RdTmp.tmp;

   tl_assert( rtmp1 < TI_MAX );
   tl_assert( rtmp2 < TI_MAX );
   
   if ( istty && is_tainted(ltmp) )
   {
      VG_(sprintf)( aTmp, "%st%d_%d%s = %s t%d_%d t%d_%d",
                    KRED,
                    ltmp, _ti(ltmp),
                    KNRM,
                    IROp_string[op],
                    rtmp1, _ti(rtmp1),
                    rtmp2, _ti(rtmp2) );
      H32_PRINTC
   } else {
      VG_(sprintf)( aTmp, "t%d_%d = %s t%d_%d t%d_%d",
                    ltmp, _ti(ltmp),
                    IROp_string[op],
                    rtmp1, _ti(rtmp1),
                    rtmp2, _ti(rtmp2) );
      H32_PRINT
   }

   // Information flow

   if ( is_tainted(rtmp1) && is_tainted(rtmp2) )
      VG_(printf)( "t%d_%d <- t%d_%d, t%d_%d\n", ltmp, _ti(ltmp), rtmp1, _ti(rtmp1), rtmp2, _ti(rtmp2) );
   if ( is_tainted(rtmp1) && !is_tainted(rtmp2) )
      VG_(printf)( "t%d_%d <- t%d_%d\n", ltmp, _ti(ltmp), rtmp1, _ti(rtmp1) );
   else if ( !is_tainted(rtmp1) && is_tainted(rtmp2) )
      VG_(printf)( "t%d_%d <- t%d_%d\n", ltmp, _ti(ltmp), rtmp2, _ti(rtmp2) );
#if _SECRETGRIND_
   else if ( !TNT_(clo_trace_taint_only) ) 
      VG_(printf)( "t%d_%d <- t%d_%d, t%d_%d\n", ltmp, _ti(ltmp), rtmp1, _ti(rtmp1), rtmp2, _ti(rtmp2) );
#endif
   else
      VG_(printf)("\n");
}

// ltmp = <op> const1 const2
VG_REGPARM(3)
void TNT_(h32_binop_cc) (
   IRStmt *clone,
   UInt value, 
   UInt taint ) {

#if _SECRETGRIND_
   //if (taint) LOG_ENTER();
   //LOG_ENTER();
#endif
   
   H_WRTMP_BOOKKEEPING

   if( TNT_(clo_critical_ins_only) ) return;

#if _SECRETGRIND_
   if (!TNT_(clo_trace)) { return; }
#endif

   H_EXIT_EARLY
   H32_PC

   UInt op = clone->Ist.WrTmp.data->Iex.Binop.op - Iop_INVALID;
   IRExpr* arg1 = clone->Ist.WrTmp.data->Iex.Binop.arg1;
   IRExpr* arg2 = clone->Ist.WrTmp.data->Iex.Binop.arg2;
   UInt c1 = extract_IRConst( arg1->Iex.Const.con );
   UInt c2 = extract_IRConst( arg2->Iex.Const.con );
   
   VG_(sprintf)( aTmp, "t%d_%d = %s 0x%x 0x%x",
                 ltmp, _ti(ltmp),
                 IROp_string[op], c1, c2 );
   H32_PRINT

   // No information flow
   VG_(printf)("\n");
}

// ltmp = <op> rtmp1, rtmp2, rtmp3
VG_REGPARM(3)
void TNT_(h32_triop) (
   IRStmt *clone, 
   UInt value, 
   UInt taint ) {

#if _SECRETGRIND_
   //LOG_ENTER();
#endif
   
   H_WRTMP_BOOKKEEPING
}

// ltmp = <op> rtmp1, rtmp2, rtmp3, rtmp4
VG_REGPARM(3)
void TNT_(h32_qop) (
   IRStmt *clone, 
   UInt value, 
   UInt taint ) {

#if _SECRETGRIND_
   //LOG_ENTER();
#endif
   
   H_WRTMP_BOOKKEEPING
}

// ltmp = rtmp
VG_REGPARM(3)
void TNT_(h32_rdtmp) (
   IRStmt *clone, 
   UInt value, 
   UInt taint ) {

#if _SECRETGRIND_
   //LOG_ENTER();
#endif
   
   H_WRTMP_BOOKKEEPING

   if( TNT_(clo_critical_ins_only) ) return;

#if _SECRETGRIND_
   if (!TNT_(clo_trace)) { return; }
#endif

   H_EXIT_EARLY
   H32_PC

   UInt rtmp = clone->Ist.WrTmp.data->Iex.RdTmp.tmp;

   tl_assert( rtmp < TI_MAX );
   
   if ( istty && is_tainted(ltmp) )
   {
      VG_(sprintf)( aTmp, "%st%d_%d%s = t%d_%d",
                    KRED,
                    ltmp, _ti(ltmp),
                    KNRM,
                    rtmp, _ti(rtmp) );
      H32_PRINTC
   } else {
      VG_(sprintf)( aTmp, "t%d_%d = t%d_%d", ltmp, _ti(ltmp),
                                          rtmp, _ti(rtmp) );
      H32_PRINT
   }

#if _SECRETGRIND_
   if ( !TNT_(clo_trace_taint_only) || is_tainted(ltmp) )
#else
   if ( is_tainted(ltmp) )
#endif
      VG_(printf)("t%d_%d <- t%d_%d\n", ltmp, _ti(ltmp),
                                        rtmp, _ti(rtmp));
   else
      VG_(printf)("\n");
}

// ltmp = ctmp? rtmp1 : const
VG_REGPARM(3)
void TNT_(h32_ite_tc) (
   IRStmt *clone, 
   UInt value, 
   UInt taint ) {

#if _SECRETGRIND_
   //LOG_ENTER();
#endif
   
   H_WRTMP_BOOKKEEPING

   if( TNT_(clo_critical_ins_only) ) return;

#if _SECRETGRIND_
   if (!TNT_(clo_trace)) { return; }
#endif

   H_EXIT_EARLY
   H32_PC

   IRExpr *data = clone->Ist.WrTmp.data;
   UInt ctmp    = data->Iex.ITE.cond->Iex.RdTmp.tmp;
   UInt rtmp1   = data->Iex.ITE.iftrue->Iex.RdTmp.tmp;
   UInt c       = extract_IRConst(data->Iex.ITE.iffalse->Iex.Const.con);

   tl_assert( ctmp  < TI_MAX );
   tl_assert( rtmp1 < TI_MAX );
   
   if ( istty && is_tainted(ltmp) )
   {
      VG_(sprintf)( aTmp, "%st%d_%d%s = t%d_%d ? t%d_%d : 0x%x",
                    KRED,
                    ltmp, _ti(ltmp),
                    KNRM,
                    ctmp, _ti(ctmp), rtmp1, _ti(rtmp1), c );
      H32_PRINTC
   } else {
      VG_(sprintf)( aTmp, "t%d_%d = t%d_%d ? t%d_%d : 0x%x",
                    ltmp, _ti(ltmp), ctmp, _ti(ctmp), rtmp1, _ti(rtmp1), c );
      H32_PRINT
   }

   // Information flow
#if _SECRETGRIND_
   if ( !TNT_(clo_trace_taint_only) || is_tainted(ltmp) )
#else
   if ( is_tainted(ltmp) )
#endif
      VG_(printf)( "t%d_%d <- t%d_%d\n", ltmp, _ti(ltmp), rtmp1, _ti(rtmp1) );
   else
      VG_(printf)("\n");
}

// ltmp = ctmp? const : rtmp2
VG_REGPARM(3)
void TNT_(h32_ite_ct) (
   IRStmt *clone, 
   UInt value, 
   UInt taint ) {

#if _SECRETGRIND_
   //LOG_ENTER();
#endif
   
   H_WRTMP_BOOKKEEPING

   if( TNT_(clo_critical_ins_only) ) return;

#if _SECRETGRIND_
   if (!TNT_(clo_trace)) { return; }
#endif

   H_EXIT_EARLY
   H32_PC

   IRExpr *data = clone->Ist.WrTmp.data;
   UInt ctmp    = data->Iex.ITE.cond->Iex.RdTmp.tmp;
   UInt c       = extract_IRConst(data->Iex.ITE.iftrue->Iex.Const.con);
   UInt rtmp2   = data->Iex.ITE.iffalse->Iex.RdTmp.tmp;

   tl_assert( ctmp  < TI_MAX );
   tl_assert( rtmp2 < TI_MAX );
  
   if ( istty && is_tainted(ltmp) )
   {
      VG_(sprintf)( aTmp, "%st%d_%d%s = t%d_%d ? 0x%x : t%d_%d",
                    KRED,
                    ltmp, _ti(ltmp),
                    KNRM,
                    ctmp, _ti(ctmp), c, rtmp2, _ti(rtmp2) );
      H32_PRINTC
   } else {
      VG_(sprintf)( aTmp, "t%d_%d = t%d_%d ? 0x%x : t%d_%d",
                    ltmp, _ti(ltmp), ctmp, _ti(ctmp), c, rtmp2, _ti(rtmp2) );
      H32_PRINT
   }

   // Information flow
#if _SECRETGRIND_
   if ( !TNT_(clo_trace_taint_only) || is_tainted(ltmp) )
#else
   if ( is_tainted(ltmp) )
#endif
      VG_(printf)( "t%d_%d <- t%d_%d\n", ltmp, _ti(ltmp), rtmp2, _ti(rtmp2) );
   else
      VG_(printf)("\n");
}

// ltmp = ctmp? rtmp1 : rtmp2
VG_REGPARM(3)
void TNT_(h32_ite_tt) (
   IRStmt *clone, 
   UInt value, 
   UInt taint ) {

#if _SECRETGRIND_
   //LOG_ENTER();
#endif
   
   H_WRTMP_BOOKKEEPING

   if( TNT_(clo_critical_ins_only) ) return;

#if _SECRETGRIND_
   if (!TNT_(clo_trace)) { return; }
#endif

   H_EXIT_EARLY
   H32_PC

   IRExpr *data = clone->Ist.WrTmp.data;
   UInt ctmp    = data->Iex.ITE.cond->Iex.RdTmp.tmp;
   UInt rtmp1   = data->Iex.ITE.iftrue->Iex.RdTmp.tmp;
   UInt rtmp2   = data->Iex.ITE.iffalse->Iex.RdTmp.tmp;

   tl_assert( ctmp  < TI_MAX );
   tl_assert( rtmp1 < TI_MAX );
   tl_assert( rtmp2 < TI_MAX );
   
   if ( istty && is_tainted(ltmp) )
   {
      VG_(sprintf)( aTmp, "%st%d_%d%s = t%d_%d ? t%d_%d : t%d_%d",
                    KRED,
                    ltmp, _ti(ltmp),
                    KNRM,
                    ctmp, _ti(ctmp),
                    rtmp1, _ti(rtmp1), rtmp2, _ti(rtmp2) );
      H32_PRINTC
   } else {
      VG_(sprintf)( aTmp, "t%d_%d = t%d_%d ? t%d_%d : t%d_%d",
                    ltmp, _ti(ltmp), ctmp, _ti(ctmp),
                    rtmp1, _ti(rtmp1), rtmp2, _ti(rtmp2) );
      H32_PRINT
   }

   // Information flow

   if ( is_tainted(rtmp1) && is_tainted(rtmp2) )
      VG_(printf)( "t%d_%d <- t%d_%d, t%d_%d\n", ltmp, _ti(ltmp),
                          rtmp1, _ti(rtmp1), rtmp2, _ti(rtmp2) );
   else if ( is_tainted(rtmp1) )
      VG_(printf)( "t%d_%d <- t%d_%d\n", ltmp, _ti(ltmp),
                                         rtmp1, _ti(rtmp1) );
   else if ( is_tainted(rtmp2) )
      VG_(printf)( "t%d_%d <- t%d_%d\n", ltmp, _ti(ltmp),
                                         rtmp2, _ti(rtmp2) );
#if _SECRETGRIND_
   else if ( !TNT_(clo_trace_taint_only) ) 
      VG_(printf)( "t%d_%d <- t%d_%d, t%d_%d\n", ltmp, _ti(ltmp),
                          rtmp1, _ti(rtmp1), rtmp2, _ti(rtmp2) );
#endif
   else
      VG_(printf)("\n");
}

// ltmp = ctmp? const1 : const2
VG_REGPARM(3)
void TNT_(h32_ite_cc) (
   IRStmt *clone, 
   UInt value, 
   UInt taint ) {

#if _SECRETGRIND_
   //LOG_ENTER();
#endif
   
   H_WRTMP_BOOKKEEPING

   if( TNT_(clo_critical_ins_only) ) return;

#if _SECRETGRIND_
   if (!TNT_(clo_trace)) { return; }
#endif

   H_EXIT_EARLY
   H32_PC

   IRExpr *data = clone->Ist.WrTmp.data;
   UInt ctmp    = data->Iex.ITE.cond->Iex.RdTmp.tmp;
   UInt c1      = extract_IRConst(data->Iex.ITE.iftrue->Iex.Const.con);
   UInt c2      = extract_IRConst(data->Iex.ITE.iffalse->Iex.Const.con);

   tl_assert( ctmp  < TI_MAX );
   // Laurent: remove below line
   //if ( (ti[ctmp] & 0x80000000) == 0 ) return;
   
   VG_(sprintf)( aTmp, "t%d_%d = t%d_%d ? 0x%x : 0x%x",
                 ltmp, _ti(ltmp), ctmp, _ti(ctmp), c1, c2 );
   H32_PRINT

   // Information flow
#if _SECRETGRIND_
   if ( !TNT_(clo_trace_taint_only) || is_tainted(ltmp) )
#else
   if ( is_tainted(ltmp) )
#endif
      VG_(printf)( "t%d_%d <- t%d_%d\n", ltmp, _ti(ltmp),
                                         ctmp, _ti(ctmp) );
   else
      VG_(printf)("\n");
}

// ltmp = callee( arg[0], ... )
VG_REGPARM(3)
void TNT_(h32_ccall) (
   IRStmt *clone, 
   UInt value, 
   UInt taint ) {

#if _SECRETGRIND_
   //LOG_ENTER();
#endif
   
   H_WRTMP_BOOKKEEPING
}

// No decoding necessary. Just print the string
VG_REGPARM(3)
void TNT_(h32_none) ( 
   HChar *str, 
   UInt value, 
   UInt taint ) {

#if _SECRETGRIND_
   //LOG_ENTER();
#endif
   
   if( TNT_(clo_critical_ins_only) ) return;

#if _SECRETGRIND_
   if (!TNT_(clo_trace)) { return; }
#endif

   H_EXIT_EARLY
   H32_PC
  
   VG_(sprintf)( aTmp, "%s", str);
   H32_PRINT
   // No information flow info
   VG_(printf)("\n");
}

/**** 64-bit helpers ****/

// IF <gtmp> GOTO <jk> addr
VG_REGPARM(3)
void TNT_(h64_exit_t) (
   IRStmt *clone,
   ULong value, 
   ULong taint ) {


#if _SECRETGRIND_
   if (!TNT_(clo_trace)) { return; }
#endif
 
   H_EXIT_EARLY
   H64_PC

   IRExpr *guard = clone->Ist.Exit.guard;
   UInt gtmp     = guard->Iex.RdTmp.tmp;
   IRConst *dst  = clone->Ist.Exit.dst;
   ULong addr    = extract_IRConst64(dst);

   tl_assert( gtmp < TI_MAX );

   if ( istty && is_tainted(gtmp) )
   {
      VG_(sprintf)( aTmp, "IF %st%d_%d%s GOTO 0x%llx", KRED, gtmp, _ti(gtmp), KNRM, addr );
      H64_PRINTC 
   } else {
      VG_(sprintf)( aTmp, "IF t%d_%d GOTO 0x%llx", gtmp, _ti(gtmp), addr );
      H64_PRINT 
   }

#if _SECRETGRIND_
   if ( !TNT_(clo_trace_taint_only) || is_tainted(gtmp) )
#else
   if ( is_tainted(gtmp) )
#endif
      VG_(printf)( "t%d_%d\n", gtmp, _ti(gtmp) );
   else
      VG_(printf)("\n");
}

// IF <gtmp> GOTO <jk> addr
VG_REGPARM(3)
void TNT_(h64_exit_c) (
   IRStmt *clone,
   ULong value, 
   ULong taint ) {

   // End of BB ??
}

// JMP tmp
VG_REGPARM(3)
void TNT_(h64_next_t) (
   IRExpr *clone, 
   ULong value, 
   ULong taint ) {

#if _SECRETGRIND_
   if (!TNT_(clo_trace)) { return; }
#endif
  
   H_EXIT_EARLY
   H64_PC

   UInt next = clone->Iex.RdTmp.tmp;

   tl_assert( next < TI_MAX );
   
   if ( istty && is_tainted(next) )
   {
      VG_(sprintf)( aTmp, "JMP %st%d_%d%s", KRED, next, _ti(next), KNRM );
      H64_PRINTC
   } else {
      VG_(sprintf)( aTmp, "JMP t%d_%d", next, _ti(next) );
      H64_PRINT
   }

#if _SECRETGRIND_
   if ( !TNT_(clo_trace_taint_only) || is_tainted(next) )
#else
   if ( is_tainted(next) )
#endif
      VG_(printf)( "t%d_%d\n", next, _ti(next) );
   else
      VG_(printf)("\n");
}

// JMP const 
VG_REGPARM(3)
void TNT_(h64_next_c) (
   IRExpr *clone, 
   ULong value, 
   ULong taint ) {

#if _SECRETGRIND_
   if (!TNT_(clo_trace)) { return; }
#endif
   
   H_EXIT_EARLY
   H64_PC
  
   VG_(sprintf)( aTmp, "JMP 0x%llx", value );
   H64_PRINT
   VG_(printf)("\n");
   // End of BB
}

#if _SECRETGRIND_

VG_REGPARM(2)
void TNT_(h64_store_v128or256_prepare_tt) (
   IRStmt *clone,
   UChar offset
    ) {
		
	LOG_ENTER();
	
	IRExpr *addr = clone->Ist.Store.addr;
    IRExpr *data = clone->Ist.Store.data;
    UInt atmp = addr->Iex.RdTmp.tmp;
	UInt dtmp = data->Iex.RdTmp.tmp;
	
	tl_assert( atmp < TI_MAX );
	tl_assert( dtmp < TI_MAX );
	
	GH64_prepare_xx.tt.atmp = atmp;
	GH64_prepare_xx.tt.dtmp = dtmp;
	GH64_prepare_xx.tt.offset = offset;
}

VG_REGPARM(3)
void TNT_(h64_store_v128or256_tt) (
   IRStmt *clone, 
   ULong value, 
   ULong taint
    ) {
	LOG_ENTER();
	
	IRExpr *addr = clone->Ist.Store.addr;
    IRExpr *data = clone->Ist.Store.data;
    UInt atmp = addr->Iex.RdTmp.tmp;
	UInt dtmp = data->Iex.RdTmp.tmp;
	UChar offset = 0;
	
	tl_assert( atmp < TI_MAX );
	tl_assert( dtmp < TI_MAX );
	
	/* make sure this is the right data */
	tl_assert ( atmp == GH64_prepare_xx.tt.atmp && dtmp == GH64_prepare_xx.tt.dtmp );
	offset = GH64_prepare_xx.tt.offset; // get the offset
	TNT_(h64_reset_prepare_struct)(&GH64_prepare_xx); // reset immediatly
	
	H_EXIT_EARLY_LDST
	
	ULong address = tv[atmp] + offset;
      
	H_VAR
	
	// need to have H_VAR get the var description for summary before returning
	if(!TNT_(clo_trace)) { return; }
	
	H64_PC
   
	// Check if it hasn't been seen before
	//if( myStringArray_getIndex( &lvar_s, varname ) == -1 ){
    //  myStringArray_push( &lvar_s, varname );
	//}
	//lvar_i[ myStringArray_getIndex( &lvar_s, varname ) ]++;
   
	
   
    if ( istty && is_tainted(dtmp) ) {
		
		VG_(sprintf)( aTmp, "STORE t%d_%d_v%u = %st%d_%d_v%u%s", atmp, _ti(atmp), offset, KRED, dtmp, _ti(dtmp), offset, KNRM); 

		H64_PRINTC
      
	} else {
		
	  VG_(sprintf)( aTmp, "STORE t%d_%d_v%u = t%d_%d_v%u", atmp, _ti(atmp), offset, dtmp, _ti(dtmp), offset); 
      
      H64_PRINT
   }
   
   // Information flow
   
   // we don't want the user to see an extra _X after the varname
	if ( is_tainted(dtmp) && is_tainted(atmp) ) {
		
		VG_(printf)( "%s <- t%d_%d_v%u", varname, dtmp, _ti(dtmp), offset );
		VG_(printf)( "; %s <*- t%d_%d_v%u\n", varname, atmp, _ti(atmp), offset );

	} else if ( is_tainted(dtmp) ) {
		VG_(printf)( "%s <- t%d_%d_v%u\n", varname, dtmp, _ti(dtmp), offset );
	}
	else if ( is_tainted(atmp) ) {
	   
		VG_(printf)( "%s <*- t%d_%d_v%u\n", varname, atmp, _ti(atmp), offset );
	} else if ( !TNT_(clo_trace_taint_only) ) {
		
		VG_(printf)( "%s <- t%d_%d_v%u", varname, dtmp, _ti(dtmp), offset );
		VG_(printf)( "; %s <*- t%d_%d_v%u\n", varname, atmp, _ti(atmp), offset );
		
	} else {
		VG_(printf)("\n");
	}	
		
}
#endif // _SECRETGRIND_

// STORE atmp = dtmp
VG_REGPARM(3)
void TNT_(h64_store_tt) (
   IRStmt *clone, 
   ULong value, 
   ULong taint ) {
	   
   IRExpr *addr = clone->Ist.Store.addr;
   IRExpr *data = clone->Ist.Store.data;
   UInt atmp = addr->Iex.RdTmp.tmp;
   UInt dtmp = data->Iex.RdTmp.tmp;
      
   tl_assert( atmp < TI_MAX );
   tl_assert( dtmp < TI_MAX );


   H_EXIT_EARLY_LDST
 
   ULong address = tv[atmp];
 
   H_VAR

#if _SECRETGRIND_
   // we must wait for H_VAR to get mem description before returning
   if( !TNT_(clo_trace) ) { return; }
#endif
   
   H64_PC
   
#if !_SECRETGRIND_
   // Check if it hasn't been seen before
   if( myStringArray_getIndex( &lvar_s, varname ) == -1 ){
      myStringArray_push( &lvar_s, varname );
   }
   lvar_i[ myStringArray_getIndex( &lvar_s, varname ) ]++;
   
#endif
  
   if ( istty && is_tainted(dtmp) )
   {
	  
      VG_(sprintf)( aTmp, "STORE t%d_%d = %st%d_%d%s",
                                  atmp, _ti(atmp),
                                  KRED,
                                  dtmp, _ti(dtmp),
                                  KNRM );
      
      H64_PRINTC
      
   } else {
	  
      VG_(sprintf)( aTmp, "STORE t%d_%d = t%d_%d",
                                  atmp, _ti(atmp),
                                  dtmp, _ti(dtmp) );
     
      H64_PRINT
   }
   
   // Information flow
#if _SECRETGRIND_
   
   // we don't want the user to see an extra _X after the varname
   if (  is_tainted(dtmp) && is_tainted(atmp)  ) {
	  VG_(printf)( "%s <- t%d_%d", varname, dtmp, _ti(dtmp) );
	  VG_(printf)( "; %s <*- t%d_%d\n", varname, atmp, _ti(atmp) );

   } else if ( is_tainted(dtmp) ) {
	  VG_(printf)( "%s <- t%d_%d\n", varname, dtmp, _ti(dtmp) );
   }
   else if ( is_tainted(atmp) ) {
	  VG_(printf)( "%s <*- t%d_%d\n", varname, atmp, _ti(atmp) );
   } else if ( !TNT_(clo_trace_taint_only) ) {
	  VG_(printf)( "%s <- t%d_%d", varname, dtmp, _ti(dtmp) );
	  VG_(printf)( "; %s <*- t%d_%d\n", varname, atmp, _ti(atmp) );
	  
   } else
	  VG_(printf)("\n");
		
#else
	
   if ( is_tainted(dtmp) && is_tainted(atmp) ) {
	  VG_(printf)( "%s_%d <- t%d_%d", varname, lvar_i[ myStringArray_getIndex( &lvar_s, varname ) ], dtmp, _ti(dtmp) );
	  VG_(printf)( "; %s_%d <*- t%d_%d\n", varname, lvar_i[ myStringArray_getIndex( &lvar_s, varname ) ], atmp, _ti(atmp) );
   } else if ( is_tainted(dtmp) )
	  VG_(printf)( "%s_%d <- t%d_%d\n", varname, lvar_i[ myStringArray_getIndex( &lvar_s, varname ) ], dtmp, _ti(dtmp) );
   else if ( is_tainted(atmp) )
	  VG_(printf)( "%s_%d <*- t%d_%d\n", varname, lvar_i[ myStringArray_getIndex( &lvar_s, varname ) ], atmp, _ti(atmp) );
   else
	  VG_(printf)("\n");
   
#endif
   
}

#if _SECRETGRIND_

VG_REGPARM(2)
void TNT_(h64_store_v128or256_prepare_tc) (
   IRStmt *clone,
   UChar offset
    ) {
		
	LOG_ENTER();
	
	IRExpr *addr = clone->Ist.Store.addr;
	IRExpr *data = clone->Ist.Store.data;
	UInt atmp    = addr->Iex.RdTmp.tmp;
	ULong c      = extract_IRConst64(data->Iex.Const.con);
   
	GH64_prepare_xx.tc.c = c;
	GH64_prepare_xx.tc.atmp = atmp;
	GH64_prepare_xx.tc.offset = offset;
}

// STORE atmp = c for SIMD instructions
VG_REGPARM(3)
void TNT_(h64_store_v128or256_tc) (
   IRStmt *clone, 
   ULong value, 
   ULong taint ) {
      
   IRExpr *addr = clone->Ist.Store.addr;
   IRExpr *data = clone->Ist.Store.data;
   UInt atmp    = addr->Iex.RdTmp.tmp;
   ULong c      = extract_IRConst64(data->Iex.Const.con);
   UChar offset = 0;
   
   tl_assert( atmp < TI_MAX );
   
   // make sure this contains the expected data
   tl_assert ( GH64_prepare_xx.tc.c == c && GH64_prepare_xx.tc.atmp == atmp );
   offset = GH64_prepare_xx.tc.offset;
   TNT_(h64_reset_prepare_struct)(&GH64_prepare_xx); // reset immediatly
	
   // exit after we've reset the struct above
   H_EXIT_EARLY_LDST

   ULong address = tv[atmp] + offset;
   
   //ULong address = c;
   
   H_VAR
   
   // we must wait for H_VAR to get mem description before returning
   if( !TNT_(clo_trace) ) { return; }

   H64_PC
   
   VG_(sprintf)( aTmp, "STORE t%d_%d_v%u = 0x%llx", atmp, _ti(atmp), offset, value );
   H64_PRINT

   // Information flow	   
   if ( !TNT_(clo_trace_taint_only) || is_tainted(atmp) ) 
	  VG_(printf)( "%s <-*- t%d_%d\n", varname, atmp, _ti(atmp) );
   else
	  VG_(printf)("\n");
	
}

#endif

// STORE atmp = c
VG_REGPARM(3)
void TNT_(h64_store_tc) (
   IRStmt *clone, 
   ULong value, 
   ULong taint ) {
      
   IRExpr *addr = clone->Ist.Store.addr;
   IRExpr *data = clone->Ist.Store.data;
   UInt atmp    = addr->Iex.RdTmp.tmp;
   ULong c      = extract_IRConst64(data->Iex.Const.con);
   
   tl_assert( atmp < TI_MAX );

   H_EXIT_EARLY_LDST

   ULong address = tv[atmp];
   //ULong address = c;
   
   H_VAR
   
#if _SECRETGRIND_
   // we must wait for H_VAR to get mem description before returning
   if( !TNT_(clo_trace) ) { return; }
#endif

   H64_PC
   
#if !_SECRETGRIND_
   // Check if it hasn't been seen before
   if( myStringArray_getIndex( &lvar_s, varname ) == -1 ){
      myStringArray_push( &lvar_s, varname );
   }
   lvar_i[ myStringArray_getIndex( &lvar_s, varname ) ]++;
   
#endif

   VG_(sprintf)( aTmp, "STORE t%d_%d = 0x%llx", atmp, _ti(atmp), c );
   H64_PRINT

   // Information flow
#if _SECRETGRIND_
	   
   if ( !TNT_(clo_trace_taint_only) || is_tainted(atmp) ) 
	  VG_(printf)( "%s <-*- t%d_%d\n", varname, atmp, _ti(atmp) );
   else
	  VG_(printf)("\n");
	    
#else
   
   if ( is_tainted(atmp) )
	  VG_(printf)( "%s_%d <-*- t%d_%d\n", varname, lvar_i[ myStringArray_getIndex( &lvar_s, varname ) ], atmp, _ti(atmp) );
   else
	  VG_(printf)("\n");
   
#endif
}

#if _SECRETGRIND_
VG_REGPARM(2)
void TNT_(h64_store_v128or256_prepare_ct) (
   IRStmt *clone,
   UChar offset
    ) {
		
	LOG_ENTER();
	
	IRExpr *addr = clone->Ist.Store.addr;
	IRExpr *data = clone->Ist.Store.data;
	ULong c      = extract_IRConst64(addr->Iex.Const.con);
	UInt dtmp    = data->Iex.RdTmp.tmp;
   
	GH64_prepare_xx.ct.c = c;
	GH64_prepare_xx.ct.dtmp = dtmp;
	GH64_prepare_xx.ct.offset = offset;
}

// STORE c = dtmp for SIMD instructions
VG_REGPARM(3)
void TNT_(h64_store_v128or256_ct) (
   IRStmt *clone, 
   ULong value, 
   ULong taint
    ) {

	IRExpr *addr = clone->Ist.Store.addr;
	IRExpr *data = clone->Ist.Store.data;
	ULong c      = extract_IRConst64(addr->Iex.Const.con);
	UInt dtmp    = data->Iex.RdTmp.tmp;
	UChar offset = 0;
	
	tl_assert( dtmp < TI_MAX );
	
	// make sure this contains the expected data
	tl_assert ( GH64_prepare_xx.ct.c == c && GH64_prepare_xx.ct.dtmp == dtmp );
	offset = GH64_prepare_xx.ct.offset;
	TNT_(h64_reset_prepare_struct)(&GH64_prepare_xx); // reset immediatly
	
	//VG_(printf)("offset:%x, %llx\n", offset, c+offset);
	//tl_assert (0 && "here we are");
	
	// this must come after we're reset the struct
	H_EXIT_EARLY
	
	ULong address = c + offset;
	H_VAR
   
	// we must wait for H_VAR to get mem description before returning
	if( !TNT_(clo_trace) ) { return; }

	H64_PC
   
   if ( istty && is_tainted(dtmp) )
   {
      VG_(sprintf)( aTmp, "STORE 0x%llx = %st%d_%d_v%u%s", address, KRED, dtmp, _ti(dtmp), offset, KNRM );
      H64_PRINTC
   } else {
      VG_(sprintf)( aTmp, "STORE 0x%llx = t%d_%d_v%u", address, dtmp, _ti(dtmp), offset );
      H64_PRINT
   }
   
	if ( !TNT_(clo_trace_taint_only) || is_tainted(dtmp) )
	  VG_(printf)( "%s <- t%d_%d\n", varname, dtmp, _ti(dtmp) );
    else
	  VG_(printf)("\n");
	
}
#endif


// STORE c = dtmp
VG_REGPARM(3)
void TNT_(h64_store_ct) (
   IRStmt *clone,
   ULong value, 
   ULong taint ) {
      
   H_EXIT_EARLY

   IRExpr *addr = clone->Ist.Store.addr;
   IRExpr *data = clone->Ist.Store.data;
   ULong c      = extract_IRConst64(addr->Iex.Const.con);
   UInt dtmp    = data->Iex.RdTmp.tmp;
   
   tl_assert( dtmp < TI_MAX );

   ULong address = c;
   H_VAR
   
#if _SECRETGRIND_
   // we must wait for H_VAR to get mem description before returning
   if( !TNT_(clo_trace) ) { return; }
#endif

   H64_PC
   
#if !_SECRETGRIND_
   // Check if it hasn't been seen before
   if( myStringArray_getIndex( &lvar_s, varname ) == -1 ){
      myStringArray_push( &lvar_s, varname );
   }
   lvar_i[ myStringArray_getIndex( &lvar_s, varname ) ]++;
   
#endif

   if ( istty && is_tainted(dtmp) )
   {
      VG_(sprintf)( aTmp, "STORE 0x%llx = %st%d_%d%s", c, KRED, dtmp, _ti(dtmp), KNRM );
      H64_PRINTC
   } else {
      VG_(sprintf)( aTmp, "STORE 0x%llx = t%d_%d", c, dtmp, _ti(dtmp) );
      H64_PRINT
   }
   
   // Information flow
#if _SECRETGRIND_

	if ( !TNT_(clo_trace_taint_only) || is_tainted(dtmp) )
	  VG_(printf)( "%s <- t%d_%d\n", varname, dtmp, _ti(dtmp) );
    else
	  VG_(printf)("\n");
	   
#else
   
   if ( is_tainted(dtmp) )
	  VG_(printf)( "%s_%d <- t%d_%d\n", varname, lvar_i[ myStringArray_getIndex( &lvar_s, varname ) ], dtmp, _ti(dtmp) );
   else
	  VG_(printf)("\n");
   	  
#endif
}

#if _SECRETGRIND_
static SizeT TNT_(size_of_load)(IRType ty, SizeT n) {

	tl_assert ( n==4 || n==8 );
	SizeT loadSize = 0;
	
	switch (ty) {
   
	/* simple cases */
	case Ity_I1:
    case Ity_I8:
    case Ity_I16: 
    case Ity_I32:
    case Ity_I64:
    case Ity_F32:
    case Ity_F64:
    case Ity_D32:
    case Ity_D64:
		loadSize = 1;
		break;
     
    /* special cases */
    case Ity_V128:
		loadSize = 128/(n*8);
		break;
		
    case Ity_V256:
		loadSize = 256/(n*8);
		break;
		
	/* trap on these for now, because I don't know if we can handle it correctly */
	case Ity_INVALID:
	case Ity_I128:
	case Ity_D128:
	case Ity_F128:
	default: VG_(tool_panic)("tnt_main.c: size_of_load: Unsupported type ty");
   }
	
	return loadSize;
}
#endif

#if _SECRETGRIND_
// ltmp = LOAD <ty> atmp
void TNT_(h64_load_v128or256_t) (
   IRStmt *clone, 
   ULong value,
   ULong taint    
   ) {
   
   // in a load, we will never need the summary info so stop here
   if(!TNT_(clo_trace)) { return; }

   UInt ty      = clone->Ist.WrTmp.data->Iex.Load.ty - Ity_INVALID;
   IRExpr* addr = clone->Ist.WrTmp.data->Iex.Load.addr;
   UInt atmp    = addr->Iex.RdTmp.tmp;
   tl_assert ( ty+Ity_INVALID==Ity_V128 || ty+Ity_INVALID==Ity_V256 );
   tl_assert( atmp < TI_MAX );
   //LOG("load:atmp:%u, tv[atmp]:%llx\n", atmp, tv[atmp]);
   ULong address = tv[atmp];
        
   ULong taintArr[4] = {0}; // no taint
   ULong valueArr[4] = {0};
   Bool isTainted = False;
   UChar loadSize = TNT_(size_of_load)(ty+Ity_INVALID, sizeof(ULong) /* ULong always 64bits */);
   //LOG("addr:%lx\n", address);
   
   /* WARNING: we must check if the address is valid before deferencing it 
    * Note: not sure the check below is exhaustive.
    * */
   const Addr MAX_ADDR = address+(loadSize*sizeof(ULong))-1;
   if ( !( TNT_(is_stack)(address) || TNT_(malloc_is_heap)(address) || TNT_(is_global)(address) || TNT_(syswrap_is_mmap_file_range)(address) || TNT_(mmap_is_region)(address)) ) { return; }
   if ( !( TNT_(is_stack)(MAX_ADDR) || TNT_(malloc_is_heap)(MAX_ADDR) || TNT_(is_global)(MAX_ADDR) || TNT_(syswrap_is_mmap_file_range)(MAX_ADDR) || TNT_(mmap_is_region)(address) ) ) { return; }
    
     
   /* read value - check for valid address done above */
   VG_(memcpy)(&valueArr[0], (void*)address, loadSize*sizeof(ULong) );
   
   /* get taint value */
   unsigned i=0;
   for (i=0; i<loadSize*sizeof(ULong); ++i) {
	UChar vbits8 = 0;
	if ( !get_vbits8 ( address+i, &vbits8 ) ) { VG_(tool_panic)("tnt_main.c: h64_load_v128or256_t: Invalid taint"); }
	((UChar*)taintArr)[i] = vbits8;
   }
   
   /* is there taint? */
   isTainted = (taintArr[0] || taintArr[1] || taintArr[2] || taintArr[3]);
   
   H_WRTMP_BOOKKEEPING_128or256
   
   H_EXIT_EARLY_LDST_128or256
   
   H64_PC
   
   H_VAR_128or256(sizeof(ULong))
   
   // Check if it hasn't been seen before
   //if( myStringArray_getIndex( &lvar_s, varname ) == -1 ){
   //   myStringArray_push( &lvar_s, varname );
   //}
   //lvar_i[ myStringArray_getIndex( &lvar_s, varname ) ]++;
   
      
   if ( istty && /*is_tainted(ltmp)*/ isTainted )
   {
	  VG_(sprintf)( aTmp, "%st%d_%d%s = LOAD %s t%d_%d", KRED, ltmp, _ti(ltmp), KNRM, IRType_string[ty], atmp, _ti(atmp) );
      H64_PRINTC_128or256(loadSize)
     
   } else {
      VG_(sprintf)( aTmp, "t%d_%d = LOAD %s t%d_%d", ltmp, _ti(ltmp), IRType_string[ty], atmp, _ti(atmp) );
      H64_PRINT_128or256(loadSize)
   }
      
   // Information flow
   if ( /*is_tainted(ltmp)*/ isTainted && is_tainted(atmp) ) {
	  VG_(printf)( "t%d_%d <- %s", ltmp, _ti(ltmp), varname);
	  VG_(printf)( "; t%d_%d <*- t%d_%d\n", ltmp, _ti(ltmp), atmp, _ti(atmp) );
   } else if ( is_tainted(ltmp) )
	  VG_(printf)( "t%d_%d <- %s\n", ltmp, _ti(ltmp), varname );
   else if ( is_tainted(atmp) )
	  VG_(printf)( "t%d_%d <*- t%d_%d\n", ltmp, _ti(ltmp), atmp, _ti(atmp) );
   else if ( !TNT_(clo_trace_taint_only) ) {
	  VG_(printf)( "t%d_%d <- %s", ltmp, _ti(ltmp), varname);
	  VG_(printf)( "; t%d_%d <*- t%d_%d\n", ltmp, _ti(ltmp), atmp, _ti(atmp) );
	  
   } else
	  VG_(printf)("\n");
		  	   
  
}
#endif

// ltmp = LOAD <ty> atmp
VG_REGPARM(3)
void TNT_(h64_load_t) (
   IRStmt *clone, 
   ULong value,
   ULong taint    
   ) {
   
#if _SECRETGRIND_
   if (taint) LOG_ENTER();
#endif

   H_WRTMP_BOOKKEEPING
   
#if _SECRETGRIND_
   // in a load, we will never need the summary info so stop here
   if(!TNT_(clo_trace)) { return; }
#endif
   
   UInt ty      = clone->Ist.WrTmp.data->Iex.Load.ty - Ity_INVALID;
   IRExpr* addr = clone->Ist.WrTmp.data->Iex.Load.addr;
   UInt atmp    = addr->Iex.RdTmp.tmp;

   tl_assert( atmp < TI_MAX );
   //LOG("load:atmp:%u, tv[atmp]:%llx\n", atmp, tv[atmp]);
   ULong address = tv[atmp];
   
  
   H_EXIT_EARLY_LDST
   H64_PC
   
   
   H_VAR
   
#if !_SECRETGRIND_
   // Check if it hasn't been seen before
   if( myStringArray_getIndex( &lvar_s, varname ) == -1 ){
      myStringArray_push( &lvar_s, varname );
   }
   //lvar_i[ myStringArray_getIndex( &lvar_s, varname ) ]++;
#endif
 
   if ( istty && is_tainted(ltmp) )
   {
      VG_(sprintf)( aTmp, "%st%d_%d%s = LOAD %s t%d_%d", KRED, ltmp, _ti(ltmp), KNRM, IRType_string[ty], atmp, _ti(atmp) );
      H64_PRINTC
   } else {
      VG_(sprintf)( aTmp, "t%d_%d = LOAD %s t%d_%d", ltmp, _ti(ltmp), IRType_string[ty], atmp, _ti(atmp) );
      H64_PRINT
   }
   
   // Information flow
#if _SECRETGRIND_
   
   if ( is_tainted(ltmp) && is_tainted(atmp) ) {
	  VG_(printf)( "t%d_%d <- %s", ltmp, _ti(ltmp), varname);
	  VG_(printf)( "; t%d_%d <*- t%d_%d\n", ltmp, _ti(ltmp), atmp, _ti(atmp) );
   } else if ( is_tainted(ltmp) )
	  VG_(printf)( "t%d_%d <- %s\n", ltmp, _ti(ltmp), varname );
   else if ( is_tainted(atmp) )
	  VG_(printf)( "t%d_%d <*- t%d_%d\n", ltmp, _ti(ltmp), atmp, _ti(atmp) );
   else if ( !TNT_(clo_trace_taint_only) ) {
	  VG_(printf)( "t%d_%d <- %s", ltmp, _ti(ltmp), varname);
	  VG_(printf)( "; t%d_%d <*- t%d_%d\n", ltmp, _ti(ltmp), atmp, _ti(atmp) ); 
   } else
	  VG_(printf)("\n");
   
   if (taint) LOG_EXIT();
   
#else
   
   if ( is_tainted(ltmp) && is_tainted(atmp) ) {
	  VG_(printf)( "t%d_%d <- %s_%d", ltmp, _ti(ltmp), varname, lvar_i[ myStringArray_getIndex( &lvar_s, varname ) ] );
	  VG_(printf)( "; t%d_%d <*- t%d_%d\n", ltmp, _ti(ltmp), atmp, _ti(atmp) );
   } else if ( is_tainted(ltmp) )
	  VG_(printf)( "t%d_%d <- %s_%d\n", ltmp, _ti(ltmp), varname, lvar_i[ myStringArray_getIndex( &lvar_s, varname ) ] );
   else if ( is_tainted(atmp) )
	  VG_(printf)( "t%d_%d <*- t%d_%d\n", ltmp, _ti(ltmp), atmp, _ti(atmp) );
   else
	  VG_(printf)("\n");
  
#endif
   
}

// ltmp = LOAD <ty> const
VG_REGPARM(3)
void TNT_(h64_load_c) (
   IRStmt *clone,
   ULong value, 
   ULong taint ) {
   
   H_WRTMP_BOOKKEEPING
   
#if _SECRETGRIND_
   // in a load, we will never need the summary info so stop here
   if(!TNT_(clo_trace)) { return; }
#endif

   H_EXIT_EARLY

   UInt ty      = clone->Ist.WrTmp.data->Iex.Load.ty - Ity_INVALID;
   IRExpr* addr = clone->Ist.WrTmp.data->Iex.Load.addr;
   ULong c      = extract_IRConst64(addr->Iex.Const.con);
   
#if _SECRETGRIND_
   /* call this to force a panic if this is not a SIMD type. Copy code from h64_load_t if this occurs */
   TNT_(size_of_load)(ty+Ity_INVALID, sizeof(ULong) /* ULong always 64bits */);
#endif

   H64_PC
   ULong address = c;
   H_VAR
   
#if !_SECRETGRIND_
   if( myStringArray_getIndex( &lvar_s, varname ) == -1 ){
      myStringArray_push( &lvar_s, varname );
   }
   //lvar_i[ myStringArray_getIndex( &lvar_s, varname ) ]++;
   
#endif

   if ( istty && is_tainted(ltmp) )
   {
      VG_(sprintf)( aTmp, "%st%d_%d%s = LOAD %s 0x%llx", KRED, ltmp, _ti(ltmp), KNRM, IRType_string[ty], c );
      H64_PRINTC
   } else {
      VG_(sprintf)( aTmp, "t%d_%d = LOAD %s 0x%llx", ltmp, _ti(ltmp), IRType_string[ty], c );
      H64_PRINT
   }
   
   // Information flow
#if _SECRETGRIND_
	   
   if ( !TNT_(clo_trace_taint_only) || is_tainted(ltmp) )
	  VG_(printf)( "t%d_%d <- %s\n", ltmp, _ti(ltmp), varname );
   else
	  VG_(printf)("\n");
		  
	   
#else
   
   if ( is_tainted(ltmp) )
	  VG_(printf)( "t%d_%d <- %s_%d\n", ltmp, _ti(ltmp), varname, lvar_i[ myStringArray_getIndex( &lvar_s, varname ) ] );
   else
	  VG_(printf)("\n");
   
#endif
}

VG_REGPARM(3)
void TNT_(h64_get) (
   IRStmt *clone, 
   ULong value, 
   ULong taint ) {
   
#if _SECRETGRIND_
   //if (taint) LOG_ENTER();
   //LOG_ENTER();
   TNT_(show_main_summary)();
#endif
   
   IRExpr *data = clone->Ist.WrTmp.data;
   UInt ty      = data->Iex.Get.ty - Ity_INVALID;
   UInt reg     = data->Iex.Get.offset;
   
   tl_assert( reg < RI_MAX );
   
   H_WRTMP_BOOKKEEPING
   
   if( TNT_(clo_critical_ins_only) ) return;
   
#if _SECRETGRIND_
   if (!TNT_(clo_trace)) { return; }
#endif


   H_EXIT_EARLY
   H64_PC
   //H_VAR
  
   if ( istty && is_tainted(ltmp) )
   {
      VG_(sprintf)(aTmp, "%st%d_%d%s = r%d_%d %s",
                           KRED,
                           ltmp, _ti(ltmp),
                           KNRM,
                           reg, ri[reg], IRType_string[ty&0xff] );
      H64_PRINTC
   } else {
      VG_(sprintf)(aTmp, "t%d_%d = r%d_%d %s",
                           ltmp, _ti(ltmp),
                           reg, ri[reg], IRType_string[ty&0xff] );
      H64_PRINT
   }

#if _SECRETGRIND_
   if ( !TNT_(clo_trace_taint_only) || is_tainted(ltmp) )
#else
   if ( is_tainted(ltmp) )
#endif
      VG_(printf)( "t%d_%d <- r%d_%d\n", ltmp, _ti(ltmp), reg, ri[reg] );
   else
      VG_(printf)("\n");
}

VG_REGPARM(3)
void TNT_(h64_geti) (
   IRStmt *clone, 
   ULong value, 
   ULong taint ) {
   
   H_WRTMP_BOOKKEEPING
}

// reg = tmp
VG_REGPARM(3)
void TNT_(h64_put_t) (
   IRStmt *clone, 
   ULong value, 
   ULong taint ) {
   
   if ( TNT_(clo_critical_ins_only) ) return;

#if _SECRETGRIND_
   if (!TNT_(clo_trace)) { return; }
#endif

   H_EXIT_EARLY
   H64_PC
   //H_VAR

   UInt reg     = clone->Ist.Put.offset;
   IRExpr *data = clone->Ist.Put.data;
   UInt tmp     = data->Iex.RdTmp.tmp;
   
   tl_assert( reg < RI_MAX );
   tl_assert( tmp < TI_MAX );
   ri[reg]++;

   if ( istty && is_tainted(tmp) )
   {
      VG_(sprintf)(aTmp, "r%d_%d = %st%d_%d%s", reg, ri[reg],
                                            KRED,
                                            tmp, _ti(tmp),
                                            KNRM );
      H64_PRINTC
   } else {
      VG_(sprintf)(aTmp, "r%d_%d = t%d_%d", reg, ri[reg],
                                            tmp, _ti(tmp) );
      H64_PRINT
   }

#if _SECRETGRIND_
   if ( !TNT_(clo_trace_taint_only) || is_tainted(tmp) )
#else
   if ( is_tainted(tmp) )
#endif // _SECRETGRIND_
      VG_(printf)("r%d_%d <- t%d_%d\n", reg, ri[reg], tmp, _ti(tmp));
   else
      VG_(printf)("\n");
}

// reg = const
VG_REGPARM(3)
void TNT_(h64_put_c) (
   IRStmt *clone, 
   ULong value, 
   ULong taint ) {
   
   if ( TNT_(clo_critical_ins_only) ) return;

#if _SECRETGRIND_
   if (!TNT_(clo_trace)) { return; }
#endif

   H_EXIT_EARLY
   H64_PC
   //H_VAR

   UInt reg     = clone->Ist.Put.offset;
   IRExpr *data = clone->Ist.Put.data;
   ULong c      = extract_IRConst(data->Iex.Const.con);

   tl_assert( reg < RI_MAX );
   ri[reg]++;
   
   VG_(sprintf)(aTmp, "r%d_%d = 0x%llx", reg, ri[reg], c);
   H64_PRINT

   VG_(printf)("\n");
}


VG_REGPARM(3)
void TNT_(h64_puti) (
   ULong tt1, 
   ULong tt2, 
   ULong value, 
   ULong taint ) {
   
   if ( TNT_(clo_critical_ins_only) ) return;

#if _SECRETGRIND_
   if (!TNT_(clo_trace)) { return; }
#endif

   H_EXIT_EARLY
   H64_PC
   //H_VAR

   UInt base = (tt1 >> 32) & 0xffffffff;
   UInt elemTy = (tt1 >> 16) & 0xff;
   UInt nElems = tt1 & 0xffff;
   UInt ix = (tt2 >> 32) & 0xffffffff;
   UInt bias = (tt2 >> 16) & 0xffff;
   UInt tmp = tt2 & 0xffff;
  
   if ( istty && is_tainted(tmp) )
   {
      VG_(sprintf)(aTmp, "PUTI<%d:%s:%d>[%x,%x] = %st%d%s", base, IRType_string[elemTy], nElems, ix, bias, KRED, tmp, KNRM);
      H64_PRINTC
   } else {
      VG_(sprintf)(aTmp, "PUTI<%d:%s:%d>[%x,%x] = t%d", base, IRType_string[elemTy], nElems, ix, bias, tmp);
      H64_PRINT
   }

   // TODO: Info flow
   //tl_assert( reg < RI_MAX );
   //tl_assert( tmp < TI_MAX );
   //ri[reg]++;

   //VG_(printf)("r%d_%d <- t%d_%d\n", reg, ri[reg], tmp, ti[tmp]);
   VG_(printf)("\n");
}

// ltmp = <op> ...
VG_REGPARM(3)
void TNT_(h64_wrtmp_c) (
   IRStmt *clone,
   ULong value, 
   ULong taint ) {
   
   H_WRTMP_BOOKKEEPING
   
#if _SECRETGRIND_
   if (!TNT_(clo_trace)) { return; }
#endif

   VG_(printf)("%llx %llx\n", value, taint);
}

// ltmp = <op> rtmp
VG_REGPARM(3)
void TNT_(h64_unop_t) (
   IRStmt *clone,
   ULong value, 
   ULong taint ) {
   
#if _SECRETGRIND_
   //if (taint) LOG_ENTER();
   //LOG_ENTER();
#endif
     
   H_WRTMP_BOOKKEEPING

   if( TNT_(clo_critical_ins_only) ) return;
   
#if _SECRETGRIND_
   if (!TNT_(clo_trace)) { return; }
#endif

   H_EXIT_EARLY
   H64_PC

   UInt op = clone->Ist.WrTmp.data->Iex.Unop.op - Iop_INVALID;
   IRExpr* arg = clone->Ist.WrTmp.data->Iex.Unop.arg;
   UInt rtmp = arg->Iex.RdTmp.tmp;
   
   tl_assert( rtmp < TI_MAX );
  
   if ( istty && is_tainted(ltmp) )
   {
      VG_(sprintf)( aTmp, "%st%d_%d%s = %s t%d_%d",
                    KRED,
                    ltmp, _ti(ltmp),
                    KNRM,
                    IROp_string[op],
                    rtmp, _ti(rtmp) );
      H64_PRINTC
   } else {
      VG_(sprintf)( aTmp, "t%d_%d = %s t%d_%d",
                    ltmp, _ti(ltmp), IROp_string[op],
                    rtmp, _ti(rtmp) );
      H64_PRINT
   }

   // Information flow
#if _SECRETGRIND_
   if ( !TNT_(clo_trace_taint_only) || is_tainted(ltmp) )
#else
   if ( is_tainted(ltmp) )
#endif // _SECRETGRIND_
      VG_(printf)( "t%d_%d <- t%d_%d\n", ltmp, _ti(ltmp), rtmp, _ti(rtmp) );
   else
      VG_(printf)("\n");
}

// ltmp = <op> const
VG_REGPARM(3)
void TNT_(h64_unop_c) (
   IRStmt *clone, 
   ULong value, 
   ULong taint ) {
   
#if _SECRETGRIND_
   //if (taint) LOG_ENTER();
   //LOG_ENTER();
#endif
   
   H_WRTMP_BOOKKEEPING

   if( TNT_(clo_critical_ins_only) ) return;

#if _SECRETGRIND_
   if (!TNT_(clo_trace)) { return; }
#endif

   H_EXIT_EARLY
   H64_PC
   
   UInt op = clone->Ist.WrTmp.data->Iex.Unop.op - Iop_INVALID;
   IRExpr* arg = clone->Ist.WrTmp.data->Iex.Unop.arg;
   ULong c = extract_IRConst( arg->Iex.Const.con );
  
   VG_(sprintf)( aTmp, "t%d_%d = %s 0x%llx",
                 ltmp, _ti(ltmp), IROp_string[op], c );
   H64_PRINT

   // No information flow
   VG_(printf)("\n");
}

// ltmp = <op> rtmp1 const
VG_REGPARM(3)
void TNT_(h64_binop_tc) (
   IRStmt *clone,
   ULong value, 
   ULong taint ) {
   
#if _SECRETGRIND_
   //if (taint) LOG_ENTER();
   //LOG_ENTER();
#endif
   
   H_WRTMP_BOOKKEEPING

   if( TNT_(clo_critical_ins_only) ) return;

#if _SECRETGRIND_
   if (!TNT_(clo_trace)) { return; }
#endif

   H_EXIT_EARLY
   H64_PC
   
   UInt op = clone->Ist.WrTmp.data->Iex.Binop.op - Iop_INVALID;
   IRExpr* arg1 = clone->Ist.WrTmp.data->Iex.Binop.arg1;
   IRExpr* arg2 = clone->Ist.WrTmp.data->Iex.Binop.arg2;
   UInt rtmp1 = arg1->Iex.RdTmp.tmp;
   
   ULong c = extract_IRConst64(arg2->Iex.Const.con);
   
   tl_assert( rtmp1 < TI_MAX );
   
   if ( istty && is_tainted(ltmp) )
   {
      VG_(sprintf)( aTmp, "%st%d_%d%s = %s t%d_%d 0x%llx",
                    KRED,
                    ltmp, _ti(ltmp),
                    KNRM,
                    IROp_string[op], rtmp1, _ti(rtmp1), c );
      H64_PRINTC
   } else {
      VG_(sprintf)( aTmp, "t%d_%d = %s t%d_%d 0x%llx",
                    ltmp, _ti(ltmp),
                    IROp_string[op], rtmp1, _ti(rtmp1), c );
      H64_PRINT
   }

   // Information flow
#if _SECRETGRIND_
   if ( !TNT_(clo_trace_taint_only) || is_tainted(ltmp) )
#else
   if ( is_tainted(ltmp) )
#endif // _SECRETGRIND_
      VG_(printf)( "t%d_%d <- t%d_%d\n", ltmp, _ti(ltmp), rtmp1, _ti(rtmp1) );
   else
      VG_(printf)("\n");
}

// ltmp = <op> const rtmp2
VG_REGPARM(3)
void TNT_(h64_binop_ct) (
   IRStmt *clone,
   ULong value, 
   ULong taint ) {
   
#if _SECRETGRIND_
   //if (taint) LOG_ENTER();
   //LOG_ENTER();
#endif
   
   H_WRTMP_BOOKKEEPING

   if( TNT_(clo_critical_ins_only) ) return;

#if _SECRETGRIND_
   if (!TNT_(clo_trace)) { return; }
#endif

   H_EXIT_EARLY
   H64_PC
   
   UInt op = clone->Ist.WrTmp.data->Iex.Binop.op - Iop_INVALID;
   IRExpr* arg1 = clone->Ist.WrTmp.data->Iex.Binop.arg1;
   IRExpr* arg2 = clone->Ist.WrTmp.data->Iex.Binop.arg2;
   ULong c = extract_IRConst64(arg1->Iex.Const.con);
   UInt rtmp2 = arg2->Iex.RdTmp.tmp;

   tl_assert( rtmp2 < TI_MAX );
   
   if ( istty && is_tainted(ltmp) )
   {
      VG_(sprintf)( aTmp, "%st%d_%d%s = %s 0x%llx t%d_%d",
                    KRED,
                    ltmp, _ti(ltmp),
                    KNRM,
                    IROp_string[op], c, rtmp2, _ti(rtmp2) );
      H64_PRINTC
   } else {
      VG_(sprintf)( aTmp, "t%d_%d = %s 0x%llx t%d_%d",
                    ltmp, _ti(ltmp),
                    IROp_string[op], c, rtmp2, _ti(rtmp2) );
      H64_PRINT
   }

   // Information flow
#if _SECRETGRIND_
   if ( !TNT_(clo_trace_taint_only) || is_tainted(ltmp) )
#else
   if ( is_tainted(ltmp) )
#endif // _SECRETGRIND_
      VG_(printf)( "t%d_%d <- t%d_%d\n", ltmp, _ti(ltmp), rtmp2, _ti(rtmp2) );
   else
      VG_(printf)("\n");
}

// ltmp = <op> rtmp1 rtmp2
VG_REGPARM(3)
void TNT_(h64_binop_tt) (
   IRStmt *clone,
   ULong value, 
   ULong taint ) {
   
#if _SECRETGRIND_
   //if (taint) LOG_ENTER();
   //LOG_ENTER();
#endif
   
   H_WRTMP_BOOKKEEPING

   if( TNT_(clo_critical_ins_only) ) return;

#if _SECRETGRIND_
   if (!TNT_(clo_trace)) { return; }
#endif

   H_EXIT_EARLY
   H64_PC
   
   UInt op = clone->Ist.WrTmp.data->Iex.Binop.op - Iop_INVALID;
   IRExpr* arg1 = clone->Ist.WrTmp.data->Iex.Binop.arg1;
   IRExpr* arg2 = clone->Ist.WrTmp.data->Iex.Binop.arg2;
   UInt rtmp1 = arg1->Iex.RdTmp.tmp;
   UInt rtmp2 = arg2->Iex.RdTmp.tmp;
   
   tl_assert( rtmp1 < TI_MAX );
   tl_assert( rtmp2 < TI_MAX );

   if ( istty && is_tainted(ltmp) )
   {
      VG_(sprintf)( aTmp, "%st%d_%d%s = %s t%d_%d t%d_%d",
                    KRED,
                    ltmp, _ti(ltmp),
                    KNRM,
                    IROp_string[op],
                    rtmp1, _ti(rtmp1),
                    rtmp2, _ti(rtmp2) );
      H64_PRINTC
   } else {
      VG_(sprintf)( aTmp, "t%d_%d = %s t%d_%d t%d_%d",
                    ltmp, _ti(ltmp),
                    IROp_string[op],
                    rtmp1, _ti(rtmp1),
                    rtmp2, _ti(rtmp2) );
      H64_PRINT
   }

   // Information flow

   if ( is_tainted(rtmp1) && is_tainted(rtmp2) )
      VG_(printf)( "t%d_%d <- t%d_%d, t%d_%d\n", ltmp, _ti(ltmp), rtmp1, _ti(rtmp1), rtmp2, _ti(rtmp2) );
   else if ( is_tainted(rtmp1) )
      VG_(printf)( "t%d_%d <- t%d_%d\n", ltmp, _ti(ltmp), rtmp1, _ti(rtmp1) );
   else if ( is_tainted(rtmp2) )
      VG_(printf)( "t%d_%d <- t%d_%d\n", ltmp, _ti(ltmp), rtmp2, _ti(rtmp2) );
#if _SECRETGRIND_
   else if ( !TNT_(clo_trace_taint_only) )
      VG_(printf)( "t%d_%d <- t%d_%d, t%d_%d\n", ltmp, _ti(ltmp), rtmp1, _ti(rtmp1), rtmp2, _ti(rtmp2) );
#endif
   else
      VG_(printf)("\n");
     
}

// ltmp = <op> const1 const2
VG_REGPARM(3)
void TNT_(h64_binop_cc) (
   IRStmt *clone,
   ULong value, 
   ULong taint ) {
   
   #if _SECRETGRIND_
   //if (taint) LOG_ENTER();
   //LOG_ENTER();
   #endif
   
   H_WRTMP_BOOKKEEPING

   if( TNT_(clo_critical_ins_only) ) return;

#if _SECRETGRIND_
   if (!TNT_(clo_trace)) { return; }
#endif

   H_EXIT_EARLY
   H64_PC

   UInt op = clone->Ist.WrTmp.data->Iex.Binop.op - Iop_INVALID;
   IRExpr* arg1 = clone->Ist.WrTmp.data->Iex.Binop.arg1;
   IRExpr* arg2 = clone->Ist.WrTmp.data->Iex.Binop.arg2;
   ULong c1 = extract_IRConst( arg1->Iex.Const.con );
   ULong c2 = extract_IRConst( arg2->Iex.Const.con );
 
   VG_(sprintf)( aTmp, "t%d_%d = %s 0x%llx 0x%llx",
                 ltmp, _ti(ltmp),
                 IROp_string[op], c1, c2 );
   H64_PRINT

   // No information flow
   VG_(printf)("\n");
}

// ltmp = <op> rtmp1, rtmp2, rtmp3
VG_REGPARM(3)
void TNT_(h64_triop) (
   IRStmt *clone, 
   ULong value, 
   ULong taint ) {
   
#if _SECRETGRIND_
   //if (taint) LOG_ENTER();
   //LOG_ENTER();
#endif
   
   H_WRTMP_BOOKKEEPING
}

// ltmp = <op> rtmp1, rtmp2, rtmp3, rtmp4
VG_REGPARM(3)
void TNT_(h64_qop) (
   IRStmt *clone, 
   ULong value, 
   ULong taint ) {
   
#if _SECRETGRIND_
   //if (taint) LOG_ENTER();
   //LOG_ENTER();
#endif
   
   H_WRTMP_BOOKKEEPING
}

VG_REGPARM(3)
void TNT_(h64_rdtmp) (
   IRStmt *clone, 
   ULong value, 
   ULong taint ) {
   
   H_WRTMP_BOOKKEEPING

   if( TNT_(clo_critical_ins_only) ) return;

#if _SECRETGRIND_
   if (!TNT_(clo_trace)) { return; }
#endif

   H_EXIT_EARLY
   H64_PC
   //H_VAR

   UInt rtmp = clone->Ist.WrTmp.data->Iex.RdTmp.tmp;

   tl_assert( rtmp < TI_MAX );

   // Sanity check for the WrTmp book-keeping,
   // since RdTmp is essentially a no-op
   if ( value != tv[rtmp] )
      VG_(printf)("value 0x%llx != tv[rtmp] 0x%llx\n", value, tv[rtmp] );
   tl_assert( value == tv[rtmp] );
  
   if ( istty && is_tainted(ltmp) )
   {
      VG_(sprintf)( aTmp, "%st%d_%d%s = t%d_%d",
                                KRED,
                                ltmp, _ti(ltmp),
                                KNRM,
                                rtmp, _ti(rtmp) );
      H64_PRINTC
   } else {
      VG_(sprintf)( aTmp, "t%d_%d = t%d_%d", ltmp, _ti(ltmp),
                                             rtmp, _ti(rtmp) );
      H64_PRINT
   }

#if _SECRETGRIND_
   if ( !TNT_(clo_trace_taint_only) || is_tainted(ltmp) )
#else
   if ( is_tainted(ltmp) )
#endif // _SECRETGRIND_
      VG_(printf)("t%d_%d <- t%d_%d\n", ltmp, _ti(ltmp), rtmp, _ti(rtmp));
   else
      VG_(printf)("\n");
}

// ltmp = ctmp? rtmp1 : const
VG_REGPARM(3)
void TNT_(h64_ite_tc) (
   IRStmt *clone, 
   ULong value, 
   ULong taint ) {
   
   H_WRTMP_BOOKKEEPING

   if( TNT_(clo_critical_ins_only) ) return;

#if _SECRETGRIND_
   if (!TNT_(clo_trace)) { return; }
#endif

   H_EXIT_EARLY
   H64_PC

   IRExpr *data = clone->Ist.WrTmp.data;
   UInt ctmp    = data->Iex.ITE.cond->Iex.RdTmp.tmp;
   UInt rtmp1   = data->Iex.ITE.iftrue->Iex.RdTmp.tmp;
   ULong c      = extract_IRConst64(data->Iex.ITE.iffalse->Iex.Const.con);

   tl_assert( ctmp  < TI_MAX );
   tl_assert( rtmp1 < TI_MAX );
   
   if ( istty && is_tainted(ltmp) )
   {
      VG_(sprintf)( aTmp, "%st%d_%d%s = t%d_%d ? t%d_%d : 0x%llx",
                    KRED,
                    ltmp, _ti(ltmp),
                    KNRM,
                    ctmp, _ti(ctmp), rtmp1, _ti(rtmp1), c );
      H64_PRINTC
   } else {
      VG_(sprintf)( aTmp, "t%d_%d = t%d_%d ? t%d_%d : 0x%llx",
                    ltmp, _ti(ltmp), ctmp, _ti(ctmp), rtmp1, _ti(rtmp1), c );
      H64_PRINT
   }

   // Information flow
#if _SECRETGRIND_
   if ( !TNT_(clo_trace_taint_only) || is_tainted(ltmp) )
#else
   if ( is_tainted(ltmp) )
#endif
      VG_(printf)( "t%d_%d <- t%d_%d\n", ltmp, _ti(ltmp), rtmp1, _ti(rtmp1) );
   else
      VG_(printf)("\n");
}

// ltmp = ctmp? const : rtmp2
VG_REGPARM(3)
void TNT_(h64_ite_ct) (
   IRStmt *clone, 
   ULong value, 
   ULong taint ) {
   
   H_WRTMP_BOOKKEEPING

   if( TNT_(clo_critical_ins_only) ) return;

#if _SECRETGRIND_
   if (!TNT_(clo_trace)) { return; }
#endif

   H_EXIT_EARLY
   H64_PC

   IRExpr *data = clone->Ist.WrTmp.data;
   UInt ctmp    = data->Iex.ITE.cond->Iex.RdTmp.tmp;
   ULong c      = extract_IRConst64(data->Iex.ITE.iftrue->Iex.Const.con);
   UInt rtmp2   = data->Iex.ITE.iffalse->Iex.RdTmp.tmp;

   tl_assert( ctmp  < TI_MAX );
   tl_assert( rtmp2 < TI_MAX );

   if ( istty && is_tainted(ltmp) )
   {
      VG_(sprintf)( aTmp, "%st%d_%d%s = t%d_%d ? 0x%llx : t%d_%d",
                    KRED,
                    ltmp, _ti(ltmp),
                    KNRM,
                    ctmp, _ti(ctmp), c, rtmp2, _ti(rtmp2) );
      H64_PRINTC
   } else {
      VG_(sprintf)( aTmp, "t%d_%d = t%d_%d ? 0x%llx : t%d_%d",
                    ltmp, _ti(ltmp), ctmp, _ti(ctmp), c, rtmp2, _ti(rtmp2) );
      H64_PRINT
   }

   // Information flow
#if _SECRETGRIND_
   if ( !TNT_(clo_trace_taint_only) || is_tainted(ltmp) )
#else
   if ( is_tainted(ltmp) )
#endif // _SECRETGRIND_
      VG_(printf)( "t%d_%d <- t%d_%d\n", ltmp, _ti(ltmp), rtmp2, _ti(rtmp2) );
   else
      VG_(printf)("\n");
}

// ltmp = ctmp? rtmp1 : rtmp2
VG_REGPARM(3)
void TNT_(h64_ite_tt) (
   IRStmt *clone, 
   ULong value, 
   ULong taint ) {
   
   H_WRTMP_BOOKKEEPING

   if( TNT_(clo_critical_ins_only) ) return;
   
#if _SECRETGRIND_
   if (!TNT_(clo_trace)) { return; }
#endif


   H_EXIT_EARLY
   H64_PC

   IRExpr *data = clone->Ist.WrTmp.data;
   UInt ctmp    = data->Iex.ITE.cond->Iex.RdTmp.tmp;
   UInt rtmp1   = data->Iex.ITE.iftrue->Iex.RdTmp.tmp;
   UInt rtmp2   = data->Iex.ITE.iffalse->Iex.RdTmp.tmp;

   tl_assert( ltmp  < TI_MAX );
   tl_assert( rtmp1 < TI_MAX );
   tl_assert( rtmp2 < TI_MAX );
   
   if ( istty && is_tainted(ltmp) )
   {
      VG_(sprintf)( aTmp, "%st%d_%d%s = t%d_%d ? t%d_%d : t%d_%d",
                    KRED,
                    ltmp, _ti(ltmp),
                    KNRM,
                    ctmp, _ti(ctmp),
                    rtmp1, _ti(rtmp1), rtmp2, _ti(rtmp2) );
      H64_PRINTC
   } else {
      VG_(sprintf)( aTmp, "t%d_%d = t%d_%d ? t%d_%d : t%d_%d",
                    ltmp, _ti(ltmp), ctmp, _ti(ctmp),
                    rtmp1, _ti(rtmp1), rtmp2, _ti(rtmp2) );
      H64_PRINT
   }

   // Information flow
   if ( is_tainted(rtmp1) && is_tainted(rtmp2) )
      VG_(printf)( "t%d_%d <- t%d_%d, t%d_%d\n", ltmp, _ti(ltmp), rtmp1, _ti(rtmp1), rtmp2, _ti(rtmp2) );
   else if ( is_tainted(rtmp1) )
      VG_(printf)( "t%d_%d <- t%d_%d\n", ltmp, _ti(ltmp), rtmp1, _ti(rtmp1) );
   else if ( is_tainted(rtmp2) )
      VG_(printf)( "t%d_%d <- t%d_%d\n", ltmp, _ti(ltmp), rtmp2, _ti(rtmp2) );
#if _SECRETGRIND_
   else if ( !TNT_(clo_trace_taint_only) )
      VG_(printf)( "t%d_%d <- t%d_%d, t%d_%d\n", ltmp, _ti(ltmp), rtmp1, _ti(rtmp1), rtmp2, _ti(rtmp2) );
#endif
   else
      VG_(printf)("\n");
}

// ltmp = ctmp? const1 : const2
VG_REGPARM(3)
void TNT_(h64_ite_cc) (
   IRStmt *clone, 
   ULong value, 
   ULong taint ) {
   
   H_WRTMP_BOOKKEEPING

   if( TNT_(clo_critical_ins_only) ) return;

#if _SECRETGRIND_
   if (!TNT_(clo_trace)) { return; }
#endif

   H_EXIT_EARLY
   H64_PC

   IRExpr *data = clone->Ist.WrTmp.data;
   UInt ctmp    = data->Iex.ITE.cond->Iex.RdTmp.tmp;
   ULong c1     = extract_IRConst64(data->Iex.ITE.iftrue->Iex.Const.con);
   ULong c2     = extract_IRConst64(data->Iex.ITE.iffalse->Iex.Const.con);

   tl_assert( ctmp  < TI_MAX );
   if ( (ti[ctmp] & 0x80000000) == 0 ) return;

   VG_(sprintf)( aTmp, "t%d_%d = t%d_%d ? 0x%llx : 0x%llx",
                 ltmp, _ti(ltmp), ctmp, _ti(ctmp), c1, c2 );
   H64_PRINT

   // Information flow
#if _SECRETGRIND_
   if ( !TNT_(clo_trace_taint_only) || is_tainted(ltmp) )
#else
   if ( is_tainted(ltmp) )
#endif
      VG_(printf)( "t%d_%d <- t%d_%d\n", ltmp, _ti(ltmp),
                                         ctmp, _ti(ctmp) );
   else
      VG_(printf)("\n");
}

// ltmp = callee( arg[0], ... )
VG_REGPARM(3)
void TNT_(h64_ccall) (
   IRStmt *clone, 
   ULong value, 
   ULong taint ) {
   
   H_WRTMP_BOOKKEEPING
}

// No decoding necessary. Just print the string
VG_REGPARM(3)
void TNT_(h64_none) ( 
   HChar *str, 
   ULong value, 
   ULong taint ) {
   
   //VG_(printf)("TNT_(h64_none) %s value=%llx taint=%llx\n", str, value, taint);
   if( TNT_(clo_critical_ins_only) ) return;

#if _SECRETGRIND_
   if (!TNT_(clo_trace)) { return; }
#endif

   H_EXIT_EARLY
   H64_PC

   VG_(sprintf)( aTmp, "%s", str);
   H64_PRINT

   // No information flow info
   VG_(printf)("\n");
}
/*-- End of 64-bit helpers --*/

#if _SECRETGRIND_

static void TNT_(rawInst2Str)(char *out, SizeT olen, Addr a, SizeT alen) {
	unsigned i;
	
	for (i=0; i<alen; ++i) {
		char tmp[4];
		// use low-hex coz it's the default in objdump and gdb
		if ( i == 0 ) { *out = '\0'; VG_(sprintf)(tmp, "%02x", *((UChar*)a+i) ); }
		else 		 { VG_(sprintf)(tmp, " %02x", *((UChar*)a+i) ); }
		tl_assert ( VG_(strlen)(out) < olen - 3 ); // sizeof(instRaw) - 3 > 0 we know that
		VG_(strcat)(out, tmp);
	}
	
}

static void TNT_(format_mnemonics_and_id)(Inst_t *ins, char *out, SizeT olen) {
	
	tl_assert ( ins && "ins is NULL" );
	
	char instRaw[128] = "\0";
	Int len = ins->len;
	Addr64 addr = ins->addr;
	
	// get the mnemonic
	tl_assert ( TNT_(asm_guest_pprint)(addr, len, ins->mnemonics, sizeof(ins->mnemonics) ) && "Failed TNT_(asm_guest_pprint)");
		
	// prepare the raw instruction to print as hex
	TNT_(rawInst2Str)(instRaw, sizeof(instRaw), addr, len);
		
	// version sprintf
	tl_assert ( VG_(snprintf)(out, olen, "0x%llX: %s: %s     ID _%lx_:", addr, instRaw, ins->mnemonics, ins->ID) < olen ); 
	
}

VG_REGPARM(1)
void TNT_(hxx_imark_t) ( IRStmt *clone) {
	
	/*
	 * Note: this was an attempt to print the machine code mnemonics
	 * But it's too much of a hassle to do now because I must replace
	 * all libc functions in capstone, to use valgrind versions instead.
	 * It's clearly do-able
	 */

	// bail out if not needed
	if ( !TNT_(clo_mnemonics) )	{ return; }
	
	// set instruction info
	TNT_(current_inst.addr) = clone->Ist.IMark.addr;
	TNT_(current_inst.len) = clone->Ist.IMark.len;
	TNT_(current_inst.mnemonics)[0] = '\0';
	TNT_(current_inst.ec) = 0;
	++ TNT_(current_inst.ID);
	
	// this is a hack :-( because valgrind can't give me the right stack trace for certain inst
	// so I added this option for users to tell me which ones I should spend more resources on.
	// Obviously i'd like to retrieve all of them here, but it hurst performance ...
	
	if ( UNLIKELY( TNT_(inst_need_fix)( TNT_(current_inst.ID) ) ) ) {
		TNT_(current_inst.ec) = VG_(record_ExeContext)( VG_(get_running_tid)(), 0 );
	}
	
	// set the ready flag
	TNT_(mnemoReady) = True;
	
	//tl_assert ("got ya" && TNT_(current_inst.ID) != 0x8934c6);
}


static Bool TNT_(parse_data)(const char *in, const char *left, const char *right, char *out, SizeT len)
{
	Bool ret = False;
	char *p = 0;
	#define GOTO_ERR do{ LOG("err line %u\n", __LINE__); goto end; }while(0)
	(*out) = '\0';
	
	// get the location
	if ( (p=VG_(strstr(in, left))) == NULL) { GOTO_ERR; }
	if ( !(libc_strlcpy(out, p+VG_(strlen(left)), len) < len) ) { GOTO_ERR; }
	if ( right ) {
		if ( (p=VG_(strstr(out, right))) == NULL) { GOTO_ERR; }
		(*p) = '\0';
	}
	
	ret = True;
	
	end:
	return ret;
}


//inline static Bool TNT_(is_known_varname)(char *vname) { (VG_(strstr)(vname, UNKNOWN_OBJ) == 0); }
static void TNT_(format_varname)(char *varnamebuf, SizeT bufsize, char *loc, char *offset, char *varname, char *filename, char *lineno, char *funcname, char *basename)
{
	if ( (*offset) != '0' ) { VG_(snprintf)(varnamebuf, bufsize, "@%s:%s[%s]", /*basename,*/ loc, varname, offset);	}
	else 					{ VG_(snprintf)(varnamebuf, bufsize, "@%s:%s", /*basename, */loc, varname);				}
	//VG_(snprintf)(varnamebuf, bufsize, "@%s:%s[%s]", /*basename,*/ loc, varname, offset);
}

static void TNT_(format_detailedvarname)(char *varnamebuf, SizeT bufsize, char *loc, char *offset, char *varname, char *filename, char *lineno, char *funcname, char * basename)
{
	if ( (*offset) != '0' )	{ VG_(snprintf)(varnamebuf, bufsize, "%s:%s:@%s:%s[%s]", filename, lineno, loc, varname, offset); 	}
	else 					{ VG_(snprintf)(varnamebuf, bufsize, "%s:%s:@%s:%s", filename, lineno, loc, varname);	}
	//VG_(snprintf)(varnamebuf, bufsize, "%s:%s:@%s:%s[%s]", filename, lineno, loc, varname, offset);
}

void TNT_(get_object_name)(char *objname, SizeT n)
{
	HChar binarynamebuf[1024] = "\0";
	UInt pc = VG_(get_IP)(VG_(get_running_tid)());
	
	// what shall I use? Both I think !
	// VG_(describe_IP) ( pc, binarynamebuf, 1024, NULL );
	#define VERSION 0
	
	// describe the IP -- Note: shall we use this for live inst too?
	#if VERSION == 1
	VG_(describe_IP) ( pc, binarynamebuf, sizeof(binarynamebuf), NULL );
	libc_strlcpy(objname, binarynamebuf, n); // assume all written for now
	
	// get the object name and add it if not already present in what we already have
	tl_assert ( VG_(get_objname)(pc, binarynamebuf, sizeof(binarynamebuf)) && "could not get obj name" );
	//tl_assert ( VG_(get_objname)(pc, binarynamebuf, sizeof(binarynamebuf)) && "could not get obj name" );
	//p = binarynamebuf;//libc_basename(binarynamebuf);
	if ( VG_(strstr)(objname, binarynamebuf) == 0) {
		VG_(snprintf)( objname+VG_(strlen)(objname), n-VG_(strlen)(objname), " (in %s)", binarynamebuf);
		//libc_strlcpy(objname+VG_(strlen)(objname), binarynamebuf, n-VG_(strlen)(objname)); // assume all written
	} 
	
	
	// add space at the end
	libc_strlcat(objname, " ", n-VG_(strlen)(objname));
	
	LOG("objname:%s\n", objname);
	
	#else // VERSION 0
	
	char *p = 0;
	
	// get the object name and add it if not already present in what we already have
	tl_assert ( VG_(get_objname)(pc, binarynamebuf, sizeof(binarynamebuf)) && "could not get obj name" );
	p = libc_basename(binarynamebuf);
	libc_strlcpy(objname, p, n); // assume all written
	
	LOG("objname:%s basename:%s\n", objname, p);
	#endif
	
	
}

// i put these together so if we decide to change the formating, we'll hopefull realize we also need to change the IS_VARNAME one...
static void TNT_(parse_all_descr)(char *descr1, char *descr2, 
									char *varnamebuf, SizeT bufsize, char *detailedvarnamebuf, SizeT detailedbufsize) 
{
	#define LOCATION "Location "
	#define IS " is "
	#define BYTE_INSIDE " bytes inside "
	#define LOCAL_VAR_LEFT "local var \""
	#define GLOBAL_VAR_LEFT "global var \""
	#define VAR_RIGHT "\""
	#define LOCAL_STACK_VAR_LEFT BYTE_INSIDE
	#define DECLARED "declared at "
	#define DDOTS ":"
	#define COMMA ","
	SizeT LEN = 256;
	char location[LEN], offset[LEN], varname[LEN], filename[LEN], lineno[LEN], funcname[LEN];
	SizeT size = LEN;
	HChar objname[128];
	SizeT ltmp=0;
	
	LOG_ENTER();
	
	if ( TNT_(parse_data)(descr1, LOCATION, IS, location, size) ) { LOG("location: %s\n", location); }
	if ( TNT_(parse_data)(descr1, IS, BYTE_INSIDE, offset, size) ) { LOG("offset: %s\n", offset); }
	if ( TNT_(parse_data)(descr1, LOCAL_VAR_LEFT, VAR_RIGHT, varname, size) ||
		 TNT_(parse_data)(descr1, GLOBAL_VAR_LEFT, VAR_RIGHT, varname, size) ||
		 TNT_(parse_data)(descr1, LOCAL_STACK_VAR_LEFT, 0, varname, size)  ) { LOG("varname: %s\n", varname); }
	if ( TNT_(parse_data)(descr2, DECLARED, DDOTS, filename, size) ) { LOG("filename: %s\n", filename); }
	if ( TNT_(parse_data)(descr2, DDOTS, COMMA, lineno, size) ) { LOG("line: %s\n", lineno); }
	if ( VG_(get_fnname)( VG_(get_IP)(VG_(get_running_tid)()), funcname, size ) ) { LOG("funcname: %s\n", funcname); }
	
	// fix the ',' at the end
	if ( varname[0] != '\0' && varname[ VG_(strlen)(varname) - 1 ] == ',' ) { varname[ VG_(strlen)(varname) - 1 ] = '\0'; }
		
	// fix the [0] at the end
	ltmp = VG_(strlen)(varname);
	if ( ltmp>=3 && VG_(strcmp)(&varname[ltmp-3], "[0]") == 0 ) {
		varname[ltmp-3] = '\0';
	}
	
	TNT_(get_object_name)(objname, sizeof(objname));
	
	// format the varname to display live, always curr_addr:name[offset]
	TNT_(format_varname)(varnamebuf, bufsize, location, offset, varname, filename, lineno, funcname, objname);
	
	// format for summary (detailed) variable
	if (detailedvarnamebuf && detailedbufsize) {
		TNT_(format_detailedvarname)(detailedvarnamebuf, detailedbufsize, location, offset, varname, filename, lineno, funcname, objname);
	}
	
	LOG_EXIT();
}

ExeContext * TNT_(retrieveExeContext)() {
	
	// fix the stack trace if necessary. That's because valgrind has a bug -- as far as i see it -- such that record_exeContext and get_StackTrace
	// do no keep the whole call history. So here I'm formatting it in a buffer...
	// this is rare but happens anyway...
	ExeContext *ec = 0;
	if ( UNLIKELY( TNT_(current_inst.ec) != 0 ) ) {
		ec = TNT_(current_inst.ec);
	} else {
		ec = VG_(record_ExeContext)( VG_(get_running_tid)(), 0 );
	}
	
	return ec;
}

static HP_Chunk * _alloc_basic(Addr a, SizeT reqLen, SizeT slopLen, sn_addr_type_t type, Bool api)
{
	if ( type == SN_ADDR_UNKNOWN ) { type = TNT_(get_addr_type)(a); }
	HP_Chunk* hc = VG_(malloc)("tnt.main.rb.x", sizeof(HP_Chunk));
	tl_assert ( hc && "hc NULL" );
	VG_(memset)(hc, 0, sizeof(HP_Chunk));
	tl_assert ( hc && "hc NULL" );
	hc->req_szB  = reqLen;
	hc->slop_szB = slopLen;
	hc->data     = a;
	hc->addrType = type;
	hc->api = api?1:0;
	if ( TNT_(clo_summary_verbose) 		|| 
		 type == SN_ADDR_HEAP_MALLOC 	|| 
		 type == SN_ADDR_MMAP_FILE ) { 
			 
		hc->stack_trace = TNT_(retrieveExeContext)();	
	}
	
	// Note: currently we only print this for mem locations on the stack...
	if ( TNT_(clo_mnemonics) ) {
		// Note: TNT_(current_inst.mnemonics) may contain nothing, ie empty strings if trace is turned off
		VG_(memcpy)(&hc->inst, &TNT_(current_inst), sizeof(TNT_(current_inst)));
	}
	
	return hc;
}

/*HP_Chunk * TNT_(alloc_chunk_from_varnames)(Addr a, SizeT reqLen, SizeT slopLen, const char *name, const char *dname)
{
	return TNT_(alloc_chunk_from_varnames_and_type)(a, reqLen, slopLen, name, dname, SN_ADDR_UNKNOWN);
}*/

HP_Chunk * TNT_(alloc_chunk_from_varnames_and_type)(Addr a, SizeT reqLen, SizeT slopLen, const char *name, const char *dname, sn_addr_type_t type, Bool api)
{
	HP_Chunk *hc = _alloc_basic(a, reqLen, slopLen, type, api);
	libc_strlcpy(hc->vname, name, sizeof(hc->vname));
	libc_strlcpy(hc->vdetailedname, dname, sizeof(hc->vdetailedname));
	
	LOG("alloc_chunk_from_varnames add block type %s name=%s dname=%s 0x%lx[%lu]\n", TNT_(addr_type_to_string)(hc->addrType), hc->vname, hc->vdetailedname, hc->data, hc->req_szB);
	//if ( hc->addrType == SN_ADDR_HEAP_MALLOC ) {
		// this is now the case for all blocks, except it means differrnt things
		tl_assert (hc->stack_trace && "invalid hc->stack_trace");
		LOG("context %u %p %p:\n", VG_(get_ECU_from_ExeContext)(hc->stack_trace), hc->stack_trace, hc);
		//TNT_(print_ExeContext)( hc->stack_trace, VG_(get_ExeContext_n_ips)(hc->stack_trace) ); // note: there does not seem to be a function to free this after 
	//}
	LOG_EXIT();
	return hc;
}

// WARNING: never call this one frmo mmap/malloc modules, as this will go into an infinite loop as describe_data calls them to check addr type
// for these modules, one must use the above function alloc_chunk_from_varnames_and_type, and add the block themselves
void TNT_(alloc_chunk_from_fn_and_add_sum_block)(Addr a, SizeT reqLen, SizeT slopLen, Bool api, const char *fn)
{
	//HP_Chunk* hc = _alloc_basic(a, reqLen, slopLen, SN_ADDR_UNKNOWN);
	
	//hc->api = api?1:0;
	//VG_(printf)("first hc:%lx\n", hc);
	//Note: describe_data adds the block to the summary -- thru sum_add_block
	char		  vname[256];
    char		  vdetailedname[1024];
	TNT_(describe_data)(a, vname, sizeof(vname), vdetailedname, sizeof(vdetailedname), fn, reqLen+slopLen, api);
	
    //LOG("alloc_chunk_from_fn_and_add_sum_block add block type %s %s %s 0x%lx[%lu]\n", TNT_(addr_type_to_string)(hc->addrType), hc->vname, hc->vdetailedname, hc->data, hc->req_szB);
    //if ( hc->addrType == SN_ADDR_HEAP_MALLOC ) {
		// this is now the case for all blocks, except it means differrnt things
	//	tl_assert (hc->stack_trace && "invalid hc->stack_trace");
	//	LOG("context %u %p %p:\n", VG_(get_ECU_from_ExeContext)(hc->stack_trace), hc->stack_trace, hc);
		//TNT_(print_ExeContext)( hc->stack_trace, VG_(get_ExeContext_n_ips)(hc->stack_trace) );
	//}
	
	// add the block to summary
	// i know it's been added by describe_data, but i want this one to be added because it contains the api bit set
	// actually i should add a param to describe_data to not add the block to summary:TODO
	// on the bright side, api call to taint memory is super rare...
	//TNT_(sum_add_block)(hc);
	
	//return hc;
}

SizeT TNT_(size_of_taint)(ULong taint)
{
	unsigned char S = sizeof(taint);
	SizeT i, lastTaint=0;
	for (i=0; i<S; ++i) {
		if ( *((unsigned char*)(&taint)+i) != 0x0 ) {
			// Note: there could bytes bytes in-between not tainted... but we consider them tainted for now
			// This does NOT mean we're over tainting mem coz this function is used only to know the length
			// of tainted blocks when tracking tainted memory
			lastTaint = i+1;
		}
	}
	
	return lastTaint;
}

/*------------------------------------------------------------*/
/*--- utility function for finding local/global variable   ---*/
/*--- name from data address, using debug symbol tables.   ---*/
/*------------------------------------------------------------*/
void TNT_(describe_data)(Addr addr, HChar* varnamebuf, SizeT bufsize, HChar* detailedvarnamebuf, SizeT detailedbufsize, const char *fn, SizeT len, Bool api) {
	
	LOG("describe_data for addr 0x%lx len %lu\n", addr, len);
	
	if ( TNT_(clo_batchmode) ) { return; }
	// NOTE: for heap, see https://github.com/svn2github/valgrind/blob/master/helgrind/hg_addrdescr.c
	
	// if not global var, check what kind of addr we're looking at
	AddrInfo info; info.tag = Addr_Undescribed;
	VG_(describe_addr) (addr, &info );
	
	// zero all
	if ( varnamebuf && bufsize ) { varnamebuf[0] = '\0'; }
	if (detailedvarnamebuf && detailedbufsize) { detailedvarnamebuf[0] = '\0'; }
	
	// Note: i use this fn because i don't want to update all the places where H_VAR is called
	//SizeT len = TNT_(get_oplen_from_fnname)(fn, taint);
	Bool recordBlk = (len>0) && TNT_(clo_summary_verbose) && (VG_(strstr)(fn, "store")!=0 || VG_(strstr)(fn, "Store")!=0); // we only record the block if we're writing to it
	LOG("recordBlk:%d (%s)\n", recordBlk, fn);
	
	
	// dont do unnecessary work if we dont need to record or print
	// continue iif:
	// - need to record the block OR
	// - show trace + taint OR
	// - show trace + no taint + trace non tainted
	if ( !( recordBlk || (TNT_(clo_trace) && (len>0 || !TNT_(clo_trace_taint_only)) ) ) ) { return; }
	
	// if we're here, we must provide data description
	// does the user want details about addresses?
	if ( TNT_(clo_var_name) ) {
			
		// see include/pub_tool_addrinfo.h
		switch(info.tag)
		{
			case Addr_Undescribed: 	// as-yet unclassified
			case Addr_Unknown:     	// classification yielded nothing useful
			{
				//VG_(printf)("address 0x%08x is %s\n", info.tag==Addr_Undescribed?"Undescribed":"Unknown");
				//tl_assert(0 && "Invalid address");
				LOG("%s address\n", info.tag==Addr_Unknown?"Unknown":"Undescribed");
				break;
			}
			
			case Addr_SectKind:		// last-ditch classification attempt
			{
				LOG("Addr_SectKind\n");
				// this gives us the name of obj like executable name
				// we could get the filename at least ot help user?
				// for now I don't use it...
				//VG_(strncpy)(varnamebuf,info.Addr.SectKind.objname, bufsize-1);
				//varnamebuf[bufsize-1] = '\0';
				
				// ===============================================================================================================
				// WARNING: this does NOT work since we cannot figure the size of the object
				// this is only "useful" when the executable is stripped of symbols...
				// During summary display, some tainted blocks will be missing in the detaile description
				// ===============================================================================================================
				char objname[128];
				TNT_(get_object_name)(objname, sizeof(objname));
				VG_(snprintf)( varnamebuf, bufsize, UNKNOWN_OBJ_IN_EXE_FMT, objname, addr, VG_(getpid)(),  VG_(get_running_tid)());
				libc_strlcpy( detailedvarnamebuf, varnamebuf, detailedbufsize<bufsize?detailedbufsize:bufsize ); // assume all written
				
				if ( recordBlk ) {
					HP_Chunk * hc = TNT_(alloc_chunk_from_varnames_and_type)(addr, len, 0, varnamebuf, detailedvarnamebuf, SN_ADDR_GLOBAL, api);
					tl_assert ( hc && "hc NULL" );
					
					LOG("add block type %s %s %lx[%lu]\n", TNT_(addr_type_to_string)(SN_ADDR_GLOBAL), hc->vname, hc->data, hc->req_szB);
					
					TNT_(sum_add_block)(hc/*, SN_ADDR_GLOBAL*/);
					recordBlk = False; // we're done
				}
				
				
				break;
			}
			
			case Addr_Block:       // in malloc'd/free'd block
			{
				LOG("Addr_Block\n");
				/* NOTE: for heap, see https://github.com/svn2github/valgrind/blob/master/helgrind/hg_addrdescr.c
				 but I don't use it coz my final summary needs things differently
				 * */
				// don't use this info, it's just saying "client"
				//VG_(strncpy)(varnamebuf, info.Addr.Block.block_desc, bufsize-1);
				//varnamebuf[bufsize-1] = '\0';
				LOG("block_kind:%u block_desc:%s\n", info.Addr.Block.block_kind, info.Addr.Block.block_desc);
				
			#if 0
				// lookup the name of a pointer to this heap memory
				if ( TNT_(malloc_get_varname)(addr, varnamebuf, bufsize, detailedvarnamebuf, detailedbufsize) == False ) {
					LOG("Addr_Block malloc_get_varname 0x%lx failed\n", addr);
					tl_assert ("failed get Addr_Block name" && 0);
				}
			#else
				// i used to use the get name function above.
				// now that i get the chunk, no need to duplicate the code
				HP_Chunk *parent = TNT_(malloc_get_parent_block)(addr, len); // this function aborts of no parent is found
				libc_strlcpy(varnamebuf, parent->vname, bufsize);
				libc_strlcpy(detailedvarnamebuf, parent->vdetailedname, detailedbufsize);
				
				HP_Chunk * hc = TNT_(alloc_chunk_from_varnames_and_type)(addr, len, 0, varnamebuf, detailedvarnamebuf, SN_ADDR_HEAP_MALLOC, api);
				tl_assert (hc && "hc NULL");
				
				// set the parent of the malloc()'ed file block
				TNT_(malloc_set_parent)(hc, parent);
				
				TNT_(sum_add_block)(hc/*, hc->addrType*/);
			#endif
				
				recordBlk = False; // we're done
				
				// Use VG_(addr_is_in_block)(a, cgbs[i].start, cgbs[i].size, 0))
				//Addr *p = 0xffefff910;
				//VG_(printf)("at 0xffefff910 we have x%lx\n", *p);
				//VG_(pp_ExeContext)(info.Addr.Block.stack_trace);
				break;
			}
			
			case Addr_Stack:       // on a thread's stack       
			{
				LOG("Addr_Stack\n");
				LOG("IP:0x%lx frameNo:%u stackPos:%u spoffset:%lu\n", info.Addr.Stack.IP, info.Addr.Stack.frameNo, info.Addr.Stack.stackPos, info.Addr.Stack.spoffset);
				
				//if ( TNT_(malloc_get_varname)(addr, varnamebuf, bufsize) == False ) {
				//	VG_(printf)("getHeapVarName failed\n");
				//}
				
				// ===============================================================================================================
				// WARNING: this is not thoroughly tested because it's only "useful" when the executable is stripped of symbols
				// ===============================================================================================================
				char objname[128];
				TNT_(get_object_name)(objname, sizeof(objname));
				VG_(snprintf)( varnamebuf, bufsize, UNKNOWN_OBJ_IN_EXE_FMT, objname, addr, VG_(getpid)(),  VG_(get_running_tid)() );
				libc_strlcpy( detailedvarnamebuf, varnamebuf, detailedbufsize<bufsize?detailedbufsize:bufsize ); // assume all written
				
				if ( recordBlk ) {
					HP_Chunk * hc = TNT_(alloc_chunk_from_varnames_and_type)(addr, len, 0, varnamebuf, detailedvarnamebuf, SN_ADDR_STACK, api);
					tl_assert ( hc && "hc NULL" );
					
					LOG("add block type %s %s %lx[%lu]\n", TNT_(addr_type_to_string)(SN_ADDR_STACK), hc->vname, hc->data, hc->req_szB);
						
					TNT_(sum_add_block)(hc/*, SN_ADDR_STACK*/);
					recordBlk = False; // we're done
				}
				
				break;
			}
			
			case Addr_DataSym:     // in a global data sym
			{
				// Note (ULong)ai->Addr.DataSym.offset is the offset within variable "DataSym.name"
				LOG("Addr_DataSym\n");
				VG_(strncpy)(varnamebuf, info.Addr.DataSym.name, bufsize-1);
				varnamebuf[bufsize-1] = '\0';
				LOG("sym name:%s[%lu]\n", varnamebuf, info.Addr.DataSym.offset);
				
				if ( recordBlk ) {
					HP_Chunk * hc = TNT_(alloc_chunk_from_varnames_and_type)(addr, len, 0, varnamebuf, detailedvarnamebuf, SN_ADDR_GLOBAL, api);
					tl_assert ( hc && "hc NULL" );
					
					LOG("add block type %s %s %lx[%lu]\n", TNT_(addr_type_to_string)(SN_ADDR_GLOBAL), hc->vname, hc->data, hc->req_szB);
						
					TNT_(sum_add_block)(hc/*, SN_ADDR_GLOBAL*/);
								
					recordBlk = False; // we're done
				}
				
				/* Note: this can also be done for this particular case with the following
				PtrdiffT pdt;
				if ( VG_(get_datasym_and_offset)( addr, varnamebuf, bufsize, &pdt ) == True ) {
					// we're done, return
					return;
				}*/
				break;
			}
		  
			case Addr_Variable:    // variable described by the debug info
			{
				LOG("Addr_Variable\n");
				
				if ( info.Addr.Variable.descr1 != NULL ) {
					LOG("descr1 %s\n", (HChar*)VG_(indexXA)(info.Addr.Variable.descr1, 0));
				}
				
				if ( info.Addr.Variable.descr2 != NULL ) {
					LOG("descr2 %s\n", (HChar*)VG_(indexXA)(info.Addr.Variable.descr2, 0));
					char *descr2 = (HChar*)VG_(indexXA)(info.Addr.Variable.descr2, 0);
					// only get the name if it corresponds to source code under analysis, no valgrind's internal
					if ( /*VG_(strstr)(descr2, "vg_replace_malloc.c") == NULL &&*/ info.Addr.Variable.descr1 != NULL) {
						char *descr1 = (HChar*)VG_(indexXA)(info.Addr.Variable.descr1, 0);
						//VG_(strncpy)(varnamebuf, descr1+VG_(strlen)(descr1)-10, 10);
						
						varnamebuf[0] = '\0';
						TNT_(parse_all_descr)(descr1, descr2, varnamebuf, bufsize, detailedvarnamebuf, detailedbufsize);
						
						if ( recordBlk ) {
							
							sn_addr_type_t type = TNT_(get_addr_type)(addr);

							// add this block info to the list of locations for summary
							// Note: this is either a stack local variable, or a global.
							// it CANNOT be in the heap -- handled in case Addr_Block above
							tl_assert ( type != SN_ADDR_HEAP_MALLOC );
							HP_Chunk * hc = TNT_(alloc_chunk_from_varnames_and_type)(addr, len, 0, varnamebuf, detailedvarnamebuf, type, api);
							TNT_(sum_add_block)(hc/*, hc->addrType*/);
							
							// set the parent of the mmap()'ed file block
							if ( SN_ADDR_MMAP_FILE == type ) {
								HP_Chunk *parent = TNT_(syswrap_mmap_get_parent_block)(addr, len); // this function aborts of no parent is found
								TNT_(syswrap_mmap_set_parent)(hc, parent);
							}
			
							recordBlk = False; // we're done
						}
								
						
					}
				}
				break;
			}
		  
		  
			default: 
			{
				tl_assert (0 && "Invalid info.tag");
			}
		}
		
		// could not get data
		if ( varnamebuf[0] == '\0' ) {
			char objname[128];
			TNT_(get_object_name)(objname, sizeof(objname));
			VG_(snprintf)( varnamebuf, bufsize, UNKNOWN_OBJ_IN_EXE_FMT, objname, addr, VG_(getpid)(),  VG_(get_running_tid)() );
		}
		
		if ( detailedvarnamebuf && detailedbufsize && detailedvarnamebuf[0] == '\0') {
			
			libc_strlcpy( detailedvarnamebuf, varnamebuf, detailedbufsize ); // assume all written
			
			// default, add it
			if ( recordBlk ) {
				
				sn_addr_type_t type = TNT_(get_addr_type)(addr);

				// add this block info to the list of locations for summary
				// Note: it CANNOT be in the heap -- handled in case Addr_Block above
				// since in this case we ALREADY have
				tl_assert ( type != SN_ADDR_HEAP_MALLOC );
				HP_Chunk * hc = TNT_(alloc_chunk_from_varnames_and_type)(addr, len, 0, varnamebuf, detailedvarnamebuf, type, api);
				TNT_(sum_add_block)(hc/*, hc->addrType*/);
				
				// set the parent of the mmap()'ed file block
				if ( SN_ADDR_MMAP_FILE == type ) {
					HP_Chunk *parent = TNT_(syswrap_mmap_get_parent_block)(addr, len); // this function aborts of no parent is found
					TNT_(syswrap_mmap_set_parent)(hc, parent);
				}
			}
						
		}
		
		//if ( (VG_(strstr)(fn, "store")!=0 || VG_(strstr)(fn, "Store")!=0) && addr >= 0xffeffd7c8 && addr<= 0xffeffd7cf ) {
			//EMIT_SUCCESS("-> %s addr %lx with length %lu (%s)\n", "store at",addr, len, detailedvarnamebuf);
			//TNT_(print_CurrentStackTrace) ( VG_(get_running_tid)(), 20, "test" );
		//}
		
		// clear data allocated by VG_(describe_addr)
		VG_(clear_addrinfo)(&info);
		
	} else { // end if ( TNT_(clo_var_name) )	
	
		// user does not request variable names, just copy the address
		VG_(snprintf)( varnamebuf, bufsize, RAW_ADDR_FMT, addr );
		libc_strlcpy( detailedvarnamebuf, varnamebuf, detailedbufsize );
		if ( recordBlk ) {
				
			sn_addr_type_t type = TNT_(get_addr_type)(addr);
			
			HP_Chunk * hc = TNT_(alloc_chunk_from_varnames_and_type)(addr, len, 0, varnamebuf, detailedvarnamebuf, type, api);
			tl_assert (hc && "hc NULL");
						
			if ( SN_ADDR_HEAP_MALLOC == type ) {
				// heap - add this block to an existing one
				HP_Chunk *parent = TNT_(malloc_get_parent_block)(addr, len); // this function aborts of no parent is found
				TNT_(malloc_set_parent)(hc, parent);
				
			} else if ( SN_ADDR_MMAP_FILE == type ) {
				HP_Chunk *parent = TNT_(syswrap_mmap_get_parent_block)(addr, len); // this function aborts of no parent is found
				TNT_(syswrap_mmap_set_parent)(hc, parent);
			}
			
			TNT_(sum_add_block)(hc/*, hc->addrType*/);
		}
	}
	
	
	LOG_EXIT();
}

#else

void TNT_(describe_data)(Addr addr, HChar* varnamebuf, UInt bufsize, enum VariableType* type, enum VariableLocation* loc) {

	// first try to see if it is a global var
	PtrdiffT pdt;
	#if _SECRETGRIND_
	char buf[1024];
	if ( VG_(get_datasym_and_offset)( addr, varnamebuf, bufsize, &pdt ) == True ) {
		// we're done, return
		//return;
	}
	#else
	VG_(get_datasym_and_offset)( addr, varnamebuf, bufsize, &pdt );
	#endif

	/// test lolo
	AddrInfo info; info.tag = Addr_Undescribed;
	VG_(describe_addr) (addr, &info );
	//if (info.tag != Addr_Undescribed) {
		//VG_(printf)("Bingo\n"); //VG_(exit)(0);
		//VG_(printf)("info->tag %x\n", info.tag);
	//}
	
	
	
	UInt pc = VG_(get_IP)(VG_(get_running_tid)());
	HChar binarynamebuf[1024];
	if (VG_(get_objname)(pc, binarynamebuf, 1024) ) {
		//VG_(printf)("get_objname:%s\n", binarynamebuf);
	}

	// Seems to get exe name?
	if ( VG_(get_objname)(addr, varnamebuf, bufsize) )
	{
		//VG_(printf)("get_objname True\n");
	   //VG_(printf)("varname %s\n", varnamebuf);
	   return;
	}

        AddrInfo ai; ai.tag = Addr_Undescribed;
        VG_(describe_addr)(addr, &ai);
        //VG_(pp_addrinfo)(addr, &ai);
        

        if ( ai.tag == Addr_DataSym )
        {
			//VG_(printf)("WM Addr_DataSym\n");
           VG_(strncpy)(varnamebuf, ai.Addr.DataSym.name, bufsize);
           return;
        } else if ( ai.tag == Addr_Variable )
        {
			//VG_(printf)("WM Addr_Variable\n");
           //VG_(printf)("descr1 %s\n", VG_(indexXA)(ai.Addr.Variable.descr1,0) );
           //VG_(printf)("descr2 %s\n", VG_(indexXA)(ai.Addr.Variable.descr2,0) );
           //VG_(strncpy)(varnamebuf, VG_(indexXA)(ai.Addr.Variable.descr1,0), bufsize );
           return;
        }

	if( varnamebuf[0] == '\0' ){
		
		// now let's try for local var
		XArray* descr1
		      = VG_(newXA)( VG_(malloc), "tnt.da.descr1",
		                    VG_(free), sizeof(HChar) );
		XArray* descr2
		      = VG_(newXA)( VG_(malloc), "tnt.da.descr2",
		                    VG_(free), sizeof(HChar) );

		   (void) VG_(get_data_description)( descr1, descr2, addr );
		   /* If there's nothing in descr1/2, free them.  Why is it safe to to
		      VG_(indexXA) at zero here?  Because VG_(get_data_description)
		      guarantees to zero terminate descr1/2 regardless of the outcome
		      of the call.  So there's always at least one element in each XA
		      after the call.
		   */
		   if (0 == VG_(strlen)( VG_(indexXA)( descr1, 0 ))) {
		      VG_(deleteXA)( descr1 );
		      descr1 = NULL;
		   }

		   if (0 == VG_(strlen)( VG_(indexXA)( descr2, 0 ))) {
		      VG_(deleteXA)( descr2 );
		      descr2 = NULL;
		   }

		   /* Assume (assert) that VG_(get_data_description) fills in descr1
		      before it fills in descr2 */
		   if (descr1 == NULL)
		      tl_assert(descr2 == NULL);

		   /* If we could not obtain the variable name, then just use "unknownobj" */
		   if (descr1 == NULL) {
			   VG_(sprintf)( varnamebuf, "%lx_unknownobj", addr );
		   }
		   else {

//			   VG_(printf)("descr1: %s descr2: %s\n", (HChar*)VG_(indexXA)(descr1,0), (HChar*)VG_(indexXA)(descr2,0));

			   // descr1 will either be of the form:
			   // (1) Location 0xbef29644 is 0 bytes inside local var "n"
			   // or
			   // (2) Location 0xbed42644 is 0 bytes inside n[1],
			   // or
			   // (3) Location 0xbebb842c is 0 bytes inside args.str,
			   // or
			   // (4) Location 0xbebb842c is 0 bytes inside args[1].str,
			   // or
			   // (5) Location 0xbebb842c is 0 bytes inside args.str[0],
			   //
			   // So, the terminator for a variable name is either '"' or ','

			   HChar* descr1str =  (HChar*)VG_(indexXA)(descr1, 0);
			   const char* commonVarPrefix = "bytes inside ";
			   char* varPrefixPtr = VG_(strstr)(descr1str, commonVarPrefix);

			   tl_assert(varPrefixPtr != NULL);

			   // fast forward to start of var name
			   varPrefixPtr += (VG_(strlen)(commonVarPrefix)*sizeof(HChar));

			   // disambiguate between local var or others
			   const char* localVarPrefix = "local var ";
			   char* varStart = VG_(strstr)(varPrefixPtr, localVarPrefix);
			   HChar* varEnd;
			   int varNameLen = 0;

			   if (varStart == NULL) {
				   // case 2, 3, 4 or 5
				   varStart = varPrefixPtr;
				   varEnd = VG_(strchr)(varStart, ',');
//				   VG_(printf)("varStart: %s, varEnd: %s, descr1: %s, descr2: %s\n", varStart, varEnd, descr1str, (HChar*)VG_(indexXA)(descr2,0));
				   tl_assert(varEnd != NULL);
			   }
			   else {
				   // case 1: local variable
				   varStart += ((VG_(strlen)(localVarPrefix)+1)*sizeof(HChar)); // +1 to skip first "
				   varEnd = VG_(strchr)(varStart, '"');
			   }

			   tl_assert(varStart != NULL);
			   tl_assert(varEnd != NULL);

//			   VG_(printf)("varStart: %s, varEnd: %s, descr1: %s, descr2: %s\n", varStart, varEnd, descr1str, (HChar*)VG_(indexXA)(descr2,0));
//			   VG_(printf)("varStart: %s, varEnd: %s\n", varStart, varEnd);

			   varNameLen = VG_(strlen)(varStart) - VG_(strlen)(varEnd);
			   if (varNameLen >= bufsize) {
				   varNameLen = bufsize-1;
			   }
//						   VG_(printf)("first: %s, second: %s, varnamelen: %d\n", first, second, varnamelen);
			   VG_(strncpy)(varnamebuf, varStart, varNameLen);
			   varnamebuf[varNameLen] = '\0';

////			   VG_(printf)("Addr: %x, Var: %s\n", addr, varnamebuf);
		   }

		   if (descr1 != NULL) {
			   VG_(deleteXA)( descr1 );
		   }

		   if (descr2 != NULL) {
			   VG_(deleteXA)( descr2 );
		   }

		   *type = Local;
	}
//	else {
//		// it's a global variable
//		*type = Global;
//
//		if (have_created_sandbox || IN_SANDBOX) {
//			tl_assert(client_binary_name != NULL);
//
//			// let's determine it's location:
//			// It is external from this application if the soname 
//      // field in its DebugInfo is non-empty
//      /*VG_(printf)("var: %s\n", varnamebuf);
//      DebugInfo* di = NULL;
//      while (di = VG_(next_DebugInfo)(di)) {
//        VG_(printf)("  soname: %s, filename: %s, handle: %d\n", VG_(DebugInfo_get_soname)(di), VG_(DebugInfo_get_filename)(di), VG_(DebugInfo_get_handle)(di));
//        XArray* gbs = VG_(di_get_global_blocks_from_dihandle)(VG_(DebugInfo_get_handle)(di), True);
//        //tl_assert(gbs);
//        int i, n = VG_(sizeXA)( gbs );
//        VG_(printf)("  n: %d\n", n);
//        for (i = 0; i < n; i++) {
//          GlobalBlock* gbp;
//          GlobalBlock* gb = VG_(indexXA)( gbs, i );
//          if (0) VG_(printf)("   new Global size %2lu at %#lx:  %s %s\n",
//                             gb->szB, gb->addr, gb->soname, gb->name );
//        }
//      }*/
//      //DebugInfo* di = VG_(find_DebugInfo)(addr);
//      //VG_(printf)("var: %s, di: %d\n", varnamebuf, di);
//      
//			UInt _pc = VG_(get_IP)(VG_(get_running_tid)());
//			HChar _binarynamebuf[1024];
//			VG_(get_objname)(_pc, _binarynamebuf, 1024);
//      //VG_(printf)("var: %s, declaring binary: %s, client binary: %s\n", varnamebuf, binarynamebuf, client_binary_name);
//			*loc = (VG_(strcmp)(_binarynamebuf, client_binary_name) == 0 && VG_(strstr)(varnamebuf, "@@") == NULL) ? GlobalFromApplication : GlobalFromElsewhere;
//      //*loc = GlobalFromElsewhere;
//		}
//	}
}
#endif // _SECRETGRIND_


/*------------------------------------------------------------*/
/*--- Initialisation                                       ---*/
/*------------------------------------------------------------*/

static void init_shadow_memory ( void )
{
   Int     i;
   SecMap* sm;

   tl_assert(V_BIT_TAINTED   == 1);
   tl_assert(V_BIT_UNTAINTED     == 0);
   tl_assert(V_BITS8_TAINTED == 0xFF);
   tl_assert(V_BITS8_UNTAINTED   == 0);

   /* Build the 3 distinguished secondaries */
   sm = &sm_distinguished[SM_DIST_NOACCESS];
   for (i = 0; i < SM_CHUNKS; i++) sm->vabits8[i] = VA_BITS8_NOACCESS;

   sm = &sm_distinguished[SM_DIST_TAINTED];
   for (i = 0; i < SM_CHUNKS; i++) sm->vabits8[i] = VA_BITS8_TAINTED;

   sm = &sm_distinguished[SM_DIST_UNTAINTED];
   for (i = 0; i < SM_CHUNKS; i++) sm->vabits8[i] = VA_BITS8_UNTAINTED;

   /* Set up the primary map. */
   /* These entries gradually get overwritten as the used address
      space expands. */
   // Taintgrind: Initialise all memory as untainted
   for (i = 0; i < N_PRIMARY_MAP; i++)
      primary_map[i] = &sm_distinguished[SM_DIST_UNTAINTED];
//      primary_map[i] = &sm_distinguished[SM_DIST_NOACCESS];

   /* Auxiliary primary maps */
   init_auxmap_L1_L2();

   /* auxmap_size = auxmap_used = 0;
      no ... these are statically initialised */

   /* Secondary V bit table */
   secVBitTable = createSecVBitTable();

#if 0
   // Taintgrind: Solely for testing
   TNT_(make_mem_tainted)(0xbe000000, 0x1000000);
#endif
}

//static void read_allowed_syscalls() {
//	char* filename = TNT_(clo_allowed_syscalls);
//	int fd = VG_(fd_open)(filename, VKI_O_RDONLY, 0);
//	if (fd != -1) {
//		Bool finished = False;
//		char c;
//		int syscallno = 0;
//		int i=0;
//		while (VG_(read)(fd, &c, 1)) {
//			if (c != '\n') {
//				syscallno = 10*syscallno + ctoi(c);
//			}
//			else {
//				// end of line
//				VG_(printf)("allowed_syscall: %s (%d)\n", syscallnames[syscallno], syscallno);
//				allowed_syscalls[syscallno] = True;
//				syscallno = 0;
//			}
//		}
//		VG_(close)(fd);
//	}
//	else {
//		VG_(printf)("Error reading allowed syscalls file: %s\n", filename);
//	}
//}


/*------------------------------------------------------------*/
/*--- Syscall event handlers                               ---*/
/*------------------------------------------------------------*/

static
void tnt_pre_syscall(ThreadId tid, UInt syscallno,
                           UWord* args, UInt nArgs)
{
#if _SECRETGRIND_
	//LOG("\e[32mtnt_pre_syscall %u\e[0m\n", syscallno);
	switch (syscallno) 
	{
		case __NR_exit:
		case __NR_exit_group:
		
			if ( UNLIKELY( !TNT_(clo_summary) ) ) { return; }
			if ( TNT_(clo_summary_main_only) ) { return; }
			
			taint_summary("On exit()");
			
			break;
			
		default: break;
	}
	
#endif
}

static
void tnt_post_syscall(ThreadId tid, UInt syscallno,
                            UWord* args, UInt nArgs, SysRes res)
{
	TNT_(syscall_allowed_check)(tid, syscallno);
	
	switch ((int)syscallno) {
#if defined VGO_freebsd
    case 3: //__NR_read:
      TNT_(syscall_read)(tid, args, nArgs, res);
      break;
    case 4: // __NR_write
      TNT_(syscall_write)(tid, args, nArgs, res);
      break;
    case 5: //__NR_open:
      TNT_(syscall_open)(tid, args, nArgs, res);
      break;
    case 6: //__NR_close:
      TNT_(syscall_close)(tid, args, nArgs, res);
      break;
    case 475: //__NR_pread64:
      TNT_(syscall_pread)(tid, args, nArgs, res);
      break;
    case 478: //__NR_lseek:
      TNT_(syscall_llseek)(tid, args, nArgs, res);
      break;
#else
    // Should be defined by respective vki/vki-arch-os.h
    case __NR_read:
      TNT_(syscall_read)(tid, args, nArgs, res);
      break;
    case __NR_write:
      TNT_(syscall_write)(tid, args, nArgs, res);
      break;
    case __NR_open:
    case __NR_openat:
      TNT_(syscall_open)(tid, args, nArgs, res);
      break;
    case __NR_close:
      TNT_(syscall_close)(tid, args, nArgs, res);
      break;
#if _SECRETGRIND_
	case __NR_mmap:
	  TNT_(syscall_mmap)(tid, args, nArgs, res);
	  break;
	case __NR_munmap:
	  TNT_(syscall_munmap)(tid, args, nArgs, res);
	  break;
#endif
    case __NR_lseek:
      TNT_(syscall_lseek)(tid, args, nArgs, res);
      break;
#ifdef __NR_llseek
    case __NR_llseek:
#endif
      TNT_(syscall_llseek)(tid, args, nArgs, res);
      break;
    case __NR_pread64:
      TNT_(syscall_pread)(tid, args, nArgs, res);
      break;
#ifdef __NR_recv
    case __NR_recv:
      TNT_(syscall_recv)(tid, args, nArgs, res);
      break;
#endif
#ifdef __NR_recvfrom
    case __NR_recvfrom:
      TNT_(syscall_recvfrom)(tid, args, nArgs, res);
      break;
#endif
#endif // VGO_freebsd
  }
}

Bool TNT_(handle_client_requests) ( ThreadId tid, UWord* arg, UWord* ret ) {
	switch (arg[0]) {
		case VG_USERREQ__TAINTGRIND_ENTER_PERSISTENT_SANDBOX: {
			persistent_sandbox_nesting_depth++;
			break;
		}
		case VG_USERREQ__TAINTGRIND_EXIT_PERSISTENT_SANDBOX: {
			persistent_sandbox_nesting_depth--;
			break;
		}
		case VG_USERREQ__TAINTGRIND_ENTER_EPHEMERAL_SANDBOX: {
			ephemeral_sandbox_nesting_depth++;
			break;
		}
		case VG_USERREQ__TAINTGRIND_EXIT_EPHEMERAL_SANDBOX: {
			ephemeral_sandbox_nesting_depth--;
			break;
		}
		case VG_USERREQ__TAINTGRIND_CREATE_SANDBOX: {
			have_created_sandbox = 1;
			break;
		}
		case VG_USERREQ__TAINTGRIND_SHARED_FD: {
			Int fd = arg[1];
			Int perm = arg[2];
			if (fd >= 0) {
				FD_SET_PERMISSION(fd, perm);
			}
			break;
		}
		case VG_USERREQ__TAINTGRIND_SHARED_VAR: {
			HChar* var = (HChar*)arg[1];
			Int perm = arg[2];
			Int var_idx = myStringArray_push(&shared_vars, var);
			VAR_SET_PERMISSION(var_idx, perm);
			break;
		}
		case VG_USERREQ__TAINTGRIND_UPDATE_SHARED_VAR: {
			// record next shared var to be updated so that we can
			// check that the user has annotated a global variable write
			next_shared_variable_to_update = (HChar*)arg[1];
			break;
		}
		case VG_USERREQ__TAINTGRIND_ALLOW_SYSCALL: {
			int syscallno = arg[1];
			allowed_syscalls[syscallno] = True;
			break;
		}
		case VG_USERREQ__TAINTGRIND_ENTER_CALLGATE: {
			callgate_nesting_depth++;
			break;
		}
		case VG_USERREQ__TAINTGRIND_EXIT_CALLGATE: {
			callgate_nesting_depth--;
			break;
		}
		case VG_USERREQ__TAINTGRIND_MAKE_MEM_TAINTED: {
			Addr addr = (Addr)arg[1];
			SizeT len = (SizeT)arg[2];
			
			/*AddrInfo info; info.tag = Addr_Undescribed;
			VG_(describe_addr) (addr, &info );
			VgSectKind kind = VG_(DebugInfo_sect_kind)(0,0, addr);
			VG_(printf)("info.tag:%u kind:%u\n", info.tag, kind);
			*/
			TNT_(make_mem_tainted)(addr, len);
			#if _SECRETGRIND_
			TNT_(record_receive_taint_for_addr)(addr, len, True, "API call");
			// keep track of varname
			//HChar varname[256];  HChar vardname[256]; 
		    //TNT_(describe_data)(addr, varname, sizeof(varname), vardname, sizeof(vardname), "Store-TAINTGRIND_MAKE_MEM_TAINTED", len);
		    #endif
			break;
		}
		case VG_USERREQ__TAINTGRIND_MAKE_MEM_UNTAINTED: {
			TNT_(make_mem_untainted)(arg[1], arg[2]);
			break;
		}
		#if _SECRETGRIND_
		case VG_USERREQ__TAINTGRIND_PRINT_ALL_INST: {	
		#else
		case VG_USERREQ__TAINTGRIND_START_PRINT: {	
		#endif
			TNT_(start_print)(False);
			break;
		}
		#if _SECRETGRIND_
		case VG_USERREQ__TAINTGRIND_PRINT_TAINTED_INST: {
			TNT_(start_print)(True);
			break;
		}
		#endif
		case VG_USERREQ__TAINTGRIND_STOP_PRINT: {
			TNT_(stop_print)();
			break;
		}
		#if _SECRETGRIND_
		case VG_USERREQ__TAINTGRIND_TAINT_SUMMARY: {
			taint_summary((const char*)arg[1]);
			break;
		}
	
		case VG_USERREQ__TAINTGRIND_READ_TAINT_STATUS: {
			var_taint_status((char*)arg[1], arg[2], arg[3]);
			break;
		}
		#endif
	}
	return True;
}

/*
   Taintgrind args
*/

// Defined in tnt_include.h
//#define MAX_PATH 256
//static Char   TNT_(default_file_filter)[]      = "";
#define LEN_DEFAULT 0x800000
#if _SECRETGRIND_
#	include "tnt_file_filter.h"
#else
HChar         TNT_(clo_file_filter)[MAX_PATH]  ;
#endif
Int           TNT_(clo_filetaint_start)            = 0;
Int           TNT_(clo_filetaint_len)              = LEN_DEFAULT;
Bool          TNT_(clo_taint_all)              	   = False;


//Int           TNT_(clo_after_kbb)              = 0;
//Int           TNT_(clo_before_kbb)             = -1;
Bool          TNT_(clo_trace_taint_only)       = True;
Bool          TNT_(clo_critical_ins_only)      = False;
Int           TNT_(do_print)                   = 0;
#if _SECRETGRIND_
ID_t		  TNT_(clo_list_inst_IDs)[MAX_FIX_IDS];	// zeroed at startup since non initialized data
Bool		  TNT_(clo_verbose)				   = False;
Bool          TNT_(clo_trace)		       	   = False;
SizeT		  TNT_(clo_mmap_pagesize)		   = 4096;
Bool 		  TNT_(clo_taint_stdin) 		   = False;
Bool          TNT_(clo_taint_df_only)       	= False;
Bool          TNT_(clo_taint_remove_on_release)    = False;
Bool          TNT_(clo_batchmode)        		= False;	// this one is not passed by user. See tnt_post_clo_init()
Bool          TNT_(clo_summary)			        = True;
Bool          TNT_(clo_summary_verbose)        = False;
Bool          TNT_(clo_summary_exit_only)      = False;
Bool          TNT_(clo_summary_main_only)      = False;
Bool          TNT_(clo_summary_total_only)     = False;
Bool		  TNT_(clo_var_name)			   = False;
Bool		  TNT_(clo_mnemonics)			   = False;
Bool		  TNT_(clo_taint_warn_on_release)	   = False;
Bool		  TNT_(clo_taint_show_source)	   = False;

Inst_t		  TNT_(current_inst)			   = {"",0,0,0};
// these are just used to be able to display the menomic accoring to the trace arguments (only tainted, all)
Bool		  TNT_(mnemoReady)				   = False;

Bool TNT_(taint_file_params_are_default)() {
	return (0 == TNT_(clo_filetaint_start) && LEN_DEFAULT == TNT_(clo_filetaint_len));
}
#endif // _SECRETGRIND_
//Char*         TNT_(clo_allowed_syscalls)       = "";
//Bool          TNT_(read_syscalls_file)         = False;

void init_soaap_data(void);

#if _SECRETGRIND_

Bool TNT_(inst_need_fix)(long ID) {
	unsigned i =0;
	
	for ( ; i<LEN( TNT_(clo_list_inst_IDs) ) ; ++i ) {
		
		if ( ID == TNT_(clo_list_inst_IDs)[i] ) {
			return True;
		}
		
		if ( 0 == TNT_(clo_list_inst_IDs)[i] ) {
			return False;
		}
	}
	
	return False;
}

static void parse_file_filter_list(const char *str) {
	
	SizeT i = 0;
	
	char *token;
	const char *del = ",";
	
	token = VG_(strtok)((HChar*)str, del);
	
	for ( i=0 ; i<TNT_(file_filter_get_max_length)() ; ++i ) {
		
		
	//	while( token != NULL ) {
		if ( token == NULL ) { break; }
		
		// now convert it
		TNT_(file_filter_set)(i, token);
		
		token = VG_(strtok)(NULL, del);
	}
	
}

static void parse_fix_instruction_id_list(const char *str) {
	SizeT i = 0;
	
	char *token;
	const char *del = ",";
	char *ptr;
	
	token = VG_(strtok)((HChar*)str, del);
	
	for ( i=0 ; i<LEN( TNT_(clo_list_inst_IDs) ) ; ++i ) {
		
	//	while( token != NULL ) {
		if ( token == NULL ) { break; }
		
		// now convert it
		TNT_(clo_list_inst_IDs)[i] = VG_(strtoll16)(token, &ptr);
		
		token = VG_(strtok)(NULL, del);
	}
	
}
#endif

static Bool tnt_process_cmd_line_options(const HChar* arg) {
   const HChar* tmp_str;
	
   // file options
   if VG_STR_CLO(arg, "--file-filter", tmp_str) {
#if _SECRETGRIND_
	  parse_file_filter_list( tmp_str );
#else
      libc_strlcpy(TNT_(clo_file_filter), tmp_str, MAX_PATH);
#endif
      TNT_(do_print) = 0;
   }
#if _SECRETGRIND_
   else if VG_BHEX_CLO(arg, "--file-taint-start", TNT_(clo_filetaint_start), 0x0000, 0x8000000) {}
   else if VG_BHEX_CLO(arg, "--file-taint-len", TNT_(clo_filetaint_len), 0x0000, 0x800000) {}
   else if VG_BINT_CLO(arg, "--file-mmap-use-pagesize", TNT_(clo_mmap_pagesize), 0x1, 1<<16) {}
#else
   //else if VG_BINT_CLO(arg, "--after-kbb", TNT_(clo_after_kbb), 0, 1000000) {}
   //else if VG_BINT_CLO(arg, "--before-kbb", TNT_(clo_before_kbb), 0, 1000000) {}
   else if VG_BHEX_CLO(arg, "--taint-start", TNT_(clo_filetaint_start), 0x0000, 0x8000000) {}
   else if VG_BHEX_CLO(arg, "--taint-len", TNT_(clo_filetaint_len), 0x0000, 0x800000) {}
   else if VG_BOOL_CLO(arg, "--taint-all", TNT_(clo_taint_all)) {}
   else if VG_BOOL_CLO(arg, "--tainted-ins-only", TNT_(clo_trace_taint_only)) {}
   else if VG_BOOL_CLO(arg, "--critical-ins-only", TNT_(clo_critical_ins_only)) {}
#endif
   
#if _SECRETGRIND_
   // taint options
   else if VG_BOOL_CLO(arg, "--taint-df-only", TNT_(clo_taint_df_only)) {}
   else if VG_BOOL_CLO(arg, "--taint-remove-on-release", TNT_(clo_taint_remove_on_release)) {}
   else if VG_BOOL_CLO(arg, "--taint-warn-on-release", TNT_(clo_taint_warn_on_release)) {}   
   else if VG_BOOL_CLO(arg, "--taint-show-source", TNT_(clo_taint_show_source)) {}
   else if VG_BOOL_CLO(arg, "--taint-stdin", TNT_(clo_taint_stdin)) {}
  
   // trace options
   else if VG_BOOL_CLO(arg, "--trace", TNT_(clo_trace)) {}
   else if VG_BOOL_CLO(arg, "--trace-taint-only", TNT_(clo_trace_taint_only)) {}
      
   // general options
   else if VG_BOOL_CLO(arg, "--var-name", TNT_(clo_var_name)) {}
   else if VG_BOOL_CLO(arg, "--debug", TNT_(clo_verbose)) {}
   else if VG_BOOL_CLO(arg, "--mnemonics", TNT_(clo_mnemonics)) {}
   
   // summary options
   else if VG_BOOL_CLO(arg, "--summary", TNT_(clo_summary)) {}
   else if VG_BOOL_CLO(arg, "--summary-verbose", TNT_(clo_summary_verbose)) {}
   else if VG_BOOL_CLO(arg, "--summary-exit-only", TNT_(clo_summary_exit_only)) {}
   else if VG_BOOL_CLO(arg, "--summary-main-only", TNT_(clo_summary_main_only)) {}
   else if VG_BOOL_CLO(arg, "--summary-total-only", TNT_(clo_summary_total_only)) {}
   else if VG_STR_CLO (arg, "--summary-fix-inst", tmp_str) {
      parse_fix_instruction_id_list(tmp_str);
   }
#endif // _SECRETGRIND_
   
//   else if VG_STR_CLO(arg, "--allowed-syscalls", TNT_(clo_allowed_syscalls)) {
//	   TNT_(read_syscalls_file) = True;
//   }
   else
      return VG_(replacement_malloc_process_cmd_line_option)(arg);

   return True;
}

static void tnt_print_usage(void) {
#if _SECRETGRIND_

	VG_(printf)(
"\n%sFile options:%s\n"
"    --file-filter=<f1,f2,...,fn>      list of files (full path) to taint, separated by comma [\"\"]\n"
"    --file-taint-start=[0,800000]     starting byte to taint (in hex) [0]\n"
"    --file-taint-len=[0,800000]       number of bytes to taint from file-taint-start (in hex) [800000]\n"
"    --file-mmap-use-pagesize=[1,2^32] size to taint when mmap()'ing tainted file [4096]\n"	// tune2fs -l /dev/sda1 | grep -i 'block size' gives it
"\n"
"%sTaint options:%s\n"
"    --taint-df-only= no|yes           propagate taint only thru 'direct flows' (df) [no]. Note: pointer arithmetic propagation not supported\n"
"    --taint-remove-on-release= no|yes remove taint when block is released (free(),mumap(file)) [no]\n" 
"    --taint-warn-on-release= no|yes   display live information when a block is released (free(),mumap(file)) yet tainted [no]\n" 
"    --taint-show-source= no|yes       show information when taint is received from file or secretgrind API [no]\n" 
"    --taint-stdin= no|yes             taint stdin input [no]. Note: --file-taint-start and --file-taint-len do not apply to stdin\n"
"\n"
"%sTrace options:%s\n"
"    --trace= no|yes                   print an instruction trace [no]. Slow, try using SG_PRINT_X_INST() instead\n"
"    --trace-taint-only= no|yes        print only tainted instructions [yes]. Must be used in conjunction with --trace=yes. Slow, try using SG_PRINT_X_INST() instead\n"
"\n"
"%sSummary options:%s\n"
"    --summary= no|yes                 display a taint summary after execution [yes]\n"
"    --summary-verbose= no|yes         print a detailed taint summary [no]. Tainted regions show as @0xAAAAAAAA_TYPE_PID_ValgrindThreadID, eg @0x4025000_mmap_10432_1\n"
"    --summary-main-only= yes|no       print taint summary at the end of the main() function only [no]\n"
"    --summary-exit-only= yes|no       print taint summary upon entering the exit() function only [no]\n"
"    --summary-total-only= no|yes      taint summary only shows the total # bytes tainted [no]\n"
"    --summary-fix-inst= [1,ffffffff]  try to fix the stack trace for instructions by giving a list of IDs separated by comma\n"
"\n"
"%sGeneral options:%s\n"
"    --var-name= no|yes                print variable names if possible [no]. Very slow, so try using in combination with SG_PRINT_X_INST()\n"
"    --mnemonics= no|yes               display the mnemonics of the original instruction responsible for tainting data [no]\n"
"    --debug= no|yes                   print debug info [no]\n",

   KUDL, KNRM, KUDL, KNRM, KUDL, KNRM, KUDL, KNRM, KUDL, KNRM);
   
#else

   VG_(printf)(
"    --file-filter=<full_path>   full path of file to taint [\"\"]\n"
"    --taint-start=[0,800000]    starting byte to taint (in hex) [0]\n"
"    --taint-len=[0,800000]      number of bytes to taint from taint-start (in hex)[800000]\n"
"    --taint-all= no|yes         taint all bytes of all files read. warning: slow! [no]\n"

//"    --after-kbb=[0,1000000]     start instrumentation after # of BBs, in thousands [0]\n"
//"    --before-kbb=[0,1000000]    stop instrumentation after # of BBs, in thousands [-1]\n"
"    --tainted-ins-only= no|yes  print tainted instructions only [yes].\n"
"    --critical-ins-only= no|yes print critical instructions only [no]\n"
   );

#endif // _SECRETGRIND_
}

static void tnt_print_debug_usage(void)
{
   VG_(printf)(
"    (none)\n"
   );
}

void TNT_(stop_print)(void) {
	TNT_(do_print) = 0;
#if _SECRETGRIND_
	TNT_(clo_trace) = True;
	TNT_(clo_trace_taint_only) = True; // needed for EARLY_EXIT macro
    TNT_(clo_critical_ins_only) = False;
#endif
}

void TNT_(start_print)(Bool taintedInstOnly) {

	TNT_(do_print) = 1; // Note: i don't need this anyway
	TNT_(clo_critical_ins_only) = False;
	TNT_(clo_trace_taint_only) = False;
	
#if _SECRETGRIND_
	// we dont support printing of this is batchmode -- this makes no sense
	// if one wants to have traces, it must at least disable batchmode so we can retrieve info about mem address
	if ( TNT_(clo_summary_total_only) ) {
		VG_(tool_panic)("tnt_main.c: --summary-total-only=yes is incompatible with the use of temporary live traces (PRINT_ALL_INST() and PRINT_TAINTED_INST()");
		VG_(exit)(-1);
	}
	TNT_(clo_trace) = False;
	TNT_(clo_trace_taint_only) = taintedInstOnly;
#endif
	
}
                                   

/*
   Valgrind core functions
*/                                                     

static int tnt_isatty(void)
{
   HChar buf[256], dev2[11];
   const HChar dev[] = "/dev/pts/";
   int i;

   // 2: stderr
   VG_(readlink)("/proc/self/fd/2", buf, 255);
   //VG_(printf)("isatty: %s\n", buf);
   // If stderr goes to terminal, buf should be /dev/pts/[0-9]
   for ( i=0; i<10; i++ )
   {
      VG_(sprintf)(dev2, "%s%d", dev, i);
      if ( VG_(strncmp)(buf, dev2, 10) == 0 ) return 1;
   }
   return 0;
}

#if _SECRETGRIND_
Bool TNT_(isPowerOfTwo) (SizeT x)
{
 while (((x % 2) == 0) && x > 1) /* While x is even and > 1 */
   x /= 2;
 return (x == 1);
}
#endif

static void tnt_post_clo_init(void)
{
#if _SECRETGRIND_
	if ( !TNT_(file_filter_present)() ) {
		// no filter applied
		if( !TNT_(clo_trace_taint_only) || !TNT_(clo_critical_ins_only) ) {
			TNT_(do_print) = 1;
		}
		
	} else {
		HChar* home = VG_(getenv)("HOME"); 
		SizeT i=0;
		for ( i=0; i<TNT_(file_filter_get_length)(); ++i ) {
			
			const char * curr_filter = TNT_(file_filter_get)(i); tl_assert( curr_filter && "curr_filter is null" );
			
			if ( curr_filter[0] == '\0' ) {
				
				VG_(printf)("*** Please provide non-empty --file-filter\n");
				VG_(exit)(1);
				//if( !TNT_(clo_trace_taint_only) || !TNT_(clo_critical_ins_only) ) {
				//	TNT_(do_print) |= 1;
				//}
			
			} else if( curr_filter[0] != '/') { // Not absolute path
			
				if ( curr_filter[0] == '~') {
					
					if (home) {
						
						HChar tmp[MAX_PATH+1];
						VG_(snprintf)( tmp, MAX_PATH, "%s%s", home, curr_filter );
						TNT_(file_filter_set)(i, tmp);
						
					 }else{
						 
						VG_(printf)("*** Please use absolute path for --file-filter\n");
						VG_(exit)(1);
					 }
				} else if ( curr_filter[0] == '*') {
					// Wildcard -  do nothing
				} else {
				 VG_(printf)("*** Please use absolute path for --file-filter\n");
				 VG_(exit)(1);
				}
			}
		}
	}
	
#else
   if(*TNT_(clo_file_filter) == '\0'){

      if( !TNT_(clo_trace_taint_only) || !TNT_(clo_critical_ins_only) )
         TNT_(do_print) = 1;

   }else if(*TNT_(clo_file_filter) != '/') { // Not absolute path
      if (*TNT_(clo_file_filter) == '~') {
         HChar* home    = VG_(getenv)("HOME");

         if (home) {
            HChar tmp[MAX_PATH+1];
            VG_(snprintf)( tmp, MAX_PATH, "%s%s", home, TNT_(clo_file_filter)+1 );
            VG_(snprintf)( TNT_(clo_file_filter), MAX_PATH, "%s", tmp );
            //VG_(printf)("%s\n", TNT_(clo_file_filter) );
         }else{
            VG_(printf)("*** Please use absolute path for --file-filter\n");
            VG_(exit)(1);
         }
      }else if (*TNT_(clo_file_filter) == '*') {
         // Wildcard
      }else{
         VG_(printf)("*** Please use absolute path for --file-filter\n");
         VG_(exit)(1);
      }
   }
#endif

   if( TNT_(clo_critical_ins_only) ) { TNT_(clo_trace_taint_only) = True; }
      
   // Initialise temporary variables/reg SSA index array
#if _SECRETGRIND_
   // Note: this is actually not necessary as it's a global and therefore zeroed on startup...
   VG_(memset)(ti, 0, sizeof(ti));
   VG_(memset)(ri, 0, sizeof(ri));
   VG_(memset)(lvar_i, 0, sizeof(lvar_i));
#else
   Int i;
   for( i=0; i< TI_MAX; i++ ) {
      ti[i] = 0;
      tv[i] = 0;
   }
   for( i=0; i< RI_MAX; i++ )
      ri[i] = 0;
   for( i=0; i< STACK_SIZE; i++ )
      lvar_i[i] = 0;
#endif
   lvar_s.size = 0;

//   if (TNT_(read_syscalls_file)) {
//	   read_allowed_syscalls();
//   }

#if _SECRETGRIND_
	if ( TNT_(clo_mmap_pagesize) && !TNT_(isPowerOfTwo)( TNT_(clo_mmap_pagesize) )) {
		VG_(printf)("*** Please use a power of 2 for --file-mmap-use-pagesize\n");
        VG_(exit)(1);
	}
	
	if ( TNT_(clo_summary_verbose) && TNT_(clo_summary_total_only) ) {
		VG_(printf)("*** --summary-verbose and --summary-total-only are imcompatible\n");
        VG_(exit)(1);
	}
	
	if ( TNT_(clo_taint_all) ) {
		// Note: the reason for this is during summary display,
		// i currently assume ranges ofr continuous address spaces do not
		// cross address type boundaries. TODO: add support for this
		VG_(printf)("*** --taint-all=yes not supoprted yet\n");
        VG_(exit)(1);
	}
	
	TNT_(clo_batchmode) = TNT_(clo_summary_total_only) && !TNT_(clo_trace);
	
	// always the case fiven stuff above
	//if ( TNT_(clo_summary_total_only) ) {
	//	!TNT_(clo_trace) = True;
	//	TNT_(clo_summary_verbose) = False;
	//}
   
	TNT_(mmap_init)();
	TNT_(sum_names_init)();
	TNT_(syswrap_init)();
	if (! TNT_(asm_init)() ) {
		VG_(tool_panic)("tnt_main.c: tnt_pre_clo_init: assembly engine initialization failed");
	}

#endif

   // DEBUG
   //tnt_read = 0;
   
	// Taintgrind: Needed for tnt_malloc_wrappers.c
	TNT_(malloc_init)();

   // If stdout is not a tty, don't highlight text
   istty = tnt_isatty();
}

#if _SECRETGRIND_
/* --------------- zerogrind ------------------ */

static Vg_FnNameKind TNT_(get_current_func_kind)(void)
{
	Addr ip = VG_(get_IP)(VG_(get_running_tid)());
	return VG_(get_fnname_kind_from_IP)(ip);
}

// this function does 2 things:
// 1- it checks if the function called is exit(). This happens when the program explicitly calls it
// 2- it checks if main() returns gracefully via return (below-main)
// if any of these 2 condition occur, we conclude main() has finished
// I do all this rather than hooking the exit function because by the time exit gets called, so much has
// happened that some tainted stack locations may be overwritten already.
// cmd line supports an option to display the summary on program exit rather than after main
static Bool TNT_(is_exiting_main)(void)
{
	Addr ip = VG_(get_IP)(VG_(get_running_tid)());
	char fnname[256];
	
	VG_(get_fnname_if_entry)( ip, fnname, sizeof(fnname) );
	//	if (fnname[0]) { LOG("\e[32m entry name:%s\e[0m\n", fnname); }
		
	return (VG_(strcmp(fnname, "exit")) == 0 || Vg_FnNameBelowMain == TNT_(get_current_func_kind)());
}

static void TNT_(show_main_summary)(void)
{
	static Bool g_main_summary_shown = False;
	static Bool g_main_entered = False;
	
	if ( UNLIKELY( !TNT_(clo_summary) ) ) { return; }
	if ( UNLIKELY( TNT_(clo_summary_exit_only) ) ) { return; }
	
	// make sure we've entered the main function first
	if ( UNLIKELY( !g_main_entered && Vg_FnNameMain == TNT_(get_current_func_kind)()) ) {
		g_main_entered = True;
	}
	
	// ... and we have exited it too
	if ( UNLIKELY( !g_main_summary_shown && TNT_(is_exiting_main)() && g_main_entered) ) {
		taint_summary("On end main()");
		g_main_summary_shown = True;
		//tl_assert (0);
	}
}

Bool TNT_(is_mem_byte_tainted)(Addr a) 
{ 
	UChar vabits2 = get_vabits2(a); 
	return ( vabits2 == VA_BITS2_TAINTED || vabits2 == VA_BITS2_PARTUNTAINTED );
}
static void var_taint_status(char *desc, Addr a, SizeT len) 
{
	// TODO: handle any size -- check code from other functions
	UChar vabits2=0;
	Bool byteTaint = False, prev_byteTaint = False;
	const char *status = 0;
	Addr startAddr = a, currAddr = a, endAddr = a+len;
	const char *COLOR = 0;
	vabits2 = get_vabits2(a);
	prev_byteTaint = (vabits2 != VA_BITS2_UNTAINTED); // could be fully or partially tainted
	++currAddr;
	
	VG_(printf)("\n[TAINT STATE]: %s (%lu bytes)\n", desc, len);
	// old form VG_(printf)("[TAINT STATE]: %s '%s' (size=%lu) %s 0x%lx is %s\n", isScalar?"scalar":"pointer", vname, currAddr-startAddr, isScalar?"at address":"pointing to address", startAddr, status);
	// Note: we should take advantage of multi-byte taint checks:TODO
	for (; currAddr<endAddr; ++currAddr) {
		vabits2 = get_vabits2(currAddr);
		byteTaint = (vabits2 != VA_BITS2_UNTAINTED); // could be fully or partially tainted
		if ( byteTaint != prev_byteTaint ) {
			if (prev_byteTaint) {
				status = "tainted";
				COLOR = KRED;
			} else {
				status = "NOT tainted";
				COLOR = KGRN;
			}
			VG_(printf)("\trange %s[0x%lx - 0x%lx]%s (%lu bytes)\tis %s%s%s\n", COLOR, startAddr, currAddr-1, KNRM, currAddr-startAddr, COLOR, status, KNRM);
			
			// start new address
			startAddr = currAddr;
		}
		prev_byteTaint = byteTaint;
	}
	
	if (currAddr-startAddr > 0) {
		if (byteTaint) {
			status = "tainted";
			COLOR = KRED;
		} else {
			status = "NOT tainted";
			COLOR = KGRN;
		}
		VG_(printf)("\trange %s[0x%lx - 0x%lx]%s (%lu bytes)\tis %s%s%s\n", COLOR, startAddr, currAddr-1, KNRM, currAddr-startAddr, COLOR, status, KNRM);
	}
}

static void TNT_(display_range_summary_header)(SizeT debugNum, const char *type, Addr start, Addr end, SizeT len) {
	if ( TNT_(clo_summary_total_only) ) { return; }
	EMIT_ERROR("\n***(%lu) (%s)\t range [0x%lx - 0x%lx]\t (%lu bytes)\t is tainted\n", debugNum, type, start, end, len);
}

#define INC_TOT_TAINTED() do{ tl_assert (*ptotTainted <= (Addr)(-1) - gLen); *ptotTainted += gLen; }while(0)
static SizeT gLen = 0;
static void _do_low_secmap_entry(Addr base, SizeT * ptotTainted, SizeT * punaccountTaint)
{
	//LOG("Found a potential SM -- range x0%lx\n", base);
	tl_assert (ptotTainted && punaccountTaint && "ptotTainted or unaccountTaint is NULL");
	
	UChar vabits2 = 0;
    SecMap *sm16=0, *sm=0;
	Addr a = base, addEnd = base + (SM_CHUNKS*4);
	UWord sm_off16=0, vabits16=0, sm_off=0, vabits8=0;
	
	// Note: i could have passed the sm from low_secmap_entry_summary
	// i did not do it coz i want to re-use this function for high addresses too
	sm16 = sm = get_secmap_for_reading(a);
	
	//VG_(printf)("checking range %08lx - %08lx\n", a, addEnd);
	// Note: we could iterate over the secmap vabits8 blocks ourselves
	// but then we need to re-construct the address from the offset.
	// instead i construct the address first and re-use existing function to derive the offset
	// we check 16-bits at a time to be faster, and fall back to 8-bits if partially tainted
	// Note: read 64/32-bit at a time to be faster
	
	for (; a<addEnd; a+=8) { 
		
		sm_off16  = SM_OFF_16(a);
		vabits16 = ((UShort*)(sm16->vabits8))[sm_off16];
		
		// VA_BITS16_NOACCESS should NEVER happen. I've fixed the find_or_alloc function for that
		// nevertheless, for debug purposes, assert it...
		tl_assert ( vabits16 != VA_BITS16_NOACCESS );
		if ( LIKELY(vabits16 == VA_BITS16_UNTAINTED /*|| vabits16 == VA_BITS16_NOACCESS*/) ) {
			if ( gLen>0 ) {
				sn_addr_type_t sa = TNT_(get_addr_type)(a-gLen);
				sn_addr_type_t ea = TNT_(get_addr_type)(a-2);
				tl_assert (sa == ea);
					
				TNT_(display_range_summary_header)(1, TNT_(addr_type_to_string)(sa), a-gLen, a-1, gLen);
				TNT_(display_names_of_mem_region)(a-gLen, gLen, sa);
				INC_TOT_TAINTED();
				gLen = 0;
			}
		} else if ( LIKELY(vabits16 == VA_BITS16_TAINTED) ) {
			
			//LOG("found addr 0x%lx->8 is tainted\n", a);
			gLen += 8;
		
		} else if ( LIKELY( vabits16 != VA_BITS16_NOACCESS ) ) {
			//LOG("addr 0x%lx - %lx (8) partially tainted: %x\n", a, a+7, vabits16);
			// only some bytes are tainted
			Addr b = a;
			for ( ; b<a+8; ++b) {
				
				sm_off  = SM_OFF(b);
				vabits8 = (sm->vabits8)[sm_off];
				vabits2 = extract_vabits2_from_vabits8 (b, vabits8);
				
				// TODO: remove after testing
				tl_assert ( vabits16 != VA_BITS2_NOACCESS );
				
				if ( UNLIKELY( vabits2 == VA_BITS2_UNTAINTED /*|| vabits2 == VA_BITS2_NOACCESS*/ ) ) {
					if ( gLen>0 ) {
						sn_addr_type_t sa = TNT_(get_addr_type)(b-gLen);
						sn_addr_type_t ea = TNT_(get_addr_type)(b-1);
						tl_assert (sa == ea);
						
						TNT_(display_range_summary_header)(2, TNT_(addr_type_to_string)(sa), b-gLen, b-1, gLen);
						TNT_(display_names_of_mem_region)(b-gLen, gLen, sa);
						INC_TOT_TAINTED();
						gLen = 0;
					} 
					
				} else if ( LIKELY(vabits2 == VA_BITS2_TAINTED) ) {
					//LOG("	found addr 0x%lx->1 is tainted\n", b);
					gLen += 1; 
					
				} else if ( LIKELY(vabits2 == VA_BITS2_PARTUNTAINTED) ) {
					//LOG("	found addr 0x%lx certain bits only are tainted\n", b);
					//TODO: properly display with partial taint, or just info
					//UWord vbits8 = get_sec_vbits8(b);
					//VG_(printf)("vbits8:%02x\n", vbits8);
					gLen += 1;
				}
			}
			//LOG("end the small loop with a %lx\n", a);
		}
	}
	//LOG_EXIT();
	// for debugging, uncomment this and comment out the callee's code
	// fon't forget the last bytes...
	// REOMVED: now i "stich" together tainted ranges in callees
	//if (gLen>0) {
		//VG_(printf)("***(3) range [0x%08lx - 0x%08lx] (%lu bytes) is tainted\n", a-gLen, a-1, gLen);
		//INC_TOT_TAINTED();
		//gLen = 0;
	//}
}
	
static void low_secmap_entry_summary(SizeT * ptotTainted, SizeT * punaccountTaint) 
{
	tl_assert (ptotTainted && punaccountTaint && "ptotTainted or unaccountTaint is NULL");
	SizeT i = 0;
    Addr lastBase = 0;
    
	for (i=0; i<N_PRIMARY_MAP; ++i) {
		// check which secondary maps differ from the dsitinguished ones
		if ( !is_distinguished_sm( primary_map[i] ) ) {
			lastBase = (Addr)(i<<16);
			_do_low_secmap_entry(lastBase, ptotTainted, punaccountTaint);
		}
	}
	
	// let's assume allocation are aligned with our low/high memory boundary, so we don't need to
	// "stich" low and high tainted memory segments
	if (gLen>0) {
		tl_assert (lastBase && "lastBase cannot be NULL");
		Addr end = lastBase + (SM_CHUNKS*4);
		sn_addr_type_t sa = TNT_(get_addr_type)(end-gLen);
		sn_addr_type_t ea = TNT_(get_addr_type)(end-1);
		tl_assert (sa == ea);
		
		TNT_(display_range_summary_header)(3, TNT_(addr_type_to_string)(sa), end-gLen, end-1, gLen);				
		TNT_(display_names_of_mem_region)(end-gLen, gLen, sa);
		INC_TOT_TAINTED();
		gLen = 0;
	}
	
}
	

static void high_secmap_entry_memory(SizeT * ptotTainted, SizeT * punaccountTaint)
{
	tl_assert (ptotTainted && punaccountTaint && "ptotTainted or unaccountTaint is NULL");
	
	// we don't care about L1 cache here. We can only iterate "blindly" over *ALL* L2 cache entries. 
	// So we cannot exclude the L1 entries we may have already found.
	AuxMapEnt *elem = 0;
	Addr lastBase = 0;
	VG_(OSetGen_ResetIter)(auxmap_L2);
	
	while ( (elem = VG_(OSetGen_Next)(auxmap_L2)) ) {
		//VG_(printf)("L2 base addr %08lx\n", elem->base);
		if ( !is_distinguished_sm( elem->sm ) ) {
			//VG_(printf)("	L2 base addr %08lx possible candidate\n", elem->base);
			tl_assert (elem->base == (elem->base & ~(Addr)0xFFFF));
			lastBase = elem->base;
			_do_low_secmap_entry(elem->base, ptotTainted, punaccountTaint);
		}
	}
	
	// let's assume allocation are aligned with our low/high memory boundary, so we don't need to
	// "stich" low and high tainted memory segments
	if (gLen>0) {
		tl_assert (lastBase && "lastBase NUL!?");
		Addr end = lastBase + (SM_CHUNKS*4);
		sn_addr_type_t sa = TNT_(get_addr_type)(end-gLen);
		sn_addr_type_t ea = TNT_(get_addr_type)(end-1);
		tl_assert (sa == ea);
			
		TNT_(display_range_summary_header)(4, TNT_(addr_type_to_string)(sa), end-gLen, end-1, gLen);
		TNT_(display_names_of_mem_region)(end-gLen, gLen, sa);
		INC_TOT_TAINTED();
		gLen = 0;
	}
}

static Bool TNT_(is_stack)(Addr a) 
{
	// is in stack -- use VG_(addr_is_in_block)( Addr a, Addr start, SizeT size, SizeT rz_szB ) pub_tool_replacemalloc.h
	ThreadId tid = VG_(get_running_tid)();
	Addr max = VG_(thread_get_stack_max) (tid );
	SizeT size = VG_(thread_get_stack_size) ( tid );
	tl_assert (max > size);
	//LOG("min %lx, max:%lx size:%u=0x%lx \n",max-size ,max, size, size);
	return VG_(addr_is_in_block)( a, max-size+1, size, 0 ) ;
	
} 

static Bool TNT_(is_global)(Addr a)
{
	VgSectKind kind = VG_(DebugInfo_sect_kind)(0,0, a);
	return ( Vg_SectBSS==kind || Vg_SectData==kind );
}

const char * TNT_(addr_type_to_string)(sn_addr_type_t type)
{
	const char *arr[] = {"global", "malloc", "fmmap", "mmap", "stack", "other"};
	tl_assert ( LEN(arr) > (type-1) );
	return arr[type-1];
}


sn_addr_type_t TNT_(get_addr_type)(Addr a) 
{
	Bool is_stack = TNT_(is_stack)(a);
	Bool is_heap_malloc = TNT_(malloc_is_heap)(a);
	Bool is_global = TNT_(is_global)(a);
	Bool is_mmap_file = TNT_(syswrap_is_mmap_file_range)(a);
	Bool is_mmap = TNT_(mmap_is_region)(a);
	
	LOG("0x%lx is heap:%u, stack:%u, global:%u file-mmap:%u mmap:%u\n", a, is_heap_malloc, is_stack, is_global, is_mmap_file, is_mmap);
	
	sn_addr_type_t addr_type = SN_ADDR_UNKNOWN;
	if (is_stack) { addr_type = SN_ADDR_STACK; }
	else if (is_heap_malloc) { addr_type = SN_ADDR_HEAP_MALLOC; }
	else if (is_global) { addr_type = SN_ADDR_GLOBAL; }
	else if (is_mmap_file) { addr_type = SN_ADDR_MMAP_FILE; }	// WARNING: this must come before the default mmap
	else if (is_mmap) { addr_type = SN_ADDR_MMAP; }
	// Note: we assume the programs behaves properly and does not access invalid address locations -- anyway it should crash at this point
	else { addr_type = SN_ADDR_OTHER; }
	
	tl_assert ( addr_type != SN_ADDR_UNKNOWN ); // no longer needed
	
	return addr_type;
}

static Bool AT = False;
static const char *ALLOC_MSG = 0;

static void TNT_(printExeIpDesc)(UInt n, Addr ip)
{
   #define BUF_LEN   4096
   
   static HChar buf[BUF_LEN];

   InlIPCursor *iipc = VG_(new_IIPC)(ip);
   
   do {
      VG_(describe_IP)(ip, buf, BUF_LEN, iipc);
      
      // skip all info about the valgrind framework
      //if ( !TNT_(clo_verbose) && 
		//VG_(strstr)(buf, "(vg_") != 0 ) { continue; }
      
	  //VG_(message)(Vg_UserMsg, "   %s %s\n", 
	//			  ( (n == 0 || !atDone) ? "at" : "by" ), buf);
	  tl_assert ( ALLOC_MSG && "alloc_at not set" );
	  const char *FMT = 0;
	  const char *at = 0, *by = 0;
	  if (AT) 	{ FMT = "        %-11s %s %s\n"; by = ""; at = "by"; }
	  else 		{ FMT = "        %11s %s %s\n";  by = ALLOC_MSG; at = "at"; }
	  
	  EMIT_INFO(FMT, by, at, buf);
	  AT = True;
            
      n++; 
      // Increase n to show "at" for only one level.
   } while (VG_(next_IIPC)(iipc));
   VG_(delete_IIPC)(iipc);
}

// for stack trace, just re-se the exeContext one
static void TNT_(printStackIpDesc)(UInt n, Addr ip, void *opaque) { 
	TNT_(printExeIpDesc)(n, ip); 
}

// for formatting into a buffer rather than printing to stdout, we must know the length of the output buffer
typedef 
	struct {
		char *buf;
		SizeT size;
		}
	outInfo_t;

static void TNT_(formatStackIpDesc)(UInt n, Addr ip, void* uu_opaque)
{
   #define BUF_LEN   4096
   
   static HChar buf[BUF_LEN];

   InlIPCursor *iipc = VG_(new_IIPC)(ip);
   outInfo_t *inData = (outInfo_t*)uu_opaque;
   
   do {
	  
      VG_(describe_IP)(ip, buf, BUF_LEN, iipc);
      
      // skip all info about the valgrind framework
      //if ( !TNT_(clo_verbose) && 
		//VG_(strstr)(buf, "(vg_") != 0 ) { continue; }
		
	  // this is to skip the first call, since we already display it 
      // using VG_(describe_IP) in read_common
	  if ( n == 0 ) { continue; }
      
      char tmp[256];
      VG_(snprintf)(tmp, sizeof(tmp), "        %s %s\n", ( !AT ? "called at" : "       by" ), buf);
      LOG("len inData->buf:%lu , len inData->size:%lu , len tmp:%lu", VG_(strlen)(inData->buf) , inData->size , VG_(strlen)(tmp));
      tl_assert ( inData->size >= VG_(strlen)(tmp) );
      tl_assert ( VG_(strlen)(inData->buf) < inData->size - VG_(strlen)(tmp) );
      libc_strlcat(inData->buf, tmp, inData->size);
	  
	  AT = True;
            
      n++; 
      // Increase n to show "at" for only one level.
   } while (VG_(next_IIPC)(iipc));
   VG_(delete_IIPC)(iipc);
   
}

#define FIX_TRACE_SYMBOL	"*"
static void TNT_(print_InstMnemonics) (Inst_t *inst) {
	
	char rawInst[128] = "\0";
	TNT_(rawInst2Str)(rawInst, sizeof(rawInst), inst->addr, inst->len);
	
	if ( inst->mnemonics[0] == '\0' ) {
		// get the mnemonic
		tl_assert( TNT_(asm_guest_pprint)(inst->addr, inst->len, inst->mnemonics, sizeof(inst->mnemonics) ) && "Failed TNT_(asm_guest_pprint)" );
	}
	EMIT_INFO("        %11s %s '%s' (raw=%s, ID=_%lx_%s)\n", inst->ec?"tainted"FIX_TRACE_SYMBOL:"tainted", "by instruction", inst->mnemonics, rawInst, inst->ID, inst->ec?FIX_TRACE_SYMBOL:"" );
	//"        %-11s %s %s\n"; by = ""; at = "by";
}

static void TNT_(print_api_taint)(void) {
	EMIT_INFO("        %11s %s\n", "tainted", "by API call");
}

// see apply_StackTrace too -- i got inspired by it :-)
// the AT bool is just used to remove the vg_-related info from output
// if clo_verbose is false
static void TNT_(print_TaintExeContext)( ExeContext* ec, UInt n_ips, Int fixed ) 
{
	ALLOC_MSG = fixed? "tainted"FIX_TRACE_SYMBOL : "tainted";
	VG_(apply_ExeContext)( &TNT_(printExeIpDesc), ec, n_ips );
	AT = False;
}

void TNT_(print_MmapExeContext)( ExeContext* ec, UInt n_ips ) 
{
	ALLOC_MSG = "mmap()'ed";
	VG_(apply_ExeContext)( &TNT_(printExeIpDesc), ec, n_ips );
	AT = False;
}

void TNT_(print_MallocParentExeContext)( ExeContext* ec, UInt n_ips ) 
{
	ALLOC_MSG = "malloc()'ed";
	VG_(apply_ExeContext)( &TNT_(printExeIpDesc), ec, n_ips );
	AT = False;
}

void TNT_(print_FreeParentExeContext)( ExeContext* ec, UInt n_ips ) 
{
	ALLOC_MSG = "free()'ed";
	VG_(apply_ExeContext)( &TNT_(printExeIpDesc), ec, n_ips );
	AT = False;
}

void TNT_(print_MunmapParentExeContext)( ExeContext* ec, UInt n_ips ) 
{
	ALLOC_MSG = "munmap()'ed";
	VG_(apply_ExeContext)( &TNT_(printExeIpDesc), ec, n_ips );
	AT = False;
}

void TNT_(print_MmapParentExeContext)( ExeContext* ec, UInt n_ips ) 
{
	ALLOC_MSG = "mmap()'ed";
	VG_(apply_ExeContext)( &TNT_(printExeIpDesc), ec, n_ips );
	AT = False;
}


void TNT_(print_MallocExeContext)( ExeContext* ec, UInt n_ips ) 
{
	ALLOC_MSG = "malloc()'ed";	// here i would like to show size of parent block:TODO
	VG_(apply_ExeContext)( &TNT_(printExeIpDesc), ec, n_ips );
	AT = False;
}

static void TNT_(print_StackTrace) ( StackTrace ips, UInt n_ips, const char *msg )
{
	tl_assert( n_ips > 0 );
	ALLOC_MSG = msg;
	VG_(apply_StackTrace)( &TNT_(printStackIpDesc), NULL, ips, n_ips );
	AT = False;
}


void TNT_(print_CurrentStackTrace) ( ThreadId tid, UInt max_n_ips, const char *msg )
{
   Addr ips[max_n_ips];
   UInt n_ips
      = VG_(get_StackTrace)(tid, ips, max_n_ips,
                            NULL/*array to dump SP values in*/,
                            NULL/*array to dump FP values in*/,
                            0/*first_ip_delta*/);
   TNT_(print_StackTrace)(ips, n_ips, msg);
}

// see apply_StackTrace too -- i got inspired by it :-)
// the AT bool is just used to remove the vg_-related info from output
// if clo_verbose is false
void TNT_(record_StackTrace)( char *out, SizeT size, SizeT max_n_ips, const char *msg ) 
{
	tl_assert( max_n_ips > 0 );
	Addr ips[max_n_ips];
	outInfo_t bufInfo = {.buf = out, .size = size};
	ThreadId tid = VG_(get_running_tid)();
    UInt n_ips
      = VG_(get_StackTrace)(tid, ips, max_n_ips,
                            NULL/*array to dump SP values in*/,
                            NULL/*array to dump FP values in*/,
                            0/*first_ip_delta*/);
	ALLOC_MSG = msg;
	VG_(apply_StackTrace)( &TNT_(formatStackIpDesc), &bufInfo, ips, n_ips );
	AT = False;
}

// check is we can de-reference an address
static void TNT_(display_names_of_mem_region)(Addr a, SizeT len, sn_addr_type_t mem_type)
{
	// I do not use VG_(describe_addr) here because this function may be called
	// after some heap blocks have been free'd. Yet I still want to figure
	// what section the address belongs to
	// For globals, I could use VG_(describe_addr) but it's return the name of the current function being
	// executed, at that point likely Exit() or os. This is not useful for the developer to pint point
	// where the var was tainted
	Addr end = a+len;
	Addr curr = a;
	
	if ( TNT_(clo_summary_total_only) || !TNT_(clo_summary_verbose) ) { return; }
	
	
	while (curr<end) {
		
		HP_Chunk *hp = NULL;
		
		// search in globals, stack and free()'ed blocks first
		TNT_(sum_names_reset_iter)(mem_type);
		Bool fix_curr = False;
		while ( (hp=TNT_(sum_names_get_next_chunk)(mem_type)) && curr < end) {
			Addr curr_org = curr;
			LOG("checking %lx against %p %lx - %lx\n", curr, hp, hp->data, hp->data+hp->req_szB+hp->slop_szB);
			while ( VG_(addr_is_in_block)( curr, hp->data, hp->req_szB, hp->slop_szB ) && curr<end ) {
				++curr;
			}
			if ( curr_org != curr ) {
				fix_curr = True;
				EMIT_INFO("   > (%s) [0x%lx - 0x%lx] (%lu bytes): %s\n", TNT_(addr_type_to_string)(mem_type), curr_org, curr-1, 
								curr-curr_org, hp->vdetailedname);
				
				tl_assert ( hp->stack_trace );
									
				if ( SN_ADDR_HEAP_MALLOC == mem_type || 
					 SN_ADDR_MMAP_FILE == mem_type ) {
										
					// either a master or a child (ie we have a parent), but not both!
					tl_assert ( (hp->Alloc.parent || hp->Alloc.master) && !(hp->Alloc.parent && hp->Alloc.master) );
				
					// get the parent block; this can be the block itself, eg im mmap()'ed block
					HP_Chunk * hpParent = hp->Alloc.master?hp:hp->Alloc.parent;
					//Bool isMasterBlk = hp->Alloc.master==1?True:False;
					
					// sanity checks, just in case: this should never happen coz it may create issues upon releasing
					// tl_assert (hp->Alloc.parent != hp); -- done in set_parent instead
					
					// first display the taint info
					TNT_(print_TaintExeContext)( hp->stack_trace, VG_(get_ExeContext_n_ips)(hp->stack_trace), hp->inst.ec!=0 );
									
					// show the instruction mnemonics that taint the data or if the call is the result of API TNT_MAKE_TAINTED()
					if ( TNT_(clo_mnemonics) ) {
						if ( hp->api ) 	{ 	TNT_(print_api_taint)(); }
						else 			{	TNT_(print_InstMnemonics) (&hp->inst); }
					}
					
					// then display the parent block info, this may be the same block
					EMIT_INFO("     Parent block [0x%lx - 0x%lx] (%lu bytes): %s\n", (Addr)hpParent->data, 
									(Addr)hpParent->data+hpParent->req_szB-1, 
									hpParent->req_szB, hpParent->vdetailedname);
					
					// pick the right function depending on block type
					void (*print_ParentEC)( ExeContext* ec, UInt n_ips ) 		= 	(SN_ADDR_HEAP_MALLOC == mem_type) ? &TNT_(print_MallocParentExeContext) : &TNT_(print_MmapParentExeContext);
					void (*print_ReleaseParentEC)( ExeContext* ec, UInt n_ips ) = 	(SN_ADDR_HEAP_MALLOC == mem_type) ? &TNT_(print_FreeParentExeContext) : &TNT_(print_MunmapParentExeContext);
							
					// print trace of how parent block was allocated
					(*print_ParentEC)( hpParent->stack_trace, VG_(get_ExeContext_n_ips)(hpParent->stack_trace) ); 
					
					// print the trace of how parent was released
					if ( hpParent->Alloc.release_trace ) {
						(*print_ReleaseParentEC)(hpParent->Alloc.release_trace, VG_(get_ExeContext_n_ips)(hpParent->Alloc.release_trace));
					} else {
						// warn if the parent block was not released
						EMIT_ERROR( (SN_ADDR_HEAP_MALLOC == mem_type) ? 
									"        *** WARNING: the block was never free()'d!\n" : 
									"        *** WARNING: the block was never munmap()'d!\n" );
					}
											
									
				} else {
										
					TNT_(print_TaintExeContext)( hp->stack_trace, VG_(get_ExeContext_n_ips)(hp->stack_trace), hp->inst.ec!=0 );

					if ( TNT_(clo_mnemonics) ) {
						if ( hp->api ) 	{ 	TNT_(print_api_taint)(); }
						else 			{	TNT_(print_InstMnemonics) (&hp->inst); }
					}
				}
			}
		}

#if 0	// this is no longer possible, because I now add the block all the time in describe_data,
		// instead of the below, i just check if the block is free()'ed to display a warning in the above code
		
		// searched in NON- free()'ed blocks
		// also tell the user about the mem leak
		TNT_(malloc_reset_iter)();
		while ( (hp=TNT_(malloc_get_next_chunk)()) && curr < end ) {
			Addr curr_org = curr;
			while ( VG_(addr_is_in_block)( curr, hp->data, hp->req_szB, hp->slop_szB ) && curr<end ) {
				++curr;
			}
			if ( curr_org != curr ) {
				fix_curr = True;
				EMIT_INFO("   > (%s) [0x%lx - 0x%lx] (%lu bytes): %s%s\n", TNT_(addr_type_to_string)(mem_type), 
								curr_org, curr-1, curr-curr_org, hp->vdetailedname, hp->release_trace?"":" - WARNING: the block was never free()'d!");
				
				tl_assert ( hp->stack_trace );
				TNT_(print_MallocExeContext)( hp->stack_trace, VG_(get_ExeContext_n_ips)(hp->stack_trace) );
				
				// mnemonics for a heap block means nothing, as the block was recorded upon being malloc()'ed
			}
		}
#endif		
		// Note: search in NON- mmap()'ed blocks. Currently I don't differentiate between mmap()'ed and NON-mmap()'ed...
		// TODO
		
		// Note: this is really important we don't increment curr if we've already do so in any of the small inner loops above
		if ( !fix_curr ) {
			++curr;
		}
	}
	

	/*
	// BSS/data section names
	char buf[1024];
	PtrdiffT pdt;
	if ( VG_(get_datasym_and_offset)( 0x60105c, buf, sizeof(buf), &pdt ) == True ) {
		LOG("get_datasym_and_offset:%s[%lu]\n", buf, pdt);
	}
	* */
}


void TNT_(display_receive_taint_for_addr)(Addr addr, SizeT len, const char *addrInfo, const char *srcname) {
	
	tl_assert (addrInfo && srcname);
	
	if ( TNT_(clo_summary_total_only) || !TNT_(clo_taint_show_source) ) { return; }
	
	// get info about stack
	char stackInfo[MAX_STACK_DESC_LEN] = "\0";
	TNT_(record_StackTrace)( stackInfo, sizeof(stackInfo), MAX_STACK_FRAME, "" );
	
	VG_(printf)("\n%s%s%s | range %s[0x%lx - 0x%lx]%s (%s%lu bytes%s) receives %staint%s from %s\n", KMAG, addrInfo, KNRM, KRED, addr, addr+len-1, KNRM, KRED, len, KNRM, KRED, KNRM, srcname);
	EMIT_INFO("%s\n", stackInfo);
	
}

void TNT_(record_receive_taint_for_addr)(Addr addr, SizeT len, Bool api, const char *srcname)
{
	LOG_ENTER();
	
	if ( TNT_(clo_summary_total_only) ) { return; }
	
	// get info about address
	HChar addrInfo[256] = "\0";
	ThreadId tid = VG_(get_running_tid());
	UInt pc = VG_(get_IP)(tid);
	VG_(describe_IP) ( pc, addrInfo, sizeof(addrInfo), NULL );
	
	// display to user
	TNT_(display_receive_taint_for_addr)(addr, len, addrInfo, srcname);
	
	// alloc and record the block 
	TNT_(alloc_chunk_from_fn_and_add_sum_block)(addr, (SizeT)len, 0, api, "Store");
	//sn_addr_type_t type = TNT_(get_addr_type)(addr);
	//LOG( "type:%s\n", TNT_(addr_type_to_string)(type) );
	//if ( (SN_ADDR_HEAP_MALLOC==type || SN_ADDR_MMAP_FILE==type) ) {
		//HP_Chunk * hc = TNT_(alloc_chunk_from_fn_and_add_sum_block)(addr, (SizeT)len, 0, "64");
		//TNT_(sum_add_block)(hc, hc->addrType);
	//}
	//if (addr>= 0x4026000 && addr<=0x402638b) { tl_assert("got it" && 0); }
	LOG_EXIT();
}

static void taint_summary(const char *name)
{    
    SizeT totalTainted = 0, unaccountTaint = 0;
    VG_(printf)("\n==%u== [TAINT SUMMARY] - %s:\n---------------------------------------------------\n", VG_(getpid)(), name);
    
    // low memory
    low_secmap_entry_summary(&totalTainted, &unaccountTaint);
	
	// high memory
	high_secmap_entry_memory(&totalTainted, &unaccountTaint);
	
	//var_taint_status(True, 0xffefff900, "0xffefff900", 1);
	
	tl_assert ( unaccountTaint==0 && "unaccountTaint not 0!" );
	if ( totalTainted ) { EMIT_ERROR("\nTotal bytes tainted: %lu\n", totalTainted); }
	else 				{ EMIT_SUCCESS("\nNo bytes tainted\n"); }

    /*
    {
		SizeT i = 0;
		SecMap *sm = 0;
		Bool isBG = !isLE();
		Addr a = 0;
		UWord   sm_off16=0, vabits16=0, sm_off=0, vabits8=0;
		SecMap *sm16=0, *sm=0;
		UChar vabits2 = 0;
		UInt len = 0;
		// iterate over low mem first  
		for (a=0; a<=(MAX_PRIMARY_ADDRESS>>4); a+=8) {
			
			sm16      = get_secmap_for_reading_low(a);
			sm_off16  = SM_OFF_16(a);
			vabits16 = ((UShort*)(sm16->vabits8))[sm_off16];
			
			if ( LIKELY(vabits16 == VA_BITS16_UNTAINTED) ) {
				if ( len>0 ) {
					VG_(printf)("***(1) range [0x%08lx - 0x%08lx] (%u bytes) is tainted\n", a-len, a-1, len);
					len = 0;
				}
				
				continue;
			}
			
			if ( LIKELY(vabits16 == VA_BITS16_TAINTED) ) {
				//VG_(printf)("found addr 0x%lx->8 is tainted\n", a);
				len += 8;
			} else {
				VG_(printf)("addr 0x%lx->8 partially tainted:\n", a);
				// only some bytes are tainted
				Addr b = a;
				for (b=a; b<a+8; ++b) {
					sm      = get_secmap_for_reading_low(b);
					sm_off  = SM_OFF(b);
					vabits8 = (sm->vabits8)[sm_off];
					vabits2 = extract_vabits2_from_vabits8 (b, vabits8);
									
					if ( UNLIKELY( vabits2 == VA_BITS2_UNTAINTED ) ) {
						if ( len>0 ) {
							VG_(printf)("***(2) range [0x%08lx - 0x%08lx] (%u bytes) is tainted\n", b-len, b-1, len);
							len = 0;
						}
						continue;
					}
					if ( LIKELY(vabits2 == VA_BITS2_TAINTED) ) {
						//VG_(printf)("found addr 0x%lx->1 is tainted\n", b);
						len += 1;
					} else if ( LIKELY(vabits2 == VA_BITS2_PARTUNTAINTED) ) {
						//VG_(printf)("found addr 0x%lx certain bites only are tainted\n", b);
						len += 1;
					}
					
				}
				
			}
		}
	}
	*/
}

#endif // _SECRETGRIND_

static void tnt_fini(Int exitcode)
{
	#if _SECRETGRIND_
	//taint_summary();
	TNT_(mmap_release)();
	TNT_(sum_names_release)();
	TNT_(malloc_release)();
	TNT_(syswrap_release)();
	TNT_(asm_release)();
	VG_(free)(client_binary_name); client_binary_name = NULL;
	#endif
}

static void TNT_(noop)(Addr a, SizeT len) { 
#if _SECRETGRIND_
	LOG("noop %08lx %lu\n", a, len); 
#endif	
}

static void tnt_pre_clo_init(void)
{ 
#if _SECRETGRIND_
   VG_(details_name)            ("Secretgrind");
   VG_(details_description)     ("find secrets in memory");
   VG_(details_copyright_author)(
      "Copyright (C) 2017-2017, and GNU GPL'd, by Laurent SIMON.\n  " \
      "Taingrind is Copyright (C) 2010-2017, and GNU GPL'd, by Wei Ming Khoo.");
   VG_(details_bug_reports_to)  ("lmrs2@cl.cam.ac.uk");
#else
   VG_(details_name)            ("Taintgrind");
   VG_(details_description)     ("the taint analysis tool");
   VG_(details_copyright_author)(
      "Taingrind is Copyright (C) 2010-2017, and GNU GPL'd, by Wei Ming Khoo.");
   VG_(details_bug_reports_to)  ("weimzz@gmail.com");
#endif

   VG_(details_version)         (NULL);
   VG_(basic_tool_funcs)        (tnt_post_clo_init,
                                 TNT_(instrument),
                                 tnt_fini);

   /* Track syscalls for tainting purposes */
   // TODO: will this conflict?
   VG_(needs_syscall_wrapper)     ( tnt_pre_syscall,
                                    tnt_post_syscall );

   init_shadow_memory();

   init_soaap_data();

#if _SECRETGRIND_ // This is need to get the name of local stack variables using VG_(get_data_description)()
	// cannot check for CL options coz they've not been retrieved at this point
	//if ( !TNT_(clo_summary_total_only) && TNT_(clo_var_name) ) { 
	VG_(needs_var_info)(); 
	//}
#endif

   VG_(needs_command_line_options)(tnt_process_cmd_line_options,
                                   tnt_print_usage,
                                   tnt_print_debug_usage);

   VG_(needs_malloc_replacement)  (TNT_(malloc),
                                   TNT_(__builtin_new),
                                   TNT_(__builtin_vec_new),
                                   TNT_(memalign),
                                   TNT_(calloc),
                                   TNT_(free),
                                   TNT_(__builtin_delete),
                                   TNT_(__builtin_vec_delete),
                                   TNT_(realloc),
                                   TNT_(malloc_usable_size),
                                   TNT_MALLOC_REDZONE_SZB );

   VG_(needs_client_requests)  (TNT_(handle_client_requests));
	   
//   TNT_(mempool_list) = VG_(HT_construct)( "TNT_(mempool_list)" );
#if 0//_SECRETGRIND_
// startup?
// stack signal?
        
    VG_(track_new_mem_startup)	   ( TNT_(new_mem_startup) );
	VG_(track_new_mem_brk)		   ( TNT_(new_mem_brk) );
	//VG_(track_die_mem_brk)         ( TNT_(die_mem_brk) );

	VG_(track_die_mem_brk)         ( TNT_(noop) );
	VG_(track_new_mem_mmap)        ( TNT_(new_mem_mmap) );
	VG_(track_die_mem_munmap)      ( TNT_(die_mem_munmap) );
	VG_(track_copy_mem_remap)      ( TNT_(copy_mem_remap) );
	VG_(track_copy_mem_remap)      ( TNT_(copy_address_range_state) );
#else
   //VG_(track_copy_mem_remap)      ( TNT_(copy_address_range_state) );
   //VG_(track_die_mem_stack_signal)( TNT_(make_mem_untainted) );
   
   VG_(track_die_mem_stack_signal)( TNT_(noop) );
   VG_(track_die_mem_brk)         ( TNT_(noop) );
   VG_(track_die_mem_munmap)      ( TNT_(noop) );
   
#endif

#if _SECRETGRIND_
	VG_(track_new_mem_startup)	   ( TNT_(new_mem_startup) );
	VG_(track_new_mem_mmap)        ( TNT_(new_mem_mmap) );
	VG_(track_copy_mem_remap)      ( TNT_(copy_mem_remap) );
#endif
}

VG_DETERMINE_INTERFACE_VERSION(tnt_pre_clo_init)

#if !_SECRETGRIND_
void TNT_(check_var_access)(ThreadId tid, HChar* varname, Int var_request, enum VariableType type, enum VariableLocation var_loc) {
	if (type == Global && var_loc == GlobalFromApplication) {
		HChar fnname[FNNAME_MAX];
		TNT_(get_fnname)(tid, fnname, FNNAME_MAX);
		Int var_idx = myStringArray_getIndex(&shared_vars, varname);
		// first check if this access is allowed
		Bool allowed = var_idx != -1 && (shared_vars_perms[var_idx] & var_request);
		if (IN_SANDBOX && !allowed) {
			const HChar* access_str;
			switch (var_request) {
				case VAR_READ: {
					access_str = "read";
					break;
				}
				case VAR_WRITE: {
					access_str = "wrote to";
					break;
				}
				default: {
					tl_assert(0);
					break;
				}
			}
			VG_(printf)("*** Sandbox %s global variable \"%s\" in method %s, but it is not allowed to. ***\n", access_str, varname, fnname);
			VG_(get_and_pp_StackTrace)(tid, STACK_TRACE_SIZE);
			VG_(printf)("\n");
		}
		// check for unnannotated writes to global vars both inside and outside
		// sandboxes
		if (var_request == VAR_WRITE) {
			if (next_shared_variable_to_update == NULL || VG_(strcmp)(next_shared_variable_to_update, varname) != 0) {
				if (IN_SANDBOX) {
					if (allowed) {
						VG_(printf)("*** Sandbox is allowed to write to global variable \"%s\" in method %s, but you have not explicitly declared this. ***\n", varname, fnname);
						VG_(get_and_pp_StackTrace)(tid, STACK_TRACE_SIZE);
						VG_(printf)("\n");
					}
				}
				else if (have_created_sandbox) {
					// only output this error if the sandbox is allowed at least read access
					Bool allowed_read = var_idx != -1 && (shared_vars_perms[var_idx] & VAR_READ);
					if (allowed_read) {
						VG_(printf)("*** Global variable \"%s\" is being written to in method %s after a sandbox has been created and so the sandbox will not see this new value. ***\n", varname, fnname);
						VG_(get_and_pp_StackTrace)(tid, STACK_TRACE_SIZE);
						VG_(printf)("\n");
					}
				}
			}
			else {
				next_shared_variable_to_update = NULL;
			}
		}

	}
}
#endif // _SECRETGRIND_

void init_soaap_data() {
	persistent_sandbox_nesting_depth = 0;
	ephemeral_sandbox_nesting_depth = 0;
	have_created_sandbox = False;

	VG_(memset)(shared_vars_perms, 0, sizeof(Int)*VAR_MAX);
	VG_(memset)(shared_fds, 0, sizeof(Int)*FD_MAX);
	VG_(memset)(allowed_syscalls, 0, sizeof(Bool)*SYSCALLS_MAX);

	next_shared_variable_to_update = NULL;
	VG_(free)(client_binary_name); client_binary_name = NULL;
}

/*--------------------------------------------------------------------*/
/*--- end                                                          ---*/
/*--------------------------------------------------------------------*/
