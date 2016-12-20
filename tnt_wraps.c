/*
 * For replacement/wrappers to work, they must be loaded 
 * in the address space of the prog under analysis [0]. This
 * means, for instance, that we must LD_PRELOAD it. Valgrind 
 * offers this out of the box, thru the Makefile.am; the resulting
 * .XX is automatically pre loaded when launching taintgrind.
 * For details on MACRO, see [1,2].
 * size_t is the equivalent of SizeT [0].
 * 
 * [0] http://valgrind.org/docs/manual/manual-core-adv.html
 * [1] pub_tool_redir.h
 * [2] pub_too_basic.h
 * 
 * from pub_tool_redir.h
 * Z-encoding
   ~~~~~~~~~~
   Z-encoding details: the scheme is like GHC's.  It is just about
   readable enough to make a preprocessor unnecessary.  First the
   "_vgrZU_" or "_vgrZZ_" prefix is added, and then the following
   characters are transformed.

     *         -->  Za    (asterisk)
     :         -->  Zc    (colon)
     .         -->  Zd    (dot)
     -         -->  Zh    (hyphen)
     +         -->  Zp    (plus)
     (space)   -->  Zs    (space)
     _         -->  Zu    (underscore)
     @         -->  ZA    (at)
     $         -->  ZD    (dollar)
     (         -->  ZL    (left)
     )         -->  ZR    (right)
     Z         -->  ZZ    (Z)

   Everything else is left unchanged.
 * 
 * WARNING: wrappers and replacements require the symbol
 * to be visible. Typically, in shared libraries, this would work.
 * If functions are inlined, eg libc's strlen, strcmp, etc,
 * then this won't work.
 */

#include "pub_tool_basics.h"
#include "pub_tool_redir.h"
#include "secretgrind.h"

#include "valgrind.h"

#include <stdio.h> // printf when testing
#include <inttypes.h>
/*
 * for wrappers
 * - CALL_FN_W_W
 * - CALL_FN_v_WWWW
 * - ...
 * see ../include/valgrind.h
 * */
 
#define W_FUNC(L,ret_ty, f, args...) \
   ret_ty I_WRAP_SONAME_FNNAME_ZU(L,f)(args); \
   ret_ty I_WRAP_SONAME_FNNAME_ZU(L,f)(args)

#define W_LIBC_FUNC(ret_ty, f, args...) W_FUNC(VG_Z_LIBC_SONAME,ret_ty,f,args)
#define W_NONE_FUNC(ret_ty, f, args...) W_FUNC(NONE,ret_ty,f,args)

// =========================================
// 				 polarssl
// =========================================
#define W_POLARSSL_FUNC(ret_ty, f, args...) W_FUNC(libmbedtlsZdsoZa/*libmbedtls.so.**/,ret_ty,f,args)
											   
// size_t mpi_msb( const mpi *X )
/*W_POLARSSL_FUNC(size_t, mpi_msb, const void * s) {
    size_t    r;
	OrigFn fn;
	VALGRIND_GET_ORIG_FN(fn);
	TNT_PRINT_TAINTED_INST();
	CALL_FN_W_W(r, fn, s);
	TNT_STOP_PRINT();
	return r;
}*/

/*W_POLARSSL_FUNC(void, mpi_mul_hlp, size_t i, void *s, void *d, uint64_t b ) {
	OrigFn fn;
	VALGRIND_GET_ORIG_FN(fn);
	TNT_PRINT_TAINTED_INST();
	CALL_FN_v_WWWW(fn, i, s, d, b);
	TNT_STOP_PRINT();
}*/

/*W_NONE_FUNC(size_t, mpi_msb, const void * s) {
    size_t    r;
	OrigFn fn;
	VALGRIND_GET_ORIG_FN(fn);
	TNT_PRINT_ALL_INST();
	CALL_FN_W_W(r, fn, s);
	TNT_STOP_PRINT();
	return r;
}*/

// Note: when strlen uses SIMD instructions, the result is tainted
// Turns out this the wrapper is not reliable because the calls 
// compilers drop a code "inline".
// I found that using a wrapper is actually WORSE, because to pass the param
// to the wrapper, a lot of tainted stuff is copied and it's hard to untaint it
// as it is handled by valgrind itself...
/*W_LIBC_FUNC(size_t, strlen, char* s) {
    size_t    r;
	OrigFn fn;
	VALGRIND_GET_ORIG_FN(fn);
	CALL_FN_W_W(r, fn, s);
	TNT_MAKE_MEM_UNTAINTED(&r, sizeof(r));
	return r;
}*/

/*W_LIBC_FUNC(int, strcmp, char* str1, char* str2) {
    printf("compare's wrapper: args %s %s\n", (char*)str1, (char*)str2);
	return 0;
}

W_LIBC_FUNC(int, open, const char *path, int oflags) {
	
	int    fd = -1;
	OrigFn fn;
	VALGRIND_GET_ORIG_FN(fn);
	printf("open's wrapper: args %s %d\n", path, oflags);
	CALL_FN_W_WW(fd, fn, path, oflags);
	printf("open's wrapper: result %d\n", fd);
	return fd;
}

W_NONE_FUNC(int, fact, int n) {

   int    r;
   OrigFn fn;
   VALGRIND_GET_ORIG_FN(fn);
   printf("in wrapper1-pre:  fact(%d)\n", n);
   CALL_FN_W_W(r, fn, n);
   printf("in wrapper1-post: fact(%d) = %d\n", n, r);
   return r;
}*/
