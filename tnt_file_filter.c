#include "secretgrind.h"
#include "tnt_include.h"
#include "pub_tool_libcassert.h"
#include "tnt_libc.h"
#include "tnt_file_filter.h"

#if _SECRETGRIND_

struct {
	HChar filter_list[MAX_FILE_FILTER][MAX_PATH];
	SizeT len;
} TNT_(clo_file_filter) = {};


Bool TNT_(file_filter_present)() { return TNT_(file_filter_get_length)()>0; }

SizeT TNT_(file_filter_get_max_length)() { return LEN( TNT_(clo_file_filter).filter_list ); }

SizeT TNT_(file_filter_get_length)() { return TNT_(clo_file_filter).len; }

const char * TNT_(file_filter_get)( SizeT index ) { tl_assert( index < TNT_(file_filter_get_max_length)()); return &TNT_(clo_file_filter).filter_list[index][0]; }

void TNT_(file_filter_set)( SizeT index, char *s )	{ 
	tl_assert( index < TNT_(file_filter_get_max_length)()); 
	libc_strlcpy( TNT_(clo_file_filter).filter_list[index], s, sizeof(TNT_(clo_file_filter).filter_list[index]) );
	TNT_(clo_file_filter).len = max(index+1, TNT_(clo_file_filter).len);
}

Bool TNT_(file_filter_all)() { 
	SizeT i=0;
	for ( i=0; i<TNT_(file_filter_get_length)() ; ++i) { 
		if ( TNT_(file_filter_get)(i)[0] == '*' ) { return True; }
	}
	return False;
}

Bool TNT_(file_filter_match)( char *s ) { 
	SizeT i=0;
	for ( i=0; i<TNT_(file_filter_get_length)() ; ++i) { 
		if ( VG_(strcmp)(s, TNT_(file_filter_get)(i)) == 0 ) { return True; }
	}
	return False;
}

#endif // _SECRETGRIND_
