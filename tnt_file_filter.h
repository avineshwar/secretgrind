#ifndef __TNT_FILE_FILTER_H
#define __TNT_FILE_FILTER_H

extern Bool TNT_(file_filter_present)(void);
extern SizeT TNT_(file_filter_get_max_length)(void);	// size
extern SizeT TNT_(file_filter_get_length)(void);
extern const char * TNT_(file_filter_get)( SizeT index );
extern void TNT_(file_filter_set)( SizeT index, char *s );
extern Bool TNT_(file_filter_match)( char *s );
extern Bool TNT_(file_filter_all)(void);

#endif	//	__TNT_FILE_FILTER_H
