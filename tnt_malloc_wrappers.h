#ifndef TNT_MALLOC_WRAPPERS_H
#define TNT_MALLOC_WRAPPERS_H


extern void TNT_(malloc_reset_iter)(void);
extern HP_Chunk * TNT_(malloc_get_next_chunk)(void);
extern Bool TNT_(malloc_is_heap)(Addr a);
extern Bool TNT_(malloc_get_varname)(Addr a, char *pname, SizeT s, char *pdetailedname, SizeT ds);
extern HP_Chunk * TNT_(malloc_get_parent_block)(Addr a, SizeT len);
extern void TNT_(malloc_set_parent)(HP_Chunk *child, HP_Chunk *parent);
extern void TNT_(malloc_init)(void);
extern void TNT_(malloc_release)(void);

#endif // TNT_MALLOC_WRAPPERS_H
