#ifndef TNT_SUM_NAMES_H
#define TNT_SUM_NAMES_H

#if _SECRETGRIND_

extern void TNT_(sum_names_reset_iter)(sn_addr_type_t type);
extern HP_Chunk * TNT_(sum_names_get_next_chunk)(sn_addr_type_t type);
extern void TNT_(sum_names_init)(void);
extern void TNT_(sum_names_release)(void);
extern void TNT_(sum_add_block)(HP_Chunk *hc);
extern void TNT_(sum_delete_block)(HP_Chunk *hc);

#endif

#endif // TNT_SUM_NAMES_H
