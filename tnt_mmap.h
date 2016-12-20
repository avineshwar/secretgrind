#ifndef TNT_MMAP_H
#define TNT_MMAP_H

#if _SECRETGRIND_

extern void TNT_(mmap_init)(void);
extern void TNT_(mmap_release)(void);
extern Bool TNT_(mmap_is_region)(Addr a);
extern void TNT_(mmap_add_region)(Addr a, SizeT len);

#endif	// _SECRETGRIND_

#endif // TNT_mmap_H
