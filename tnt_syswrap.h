#ifndef TNT_SYSWRAP_H
#define TNT_SYSWRAP_H

extern void TNT_(syscall_mmap)(ThreadId tid, UWord* args, UInt nArgs, SysRes res);
extern void TNT_(syscall_munmap)(ThreadId tid, UWord* args, UInt nArgs, SysRes res);
extern void TNT_(syswrap_init)(void);
extern void TNT_(syswrap_release)(void);
extern Bool TNT_(syswrap_is_mmap_file_range)(Addr a);
extern void TNT_(syswrap_mmap_set_parent)(HP_Chunk *child, HP_Chunk *parent);
HP_Chunk * TNT_(syswrap_mmap_get_parent_block)(Addr a, SizeT len);

#endif // TNT_SYSWRAP_H
