
/*--------------------------------------------------------------------*/
/*--- Wrappers for tainting syscalls                               ---*/
/*---                                                tnt_syswrap.c ---*/
/*--------------------------------------------------------------------*/

/*
   This file is part of Taintgrind, a Valgrind tool for
   tracking marked/tainted data through memory.

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
#include "pub_tool_vki.h"
#include "pub_tool_vkiscnums.h"
#include "pub_tool_hashtable.h"
#include "pub_tool_tooliface.h"
#include "pub_tool_libcbase.h"
#include "pub_tool_libcassert.h"
#include "pub_tool_libcprint.h"
#include "pub_tool_libcproc.h"
#include "pub_tool_libcfile.h"
#include "pub_tool_machine.h"
#include "pub_tool_aspacemgr.h"
#include "pub_tool_threadstate.h"
#include "pub_tool_mallocfree.h"
#include "pub_tool_stacktrace.h"   // for VG_(get_and_pp_StackTrace)
#include "pub_tool_debuginfo.h"	   // VG_(describe_IP), VG_(get_fnname)
#include "pub_tool_replacemalloc.h"

#include "valgrind.h"

#include "tnt_include.h"
#include "tnt_malloc_wrappers.h"
#include "tnt_libc.h"
#include "tnt_summary_names.h"
#include "tnt_subblock_helper.h"
#include "tnt_syswrap.h"
#include "tnt_file_filter.h"

static void resolve_filename(Int fd, HChar *path, SizeT max)
{
   HChar src[FD_MAX_PATH];
   Int len = 0;

   // TODO: Cache resolved fds by also catching open()s and close()s
   VG_(sprintf)(src, "/proc/%d/fd/%d", VG_(getpid)(), (int)fd);
   
   len = VG_(readlink)(src, path, max);
   
   // Just give emptiness on error.
   if (len == -1) len = 0;
   path[len] = '\0';
}

/* enforce an arbitrary maximum */
#if _SECRETGRIND_
static struct {
	Bool taint;
	UInt read_offset;
} tainted_fds[VG_N_THREADS][FD_MAX] = {};

static void set_fd_taint( ThreadId tid, Int fd, Bool taint ) 			{	tl_assert(fd<FD_MAX); tainted_fds[tid][fd].taint = taint; 		}
static Bool get_fd_taint( ThreadId tid, Int fd ) 						{	tl_assert(fd<FD_MAX); return tainted_fds[tid][fd].taint;		}
static UInt get_fd_read_offset( ThreadId tid, Int fd ) 				{	tl_assert(fd<FD_MAX); return tainted_fds[tid][fd].read_offset;	}
static void set_fd_read_offset( ThreadId tid, Int fd, UInt offset ) 	{	tl_assert(fd<FD_MAX); tainted_fds[tid][fd].read_offset = offset;}
#else
static Bool tainted_fds[VG_N_THREADS][FD_MAX] = {};
static UInt read_offset = 0;
#endif


void TNT_(syscall_lseek)(ThreadId tid, UWord* args, UInt nArgs,
                                  SysRes res) {
// off_t lseek(int fd, off_t offset, int whence);
   Int   fd      = args[0];
   ULong offset  = args[1];
   UInt  whence  = args[2];
#if _SECRETGRIND_
   Bool  verbose      = TNT_(clo_verbose);
#else
   Bool  verbose      = False;
#endif

#if _SECRETGRIND_
	if ( get_fd_taint(tid,fd) == False)
      return;
#else
   if (fd >= FD_MAX || tainted_fds[tid][fd] == False)
      return;
#endif

   Int   retval       = sr_Res(res);

   if ( verbose )
   {
      VG_(printf)("syscall _lseek %d %d ", tid, fd);
      VG_(printf)("offset: 0x%x whence: 0x%x ", (UInt)offset, whence);
#if _SECRETGRIND_
	  VG_(printf)("retval: 0x%x read_offset: 0x%x\n", retval, get_fd_read_offset(tid,fd));
#else
      VG_(printf)("retval: 0x%x read_offset: 0x%x\n", retval, read_offset);
#endif
   }

#if _SECRETGRIND_
   if( whence == 0/*SEEK_SET*/ )
      set_fd_read_offset(tid,fd,0 + (UInt)offset);
   else if( whence == 1/*SEEK_CUR*/ )
      set_fd_read_offset(tid,fd, get_fd_read_offset(tid,fd) + (UInt)offset);
   else if( whence == 2/*SEEK_END*/ )
      set_fd_read_offset(tid,fd,retval);
   else {
      VG_(printf)("whence %x\n", whence);
      tl_assert(0);
   }
#else
   if( whence == 0/*SEEK_SET*/ )
      read_offset = 0 + (UInt)offset;
   else if( whence == 1/*SEEK_CUR*/ )
      read_offset += (UInt)offset;
   else if( whence == 2/*SEEK_END*/ )
      read_offset = retval;
   else {
      VG_(printf)("whence %x\n", whence);
      tl_assert(0);
   }
#endif
}

void TNT_(syscall_llseek)(ThreadId tid, UWord* args, UInt nArgs,
                                  SysRes res) {
// int  _llseek(int fildes, ulong offset_high, ulong offset_low, loff_t *result,, uint whence);
   Int   fd           = args[0];
   ULong offset_high  = args[1];
   ULong offset_low   = args[2];
   UInt  result       = args[3];
   UInt  whence       = args[4];
   ULong offset;
#if _SECRETGRIND_
   Bool  verbose      = TNT_(clo_verbose);
#else
   Bool  verbose      = False;
#endif

#if _SECRETGRIND_
   if ( get_fd_taint(tid,fd) == False)
      return;
#else
   if (fd >= FD_MAX || tainted_fds[tid][fd] == False)
      return;
#endif

   Int   retval       = sr_Res(res);

   if ( verbose )
   {
      VG_(printf)("syscall _llseek %d %d ", tid, fd);
      VG_(printf)("0x%x 0x%x 0x%x 0x%x\n", (UInt)offset_high, (UInt)offset_low, result, whence);
      VG_(printf)("0x%x\n", retval);
   }

   offset = (offset_high<<32) | offset_low;

#if _SECRETGRIND_
   if( whence == 0/*SEEK_SET*/ )
      set_fd_read_offset(tid,fd,0 + (UInt)offset);
   else if( whence == 1/*SEEK_CUR*/ )
      set_fd_read_offset(tid,fd, get_fd_read_offset(tid,fd) + (UInt)offset);
   else {
      VG_(printf)("whence %x\n", whence);
      tl_assert(0);
   }
#else
   if( whence == 0/*SEEK_SET*/ )
      read_offset = 0 + (UInt)offset;
   else if( whence == 1/*SEEK_CUR*/ )
      read_offset += (UInt)offset;
   else {//if( whence == 2/*SEEK_END*/ )
      VG_(printf)("whence %x\n", whence);
      tl_assert(0);
   }
#endif
}

Bool TNT_(syscall_allowed_check)(ThreadId tid, int syscallno) {
	if (IN_SANDBOX && IS_SYSCALL_ALLOWED(syscallno)) {
		HChar fnname[FNNAME_MAX];
		TNT_(get_fnname)(tid, fnname, FNNAME_MAX);
		VG_(printf)("*** Sandbox performed system call %s (%d) in method %s, but it is not allowed to. ***\n", syscallnames[syscallno], syscallno, fnname);
		VG_(get_and_pp_StackTrace)(tid, STACK_TRACE_SIZE);
		VG_(printf)("\n");
		return False;
	}
	return True;
}

#if _SECRETGRIND_

//TODO: this function does not work properly...
static __inline__ 
void _range_common(UWord *addr, Int *len, UInt taint_offset, Int taint_len,
                   UInt curr_offset, Int curr_len, HChar *data, Bool isMmap) 
{
	
	tl_assert ( addr && len ); 
	
	// data should be a multiple of the block size of it's an mmap call
	SizeT mmapPageSize = TNT_(clo_mmap_pagesize);
	if ( isMmap ) { tl_assert ( ((Addr)data & ~(mmapPageSize-1)) == (Addr)data && "block size appears invalid" ); }
	
	
	(*addr) = 0;
	(*len) = 0;
	
	if( TNT_(clo_taint_all) ){
      (*addr) = (UWord)data;
      (*len)  = curr_len;
   
   } else {
		
      //VG_(printf)("curr_offset 0x%x\n", curr_offset);
      //VG_(printf)("curr_len    0x%x\n", curr_len);
      //VG_(printf)("tnt_offset 0x%x\n", taint_offset);
      //VG_(printf)("tnt_len    0x%x\n", taint_len);

	   /* Here we determine what bytes to taint
		  We have 4 variables -
		  taint_offset    Starting file offset to taint
		  taint_len       Number of bytes to taint
		  curr_offset     Starting file offset currently read
		  curr_len        Number of bytes currently read
		  We have to deal with 4 cases: (= refers to the region to be tainted)
		  Case 1:
							  taint_len
		  taint_offset   |-----------------|
							  curr_len
		  curr_offset |---=================---|
		  Case 2:
							  taint_len
		  taint_offset   |-----------------------|
							  curr_len
		  curr_offset |---====================|
		  Case 3:
							  taint_len
		  taint_offset |----------------------|
							  curr_len
		  curr_offset    |====================---|
		  Case 4:
							  taint_len
		  taint_offset |-----------------------|
							  curr_len
		  curr_offset    |====================|
	   */

	   if( taint_offset >= curr_offset &&
		   taint_offset <= curr_offset + curr_len ){
		   if( (taint_offset + taint_len) <= (curr_offset + curr_len) ){
			 // Case 1
			 (*addr) = (UWord)(data + taint_offset - curr_offset);
			 (*len)  = taint_len;
		  }else{
			  // Case 2
			  (*addr) = (UWord)(data + taint_offset - curr_offset);
			  (*len)  = curr_len - taint_offset + curr_offset;
		  }

	   }else if( ( ( taint_offset + taint_len ) >= curr_offset ) &&
				 ( ( taint_offset + taint_len ) <= (curr_offset + curr_len ) ) ){
		  // Case 3
		  (*addr) = (UWord)data;
		  (*len)  = taint_len - curr_offset + taint_offset;
	   }else if( ( taint_offset <= curr_offset ) &&
		   ( taint_offset + taint_len ) >= ( curr_offset + curr_len ) ){
		  // Case 4
		  (*addr) = (UWord)data;
		  (*len)  = curr_len;
	   }else{
		  // nothing to do
		  //return; Laurent:removed
	   }
   }
   
   // taint mem in block of blkSize, only if 
   // - this calls if from mmap
   // - mmapPageSize not 0 and multiple of 2 -- check done in main.c:tnt_post_clo_init()
   // - input param are the default ones. If they are not, then we only use the values provided for tainting
  if ( isMmap && TNT_(taint_file_params_are_default)() ) {
	
	// must be power of 2
	(*addr) &= ~(mmapPageSize-1);
	(*len) = mmapPageSize * ( ((*len) + (mmapPageSize - 1)) / mmapPageSize );
  }
}

#endif

static
void read_common ( UInt taint_offset, Int taint_len,
                   UInt curr_offset, Int curr_len,
                   HChar *data ) {
   UWord addr = 0;
   Int   len = 0;
   //Int   i;

	
#if _SECRETGRIND_
	//HP_Chunk *hc = 0;
	_range_common(&addr, &len, taint_offset, taint_len,
                   curr_offset, curr_len, data, False);
#else
   if( TNT_(clo_taint_all) ){
      addr = (UWord)data;
      len  = curr_len;
   } else
		
      //VG_(printf)("curr_offset 0x%x\n", curr_offset);
      //VG_(printf)("curr_len    0x%x\n", curr_len);
      //VG_(printf)("tnt_offset 0x%x\n", taint_offset);
      //VG_(printf)("tnt_len    0x%x\n", taint_len);

   /* Here we determine what bytes to taint
      We have 4 variables -
      taint_offset    Starting file offset to taint
      taint_len       Number of bytes to taint
      curr_offset     Starting file offset currently read
      curr_len        Number of bytes currently read
      We have to deal with 4 cases: (= refers to the region to be tainted)
      Case 1:
                          taint_len
      taint_offset   |-----------------|
                          curr_len
      curr_offset |---=================---|
      Case 2:
                          taint_len
      taint_offset   |-----------------------|
                          curr_len
      curr_offset |---====================|
      Case 3:
                          taint_len
      taint_offset |----------------------|
                          curr_len
      curr_offset    |====================---|
      Case 4:
                          taint_len
      taint_offset |-----------------------|
                          curr_len
      curr_offset    |====================|
   */

   if( taint_offset >= curr_offset &&
       taint_offset <= curr_offset + curr_len ){
       if( (taint_offset + taint_len) <= (curr_offset + curr_len) ){
         // Case 1
         addr = (UWord)(data + taint_offset - curr_offset);
         len  = taint_len;
      }else{
          // Case 2
          addr = (UWord)(data + taint_offset - curr_offset);
          len  = curr_len - taint_offset + curr_offset;
      }

   }else if( ( ( taint_offset + taint_len ) >= curr_offset ) &&
             ( ( taint_offset + taint_len ) <= (curr_offset + curr_len ) ) ){
      // Case 3
      addr = (UWord)data;
      len  = taint_len - curr_offset + taint_offset;
   }else if( ( taint_offset <= curr_offset ) &&
       ( taint_offset + taint_len ) >= ( curr_offset + curr_len ) ){
      // Case 4
      addr = (UWord)data;
      len  = curr_len;
   }else{
      //return; Laurent:removed
   }
   
#endif // _SECRETGRIND_

#if _SECRETGRIND_
   if ( addr && len ) {
#endif

   TNT_(make_mem_tainted)( addr, len );

   #if _SECRETGRIND_
   }
   
   // it is fone to call this function because it's not a master block
   // the master block was created in syscall_mmap
   TNT_(record_receive_taint_for_addr)(addr, (SizeT)len, False, "file");
   
   #endif
   //for( i=0; i<len; i++) 
   //   VG_(printf)("taint_byte 0x%08lx 0x%02x\n", addr+i, *(Char *)(addr+i));
}

void TNT_(syscall_read)(ThreadId tid, UWord* args, UInt nArgs,
                                  SysRes res) {
// ssize_t  read(int fildes, void *buf, size_t nbyte);
   LOG_ENTER();
    
   Int   fd           = args[0];
   HChar *data        = (HChar *)args[1];
#if _SECRETGRIND_
   UInt  curr_offset  = get_fd_read_offset(tid,fd);
#else
   UInt  curr_offset  = read_offset;
#endif
   Int   curr_len     = sr_Res(res); // Laurent: can this overflow as the read syscall returns ssize_t which has a different size based on platform http://lxr.free-electrons.com/source/arch/mn10300/include/uapi/asm/posix_types.h#L32?
   UInt  taint_offset = TNT_(clo_filetaint_start);
   UInt  taint_len    = TNT_(clo_filetaint_len);
   #if _SECRETGRIND_
   Bool  verbose      = TNT_(clo_verbose);
   #else
   Bool  verbose      = False;
   #endif

   TNT_(check_fd_access)(tid, fd, FD_READ);

   //LOG("curr_len:%d, data:%s, curr_offset:%u, fd:%d, is_tainted:%d\n", curr_len, data, curr_offset, fd, get_fd_taint(tid,fd));
   if (curr_len == 0) return;

   TNT_(make_mem_untainted)( (UWord)data, curr_len );

#if _SECRETGRIND_
   if (get_fd_taint(tid,fd) == False)
      return;
#else
   if (fd >= FD_MAX || tainted_fds[tid][fd] == False)
      return;
#endif

   if(verbose){
	   
      //VG_(printf)("taint_offset: 0x%x\ttaint_len: 0x%x\n", taint_offset, taint_len);
      //VG_(printf)("curr_offset : 0x%x\tcurr_len : 0x%x\n", curr_offset, curr_len);
      VG_(printf)("syscall read %d %d ", tid, fd);
#ifdef VGA_amd64
      VG_(printf)("0x%x 0x%x 0x%llx 0x%x\n", curr_offset, curr_len, (ULong)data,
          *(HChar *)data);
#else
      VG_(printf)("0x%x 0x%x 0x%x 0x%x\n", curr_offset, curr_len, (UInt)data,
          *(HChar *)data);
#endif
   }

   read_common ( taint_offset, taint_len, curr_offset, curr_len, data );

   // Update file position
#if _SECRETGRIND_
   set_fd_read_offset( tid, fd, get_fd_read_offset(tid,fd) + curr_len) ;
#else
   read_offset += curr_len;
#endif

   // DEBUG
   //tnt_read = 1;
}

void TNT_(syscall_pread)(ThreadId tid, UWord* args, UInt nArgs,
                                  SysRes res) {
// ssize_t pread(int fildes, void *buf, size_t nbyte, size_t offset);
   Int   fd           = args[0];
   HChar *data        = (HChar *)args[1];
   UInt  curr_offset  = (Int)args[3];
   Int   curr_len     = sr_Res(res);
   UInt  taint_offset = TNT_(clo_filetaint_start);
   Int   taint_len    = TNT_(clo_filetaint_len);
   #if _SECRETGRIND_
   Bool  verbose      = TNT_(clo_verbose);
   #else
   Bool  verbose      = False;
   #endif

   if (curr_len == 0) return;

   TNT_(make_mem_untainted)( (UWord)data, curr_len );

#if _SECRETGRIND_
   if (get_fd_taint(tid,fd) == False)
      return;
#else
   if (fd >= FD_MAX || tainted_fds[tid][fd] == False)
      return;
#endif

   if(verbose){
      //VG_(printf)("taint_offset: 0x%x\ttaint_len: 0x%x\n", taint_offset, taint_len);
      //VG_(printf)("curr_offset : 0x%x\tcurr_len : 0x%x\n", curr_offset, curr_len);
      VG_(printf)("syscall pread %d %d ", tid, fd);

#ifdef VGA_amd64
      VG_(printf)("0x%x 0x%x 0x%llx\n", curr_offset, curr_len, (ULong)data);
#else
      VG_(printf)("0x%x 0x%x 0x%x\n", curr_offset, curr_len, (UInt)data);
#endif

   }

   read_common ( taint_offset, taint_len, curr_offset, curr_len, data );
}


void TNT_(syscall_open)(ThreadId tid, UWord* args, UInt nArgs, SysRes res) {
//  int open (const char *filename, int flags[, mode_t mode])
   HChar fdpath[FD_MAX_PATH];
   Int fd = sr_Res(res);
#if _SECRETGRIND_
   Bool  verbose      = TNT_(clo_verbose);
   //LOG("open nArgs:%u, fd:%d\n", nArgs, fd);
#else
   Bool  verbose      = False;
#endif
   
   // check if we have already created a sandbox
   if (have_created_sandbox && !IN_SANDBOX) {
#ifdef VGO_freebsd
	   VG_(resolve_filename)(fd, fdpath, FD_MAX_PATH-1);
#elif defined VGO_linux
	   resolve_filename(fd, fdpath, FD_MAX_PATH-1);
#else
#error OS unknown
#endif
	   HChar fnname[FNNAME_MAX];
	   TNT_(get_fnname)(tid, fnname, FNNAME_MAX);
	   VG_(printf)("*** The file %s (fd: %d) was opened in method %s after a sandbox was created, hence it will not be accessible to the sandbox. It will need to be passed to the sandbox using sendmsg. ***\n", fdpath, fd, fnname);
	   VG_(get_and_pp_StackTrace)(tid, STACK_TRACE_SIZE);
	   VG_(printf)("\n");
   }

    // Nothing to do if no file tainting
#if _SECRETGRIND_
	if ( !TNT_(file_filter_present)() )
#else
    if ( VG_(strlen)( TNT_(clo_file_filter)) == 0 )
#endif
        return;

    if (fd > -1 && fd < FD_MAX) {

#ifdef VGO_freebsd
	VG_(resolve_filename)(fd, fdpath, FD_MAX_PATH-1);
#elif defined VGO_linux
        resolve_filename(fd, fdpath, FD_MAX_PATH-1);
#else
#error OS unknown
#endif

		//LOG("fdpath:%s, filter:%s\n", fdpath, TNT_(clo_file_filter));
        if( TNT_(clo_taint_all) ){

#if _SECRETGRIND_
			set_fd_taint(tid,fd,True);
#else
            tainted_fds[tid][fd] = True;
#endif
            if ( verbose )
               VG_(printf)("syscall open %d %s %lx %d\n", tid, fdpath, args[1], fd);
#if _SECRETGRIND_
			set_fd_read_offset( tid, fd, 0 );
#else 
            read_offset = 0;
#endif

#if _SECRETGRIND_
		} else if ( TNT_(file_filter_match)(fdpath) ) {
#else
        } else if ( VG_(strncmp)(fdpath, TNT_(clo_file_filter), 
                            VG_(strlen)( TNT_(clo_file_filter))) == 0 ) {
#endif
		
#if _SECRETGRIND_
			set_fd_taint(tid,fd,True);
#else
            tainted_fds[tid][fd] = True;
#endif
   
            if ( verbose )
               VG_(printf)("syscall open %d %s %lx %d\n", tid, fdpath, args[1], fd);
#if _SECRETGRIND_
			set_fd_read_offset( tid, fd, 0 );
#else 
			read_offset = 0;
#endif

#if _SECRETGRIND_
		} else if ( TNT_(file_filter_all)() ) {
#else
        } else if ( TNT_(clo_file_filter)[0] == '*' &&
            VG_(strncmp)( fdpath + VG_(strlen)(fdpath) 
                        - VG_(strlen)( TNT_(clo_file_filter) ) + 1, 
                          TNT_(clo_file_filter) + 1, 
                          VG_(strlen)( TNT_(clo_file_filter)) - 1 ) == 0 ) {
#endif

#if _SECRETGRIND_
			set_fd_taint(tid,fd,True);
#else
            tainted_fds[tid][fd] = True;
#endif
            if ( verbose )
               VG_(printf)("syscall open %d %s %lx %d\n", tid, fdpath, args[1], fd);
#if _SECRETGRIND_
			set_fd_read_offset( tid, fd, 0 );
#else 
			read_offset = 0;
#endif

        } else {
#if _SECRETGRIND_
			set_fd_taint(tid,fd,False);
#else
            tainted_fds[tid][fd] = False;
#endif
		}

    }
}

void TNT_(syscall_close)(ThreadId tid, UWord* args, UInt nArgs, SysRes res) {
//   int close (int filedes)
   Int fd = args[0];

   if (fd > -1 && fd < FD_MAX){
     //if (tainted_fds[tid][fd] == True)
#if _SECRETGRIND_
     LOG("syscall close tid=%d %d\n", tid, fd);
#endif
     shared_fds[fd] = 0;
#if _SECRETGRIND_
	 set_fd_taint(tid,fd,False);
#else
	 tainted_fds[tid][fd] = False;
#endif
   }
}

void TNT_(syscall_write)(ThreadId tid, UWord* args, UInt nArgs, SysRes res) {
	Int fd = args[0];
	TNT_(check_fd_access)(tid, fd, FD_WRITE);
}

void TNT_(get_fnname)(ThreadId tid, HChar* buf, UInt buf_size) {
	   UInt pc = VG_(get_IP)(tid);
	   VG_(get_fnname)(pc, buf, buf_size);
}

void TNT_(check_fd_access)(ThreadId tid, UInt fd, Int fd_request) {
	if (IN_SANDBOX) {
		Bool allowed = shared_fds[fd] & fd_request;
//		VG_(printf)("checking if allowed to %s from fd %d ... %d\n", (fd_request == FD_READ ? "read" : "write"), fd, allowed);
		if (!allowed) {
			const HChar* access_str;
			switch (fd_request) {
				case FD_READ: {
					access_str = "read from";
					break;
				}
				case FD_WRITE: {
					access_str = "wrote to";
					break;
				}
				default: {
					tl_assert(0);
					break;
				}
			}
			HChar fdpath[FD_MAX_PATH];
#ifdef VGO_freebsd
			VG_(resolve_filename)(fd, fdpath, FD_MAX_PATH-1);
#elif defined VGO_linux
			resolve_filename(fd, fdpath, FD_MAX_PATH-1);
#else
#error OS unknown
#endif
			HChar fnname[FNNAME_MAX];
			TNT_(get_fnname)(tid, fnname, FNNAME_MAX);
			VG_(printf)("*** Sandbox %s %s (fd: %d) in method %s, but it is not allowed to. ***\n", access_str, fdpath, fd, fnname);
			VG_(get_and_pp_StackTrace)(tid, STACK_TRACE_SIZE);
			VG_(printf)("\n");
		}
	}
}

void TNT_(syscall_recv)(ThreadId tid, UWord* args, UInt nArgs, SysRes res) {
// ssize_t recv(int sockfd, void *buf, size_t len, int flags)
   Int msglen  = sr_Res(res);
   HChar *data = (HChar *)args[1];
   VG_(printf)("syscall recv %d 0x%x 0x%02x\n", tid, msglen, data[0]);

}

void TNT_(syscall_recvfrom)(ThreadId tid, UWord* args, UInt nArgs, SysRes res) {
// ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags,
//                 struct sockaddr *src_addr, socklen_t *addrlen)
// TODO: #include <arpa/inet.h> inet_ntop to pretty print IP address
   Int msglen  = sr_Res(res);
   HChar *data = (HChar *)args[1];
   VG_(printf)("syscall recvfrom %d 0x%x 0x%02x\n", tid, msglen, data[0]);

}

#if _SECRETGRIND_

#define UNKNOWN_MMAPED_OBJ_FMT	"@0x%lx_mmap_%u_%u"

void TNT_(syscall_munmap)(ThreadId tid, UWord* args, UInt nArgs, SysRes res)
{
	LOG_ENTER();
	
	if ( TNT_(clo_summary_total_only) ) { return; }
	
	Addr addr = args[0];
	UInt length = args[1];
	
	LOG("addr:0x%lx, length:%u\n", addr, length);
	
	sn_addr_type_t type = SN_ADDR_MMAP_FILE;
	TNT_(sum_names_reset_iter)(type);
	HP_Chunk *hp = NULL;
	SizeT mmapPageSize = TNT_(clo_mmap_pagesize);
		
	while ( (hp=TNT_(sum_names_get_next_chunk)(type)) ) {
		
		// get the size of the block allocated given the address and size of the memory region we're munmap()'ing
		UInt blkLength = mmapPageSize * ( (length + (mmapPageSize - 1)) / mmapPageSize ); 
		LOG("blkLength:%u\n", blkLength);
		
		//LOG("checking %lx against %lx - %lx\n", curr, hp->data, hp->data+hp->req_szB+hp->slop_szB);
		if ( /*VG_(addr_is_in_block)( addr, hp->data, hp->req_szB, hp->slop_szB )*/ 
			addr == hp->data && (hp->req_szB == blkLength || blkLength == hp->req_szB+hp->slop_szB)  ) {
			// display warning if any byte is tainted
			// Note: we could remove the mapping entry from the tnt_summary_names
			// but mmap/munmap occurs rarely I think
			if ( subblk_warn_if_tainted(hp, &TNT_(print_MmapExeContext), "munmap()'ed", False) ) {
			
				// the block contains some tainted 
								
				// set the block as released, and keep track of how the trace that led to it
				hp->Alloc.release_trace = TNT_(retrieveExeContext)();
				
			} else {
			
				// no taint in the block
				// we can free this block and remove it from summary if there's no taint in it:TODO
				// even if some child blocks point to this one, they will never have to get the parent anyway
				TNT_(sum_delete_block)(hp);
				
			}
			
			break;
		}
	}
	
	#if 0
	// display error if file unmapped and is tainted
	
	#endif
	
	LOG_EXIT();
}

// Note: remap taken care of in tnt_main
// Laurent: Note: regardless of the size of the file, whatever we're asked to map will contain
// tainted data. This means if use maps 100 bytes of a 50byte file, then we will taint 100 bytes in memory
void TNT_(syscall_mmap)(ThreadId tid, UWord* args, UInt nArgs, SysRes res)
{
	/*
	 * void *mmap(void *addr, size_t length, int prot, int flags,
                  int fd, off_t offset)
	 */
	
	LOG_ENTER();
	
	//tl_assert ( nArgs == 6 );
	Addr addr_ret  = sr_Res(res);	
	//Addr addr = args[0];
	UInt length = args[1];
	//int prot = args[2];
	//int flags = args[3];
	int fd = args[4];
	SizeT offset = args[5];
	
	if (fd > -1 && get_fd_taint(tid,fd) == True) {

		//VG_(printf)("found tainted file %d passed to mmap length:%lu\n", fd, length);
		char objname[128];
		char vname[128], vdname[128];
		HP_Chunk* hc = 0;
		
		//if ( TNT_(clo_var_name) ) {
			TNT_(get_object_name)(objname, sizeof(objname));
			VG_(snprintf)(vname, sizeof(vname), UNKNOWN_MMAPED_OBJ_FMT, addr_ret, VG_(getpid)(),  VG_(get_running_tid)());
			VG_(snprintf)(vdname, sizeof(vdname), UNKNOWN_MMAPED_OBJ_FMT, addr_ret, VG_(getpid)(),  VG_(get_running_tid)());
	    //} else {
		//	VG_(snprintf)(vname, sizeof(vname), RAW_ADDR_FMT, addr_ret);
		//	VG_(snprintf)(vdname, sizeof(vdname), RAW_ADDR_FMT, addr_ret);
		//}
		
		// create this block only if the user requested a verbose sumary
		//if ( TNT_(clo_summary_verbose) ) {
		hc = TNT_(alloc_chunk_from_varnames_and_type)(addr_ret, length, 0, vname, vdname, SN_ADDR_MMAP_FILE, False);
		hc->Alloc.master = 1;
		//}
						
		// taint mem -- copy-paste of read_common code
		Addr addr_start = 0;
		Int addr_len = 0; // for compatibility with read()... not sure this is wise.
		UInt  taint_offset = TNT_(clo_filetaint_start);
		Int  taint_len    = TNT_(clo_filetaint_len);
		UInt curr_offset = offset;
		Int curr_len = length;
		
		tl_assert ( length <= INT_MAX );
		tl_assert ( curr_offset == (curr_offset & ~(TNT_(clo_mmap_pagesize)-1)) && "offset not a multiple of block size" );
		_range_common(&addr_start, &addr_len, taint_offset, taint_len, curr_offset, curr_len, (HChar*)addr_ret, True);
		if ( addr_start && addr_len ) {
			
			if ( hc && addr_len > length ) {
				// that's possible if we take the filesystem block size into account
				hc->req_szB = addr_len;
				hc->slop_szB = 0; // already 0 normally
			}
			TNT_(make_mem_tainted)( addr_start, addr_len );
			
			// we only display and do not record because it's already done with mmap formatting above
			TNT_(display_receive_taint_for_addr)(addr_start, addr_len, vname, "mmap'ed file");
			
			// WARNING: we dont set a parent; this means the taint was from a mmap()'ed file 
			// and there is no instruction to show
		}
		
		// add this block only if we user requested a verbose sumary
		// the block is null otherwise -- see above
		if ( hc ) {
			//VG_(printf)("add block mapp file %lx %lu\n", addr_start, addr_len);
			TNT_(sum_add_block)(hc/*, SN_ADDR_MMAP_FILE*/);
		} 
	}

	LOG( "addr_ret:0x%lx, addr:0x%lx, length:%u, proto:%d, flags:%d fd:%d, offset:%lu\n", addr_ret, addr, length, prot, flags, fd, offset );
	
	LOG_EXIT();
}

void TNT_(syswrap_mmap_set_parent)(HP_Chunk *child, HP_Chunk *parent) {
	tl_assert (child && parent && parent->Alloc.master);
	// sanity checks, just in case: this should never happen coz it may create issues upon releasing
	tl_assert (child != parent);
	
	child->Alloc.parent = parent;
	parent->Alloc.hasChild = 1;
}

HP_Chunk * TNT_(syswrap_mmap_get_parent_block)(Addr a, SizeT len) {
	
	sn_addr_type_t type = SN_ADDR_MMAP_FILE;
	TNT_(sum_names_reset_iter)(type);
	HP_Chunk *hp = NULL;
	while ( (hp=TNT_(sum_names_get_next_chunk)(type)) ) {
		
		// check that it is a master block is set os that we're looking at mmap()'ed blocks rather than a block
		// that contains taint info
		// this is not optimized as we may be looping over many blocks of no interest
		// so we should keep track of our own block like malloc module:TODO
		// on the bright side, mapp()'ed files are rare compared to malloc()'ed ones
		if ( !hp->Alloc.master ) { continue; } 
		
		//LOG("checking %lx against %lx - %lx\n", curr, hp->data, hp->data+hp->req_szB+hp->slop_szB);
		// WARNING: for now assume the [addr, addr+len] does not overlap with multiple heap-allocated blocks
		// that is, the block is contained within the parent block completly
		tl_assert ( a <= (SizeT)(-1) - len ); // ensures no overflow
		tl_assert ( hp->data <= (SizeT)(-1) - hp->req_szB ); // ensures no overflow
		tl_assert ( a >= hp->data && a+len <= hp->data + hp->req_szB ); // Note: i dont account for the alignment space
		break;
	}
	
	tl_assert (hp && "hp is NULL");
	
	return hp;
}

Bool TNT_(syswrap_is_mmap_file_range)(Addr a)
{
	sn_addr_type_t type = SN_ADDR_MMAP_FILE;
	TNT_(sum_names_reset_iter)(type);
	HP_Chunk *hp = NULL;
	while ( (hp=TNT_(sum_names_get_next_chunk)(type)) ) {
		// here I dont care about master block; the first one we find is good enough...
		if ( VG_(addr_is_in_block)( a, hp->data, hp->req_szB, hp->slop_szB )  ) {
			return True;
		}
	}

	return False;
}



void TNT_(syswrap_init)(void) 
{
	ThreadId t = 0;
	VG_(memset)(&tainted_fds[0], 0, sizeof(tainted_fds));
	tl_assert ( (ThreadId)(-1) >= VG_N_THREADS );	// make sure threadId can be incremented in the loop without overflowing
	
	if (TNT_(clo_taint_stdin)) {
		for(t=0; t < VG_N_THREADS; ++t) {
			set_fd_taint(t, 0, True);
			// read_offset unchnaged: so it won't use the --file-taint-start and --file-taint-len options
		}
	}
	
}

void TNT_(syswrap_release)(void) 
{	
}

#endif

/*--------------------------------------------------------------------*/
/*--- end                                                          ---*/
/*--------------------------------------------------------------------*/
