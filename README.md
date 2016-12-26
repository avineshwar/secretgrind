Secretgrind: a Valgrind analysis tool to detect secrets in memory
=================================================================

Secretgrind is based on [Taintgrind](https://github.com/wmkhoo/taintgrind) by Wei Ming Khoo.
Taintgrind is based on [Valgrind](http://valgrind/org)'s MemCheck and work by Will Drewry on [Flayer](http://code.google.com/p/flayer/).

Warnings:
---------
1. Secretgrind was tested on x86_64 Linux. If you encounter problems building/running it on different arch/platforms, create an issue [here](https://github.com/lmrs2/secretgrind/issues)

2. Do not run Secretgrind on untrusted software as the code has not been properly audited. There are a lot of memory-copy operations...
	
Requirements:
------------
1. Python must be installed on your machine for the installation process to complete

2. Please follow the instruction *in order*. You will get an error if you don't
	
Installation:
-------------

1. Download [Valgrind](http://valgrind.org) and build


		[me@machine ~/] wget valgrind.org/downloads/valgrind-3.10.1.tar.bz2
		[me@machine ~/] diff <(sha256sum -b valgrind-3.10.1.tar.bz2) <(echo 'fa253dc26ddb661b6269df58144eff607ea3f76a9bcfe574b0c7726e1dfcb997 *valgrind-3.10.1.tar.bz2')
                    		An empty results means files are identical
		[me@machine ~/] tar jxvf valgrind-3.10.1.tar.bz2
		[me@machine ~/] cd valgrind-3.10.1

2. Git clone Secretgrind

		[me@machine ~/valgrind-3.10.1] git clone https://github.com/lmrs2/secretgrind.git
		[me@machine ~/valgrind-3.10.1] cd secretgrind 

3. Download [Capstone](http://www.capstone-engine.org/)

		[me@machine ~/valgrind-3.10.1/secretgrind] wget https://github.com/aquynh/capstone/archive/3.0.4.tar.gz -O capstone-3.0.4.tar.gz
		[me@machine ~/valgrind-3.10.1/secretgrind] tar zxvf capstone-3.0.4.tar.gz

4. Configure and build Valgrind

		[me@machine ~/valgrind-3.10.1/secretgrind] sh configure_valgrind.sh
		[me@machine ~/valgrind-3.10.1] cd ..
		[me@machine ~/valgrind-3.10.1] ./autogen.sh
		[me@machine ~/valgrind-3.10.1] ./configure --prefix=`pwd`/inst 							
		[me@machine ~/valgrind-3.10.1] make && make install


5. Configure and build Capstone

		[me@machine ~/valgrind-3.10.1] cd secretgrind
		[me@machine ~/valgrind-3.10.1/secretgrind] sh configure_capstone.sh `pwd`/../inst		// Note: obviously this should be the same as the one used to configure Valgrind!
		[me@machine ~/valgrind-3.10.1/secretgrind] cd capstone-3.0.4
		[me@machine ~/valgrind-3.10.1/secretgrind/capstone-3.0.4] sh make_capstone.sh

6. Configure and build Secretgrind

		[me@machine ~/valgrind-3.10.1/secretgrind/capstone-3.0.4] cd ../
		[me@machine ~/valgrind-3.10.1/secretgrind] ../autogen.sh
		[me@machine ~/valgrind-3.10.1/secretgrind] ./configure --prefix=`pwd`/../inst			// Note: obviously this should be the same as the one used to configure Valgrind and Capstone!
		[me@machine ~/valgrind-3.10.1/secretgrind] make && make install


Usage
-----
	[me@machine ~/wherever/] alias secretgrind="~/valgrind-3.10.1/inst/bin/valgrind --tool=secretgrind"
	[me@machine ~/wherever/] secretgrind --help
	[me@machine ~/wherever/] secretgrind --file-filter=taintedfile.txt ./program_that_reads_tainted_file

	...
	  user options for Secretgrind:

	File options:
	    --file-filter=<f1,f2,...,fn>      list of files (full path) to taint, separated by comma [""]
	    --file-taint-start=[0,800000]     starting byte to taint (in hex) [0]
	    --file-taint-len=[0,800000]       number of bytes to taint from file-taint-start (in hex) [800000]
	    --file-mmap-use-pagesize=[1,2^32] size to taint when mmap()'ing tainted file [4096]

	Taint options:
	    --taint-df-only= no|yes           propagate taint only thru 'direct flows' (df) [no]. Note: pointer arithmetic propagation not supported
	    --taint-remove-on-release= no|yes remove taint when block is released (free(),mumap(file)) [no]
	    --taint-warn-on-release= no|yes   display live information when a block is released (free(),mumap(file)) yet tainted [no]
	    --taint-show-source= no|yes       show information when taint is received from file or secretgrind API [no]
	    --taint-stdin= no|yes             taint stdin input [no]. Note: --file-taint-start and --file-taint-len do not apply to stdin

	Trace options:
	    --trace= no|yes                   print an instruction trace [no]. Slow, try using SG_PRINT_X_INST() instead
	    --trace-taint-only= no|yes        print only tainted instructions [yes]. Must be used in conjunction with --trace=yes. Slow, try using SG_PRINT_X_INST() instead

	Summary options:
	    --summary= no|yes                 display a taint summary after execution [yes]
	    --summary-verbose= no|yes         print a detailed taint summary [no]. Tainted regions show as @0xAAAAAAAA_TYPE_PID_ValgrindThreadID, eg @0x4025000_mmap_10432_1
	    --summary-main-only= yes|no       print taint summary at the end of the main() function only [no]
	    --summary-exit-only= yes|no       print taint summary upon entering the exit() function only [no]
	    --summary-total-only= no|yes      taint summary only shows the total # bytes tainted [no]
	    --summary-fix-inst= [1,ffffffff]  try to fix the stack trace for instructions by giving a list of IDs separated by comma

	General options:
	    --var-name= no|yes                print variable names if possible [no]. Very slow, so try using in combination with SG_PRINT_X_INST()
	    --mnemonics= no|yes               display the mnemonics of the original instruction responsible for tainting data [no]
	    --debug= no|yes                   print debug info [no]



Examples
--------
1. Create a file containing tainted data:
	
		[me@machine ~/examples] echo "This is a tainted file" > tainted.txt

2. Consider the following code (call it test.c):
	```c
	#include <stdlib.h>
	#include <unistd.h>
	#include <stdio.h>
	#include <stdint.h>
	#include <errno.h>
	#include <sys/types.h>
	#include <sys/stat.h>
	#include <fcntl.h>
	#include <string.h>
	
	#define LEN	(50)

	int main(int argc, char* argv[])
	{
		char *s = 0;
		int fd = 0;
		ssize_t n = 0;
		
		if ( (s = malloc(LEN)) == 0) {
			printf("error malloc %d (%s)\n", errno, strerror(errno)); 
			goto end;
		}
		
		if ( (fd = open (argv[1], O_RDWR )) < 0) { 
			printf("error open %d (%s)\n", errno, strerror(errno)); 
			goto end;
		}
		
		if ( (n = read(fd, s, LEN)) < 0) {
			printf("error read %d (%s)\n", errno, strerror(errno));
			goto end;
		}
				
	end:
		if (fd>0)	{ close(fd); }
		if (s)		{ free(s); 	 }
		
		return 0;
	}
	```
	
3. Compile as:
	
		[me@machine ~/examples] gcc -Wall -O0 test.c -o test
	
4.1 Run Secretgrind as:
	
		[me@machine ~/examples] secretgrind ./test tainted.txt
		[me@machine ~/examples] ...

		==123== [TAINT SUMMARY] - On end main():
		---------------------------------------------------

		No bytes tainted

		==123== [TAINT SUMMARY] - On exit():
		---------------------------------------------------

		No bytes tainted
		==123== 

By default, Secretgrind only displays a short summary about bytes tainted after returning from the main() function ("==123== [TAINT SUMMARY] - On end main():")
and before exiting the program ("==123== [TAINT SUMMARY] - On exit():"). The n-digit number "==123==" indicates the process ID of the process during execution.
In this run, the process ID is 123. This run indicates no taint "No bytes tainted" right after main() and before exit()'ing the program. This is normal since we
have not indicated that the file tainted.txt should be considered tainted.

4.2 To tell Secretgind that tainted.txt is tainted, use the option --file-filter=file1,file2,fileN (the fullpath of files is necessary):

		[me@machine ~/examples] secretgrind --file-filter=/home/me/examples/tainted.txt ./test tainted.txt
		[me@machine ~/examples] ...

		==123== [TAINT SUMMARY] - On end main():
		---------------------------------------------------

		***(1) (malloc)	 range [0x51ec040 - 0x51ec057]	 (24 bytes)	 is tainted

		Total bytes tainted: 24

		==123== [TAINT SUMMARY] - On exit():
		---------------------------------------------------

		***(1) (malloc)	 range [0x51ec040 - 0x51ec057]	 (24 bytes)	 is tainted

		Total bytes tainted: 24
		==123== 

By default, Secretgrind provides a short summary of each memory region found tainted. In this run, 24 bytes (range [0x51ec040 - 0x51ec057]) are tainted. It also 
indicates the "type" of the memory that is tainted, here "malloc" since the variable "char *s" was malloc()'ed. Other keywords you might see here are: 
"fmmap" for mapp()'ed files, "mmap" for non-file mapp()'ed 
memory regions, "stack", "global", and "other" for anything else.

4.3 To get more information about the taint, such as the stacktrace that led to the taint, and how the block was allocated (in the case of malloc()'ed and mmap()'ed regions), run:

		[me@machine ~/examples] secretgrind --summary-verbose=yes --file-filter=/home/me/examples/tainted.txt ./test tainted.txt
		[me@machine ~/examples] ...

		==123== [TAINT SUMMARY] - On end main():
		---------------------------------------------------

		***(1) (malloc)	 range [0x51ec040 - 0x51ec057]	 (24 bytes)	 is tainted
		   > (malloc) [0x51ec040 - 0x51ec057] (24 bytes): 0x51ec040
				tainted     at 0x4F13F30: read (in /lib/x86_64-linux-gnu/libc-2.15.so)
							by 0x4007F2: main (in /auto/homes/lmrs2/zero_mem/VALGRIND/tests/test1)
			 Parent block [0x51ec040 - 0x51ec071] (50 bytes): @0x51ec040_malloc_2030_1
				malloc()'ed at 0x4C2B3E4: malloc (vg_replace_malloc.c:296)
							by 0x40074C: main (in /auto/homes/lmrs2/zero_mem/VALGRIND/tests/test1)
				free()'ed   at 0x4C2A2EA: free (vg_replace_malloc.c:473)
							by 0x40084D: main (in /auto/homes/lmrs2/zero_mem/VALGRIND/tests/test1)

		Total bytes tainted: 24

		==123== [TAINT SUMMARY] - On exit():
		---------------------------------------------------

		***(1) (malloc)	 range [0x51ec040 - 0x51ec057]	 (24 bytes)	 is tainted
		   > (malloc) [0x51ec040 - 0x51ec057] (24 bytes): 0x51ec040
				tainted     at 0x4F13F30: read (in /lib/x86_64-linux-gnu/libc-2.15.so)
							by 0x4007F2: main (in /auto/homes/lmrs2/zero_mem/VALGRIND/tests/test1)
			 Parent block [0x51ec040 - 0x51ec071] (50 bytes): @0x51ec040_malloc_2030_1
				malloc()'ed at 0x4C2B3E4: malloc (vg_replace_malloc.c:296)
							by 0x40074C: main (in /auto/homes/lmrs2/zero_mem/VALGRIND/tests/test1)
				free()'ed   at 0x4C2A2EA: free (vg_replace_malloc.c:473)
							by 0x40084D: main (in /auto/homes/lmrs2/zero_mem/VALGRIND/tests/test1)

		Total bytes tainted: 24
		==123== 



4.4 Taint after main() and before exit() may differ, and that is why Secretgrind displays both by default. But you can tell Secretgrind to display only one of them:

		[me@machine ~/examples] secretgrind --summary-verbose=yes --file-filter=/home/me/examples/tainted.txt ./test tainted.txt
		[me@machine ~/examples] ...

		==123== [TAINT SUMMARY] - On end main():
		---------------------------------------------------

		***(1) (malloc)	 range [0x51ec040 - 0x51ec057]	 (24 bytes)	 is tainted
		   > (malloc) [0x51ec040 - 0x51ec057] (24 bytes): 0x51ec040
				tainted     at 0x4F13F30: read (in /lib/x86_64-linux-gnu/libc-2.15.so)
							by 0x4007F2: main (in /auto/homes/lmrs2/zero_mem/VALGRIND/tests/test1)
			 Parent block [0x51ec040 - 0x51ec071] (50 bytes): @0x51ec040_malloc_2030_1
				malloc()'ed at 0x4C2B3E4: malloc (vg_replace_malloc.c:296)
							by 0x40074C: main (in /auto/homes/lmrs2/zero_mem/VALGRIND/tests/test1)
				free()'ed   at 0x4C2A2EA: free (vg_replace_malloc.c:473)
							by 0x40084D: main (in /auto/homes/lmrs2/zero_mem/VALGRIND/tests/test1)

		Total bytes tainted: 24
		==123==
	
We see that the tainted memory region [0x51ec040 - 0x51ec057] was tainted because of a call to read() in libc, and the call originated from the main() function.
Furthermore, the tainted region belongs to the "parent" block [0x51ec040 - 0x51ec071] which is 50-byte long ("malloc(LEN)"). The block was malloc()'ed by the main() function.
There is a strange line about "malloc (vg_replace_malloc.c:XXX)": this is an artifact of Valgrind's instrumentation and can be ignored in practice.

4.5 Sometimes it can be difficult to pinpoint which instruction is responsible for the tain, especially when it is because of register pressure, calling convention, etc.
So you can also ask Secretgrind to display the instructions:

		[me@machine ~/examples] secretgrind --mnemonics=yes --summary-verbose=yes --file-filter=/home/me/examples/tainted.txt ./test tainted.txt
		[me@machine ~/examples] ...

		==123== [TAINT SUMMARY] - On end main():
		---------------------------------------------------

		***(1) (malloc)	 range [0x51ec040 - 0x51ec057]	 (24 bytes)	 is tainted
		   > (malloc) [0x51ec040 - 0x51ec057] (24 bytes): 0x51ec040
				tainted     at 0x4F13F30: read (in /lib/x86_64-linux-gnu/libc-2.15.so)
							by 0x4007F2: main (in /auto/homes/lmrs2/zero_mem/VALGRIND/tests/test1)
				tainted     by instruction 'syscall ' (raw=0f 05, ID=_1cb37_)
			 Parent block [0x51ec040 - 0x51ec071] (50 bytes): @0x51ec040_malloc_2491_1
				malloc()'ed at 0x4C2B3E4: malloc (vg_replace_malloc.c:296)
							by 0x40074C: main (in /auto/homes/lmrs2/zero_mem/VALGRIND/tests/test1)
				free()'ed   at 0x4C2A2EA: free (vg_replace_malloc.c:473)
							by 0x40084D: main (in /auto/homes/lmrs2/zero_mem/VALGRIND/tests/test1)

		Total bytes tainted: 24
		==123== 

There is now an extra line indicating the instruction was "syscall" (0f 05 in hex). There is also an instruction ID "_1cb37_". If you ever see an inconsistent stacktrace, then 
it is possible Secretgrind did not manage to retrieve the stacktrace correctly. In this case, you can the pass this instruction ID to --summary-fix-inst=1cb37 to tell Secretgrind 
to try to fix the problem. It worked fine here, so we need not use "--summary-fix-inst". In general, Secretgrind gets the stacktrace right so 
you should not have to use this option often in practice. Something you must be aware of if that your compiler may be inlining functions. So it is possible that you have 
a function foo1() -> foo2() -> foo3() -> foo4() i your source code, but the compiler might inline calls as foo1() -> foo2(); where foo2() contains the code of foo3() and foo4().
So you objdump to check this before you resort to "--summary-fix-inst".

4.6 Secregrind can also be asked to retrieve the names (as they appear in the source code) of the variables that are tainted. This works for stack and global variables only 
at the moment. This will make Secregtgrind much much slower, as it will try to lookup the name of variables for each access to taint memory. So you use this option sparsely!
Update the code as follows (note the use of a new stack variable "stack_var" and "stack_var = s[4];" to assign it some tainted data ):

	```c
	#include <stdlib.h>
	#include <unistd.h>
	#include <stdio.h>
	#include <stdint.h>
	#include <errno.h>
	#include <sys/types.h>
	#include <sys/stat.h>
	#include <fcntl.h>
	#include <string.h>

	#define LEN	(50)
	
	int main(int argc, char* argv[])
	{
		char *s = 0;
		int fd = 0;
		ssize_t n = 0;
		char stack_var = 0;
		
		if ( (s = malloc(LEN)) == 0) {
			printf("error malloc %d (%s)\n", errno, strerror(errno)); 
			goto end;
		}
		
		if ( (fd = open (argv[1], O_RDWR )) < 0) { 
			printf("error open %d (%s)\n", errno, strerror(errno)); 
			goto end;
		}
		
		if ( (n = read(fd, s, LEN)) < 0) {
			printf("error read %d (%s)\n", errno, strerror(errno));
			goto end;
		}
		
		stack_var = s[4]; // stack_var should not be tainted
		
	end:
		if (fd>0)	{ close(fd); }
		if (s)		{ free(s); 	 }
		
		return 0;
	}
	```
	
and recompile it as:
	
		[me@machine ~/examples] gcc -Wall -O0 test.c -o test
	
Now run Secretgrind and ask it to display variable names:

		[me@machine ~/examples] secretgrind --var-name=yes --mnemonics=yes --summary-verbose=yes --file-filter=/home/me/examples/tainted.txt ./test tainted.txt
		[me@machine ~/examples] ...
	

		==123== [TAINT SUMMARY] - On end main():
		---------------------------------------------------

		***(1) (malloc)	 range [0x51ec040 - 0x51ec057]	 (24 bytes)	 is tainted
		   > (malloc) [0x51ec040 - 0x51ec057] (24 bytes): @0x51ec040_malloc_4208_1
				tainted     at 0x4F13F30: read (in /lib/x86_64-linux-gnu/libc-2.15.so)
							by 0x4007F6: main (in /auto/homes/lmrs2/zero_mem/VALGRIND/tests/test1)
				tainted     by instruction 'syscall ' (raw=0f 05, ID=_1cb38_)
			 Parent block [0x51ec040 - 0x51ec071] (50 bytes): @0x51ec040_malloc_4208_1
				malloc()'ed at 0x4C2B3E4: malloc (vg_replace_malloc.c:296)
							by 0x400750: main (in /auto/homes/lmrs2/zero_mem/VALGRIND/tests/test1)
				free()'ed   at 0x4C2A2EA: free (vg_replace_malloc.c:473)
							by 0x40085D: main (in /auto/homes/lmrs2/zero_mem/VALGRIND/tests/test1)

		***(2) (stack)	 range [0xffefffb4b - 0xffefffb4b]	 (1 bytes)	 is tainted
		   > (stack) [0xffefffb4b - 0xffefffb4b] (1 bytes): obj_test1@0xffefffb4b_unknownvar_4208_1
				tainted     at 0x400838: main (in /auto/homes/lmrs2/zero_mem/VALGRIND/tests/test1)
				tainted     by instruction 'movb %al, -0x25(%rbp)' (raw=88 45 db, ID=_1cb41_)

		Total bytes tainted: 25
		==123==

As expected, an extra byte is tainted, and it is a stack variable. However, Secregtgrind is unable to show us the original variable name. We can try to recompile with debugging information:

		[me@machine ~/examples] gcc -g -Wall -O0 test.c -o test
	
Re-run Secretgrind:

		[me@machine ~/examples] secretgrind --var-name=yes --mnemonics=yes --summary-verbose=yes --file-filter=/home/me/examples/tainted.txt ./test tainted.txt
		[me@machine ~/examples] ...
	
		==123== [TAINT SUMMARY] - On end main():
		---------------------------------------------------

		***(1) (malloc)	 range [0x51ec040 - 0x51ec057]	 (24 bytes)	 is tainted
		   [...]

		***(2) (stack)	 range [0xffefffb4b - 0xffefffb4b]	 (1 bytes)	 is tainted
		   > (stack) [0xffefffb4b - 0xffefffb4b] (1 bytes): test1.c:18:@0xffefffb4b:stack_var
				tainted     at 0x400838: main (test1.c:35)
				tainted     by instruction 'movb %al, -0x25(%rbp)' (raw=88 45 db, ID=_1cb41_)

		Total bytes tainted: 25
		==123== 

Secregtgrind is now able to infer the information we want: "test1.c:18:@0xffefffb4b:stack_var": this means the variable is stored at address 0xffefffb4b, its name is stack_var
and was declared in the file test1.c at line 18.

Now recompile test1.c with optimization:

		[me@machine ~/examples] gcc -Wall -O2 test.c -o test
	
	
and re-run Secretgrind:

		[me@machine ~/examples] secretgrind --var-name=yes --mnemonics=yes --summary-verbose=yes --file-filter=/home/me/examples/tainted.txt ./test tainted.txt
		[me@machine ~/examples] ...
	
		==123== [TAINT SUMMARY] - On end main():
		---------------------------------------------------

		***(1) (malloc)	 range [0x51ec040 - 0x51ec057]	 (24 bytes)	 is tainted
		   [...]

		Total bytes tainted: 24
		==123== 

The stack variable is no longer tainted. The compiler realized the stack_var was never used and has no effect on the program, so it has just removed it entirely 
from the binary. In other words, it no longer exists in the binary. That is why it is no longer tainted... Even if the variable was not removed entirely, it could 
be kept in a register rather than allocated on the stack: the register would be tainted but not memory, and so Secregtgrind would still display 
only 24 tainted bytes. If you see unexpected results, look at the assembly code.


4.7 Secretgrind can also display a live trace of what is executed with --trace=yes option. The output can be overwhelming, so if you are only interested in the taint, it is 
good practice to --trace-taint-only=yes:

		[me@machine ~/examples] gcc -Wall -O0 test.c -o test	# we want to see stack_var
		[me@machine ~/examples] secretgrind --trace-taint-only=yes --trace=yes --var-name=yes --mnemonics=yes --summary-verbose=yes --file-filter=/home/me/examples/tainted.txt ./test tainted.txt
		[me@machine ~/examples] ...

		==123== 0x400834: 0f b6 40 04: movzbl 4(%rax), %eax     ID _1cb40_:
		==123== 0x400834: main (in /auto/homes/lmrs2/zero_mem/VALGRIND/tests/test1) | t14_9600 = LOAD I8 t10_10371 | 0x2000000000000000 | 0xff00000000000000 | t14_9600 <- @0x51ec040_malloc_123_1
		==123== 0x400834: main (in /auto/homes/lmrs2/zero_mem/VALGRIND/tests/test1) | t29_5404 = 8Uto32 t14_9600 | 0x2000000000000000 | 0xff00000000000000 | t29_5404 <- t14_9600
		==123== 0x400834: main (in /auto/homes/lmrs2/zero_mem/VALGRIND/tests/test1) | t13_11966 = t29_5404 | 0x2000000000000000 | 0xff00000000000000 | t13_11966 <- t29_5404
		==123== 0x400834: main (in /auto/homes/lmrs2/zero_mem/VALGRIND/tests/test1) | t30_6184 = 32Uto64 t13_11966 | 0x2000000000000000 | 0xff00000000000000 | t30_6184 <- t13_11966
		==123== 0x400834: main (in /auto/homes/lmrs2/zero_mem/VALGRIND/tests/test1) | t12_11569 = t30_6184 | 0x2000000000000000 | 0xff00000000000000 | t12_11569 <- t30_6184
		==123== 0x400834: main (in /auto/homes/lmrs2/zero_mem/VALGRIND/tests/test1) | r16_1 = t12_11569 | 0x2000000000000000 | 0xff00000000000000 | r16_1 <- t12_11569

		==123== 0x400838: 88 45 db: movb %al, -0x25(%rbp)     ID _1cb41_:
		==123== 0x400838: main (in /auto/homes/lmrs2/zero_mem/VALGRIND/tests/test1) | t17_9609 = r16_1 I8 | 0x2000000000000000 | 0xff00000000000000 | t17_9609 <- r16_1
		==123== 0x400838: main (in /auto/homes/lmrs2/zero_mem/VALGRIND/tests/test1) | STORE t15_10583 = t17_9609 | 0x2000000000000000 | 0xff00000000000000 | obj_test1@0xffefffb4b_unknownvar_123_1 <- t17_9609

		==123== [TAINT SUMMARY] - On end main():
		---------------------------------------------------
		[...]
	
Secretgrind displays each instruction that are executed. The first that appears in the run is "0f b6 40 04: movzbl 4(%rax), %eax     ID _1cb40_:". This shows both the raw 
instruction in hex (0f b6 40 04), its mnemonics (movzbl 4(%rax), %eax), and an instruction ID (_1cb40_). This correponds to "stack_var = s[4];" in the source code.
Valgrind represents an instruction in [Single-Static-Assignment (SSA) form](https://en.wikipedia.org/wiki/Static_single_assignment_form). That is why you see
multiple lines of "execution"  for each instruction. As explained by [Taintgrind](https://github.com/wmkhoo/taintgrind), the output of taintgrind is a list of Valgrind IR (VEX) statements of the form:

		Address/Location 	| VEX-IRStmt 		  | Runtime value(s)   | Taint value(s) 	| Information flow
		t14_9600 = 			  LOAD I8 t10_10371   | 0x2000000000000000 | 0xff00000000000000 | t14_9600 <- @0x51ec040_malloc_123_1

Only one run-time/taint value per instruction is shown. That variable is usually the one being assigned, e.g. t14_9600 in this case. 
In the case of an if-goto, it is the conditional variable; in the case of an indirect jump, it is the jump target. 
Loads and stores have two possible useful run-time values: the address and the data being loaded/stored. We have simply chosen to print the data.
Runtime values are displayed as they appear in memory: for exmaple, on an LE platform the integer 4 will show as 0x04000000; on a BE platform
it will show as 0x00000004. Here, t14_9600 is loaded with value 0x2000000000000000. 0x20 is the space character ' ', which is indeed the 5th character of 
the string "This is a tainted file." contained in tainted.txt . The values loaded in t14_9600 is "variable" @0x51ec040_malloc_123_1, ie 
data at memory address 0x51ec040, which is of type "malloc", allocated by process with pid "123" and Valgrind thread ID "1". 
Details of VEX operators and IRStmts can be found in VEX/pub/libvex_ir.h .

If you are interested only in the total number of tainted bytes, and not the summary, you can use --summary-total-only=yes; and you can full disable the summary with --summary=no.

	
Client requests
---------------

Secretgrind may be further controlled via client requests defined in secretgrind.h:
	
		SG_PRINT_ALL_INST()			-> print all instructions
		SG_PRINT_TAINTED_INST()			-> print tainted instructions
		SG_STOP_PRINT()				-> stop all printing

		SG_MAKE_MEM_TAINTED(address, length)	-> taint memory region
		SG_MAKE_MEM_UNTAINTED(address, length)	-> untaint memory region

		SG_TAINT_SUMMARY(name)				-> display a summary
		SG_READ_TAINT_STATE(name, address, length)	-> display taint for range [address - address + length - 1]
	
However, you should use those sparsely: as they are inserted in your code at compilation time, they change the original program binary.
For example, you might see stack variables not tainted when you use these APIs, and not tainted when you do not - the stack may be used to push 
function arguments...

To use those APIs, you must #include "secretgrind.h" in your file:

	```c
	#include <stdlib.h>
	#include <unistd.h>
	#include <stdio.h>
	#include <stdint.h>
	#include <errno.h>
	#include <sys/types.h>
	#include <sys/stat.h>
	#include <fcntl.h>
	#include <string.h>

	#define LEN	(50)
	
	#include "secretgrind.h"	// header file for APIs
	
	int main(int argc, char* argv[])
	{
		char *s = 0;
		int fd = 0;
		ssize_t n = 0;
		char stack_var = 0;
		
		if ( (s = malloc(LEN)) == 0) {
			printf("error malloc %d (%s)\n", errno, strerror(errno)); 
			goto end;
		}
		
		if ( (fd = open (argv[1], O_RDWR )) < 0) { 
			printf("error open %d (%s)\n", errno, strerror(errno)); 
			goto end;
		}
		
		SG_TAINT_SUMMARY("before we read");	// show taint summary
		
		if ( (n = read(fd, s, LEN)) < 0) {
			printf("error read %d (%s)\n", errno, strerror(errno));
			goto end;
		}
		
		SG_TAINT_SUMMARY("after we read");	// show taint summary
		
		stack_var = s[4]; // stack_var should not be tainted
		
		SG_READ_TAINT_STATE("stack_var taint", &stack_var, sizeof(stack_var));
		
	end:
		if (fd>0)	{ close(fd); }
		if (s)		{ free(s); 	 }
		
		SG_MAKE_MEM_UNTAINTED(&stack_var, sizeof(stack_var));	// untaint the stack_var
		
		SG_MAKE_MEM_TAINTED(&n, sizeof(n));		// taint n
		
		return 0;
	}
	```
	
Compile as:

		gcc -I/home/me/valgrind-3.10.1/inst/include/valgrind -Wall -O0 -g test.c -o test	# we want to see stack_var and names
	
Run, for example:

		[me@machine ~/examples] secretgrind --var-name=yes --summary-main-only=yes --summary-verbose=yes --mnemonics=yes --file-filter=/home/me/examples/tainted.txt ./test tainted.txt
		[me@machine ~/examples] ...

		==123== [TAINT SUMMARY] - before we read:
		---------------------------------------------------

		No bytes tainted

		==123== [TAINT SUMMARY] - after we read:
		---------------------------------------------------

		***(1) (malloc)	 range [0x51ec040 - 0x51ec057]	 (24 bytes)	 is tainted

		Total bytes tainted: 24

		[TAINT STATE]: stack_var taint (1 bytes)
			range [0xffefffa33 - 0xffefffa33] (1 bytes)	is NOT tainted

		==123== [TAINT SUMMARY] - On end main():
		---------------------------------------------------

		***(1) (malloc)	 range [0x51ec040 - 0x51ec057]	 (24 bytes)	 is tainted
		   > (malloc) [0x51ec040 - 0x51ec057] (24 bytes): @0x51ec040_malloc_10382_1
				tainted     at 0x4F13F30: read (in /lib/x86_64-linux-gnu/libc-2.15.so)
							by 0x400AD3: main (test1.c:34)
				tainted     by instruction 'syscall ' (raw=0f 05, ID=_1cb45_)
			 Parent block [0x51ec040 - 0x51ec071] (50 bytes): @0x51ec040_malloc_10382_1
				malloc()'ed at 0x4C2B3E4: malloc (vg_replace_malloc.c:296)
							by 0x400997: main (test1.c:22)
				free()'ed   at 0x4C2A2EA: free (vg_replace_malloc.c:473)
							by 0x400C50: main (test1.c:47)

		***(1) (stack)	 range [0xffefffa38 - 0xffefffa3f]	 (8 bytes)	 is tainted
		   > (stack) [0xffefffa38 - 0xffefffa3f] (8 bytes): test1.c:19:@0xffefffa38:n
				tainted     at 0x400D16: main (test1.c:51)
				tainted     by API call


		Total bytes tainted: 32
		==123== 

We see additional information: two [TAINT SUMMARY] in response to calls to SG_TAINT_SUMMARY(), one [TAINT STATE] for SG_READ_TAINT_STATE().
Furthermore, stack_var is no longer tainted because of the call to SG_MAKE_MEM_UNTAINTED(), and 8 additional bytes are tainted because of the call
to SG_MAKE_MEM_TAINTED(). The instruction responsible for tainting "n" is "API call" because it was tainted artificially by a call to SG_MAKE_MEM_TAINTED().

Notes
-----
Secretgrind is based on [Valgrind](https://github.com/wmkhoo/taintgrind) by Wei Ming Khoo.
Taintgrind is based on [Valgrind](http://valgrind/org)'s MemCheck and work by Will Drewry on [Flayer](http://code.google.com/p/flayer/).
