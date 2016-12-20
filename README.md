Taintgrind: a Valgrind taint analysis tool
==========================================


2013-11-18 Currently supporting: Valgrind 3.9.0, x86\_linux and amd64\_linux


This text is available in [Czech](http://czlib.bizcow.com/post/taintgrind-a-valgrind-poskvrnit-nastroj-pro-analyzu) (kindly translated by [Alex Novak](http://bizcow.com))

Requirements:
------------
	1. Python must be installed on your machine for the installation process to complete
	2. Please follow the instruction *in order*. You will get an error if you don't.
	
Installation:
-------------

1. Download [Valgrind](http://valgrind.org) and build


		[me@machine ~/] wget valgrind.org/downloads/valgrind-3.10.1.tar.bz2
		[me@machine ~/] diff <(sha256sum -b valgrind-3.10.1.tar.bz2) <(echo 'fa253dc26ddb661b6269df58144eff607ea3f76a9bcfe574b0c7726e1dfcb997 *valgrind-3.10.1.tar.bz2')
                    		An empty results means files are identical
		[me@machine ~/] tar jxvf valgrind-3.10.1.tar.bz2
		[me@machine ~/] cd valgrind-3.10.1

2. Git clone Secretgrind

		[me@machine ~/valgrind-3.10.1] wget https://www.cl.cam.ac.uk/~lmrs2/secretgrind.zip
		[me@machine ~/valgrind-3.10.1] 7z x secretgrind.zip
		[me@machine ~/valgrind-3.10.1] cd secretgrind 

3. Download Capstone

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

6. Configure and build Taintgrind

		[me@machine ~/valgrind-3.10.1/secretgrind/capstone-3.0.4] cd ../
		[me@machine ~/valgrind-3.10.1/secretgrind] ../autogen.sh
		[me@machine ~/valgrind-3.10.1/secretgrind] ./configure --prefix=`pwd`/../inst			// Note: obviously this should be the same as the one used to configure Valgrind and Capstone!
		[me@machine ~/valgrind-3.10.1/secretgrind] make && make install


Usage
-----
	[me@machine ~/wherever/] alias secretgrind=~/valgrind-3.10.1/inst/bin/valgrind --tool=secretgrind
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



Sample output
-------------

TODO
Details of VEX-IDs and VEX-IRStmts can be found in VEX/pub/libvex\_ir.h .

Notes
-----
Secretgrind is based on [Valgrind](https://github.com/wmkhoo/taintgrind) by Wei Ming Khoo.
Taintgrind is based on [Valgrind](http://valgrind/org)'s MemCheck and work by Will Drewry on [Flayer](http://code.google.com/p/flayer/).

TODO: examples

The output of Taintgrind can be *huge*. You might consider piping the output to gzip.

	[valgrind command] 2>&1 | gzip > output.gz

