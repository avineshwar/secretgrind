#!/bin/sh

#- 1 Apply patches
#==================
# guide to patches http://www.cyberciti.biz/faq/appy-patch-file-using-patch-command/
# patches were created with
# cd ../coregrind/
# diff -u m_execontext.c m_execontext.c.patch > ../taintgrind/valgrind.patch

cd ../coregrind/
patch < ../secretgrind/valgrind.patch
retval=$?
if [ $retval -ne 0 ]; then
	echo "Return code was not zero but $retval"
	exit
fi

echo SUCCESS
