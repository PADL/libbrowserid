#!/bin/sh
#
# Regenerate autotools files.
#

PATH=/usr/local/bin:$PATH

if [ -x "`which autoreconf 2>/dev/null`" ] ; then
   exec autoreconf -ivf
fi

aclocal -I . -I m4 && \
    autoheader && \
    libtoolize --automake -c && \
    autoconf && \
    automake --add-missing --copy
