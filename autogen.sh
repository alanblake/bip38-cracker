#!/bin/sh

# I used automake 1.14.1 and autoconf 2.69.  Your milage may vary.

set -e

aclocal
#autoheader
automake --gnu --add-missing --copy
autoconf
