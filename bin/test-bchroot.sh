#!/bin/bash
set -eux

tmp=$(mktemp -d)

cd "$tmp"
plash copy -A -- rootfs
chmod 755 rootfs

bchroot="$OLDPWD"/dist/bchroot

$bchroot rootfs true

: test some exported var gets in by default
export TESTVAR1=111
export TESTVAR2=222
out=$($bchroot rootfs printenv TESTVAR1)
test $out = 111

: test only explicit allowed var gets in
out=$($bchroot -e TESTVAR1 rootfs sh -c 'echo $TESTVAR1:$TESTVAR2')
test $out = 111:

: test mounting and current dir propagation
test $($bchroot -m /tmp rootfs pwd) = $(pwd)

: test setuid/setgid
test "$($bchroot -u 123 rootfs id -u)" = 123
test "$($bchroot -g 321 rootfs id -g)" = 321

set +x
echo
echo "    PASS"
echo
