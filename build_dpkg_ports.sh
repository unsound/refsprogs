#!/bin/bash

if [ $# -ne 1 ]; then
	echo "usage: $0 <version>"
	exit 1
fi

VERSION=$1
git clean -f -d -x debian/ && \
	./autogen.sh && \
	./configure && \
	make dist && \
	mv -v refsprogs-$VERSION.tar.gz ../refsprogs_$VERSION.orig.tar.gz && \
	apt install libfuse3-dev && \
	dpkg-buildpackage -us -uc && \
	for i in alpha hppa ia64 m68k powerpc ppc64 riscv64 sh4 sparc64 x32; do \
		apt install -y libfuse3-dev:$i && \
			dpkg-buildpackage -us -uc -b --host-arch $i && \
			apt remove $(dpkg --list | grep :$i | cut -d ' ' -f 3); \
	done
