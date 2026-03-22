#!/bin/bash

export LANG=C

IGNORE_REGEX='\.git|build_dpkg.*.sh|bump_debian_version.sh|targets'

if [ $# -ne 1 ]; then
	echo "usage: $0 <version>"
	exit 1
fi

VERSION=$1

archs=""
if [ "$(echo `lsb_release -i | cut -d ':' -f 2-`)" == "Debian" ]; then
    case "$(echo `lsb_release -r | cut -d ':' -f 2-`)" in
	"10")
	    archs="arm64 armel armhf i386 mips mips64el mipsel ppc64el s390x"
	    ;;
	"13")
	    archs="arm64 armel armhf i386 ppc64el riscv64 s390x"
	    ;;
	*)
	    ;;
    esac
fi

if [ -z "$archs" ]; then
    echo "Only Debian 10 (buster) and 13 (trixie) can be used to build packages."
    exit 1
fi

GIT_DIFF=$(git diff HEAD 2>&1)
if [ ! -z "$GIT_DIFF" ]; then
    echo "There are uncommitted changes:"
    echo "$GIT_DIFF"
    echo "Please stash or commit the changes before building the Debian package."
    exit 1
fi

GIT_CLEAN=$(git clean -n -d -x 2>&1)
if [ ! -z "$GIT_CLEAN" ]; then
    echo "There are untracked files:"
    echo "$GIT_CLEAN"
    echo "Please stash or commit the untracked files before building the Debian package."
    exit 1
fi

if [ ! -f ../refsprogs_$VERSION-orig.tar.gz ]; then
    echo "Creating source tarball..."
    ( ./autogen.sh && ./configure && make dist && mv -vn refsprogs-$VERSION.tar.gz ../refsprogs_$VERSION-orig.tar.gz && make maintainer-clean) || exit 1
fi

echo "Building debian packages..."
git clean -f -d -x debian/ && \
	./autogen.sh && \
	./configure && \
	make dist && \
	mv -v refsprogs-$VERSION.tar.gz ../refsprogs_$VERSION.orig.tar.gz && \
	apt install libfuse3-dev && \
	dpkg-buildpackage -us -uc --diff-ignore="$IGNORE_REGEX"&& \
	for i in $archs; do \
		apt install -y libfuse3-dev:$i && \
			dpkg-buildpackage -us -uc --diff-ignore="$IGNORE_REGEX" -b --host-arch $i && \
			apt remove $(dpkg --list | grep "^ii .*:$i" | cut -d ' ' -f 3); \
	done
