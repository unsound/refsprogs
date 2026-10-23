#!/bin/bash

export LANG=C

IGNORE_REGEX='\.git|build_dpkg.*.sh|bump_debian_version.sh|targets'

if [ $# -ne 1 ]; then
	echo "usage: $0 <version>"
	exit 1
fi

VERSION=$1

if [ $UID -ne 0 ]; then
    echo "build_dpkg_hurd.sh should be run as root."
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

if [ ! -f ../refsprogs_$VERSION.orig.tar.gz ]; then
    echo "Creating source tarball..."
    # TODO: When building in GNU/Hurd for some reason it need the libraries to
    # already be installed on the host system or 'dpkg-buildpackage' will
    # complain when building the package.
    # This must be an issue with the deb package or my setup. Resolving it is
    # TODO.
    ( ./autogen.sh && \
      ./configure && \
      make clean && \
      make install && \
      make clean && \
      make dist && \
      mv -vn refsprogs-$VERSION.tar.gz ../refsprogs_$VERSION.orig.tar.gz && \
      make maintainer-clean ) || exit 1
fi

echo "Building debian package..."
git clean -f -d -x debian/ && \
	./autogen.sh && \
	./configure && \
	apt install -y libfuse-hurd-dev && \
	dpkg-buildpackage -us -uc --diff-ignore="$IGNORE_REGEX" -b
