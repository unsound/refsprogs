#!/bin/sh

if [ $# -ne 2 ] && [ $# -ne 3 ]; then
    echo "usage: bump_debian_version.sh <version> <library version> [<revision>]"
    exit 1
fi

VERSION="$1"
LIBRARY_VERSION="$2"
if [ $# -eq 3 ]; then
    REVISION="$3"
else
    REVISION="1"
fi

set -x

if [ ! -f debian/librefs${LIBRARY_VERSION}.install ]; then
    # Change the library version of librefs*.install.
    git mv debian/librefs[0-9]*.install debian/librefs${LIBRARY_VERSION}.install || exit 1
fi

# Update library version in debian/control.
( sed "s/librefs[0-9][0-9]*/librefs${LIBRARY_VERSION}/g" debian/control > debian/control.new && mv debian/control.new debian/control ) || exit 1

# Update library version in debian/refsprogs-udeb.lintian-overrides.
( sed "s/librefs[0-9][0-9]*/librefs${LIBRARY_VERSION}/g" debian/refsprogs-udeb.lintian-overrides > debian/refsprogs-udeb.lintian-overrides.new && mv debian/refsprogs-udeb.lintian-overrides.new debian/refsprogs-udeb.lintian-overrides ) || exit 1

# Generate changelog entry.
echo "refsprogs (${VERSION}-${REVISION}) main; urgency=medium" > debian/changelog.new || exit 1
echo "" >> debian/changelog.new || exit 1
echo "  * New upstream release." >> debian/changelog.new || exit 1
echo "" >> debian/changelog.new || exit 1
echo " -- Erik Larsson <catacombae@gmail.com>  $(LANG=C date -R)" >> debian/changelog.new || exit 1
echo "" >> debian/changelog.new || exit 1
cat debian/changelog >> debian/changelog.new || exit 1
mv -v debian/changelog.new debian/changelog || exit 1

# Generate local changelog entry.

echo "Version ${VERSION}-${REVISION} ($(LANG=C date '+%b %e'))" > debian/local/changelog.new || exit 1
echo "" >> debian/local/changelog.new || exit 1
echo "     * New upstream release." >> debian/local/changelog.new
echo "" >> debian/local/changelog.new || exit 1
cat debian/local/changelog >> debian/local/changelog.new || exit 1
mv -v debian/local/changelog.new debian/local/changelog || exit 1
