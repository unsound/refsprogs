#!/bin/sh

if [ $# -ne 2 ]; then
    echo "usage: bump_debian_version.sh <version> <library version>"
    exit 1
fi

VERSION="$1"
LIBRARY_VERSION="$2"

set -x

# Change the library version of librefs*.install.
git mv debian/librefs[0-9]*.install debian/librefs${LIBRARY_VERSION}.install || exit 1

# Update library version in debian/control.
( sed "s/librefs[0-9][0-9]*/librefs${LIBRARY_VERSION}/g" debian/control > debian/control.new && mv debian/control.new debian/control ) || exit 1

# Generate changelog entry.
echo "refsprogs (${VERSION}-1) main; urgency=medium" > debian/changelog.new || exit 1
echo "" >> debian/changelog.new || exit 1
echo "  * New upstream release." >> debian/changelog.new || exit 1
echo "" >> debian/changelog.new || exit 1
echo " -- Erik Larsson <catacombae@gmail.com>  $(LANG=C date -R)" >> debian/changelog.new || exit 1
echo "" >> debian/changelog.new || exit 1
cat debian/changelog >> debian/changelog.new || exit 1
mv -v debian/changelog.new debian/changelog || exit 1

# Generate local changelog entry.

echo "Version ${VERSION}-1 ($(LANG=C date '+%b %e'))" > debian/local/changelog.new || exit 1
echo "" >> debian/local/changelog.new || exit 1
echo "     * New upstream release." >> debian/local/changelog.new
echo "" >> debian/local/changelog.new || exit 1
cat debian/local/changelog >> debian/local/changelog.new || exit 1
mv -v debian/local/changelog.new debian/local/changelog || exit 1
