#!/bin/bash

# This file is to automate some of the release process.
# It will package up releases built and installed into
# a prefix directory of "release". The result will be
# signed tar and zip files in "release/packages".

set -e

basename="libstorj-2.0.0-beta2"

releases=(arm-linux-gnueabihf
          i686-pc-linux-gnu
          i686-w64-mingw32
          x86_64-apple-darwin11
          x86_64-pc-linux-gnu
          x86_64-w64-mingw32)

short_releases=(linux-armv7
                linux32
                win32
                macos
                linux64
                win64)

for i in "${!releases[@]}"; do
    release="${releases[$i]}"
    short="${short_releases[$i]}"

    printf "Starting %s (%s)...\n" $release $short

    echo "Copying documents..."
    rel_dir="release/${release}"
    cp -v "README.md" "${rel_dir}/"
    cp -v "LICENSE" "${rel_dir}/"

    echo "Preparing directory..."
    new_dir="release/${release}/${basename}"
    mkdir -p "${new_dir}"
    mv -v $rel_dir/[^$basename]* $new_dir/

    echo "Packaging..."
    mkdir -p "release/packages"
    pushd $rel_dir
    if [[ "$release" =~ "w64" ]]; then
        zip -r $basename-$short.zip $basename
        mv $basename-$short.zip ../packages/
    else
        tar -cvzf $basename-$short.tar.gz $basename
        mv $basename-$short.tar.gz ../packages/
    fi
    popd

    printf "\n\n"
done

echo "Hashing and signing packages..."
pushd "release/packages"
sha256sum [!SHA256SUMS]* > SHA256SUMS
gpg --clearsign SHA256SUMS
popd
