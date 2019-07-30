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

    echo "Copying dependencies..."
    dep_src_dir="./depends/build/${release}"
    dep_dir="./release/${release}/depends"
    if [ -d "${dep_src_dir}" ]; then
        mkdir -p $dep_dir
        cp -vR $dep_src_dir/* $dep_dir
        rm -rf $dep_dir/bin
        rm -rf $dep_dir/share
    else
        echo "Skipping copying ${dep_src_dir} to ${dep_dir}, source directory does not exist."
    fi

    echo "Copying documents..."
    rel_dir="release/${release}"
    cp -v "README.md" "${rel_dir}/"
    cp -v "LICENSE" "${rel_dir}/"

    echo "Preparing directory..."
    pkg_dir="release/packages"
    mkdir -p "${pkg_dir}"
    new_dir="${pkg_dir}/${release}/${basename}"
    mkdir -p "${new_dir}"
    cp -vR $rel_dir/* $new_dir/

    echo "Packaging..."
    pushd $pkg_dir/$release
    if [[ "$release" =~ "w64" ]]; then
        zip -r $basename-$short.zip $basename
        mv $basename-$short.zip ..
    else
        tar -cvzf $basename-$short.tar.gz $basename
        mv $basename-$short.tar.gz ..
    fi
    popd

    echo "Cleaning up..."
    rm -rfv $pkg_dir/$release

    printf "\n\n"
done

echo "Hashing and signing packages..."
pushd "release/packages"
sha256sum [!SHA256SUMS]* > SHA256SUMS
gpg --clearsign SHA256SUMS
popd
