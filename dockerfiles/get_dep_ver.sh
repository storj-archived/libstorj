#!/bin/bash
RESULT="`wget -q https://github.com/Storj/libstorj/releases -O - | sed -n 's/.*href="\([^"]*\).*/\1/p'`"

LINKS=$(echo $RESULT | tr " " "\n")
FOUND=0
FILENAME=""

for link in $LINKS
do
    if [[ $link == *"linux64"* ]]; then
	if [[ $FOUND -eq 0 ]]; then
		FILENAME="$link"
		FOUND=1
	fi
    fi
done

VERSION=$(echo $FILENAME | grep -o "/libstorj-.*")
LIBSTORJ_VERSION=${VERSION:10:-15}
echo "Found Latest Version of Libstorj - $LIBSTORJ_VERSION"
echo $LIBSTORJ_VERSION > libstorj
