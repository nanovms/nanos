#!/bin/sh

version=0.1.17
plat="$(uname -s | awk '{print tolower($0)}')"

tgz="nanos-release-$plat-$version.tar.gz"
hash="nanos-release-$plat-$version.md5"

rm "$tgz"
rm "$hash"

version="$version" make release

gsutil cp release/"$tgz" gs://nanos/release/"$version"/"$tgz"
gsutil setacl public-read gs://nanos/release/"$version"/"$tgz"

if [ "$plat" = 'darwin' ]
then
  md5 -q release/"$tgz" > "$hash"
else
  md5sum release/"$tgz" | awk '{print $1}' > "$hash"
fi

gsutil cp "$hash" gs://nanos/release/"$version"/"$hash"
gsutil setacl public-read gs://nanos/release/"$version"/"$hash"

echo "$version" > latest.txt
gsutil cp latest.txt gs://nanos/release/latest.txt
gsutil setacl public-read gs://nanos/release/latest.txt
