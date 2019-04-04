# Release Process

## Nanos
Create a [github release](https://github.com/nanovms/nanos/releases) and build the source on 
Linux and Mac. Update the below.

example:
```
  version=0.1.11 make release
  gsutil cp nanos-release-darwin-0.1.11.tar.gz gs://nanos/release/0.1.11/nanos-release-darwin-0.1.11.tar.gz
  gsutil -D setacl public-read gs://nanos/release/0.1.11/nanos-release-darwin-0.1.11.tar.gz

  # osx
  md5 -q nanos-release-darwin-0.1.11.tar.gz > nanos-release-darwin-0.1.11.md5

  # linux
  md5sum nanos-release-linux-0.1.11.tar.gz |  awk '{print $1} > nanos-release-linux-0.1.11.md5

  gsutil cp nanos-release-darwin-0.1.11.md5 gs://nanos/release/0.1.11/nanos-release-darwin-0.1.11.md5
  gsutil -D setacl public-read gs://nanos/release/0.1.11/nanos-release-darwin-0.1.11.md5

  echo "0.1.11" > latest.txt
  gsutil cp latest.txt gs://nanos/release/latest.txt
  gsutil -D setacl public-read gs://nanos/release/latest.txt
 
```


## Ops

See [OPS release.sh](https://github.com/nanovms/ops/blob/master/release.sh)

## Packages
    Follow the (PACKAGES.md)[PACKAGES.md] to update the packages.

## How end-user gets updates?
Right now we dont push updates to user, but user need to request for update.
    
1. **Updating ops**:
```
    ops update
```
2. **Updating nanos**:
```
    Use the -f flag with ops commands.
    ops run/load -f  
```
