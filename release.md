# Release Process

## Nanos
Create a [github release](https://github.com/nanovms/nanos/releases) and build the source on 
Linux and Mac. Update the below.

example:
```
  ./release.sh
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
