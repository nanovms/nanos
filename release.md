# Release Process

## Nanos
Create a github release and build the source on 
Linux and Mac. Update the below.

```
    gsutil cp stage3.img gs://nanos/release/
    gsutil cp boot.img gs://nanos/release/
    gsutil cp mkfs gs://nanos/release/linux 
    gsutil cp mkfs gs://nanos/release/darwin

    gsutil -D setacl public-read  gs://nanos/release/linux/mkfs 
    gsutil -D setacl public-read  gs://nanos/release/darwin/mkfs 
        
    gsutil -D setacl public-read  gs://nanos/release/stage3.img 
    gsutil -D setacl public-read  gs://nanos/release/boot.img 
```

## Ops
Build ops for Mac and Linux and update below.
```
    gsutil cp ops gs://cli/linux 
    gsutil cp ops gs://cli/darwin
    gsutil -D setacl public-read  gs://cli/linux/ops 
    gsutil -D setacl public-read  gs://cli/darwin/ops 

```
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
