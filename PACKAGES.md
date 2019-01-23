# Packages

This really belongs in ops but I'm putting here for now because of some
slightly sensitive info.

### Create Directory

For example if we want to make a package for Lua 5.2.4 we'd have the
following:

```
export PKGNAME=lua
export PKGVERSION=5.2.4

mkdir $PKGNAME_$PKGVERSION
```

### Populate it

For exammple:

```
eyberg@s1:~/plz/lua_5.2.4$ tree
.
├── lua
├── package.manifest
└── sysroot
    ├── lib
    │   └── x86_64-linux-gnu
    │       ├── libc.so.6
    │       ├── libdl.so.2
    │       ├── libm.so.6
    │       ├── libreadline.so.6
    │       └── libtinfo.so.5
    └── lib64
        └── ld-linux-x86-64.so.2

4 directories, 8 files
```

Your package.manifest should look something like this:

```
{
   "Program":"lua_5.2.4/lua",
   "Args" : ["lua"],
   "Version":"5.2.4"
}
```

In many cases this is a dump from ldd:

```
eyberg@s1:~/plz/lua_5.2.4$ ldd lua
        linux-vdso.so.1 =>  (0x00007ffd18bf3000)
        libreadline.so.6 => /lib/x86_64-linux-gnu/libreadline.so.6 (0x00007f74e8836000)
        libm.so.6 => /lib/x86_64-linux-gnu/libm.so.6 (0x00007f74e852d000)
        libdl.so.2 => /lib/x86_64-linux-gnu/libdl.so.2 (0x00007f74e8329000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f74e7f5f000)
        libtinfo.so.5 => /lib/x86_64-linux-gnu/libtinfo.so.5 (0x00007f74e7d36000)
        /lib64/ld-linux-x86-64.so.2 (0x00007f74e8a7c000)
```

but don't forget libnss and friends.

```
/lib/x86_64-linux-gnu/libnss_dns.so.2
```

Needs more information on exactly what we want/need here (prob. not
everything).

```
/etc/ssl/certs
```

### Tar it up

The name needs to reflect this format:

```
tar czf $PKGNAME_PKGVERSION.tar.gz $PKGNAME_$PKGVERSION
```

### Update the manifest.json

```
gsutil cp g://packagehub/manifest.json .
```

```
  "lua_5.2.4": {
      "runtime" : "lua",
      "version": "5.2.4",
      "language": "lua",
      "description": "lua"
  },
```

### Upload

Note: If you need access to google cloud talk to Ian. Also, we'll be
moving this to a self hosted minio instance before too long.

```
gsutil cp ~/$lang_$version.tar.gz gs://packagehub/$lang_version.tar.gz
gsutil -D setacl public-read gs://packagehub/$lang_$version.tar.gz
gsutil -D setacl public-read gs://packagehub/manifest.json
```

### NOTE

For some crazy reason google doesn't update the last-modified header and
it gets cached for a while.

I've tried looking at this but that doesn't seem to work either.
https://cloud.google.com/storage/docs/gsutil/commands/setmeta
