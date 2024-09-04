## Security

Security is not binary. Software is not 'secure' or 'insecure'. It's
more of a spectrum.

This document contains any pro-active measures we've enabled.

__ASLR__:

* Stack Randomization

* Heap Randomization

* Library Randomization

* Binary Randomization

__KASLR__:

* Kernel Load Address Randomization

* Klib Load Address Randomization

__Page Protections__:

* Stack Execution off by Default

* Heap Execution off by Default

* Null Page is Not Mapped

* Stack Cookies/Canaries

* Rodata no execute

* Text no write

* Guard gap between process stack and adjacent mapping

__Random Number Generation__:

* virtio-rng driver

* rdseed and rdrand CPU instructions on x86 platforms

By default neither the user application nor the interpreter is allowed to be overwritten.

Optional 'exec_protection' may also be turned on where one needs to
explicitly mark files as executable. When this is turned on the
application can not modify the executable and cannot create new
executable files.

Nanos also supports the pledge and unveil syscalls from OpenBSD for more
restricted operating modes.

## Other Considerations

* Single Process

* No Users

* No Shell

To report security issues email security @ . We don't do PGP.
(https://gist.github.com/rjhansen/67ab921ffb4084c865b3618d6955275f)
