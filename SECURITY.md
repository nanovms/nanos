## Security

Security is not binary. Software is not 'secure' or 'insecure'. It's
more of a spectrum.

This document contains any pro-active measures we've enabled.

__ASLR__:

* Stack Randomization

* Heap Randomization

* Library Randomization

* Binary Randomization

__Page Protections__:

* Stack Execution off by Default

* Heap Execution off by Default

* Null Page is Not Mapped

* Stack Cookies/Canaries

* Rodata no execute

* Text no write

## Other Considerations

* Single Process

* No Users

* No Shell
